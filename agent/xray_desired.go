package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type xrayDesiredApplyFunc func(context.Context, XrayDesiredState) (xrayApplyResult, error)

type xrayDesiredFailure struct {
	Code       XrayAgentErrorCode
	Message    string
	Generation int64
	OccurredAt time.Time
}

var xrayDesiredOutcome = struct {
	sync.Mutex
	failure *xrayDesiredFailure
}{}

func xrayDesiredFailureMessage(code XrayAgentErrorCode) string {
	switch code {
	case XrayErrorCapabilityUnsupported, XrayErrorHostPlatformUnsupported:
		return "Managed Xray is not supported on this Agent"
	case XrayErrorConfigInvalid:
		return "Managed Xray rejected the desired configuration"
	case XrayErrorGenerationHashConflict:
		return "Managed Xray rejected a conflicting desired generation"
	case XrayErrorArtifactNotFound, XrayErrorArtifactHashMismatch, XrayErrorArtifactArchMismatch:
		return "The managed Xray binary is unavailable"
	case XrayErrorRuntimeStartFailed:
		return "Managed Xray could not be started"
	case XrayErrorRuntimeNotReady:
		return "Managed Xray listeners did not become ready"
	case XrayErrorRollbackFailed:
		return "Managed Xray could not restore the last-good runtime"
	default:
		return "Managed Xray could not apply the desired state"
	}
}

func recordXrayDesiredFailure(code XrayAgentErrorCode, generation int64) {
	if !knownXrayDesiredErrorCode(code) {
		code = XrayErrorInternal
	}
	xrayDesiredOutcome.Lock()
	xrayDesiredOutcome.failure = &xrayDesiredFailure{
		Code: code, Message: xrayDesiredFailureMessage(code), Generation: generation, OccurredAt: time.Now().UTC(),
	}
	xrayDesiredOutcome.Unlock()
}

func knownXrayDesiredErrorCode(code XrayAgentErrorCode) bool {
	switch code {
	case XrayErrorCapabilityUnsupported, XrayErrorTaskExpired, XrayErrorTaskAlreadyCompleted,
		XrayErrorInvalidPayload, XrayErrorHostPlatformUnsupported, XrayErrorPortInUse,
		XrayErrorPortBindDenied, XrayErrorRealityTargetBlocked, XrayErrorRealityTLSUnsupported,
		XrayErrorArtifactNotFound, XrayErrorArtifactSizeMismatch, XrayErrorArtifactHashMismatch,
		XrayErrorArtifactArchMismatch, XrayErrorVersionMismatch, XrayErrorConfigInvalid,
		XrayErrorGenerationHashConflict, XrayErrorRuntimeStartFailed, XrayErrorRuntimeNotReady,
		XrayErrorRollbackFailed, XrayErrorInternal:
		return true
	default:
		return false
	}
}

func clearXrayDesiredFailure() {
	xrayDesiredOutcome.Lock()
	xrayDesiredOutcome.failure = nil
	xrayDesiredOutcome.Unlock()
}

func latestXrayDesiredFailure() *xrayDesiredFailure {
	xrayDesiredOutcome.Lock()
	defer xrayDesiredOutcome.Unlock()
	if xrayDesiredOutcome.failure == nil {
		return nil
	}
	copy := *xrayDesiredOutcome.failure
	return &copy
}

func decorateXrayObservedStateWithDesiredFailure(observed *XrayObservedState) {
	if observed == nil {
		return
	}
	failure := latestXrayDesiredFailure()
	if failure == nil || failure.Generation < observed.AppliedGeneration {
		return
	}
	observed.LastError = &XrayObservedError{
		Code: string(failure.Code), Message: failure.Message, Generation: failure.Generation,
		OccurredAt: failure.OccurredAt.Format(time.RFC3339Nano),
	}
}

func reconcileXrayDesiredState(desired XrayDesiredState, capability XrayCapability, apply xrayDesiredApplyFunc) {
	if err := validateXrayDesiredPayload(desired); err != nil {
		recordXrayDesiredFailure(XrayErrorConfigInvalid, desired.Generation)
		requestXrayStateUpload()
		return
	}
	if err := capability.Validate(); err != nil || !capability.Supported {
		recordXrayDesiredFailure(XrayErrorCapabilityUnsupported, desired.Generation)
		requestXrayStateUpload()
		return
	}
	if apply == nil {
		recordXrayDesiredFailure(XrayErrorInternal, desired.Generation)
		requestXrayStateUpload()
		return
	}
	result, err := apply(context.Background(), desired)
	if err != nil || !result.Applied {
		code := result.ErrorCode
		var runtimeError *xrayRuntimeApplyError
		if code == "" && errors.As(err, &runtimeError) {
			code = runtimeError.code
		}
		if code == "" {
			code = XrayErrorInternal
		}
		recordXrayDesiredFailure(code, desired.Generation)
	} else {
		clearXrayDesiredFailure()
	}
	requestXrayStateUpload()
}

func validateXrayDesiredPayload(desired XrayDesiredState) error {
	if err := desired.Validate(); err != nil {
		return err
	}
	if desired.TargetVersion != XrayManagedVersion {
		return fmt.Errorf("unsupported managed Xray target version")
	}
	if hashXrayBytes([]byte(desired.ConfigJSON)) != desired.ConfigHash {
		return fmt.Errorf("managed Xray config hash mismatch")
	}
	return nil
}

type xrayDesiredApplyJob struct {
	desired XrayDesiredState
	waiters []chan struct{}
}

type xrayDesiredApplyScheduler struct {
	mu                sync.Mutex
	current           *xrayDesiredApplyJob
	pending           *xrayDesiredApplyJob
	process           func(XrayDesiredState)
	rejectConflict    func(XrayDesiredState)
	rejectInvalid     func(XrayDesiredState)
	hasHighest        bool
	highestGeneration int64
	highestConfigHash string
}

func newXrayDesiredApplyScheduler(process func(XrayDesiredState)) *xrayDesiredApplyScheduler {
	return &xrayDesiredApplyScheduler{process: process}
}

func sameXrayDesiredIdentity(left, right XrayDesiredState) bool {
	return left.SchemaVersion == right.SchemaVersion && left.Generation == right.Generation && left.ConfigHash == right.ConfigHash
}

func closeXrayDesiredWaiters(waiters []chan struct{}) {
	for _, waiter := range waiters {
		close(waiter)
	}
}

func (scheduler *xrayDesiredApplyScheduler) Schedule(desired XrayDesiredState) <-chan struct{} {
	done := make(chan struct{})
	scheduler.mu.Lock()
	if validateXrayDesiredPayload(desired) != nil {
		reject := scheduler.rejectInvalid
		scheduler.mu.Unlock()
		if reject != nil {
			reject(desired)
		}
		close(done)
		return done
	}
	if scheduler.current != nil && sameXrayDesiredIdentity(scheduler.current.desired, desired) {
		scheduler.current.waiters = append(scheduler.current.waiters, done)
		scheduler.mu.Unlock()
		return done
	}
	if scheduler.pending != nil && sameXrayDesiredIdentity(scheduler.pending.desired, desired) {
		scheduler.pending.waiters = append(scheduler.pending.waiters, done)
		scheduler.mu.Unlock()
		return done
	}
	if scheduler.hasHighest && (desired.Generation < scheduler.highestGeneration ||
		(desired.Generation == scheduler.highestGeneration && desired.ConfigHash != scheduler.highestConfigHash)) {
		reject := scheduler.rejectConflict
		scheduler.mu.Unlock()
		if reject != nil {
			reject(desired)
		}
		close(done)
		return done
	}
	if !scheduler.hasHighest || desired.Generation > scheduler.highestGeneration {
		scheduler.hasHighest = true
		scheduler.highestGeneration = desired.Generation
		scheduler.highestConfigHash = desired.ConfigHash
	}
	job := &xrayDesiredApplyJob{desired: desired, waiters: []chan struct{}{done}}
	if scheduler.current == nil {
		scheduler.current = job
		scheduler.mu.Unlock()
		go scheduler.run()
		return done
	}
	if scheduler.pending == nil {
		scheduler.pending = job
		scheduler.mu.Unlock()
		return done
	}
	if desired.Generation > scheduler.pending.desired.Generation {
		closeXrayDesiredWaiters(scheduler.pending.waiters)
		scheduler.pending = job
	} else {
		close(done)
	}
	scheduler.mu.Unlock()
	return done
}

func (scheduler *xrayDesiredApplyScheduler) run() {
	for {
		scheduler.mu.Lock()
		job := scheduler.current
		scheduler.mu.Unlock()
		if job == nil {
			return
		}
		if scheduler.process != nil {
			scheduler.process(job.desired)
		}
		scheduler.mu.Lock()
		closeXrayDesiredWaiters(job.waiters)
		if scheduler.pending == nil {
			scheduler.current = nil
			scheduler.mu.Unlock()
			return
		}
		scheduler.current = scheduler.pending
		scheduler.pending = nil
		scheduler.mu.Unlock()
	}
}

var managedXrayDesiredApplyScheduler = newManagedXrayDesiredApplyScheduler()

func newManagedXrayDesiredApplyScheduler() *xrayDesiredApplyScheduler {
	scheduler := newXrayDesiredApplyScheduler(func(desired XrayDesiredState) {
		reconcileXrayDesiredState(desired, currentXrayCapability(), managedXrayRuntimeManager.Apply)
	})
	scheduler.rejectConflict = func(desired XrayDesiredState) {
		recordXrayDesiredFailure(XrayErrorGenerationHashConflict, desired.Generation)
		requestXrayStateUpload()
	}
	scheduler.rejectInvalid = func(desired XrayDesiredState) {
		recordXrayDesiredFailure(XrayErrorConfigInvalid, desired.Generation)
		requestXrayStateUpload()
	}
	return scheduler
}

func syncXrayDesiredState(desired *XrayDesiredState) <-chan struct{} {
	if desired == nil {
		return nil
	}
	return managedXrayDesiredApplyScheduler.Schedule(*desired)
}

func resetXrayDesiredOutcomeForTest() {
	clearXrayDesiredFailure()
}
