package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const xrayStateAuditInterval = 10 * time.Minute

var (
	detectXrayPlatform            = func() (string, string) { return runtime.GOOS, runtime.GOARCH }
	xrayServiceLifecycleSupported = isSystemdHost
)

func currentXrayCapability() XrayCapability {
	platformOS, platformArch := detectXrayPlatform()
	capability := XrayCapability{
		SchemaVersion: XraySchemaVersion, Supervisor: "AGENT_CHILD", SupportedOS: platformOS, SupportedArch: platformArch,
		SupportsArtifactInstall: false, SupportsPortProbe: false, SupportsRealityScan: false,
	}
	if platformOS != "linux" || (platformArch != "amd64" && platformArch != "arm64") {
		capability.ErrorCode = string(XrayErrorHostPlatformUnsupported)
		return capability
	}
	if !xrayServiceLifecycleSupported() {
		capability.ErrorCode = string(XrayErrorCapabilityUnsupported)
		return capability
	}
	capability.Supported = true
	capability.SupportsArtifactInstall = true
	capability.SupportsPortProbe = true
	capability.SupportsUDPPortProbe = true
	capability.SupportsUDPListenerReadiness = true
	capability.SupportsRealityScan = true
	return capability
}

func (runtimeManager *xrayRuntime) ObservedState(now time.Time) XrayObservedState {
	runtimeManager.mu.Lock()
	defer runtimeManager.mu.Unlock()
	observed := XrayObservedState{
		SchemaVersion: XraySchemaVersion, ServiceStatus: XrayServiceStopped,
		Listeners: []XrayObservedListener{}, ObservedAt: now.UTC().Format(time.RFC3339Nano),
	}
	state, stateErr := readXrayRuntimeStateAt(runtimeManager.managedRoot)
	var binaryPath string
	if state != nil {
		observed.AppliedGeneration = state.AppliedGeneration
		configHash := state.AppliedConfigHash
		observed.AppliedConfigHash = &configHash
		binaryPath, stateErr = readCurrentXrayBinary(runtimeManager.managedRoot)
		if stateErr == nil {
			binaryHash, hashErr := sha256File(binaryPath, xrayArtifactMaxBinaryBytes)
			if hashErr != nil || binaryHash != state.CurrentBinarySHA256 ||
				!strings.Contains(binaryPath, string(filepath.Separator)+state.CurrentVersion+string(filepath.Separator)) {
				stateErr = errXrayBinaryHashMismatch
			} else {
				version := state.CurrentVersion
				observed.IsInstalled = true
				observed.InstalledVersion = &version
				observed.BinarySHA256 = &binaryHash
			}
		}
		if stateErr == nil {
			_, stateErr = runtimeManager.snapshot()
		}
	} else if stateErr == nil {
		if installedPath, binaryHash, installedErr := runtimeManager.resolveBinary(XrayManagedVersion); installedErr == nil {
			binaryPath = installedPath
			version := XrayManagedVersion
			observed.IsInstalled = true
			observed.InstalledVersion = &version
			observed.BinarySHA256 = &binaryHash
		}
	}
	status := runtimeManager.supervisor.Status()
	if state != nil && stateErr == nil && state.DesiredRunning && status.ServiceStatus == XrayServiceRunning &&
		status.PID > 0 && status.Generation == state.AppliedGeneration && status.ConfigHash == state.AppliedConfigHash &&
		status.Version == state.CurrentVersion && filepath.Clean(status.BinaryPath) == filepath.Clean(binaryPath) {
		observed.ServiceStatus = XrayServiceRunning
		runningVersion := state.CurrentVersion
		observed.RunningVersion = &runningVersion
		pid := status.PID
		observed.ProcessID = &pid
		listeners, probeErr := runtimeManager.probeListeners(status.PID, state.ExpectedListeners)
		if probeErr == nil {
			observed.Listeners = listeners
			if !allXrayListenersReady(state.ExpectedListeners, listeners) {
				observed.LastError = newXrayObservedError(XrayErrorRuntimeNotReady, "Managed Xray listeners are not ready", state.AppliedGeneration, now)
			}
		} else {
			observed.Listeners = unknownXrayListeners(state.ExpectedListeners, XrayErrorInternal)
			observed.LastError = newXrayObservedError(XrayErrorInternal, "Managed Xray listeners could not be inspected", state.AppliedGeneration, now)
		}
	} else if state != nil {
		observed.Listeners = missingXrayListeners(state.ExpectedListeners)
		if state.DesiredRunning && stateErr == nil {
			observed.ServiceStatus = XrayServiceError
			observed.LastError = newXrayObservedError(XrayErrorRuntimeStartFailed, "Managed Xray is not running", state.AppliedGeneration, now)
		} else if !state.DesiredRunning && stateErr == nil && status.ServiceStatus == XrayServiceRunning {
			observed.ServiceStatus = XrayServiceError
			observed.LastError = newXrayObservedError(XrayErrorInternal, "Managed Xray supervisor state conflicts with runtime state", state.AppliedGeneration, now)
		}
	}
	if stateErr != nil {
		observed.ServiceStatus = XrayServiceError
		generation := int64(0)
		if state != nil {
			generation = state.AppliedGeneration
		}
		observed.LastError = newXrayObservedError(XrayErrorInternal, "Managed Xray runtime state is invalid", generation, now)
	} else if status.ServiceStatus == XrayServiceError && observed.LastError == nil {
		observed.ServiceStatus = XrayServiceError
		generation := observed.AppliedGeneration
		observed.LastError = newXrayObservedError(XrayErrorRuntimeStartFailed, "Managed Xray supervisor reported an error", generation, now)
	}
	decorateXrayObservedStateWithDesiredFailure(&observed)
	return observed
}

func newXrayObservedError(code XrayAgentErrorCode, message string, generation int64, now time.Time) *XrayObservedError {
	return &XrayObservedError{Code: string(code), Message: message, Generation: generation, OccurredAt: now.UTC().Format(time.RFC3339Nano)}
}

func missingXrayListeners(expected []XrayExpectedListener) []XrayObservedListener {
	listeners := make([]XrayObservedListener, 0, len(expected))
	for _, listener := range expected {
		listeners = append(listeners, XrayObservedListener{
			RuntimeTag: listener.RuntimeTag, Network: listener.Network, Port: listener.Port, Status: XrayListenerMissing,
		})
	}
	return listeners
}

func unknownXrayListeners(expected []XrayExpectedListener, code XrayAgentErrorCode) []XrayObservedListener {
	listeners := make([]XrayObservedListener, 0, len(expected))
	errorCode := string(code)
	for _, listener := range expected {
		listeners = append(listeners, XrayObservedListener{
			RuntimeTag: listener.RuntimeTag, Network: listener.Network, Port: listener.Port,
			Status: XrayListenerUnknown, ErrorCode: &errorCode,
		})
	}
	return listeners
}

type xrayHeartbeatReport struct {
	Signature         string
	State             *XrayObservedState
	requestGeneration uint64
}

type xrayHeartbeatCache struct {
	sync.Mutex
	lastSignature              string
	lastFullReportedAt         time.Time
	requestGeneration          uint64
	committedRequestGeneration uint64
}

var xrayHeartbeatState xrayHeartbeatCache
var managedXrayRuntimeManager = newXrayRuntime(xrayManagedRoot, xrayManagedConfigRoot, managedXrayRuntimeSupervisor)
var buildCurrentXrayObservedState = func(now time.Time) XrayObservedState {
	return managedXrayRuntimeManager.ObservedState(now)
}

func xrayObservedStateSignature(state XrayObservedState) string {
	state.ObservedAt = ""
	if state.LastError != nil {
		lastError := *state.LastError
		lastError.OccurredAt = ""
		state.LastError = &lastError
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

func xrayStateForHeartbeatAt(now time.Time, force bool) xrayHeartbeatReport {
	state := buildCurrentXrayObservedState(now)
	signature := xrayObservedStateSignature(state)
	xrayHeartbeatState.Lock()
	requestGeneration := xrayHeartbeatState.requestGeneration
	sendFull := force || signature != xrayHeartbeatState.lastSignature ||
		requestGeneration > xrayHeartbeatState.committedRequestGeneration || xrayHeartbeatState.lastFullReportedAt.IsZero() ||
		now.Sub(xrayHeartbeatState.lastFullReportedAt) >= xrayStateAuditInterval
	xrayHeartbeatState.Unlock()
	report := xrayHeartbeatReport{Signature: signature, requestGeneration: requestGeneration}
	if sendFull {
		stateCopy := state
		report.State = &stateCopy
	}
	return report
}

func appendXrayHeartbeatState(payload map[string]any, now time.Time) xrayHeartbeatReport {
	report := xrayStateForHeartbeatAt(now, false)
	if report.Signature == "" {
		return report
	}
	payload["xrayStateSignature"] = report.Signature
	if report.State != nil {
		payload["xrayState"] = report.State
	}
	return report
}

func commitXrayHeartbeatState(report xrayHeartbeatReport, reportedAt time.Time) {
	if report.Signature == "" || report.State == nil {
		return
	}
	xrayHeartbeatState.Lock()
	xrayHeartbeatState.lastSignature = report.Signature
	xrayHeartbeatState.lastFullReportedAt = reportedAt
	if report.requestGeneration > xrayHeartbeatState.committedRequestGeneration {
		xrayHeartbeatState.committedRequestGeneration = report.requestGeneration
	}
	xrayHeartbeatState.Unlock()
}

func requestXrayStateUpload() {
	xrayHeartbeatState.Lock()
	xrayHeartbeatState.requestGeneration++
	xrayHeartbeatState.Unlock()
}

func resetXrayHeartbeatStateForTest() {
	xrayHeartbeatState.Lock()
	xrayHeartbeatState.lastSignature = ""
	xrayHeartbeatState.lastFullReportedAt = time.Time{}
	xrayHeartbeatState.requestGeneration = 0
	xrayHeartbeatState.committedRequestGeneration = 0
	xrayHeartbeatState.Unlock()
}

func (runtimeManager *xrayRuntime) RecoverLocal(ctx context.Context) (*xraySupervisorStatus, error) {
	runtimeManager.mu.Lock()
	defer runtimeManager.mu.Unlock()
	if err := ensurePrivateXrayDirectory(runtimeManager.configRoot); err != nil {
		return nil, err
	}
	if err := runtimeManager.recoverInterruptedApply(); err != nil {
		return nil, err
	}
	state, err := readXrayRuntimeStateAt(runtimeManager.managedRoot)
	if err != nil || state == nil || !state.DesiredRunning {
		return nil, err
	}
	snapshot, err := runtimeManager.snapshot()
	if err != nil || !snapshot.hasConfig || !snapshot.hasCurrent {
		return nil, err
	}
	if err := runtimeManager.testConfig(ctx, snapshot.currentBinary, filepath.Join(runtimeManager.configRoot, "config.json")); err != nil {
		return nil, &xrayRuntimeApplyError{code: XrayErrorConfigInvalid, message: "The local Xray config test failed", cause: err}
	}
	launchSpec := xrayLaunchSpec{
		BinaryPath: snapshot.currentBinary, BinarySHA256: state.CurrentBinarySHA256,
		ConfigPath: filepath.Join(runtimeManager.configRoot, "config.json"), Version: state.CurrentVersion,
		Generation: state.AppliedGeneration, ConfigHash: state.AppliedConfigHash,
	}
	var status xraySupervisorStatus
	if recovering, ok := runtimeManager.supervisor.(interface {
		Recover() (*xraySupervisorStatus, error)
	}); ok {
		recovered, recoverErr := recovering.Recover()
		if recoverErr == nil && recovered != nil {
			status = *recovered
			if status.Generation != launchSpec.Generation || status.ConfigHash != launchSpec.ConfigHash ||
				status.Version != launchSpec.Version || filepath.Clean(status.BinaryPath) != filepath.Clean(launchSpec.BinaryPath) {
				if err := runtimeManager.supervisor.Stop(); err != nil {
					return nil, errors.New("recovered Xray supervisor identity does not match runtime state")
				}
				status = xraySupervisorStatus{ServiceStatus: XrayServiceStopped}
			}
		} else if recoverErr != nil && !errors.Is(recoverErr, errXrayConfigHashMismatch) &&
			!errors.Is(recoverErr, errXrayBinaryHashMismatch) && !errors.Is(recoverErr, errXrayUnmanagedPath) {
			return nil, recoverErr
		}
	}
	if status.ServiceStatus != XrayServiceRunning {
		status, err = runtimeManager.supervisor.Start(launchSpec)
		if err != nil {
			return nil, err
		}
	}
	if _, ready := runtimeManager.waitForReady(state.ExpectedListeners); !ready {
		return nil, &xrayRuntimeApplyError{code: XrayErrorRuntimeNotReady, message: "The recovered Xray runtime is not ready"}
	}
	return &status, nil
}
