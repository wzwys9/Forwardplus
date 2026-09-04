package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func supportedXrayDesiredTestCapability() XrayCapability {
	return XrayCapability{
		SchemaVersion: XraySchemaVersion, Supported: true, Supervisor: "AGENT_CHILD",
		SupportsPortProbe: true, SupportsRealityScan: true, SupportsArtifactInstall: true,
		SupportedOS: "linux", SupportedArch: "amd64",
	}
}

func waitXrayDesiredDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Xray desired reconciliation")
	}
}

func TestXrayDesiredSSEAndHeartbeatShareOneSerializedApply(t *testing.T) {
	fixture := newXrayRuntimeFixture(t)
	started := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	applyCount := 0
	rejectCount := 0
	scheduler := newXrayDesiredApplyScheduler(func(desired XrayDesiredState) {
		mu.Lock()
		applyCount++
		count := applyCount
		mu.Unlock()
		if count == 1 {
			close(started)
			<-release
		}
	})
	scheduler.rejectConflict = func(XrayDesiredState) {
		mu.Lock()
		rejectCount++
		mu.Unlock()
	}
	previousScheduler := managedXrayDesiredApplyScheduler
	managedXrayDesiredApplyScheduler = scheduler
	t.Cleanup(func() { managedXrayDesiredApplyScheduler = previousScheduler })

	sseDone := syncXrayDesiredState(&fixture.desired)
	<-started
	heartbeatDone := syncXrayDesiredState(&fixture.desired)
	conflict := fixture.desired
	conflict.ConfigJSON = `{"log":{"loglevel":"error"},"inbounds":[],"outbounds":[]}`
	conflict.ConfigHash = hashXrayBytes([]byte(conflict.ConfigJSON))
	conflictDone := syncXrayDesiredState(&conflict)
	waitXrayDesiredDone(t, conflictDone)
	close(release)
	waitXrayDesiredDone(t, sseDone)
	waitXrayDesiredDone(t, heartbeatDone)
	mu.Lock()
	defer mu.Unlock()
	if applyCount != 1 || rejectCount != 1 {
		t.Fatalf("same SSE/heartbeat desired applies=%d conflicts=%d", applyCount, rejectCount)
	}
}

func TestXrayDesiredReappliesDriftAndReportsConflictWithoutLosingLastGood(t *testing.T) {
	resetXrayDesiredOutcomeForTest()
	t.Cleanup(resetXrayDesiredOutcomeForTest)
	fixture := newXrayRuntimeFixture(t)
	capability := supportedXrayDesiredTestCapability()
	scheduler := newXrayDesiredApplyScheduler(func(desired XrayDesiredState) {
		reconcileXrayDesiredState(desired, capability, fixture.runtime.Apply)
	})
	scheduler.rejectConflict = func(desired XrayDesiredState) {
		recordXrayDesiredFailure(XrayErrorGenerationHashConflict, desired.Generation)
	}

	waitXrayDesiredDone(t, scheduler.Schedule(fixture.desired))
	firstConfigTests := fixture.configTests
	firstStarts := len(fixture.supervisor.starts)
	if failure := latestXrayDesiredFailure(); failure != nil {
		t.Fatalf("successful desired left failure: %#v", failure)
	}
	waitXrayDesiredDone(t, scheduler.Schedule(fixture.desired))
	if fixture.configTests != firstConfigTests || len(fixture.supervisor.starts) != firstStarts {
		t.Fatalf("identical desired changed runtime: configTests=%d starts=%d", fixture.configTests, len(fixture.supervisor.starts))
	}

	fixture.supervisor.status = xraySupervisorStatus{ServiceStatus: XrayServiceStopped}
	waitXrayDesiredDone(t, scheduler.Schedule(fixture.desired))
	if fixture.configTests != firstConfigTests+1 || len(fixture.supervisor.starts) != firstStarts+1 {
		t.Fatalf("runtime drift was not reapplied: configTests=%d starts=%d", fixture.configTests, len(fixture.supervisor.starts))
	}

	conflict := fixture.desired
	conflict.ConfigJSON = `{"log":{"loglevel":"error"},"inbounds":[],"outbounds":[]}`
	conflict.ConfigHash = hashXrayBytes([]byte(conflict.ConfigJSON))
	waitXrayDesiredDone(t, scheduler.Schedule(conflict))
	failure := latestXrayDesiredFailure()
	if failure == nil || failure.Code != XrayErrorGenerationHashConflict || failure.Generation != fixture.desired.Generation {
		t.Fatalf("generation conflict failure = %#v", failure)
	}
	state, err := readXrayRuntimeStateAt(fixture.managedRoot)
	if err != nil || state == nil || state.AppliedGeneration != fixture.desired.Generation || state.AppliedConfigHash != fixture.desired.ConfigHash {
		t.Fatalf("last-good state changed after conflict: %#v err=%v", state, err)
	}
	observed := fixture.runtime.ObservedState(time.Now())
	if observed.LastError == nil || observed.LastError.Code != string(XrayErrorGenerationHashConflict) {
		t.Fatalf("desired failure missing from observed state: %#v", observed.LastError)
	}
	raw, err := json.Marshal(observed)
	if err != nil || strings.Contains(string(raw), conflict.ConfigJSON) {
		t.Fatalf("observed state leaked config: %s err=%v", raw, err)
	}
}

func TestXrayDesiredRejectsInvalidPayloadBeforeRuntimeAndDecodesAsOptional(t *testing.T) {
	resetXrayDesiredOutcomeForTest()
	t.Cleanup(resetXrayDesiredOutcomeForTest)
	fixture := newXrayRuntimeFixture(t)
	outerRaw, err := json.Marshal(map[string]any{
		"version": 1, "actions": []any{}, "xray": fixture.desired,
	})
	if err != nil {
		t.Fatal(err)
	}
	var outer desiredState
	if err := json.Unmarshal(outerRaw, &outer); err != nil || outer.Xray == nil || outer.Xray.ConfigHash != fixture.desired.ConfigHash {
		t.Fatalf("optional Xray desired decode failed: %#v err=%v", outer.Xray, err)
	}

	invalid := fixture.desired
	invalid.ConfigHash = strings.Repeat("F", 64)
	called := false
	reconcileXrayDesiredState(invalid, supportedXrayDesiredTestCapability(), func(context.Context, XrayDesiredState) (xrayApplyResult, error) {
		called = true
		return xrayApplyResult{}, nil
	})
	if called {
		t.Fatal("invalid desired reached the Xray runtime")
	}
	failure := latestXrayDesiredFailure()
	if failure == nil || failure.Code != XrayErrorConfigInvalid || failure.Generation != invalid.Generation {
		t.Fatalf("invalid desired failure = %#v", failure)
	}
	called = false
	unsupported := supportedXrayDesiredTestCapability()
	unsupported.Supported = false
	unsupported.ErrorCode = string(XrayErrorCapabilityUnsupported)
	reconcileXrayDesiredState(fixture.desired, unsupported, func(context.Context, XrayDesiredState) (xrayApplyResult, error) {
		called = true
		return xrayApplyResult{}, nil
	})
	if called {
		t.Fatal("unsupported Agent attempted Xray desired apply")
	}
	failure = latestXrayDesiredFailure()
	if failure == nil || failure.Code != XrayErrorCapabilityUnsupported {
		t.Fatalf("unsupported desired failure = %#v", failure)
	}
}
