package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestXrayCapabilityRequiresSupportedPlatformAndServiceLifecycle(t *testing.T) {
	previousPlatform := detectXrayPlatform
	previousLifecycle := xrayServiceLifecycleSupported
	t.Cleanup(func() {
		detectXrayPlatform = previousPlatform
		xrayServiceLifecycleSupported = previousLifecycle
	})
	detectXrayPlatform = func() (string, string) { return "linux", "amd64" }
	xrayServiceLifecycleSupported = func() bool { return true }
	capability := currentXrayCapability()
	if !capability.Supported || capability.Supervisor != "AGENT_CHILD" || !capability.SupportsArtifactInstall ||
		!capability.SupportsPortProbe || !capability.SupportsRealityScan {
		t.Fatalf("supported capability = %#v", capability)
	}
	if err := capability.Validate(); err != nil {
		t.Fatal(err)
	}

	detectXrayPlatform = func() (string, string) { return "linux", "riscv64" }
	unsupported := currentXrayCapability()
	if unsupported.Supported || unsupported.ErrorCode != string(XrayErrorHostPlatformUnsupported) {
		t.Fatalf("unsupported platform capability = %#v", unsupported)
	}
	detectXrayPlatform = func() (string, string) { return "linux", "arm64" }
	xrayServiceLifecycleSupported = func() bool { return false }
	unsupported = currentXrayCapability()
	if unsupported.Supported || unsupported.ErrorCode != string(XrayErrorCapabilityUnsupported) {
		t.Fatalf("unsupported service lifecycle capability = %#v", unsupported)
	}
}

func TestXrayObservedStateReportsManagedRuntimeWithoutSecrets(t *testing.T) {
	fixture := newXrayRuntimeFixture(t)
	result, err := fixture.runtime.Apply(context.Background(), fixture.desired)
	if err != nil || !result.Applied {
		t.Fatalf("fixture apply = %#v, %v", result, err)
	}
	now := time.Now().UTC()
	state := fixture.runtime.ObservedState(now)
	if !state.IsInstalled || state.InstalledVersion == nil || *state.InstalledVersion != XrayManagedVersion ||
		state.RunningVersion == nil || *state.RunningVersion != XrayManagedVersion || state.ServiceStatus != XrayServiceRunning {
		t.Fatalf("unexpected runtime identity: %#v", state)
	}
	if state.ProcessID == nil || *state.ProcessID != 4242 || state.BinarySHA256 == nil || *state.BinarySHA256 != fixture.binarySHA256 {
		t.Fatalf("unexpected process identity: %#v", state)
	}
	if state.AppliedGeneration != fixture.desired.Generation || state.AppliedConfigHash == nil || *state.AppliedConfigHash != fixture.desired.ConfigHash {
		t.Fatalf("unexpected applied identity: %#v", state)
	}
	if len(state.Listeners) != 1 || state.Listeners[0].Status != XrayListenerReady || state.LastError != nil {
		t.Fatalf("unexpected observed listeners: %#v", state)
	}
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"privateKey", "uuid", "shortId", "configJson", "token", "secret"} {
		if strings.Contains(strings.ToLower(string(raw)), strings.ToLower(forbidden)) {
			t.Fatalf("observed state contains %q: %s", forbidden, raw)
		}
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("observed state contract invalid: %v", err)
	}
}

func TestXrayObservedStateRejectsRunningSupervisorWhenDesiredStopped(t *testing.T) {
	fixture := newXrayRuntimeFixture(t)
	if result, err := fixture.runtime.Apply(context.Background(), fixture.desired); err != nil || !result.Applied {
		t.Fatalf("fixture apply = %#v, %v", result, err)
	}
	stateRecord, err := readXrayRuntimeStateAt(fixture.managedRoot)
	if err != nil || stateRecord == nil {
		t.Fatalf("read fixture state = %#v, %v", stateRecord, err)
	}
	stateRecord.DesiredRunning = false
	stateRecord.ExpectedListeners = []XrayExpectedListener{}
	if err := writeXrayRuntimeStateAt(fixture.managedRoot, *stateRecord); err != nil {
		t.Fatal(err)
	}

	state := fixture.runtime.ObservedState(time.Now().UTC())
	if state.ServiceStatus != XrayServiceError || state.LastError == nil || state.ProcessID != nil || state.RunningVersion != nil {
		t.Fatalf("running/desired-stopped drift was not reported safely: %#v", state)
	}
}

func TestXrayObservedHeartbeatSendsFullStateOnChangeRequestAndAudit(t *testing.T) {
	previousBuilder := buildCurrentXrayObservedState
	t.Cleanup(func() { buildCurrentXrayObservedState = previousBuilder })
	version := XrayManagedVersion
	hash := strings.Repeat("a", 64)
	binaryHash := strings.Repeat("b", 64)
	state := XrayObservedState{
		SchemaVersion: XraySchemaVersion, IsInstalled: true, InstalledVersion: &version, RunningVersion: &version,
		ServiceStatus: XrayServiceRunning, AppliedGeneration: 3, AppliedConfigHash: &hash, BinarySHA256: &binaryHash,
		Listeners: []XrayObservedListener{}, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	pid := 100
	state.ProcessID = &pid
	buildCurrentXrayObservedState = func(now time.Time) XrayObservedState {
		copy := state
		copy.ObservedAt = now.UTC().Format(time.RFC3339Nano)
		return copy
	}
	resetXrayHeartbeatStateForTest()
	start := time.Now().UTC()
	first := xrayStateForHeartbeatAt(start, false)
	if first.Signature == "" || first.State == nil {
		t.Fatalf("first heartbeat omitted full state: %#v", first)
	}
	commitXrayHeartbeatState(first, start)
	unchanged := xrayStateForHeartbeatAt(start.Add(time.Minute), false)
	if unchanged.Signature != first.Signature || unchanged.State != nil {
		t.Fatalf("unchanged heartbeat sent full state: %#v", unchanged)
	}
	requestXrayStateUpload()
	requested := xrayStateForHeartbeatAt(start.Add(2*time.Minute), false)
	if requested.State == nil {
		t.Fatal("explicit request did not send full Xray state")
	}
	commitXrayHeartbeatState(requested, start.Add(2*time.Minute))
	audit := xrayStateForHeartbeatAt(start.Add(xrayStateAuditInterval+3*time.Minute), false)
	if audit.State == nil {
		t.Fatal("periodic audit did not send full Xray state")
	}
	state.ServiceStatus = XrayServiceError
	changed := xrayStateForHeartbeatAt(start.Add(3*time.Minute), false)
	if changed.State == nil || changed.Signature == first.Signature {
		t.Fatalf("changed state was not uploaded: %#v", changed)
	}
}

func TestXrayObservedHeartbeatRetriesFullStateAfterPostFailure(t *testing.T) {
	previousBuilder := buildCurrentXrayObservedState
	t.Cleanup(func() { buildCurrentXrayObservedState = previousBuilder })
	buildCurrentXrayObservedState = func(now time.Time) XrayObservedState {
		return XrayObservedState{
			SchemaVersion: XraySchemaVersion, ServiceStatus: XrayServiceStopped,
			AppliedGeneration: 0, Listeners: []XrayObservedListener{}, ObservedAt: now.UTC().Format(time.RFC3339Nano),
		}
	}
	resetXrayHeartbeatStateForTest()
	now := time.Now().UTC()
	first := xrayStateForHeartbeatAt(now, false)
	if first.State == nil {
		t.Fatal("first full state missing")
	}
	// No commit models a failed heartbeat POST.
	retry := xrayStateForHeartbeatAt(now.Add(time.Second), false)
	if retry.State == nil || retry.Signature != first.Signature {
		t.Fatalf("failed full upload was not retried: first=%#v retry=%#v", first, retry)
	}
}

func TestXrayObservedHeartbeatPayloadUsesProtocolKeys(t *testing.T) {
	previousBuilder := buildCurrentXrayObservedState
	t.Cleanup(func() {
		buildCurrentXrayObservedState = previousBuilder
		resetXrayHeartbeatStateForTest()
	})
	buildCurrentXrayObservedState = func(now time.Time) XrayObservedState {
		return XrayObservedState{
			SchemaVersion: XraySchemaVersion, ServiceStatus: XrayServiceStopped,
			Listeners: []XrayObservedListener{}, ObservedAt: now.UTC().Format(time.RFC3339Nano),
		}
	}
	resetXrayHeartbeatStateForTest()
	now := time.Now().UTC()
	payload := map[string]any{}
	report := appendXrayHeartbeatState(payload, now)
	if payload["xrayStateSignature"] != report.Signature || payload["xrayState"] == nil {
		t.Fatalf("initial Xray heartbeat payload = %#v", payload)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeXrayObservedReport(raw)
	if err != nil || decoded.XrayState == nil {
		t.Fatalf("heartbeat payload does not satisfy the protocol: %#v, %v", decoded, err)
	}
	commitXrayHeartbeatState(report, now)
	compactPayload := map[string]any{}
	compactReport := appendXrayHeartbeatState(compactPayload, now.Add(time.Minute))
	if compactPayload["xrayStateSignature"] != compactReport.Signature {
		t.Fatalf("compact Xray signature missing: %#v", compactPayload)
	}
	if _, present := compactPayload["xrayState"]; present {
		t.Fatalf("unchanged heartbeat included full Xray state: %#v", compactPayload)
	}
}

func TestXrayRecoveryValidatesLocalStateBeforeStartingWithoutPanel(t *testing.T) {
	fixture := newXrayRuntimeFixture(t)
	_, oldBinary := fixture.installPreviousRuntime(t)
	fixture.supervisor.status = xraySupervisorStatus{ServiceStatus: XrayServiceStopped}
	events := []string{}
	fixture.runtime.testConfig = func(context.Context, string, string) error {
		events = append(events, "config-test")
		return nil
	}
	fixture.supervisor.starts = nil
	status, err := fixture.runtime.RecoverLocal(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status == nil || status.ServiceStatus != XrayServiceRunning || status.BinaryPath != oldBinary {
		t.Fatalf("unexpected recovered status: %#v", status)
	}
	if len(events) != 1 || len(fixture.supervisor.starts) != 1 || fixture.supervisor.starts[0].BinaryPath != oldBinary {
		t.Fatalf("recovery order/start = events=%v starts=%#v", events, fixture.supervisor.starts)
	}
	if fixture.readinessRuns == 0 {
		t.Fatal("recovery did not verify last-good listeners")
	}
}

func TestXrayRecoveryRejectsTamperedConfigBeforeStarting(t *testing.T) {
	fixture := newXrayRuntimeFixture(t)
	fixture.installPreviousRuntime(t)
	fixture.supervisor.status = xraySupervisorStatus{ServiceStatus: XrayServiceStopped}
	fixture.supervisor.starts = nil
	if err := os.WriteFile(filepath.Join(fixture.configRoot, "config.json"), []byte(`{"tampered":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.runtime.RecoverLocal(context.Background()); !errors.Is(err, errXrayConfigHashMismatch) {
		t.Fatalf("tampered recovery error = %v", err)
	}
	if len(fixture.supervisor.starts) != 0 {
		t.Fatal("tampered runtime was started before panel authentication")
	}
}
