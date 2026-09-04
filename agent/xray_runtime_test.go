package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeXrayRuntimeSupervisor struct {
	mu          sync.Mutex
	status      xraySupervisorStatus
	starts      []xrayLaunchSpec
	restarts    []xrayLaunchSpec
	stopCount   int
	startErrors []error
}

func (supervisor *fakeXrayRuntimeSupervisor) Start(spec xrayLaunchSpec) (xraySupervisorStatus, error) {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	supervisor.starts = append(supervisor.starts, spec)
	return supervisor.started(spec)
}

func (supervisor *fakeXrayRuntimeSupervisor) Restart(spec xrayLaunchSpec) (xraySupervisorStatus, error) {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	supervisor.restarts = append(supervisor.restarts, spec)
	return supervisor.started(spec)
}

func (supervisor *fakeXrayRuntimeSupervisor) started(spec xrayLaunchSpec) (xraySupervisorStatus, error) {
	if len(supervisor.startErrors) > 0 {
		err := supervisor.startErrors[0]
		supervisor.startErrors = supervisor.startErrors[1:]
		if err != nil {
			return xraySupervisorStatus{}, err
		}
	}
	supervisor.status = xraySupervisorStatus{
		ServiceStatus: XrayServiceRunning, PID: 4242, Version: spec.Version, Generation: spec.Generation,
		ConfigHash: spec.ConfigHash, BinaryPath: spec.BinaryPath,
	}
	return supervisor.status, nil
}

func (supervisor *fakeXrayRuntimeSupervisor) Stop() error {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	supervisor.stopCount++
	supervisor.status = xraySupervisorStatus{ServiceStatus: XrayServiceStopped}
	return nil
}

func (supervisor *fakeXrayRuntimeSupervisor) Status() xraySupervisorStatus {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	return supervisor.status
}

func (supervisor *fakeXrayRuntimeSupervisor) Recover() (*xraySupervisorStatus, error) {
	status := supervisor.Status()
	return &status, nil
}

type xrayRuntimeFixture struct {
	runtime       *xrayRuntime
	supervisor    *fakeXrayRuntimeSupervisor
	desired       XrayDesiredState
	binaryPath    string
	binarySHA256  string
	configRoot    string
	managedRoot   string
	configTests   int
	readinessRuns int
}

func newXrayRuntimeFixture(t *testing.T) *xrayRuntimeFixture {
	t.Helper()
	managedRoot := filepath.Join(t.TempDir(), "managed-xray")
	configRoot := filepath.Join(t.TempDir(), "etc-xray")
	binaryPath := filepath.Join(managedRoot, "versions", XrayManagedVersion, "linux-"+runtime.GOARCH, "xray")
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0700); err != nil {
		t.Fatal(err)
	}
	binary := []byte("verified-runtime-binary")
	if err := os.WriteFile(binaryPath, binary, 0700); err != nil {
		t.Fatal(err)
	}
	binaryHash := sha256.Sum256(binary)
	config := `{"log":{"loglevel":"warning"},"inbounds":[],"outbounds":[]}`
	configHash := sha256.Sum256([]byte(config))
	desired := XrayDesiredState{
		SchemaVersion: XraySchemaVersion, Generation: 7, IssuedAt: time.Now().UTC().Format(time.RFC3339Nano),
		TargetVersion: XrayManagedVersion, ConfigHash: hex.EncodeToString(configHash[:]), ConfigEncoding: "JSON_UTF8", ConfigJSON: config,
		ExpectedListeners: []XrayExpectedListener{{
			InboundID: 1, RuntimeTag: "forwardx-inbound-runtime-test", Network: "tcp", ListenAddress: "0.0.0.0", Port: 23456,
		}},
	}
	supervisor := &fakeXrayRuntimeSupervisor{status: xraySupervisorStatus{ServiceStatus: XrayServiceStopped}}
	fixture := &xrayRuntimeFixture{
		supervisor: supervisor, desired: desired, binaryPath: binaryPath,
		binarySHA256: hex.EncodeToString(binaryHash[:]), configRoot: configRoot, managedRoot: managedRoot,
	}
	fixture.runtime = newXrayRuntime(managedRoot, configRoot, supervisor)
	fixture.runtime.resolveBinary = func(string) (string, string, error) {
		return fixture.binaryPath, fixture.binarySHA256, nil
	}
	fixture.runtime.testConfig = func(_ context.Context, binary, config string) error {
		fixture.configTests++
		if binary != fixture.binaryPath || !strings.Contains(config, filepath.Join("pending", "7-"+fixture.desired.ConfigHash+".json")) {
			t.Fatalf("unexpected config test paths: binary=%s config=%s", binary, config)
		}
		return nil
	}
	fixture.runtime.probeListeners = func(_ int, expected []XrayExpectedListener) ([]XrayObservedListener, error) {
		fixture.readinessRuns++
		observed := make([]XrayObservedListener, len(expected))
		for index, listener := range expected {
			observed[index] = XrayObservedListener{RuntimeTag: listener.RuntimeTag, Network: listener.Network, Port: listener.Port, Status: XrayListenerReady}
		}
		return observed, nil
	}
	fixture.runtime.waitDelay = func(time.Duration) bool { return true }
	fixture.runtime.readinessAttempts = 3
	return fixture
}

func TestXrayHeartbeatInvalidTokenDoesNotStopManagedRuntime(t *testing.T) {
	fixture := newXrayRuntimeFixture(t)
	if result, err := fixture.runtime.Apply(context.Background(), fixture.desired); err != nil || !result.Applied || fixture.supervisor.Status().ServiceStatus != XrayServiceRunning {
		t.Fatalf("failed to seed managed runtime: result=%#v err=%v", result, err)
	}
	previousRuntime := managedXrayRuntimeManager
	managedXrayRuntimeManager = fixture.runtime
	defer func() { managedXrayRuntimeManager = previousRuntime }()

	panel := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusUnauthorized)
		_, _ = response.Write([]byte(`{"error":"invalid agent token"}`))
	}))
	defer panel.Close()

	_, err := heartbeatKeepalive(Config{PanelURL: panel.URL, Token: "invalid-token", Interval: 60})
	var statusError agentHTTPStatusError
	if !errors.As(err, &statusError) || statusError.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid token heartbeat error = %v", err)
	}
	status := fixture.supervisor.Status()
	if status.ServiceStatus != XrayServiceRunning || fixture.supervisor.stopCount != 0 {
		t.Fatalf("invalid token heartbeat affected managed Xray: status=%#v stops=%d", status, fixture.supervisor.stopCount)
	}
}

func (fixture *xrayRuntimeFixture) installPreviousRuntime(t *testing.T) (oldConfig, oldBinary string) {
	t.Helper()
	oldConfig = `{"log":{"loglevel":"error"},"inbounds":[],"outbounds":[]}`
	oldHash := sha256.Sum256([]byte(oldConfig))
	oldHashText := hex.EncodeToString(oldHash[:])
	oldVersion := "v26.3.26"
	oldBinary = filepath.Join(fixture.managedRoot, "versions", oldVersion, "linux-"+runtime.GOARCH, "xray")
	if err := os.MkdirAll(filepath.Dir(oldBinary), 0700); err != nil {
		t.Fatal(err)
	}
	oldBinaryBytes := []byte("previous-runtime-binary")
	if err := os.WriteFile(oldBinary, oldBinaryBytes, 0700); err != nil {
		t.Fatal(err)
	}
	oldBinaryHash := sha256.Sum256(oldBinaryBytes)
	if err := writeAtomicXrayFile(filepath.Join(fixture.configRoot, "config.json"), []byte(oldConfig), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicXrayFile(filepath.Join(fixture.configRoot, "config.json.sha256"), []byte(oldHashText+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := switchCurrentXrayBinary(fixture.managedRoot, oldBinary); err != nil {
		t.Fatal(err)
	}
	state := xrayRuntimeState{
		Version: xrayRuntimeStateVersion, DesiredRunning: true, AppliedGeneration: 6, AppliedConfigHash: oldHashText,
		CurrentVersion: oldVersion, CurrentBinarySHA256: hex.EncodeToString(oldBinaryHash[:]), ExpectedListeners: fixture.desired.ExpectedListeners,
	}
	if err := writeXrayRuntimeStateAt(fixture.managedRoot, state); err != nil {
		t.Fatal(err)
	}
	fixture.supervisor.status = xraySupervisorStatus{
		ServiceStatus: XrayServiceRunning, PID: 3131, Version: oldVersion, Generation: state.AppliedGeneration,
		ConfigHash: oldHashText, BinaryPath: oldBinary,
	}
	return oldConfig, oldBinary
}

func TestXrayConfigHashOrConfigTestFailureDoesNotTouchCurrent(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		mutate func(*xrayRuntimeFixture)
	}{
		{name: "hash mismatch", mutate: func(fixture *xrayRuntimeFixture) { fixture.desired.ConfigHash = strings.Repeat("f", 64) }},
		{name: "config test", mutate: func(fixture *xrayRuntimeFixture) {
			fixture.runtime.testConfig = func(context.Context, string, string) error { return errors.New("secret command output") }
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newXrayRuntimeFixture(t)
			oldConfig, oldBinary := fixture.installPreviousRuntime(t)
			testCase.mutate(fixture)
			result, err := fixture.runtime.Apply(context.Background(), fixture.desired)
			if err == nil || result.ErrorCode != XrayErrorConfigInvalid || strings.Contains(err.Error(), "secret command output") {
				t.Fatalf("unexpected apply failure: result=%#v err=%v", result, err)
			}
			currentConfig, readErr := os.ReadFile(filepath.Join(fixture.configRoot, "config.json"))
			if readErr != nil || string(currentConfig) != oldConfig {
				t.Fatalf("current config changed: %q err=%v", currentConfig, readErr)
			}
			currentBinary, readErr := readCurrentXrayBinary(fixture.managedRoot)
			if readErr != nil || currentBinary != oldBinary {
				t.Fatalf("current binary changed: %q err=%v", currentBinary, readErr)
			}
			if len(fixture.supervisor.restarts) != 0 {
				t.Fatal("supervisor restarted for an invalid config")
			}
		})
	}
}

func TestXrayApplyCommitsStateOnlyAfterEveryListenerIsReady(t *testing.T) {
	fixture := newXrayRuntimeFixture(t)
	fixture.runtime.probeListeners = func(_ int, expected []XrayExpectedListener) ([]XrayObservedListener, error) {
		fixture.readinessRuns++
		if _, err := os.Lstat(filepath.Join(fixture.managedRoot, xrayRuntimeStateFile)); !os.IsNotExist(err) {
			t.Fatalf("state committed before readiness: %v", err)
		}
		status := XrayListenerMissing
		if fixture.readinessRuns == 2 {
			status = XrayListenerReady
		}
		return []XrayObservedListener{{
			RuntimeTag: expected[0].RuntimeTag, Network: "tcp", Port: expected[0].Port, Status: status,
		}}, nil
	}
	result, err := fixture.runtime.Apply(context.Background(), fixture.desired)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Applied || result.RolledBack || fixture.readinessRuns != 2 || len(fixture.supervisor.starts) != 1 {
		t.Fatalf("unexpected apply result: %#v readiness=%d starts=%d", result, fixture.readinessRuns, len(fixture.supervisor.starts))
	}
	state, err := readXrayRuntimeStateAt(fixture.managedRoot)
	if err != nil || state == nil || state.AppliedGeneration != fixture.desired.Generation || state.AppliedConfigHash != fixture.desired.ConfigHash {
		t.Fatalf("committed state = %#v, err=%v", state, err)
	}
	if matches, err := filepath.Glob(filepath.Join(fixture.configRoot, "pending", "*.json")); err != nil || len(matches) != 0 {
		t.Fatalf("pending configs remained: %v err=%v", matches, err)
	}
}

func TestXrayApplyStartFailureRestoresOldConfigAndBinary(t *testing.T) {
	fixture := newXrayRuntimeFixture(t)
	oldConfig, oldBinary := fixture.installPreviousRuntime(t)
	fixture.supervisor.startErrors = []error{errors.New("new runtime failed"), nil}
	result, err := fixture.runtime.Apply(context.Background(), fixture.desired)
	if err == nil || result.ErrorCode != XrayErrorRuntimeStartFailed || !result.RolledBack {
		t.Fatalf("unexpected rollback result: %#v err=%v", result, err)
	}
	config, readErr := os.ReadFile(filepath.Join(fixture.configRoot, "config.json"))
	if readErr != nil || string(config) != oldConfig {
		t.Fatalf("old config not restored: %q err=%v", config, readErr)
	}
	binary, readErr := readCurrentXrayBinary(fixture.managedRoot)
	if readErr != nil || binary != oldBinary {
		t.Fatalf("old binary not restored: %q err=%v", binary, readErr)
	}
	if len(fixture.supervisor.restarts) != 2 || fixture.supervisor.restarts[1].BinaryPath != oldBinary {
		t.Fatalf("old supervisor spec not restored: %#v", fixture.supervisor.restarts)
	}
	state, readErr := readXrayRuntimeStateAt(fixture.managedRoot)
	if readErr != nil || state == nil || state.AppliedGeneration != 6 {
		t.Fatalf("old applied state changed: %#v err=%v", state, readErr)
	}
}

func TestXrayRestartLastGoodValidatesAndRestartsCommittedRuntime(t *testing.T) {
	fixture := newXrayRuntimeFixture(t)
	_, oldBinary := fixture.installPreviousRuntime(t)
	fixture.runtime.testConfig = func(_ context.Context, binary, config string) error {
		if binary != oldBinary || config != filepath.Join(fixture.configRoot, "config.json") {
			t.Fatalf("unexpected restart validation paths: binary=%s config=%s", binary, config)
		}
		return nil
	}

	result, err := fixture.runtime.RestartLastGood(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.PreviousVersion == nil || *result.PreviousVersion != "v26.3.26" || result.RunningVersion == nil ||
		*result.RunningVersion != "v26.3.26" || result.ServiceStatus != XrayServiceRunning || result.ReadyListenerCount != 1 {
		t.Fatalf("restart result = %#v", result)
	}
	if len(fixture.supervisor.restarts) != 1 || fixture.supervisor.restarts[0].BinaryPath != oldBinary {
		t.Fatalf("restart specs = %#v", fixture.supervisor.restarts)
	}
}

func TestXrayRestartLastGoodFailureRestoresSameCommittedRuntime(t *testing.T) {
	fixture := newXrayRuntimeFixture(t)
	_, oldBinary := fixture.installPreviousRuntime(t)
	fixture.runtime.testConfig = func(context.Context, string, string) error { return nil }
	fixture.supervisor.startErrors = []error{errors.New("restart failed"), nil}

	_, err := fixture.runtime.RestartLastGood(context.Background())
	var runtimeError *xrayRuntimeApplyError
	if !errors.As(err, &runtimeError) || runtimeError.code != XrayErrorRuntimeStartFailed {
		t.Fatalf("restart error = %v", err)
	}
	if len(fixture.supervisor.restarts) != 1 || len(fixture.supervisor.starts) != 1 ||
		fixture.supervisor.starts[0].BinaryPath != oldBinary || fixture.supervisor.Status().ServiceStatus != XrayServiceRunning {
		t.Fatalf("committed runtime was not restored: restarts=%#v starts=%#v", fixture.supervisor.restarts, fixture.supervisor.starts)
	}
}

func TestXrayApplyFirstFailureDoesNotFabricateLastGood(t *testing.T) {
	fixture := newXrayRuntimeFixture(t)
	fixture.supervisor.startErrors = []error{errors.New("first start failed")}
	result, err := fixture.runtime.Apply(context.Background(), fixture.desired)
	if err == nil || result.RolledBack {
		t.Fatalf("unexpected first failure: result=%#v err=%v", result, err)
	}
	for _, name := range []string{"config.json", "config.json.sha256", "last-good.json", "last-good.json.sha256"} {
		if _, statErr := os.Lstat(filepath.Join(fixture.configRoot, name)); !os.IsNotExist(statErr) {
			t.Fatalf("first failure left %s: %v", name, statErr)
		}
	}
	if _, statErr := os.Lstat(filepath.Join(fixture.managedRoot, "current")); !os.IsNotExist(statErr) {
		t.Fatalf("first failure fabricated current: %v", statErr)
	}
}

func TestXrayApplyListenerFailureRollsBackOnlyAfterReadinessExhausted(t *testing.T) {
	fixture := newXrayRuntimeFixture(t)
	fixture.desired.ExpectedListeners = append(fixture.desired.ExpectedListeners, XrayExpectedListener{
		InboundID: 2, RuntimeTag: "forwardx-inbound-runtime-test-kcp", Network: "udp", ListenAddress: "0.0.0.0", Port: 23457,
	})
	oldConfig, oldBinary := fixture.installPreviousRuntime(t)
	fixture.runtime.probeListeners = func(_ int, expected []XrayExpectedListener) ([]XrayObservedListener, error) {
		fixture.readinessRuns++
		if len(expected) != 2 || expected[0].Network != "tcp" || expected[1].Network != "udp" {
			t.Fatalf("readiness probe lost mixed listeners: %#v", expected)
		}
		status := XrayListenerMissing
		if fixture.supervisor.Status().Generation == 6 {
			status = XrayListenerReady
		}
		observed := make([]XrayObservedListener, len(expected))
		for index, listener := range expected {
			observed[index] = XrayObservedListener{
				RuntimeTag: listener.RuntimeTag, Network: listener.Network, Port: listener.Port, Status: status,
			}
		}
		return observed, nil
	}
	result, err := fixture.runtime.Apply(context.Background(), fixture.desired)
	if err == nil || result.ErrorCode != XrayErrorRuntimeNotReady || !result.RolledBack {
		t.Fatalf("unexpected readiness rollback: result=%#v err=%v", result, err)
	}
	if fixture.readinessRuns != fixture.runtime.readinessAttempts+1 {
		t.Fatalf("readiness attempts = %d, want %d new + 1 rollback", fixture.readinessRuns, fixture.runtime.readinessAttempts)
	}
	config, _ := os.ReadFile(filepath.Join(fixture.configRoot, "config.json"))
	binary, _ := readCurrentXrayBinary(fixture.managedRoot)
	if string(config) != oldConfig || binary != oldBinary {
		t.Fatalf("readiness rollback did not restore files: config=%q binary=%q", config, binary)
	}
}

func TestXrayApplyReportsRollbackFailure(t *testing.T) {
	fixture := newXrayRuntimeFixture(t)
	fixture.installPreviousRuntime(t)
	fixture.supervisor.startErrors = []error{errors.New("new start failed"), errors.New("old restart failed")}
	result, err := fixture.runtime.Apply(context.Background(), fixture.desired)
	if err == nil || result.ErrorCode != XrayErrorRollbackFailed || result.RolledBack {
		t.Fatalf("unexpected rollback failure: result=%#v err=%v", result, err)
	}
}

func TestXrayApplyStateCommitFailureRestoresOldState(t *testing.T) {
	fixture := newXrayRuntimeFixture(t)
	fixture.installPreviousRuntime(t)
	failedNewState := false
	fixture.runtime.writeState = func(root string, state xrayRuntimeState) error {
		if err := writeXrayRuntimeStateAt(root, state); err != nil {
			return err
		}
		if state.AppliedGeneration == fixture.desired.Generation && !failedNewState {
			failedNewState = true
			return errors.New("directory sync failed after state rename")
		}
		return nil
	}
	result, err := fixture.runtime.Apply(context.Background(), fixture.desired)
	if err == nil || result.ErrorCode != XrayErrorInternal || !result.RolledBack {
		t.Fatalf("unexpected state rollback: result=%#v err=%v", result, err)
	}
	state, readErr := readXrayRuntimeStateAt(fixture.managedRoot)
	if readErr != nil || state == nil || state.AppliedGeneration != 6 {
		t.Fatalf("old state was not restored: %#v err=%v", state, readErr)
	}
}

func TestXrayApplySameGenerationAndHashIsIdempotent(t *testing.T) {
	fixture := newXrayRuntimeFixture(t)
	first, err := fixture.runtime.Apply(context.Background(), fixture.desired)
	if err != nil || !first.Applied {
		t.Fatalf("first apply = %#v, %v", first, err)
	}
	configTests := fixture.configTests
	starts := len(fixture.supervisor.starts)
	second, err := fixture.runtime.Apply(context.Background(), fixture.desired)
	if err != nil || !second.Applied || !second.Reused {
		t.Fatalf("idempotent apply = %#v, %v", second, err)
	}
	if fixture.configTests != configTests || len(fixture.supervisor.starts) != starts || len(fixture.supervisor.restarts) != 0 {
		t.Fatalf("idempotent apply changed runtime: tests=%d starts=%d restarts=%d", fixture.configTests, len(fixture.supervisor.starts), len(fixture.supervisor.restarts))
	}
}

func TestXrayApplySameGenerationDifferentHashIsRejected(t *testing.T) {
	fixture := newXrayRuntimeFixture(t)
	if _, err := fixture.runtime.Apply(context.Background(), fixture.desired); err != nil {
		t.Fatal(err)
	}
	conflict := fixture.desired
	conflict.ConfigJSON = `{"log":{"loglevel":"error"},"inbounds":[],"outbounds":[]}`
	conflict.ConfigHash = hashXrayBytes([]byte(conflict.ConfigJSON))
	result, err := fixture.runtime.Apply(context.Background(), conflict)
	if err == nil || result.ErrorCode != XrayErrorGenerationHashConflict {
		t.Fatalf("generation conflict = %#v, %v", result, err)
	}
}

func TestXrayApplyRejectsAutomaticDowngrade(t *testing.T) {
	fixture := newXrayRuntimeFixture(t)
	fixture.installPreviousRuntime(t)
	state, err := readXrayRuntimeStateAt(fixture.managedRoot)
	if err != nil || state == nil {
		t.Fatalf("read previous state: %#v, %v", state, err)
	}
	newerVersion := "v26.7.29"
	newerBinary := filepath.Join(fixture.managedRoot, "versions", newerVersion, "linux-"+runtime.GOARCH, "xray")
	if err := os.MkdirAll(filepath.Dir(newerBinary), 0700); err != nil {
		t.Fatal(err)
	}
	newerBytes := []byte("newer-runtime-binary")
	if err := os.WriteFile(newerBinary, newerBytes, 0700); err != nil {
		t.Fatal(err)
	}
	newerHash := sha256.Sum256(newerBytes)
	state.CurrentVersion = newerVersion
	state.CurrentBinarySHA256 = hex.EncodeToString(newerHash[:])
	if err := switchCurrentXrayBinary(fixture.managedRoot, newerBinary); err != nil {
		t.Fatal(err)
	}
	if err := writeXrayRuntimeStateAt(fixture.managedRoot, *state); err != nil {
		t.Fatal(err)
	}
	fixture.supervisor.status.Version = newerVersion
	fixture.supervisor.status.BinaryPath = newerBinary

	result, err := fixture.runtime.Apply(context.Background(), fixture.desired)
	if err == nil || result.ErrorCode != XrayErrorVersionMismatch {
		t.Fatalf("downgrade result = %#v, %v", result, err)
	}
	current, readErr := readCurrentXrayBinary(fixture.managedRoot)
	if readErr != nil || current != newerBinary || fixture.configTests != 0 || len(fixture.supervisor.restarts) != 0 {
		t.Fatalf("downgrade changed runtime: current=%q readErr=%v tests=%d restarts=%d", current, readErr, fixture.configTests, len(fixture.supervisor.restarts))
	}
}

func TestXrayRecoverRestoresLastGoodAfterInterruptedApply(t *testing.T) {
	fixture := newXrayRuntimeFixture(t)
	oldConfig, oldBinary := fixture.installPreviousRuntime(t)
	snapshot, err := fixture.runtime.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.saveLastGood(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.beginApplyTransaction(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := switchCurrentXrayBinary(fixture.managedRoot, fixture.binaryPath); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicXrayFile(filepath.Join(fixture.configRoot, "config.json"), []byte(fixture.desired.ConfigJSON), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicXrayFile(filepath.Join(fixture.configRoot, "config.json.sha256"), []byte(fixture.desired.ConfigHash+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fixture.supervisor.status = xraySupervisorStatus{
		ServiceStatus: XrayServiceRunning, PID: 4242, Version: fixture.desired.TargetVersion,
		Generation: fixture.desired.Generation, ConfigHash: fixture.desired.ConfigHash, BinaryPath: fixture.binaryPath,
	}
	fixture.runtime.testConfig = func(_ context.Context, binary, config string) error {
		if binary != oldBinary || config != filepath.Join(fixture.configRoot, "config.json") {
			t.Fatalf("recovery validated wrong files: binary=%q config=%q", binary, config)
		}
		return nil
	}

	status, err := fixture.runtime.RecoverLocal(context.Background())
	if err != nil || status == nil || status.Generation != 6 || status.BinaryPath != oldBinary {
		t.Fatalf("recover status = %#v, %v", status, err)
	}
	config, readErr := os.ReadFile(filepath.Join(fixture.configRoot, "config.json"))
	current, currentErr := readCurrentXrayBinary(fixture.managedRoot)
	if readErr != nil || currentErr != nil || string(config) != oldConfig || current != oldBinary {
		t.Fatalf("last-good not restored: config=%q current=%q readErr=%v currentErr=%v", config, current, readErr, currentErr)
	}
	if _, statErr := os.Lstat(filepath.Join(fixture.managedRoot, xrayRuntimeApplyMarkerFile)); !os.IsNotExist(statErr) {
		t.Fatalf("apply marker remained after recovery: %v", statErr)
	}
}

func TestXrayRecoverFinalizesCommittedApplyWithStaleMarker(t *testing.T) {
	fixture := newXrayRuntimeFixture(t)
	fixture.installPreviousRuntime(t)
	snapshot, err := fixture.runtime.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.saveLastGood(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := fixture.runtime.beginApplyTransaction(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := switchCurrentXrayBinary(fixture.managedRoot, fixture.binaryPath); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicXrayFile(filepath.Join(fixture.configRoot, "config.json"), []byte(fixture.desired.ConfigJSON), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicXrayFile(filepath.Join(fixture.configRoot, "config.json.sha256"), []byte(fixture.desired.ConfigHash+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	committed := xrayRuntimeState{
		Version: xrayRuntimeStateVersion, DesiredRunning: true, AppliedGeneration: fixture.desired.Generation,
		AppliedConfigHash: fixture.desired.ConfigHash, CurrentVersion: fixture.desired.TargetVersion,
		CurrentBinarySHA256: fixture.binarySHA256, ExpectedListeners: fixture.desired.ExpectedListeners,
	}
	if err := writeXrayRuntimeStateAt(fixture.managedRoot, committed); err != nil {
		t.Fatal(err)
	}
	fixture.supervisor.status = xraySupervisorStatus{
		ServiceStatus: XrayServiceRunning, PID: 4242, Version: committed.CurrentVersion,
		Generation: committed.AppliedGeneration, ConfigHash: committed.AppliedConfigHash, BinaryPath: fixture.binaryPath,
	}
	fixture.runtime.testConfig = func(_ context.Context, binary, config string) error {
		if binary != fixture.binaryPath || config != filepath.Join(fixture.configRoot, "config.json") {
			t.Fatalf("recovery validated wrong committed files: binary=%q config=%q", binary, config)
		}
		return nil
	}

	status, err := fixture.runtime.RecoverLocal(context.Background())
	if err != nil || status == nil || status.Generation != fixture.desired.Generation || status.BinaryPath != fixture.binaryPath {
		t.Fatalf("recover status = %#v, %v", status, err)
	}
	if fixture.supervisor.stopCount != 0 {
		t.Fatalf("committed runtime was stopped %d times", fixture.supervisor.stopCount)
	}
	if _, statErr := os.Lstat(filepath.Join(fixture.managedRoot, xrayRuntimeApplyMarkerFile)); !os.IsNotExist(statErr) {
		t.Fatalf("stale apply marker remained after committed recovery: %v", statErr)
	}
}

func TestXrayApplyListenerProbeRequiresManagedPIDOwnership(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("listener ownership uses Linux procfs")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	expected := []XrayExpectedListener{{
		InboundID: 1, RuntimeTag: "forwardx-inbound-owned", Network: "tcp", ListenAddress: "127.0.0.1", Port: port,
	}}
	owned, err := probeManagedXrayListeners(os.Getpid(), expected)
	if err != nil || len(owned) != 1 || owned[0].Status != XrayListenerReady {
		t.Fatalf("owned listener = %#v, err=%v", owned, err)
	}
	unowned, err := probeManagedXrayListeners(os.Getppid(), expected)
	if err != nil {
		t.Skipf("parent process fds are not inspectable: %v", err)
	}
	if len(unowned) != 1 || unowned[0].Status != XrayListenerWrongProcess {
		t.Fatalf("unowned listener = %#v", unowned)
	}
}

func TestXrayApplyListenerProbeSeparatesTCPAndUDPWithSameRuntimeTag(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("listener ownership uses Linux procfs")
	}
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	port := udp.LocalAddr().(*net.UDPAddr).Port
	expected := []XrayExpectedListener{
		{InboundID: 2, RuntimeTag: "forwardx-inbound-dual-network", Network: "tcp", ListenAddress: "127.0.0.1", Port: port},
		{InboundID: 2, RuntimeTag: "forwardx-inbound-dual-network", Network: "udp", ListenAddress: "127.0.0.1", Port: port},
	}

	udpOnly, err := probeManagedXrayListeners(os.Getpid(), expected)
	if err != nil || len(udpOnly) != 2 || udpOnly[0].Status != XrayListenerMissing || udpOnly[1].Status != XrayListenerReady {
		t.Fatalf("UDP-only listeners = %#v, err=%v", udpOnly, err)
	}
	if allXrayListenersReady(expected, udpOnly) {
		t.Fatal("mixed listener set was ready without TCP")
	}

	tcp, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	both, err := probeManagedXrayListeners(os.Getpid(), expected)
	if err != nil || len(both) != 2 || both[0].Status != XrayListenerReady || both[1].Status != XrayListenerReady {
		t.Fatalf("dual-network listeners = %#v, err=%v", both, err)
	}
	if !allXrayListenersReady(expected, both) {
		t.Fatal("same-tag TCP/UDP listener pair did not converge")
	}
}

func TestXrayApplyListenerProbeAcceptsOwnedDualStackWildcardForIPv4(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("listener ownership uses Linux procfs")
	}
	listener, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		t.Skipf("IPv6 wildcard listener is unavailable: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	connection, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Skipf("IPv6 wildcard is not dual-stack on this host: %v", err)
	}
	_ = connection.Close()
	expected := []XrayExpectedListener{{
		InboundID: 1, RuntimeTag: "forwardx-inbound-dual-stack", Network: "tcp", ListenAddress: "0.0.0.0", Port: port,
	}}
	observed, err := probeManagedXrayListeners(os.Getpid(), expected)
	if err != nil || len(observed) != 1 || observed[0].Status != XrayListenerReady {
		t.Fatalf("dual-stack listener = %#v, err=%v", observed, err)
	}
}

func TestXrayConfigCommandUsesFixedTestModeAndSanitizedEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper uses a Unix executable script")
	}
	directory := t.TempDir()
	outputPath := filepath.Join(directory, "invocation.txt")
	scriptPath := filepath.Join(directory, "xray")
	script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %q\nenv >> %q\n", outputPath, outputPath)
	if err := os.WriteFile(scriptPath, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(directory, "config.json")
	if err := os.WriteFile(configPath, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FORWARDX_TEST_AGENT_TOKEN", "must-not-reach-xray")
	if err := runManagedXrayConfigTest(context.Background(), scriptPath, configPath); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.HasPrefix(text, "run\n-test\n-config\n"+configPath+"\n") {
		t.Fatalf("unexpected config-test invocation: %q", text)
	}
	if strings.Contains(text, "FORWARDX_TEST_AGENT_TOKEN") || strings.Contains(text, "must-not-reach-xray") {
		t.Fatalf("config test inherited Agent environment: %q", text)
	}
}

func TestXrayConfigRealManagedBinary(t *testing.T) {
	binaryPath := strings.TrimSpace(os.Getenv("FORWARDX_XRAY_TEST_BINARY"))
	if binaryPath == "" {
		t.Skip("set FORWARDX_XRAY_TEST_BINARY to the verified v26.3.27 binary")
	}
	raw, err := os.ReadFile(filepath.Join("..", "docs", "xray", "examples", "desired-state.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	desired, err := DecodeXrayDesiredState(raw)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte(desired.ConfigJSON), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runManagedXrayConfigTest(context.Background(), binaryPath, configPath); err != nil {
		t.Fatalf("verified Xray rejected approved example config: %v", err)
	}
}
