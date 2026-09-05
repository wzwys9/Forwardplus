package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeXrayManagedProcess struct {
	pid          int
	wait         chan error
	exitOnce     sync.Once
	mu           sync.Mutex
	signals      []os.Signal
	killCount    int
	exitOnSignal bool
}

func newFakeXrayManagedProcess(pid int) *fakeXrayManagedProcess {
	return &fakeXrayManagedProcess{pid: pid, wait: make(chan error, 1), exitOnSignal: true}
}

func (process *fakeXrayManagedProcess) PID() int { return process.pid }

func (process *fakeXrayManagedProcess) Wait() error { return <-process.wait }

func (process *fakeXrayManagedProcess) Signal(signal os.Signal) error {
	process.mu.Lock()
	process.signals = append(process.signals, signal)
	exitOnSignal := process.exitOnSignal
	process.mu.Unlock()
	if exitOnSignal {
		process.Exit(nil)
	}
	return nil
}

func (process *fakeXrayManagedProcess) Kill() error {
	process.mu.Lock()
	process.killCount++
	process.mu.Unlock()
	process.Exit(errors.New("killed"))
	return nil
}

func (process *fakeXrayManagedProcess) Exit(err error) {
	process.exitOnce.Do(func() { process.wait <- err })
}

func (process *fakeXrayManagedProcess) signalCount() int {
	process.mu.Lock()
	defer process.mu.Unlock()
	return len(process.signals)
}

type xraySupervisorFixture struct {
	supervisor *xraySupervisor
	spec       xrayLaunchSpec
	identities map[int]xrayProcessIdentity
	processes  []*fakeXrayManagedProcess
	launches   []xrayProcessLaunch
	mu         sync.Mutex
}

func newXraySupervisorFixture(t *testing.T) *xraySupervisorFixture {
	t.Helper()
	root := filepath.Join(t.TempDir(), "managed-xray")
	configRoot := filepath.Join(t.TempDir(), "etc-xray")
	binaryPath := filepath.Join(root, "versions", XrayManagedVersion, runtime.GOOS+"-"+runtime.GOARCH, "xray")
	configPath := filepath.Join(configRoot, "config.json")
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(configRoot, 0700); err != nil {
		t.Fatal(err)
	}
	binary := []byte("verified-test-binary")
	if err := os.WriteFile(binaryPath, binary, 0700); err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"inbounds":[],"outbounds":[]}`)
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(config)
	binaryHash := sha256.Sum256(binary)
	fixture := &xraySupervisorFixture{
		identities: make(map[int]xrayProcessIdentity),
		spec: xrayLaunchSpec{
			BinaryPath:   binaryPath,
			BinarySHA256: hex.EncodeToString(binaryHash[:]),
			ConfigPath:   configPath,
			Version:      XrayManagedVersion,
			Generation:   7,
			ConfigHash:   hex.EncodeToString(hash[:]),
		},
	}
	fixture.supervisor = newXraySupervisor(root, configRoot)
	fixture.supervisor.launch = func(launch xrayProcessLaunch) (xrayManagedProcess, error) {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		pid := 4100 + len(fixture.processes)
		process := newFakeXrayManagedProcess(pid)
		fixture.processes = append(fixture.processes, process)
		fixture.launches = append(fixture.launches, launch)
		fixture.identities[pid] = xrayProcessIdentity{PID: pid, StartTime: "start-" + time.Unix(int64(pid), 0).UTC().Format(time.RFC3339), Executable: launch.BinaryPath}
		return process, nil
	}
	fixture.supervisor.inspect = func(pid int, binaryPath string) (xrayProcessIdentity, error) {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		identity, ok := fixture.identities[pid]
		if !ok || identity.Executable != binaryPath {
			return xrayProcessIdentity{}, errXrayProcessIdentityMismatch
		}
		return identity, nil
	}
	fixture.supervisor.waitDelay = func(time.Duration) bool { return true }
	fixture.supervisor.stopTimeout = 100 * time.Millisecond
	return fixture
}

func (fixture *xraySupervisorFixture) launchCount() int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return len(fixture.launches)
}

func (fixture *xraySupervisorFixture) process(index int) *fakeXrayManagedProcess {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.processes[index]
}

func waitForXraySupervisor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for Xray supervisor state")
}

func TestXrayManagedSupervisorStartsOnlyFixedManagedPathsAndIsIdempotent(t *testing.T) {
	fixture := newXraySupervisorFixture(t)
	started, err := fixture.supervisor.Start(fixture.spec)
	if err != nil {
		t.Fatal(err)
	}
	if started.Reused || started.ServiceStatus != XrayServiceRunning || started.PID <= 0 {
		t.Fatalf("unexpected start result: %#v", started)
	}
	reused, err := fixture.supervisor.Start(fixture.spec)
	if err != nil {
		t.Fatal(err)
	}
	if !reused.Reused || fixture.launchCount() != 1 {
		t.Fatalf("same spec was not reused: result=%#v launches=%d", reused, fixture.launchCount())
	}

	fixture.mu.Lock()
	launch := fixture.launches[0]
	fixture.mu.Unlock()
	if launch.BinaryPath != fixture.spec.BinaryPath || launch.Directory != filepath.Dir(fixture.spec.ConfigPath) {
		t.Fatalf("unexpected fixed launch paths: %#v", launch)
	}
	if len(launch.Args) != 3 || launch.Args[0] != "run" || launch.Args[1] != "-config" || launch.Args[2] != fixture.spec.ConfigPath {
		t.Fatalf("unexpected Xray arguments: %#v", launch.Args)
	}
	if !slices.Equal(launch.Environment, []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}) {
		t.Fatalf("Xray inherited an unexpected environment: %#v", launch.Environment)
	}

	unsafe := fixture.spec
	unsafe.BinaryPath = "/usr/local/bin/xray"
	if _, err := fixture.supervisor.Restart(unsafe); !errors.Is(err, errXrayUnmanagedPath) {
		t.Fatalf("unmanaged binary error = %v", err)
	}
	if fixture.process(0).signalCount() != 0 || fixture.launchCount() != 1 {
		t.Fatal("invalid restart touched the running managed process")
	}
}

func TestXrayManagedSupervisorControlPlaneCancellationDoesNotStop(t *testing.T) {
	fixture := newXraySupervisorFixture(t)
	if _, err := fixture.supervisor.Start(fixture.spec); err != nil {
		t.Fatal(err)
	}
	controlPlaneDone := make(chan struct{})
	close(controlPlaneDone)
	select {
	case <-controlPlaneDone:
	case <-time.After(time.Second):
		t.Fatal("control-plane cancellation did not fire")
	}
	time.Sleep(20 * time.Millisecond)
	status := fixture.supervisor.Status()
	if status.ServiceStatus != XrayServiceRunning || fixture.process(0).signalCount() != 0 {
		t.Fatalf("control-plane cancellation affected Xray: %#v", status)
	}
}

func TestXrayManagedSupervisorInvalidTokenDoesNotStop(t *testing.T) {
	fixture := newXraySupervisorFixture(t)
	if _, err := fixture.supervisor.Start(fixture.spec); err != nil {
		t.Fatal(err)
	}
	panel := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusUnauthorized)
		_, _ = response.Write([]byte(`{"error":"invalid agent token"}`))
	}))
	defer panel.Close()

	var response map[string]any
	err := postWithClientToPanelURL(
		panel.Client(), Config{PanelURL: panel.URL, Token: "invalid-token"}, panel.URL,
		"/api/agent/heartbeat", map[string]any{"xrayStateSignature": strings.Repeat("a", 64)}, &response,
	)
	var statusError agentHTTPStatusError
	if !errors.As(err, &statusError) || statusError.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid token request error = %v", err)
	}
	status := fixture.supervisor.Status()
	if status.ServiceStatus != XrayServiceRunning || fixture.process(0).signalCount() != 0 {
		t.Fatalf("invalid token affected managed Xray: %#v", status)
	}
	if err := fixture.supervisor.Stop(); err != nil {
		t.Fatal(err)
	}
	// Stop waits for process exit; the watcher persists STOPPED afterward.
	// Status takes the same mutex, so this also waits for that final write before
	// t.TempDir cleanup removes the managed state directory.
	waitForXraySupervisor(t, func() bool {
		return fixture.supervisor.Status().ServiceStatus == XrayServiceStopped
	})
}

func TestXrayManagedSupervisorRefusesToSignalIdentityMismatch(t *testing.T) {
	fixture := newXraySupervisorFixture(t)
	if _, err := fixture.supervisor.Start(fixture.spec); err != nil {
		t.Fatal(err)
	}
	process := fixture.process(0)
	fixture.mu.Lock()
	fixture.identities[process.pid] = xrayProcessIdentity{PID: process.pid, StartTime: "reused-pid", Executable: "/usr/bin/unrelated"}
	fixture.mu.Unlock()
	if err := fixture.supervisor.Stop(); !errors.Is(err, errXrayProcessIdentityMismatch) {
		t.Fatalf("stop identity error = %v", err)
	}
	if process.signalCount() != 0 {
		t.Fatal("identity-mismatched PID was signaled")
	}
}

func TestXrayManagedSupervisorRestartWaitsForOldProcess(t *testing.T) {
	fixture := newXraySupervisorFixture(t)
	if _, err := fixture.supervisor.Start(fixture.spec); err != nil {
		t.Fatal(err)
	}
	next := fixture.spec
	next.Generation++
	if _, err := fixture.supervisor.Restart(next); err != nil {
		t.Fatal(err)
	}
	if fixture.launchCount() != 2 || fixture.process(0).signalCount() != 1 {
		t.Fatalf("restart did not stop then start: launches=%d signals=%d", fixture.launchCount(), fixture.process(0).signalCount())
	}
	status := fixture.supervisor.Status()
	if status.Generation != next.Generation || status.PID != fixture.process(1).pid || status.ServiceStatus != XrayServiceRunning {
		t.Fatalf("unexpected restarted status: %#v", status)
	}
}

func TestXrayManagedSupervisorWatchdogUsesBoundedRestarts(t *testing.T) {
	fixture := newXraySupervisorFixture(t)
	fixture.supervisor.maxRestarts = 2
	if _, err := fixture.supervisor.Start(fixture.spec); err != nil {
		t.Fatal(err)
	}
	fixture.process(0).Exit(errors.New("unexpected exit 1"))
	waitForXraySupervisor(t, func() bool { return fixture.launchCount() == 2 })
	fixture.process(1).Exit(errors.New("unexpected exit 2"))
	waitForXraySupervisor(t, func() bool { return fixture.launchCount() == 3 })
	fixture.process(2).Exit(errors.New("unexpected exit 3"))
	waitForXraySupervisor(t, func() bool { return fixture.supervisor.Status().ServiceStatus == XrayServiceError })
	time.Sleep(20 * time.Millisecond)
	if fixture.launchCount() != 3 {
		t.Fatalf("watchdog exceeded restart bound: %d launches", fixture.launchCount())
	}
	status := fixture.supervisor.Status()
	if status.RestartAttempts != 2 || status.ErrorCode != XrayErrorRuntimeStartFailed {
		t.Fatalf("unexpected exhausted watchdog status: %#v", status)
	}
	if err := fixture.supervisor.Stop(); err != nil {
		t.Fatalf("stop exhausted watchdog: %v", err)
	}
}

func TestXrayManagedSupervisorWatchdogRejectsRuntimeDrift(t *testing.T) {
	fixture := newXraySupervisorFixture(t)
	fixture.supervisor.maxRestarts = 2
	if _, err := fixture.supervisor.Start(fixture.spec); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.spec.ConfigPath, []byte(`{"drifted":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	fixture.process(0).Exit(errors.New("unexpected exit after drift"))
	waitForXraySupervisor(t, func() bool {
		return fixture.supervisor.Status().RestartAttempts == fixture.supervisor.maxRestarts
	})
	if fixture.launchCount() != 1 {
		t.Fatalf("watchdog launched drifted runtime: %d launches", fixture.launchCount())
	}
	if status := fixture.supervisor.Status(); status.ServiceStatus != XrayServiceError || status.ErrorCode != XrayErrorRuntimeStartFailed {
		t.Fatalf("unexpected drift status: %#v", status)
	}
	// Synchronize with the restart loop before TempDir cleanup. Seeing the
	// attempt counter alone does not mean its final state write has returned.
	if err := fixture.supervisor.Stop(); err != nil {
		t.Fatalf("stop drifted watchdog: %v", err)
	}
}

func TestXrayManagedSupervisorRecoveryAdoptsOrStartsWithoutPanel(t *testing.T) {
	fixture := newXraySupervisorFixture(t)
	identity := xrayProcessIdentity{PID: 8123, StartTime: "stable-start", Executable: fixture.spec.BinaryPath}
	if err := persistXraySupervisorRecordAt(fixture.supervisor.root, xraySupervisorRecord{
		Version: 1, DesiredRunning: true, Spec: fixture.spec, Process: &identity,
	}); err != nil {
		t.Fatal(err)
	}
	adopted := newFakeXrayManagedProcess(identity.PID)
	fixture.mu.Lock()
	fixture.identities[identity.PID] = identity
	fixture.mu.Unlock()
	fixture.supervisor.adopt = func(actual xrayProcessIdentity) (xrayManagedProcess, error) {
		if actual != identity {
			t.Fatalf("adopt identity = %#v, want %#v", actual, identity)
		}
		return adopted, nil
	}
	result, err := fixture.supervisor.Recover()
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || !result.Reused || result.PID != identity.PID || fixture.launchCount() != 0 {
		t.Fatalf("existing managed process was not adopted: result=%#v launches=%d", result, fixture.launchCount())
	}

	second := newXraySupervisor(fixture.supervisor.root, fixture.supervisor.configRoot)
	second.launch = fixture.supervisor.launch
	second.inspect = func(pid int, binaryPath string) (xrayProcessIdentity, error) {
		if pid == identity.PID {
			return xrayProcessIdentity{}, os.ErrNotExist
		}
		return fixture.supervisor.inspect(pid, binaryPath)
	}
	second.waitDelay = func(time.Duration) bool { return true }
	result, err = second.Recover()
	if err != nil {
		t.Fatal(err)
	}
	if result == nil || result.Reused || fixture.launchCount() != 1 {
		t.Fatalf("missing managed process was not recovered locally: result=%#v launches=%d", result, fixture.launchCount())
	}
	if mode := mustFileMode(t, filepath.Join(fixture.supervisor.root, xraySupervisorStateFile)).Perm(); mode != 0600 {
		t.Fatalf("supervisor record mode = %o, want 0600", mode)
	}
}

func TestXrayManagedSupervisorRejectsConfigHashDrift(t *testing.T) {
	fixture := newXraySupervisorFixture(t)
	if err := os.WriteFile(fixture.spec.ConfigPath, []byte(`{"tampered":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.supervisor.Start(fixture.spec); !errors.Is(err, errXrayConfigHashMismatch) {
		t.Fatalf("config drift error = %v", err)
	}
	if fixture.launchCount() != 0 {
		t.Fatal("hash-drifted config was launched")
	}
}

func TestXrayManagedSupervisorCanRestoreVerifiedPreviousVersion(t *testing.T) {
	fixture := newXraySupervisorFixture(t)
	previous := fixture.spec
	previous.Version = "v26.7.27"
	previous.BinaryPath = filepath.Join(fixture.supervisor.root, "versions", previous.Version, runtime.GOOS+"-"+runtime.GOARCH, "xray")
	if err := os.MkdirAll(filepath.Dir(previous.BinaryPath), 0700); err != nil {
		t.Fatal(err)
	}
	binary := []byte("verified-previous-binary")
	if err := os.WriteFile(previous.BinaryPath, binary, 0700); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(binary)
	previous.BinarySHA256 = hex.EncodeToString(hash[:])
	if _, err := fixture.supervisor.Start(previous); err != nil {
		t.Fatalf("verified previous managed version could not be restored: %v", err)
	}
	if fixture.launchCount() != 1 {
		t.Fatalf("previous version launch count = %d", fixture.launchCount())
	}
}

func TestXrayManagedSupervisorRecoveryWithoutStateIsNoop(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing-managed-root")
	supervisor := newXraySupervisor(root, filepath.Join(t.TempDir(), "etc-xray"))
	result, err := supervisor.Recover()
	if err != nil || result != nil {
		t.Fatalf("empty recovery = (%#v, %v), want (nil, nil)", result, err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("empty recovery created managed root: %v", err)
	}
}

func TestXrayManagedSupervisorRejectsSymlinkedManagedRoot(t *testing.T) {
	fixture := newXraySupervisorFixture(t)
	realRoot := fixture.supervisor.root
	linkRoot := filepath.Join(t.TempDir(), "xray-root-link")
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Fatal(err)
	}
	supervisor := newXraySupervisor(linkRoot, fixture.supervisor.configRoot)
	supervisor.launch = fixture.supervisor.launch
	unsafe := fixture.spec
	unsafe.BinaryPath = filepath.Join(linkRoot, "versions", unsafe.Version, runtime.GOOS+"-"+runtime.GOARCH, "xray")
	if _, err := supervisor.Start(unsafe); !errors.Is(err, errXrayUnmanagedPath) {
		t.Fatalf("symlinked root error = %v", err)
	}
	if fixture.launchCount() != 0 {
		t.Fatal("symlinked managed root was launched")
	}
}

func TestXrayManagedSupervisorProcessIdentityChecksExecutableAndStartTime(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("managed Xray process identity uses Linux procfs")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := inspectManagedXrayProcess(os.Getpid(), executable)
	if err != nil {
		t.Fatal(err)
	}
	if identity.PID != os.Getpid() || identity.StartTime == "" || filepath.Clean(identity.Executable) != filepath.Clean(executable) {
		t.Fatalf("unexpected current process identity: %#v", identity)
	}
	wrongExecutable := filepath.Join(t.TempDir(), "unrelated")
	if err := os.WriteFile(wrongExecutable, []byte("not this process"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectManagedXrayProcess(os.Getpid(), wrongExecutable); !errors.Is(err, errXrayProcessIdentityMismatch) {
		t.Fatalf("wrong executable identity error = %v", err)
	}
}
