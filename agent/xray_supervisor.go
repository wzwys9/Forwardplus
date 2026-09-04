package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	xraySupervisorStateFile       = "supervisor.json"
	xraySupervisorRecordVersion   = 1
	xraySupervisorStateMaxBytes   = 64 * 1024
	xraySupervisorDefaultRestarts = 4
	xraySupervisorStopTimeout     = 10 * time.Second
	xraySupervisorStableWindow    = 5 * time.Minute
	xrayManagedConfigRoot         = "/etc/forwardx/xray"
)

var (
	errXrayUnmanagedPath           = errors.New("Xray path is outside the managed runtime")
	errXrayConfigHashMismatch      = errors.New("Xray config hash does not match")
	errXrayBinaryHashMismatch      = errors.New("Xray binary hash does not match")
	errXrayProcessIdentityMismatch = errors.New("Xray process identity does not match")
	errXrayRuntimeAlreadyRunning   = errors.New("a different managed Xray runtime is already running")
)

type xrayLaunchSpec struct {
	BinaryPath   string `json:"binaryPath"`
	BinarySHA256 string `json:"binarySha256"`
	ConfigPath   string `json:"configPath"`
	Version      string `json:"version"`
	Generation   int64  `json:"generation"`
	ConfigHash   string `json:"configHash"`
}

type xrayProcessIdentity struct {
	PID        int    `json:"pid"`
	StartTime  string `json:"startTime"`
	Executable string `json:"executable"`
}

type xraySupervisorRecord struct {
	Version        int                  `json:"version"`
	DesiredRunning bool                 `json:"desiredRunning"`
	Spec           xrayLaunchSpec       `json:"spec"`
	Process        *xrayProcessIdentity `json:"process"`
}

type xrayProcessLaunch struct {
	BinaryPath  string
	Args        []string
	Directory   string
	Environment []string
	Stdout      io.Writer
	Stderr      io.Writer
}

type xrayManagedProcess interface {
	PID() int
	Wait() error
	Signal(os.Signal) error
	Kill() error
}

type execXrayManagedProcess struct {
	command *exec.Cmd
}

func (process *execXrayManagedProcess) PID() int    { return process.command.Process.Pid }
func (process *execXrayManagedProcess) Wait() error { return process.command.Wait() }
func (process *execXrayManagedProcess) Signal(signal os.Signal) error {
	return process.command.Process.Signal(signal)
}
func (process *execXrayManagedProcess) Kill() error { return process.command.Process.Kill() }

type adoptedXrayManagedProcess struct {
	process  *os.Process
	identity xrayProcessIdentity
	inspect  func(int, string) (xrayProcessIdentity, error)
}

func (process *adoptedXrayManagedProcess) PID() int { return process.identity.PID }

func (process *adoptedXrayManagedProcess) Wait() error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		actual, err := process.inspect(process.identity.PID, process.identity.Executable)
		if err != nil || !sameXrayProcessIdentity(actual, process.identity) {
			return err
		}
	}
	return nil
}

func (process *adoptedXrayManagedProcess) Signal(signal os.Signal) error {
	return process.process.Signal(signal)
}

func (process *adoptedXrayManagedProcess) Kill() error { return process.process.Kill() }

type trackedXrayProcess struct {
	process   xrayManagedProcess
	identity  xrayProcessIdentity
	spec      xrayLaunchSpec
	startedAt time.Time
	done      chan struct{}
	epoch     uint64
}

type xraySupervisorStatus struct {
	ServiceStatus   XrayServiceStatus
	PID             int
	StartedAt       string
	BinaryPath      string
	Version         string
	Generation      int64
	ConfigHash      string
	RestartAttempts int
	ErrorCode       XrayAgentErrorCode
	Reused          bool
}

type xraySupervisor struct {
	transitionMu sync.Mutex
	mu           sync.Mutex

	root         string
	configRoot   string
	platformOS   string
	platformArch string
	launch       func(xrayProcessLaunch) (xrayManagedProcess, error)
	inspect      func(int, string) (xrayProcessIdentity, error)
	adopt        func(xrayProcessIdentity) (xrayManagedProcess, error)
	waitDelay    func(time.Duration) bool
	now          func() time.Time
	stopTimeout  time.Duration
	stableWindow time.Duration
	maxRestarts  int

	current         *trackedXrayProcess
	spec            xrayLaunchSpec
	desiredRunning  bool
	status          XrayServiceStatus
	errorCode       XrayAgentErrorCode
	restartAttempts int
	epoch           uint64
}

func newXraySupervisor(root, configRoot string) *xraySupervisor {
	supervisor := &xraySupervisor{
		root:         filepath.Clean(root),
		configRoot:   filepath.Clean(configRoot),
		platformOS:   runtime.GOOS,
		platformArch: runtime.GOARCH,
		launch:       launchManagedXrayProcess,
		inspect:      inspectManagedXrayProcess,
		now:          time.Now,
		stopTimeout:  xraySupervisorStopTimeout,
		stableWindow: xraySupervisorStableWindow,
		maxRestarts:  xraySupervisorDefaultRestarts,
		status:       XrayServiceStopped,
	}
	supervisor.adopt = func(identity xrayProcessIdentity) (xrayManagedProcess, error) {
		process, err := os.FindProcess(identity.PID)
		if err != nil {
			return nil, err
		}
		return &adoptedXrayManagedProcess{process: process, identity: identity, inspect: supervisor.inspect}, nil
	}
	supervisor.waitDelay = func(delay time.Duration) bool {
		time.Sleep(delay)
		return true
	}
	return supervisor
}

func launchManagedXrayProcess(launch xrayProcessLaunch) (xrayManagedProcess, error) {
	command := exec.Command(launch.BinaryPath, launch.Args...)
	command.Dir = launch.Directory
	command.Env = append([]string(nil), launch.Environment...)
	command.Stdout = launch.Stdout
	command.Stderr = launch.Stderr
	if err := command.Start(); err != nil {
		return nil, err
	}
	return &execXrayManagedProcess{command: command}, nil
}

func managedXrayEnvironment() []string {
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
}

func inspectManagedXrayProcess(pid int, binaryPath string) (xrayProcessIdentity, error) {
	if runtime.GOOS != "linux" || pid <= 0 || strings.TrimSpace(binaryPath) == "" {
		return xrayProcessIdentity{}, errXrayProcessIdentityMismatch
	}
	installed, err := os.Stat(binaryPath)
	if err != nil || installed.IsDir() {
		return xrayProcessIdentity{}, errXrayProcessIdentityMismatch
	}
	running, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil || !os.SameFile(installed, running) {
		return xrayProcessIdentity{}, errXrayProcessIdentityMismatch
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return xrayProcessIdentity{}, errXrayProcessIdentityMismatch
	}
	closing := strings.LastIndexByte(string(raw), ')')
	if closing < 0 {
		return xrayProcessIdentity{}, errXrayProcessIdentityMismatch
	}
	fields := strings.Fields(string(raw[closing+1:]))
	if len(fields) <= 19 || fields[19] == "" {
		return xrayProcessIdentity{}, errXrayProcessIdentityMismatch
	}
	return xrayProcessIdentity{PID: pid, StartTime: fields[19], Executable: filepath.Clean(binaryPath)}, nil
}

func (supervisor *xraySupervisor) validateSpec(spec xrayLaunchSpec) error {
	if supervisor == nil || supervisor.platformOS != "linux" || (supervisor.platformArch != "amd64" && supervisor.platformArch != "arm64") {
		return fmt.Errorf("%w: unsupported platform", errXrayUnmanagedPath)
	}
	if !xrayVersionPattern.MatchString(spec.Version) || spec.Generation < 0 || spec.Generation > XrayMaxSafeInteger ||
		!xraySHA256Pattern.MatchString(spec.BinarySHA256) || !xraySHA256Pattern.MatchString(spec.ConfigHash) {
		return fmt.Errorf("%w: invalid runtime identity", errXrayUnmanagedPath)
	}
	expectedBinary := filepath.Join(supervisor.root, "versions", spec.Version, supervisor.platformOS+"-"+supervisor.platformArch, "xray")
	expectedConfig := filepath.Join(supervisor.configRoot, "config.json")
	if filepath.Clean(spec.BinaryPath) != expectedBinary || filepath.Clean(spec.ConfigPath) != expectedConfig {
		return errXrayUnmanagedPath
	}
	if err := validateManagedXrayFile(supervisor.root, spec.BinaryPath, 0700); err != nil {
		return fmt.Errorf("%w: binary", errXrayUnmanagedPath)
	}
	if err := validateManagedXrayFile(supervisor.configRoot, spec.ConfigPath, 0600); err != nil {
		return fmt.Errorf("%w: config", errXrayUnmanagedPath)
	}
	binaryHash, err := sha256File(spec.BinaryPath, xrayArtifactMaxBinaryBytes)
	if err != nil || binaryHash != spec.BinarySHA256 {
		return errXrayBinaryHashMismatch
	}
	configHash, err := sha256File(spec.ConfigPath, XrayMaxConfigJSONBytes)
	if err != nil || configHash != spec.ConfigHash {
		return errXrayConfigHashMismatch
	}
	return nil
}

func validateManagedXrayFile(root, path string, requiredMode os.FileMode) error {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	if !filepath.IsAbs(root) || !filepath.IsAbs(path) {
		return errXrayUnmanagedPath
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || !xrayPathOwnerAllowed(rootInfo, true) {
		return errXrayUnmanagedPath
	}
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errXrayUnmanagedPath
	}
	current := root
	for _, segment := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, segment)
		info, statErr := os.Lstat(current)
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 || !xrayPathOwnerAllowed(info, true) {
			return errXrayUnmanagedPath
		}
		if current != path && !info.IsDir() {
			return errXrayUnmanagedPath
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != requiredMode {
		return errXrayUnmanagedPath
	}
	return nil
}

func sameXrayLaunchSpec(left, right xrayLaunchSpec) bool {
	return left == right
}

func sameXrayProcessIdentity(left, right xrayProcessIdentity) bool {
	return left.PID > 0 && left.PID == right.PID && left.StartTime != "" && left.StartTime == right.StartTime && filepath.Clean(left.Executable) == filepath.Clean(right.Executable)
}

func (supervisor *xraySupervisor) Start(spec xrayLaunchSpec) (xraySupervisorStatus, error) {
	if err := supervisor.validateSpec(spec); err != nil {
		return xraySupervisorStatus{}, err
	}
	supervisor.transitionMu.Lock()
	defer supervisor.transitionMu.Unlock()
	return supervisor.startLocked(spec, false)
}

func (supervisor *xraySupervisor) startLocked(spec xrayLaunchSpec, watchdog bool) (xraySupervisorStatus, error) {
	if err := supervisor.validateSpec(spec); err != nil {
		return xraySupervisorStatus{}, err
	}
	supervisor.mu.Lock()
	if supervisor.current != nil {
		tracked := supervisor.current
		actual, err := supervisor.inspect(tracked.identity.PID, tracked.identity.Executable)
		if err != nil || !sameXrayProcessIdentity(actual, tracked.identity) {
			supervisor.status = XrayServiceError
			supervisor.errorCode = XrayErrorRuntimeStartFailed
			supervisor.mu.Unlock()
			return xraySupervisorStatus{}, errXrayProcessIdentityMismatch
		}
		if !sameXrayLaunchSpec(tracked.spec, spec) {
			supervisor.mu.Unlock()
			return xraySupervisorStatus{}, errXrayRuntimeAlreadyRunning
		}
		status := supervisor.statusLocked(true)
		supervisor.mu.Unlock()
		return status, nil
	}
	if !watchdog {
		supervisor.epoch++
		supervisor.restartAttempts = 0
	}
	epoch := supervisor.epoch
	supervisor.mu.Unlock()

	launch := xrayProcessLaunch{
		BinaryPath:  spec.BinaryPath,
		Args:        []string{"run", "-config", spec.ConfigPath},
		Directory:   filepath.Dir(spec.ConfigPath),
		Environment: managedXrayEnvironment(),
		Stdout:      io.Discard,
		Stderr:      io.Discard,
	}
	process, err := supervisor.launch(launch)
	if err != nil {
		supervisor.mu.Lock()
		supervisor.status = XrayServiceError
		supervisor.errorCode = XrayErrorRuntimeStartFailed
		supervisor.mu.Unlock()
		return xraySupervisorStatus{}, fmt.Errorf("start managed Xray: %w", err)
	}
	identity, err := supervisor.inspect(process.PID(), spec.BinaryPath)
	if err != nil || identity.PID != process.PID() || filepath.Clean(identity.Executable) != filepath.Clean(spec.BinaryPath) || identity.StartTime == "" {
		_ = process.Kill()
		go process.Wait()
		return xraySupervisorStatus{}, errXrayProcessIdentityMismatch
	}
	tracked := &trackedXrayProcess{
		process: process, identity: identity, spec: spec, startedAt: supervisor.now().UTC(), done: make(chan struct{}), epoch: epoch,
	}
	supervisor.mu.Lock()
	if supervisor.epoch != epoch || supervisor.current != nil {
		supervisor.mu.Unlock()
		_ = process.Kill()
		go process.Wait()
		return xraySupervisorStatus{}, errXrayRuntimeAlreadyRunning
	}
	supervisor.current = tracked
	supervisor.spec = spec
	supervisor.desiredRunning = true
	supervisor.status = XrayServiceRunning
	supervisor.errorCode = ""
	if err := supervisor.persistLocked(); err != nil {
		supervisor.current = nil
		supervisor.desiredRunning = false
		supervisor.status = XrayServiceError
		supervisor.errorCode = XrayErrorInternal
		supervisor.mu.Unlock()
		_ = process.Kill()
		go process.Wait()
		return xraySupervisorStatus{}, fmt.Errorf("persist managed Xray identity: %w", err)
	}
	status := supervisor.statusLocked(false)
	supervisor.mu.Unlock()
	go supervisor.watch(tracked)
	return status, nil
}

func (supervisor *xraySupervisor) Stop() error {
	supervisor.transitionMu.Lock()
	defer supervisor.transitionMu.Unlock()
	return supervisor.stopLocked()
}

func (supervisor *xraySupervisor) stopLocked() error {
	supervisor.mu.Lock()
	supervisor.epoch++
	supervisor.desiredRunning = false
	tracked := supervisor.current
	if tracked == nil {
		supervisor.status = XrayServiceStopped
		supervisor.errorCode = ""
		err := supervisor.persistLocked()
		supervisor.mu.Unlock()
		return err
	}
	if err := supervisor.persistLocked(); err != nil {
		supervisor.mu.Unlock()
		return err
	}
	supervisor.mu.Unlock()

	actual, err := supervisor.inspect(tracked.identity.PID, tracked.identity.Executable)
	if err != nil || !sameXrayProcessIdentity(actual, tracked.identity) {
		supervisor.mu.Lock()
		supervisor.status = XrayServiceError
		supervisor.errorCode = XrayErrorRuntimeStartFailed
		_ = supervisor.persistLocked()
		supervisor.mu.Unlock()
		return errXrayProcessIdentityMismatch
	}
	if err := tracked.process.Signal(os.Interrupt); err != nil {
		return fmt.Errorf("signal managed Xray: %w", err)
	}
	if !waitXrayProcessDone(tracked.done, supervisor.stopTimeout) {
		actual, inspectErr := supervisor.inspect(tracked.identity.PID, tracked.identity.Executable)
		if inspectErr != nil || !sameXrayProcessIdentity(actual, tracked.identity) {
			return errXrayProcessIdentityMismatch
		}
		if err := tracked.process.Kill(); err != nil {
			return fmt.Errorf("kill managed Xray: %w", err)
		}
		if !waitXrayProcessDone(tracked.done, supervisor.stopTimeout) {
			return errors.New("managed Xray did not exit")
		}
	}
	return nil
}

func waitXrayProcessDone(done <-chan struct{}, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

func (supervisor *xraySupervisor) Restart(spec xrayLaunchSpec) (xraySupervisorStatus, error) {
	if err := supervisor.validateSpec(spec); err != nil {
		return xraySupervisorStatus{}, err
	}
	supervisor.transitionMu.Lock()
	defer supervisor.transitionMu.Unlock()
	if err := supervisor.stopLocked(); err != nil {
		return xraySupervisorStatus{}, err
	}
	return supervisor.startLocked(spec, false)
}

func (supervisor *xraySupervisor) Status() xraySupervisorStatus {
	if supervisor == nil {
		return xraySupervisorStatus{ServiceStatus: XrayServiceUnknown, ErrorCode: XrayErrorInternal}
	}
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	return supervisor.statusLocked(false)
}

func (supervisor *xraySupervisor) statusLocked(reused bool) xraySupervisorStatus {
	status := xraySupervisorStatus{
		ServiceStatus: supervisor.status, Version: supervisor.spec.Version, Generation: supervisor.spec.Generation,
		ConfigHash: supervisor.spec.ConfigHash, RestartAttempts: supervisor.restartAttempts, ErrorCode: supervisor.errorCode, Reused: reused,
	}
	if supervisor.current != nil {
		status.PID = supervisor.current.identity.PID
		status.StartedAt = supervisor.current.startedAt.Format(time.RFC3339Nano)
		status.BinaryPath = supervisor.current.spec.BinaryPath
	}
	return status
}

func (supervisor *xraySupervisor) watch(tracked *trackedXrayProcess) {
	_ = tracked.process.Wait()
	close(tracked.done)
	supervisor.mu.Lock()
	if supervisor.current != tracked {
		supervisor.mu.Unlock()
		return
	}
	supervisor.current = nil
	desired := supervisor.desiredRunning && supervisor.epoch == tracked.epoch
	if !desired {
		supervisor.status = XrayServiceStopped
		supervisor.errorCode = ""
		_ = supervisor.persistLocked()
		supervisor.mu.Unlock()
		return
	}
	if supervisor.now().Sub(tracked.startedAt) >= supervisor.stableWindow {
		supervisor.restartAttempts = 0
	}
	supervisor.status = XrayServiceError
	supervisor.errorCode = XrayErrorRuntimeStartFailed
	_ = supervisor.persistLocked()
	epoch := tracked.epoch
	supervisor.mu.Unlock()
	go supervisor.restartAfterUnexpectedExit(epoch)
}

func (supervisor *xraySupervisor) restartAfterUnexpectedExit(epoch uint64) {
	for {
		supervisor.mu.Lock()
		if !supervisor.desiredRunning || supervisor.epoch != epoch || supervisor.current != nil {
			supervisor.mu.Unlock()
			return
		}
		if supervisor.restartAttempts >= supervisor.maxRestarts {
			supervisor.status = XrayServiceError
			supervisor.errorCode = XrayErrorRuntimeStartFailed
			_ = supervisor.persistLocked()
			supervisor.mu.Unlock()
			return
		}
		supervisor.restartAttempts++
		attempt := supervisor.restartAttempts
		spec := supervisor.spec
		_ = supervisor.persistLocked()
		supervisor.mu.Unlock()
		delay := time.Second << min(attempt-1, 5)
		if !supervisor.waitDelay(delay) {
			return
		}

		supervisor.transitionMu.Lock()
		supervisor.mu.Lock()
		stillDesired := supervisor.desiredRunning && supervisor.epoch == epoch && supervisor.current == nil
		supervisor.mu.Unlock()
		if !stillDesired {
			supervisor.transitionMu.Unlock()
			return
		}
		_, err := supervisor.startLocked(spec, true)
		supervisor.transitionMu.Unlock()
		if err == nil {
			return
		}
	}
}

func (supervisor *xraySupervisor) persistLocked() error {
	record := xraySupervisorRecord{Version: xraySupervisorRecordVersion, DesiredRunning: supervisor.desiredRunning, Spec: supervisor.spec}
	if supervisor.current != nil {
		identity := supervisor.current.identity
		record.Process = &identity
	}
	return persistXraySupervisorRecordAt(supervisor.root, record)
}

func persistXraySupervisorRecordAt(root string, record xraySupervisorRecord) error {
	if record.Version != xraySupervisorRecordVersion {
		return errors.New("invalid Xray supervisor record version")
	}
	if err := ensureXrayManagedDirectories(root); err != nil {
		return err
	}
	return writePersistentJSON(filepath.Join(root, xraySupervisorStateFile), record)
}

func readXraySupervisorRecordAt(root string) (*xraySupervisorRecord, error) {
	path := filepath.Join(root, xraySupervisorStateFile)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 {
		return nil, errors.New("invalid Xray supervisor state file")
	}
	raw, err := readBoundedXrayFile(path, xraySupervisorStateMaxBytes)
	if err != nil {
		return nil, err
	}
	var record xraySupervisorRecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF || record.Version != xraySupervisorRecordVersion {
		return nil, errors.New("invalid Xray supervisor record")
	}
	return &record, nil
}

func (supervisor *xraySupervisor) Recover() (*xraySupervisorStatus, error) {
	if supervisor == nil {
		return nil, errors.New("Xray supervisor is unavailable")
	}
	supervisor.transitionMu.Lock()
	defer supervisor.transitionMu.Unlock()
	record, err := readXraySupervisorRecordAt(supervisor.root)
	if err != nil || record == nil || !record.DesiredRunning {
		return nil, err
	}
	if err := supervisor.validateSpec(record.Spec); err != nil {
		return nil, err
	}
	if record.Process != nil {
		actual, inspectErr := supervisor.inspect(record.Process.PID, record.Process.Executable)
		if inspectErr == nil && sameXrayProcessIdentity(actual, *record.Process) {
			process, adoptErr := supervisor.adopt(actual)
			if adoptErr != nil {
				return nil, adoptErr
			}
			supervisor.mu.Lock()
			supervisor.epoch++
			tracked := &trackedXrayProcess{
				process: process, identity: actual, spec: record.Spec, startedAt: supervisor.now().UTC(), done: make(chan struct{}), epoch: supervisor.epoch,
			}
			supervisor.current = tracked
			supervisor.spec = record.Spec
			supervisor.desiredRunning = true
			supervisor.status = XrayServiceRunning
			supervisor.errorCode = ""
			status := supervisor.statusLocked(true)
			supervisor.mu.Unlock()
			go supervisor.watch(tracked)
			return &status, nil
		}
	}
	status, err := supervisor.startLocked(record.Spec, false)
	if err != nil {
		return nil, err
	}
	return &status, nil
}

var managedXrayRuntimeSupervisor = newXraySupervisor(xrayManagedRoot, xrayManagedConfigRoot)

func restoreManagedXrayBeforePanelAuth() {
	status, err := managedXrayRuntimeManager.RecoverLocal(context.Background())
	if err != nil {
		logf("Xray local runtime recovery failed")
		return
	}
	if status != nil {
		hashPrefix := status.ConfigHash
		if len(hashPrefix) > 12 {
			hashPrefix = hashPrefix[:12]
		}
		logf("Xray local runtime recovered version=%s generation=%d configHash=%s pid=%d reused=%v", status.Version, status.Generation, hashPrefix, status.PID, status.Reused)
	}
}
