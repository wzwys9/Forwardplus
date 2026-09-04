package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	xrayConfigTestTimeout        = 15 * time.Second
	xrayRuntimeReadinessAttempts = 20
	xrayRuntimeReadinessDelay    = 250 * time.Millisecond
)

type xraySupervisorController interface {
	Start(xrayLaunchSpec) (xraySupervisorStatus, error)
	Restart(xrayLaunchSpec) (xraySupervisorStatus, error)
	Stop() error
	Status() xraySupervisorStatus
}

type xrayApplyResult struct {
	Applied    bool
	Reused     bool
	RolledBack bool
	ErrorCode  XrayAgentErrorCode
	Listeners  []XrayObservedListener
}

type xrayRuntimeApplyError struct {
	code    XrayAgentErrorCode
	message string
	cause   error
}

func (runtimeError *xrayRuntimeApplyError) Error() string { return runtimeError.message }
func (runtimeError *xrayRuntimeApplyError) Unwrap() error { return runtimeError.cause }

type xrayRuntime struct {
	mu sync.Mutex

	managedRoot       string
	configRoot        string
	supervisor        xraySupervisorController
	resolveBinary     func(string) (string, string, error)
	testConfig        func(context.Context, string, string) error
	probeListeners    func(int, []XrayExpectedListener) ([]XrayObservedListener, error)
	writeState        func(string, xrayRuntimeState) error
	waitDelay         func(time.Duration) bool
	readinessAttempts int
}

type xrayRuntimeSnapshot struct {
	state         *xrayRuntimeState
	config        []byte
	configHash    string
	hasConfig     bool
	currentBinary string
	hasCurrent    bool
}

func newXrayRuntime(managedRoot, configRoot string, supervisor xraySupervisorController) *xrayRuntime {
	runtimeManager := &xrayRuntime{
		managedRoot: filepath.Clean(managedRoot), configRoot: filepath.Clean(configRoot), supervisor: supervisor,
		testConfig: runManagedXrayConfigTest, probeListeners: probeManagedXrayListeners,
		writeState:        writeXrayRuntimeStateAt,
		readinessAttempts: xrayRuntimeReadinessAttempts,
	}
	runtimeManager.resolveBinary = func(version string) (string, string, error) {
		return resolveInstalledXrayBinary(runtimeManager.managedRoot, version)
	}
	runtimeManager.waitDelay = func(delay time.Duration) bool {
		time.Sleep(delay)
		return true
	}
	return runtimeManager
}

func (runtimeManager *xrayRuntime) Apply(ctx context.Context, desired XrayDesiredState) (xrayApplyResult, error) {
	runtimeManager.mu.Lock()
	defer runtimeManager.mu.Unlock()
	if runtimeManager.supervisor == nil || runtimeManager.resolveBinary == nil || runtimeManager.testConfig == nil ||
		runtimeManager.probeListeners == nil || runtimeManager.writeState == nil {
		return xrayApplyFailure(XrayErrorInternal, "The managed Xray runtime is unavailable", nil, false)
	}
	if err := desired.Validate(); err != nil || desired.TargetVersion != XrayManagedVersion {
		return xrayApplyFailure(XrayErrorConfigInvalid, "The Xray desired state is invalid", err, false)
	}
	configBytes := []byte(desired.ConfigJSON)
	if hashXrayBytes(configBytes) != desired.ConfigHash {
		return xrayApplyFailure(XrayErrorConfigInvalid, "The Xray config hash does not match", nil, false)
	}
	if err := ensurePrivateXrayDirectory(runtimeManager.managedRoot); err != nil {
		return xrayApplyFailure(XrayErrorInternal, "The managed Xray storage is unavailable", err, false)
	}
	if err := ensurePrivateXrayDirectory(runtimeManager.configRoot); err != nil {
		return xrayApplyFailure(XrayErrorInternal, "The managed Xray config storage is unavailable", err, false)
	}
	if err := runtimeManager.recoverInterruptedApply(); err != nil {
		return xrayApplyFailure(XrayErrorRollbackFailed, "An interrupted Xray apply could not be recovered", err, false)
	}
	snapshot, err := runtimeManager.snapshot()
	if err != nil {
		return xrayApplyFailure(XrayErrorInternal, "The current Xray runtime state is invalid", err, false)
	}
	if snapshot.state != nil {
		if compareXrayVersions(snapshot.state.CurrentVersion, desired.TargetVersion) > 0 {
			return xrayApplyFailure(XrayErrorVersionMismatch, "Automatic Xray downgrade is not allowed", nil, false)
		}
		if desired.Generation < snapshot.state.AppliedGeneration ||
			(desired.Generation == snapshot.state.AppliedGeneration && desired.ConfigHash != snapshot.state.AppliedConfigHash) {
			return xrayApplyFailure(XrayErrorGenerationHashConflict, "The Xray generation conflicts with the applied state", nil, false)
		}
		if desired.Generation == snapshot.state.AppliedGeneration && desired.ConfigHash == snapshot.state.AppliedConfigHash {
			if !snapshot.state.DesiredRunning && len(desired.ExpectedListeners) == 0 && runtimeManager.supervisor.Status().ServiceStatus == XrayServiceStopped {
				return xrayApplyResult{Applied: true, Reused: true, Listeners: []XrayObservedListener{}}, nil
			}
			if listeners, ready := runtimeManager.currentRuntimeReady(snapshot.state.ExpectedListeners); ready {
				return xrayApplyResult{Applied: true, Reused: true, Listeners: listeners}, nil
			}
		}
	}
	binaryPath, binarySHA256, err := runtimeManager.resolveBinary(desired.TargetVersion)
	if err != nil {
		return xrayApplyFailure(XrayErrorArtifactNotFound, "The managed Xray binary is unavailable", err, false)
	}
	pendingPath := filepath.Join(runtimeManager.configRoot, "pending", fmt.Sprintf("%d-%s.json", desired.Generation, desired.ConfigHash))
	defer removeXrayFile(pendingPath)
	if err := writeAtomicXrayFile(pendingPath, configBytes, 0600); err != nil {
		return xrayApplyFailure(XrayErrorInternal, "The pending Xray config could not be persisted", err, false)
	}
	if err := runtimeManager.testConfig(ctx, binaryPath, pendingPath); err != nil {
		return xrayApplyFailure(XrayErrorConfigInvalid, "The Xray config test failed", err, false)
	}
	if snapshot.hasConfig {
		if err := runtimeManager.saveLastGood(snapshot); err != nil {
			return xrayApplyFailure(XrayErrorInternal, "The last-good Xray config could not be persisted", err, false)
		}
		if err := runtimeManager.beginApplyTransaction(snapshot); err != nil {
			return xrayApplyFailure(XrayErrorInternal, "The Xray apply transaction could not be persisted", err, false)
		}
	}
	if err := switchCurrentXrayBinary(runtimeManager.managedRoot, binaryPath); err != nil {
		return runtimeManager.rollbackAfterFailure(snapshot, XrayErrorInternal, "The managed Xray binary could not be selected", err)
	}
	if err := writeAtomicXrayFile(filepath.Join(runtimeManager.configRoot, "config.json"), configBytes, 0600); err != nil {
		return runtimeManager.rollbackAfterFailure(snapshot, XrayErrorInternal, "The Xray config could not be activated", err)
	}
	if err := writeAtomicXrayFile(filepath.Join(runtimeManager.configRoot, "config.json.sha256"), []byte(desired.ConfigHash+"\n"), 0600); err != nil {
		return runtimeManager.rollbackAfterFailure(snapshot, XrayErrorInternal, "The Xray config hash could not be activated", err)
	}
	if len(desired.ExpectedListeners) == 0 {
		if err := runtimeManager.supervisor.Stop(); err != nil {
			return runtimeManager.rollbackAfterFailure(snapshot, XrayErrorRuntimeStartFailed, "The managed Xray runtime could not be stopped", err)
		}
		state := xrayRuntimeState{
			Version: xrayRuntimeStateVersion, DesiredRunning: false, AppliedGeneration: desired.Generation,
			AppliedConfigHash: desired.ConfigHash, CurrentVersion: desired.TargetVersion, CurrentBinarySHA256: binarySHA256,
			ExpectedListeners: []XrayExpectedListener{},
		}
		if err := runtimeManager.writeState(runtimeManager.managedRoot, state); err != nil {
			return runtimeManager.rollbackAfterFailure(snapshot, XrayErrorInternal, "The stopped Xray state could not be committed", err)
		}
		if err := runtimeManager.finishApplyTransaction(); err != nil {
			return xrayApplyFailure(XrayErrorInternal, "The Xray apply transaction could not be finalized", err, false)
		}
		return xrayApplyResult{Applied: true, Listeners: []XrayObservedListener{}}, nil
	}
	launchSpec := xrayLaunchSpec{
		BinaryPath: binaryPath, BinarySHA256: binarySHA256, ConfigPath: filepath.Join(runtimeManager.configRoot, "config.json"),
		Version: desired.TargetVersion, Generation: desired.Generation, ConfigHash: desired.ConfigHash,
	}
	status := runtimeManager.supervisor.Status()
	if status.ServiceStatus == XrayServiceRunning {
		_, err = runtimeManager.supervisor.Restart(launchSpec)
	} else {
		_, err = runtimeManager.supervisor.Start(launchSpec)
	}
	if err != nil {
		return runtimeManager.rollbackAfterFailure(snapshot, XrayErrorRuntimeStartFailed, "The managed Xray runtime failed to start", err)
	}
	listeners, ready := runtimeManager.waitForReady(desired.ExpectedListeners)
	if !ready {
		return runtimeManager.rollbackAfterFailure(snapshot, XrayErrorRuntimeNotReady, "The managed Xray listeners were not ready", nil)
	}
	state := xrayRuntimeState{
		Version: xrayRuntimeStateVersion, DesiredRunning: true, AppliedGeneration: desired.Generation,
		AppliedConfigHash: desired.ConfigHash, CurrentVersion: desired.TargetVersion, CurrentBinarySHA256: binarySHA256,
		ExpectedListeners: append([]XrayExpectedListener(nil), desired.ExpectedListeners...),
	}
	if err := runtimeManager.writeState(runtimeManager.managedRoot, state); err != nil {
		return runtimeManager.rollbackAfterFailure(snapshot, XrayErrorInternal, "The applied Xray state could not be committed", err)
	}
	if err := runtimeManager.finishApplyTransaction(); err != nil {
		return xrayApplyFailure(XrayErrorInternal, "The Xray apply transaction could not be finalized", err, false)
	}
	return xrayApplyResult{Applied: true, Listeners: listeners}, nil
}

func (runtimeManager *xrayRuntime) RestartLastGood(ctx context.Context) (XrayRestartResult, error) {
	runtimeManager.mu.Lock()
	defer runtimeManager.mu.Unlock()
	if runtimeManager.supervisor == nil || runtimeManager.testConfig == nil || runtimeManager.probeListeners == nil {
		return XrayRestartResult{}, &xrayRuntimeApplyError{code: XrayErrorInternal, message: "The managed Xray runtime is unavailable"}
	}
	if err := ensurePrivateXrayDirectory(runtimeManager.managedRoot); err != nil {
		return XrayRestartResult{}, &xrayRuntimeApplyError{code: XrayErrorInternal, message: "The managed Xray storage is unavailable", cause: err}
	}
	if err := ensurePrivateXrayDirectory(runtimeManager.configRoot); err != nil {
		return XrayRestartResult{}, &xrayRuntimeApplyError{code: XrayErrorInternal, message: "The managed Xray config storage is unavailable", cause: err}
	}
	snapshot, err := runtimeManager.snapshot()
	if err != nil || snapshot.state == nil || !snapshot.state.DesiredRunning || !snapshot.hasConfig || !snapshot.hasCurrent ||
		len(snapshot.state.ExpectedListeners) == 0 {
		return XrayRestartResult{}, &xrayRuntimeApplyError{code: XrayErrorRuntimeNotReady, message: "The last-good Xray runtime is unavailable", cause: err}
	}
	configPath := filepath.Join(runtimeManager.configRoot, "config.json")
	if err := runtimeManager.testConfig(ctx, snapshot.currentBinary, configPath); err != nil {
		return XrayRestartResult{}, &xrayRuntimeApplyError{code: XrayErrorConfigInvalid, message: "The last-good Xray config test failed", cause: err}
	}
	state := snapshot.state
	launchSpec := xrayLaunchSpec{
		BinaryPath: snapshot.currentBinary, BinarySHA256: state.CurrentBinarySHA256, ConfigPath: configPath,
		Version: state.CurrentVersion, Generation: state.AppliedGeneration, ConfigHash: state.AppliedConfigHash,
	}
	previousVersion := state.CurrentVersion
	if status := runtimeManager.supervisor.Status(); status.Version != "" {
		previousVersion = status.Version
	}
	status, restartErr := runtimeManager.supervisor.Restart(launchSpec)
	if restartErr != nil {
		if _, restoreErr := runtimeManager.supervisor.Start(launchSpec); restoreErr != nil {
			return XrayRestartResult{}, &xrayRuntimeApplyError{code: XrayErrorRollbackFailed, message: "The last-good Xray runtime could not be restored", cause: errors.Join(restartErr, restoreErr)}
		}
		if _, ready := runtimeManager.waitForReady(state.ExpectedListeners); !ready {
			return XrayRestartResult{}, &xrayRuntimeApplyError{code: XrayErrorRollbackFailed, message: "The last-good Xray runtime did not become ready", cause: restartErr}
		}
		return XrayRestartResult{}, &xrayRuntimeApplyError{code: XrayErrorRuntimeStartFailed, message: "The managed Xray runtime could not be restarted", cause: restartErr}
	}
	listeners, ready := runtimeManager.waitForReady(state.ExpectedListeners)
	if !ready {
		if _, restoreErr := runtimeManager.supervisor.Restart(launchSpec); restoreErr != nil {
			return XrayRestartResult{}, &xrayRuntimeApplyError{code: XrayErrorRollbackFailed, message: "The last-good Xray runtime could not be restored", cause: restoreErr}
		}
		if _, restored := runtimeManager.waitForReady(state.ExpectedListeners); !restored {
			return XrayRestartResult{}, &xrayRuntimeApplyError{code: XrayErrorRollbackFailed, message: "The last-good Xray runtime did not become ready"}
		}
		return XrayRestartResult{}, &xrayRuntimeApplyError{code: XrayErrorRuntimeNotReady, message: "The managed Xray listeners did not become ready"}
	}
	runningVersion := status.Version
	if runningVersion == "" {
		runningVersion = state.CurrentVersion
	}
	return XrayRestartResult{
		PreviousVersion: &previousVersion, RunningVersion: &runningVersion,
		ServiceStatus: status.ServiceStatus, ReadyListenerCount: len(listeners),
	}, nil
}

func xrayApplyFailure(code XrayAgentErrorCode, message string, cause error, rolledBack bool) (xrayApplyResult, error) {
	return xrayApplyResult{ErrorCode: code, RolledBack: rolledBack}, &xrayRuntimeApplyError{code: code, message: message, cause: cause}
}

func hashXrayBytes(raw []byte) string {
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

func compareXrayVersions(left, right string) int {
	parse := func(value string) ([3]int64, bool) {
		var parsed [3]int64
		parts := strings.Split(strings.TrimPrefix(value, "v"), ".")
		if len(parts) != len(parsed) {
			return parsed, false
		}
		for index, part := range parts {
			number, err := strconv.ParseInt(part, 10, 64)
			if err != nil || number < 0 {
				return parsed, false
			}
			parsed[index] = number
		}
		return parsed, true
	}
	leftVersion, leftOK := parse(left)
	rightVersion, rightOK := parse(right)
	if !leftOK || !rightOK {
		return 0
	}
	for index := range leftVersion {
		if leftVersion[index] < rightVersion[index] {
			return -1
		}
		if leftVersion[index] > rightVersion[index] {
			return 1
		}
	}
	return 0
}

func (runtimeManager *xrayRuntime) snapshot() (xrayRuntimeSnapshot, error) {
	state, err := readXrayRuntimeStateAt(runtimeManager.managedRoot)
	if err != nil {
		return xrayRuntimeSnapshot{}, err
	}
	snapshot := xrayRuntimeSnapshot{state: state}
	configPath := filepath.Join(runtimeManager.configRoot, "config.json")
	hashPath := filepath.Join(runtimeManager.configRoot, "config.json.sha256")
	configInfo, configErr := os.Lstat(configPath)
	hashInfo, hashErr := os.Lstat(hashPath)
	if state == nil {
		for _, candidate := range []struct {
			info os.FileInfo
			err  error
		}{{configInfo, configErr}, {hashInfo, hashErr}} {
			if candidate.err == nil && (!candidate.info.Mode().IsRegular() || candidate.info.Mode().Perm() != 0600 || candidate.info.Mode()&os.ModeSymlink != 0) {
				return xrayRuntimeSnapshot{}, errXrayUnmanagedPath
			}
			if candidate.err != nil && !os.IsNotExist(candidate.err) {
				return xrayRuntimeSnapshot{}, candidate.err
			}
		}
		if current, currentErr := readCurrentXrayBinary(runtimeManager.managedRoot); currentErr == nil {
			_ = current // A valid but uncommitted current is not a rollback source.
		} else if !os.IsNotExist(currentErr) {
			return xrayRuntimeSnapshot{}, currentErr
		}
		return snapshot, nil
	}
	if os.IsNotExist(configErr) && os.IsNotExist(hashErr) {
		// First deployment.
	} else {
		if configErr != nil || hashErr != nil || !configInfo.Mode().IsRegular() || configInfo.Mode().Perm() != 0600 ||
			!hashInfo.Mode().IsRegular() || hashInfo.Mode().Perm() != 0600 || configInfo.Mode()&os.ModeSymlink != 0 || hashInfo.Mode()&os.ModeSymlink != 0 {
			return xrayRuntimeSnapshot{}, errXrayUnmanagedPath
		}
		config, err := readBoundedXrayFile(configPath, XrayMaxConfigJSONBytes)
		if err != nil {
			return xrayRuntimeSnapshot{}, err
		}
		hashRaw, err := readBoundedXrayFile(hashPath, 128)
		if err != nil {
			return xrayRuntimeSnapshot{}, err
		}
		snapshot.config = config
		snapshot.configHash = strings.TrimSpace(string(hashRaw))
		if !xraySHA256Pattern.MatchString(snapshot.configHash) || hashXrayBytes(config) != snapshot.configHash {
			return xrayRuntimeSnapshot{}, errXrayConfigHashMismatch
		}
		snapshot.hasConfig = true
	}
	current, currentErr := readCurrentXrayBinary(runtimeManager.managedRoot)
	if currentErr == nil {
		snapshot.currentBinary = current
		snapshot.hasCurrent = true
	} else if !os.IsNotExist(currentErr) {
		return xrayRuntimeSnapshot{}, currentErr
	}
	if !snapshot.hasConfig || snapshot.configHash != state.AppliedConfigHash || !snapshot.hasCurrent {
		return xrayRuntimeSnapshot{}, errors.New("Xray runtime state does not match current files")
	}
	binaryHash, err := sha256File(snapshot.currentBinary, xrayArtifactMaxBinaryBytes)
	if err != nil || binaryHash != state.CurrentBinarySHA256 ||
		!strings.Contains(snapshot.currentBinary, string(filepath.Separator)+state.CurrentVersion+string(filepath.Separator)) {
		return xrayRuntimeSnapshot{}, errors.New("Xray runtime state does not match the current binary")
	}
	return snapshot, nil
}

func (runtimeManager *xrayRuntime) saveLastGood(snapshot xrayRuntimeSnapshot) error {
	if !snapshot.hasConfig {
		return nil
	}
	if err := writeAtomicXrayFile(filepath.Join(runtimeManager.configRoot, "last-good.json"), snapshot.config, 0600); err != nil {
		return err
	}
	return writeAtomicXrayFile(filepath.Join(runtimeManager.configRoot, "last-good.json.sha256"), []byte(snapshot.configHash+"\n"), 0600)
}

func (runtimeManager *xrayRuntime) rollbackAfterFailure(
	snapshot xrayRuntimeSnapshot,
	originalCode XrayAgentErrorCode,
	message string,
	cause error,
) (xrayApplyResult, error) {
	if !snapshot.hasConfig || snapshot.state == nil || !snapshot.hasCurrent {
		if err := runtimeManager.supervisor.Stop(); err != nil {
			return xrayApplyFailure(XrayErrorRollbackFailed, "The failed Xray runtime could not be stopped", err, false)
		}
		var cleanupErrors []error
		for _, path := range []string{
			filepath.Join(runtimeManager.configRoot, "config.json"), filepath.Join(runtimeManager.configRoot, "config.json.sha256"),
			filepath.Join(runtimeManager.managedRoot, "current"), filepath.Join(runtimeManager.managedRoot, xrayRuntimeStateFile),
		} {
			if err := removeXrayFile(path); err != nil {
				cleanupErrors = append(cleanupErrors, err)
			}
		}
		if len(cleanupErrors) > 0 {
			return xrayApplyFailure(XrayErrorRollbackFailed, "The failed Xray runtime files could not be cleaned", errors.Join(cleanupErrors...), false)
		}
		return xrayApplyFailure(originalCode, message, cause, false)
	}
	if err := writeAtomicXrayFile(filepath.Join(runtimeManager.configRoot, "config.json"), snapshot.config, 0600); err != nil {
		return xrayApplyFailure(XrayErrorRollbackFailed, "The last-good Xray config could not be restored", err, false)
	}
	if err := writeAtomicXrayFile(filepath.Join(runtimeManager.configRoot, "config.json.sha256"), []byte(snapshot.configHash+"\n"), 0600); err != nil {
		return xrayApplyFailure(XrayErrorRollbackFailed, "The last-good Xray config hash could not be restored", err, false)
	}
	if err := switchCurrentXrayBinary(runtimeManager.managedRoot, snapshot.currentBinary); err != nil {
		return xrayApplyFailure(XrayErrorRollbackFailed, "The previous Xray binary could not be restored", err, false)
	}
	if err := runtimeManager.writeState(runtimeManager.managedRoot, *snapshot.state); err != nil {
		return xrayApplyFailure(XrayErrorRollbackFailed, "The previous Xray state could not be restored", err, false)
	}
	rollbackSpec := xrayLaunchSpec{
		BinaryPath: snapshot.currentBinary, BinarySHA256: snapshot.state.CurrentBinarySHA256,
		ConfigPath: filepath.Join(runtimeManager.configRoot, "config.json"), Version: snapshot.state.CurrentVersion,
		Generation: snapshot.state.AppliedGeneration, ConfigHash: snapshot.state.AppliedConfigHash,
	}
	if _, err := runtimeManager.supervisor.Restart(rollbackSpec); err != nil {
		return xrayApplyFailure(XrayErrorRollbackFailed, "The previous Xray runtime could not be restarted", err, false)
	}
	if _, ready := runtimeManager.waitForReady(snapshot.state.ExpectedListeners); !ready {
		return xrayApplyFailure(XrayErrorRollbackFailed, "The previous Xray runtime did not become ready", nil, false)
	}
	if err := runtimeManager.finishApplyTransaction(); err != nil {
		return xrayApplyFailure(XrayErrorRollbackFailed, "The Xray rollback transaction could not be finalized", err, false)
	}
	return xrayApplyFailure(originalCode, message, cause, true)
}

func (runtimeManager *xrayRuntime) currentRuntimeReady(expected []XrayExpectedListener) ([]XrayObservedListener, bool) {
	status := runtimeManager.supervisor.Status()
	if status.ServiceStatus != XrayServiceRunning || status.PID <= 0 {
		return nil, false
	}
	listeners, err := runtimeManager.probeListeners(status.PID, expected)
	return listeners, err == nil && allXrayListenersReady(expected, listeners)
}

func (runtimeManager *xrayRuntime) waitForReady(expected []XrayExpectedListener) ([]XrayObservedListener, bool) {
	for attempt := 0; attempt < runtimeManager.readinessAttempts; attempt++ {
		if listeners, ready := runtimeManager.currentRuntimeReady(expected); ready {
			return listeners, true
		}
		if attempt+1 < runtimeManager.readinessAttempts && !runtimeManager.waitDelay(xrayRuntimeReadinessDelay) {
			break
		}
	}
	return nil, false
}

func allXrayListenersReady(expected []XrayExpectedListener, observed []XrayObservedListener) bool {
	if len(expected) != len(observed) {
		return false
	}
	type listenerIdentity struct {
		runtimeTag string
		network    string
		port       int
	}
	byIdentity := make(map[listenerIdentity]XrayObservedListener, len(observed))
	for _, listener := range observed {
		identity := listenerIdentity{runtimeTag: listener.RuntimeTag, network: listener.Network, port: listener.Port}
		if _, duplicate := byIdentity[identity]; duplicate {
			return false
		}
		byIdentity[identity] = listener
	}
	for _, listener := range expected {
		identity := listenerIdentity{runtimeTag: listener.RuntimeTag, network: listener.Network, port: listener.Port}
		actual, ok := byIdentity[identity]
		if !ok || actual.Status != XrayListenerReady {
			return false
		}
	}
	return true
}

func runManagedXrayConfigTest(ctx context.Context, binaryPath, configPath string) error {
	testContext, cancel := context.WithTimeout(ctx, xrayConfigTestTimeout)
	defer cancel()
	output := &boundedXrayOutput{limit: xrayArtifactVersionOutputLimit}
	command := exec.CommandContext(testContext, binaryPath, "run", "-test", "-config", configPath)
	command.Dir = filepath.Dir(configPath)
	command.Env = managedXrayEnvironment()
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil || testContext.Err() != nil || output.truncated {
		return errors.New("managed Xray config test failed")
	}
	return nil
}

func resolveInstalledXrayBinary(root, version string) (string, string, error) {
	if version != XrayManagedVersion || runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return "", "", errXrayUnmanagedPath
	}
	directory := filepath.Join(root, "versions", version, runtime.GOOS+"-"+runtime.GOARCH)
	manifestPath := filepath.Join(directory, "artifact.json")
	manifestInfo, err := os.Lstat(manifestPath)
	if err != nil || !manifestInfo.Mode().IsRegular() || manifestInfo.Mode()&os.ModeSymlink != 0 || manifestInfo.Mode().Perm() != 0600 {
		return "", "", errXrayUnmanagedPath
	}
	manifestRaw, err := readBoundedXrayFile(manifestPath, xrayArtifactManifestMaxBytes)
	if err != nil {
		return "", "", err
	}
	var manifest installedXrayArtifactManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil || manifest.Version != version || manifest.OS != runtime.GOOS || manifest.Arch != runtime.GOARCH ||
		manifest.ArchiveSize <= 0 || !xraySHA256Pattern.MatchString(manifest.ArchiveSHA256) || !xraySHA256Pattern.MatchString(manifest.BinarySHA256) {
		return "", "", errors.New("invalid installed Xray artifact manifest")
	}
	binaryPath := filepath.Join(directory, "xray")
	if err := validateXrayVersionBinaryPath(root, binaryPath); err != nil {
		return "", "", err
	}
	binaryHash, err := sha256File(binaryPath, xrayArtifactMaxBinaryBytes)
	if err != nil || binaryHash != manifest.BinarySHA256 {
		return "", "", errXrayBinaryHashMismatch
	}
	return binaryPath, binaryHash, nil
}

type xrayProcListener struct {
	network string
	address net.IP
	port    int
	inode   string
}

func probeManagedXrayListeners(pid int, expected []XrayExpectedListener) ([]XrayObservedListener, error) {
	owned, err := xrayProcessSocketInodes(pid)
	if err != nil {
		return nil, err
	}
	listeners := []xrayProcListener{}
	neededNetworks := map[string]bool{}
	for _, wanted := range expected {
		neededNetworks[wanted.Network] = true
	}
	for _, network := range []string{"tcp", "udp"} {
		if !neededNetworks[network] {
			continue
		}
		networkListeners, readErr := readLinuxNetworkListeners(network)
		if readErr != nil {
			return nil, readErr
		}
		listeners = append(listeners, networkListeners...)
	}
	observed := make([]XrayObservedListener, 0, len(expected))
	for _, wanted := range expected {
		status := XrayListenerMissing
		for _, actual := range listeners {
			if actual.network != wanted.Network || actual.port != wanted.Port || !xrayListenAddressMatches(wanted.ListenAddress, actual.address) {
				continue
			}
			if owned[actual.inode] {
				status = XrayListenerReady
				break
			}
			status = XrayListenerWrongProcess
		}
		observed = append(observed, XrayObservedListener{
			RuntimeTag: wanted.RuntimeTag, Network: wanted.Network, Port: wanted.Port, Status: status,
		})
	}
	return observed, nil
}

func xrayProcessSocketInodes(pid int) (map[string]bool, error) {
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return nil, err
	}
	inodes := make(map[string]bool)
	for _, entry := range entries {
		target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name()))
		if err == nil && strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = true
		}
	}
	return inodes, nil
}

func readLinuxTCPListeners() ([]xrayProcListener, error) {
	return readLinuxNetworkListeners("tcp")
}

func readLinuxNetworkListeners(network string) ([]xrayProcListener, error) {
	if network != "tcp" && network != "udp" {
		return nil, fmt.Errorf("unsupported procfs listener network %q", network)
	}
	listeners := []xrayProcListener{}
	wantedState := "0A"
	if network == "udp" {
		wantedState = "07"
	}
	for _, source := range []struct {
		path string
		ipv6 bool
	}{{"/proc/net/" + network, false}, {"/proc/net/" + network + "6", true}} {
		file, err := os.Open(source.path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(file)
		if scanner.Scan() { // header
		}
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 || fields[3] != wantedState {
				continue
			}
			address, port, ok := decodeProcTCPAddress(fields[1], source.ipv6)
			if ok {
				listeners = append(listeners, xrayProcListener{network: network, address: address, port: port, inode: fields[9]})
			}
		}
		scanErr := scanner.Err()
		closeErr := file.Close()
		if scanErr != nil || closeErr != nil {
			return nil, errors.Join(scanErr, closeErr)
		}
	}
	return listeners, nil
}

func decodeProcTCPAddress(value string, ipv6 bool) (net.IP, int, bool) {
	addressHex, portHex, ok := strings.Cut(value, ":")
	if !ok {
		return nil, 0, false
	}
	portValue, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return nil, 0, false
	}
	raw, err := hex.DecodeString(addressHex)
	if err != nil || (!ipv6 && len(raw) != net.IPv4len) || (ipv6 && len(raw) != net.IPv6len) {
		return nil, 0, false
	}
	wordSize := 4
	for offset := 0; offset < len(raw); offset += wordSize {
		for left, right := offset, offset+wordSize-1; left < right; left, right = left+1, right-1 {
			raw[left], raw[right] = raw[right], raw[left]
		}
	}
	return net.IP(raw), int(portValue), true
}

func xrayListenAddressMatches(expected string, actual net.IP) bool {
	wanted := net.ParseIP(strings.TrimSpace(expected))
	if wanted == nil || actual == nil {
		return false
	}
	if wanted.IsUnspecified() {
		if wanted.To4() != nil {
			// The fixed Xray version can represent an explicit 0.0.0.0 TCP listener as
			// an owned dual-stack :: socket on Linux. Treat either procfs
			// representation as the same wildcard listener; inode ownership
			// remains mandatory in probeManagedXrayListeners.
			return actual.IsUnspecified()
		}
		return actual.To4() == nil && actual.IsUnspecified()
	}
	return wanted.Equal(actual)
}
