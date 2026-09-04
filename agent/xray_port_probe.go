package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const xrayPortProbeTaskTimeout = 15 * time.Second

const (
	xrayPortProbeWorkerCount = 4
	xrayPortProbeQueueSize   = 64
	xrayArtifactQueueSize    = 16
)

type xrayPortProbeRunner struct {
	root     string
	now      func() time.Time
	timeout  time.Duration
	probe    func(context.Context, string) error
	probeUDP func(context.Context, string) error
}

var xrayTaskExecutionLocks [32]sync.Mutex

var (
	managedXrayPortProbeRunner = newXrayPortProbeRunner(xrayManagedRoot)
	xrayPortProbeQueue         = make(chan queuedXrayTask, xrayPortProbeQueueSize)
	xrayArtifactQueue          = make(chan queuedXrayTask, xrayArtifactQueueSize)
	xrayPortProbeWorkersOnce   sync.Once
	xrayArtifactWorkerOnce     sync.Once
	xrayArtifactTaskLocks      [32]sync.Mutex
)

type queuedXrayTask struct {
	raw json.RawMessage
	cfg Config
}

func newXrayPortProbeRunner(root string) *xrayPortProbeRunner {
	runner := &xrayPortProbeRunner{
		root: filepath.Clean(root), now: time.Now, timeout: xrayPortProbeTaskTimeout,
	}
	runner.probe = probeXrayTCPPort
	runner.probeUDP = probeXrayUDPPort
	return runner
}

func probeXrayTCPPort(ctx context.Context, address string) error {
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", address)
	if err != nil {
		return err
	}
	return listener.Close()
}

func probeXrayUDPPort(ctx context.Context, address string) error {
	// ListenPacket performs a real UDP bind while honoring the task context.
	// Source: https://pkg.go.dev/net#ListenConfig.ListenPacket
	packet, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp4", address)
	if err != nil {
		return err
	}
	return packet.Close()
}

func dispatchXrayTask(ctx context.Context, raw json.RawMessage, runner *xrayPortProbeRunner, realityRunners ...*xrayRealityScanner) (XrayTaskResult, bool) {
	task, decodeErr := DecodeXrayTask(raw)
	if (task.Type != XrayTaskPortProbe && task.Type != XrayTaskRealityScan) || validateXrayIdentifier("taskId", task.TaskID) != nil {
		return XrayTaskResult{}, false
	}
	if task.Type == XrayTaskPortProbe {
		if decodeErr != nil {
			// The typed decoder retains a safe envelope when only its payload is
			// invalid. Let the runner persist a stable REJECTED terminal result.
			task.PortProbePayload = nil
		}
		return runner.Run(ctx, task), true
	}
	realityRunner := managedXrayRealityScanner
	if len(realityRunners) > 0 && realityRunners[0] != nil {
		realityRunner = realityRunners[0]
	}
	if decodeErr != nil {
		task.RealityScanPayload = nil
	}
	return realityRunner.Run(ctx, task), true
}

func dispatchManagedXrayTask(
	ctx context.Context,
	cfg Config,
	raw json.RawMessage,
	portRunner *xrayPortProbeRunner,
	realityRunner *xrayRealityScanner,
	artifactInstaller *xrayArtifactInstaller,
	restartRunners ...*xrayRestartRunner,
) (XrayTaskResult, bool) {
	task, decodeErr := DecodeXrayTask(raw)
	if task.Type != XrayTaskInstall && task.Type != XrayTaskUpgrade && task.Type != XrayTaskRestart {
		return dispatchXrayTask(ctx, raw, portRunner, realityRunner)
	}
	if validateXrayIdentifier("taskId", task.TaskID) != nil {
		return XrayTaskResult{}, false
	}
	if task.Type == XrayTaskRestart {
		restartRunner := managedXrayRestartRunner
		if len(restartRunners) > 0 && restartRunners[0] != nil {
			restartRunner = restartRunners[0]
		}
		if decodeErr != nil {
			task.RestartPayload = nil
		}
		return restartRunner.Run(ctx, task), true
	}
	taskLock := &xrayArtifactTaskLocks[xrayTaskLockHash(task.TaskID)]
	taskLock.Lock()
	defer taskLock.Unlock()
	if persisted, readErr := readPersistedXrayTaskResultAt(artifactInstaller.root, task.TaskID); readErr == nil && persisted != nil {
		return *persisted, true
	} else if readErr != nil {
		now := artifactInstaller.now().UTC().Format(time.RFC3339Nano)
		result := XrayTaskResult{
			SchemaVersion: XraySchemaVersion, TaskID: task.TaskID, Type: task.Type,
			Status: XrayTaskResultFailed, StartedAt: now, FinishedAt: now,
			Error: &XrayTaskError{Code: string(XrayErrorInternal), Message: "The persisted Xray task result is invalid", Retryable: false},
		}
		_ = persistXrayTaskResultAt(artifactInstaller.root, result)
		return result, true
	}
	if decodeErr != nil {
		task.InstallPayload = nil
		task.UpgradePayload = nil
	}
	return runXrayArtifactTask(ctx, cfg, task, artifactInstaller), true
}

func enqueueXrayTask(cfg Config, raw json.RawMessage) {
	queued := queuedXrayTask{raw: append(json.RawMessage(nil), raw...), cfg: cfg}
	task, _ := DecodeXrayTask(raw)
	if task.Type == XrayTaskInstall || task.Type == XrayTaskUpgrade || task.Type == XrayTaskRestart {
		xrayArtifactWorkerOnce.Do(func() {
			go func() {
				for artifactTask := range xrayArtifactQueue {
					_, handled := dispatchManagedXrayTask(
						context.Background(), artifactTask.cfg, artifactTask.raw, managedXrayPortProbeRunner,
						managedXrayRealityScanner, newXrayArtifactInstaller(xrayManagedRoot, agentSyncHTTPClient), managedXrayRestartRunner,
					)
					if handled {
						signalHeartbeatWake()
					}
				}
			}()
		})
		select {
		case xrayArtifactQueue <- queued:
		default:
			logf("Xray artifact task queue is full; task will be retried by the panel")
		}
		return
	}
	xrayPortProbeWorkersOnce.Do(func() {
		for worker := 0; worker < xrayPortProbeWorkerCount; worker++ {
			go func() {
				for queued := range xrayPortProbeQueue {
					result, handled := dispatchManagedXrayTask(
						context.Background(), queued.cfg, queued.raw, managedXrayPortProbeRunner,
						managedXrayRealityScanner, newXrayArtifactInstaller(xrayManagedRoot, agentSyncHTTPClient),
					)
					if handled {
						signalHeartbeatWake()
						continue
					}
					logf("unsupported or invalid Xray task ignored")
					_ = result
				}
			}()
		}
	})
	select {
	case xrayPortProbeQueue <- queued:
	default:
		logf("Xray interactive task queue is full; task will be retried by the panel")
	}
}

func (runner *xrayPortProbeRunner) Run(ctx context.Context, task XrayTask) XrayTaskResult {
	taskLock := &xrayTaskExecutionLocks[xrayTaskLockHash(task.TaskID)]
	taskLock.Lock()
	defer taskLock.Unlock()

	startedAt := runner.now().UTC()
	result := XrayTaskResult{
		SchemaVersion: XraySchemaVersion, TaskID: task.TaskID, Type: XrayTaskPortProbe,
		Status: XrayTaskResultFailed, StartedAt: startedAt.Format(time.RFC3339Nano),
	}
	if err := validateXrayIdentifier("taskId", task.TaskID); err == nil {
		persisted, readErr := readPersistedXrayTaskResultAt(runner.root, task.TaskID)
		if readErr == nil && persisted != nil {
			return *persisted
		}
		if readErr != nil {
			result.Error = &XrayTaskError{Code: string(XrayErrorInternal), Message: "The persisted Xray task result is invalid", Retryable: false}
			return runner.finish(result, false)
		}
	}
	if err := task.Validate(); err != nil || task.Type != XrayTaskPortProbe || task.PortProbePayload == nil {
		result.Status = XrayTaskResultRejected
		result.Error = &XrayTaskError{Code: string(XrayErrorInvalidPayload), Message: "Invalid Xray port probe task", Retryable: false}
		return runner.finish(result, true)
	}
	expiresAt, err := parseXrayTimestamp("expiresAt", task.ExpiresAt)
	if err != nil || !expiresAt.After(startedAt) {
		result.Status = XrayTaskResultRejected
		result.Error = &XrayTaskError{Code: string(XrayErrorTaskExpired), Message: "The Xray port probe task has expired", Retryable: false}
		return runner.finish(result, true)
	}
	probe := runner.probe
	if task.PortProbePayload.Network == "udp" {
		probe = runner.probeUDP
	}
	if probe == nil || runner.timeout <= 0 {
		result.Error = &XrayTaskError{Code: string(XrayErrorInternal), Message: "The Xray port probe is unavailable", Retryable: true}
		return runner.finish(result, true)
	}

	taskContext, cancel := context.WithTimeout(ctx, runner.timeout)
	defer cancel()
	ports := make([]XrayPortProbeResultItem, 0, len(task.PortProbePayload.Ports))
	for _, port := range task.PortProbePayload.Ports {
		if taskContext.Err() != nil {
			return runner.finishPortProbeTimeout(result)
		}
		address := net.JoinHostPort(task.PortProbePayload.ListenAddress, strconv.Itoa(port))
		probeErr := probe(taskContext, address)
		if taskContext.Err() != nil && (probeErr == nil || errors.Is(probeErr, context.Canceled) || errors.Is(probeErr, context.DeadlineExceeded)) {
			return runner.finishPortProbeTimeout(result)
		}
		item := XrayPortProbeResultItem{Port: port, Available: probeErr == nil}
		if probeErr != nil {
			code := classifyXrayPortProbeError(probeErr)
			item.ErrorCode = xrayErrorCodePointerValue(code)
		}
		ports = append(ports, item)
	}
	result.Status = XrayTaskResultSuccess
	result.PortProbeResult = &XrayPortProbeResult{Ports: ports, ObservedAt: runner.now().UTC().Format(time.RFC3339Nano)}
	return runner.finish(result, true)
}

func (runner *xrayPortProbeRunner) finishPortProbeTimeout(result XrayTaskResult) XrayTaskResult {
	result.Status = XrayTaskResultTimeout
	result.Error = &XrayTaskError{Code: string(XrayErrorInternal), Message: "The Xray port probe task timed out", Retryable: true}
	return runner.finish(result, true)
}

func (runner *xrayPortProbeRunner) finish(result XrayTaskResult, persist bool) XrayTaskResult {
	finishedAt := runner.now().UTC()
	if startedAt, err := parseXrayTimestamp("startedAt", result.StartedAt); err == nil && finishedAt.Before(startedAt) {
		finishedAt = startedAt
	}
	result.FinishedAt = finishedAt.Format(time.RFC3339Nano)
	if persist {
		if err := persistXrayTaskResultAt(runner.root, result); err != nil {
			logf("Xray task result persist failed task=%s type=%s", taskLogIdentifier(result.TaskID), result.Type)
		}
	}
	return result
}

func classifyXrayPortProbeError(err error) XrayAgentErrorCode {
	switch {
	case errors.Is(err, syscall.EADDRINUSE):
		return XrayErrorPortInUse
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return XrayErrorPortBindDenied
	default:
		return XrayErrorInternal
	}
}

func xrayErrorCodePointerValue(code XrayAgentErrorCode) *string {
	value := string(code)
	return &value
}

func readPersistedXrayTaskResultAt(root, taskID string) (*XrayTaskResult, error) {
	if err := validateXrayIdentifier("taskId", taskID); err != nil {
		return nil, err
	}
	path := filepath.Join(filepath.Clean(root), "task-results", taskID+".json")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 {
		return nil, errors.New("invalid persisted Xray task result")
	}
	raw, err := readBoundedXrayFile(path, XrayMaxTaskResultBytes)
	if err != nil {
		return nil, err
	}
	result, err := DecodeXrayTaskResult(raw)
	if err != nil || result.TaskID != taskID {
		return nil, errors.New("invalid persisted Xray task result")
	}
	return &result, nil
}

func taskLogIdentifier(taskID string) string {
	if validateXrayIdentifier("taskId", taskID) == nil {
		return taskID
	}
	return "invalid"
}
