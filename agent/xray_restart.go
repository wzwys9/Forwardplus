package main

import (
	"context"
	"errors"
	"time"
)

type xrayRestartFunc func(context.Context) (XrayRestartResult, error)

type xrayRestartRunner struct {
	root    string
	now     func() time.Time
	restart xrayRestartFunc
}

var managedXrayRestartRunner = newXrayRestartRunner(xrayManagedRoot, managedXrayRuntimeManager.RestartLastGood)

func newXrayRestartRunner(root string, restart xrayRestartFunc) *xrayRestartRunner {
	return &xrayRestartRunner{root: root, now: time.Now, restart: restart}
}

func (runner *xrayRestartRunner) Run(ctx context.Context, task XrayTask) XrayTaskResult {
	taskLock := &xrayArtifactTaskLocks[xrayTaskLockHash(task.TaskID)]
	taskLock.Lock()
	defer taskLock.Unlock()

	startedAt := runner.now().UTC()
	result := XrayTaskResult{
		SchemaVersion: XraySchemaVersion, TaskID: task.TaskID, Type: XrayTaskRestart,
		Status: XrayTaskResultFailed, StartedAt: startedAt.Format(time.RFC3339Nano),
	}
	if err := validateXrayIdentifier("taskId", task.TaskID); err == nil {
		persisted, readErr := readPersistedXrayTaskResultAt(runner.root, task.TaskID)
		if readErr == nil && persisted != nil {
			return *persisted
		}
		if readErr != nil {
			result.Error = &XrayTaskError{Code: string(XrayErrorInternal), Message: "The persisted Xray task result is invalid", Retryable: false}
			return runner.finish(result)
		}
	}
	if err := task.Validate(); err != nil || task.Type != XrayTaskRestart || task.RestartPayload == nil {
		result.Status = XrayTaskResultRejected
		result.Error = &XrayTaskError{Code: string(XrayErrorInvalidPayload), Message: "Invalid Xray restart task", Retryable: false}
		return runner.finish(result)
	}
	expiresAt, err := parseXrayTimestamp("expiresAt", task.ExpiresAt)
	if err != nil || !expiresAt.After(startedAt) {
		result.Status = XrayTaskResultRejected
		result.Error = &XrayTaskError{Code: string(XrayErrorTaskExpired), Message: "The Xray restart task has expired", Retryable: false}
		return runner.finish(result)
	}
	if runner.restart == nil {
		result.Error = &XrayTaskError{Code: string(XrayErrorInternal), Message: "The managed Xray restart is unavailable", Retryable: true}
		return runner.finish(result)
	}
	restarted, restartErr := runner.restart(ctx)
	if restartErr == nil {
		if validateErr := restarted.Validate(); validateErr == nil {
			result.Status = XrayTaskResultSuccess
			result.RestartResult = &restarted
			return runner.finish(result)
		}
		restartErr = errors.New("invalid managed Xray restart result")
	}
	code := XrayErrorInternal
	var runtimeError *xrayRuntimeApplyError
	if errors.As(restartErr, &runtimeError) && knownXrayDesiredErrorCode(runtimeError.code) {
		code = runtimeError.code
	}
	result.Error = &XrayTaskError{Code: string(code), Message: xrayDesiredFailureMessage(code), Retryable: code == XrayErrorInternal}
	return runner.finish(result)
}

func (runner *xrayRestartRunner) finish(result XrayTaskResult) XrayTaskResult {
	result.FinishedAt = runner.now().UTC().Format(time.RFC3339Nano)
	if err := persistXrayTaskResultAt(runner.root, result); err != nil {
		logf("Xray task result persist failed task=%s type=%s", taskLogIdentifier(result.TaskID), result.Type)
	}
	return result
}
