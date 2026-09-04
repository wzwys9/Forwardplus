package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func restartTaskWire(t *testing.T, taskID string, createdAt, expiresAt time.Time, reason string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"schemaVersion": XraySchemaVersion,
		"taskId":        taskID,
		"type":          XrayTaskRestart,
		"createdAt":     createdAt.UTC().Format(time.RFC3339Nano),
		"expiresAt":     expiresAt.UTC().Format(time.RFC3339Nano),
		"payload":       map[string]any{"reason": reason},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestXrayRestartTaskIsPersistentIdempotentAndRejectsExpiredPayload(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	calls := 0
	runner := newXrayRestartRunner(root, func(context.Context) (XrayRestartResult, error) {
		calls++
		version := XrayManagedVersion
		return XrayRestartResult{
			PreviousVersion: &version, RunningVersion: &version,
			ServiceStatus: XrayServiceRunning, ReadyListenerCount: 2,
		}, nil
	})
	runner.now = func() time.Time { return now }
	raw := restartTaskWire(t, "restart-task-1", now.Add(-time.Second), now.Add(time.Minute), "ADMIN_REQUEST")
	installer := testXrayArtifactInstaller(root, nil)

	first, handled := dispatchManagedXrayTask(context.Background(), Config{}, raw, newXrayPortProbeRunner(root), nil, installer, runner)
	second, handledAgain := dispatchManagedXrayTask(context.Background(), Config{}, raw, newXrayPortProbeRunner(root), nil, installer, runner)
	if !handled || !handledAgain || first.Status != XrayTaskResultSuccess || second.Status != XrayTaskResultSuccess || calls != 1 {
		t.Fatalf("restart dispatch first=%#v second=%#v handled=%v/%v calls=%d", first, second, handled, handledAgain, calls)
	}
	if first.RestartResult == nil || first.RestartResult.ReadyListenerCount != 2 {
		t.Fatalf("restart result = %#v", first.RestartResult)
	}
	info, err := os.Stat(filepath.Join(root, "task-results", "restart-task-1.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("persisted restart result mode=%v err=%v", info, err)
	}

	expired := restartTaskWire(t, "restart-task-expired", now.Add(-2*time.Minute), now.Add(-time.Minute), "ADMIN_REQUEST")
	expiredResult, handled := dispatchManagedXrayTask(context.Background(), Config{}, expired, newXrayPortProbeRunner(root), nil, installer, runner)
	if !handled || expiredResult.Status != XrayTaskResultRejected || expiredResult.Error == nil ||
		expiredResult.Error.Code != string(XrayErrorTaskExpired) || calls != 1 {
		t.Fatalf("expired restart = %#v handled=%v calls=%d", expiredResult, handled, calls)
	}
}

func TestXrayRestartTaskReturnsStableRuntimeFailure(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	runner := newXrayRestartRunner(root, func(context.Context) (XrayRestartResult, error) {
		return XrayRestartResult{}, &xrayRuntimeApplyError{
			code: XrayErrorRuntimeNotReady, message: "Managed Xray listeners did not become ready", cause: errors.New("private detail"),
		}
	})
	runner.now = func() time.Time { return now }
	raw := restartTaskWire(t, "restart-task-failed", now.Add(-time.Second), now.Add(time.Minute), "ADMIN_REQUEST")
	result := runner.Run(context.Background(), mustDecodeXrayTask(t, raw))
	if result.Status != XrayTaskResultFailed || result.Error == nil || result.Error.Code != string(XrayErrorRuntimeNotReady) ||
		result.Error.Message == "private detail" {
		t.Fatalf("failed restart result = %#v", result)
	}
}

func mustDecodeXrayTask(t *testing.T, raw []byte) XrayTask {
	t.Helper()
	task, err := DecodeXrayTask(raw)
	if err != nil {
		t.Fatal(err)
	}
	return task
}
