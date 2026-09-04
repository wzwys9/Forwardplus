package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func xrayPortProbeTask(taskID string, now time.Time, ports ...int) XrayTask {
	return XrayTask{
		SchemaVersion: XraySchemaVersion,
		TaskID:        taskID,
		Type:          XrayTaskPortProbe,
		CreatedAt:     now.Add(-time.Second).Format(time.RFC3339Nano),
		ExpiresAt:     now.Add(time.Minute).Format(time.RFC3339Nano),
		PortProbePayload: &XrayPortProbePayload{
			Network: "tcp", ListenAddress: "0.0.0.0", Ports: ports,
		},
	}
}

func TestXrayPortProbeUsesRealBindAndPersistsSafeResult(t *testing.T) {
	busy, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	busyPort := busy.Addr().(*net.TCPAddr).Port
	free, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	freePort := free.Addr().(*net.TCPAddr).Port
	if err := free.Close(); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	now := time.Now().UTC()
	runner := newXrayPortProbeRunner(root)
	result := runner.Run(context.Background(), xrayPortProbeTask("real-bind-probe", now, freePort, busyPort))
	if result.Status != XrayTaskResultSuccess || result.PortProbeResult == nil || len(result.PortProbeResult.Ports) != 2 {
		t.Fatalf("port probe result = %#v", result)
	}
	if !result.PortProbeResult.Ports[0].Available || result.PortProbeResult.Ports[0].ErrorCode != nil {
		t.Fatalf("free port result = %#v", result.PortProbeResult.Ports[0])
	}
	busyResult := result.PortProbeResult.Ports[1]
	if busyResult.Available || busyResult.ErrorCode == nil || *busyResult.ErrorCode != string(XrayErrorPortInUse) {
		t.Fatalf("busy port result = %#v", busyResult)
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"process", "command", "pid", "token", "configJson", "privateKey"} {
		if strings.Contains(strings.ToLower(string(raw)), strings.ToLower(forbidden)) {
			t.Fatalf("port result contains %q: %s", forbidden, raw)
		}
	}
	resultPath := filepath.Join(root, "task-results", result.TaskID+".json")
	info, err := os.Stat(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("persisted result mode = %o", info.Mode().Perm())
	}
	persisted, err := readPersistedXrayTaskResultAt(root, result.TaskID)
	if err != nil || persisted == nil || persisted.PortProbeResult == nil {
		t.Fatalf("persisted result = %#v, %v", persisted, err)
	}
}

func TestXrayPortProbeUsesRealUDPBindWithoutCollidingWithTCP(t *testing.T) {
	tcp, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	tcpPort := tcp.Addr().(*net.TCPAddr).Port

	udp, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udpPort := udp.LocalAddr().(*net.UDPAddr).Port

	now := time.Now().UTC()
	runner := newXrayPortProbeRunner(t.TempDir())
	available := xrayPortProbeTask("real-udp-bind-free", now, tcpPort)
	available.PortProbePayload.Network = "udp"
	availableResult := runner.Run(context.Background(), available)
	if availableResult.Status != XrayTaskResultSuccess || availableResult.PortProbeResult == nil ||
		len(availableResult.PortProbeResult.Ports) != 1 || !availableResult.PortProbeResult.Ports[0].Available {
		t.Fatalf("UDP probe against TCP-only port = %#v", availableResult)
	}

	busy := xrayPortProbeTask("real-udp-bind-busy", now, udpPort)
	busy.PortProbePayload.Network = "udp"
	busyResult := runner.Run(context.Background(), busy)
	if busyResult.Status != XrayTaskResultSuccess || busyResult.PortProbeResult == nil ||
		len(busyResult.PortProbeResult.Ports) != 1 || busyResult.PortProbeResult.Ports[0].Available ||
		busyResult.PortProbeResult.Ports[0].ErrorCode == nil ||
		*busyResult.PortProbeResult.Ports[0].ErrorCode != string(XrayErrorPortInUse) {
		t.Fatalf("UDP occupied port result = %#v", busyResult)
	}
}

func TestXrayPortProbeClassifiesBindErrorsWithoutProcessDetails(t *testing.T) {
	now := time.Now().UTC()
	runner := newXrayPortProbeRunner(t.TempDir())
	runner.now = func() time.Time { return now }
	runner.probe = func(_ context.Context, address string) error {
		switch address {
		case "0.0.0.0:1000":
			return syscall.EACCES
		case "0.0.0.0:1001":
			return errors.New("bind failed: " + syscall.EADDRINUSE.Error())
		case "0.0.0.0:1002":
			return syscall.EADDRINUSE
		default:
			return nil
		}
	}
	result := runner.Run(context.Background(), xrayPortProbeTask("classified-probe", now, 1000, 1001, 1002, 1003))
	if result.Status != XrayTaskResultSuccess || result.PortProbeResult == nil {
		t.Fatalf("classified result = %#v", result)
	}
	want := []*string{xrayErrorCodePointer(XrayErrorPortBindDenied), xrayErrorCodePointer(XrayErrorInternal), xrayErrorCodePointer(XrayErrorPortInUse), nil}
	for index, item := range result.PortProbeResult.Ports {
		if (item.ErrorCode == nil) != (want[index] == nil) || item.ErrorCode != nil && *item.ErrorCode != *want[index] {
			t.Fatalf("port %d error = %v, want %v", item.Port, item.ErrorCode, want[index])
		}
	}
}

func TestXrayPortProbeRejectsInvalidAndExpiredTasks(t *testing.T) {
	now := time.Now().UTC()
	runner := newXrayPortProbeRunner(t.TempDir())
	runner.now = func() time.Time { return now }
	var probes atomic.Int32
	runner.probe = func(context.Context, string) error {
		probes.Add(1)
		return nil
	}

	invalid := xrayPortProbeTask("invalid-port-probe", now, 1000)
	invalid.PortProbePayload.Network = "both"
	invalidResult := runner.Run(context.Background(), invalid)
	if invalidResult.Status != XrayTaskResultRejected || invalidResult.Error == nil || invalidResult.Error.Code != string(XrayErrorInvalidPayload) {
		t.Fatalf("invalid task result = %#v", invalidResult)
	}
	expired := xrayPortProbeTask("expired-port-probe", now, 1000)
	expired.ExpiresAt = now.Add(-time.Nanosecond).Format(time.RFC3339Nano)
	expiredResult := runner.Run(context.Background(), expired)
	if expiredResult.Status != XrayTaskResultRejected || expiredResult.Error == nil || expiredResult.Error.Code != string(XrayErrorTaskExpired) {
		t.Fatalf("expired task result = %#v", expiredResult)
	}
	if probes.Load() != 0 {
		t.Fatalf("rejected tasks performed %d binds", probes.Load())
	}
}

func TestXrayPortProbeHonorsTaskTimeout(t *testing.T) {
	now := time.Now().UTC()
	runner := newXrayPortProbeRunner(t.TempDir())
	runner.now = func() time.Time { return now }
	runner.timeout = 10 * time.Millisecond
	runner.probe = func(ctx context.Context, _ string) error {
		<-ctx.Done()
		return ctx.Err()
	}
	result := runner.Run(context.Background(), xrayPortProbeTask("timeout-port-probe", now, 1000))
	if result.Status != XrayTaskResultTimeout || result.Error == nil || result.Error.Code != string(XrayErrorInternal) || !result.Error.Retryable {
		t.Fatalf("timeout task result = %#v", result)
	}
}

func TestXrayPortProbeConcurrentDuplicateTaskIsExecutedOnce(t *testing.T) {
	now := time.Now().UTC()
	runner := newXrayPortProbeRunner(t.TempDir())
	runner.now = func() time.Time { return now }
	entered := make(chan struct{})
	release := make(chan struct{})
	var probes atomic.Int32
	runner.probe = func(context.Context, string) error {
		if probes.Add(1) == 1 {
			close(entered)
		}
		<-release
		return nil
	}
	task := xrayPortProbeTask("duplicate-port-probe", now, 1000)
	results := make(chan XrayTaskResult, 2)
	go func() { results <- runner.Run(context.Background(), task) }()
	<-entered
	go func() { results <- runner.Run(context.Background(), task) }()
	close(release)
	first := <-results
	second := <-results
	if probes.Load() != 1 {
		t.Fatalf("duplicate task performed %d binds", probes.Load())
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("duplicate result changed:\n%s\n%s", firstJSON, secondJSON)
	}
}

func TestXrayPortProbeDispatcherDecodesHeartbeatTask(t *testing.T) {
	now := time.Now().UTC()
	raw, err := json.Marshal(map[string]any{
		"schemaVersion": XraySchemaVersion,
		"taskId":        "dispatched-port-probe",
		"type":          XrayTaskPortProbe,
		"createdAt":     now.Add(-time.Second).Format(time.RFC3339Nano),
		"expiresAt":     now.Add(time.Minute).Format(time.RFC3339Nano),
		"payload": map[string]any{
			"network": "tcp", "listenAddress": "0.0.0.0", "ports": []int{1000},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var heartbeatResponse heartbeatResp
	if err := json.Unmarshal([]byte(`{"xrayTasks":[`+string(raw)+`]}`), &heartbeatResponse); err != nil {
		t.Fatal(err)
	}
	if len(heartbeatResponse.XrayTasks) != 1 {
		t.Fatalf("heartbeat Xray task count = %d", len(heartbeatResponse.XrayTasks))
	}
	runner := newXrayPortProbeRunner(t.TempDir())
	runner.now = func() time.Time { return now }
	var probes atomic.Int32
	runner.probe = func(context.Context, string) error {
		probes.Add(1)
		return nil
	}
	result, handled := dispatchXrayTask(context.Background(), heartbeatResponse.XrayTasks[0], runner)
	if !handled || result.Status != XrayTaskResultSuccess || probes.Load() != 1 {
		t.Fatalf("dispatched result = %#v handled=%v probes=%d", result, handled, probes.Load())
	}
}

func TestXrayPortProbeHeartbeatResultRetryAndAcknowledgement(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	for _, taskID := range []string{"probe-result-a", "probe-result-b"} {
		result := XrayTaskResult{
			SchemaVersion: XraySchemaVersion,
			TaskID:        taskID,
			Type:          XrayTaskPortProbe,
			Status:        XrayTaskResultSuccess,
			StartedAt:     now.Format(time.RFC3339Nano),
			FinishedAt:    now.Add(time.Second).Format(time.RFC3339Nano),
			PortProbeResult: &XrayPortProbeResult{
				Ports:      []XrayPortProbeResultItem{{Port: 21000, Available: true}},
				ObservedAt: now.Add(time.Second).Format(time.RFC3339Nano),
			},
		}
		if err := persistXrayTaskResultAt(root, result); err != nil {
			t.Fatalf("persist %s: %v", taskID, err)
		}
	}

	payload := map[string]any{}
	submitted := appendXrayTaskResultsToHeartbeat(payload, root, 1)
	rawResults, ok := payload["xrayTaskResults"].([]json.RawMessage)
	if !ok || len(rawResults) != 1 || len(submitted) != 1 {
		t.Fatalf("heartbeat results = %#v, submitted=%d", payload["xrayTaskResults"], len(submitted))
	}
	var uploaded XrayTaskResult
	if err := json.Unmarshal(rawResults[0], &uploaded); err != nil || uploaded.TaskID != "probe-result-a" {
		t.Fatalf("uploaded result = %#v, err=%v", uploaded, err)
	}

	acknowledgeXrayTaskResultsAt(root, []string{"probe-result-b", "../probe-result-a"}, submitted)
	if _, err := os.Stat(filepath.Join(root, "task-results", "probe-result-a.json")); err != nil {
		t.Fatalf("unacknowledged submitted result removed: %v", err)
	}
	acknowledgeXrayTaskResultsAt(root, []string{"probe-result-a"}, submitted)
	if _, err := os.Stat(filepath.Join(root, "task-results", "probe-result-a.json")); !os.IsNotExist(err) {
		t.Fatalf("accepted result still present: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "task-results", "probe-result-b.json")); err != nil {
		t.Fatalf("result outside submitted batch removed: %v", err)
	}
}

func xrayErrorCodePointer(code XrayAgentErrorCode) *string {
	value := string(code)
	return &value
}
