package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readXrayContractFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "docs", "xray", "examples", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return raw
}

func decodeFixtureObject(t *testing.T, name string) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(readXrayContractFixture(t, name), &value); err != nil {
		t.Fatalf("decode fixture %s: %v", name, err)
	}
	return value
}

func encodeXrayContractValue(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encode contract value: %v", err)
	}
	return raw
}

func validXrayPortProbeTaskObject(t *testing.T) map[string]any {
	t.Helper()
	return decodeFixtureObject(t, "agent-task.v1.json")
}

func udpXrayContractFixture(t *testing.T) map[string]any {
	t.Helper()
	return decodeFixtureObject(t, "udp-contract.v1.json")
}

func TestXrayV1ContractFixtures(t *testing.T) {
	desired, err := DecodeXrayDesiredState(readXrayContractFixture(t, "desired-state.v1.json"))
	if err != nil {
		t.Fatalf("decode desired fixture: %v", err)
	}
	if desired.SchemaVersion != XraySchemaVersion || desired.Generation != 12 || len(desired.ExpectedListeners) != 1 {
		t.Fatalf("unexpected desired fixture: %+v", desired)
	}

	observed, err := DecodeXrayObservedReport(readXrayContractFixture(t, "observed-state.v1.json"))
	if err != nil {
		t.Fatalf("decode observed fixture: %v", err)
	}
	if observed.XrayState == nil || observed.XrayState.ServiceStatus != XrayServiceRunning {
		t.Fatalf("unexpected observed fixture: %+v", observed)
	}

	task, err := DecodeXrayTask(readXrayContractFixture(t, "agent-task.v1.json"))
	if err != nil {
		t.Fatalf("decode task fixture: %v", err)
	}
	if task.Type != XrayTaskPortProbe || task.PortProbePayload == nil || len(task.PortProbePayload.Ports) != 3 {
		t.Fatalf("unexpected task fixture: %+v", task)
	}
}

func TestXrayV1AdditiveUDPContractFixture(t *testing.T) {
	fixture := udpXrayContractFixture(t)

	capability, err := DecodeXrayCapability(encodeXrayContractValue(t, fixture["capability"]))
	if err != nil {
		t.Fatalf("decode UDP capability fixture: %v", err)
	}
	if !capability.SupportsUDPPortProbe || !capability.SupportsUDPListenerReadiness {
		t.Fatalf("UDP capability flags missing: %+v", capability)
	}
	desired, err := DecodeXrayDesiredState(encodeXrayContractValue(t, fixture["desired"]))
	if err != nil {
		t.Fatalf("decode UDP desired fixture: %v", err)
	}
	if len(desired.ExpectedListeners) != 2 || desired.ExpectedListeners[1].Network != "udp" {
		t.Fatalf("UDP desired listeners missing: %+v", desired.ExpectedListeners)
	}
	observed, err := DecodeXrayObservedReport(encodeXrayContractValue(t, fixture["observed"]))
	if err != nil {
		t.Fatalf("decode UDP observed fixture: %v", err)
	}
	if observed.XrayState == nil || len(observed.XrayState.Listeners) != 2 || observed.XrayState.Listeners[1].Network != "udp" {
		t.Fatalf("UDP observed listeners missing: %+v", observed.XrayState)
	}
	task, err := DecodeXrayTask(encodeXrayContractValue(t, fixture["task"]))
	if err != nil {
		t.Fatalf("decode UDP task fixture: %v", err)
	}
	if task.PortProbePayload == nil || task.PortProbePayload.Network != "udp" || len(task.PortProbePayload.Ports) != 1 {
		t.Fatalf("UDP probe payload missing: %+v", task.PortProbePayload)
	}

	oldCapability := cloneXrayContractObject(t, fixture["capability"].(map[string]any))
	delete(oldCapability, "supportsUdpPortProbe")
	delete(oldCapability, "supportsUdpListenerReadiness")
	decodedOld, err := DecodeXrayCapability(encodeXrayContractValue(t, oldCapability))
	if err != nil || decodedOld.SupportsUDPPortProbe || decodedOld.SupportsUDPListenerReadiness {
		t.Fatalf("old capability compatibility = %+v, err=%v", decodedOld, err)
	}

	for name, mutate := range map[string]func(map[string]any){
		"multiple UDP ports": func(candidate map[string]any) {
			candidate["payload"].(map[string]any)["ports"] = []int{24456, 24457}
		},
		"ambiguous network": func(candidate map[string]any) {
			candidate["payload"].(map[string]any)["network"] = "both"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneXrayContractObject(t, fixture["task"].(map[string]any))
			mutate(candidate)
			if _, err := DecodeXrayTask(encodeXrayContractValue(t, candidate)); err == nil {
				t.Fatal("invalid UDP task was accepted")
			}
		})
	}
}

func TestXrayV1ContractTypedTaskVariants(t *testing.T) {
	base := map[string]any{
		"schemaVersion": 1,
		"taskId":        "task-123",
		"createdAt":     "2026-09-01T08:00:00Z",
		"expiresAt":     "2026-09-01T08:01:00Z",
	}
	fixtures := []map[string]any{
		{"type": "PORT_PROBE", "payload": map[string]any{"network": "tcp", "listenAddress": "0.0.0.0", "ports": []int{1000, 65535}}},
		{"type": "REALITY_SCAN", "payload": map[string]any{"targets": []string{"www.microsoft.com:443"}, "timeoutMs": 10000, "maxConcurrency": 16}},
		{"type": "INSTALL", "payload": map[string]any{
			"artifactId": 7, "version": "v26.3.27", "os": "linux", "arch": "amd64",
			"size": 17234567, "sha256": strings.Repeat("a", 64), "downloadPath": "/api/agent/artifacts/xray/7",
		}},
		{"type": "UPGRADE", "payload": map[string]any{
			"artifactId": 8, "version": "v26.3.27", "os": "linux", "arch": "arm64",
			"size": 17234567, "sha256": strings.Repeat("b", 64), "downloadPath": "/api/agent/artifacts/xray/8",
		}},
		{"type": "RESTART", "payload": map[string]any{"reason": "ADMIN_REQUEST"}},
	}
	wantTypes := []XrayTaskType{XrayTaskPortProbe, XrayTaskRealityScan, XrayTaskInstall, XrayTaskUpgrade, XrayTaskRestart}
	for index, fixture := range fixtures {
		candidate := cloneXrayContractObject(t, base)
		for key, value := range fixture {
			candidate[key] = value
		}
		task, err := DecodeXrayTask(encodeXrayContractValue(t, candidate))
		if err != nil {
			t.Fatalf("decode %s task: %v", wantTypes[index], err)
		}
		if task.Type != wantTypes[index] {
			t.Fatalf("decoded task type %q, want %q", task.Type, wantTypes[index])
		}
	}
}

func TestXrayV1ContractAcceptsSafeUnknownOptionalFields(t *testing.T) {
	capability := []byte(`{
		"schemaVersion":1,"supported":true,"supervisor":"AGENT_CHILD",
		"supportsPortProbe":true,"supportsRealityScan":true,"supportsArtifactInstall":true,
		"supportedOS":"linux","supportedArch":"amd64","futureCapability":"safe"
	}`)
	if _, err := DecodeXrayCapability(capability); err != nil {
		t.Fatalf("safe capability extension rejected: %v", err)
	}

	taskObject := validXrayPortProbeTaskObject(t)
	taskObject["futureEnvelopeField"] = true
	payload := taskObject["payload"].(map[string]any)
	payload["futurePayloadField"] = "safe"
	task, err := DecodeXrayTask(encodeXrayContractValue(t, taskObject))
	if err != nil {
		t.Fatalf("safe task extension rejected: %v", err)
	}
	if task.PortProbePayload == nil || len(task.PortProbePayload.Ports) != 3 {
		t.Fatalf("typed payload lost after extension: %+v", task)
	}
}

func TestXrayV1ContractRejectsUnknownVersionsAndDiscriminators(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"schema version": func(task map[string]any) { task["schemaVersion"] = 2 },
		"task type":      func(task map[string]any) { task["type"] = "SHELL" },
		"task id":        func(task map[string]any) { task["taskId"] = "bad id with spaces" },
		"chronology": func(task map[string]any) {
			task["createdAt"] = "2026-09-01T08:00:30Z"
			task["expiresAt"] = "2026-09-01T08:00:00Z"
		},
	} {
		t.Run(name, func(t *testing.T) {
			task := validXrayPortProbeTaskObject(t)
			mutate(task)
			if _, err := DecodeXrayTask(encodeXrayContractValue(t, task)); err == nil {
				t.Fatal("invalid task was accepted")
			}
		})
	}

	unsupported := []byte(`{
		"schemaVersion":1,"supported":false,"supervisor":"AGENT_CHILD",
		"supportsPortProbe":false,"supportsRealityScan":false,"supportsArtifactInstall":false,
		"supportedOS":"linux","supportedArch":"riscv64","errorCode":"HOST_PLATFORM_UNSUPPORTED"
	}`)
	if _, err := DecodeXrayCapability(unsupported); err != nil {
		t.Fatalf("unsupported platform report rejected: %v", err)
	}
	supportedRiscV := strings.Replace(string(unsupported), `"supported":false`, `"supported":true`, 1)
	if _, err := DecodeXrayCapability([]byte(supportedRiscV)); err == nil {
		t.Fatal("unsupported architecture was accepted as supported")
	}
	withNullErrorCode := strings.Replace(string(unsupported), `"errorCode":"HOST_PLATFORM_UNSUPPORTED"`, `"errorCode":null`, 1)
	if _, err := DecodeXrayCapability([]byte(withNullErrorCode)); err == nil {
		t.Fatal("nullable capability errorCode diverged from the TypeScript contract")
	}
}

func TestXrayV1ContractEnforcesDesiredLimits(t *testing.T) {
	for name, mutate := range map[string]func(map[string]any){
		"invalid config json": func(desired map[string]any) { desired["configJson"] = "not-json" },
		"uppercase hash":      func(desired map[string]any) { desired["configHash"] = strings.Repeat("A", 64) },
		"oversize config": func(desired map[string]any) {
			desired["configJson"] = `{"padding":"` + strings.Repeat("x", XrayMaxConfigJSONBytes) + `"}`
		},
		"too many listeners": func(desired map[string]any) {
			listener := desired["expectedListeners"].([]any)[0]
			listeners := make([]any, XrayMaxExpectedListeners+1)
			for index := range listeners {
				listeners[index] = listener
			}
			desired["expectedListeners"] = listeners
		},
	} {
		t.Run(name, func(t *testing.T) {
			desired := decodeFixtureObject(t, "desired-state.v1.json")
			mutate(desired)
			if _, err := DecodeXrayDesiredState(encodeXrayContractValue(t, desired)); err == nil {
				t.Fatal("invalid desired state was accepted")
			}
		})
	}
}

func TestXrayV1ContractEnforcesTaskLimits(t *testing.T) {
	t.Run("port probe", func(t *testing.T) {
		for _, ports := range [][]int{{999}, {65536}, {20000, 20000}} {
			task := validXrayPortProbeTaskObject(t)
			task["payload"].(map[string]any)["ports"] = ports
			if _, err := DecodeXrayTask(encodeXrayContractValue(t, task)); err == nil {
				t.Fatalf("invalid ports accepted: %v", ports)
			}
		}
		task := validXrayPortProbeTaskObject(t)
		ports := make([]int, XrayMaxPortProbeCandidates+1)
		for index := range ports {
			ports[index] = 20000 + index
		}
		task["payload"].(map[string]any)["ports"] = ports
		if _, err := DecodeXrayTask(encodeXrayContractValue(t, task)); err == nil {
			t.Fatal("too many ports accepted")
		}
	})

	t.Run("reality scan", func(t *testing.T) {
		base := map[string]any{
			"schemaVersion": 1,
			"taskId":        "reality-scan-1",
			"type":          "REALITY_SCAN",
			"createdAt":     "2026-09-01T08:00:00Z",
			"expiresAt":     "2026-09-01T08:01:00Z",
			"payload": map[string]any{
				"targets":        []string{"www.microsoft.com:443"},
				"timeoutMs":      10000,
				"maxConcurrency": 16,
			},
		}
		for _, target := range []string{"10.0.0.0/8", "https://example.com", "user@example.com:443", "example.com:0"} {
			candidate := cloneXrayContractObject(t, base)
			candidate["payload"].(map[string]any)["targets"] = []string{target}
			if _, err := DecodeXrayTask(encodeXrayContractValue(t, candidate)); err == nil {
				t.Fatalf("invalid target accepted: %s", target)
			}
		}
		for field, value := range map[string]any{"timeoutMs": 10001, "maxConcurrency": 17} {
			candidate := cloneXrayContractObject(t, base)
			candidate["payload"].(map[string]any)[field] = value
			if _, err := DecodeXrayTask(encodeXrayContractValue(t, candidate)); err == nil {
				t.Fatalf("invalid %s accepted", field)
			}
		}
		candidate := cloneXrayContractObject(t, base)
		targets := make([]string, XrayMaxRealityTargets+1)
		for index := range targets {
			targets[index] = "host-" + strings.Repeat("a", 3) + ".example.com:443"
		}
		candidate["payload"].(map[string]any)["targets"] = targets
		if _, err := DecodeXrayTask(encodeXrayContractValue(t, candidate)); err == nil {
			t.Fatal("too many Reality targets accepted")
		}
	})

	t.Run("JavaScript safe integer", func(t *testing.T) {
		task := map[string]any{
			"schemaVersion": 1,
			"taskId":        "install-unsafe-integer",
			"type":          "INSTALL",
			"createdAt":     "2026-09-01T08:00:00Z",
			"expiresAt":     "2026-09-01T08:01:00Z",
			"payload": map[string]any{
				"artifactId": int64(9007199254740992), "version": "v26.3.27", "os": "linux", "arch": "amd64",
				"size": 17234567, "sha256": strings.Repeat("a", 64), "downloadPath": "/api/agent/artifacts/xray/9007199254740992",
			},
		}
		if _, err := DecodeXrayTask(encodeXrayContractValue(t, task)); err == nil {
			t.Fatal("integer above JavaScript safe range was accepted")
		}
	})
}

func cloneXrayContractObject(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	var cloned map[string]any
	if err := json.Unmarshal(encodeXrayContractValue(t, value), &cloned); err != nil {
		t.Fatalf("clone contract object: %v", err)
	}
	return cloned
}

func TestXrayV1ContractRejectsSecretsAndCommands(t *testing.T) {
	for _, injected := range []map[string]any{
		{"configJson": "secret-config"},
		{"privateKey": "secret-private-key"},
		{"nested": map[string]any{"uuid": "00000000-0000-4000-8000-000000000001"}},
		{"nested": []any{map[string]any{"shortId": "0123456789abcdef"}}},
	} {
		observed := decodeFixtureObject(t, "observed-state.v1.json")
		state := observed["xrayState"].(map[string]any)
		for key, value := range injected {
			state[key] = value
		}
		if _, err := DecodeXrayObservedReport(encodeXrayContractValue(t, observed)); err == nil {
			t.Fatalf("observed secret was accepted: %v", injected)
		}
	}

	for _, field := range []string{"command", "script", "shell"} {
		task := validXrayPortProbeTaskObject(t)
		task["payload"].(map[string]any)[field] = "id"
		if _, err := DecodeXrayTask(encodeXrayContractValue(t, task)); err == nil {
			t.Fatalf("task %s field was accepted", field)
		}
	}
}

func TestXrayV1ContractBoundsRawPayloads(t *testing.T) {
	task := validXrayPortProbeTaskObject(t)
	task["futureField"] = strings.Repeat("x", XrayMaxControlPayloadBytes)
	if _, err := DecodeXrayTask(encodeXrayContractValue(t, task)); err == nil {
		t.Fatal("oversize task was accepted")
	}

	observed := decodeFixtureObject(t, "observed-state.v1.json")
	observed["futureField"] = strings.Repeat("x", XrayMaxControlPayloadBytes)
	if _, err := DecodeXrayObservedReport(encodeXrayContractValue(t, observed)); err == nil {
		t.Fatal("oversize observed report was accepted")
	}
}

func TestXrayV1ContractTypedTaskResults(t *testing.T) {
	raw := []byte(`{
		"schemaVersion":1,"taskId":"task-result-1","type":"PORT_PROBE","status":"SUCCESS",
		"startedAt":"2026-09-01T08:00:01Z","finishedAt":"2026-09-01T08:00:02Z",
		"result":{"ports":[{"port":23456,"available":true,"errorCode":null}],"observedAt":"2026-09-01T08:00:02Z"},
		"error":null
	}`)
	result, err := DecodeXrayTaskResult(raw)
	if err != nil {
		t.Fatalf("decode task result: %v", err)
	}
	if result.PortProbeResult == nil || len(result.PortProbeResult.Ports) != 1 {
		t.Fatalf("typed result missing: %+v", result)
	}

	badAvailability := strings.Replace(string(raw), `"available":true,"errorCode":null`, `"available":false,"errorCode":null`, 1)
	if _, err := DecodeXrayTaskResult([]byte(badAvailability)); err == nil {
		t.Fatal("unavailable port without error code was accepted")
	}
	secretResult := strings.Replace(string(raw), `"observedAt":`, `"configJson":"secret","observedAt":`, 1)
	if _, err := DecodeXrayTaskResult([]byte(secretResult)); err == nil {
		t.Fatal("task result secret was accepted")
	}

	missingAvailable := strings.Replace(string(raw), `"available":true,`, "", 1)
	missingAvailable = strings.Replace(missingAvailable, `"errorCode":null`, `"errorCode":"PORT_IN_USE"`, 1)
	if _, err := DecodeXrayTaskResult([]byte(missingAvailable)); err == nil {
		t.Fatal("port result missing required available field was accepted")
	}

	install := &XrayInstallResult{
		InstalledVersion: "v26.3.27",
		BinarySHA256:     strings.Repeat("a", 64),
	}
	mismatched := XrayTaskResult{
		SchemaVersion: XraySchemaVersion,
		TaskID:        "task-result-mismatch",
		Type:          XrayTaskRestart,
		Status:        XrayTaskResultSuccess,
		StartedAt:     "2026-09-01T08:00:01Z",
		FinishedAt:    "2026-09-01T08:00:02Z",
		InstallResult: install,
	}
	if err := mismatched.Validate(); err == nil {
		t.Fatal("task result with mismatched type and typed result was accepted")
	}
}

func TestXrayV1ContractTypedSuccessResultVariants(t *testing.T) {
	base := map[string]any{
		"schemaVersion": 1,
		"taskId":        "task-result-1",
		"status":        "SUCCESS",
		"startedAt":     "2026-09-01T08:00:01Z",
		"finishedAt":    "2026-09-01T08:00:02Z",
		"error":         nil,
	}
	fixtures := []map[string]any{
		{"type": "REALITY_SCAN", "result": map[string]any{
			"results": []any{map[string]any{
				"target": "www.microsoft.com:443", "host": "www.microsoft.com", "resolvedIp": "203.0.113.10",
				"port": 443, "feasible": true, "tls13": true, "h2": true, "x25519": true,
				"certificateValid": true, "serverNames": []string{"www.microsoft.com"}, "latencyMs": 83, "reasonCode": nil,
			}},
			"observedAt": "2026-09-01T08:00:02Z",
		}},
		{"type": "INSTALL", "result": map[string]any{
			"installedVersion": "v26.3.27", "binarySha256": strings.Repeat("a", 64), "reused": false,
		}},
		{"type": "UPGRADE", "result": map[string]any{
			"previousVersion": "v26.3.26", "installedVersion": "v26.3.27",
			"binarySha256": strings.Repeat("b", 64), "rolledBack": false,
		}},
		{"type": "RESTART", "result": map[string]any{
			"previousVersion": "v26.3.27", "runningVersion": "v26.3.27",
			"serviceStatus": "RUNNING", "readyListenerCount": 2,
		}},
	}
	wantTypes := []XrayTaskType{XrayTaskRealityScan, XrayTaskInstall, XrayTaskUpgrade, XrayTaskRestart}
	for index, fixture := range fixtures {
		candidate := cloneXrayContractObject(t, base)
		for key, value := range fixture {
			candidate[key] = value
		}
		result, err := DecodeXrayTaskResult(encodeXrayContractValue(t, candidate))
		if err != nil {
			t.Fatalf("decode %s result: %v", wantTypes[index], err)
		}
		if result.Type != wantTypes[index] {
			t.Fatalf("decoded result type %q, want %q", result.Type, wantTypes[index])
		}
	}
}
