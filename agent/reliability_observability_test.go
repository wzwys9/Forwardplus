package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestMimicConnectionStateParsing(t *testing.T) {
	cases := map[string]string{
		"Connection: Established": "established",
		"state Idle":              "idle",
		"no active connection":    "waiting",
		"Connecting to peer":      "connecting",
		"State: SYN sent":         "connecting",
		"State: SYN received":     "connecting",
		"hooks ready":             "unknown",
	}
	for input, expected := range cases {
		if actual := mimicConnectionState(input); actual != expected {
			t.Fatalf("input=%q state=%q want=%q", input, actual, expected)
		}
	}
}

func TestCompactShellFailureOutputKeepsFailureTail(t *testing.T) {
	output := []byte(strings.Repeat("service startup output ", 100) + "XDP hook attach failed")
	got := compactShellFailureOutput(output, errors.New("exit status 1"), false)
	if len([]rune(got)) > 240 {
		t.Fatalf("failure output is too long: %d", len([]rune(got)))
	}
	if !strings.HasSuffix(got, "XDP hook attach failed") {
		t.Fatalf("failure tail was lost: %q", got)
	}
}

func TestCompactShellFailureOutputFallsBackToExecutionError(t *testing.T) {
	if got := compactShellFailureOutput(nil, errors.New("exit status 1"), false); got != "exit status 1" {
		t.Fatalf("unexpected execution fallback: %q", got)
	}
	if got := compactShellFailureOutput(nil, context.DeadlineExceeded, true); got != "command timed out" {
		t.Fatalf("unexpected timeout fallback: %q", got)
	}
}

func TestFXPEndpointEventTracksFailureAndRecovery(t *testing.T) {
	fxpEndpointEventMu.Lock()
	fxpEndpointEvents = map[string]fxpEndpointEvent{}
	fxpEndpointEventMu.Unlock()
	spec := fxpSpec{Role: "entry", TunnelID: 3, RuleID: 8}
	recordFXPEndpointLog(spec, "exit endpoint unhealthy index=1 endpoint=203.0.113.8:62444 reason=i/o timeout")
	events := fxpEndpointEventsSnapshot()
	if len(events) != 1 || events[0].Status != "unhealthy" || !strings.Contains(events[0].Message, "timeout") {
		t.Fatalf("unexpected unhealthy event: %#v", events)
	}
	recordFXPEndpointLog(spec, "exit endpoint recovered index=1 endpoint=203.0.113.8:62444")
	events = fxpEndpointEventsSnapshot()
	if len(events) != 1 || events[0].Status != "recovered" || events[0].StartedAt <= 0 {
		t.Fatalf("unexpected recovered event: %#v", events)
	}
}

func TestSupportOutputRedactsCredentials(t *testing.T) {
	bareRealityKey := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq"
	redacted := redactSupportOutput("token=abc password: def safe=value key-output=" + bareRealityKey)
	if strings.Contains(redacted, "abc") || strings.Contains(redacted, "def") || strings.Contains(redacted, bareRealityKey) || !strings.Contains(redacted, "safe=value") {
		t.Fatalf("unexpected redaction: %s", redacted)
	}
}

func TestXraySupportScrubberRemovesNestedConfigAndCommandSecrets(t *testing.T) {
	secrets := []string{
		"xray-token-UNIQUE-031-secret",
		"03103103-1031-4031-8031-031031031031",
		"0310310310310310",
		"PRIVATEKEYUNIQUE031abcdefghijklmno1234567890_",
	}
	input := `Authorization: Bearer xray-token-UNIQUE-031-secret
runtime={"uuid":"03103103-1031-4031-8031-031031031031","shortId":"0310310310310310","privateKey":"PRIVATEKEYUNIQUE031abcdefghijklmno1234567890_","configJson":"{\\"inbounds\\":[]}"}
file=/tmp/privateKey-PRIVATEKEYUNIQUE031abcdefghijklmno1234567890_.json vless://03103103-1031-4031-8031-031031031031@example.com:443?sid=0310310310310310`
	redacted := redactSupportOutput(input)
	for _, secret := range secrets {
		if strings.Contains(redacted, secret) {
			t.Fatalf("support output leaked %q: %s", secret, redacted)
		}
	}
}

func TestXraySupportDiagnosticsUseOnlyApprovedRuntimeFields(t *testing.T) {
	installedVersion := "26.7.28"
	runningVersion := "26.7.28"
	configHash := strings.Repeat("a", 64)
	binaryHash := strings.Repeat("b", 64)
	state := XrayObservedState{
		InstalledVersion: &installedVersion, RunningVersion: &runningVersion, ServiceStatus: XrayServiceRunning,
		AppliedConfigHash: &configHash, BinarySHA256: &binaryHash,
		Listeners: []XrayObservedListener{{RuntimeTag: "forwardx-inbound-safe", Network: "tcp", Port: 443, Status: XrayListenerReady}},
	}
	diagnostics := xraySupportDiagnosticsFromObserved(state)
	raw, err := json.Marshal(diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(raw)
	for _, forbidden := range []string{"appliedConfigHash", strings.Repeat("a", 64), "binarySha256", strings.Repeat("b", 64), "processId", "generation", "network"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("Xray support diagnostics leaked %q: %s", forbidden, encoded)
		}
	}
	for _, required := range []string{"configHashPrefix", "aaaaaaaaaaaa", "binaryHashPrefix", "bbbbbbbbbbbb", "forwardx-inbound-safe", "443", "RUNNING"} {
		if !strings.Contains(encoded, required) {
			t.Fatalf("Xray support diagnostics missing %q: %s", required, encoded)
		}
	}
}

func TestSupportOutputTruncationKeepsUTF8AndLimit(t *testing.T) {
	value := strings.Repeat("中", 100)
	truncated := truncateSupportOutput(value, 64)
	if len(truncated) > 64 {
		t.Fatalf("truncated output is too large: %d", len(truncated))
	}
	if !utf8.ValidString(truncated) {
		t.Fatalf("truncated output is not valid UTF-8: %q", truncated)
	}
	if !strings.HasSuffix(truncated, supportTruncationMarker) {
		t.Fatalf("missing truncation marker: %q", truncated)
	}
}

func TestSupportOutputTotalLimit(t *testing.T) {
	results := []supportCommandResult{
		{Name: "one", Output: strings.Repeat("a", 80)},
		{Name: "two", Output: strings.Repeat("b", 80)},
		{Name: "three", Output: strings.Repeat("c", 80)},
	}
	enforceSupportOutputTotalLimit(results, 150)
	total := 0
	for _, result := range results {
		total += len(result.Output)
	}
	if total > 150 {
		t.Fatalf("total output=%d exceeds limit", total)
	}
	if results[0].Output != strings.Repeat("a", 80) {
		t.Fatal("earlier result was unexpectedly truncated")
	}
	if results[2].Output != "" {
		t.Fatalf("expected later result to be omitted, got %q", results[2].Output)
	}
}

func TestSupportCommandsIncludeNginxDisconnectDiagnostics(t *testing.T) {
	commands := map[string]string{}
	for _, spec := range supportCommandSpecs() {
		commands[spec.name] = spec.command
	}
	for _, name := range []string{"nginx-journal", "nginx-logs", "kernel-network-events", "network-sysctl"} {
		if commands[name] == "" {
			t.Fatalf("support command %q is missing", name)
		}
	}
	if !strings.Contains(commands["nginx-logs"], "forwardx-nginx-error.log") ||
		!strings.Contains(commands["nginx-logs"], "forwardx-nginx-session.log") {
		t.Fatal("nginx runtime logs are not included in the support bundle")
	}
	if !strings.Contains(commands["network-sysctl"], "tcp_keepalive_time") ||
		!strings.Contains(commands["network-sysctl"], "nf_conntrack_udp_timeout") {
		t.Fatal("network timeout diagnostics are incomplete")
	}
}
