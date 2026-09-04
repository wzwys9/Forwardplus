package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestXrayAPIToAgentListenerE2E(t *testing.T) {
	desiredPath := strings.TrimSpace(os.Getenv("FORWARDX_XRAY_E2E_DESIRED_FILE"))
	binarySource := strings.TrimSpace(os.Getenv("FORWARDX_XRAY_TEST_BINARY"))
	if desiredPath == "" || binarySource == "" {
		t.Skip("set the generated desired file and verified Xray binary for the API-to-listener test")
	}
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("Xray v1 supports linux-amd64 and linux-arm64")
	}
	rawDesired, err := os.ReadFile(desiredPath)
	if err != nil {
		t.Fatal(err)
	}
	desired, err := DecodeXrayDesiredState(rawDesired)
	if err != nil {
		t.Fatal(err)
	}
	if len(desired.ExpectedListeners) < 1 {
		t.Fatal("generated API desired state has no listener")
	}

	managedRoot := filepath.Join(t.TempDir(), "managed-xray")
	configRoot := filepath.Join(t.TempDir(), "etc-xray")
	binaryPath := filepath.Join(managedRoot, "versions", XrayManagedVersion, "linux-"+runtime.GOARCH, "xray")
	if err := os.MkdirAll(filepath.Dir(binaryPath), 0700); err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(binarySource)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binaryPath, binary, 0700); err != nil {
		t.Fatal(err)
	}
	binaryDigest := sha256.Sum256(binary)
	binaryHash := hex.EncodeToString(binaryDigest[:])

	supervisor := newXraySupervisor(managedRoot, configRoot)
	supervisor.stopTimeout = 3 * time.Second
	var processOutput bytes.Buffer
	supervisor.launch = func(launch xrayProcessLaunch) (xrayManagedProcess, error) {
		command := exec.Command(launch.BinaryPath, launch.Args...)
		command.Dir = launch.Directory
		command.Env = append([]string(nil), launch.Environment...)
		command.Stdout = &processOutput
		command.Stderr = &processOutput
		if startErr := command.Start(); startErr != nil {
			return nil, startErr
		}
		return &execXrayManagedProcess{command: command}, nil
	}
	defer func() {
		_ = supervisor.Stop()
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			status := supervisor.Status()
			if status.ServiceStatus == XrayServiceStopped && status.PID == 0 {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	runtimeManager := newXrayRuntime(managedRoot, configRoot, supervisor)
	runtimeManager.resolveBinary = func(version string) (string, string, error) {
		return binaryPath, binaryHash, nil
	}
	var lastObserved []XrayObservedListener
	var lastProcListeners []xrayProcListener
	var lastOwnedSockets map[string]bool
	var lastDialError error
	originalProbe := runtimeManager.probeListeners
	runtimeManager.probeListeners = func(pid int, expected []XrayExpectedListener) ([]XrayObservedListener, error) {
		observed, probeErr := originalProbe(pid, expected)
		lastObserved = observed
		lastOwnedSockets, _ = xrayProcessSocketInodes(pid)
		allListeners, _ := readLinuxTCPListeners()
		lastProcListeners = lastProcListeners[:0]
		for _, actual := range allListeners {
			if actual.port == expected[0].Port {
				lastProcListeners = append(lastProcListeners, actual)
			}
		}
		connection, dialErr := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(expected[0].Port)), 50*time.Millisecond)
		lastDialError = dialErr
		if connection != nil {
			_ = connection.Close()
		}
		return observed, probeErr
	}
	result, err := runtimeManager.Apply(context.Background(), desired)
	if err != nil {
		t.Fatalf("Agent runtime rejected API desired state: %v (code=%s observed=%#v proc=%#v owned=%#v dial=%v output=%q)",
			err, result.ErrorCode, lastObserved, lastProcListeners, lastOwnedSockets, lastDialError, processOutput.String())
	}
	if !result.Applied || len(result.Listeners) != len(desired.ExpectedListeners) {
		t.Fatalf("unexpected Agent apply result: %#v", result)
	}
	status := supervisor.Status()
	if status.ServiceStatus != XrayServiceRunning || status.PID <= 0 {
		t.Fatalf("managed Xray is not running: %#v", status)
	}
	for _, listener := range desired.ExpectedListeners {
		connection, dialErr := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", intString(listener.Port)), 2*time.Second)
		if dialErr != nil {
			t.Fatalf("managed listener %d is unreachable: %v", listener.Port, dialErr)
		}
		_ = connection.Close()
	}
}

func intString(value int) string {
	return strconv.Itoa(value)
}
