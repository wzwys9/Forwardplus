package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestXrayConfigPersistenceIsAtomicAndPrivate(t *testing.T) {
	root := filepath.Join(t.TempDir(), "etc-xray")
	path := filepath.Join(root, "config.json")
	secret := []byte(`{"privateKey":"persistence-test-secret"}`)
	if err := writeAtomicXrayFile(path, secret, 0600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != string(secret) {
		t.Fatalf("persisted config = %q, err=%v", raw, err)
	}
	if mode := mustFileMode(t, root).Perm(); mode != 0700 {
		t.Fatalf("config root mode = %o, want 0700", mode)
	}
	if mode := mustFileMode(t, path).Perm(); mode != 0600 {
		t.Fatalf("config mode = %o, want 0600", mode)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".forwardx-xray-") {
			t.Fatalf("atomic temp file remained: %s", entry.Name())
		}
	}
}

func TestXrayConfigPersistenceRejectsSymlinkedDirectory(t *testing.T) {
	external := t.TempDir()
	link := filepath.Join(t.TempDir(), "etc-xray")
	if err := os.Symlink(external, link); err != nil {
		t.Fatal(err)
	}
	err := writeAtomicXrayFile(filepath.Join(link, "config.json"), []byte(`{}`), 0600)
	if !errors.Is(err, errXrayUnmanagedPath) {
		t.Fatalf("symlinked config directory error = %v", err)
	}
	entries, readErr := os.ReadDir(external)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("symlink target was modified: entries=%v err=%v", entries, readErr)
	}
}

func TestXrayCurrentBinarySwitchStaysWithinManagedVersions(t *testing.T) {
	root := filepath.Join(t.TempDir(), "xray")
	binary := filepath.Join(root, "versions", XrayManagedVersion, "linux-"+runtime.GOARCH, "xray")
	if err := os.MkdirAll(filepath.Dir(binary), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("binary"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := switchCurrentXrayBinary(root, binary); err != nil {
		t.Fatal(err)
	}
	resolved, err := readCurrentXrayBinary(root)
	if err != nil || resolved != binary {
		t.Fatalf("current binary = %q, err=%v", resolved, err)
	}
	target, err := os.Readlink(filepath.Join(root, "current"))
	if err != nil || filepath.IsAbs(target) {
		t.Fatalf("current link target = %q, err=%v", target, err)
	}
	outside := filepath.Join(t.TempDir(), "system-xray")
	if err := os.WriteFile(outside, []byte("system"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := switchCurrentXrayBinary(root, outside); !errors.Is(err, errXrayUnmanagedPath) {
		t.Fatalf("outside current error = %v", err)
	}
	resolved, err = readCurrentXrayBinary(root)
	if err != nil || resolved != binary {
		t.Fatalf("unsafe switch changed current: %q, err=%v", resolved, err)
	}
}

func TestXrayRuntimeStateExcludesConfigSecrets(t *testing.T) {
	root := filepath.Join(t.TempDir(), "xray")
	state := xrayRuntimeState{
		Version:             xrayRuntimeStateVersion,
		DesiredRunning:      true,
		AppliedGeneration:   9,
		AppliedConfigHash:   strings.Repeat("a", 64),
		CurrentVersion:      XrayManagedVersion,
		CurrentBinarySHA256: strings.Repeat("b", 64),
		ExpectedListeners: []XrayExpectedListener{{
			InboundID: 1, RuntimeTag: "forwardx-inbound-test", Network: "tcp", ListenAddress: "0.0.0.0", Port: 12345,
		}},
	}
	if err := writeXrayRuntimeStateAt(root, state); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, xrayRuntimeStateFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"privateKey", "uuid", "shortId", "configJson", "token"} {
		if strings.Contains(strings.ToLower(string(raw)), strings.ToLower(forbidden)) {
			t.Fatalf("runtime state contains forbidden field %q: %s", forbidden, raw)
		}
	}
	restored, err := readXrayRuntimeStateAt(root)
	if err != nil || restored == nil || restored.AppliedGeneration != state.AppliedGeneration || restored.AppliedConfigHash != state.AppliedConfigHash {
		t.Fatalf("restored state = %#v, err=%v", restored, err)
	}
}
