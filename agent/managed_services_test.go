package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

type managedServicesContractFixture struct {
	Capability     ManagedServicesCapability `json:"capability"`
	Desired        json.RawMessage           `json:"desired"`
	ObservedReport struct {
		Signature string                       `json:"managedServicesStateSignature"`
		State     ManagedServicesObservedState `json:"managedServicesState"`
	} `json:"observedReport"`
}

func writeManagedServiceArchive(t *testing.T, path string, entries []tar.Header, bodies [][]byte) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for index := range entries {
		header := entries[index]
		header.Size = int64(len(bodies[index]))
		if err = tarWriter.WriteHeader(&header); err == nil && len(bodies[index]) > 0 {
			_, err = tarWriter.Write(bodies[index])
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = tarWriter.Close(); err == nil {
		err = gzipWriter.Close()
	}
	if err == nil {
		err = file.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestManagedServicesContractAndRuntimeSafety(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "docs", "xray", "examples", "managed-services.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture managedServicesContractFixture
	if err = strictManagedServicesJSON(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Capability.SchemaVersion != managedServicesSchemaVersion ||
		!reflect.DeepEqual(fixture.Capability.SupportedKinds, []string{managedServicesKindMTProto}) ||
		!reflect.DeepEqual(fixture.Capability.KindCapabilities, []ManagedServiceKindCapability{
			{Kind: managedServicesKindMTProto, Supervisor: "AGENT_CHILD", SupportsArtifactInstall: true, RunsAsDedicatedUser: true, Network: "tcp"},
			{Kind: managedServicesKindAmneziaWG, Supervisor: "AGENT_CHILD", SupportsArtifactInstall: false, RunsAsDedicatedUser: true, Network: "udp"},
		}) ||
		fixture.Capability.Supervisor != "AGENT_CHILD" || !fixture.Capability.SupportsArtifactInstall ||
		!fixture.Capability.RunsAsDedicatedUser || fixture.Capability.SupportedOS != "linux" || fixture.Capability.SupportedArch != "amd64" {
		t.Fatalf("unexpected managed service capability: %#v", fixture.Capability)
	}
	desired, err := DecodeManagedServicesDesiredState(fixture.Desired)
	if err != nil {
		var decoded managedServicesDesiredStateWire
		if decodeErr := strictManagedServicesJSON(fixture.Desired, &decoded); decodeErr == nil {
			canonical, _ := marshalManagedServicesCanonical(decoded.Services)
			t.Fatalf("%v (Go canonical configHash=%s)", err, hashManagedServicesBytes(canonical))
		}
		t.Fatal(err)
	}
	if len(desired.Services) != 2 || desired.Services[1].Kind != managedServicesKindAmneziaWG || desired.Services[1].PublicAddress != "vpn.example.com" {
		t.Fatalf("mixed managed service fixture was not decoded: %#v", desired.Services)
	}
	if managedServicesObservedSignature(fixture.ObservedReport.State) != fixture.ObservedReport.Signature {
		t.Fatal("observed state signature differs across the shared contract")
	}
	pinned, supported := managedServicesArtifacts[runtime.GOARCH]
	if supported {
		artifact := desired.Services[0].Artifact
		artifact.SHA256, artifact.FileSize = pinned.SHA256, pinned.FileSize
		if err = artifact.ValidateForCurrentPlatform(); err != nil {
			t.Fatal(err)
		}
		artifact.SHA256 = strings.Repeat("0", 64)
		if err = artifact.ValidateForCurrentPlatform(); err == nil {
			t.Fatal("unpinned managed service artifact was accepted")
		}
	}

	config := string(renderMTProtoConfig(desired.Services[0]))
	if strings.Contains(config, "api-bind-to") || strings.Contains(config, "exec") ||
		!strings.HasPrefix(config, "bind-to = \"0.0.0.0:24443\"\n\n[secrets]\n") ||
		!strings.HasSuffix(config, "\"forwardx-mtproto-account-22222222-2222-4222-8222-222222222222\" = \"ee000102030405060708090a0b0c0d0e0f6578616d706c652e636f6d\"\n") {
		t.Fatalf("unsafe or unexpected generated config:\n%s", config)
	}
	command := managedServiceCommand(context.Background(), 1234, 1235, "/opt/forwardx-agent/managed-services/mtproto/amd64/mtg-multi", "run", "/etc/forwardx/managed-services/mtproto/service/config.toml")
	if command.Dir != "/" || !reflect.DeepEqual(command.Env, []string{"PATH=/usr/bin:/bin", "LANG=C"}) ||
		!reflect.DeepEqual(command.Args, []string{"/opt/forwardx-agent/managed-services/mtproto/amd64/mtg-multi", "run", "/etc/forwardx/managed-services/mtproto/service/config.toml"}) ||
		command.SysProcAttr == nil || command.SysProcAttr.Credential == nil ||
		command.SysProcAttr.Credential.Uid != 1234 || command.SysProcAttr.Credential.Gid != 1235 ||
		!command.SysProcAttr.Credential.NoSetGroups || command.SysProcAttr.Pdeathsig == 0 || !command.SysProcAttr.Setpgid {
		t.Fatalf("managed service command escaped its fixed identity or argv: %#v", command)
	}

	temporary := t.TempDir()
	safeArchive := filepath.Join(temporary, "safe.tar.gz")
	writeManagedServiceArchive(t, safeArchive, []tar.Header{{Name: "release/mtg-multi", Mode: 0755, Typeflag: tar.TypeReg}}, [][]byte{[]byte("safe-binary")})
	safeBinary := filepath.Join(temporary, "mtg-multi")
	if err = extractManagedServiceArtifact(safeArchive, safeBinary); err != nil {
		t.Fatal(err)
	}
	if contents, readErr := os.ReadFile(safeBinary); readErr != nil || !bytes.Equal(contents, []byte("safe-binary")) {
		t.Fatalf("safe archive was not extracted exactly: %q, %v", contents, readErr)
	}

	unsafeArchive := filepath.Join(temporary, "unsafe.tar.gz")
	writeManagedServiceArchive(t, unsafeArchive, []tar.Header{{Name: "../mtg-multi", Mode: 0755, Typeflag: tar.TypeReg}}, [][]byte{[]byte("escape")})
	if err = extractManagedServiceArtifact(unsafeArchive, filepath.Join(temporary, "escaped")); err == nil {
		t.Fatal("path traversal archive was accepted")
	}
	extraExecutableArchive := filepath.Join(temporary, "extra-executable.tar.gz")
	writeManagedServiceArchive(t, extraExecutableArchive, []tar.Header{{Name: "release/helper", Mode: 0755, Typeflag: tar.TypeReg}}, [][]byte{[]byte("helper")})
	if err = extractManagedServiceArtifact(extraExecutableArchive, filepath.Join(temporary, "extra")); err == nil {
		t.Fatal("archive with an extra executable was accepted")
	}

	var desiredObject map[string]any
	if err = json.Unmarshal(fixture.Desired, &desiredObject); err != nil {
		t.Fatal(err)
	}
	desiredObject["shellCommand"] = "id"
	unknownField, err := json.Marshal(desiredObject)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = DecodeManagedServicesDesiredState(unknownField); err == nil {
		t.Fatal("unknown managed service command field was accepted")
	}
	heartbeatEnvelope := append([]byte(`{"managedServices":`), unknownField...)
	heartbeatEnvelope = append(heartbeatEnvelope, '}')
	var heartbeat struct {
		ManagedServices *ManagedServicesDesiredState `json:"managedServices"`
	}
	if err = json.Unmarshal(heartbeatEnvelope, &heartbeat); err == nil {
		t.Fatal("real heartbeat decoding accepted an unknown managed service command field")
	}
	mutated := desired
	mutated.ConfigHash = strings.Repeat("0", 64)
	if err = mutated.Validate(); err == nil {
		t.Fatal("managed service config hash mismatch was accepted")
	}
	runtimeState := &managedServicesRuntime{restarts: map[int64]int{}, watchdogs: map[int64]int{desired.Services[0].ServiceID: 1}}
	if !runtimeState.watchdogOwnsRecoveryLocked(desired) {
		t.Fatal("active watchdog did not own same-generation recovery")
	}
	runtimeState.watchdogs = map[int64]int{}
	runtimeState.restarts[desired.Services[0].ServiceID] = managedServicesRestartAttempts
	if !runtimeState.watchdogOwnsRecoveryLocked(desired) {
		t.Fatal("exhausted watchdog budget allowed same-generation recovery")
	}
	if !sameManagedServicesApplyIdentity(desired, desired) {
		t.Fatal("identical queued managed service states did not coalesce")
	}
	assertManagedAmneziaWGContractAndRuntime(t, fixture.Desired, desired)
}
