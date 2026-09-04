package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type xrayArtifactZipEntry struct {
	name string
	data []byte
	mode os.FileMode
}

func xrayArtifactTestBinary(t *testing.T) []byte {
	t.Helper()
	path, err := exec.LookPath("true")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func xrayArtifactZip(t *testing.T, entries ...xrayArtifactZipEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Deflate}
		header.SetMode(entry.mode)
		file, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func xrayArtifactPayload(archive []byte) XrayArtifactTaskPayload {
	digest := sha256.Sum256(archive)
	return XrayArtifactTaskPayload{
		ArtifactID:   7,
		Version:      XrayManagedVersion,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		Size:         int64(len(archive)),
		SHA256:       hex.EncodeToString(digest[:]),
		DownloadPath: "/api/agent/artifacts/xray/7",
	}
}

func xrayArtifactServer(
	t *testing.T,
	archive []byte,
	payload XrayArtifactTaskPayload,
) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	requests := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.URL.Path != payload.DownloadPath || request.URL.RawQuery != "" {
			response.WriteHeader(http.StatusNotFound)
			return
		}
		if !strings.HasPrefix(request.Header.Get("Authorization"), "Bearer ") {
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		if request.Header.Get(XrayAgentOSHeader) != payload.OS || request.Header.Get(XrayAgentArchHeader) != payload.Arch {
			response.WriteHeader(http.StatusForbidden)
			return
		}
		response.Header().Set(agentAuthResultHeader, agentAuthResultAccepted)
		response.Header().Set("Content-Type", "application/octet-stream")
		response.Header().Set("Content-Length", stringInt64(payload.Size))
		response.Header().Set("ETag", `"sha256:`+payload.SHA256+`"`)
		response.Header().Set("X-ForwardX-Artifact-SHA256", payload.SHA256)
		response.Header().Set("X-ForwardX-Artifact-Version", payload.Version)
		response.Header().Set("X-ForwardX-Artifact-OS", payload.OS)
		response.Header().Set("X-ForwardX-Artifact-Arch", payload.Arch)
		_, _ = response.Write(archive)
	}))
	return server, requests
}

func stringInt64(value int64) string {
	return strconv.FormatInt(value, 10)
}

func testXrayArtifactInstaller(root string, client *http.Client) *xrayArtifactInstaller {
	installer := newXrayArtifactInstaller(root, client)
	installer.platformOS = runtime.GOOS
	installer.platformArch = runtime.GOARCH
	installer.runVersion = func(context.Context, string) ([]byte, error) {
		return []byte("Xray 26.3.27 (Xray, Penetrates Everything.)\n"), nil
	}
	return installer
}

func TestXrayManagedVersionIsApproved(t *testing.T) {
	if XrayManagedVersion != "v26.3.27" {
		t.Fatalf("XrayManagedVersion = %q, want v26.3.27", XrayManagedVersion)
	}
}

func requireXrayArtifactErrorCode(t *testing.T, err error, code XrayAgentErrorCode) {
	t.Helper()
	var artifactError *XrayArtifactInstallError
	if !errors.As(err, &artifactError) {
		t.Fatalf("error = %T %v, want XrayArtifactInstallError", err, err)
	}
	if artifactError.Code != code {
		t.Fatalf("error code = %q, want %q", artifactError.Code, code)
	}
}

func TestXrayArtifactInstallIsAuthenticatedAtomicAndIdempotent(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("Xray v1 artifacts support linux-amd64 and linux-arm64")
	}
	binaryData := xrayArtifactTestBinary(t)
	archive := xrayArtifactZip(t,
		xrayArtifactZipEntry{name: "xray", data: binaryData, mode: 0755},
		xrayArtifactZipEntry{name: "README.md", data: []byte("official documentation"), mode: 0644},
	)
	payload := xrayArtifactPayload(archive)
	server, requests := xrayArtifactServer(t, archive, payload)
	defer server.Close()

	root := t.TempDir()
	sentinel := filepath.Join(root, "sentinel-current")
	if err := os.MkdirAll(sentinel, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sentinel-current", filepath.Join(root, "current")); err != nil {
		t.Fatal(err)
	}
	installer := testXrayArtifactInstaller(root, server.Client())
	cfg := Config{PanelURL: server.URL, Token: "artifact-test-token"}

	first, err := installer.Install(context.Background(), cfg, "artifact-task-1", payload)
	if err != nil {
		t.Fatal(err)
	}
	if first.Reused || first.InstalledVersion != XrayManagedVersion || !xraySHA256Pattern.MatchString(first.BinarySHA256) {
		t.Fatalf("unexpected first install result: %#v", first)
	}
	target := filepath.Join(root, "versions", XrayManagedVersion, runtime.GOOS+"-"+runtime.GOARCH)
	info, err := os.Lstat(filepath.Join(target, "xray"))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		t.Fatalf("installed binary mode = %v", info.Mode())
	}
	if link, err := os.Readlink(filepath.Join(root, "current")); err != nil || link != "sentinel-current" {
		t.Fatalf("current link changed: link=%q err=%v", link, err)
	}
	if entries, err := os.ReadDir(filepath.Join(root, "downloads")); err != nil || len(entries) != 0 {
		t.Fatalf("download staging was not cleaned: entries=%v err=%v", entries, err)
	}

	secondPayload := payload
	secondPayload.ArtifactID = 8
	secondPayload.DownloadPath = "/api/agent/artifacts/xray/8"
	second, err := installer.Install(context.Background(), cfg, "artifact-task-2", secondPayload)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Reused || second.BinarySHA256 != first.BinarySHA256 {
		t.Fatalf("unexpected reused result: %#v", second)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("artifact requests = %d, want 1", got)
	}
	if mode := mustFileMode(t, root).Perm(); mode != 0700 {
		t.Fatalf("managed root mode = %o, want 0700", mode)
	}
}

func TestXrayArtifactRejectsUnsafeAndMalformedArchives(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("Xray v1 artifacts support linux-amd64 and linux-arm64")
	}
	binaryData := xrayArtifactTestBinary(t)
	tests := []struct {
		name    string
		archive func(*testing.T) []byte
	}{
		{name: "corrupt zip", archive: func(*testing.T) []byte { return []byte("not a zip archive") }},
		{name: "parent traversal", archive: func(t *testing.T) []byte {
			return xrayArtifactZip(t,
				xrayArtifactZipEntry{name: "../escape", data: []byte("escape"), mode: 0644},
				xrayArtifactZipEntry{name: "xray", data: binaryData, mode: 0755},
			)
		}},
		{name: "absolute path", archive: func(t *testing.T) []byte {
			return xrayArtifactZip(t,
				xrayArtifactZipEntry{name: "/tmp/escape", data: []byte("escape"), mode: 0644},
				xrayArtifactZipEntry{name: "xray", data: binaryData, mode: 0755},
			)
		}},
		{name: "backslash traversal", archive: func(t *testing.T) []byte {
			return xrayArtifactZip(t,
				xrayArtifactZipEntry{name: `..\escape`, data: []byte("escape"), mode: 0644},
				xrayArtifactZipEntry{name: "xray", data: binaryData, mode: 0755},
			)
		}},
		{name: "symbolic link", archive: func(t *testing.T) []byte {
			return xrayArtifactZip(t,
				xrayArtifactZipEntry{name: "linked", data: []byte("/tmp/escape"), mode: os.ModeSymlink | 0777},
				xrayArtifactZipEntry{name: "xray", data: binaryData, mode: 0755},
			)
		}},
		{name: "device", archive: func(t *testing.T) []byte {
			return xrayArtifactZip(t,
				xrayArtifactZipEntry{name: "device", data: nil, mode: os.ModeDevice | 0600},
				xrayArtifactZipEntry{name: "xray", data: binaryData, mode: 0755},
			)
		}},
		{name: "extra executable", archive: func(t *testing.T) []byte {
			return xrayArtifactZip(t,
				xrayArtifactZipEntry{name: "install.sh", data: []byte("#!/bin/sh"), mode: 0755},
				xrayArtifactZipEntry{name: "xray", data: binaryData, mode: 0755},
			)
		}},
		{name: "duplicate binary", archive: func(t *testing.T) []byte {
			return xrayArtifactZip(t,
				xrayArtifactZipEntry{name: "xray", data: binaryData, mode: 0755},
				xrayArtifactZipEntry{name: "xray", data: binaryData, mode: 0755},
			)
		}},
		{name: "missing binary", archive: func(t *testing.T) []byte {
			return xrayArtifactZip(t, xrayArtifactZipEntry{name: "README.md", data: []byte("none"), mode: 0644})
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archive := test.archive(t)
			payload := xrayArtifactPayload(archive)
			server, _ := xrayArtifactServer(t, archive, payload)
			defer server.Close()
			root := t.TempDir()
			installer := testXrayArtifactInstaller(root, server.Client())
			_, err := installer.Install(context.Background(), Config{PanelURL: server.URL, Token: "artifact-token"}, "unsafe-task", payload)
			if err == nil {
				t.Fatal("unsafe artifact was installed")
			}
			requireXrayArtifactErrorCode(t, err, XrayErrorInvalidPayload)
			for _, escaped := range []string{filepath.Join(root, "escape"), filepath.Join(root, "versions", "escape")} {
				if _, statErr := os.Lstat(escaped); !os.IsNotExist(statErr) {
					t.Fatalf("archive escaped to %s: %v", escaped, statErr)
				}
			}
		})
	}
}

func TestXrayArtifactRejectsSizeHashArchitectureAndVersionMismatch(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("Xray v1 artifacts support linux-amd64 and linux-arm64")
	}
	binaryData := xrayArtifactTestBinary(t)
	archive := xrayArtifactZip(t, xrayArtifactZipEntry{name: "xray", data: binaryData, mode: 0755})

	t.Run("size", func(t *testing.T) {
		payload := xrayArtifactPayload(archive)
		payload.Size++
		server, _ := xrayArtifactServer(t, archive, payload)
		defer server.Close()
		_, err := testXrayArtifactInstaller(t.TempDir(), server.Client()).Install(
			context.Background(), Config{PanelURL: server.URL, Token: "token"}, "size-task", payload,
		)
		requireXrayArtifactErrorCode(t, err, XrayErrorArtifactSizeMismatch)
	})

	t.Run("hash", func(t *testing.T) {
		payload := xrayArtifactPayload(archive)
		payload.SHA256 = strings.Repeat("0", 64)
		server, _ := xrayArtifactServer(t, archive, payload)
		defer server.Close()
		_, err := testXrayArtifactInstaller(t.TempDir(), server.Client()).Install(
			context.Background(), Config{PanelURL: server.URL, Token: "token"}, "hash-task", payload,
		)
		requireXrayArtifactErrorCode(t, err, XrayErrorArtifactHashMismatch)
	})

	t.Run("task platform", func(t *testing.T) {
		payload := xrayArtifactPayload(archive)
		if payload.Arch == "amd64" {
			payload.Arch = "arm64"
		} else {
			payload.Arch = "amd64"
		}
		installer := testXrayArtifactInstaller(t.TempDir(), http.DefaultClient)
		_, err := installer.Install(context.Background(), Config{PanelURL: "https://panel.invalid", Token: "token"}, "platform-task", payload)
		requireXrayArtifactErrorCode(t, err, XrayErrorArtifactArchMismatch)
	})

	t.Run("binary architecture", func(t *testing.T) {
		wrongBinary := append([]byte(nil), binaryData...)
		if runtime.GOARCH == "amd64" {
			binary.LittleEndian.PutUint16(wrongBinary[18:20], 183)
		} else {
			binary.LittleEndian.PutUint16(wrongBinary[18:20], 62)
		}
		wrongArchive := xrayArtifactZip(t, xrayArtifactZipEntry{name: "xray", data: wrongBinary, mode: 0755})
		payload := xrayArtifactPayload(wrongArchive)
		server, _ := xrayArtifactServer(t, wrongArchive, payload)
		defer server.Close()
		_, err := testXrayArtifactInstaller(t.TempDir(), server.Client()).Install(
			context.Background(), Config{PanelURL: server.URL, Token: "token"}, "arch-task", payload,
		)
		requireXrayArtifactErrorCode(t, err, XrayErrorArtifactArchMismatch)
	})

	t.Run("binary version", func(t *testing.T) {
		payload := xrayArtifactPayload(archive)
		server, _ := xrayArtifactServer(t, archive, payload)
		defer server.Close()
		installer := testXrayArtifactInstaller(t.TempDir(), server.Client())
		installer.runVersion = func(context.Context, string) ([]byte, error) { return []byte("Xray 0.0.1\n"), nil }
		_, err := installer.Install(context.Background(), Config{PanelURL: server.URL, Token: "token"}, "version-task", payload)
		requireXrayArtifactErrorCode(t, err, XrayErrorVersionMismatch)
	})

	t.Run("download cap", func(t *testing.T) {
		payload := xrayArtifactPayload(archive)
		payload.Size = XrayArtifactMaxDownloadBytes + 1
		installer := testXrayArtifactInstaller(t.TempDir(), http.DefaultClient)
		_, err := installer.Install(context.Background(), Config{PanelURL: "https://panel.invalid", Token: "token"}, "large-task", payload)
		requireXrayArtifactErrorCode(t, err, XrayErrorInvalidPayload)
	})

	t.Run("redirect", func(t *testing.T) {
		var redirectedRequests atomic.Int32
		target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			redirectedRequests.Add(1)
			response.WriteHeader(http.StatusOK)
		}))
		defer target.Close()
		payload := xrayArtifactPayload(archive)
		redirect := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			response.Header().Set(agentAuthResultHeader, agentAuthResultAccepted)
			http.Redirect(response, request, target.URL+payload.DownloadPath, http.StatusFound)
		}))
		defer redirect.Close()
		_, err := testXrayArtifactInstaller(t.TempDir(), redirect.Client()).Install(
			context.Background(), Config{PanelURL: redirect.URL, Token: "token"}, "redirect-task", payload,
		)
		requireXrayArtifactErrorCode(t, err, XrayErrorArtifactNotFound)
		if redirectedRequests.Load() != 0 {
			t.Fatal("artifact downloader followed a redirect away from the panel endpoint")
		}
	})
}

func TestXrayArtifactRejectsManagedDirectorySymlink(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("Xray v1 artifacts support linux-amd64 and linux-arm64")
	}
	archive := xrayArtifactZip(t, xrayArtifactZipEntry{name: "xray", data: xrayArtifactTestBinary(t), mode: 0755})
	payload := xrayArtifactPayload(archive)
	server, requests := xrayArtifactServer(t, archive, payload)
	defer server.Close()
	root := t.TempDir()
	external := t.TempDir()
	if err := os.Symlink(external, filepath.Join(root, "downloads")); err != nil {
		t.Fatal(err)
	}
	_, err := testXrayArtifactInstaller(root, server.Client()).Install(
		context.Background(), Config{PanelURL: server.URL, Token: "token"}, "symlink-task", payload,
	)
	requireXrayArtifactErrorCode(t, err, XrayErrorInternal)
	if requests.Load() != 0 {
		t.Fatal("artifact request started through a symlinked managed directory")
	}
	entries, readErr := os.ReadDir(external)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("symlink target was modified: entries=%v err=%v", entries, readErr)
	}
}

func TestXrayArtifactTaskResultPersistsWhenPanelIsUnavailable(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("Xray v1 artifacts support linux-amd64 and linux-arm64")
	}
	archive := xrayArtifactZip(t, xrayArtifactZipEntry{name: "xray", data: xrayArtifactTestBinary(t), mode: 0755})
	payload := xrayArtifactPayload(archive)
	server, _ := xrayArtifactServer(t, archive, payload)
	panelURL := server.URL
	client := server.Client()
	server.Close()

	root := t.TempDir()
	installer := testXrayArtifactInstaller(root, client)
	now := time.Now().UTC()
	task := XrayTask{
		SchemaVersion:  XraySchemaVersion,
		TaskID:         "offline-result-task",
		Type:           XrayTaskInstall,
		CreatedAt:      now.Add(-time.Second).Format(time.RFC3339Nano),
		ExpiresAt:      now.Add(time.Minute).Format(time.RFC3339Nano),
		InstallPayload: &payload,
	}
	result := runXrayArtifactTask(context.Background(), Config{PanelURL: panelURL, Token: "offline-token"}, task, installer)
	if result.Status != XrayTaskResultFailed || result.Error == nil {
		t.Fatalf("unexpected offline result: %#v", result)
	}
	resultPath := filepath.Join(root, "task-results", task.TaskID+".json")
	raw, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeXrayTaskResult(raw)
	if err != nil {
		t.Fatal(err)
	}
	if restored.TaskID != task.TaskID || restored.Status != XrayTaskResultFailed || restored.Error == nil {
		t.Fatalf("unexpected restored result: %#v", restored)
	}
	if mode := mustFileMode(t, resultPath).Perm(); mode != 0600 {
		t.Fatalf("result mode = %o, want 0600", mode)
	}
	if matches, err := filepath.Glob(filepath.Join(root, "task-results", "*.tmp")); err != nil || len(matches) != 0 {
		t.Fatalf("result temp files = %v, err=%v", matches, err)
	}

	success := XrayTaskResult{
		SchemaVersion: XraySchemaVersion,
		TaskID:        "successful-install-result",
		Type:          XrayTaskInstall,
		Status:        XrayTaskResultSuccess,
		StartedAt:     now.Format(time.RFC3339Nano),
		FinishedAt:    now.Add(time.Second).Format(time.RFC3339Nano),
		InstallResult: &XrayInstallResult{
			InstalledVersion: XrayManagedVersion,
			BinarySHA256:     strings.Repeat("a", 64),
			Reused:           true,
		},
	}
	if err := persistXrayTaskResultAt(root, success); err != nil {
		t.Fatal(err)
	}
	successRaw, err := os.ReadFile(filepath.Join(root, "task-results", success.TaskID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	successRestored, err := DecodeXrayTaskResult(successRaw)
	if err != nil {
		t.Fatal(err)
	}
	if successRestored.InstallResult == nil || !successRestored.InstallResult.Reused || successRestored.InstallResult.BinarySHA256 != strings.Repeat("a", 64) {
		t.Fatalf("successful typed result did not round trip: %#v", successRestored)
	}
}

func TestXrayArtifactTaskDispatchIsBoundedAndIdempotent(t *testing.T) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		t.Skip("Xray v1 artifacts support linux-amd64 and linux-arm64")
	}
	archive := xrayArtifactZip(t, xrayArtifactZipEntry{name: "xray", data: xrayArtifactTestBinary(t), mode: 0755})
	payload := xrayArtifactPayload(archive)
	server, requests := xrayArtifactServer(t, archive, payload)
	defer server.Close()

	now := time.Now().UTC()
	task := XrayTask{
		SchemaVersion: XraySchemaVersion, TaskID: "dispatched-install-task", Type: XrayTaskInstall,
		CreatedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		InstallPayload: &payload,
	}
	wireTask := func(value XrayTask) []byte {
		raw, marshalErr := json.Marshal(map[string]any{
			"schemaVersion": value.SchemaVersion, "taskId": value.TaskID, "type": value.Type,
			"createdAt": value.CreatedAt, "expiresAt": value.ExpiresAt, "payload": payload,
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return raw
	}
	raw := wireTask(task)
	installer := testXrayArtifactInstaller(t.TempDir(), server.Client())
	cfg := Config{PanelURL: server.URL, Token: "bounded-secret-token"}
	first, handled := dispatchManagedXrayTask(context.Background(), cfg, raw, newXrayPortProbeRunner(t.TempDir()), nil, installer)
	if !handled || first.Status != XrayTaskResultSuccess || first.InstallResult == nil || first.InstallResult.Reused {
		t.Fatalf("first dispatch = %#v handled=%v", first, handled)
	}
	second, handled := dispatchManagedXrayTask(context.Background(), cfg, raw, newXrayPortProbeRunner(t.TempDir()), nil, installer)
	if !handled || second.Status != XrayTaskResultSuccess || second.InstallResult == nil || second.InstallResult.Reused {
		t.Fatalf("second dispatch = %#v handled=%v", second, handled)
	}
	firstRaw, _ := json.Marshal(first)
	secondRaw, _ := json.Marshal(second)
	if !bytes.Equal(firstRaw, secondRaw) || requests.Load() != 1 {
		t.Fatalf("duplicate dispatch changed result or download count: first=%s second=%s requests=%d", firstRaw, secondRaw, requests.Load())
	}

	expired := task
	expired.TaskID = "expired-install-task"
	expired.CreatedAt = now.Add(-2 * time.Minute).Format(time.RFC3339Nano)
	expired.ExpiresAt = now.Add(-time.Minute).Format(time.RFC3339Nano)
	expiredRaw := wireTask(expired)
	expiredResult, handled := dispatchManagedXrayTask(context.Background(), cfg, expiredRaw, newXrayPortProbeRunner(t.TempDir()), nil, installer)
	if !handled || expiredResult.Status != XrayTaskResultRejected || expiredResult.Error == nil || expiredResult.Error.Code != string(XrayErrorTaskExpired) {
		t.Fatalf("expired dispatch = %#v handled=%v", expiredResult, handled)
	}
	if requests.Load() != 1 {
		t.Fatalf("expired task performed a download: requests=%d", requests.Load())
	}
}

func mustFileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode()
}
