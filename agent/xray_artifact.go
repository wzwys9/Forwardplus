package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	archivepath "path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	XrayManagedVersion             = "v26.3.27"
	XrayAgentOSHeader              = "X-ForwardX-Xray-OS"
	XrayAgentArchHeader            = "X-ForwardX-Xray-Arch"
	XrayArtifactMaxDownloadBytes   = int64(128 * 1024 * 1024)
	xrayArtifactMaxUnpackedBytes   = uint64(256 * 1024 * 1024)
	xrayArtifactMaxBinaryBytes     = uint64(128 * 1024 * 1024)
	xrayArtifactMaxArchiveEntries  = 128
	xrayArtifactDownloadTimeout    = 2 * time.Minute
	xrayArtifactVersionTimeout     = 10 * time.Second
	xrayArtifactVersionOutputLimit = 8 * 1024
	xrayArtifactManifestMaxBytes   = 64 * 1024
	xrayManagedRoot                = "/var/lib/forwardx-agent/xray"
)

var xrayVersionOutputPattern = regexp.MustCompile(`(?m)^Xray[ \t]+v?([0-9]+\.[0-9]+\.[0-9]+)(?:[ \t]|$)`)
var xrayArtifactInstallMu sync.Mutex

type XrayArtifactInstallError struct {
	Code      XrayAgentErrorCode
	Message   string
	Retryable bool
	cause     error
}

func (installError *XrayArtifactInstallError) Error() string {
	if installError == nil {
		return "Xray artifact installation failed"
	}
	return installError.Message
}

func (installError *XrayArtifactInstallError) Unwrap() error {
	if installError == nil {
		return nil
	}
	return installError.cause
}

func newXrayArtifactInstallError(code XrayAgentErrorCode, message string, retryable bool, cause error) error {
	return &XrayArtifactInstallError{Code: code, Message: message, Retryable: retryable, cause: cause}
}

type xrayArtifactInstaller struct {
	root         string
	client       *http.Client
	platformOS   string
	platformArch string
	runVersion   func(context.Context, string) ([]byte, error)
	now          func() time.Time
}

type installedXrayArtifactManifest struct {
	Version       string `json:"version"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	ArchiveSHA256 string `json:"archiveSha256"`
	ArchiveSize   int64  `json:"archiveSize"`
	BinarySHA256  string `json:"binarySha256"`
}

func newXrayArtifactInstaller(root string, client *http.Client) *xrayArtifactInstaller {
	if client == nil {
		client = agentSyncHTTPClient
	}
	return &xrayArtifactInstaller{
		root:         root,
		client:       client,
		platformOS:   runtime.GOOS,
		platformArch: runtime.GOARCH,
		runVersion:   runManagedXrayVersion,
		now:          time.Now,
	}
}

func installManagedXrayArtifact(ctx context.Context, cfg Config, taskID string, payload XrayArtifactTaskPayload) (XrayInstallResult, error) {
	return newXrayArtifactInstaller(xrayManagedRoot, agentSyncHTTPClient).Install(ctx, cfg, taskID, payload)
}

func (installer *xrayArtifactInstaller) Install(
	ctx context.Context,
	cfg Config,
	taskID string,
	payload XrayArtifactTaskPayload,
) (XrayInstallResult, error) {
	if installer == nil {
		return XrayInstallResult{}, newXrayArtifactInstallError(XrayErrorInternal, "The Xray artifact installer is unavailable", true, nil)
	}
	xrayArtifactInstallMu.Lock()
	defer xrayArtifactInstallMu.Unlock()

	if err := payload.Validate(); err != nil {
		return XrayInstallResult{}, newXrayArtifactInstallError(XrayErrorInvalidPayload, "Invalid Xray artifact payload", false, err)
	}
	if err := validateXrayIdentifier("taskId", taskID); err != nil {
		return XrayInstallResult{}, newXrayArtifactInstallError(XrayErrorInvalidPayload, "Invalid Xray artifact task identity", false, err)
	}
	if payload.Version != XrayManagedVersion {
		return XrayInstallResult{}, newXrayArtifactInstallError(XrayErrorVersionMismatch, "The Xray artifact version is not approved", false, nil)
	}
	if installer.platformOS != "linux" || (installer.platformArch != "amd64" && installer.platformArch != "arm64") {
		return XrayInstallResult{}, newXrayArtifactInstallError(XrayErrorHostPlatformUnsupported, "The Agent platform does not support managed Xray", false, nil)
	}
	if payload.OS != installer.platformOS || payload.Arch != installer.platformArch {
		return XrayInstallResult{}, newXrayArtifactInstallError(XrayErrorArtifactArchMismatch, "The Xray artifact does not match the Agent platform", false, nil)
	}
	if payload.Size > XrayArtifactMaxDownloadBytes {
		return XrayInstallResult{}, newXrayArtifactInstallError(XrayErrorInvalidPayload, "The Xray artifact exceeds the download limit", false, nil)
	}
	if strings.TrimSpace(installer.root) == "" || !filepath.IsAbs(installer.root) {
		return XrayInstallResult{}, newXrayArtifactInstallError(XrayErrorInternal, "The managed Xray storage is unavailable", true, nil)
	}
	if installer.client == nil || installer.runVersion == nil {
		return XrayInstallResult{}, newXrayArtifactInstallError(XrayErrorInternal, "The Xray artifact installer is unavailable", true, nil)
	}
	if err := ensureXrayManagedDirectories(installer.root); err != nil {
		return XrayInstallResult{}, newXrayArtifactInstallError(XrayErrorInternal, "The managed Xray storage is unavailable", true, err)
	}

	versionRoot, err := ensureXrayManagedSubdirectory(installer.root, "versions", payload.Version)
	if err != nil {
		return XrayInstallResult{}, newXrayArtifactInstallError(XrayErrorInternal, "The managed Xray version storage is unavailable", true, err)
	}
	target := filepath.Join(versionRoot, payload.OS+"-"+payload.Arch)
	manifest := installedXrayArtifactManifest{
		Version:       payload.Version,
		OS:            payload.OS,
		Arch:          payload.Arch,
		ArchiveSHA256: payload.SHA256,
		ArchiveSize:   payload.Size,
	}
	if _, statErr := os.Lstat(target); statErr == nil {
		binarySHA256, reuseErr := installer.validateInstalled(ctx, target, manifest)
		if reuseErr != nil {
			return XrayInstallResult{}, reuseErr
		}
		return XrayInstallResult{InstalledVersion: payload.Version, BinarySHA256: binarySHA256, Reused: true}, nil
	} else if !os.IsNotExist(statErr) {
		return XrayInstallResult{}, newXrayArtifactInstallError(XrayErrorInternal, "The managed Xray version cannot be inspected", true, statErr)
	}

	downloadPath := filepath.Join(installer.root, "downloads", taskID+".part")
	if err := removeXrayFile(downloadPath); err != nil {
		return XrayInstallResult{}, newXrayArtifactInstallError(XrayErrorInternal, "The Xray download staging file is unavailable", true, err)
	}
	defer removeXrayFile(downloadPath)
	if err := installer.download(ctx, cfg, payload, downloadPath); err != nil {
		return XrayInstallResult{}, err
	}

	staging, err := os.MkdirTemp(versionRoot, ".install-"+payload.OS+"-"+payload.Arch+"-")
	if err != nil {
		return XrayInstallResult{}, newXrayArtifactInstallError(XrayErrorInternal, "The Xray install staging directory is unavailable", true, err)
	}
	defer os.RemoveAll(staging)
	if err := os.Chmod(staging, 0700); err != nil {
		return XrayInstallResult{}, newXrayArtifactInstallError(XrayErrorInternal, "The Xray install staging directory is unavailable", true, err)
	}
	if err := extractManagedXrayArchive(downloadPath, staging); err != nil {
		return XrayInstallResult{}, err
	}
	binarySHA256, err := installer.validateBinary(ctx, filepath.Join(staging, "xray"), payload.Version, payload.Arch)
	if err != nil {
		return XrayInstallResult{}, err
	}
	manifest.BinarySHA256 = binarySHA256
	if err := writePersistentJSON(filepath.Join(staging, "artifact.json"), manifest); err != nil {
		return XrayInstallResult{}, newXrayArtifactInstallError(XrayErrorInternal, "The Xray artifact manifest could not be persisted", true, err)
	}
	if err := syncXrayDirectory(staging); err != nil {
		return XrayInstallResult{}, newXrayArtifactInstallError(XrayErrorInternal, "The Xray install staging directory could not be synchronized", true, err)
	}
	if err := os.Rename(staging, target); err != nil {
		if _, statErr := os.Lstat(target); statErr == nil {
			if reusedSHA, reuseErr := installer.validateInstalled(ctx, target, manifest); reuseErr == nil {
				return XrayInstallResult{InstalledVersion: payload.Version, BinarySHA256: reusedSHA, Reused: true}, nil
			}
		}
		return XrayInstallResult{}, newXrayArtifactInstallError(XrayErrorInternal, "The Xray version could not be installed atomically", true, err)
	}
	if err := syncXrayDirectory(versionRoot); err != nil {
		return XrayInstallResult{}, newXrayArtifactInstallError(XrayErrorInternal, "The Xray version directory could not be synchronized", true, err)
	}
	return XrayInstallResult{InstalledVersion: payload.Version, BinarySHA256: binarySHA256, Reused: false}, nil
}

func ensureXrayManagedDirectories(root string) error {
	if err := ensurePrivateXrayDirectory(root); err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !xrayPathOwnerAllowed(info, true) {
		return errors.New("managed Xray root is not a regular directory")
	}
	if err := os.Chmod(root, 0700); err != nil {
		return err
	}
	for _, child := range []string{"downloads", "versions", "task-results"} {
		if _, err := ensureXrayManagedSubdirectory(root, child); err != nil {
			return err
		}
	}
	return nil
}

func ensureXrayManagedSubdirectory(root string, segments ...string) (string, error) {
	current := filepath.Clean(root)
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." || filepath.Base(segment) != segment {
			return "", errors.New("invalid managed Xray directory segment")
		}
		current = filepath.Join(current, segment)
		if err := os.Mkdir(current, 0700); err != nil && !os.IsExist(err) {
			return "", err
		}
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !xrayPathOwnerAllowed(info, true) {
			return "", errors.New("managed Xray path contains a non-directory")
		}
		if err := os.Chmod(current, 0700); err != nil {
			return "", err
		}
	}
	return current, nil
}

func (installer *xrayArtifactInstaller) download(
	ctx context.Context,
	cfg Config,
	payload XrayArtifactTaskPayload,
	destination string,
) error {
	panelURL := normalizePanelURL(currentPanelURL(cfg))
	if panelURL == "" {
		return newXrayArtifactInstallError(XrayErrorArtifactNotFound, "The panel artifact endpoint is unavailable", true, nil)
	}
	base, err := url.Parse(panelURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return newXrayArtifactInstallError(XrayErrorArtifactNotFound, "The panel artifact endpoint is unavailable", true, err)
	}
	downloadURL, err := url.Parse(strings.TrimRight(panelURL, "/") + payload.DownloadPath)
	if err != nil || downloadURL.Scheme != base.Scheme || downloadURL.Host != base.Host || downloadURL.RawQuery != "" || downloadURL.Fragment != "" {
		return newXrayArtifactInstallError(XrayErrorInvalidPayload, "The Xray artifact download path is invalid", false, err)
	}
	downloadContext, cancel := context.WithTimeout(ctx, xrayArtifactDownloadTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(downloadContext, http.MethodGet, downloadURL.String(), nil)
	if err != nil {
		return newXrayArtifactInstallError(XrayErrorInvalidPayload, "The Xray artifact request is invalid", false, err)
	}
	auth, err := newAgentRequestAuth(request.Context(), installer.client, panelURL, cfg.Token, request.Method, request.URL.Path, nil)
	if err != nil {
		return newXrayArtifactInstallError(XrayErrorArtifactNotFound, "The panel artifact authentication is unavailable", true, err)
	}
	request.Header.Set("Authorization", "Bearer "+auth.proof)
	request.Header.Set(XrayAgentOSHeader, payload.OS)
	request.Header.Set(XrayAgentArchHeader, payload.Arch)
	downloadClient := *installer.client
	downloadClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := downloadClient.Do(request)
	if err != nil {
		return newXrayArtifactInstallError(XrayErrorArtifactNotFound, "The panel artifact download failed", true, err)
	}
	defer response.Body.Close()
	observeAgentAuthCapability(panelURL, response.Header.Get(agentAuthCapabilityHeader))
	authResult := strings.TrimSpace(response.Header.Get(agentAuthResultHeader))
	if auth.version == "v2" && strings.EqualFold(authResult, agentAuthResultRejected) {
		invalidateAgentAuthChallenges(panelURL, auth.challengeGeneration)
	}
	if !strings.EqualFold(authResult, agentAuthResultAccepted) {
		return newXrayArtifactInstallError(XrayErrorArtifactNotFound, "The panel artifact response was not authenticated", true, nil)
	}
	if response.StatusCode != http.StatusOK {
		code := XrayErrorArtifactNotFound
		retryable := response.StatusCode >= 500 || response.StatusCode == http.StatusNotFound
		if response.StatusCode == http.StatusForbidden {
			code = XrayErrorArtifactArchMismatch
			retryable = false
		}
		return newXrayArtifactInstallError(code, "The panel artifact is unavailable", retryable, nil)
	}
	if response.ContentLength != payload.Size {
		return newXrayArtifactInstallError(XrayErrorArtifactSizeMismatch, "The Xray artifact size does not match", false, nil)
	}
	if response.Header.Get("X-ForwardX-Artifact-SHA256") != payload.SHA256 || response.Header.Get("ETag") != `"sha256:`+payload.SHA256+`"` {
		return newXrayArtifactInstallError(XrayErrorArtifactHashMismatch, "The Xray artifact hash metadata does not match", false, nil)
	}
	if response.Header.Get("X-ForwardX-Artifact-Version") != payload.Version {
		return newXrayArtifactInstallError(XrayErrorVersionMismatch, "The Xray artifact version metadata does not match", false, nil)
	}
	if response.Header.Get("X-ForwardX-Artifact-OS") != payload.OS || response.Header.Get("X-ForwardX-Artifact-Arch") != payload.Arch {
		return newXrayArtifactInstallError(XrayErrorArtifactArchMismatch, "The Xray artifact platform metadata does not match", false, nil)
	}

	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return newXrayArtifactInstallError(XrayErrorInternal, "The Xray download staging file is unavailable", true, err)
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, payload.Size+1))
	syncErr := file.Sync()
	closeErr := file.Close()
	if written != payload.Size {
		return newXrayArtifactInstallError(XrayErrorArtifactSizeMismatch, "The Xray artifact size does not match", false, copyErr)
	}
	if copyErr != nil {
		return newXrayArtifactInstallError(XrayErrorArtifactNotFound, "The Xray artifact download failed", true, copyErr)
	}
	if syncErr != nil || closeErr != nil {
		return newXrayArtifactInstallError(XrayErrorInternal, "The Xray download could not be synchronized", true, errors.Join(syncErr, closeErr))
	}
	if hex.EncodeToString(hash.Sum(nil)) != payload.SHA256 {
		return newXrayArtifactInstallError(XrayErrorArtifactHashMismatch, "The Xray artifact hash does not match", false, nil)
	}
	return nil
}

func validXrayArchivePath(name string) (string, bool) {
	if name == "" || strings.ContainsRune(name, '\x00') || strings.Contains(name, `\`) || strings.HasPrefix(name, "/") {
		return "", false
	}
	if len(name) >= 2 && ((name[0] >= 'A' && name[0] <= 'Z') || (name[0] >= 'a' && name[0] <= 'z')) && name[1] == ':' {
		return "", false
	}
	clean := archivepath.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || clean != strings.TrimSuffix(name, "/") {
		return "", false
	}
	return clean, true
}

func extractManagedXrayArchive(archivePath, destination string) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return newXrayArtifactInstallError(XrayErrorInvalidPayload, "The Xray artifact archive is invalid", false, err)
	}
	defer reader.Close()
	if len(reader.File) == 0 || len(reader.File) > xrayArtifactMaxArchiveEntries {
		return newXrayArtifactInstallError(XrayErrorInvalidPayload, "The Xray artifact archive entry count is invalid", false, nil)
	}
	seen := make(map[string]struct{}, len(reader.File))
	var total uint64
	foundBinary := false
	for _, entry := range reader.File {
		name, valid := validXrayArchivePath(entry.Name)
		if !valid {
			return newXrayArtifactInstallError(XrayErrorInvalidPayload, "The Xray artifact archive contains an unsafe path", false, nil)
		}
		if _, duplicate := seen[name]; duplicate {
			return newXrayArtifactInstallError(XrayErrorInvalidPayload, "The Xray artifact archive contains duplicate entries", false, nil)
		}
		seen[name] = struct{}{}
		mode := entry.Mode()
		if entry.Flags&0x1 != 0 || mode&os.ModeSymlink != 0 || (!mode.IsRegular() && !mode.IsDir()) {
			return newXrayArtifactInstallError(XrayErrorInvalidPayload, "The Xray artifact archive contains an unsupported entry", false, nil)
		}
		if mode.IsDir() {
			continue
		}
		if mode.Perm()&0111 != 0 && name != "xray" {
			return newXrayArtifactInstallError(XrayErrorInvalidPayload, "The Xray artifact archive contains an extra executable", false, nil)
		}
		if entry.UncompressedSize64 > xrayArtifactMaxUnpackedBytes-total {
			return newXrayArtifactInstallError(XrayErrorInvalidPayload, "The Xray artifact archive expands beyond the limit", false, nil)
		}
		total += entry.UncompressedSize64
		if name != "xray" {
			continue
		}
		if foundBinary || entry.UncompressedSize64 == 0 || entry.UncompressedSize64 > xrayArtifactMaxBinaryBytes {
			return newXrayArtifactInstallError(XrayErrorInvalidPayload, "The Xray artifact binary entry is invalid", false, nil)
		}
		foundBinary = true
		input, openErr := entry.Open()
		if openErr != nil {
			return newXrayArtifactInstallError(XrayErrorInvalidPayload, "The Xray artifact binary cannot be read", false, openErr)
		}
		output, createErr := os.OpenFile(filepath.Join(destination, "xray"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
		if createErr != nil {
			input.Close()
			return newXrayArtifactInstallError(XrayErrorInternal, "The Xray binary staging file cannot be created", true, createErr)
		}
		written, copyErr := io.Copy(output, io.LimitReader(input, int64(entry.UncompressedSize64)+1))
		inputErr := input.Close()
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil || inputErr != nil || syncErr != nil || closeErr != nil || uint64(written) != entry.UncompressedSize64 {
			return newXrayArtifactInstallError(XrayErrorInvalidPayload, "The Xray artifact binary extraction failed", false,
				errors.Join(copyErr, inputErr, syncErr, closeErr))
		}
		if err := os.Chmod(filepath.Join(destination, "xray"), 0700); err != nil {
			return newXrayArtifactInstallError(XrayErrorInternal, "The Xray binary permissions could not be applied", true, err)
		}
	}
	if !foundBinary {
		return newXrayArtifactInstallError(XrayErrorInvalidPayload, "The Xray artifact archive does not contain the managed binary", false, nil)
	}
	return nil
}

func (installer *xrayArtifactInstaller) validateBinary(ctx context.Context, binaryPath, expectedVersion, expectedArch string) (string, error) {
	info, err := os.Lstat(binaryPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0111 == 0 {
		return "", newXrayArtifactInstallError(XrayErrorInvalidPayload, "The extracted Xray binary is invalid", false, err)
	}
	elfFile, err := elf.Open(binaryPath)
	if err != nil {
		return "", newXrayArtifactInstallError(XrayErrorArtifactArchMismatch, "The Xray binary format does not match Linux", false, err)
	}
	expectedMachine := elf.EM_NONE
	switch expectedArch {
	case "amd64":
		expectedMachine = elf.EM_X86_64
	case "arm64":
		expectedMachine = elf.EM_AARCH64
	}
	machineMatches := elfFile.Class == elf.ELFCLASS64 && elfFile.Machine == expectedMachine && (elfFile.Type == elf.ET_EXEC || elfFile.Type == elf.ET_DYN)
	_ = elfFile.Close()
	if !machineMatches {
		return "", newXrayArtifactInstallError(XrayErrorArtifactArchMismatch, "The Xray binary architecture does not match the Agent", false, nil)
	}
	binarySHA256, err := sha256File(binaryPath, xrayArtifactMaxBinaryBytes)
	if err != nil {
		return "", newXrayArtifactInstallError(XrayErrorInvalidPayload, "The Xray binary cannot be verified", false, err)
	}
	output, err := installer.runVersion(ctx, binaryPath)
	if err != nil || len(output) > xrayArtifactVersionOutputLimit {
		return "", newXrayArtifactInstallError(XrayErrorVersionMismatch, "The Xray binary version check failed", false, err)
	}
	match := xrayVersionOutputPattern.FindSubmatch(output)
	if len(match) != 2 || "v"+string(match[1]) != expectedVersion {
		return "", newXrayArtifactInstallError(XrayErrorVersionMismatch, "The Xray binary reported an unexpected version", false, nil)
	}
	return binarySHA256, nil
}

func (installer *xrayArtifactInstaller) validateInstalled(
	ctx context.Context,
	target string,
	expected installedXrayArtifactManifest,
) (string, error) {
	info, err := os.Lstat(target)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", newXrayArtifactInstallError(XrayErrorInvalidPayload, "The existing Xray version directory is invalid", false, err)
	}
	raw, err := readBoundedXrayFile(filepath.Join(target, "artifact.json"), xrayArtifactManifestMaxBytes)
	if err != nil {
		return "", newXrayArtifactInstallError(XrayErrorInvalidPayload, "The existing Xray artifact manifest is invalid", false, err)
	}
	var current installedXrayArtifactManifest
	if json.Unmarshal(raw, &current) != nil || current.Version != expected.Version || current.OS != expected.OS || current.Arch != expected.Arch ||
		current.ArchiveSHA256 != expected.ArchiveSHA256 || current.ArchiveSize != expected.ArchiveSize ||
		!xraySHA256Pattern.MatchString(current.BinarySHA256) {
		return "", newXrayArtifactInstallError(XrayErrorInvalidPayload, "The existing Xray artifact manifest does not match", false, nil)
	}
	binarySHA256, err := installer.validateBinary(ctx, filepath.Join(target, "xray"), expected.Version, expected.Arch)
	if err != nil {
		return "", err
	}
	if binarySHA256 != current.BinarySHA256 {
		return "", newXrayArtifactInstallError(XrayErrorArtifactHashMismatch, "The existing Xray binary hash does not match", false, nil)
	}
	return binarySHA256, nil
}

type boundedXrayOutput struct {
	mu        sync.Mutex
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (output *boundedXrayOutput) Write(data []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	remaining := output.limit - output.buffer.Len()
	if remaining > 0 {
		if len(data) > remaining {
			_, _ = output.buffer.Write(data[:remaining])
			output.truncated = true
		} else {
			_, _ = output.buffer.Write(data)
		}
	} else if len(data) > 0 {
		output.truncated = true
	}
	return len(data), nil
}

func runManagedXrayVersion(ctx context.Context, binaryPath string) ([]byte, error) {
	versionContext, cancel := context.WithTimeout(ctx, xrayArtifactVersionTimeout)
	defer cancel()
	output := &boundedXrayOutput{limit: xrayArtifactVersionOutputLimit}
	command := exec.CommandContext(versionContext, binaryPath, "version")
	command.Dir = filepath.Dir(binaryPath)
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	if versionContext.Err() != nil {
		return output.buffer.Bytes(), versionContext.Err()
	}
	if output.truncated {
		return output.buffer.Bytes(), errors.New("Xray version output exceeded the limit")
	}
	return output.buffer.Bytes(), err
}

func sha256File(path string, maxSize uint64) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !xrayPathOwnerAllowed(info, true) || info.Size() <= 0 || uint64(info.Size()) > maxSize {
		return "", errors.New("invalid file for SHA-256")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, int64(maxSize)+1))
	if err != nil || written != info.Size() {
		return "", errors.New("file changed during SHA-256 verification")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func readBoundedXrayFile(path string, maxSize int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !xrayPathOwnerAllowed(info, true) || info.Size() <= 0 || info.Size() > maxSize {
		return nil, errors.New("invalid bounded Xray file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, maxSize+1))
}

func syncXrayDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func persistXrayTaskResultAt(root string, result XrayTaskResult) error {
	if err := result.Validate(); err != nil {
		return err
	}
	if err := ensureXrayManagedDirectories(root); err != nil {
		return err
	}
	return writePersistentJSON(filepath.Join(root, "task-results", result.TaskID+".json"), result)
}

func runXrayArtifactTask(
	ctx context.Context,
	cfg Config,
	task XrayTask,
	installer *xrayArtifactInstaller,
) XrayTaskResult {
	startedAt := installer.now().UTC()
	result := XrayTaskResult{
		SchemaVersion: XraySchemaVersion,
		TaskID:        task.TaskID,
		Type:          task.Type,
		Status:        XrayTaskResultFailed,
		StartedAt:     startedAt.Format(time.RFC3339Nano),
	}
	payload := task.InstallPayload
	if task.Type == XrayTaskUpgrade {
		payload = task.UpgradePayload
	}
	if err := task.Validate(); err != nil || payload == nil || (task.Type != XrayTaskInstall && task.Type != XrayTaskUpgrade) {
		result.Status = XrayTaskResultRejected
		result.Error = &XrayTaskError{Code: string(XrayErrorInvalidPayload), Message: "Invalid Xray artifact task", Retryable: false}
	} else if expiresAt, parseErr := parseXrayTimestamp("expiresAt", task.ExpiresAt); parseErr != nil || !expiresAt.After(startedAt) {
		result.Status = XrayTaskResultRejected
		result.Error = &XrayTaskError{Code: string(XrayErrorTaskExpired), Message: "The Xray artifact task has expired", Retryable: false}
	} else {
		var previousVersion *string
		if task.Type == XrayTaskUpgrade {
			if state, stateErr := readXrayRuntimeStateAt(installer.root); stateErr == nil && state != nil && state.CurrentVersion != "" {
				version := state.CurrentVersion
				previousVersion = &version
			}
		}
		installed, installErr := installer.Install(ctx, cfg, task.TaskID, *payload)
		if installErr == nil {
			result.Status = XrayTaskResultSuccess
			if task.Type == XrayTaskInstall {
				result.InstallResult = &installed
			} else {
				result.UpgradeResult = &XrayUpgradeResult{
					PreviousVersion:  previousVersion,
					InstalledVersion: installed.InstalledVersion,
					BinarySHA256:     installed.BinarySHA256,
					RolledBack:       false,
				}
			}
		} else {
			var artifactError *XrayArtifactInstallError
			if errors.As(installErr, &artifactError) {
				result.Error = &XrayTaskError{Code: string(artifactError.Code), Message: artifactError.Message, Retryable: artifactError.Retryable}
			} else {
				result.Error = &XrayTaskError{Code: string(XrayErrorInternal), Message: "The Xray artifact task failed", Retryable: true}
			}
		}
	}
	result.FinishedAt = installer.now().UTC().Format(time.RFC3339Nano)
	if err := persistXrayTaskResultAt(installer.root, result); err != nil {
		logf("Xray task result persist failed task=%s type=%s", taskLogIdentifier(task.TaskID), task.Type)
	}
	return result
}
