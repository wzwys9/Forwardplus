package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
)

const (
	xrayRuntimeStateFile          = "state.json"
	xrayRuntimeStateVersion       = 1
	xrayRuntimeStateMaxBytes      = 256 * 1024
	xrayRuntimeApplyMarkerFile    = "apply-pending.json"
	xrayRuntimeApplyMarkerVersion = 1
)

type xrayRuntimeApplyMarker struct {
	Version       int              `json:"version"`
	PreviousState xrayRuntimeState `json:"previousState"`
}

type xrayRuntimeState struct {
	Version             int                    `json:"version"`
	DesiredRunning      bool                   `json:"desiredRunning"`
	AppliedGeneration   int64                  `json:"appliedGeneration"`
	AppliedConfigHash   string                 `json:"appliedConfigHash"`
	CurrentVersion      string                 `json:"currentVersion"`
	CurrentBinarySHA256 string                 `json:"currentBinarySha256"`
	ExpectedListeners   []XrayExpectedListener `json:"expectedListeners"`
}

func (state xrayRuntimeState) Validate() error {
	if state.Version != xrayRuntimeStateVersion || state.AppliedGeneration < 0 || state.AppliedGeneration > XrayMaxSafeInteger {
		return errors.New("invalid Xray runtime state version or generation")
	}
	if !xraySHA256Pattern.MatchString(state.AppliedConfigHash) || !xraySHA256Pattern.MatchString(state.CurrentBinarySHA256) {
		return errors.New("invalid Xray runtime state hash")
	}
	if !xrayVersionPattern.MatchString(state.CurrentVersion) {
		return errors.New("invalid Xray runtime state version")
	}
	if len(state.ExpectedListeners) > XrayMaxExpectedListeners {
		return errors.New("too many Xray runtime listeners")
	}
	for _, listener := range state.ExpectedListeners {
		if err := listener.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func ensurePrivateXrayDirectory(directory string) error {
	directory = filepath.Clean(directory)
	if !filepath.IsAbs(directory) {
		return errXrayUnmanagedPath
	}
	volume := filepath.VolumeName(directory)
	current := string(filepath.Separator)
	if volume != "" {
		current = volume + string(filepath.Separator)
	}
	relative := strings.TrimPrefix(directory, current)
	for _, segment := range strings.Split(relative, string(filepath.Separator)) {
		if segment == "" || segment == "." || segment == ".." {
			return errXrayUnmanagedPath
		}
		current = filepath.Join(current, segment)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, 0700); err != nil {
				return err
			}
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !xrayPathOwnerAllowed(info, current == directory) {
			return errXrayUnmanagedPath
		}
	}
	return os.Chmod(directory, 0700)
}

func writeAtomicXrayFile(path string, raw []byte, mode os.FileMode) error {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) || filepath.Base(path) == "." || (mode != 0600 && mode != 0700) {
		return errXrayUnmanagedPath
	}
	directory := filepath.Dir(path)
	if err := ensurePrivateXrayDirectory(directory); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !xrayPathOwnerAllowed(info, true) {
			return errXrayUnmanagedPath
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".forwardx-xray-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return syncXrayDirectory(directory)
}

func removeXrayFile(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || info.IsDir() || !xrayPathOwnerAllowed(info, true) {
		return errXrayUnmanagedPath
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncXrayDirectory(filepath.Dir(path))
}

func validateXrayVersionBinaryPath(root, binaryPath string) error {
	root = filepath.Clean(root)
	binaryPath = filepath.Clean(binaryPath)
	versionsRoot := filepath.Join(root, "versions")
	relative, err := filepath.Rel(versionsRoot, binaryPath)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errXrayUnmanagedPath
	}
	segments := strings.Split(relative, string(filepath.Separator))
	if len(segments) != 3 || !xrayVersionPattern.MatchString(segments[0]) ||
		(segments[1] != "linux-amd64" && segments[1] != "linux-arm64") || segments[2] != "xray" {
		return errXrayUnmanagedPath
	}
	return validateManagedXrayFile(root, binaryPath, 0700)
}

func switchCurrentXrayBinary(root, binaryPath string) error {
	root = filepath.Clean(root)
	binaryPath = filepath.Clean(binaryPath)
	if err := validateXrayVersionBinaryPath(root, binaryPath); err != nil {
		return err
	}
	if err := ensurePrivateXrayDirectory(root); err != nil {
		return err
	}
	currentPath := filepath.Join(root, "current")
	if info, err := os.Lstat(currentPath); err == nil {
		if info.Mode()&os.ModeSymlink == 0 || !xrayPathOwnerAllowed(info, true) {
			return errXrayUnmanagedPath
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	temporary, err := os.CreateTemp(root, ".current-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Remove(temporaryPath); err != nil {
		return err
	}
	defer os.Remove(temporaryPath)
	target, err := filepath.Rel(root, binaryPath)
	if err != nil || filepath.IsAbs(target) || filepath.Clean(target) != target || strings.HasPrefix(target, "..") {
		return errXrayUnmanagedPath
	}
	if err := os.Symlink(target, temporaryPath); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, currentPath); err != nil {
		return err
	}
	return syncXrayDirectory(root)
}

func readCurrentXrayBinary(root string) (string, error) {
	root = filepath.Clean(root)
	currentPath := filepath.Join(root, "current")
	info, err := os.Lstat(currentPath)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink == 0 || !xrayPathOwnerAllowed(info, true) {
		return "", errXrayUnmanagedPath
	}
	target, err := os.Readlink(currentPath)
	if err != nil || target == "" || filepath.IsAbs(target) || filepath.Clean(target) != target {
		return "", errXrayUnmanagedPath
	}
	binaryPath := filepath.Join(root, target)
	if err := validateXrayVersionBinaryPath(root, binaryPath); err != nil {
		return "", err
	}
	return filepath.Clean(binaryPath), nil
}

func writeXrayRuntimeStateAt(root string, state xrayRuntimeState) error {
	if err := state.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return writeAtomicXrayFile(filepath.Join(root, xrayRuntimeStateFile), raw, 0600)
}

func readXrayRuntimeStateAt(root string) (*xrayRuntimeState, error) {
	rootInfo, rootErr := os.Lstat(filepath.Clean(root))
	if os.IsNotExist(rootErr) {
		return nil, nil
	}
	if rootErr != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || !xrayPathOwnerAllowed(rootInfo, true) {
		return nil, errXrayUnmanagedPath
	}
	path := filepath.Join(root, xrayRuntimeStateFile)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || !xrayPathOwnerAllowed(info, true) {
		return nil, errXrayUnmanagedPath
	}
	raw, err := readBoundedXrayFile(path, xrayRuntimeStateMaxBytes)
	if err != nil {
		return nil, err
	}
	var state xrayRuntimeState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil {
		return nil, err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("invalid trailing Xray runtime state")
	}
	if err := state.Validate(); err != nil {
		return nil, err
	}
	return &state, nil
}

func (runtimeManager *xrayRuntime) beginApplyTransaction(snapshot xrayRuntimeSnapshot) error {
	if snapshot.state == nil || !snapshot.hasConfig || !snapshot.hasCurrent {
		return nil
	}
	marker := xrayRuntimeApplyMarker{Version: xrayRuntimeApplyMarkerVersion, PreviousState: *snapshot.state}
	raw, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	return writeAtomicXrayFile(filepath.Join(runtimeManager.managedRoot, xrayRuntimeApplyMarkerFile), raw, 0600)
}

func (runtimeManager *xrayRuntime) finishApplyTransaction() error {
	return removeXrayFile(filepath.Join(runtimeManager.managedRoot, xrayRuntimeApplyMarkerFile))
}

func readXrayRuntimeApplyMarker(root string) (*xrayRuntimeApplyMarker, error) {
	path := filepath.Join(filepath.Clean(root), xrayRuntimeApplyMarkerFile)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || !xrayPathOwnerAllowed(info, true) {
		return nil, errXrayUnmanagedPath
	}
	raw, err := readBoundedXrayFile(path, xrayRuntimeStateMaxBytes)
	if err != nil {
		return nil, err
	}
	var marker xrayRuntimeApplyMarker
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&marker); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		marker.Version != xrayRuntimeApplyMarkerVersion || marker.PreviousState.Validate() != nil {
		return nil, errors.New("invalid Xray apply marker")
	}
	return &marker, nil
}

func (runtimeManager *xrayRuntime) recoverInterruptedApply() error {
	marker, err := readXrayRuntimeApplyMarker(runtimeManager.managedRoot)
	if err != nil || marker == nil {
		return err
	}
	currentState, err := readXrayRuntimeStateAt(runtimeManager.managedRoot)
	if err != nil {
		return err
	}
	if currentState != nil && !reflect.DeepEqual(*currentState, marker.PreviousState) {
		if _, err := runtimeManager.snapshot(); err != nil {
			return err
		}
		return runtimeManager.finishApplyTransaction()
	}
	configPath := filepath.Join(runtimeManager.configRoot, "last-good.json")
	hashPath := filepath.Join(runtimeManager.configRoot, "last-good.json.sha256")
	for _, path := range []string{configPath, hashPath} {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || !xrayPathOwnerAllowed(info, true) {
			return errXrayUnmanagedPath
		}
	}
	config, err := readBoundedXrayFile(configPath, XrayMaxConfigJSONBytes)
	if err != nil {
		return err
	}
	hashRaw, err := readBoundedXrayFile(hashPath, 128)
	if err != nil {
		return err
	}
	configHash := strings.TrimSpace(string(hashRaw))
	if configHash != marker.PreviousState.AppliedConfigHash || hashXrayBytes(config) != configHash {
		return errXrayConfigHashMismatch
	}
	binaryPath := filepath.Join(runtimeManager.managedRoot, "versions", marker.PreviousState.CurrentVersion, "linux-"+runtime.GOARCH, "xray")
	if err := validateXrayVersionBinaryPath(runtimeManager.managedRoot, binaryPath); err != nil {
		return err
	}
	binaryHash, err := sha256File(binaryPath, xrayArtifactMaxBinaryBytes)
	if err != nil || binaryHash != marker.PreviousState.CurrentBinarySHA256 {
		return errXrayBinaryHashMismatch
	}
	if err := writeAtomicXrayFile(filepath.Join(runtimeManager.configRoot, "config.json"), config, 0600); err != nil {
		return err
	}
	if err := writeAtomicXrayFile(filepath.Join(runtimeManager.configRoot, "config.json.sha256"), []byte(configHash+"\n"), 0600); err != nil {
		return err
	}
	if err := switchCurrentXrayBinary(runtimeManager.managedRoot, binaryPath); err != nil {
		return err
	}
	if err := runtimeManager.writeState(runtimeManager.managedRoot, marker.PreviousState); err != nil {
		return err
	}
	return runtimeManager.finishApplyTransaction()
}
