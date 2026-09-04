package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	xrayHeartbeatTaskResultBatchSize = 8
	xrayHeartbeatTaskResultMaxBytes  = 1024 * 1024
)

type XrayTaskError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

type XrayPortProbeResultItem struct {
	Port      int     `json:"port"`
	Available bool    `json:"available"`
	ErrorCode *string `json:"errorCode"`
}

type XrayPortProbeResult struct {
	Ports      []XrayPortProbeResultItem `json:"ports"`
	ObservedAt string                    `json:"observedAt"`
}

type XrayRealityScanResultItem struct {
	Target           string   `json:"target"`
	Host             string   `json:"host"`
	ResolvedIP       string   `json:"resolvedIp"`
	Port             int      `json:"port"`
	Feasible         bool     `json:"feasible"`
	TLS13            bool     `json:"tls13"`
	H2               bool     `json:"h2"`
	X25519           bool     `json:"x25519"`
	CertificateValid bool     `json:"certificateValid"`
	ServerNames      []string `json:"serverNames"`
	LatencyMS        int      `json:"latencyMs"`
	ReasonCode       *string  `json:"reasonCode"`
	ReasonMessage    string   `json:"reasonMessage,omitempty"`
}

type XrayRealityScanResult struct {
	Results    []XrayRealityScanResultItem `json:"results"`
	ObservedAt string                      `json:"observedAt"`
}

type XrayInstallResult struct {
	InstalledVersion string `json:"installedVersion"`
	BinarySHA256     string `json:"binarySha256"`
	Reused           bool   `json:"reused"`
}

type XrayUpgradeResult struct {
	PreviousVersion  *string `json:"previousVersion"`
	InstalledVersion string  `json:"installedVersion"`
	BinarySHA256     string  `json:"binarySha256"`
	RolledBack       bool    `json:"rolledBack"`
}

type XrayRestartResult struct {
	PreviousVersion    *string           `json:"previousVersion"`
	RunningVersion     *string           `json:"runningVersion"`
	ServiceStatus      XrayServiceStatus `json:"serviceStatus"`
	ReadyListenerCount int               `json:"readyListenerCount"`
}

type XrayTaskResult struct {
	SchemaVersion     int                    `json:"schemaVersion"`
	TaskID            string                 `json:"taskId"`
	Type              XrayTaskType           `json:"type"`
	Status            XrayTaskResultStatus   `json:"status"`
	StartedAt         string                 `json:"startedAt"`
	FinishedAt        string                 `json:"finishedAt"`
	Error             *XrayTaskError         `json:"error"`
	PortProbeResult   *XrayPortProbeResult   `json:"-"`
	RealityScanResult *XrayRealityScanResult `json:"-"`
	InstallResult     *XrayInstallResult     `json:"-"`
	UpgradeResult     *XrayUpgradeResult     `json:"-"`
	RestartResult     *XrayRestartResult     `json:"-"`
}

type xrayTaskResultEnvelope struct {
	SchemaVersion int                  `json:"schemaVersion"`
	TaskID        string               `json:"taskId"`
	Type          XrayTaskType         `json:"type"`
	Status        XrayTaskResultStatus `json:"status"`
	StartedAt     string               `json:"startedAt"`
	FinishedAt    string               `json:"finishedAt"`
	Result        json.RawMessage      `json:"result"`
	Error         *XrayTaskError       `json:"error"`
}

type xrayTaskResultJSON struct {
	SchemaVersion int                  `json:"schemaVersion"`
	TaskID        string               `json:"taskId"`
	Type          XrayTaskType         `json:"type"`
	Status        XrayTaskResultStatus `json:"status"`
	StartedAt     string               `json:"startedAt"`
	FinishedAt    string               `json:"finishedAt"`
	Result        any                  `json:"result"`
	Error         *XrayTaskError       `json:"error"`
}

func appendXrayTaskResultsToHeartbeat(payload map[string]any, root string, requestedLimit ...int) map[string]struct{} {
	limit := xrayHeartbeatTaskResultBatchSize
	if len(requestedLimit) > 0 && requestedLimit[0] > 0 && requestedLimit[0] < limit {
		limit = requestedLimit[0]
	}
	submitted := make(map[string]struct{})
	directory := filepath.Join(filepath.Clean(root), "task-results")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return submitted
	}
	results := make([]json.RawMessage, 0, limit)
	totalBytes := 0
	for _, entry := range entries {
		if len(results) >= limit || entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		taskID := strings.TrimSuffix(entry.Name(), ".json")
		if taskID+".json" != entry.Name() || validateXrayIdentifier("taskId", taskID) != nil {
			continue
		}
		result, readErr := readPersistedXrayTaskResultAt(root, taskID)
		if readErr != nil || result == nil {
			continue
		}
		raw, marshalErr := json.Marshal(result)
		if marshalErr != nil || len(raw) == 0 || len(raw) > XrayMaxTaskResultBytes {
			continue
		}
		if totalBytes+len(raw) > xrayHeartbeatTaskResultMaxBytes {
			break
		}
		results = append(results, json.RawMessage(raw))
		submitted[taskID] = struct{}{}
		totalBytes += len(raw)
	}
	if len(results) > 0 {
		payload["xrayTaskResults"] = results
	}
	return submitted
}

func acknowledgeXrayTaskResultsAt(root string, accepted []string, submitted map[string]struct{}) {
	directory := filepath.Join(filepath.Clean(root), "task-results")
	removed := false
	for _, taskID := range accepted {
		if _, ok := submitted[taskID]; !ok || validateXrayIdentifier("taskId", taskID) != nil {
			continue
		}
		path := filepath.Join(directory, taskID+".json")
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if os.Remove(path) == nil {
			removed = true
		}
	}
	if removed {
		_ = syncXrayDirectory(directory)
	}
}

func (result XrayTaskResult) MarshalJSON() ([]byte, error) {
	var typed any
	switch result.Type {
	case XrayTaskPortProbe:
		typed = result.PortProbeResult
	case XrayTaskRealityScan:
		typed = result.RealityScanResult
	case XrayTaskInstall:
		typed = result.InstallResult
	case XrayTaskUpgrade:
		typed = result.UpgradeResult
	case XrayTaskRestart:
		typed = result.RestartResult
	}
	return json.Marshal(xrayTaskResultJSON{
		SchemaVersion: result.SchemaVersion,
		TaskID:        result.TaskID,
		Type:          result.Type,
		Status:        result.Status,
		StartedAt:     result.StartedAt,
		FinishedAt:    result.FinishedAt,
		Result:        typed,
		Error:         result.Error,
	})
}

func DecodeXrayTaskResult(raw []byte) (XrayTaskResult, error) {
	var result XrayTaskResult
	object, err := decodeXrayObject(raw, XrayMaxTaskResultBytes, xrayObservedForbiddenKeys)
	if err != nil {
		return result, err
	}
	if err := requireXrayFields(object, "schemaVersion", "taskId", "type", "status", "startedAt", "finishedAt"); err != nil {
		return result, err
	}
	var envelope xrayTaskResultEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return result, fmt.Errorf("decode Xray task result: %w", err)
	}
	result.SchemaVersion = envelope.SchemaVersion
	result.TaskID = envelope.TaskID
	result.Type = envelope.Type
	result.Status = envelope.Status
	result.StartedAt = envelope.StartedAt
	result.FinishedAt = envelope.FinishedAt
	result.Error = envelope.Error
	if envelope.Error != nil {
		if errorRaw := object["error"]; !isXrayJSONNull(errorRaw) {
			errorObject, objectErr := decodeXrayObject(errorRaw, 0, xrayObservedForbiddenKeys)
			if objectErr != nil {
				return result, objectErr
			}
			if objectErr = requireXrayFields(errorObject, "code", "message", "retryable"); objectErr != nil {
				return result, objectErr
			}
		}
	}
	if len(envelope.Result) > 0 && !isXrayJSONNull(envelope.Result) {
		if err := result.decodeTypedResult(envelope.Result); err != nil {
			return result, err
		}
	}
	return result, result.Validate()
}

func (result *XrayTaskResult) decodeTypedResult(raw []byte) error {
	switch result.Type {
	case XrayTaskPortProbe:
		var typed XrayPortProbeResult
		object, err := decodeXrayObject(raw, 0, xrayObservedForbiddenKeys)
		if err != nil {
			return err
		}
		if err = requireXrayFields(object, "ports", "observedAt"); err != nil {
			return err
		}
		if err = requireXrayArrayObjectFields(object, "ports", "port", "available", "errorCode"); err != nil {
			return err
		}
		if err = json.Unmarshal(raw, &typed); err != nil {
			return err
		}
		result.PortProbeResult = &typed
	case XrayTaskRealityScan:
		var typed XrayRealityScanResult
		object, err := decodeXrayObject(raw, 0, xrayObservedForbiddenKeys)
		if err != nil {
			return err
		}
		if err = requireXrayFields(object, "results", "observedAt"); err != nil {
			return err
		}
		if err = requireXrayArrayObjectFields(object, "results",
			"target", "host", "resolvedIp", "port", "feasible", "tls13", "h2", "x25519",
			"certificateValid", "serverNames", "latencyMs", "reasonCode"); err != nil {
			return err
		}
		if err = json.Unmarshal(raw, &typed); err != nil {
			return err
		}
		result.RealityScanResult = &typed
	case XrayTaskInstall:
		var typed XrayInstallResult
		if err := decodeXrayJSONObject(raw, 0, xrayObservedForbiddenKeys, &typed, "installedVersion", "binarySha256", "reused"); err != nil {
			return err
		}
		result.InstallResult = &typed
	case XrayTaskUpgrade:
		var typed XrayUpgradeResult
		if err := decodeXrayJSONObject(raw, 0, xrayObservedForbiddenKeys, &typed,
			"previousVersion", "installedVersion", "binarySha256", "rolledBack"); err != nil {
			return err
		}
		result.UpgradeResult = &typed
	case XrayTaskRestart:
		var typed XrayRestartResult
		if err := decodeXrayJSONObject(raw, 0, xrayObservedForbiddenKeys, &typed,
			"previousVersion", "runningVersion", "serviceStatus", "readyListenerCount"); err != nil {
			return err
		}
		result.RestartResult = &typed
	default:
		return fmt.Errorf("unsupported Xray task result type %q", result.Type)
	}
	return nil
}

func (result XrayTaskResult) Validate() error {
	if result.SchemaVersion != XraySchemaVersion {
		return fmt.Errorf("unsupported Xray task result schemaVersion %d", result.SchemaVersion)
	}
	if err := validateXrayIdentifier("taskId", result.TaskID); err != nil {
		return err
	}
	startedAt, err := parseXrayTimestamp("startedAt", result.StartedAt)
	if err != nil {
		return err
	}
	finishedAt, err := parseXrayTimestamp("finishedAt", result.FinishedAt)
	if err != nil {
		return err
	}
	if finishedAt.Before(startedAt) {
		return fmt.Errorf("Xray finishedAt must not be earlier than startedAt")
	}
	if !validXrayTaskResultStatus(result.Status) {
		return fmt.Errorf("invalid Xray task result status %q", result.Status)
	}
	if result.Error != nil {
		if err := result.Error.Validate(); err != nil {
			return err
		}
	}
	typedResultCount := 0
	for _, present := range []bool{
		result.PortProbeResult != nil, result.RealityScanResult != nil, result.InstallResult != nil,
		result.UpgradeResult != nil, result.RestartResult != nil,
	} {
		if present {
			typedResultCount++
		}
	}
	if typedResultCount > 1 {
		return fmt.Errorf("Xray task result contains multiple typed results")
	}
	if result.Status == XrayTaskResultSuccess {
		if typedResultCount != 1 || result.Error != nil {
			return fmt.Errorf("successful Xray task must contain one result and no error")
		}
	} else if result.Error == nil {
		return fmt.Errorf("non-successful Xray task must contain an error")
	}
	switch result.Type {
	case XrayTaskPortProbe:
		if typedResultCount > 0 && result.PortProbeResult == nil {
			return fmt.Errorf("Xray task result type does not match typed result")
		}
		if result.PortProbeResult != nil {
			return result.PortProbeResult.Validate()
		}
	case XrayTaskRealityScan:
		if typedResultCount > 0 && result.RealityScanResult == nil {
			return fmt.Errorf("Xray task result type does not match typed result")
		}
		if result.RealityScanResult != nil {
			return result.RealityScanResult.Validate()
		}
	case XrayTaskInstall:
		if typedResultCount > 0 && result.InstallResult == nil {
			return fmt.Errorf("Xray task result type does not match typed result")
		}
		if result.InstallResult != nil {
			return result.InstallResult.Validate()
		}
	case XrayTaskUpgrade:
		if typedResultCount > 0 && result.UpgradeResult == nil {
			return fmt.Errorf("Xray task result type does not match typed result")
		}
		if result.UpgradeResult != nil {
			return result.UpgradeResult.Validate()
		}
	case XrayTaskRestart:
		if typedResultCount > 0 && result.RestartResult == nil {
			return fmt.Errorf("Xray task result type does not match typed result")
		}
		if result.RestartResult != nil {
			return result.RestartResult.Validate()
		}
	default:
		return fmt.Errorf("unsupported Xray task result type %q", result.Type)
	}
	return nil
}

func (taskError XrayTaskError) Validate() error {
	if err := validateXrayErrorCode(taskError.Code); err != nil {
		return err
	}
	if len(taskError.Message) > XrayMaxErrorMessageBytes {
		return fmt.Errorf("Xray task error message exceeds size limit")
	}
	return nil
}

func (result XrayPortProbeResult) Validate() error {
	if len(result.Ports) < 1 || len(result.Ports) > XrayMaxPortProbeCandidates {
		return fmt.Errorf("invalid Xray port probe result count")
	}
	for _, item := range result.Ports {
		if err := validateXrayPort(item.Port); err != nil {
			return err
		}
		if item.Available == (item.ErrorCode != nil) {
			return fmt.Errorf("Xray port availability and errorCode disagree")
		}
		if item.ErrorCode != nil {
			if err := validateXrayErrorCode(*item.ErrorCode); err != nil {
				return err
			}
		}
	}
	return validateXrayTimestamp("observedAt", result.ObservedAt)
}

func (result XrayRealityScanResult) Validate() error {
	if len(result.Results) > XrayMaxRealityTargets {
		return fmt.Errorf("too many Xray Reality scan results")
	}
	for _, item := range result.Results {
		if err := item.Validate(); err != nil {
			return err
		}
	}
	return validateXrayTimestamp("observedAt", result.ObservedAt)
}

func (item XrayRealityScanResultItem) Validate() error {
	if err := validateXrayRealityTarget(item.Target); err != nil {
		return err
	}
	if err := validateXrayString("host", item.Host, 253); err != nil {
		return err
	}
	if err := validateXrayString("resolvedIp", item.ResolvedIP, 64); err != nil {
		return err
	}
	if item.Port < 1 || item.Port > 65535 || item.LatencyMS < 0 || item.LatencyMS > 60_000 {
		return fmt.Errorf("invalid Xray Reality scan port or latency")
	}
	if len(item.ServerNames) > 16 {
		return fmt.Errorf("too many Xray Reality serverNames")
	}
	for _, serverName := range item.ServerNames {
		if err := validateXrayString("serverName", serverName, 253); err != nil {
			return err
		}
	}
	if item.ReasonCode != nil {
		if err := validateXrayErrorCode(*item.ReasonCode); err != nil {
			return err
		}
	}
	if len(item.ReasonMessage) > XrayMaxErrorMessageBytes {
		return fmt.Errorf("Xray Reality reason message exceeds size limit")
	}
	return nil
}

func (result XrayInstallResult) Validate() error {
	if err := validateXrayVersion(result.InstalledVersion); err != nil {
		return err
	}
	if !xraySHA256Pattern.MatchString(result.BinarySHA256) {
		return fmt.Errorf("invalid installed Xray binarySha256")
	}
	return nil
}

func (result XrayUpgradeResult) Validate() error {
	if result.PreviousVersion != nil {
		if err := validateXrayVersion(*result.PreviousVersion); err != nil {
			return err
		}
	}
	return XrayInstallResult{InstalledVersion: result.InstalledVersion, BinarySHA256: result.BinarySHA256}.Validate()
}

func (result XrayRestartResult) Validate() error {
	for _, version := range []*string{result.PreviousVersion, result.RunningVersion} {
		if version != nil {
			if err := validateXrayVersion(*version); err != nil {
				return err
			}
		}
	}
	if !validXrayServiceStatus(result.ServiceStatus) || result.ReadyListenerCount < 0 || int64(result.ReadyListenerCount) > XrayMaxSafeInteger {
		return fmt.Errorf("invalid Xray restart result")
	}
	return nil
}
