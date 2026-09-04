package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	XraySchemaVersion                  = 1
	XrayMaxConfigJSONBytes             = 1024 * 1024
	XrayMaxExpectedListeners           = 256
	XrayMaxPortProbeCandidates         = 32
	XrayMaxRealityTargets              = 64
	XrayMaxRealityConcurrency          = 16
	XrayMaxRealityTimeoutMS            = 10_000
	XrayMaxControlPayloadBytes         = 256 * 1024
	XrayMaxTaskResultBytes             = 256 * 1024
	XrayMaxErrorMessageBytes           = 2 * 1024
	XrayMaxProtocolIdentifierLen       = 128
	XrayMaxSafeInteger           int64 = 1<<53 - 1
)

type XrayTaskType string

const (
	XrayTaskPortProbe   XrayTaskType = "PORT_PROBE"
	XrayTaskRealityScan XrayTaskType = "REALITY_SCAN"
	XrayTaskInstall     XrayTaskType = "INSTALL"
	XrayTaskUpgrade     XrayTaskType = "UPGRADE"
	XrayTaskRestart     XrayTaskType = "RESTART"
)

type XrayTaskResultStatus string

const (
	XrayTaskResultSuccess  XrayTaskResultStatus = "SUCCESS"
	XrayTaskResultFailed   XrayTaskResultStatus = "FAILED"
	XrayTaskResultTimeout  XrayTaskResultStatus = "TIMEOUT"
	XrayTaskResultRejected XrayTaskResultStatus = "REJECTED"
)

type XrayServiceStatus string

const (
	XrayServiceRunning XrayServiceStatus = "RUNNING"
	XrayServiceStopped XrayServiceStatus = "STOPPED"
	XrayServiceError   XrayServiceStatus = "ERROR"
	XrayServiceUnknown XrayServiceStatus = "UNKNOWN"
)

type XrayListenerStatus string

const (
	XrayListenerReady        XrayListenerStatus = "READY"
	XrayListenerMissing      XrayListenerStatus = "MISSING"
	XrayListenerWrongProcess XrayListenerStatus = "WRONG_PROCESS"
	XrayListenerUnknown      XrayListenerStatus = "UNKNOWN"
)

type XrayAgentErrorCode string

const (
	XrayErrorCapabilityUnsupported   XrayAgentErrorCode = "CAPABILITY_UNSUPPORTED"
	XrayErrorTaskExpired             XrayAgentErrorCode = "TASK_EXPIRED"
	XrayErrorTaskAlreadyCompleted    XrayAgentErrorCode = "TASK_ALREADY_COMPLETED"
	XrayErrorInvalidPayload          XrayAgentErrorCode = "INVALID_PAYLOAD"
	XrayErrorHostPlatformUnsupported XrayAgentErrorCode = "HOST_PLATFORM_UNSUPPORTED"
	XrayErrorPortInUse               XrayAgentErrorCode = "PORT_IN_USE"
	XrayErrorPortBindDenied          XrayAgentErrorCode = "PORT_BIND_DENIED"
	XrayErrorRealityTargetBlocked    XrayAgentErrorCode = "REALITY_TARGET_BLOCKED"
	XrayErrorRealityTLSUnsupported   XrayAgentErrorCode = "REALITY_TLS_UNSUPPORTED"
	XrayErrorArtifactNotFound        XrayAgentErrorCode = "ARTIFACT_NOT_FOUND"
	XrayErrorArtifactSizeMismatch    XrayAgentErrorCode = "ARTIFACT_SIZE_MISMATCH"
	XrayErrorArtifactHashMismatch    XrayAgentErrorCode = "ARTIFACT_HASH_MISMATCH"
	XrayErrorArtifactArchMismatch    XrayAgentErrorCode = "ARTIFACT_ARCH_MISMATCH"
	XrayErrorVersionMismatch         XrayAgentErrorCode = "XRAY_VERSION_MISMATCH"
	XrayErrorConfigInvalid           XrayAgentErrorCode = "CONFIG_INVALID"
	XrayErrorGenerationHashConflict  XrayAgentErrorCode = "GENERATION_HASH_CONFLICT"
	XrayErrorRuntimeStartFailed      XrayAgentErrorCode = "RUNTIME_START_FAILED"
	XrayErrorRuntimeNotReady         XrayAgentErrorCode = "RUNTIME_NOT_READY"
	XrayErrorRollbackFailed          XrayAgentErrorCode = "ROLLBACK_FAILED"
	XrayErrorInternal                XrayAgentErrorCode = "INTERNAL_ERROR"
)

var (
	xrayIdentifierPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)
	xrayErrorCodePattern     = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	xraySHA256Pattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	xrayVersionPattern       = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	xrayRealityTargetPattern = regexp.MustCompile(
		`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?:([1-9][0-9]{0,4})$`,
	)
	xrayObservedForbiddenKeys = map[string]struct{}{
		"agenttoken": {}, "authorization": {}, "client": {}, "clients": {},
		"configjson": {}, "privatekey": {}, "realityprivatekey": {}, "shortid": {},
		"shareuri": {}, "token": {}, "uuid": {}, "vlessuri": {},
	}
	xrayTaskForbiddenKeys = map[string]struct{}{
		"command": {}, "script": {}, "shell": {},
	}
)

type XrayCapability struct {
	SchemaVersion                int    `json:"schemaVersion"`
	Supported                    bool   `json:"supported"`
	Supervisor                   string `json:"supervisor"`
	SupportsPortProbe            bool   `json:"supportsPortProbe"`
	SupportsUDPPortProbe         bool   `json:"supportsUdpPortProbe,omitempty"`
	SupportsUDPListenerReadiness bool   `json:"supportsUdpListenerReadiness,omitempty"`
	SupportsRealityScan          bool   `json:"supportsRealityScan"`
	SupportsArtifactInstall      bool   `json:"supportsArtifactInstall"`
	SupportedOS                  string `json:"supportedOS"`
	SupportedArch                string `json:"supportedArch"`
	ErrorCode                    string `json:"errorCode,omitempty"`
}

func DecodeXrayCapability(raw []byte) (XrayCapability, error) {
	var capability XrayCapability
	object, err := decodeXrayObject(raw, XrayMaxControlPayloadBytes, nil)
	if err != nil {
		return capability, err
	}
	if err = requireXrayFields(object,
		"schemaVersion", "supported", "supervisor", "supportsPortProbe", "supportsRealityScan",
		"supportsArtifactInstall", "supportedOS", "supportedArch"); err != nil {
		return capability, err
	}
	if errorCodeRaw, present := object["errorCode"]; present && isXrayJSONNull(errorCodeRaw) {
		return capability, fmt.Errorf("Xray capability errorCode must be omitted or contain a string")
	}
	if err = json.Unmarshal(raw, &capability); err != nil {
		return capability, fmt.Errorf("decode Xray capability: %w", err)
	}
	return capability, capability.Validate()
}

func (capability XrayCapability) Validate() error {
	if capability.SchemaVersion != XraySchemaVersion {
		return fmt.Errorf("unsupported Xray capability schemaVersion %d", capability.SchemaVersion)
	}
	if capability.Supervisor != "AGENT_CHILD" {
		return fmt.Errorf("unsupported Xray supervisor %q", capability.Supervisor)
	}
	if capability.Supported {
		if capability.SupportedOS != "linux" || (capability.SupportedArch != "amd64" && capability.SupportedArch != "arm64") {
			return fmt.Errorf("unsupported Xray platform %s-%s", capability.SupportedOS, capability.SupportedArch)
		}
	} else {
		if err := validateXrayString("supportedOS", capability.SupportedOS, 32); err != nil {
			return err
		}
		if err := validateXrayString("supportedArch", capability.SupportedArch, 32); err != nil {
			return err
		}
	}
	if capability.ErrorCode != "" {
		return validateXrayErrorCode(capability.ErrorCode)
	}
	return nil
}

type XrayExpectedListener struct {
	InboundID     int64  `json:"inboundId"`
	RuntimeTag    string `json:"runtimeTag"`
	Network       string `json:"network"`
	ListenAddress string `json:"listenAddress"`
	Port          int    `json:"port"`
}

type XrayDesiredState struct {
	SchemaVersion     int                    `json:"schemaVersion"`
	Generation        int64                  `json:"generation"`
	IssuedAt          string                 `json:"issuedAt"`
	TargetVersion     string                 `json:"targetVersion"`
	ConfigHash        string                 `json:"configHash"`
	ConfigEncoding    string                 `json:"configEncoding"`
	ConfigJSON        string                 `json:"configJson"`
	ExpectedListeners []XrayExpectedListener `json:"expectedListeners"`
}

func DecodeXrayDesiredState(raw []byte) (XrayDesiredState, error) {
	var desired XrayDesiredState
	if err := decodeXrayJSONObject(raw, 0, nil, &desired,
		"schemaVersion", "generation", "issuedAt", "targetVersion", "configHash",
		"configEncoding", "configJson", "expectedListeners"); err != nil {
		return desired, err
	}
	return desired, desired.Validate()
}

func (desired XrayDesiredState) Validate() error {
	if desired.SchemaVersion != XraySchemaVersion {
		return fmt.Errorf("unsupported Xray desired schemaVersion %d", desired.SchemaVersion)
	}
	if desired.Generation < 0 || desired.Generation > XrayMaxSafeInteger {
		return fmt.Errorf("Xray generation must be a non-negative safe integer")
	}
	if err := validateXrayTimestamp("issuedAt", desired.IssuedAt); err != nil {
		return err
	}
	if err := validateXrayVersion(desired.TargetVersion); err != nil {
		return err
	}
	if !xraySHA256Pattern.MatchString(desired.ConfigHash) {
		return fmt.Errorf("invalid Xray configHash")
	}
	if desired.ConfigEncoding != "JSON_UTF8" {
		return fmt.Errorf("unsupported Xray configEncoding %q", desired.ConfigEncoding)
	}
	if len(desired.ConfigJSON) < 2 || len(desired.ConfigJSON) > XrayMaxConfigJSONBytes {
		return fmt.Errorf("Xray configJson exceeds size limit")
	}
	var configObject map[string]json.RawMessage
	if err := json.Unmarshal([]byte(desired.ConfigJSON), &configObject); err != nil || configObject == nil {
		return fmt.Errorf("Xray configJson must encode a JSON object")
	}
	if len(desired.ExpectedListeners) > XrayMaxExpectedListeners {
		return fmt.Errorf("too many Xray expected listeners")
	}
	for index, listener := range desired.ExpectedListeners {
		if err := listener.Validate(); err != nil {
			return fmt.Errorf("expected listener %d: %w", index, err)
		}
	}
	return nil
}

func (listener XrayExpectedListener) Validate() error {
	if listener.InboundID <= 0 || listener.InboundID > XrayMaxSafeInteger {
		return fmt.Errorf("inboundId must be positive")
	}
	if err := validateXrayIdentifier("runtimeTag", listener.RuntimeTag); err != nil {
		return err
	}
	if listener.Network != "tcp" && listener.Network != "udp" {
		return fmt.Errorf("unsupported listener network %q", listener.Network)
	}
	if err := validateXrayString("listenAddress", listener.ListenAddress, 64); err != nil {
		return err
	}
	return validateXrayPort(listener.Port)
}

type XrayObservedListener struct {
	RuntimeTag string             `json:"runtimeTag"`
	Network    string             `json:"network"`
	Port       int                `json:"port"`
	Status     XrayListenerStatus `json:"status"`
	ErrorCode  *string            `json:"errorCode,omitempty"`
}

type XrayObservedError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Generation int64  `json:"generation"`
	OccurredAt string `json:"occurredAt"`
}

type XrayObservedState struct {
	SchemaVersion     int                    `json:"schemaVersion"`
	IsInstalled       bool                   `json:"isInstalled"`
	InstalledVersion  *string                `json:"installedVersion"`
	RunningVersion    *string                `json:"runningVersion"`
	ServiceStatus     XrayServiceStatus      `json:"serviceStatus"`
	ProcessID         *int                   `json:"processId"`
	BinarySHA256      *string                `json:"binarySha256"`
	AppliedGeneration int64                  `json:"appliedGeneration"`
	AppliedConfigHash *string                `json:"appliedConfigHash"`
	Listeners         []XrayObservedListener `json:"listeners"`
	LastError         *XrayObservedError     `json:"lastError"`
	ObservedAt        string                 `json:"observedAt"`
}

type XrayObservedReport struct {
	XrayStateSignature string             `json:"xrayStateSignature"`
	XrayState          *XrayObservedState `json:"xrayState,omitempty"`
}

func DecodeXrayObservedReport(raw []byte) (XrayObservedReport, error) {
	var report XrayObservedReport
	object, err := decodeXrayObject(raw, XrayMaxControlPayloadBytes, xrayObservedForbiddenKeys)
	if err != nil {
		return report, err
	}
	if err := requireXrayFields(object, "xrayStateSignature"); err != nil {
		return report, err
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		return report, fmt.Errorf("decode Xray observed report: %w", err)
	}
	if !xraySHA256Pattern.MatchString(report.XrayStateSignature) {
		return report, fmt.Errorf("invalid Xray state signature")
	}
	if stateRaw, present := object["xrayState"]; present {
		if isXrayJSONNull(stateRaw) {
			return report, fmt.Errorf("xrayState must be omitted or contain an object")
		}
		state, decodeErr := decodeXrayObservedState(stateRaw)
		if decodeErr != nil {
			return report, decodeErr
		}
		report.XrayState = &state
	}
	return report, nil
}

func decodeXrayObservedState(raw []byte) (XrayObservedState, error) {
	var state XrayObservedState
	object, err := decodeXrayObject(raw, XrayMaxControlPayloadBytes, xrayObservedForbiddenKeys)
	if err != nil {
		return state, err
	}
	if err := requireXrayFields(object,
		"schemaVersion", "isInstalled", "installedVersion", "runningVersion", "serviceStatus",
		"processId", "binarySha256", "appliedGeneration", "appliedConfigHash", "listeners",
		"lastError", "observedAt"); err != nil {
		return state, err
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return state, fmt.Errorf("decode Xray observed state: %w", err)
	}
	if lastErrorRaw := object["lastError"]; !isXrayJSONNull(lastErrorRaw) {
		lastErrorObject, objectErr := decodeXrayObject(lastErrorRaw, 0, xrayObservedForbiddenKeys)
		if objectErr != nil {
			return state, objectErr
		}
		if objectErr = requireXrayFields(lastErrorObject, "code", "message", "generation", "occurredAt"); objectErr != nil {
			return state, objectErr
		}
	}
	return state, state.Validate()
}

func (state XrayObservedState) Validate() error {
	if state.SchemaVersion != XraySchemaVersion {
		return fmt.Errorf("unsupported Xray observed schemaVersion %d", state.SchemaVersion)
	}
	for name, version := range map[string]*string{"installedVersion": state.InstalledVersion, "runningVersion": state.RunningVersion} {
		if version != nil {
			if err := validateXrayVersion(*version); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	}
	if !validXrayServiceStatus(state.ServiceStatus) {
		return fmt.Errorf("invalid Xray serviceStatus %q", state.ServiceStatus)
	}
	if state.ProcessID != nil && (*state.ProcessID <= 0 || int64(*state.ProcessID) > XrayMaxSafeInteger) {
		return fmt.Errorf("Xray processId must be positive")
	}
	if state.BinarySHA256 != nil && !xraySHA256Pattern.MatchString(*state.BinarySHA256) {
		return fmt.Errorf("invalid Xray binarySha256")
	}
	if state.AppliedGeneration < 0 || state.AppliedGeneration > XrayMaxSafeInteger {
		return fmt.Errorf("Xray appliedGeneration must be a non-negative safe integer")
	}
	if state.AppliedConfigHash != nil && !xraySHA256Pattern.MatchString(*state.AppliedConfigHash) {
		return fmt.Errorf("invalid Xray appliedConfigHash")
	}
	if len(state.Listeners) > XrayMaxExpectedListeners {
		return fmt.Errorf("too many Xray observed listeners")
	}
	for index, listener := range state.Listeners {
		if err := listener.Validate(); err != nil {
			return fmt.Errorf("observed listener %d: %w", index, err)
		}
	}
	if state.LastError != nil {
		if err := state.LastError.Validate(); err != nil {
			return err
		}
	}
	return validateXrayTimestamp("observedAt", state.ObservedAt)
}

func (listener XrayObservedListener) Validate() error {
	if err := validateXrayIdentifier("runtimeTag", listener.RuntimeTag); err != nil {
		return err
	}
	if listener.Network != "tcp" && listener.Network != "udp" {
		return fmt.Errorf("unsupported observed listener network %q", listener.Network)
	}
	if err := validateXrayPort(listener.Port); err != nil {
		return err
	}
	if !validXrayListenerStatus(listener.Status) {
		return fmt.Errorf("invalid Xray listener status %q", listener.Status)
	}
	if listener.ErrorCode != nil {
		return validateXrayErrorCode(*listener.ErrorCode)
	}
	return nil
}

func (observedError XrayObservedError) Validate() error {
	if err := validateXrayErrorCode(observedError.Code); err != nil {
		return err
	}
	if len(observedError.Message) > XrayMaxErrorMessageBytes {
		return fmt.Errorf("Xray error message exceeds size limit")
	}
	if observedError.Generation < 0 || observedError.Generation > XrayMaxSafeInteger {
		return fmt.Errorf("Xray error generation must be a non-negative safe integer")
	}
	return validateXrayTimestamp("occurredAt", observedError.OccurredAt)
}

type XrayPortProbePayload struct {
	Network       string `json:"network"`
	ListenAddress string `json:"listenAddress"`
	Ports         []int  `json:"ports"`
}

type XrayRealityScanPayload struct {
	Targets        []string `json:"targets"`
	TimeoutMS      int      `json:"timeoutMs"`
	MaxConcurrency int      `json:"maxConcurrency"`
}

type XrayArtifactTaskPayload struct {
	ArtifactID   int64  `json:"artifactId"`
	Version      string `json:"version"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
	DownloadPath string `json:"downloadPath"`
}

type XrayRestartPayload struct {
	Reason string `json:"reason"`
}

type XrayTask struct {
	SchemaVersion      int                      `json:"schemaVersion"`
	TaskID             string                   `json:"taskId"`
	Type               XrayTaskType             `json:"type"`
	CreatedAt          string                   `json:"createdAt"`
	ExpiresAt          string                   `json:"expiresAt"`
	PortProbePayload   *XrayPortProbePayload    `json:"-"`
	RealityScanPayload *XrayRealityScanPayload  `json:"-"`
	InstallPayload     *XrayArtifactTaskPayload `json:"-"`
	UpgradePayload     *XrayArtifactTaskPayload `json:"-"`
	RestartPayload     *XrayRestartPayload      `json:"-"`
}

type xrayTaskEnvelope struct {
	SchemaVersion int             `json:"schemaVersion"`
	TaskID        string          `json:"taskId"`
	Type          XrayTaskType    `json:"type"`
	CreatedAt     string          `json:"createdAt"`
	ExpiresAt     string          `json:"expiresAt"`
	Payload       json.RawMessage `json:"payload"`
}

func DecodeXrayTask(raw []byte) (XrayTask, error) {
	var task XrayTask
	object, err := decodeXrayObject(raw, XrayMaxControlPayloadBytes, xrayTaskForbiddenKeys)
	if err != nil {
		return task, err
	}
	if err := requireXrayFields(object, "schemaVersion", "taskId", "type", "createdAt", "expiresAt", "payload"); err != nil {
		return task, err
	}
	var envelope xrayTaskEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return task, fmt.Errorf("decode Xray task: %w", err)
	}
	task.SchemaVersion = envelope.SchemaVersion
	task.TaskID = envelope.TaskID
	task.Type = envelope.Type
	task.CreatedAt = envelope.CreatedAt
	task.ExpiresAt = envelope.ExpiresAt
	if err := task.validateEnvelope(); err != nil {
		return task, err
	}
	switch task.Type {
	case XrayTaskPortProbe:
		var payload XrayPortProbePayload
		if err := decodeXrayJSONObject(envelope.Payload, 0, xrayTaskForbiddenKeys, &payload, "network", "listenAddress", "ports"); err != nil {
			return task, err
		}
		task.PortProbePayload = &payload
	case XrayTaskRealityScan:
		var payload XrayRealityScanPayload
		if err := decodeXrayJSONObject(envelope.Payload, 0, xrayTaskForbiddenKeys, &payload, "targets", "timeoutMs", "maxConcurrency"); err != nil {
			return task, err
		}
		task.RealityScanPayload = &payload
	case XrayTaskInstall, XrayTaskUpgrade:
		var payload XrayArtifactTaskPayload
		if err := decodeXrayJSONObject(envelope.Payload, 0, xrayTaskForbiddenKeys, &payload,
			"artifactId", "version", "os", "arch", "size", "sha256", "downloadPath"); err != nil {
			return task, err
		}
		if task.Type == XrayTaskInstall {
			task.InstallPayload = &payload
		} else {
			task.UpgradePayload = &payload
		}
	case XrayTaskRestart:
		var payload XrayRestartPayload
		if err := decodeXrayJSONObject(envelope.Payload, 0, xrayTaskForbiddenKeys, &payload, "reason"); err != nil {
			return task, err
		}
		task.RestartPayload = &payload
	default:
		return task, fmt.Errorf("unsupported Xray task type %q", task.Type)
	}
	return task, task.Validate()
}

func (task XrayTask) validateEnvelope() error {
	if task.SchemaVersion != XraySchemaVersion {
		return fmt.Errorf("unsupported Xray task schemaVersion %d", task.SchemaVersion)
	}
	if err := validateXrayIdentifier("taskId", task.TaskID); err != nil {
		return err
	}
	createdAt, err := parseXrayTimestamp("createdAt", task.CreatedAt)
	if err != nil {
		return err
	}
	expiresAt, err := parseXrayTimestamp("expiresAt", task.ExpiresAt)
	if err != nil {
		return err
	}
	if !expiresAt.After(createdAt) {
		return fmt.Errorf("Xray expiresAt must be later than createdAt")
	}
	return nil
}

func (task XrayTask) Validate() error {
	if err := task.validateEnvelope(); err != nil {
		return err
	}
	payloadCount := 0
	for _, present := range []bool{
		task.PortProbePayload != nil, task.RealityScanPayload != nil, task.InstallPayload != nil,
		task.UpgradePayload != nil, task.RestartPayload != nil,
	} {
		if present {
			payloadCount++
		}
	}
	if payloadCount != 1 {
		return fmt.Errorf("Xray task must contain exactly one typed payload")
	}
	switch task.Type {
	case XrayTaskPortProbe:
		if task.PortProbePayload == nil {
			return fmt.Errorf("PORT_PROBE payload is missing")
		}
		return task.PortProbePayload.Validate()
	case XrayTaskRealityScan:
		if task.RealityScanPayload == nil {
			return fmt.Errorf("REALITY_SCAN payload is missing")
		}
		return task.RealityScanPayload.Validate()
	case XrayTaskInstall:
		if task.InstallPayload == nil {
			return fmt.Errorf("INSTALL payload is missing")
		}
		return task.InstallPayload.Validate()
	case XrayTaskUpgrade:
		if task.UpgradePayload == nil {
			return fmt.Errorf("UPGRADE payload is missing")
		}
		return task.UpgradePayload.Validate()
	case XrayTaskRestart:
		if task.RestartPayload == nil {
			return fmt.Errorf("RESTART payload is missing")
		}
		return task.RestartPayload.Validate()
	default:
		return fmt.Errorf("unsupported Xray task type %q", task.Type)
	}
}

func (payload XrayPortProbePayload) Validate() error {
	if (payload.Network != "tcp" && payload.Network != "udp") || payload.ListenAddress != "0.0.0.0" {
		return fmt.Errorf("unsupported Xray port probe bind settings")
	}
	if len(payload.Ports) < 1 || len(payload.Ports) > XrayMaxPortProbeCandidates {
		return fmt.Errorf("invalid Xray port probe candidate count")
	}
	if payload.Network == "udp" && len(payload.Ports) != 1 {
		return fmt.Errorf("UDP Xray port probe must contain exactly one port")
	}
	seen := make(map[int]struct{}, len(payload.Ports))
	for _, port := range payload.Ports {
		if err := validateXrayPort(port); err != nil {
			return err
		}
		if _, exists := seen[port]; exists {
			return fmt.Errorf("duplicate Xray port probe candidate %d", port)
		}
		seen[port] = struct{}{}
	}
	return nil
}

func (payload XrayRealityScanPayload) Validate() error {
	if len(payload.Targets) < 1 || len(payload.Targets) > XrayMaxRealityTargets {
		return fmt.Errorf("invalid Xray Reality target count")
	}
	for _, target := range payload.Targets {
		if err := validateXrayRealityTarget(target); err != nil {
			return err
		}
	}
	if payload.TimeoutMS < 1 || payload.TimeoutMS > XrayMaxRealityTimeoutMS {
		return fmt.Errorf("invalid Xray Reality timeoutMs")
	}
	if payload.MaxConcurrency < 1 || payload.MaxConcurrency > XrayMaxRealityConcurrency {
		return fmt.Errorf("invalid Xray Reality maxConcurrency")
	}
	return nil
}

func (payload XrayArtifactTaskPayload) Validate() error {
	if payload.ArtifactID <= 0 || payload.ArtifactID > XrayMaxSafeInteger || payload.Size <= 0 || payload.Size > XrayMaxSafeInteger {
		return fmt.Errorf("invalid Xray artifact identity or size")
	}
	if err := validateXrayVersion(payload.Version); err != nil {
		return err
	}
	if payload.OS != "linux" || (payload.Arch != "amd64" && payload.Arch != "arm64") {
		return fmt.Errorf("unsupported Xray artifact platform")
	}
	if !xraySHA256Pattern.MatchString(payload.SHA256) {
		return fmt.Errorf("invalid Xray artifact sha256")
	}
	expectedPath := "/api/agent/artifacts/xray/" + strconv.FormatInt(payload.ArtifactID, 10)
	if payload.DownloadPath != expectedPath {
		return fmt.Errorf("Xray artifact downloadPath does not match artifactId")
	}
	return nil
}

func (payload XrayRestartPayload) Validate() error {
	if payload.Reason != "ADMIN_REQUEST" {
		return fmt.Errorf("unsupported Xray restart reason %q", payload.Reason)
	}
	return nil
}

func decodeXrayJSONObject(raw []byte, maxBytes int, forbidden map[string]struct{}, destination any, required ...string) error {
	object, err := decodeXrayObject(raw, maxBytes, forbidden)
	if err != nil {
		return err
	}
	if err := requireXrayFields(object, required...); err != nil {
		return err
	}
	if err := json.Unmarshal(raw, destination); err != nil {
		return fmt.Errorf("decode Xray payload: %w", err)
	}
	return nil
}

func decodeXrayObject(raw []byte, maxBytes int, forbidden map[string]struct{}) (map[string]json.RawMessage, error) {
	if len(raw) == 0 || (maxBytes > 0 && len(raw) > maxBytes) {
		return nil, fmt.Errorf("Xray JSON payload exceeds size limit")
	}
	if !json.Valid(raw) {
		return nil, fmt.Errorf("invalid Xray JSON payload")
	}
	if forbidden != nil {
		if err := rejectXrayForbiddenJSONKeys(raw, forbidden); err != nil {
			return nil, err
		}
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, fmt.Errorf("Xray payload must be a JSON object")
	}
	return object, nil
}

func rejectXrayForbiddenJSONKeys(raw []byte, forbidden map[string]struct{}) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var root any
	if err := decoder.Decode(&root); err != nil {
		return fmt.Errorf("decode Xray JSON for field validation: %w", err)
	}
	queue := []any{root}
	for len(queue) > 0 {
		value := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		switch typed := value.(type) {
		case map[string]any:
			for key, child := range typed {
				if _, blocked := forbidden[normalizeXrayJSONKey(key)]; blocked {
					return fmt.Errorf("Xray payload contains forbidden field %q", key)
				}
				queue = append(queue, child)
			}
		case []any:
			queue = append(queue, typed...)
		}
	}
	return nil
}

func normalizeXrayJSONKey(key string) string {
	return strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key))
}

func requireXrayFields(object map[string]json.RawMessage, fields ...string) error {
	for _, field := range fields {
		if _, present := object[field]; !present {
			return fmt.Errorf("Xray payload is missing required field %q", field)
		}
	}
	return nil
}

func requireXrayArrayObjectFields(object map[string]json.RawMessage, arrayField string, fields ...string) error {
	raw, present := object[arrayField]
	if !present {
		return fmt.Errorf("Xray payload is missing required field %q", arrayField)
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return fmt.Errorf("Xray field %q must be an array", arrayField)
	}
	for index, itemRaw := range items {
		item, err := decodeXrayObject(itemRaw, 0, xrayObservedForbiddenKeys)
		if err != nil {
			return fmt.Errorf("Xray %s item %d: %w", arrayField, index, err)
		}
		if err := requireXrayFields(item, fields...); err != nil {
			return fmt.Errorf("Xray %s item %d: %w", arrayField, index, err)
		}
	}
	return nil
}

func isXrayJSONNull(raw []byte) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func validateXrayIdentifier(name string, value string) error {
	if len(value) < 1 || len(value) > XrayMaxProtocolIdentifierLen || !xrayIdentifierPattern.MatchString(value) {
		return fmt.Errorf("invalid Xray %s", name)
	}
	return nil
}

func validateXrayErrorCode(value string) error {
	if len(value) < 1 || len(value) > 64 || !xrayErrorCodePattern.MatchString(value) {
		return fmt.Errorf("invalid Xray error code")
	}
	return nil
}

func validateXrayVersion(value string) error {
	if len(value) < 1 || len(value) > 64 || !xrayVersionPattern.MatchString(value) {
		return fmt.Errorf("invalid Xray version")
	}
	return nil
}

func validateXrayPort(port int) error {
	if port < 1000 || port > 65535 {
		return fmt.Errorf("Xray port must be between 1000 and 65535")
	}
	return nil
}

func validateXrayRealityTarget(target string) error {
	if len(target) < 1 || len(target) > 260 || !xrayRealityTargetPattern.MatchString(target) {
		return fmt.Errorf("invalid Xray Reality target")
	}
	separator := strings.LastIndexByte(target, ':')
	port, err := strconv.Atoi(target[separator+1:])
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid Xray Reality target port")
	}
	return nil
}

func validateXrayString(name string, value string, maxBytes int) error {
	if len(value) < 1 || len(value) > maxBytes {
		return fmt.Errorf("invalid Xray %s", name)
	}
	return nil
}

func parseXrayTimestamp(name string, value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid Xray %s", name)
	}
	return parsed, nil
}

func validateXrayTimestamp(name string, value string) error {
	_, err := parseXrayTimestamp(name, value)
	return err
}

func validXrayServiceStatus(status XrayServiceStatus) bool {
	return status == XrayServiceRunning || status == XrayServiceStopped || status == XrayServiceError || status == XrayServiceUnknown
}

func validXrayListenerStatus(status XrayListenerStatus) bool {
	return status == XrayListenerReady || status == XrayListenerMissing || status == XrayListenerWrongProcess || status == XrayListenerUnknown
}

func validXrayTaskResultStatus(status XrayTaskResultStatus) bool {
	return status == XrayTaskResultSuccess || status == XrayTaskResultFailed || status == XrayTaskResultTimeout || status == XrayTaskResultRejected
}
