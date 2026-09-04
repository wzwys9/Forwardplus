package main

import (
	"context"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type supportBundleRequest struct {
	TaskID string `json:"taskId"`
}

type supportBundleJob struct {
	cfg     Config
	request supportBundleRequest
}

const supportBundleCompletedRetention = 30 * time.Minute

// supportBundleScheduler prevents duplicate SSE deliveries from launching
// overlapping command sets. Distinct administrator requests remain queued and
// are collected one at a time, keeping subprocess concurrency globally bounded.
type supportBundleScheduler struct {
	mu        sync.Mutex
	running   bool
	queue     []supportBundleJob
	tasks     map[string]time.Time
	process   func(Config, supportBundleRequest) bool
	retention time.Duration
}

func newSupportBundleScheduler(process func(Config, supportBundleRequest) bool) *supportBundleScheduler {
	return &supportBundleScheduler{
		tasks:     make(map[string]time.Time),
		process:   process,
		retention: supportBundleCompletedRetention,
	}
}

func (scheduler *supportBundleScheduler) schedule(cfg Config, request supportBundleRequest) bool {
	taskID := strings.TrimSpace(request.TaskID)
	if taskID == "" {
		return false
	}
	request.TaskID = taskID
	now := time.Now()
	scheduler.mu.Lock()
	for id, completedAt := range scheduler.tasks {
		if !completedAt.IsZero() && now.Sub(completedAt) >= scheduler.retention {
			delete(scheduler.tasks, id)
		}
	}
	if _, exists := scheduler.tasks[taskID]; exists {
		scheduler.mu.Unlock()
		return false
	}
	scheduler.tasks[taskID] = time.Time{}
	scheduler.queue = append(scheduler.queue, supportBundleJob{cfg: cfg, request: request})
	if scheduler.running {
		scheduler.mu.Unlock()
		return true
	}
	scheduler.running = true
	job := scheduler.queue[0]
	scheduler.queue[0] = supportBundleJob{}
	scheduler.queue = scheduler.queue[1:]
	if len(scheduler.queue) == 0 {
		scheduler.queue = nil
	}
	scheduler.mu.Unlock()
	go scheduler.run(job)
	return true
}

func (scheduler *supportBundleScheduler) run(job supportBundleJob) {
	for {
		reported := scheduler.process(job.cfg, job.request)
		scheduler.mu.Lock()
		if reported {
			scheduler.tasks[job.request.TaskID] = time.Now()
		} else {
			// A later delivery may retry a report that failed while the panel was
			// temporarily unavailable.
			delete(scheduler.tasks, job.request.TaskID)
		}
		if len(scheduler.queue) == 0 {
			scheduler.running = false
			scheduler.mu.Unlock()
			return
		}
		job = scheduler.queue[0]
		scheduler.queue[0] = supportBundleJob{}
		scheduler.queue = scheduler.queue[1:]
		if len(scheduler.queue) == 0 {
			scheduler.queue = nil
		}
		scheduler.mu.Unlock()
	}
}

var agentSupportBundles = newSupportBundleScheduler(collectAndReportSupportBundle)

type supportCommandResult struct {
	Name       string `json:"name"`
	Output     string `json:"output"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"durationMs"`
}

var (
	supportSecretPattern            = regexp.MustCompile(`(?i)((?:agent.?token|token|password|passwd|secret|private.?key|pre.?shared.?key|psk|header.?protection.?key|reality.?private|uuid|short.?id|stats.?key|config.?json|share.?uri|vless.?uri|vpn.?uri|credential|ciphertext|encrypted|envelope|master.?key)["']?\s*[=:]\s*["']?)[^\s,;"'}]+`)
	supportBearerPattern            = regexp.MustCompile(`(?i)(authorization\s*:\s*(?:bearer\s+)?)[^\s,"';]+`)
	supportVLESSPattern             = regexp.MustCompile(`(?i)vless://[^\s"'<>]+`)
	supportVPNPattern               = regexp.MustCompile(`(?i)vpn://[^\s"'<>]+`)
	supportAWGAssignmentPattern     = regexp.MustCompile(`(?im)^(\s*(?:private.?key|pre.?shared.?key|psk|header.?protection.?key)\s*=\s*)[^\s#;]+`)
	supportUUIDPattern              = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	supportBareRealityKeyPattern    = regexp.MustCompile(`(^|[^A-Za-z0-9_-])([A-Za-z0-9_-]{43})([^A-Za-z0-9_-]|$)`)
	supportBareAmneziaWGKeyPattern  = regexp.MustCompile(`(^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{43}=)([^A-Za-z0-9+/=]|$)`)
	supportSensitiveFilenamePattern = regexp.MustCompile(`(?i)((?:private.?key|uuid|short.?id|token|secret|config.?json)[-_.])[A-Za-z0-9_-]{8,}`)
	supportVersionPattern           = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+$`)
	supportRuntimeTagPattern        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

const (
	supportJournalOutputLimit = 48 * 1024
	supportCommandOutputLimit = 16 * 1024
	supportNginxOutputLimit   = 24 * 1024
	supportTotalOutputLimit   = 224 * 1024
	supportTruncationMarker   = "\n[TRUNCATED]"
)

type supportCommandSpec struct {
	name, command string
	outputLimit   int
}

func redactSupportOutput(value string) string {
	value = supportVLESSPattern.ReplaceAllString(value, "vless://[REDACTED]")
	value = supportVPNPattern.ReplaceAllString(value, "vpn://[REDACTED]")
	value = supportAWGAssignmentPattern.ReplaceAllString(value, "${1}[REDACTED]")
	value = supportBearerPattern.ReplaceAllString(value, "${1}[REDACTED]")
	value = supportSecretPattern.ReplaceAllString(value, "${1}[REDACTED]")
	value = supportSensitiveFilenamePattern.ReplaceAllString(value, "${1}[REDACTED]")
	value = supportUUIDPattern.ReplaceAllString(value, "[REDACTED]")
	value = supportBareAmneziaWGKeyPattern.ReplaceAllString(value, "${1}[REDACTED]${3}")
	return supportBareRealityKeyPattern.ReplaceAllString(value, "${1}[REDACTED]${3}")
}

func truncateSupportOutput(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	if limit <= len(supportTruncationMarker) {
		return supportTruncationMarker[:limit]
	}
	prefixEnd := limit - len(supportTruncationMarker)
	for prefixEnd > 0 && !utf8.ValidString(value[:prefixEnd]) {
		prefixEnd--
	}
	return value[:prefixEnd] + supportTruncationMarker
}

func runSupportCommand(name, command string, outputLimit int) supportCommandResult {
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmd, cleanup, _, err := shellCommand(ctx, command)
	if err != nil {
		return supportCommandResult{Name: name, Error: truncateSupportOutput(redactSupportOutput(err.Error()), 2048), DurationMS: time.Since(started).Milliseconds()}
	}
	defer cleanup()
	output, runErr := cmd.CombinedOutput()
	result := supportCommandResult{Name: name, Output: truncateSupportOutput(redactSupportOutput(string(output)), outputLimit), DurationMS: time.Since(started).Milliseconds()}
	if ctx.Err() == context.DeadlineExceeded {
		result.Error = "timeout"
	} else if runErr != nil {
		result.Error = truncateSupportOutput(redactSupportOutput(runErr.Error()), 2048)
	}
	return result
}

type xraySupportListener struct {
	RuntimeTag string             `json:"runtimeTag"`
	Port       int                `json:"port"`
	Status     XrayListenerStatus `json:"status"`
}

type xraySupportDiagnostics struct {
	InstalledVersion *string               `json:"installedVersion,omitempty"`
	RunningVersion   *string               `json:"runningVersion,omitempty"`
	ServiceStatus    XrayServiceStatus     `json:"serviceStatus"`
	ConfigHashPrefix string                `json:"configHashPrefix,omitempty"`
	BinaryHashPrefix string                `json:"binaryHashPrefix,omitempty"`
	Listeners        []xraySupportListener `json:"listeners"`
}

func supportVersion(value *string) *string {
	if value == nil || !supportVersionPattern.MatchString(*value) {
		return nil
	}
	copy := *value
	return &copy
}

func supportHashPrefix(value *string) string {
	if value == nil || !xraySHA256Pattern.MatchString(*value) {
		return ""
	}
	return (*value)[:12]
}

func xraySupportDiagnosticsFromObserved(state XrayObservedState) xraySupportDiagnostics {
	status := state.ServiceStatus
	if !validXrayServiceStatus(status) {
		status = XrayServiceUnknown
	}
	listeners := make([]xraySupportListener, 0, len(state.Listeners))
	for _, listener := range state.Listeners {
		if len(listeners) >= XrayMaxExpectedListeners || !supportRuntimeTagPattern.MatchString(listener.RuntimeTag) ||
			listener.Port < 1 || listener.Port > 65535 || !validXrayListenerStatus(listener.Status) {
			continue
		}
		listeners = append(listeners, xraySupportListener{RuntimeTag: listener.RuntimeTag, Port: listener.Port, Status: listener.Status})
	}
	return xraySupportDiagnostics{
		InstalledVersion: supportVersion(state.InstalledVersion),
		RunningVersion:   supportVersion(state.RunningVersion),
		ServiceStatus:    status,
		ConfigHashPrefix: supportHashPrefix(state.AppliedConfigHash),
		BinaryHashPrefix: supportHashPrefix(state.BinarySHA256),
		Listeners:        listeners,
	}
}

func enforceSupportOutputTotalLimit(results []supportCommandResult, limit int) {
	remaining := limit
	for index := range results {
		results[index].Output = truncateSupportOutput(results[index].Output, remaining)
		remaining -= len(results[index].Output)
		if remaining < 0 {
			remaining = 0
		}
	}
}

func supportCommandSpecs() []supportCommandSpec {
	return []supportCommandSpec{
		{"agent-journal-current-boot", "journalctl -u forwardx-agent -b -n 600 --no-pager 2>&1 || tail -n 600 /var/log/forwardx-agent/agent-go.log 2>&1", supportJournalOutputLimit},
		{"agent-journal-previous-boot", "journalctl -u forwardx-agent -b -1 -n 300 --no-pager 2>&1 || true", supportJournalOutputLimit},
		{"service-status", "systemctl status forwardx-agent forwardx-runtime forwardx-tunnel-runtime forwardx-nginx --no-pager -l 2>&1 || true", supportCommandOutputLimit},
		{"service-restarts", "systemctl show forwardx-agent forwardx-runtime forwardx-tunnel-runtime forwardx-nginx -p Id -p ActiveState -p SubState -p NRestarts -p ExecMainStartTimestamp 2>&1 || true", supportCommandOutputLimit},
		{"nginx-journal", "journalctl -u forwardx-nginx -b -n 400 --no-pager 2>&1 || true", supportNginxOutputLimit},
		{"nginx-logs", "for f in /var/log/forwardx-agent/forwardx-nginx-error.log /var/log/forwardx-agent/forwardx-nginx-session.log; do echo \"### $f\"; if [ -f \"$f\" ]; then tail -n 400 \"$f\"; else echo missing; fi; done 2>&1", supportNginxOutputLimit},
		{"kernel-network-events", "journalctl -k -b --since '-2 hours' --no-pager 2>&1 | grep -Ei 'out of memory|oom|killed process|nf_conntrack.*(full|drop)|TCP:.*memory' | tail -n 300 || true", supportCommandOutputLimit},
		{"mimic", "for f in /etc/mimic/*.conf; do [ -f \"$f\" ] || continue; i=${f##*/}; i=${i%.conf}; echo \"### $i\"; mimic show \"$i\" 2>&1 || true; ip -details -statistics link show dev \"$i\" 2>&1 || true; command -v ethtool >/dev/null 2>&1 && ethtool -k \"$i\" 2>&1 || true; tc filter show dev \"$i\" ingress 2>&1 || true; tc filter show dev \"$i\" egress 2>&1 || true; done", supportCommandOutputLimit},
		{"listeners", "ss -H -ltnup 2>&1 | head -n 2000", supportCommandOutputLimit},
		{"routes", "ip -4 route show 2>&1; ip -6 route show 2>&1", supportCommandOutputLimit},
		{"qdisc", "tc qdisc show 2>&1 || true", supportCommandOutputLimit},
		{"network-sysctl", "sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.core.rmem_max net.core.wmem_max net.ipv4.tcp_keepalive_time net.ipv4.tcp_keepalive_intvl net.ipv4.tcp_keepalive_probes net.netfilter.nf_conntrack_tcp_timeout_established net.netfilter.nf_conntrack_udp_timeout net.netfilter.nf_conntrack_udp_timeout_stream 2>&1 || true", supportCommandOutputLimit},
		{"nft-summary", "nft list ruleset 2>&1 | head -n 2500 || true", supportCommandOutputLimit},
	}
}

func collectSupportDiagnostics() map[string]any {
	commands := supportCommandSpecs()
	results := make([]supportCommandResult, len(commands))
	semaphore := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for index, item := range commands {
		wg.Add(1)
		go func(index int, name, command string, outputLimit int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			results[index] = runSupportCommand(name, command, outputLimit)
		}(index, item.name, item.command, item.outputLimit)
	}
	wg.Wait()
	enforceSupportOutputTotalLimit(results, supportTotalOutputLimit)
	receivedRevision, appliedRevision, receivedHash, appliedHash := desiredRevisionSnapshot()
	return map[string]any{
		"agentVersion":         Version,
		"bootId":               agentBootID,
		"processId":            os.Getpid(),
		"processStartedAt":     agentProcessStartedAt.Format(time.RFC3339Nano),
		"lastReceivedRevision": receivedRevision,
		"lastAppliedRevision":  appliedRevision,
		"lastReceivedHash":     receivedHash,
		"lastAppliedHash":      appliedHash,
		"mimicEnvironment":     mimicRuntimeEnvironment(),
		"mimicRuntime":         mimicRuntimeDiagnostics(),
		"fxpEndpointEvents":    fxpEndpointEventsSnapshot(),
		"xrayRuntime":          xraySupportDiagnosticsFromObserved(buildCurrentXrayObservedState(time.Now())),
		"commands":             results,
	}
}

func collectAndReportSupportBundle(cfg Config, request supportBundleRequest) bool {
	taskID := strings.TrimSpace(request.TaskID)
	if taskID == "" {
		return false
	}
	diagnostics := collectSupportDiagnostics()
	var response map[string]any
	if err := post(cfg, "/api/agent/support-bundle-result", map[string]any{
		"taskId":      taskID,
		"diagnostics": diagnostics,
	}, &response); err != nil {
		logf("support bundle report failed task=%s", taskLogIdentifier(taskID))
		return false
	}
	return true
}
