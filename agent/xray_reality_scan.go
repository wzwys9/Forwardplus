package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	xrayRealityTaskTimeout       = 60 * time.Second
	xrayRealityMaxResolvedAddrs  = 16
	xrayRealityRedactedAddress   = "redacted"
	xrayRealityUnresolvedAddress = "unresolved"
)

var xrayRealityBlockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("5f00::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

var xrayRealityPublicIPv6Prefix = netip.MustParsePrefix("2000::/3")
var xrayRealityBlockedEndpoints = map[netip.Addr]struct{}{
	netip.MustParseAddr("168.63.129.16"): {}, // Azure platform virtual IP.
}

type xrayRealityLookup func(context.Context, string) ([]netip.Addr, error)
type xrayRealityDial func(context.Context, string, string) (net.Conn, error)
type xrayRealityProbe func(context.Context, string, time.Duration) XrayRealityScanResultItem

type xrayRealityScanner struct {
	root         string
	now          func() time.Time
	totalTimeout time.Duration
	lookup       xrayRealityLookup
	dial         xrayRealityDial
	roots        *x509.CertPool
	probe        xrayRealityProbe
}

var (
	managedXrayRealityScanner = newXrayRealityScanner(xrayManagedRoot)
	xrayRealityTaskGate       = make(chan struct{}, 1)
)

func newXrayRealityScanner(root string) *xrayRealityScanner {
	dialer := &net.Dialer{}
	scanner := &xrayRealityScanner{
		root: root, now: time.Now, totalTimeout: xrayRealityTaskTimeout,
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		dial: dialer.DialContext,
	}
	scanner.probe = scanner.scanTarget
	return scanner
}

func isAllowedXrayRealityAddress(address netip.Addr) bool {
	if !address.IsValid() || address.Zone() != "" {
		return false
	}
	address = address.Unmap()
	if _, blocked := xrayRealityBlockedEndpoints[address]; blocked {
		return false
	}
	if address.Is6() && !xrayRealityPublicIPv6Prefix.Contains(address) {
		return false
	}
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() ||
		address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range xrayRealityBlockedPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func xrayRealityErrorCode(code XrayAgentErrorCode) *string {
	value := string(code)
	return &value
}

func xrayRealityFailure(target, host string, port int, resolvedIP string, code XrayAgentErrorCode, latency time.Duration) XrayRealityScanResultItem {
	latencyMS := int(latency / time.Millisecond)
	if latencyMS < 0 {
		latencyMS = 0
	}
	if latencyMS > 60_000 {
		latencyMS = 60_000
	}
	return XrayRealityScanResultItem{
		Target: target, Host: host, ResolvedIP: resolvedIP, Port: port,
		ServerNames: []string{}, LatencyMS: latencyMS, ReasonCode: xrayRealityErrorCode(code),
		ReasonMessage: "Target did not satisfy the safe Reality scan requirements",
	}
}

func normalizedXrayRealityAddresses(addresses []netip.Addr) ([]netip.Addr, bool) {
	if len(addresses) == 0 || len(addresses) > xrayRealityMaxResolvedAddrs {
		return nil, false
	}
	unique := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if !isAllowedXrayRealityAddress(address) {
			return nil, false
		}
		unique[address] = struct{}{}
	}
	normalized := make([]netip.Addr, 0, len(unique))
	for address := range unique {
		normalized = append(normalized, address)
	}
	sort.Slice(normalized, func(left, right int) bool {
		if normalized[left].Is4() != normalized[right].Is4() {
			return normalized[left].Is4()
		}
		return normalized[left].Compare(normalized[right]) < 0
	})
	return normalized, len(normalized) > 0
}

func (scanner *xrayRealityScanner) scanTarget(parent context.Context, target string, timeout time.Duration) XrayRealityScanResultItem {
	started := time.Now()
	host, rawPort, err := net.SplitHostPort(target)
	port, portErr := strconv.Atoi(rawPort)
	if err != nil || portErr != nil || host == "" || port < 1 || port > 65535 || timeout <= 0 {
		return xrayRealityFailure(target, "invalid", 1, xrayRealityUnresolvedAddress, XrayErrorRealityTargetBlocked, time.Since(started))
	}
	host = strings.ToLower(host)
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	addresses, err := scanner.lookup(ctx, host)
	if err != nil || len(addresses) == 0 {
		return xrayRealityFailure(target, host, port, xrayRealityUnresolvedAddress, XrayErrorRealityTLSUnsupported, time.Since(started))
	}
	addresses, allowed := normalizedXrayRealityAddresses(addresses)
	if !allowed {
		return xrayRealityFailure(target, host, port, xrayRealityRedactedAddress, XrayErrorRealityTargetBlocked, time.Since(started))
	}

	var best XrayRealityScanResultItem
	for index, address := range addresses {
		attemptContext := ctx
		attemptCancel := func() {}
		if deadline, ok := ctx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				break
			}
			attemptContext, attemptCancel = context.WithTimeout(ctx, remaining/time.Duration(len(addresses)-index))
		}
		item := scanner.probeAddress(attemptContext, target, host, port, address, started)
		attemptCancel()
		if best.Target == "" || xrayRealityFeatureScore(item) > xrayRealityFeatureScore(best) ||
			(xrayRealityFeatureScore(item) == xrayRealityFeatureScore(best) && item.LatencyMS < best.LatencyMS) {
			best = item
		}
		if item.Feasible {
			return item
		}
	}
	if best.Target != "" {
		return best
	}
	return xrayRealityFailure(target, host, port, addresses[0].String(), XrayErrorRealityTLSUnsupported, time.Since(started))
}

func xrayRealityFeatureScore(item XrayRealityScanResultItem) int {
	score := 0
	for _, supported := range []bool{item.TLS13, item.H2, item.X25519, item.CertificateValid} {
		if supported {
			score++
		}
	}
	return score
}

func (scanner *xrayRealityScanner) tlsHandshake(ctx context.Context, address string, config *tls.Config) (tls.ConnectionState, error) {
	var state tls.ConnectionState
	connection, err := scanner.dial(ctx, "tcp", address)
	if err != nil {
		return state, err
	}
	tlsConnection := tls.Client(connection, config)
	defer tlsConnection.Close()
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return state, err
	}
	return tlsConnection.ConnectionState(), nil
}

func (scanner *xrayRealityScanner) probeAddress(
	ctx context.Context,
	target string,
	host string,
	port int,
	address netip.Addr,
	started time.Time,
) XrayRealityScanResultItem {
	dialAddress := net.JoinHostPort(address.String(), strconv.Itoa(port))
	state, err := scanner.tlsHandshake(ctx, dialAddress, &tls.Config{
		ServerName: host, InsecureSkipVerify: true, // Certificate verification is performed below without aborting diagnostics.
		MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err != nil {
		return xrayRealityFailure(target, host, port, address.String(), XrayErrorRealityTLSUnsupported, time.Since(started))
	}
	item := XrayRealityScanResultItem{
		Target: target, Host: host, ResolvedIP: address.String(), Port: port,
		TLS13: state.Version == tls.VersionTLS13,
		H2:    state.NegotiatedProtocol == "h2", ServerNames: []string{},
	}
	item.CertificateValid = scanner.verifyCertificate(state, host)
	if item.CertificateValid {
		item.ServerNames = []string{host}
	}
	if item.TLS13 {
		_, x25519Err := scanner.tlsHandshake(ctx, dialAddress, &tls.Config{
			ServerName: host, InsecureSkipVerify: true,
			MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519}, NextProtos: []string{"h2", "http/1.1"},
		})
		item.X25519 = x25519Err == nil
	}
	item.LatencyMS = int(time.Since(started) / time.Millisecond)
	if item.LatencyMS < 0 {
		item.LatencyMS = 0
	}
	if item.LatencyMS > 60_000 {
		item.LatencyMS = 60_000
	}
	item.Feasible = item.TLS13 && item.H2 && item.X25519 && item.CertificateValid
	if !item.Feasible {
		item.ReasonCode = xrayRealityErrorCode(XrayErrorRealityTLSUnsupported)
		item.ReasonMessage = "Target did not satisfy the required TLS capabilities"
	}
	return item
}

func (scanner *xrayRealityScanner) verifyCertificate(state tls.ConnectionState, host string) bool {
	if len(state.PeerCertificates) == 0 {
		return false
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	options := x509.VerifyOptions{
		DNSName: host, Intermediates: intermediates, Roots: scanner.roots, CurrentTime: scanner.now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	_, err := state.PeerCertificates[0].Verify(options)
	return err == nil
}

func (scanner *xrayRealityScanner) Run(parent context.Context, task XrayTask) XrayTaskResult {
	lockHash := xrayTaskLockHash(task.TaskID)
	taskLock := &xrayTaskExecutionLocks[lockHash]
	taskLock.Lock()
	defer taskLock.Unlock()

	startedAt := scanner.now().UTC()
	result := XrayTaskResult{
		SchemaVersion: XraySchemaVersion, TaskID: task.TaskID, Type: XrayTaskRealityScan,
		Status: XrayTaskResultFailed, StartedAt: startedAt.Format(time.RFC3339Nano),
	}
	if err := validateXrayIdentifier("taskId", task.TaskID); err == nil {
		persisted, readErr := readPersistedXrayTaskResultAt(scanner.root, task.TaskID)
		if readErr == nil && persisted != nil && persisted.Type == XrayTaskRealityScan {
			return *persisted
		}
		if readErr != nil || (persisted != nil && persisted.Type != XrayTaskRealityScan) {
			result.Error = &XrayTaskError{Code: string(XrayErrorInternal), Message: "The persisted Xray task result is invalid", Retryable: false}
			return scanner.finish(result, false)
		}
	}
	if err := task.Validate(); err != nil || task.Type != XrayTaskRealityScan || task.RealityScanPayload == nil {
		result.Status = XrayTaskResultRejected
		result.Error = &XrayTaskError{Code: string(XrayErrorInvalidPayload), Message: "Invalid Xray Reality scan task", Retryable: false}
		return scanner.finish(result, true)
	}
	expiresAt, err := parseXrayTimestamp("expiresAt", task.ExpiresAt)
	if err != nil || !expiresAt.After(startedAt) {
		result.Status = XrayTaskResultRejected
		result.Error = &XrayTaskError{Code: string(XrayErrorTaskExpired), Message: "The Xray Reality scan task has expired", Retryable: false}
		return scanner.finish(result, true)
	}
	if scanner.probe == nil || scanner.totalTimeout <= 0 {
		result.Error = &XrayTaskError{Code: string(XrayErrorInternal), Message: "The Xray Reality scanner is unavailable", Retryable: true}
		return scanner.finish(result, true)
	}
	deadline := time.Now().Add(scanner.totalTimeout)
	if expiresAt.Before(deadline) {
		deadline = expiresAt
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	select {
	case xrayRealityTaskGate <- struct{}{}:
		defer func() { <-xrayRealityTaskGate }()
	case <-ctx.Done():
		return scanner.finishTimeout(result)
	}

	payload := task.RealityScanPayload
	items := make([]XrayRealityScanResultItem, len(payload.Targets))
	type indexedTarget struct {
		index  int
		target string
	}
	jobs := make(chan indexedTarget, len(payload.Targets))
	for index, target := range payload.Targets {
		jobs <- indexedTarget{index: index, target: target}
	}
	close(jobs)
	workerCount := payload.MaxConcurrency
	if workerCount > len(payload.Targets) {
		workerCount = len(payload.Targets)
	}
	var workers sync.WaitGroup
	for worker := 0; worker < workerCount; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range jobs {
				items[job.index] = scanner.probe(ctx, job.target, time.Duration(payload.TimeoutMS)*time.Millisecond)
			}
		}()
	}
	workers.Wait()
	if ctx.Err() != nil {
		return scanner.finishTimeout(result)
	}
	sort.SliceStable(items, func(left, right int) bool {
		if items[left].Feasible != items[right].Feasible {
			return items[left].Feasible
		}
		if items[left].LatencyMS != items[right].LatencyMS {
			return items[left].LatencyMS < items[right].LatencyMS
		}
		return items[left].Target < items[right].Target
	})
	result.Status = XrayTaskResultSuccess
	result.RealityScanResult = &XrayRealityScanResult{
		Results: items, ObservedAt: scanner.now().UTC().Format(time.RFC3339Nano),
	}
	return scanner.finish(result, true)
}

func xrayTaskLockHash(taskID string) int {
	hash := byte(0)
	for index := 0; index < len(taskID); index++ {
		hash = hash*31 + taskID[index]
	}
	return int(hash) % len(xrayTaskExecutionLocks)
}

func (scanner *xrayRealityScanner) finishTimeout(result XrayTaskResult) XrayTaskResult {
	result.Status = XrayTaskResultTimeout
	result.Error = &XrayTaskError{Code: string(XrayErrorInternal), Message: "The Xray Reality scan task timed out", Retryable: true}
	return scanner.finish(result, true)
}

func (scanner *xrayRealityScanner) finish(result XrayTaskResult, persist bool) XrayTaskResult {
	finishedAt := scanner.now().UTC()
	if startedAt, err := parseXrayTimestamp("startedAt", result.StartedAt); err == nil && finishedAt.Before(startedAt) {
		finishedAt = startedAt
	}
	result.FinishedAt = finishedAt.Format(time.RFC3339Nano)
	if persist {
		if err := persistXrayTaskResultAt(scanner.root, result); err != nil {
			logf("Xray task result persist failed task=%s type=%s", taskLogIdentifier(result.TaskID), result.Type)
		}
	}
	return result
}
