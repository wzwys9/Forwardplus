package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestXrayRealityAddressPolicyRejectsNonPublicRanges(t *testing.T) {
	tests := map[string]bool{
		"1.1.1.1": true, "2606:4700:4700::1111": true,
		"0.0.0.0": false, "10.0.0.1": false, "100.64.0.1": false,
		"127.0.0.1": false, "169.254.169.254": false, "172.16.0.1": false,
		"168.63.129.16": false,
		"192.0.2.1":     false, "192.168.0.1": false, "198.18.0.1": false,
		"198.51.100.1": false, "203.0.113.1": false, "224.0.0.1": false,
		"240.0.0.1": false, "::": false, "::1": false, "::ffff:10.0.0.1": false,
		"64:ff9b::a00:1": false, "100::1": false, "2001:db8::1": false,
		"2002:0a00:0001::1": false, "3fff::1": false, "5f00::1": false,
		"fc00::1": false, "fe80::1": false, "fec0::1": false, "ff02::1": false, "4000::1": false,
	}
	for raw, want := range tests {
		if got := isAllowedXrayRealityAddress(netip.MustParseAddr(raw)); got != want {
			t.Errorf("address %s allowed=%v, want %v", raw, got, want)
		}
	}
}

func newXrayRealityTLSFixture(t *testing.T, host string, now time.Time) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ForwardX Reality Test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host, "internal.invalid"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{leafDER, caDER}, PrivateKey: leafKey}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return certificate, pool
}

func TestXrayRealityScanPinsValidatedAddressAndReportsTLSFeatures(t *testing.T) {
	now := time.Now().UTC()
	host := "scan.example.com"
	certificate, roots := newXrayRealityTLSFixture(t, host, now)
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519}, NextProtos: []string{"h2"},
	}
	scanner := newXrayRealityScanner(t.TempDir())
	scanner.now = func() time.Time { return now }
	scanner.roots = roots
	var resolverCalls atomic.Int32
	scanner.lookup = func(context.Context, string) ([]netip.Addr, error) {
		if resolverCalls.Add(1) == 1 {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	var dialMu sync.Mutex
	var dialed []string
	scanner.dial = func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			t.Errorf("network = %q", network)
		}
		dialMu.Lock()
		dialed = append(dialed, address)
		dialMu.Unlock()
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			_ = tls.Server(server, serverConfig).Handshake()
		}()
		return client, nil
	}

	item := scanner.scanTarget(context.Background(), host+":443", 2*time.Second)
	if !item.Feasible || !item.TLS13 || !item.H2 || !item.X25519 || !item.CertificateValid {
		t.Fatalf("TLS feature result = %#v", item)
	}
	if item.ResolvedIP != "93.184.216.34" || item.ReasonCode != nil || len(item.ServerNames) != 1 || item.ServerNames[0] != host {
		t.Fatalf("safe result projection = %#v", item)
	}
	if resolverCalls.Load() != 1 {
		t.Fatalf("resolver calls = %d, want one pinned resolution", resolverCalls.Load())
	}
	dialMu.Lock()
	defer dialMu.Unlock()
	if len(dialed) != 2 || dialed[0] != "93.184.216.34:443" || dialed[1] != "93.184.216.34:443" {
		t.Fatalf("dialed addresses = %v", dialed)
	}
}

func TestXrayRealityScanReportsUnsupportedTLSFeaturesWithoutCertificateNames(t *testing.T) {
	now := time.Now().UTC()
	certificate, roots := newXrayRealityTLSFixture(t, "other.example.com", now)
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{tls.CurveP256}, NextProtos: []string{"http/1.1"},
	}
	scanner := newXrayRealityScanner(t.TempDir())
	scanner.now = func() time.Time { return now }
	scanner.roots = roots
	scanner.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
	}
	var dials atomic.Int32
	scanner.dial = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			_ = tls.Server(server, serverConfig).Handshake()
		}()
		return client, nil
	}
	item := scanner.scanTarget(context.Background(), "scan.example.com:443", 2*time.Second)
	if item.Feasible || item.TLS13 || item.H2 || item.X25519 || item.CertificateValid || len(item.ServerNames) != 0 {
		t.Fatalf("unsupported TLS result = %#v", item)
	}
	if item.ReasonCode == nil || *item.ReasonCode != string(XrayErrorRealityTLSUnsupported) || dials.Load() != 1 {
		t.Fatalf("unsupported TLS reason = %#v dials=%d", item, dials.Load())
	}
}

func TestXrayRealityScanRejectsMixedDNSBeforeDialWithoutLeakingAddress(t *testing.T) {
	scanner := newXrayRealityScanner(t.TempDir())
	scanner.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("169.254.169.254")}, nil
	}
	var dialed atomic.Int32
	scanner.dial = func(context.Context, string, string) (net.Conn, error) {
		dialed.Add(1)
		return nil, context.Canceled
	}
	item := scanner.scanTarget(context.Background(), "mixed.example.com:443", time.Second)
	if item.Feasible || item.ReasonCode == nil || *item.ReasonCode != string(XrayErrorRealityTargetBlocked) {
		t.Fatalf("mixed DNS result = %#v", item)
	}
	if item.ResolvedIP != xrayRealityRedactedAddress || strings.Contains(item.ReasonMessage, "169.254") || dialed.Load() != 0 {
		t.Fatalf("mixed DNS leaked or dialed: %#v dials=%d", item, dialed.Load())
	}
}

func xrayRealityTask(taskID string, now time.Time, targets ...string) XrayTask {
	return XrayTask{
		SchemaVersion: XraySchemaVersion, TaskID: taskID, Type: XrayTaskRealityScan,
		CreatedAt: now.Add(-time.Second).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		RealityScanPayload: &XrayRealityScanPayload{Targets: targets, TimeoutMS: 1000, MaxConcurrency: 2},
	}
}

func TestXrayRealityScanRunnerBoundsConcurrencySortsAndPersistsIdempotently(t *testing.T) {
	now := time.Now().UTC()
	runner := newXrayRealityScanner(t.TempDir())
	runner.now = func() time.Time { return now }
	var active atomic.Int32
	var maximum atomic.Int32
	var calls atomic.Int32
	runner.probe = func(ctx context.Context, target string, _ time.Duration) XrayRealityScanResultItem {
		calls.Add(1)
		current := active.Add(1)
		defer active.Add(-1)
		for {
			seen := maximum.Load()
			if current <= seen || maximum.CompareAndSwap(seen, current) {
				break
			}
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-ctx.Done():
		}
		host, port, _ := net.SplitHostPort(target)
		feasible := !strings.HasPrefix(host, "blocked")
		item := XrayRealityScanResultItem{
			Target: target, Host: host, ResolvedIP: "1.1.1.1", Port: 443,
			Feasible: feasible, TLS13: feasible, H2: feasible, X25519: feasible, CertificateValid: feasible,
			LatencyMS: len(host), ServerNames: []string{},
		}
		_ = port
		if feasible {
			item.ServerNames = []string{host}
		} else {
			item.ReasonCode = xrayRealityErrorCode(XrayErrorRealityTargetBlocked)
		}
		return item
	}
	task := xrayRealityTask("bounded-reality-scan", now,
		"zz.example.com:443", "a.example.com:443", "blocked.example.com:443", "bbb.example.com:443")
	first := runner.Run(context.Background(), task)
	second := runner.Run(context.Background(), task)
	if first.Status != XrayTaskResultSuccess || first.RealityScanResult == nil || second.Status != XrayTaskResultSuccess {
		t.Fatalf("scan results = %#v / %#v", first, second)
	}
	if calls.Load() != 4 || maximum.Load() != 2 || active.Load() != 0 {
		t.Fatalf("calls=%d maximum=%d active=%d", calls.Load(), maximum.Load(), active.Load())
	}
	results := first.RealityScanResult.Results
	if len(results) != 4 || !results[0].Feasible || !results[1].Feasible || !results[2].Feasible || results[3].Feasible {
		t.Fatalf("feasibility ordering = %#v", results)
	}
	for index := 1; index < 3; index++ {
		if results[index-1].LatencyMS > results[index].LatencyMS {
			t.Fatalf("latency ordering = %#v", results)
		}
	}
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("persisted result changed:\n%s\n%s", firstJSON, secondJSON)
	}
}

func TestXrayRealityScanRunnerTotalTimeoutDoesNotLeakWorkers(t *testing.T) {
	now := time.Now().UTC()
	runner := newXrayRealityScanner(t.TempDir())
	runner.now = func() time.Time { return now }
	runner.totalTimeout = 20 * time.Millisecond
	var active atomic.Int32
	runner.probe = func(ctx context.Context, target string, _ time.Duration) XrayRealityScanResultItem {
		active.Add(1)
		defer active.Add(-1)
		<-ctx.Done()
		host, _, _ := net.SplitHostPort(target)
		return XrayRealityScanResultItem{
			Target: target, Host: host, ResolvedIP: xrayRealityUnresolvedAddress, Port: 443,
			ReasonCode: xrayRealityErrorCode(XrayErrorRealityTLSUnsupported), ServerNames: []string{},
		}
	}
	result := runner.Run(context.Background(), xrayRealityTask("timed-out-reality-scan", now,
		"a.example.com:443", "b.example.com:443", "c.example.com:443"))
	if result.Status != XrayTaskResultTimeout || result.Error == nil || active.Load() != 0 {
		t.Fatalf("timeout result = %#v active=%d", result, active.Load())
	}
}

func TestXrayRealityScanDispatcherAcceptsTypedTask(t *testing.T) {
	now := time.Now().UTC()
	task := xrayRealityTask("dispatched-reality-scan", now, "scan.example.com:443")
	raw, err := json.Marshal(map[string]any{
		"schemaVersion": task.SchemaVersion,
		"taskId":        task.TaskID,
		"type":          task.Type,
		"createdAt":     task.CreatedAt,
		"expiresAt":     task.ExpiresAt,
		"payload":       task.RealityScanPayload,
	})
	if err != nil {
		t.Fatal(err)
	}
	runner := newXrayRealityScanner(t.TempDir())
	runner.now = func() time.Time { return now }
	runner.probe = func(context.Context, string, time.Duration) XrayRealityScanResultItem {
		return XrayRealityScanResultItem{
			Target: "scan.example.com:443", Host: "scan.example.com", ResolvedIP: "1.1.1.1", Port: 443,
			Feasible: true, TLS13: true, H2: true, X25519: true, CertificateValid: true,
			ServerNames: []string{"scan.example.com"},
		}
	}
	result, handled := dispatchXrayTask(context.Background(), raw, newXrayPortProbeRunner(t.TempDir()), runner)
	if !handled || result.Type != XrayTaskRealityScan || result.Status != XrayTaskResultSuccess {
		t.Fatalf("dispatched result = %#v handled=%v", result, handled)
	}
}
