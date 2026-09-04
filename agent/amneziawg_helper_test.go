package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	awgconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	awgdevice "github.com/amnezia-vpn/amneziawg-go/v3/device"
	awgnetstack "github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/crypto/curve25519"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
)

func assertManagedAmneziaWGContractAndRuntime(t *testing.T, raw json.RawMessage, desired ManagedServicesDesiredState) {
	t.Helper()
	assertManagedAmneziaWGStrictContract(t, raw)
	assertManagedAmneziaWGStackAndPolicy(t, desired.Services[1])
	assertManagedAmneziaWGPanelURLRefresh(t, desired.Services[1])
	assertManagedServiceObservedTargetsArePerKind(t, desired.Services)
	assertManagedAmneziaWGPeerTCPAndUDP(t, desired.Services[1])
}

func assertManagedAmneziaWGPanelURLRefresh(t *testing.T, service ManagedServiceDesired) {
	t.Helper()
	previousURL, _ := runtimePanelURL.Load().(string)
	previousPrepareHook := managedServicesPanelURLPrepareHook
	previousStableHook := managedServicesPanelURLStableHook
	previousDurableHoldHook := managedServicesDurableHoldHook
	previousDurableHoldPresentHook := managedServicesDurableHoldPresentHook
	previousPanelConfigDirectorySync := panelConfigDirectorySync
	previousConfigPath := activeConfigPath
	t.Cleanup(func() {
		managedServicesPanelURLPrepareHook = previousPrepareHook
		managedServicesPanelURLStableHook = previousStableHook
		managedServicesDurableHoldHook = previousDurableHoldHook
		managedServicesDurableHoldPresentHook = previousDurableHoldPresentHook
		panelConfigDirectorySync = previousPanelConfigDirectorySync
		activeConfigPath = previousConfigPath
		runtimePanelURL.Store(previousURL)
	})
	var preparedBeforeSwitch, stabilizedAfterSwitch bool
	managedServicesPanelURLPrepareHook = func(previous, current string) bool {
		preparedBeforeSwitch = previous == "https://old-panel.example.com" && current == "https://new-panel.example.com" && currentPanelURL(Config{}) == previous
		return true
	}
	managedServicesPanelURLStableHook = func(current string) bool {
		stabilizedAfterSwitch = current == "https://new-panel.example.com" && currentPanelURL(Config{}) == current
		return true
	}
	runtimePanelURL.Store("https://old-panel.example.com")
	if !setRuntimePanelURL("https://new-panel.example.com") || !preparedBeforeSwitch || !stabilizedAfterSwitch {
		t.Fatal("panel URL change was not acknowledged before switching and stabilized afterward")
	}
	managedServicesPanelURLPrepareHook = func(string, string) bool { return false }
	stabilizedAfterSwitch = false
	if setRuntimePanelURL("https://rejected-panel.example.com") || currentPanelURL(Config{}) != "https://new-panel.example.com" || !stabilizedAfterSwitch {
		t.Fatal("failed transition-policy acknowledgement did not restore the previous stable policy and URL")
	}
	stableCalls := make([]string, 0, 2)
	managedServicesPanelURLPrepareHook = func(string, string) bool { return true }
	managedServicesPanelURLStableHook = func(current string) bool {
		stableCalls = append(stableCalls, current)
		return current == "https://new-panel.example.com"
	}
	if setRuntimePanelURL("https://unstable-panel.example.com") || currentPanelURL(Config{}) != "https://new-panel.example.com" ||
		len(stableCalls) != 2 || stableCalls[0] != "https://unstable-panel.example.com" || stableCalls[1] != "https://new-panel.example.com" {
		t.Fatal("failed stable-policy acknowledgement did not restore the previous panel policy and URL")
	}
	configPath := t.TempDir() + "/agent.json"
	if err := os.WriteFile(configPath, []byte("{\"panelUrl\":\"https://old-panel.example.com\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	activeConfigPath = configPath
	runtimePanelURL.Store("https://old-panel.example.com")
	managedServicesDurableHoldPresentHook = func() bool { return false }
	managedServicesPanelURLPrepareHook = func(string, string) bool { return true }
	var policyMu sync.Mutex
	stablePolicy := "https://old-panel.example.com"
	managedServicesPanelURLStableHook = func(current string) bool {
		policyMu.Lock()
		stablePolicy = current
		policyMu.Unlock()
		return true
	}
	var updates sync.WaitGroup
	for _, panelURL := range []string{"https://panel-a.example.com", "https://panel-b.example.com"} {
		updates.Add(1)
		go func() {
			defer updates.Done()
			syncPanelURLFromResponse(panelURL)
		}()
	}
	updates.Wait()
	var persisted map[string]any
	persistedRaw, err := os.ReadFile(configPath)
	if err != nil || json.Unmarshal(persistedRaw, &persisted) != nil {
		t.Fatal("concurrent panel URL update did not leave a readable config")
	}
	policyMu.Lock()
	finalPolicy := stablePolicy
	policyMu.Unlock()
	finalURL := currentPanelURL(Config{})
	if persisted["panelUrl"] != finalURL || finalPolicy != finalURL {
		t.Fatalf("concurrent panel URL transaction diverged: runtime=%q persisted=%v policy=%q", finalURL, persisted["panelUrl"], finalPolicy)
	}
	panelConfigDirectorySync = func(string) error { return errors.New("injected directory sync failure") }
	if err = persistPanelMigrationConfig("https://sync-failure.example.com", "", "", time.Time{}, true); err == nil {
		t.Fatal("panel configuration directory sync failure was ignored")
	}
	panelConfigDirectorySync = previousPanelConfigDirectorySync
	recoveredSameURL := false
	managedServicesDurableHoldPresentHook = func() bool { return true }
	managedServicesPanelURLStableHook = func(current string) bool {
		recoveredSameURL = current == finalURL
		return true
	}
	syncPanelURLFromResponse(finalURL)
	if !recoveredSameURL {
		t.Fatal("same-URL heartbeat did not recover a durable deny hold")
	}
	brokenPath := t.TempDir() + "/agent.json"
	if err = os.WriteFile(brokenPath, []byte("{\"panelUrl\":\""+finalURL+"\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	activeConfigPath = brokenPath
	durableHoldCalls := 0
	managedServicesDurableHoldHook = func() { durableHoldCalls++ }
	managedServicesDurableHoldPresentHook = func() bool { return false }
	rollbackStableCalls := 0
	managedServicesPanelURLStableHook = func(current string) bool {
		if current == "https://broken-panel.example.com" {
			if removeErr := os.Remove(brokenPath); removeErr != nil {
				t.Fatal(removeErr)
			}
			if mkdirErr := os.Mkdir(brokenPath, 0700); mkdirErr != nil {
				t.Fatal(mkdirErr)
			}
			return false
		}
		rollbackStableCalls++
		return true
	}
	if switchToCommittedPanel(Config{}, "https://broken-panel.example.com", "", "test") || currentPanelURL(Config{}) != finalURL ||
		durableHoldCalls != 1 || rollbackStableCalls != 0 {
		t.Fatal("migration rollback persistence failure cleared the hold before the old URL was durable")
	}
	managedServicesPanelURLPrepareHook = previousPrepareHook
	managedServicesPanelURLStableHook = previousStableHook
	managedServicesDurableHoldHook = previousDurableHoldHook
	managedServicesDurableHoldPresentHook = previousDurableHoldPresentHook
	panelConfigDirectorySync = previousPanelConfigDirectorySync
	activeConfigPath = previousConfigPath

	service.PublicAddress = "8.8.4.4"
	resolved := map[string][]netip.Addr{
		"old-panel.example.com": {netip.MustParseAddr("1.1.1.1")},
		"new-panel.example.com": {netip.MustParseAddr("9.9.9.9")},
	}
	relay := &managedAmneziaWGRelay{
		denyHosts: []string{"8.8.4.4", "old-panel.example.com"}, denied: map[netip.Addr]struct{}{}, denyFailed: true,
		interfaceAddrs: func() ([]net.Addr, error) { return nil, nil },
		lookupNetIP: func(_ context.Context, _, host string) ([]netip.Addr, error) {
			addresses, ok := resolved[host]
			if !ok {
				return nil, errors.New("DNS unavailable")
			}
			return addresses, nil
		},
		tcp: map[*managedAmneziaWGTCPRelay]struct{}{}, udp: map[string]*managedAmneziaWGUDPSession{}, closed: make(chan struct{}),
	}
	defer relay.Close()
	relay.refreshDeniedDestinations()
	runtimePanelURL.Store("https://new-panel.example.com")
	staleRaw, staleErr := renderManagedAmneziaWGConfigForPanelPolicy(service, managedAmneziaWGPolicyStable, "https://old-panel.example.com")
	if staleErr != nil || managedAmneziaWGHelperConfigMatches(staleRaw, service) {
		t.Fatal("wrapper with only the previous panel host matched the current policy")
	}
	transitionRaw, err := renderManagedAmneziaWGConfigForPanelPolicy(service, managedAmneziaWGPolicyTransition, "https://new-panel.example.com")
	if err != nil || !managedAmneziaWGHelperConfigMatches(transitionRaw, service) {
		t.Fatalf("panel transition wrapper was not valid for the running service: %v", err)
	}
	var transition managedAmneziaWGHelperConfig
	if err = strictManagedServicesJSON(transitionRaw, &transition); err != nil {
		t.Fatal(err)
	}
	currentRevision := managedAmneziaWGDenyRevision(managedAmneziaWGPolicyStable, relay.denyHosts)
	delete(resolved, "old-panel.example.com")
	if !applyManagedAmneziaWGDenyReload(relay, service, &currentRevision, true, "", func() (managedAmneziaWGHelperConfig, error) { return transition, nil }) {
		t.Fatal("valid panel URL deny update was rejected")
	}
	if relay.destinationAllowed(netip.MustParseAddrPort("1.1.1.1:443")) ||
		relay.destinationAllowed(netip.MustParseAddrPort("9.9.9.9:443")) ||
		!relay.destinationAllowed(netip.MustParseAddrPort("8.8.8.8:443")) {
		t.Fatal("transition did not preserve the old address while denying the new panel")
	}
	relay.denyMu.RLock()
	unchangedGeneration := relay.denyGeneration
	relay.denyMu.RUnlock()
	tunnel, tunnelPeer := net.Pipe()
	upstream, upstreamPeer := net.Pipe()
	defer tunnelPeer.Close()
	defer upstreamPeer.Close()
	activeTCP := &managedAmneziaWGTCPRelay{target: netip.MustParseAddrPort("8.8.8.8:443"), tunnel: tunnel, upstream: upstream}
	relay.tcp[activeTCP] = struct{}{}
	udpConnection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	activeUDP := &managedAmneziaWGUDPSession{conn: udpConnection, source: netip.MustParseAddrPort("10.8.1.2:1234"), target: netip.MustParseAddrPort("8.8.8.8:53"), done: make(chan struct{})}
	relay.udp[activeUDP.source.String()+"|"+activeUDP.target.String()] = activeUDP
	if !applyManagedAmneziaWGDenyReload(relay, service, &currentRevision, true, "", func() (managedAmneziaWGHelperConfig, error) { return transition, nil }) {
		t.Fatal("unchanged policy was rejected")
	}
	relay.denyMu.RLock()
	if relay.denyGeneration != unchangedGeneration || activeUDP.closed.Load() {
		relay.denyMu.RUnlock()
		t.Fatal("unchanged periodic reload disrupted an active session")
	}
	relay.denyMu.RUnlock()
	_ = tunnelPeer.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	if _, readErr := tunnelPeer.Read(make([]byte, 1)); readErr == nil || !errors.Is(readErr, os.ErrDeadlineExceeded) {
		t.Fatal("unchanged periodic reload closed an active TCP session")
	}
	stableRaw, err := renderManagedAmneziaWGConfigForPanelPolicy(service, managedAmneziaWGPolicyStable, "https://new-panel.example.com")
	var stable managedAmneziaWGHelperConfig
	if err != nil || strictManagedServicesJSON(stableRaw, &stable) != nil ||
		!applyManagedAmneziaWGDenyReload(relay, service, &currentRevision, true, "", func() (managedAmneziaWGHelperConfig, error) { return stable, nil }) {
		t.Fatal("stable panel policy cleanup failed")
	}
	if !relay.destinationAllowed(netip.MustParseAddrPort("1.1.1.1:443")) || relay.destinationAllowed(netip.MustParseAddrPort("9.9.9.9:443")) {
		t.Fatal("stable policy did not remove the old panel address")
	}
	if managedAmneziaWGAckTimeout < 2*managedAmneziaWGDNSDeadline+2*time.Second {
		t.Fatal("deny-policy acknowledgement timeout does not cover two serial DNS lookups")
	}
	restartRoot := t.TempDir()
	restartDirectory := restartRoot + "/" + service.ServiceTag
	if err = os.Mkdir(restartDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	restartConfig := restartDirectory + "/config.json"
	if err = os.WriteFile(managedAmneziaWGDenyHoldPath(restartConfig), []byte("corrupt\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.RemoveAll(restartDirectory); err != nil || os.Mkdir(restartDirectory, 0700) != nil {
		t.Fatal("could not simulate managed service config replacement")
	}
	if applyManagedAmneziaWGDenyTickerReload(relay, service, &currentRevision, restartConfig, func() (managedAmneziaWGHelperConfig, error) { return stable, nil }) ||
		relay.destinationAllowed(netip.MustParseAddrPort("8.8.8.8:443")) {
		t.Fatal("durable hold marker was bypassed by a periodic or restarted helper reload")
	}
	if applyManagedAmneziaWGDenyReload(relay, service, &currentRevision, false, strings.Repeat("0", 64), func() (managedAmneziaWGHelperConfig, error) { return stable, nil }) {
		t.Fatal("a stale wrapper was acknowledged against a different pinned revision")
	}
	if !applyManagedAmneziaWGDenyReload(relay, service, &currentRevision, false, stable.DenyRevision, func() (managedAmneziaWGHelperConfig, error) { return stable, nil }) ||
		relay.destinationAllowed(netip.MustParseAddrPort("8.8.8.8:443")) {
		t.Fatal("pinned policy acknowledgement released the durable hold before the parent cleared it")
	}
	if !applyManagedAmneziaWGDenyReload(relay, service, &currentRevision, true, "", func() (managedAmneziaWGHelperConfig, error) { return stable, nil }) ||
		!relay.destinationAllowed(netip.MustParseAddrPort("8.8.8.8:443")) {
		t.Fatal("same-revision stable recovery acknowledged while the relay remained held fail closed")
	}
	lifecycleRoot := t.TempDir()
	otherTag := service.ServiceTag[:len(service.ServiceTag)-1] + "0"
	if otherTag == service.ServiceTag {
		otherTag = service.ServiceTag[:len(service.ServiceTag)-1] + "1"
	}
	retainedConfig := lifecycleRoot + "/" + service.ServiceTag + "/config.json"
	staleConfig := lifecycleRoot + "/" + otherTag + "/config.json"
	if err = os.WriteFile(managedAmneziaWGDenyHoldPath(retainedConfig), []byte(stable.DenyRevision+"\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(managedAmneziaWGDenyHoldPath(staleConfig), []byte(stable.DenyRevision+"\n"), 0640); err != nil {
		t.Fatal(err)
	}
	ownerUID, ownerGID := uint32(os.Geteuid()), uint32(os.Getegid())
	if err = removeManagedAmneziaWGHoldMarkersOwned(lifecycleRoot, map[string]bool{service.ServiceTag: true}, ownerUID, ownerGID); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(managedAmneziaWGDenyHoldPath(retainedConfig)); err != nil {
		t.Fatal("desired AWG marker was removed during config activation")
	}
	if _, err = os.Lstat(managedAmneziaWGDenyHoldPath(staleConfig)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("removed AWG service marker survived config activation")
	}
	if err = removeManagedAmneziaWGHoldMarkersOwned(lifecycleRoot, nil, ownerUID, ownerGID); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(managedAmneziaWGDenyHoldPath(retainedConfig)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("AWG hold marker survived managed service uninstall cleanup")
	}
	select {
	case <-relay.closed:
		t.Fatal("panel URL refresh stopped the running data plane")
	default:
	}
	if applyManagedAmneziaWGDenyReload(relay, service, &currentRevision, true, "", func() (managedAmneziaWGHelperConfig, error) {
		return managedAmneziaWGHelperConfig{}, errors.New("wrapper temporarily unavailable")
	}) || relay.destinationAllowed(netip.MustParseAddrPort("8.8.8.8:443")) {
		t.Fatal("reload failure did not keep the running relay fail closed")
	}
	relay.refreshDeniedDestinations()
	if relay.destinationAllowed(netip.MustParseAddrPort("8.8.8.8:443")) {
		t.Fatal("an in-flight or periodic refresh reopened a failed wrapper reload")
	}
	select {
	case <-relay.closed:
		t.Fatal("reload failure stopped the running data plane")
	default:
	}
}

func assertManagedAmneziaWGStrictContract(t *testing.T, raw json.RawMessage) {
	t.Helper()
	mutate := func(apply func([]map[string]any)) []byte {
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatal(err)
		}
		servicesRaw := document["services"].([]any)
		services := make([]map[string]any, len(servicesRaw))
		for index := range servicesRaw {
			services[index] = servicesRaw[index].(map[string]any)
		}
		apply(services)
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	zeroKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	unclampedKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	cases := []struct {
		name  string
		apply func([]map[string]any)
	}{
		{name: "AWG explicit null MTProto field", apply: func(services []map[string]any) { services[1]["artifact"] = nil }},
		{name: "MTProto explicit null AWG field", apply: func(services []map[string]any) { services[0]["publicAddress"] = nil }},
		{name: "AWG explicit null required field", apply: func(services []map[string]any) { services[1]["publicAddress"] = nil }},
		{name: "zero server private key", apply: func(services []map[string]any) { services[1]["serverPrivateKey"] = zeroKey }},
		{name: "unclamped server private key", apply: func(services []map[string]any) { services[1]["serverPrivateKey"] = unclampedKey }},
		{name: "zero peer public key", apply: func(services []map[string]any) {
			services[1]["peers"].([]any)[0].(map[string]any)["publicKey"] = zeroKey
		}},
		{name: "zero peer PSK", apply: func(services []map[string]any) {
			services[1]["peers"].([]any)[0].(map[string]any)["preSharedKey"] = zeroKey
		}},
		{name: "zero header key", apply: func(services []map[string]any) {
			services[1]["obfuscation"].(map[string]any)["headerProtectionKey"] = zeroKey
		}},
	}
	for _, testCase := range cases {
		if _, err := DecodeManagedServicesDesiredState(mutate(testCase.apply)); err == nil {
			t.Fatalf("%s was accepted", testCase.name)
		}
	}
}

func assertManagedAmneziaWGStackAndPolicy(t *testing.T, service ManagedServiceDesired) {
	t.Helper()
	tunnel, err := newManagedAmneziaWGStackTun(service.MTU)
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Close()
	address, stackErr := tunnel.stack.GetMainNICAddress(1, ipv4.ProtocolNumber)
	if stackErr != nil || address.Address.String() != "10.8.1.1" || address.PrefixLen != 24 {
		t.Fatalf("userspace server address is not 10.8.1.1/24: %#v, %v", address, stackErr)
	}

	resolved := map[string][]netip.Addr{
		"vpn.example.com":   {netip.MustParseAddr("8.8.4.4")},
		"panel.example.com": {netip.MustParseAddr("1.1.1.1")},
	}
	interfaceIP := "9.9.9.9"
	relay := &managedAmneziaWGRelay{
		denyHosts: []string{"vpn.example.com", "panel.example.com"}, denied: map[netip.Addr]struct{}{}, denyFailed: true,
		interfaceAddrs: func() ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP(interfaceIP), Mask: net.CIDRMask(32, 32)}}, nil
		},
		lookupNetIP: func(_ context.Context, _, host string) ([]netip.Addr, error) {
			addresses, ok := resolved[host]
			if !ok {
				return nil, errors.New("unresolved")
			}
			return addresses, nil
		},
		tcp: map[*managedAmneziaWGTCPRelay]struct{}{}, udp: map[string]*managedAmneziaWGUDPSession{}, closed: make(chan struct{}),
	}
	if relay.destinationAllowed(netip.MustParseAddrPort("8.8.8.8:443")) {
		t.Fatal("relay did not start fail closed")
	}
	relay.refreshDeniedDestinations()
	for _, denied := range []string{"8.8.4.4:443", "1.1.1.1:443", "9.9.9.9:443", "10.0.0.1:443", "169.254.169.254:80"} {
		if relay.destinationAllowed(netip.MustParseAddrPort(denied)) {
			t.Fatalf("denied destination %s was allowed", denied)
		}
	}
	if !relay.destinationAllowed(netip.MustParseAddrPort("8.8.8.8:443")) {
		t.Fatal("public destination was not allowed after a complete refresh")
	}
	resolved["vpn.example.com"] = []netip.Addr{netip.MustParseAddr("208.67.222.222")}
	interfaceIP = "4.2.2.2"
	relay.refreshDeniedDestinations()
	for _, denied := range []string{"208.67.222.222:443", "4.2.2.2:443"} {
		if relay.destinationAllowed(netip.MustParseAddrPort(denied)) {
			t.Fatalf("refreshed destination %s was allowed", denied)
		}
	}
	delete(resolved, "panel.example.com")
	relay.refreshDeniedDestinations()
	if relay.destinationAllowed(netip.MustParseAddrPort("8.8.8.8:443")) {
		t.Fatal("DNS failure did not fail the relay closed")
	}
}

func assertManagedServiceObservedTargetsArePerKind(t *testing.T, services []ManagedServiceDesired) {
	t.Helper()
	targets, targetErrors := inspectManagedServiceTargetsForObserved(services, func(service ManagedServiceDesired) (managedServiceTarget, error) {
		if service.Kind == managedServicesKindMTProto {
			return managedServiceTarget{}, errors.New("MTProto artifact unavailable")
		}
		return managedServiceTarget{version: service.TargetVersion, binaryHash: strings.Repeat("a", 64)}, nil
	})
	if targetErrors[managedServicesKindMTProto] == nil || targetErrors[managedServicesKindAmneziaWG] != nil || targets[managedServicesKindAmneziaWG].version != managedServicesAmneziaWGVersion {
		t.Fatalf("one kind poisoned the other kind's observed target: targets=%#v errors=%#v", targets, targetErrors)
	}
}

func assertManagedAmneziaWGPeerTCPAndUDP(t *testing.T, template ManagedServiceDesired) {
	t.Helper()
	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpListener.Close()
	go func() {
		connection, acceptErr := tcpListener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		payload := make([]byte, 32)
		count, readErr := connection.Read(payload)
		if readErr == nil {
			_, _ = connection.Write(payload[:count])
		}
	}()
	udpEcho, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go func() {
		payload := make([]byte, 32)
		count, remote, readErr := udpEcho.ReadFromUDP(payload)
		if readErr == nil {
			_, _ = udpEcho.WriteToUDP(payload[:count], remote)
		}
	}()
	portReservation, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	listenPort := portReservation.LocalAddr().(*net.UDPAddr).Port
	_ = portReservation.Close()

	serverPrivate := []byte{8}
	serverPrivate = append(serverPrivate, bytes.Repeat([]byte{1}, 30)...)
	serverPrivate = append(serverPrivate, 64)
	peerPrivate := []byte{16}
	peerPrivate = append(peerPrivate, bytes.Repeat([]byte{2}, 30)...)
	peerPrivate = append(peerPrivate, 64)
	serverPublic, err := curve25519.X25519(serverPrivate, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	peerPublic, err := curve25519.X25519(peerPrivate, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	service := template
	service.ListenPort = listenPort
	service.PublicAddress = "8.8.4.4"
	service.ServerPrivateKey = base64.StdEncoding.EncodeToString(serverPrivate)
	service.Peers = append([]ManagedAmneziaWGPeerDesired(nil), template.Peers...)
	service.Peers[0].PublicKey = base64.StdEncoding.EncodeToString(peerPublic)

	serverTunnel, err := newManagedAmneziaWGStackTun(service.MTU)
	if err != nil {
		t.Fatal(err)
	}
	defer serverTunnel.Close()
	tcpEchoAddress := tcpListener.Addr().String()
	udpEchoAddress := udpEcho.LocalAddr().(*net.UDPAddr)
	dialer := &net.Dialer{}
	relay := newManagedAmneziaWGRelayWithEnvironment(service, []string{"8.8.4.4", "1.1.1.1"}, serverTunnel.stack, managedAmneziaWGRelayEnvironment{
		interfaceAddrs: func() ([]net.Addr, error) { return nil, nil },
		lookupNetIP:    func(context.Context, string, string) ([]netip.Addr, error) { return nil, errors.New("unexpected DNS") },
		dialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, tcpEchoAddress)
		},
		dialUDP: func(network string, local, _ *net.UDPAddr) (*net.UDPConn, error) {
			return net.DialUDP(network, local, udpEchoAddress)
		},
	})
	defer relay.Close()
	relay.refreshDeniedDestinations()
	serverDevice := awgdevice.NewDevice(serverTunnel, awgconn.NewDefaultBind(), awgdevice.NewLogger(awgdevice.LogLevelSilent, ""))
	defer serverDevice.Close()
	serverConfiguration, err := buildManagedAmneziaWGUAPI(service)
	if err != nil || serverDevice.IpcSet(serverConfiguration) != nil || serverDevice.Up() != nil {
		t.Fatalf("official server device did not start: %v", err)
	}

	clientTunnel, clientNetwork, err := awgnetstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.8.1.2")}, nil, service.MTU)
	if err != nil {
		t.Fatal(err)
	}
	clientDevice := awgdevice.NewDevice(clientTunnel, awgconn.NewDefaultBind(), awgdevice.NewLogger(awgdevice.LogLevelSilent, ""))
	defer clientDevice.Close()
	clientConfiguration := buildManagedAmneziaWGClientUAPI(service, peerPrivate, serverPublic)
	if err = clientDevice.IpcSet(clientConfiguration); err != nil {
		t.Fatalf("official client config failed: %v", err)
	}
	if err = clientDevice.Up(); err != nil {
		t.Fatalf("official client start failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tcpConnection, err := clientNetwork.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort("8.8.8.8:443"))
	if err != nil {
		t.Fatalf("official peer TCP acceptance failed: %v", err)
	}
	defer tcpConnection.Close()
	_ = tcpConnection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = tcpConnection.Write([]byte("tcp-ok")); err != nil {
		t.Fatal(err)
	}
	tcpReply := make([]byte, 6)
	if _, err = io.ReadFull(tcpConnection, tcpReply); err != nil || string(tcpReply) != "tcp-ok" {
		t.Fatalf("official peer TCP payload failed: %q, %v", tcpReply, err)
	}

	udpConnection, err := clientNetwork.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("8.8.8.8:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer udpConnection.Close()
	_ = udpConnection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = udpConnection.Write([]byte("udp-ok")); err != nil {
		t.Fatal(err)
	}
	udpReply := make([]byte, 6)
	if _, err = io.ReadFull(udpConnection, udpReply); err != nil || string(udpReply) != "udp-ok" {
		t.Fatalf("official peer UDP payload failed: %q, %v", udpReply, err)
	}

	for _, denied := range []string{"10.0.0.1:443", "169.254.169.254:80", "8.8.4.4:443", "1.1.1.1:443"} {
		denyContext, denyCancel := context.WithTimeout(context.Background(), time.Second)
		connection, dialErr := clientNetwork.DialContextTCPAddrPort(denyContext, netip.MustParseAddrPort(denied))
		denyCancel()
		if dialErr == nil {
			_ = connection.Close()
			t.Fatalf("official peer reached denied destination %s", denied)
		}
	}
}

func buildManagedAmneziaWGClientUAPI(service ManagedServiceDesired, privateKey, serverPublic []byte) string {
	o := service.Obfuscation
	privateHex := hex.EncodeToString(privateKey)
	serverPublicHex := hex.EncodeToString(serverPublic)
	preSharedKey, _ := managedAmneziaWGKeyHex(service.Peers[0].PreSharedKey)
	headerKey, _ := managedAmneziaWGKeyHex(o.HeaderProtectionKey)
	var builder strings.Builder
	fmt.Fprintf(&builder, "private_key=%s\nlisten_port=0\nreplace_peers=true\n", privateHex)
	fmt.Fprintf(&builder, "jc=%d\njmin=%d\njmax=%d\ns1=%d\ns2=%d\ns3=%d\ns4=%d\n", o.JC, o.JMin, o.JMax, o.S1, o.S2, o.S3, o.S4)
	fmt.Fprintf(&builder, "h1=%s\nh2=%s\nh3=%s\nh4=%s\ni1=%s\n", o.H1, o.H2, o.H3, o.H4, o.I1)
	fmt.Fprintf(&builder, "header_protection_key=%s\ncontent_padding_addition=%s\n", headerKey, o.ContentPaddingAddition)
	fmt.Fprintf(&builder, "rekey_after_time=%s\nrekey_timeout=%s\nreject_after_time=%s\n", o.RekeyAfterTime, o.RekeyTimeout, o.RejectAfterTime)
	fmt.Fprintf(&builder, "keepalive_timeout=%s\nmax_handshake_attempts=%s\nrandom_trailers=true\ndisable_cookies=true\n", o.KeepaliveTimeout, o.MaxHandshakeAttempts)
	fmt.Fprintf(&builder, "public_key=%s\npreshared_key=%s\nendpoint=127.0.0.1:%d\npersistent_keepalive_interval=25\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\n", serverPublicHex, preSharedKey, service.ListenPort)
	return builder.String()
}
