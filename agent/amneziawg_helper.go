package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	awgconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	awgdevice "github.com/amnezia-vpn/amneziawg-go/v3/device"
	awgtun "github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	managedAmneziaWGHelperCommand    = "__forwardx-amneziawg"
	managedAmneziaWGQueueDepth       = 1024
	managedAmneziaWGTCPMaxSessions   = 256
	managedAmneziaWGUDPMaxSessions   = 512
	managedAmneziaWGUDPQueueDepth    = 8
	managedAmneziaWGUDPMaxPayload    = 8192
	managedAmneziaWGSessionTimeout   = 5 * time.Minute
	managedAmneziaWGUDPIdleTimeout   = 2 * time.Minute
	managedAmneziaWGDenyRefresh      = 30 * time.Second
	managedAmneziaWGDNSDeadline      = 5 * time.Second
	managedAmneziaWGAckTimeout       = 2*managedAmneziaWGDNSDeadline + 2*time.Second
	managedAmneziaWGDNSMaxResults    = 32
	managedAmneziaWGPolicyStable     = "STABLE"
	managedAmneziaWGPolicyTransition = "TRANSITION"
	managedAmneziaWGAckFileName      = "deny-policy.ack"
	managedAmneziaWGHoldFileSuffix   = ".deny-policy.hold"
)

var (
	managedAmneziaWGKeyPattern         = regexpMustCompile(`^[A-Za-z0-9+/]{43}=$`)
	managedAmneziaWGPeerAddressPattern = regexpMustCompile(`^10\.8\.1\.(?:[2-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])/32$`)
	managedAmneziaWGI1Pattern          = regexpMustCompile(`^<r (?:3[2-9]|[4-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-6])>$`)
	managedAmneziaWGRangePattern       = regexpMustCompile(`^(?:0|[1-9][0-9]{0,9})(?:-(?:0|[1-9][0-9]{0,9}))?$`)
	managedAmneziaWGStagePattern       = regexpMustCompile(`^\.stage-[A-Za-z0-9]+$`)
)

// regexpMustCompile is kept local to this runtime so the hidden helper does
// not need any user-controlled regular expression input.
func regexpMustCompile(expression string) *regexp.Regexp { return regexp.MustCompile(expression) }

func (service ManagedServiceDesired) hasAmneziaWGFields() bool {
	return service.PublicAddress != "" || service.Subnet != "" || service.MTU != 0 || len(service.DNS) != 0 || service.ServerPrivateKey != "" ||
		service.Obfuscation != nil || len(service.Peers) != 0
}

func (service ManagedServiceDesired) hasMTProtoFields() bool {
	return service.Artifact != nil || service.FakeTLSDomain != "" || len(service.Accounts) != 0
}

func validateManagedAmneziaWGDesired(service ManagedServiceDesired) ([]string, error) {
	if !managedAmneziaWGServiceTagPattern.MatchString(service.ServiceTag) || service.TargetVersion != managedServicesAmneziaWGVersion ||
		service.hasMTProtoFields() || !validManagedAmneziaWGPublicAddress(service.PublicAddress) || service.Subnet != "10.8.1.0/24" || service.MTU != 1420 ||
		len(service.DNS) != 2 || service.DNS[0] != "1.1.1.1" || service.DNS[1] != "1.0.0.1" ||
		service.Obfuscation == nil ||
		len(service.Peers) == 0 || len(service.Peers) > 32 {
		return nil, errors.New("invalid AmneziaWG desired service")
	}
	if err := validateManagedAmneziaWGPrivateKey(service.ServerPrivateKey); err != nil {
		return nil, errors.New("invalid AmneziaWG server private key")
	}
	if err := validateManagedAmneziaWGObfuscation(*service.Obfuscation); err != nil {
		return nil, err
	}
	seenTags := map[string]bool{}
	seenAddresses := map[string]bool{}
	seenPublicKeys := map[string]bool{}
	seenPreSharedKeys := map[string]bool{}
	tags := make([]string, 0, len(service.Peers))
	for _, peer := range service.Peers {
		if !managedAmneziaWGAccountTagPattern.MatchString(peer.AccountTag) ||
			!managedAmneziaWGPeerAddressPattern.MatchString(peer.Address) ||
			seenTags[peer.AccountTag] || seenAddresses[peer.Address] || seenPublicKeys[peer.PublicKey] || seenPreSharedKeys[peer.PreSharedKey] {
			return nil, errors.New("invalid AmneziaWG desired peer")
		}
		if _, err := decodeManagedAmneziaWGNonZeroKey(peer.PublicKey); err != nil {
			return nil, errors.New("invalid AmneziaWG peer public key")
		}
		if _, err := decodeManagedAmneziaWGNonZeroKey(peer.PreSharedKey); err != nil {
			return nil, errors.New("invalid AmneziaWG peer pre-shared key")
		}
		seenTags[peer.AccountTag], seenAddresses[peer.Address] = true, true
		seenPublicKeys[peer.PublicKey], seenPreSharedKeys[peer.PreSharedKey] = true, true
		tags = append(tags, peer.AccountTag)
	}
	return tags, nil
}

func validManagedAmneziaWGPublicAddress(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) {
		return false
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == ""
	}
	return managedDomainPattern.MatchString(value)
}

func validateManagedAmneziaWGObfuscation(value ManagedAmneziaWGObfuscationDesired) error {
	if value.JC < 1 || value.JC > 128 || value.JMin < 0 || value.JMin > 1280 || value.JMax < value.JMin || value.JMax > 1280 ||
		value.S1 < 12 || value.S1 > 1024 || value.S2 < 12 || value.S2 > 1024 || value.S1+56 == value.S2 ||
		value.S3 < 12 || value.S3 > 64 || value.S4 < 12 || value.S4 > 32 ||
		!managedAmneziaWGI1Pattern.MatchString(value.I1) ||
		!value.RandomTrailers || !value.DisableCookies {
		return errors.New("invalid AmneziaWG obfuscation")
	}
	if _, err := decodeManagedAmneziaWGNonZeroKey(value.HeaderProtectionKey); err != nil {
		return errors.New("invalid AmneziaWG header protection key")
	}
	ranges := make([][2]uint64, 0, 4)
	for _, raw := range []string{value.H1, value.H2, value.H3, value.H4} {
		parsed, err := parseManagedAmneziaWGRange(raw, 5, 4294967295)
		if err != nil {
			return errors.New("invalid AmneziaWG header range")
		}
		ranges = append(ranges, parsed)
	}
	sort.Slice(ranges, func(i, j int) bool { return ranges[i][0] < ranges[j][0] })
	for index := 1; index < len(ranges); index++ {
		if ranges[index][0] <= ranges[index-1][1] {
			return errors.New("overlapping AmneziaWG header ranges")
		}
	}
	for _, rule := range []struct {
		value   string
		minimum uint64
		maximum uint64
	}{
		{value.ContentPaddingAddition, 0, 64},
		{value.RekeyAfterTime, 1, 86400},
		{value.RekeyTimeout, 1, 300},
		{value.RejectAfterTime, 1, 86400},
		{value.KeepaliveTimeout, 1, 300},
		{value.MaxHandshakeAttempts, 1, 1000},
	} {
		if _, err := parseManagedAmneziaWGRange(rule.value, rule.minimum, rule.maximum); err != nil {
			return errors.New("invalid AmneziaWG timing range")
		}
	}
	return nil
}

func parseManagedAmneziaWGRange(value string, minimum, maximum uint64) ([2]uint64, error) {
	var result [2]uint64
	if len(value) > 32 || !managedAmneziaWGRangePattern.MatchString(value) {
		return result, errors.New("invalid range")
	}
	parts := strings.SplitN(value, "-", 2)
	lower, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return result, err
	}
	upper := lower
	if len(parts) == 2 {
		upper, err = strconv.ParseUint(parts[1], 10, 64)
	}
	if err != nil || lower < minimum || upper < lower || upper > maximum {
		return result, errors.New("range outside bounds")
	}
	return [2]uint64{lower, upper}, nil
}

func renderManagedAmneziaWGConfig(service ManagedServiceDesired) ([]byte, error) {
	return renderManagedAmneziaWGConfigForPanelPolicy(service, managedAmneziaWGPolicyStable, currentPanelURL(Config{}))
}

func renderManagedAmneziaWGConfigForPanelPolicy(service ManagedServiceDesired, denyMode, panelURL string) ([]byte, error) {
	if _, err := validateManagedAmneziaWGDesired(service); err != nil {
		return nil, err
	}
	if denyMode != managedAmneziaWGPolicyStable && denyMode != managedAmneziaWGPolicyTransition {
		return nil, errors.New("managed service deny mode is invalid")
	}
	denyHosts, err := managedAmneziaWGDenyHostsForPanelURL(service, panelURL)
	if err != nil {
		return nil, err
	}
	return json.Marshal(managedAmneziaWGHelperConfig{
		SchemaVersion: 1, Service: service, DenyMode: denyMode,
		DenyRevision: managedAmneziaWGDenyRevision(denyMode, denyHosts), DenyHosts: denyHosts,
	})
}

type managedAmneziaWGHelperConfig struct {
	SchemaVersion int                   `json:"schemaVersion"`
	Service       ManagedServiceDesired `json:"service"`
	DenyMode      string                `json:"denyMode"`
	DenyRevision  string                `json:"denyRevision"`
	DenyHosts     []string              `json:"denyHosts"`
}

func managedAmneziaWGDenyHosts(service ManagedServiceDesired) ([]string, error) {
	return managedAmneziaWGDenyHostsForPanelURL(service, currentPanelURL(Config{}))
}

func managedAmneziaWGDenyHostsForPanelURL(service ManagedServiceDesired, panelURL string) ([]string, error) {
	hosts := []string{strings.ToLower(strings.TrimSuffix(service.PublicAddress, "."))}
	parsedPanel, err := url.Parse(strings.TrimSpace(panelURL))
	if err != nil || (parsedPanel.Scheme != "http" && parsedPanel.Scheme != "https") || parsedPanel.Hostname() == "" {
		return nil, errors.New("managed service panel host is unavailable")
	}
	hosts = append(hosts, strings.ToLower(strings.TrimSuffix(parsedPanel.Hostname(), ".")))
	result := make([]string, 0, len(hosts))
	seen := map[string]bool{}
	for _, host := range hosts {
		if !validManagedAmneziaWGDenyHost(host) {
			return nil, errors.New("managed service deny host is invalid")
		}
		if !seen[host] {
			seen[host] = true
			result = append(result, host)
		}
	}
	sort.Strings(result)
	return result, nil
}

func managedAmneziaWGDenyRevision(denyMode string, denyHosts []string) string {
	return hashManagedServicesBytes([]byte(denyMode + "\n" + strings.Join(denyHosts, "\n")))
}

func validManagedAmneziaWGDenyHost(value string) bool {
	if value == "" || len(value) > 253 || value != strings.ToLower(value) || strings.ContainsAny(value, "\x00\r\n\t /[]") {
		return false
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == ""
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func validateManagedAmneziaWGHelperConfig(config managedAmneziaWGHelperConfig) error {
	if config.SchemaVersion != 1 || (config.DenyMode != managedAmneziaWGPolicyStable && config.DenyMode != managedAmneziaWGPolicyTransition) ||
		!xraySHA256Pattern.MatchString(config.DenyRevision) || len(config.DenyHosts) == 0 || len(config.DenyHosts) > 2 ||
		config.DenyRevision != managedAmneziaWGDenyRevision(config.DenyMode, config.DenyHosts) {
		return errors.New("invalid AmneziaWG helper wrapper")
	}
	if _, err := validateManagedAmneziaWGDesired(config.Service); err != nil {
		return err
	}
	seen := map[string]bool{}
	containsPublicAddress := false
	for _, host := range config.DenyHosts {
		if !validManagedAmneziaWGDenyHost(host) || seen[host] {
			return errors.New("invalid AmneziaWG helper deny host")
		}
		seen[host] = true
		containsPublicAddress = containsPublicAddress || host == config.Service.PublicAddress
	}
	if !containsPublicAddress {
		return errors.New("AmneziaWG public address is not denied")
	}
	return nil
}

func managedAmneziaWGHelperConfigMatches(raw []byte, service ManagedServiceDesired) bool {
	var config managedAmneziaWGHelperConfig
	if strictManagedServicesJSON(raw, &config) != nil || validateManagedAmneziaWGHelperConfig(config) != nil ||
		!sameManagedAmneziaWGService(config.Service, service) {
		return false
	}
	required, err := managedAmneziaWGDenyHosts(service)
	if err != nil {
		return false
	}
	present := map[string]bool{}
	for _, host := range config.DenyHosts {
		present[host] = true
	}
	for _, host := range required {
		if !present[host] {
			return false
		}
	}
	return true
}

func decodeManagedAmneziaWGKey(value string) ([32]byte, error) {
	var key [32]byte
	if !managedAmneziaWGKeyPattern.MatchString(value) {
		return key, errors.New("invalid AmneziaWG key")
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != len(key) || base64.StdEncoding.EncodeToString(decoded) != value {
		return key, errors.New("invalid AmneziaWG key")
	}
	copy(key[:], decoded)
	return key, nil
}

func decodeManagedAmneziaWGNonZeroKey(value string) ([32]byte, error) {
	key, err := decodeManagedAmneziaWGKey(value)
	if err != nil {
		return key, err
	}
	var aggregate byte
	for _, value := range key {
		aggregate |= value
	}
	if aggregate == 0 {
		return key, errors.New("zero AmneziaWG key")
	}
	return key, nil
}

func validateManagedAmneziaWGPrivateKey(value string) error {
	key, err := decodeManagedAmneziaWGNonZeroKey(value)
	if err != nil {
		return err
	}
	if key[0]&7 != 0 || key[31]&128 != 0 || key[31]&64 == 0 {
		return errors.New("AmneziaWG private key is not clamped")
	}
	return nil
}

func managedAmneziaWGKeyHex(value string) (string, error) {
	key, err := decodeManagedAmneziaWGKey(value)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key[:]), nil
}

func buildManagedAmneziaWGUAPI(service ManagedServiceDesired) (string, error) {
	privateKey, err := managedAmneziaWGKeyHex(service.ServerPrivateKey)
	if err != nil {
		return "", err
	}
	o := service.Obfuscation
	var builder strings.Builder
	fmt.Fprintf(&builder, "private_key=%s\nlisten_port=%d\nreplace_peers=true\n", privateKey, service.ListenPort)
	fmt.Fprintf(&builder, "jc=%d\njmin=%d\njmax=%d\ns1=%d\ns2=%d\ns3=%d\ns4=%d\n", o.JC, o.JMin, o.JMax, o.S1, o.S2, o.S3, o.S4)
	fmt.Fprintf(&builder, "h1=%s\nh2=%s\nh3=%s\nh4=%s\ni1=%s\n", o.H1, o.H2, o.H3, o.H4, o.I1)
	headerKey, err := managedAmneziaWGKeyHex(o.HeaderProtectionKey)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(&builder, "header_protection_key=%s\ncontent_padding_addition=%s\n", headerKey, o.ContentPaddingAddition)
	fmt.Fprintf(&builder, "rekey_after_time=%s\nrekey_timeout=%s\nreject_after_time=%s\n", o.RekeyAfterTime, o.RekeyTimeout, o.RejectAfterTime)
	fmt.Fprintf(&builder, "keepalive_timeout=%s\nmax_handshake_attempts=%s\nrandom_trailers=true\ndisable_cookies=true\n", o.KeepaliveTimeout, o.MaxHandshakeAttempts)
	for _, peer := range service.Peers {
		publicKey, publicErr := managedAmneziaWGKeyHex(peer.PublicKey)
		preSharedKey, preSharedErr := managedAmneziaWGKeyHex(peer.PreSharedKey)
		if publicErr != nil || preSharedErr != nil {
			return "", errors.New("invalid AmneziaWG peer key")
		}
		fmt.Fprintf(&builder, "public_key=%s\npreshared_key=%s\nallowed_ip=%s\n", publicKey, preSharedKey, peer.Address)
	}
	return builder.String(), nil
}

func runManagedAmneziaWGHelperCommand(args []string) (bool, int) {
	if len(args) < 2 || args[1] != managedAmneziaWGHelperCommand {
		return false, 0
	}
	if len(args) != 4 || (args[2] != "validate" && args[2] != "run") {
		return true, 2
	}
	config, err := loadManagedAmneziaWGHelperConfig(args[3])
	if err != nil {
		return true, 1
	}
	if args[2] == "validate" {
		if err = validateManagedAmneziaWGDeviceConfig(config.Service); err != nil {
			return true, 1
		}
		return true, 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	reloadSignals := make(chan os.Signal, 2)
	signal.Notify(reloadSignals, syscall.SIGUSR1, syscall.SIGUSR2)
	defer signal.Stop(reloadSignals)
	if err = runManagedAmneziaWGWithReload(ctx, config.Service, config.DenyHosts, config.DenyRevision, args[3], reloadSignals, func() (managedAmneziaWGHelperConfig, error) {
		return loadManagedAmneziaWGHelperConfig(args[3])
	}); err != nil {
		return true, 1
	}
	return true, 0
}

func validateManagedAmneziaWGDeviceConfig(service ManagedServiceDesired) error {
	tunnel, err := newManagedAmneziaWGStackTun(service.MTU)
	if err != nil {
		return err
	}
	defer tunnel.Close()
	configuration, err := buildManagedAmneziaWGUAPI(service)
	if err != nil {
		return err
	}
	configuration = strings.Replace(configuration, fmt.Sprintf("listen_port=%d\n", service.ListenPort), "listen_port=0\n", 1)
	device := awgdevice.NewDevice(tunnel, awgconn.NewDefaultBind(), awgdevice.NewLogger(awgdevice.LogLevelSilent, ""))
	defer device.Close()
	if err = device.IpcSet(configuration); err != nil {
		return errors.New("AmneziaWG device rejected configuration")
	}
	return nil
}

func loadManagedAmneziaWGHelperConfig(path string) (managedAmneziaWGHelperConfig, error) {
	var config managedAmneziaWGHelperConfig
	account, err := user.Lookup(managedServicesAmneziaWGUserName)
	if err != nil || strconv.Itoa(os.Geteuid()) != account.Uid || os.Geteuid() == 0 {
		return config, errors.New("AmneziaWG helper identity mismatch")
	}
	groupID, err := strconv.ParseUint(account.Gid, 10, 32)
	if err != nil || groupID == 0 || uint64(os.Getegid()) != groupID {
		return config, errors.New("AmneziaWG helper group identity mismatch")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || !managedServiceStatusIDsMatch(status, "Uid:", uint32(os.Geteuid())) ||
		!managedServiceStatusIDsMatch(status, "Gid:", uint32(groupID)) || !managedServiceSupplementaryGroupsEmpty(status) ||
		!managedServiceStatusCapabilitiesEmpty(status) {
		return config, errors.New("AmneziaWG helper credentials are unsafe")
	}
	clean := filepath.Clean(path)
	directory := filepath.Dir(clean)
	tag := filepath.Base(directory)
	if filepath.Base(clean) != "config.json" || !managedAmneziaWGServiceTagPattern.MatchString(tag) ||
		!managedAmneziaWGHelperPathAllowed(clean, uint32(groupID)) {
		return config, errors.New("AmneziaWG helper path is unsafe")
	}
	info, err := os.Lstat(clean)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0640 ||
		info.Size() <= 0 || info.Size() > managedServicesMaxControlBytes {
		return config, errors.New("AmneziaWG helper config is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || strconv.FormatUint(uint64(stat.Gid), 10) != account.Gid {
		return config, errors.New("AmneziaWG helper config ownership mismatch")
	}
	raw, err := os.ReadFile(clean)
	if err != nil || strictManagedServicesJSON(raw, &config) != nil {
		return config, errors.New("AmneziaWG helper config is invalid")
	}
	if err = validateManagedAmneziaWGHelperConfig(config); err != nil || config.Service.ServiceTag != tag {
		return config, errors.New("AmneziaWG helper config does not match its path")
	}
	return config, nil
}

func managedAmneziaWGHelperPathAllowed(path string, gid uint32) bool {
	relative, err := filepath.Rel(managedServicesConfigBaseRoot, path)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false
	}
	parts := strings.Split(relative, string(filepath.Separator))
	var directories []struct {
		path string
		gid  uint32
		mode os.FileMode
	}
	directories = append(directories, struct {
		path string
		gid  uint32
		mode os.FileMode
	}{managedServicesConfigBaseRoot, 0, 0755})
	switch {
	case len(parts) == 3 && parts[0] == "amneziawg":
		directories = append(directories,
			struct {
				path string
				gid  uint32
				mode os.FileMode
			}{managedServicesAmneziaWGConfigRoot, 0, 0755},
			struct {
				path string
				gid  uint32
				mode os.FileMode
			}{filepath.Join(managedServicesAmneziaWGConfigRoot, parts[1]), gid, 0750},
		)
	case len(parts) == 4 && managedAmneziaWGStagePattern.MatchString(parts[0]) && parts[1] == "amneziawg":
		stage := filepath.Join(managedServicesConfigBaseRoot, parts[0])
		directories = append(directories,
			struct {
				path string
				gid  uint32
				mode os.FileMode
			}{stage, 0, 0755},
			struct {
				path string
				gid  uint32
				mode os.FileMode
			}{filepath.Join(stage, "amneziawg"), 0, 0755},
			struct {
				path string
				gid  uint32
				mode os.FileMode
			}{filepath.Join(stage, "amneziawg", parts[2]), gid, 0750},
		)
	default:
		return false
	}
	for _, expected := range directories {
		info, statErr := os.Lstat(expected.path)
		stat, ok := infoSysStat(info)
		if statErr != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != expected.mode ||
			stat.Uid != 0 || stat.Gid != expected.gid {
			return false
		}
	}
	return true
}

func infoSysStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

type managedAmneziaWGStackTun struct {
	ep        *channel.Endpoint
	stack     *stack.Stack
	events    chan awgtun.Event
	notify    *channel.NotificationHandle
	packets   chan *buffer.View
	done      chan struct{}
	closeOnce sync.Once
	mtu       int
}

func newManagedAmneziaWGStackTun(mtu int) (*managedAmneziaWGStackTun, error) {
	t := &managedAmneziaWGStackTun{
		ep: channel.New(managedAmneziaWGQueueDepth, uint32(mtu), ""),
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
		}),
		events: make(chan awgtun.Event, 1), packets: make(chan *buffer.View, managedAmneziaWGQueueDepth), done: make(chan struct{}), mtu: mtu,
	}
	t.notify = t.ep.AddNotify(t)
	if err := t.stack.CreateNIC(1, t.ep); err != nil {
		t.Close()
		return nil, errors.New("AmneziaWG userspace NIC creation failed")
	}
	address := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address: tcpip.AddrFrom4([4]byte{10, 8, 1, 1}), PrefixLen: 24,
		},
	}
	if err := t.stack.AddProtocolAddress(1, address, stack.AddressProperties{}); err != nil {
		t.Close()
		return nil, errors.New("AmneziaWG userspace address setup failed")
	}
	t.stack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	t.stack.SetPromiscuousMode(1, true)
	t.stack.SetSpoofing(1, true)
	t.events <- awgtun.EventUp
	return t, nil
}

func (t *managedAmneziaWGStackTun) Name() (string, error)       { return "forwardx-amneziawg", nil }
func (t *managedAmneziaWGStackTun) File() *os.File              { return nil }
func (t *managedAmneziaWGStackTun) Events() <-chan awgtun.Event { return t.events }
func (t *managedAmneziaWGStackTun) MTU() (int, error)           { return t.mtu, nil }
func (t *managedAmneziaWGStackTun) BatchSize() int              { return 1 }

func (t *managedAmneziaWGStackTun) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	count := 0
	for count < len(buffers) {
		var view *buffer.View
		if count == 0 {
			select {
			case <-t.done:
				return 0, os.ErrClosed
			case view = <-t.packets:
			}
		} else {
			select {
			case <-t.done:
				return count, nil
			case view = <-t.packets:
			default:
				return count, nil
			}
		}
		n, err := view.Read(buffers[count][offset:])
		view.Release()
		if err != nil && !errors.Is(err, io.EOF) {
			return count, err
		}
		sizes[count] = n
		count++
	}
	return count, nil
}

func (t *managedAmneziaWGStackTun) Write(buffers [][]byte, offset int) (int, error) {
	for _, raw := range buffers {
		packet := raw[offset:]
		if len(packet) == 0 || packet[0]>>4 != 4 {
			return 0, syscall.EAFNOSUPPORT
		}
		payload := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		t.ep.InjectInbound(header.IPv4ProtocolNumber, payload)
	}
	return len(buffers), nil
}

func (t *managedAmneziaWGStackTun) WriteNotify() {
	packet := t.ep.Read()
	if packet == nil {
		return
	}
	view := packet.ToView()
	packet.DecRef()
	select {
	case t.packets <- view:
	case <-t.done:
		view.Release()
	}
}

func (t *managedAmneziaWGStackTun) Close() error {
	t.closeOnce.Do(func() {
		close(t.done)
		close(t.events)
		t.ep.RemoveNotify(t.notify)
		t.ep.Close()
		t.stack.RemoveNIC(1)
		t.stack.Close()
		for {
			select {
			case view := <-t.packets:
				view.Release()
			default:
				return
			}
		}
	})
	return nil
}

type managedAmneziaWGRelay struct {
	stack                *stack.Stack
	peers                map[netip.Addr]struct{}
	denyHosts            []string
	interfaceAddrs       func() ([]net.Addr, error)
	lookupNetIP          func(context.Context, string, string) ([]netip.Addr, error)
	dialContext          func(context.Context, string, string) (net.Conn, error)
	dialUDP              func(string, *net.UDPAddr, *net.UDPAddr) (*net.UDPConn, error)
	denyMu               sync.RWMutex
	denied               map[netip.Addr]struct{}
	denyPreserved        map[netip.Addr]struct{}
	denyResolutionFailed bool
	denyFailed           bool
	denyHold             bool
	denyGeneration       uint64
	tcpSlots             chan struct{}
	tcpMu                sync.Mutex
	tcp                  map[*managedAmneziaWGTCPRelay]struct{}
	udpMu                sync.Mutex
	udp                  map[string]*managedAmneziaWGUDPSession
	closed               chan struct{}
	closeOnce            sync.Once
}

type managedAmneziaWGRelayEnvironment struct {
	interfaceAddrs func() ([]net.Addr, error)
	lookupNetIP    func(context.Context, string, string) ([]netip.Addr, error)
	dialContext    func(context.Context, string, string) (net.Conn, error)
	dialUDP        func(string, *net.UDPAddr, *net.UDPAddr) (*net.UDPConn, error)
}

type managedAmneziaWGTCPRelay struct {
	target   netip.AddrPort
	tunnel   net.Conn
	upstream net.Conn
}

type managedAmneziaWGUDPSession struct {
	conn     *net.UDPConn
	source   netip.AddrPort
	target   netip.AddrPort
	send     chan []byte
	done     chan struct{}
	lastSeen atomic.Int64
	closed   atomic.Bool
}

func newManagedAmneziaWGRelay(service ManagedServiceDesired, denyHosts []string, networkStack *stack.Stack) *managedAmneziaWGRelay {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return newManagedAmneziaWGRelayWithEnvironment(service, denyHosts, networkStack, managedAmneziaWGRelayEnvironment{
		interfaceAddrs: net.InterfaceAddrs,
		lookupNetIP:    net.DefaultResolver.LookupNetIP,
		dialContext:    dialer.DialContext,
		dialUDP:        net.DialUDP,
	})
}

func newManagedAmneziaWGRelayWithEnvironment(service ManagedServiceDesired, denyHosts []string, networkStack *stack.Stack, environment managedAmneziaWGRelayEnvironment) *managedAmneziaWGRelay {
	relay := &managedAmneziaWGRelay{
		stack: networkStack, peers: map[netip.Addr]struct{}{}, denyHosts: append([]string(nil), denyHosts...),
		interfaceAddrs: environment.interfaceAddrs, lookupNetIP: environment.lookupNetIP,
		dialContext: environment.dialContext, dialUDP: environment.dialUDP,
		denied: map[netip.Addr]struct{}{}, denyFailed: true,
		tcpSlots: make(chan struct{}, managedAmneziaWGTCPMaxSessions), tcp: map[*managedAmneziaWGTCPRelay]struct{}{},
		udp: map[string]*managedAmneziaWGUDPSession{}, closed: make(chan struct{}),
	}
	for _, peer := range service.Peers {
		prefix, _ := netip.ParsePrefix(peer.Address)
		relay.peers[prefix.Addr()] = struct{}{}
	}
	relay.attach()
	go relay.monitorDeniedDestinations()
	return relay
}

func (r *managedAmneziaWGRelay) destinationAllowed(destination netip.AddrPort) bool {
	if !destination.IsValid() || destination.Port() == 0 || !destination.Addr().Is4() || !isAllowedXrayRealityAddress(destination.Addr()) {
		return false
	}
	r.denyMu.RLock()
	_, denied := r.denied[destination.Addr().Unmap()]
	failed := r.denyFailed
	r.denyMu.RUnlock()
	return !failed && !denied
}

func (r *managedAmneziaWGRelay) monitorDeniedDestinations() {
	ticker := time.NewTicker(managedAmneziaWGDenyRefresh)
	defer ticker.Stop()
	for {
		r.refreshDeniedDestinations()
		select {
		case <-r.closed:
			return
		case <-ticker.C:
		}
	}
}

func (r *managedAmneziaWGRelay) refreshDeniedDestinations() {
	r.denyMu.RLock()
	denyHosts := append([]string(nil), r.denyHosts...)
	denied := make(map[netip.Addr]struct{}, len(r.denyPreserved))
	for address := range r.denyPreserved {
		denied[address] = struct{}{}
	}
	generation := r.denyGeneration
	r.denyMu.RUnlock()
	failed := false
	interfaceAddresses, err := r.interfaceAddrs()
	if err != nil {
		failed = true
	} else {
		for _, raw := range interfaceAddresses {
			prefix, parseErr := netip.ParsePrefix(raw.String())
			if parseErr == nil && prefix.Addr().Is4() {
				denied[prefix.Addr().Unmap()] = struct{}{}
			}
		}
	}
	for _, host := range denyHosts {
		if address, parseErr := netip.ParseAddr(host); parseErr == nil {
			if address.Is4() {
				denied[address.Unmap()] = struct{}{}
			}
			continue
		}
		lookupContext, cancel := context.WithTimeout(context.Background(), managedAmneziaWGDNSDeadline)
		addresses, lookupErr := r.lookupNetIP(lookupContext, "ip4", host)
		cancel()
		resolved := false
		if lookupErr == nil && len(addresses) <= managedAmneziaWGDNSMaxResults {
			for _, address := range addresses {
				if address.Is4() {
					denied[address.Unmap()] = struct{}{}
					resolved = true
				}
			}
		}
		if !resolved {
			failed = true
		}
	}
	r.denyMu.Lock()
	if generation != r.denyGeneration {
		r.denyMu.Unlock()
		return
	}
	r.denied = denied
	r.denyResolutionFailed = failed
	r.denyFailed = failed || r.denyHold
	r.denyMu.Unlock()
	r.closeDisallowedSessions()
}

func (r *managedAmneziaWGRelay) failClosed() {
	r.denyMu.Lock()
	r.denyGeneration++
	r.denyFailed = true
	r.denyHold = true
	r.denyMu.Unlock()
	r.closeDisallowedSessions()
}

func (r *managedAmneziaWGRelay) replaceDenyHosts(denyHosts []string, preserveCurrent, releaseHold bool) {
	r.denyMu.Lock()
	preserved := map[netip.Addr]struct{}{}
	if preserveCurrent {
		for address := range r.denied {
			preserved[address] = struct{}{}
		}
	}
	r.denyGeneration++
	r.denyHosts = append([]string(nil), denyHosts...)
	r.denyPreserved = preserved
	r.denyResolutionFailed = true
	r.denyFailed = true
	r.denyHold = !releaseHold
	r.denyMu.Unlock()
	r.closeDisallowedSessions()
	r.refreshDeniedDestinations()
}

func sameManagedAmneziaWGService(left, right ManagedServiceDesired) bool {
	leftJSON, leftErr := marshalManagedServicesCanonical(left)
	rightJSON, rightErr := marshalManagedServicesCanonical(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}

func applyManagedAmneziaWGDenyReload(relay *managedAmneziaWGRelay, expected ManagedServiceDesired, currentRevision *string, releaseHold bool, requiredRevision string, load func() (managedAmneziaWGHelperConfig, error)) bool {
	config, err := load()
	if err != nil || validateManagedAmneziaWGHelperConfig(config) != nil || !sameManagedAmneziaWGService(config.Service, expected) ||
		(requiredRevision != "" && config.DenyRevision != requiredRevision) {
		relay.failClosed()
		return false
	}
	if currentRevision != nil && config.DenyRevision == *currentRevision {
		relay.denyMu.RLock()
		held := relay.denyHold
		relay.denyMu.RUnlock()
		if !held && releaseHold {
			return true
		}
	}
	relay.failClosed()
	relay.replaceDenyHosts(config.DenyHosts, config.DenyMode == managedAmneziaWGPolicyTransition, releaseHold)
	relay.denyMu.RLock()
	ready := !relay.denyResolutionFailed
	relay.denyMu.RUnlock()
	if ready && currentRevision != nil {
		*currentRevision = config.DenyRevision
	}
	return ready
}

func applyManagedAmneziaWGDenyTickerReload(relay *managedAmneziaWGRelay, expected ManagedServiceDesired, currentRevision *string, configPath string, load func() (managedAmneziaWGHelperConfig, error)) bool {
	if held, _ := managedAmneziaWGDenyHoldRevision(configPath); held {
		relay.failClosed()
		return false
	}
	return applyManagedAmneziaWGDenyReload(relay, expected, currentRevision, true, "", load)
}

func (r *managedAmneziaWGRelay) closeDisallowedSessions() {
	r.tcpMu.Lock()
	for relay := range r.tcp {
		if !r.destinationAllowed(relay.target) {
			_ = relay.tunnel.Close()
			_ = relay.upstream.Close()
		}
	}
	r.tcpMu.Unlock()
	r.udpMu.Lock()
	sessions := make([]*managedAmneziaWGUDPSession, 0)
	for _, session := range r.udp {
		if !r.destinationAllowed(session.target) {
			sessions = append(sessions, session)
		}
	}
	r.udpMu.Unlock()
	for _, session := range sessions {
		r.closeUDPSession(session.source.String()+"|"+session.target.String(), session)
	}
}

func managedAmneziaWGAddr(address tcpip.Address) netip.Addr {
	var raw [4]byte
	copy(raw[:], address.AsSlice())
	return netip.AddrFrom4(raw)
}

func (r *managedAmneziaWGRelay) attach() {
	forwarder := tcp.NewForwarder(r.stack, 0, managedAmneziaWGTCPMaxSessions, func(request *tcp.ForwarderRequest) {
		select {
		case r.tcpSlots <- struct{}{}:
		default:
			request.Complete(true)
			return
		}
		go func() {
			defer func() { <-r.tcpSlots }()
			id := request.ID()
			source := managedAmneziaWGAddr(id.RemoteAddress)
			destination := netip.AddrPortFrom(managedAmneziaWGAddr(id.LocalAddress), id.LocalPort)
			if _, ok := r.peers[source]; !ok || !r.destinationAllowed(destination) {
				request.Complete(true)
				return
			}
			var queue waiter.Queue
			endpoint, endpointErr := request.CreateEndpoint(&queue)
			if endpointErr != nil {
				request.Complete(true)
				return
			}
			request.Complete(false)
			tunnel := gonet.NewTCPConn(&queue, endpoint)
			defer tunnel.Close()
			dialContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			upstream, dialErr := r.dialContext(dialContext, "tcp4", destination.String())
			cancel()
			if dialErr != nil {
				return
			}
			defer upstream.Close()
			active := &managedAmneziaWGTCPRelay{target: destination, tunnel: tunnel, upstream: upstream}
			r.tcpMu.Lock()
			if !r.destinationAllowed(destination) {
				r.tcpMu.Unlock()
				return
			}
			r.tcp[active] = struct{}{}
			r.tcpMu.Unlock()
			defer func() {
				r.tcpMu.Lock()
				delete(r.tcp, active)
				r.tcpMu.Unlock()
			}()
			deadline := time.Now().Add(managedAmneziaWGSessionTimeout)
			_ = tunnel.SetDeadline(deadline)
			_ = upstream.SetDeadline(deadline)
			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(upstream, tunnel); done <- struct{}{} }()
			go func() { _, _ = io.Copy(tunnel, upstream); done <- struct{}{} }()
			select {
			case <-done:
			case <-r.closed:
			}
		}()
	})
	r.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)
	r.stack.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, packet *stack.PacketBuffer) bool {
		source := netip.AddrPortFrom(managedAmneziaWGAddr(id.RemoteAddress), id.RemotePort)
		target := netip.AddrPortFrom(managedAmneziaWGAddr(id.LocalAddress), id.LocalPort)
		clone := packet.Clone()
		payload := clone.Data().AsRange().ToSlice()
		clone.DecRef()
		r.handleUDP(source, target, payload)
		return true
	})
}

func (r *managedAmneziaWGRelay) handleUDP(source, target netip.AddrPort, payload []byte) {
	select {
	case <-r.closed:
		return
	default:
	}
	if len(payload) > managedAmneziaWGUDPMaxPayload || !r.destinationAllowed(target) {
		return
	}
	if _, ok := r.peers[source.Addr()]; !ok {
		return
	}
	key := source.String() + "|" + target.String()
	r.udpMu.Lock()
	select {
	case <-r.closed:
		r.udpMu.Unlock()
		return
	default:
	}
	session := r.udp[key]
	if session == nil && len(r.udp) < managedAmneziaWGUDPMaxSessions {
		connection, err := r.dialUDP("udp4", nil, net.UDPAddrFromAddrPort(target))
		if err == nil {
			session = &managedAmneziaWGUDPSession{
				conn: connection, source: source, target: target,
				send: make(chan []byte, managedAmneziaWGUDPQueueDepth), done: make(chan struct{}),
			}
			session.lastSeen.Store(time.Now().UnixNano())
			r.udp[key] = session
			go r.readUDP(key, session)
			go r.writeUDP(key, session)
		}
	}
	r.udpMu.Unlock()
	if session != nil && !session.closed.Load() {
		session.lastSeen.Store(time.Now().UnixNano())
		packet := append([]byte(nil), payload...)
		select {
		case session.send <- packet:
		case <-session.done:
		default:
		}
	}
}

func (r *managedAmneziaWGRelay) readUDP(key string, session *managedAmneziaWGUDPSession) {
	defer r.closeUDPSession(key, session)
	buffer := make([]byte, managedAmneziaWGUDPMaxPayload+1)
	for {
		_ = session.conn.SetReadDeadline(time.Now().Add(managedAmneziaWGUDPIdleTimeout))
		count, err := session.conn.Read(buffer)
		if err != nil {
			if networkError, ok := err.(net.Error); ok && networkError.Timeout() &&
				time.Since(time.Unix(0, session.lastSeen.Load())) <= managedAmneziaWGUDPIdleTimeout {
				continue
			}
			break
		}
		if count > managedAmneziaWGUDPMaxPayload {
			continue
		}
		session.lastSeen.Store(time.Now().UnixNano())
		_ = writeManagedAmneziaWGUDPReply(r.stack, session.target, session.source, buffer[:count])
	}

}

func (r *managedAmneziaWGRelay) writeUDP(key string, session *managedAmneziaWGUDPSession) {
	defer r.closeUDPSession(key, session)
	for {
		select {
		case <-r.closed:
			return
		case <-session.done:
			return
		case packet := <-session.send:
			if session.closed.Load() {
				return
			}
			_ = session.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := session.conn.Write(packet); err != nil {
				return
			}
		}
	}
}

func (r *managedAmneziaWGRelay) closeUDPSession(key string, session *managedAmneziaWGUDPSession) {
	if !session.closed.CompareAndSwap(false, true) {
		return
	}
	close(session.done)
	_ = session.conn.Close()
	r.udpMu.Lock()
	if r.udp[key] == session {
		delete(r.udp, key)
	}
	r.udpMu.Unlock()
}

func writeManagedAmneziaWGUDPReply(networkStack *stack.Stack, source, target netip.AddrPort, payload []byte) error {
	udpLength := header.UDPMinimumSize + len(payload)
	sourceIP := tcpip.AddrFrom4(source.Addr().As4())
	targetIP := tcpip.AddrFrom4(target.Addr().As4())
	packet := stack.NewPacketBuffer(stack.PacketBufferOptions{ReserveHeaderBytes: header.IPv4MinimumSize + header.UDPMinimumSize, Payload: buffer.MakeWithData(payload)})
	defer packet.DecRef()
	udpHeader := header.UDP(packet.TransportHeader().Push(header.UDPMinimumSize))
	udpHeader.Encode(&header.UDPFields{SrcPort: source.Port(), DstPort: target.Port(), Length: uint16(udpLength)})
	pseudo := header.PseudoHeaderChecksum(header.UDPProtocolNumber, sourceIP, targetIP, uint16(udpLength))
	udpHeader.SetChecksum(^udpHeader.CalculateChecksum(checksum.Checksum(payload, pseudo)))
	ipHeader := header.IPv4(packet.NetworkHeader().Push(header.IPv4MinimumSize))
	ipHeader.Encode(&header.IPv4Fields{TotalLength: uint16(header.IPv4MinimumSize + udpLength), TTL: 64, Protocol: uint8(header.UDPProtocolNumber), SrcAddr: sourceIP, DstAddr: targetIP})
	ipHeader.SetChecksum(^ipHeader.CalculateChecksum())
	if err := networkStack.WriteRawPacket(1, header.IPv4ProtocolNumber, buffer.MakeWithView(packet.ToView())); err != nil {
		return errors.New("AmneziaWG UDP reply injection failed")
	}
	return nil
}

func (r *managedAmneziaWGRelay) Close() {
	r.closeOnce.Do(func() {
		close(r.closed)
		r.tcpMu.Lock()
		for relay := range r.tcp {
			_ = relay.tunnel.Close()
			_ = relay.upstream.Close()
		}
		r.tcpMu.Unlock()
		r.udpMu.Lock()
		sessions := make([]*managedAmneziaWGUDPSession, 0, len(r.udp))
		for _, session := range r.udp {
			sessions = append(sessions, session)
		}
		r.udp = map[string]*managedAmneziaWGUDPSession{}
		r.udpMu.Unlock()
		for _, session := range sessions {
			if session.closed.CompareAndSwap(false, true) {
				close(session.done)
				_ = session.conn.Close()
			}
		}
	})
}

func runManagedAmneziaWG(ctx context.Context, service ManagedServiceDesired, denyHosts []string) error {
	return runManagedAmneziaWGWithReload(ctx, service, denyHosts, "", "", nil, nil)
}

func runManagedAmneziaWGWithReload(ctx context.Context, service ManagedServiceDesired, denyHosts []string, currentRevision, configPath string, reloadSignals <-chan os.Signal, load func() (managedAmneziaWGHelperConfig, error)) error {
	tunnel, err := newManagedAmneziaWGStackTun(service.MTU)
	if err != nil {
		return err
	}
	defer tunnel.Close()
	relay := newManagedAmneziaWGRelay(service, denyHosts, tunnel.stack)
	defer relay.Close()
	if held, _ := managedAmneziaWGDenyHoldRevision(configPath); held {
		relay.failClosed()
	}
	configuration, err := buildManagedAmneziaWGUAPI(service)
	if err != nil {
		return err
	}
	device := awgdevice.NewDevice(tunnel, awgconn.NewDefaultBind(), awgdevice.NewLogger(awgdevice.LogLevelSilent, ""))
	defer device.Close()
	if err = device.IpcSet(configuration); err != nil {
		return errors.New("AmneziaWG device configuration failed")
	}
	if err = device.Up(); err != nil {
		return errors.New("AmneziaWG device start failed")
	}
	var reloadTicker *time.Ticker
	var reloadTick <-chan time.Time
	if load != nil {
		reloadTicker = time.NewTicker(managedAmneziaWGDenyRefresh)
		reloadTick = reloadTicker.C
		defer reloadTicker.Stop()
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case reloadSignal := <-reloadSignals:
			if reloadSignal == syscall.SIGUSR2 || load == nil {
				relay.failClosed()
				continue
			}
			held, requiredRevision := managedAmneziaWGDenyHoldRevision(configPath)
			if held && requiredRevision == "" {
				relay.failClosed()
				continue
			}
			if applyManagedAmneziaWGDenyReload(relay, service, &currentRevision, !held, requiredRevision, load) {
				_ = writeManagedAmneziaWGDenyAck(configPath, currentRevision)
			}
		case <-reloadTick:
			if applyManagedAmneziaWGDenyTickerReload(relay, service, &currentRevision, configPath, load) {
				_ = writeManagedAmneziaWGDenyAck(configPath, currentRevision)
			}
		}
	}
}

func managedAmneziaWGDenyAckPath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), managedAmneziaWGAckFileName)
}

func managedAmneziaWGDenyHoldPath(configPath string) string {
	clean := filepath.Clean(configPath)
	if !filepath.IsAbs(clean) || clean != configPath {
		return ""
	}
	serviceDirectory := filepath.Dir(clean)
	serviceTag := filepath.Base(serviceDirectory)
	if filepath.Base(clean) != "config.json" || !managedAmneziaWGServiceTagPattern.MatchString(serviceTag) {
		return ""
	}
	return filepath.Join(filepath.Dir(serviceDirectory), "."+serviceTag+managedAmneziaWGHoldFileSuffix)
}

// Any unreadable or unsafe marker is treated as active with no permitted
// revision, so a corrupt marker can never turn a fail-closed state into an open relay.
func managedAmneziaWGDenyHoldRevision(configPath string) (bool, string) {
	if configPath == "" {
		return false, ""
	}
	path := managedAmneziaWGDenyHoldPath(configPath)
	if path == "" {
		return true, ""
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, ""
	}
	if err != nil {
		return true, ""
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0640 ||
		stat.Uid != 0 || stat.Gid != uint32(os.Getegid()) || info.Size() <= 0 || info.Size() > 65 {
		return true, ""
	}
	raw, err := os.ReadFile(path)
	revision := strings.TrimSpace(string(raw))
	if err != nil || !xraySHA256Pattern.MatchString(revision) || string(raw) != revision+"\n" {
		return true, ""
	}
	return true, revision
}

func writeManagedAmneziaWGDenyAck(configPath, revision string) error {
	if configPath == "" || !xraySHA256Pattern.MatchString(revision) {
		return errors.New("AmneziaWG deny acknowledgement is invalid")
	}
	path := managedAmneziaWGDenyAckPath(configPath)
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0620 ||
		stat.Uid != 0 || stat.Gid != uint32(os.Getegid()) || info.Size() > 65 {
		return errors.New("AmneziaWG deny acknowledgement file is unsafe")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	_, writeErr := io.WriteString(file, revision+"\n")
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func managedAmneziaWGExecutable() (string, string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", "", err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil || !filepath.IsAbs(path) {
		return "", "", errors.New("Agent executable path is unsafe")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0755 || info.Size() <= 0 {
		return "", "", errors.New("Agent executable is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm()&0022 != 0 {
		return "", "", errors.New("Agent executable ownership is unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", "", err
	}
	return path, hex.EncodeToString(hash.Sum(nil)), nil
}
