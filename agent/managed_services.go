package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	managedServicesSchemaVersion       = 1
	managedServicesKindMTProto         = "MTPROTO_FAKE_TLS"
	managedServicesKindAmneziaWG       = "AMNEZIAWG"
	managedServicesMTProtoVersion      = "v1.15.0"
	managedServicesAmneziaWGVersion    = "v3.1.20260814"
	managedServicesMTProtoUserName     = "forwardx-mtproto"
	managedServicesAmneziaWGUserName   = "forwardx-amneziawg"
	managedServicesStateRoot           = "/var/lib/forwardx-agent/managed-services"
	managedServicesArtifactRoot        = "/opt/forwardx-agent/managed-services"
	managedServicesConfigBaseRoot      = "/etc/forwardx/managed-services"
	managedServicesConfigRoot          = "/etc/forwardx/managed-services/mtproto"
	managedServicesAmneziaWGConfigRoot = "/etc/forwardx/managed-services/amneziawg"
	managedServicesMaxServices         = 32
	managedServicesMaxAccounts         = 64
	managedServicesMaxControlBytes     = 256 * 1024
	managedServicesMaxArtifactBytes    = 16 * 1024 * 1024
	managedServicesMaxBinaryBytes      = 32 * 1024 * 1024
	managedServicesMaxExpandedBytes    = 64 * 1024 * 1024
	managedServicesStateAuditInterval  = 10 * time.Minute
	managedServicesDownloadTimeout     = 2 * time.Minute
	managedServicesCommandTimeout      = 15 * time.Second
	managedServicesReadinessAttempts   = 20
	managedServicesReadinessDelay      = 250 * time.Millisecond
	managedServicesRestartAttempts     = 3
	managedServicesAgentOSHeader       = "X-ForwardX-Managed-Service-OS"
	managedServicesAgentArchHeader     = "X-ForwardX-Managed-Service-Arch"
	managedServicesCurrentStateFile    = "current.json"
	managedServicesLastGoodStateFile   = "last-good.json"
	managedServicesApplyMarkerFile     = "apply-in-progress"
)

var (
	managedServiceTagPattern          = regexp.MustCompile(`^forwardx-mtproto-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	managedAccountTagPattern          = regexp.MustCompile(`^forwardx-mtproto-account-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	managedAmneziaWGServiceTagPattern = regexp.MustCompile(`^forwardx-amneziawg-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	managedAmneziaWGAccountTagPattern = regexp.MustCompile(`^forwardx-amneziawg-peer-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	managedDomainPattern              = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)
	managedSecretPattern              = regexp.MustCompile(`^ee[0-9a-f]{34,538}$`)
	managedServicesArtifacts          = map[string]struct {
		SHA256   string
		FileSize int64
	}{
		"amd64": {SHA256: "f1f8763504753fb863a0ddff83eab19c856747289c376275c44b717f1747908e", FileSize: 5_307_638},
		"arm64": {SHA256: "9ed776b2052b95e8344896d43fbe01250014f36d7cfdd7f29f7903179bce4bed", FileSize: 4_767_178},
	}
)

type ManagedServicesCapability struct {
	SchemaVersion           int                            `json:"schemaVersion"`
	SupportedKinds          []string                       `json:"supportedKinds"`
	Supervisor              string                         `json:"supervisor"`
	SupportsArtifactInstall bool                           `json:"supportsArtifactInstall"`
	RunsAsDedicatedUser     bool                           `json:"runsAsDedicatedUser"`
	SupportedOS             string                         `json:"supportedOS"`
	SupportedArch           string                         `json:"supportedArch"`
	ErrorCode               string                         `json:"errorCode,omitempty"`
	KindCapabilities        []ManagedServiceKindCapability `json:"kindCapabilities,omitempty"`
}

type ManagedServiceKindCapability struct {
	Kind                    string `json:"kind"`
	Supervisor              string `json:"supervisor"`
	SupportsArtifactInstall bool   `json:"supportsArtifactInstall"`
	RunsAsDedicatedUser     bool   `json:"runsAsDedicatedUser"`
	Network                 string `json:"network"`
}

type ManagedServiceArtifact struct {
	ArtifactID    int64  `json:"artifactId"`
	PackageFormat string `json:"packageFormat"`
	SHA256        string `json:"sha256"`
	FileSize      int64  `json:"fileSize"`
}

type installedManagedServiceArtifact struct {
	SchemaVersion   int    `json:"schemaVersion"`
	Kind            string `json:"kind"`
	Version         string `json:"version"`
	OS              string `json:"os"`
	Arch            string `json:"arch"`
	ArtifactID      int64  `json:"artifactId"`
	PackageFormat   string `json:"packageFormat"`
	ArchiveSHA256   string `json:"archiveSha256"`
	ArchiveFileSize int64  `json:"archiveFileSize"`
	BinarySHA256    string `json:"binarySha256"`
}

type ManagedServiceAccountDesired struct {
	AccountTag string `json:"accountTag"`
	Secret     string `json:"secret"`
}

type ManagedAmneziaWGObfuscationDesired struct {
	JC                     int    `json:"jc"`
	JMin                   int    `json:"jmin"`
	JMax                   int    `json:"jmax"`
	S1                     int    `json:"s1"`
	S2                     int    `json:"s2"`
	S3                     int    `json:"s3"`
	S4                     int    `json:"s4"`
	H1                     string `json:"h1"`
	H2                     string `json:"h2"`
	H3                     string `json:"h3"`
	H4                     string `json:"h4"`
	I1                     string `json:"i1"`
	HeaderProtectionKey    string `json:"headerProtectionKey"`
	ContentPaddingAddition string `json:"contentPaddingAddition"`
	RekeyAfterTime         string `json:"rekeyAfterTime"`
	RekeyTimeout           string `json:"rekeyTimeout"`
	RejectAfterTime        string `json:"rejectAfterTime"`
	KeepaliveTimeout       string `json:"keepaliveTimeout"`
	MaxHandshakeAttempts   string `json:"maxHandshakeAttempts"`
	RandomTrailers         bool   `json:"randomTrailers"`
	DisableCookies         bool   `json:"disableCookies"`
}

type ManagedAmneziaWGPeerDesired struct {
	AccountTag   string `json:"accountTag"`
	Address      string `json:"address"`
	PublicKey    string `json:"publicKey"`
	PreSharedKey string `json:"preSharedKey"`
}

type ManagedServiceDesired struct {
	Kind             string                              `json:"kind"`
	ServiceID        int64                               `json:"serviceId"`
	ServiceTag       string                              `json:"serviceTag"`
	TargetVersion    string                              `json:"targetVersion"`
	Artifact         *ManagedServiceArtifact             `json:"artifact,omitempty"`
	ListenAddress    string                              `json:"listenAddress"`
	ListenPort       int                                 `json:"listenPort"`
	PublicAddress    string                              `json:"publicAddress,omitempty"`
	FakeTLSDomain    string                              `json:"fakeTlsDomain,omitempty"`
	Accounts         []ManagedServiceAccountDesired      `json:"accounts,omitempty"`
	Subnet           string                              `json:"subnet,omitempty"`
	MTU              int                                 `json:"mtu,omitempty"`
	DNS              []string                            `json:"dns,omitempty"`
	ServerPrivateKey string                              `json:"serverPrivateKey,omitempty"`
	Obfuscation      *ManagedAmneziaWGObfuscationDesired `json:"obfuscation,omitempty"`
	Peers            []ManagedAmneziaWGPeerDesired       `json:"peers,omitempty"`
}

type managedServiceDesiredWire ManagedServiceDesired

func (service *ManagedServiceDesired) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	kindRaw, ok := fields["kind"]
	if !ok {
		return errors.New("managed service kind is missing")
	}
	var kind string
	if err := json.Unmarshal(kindRaw, &kind); err != nil {
		return errors.New("managed service kind is invalid")
	}
	common := []string{"kind", "serviceId", "serviceTag", "targetVersion", "listenAddress", "listenPort"}
	expected := append([]string(nil), common...)
	switch kind {
	case managedServicesKindMTProto:
		expected = append(expected, "artifact", "fakeTlsDomain", "accounts")
	case managedServicesKindAmneziaWG:
		expected = append(expected, "publicAddress", "subnet", "mtu", "dns", "serverPrivateKey", "obfuscation", "peers")
	default:
		return errors.New("unsupported managed service kind")
	}
	if len(fields) != len(expected) {
		return errors.New("managed service fields do not match kind")
	}
	for _, key := range expected {
		if _, exists := fields[key]; !exists {
			return errors.New("managed service fields do not match kind")
		}
	}
	var decoded managedServiceDesiredWire
	if err := strictManagedServicesJSON(raw, &decoded); err != nil {
		return err
	}
	*service = ManagedServiceDesired(decoded)
	return nil
}

type ManagedServicesDesiredState struct {
	SchemaVersion int                     `json:"schemaVersion"`
	Generation    int64                   `json:"generation"`
	IssuedAt      string                  `json:"issuedAt"`
	ConfigHash    string                  `json:"configHash"`
	Services      []ManagedServiceDesired `json:"services"`
}

type managedServicesDesiredStateWire ManagedServicesDesiredState

func (desired *ManagedServicesDesiredState) UnmarshalJSON(raw []byte) error {
	var decoded managedServicesDesiredStateWire
	if err := strictManagedServicesJSON(raw, &decoded); err != nil {
		return err
	}
	validated := ManagedServicesDesiredState(decoded)
	if err := validated.Validate(); err != nil {
		return err
	}
	*desired = validated
	return nil
}

type ManagedServiceObservedListener struct {
	Network       string  `json:"network"`
	ListenAddress string  `json:"listenAddress"`
	Port          int     `json:"port"`
	Status        string  `json:"status"`
	ErrorCode     *string `json:"errorCode"`
}

type ManagedServiceObserved struct {
	Kind             string                         `json:"kind"`
	ServiceID        int64                          `json:"serviceId"`
	ServiceTag       string                         `json:"serviceTag"`
	InstalledVersion *string                        `json:"installedVersion"`
	RunningVersion   *string                        `json:"runningVersion"`
	ServiceStatus    string                         `json:"serviceStatus"`
	ProcessID        *int                           `json:"processId"`
	BinarySHA256     *string                        `json:"binarySha256"`
	Listener         ManagedServiceObservedListener `json:"listener"`
	ErrorCode        *string                        `json:"errorCode"`
}

type ManagedServicesObservedState struct {
	SchemaVersion     int                      `json:"schemaVersion"`
	AppliedGeneration int64                    `json:"appliedGeneration"`
	AppliedConfigHash *string                  `json:"appliedConfigHash"`
	Services          []ManagedServiceObserved `json:"services"`
	ObservedAt        string                   `json:"observedAt"`
}

func strictManagedServicesJSON(raw []byte, target any) error {
	if len(raw) == 0 || len(raw) > managedServicesMaxControlBytes {
		return errors.New("managed services payload exceeds size limit")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("managed services payload contains trailing data")
	}
	return nil
}

func (artifact ManagedServiceArtifact) Validate() error {
	if artifact.ArtifactID <= 0 || artifact.ArtifactID > XrayMaxSafeInteger || artifact.PackageFormat != "tar.gz" ||
		!xraySHA256Pattern.MatchString(artifact.SHA256) || artifact.FileSize <= 0 || artifact.FileSize > managedServicesMaxArtifactBytes {
		return errors.New("invalid managed service artifact")
	}
	return nil
}

func (artifact ManagedServiceArtifact) ValidateForCurrentPlatform() error {
	pinned, supported := managedServicesArtifacts[runtime.GOARCH]
	if runtime.GOOS != "linux" || !supported || artifact.Validate() != nil ||
		artifact.SHA256 != pinned.SHA256 || artifact.FileSize != pinned.FileSize {
		return errors.New("managed service artifact is not pinned for this platform")
	}
	return nil
}

func (desired ManagedServicesDesiredState) Validate() error {
	if desired.SchemaVersion != managedServicesSchemaVersion || desired.Generation < 0 || desired.Generation > XrayMaxSafeInteger ||
		!xraySHA256Pattern.MatchString(desired.ConfigHash) || len(desired.Services) > managedServicesMaxServices {
		return errors.New("invalid managed services desired state")
	}
	if _, err := time.Parse(time.RFC3339Nano, desired.IssuedAt); err != nil {
		return errors.New("invalid managed services issuedAt")
	}
	if raw, err := json.Marshal(desired); err != nil || len(raw) > managedServicesMaxControlBytes {
		return errors.New("managed services payload exceeds size limit")
	}
	serviceIDs := map[int64]bool{}
	tags := map[string]bool{}
	allAccountTags := map[string]bool{}
	ports := map[int]bool{}
	for _, service := range desired.Services {
		if service.ServiceID <= 0 || service.ServiceID > XrayMaxSafeInteger || service.ListenAddress != "0.0.0.0" ||
			service.ListenPort < 1000 || service.ListenPort > 65535 {
			return errors.New("invalid managed service identity")
		}
		accountTags, err := validateManagedServiceDesired(service)
		if err != nil {
			return err
		}
		if serviceIDs[service.ServiceID] || tags[service.ServiceTag] || ports[service.ListenPort] {
			return errors.New("duplicate managed service identity")
		}
		serviceIDs[service.ServiceID], tags[service.ServiceTag], ports[service.ListenPort] = true, true, true
		for _, accountTag := range accountTags {
			if allAccountTags[accountTag] {
				return errors.New("duplicate managed service account identity")
			}
			allAccountTags[accountTag] = true
		}
	}
	raw, err := marshalManagedServicesCanonical(desired.Services)
	if err != nil || hashManagedServicesBytes(raw) != desired.ConfigHash {
		return errors.New("managed services config hash mismatch")
	}
	return nil
}

func validateManagedServiceDesired(service ManagedServiceDesired) ([]string, error) {
	switch service.Kind {
	case managedServicesKindMTProto:
		if !managedServiceTagPattern.MatchString(service.ServiceTag) || service.TargetVersion != managedServicesMTProtoVersion ||
			service.Artifact == nil || len(service.FakeTLSDomain) > 253 || !managedDomainPattern.MatchString(service.FakeTLSDomain) ||
			len(service.Accounts) == 0 || len(service.Accounts) > managedServicesMaxAccounts || service.hasAmneziaWGFields() {
			return nil, errors.New("invalid MTProto desired service")
		}
		if err := service.Artifact.Validate(); err != nil {
			return nil, err
		}
		domainHex := hex.EncodeToString([]byte(service.FakeTLSDomain))
		seen := map[string]bool{}
		result := make([]string, 0, len(service.Accounts))
		for _, account := range service.Accounts {
			if !managedAccountTagPattern.MatchString(account.AccountTag) || seen[account.AccountTag] ||
				!managedSecretPattern.MatchString(account.Secret) || len(account.Secret) != 2+32+len(domainHex) ||
				!strings.HasSuffix(account.Secret, domainHex) {
				return nil, errors.New("invalid MTProto desired account")
			}
			seen[account.AccountTag] = true
			result = append(result, account.AccountTag)
		}
		return result, nil
	case managedServicesKindAmneziaWG:
		return validateManagedAmneziaWGDesired(service)
	default:
		return nil, errors.New("unsupported managed service kind")
	}
}

func DecodeManagedServicesDesiredState(raw []byte) (ManagedServicesDesiredState, error) {
	var desired ManagedServicesDesiredState
	if err := strictManagedServicesJSON(raw, &desired); err != nil {
		return desired, err
	}
	return desired, desired.Validate()
}

func marshalManagedServicesCanonical(value any) ([]byte, error) {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(encoded.Bytes(), []byte("\n")), nil
}

func hashManagedServicesBytes(raw []byte) string {
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

func managedServicesDedicatedIdentityForKind(kind string) (uint32, uint32, error) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") || os.Geteuid() != 0 {
		return 0, 0, errors.New("managed services require a supported root Agent")
	}
	userName := managedServicesMTProtoUserName
	if kind == managedServicesKindAmneziaWG {
		userName = managedServicesAmneziaWGUserName
	} else if kind != managedServicesKindMTProto {
		return 0, 0, errors.New("unsupported managed service identity")
	}
	account, err := user.Lookup(userName)
	if err != nil || account.Username != userName || account.HomeDir != "/nonexistent" {
		return 0, 0, errors.New("managed service account is unavailable")
	}
	group, groupErr := user.LookupGroup(userName)
	if groupErr != nil || group.Gid != account.Gid {
		return 0, 0, errors.New("managed service group is unavailable")
	}
	uidValue, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gidValue, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uidValue == 0 || gidValue == 0 {
		return 0, 0, errors.New("managed service account is privileged")
	}
	if kind == managedServicesKindAmneziaWG {
		if mtprotoAccount, lookupErr := user.Lookup(managedServicesMTProtoUserName); lookupErr == nil &&
			(mtprotoAccount.Uid == account.Uid || mtprotoAccount.Gid == account.Gid) {
			return 0, 0, errors.New("managed service accounts are not isolated")
		}
	}
	passwd, readErr := os.ReadFile("/etc/passwd")
	if readErr != nil || len(passwd) > 4*1024*1024 {
		return 0, 0, errors.New("managed service account cannot be verified")
	}
	found := false
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) == 7 && fields[0] == userName {
			found = fields[5] == "/nonexistent" && (fields[6] == "/usr/sbin/nologin" || fields[6] == "/sbin/nologin" || fields[6] == "/bin/false")
			break
		}
	}
	if !found {
		return 0, 0, errors.New("managed service account login policy is unsafe")
	}
	return uint32(uidValue), uint32(gidValue), nil
}

func managedServicesDedicatedIdentity() (uint32, uint32, error) {
	return managedServicesDedicatedIdentityForKind(managedServicesKindMTProto)
}

func ensureManagedDirectory(path string, mode os.FileMode) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return errors.New("managed service path is unsafe")
	}
	current := string(filepath.Separator)
	for _, segment := range strings.Split(strings.TrimPrefix(clean, current), string(filepath.Separator)) {
		if segment == "" || segment == "." || segment == ".." {
			return errors.New("managed service path is unsafe")
		}
		current = filepath.Join(current, segment)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			createMode := os.FileMode(0755)
			if current == clean {
				createMode = mode
			}
			if err = os.Mkdir(current, createMode); err != nil {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		stat, statOK := info.Sys().(*syscall.Stat_t)
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !statOK || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm()&0022 != 0 {
			return errors.New("managed service path is unsafe")
		}
	}
	if err := os.Chown(clean, 0, 0); err != nil {
		return err
	}
	return os.Chmod(clean, mode)
}

func currentManagedServicesCapability() ManagedServicesCapability {
	capability := ManagedServicesCapability{
		SchemaVersion: managedServicesSchemaVersion, SupportedKinds: []string{}, Supervisor: "AGENT_CHILD",
		SupportedOS: runtime.GOOS, SupportedArch: runtime.GOARCH,
	}
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") || os.Geteuid() != 0 {
		capability.ErrorCode = "CAPABILITY_UNSUPPORTED"
		return capability
	}
	if err := ensureManagedDirectory(managedServicesStateRoot, 0700); err != nil {
		capability.ErrorCode = "CAPABILITY_UNSUPPORTED"
		return capability
	}
	if _, _, mtprotoIdentityErr := managedServicesDedicatedIdentityForKind(managedServicesKindMTProto); mtprotoIdentityErr == nil {
		if directoryErr := ensureManagedDirectory(managedServicesConfigRoot, 0755); directoryErr == nil {
			capability.SupportedKinds = []string{managedServicesKindMTProto}
			capability.SupportsArtifactInstall = true
			capability.RunsAsDedicatedUser = true
			capability.KindCapabilities = append(capability.KindCapabilities, ManagedServiceKindCapability{
				Kind: managedServicesKindMTProto, Supervisor: "AGENT_CHILD", SupportsArtifactInstall: true,
				RunsAsDedicatedUser: true, Network: "tcp",
			})
		}
	}
	if _, _, awgIdentityErr := managedServicesDedicatedIdentityForKind(managedServicesKindAmneziaWG); awgIdentityErr == nil {
		if directoryErr := ensureManagedDirectory(managedServicesAmneziaWGConfigRoot, 0755); directoryErr == nil {
			if _, _, executableErr := managedAmneziaWGExecutable(); executableErr == nil {
				capability.KindCapabilities = append(capability.KindCapabilities, ManagedServiceKindCapability{
					Kind: managedServicesKindAmneziaWG, Supervisor: "AGENT_CHILD", SupportsArtifactInstall: false,
					RunsAsDedicatedUser: true, Network: "udp",
				})
			}
		}
	}
	if len(capability.KindCapabilities) == 0 {
		capability.ErrorCode = "CAPABILITY_UNSUPPORTED"
	}
	return capability
}

type managedServiceProcess struct {
	cmd        *exec.Cmd
	done       chan struct{}
	identity   xrayProcessIdentity
	desired    ManagedServiceDesired
	generation int64
	configHash string
	config     string
	binary     string
	argv       []string
	uid        uint32
	gid        uint32
	stopping   bool
}

type managedServiceTarget struct {
	uid        uint32
	gid        uint32
	binary     string
	binaryHash string
	version    string
}

type managedServicesRuntime struct {
	mu        sync.Mutex
	processes map[string]*managedServiceProcess
	current   *ManagedServicesDesiredState
	attempted *ManagedServicesDesiredState
	failures  map[int64]string
	restarts  map[int64]int
	watchdogs map[int64]int
}

var managedServicesRuntimeManager = &managedServicesRuntime{
	processes: map[string]*managedServiceProcess{}, failures: map[int64]string{}, restarts: map[int64]int{}, watchdogs: map[int64]int{},
}

var managedServicesPanelURLPrepareHook = func(previousPanelURL, currentPanelURL string) bool {
	return refreshManagedAmneziaWGPanelDenyHosts(managedAmneziaWGPolicyTransition, currentPanelURL)
}

var managedServicesPanelURLStableHook = func(currentPanelURL string) bool {
	return refreshManagedAmneziaWGPanelDenyHosts(managedAmneziaWGPolicyStable, currentPanelURL)
}

var managedServicesDurableHoldHook = enterManagedAmneziaWGDurableHold
var managedServicesDurableHoldPresentHook = managedAmneziaWGDurableHoldPresent

func managedServicesBinaryPath() string {
	return filepath.Join(managedServicesArtifactRoot, "mtproto", managedServicesMTProtoVersion, runtime.GOARCH, "mtg-multi")
}

func managedServicesArtifactMetadataPath() string {
	return filepath.Join(filepath.Dir(managedServicesBinaryPath()), "artifact.json")
}

func managedServiceConfigPath(tag string) string {
	return filepath.Join(managedServicesConfigRoot, tag, "config.toml")
}

func managedServiceConfigPathForKind(kind, tag string) string {
	if kind == managedServicesKindAmneziaWG {
		return filepath.Join(managedServicesAmneziaWGConfigRoot, tag, "config.json")
	}
	return managedServiceConfigPath(tag)
}

func managedServiceConfigRootForKind(kind string) string {
	if kind == managedServicesKindAmneziaWG {
		return managedServicesAmneziaWGConfigRoot
	}
	return managedServicesConfigRoot
}

func managedServiceTagPatternForKind(kind string) *regexp.Regexp {
	if kind == managedServicesKindAmneziaWG {
		return managedAmneziaWGServiceTagPattern
	}
	return managedServiceTagPattern
}

func safeManagedStateFile(name string) string {
	return filepath.Join(managedServicesStateRoot, name)
}

func writeAtomicManagedFile(path string, content []byte, mode os.FileMode, uid, gid int) error {
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil {
		return err
	}
	stat, statOK := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !statOK || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("managed service parent directory is unsafe")
	}
	temporary, err := os.CreateTemp(directory, ".forwardx-managed-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err = temporary.Chmod(mode); err == nil && uid >= 0 && gid >= 0 {
		err = temporary.Chown(uid, gid)
	}
	if err == nil {
		_, err = temporary.Write(content)
	}
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(temporaryPath, path)
	}
	return err
}

func readManagedState(path string) (*ManagedServicesDesiredState, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	stat, statOK := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 ||
		!statOK || stat.Uid != 0 || stat.Gid != 0 || info.Size() <= 0 || info.Size() > managedServicesMaxControlBytes {
		return nil, errors.New("managed service state file is unsafe")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	state, err := DecodeManagedServicesDesiredState(raw)
	return &state, err
}

func persistManagedState(path string, state ManagedServicesDesiredState) error {
	raw, err := json.Marshal(state)
	if err != nil || len(raw) > managedServicesMaxControlBytes {
		return errors.New("managed service state cannot be encoded")
	}
	return writeAtomicManagedFile(path, raw, 0600, 0, 0)
}

func renderMTProtoConfig(service ManagedServiceDesired) []byte {
	var builder strings.Builder
	fmt.Fprintf(&builder, "bind-to = \"0.0.0.0:%d\"\n\n[secrets]\n", service.ListenPort)
	for _, account := range service.Accounts {
		fmt.Fprintf(&builder, "\"%s\" = \"%s\"\n", account.AccountTag, account.Secret)
	}
	return []byte(builder.String())
}

func managedServiceConfigMatches(path string, gid uint32, desired ManagedServiceDesired) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0640 || info.Size() <= 0 || info.Size() > managedServicesMaxControlBytes {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != gid {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	if desired.Kind == managedServicesKindAmneziaWG {
		return managedAmneziaWGHelperConfigMatches(raw, desired)
	}
	expected, err := renderManagedServiceConfig(desired)
	return err == nil && string(raw) == string(expected)
}

type managedAmneziaWGPolicyAck struct {
	process  *managedServiceProcess
	revision string
}

func refreshManagedAmneziaWGPanelDenyHosts(denyMode, panelURL string) bool {
	runtimeManager := managedServicesRuntimeManager
	runtimeManager.mu.Lock()
	defer runtimeManager.mu.Unlock()
	pending := make([]managedAmneziaWGPolicyAck, 0)
	for _, process := range runtimeManager.processes {
		if process == nil || process.desired.Kind != managedServicesKindAmneziaWG || process.cmd == nil || process.cmd.Process == nil {
			continue
		}
		if _, err := inspectManagedServiceProcess(process); err != nil {
			enterManagedAmneziaWGDurableHoldLocked(runtimeManager)
			return false
		}
		config, err := renderManagedAmneziaWGConfigForPanelPolicy(process.desired, denyMode, panelURL)
		if err != nil {
			enterManagedAmneziaWGDurableHoldLocked(runtimeManager)
			return false
		}
		var wrapper managedAmneziaWGHelperConfig
		if strictManagedServicesJSON(config, &wrapper) != nil {
			enterManagedAmneziaWGDurableHoldLocked(runtimeManager)
			return false
		}
		pending = append(pending, managedAmneziaWGPolicyAck{process: process, revision: wrapper.DenyRevision})
		if err = writeManagedAmneziaWGDenyHold(process.config, process.gid, wrapper.DenyRevision); err != nil {
			enterManagedAmneziaWGDurableHoldLocked(runtimeManager)
			return false
		}
		ackPath := managedAmneziaWGDenyAckPath(process.config)
		if err = writeAtomicManagedFile(ackPath, nil, 0620, 0, int(process.gid)); err != nil {
			enterManagedAmneziaWGDurableHoldLocked(runtimeManager)
			return false
		}
		if err = writeAtomicManagedFile(process.config, config, 0640, 0, int(process.gid)); err != nil {
			enterManagedAmneziaWGDurableHoldLocked(runtimeManager)
			return false
		}
		if err = syncDirectory(filepath.Dir(process.config)); err != nil {
			enterManagedAmneziaWGDurableHoldLocked(runtimeManager)
			return false
		}
		if err = process.cmd.Process.Signal(syscall.SIGUSR1); err != nil {
			enterManagedAmneziaWGDurableHoldLocked(runtimeManager)
			return false
		}
	}
	if !waitManagedAmneziaWGDenyAcks(pending) {
		enterManagedAmneziaWGDurableHoldLocked(runtimeManager)
		return false
	}
	for _, item := range pending {
		if clearManagedAmneziaWGDenyHold(item.process.config, item.process.gid) != nil ||
			writeAtomicManagedFile(managedAmneziaWGDenyAckPath(item.process.config), nil, 0620, 0, int(item.process.gid)) != nil ||
			item.process.cmd.Process.Signal(syscall.SIGUSR1) != nil {
			enterManagedAmneziaWGDurableHoldLocked(runtimeManager)
			return false
		}
	}
	if !waitManagedAmneziaWGDenyAcks(pending) {
		enterManagedAmneziaWGDurableHoldLocked(runtimeManager)
		return false
	}
	return true
}

func waitManagedAmneziaWGDenyAcks(pending []managedAmneziaWGPolicyAck) bool {
	deadline := time.Now().Add(managedAmneziaWGAckTimeout)
	for _, item := range pending {
		for !managedAmneziaWGDenyAckMatches(item.process.config, item.process.gid, item.revision) {
			if time.Now().After(deadline) {
				return false
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	return true
}

func clearManagedAmneziaWGDenyHold(configPath string, gid uint32) error {
	path := managedAmneziaWGDenyHoldPath(configPath)
	if path == "" {
		return errors.New("AmneziaWG deny hold path is invalid")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0640 || stat.Uid != 0 || stat.Gid != gid {
		return errors.New("AmneziaWG deny hold marker is unsafe")
	}
	if err = os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func writeManagedAmneziaWGDenyHold(configPath string, gid uint32, revision string) error {
	if !xraySHA256Pattern.MatchString(revision) {
		return errors.New("AmneziaWG deny hold revision is invalid")
	}
	path := managedAmneziaWGDenyHoldPath(configPath)
	if path == "" {
		return errors.New("AmneziaWG deny hold path is invalid")
	}
	if err := writeAtomicManagedFile(path, []byte(revision+"\n"), 0640, 0, int(gid)); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func enterManagedAmneziaWGDurableHold() {
	runtimeManager := managedServicesRuntimeManager
	runtimeManager.mu.Lock()
	defer runtimeManager.mu.Unlock()
	enterManagedAmneziaWGDurableHoldLocked(runtimeManager)
}

func managedAmneziaWGDurableHoldPresent() bool {
	runtimeManager := managedServicesRuntimeManager
	runtimeManager.mu.Lock()
	defer runtimeManager.mu.Unlock()
	for _, process := range runtimeManager.processes {
		if process == nil || process.desired.Kind != managedServicesKindAmneziaWG {
			continue
		}
		if _, err := os.Lstat(managedAmneziaWGDenyHoldPath(process.config)); !errors.Is(err, os.ErrNotExist) {
			return true
		}
	}
	return false
}

func enterManagedAmneziaWGDurableHoldLocked(runtimeManager *managedServicesRuntime) {
	for _, process := range runtimeManager.processes {
		if process == nil || process.desired.Kind != managedServicesKindAmneziaWG || process.cmd == nil || process.cmd.Process == nil {
			continue
		}
		revision := strings.Repeat("0", 64)
		if raw, err := os.ReadFile(process.config); err == nil {
			var wrapper managedAmneziaWGHelperConfig
			if strictManagedServicesJSON(raw, &wrapper) == nil && validateManagedAmneziaWGHelperConfig(wrapper) == nil {
				revision = wrapper.DenyRevision
			}
		}
		markerErr := writeManagedAmneziaWGDenyHold(process.config, process.gid, revision)
		signalErr := process.cmd.Process.Signal(syscall.SIGUSR2)
		if markerErr != nil || signalErr != nil {
			if _, inspectErr := inspectManagedServiceProcess(process); inspectErr == nil {
				process.stopping = true
				_ = syscall.Kill(-process.identity.PID, syscall.SIGKILL)
			}
		}
	}
}

func managedAmneziaWGDenyAckMatches(configPath string, gid uint32, revision string) bool {
	if !xraySHA256Pattern.MatchString(revision) {
		return false
	}
	info, err := os.Lstat(managedAmneziaWGDenyAckPath(configPath))
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0620 ||
		stat.Uid != 0 || stat.Gid != gid || info.Size() <= 0 || info.Size() > 65 {
		return false
	}
	raw, err := os.ReadFile(managedAmneziaWGDenyAckPath(configPath))
	return err == nil && strings.TrimSpace(string(raw)) == revision
}

func renderManagedServiceConfig(service ManagedServiceDesired) ([]byte, error) {
	if service.Kind == managedServicesKindAmneziaWG {
		return renderManagedAmneziaWGConfig(service)
	}
	if service.Kind == managedServicesKindMTProto {
		return renderMTProtoConfig(service), nil
	}
	return nil, errors.New("unsupported managed service kind")
}

func managedServiceCommand(ctx context.Context, uid, gid uint32, binary string, args ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, binary, args...)
	command.Dir = "/"
	command.Stdin = nil
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	command.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: gid, NoSetGroups: true},
		Pdeathsig:  syscall.SIGTERM,
		Setpgid:    true,
	}
	return command
}

func runMTProtoCommand(ctx context.Context, uid, gid uint32, binary string, args ...string) error {
	command := managedServiceCommand(ctx, uid, gid, binary, args...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	return command.Run()
}

func validateMTProtoConfig(uid, gid uint32, binary, configPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), managedServicesCommandTimeout)
	defer cancel()
	return runMTProtoCommand(ctx, uid, gid, binary, "access", "--ipv4", "192.0.2.1", configPath)
}

func validateManagedServiceConfig(uid, gid uint32, binary, configPath string, service ManagedServiceDesired) error {
	if service.Kind == managedServicesKindAmneziaWG {
		ctx, cancel := context.WithTimeout(context.Background(), managedServicesCommandTimeout)
		defer cancel()
		return runMTProtoCommand(ctx, uid, gid, binary, managedAmneziaWGHelperCommand, "validate", configPath)
	}
	return validateMTProtoConfig(uid, gid, binary, configPath)
}

func validateManagedServiceBinary(path string, uid, gid uint32) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	stat, statOK := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0755 ||
		!statOK || stat.Uid != 0 || stat.Gid != 0 || info.Size() <= 0 || info.Size() > managedServicesMaxBinaryBytes {
		return "", errors.New("managed MTProto binary is unsafe")
	}
	executable, err := elf.Open(path)
	if err != nil {
		return "", err
	}
	expected := elf.EM_X86_64
	if runtime.GOARCH == "arm64" {
		expected = elf.EM_AARCH64
	}
	valid := executable.Class == elf.ELFCLASS64 && executable.Machine == expected && (executable.Type == elf.ET_EXEC || executable.Type == elf.ET_DYN)
	_ = executable.Close()
	if !valid {
		return "", errors.New("managed MTProto binary architecture mismatch")
	}
	hash, err := sha256File(path, managedServicesMaxBinaryBytes)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), managedServicesCommandTimeout)
	defer cancel()
	command := managedServiceCommand(ctx, uid, gid, path, "--version")
	output, err := command.CombinedOutput()
	if err != nil || len(output) > 8192 || !strings.Contains(string(output), "1.15.0") {
		return "", errors.New("managed MTProto binary version mismatch")
	}
	return hash, nil
}

func readInstalledManagedServiceArtifact(path string) (installedManagedServiceArtifact, error) {
	var metadata installedManagedServiceArtifact
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > 8192 {
		return metadata, errors.New("managed service artifact metadata is unsafe")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 {
		return metadata, errors.New("managed service artifact metadata ownership is unsafe")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return metadata, err
	}
	if err = strictManagedServicesJSON(raw, &metadata); err != nil {
		return metadata, err
	}
	return metadata, nil
}

func validateInstalledManagedServiceArtifact(artifact ManagedServiceArtifact, uid, gid uint32) (string, error) {
	if err := artifact.ValidateForCurrentPlatform(); err != nil {
		return "", err
	}
	metadata, err := readInstalledManagedServiceArtifact(managedServicesArtifactMetadataPath())
	if err != nil || metadata.SchemaVersion != managedServicesSchemaVersion || metadata.Kind != managedServicesKindMTProto ||
		metadata.Version != managedServicesMTProtoVersion || metadata.OS != runtime.GOOS || metadata.Arch != runtime.GOARCH ||
		metadata.ArtifactID <= 0 || metadata.PackageFormat != artifact.PackageFormat ||
		metadata.ArchiveSHA256 != artifact.SHA256 || metadata.ArchiveFileSize != artifact.FileSize ||
		!xraySHA256Pattern.MatchString(metadata.BinarySHA256) {
		return "", errors.New("managed service installed artifact does not match desired metadata")
	}
	hash, err := validateManagedServiceBinary(managedServicesBinaryPath(), uid, gid)
	if err != nil || hash != metadata.BinarySHA256 {
		return "", errors.New("managed service installed artifact hash mismatch")
	}
	return hash, nil
}

func downloadManagedServiceArtifact(ctx context.Context, cfg Config, artifact ManagedServiceArtifact, destination string) error {
	panelURL := normalizePanelURL(currentPanelURL(cfg))
	base, err := url.Parse(panelURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return errors.New("managed service panel artifact endpoint is unavailable")
	}
	downloadPath := fmt.Sprintf("/api/agent/artifacts/managed-service/%d", artifact.ArtifactID)
	downloadURL, err := url.Parse(strings.TrimRight(panelURL, "/") + downloadPath)
	if err != nil || downloadURL.Scheme != base.Scheme || downloadURL.Host != base.Host || downloadURL.RawQuery != "" || downloadURL.Fragment != "" {
		return errors.New("managed service artifact URL is invalid")
	}
	downloadContext, cancel := context.WithTimeout(ctx, managedServicesDownloadTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(downloadContext, http.MethodGet, downloadURL.String(), nil)
	if err != nil {
		return err
	}
	auth, err := newAgentRequestAuth(request.Context(), agentSyncHTTPClient, panelURL, cfg.Token, request.Method, request.URL.Path, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+auth.proof)
	request.Header.Set(managedServicesAgentOSHeader, runtime.GOOS)
	request.Header.Set(managedServicesAgentArchHeader, runtime.GOARCH)
	client := *agentSyncHTTPClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	observeAgentAuthCapability(panelURL, response.Header.Get(agentAuthCapabilityHeader))
	if !strings.EqualFold(strings.TrimSpace(response.Header.Get(agentAuthResultHeader)), agentAuthResultAccepted) || response.StatusCode != http.StatusOK {
		return errors.New("managed service artifact response was rejected")
	}
	if response.ContentLength != artifact.FileSize || response.Header.Get("X-ForwardX-Artifact-SHA256") != artifact.SHA256 ||
		response.Header.Get("ETag") != `"sha256:`+artifact.SHA256+`"` || response.Header.Get("X-ForwardX-Artifact-Version") != managedServicesMTProtoVersion ||
		response.Header.Get("X-ForwardX-Artifact-OS") != runtime.GOOS || response.Header.Get("X-ForwardX-Artifact-Arch") != runtime.GOARCH {
		return errors.New("managed service artifact metadata mismatch")
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(response.Body, artifact.FileSize+1))
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || written != artifact.FileSize || hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 {
		return errors.Join(copyErr, syncErr, closeErr, errors.New("managed service artifact integrity mismatch"))
	}
	return nil
}

func extractManagedServiceArtifact(archivePath, binaryPath string) error {
	archive, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer archive.Close()
	gzipReader, err := gzip.NewReader(archive)
	if err != nil {
		return err
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	found := false
	entries := 0
	var expandedBytes int64
	for {
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return nextErr
		}
		entries++
		if entries > 128 || header == nil || header.Name == "" || strings.Contains(header.Name, "\\") || filepath.IsAbs(header.Name) {
			return errors.New("managed service artifact contains an unsafe entry")
		}
		if header.Size < 0 || header.Size > managedServicesMaxExpandedBytes-expandedBytes {
			return errors.New("managed service artifact expands beyond its limit")
		}
		expandedBytes += header.Size
		clean := filepath.Clean(header.Name)
		if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
			return errors.New("managed service artifact contains an unsafe path")
		}
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			if header.Typeflag == tar.TypeDir {
				continue
			}
			return errors.New("managed service artifact contains an unsupported entry")
		}
		if header.Mode&0111 != 0 && filepath.Base(clean) != "mtg-multi" {
			return errors.New("managed service artifact contains an extra executable")
		}
		if filepath.Base(clean) != "mtg-multi" {
			continue
		}
		if found || header.Size <= 0 || header.Size > managedServicesMaxBinaryBytes {
			return errors.New("managed service artifact binary entry is invalid")
		}
		found = true
		output, createErr := os.OpenFile(binaryPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0755)
		if createErr != nil {
			return createErr
		}
		written, copyErr := io.Copy(output, io.LimitReader(tarReader, header.Size+1))
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || written != header.Size {
			return errors.Join(copyErr, syncErr, closeErr, errors.New("managed service artifact extraction failed"))
		}
	}
	if !found {
		return errors.New("managed service artifact is missing mtg-multi")
	}
	return nil
}

func pathExistsWithoutFollowing(path string) (bool, error) {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func installManagedServiceArtifactFiles(stagedBinary, stagedMetadata, temporaryDirectory string, artifact ManagedServiceArtifact, uid, gid uint32) error {
	binaryPath := managedServicesBinaryPath()
	metadataPath := managedServicesArtifactMetadataPath()
	backupBinary := filepath.Join(temporaryDirectory, "previous-mtg-multi")
	backupMetadata := filepath.Join(temporaryDirectory, "previous-artifact.json")
	hadBinary, err := pathExistsWithoutFollowing(binaryPath)
	if err != nil {
		return err
	}
	hadMetadata, err := pathExistsWithoutFollowing(metadataPath)
	if err != nil {
		return err
	}
	if hadBinary {
		if err = os.Rename(binaryPath, backupBinary); err != nil {
			return err
		}
	}
	if hadMetadata {
		if err = os.Rename(metadataPath, backupMetadata); err != nil {
			if hadBinary {
				_ = os.Rename(backupBinary, binaryPath)
			}
			return err
		}
	}
	restore := func(cause error) error {
		_ = os.Remove(binaryPath)
		_ = os.Remove(metadataPath)
		var restoreErrors []error
		if hadBinary {
			restoreErrors = append(restoreErrors, os.Rename(backupBinary, binaryPath))
		}
		if hadMetadata {
			restoreErrors = append(restoreErrors, os.Rename(backupMetadata, metadataPath))
		}
		return errors.Join(append([]error{cause}, restoreErrors...)...)
	}
	if err = os.Rename(stagedBinary, binaryPath); err != nil {
		return restore(err)
	}
	if err = os.Rename(stagedMetadata, metadataPath); err != nil {
		return restore(err)
	}
	if _, err = validateInstalledManagedServiceArtifact(artifact, uid, gid); err != nil {
		return restore(err)
	}
	return nil
}

func ensureManagedServiceArtifact(ctx context.Context, cfg Config, artifact ManagedServiceArtifact, uid, gid uint32) (string, string, error) {
	if err := artifact.ValidateForCurrentPlatform(); err != nil {
		return "", "", err
	}
	binaryPath := managedServicesBinaryPath()
	if hash, err := validateInstalledManagedServiceArtifact(artifact, uid, gid); err == nil {
		return binaryPath, hash, nil
	}
	directory := filepath.Dir(binaryPath)
	if err := ensureManagedDirectory(directory, 0755); err != nil {
		return "", "", err
	}
	temporaryDirectory, err := os.MkdirTemp(directory, ".install-*")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(temporaryDirectory)
	archivePath := filepath.Join(temporaryDirectory, "artifact.tar.gz")
	if err = downloadManagedServiceArtifact(ctx, cfg, artifact, archivePath); err != nil {
		return "", "", err
	}
	stagedBinary := filepath.Join(temporaryDirectory, "mtg-multi")
	if err = extractManagedServiceArtifact(archivePath, stagedBinary); err != nil {
		return "", "", err
	}
	if err = os.Chown(temporaryDirectory, 0, int(gid)); err == nil {
		err = os.Chmod(temporaryDirectory, 0750)
	}
	if err == nil {
		err = os.Chown(stagedBinary, 0, 0)
	}
	if err == nil {
		err = os.Chmod(stagedBinary, 0755)
	}
	if err != nil {
		return "", "", err
	}
	hash, err := validateManagedServiceBinary(stagedBinary, uid, gid)
	if err != nil {
		return "", "", err
	}
	if err = os.Chown(stagedBinary, 0, 0); err != nil {
		return "", "", err
	}
	if err = os.Chmod(stagedBinary, 0755); err != nil {
		return "", "", err
	}
	metadata := installedManagedServiceArtifact{
		SchemaVersion: managedServicesSchemaVersion, Kind: managedServicesKindMTProto, Version: managedServicesMTProtoVersion,
		OS: runtime.GOOS, Arch: runtime.GOARCH, ArtifactID: artifact.ArtifactID, PackageFormat: artifact.PackageFormat,
		ArchiveSHA256: artifact.SHA256, ArchiveFileSize: artifact.FileSize, BinarySHA256: hash,
	}
	metadataJSON, marshalErr := json.Marshal(metadata)
	if marshalErr != nil {
		return "", "", marshalErr
	}
	stagedMetadata := filepath.Join(temporaryDirectory, "artifact.json")
	if err = writeAtomicManagedFile(stagedMetadata, metadataJSON, 0600, 0, 0); err != nil {
		return "", "", err
	}
	if err = installManagedServiceArtifactFiles(stagedBinary, stagedMetadata, temporaryDirectory, artifact, uid, gid); err != nil {
		return "", "", err
	}
	return binaryPath, hash, nil
}

func sameManagedServiceArtifact(left, right *ManagedServiceArtifact) bool {
	return left != nil && right != nil && *left == *right
}

func prepareManagedServiceTargets(ctx context.Context, cfg Config, desired ManagedServicesDesiredState, allowInstall bool) (map[string]managedServiceTarget, error) {
	targets := map[string]managedServiceTarget{}
	var mtprotoArtifact *ManagedServiceArtifact
	for _, service := range desired.Services {
		if _, exists := targets[service.Kind]; exists {
			if service.Kind == managedServicesKindMTProto && !sameManagedServiceArtifact(mtprotoArtifact, service.Artifact) {
				return nil, errors.New("managed MTProto services must use one approved artifact")
			}
			continue
		}
		uid, gid, err := managedServicesDedicatedIdentityForKind(service.Kind)
		if err != nil {
			return nil, err
		}
		switch service.Kind {
		case managedServicesKindMTProto:
			mtprotoArtifact = service.Artifact
			if mtprotoArtifact == nil {
				return nil, errors.New("managed MTProto artifact is missing")
			}
			var binary, hash string
			if allowInstall {
				binary, hash, err = ensureManagedServiceArtifact(ctx, cfg, *mtprotoArtifact, uid, gid)
			} else {
				binary = managedServicesBinaryPath()
				hash, err = validateInstalledManagedServiceArtifact(*mtprotoArtifact, uid, gid)
			}
			if err != nil {
				return nil, err
			}
			targets[service.Kind] = managedServiceTarget{uid: uid, gid: gid, binary: binary, binaryHash: hash, version: managedServicesMTProtoVersion}
		case managedServicesKindAmneziaWG:
			binary, hash, executableErr := managedAmneziaWGExecutable()
			if executableErr != nil {
				return nil, executableErr
			}
			targets[service.Kind] = managedServiceTarget{uid: uid, gid: gid, binary: binary, binaryHash: hash, version: managedServicesAmneziaWGVersion}
		default:
			return nil, errors.New("unsupported managed service kind")
		}
	}
	return targets, nil
}

func inspectManagedServiceTarget(service ManagedServiceDesired) (managedServiceTarget, error) {
	uid, gid, err := managedServicesDedicatedIdentityForKind(service.Kind)
	if err != nil {
		return managedServiceTarget{}, err
	}
	switch service.Kind {
	case managedServicesKindMTProto:
		if service.Artifact == nil {
			return managedServiceTarget{}, errors.New("managed MTProto artifact is missing")
		}
		hash, artifactErr := validateInstalledManagedServiceArtifact(*service.Artifact, uid, gid)
		if artifactErr != nil {
			return managedServiceTarget{}, artifactErr
		}
		return managedServiceTarget{uid: uid, gid: gid, binary: managedServicesBinaryPath(), binaryHash: hash, version: managedServicesMTProtoVersion}, nil
	case managedServicesKindAmneziaWG:
		binary, hash, executableErr := managedAmneziaWGExecutable()
		if executableErr != nil {
			return managedServiceTarget{}, executableErr
		}
		return managedServiceTarget{uid: uid, gid: gid, binary: binary, binaryHash: hash, version: managedServicesAmneziaWGVersion}, nil
	default:
		return managedServiceTarget{}, errors.New("unsupported managed service kind")
	}
}

func (runtimeManager *managedServicesRuntime) watchProcess(process *managedServiceProcess) {
	_ = process.cmd.Wait()
	close(process.done)
	runtimeManager.mu.Lock()
	unexpected := false
	if runtimeManager.processes[process.desired.ServiceTag] == process {
		delete(runtimeManager.processes, process.desired.ServiceTag)
		if !process.stopping {
			runtimeManager.failures[process.desired.ServiceID] = "RUNTIME_START_FAILED"
			unexpected = runtimeManager.processStillDesiredLocked(process)
			if unexpected {
				runtimeManager.watchdogs[process.desired.ServiceID]++
			}
		}
	}
	runtimeManager.mu.Unlock()
	requestManagedServicesStateUpload()
	wakeHeartbeat()
	if unexpected {
		runtimeManager.restartUnexpectedProcess(process)
	}
}

func (runtimeManager *managedServicesRuntime) processStillDesiredLocked(process *managedServiceProcess) bool {
	if runtimeManager.current == nil || runtimeManager.current.Generation != process.generation || runtimeManager.current.ConfigHash != process.configHash {
		return false
	}
	for _, desired := range runtimeManager.current.Services {
		if desired.ServiceID == process.desired.ServiceID && desired.ServiceTag == process.desired.ServiceTag {
			return true
		}
	}
	return false
}

func (runtimeManager *managedServicesRuntime) watchdogOwnsRecoveryLocked(desired ManagedServicesDesiredState) bool {
	for _, service := range desired.Services {
		if runtimeManager.watchdogs[service.ServiceID] > 0 || runtimeManager.restarts[service.ServiceID] >= managedServicesRestartAttempts {
			return true
		}
	}
	return false
}

func (runtimeManager *managedServicesRuntime) restartUnexpectedProcess(process *managedServiceProcess) {
	defer func() {
		runtimeManager.mu.Lock()
		if runtimeManager.watchdogs[process.desired.ServiceID] > 1 {
			runtimeManager.watchdogs[process.desired.ServiceID]--
		} else {
			delete(runtimeManager.watchdogs, process.desired.ServiceID)
		}
		runtimeManager.mu.Unlock()
	}()
	for {
		runtimeManager.mu.Lock()
		if !runtimeManager.processStillDesiredLocked(process) || runtimeManager.processes[process.desired.ServiceTag] != nil {
			runtimeManager.mu.Unlock()
			return
		}
		attempt := runtimeManager.restarts[process.desired.ServiceID]
		if attempt >= managedServicesRestartAttempts {
			runtimeManager.failures[process.desired.ServiceID] = "RUNTIME_START_FAILED"
			runtimeManager.mu.Unlock()
			break
		}
		attempt++
		runtimeManager.restarts[process.desired.ServiceID] = attempt
		runtimeManager.mu.Unlock()
		time.Sleep(time.Duration(1<<(attempt-1)) * time.Second)
		runtimeManager.mu.Lock()
		if !runtimeManager.processStillDesiredLocked(process) || runtimeManager.processes[process.desired.ServiceTag] != nil {
			runtimeManager.mu.Unlock()
			return
		}
		configBytes, configErr := renderManagedServiceConfig(process.desired)
		if configErr == nil {
			configErr = writeAtomicManagedFile(process.config, configBytes, 0640, 0, int(process.gid))
		}
		if configErr == nil {
			configErr = validateManagedServiceConfig(process.uid, process.gid, process.binary, process.config, process.desired)
		}
		var replacement *managedServiceProcess
		var startErr error
		if configErr == nil {
			replacement, startErr = runtimeManager.startProcessLocked(process.uid, process.gid, process.binary, process.config, *runtimeManager.current, process.desired)
		} else {
			startErr = configErr
		}
		if startErr == nil && waitManagedServiceReady(replacement) {
			delete(runtimeManager.failures, process.desired.ServiceID)
			runtimeManager.mu.Unlock()
			requestManagedServicesStateUpload()
			wakeHeartbeat()
			return
		}
		if replacement != nil {
			replacement.stopping = true
			_ = stopManagedServiceChildProcess(replacement)
			if runtimeManager.processes[process.desired.ServiceTag] == replacement {
				delete(runtimeManager.processes, process.desired.ServiceTag)
			}
		}
		runtimeManager.failures[process.desired.ServiceID] = "RUNTIME_START_FAILED"
		runtimeManager.mu.Unlock()
	}
	requestManagedServicesStateUpload()
	wakeHeartbeat()
}

func (runtimeManager *managedServicesRuntime) startProcessLocked(uid, gid uint32, binary, configPath string, state ManagedServicesDesiredState, desired ManagedServiceDesired) (*managedServiceProcess, error) {
	args := []string{"run", configPath}
	if desired.Kind == managedServicesKindAmneziaWG {
		args = []string{managedAmneziaWGHelperCommand, "run", configPath}
	}
	command := managedServiceCommand(context.Background(), uid, gid, binary, args...)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return nil, err
	}
	identity, err := inspectManagedXrayProcess(command.Process.Pid, binary)
	if err != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		_ = command.Wait()
		return nil, errors.New("managed service process identity is unavailable")
	}
	process := &managedServiceProcess{
		cmd: command, done: make(chan struct{}), identity: identity, desired: desired, generation: state.Generation,
		configHash: state.ConfigHash, config: configPath, binary: binary, argv: append([]string{binary}, args...), uid: uid, gid: gid,
	}
	if _, err = inspectManagedServiceProcess(process); err != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		_ = command.Wait()
		return nil, err
	}
	runtimeManager.processes[desired.ServiceTag] = process
	go runtimeManager.watchProcess(process)
	return process, nil
}

func inspectManagedServiceProcess(process *managedServiceProcess) (xrayProcessIdentity, error) {
	if process == nil || process.identity.PID <= 0 || len(process.argv) == 0 {
		return xrayProcessIdentity{}, errors.New("managed service process identity is invalid")
	}
	identity, err := inspectManagedXrayProcess(process.identity.PID, process.identity.Executable)
	if err != nil || !sameXrayProcessIdentity(identity, process.identity) {
		return xrayProcessIdentity{}, errors.New("managed service process identity changed")
	}
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(process.identity.PID), "cmdline"))
	if err != nil || len(raw) == 0 || len(raw) > 16*1024 || raw[len(raw)-1] != 0 {
		return xrayProcessIdentity{}, errors.New("managed service process argv is unavailable")
	}
	parts := strings.Split(string(raw[:len(raw)-1]), "\x00")
	if len(parts) != len(process.argv) {
		return xrayProcessIdentity{}, errors.New("managed service process argv changed")
	}
	for index := range parts {
		if parts[index] != process.argv[index] {
			return xrayProcessIdentity{}, errors.New("managed service process argv changed")
		}
	}
	status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(process.identity.PID), "status"))
	if err != nil || len(status) == 0 || len(status) > 1024*1024 ||
		!managedServiceStatusIDsMatch(status, "Uid:", process.uid) || !managedServiceStatusIDsMatch(status, "Gid:", process.gid) ||
		!managedServiceSupplementaryGroupsEmpty(status) || !managedServiceStatusCapabilitiesEmpty(status) {
		return xrayProcessIdentity{}, errors.New("managed service process credentials changed")
	}
	return identity, nil
}

func managedServiceStatusCapabilitiesEmpty(status []byte) bool {
	required := map[string]bool{"CapInh:": false, "CapPrm:": false, "CapEff:": false, "CapAmb:": false}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if _, expected := required[fields[0]]; !expected {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 16, 64)
		if err != nil || value != 0 {
			return false
		}
		required[fields[0]] = true
	}
	for _, found := range required {
		if !found {
			return false
		}
	}
	return true
}

func managedServiceSupplementaryGroupsEmpty(status []byte) bool {
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "Groups:" {
			return len(fields) == 1
		}
	}
	return false
}

func managedServiceStatusIDsMatch(status []byte, label string, expected uint32) bool {
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 5 || fields[0] != label {
			continue
		}
		for _, value := range fields[1:] {
			parsed, err := strconv.ParseUint(value, 10, 32)
			if err != nil || uint32(parsed) != expected {
				return false
			}
		}
		return true
	}
	return false
}

func stopManagedServiceChildProcess(process *managedServiceProcess) error {
	if process == nil || process.cmd == nil || process.cmd.Process == nil {
		return nil
	}
	select {
	case <-process.done:
		return nil
	default:
	}
	if _, err := inspectManagedServiceProcess(process); err != nil {
		return err
	}
	process.stopping = true
	if err := syscall.Kill(-process.identity.PID, syscall.SIGTERM); err != nil {
		process.stopping = false
		return err
	}
	select {
	case <-process.done:
		return nil
	case <-time.After(5 * time.Second):
		if _, identityErr := inspectManagedServiceProcess(process); identityErr != nil {
			process.stopping = false
			return errors.New("managed service process identity changed before forced stop")
		}
		if killErr := syscall.Kill(-process.identity.PID, syscall.SIGKILL); killErr != nil {
			process.stopping = false
			return killErr
		}
		select {
		case <-process.done:
			return nil
		case <-time.After(2 * time.Second):
			process.stopping = false
			return errors.New("managed service process did not stop")
		}
	}
}

func (runtimeManager *managedServicesRuntime) stopAllLocked() error {
	processes := make([]*managedServiceProcess, 0, len(runtimeManager.processes))
	for _, process := range runtimeManager.processes {
		processes = append(processes, process)
	}
	var stopErrors []error
	for _, process := range processes {
		if err := stopManagedServiceChildProcess(process); err != nil {
			stopErrors = append(stopErrors, err)
			continue
		}
		delete(runtimeManager.processes, process.desired.ServiceTag)
	}
	return errors.Join(stopErrors...)
}

func managedExpectedListener(service ManagedServiceDesired) []XrayExpectedListener {
	network := "tcp"
	if service.Kind == managedServicesKindAmneziaWG {
		network = "udp"
	}
	return []XrayExpectedListener{{
		InboundID: service.ServiceID, RuntimeTag: service.ServiceTag, Network: network,
		ListenAddress: service.ListenAddress, Port: service.ListenPort,
	}}
}

func waitManagedServiceReady(process *managedServiceProcess) bool {
	for attempt := 0; attempt < managedServicesReadinessAttempts; attempt++ {
		if process != nil && process.cmd != nil && process.cmd.Process != nil {
			if _, identityErr := inspectManagedServiceProcess(process); identityErr == nil {
				observed, err := probeManagedXrayListeners(process.identity.PID, managedExpectedListener(process.desired))
				if err == nil && len(observed) == 1 && observed[0].Status == XrayListenerReady {
					return true
				}
			}
		}
		if attempt+1 < managedServicesReadinessAttempts {
			time.Sleep(managedServicesReadinessDelay)
		}
	}
	return false
}

func (runtimeManager *managedServicesRuntime) prepareConfigsLocked(targets map[string]managedServiceTarget, desired ManagedServicesDesiredState) (string, error) {
	if err := ensureManagedDirectory(managedServicesConfigBaseRoot, 0755); err != nil {
		return "", err
	}
	staging, err := os.MkdirTemp(managedServicesConfigBaseRoot, ".stage-*")
	if err != nil {
		return "", err
	}
	if err = os.Chown(staging, 0, 0); err != nil {
		os.RemoveAll(staging)
		return "", err
	}
	if err = os.Chmod(staging, 0755); err != nil {
		os.RemoveAll(staging)
		return "", err
	}
	createdKinds := map[string]bool{}
	for _, service := range desired.Services {
		target, ok := targets[service.Kind]
		if !ok {
			os.RemoveAll(staging)
			return "", errors.New("managed service runtime target is unavailable")
		}
		kindDirectory := filepath.Join(staging, strings.ToLower(service.Kind))
		if !createdKinds[service.Kind] {
			if err = os.Mkdir(kindDirectory, 0755); err == nil {
				err = os.Chown(kindDirectory, 0, 0)
			}
			if err != nil {
				os.RemoveAll(staging)
				return "", err
			}
			createdKinds[service.Kind] = true
		}
		directory := filepath.Join(kindDirectory, service.ServiceTag)
		if err = os.Mkdir(directory, 0750); err == nil {
			err = os.Chown(directory, 0, int(target.gid))
		}
		configName := "config.toml"
		if service.Kind == managedServicesKindAmneziaWG {
			configName = "config.json"
		}
		configPath := filepath.Join(directory, configName)
		var config []byte
		if err == nil {
			config, err = renderManagedServiceConfig(service)
		}
		if err == nil {
			err = writeAtomicManagedFile(configPath, config, 0640, 0, int(target.gid))
		}
		if err == nil && service.Kind == managedServicesKindAmneziaWG {
			err = writeAtomicManagedFile(managedAmneziaWGDenyAckPath(configPath), nil, 0620, 0, int(target.gid))
		}
		if err == nil {
			err = validateManagedServiceConfig(target.uid, target.gid, target.binary, configPath, service)
		}
		if err != nil {
			os.RemoveAll(staging)
			return "", err
		}
	}
	return staging, nil
}

func activateManagedServiceConfigs(staging string, desired ManagedServicesDesiredState) error {
	// Hold markers live above service directories and deliberately survive this
	// replace. Stale markers are removed only after the new generation commits.
	for _, kind := range []string{managedServicesKindMTProto, managedServicesKindAmneziaWG} {
		root := managedServiceConfigRootForKind(kind)
		if err := ensureManagedDirectory(root, 0755); err != nil {
			return err
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if managedServiceTagPatternForKind(kind).MatchString(entry.Name()) {
				if err = os.RemoveAll(filepath.Join(root, entry.Name())); err != nil {
					return err
				}
			}
		}
	}
	for _, service := range desired.Services {
		source := filepath.Join(staging, strings.ToLower(service.Kind), service.ServiceTag)
		destination := filepath.Join(managedServiceConfigRootForKind(service.Kind), service.ServiceTag)
		if err := os.Rename(source, destination); err != nil {
			return err
		}
	}
	return os.RemoveAll(staging)
}

func removeManagedServiceConfigs() error {
	var removeErrors []error
	for _, kind := range []string{managedServicesKindMTProto, managedServicesKindAmneziaWG} {
		root := managedServiceConfigRootForKind(kind)
		entries, err := os.ReadDir(root)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			removeErrors = append(removeErrors, err)
			continue
		}
		for _, entry := range entries {
			if managedServiceTagPatternForKind(kind).MatchString(entry.Name()) {
				removeErrors = append(removeErrors, os.RemoveAll(filepath.Join(root, entry.Name())))
			}
		}
		if kind == managedServicesKindAmneziaWG {
			removeErrors = append(removeErrors, removeManagedAmneziaWGHoldMarkers(root, nil))
		}
	}
	return errors.Join(removeErrors...)
}

func managedAmneziaWGHoldMarkerTag(name string) (string, bool) {
	if !strings.HasPrefix(name, ".") || !strings.HasSuffix(name, managedAmneziaWGHoldFileSuffix) {
		return "", false
	}
	tag := strings.TrimSuffix(strings.TrimPrefix(name, "."), managedAmneziaWGHoldFileSuffix)
	return tag, managedAmneziaWGServiceTagPattern.MatchString(tag)
}

func removeManagedAmneziaWGHoldMarkers(root string, retained map[string]bool) error {
	_, expectedGID, identityErr := managedServicesDedicatedIdentityForKind(managedServicesKindAmneziaWG)
	if identityErr != nil {
		entries, err := os.ReadDir(root)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if tag, validName := managedAmneziaWGHoldMarkerTag(entry.Name()); validName && !retained[tag] {
				return identityErr
			}
		}
		return nil
	}
	return removeManagedAmneziaWGHoldMarkersOwned(root, retained, 0, expectedGID)
}

func removeManagedAmneziaWGHoldMarkersOwned(root string, retained map[string]bool, expectedUID, expectedGID uint32) error {
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		tag, validName := managedAmneziaWGHoldMarkerTag(entry.Name())
		if !validName || retained[tag] {
			continue
		}
		path := filepath.Join(root, entry.Name())
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return statErr
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0640 ||
			stat.Uid != expectedUID || stat.Gid != expectedGID || info.Size() <= 0 || info.Size() > 65 {
			return errors.New("AmneziaWG deny hold marker is unsafe")
		}
		raw, readErr := os.ReadFile(path)
		revision := strings.TrimSpace(string(raw))
		if readErr != nil || !xraySHA256Pattern.MatchString(revision) || string(raw) != revision+"\n" {
			return errors.New("AmneziaWG deny hold marker is invalid")
		}
		if removeErr := os.Remove(path); removeErr != nil {
			return removeErr
		}
		removed = true
	}
	if removed {
		return syncDirectory(root)
	}
	return nil
}

func (runtimeManager *managedServicesRuntime) launchDesiredLocked(targets map[string]managedServiceTarget, desired ManagedServicesDesiredState) error {
	for _, service := range desired.Services {
		target, ok := targets[service.Kind]
		if !ok {
			return errors.New("managed service runtime target is unavailable")
		}
		process, err := runtimeManager.startProcessLocked(target.uid, target.gid, target.binary, managedServiceConfigPathForKind(service.Kind, service.ServiceTag), desired, service)
		if err != nil || !waitManagedServiceReady(process) {
			if err == nil {
				err = errors.New("managed service listener did not become ready")
			}
			runtimeManager.failures[service.ServiceID] = "RUNTIME_NOT_READY"
			return err
		}
	}
	return nil
}

func (runtimeManager *managedServicesRuntime) restoreLocked(previous *ManagedServicesDesiredState) error {
	if previous == nil {
		runtimeManager.current = nil
		return nil
	}
	targets, err := prepareManagedServiceTargets(context.Background(), Config{}, *previous, false)
	if err != nil {
		return err
	}
	staging, err := runtimeManager.prepareConfigsLocked(targets, *previous)
	if err != nil {
		return err
	}
	if err = activateManagedServiceConfigs(staging, *previous); err != nil {
		return err
	}
	if err = runtimeManager.launchDesiredLocked(targets, *previous); err != nil {
		return errors.Join(err, runtimeManager.stopAllLocked())
	}
	copy := *previous
	runtimeManager.current = &copy
	return nil
}

func (runtimeManager *managedServicesRuntime) Apply(ctx context.Context, cfg Config, desired ManagedServicesDesiredState) error {
	if err := desired.Validate(); err != nil {
		return err
	}
	for _, service := range desired.Services {
		if service.Kind == managedServicesKindMTProto {
			if service.Artifact == nil {
				return errors.New("managed MTProto artifact is missing")
			}
			if err := service.Artifact.ValidateForCurrentPlatform(); err != nil {
				return err
			}
		}
	}
	runtimeManager.mu.Lock()
	defer runtimeManager.mu.Unlock()
	attempted := desired
	runtimeManager.attempted = &attempted
	current, err := readManagedState(safeManagedStateFile(managedServicesCurrentStateFile))
	if err != nil {
		return err
	}
	if current != nil {
		if desired.Generation < current.Generation || (desired.Generation == current.Generation && desired.ConfigHash != current.ConfigHash) {
			return errors.New("managed service generation conflicts with applied state")
		}
		if desired.Generation == current.Generation && desired.ConfigHash == current.ConfigHash {
			allReady := len(runtimeManager.processes) == len(desired.Services)
			for _, service := range desired.Services {
				process := runtimeManager.processes[service.ServiceTag]
				allReady = allReady && process != nil && managedServiceConfigMatches(process.config, process.gid, service) && waitManagedServiceReady(process)
			}
			if allReady {
				runtimeManager.current = current
				return nil
			}
			if runtimeManager.watchdogOwnsRecoveryLocked(desired) {
				return errors.New("managed service watchdog owns recovery for the applied generation")
			}
		}
	}
	targets, err := prepareManagedServiceTargets(ctx, cfg, desired, true)
	if err != nil {
		return err
	}
	staging, err := runtimeManager.prepareConfigsLocked(targets, desired)
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	if err = writeAtomicManagedFile(safeManagedStateFile(managedServicesApplyMarkerFile), []byte(desired.ConfigHash+"\n"), 0600, 0, 0); err != nil {
		return err
	}
	previous := current
	rollback := func(cause error) error {
		stopErr := runtimeManager.stopAllLocked()
		var restoreErr error
		if stopErr == nil {
			restoreErr = runtimeManager.restoreLocked(previous)
		} else {
			restoreErr = stopErr
		}
		var stateErr error
		if previous == nil {
			restoreErr = errors.Join(restoreErr, removeManagedServiceConfigs())
			currentRemoveErr := os.Remove(safeManagedStateFile(managedServicesCurrentStateFile))
			if errors.Is(currentRemoveErr, os.ErrNotExist) {
				currentRemoveErr = nil
			}
			lastGoodRemoveErr := os.Remove(safeManagedStateFile(managedServicesLastGoodStateFile))
			if errors.Is(lastGoodRemoveErr, os.ErrNotExist) {
				lastGoodRemoveErr = nil
			}
			stateErr = errors.Join(currentRemoveErr, lastGoodRemoveErr)
		} else {
			stateErr = errors.Join(
				persistManagedState(safeManagedStateFile(managedServicesCurrentStateFile), *previous),
				persistManagedState(safeManagedStateFile(managedServicesLastGoodStateFile), *previous),
			)
		}
		_ = os.Remove(safeManagedStateFile(managedServicesApplyMarkerFile))
		if restoreErr != nil || stateErr != nil {
			return errors.Join(cause, errors.New("managed services rollback failed"), restoreErr, stateErr)
		}
		return cause
	}
	if err = runtimeManager.stopAllLocked(); err != nil {
		return rollback(err)
	}
	if err = activateManagedServiceConfigs(staging, desired); err != nil {
		return rollback(err)
	}
	if len(desired.Services) > 0 {
		if err = runtimeManager.launchDesiredLocked(targets, desired); err != nil {
			return rollback(err)
		}
	}
	if err = persistManagedState(safeManagedStateFile(managedServicesCurrentStateFile), desired); err != nil {
		return rollback(err)
	}
	if err = persistManagedState(safeManagedStateFile(managedServicesLastGoodStateFile), desired); err != nil {
		return rollback(err)
	}
	_ = os.Remove(safeManagedStateFile(managedServicesApplyMarkerFile))
	copy := desired
	runtimeManager.current = &copy
	runtimeManager.attempted = &copy
	runtimeManager.failures = map[int64]string{}
	if current == nil || desired.Generation > current.Generation {
		runtimeManager.restarts = map[int64]int{}
		runtimeManager.watchdogs = map[int64]int{}
	}
	retainedAmneziaWGMarkers := map[string]bool{}
	for _, service := range desired.Services {
		if service.Kind == managedServicesKindAmneziaWG {
			retainedAmneziaWGMarkers[service.ServiceTag] = true
		}
	}
	if cleanupErr := removeManagedAmneziaWGHoldMarkers(managedServicesAmneziaWGConfigRoot, retainedAmneziaWGMarkers); cleanupErr != nil {
		logf("managed AmneziaWG stale deny hold cleanup failed after commit: %v", cleanupErr)
	}
	return nil
}

func (runtimeManager *managedServicesRuntime) RecoverLocal() error {
	runtimeManager.mu.Lock()
	defer runtimeManager.mu.Unlock()
	lastGood, err := readManagedState(safeManagedStateFile(managedServicesLastGoodStateFile))
	if err != nil {
		return err
	}
	if lastGood == nil {
		markerExists, markerErr := pathExistsWithoutFollowing(safeManagedStateFile(managedServicesApplyMarkerFile))
		if markerErr != nil || !markerExists {
			return markerErr
		}
		configErr := removeManagedServiceConfigs()
		currentErr := os.Remove(safeManagedStateFile(managedServicesCurrentStateFile))
		if errors.Is(currentErr, os.ErrNotExist) {
			currentErr = nil
		}
		markerErr = os.Remove(safeManagedStateFile(managedServicesApplyMarkerFile))
		if errors.Is(markerErr, os.ErrNotExist) {
			markerErr = nil
		}
		runtimeManager.current = nil
		runtimeManager.attempted = nil
		runtimeManager.failures = map[int64]string{}
		runtimeManager.restarts = map[int64]int{}
		runtimeManager.watchdogs = map[int64]int{}
		return errors.Join(configErr, currentErr, markerErr)
	}
	if err = runtimeManager.stopAllLocked(); err != nil {
		return err
	}
	if err = runtimeManager.restoreLocked(lastGood); err != nil {
		return err
	}
	if err = persistManagedState(safeManagedStateFile(managedServicesCurrentStateFile), *lastGood); err != nil {
		return err
	}
	_ = os.Remove(safeManagedStateFile(managedServicesApplyMarkerFile))
	copy := *lastGood
	runtimeManager.attempted = &copy
	runtimeManager.failures = map[int64]string{}
	runtimeManager.restarts = map[int64]int{}
	runtimeManager.watchdogs = map[int64]int{}
	return nil
}

func (runtimeManager *managedServicesRuntime) ObservedState(now time.Time) ManagedServicesObservedState {
	runtimeManager.mu.Lock()
	defer runtimeManager.mu.Unlock()
	state := runtimeManager.current
	applied := state != nil
	if state == nil {
		state, _ = readManagedState(safeManagedStateFile(managedServicesCurrentStateFile))
		applied = state != nil
	}
	if state == nil {
		state = runtimeManager.attempted
	}
	observed := ManagedServicesObservedState{
		SchemaVersion: managedServicesSchemaVersion, Services: []ManagedServiceObserved{}, ObservedAt: now.UTC().Format(time.RFC3339Nano),
	}
	if state == nil {
		return observed
	}
	if applied {
		observed.AppliedGeneration = state.Generation
		hash := state.ConfigHash
		observed.AppliedConfigHash = &hash
	}
	targets, targetErrors := inspectManagedServiceTargetsForObserved(state.Services, inspectManagedServiceTarget)
	for _, service := range state.Services {
		target, targetOK := targets[service.Kind]
		version := target.version
		if version == "" {
			version = service.TargetVersion
		}
		network := "tcp"
		if service.Kind == managedServicesKindAmneziaWG {
			network = "udp"
		}
		entry := ManagedServiceObserved{
			Kind: service.Kind, ServiceID: service.ServiceID, ServiceTag: service.ServiceTag,
			ServiceStatus: string(XrayServiceError),
			Listener:      ManagedServiceObservedListener{Network: network, ListenAddress: "0.0.0.0", Port: service.ListenPort, Status: string(XrayListenerMissing)},
		}
		if targetErrors[service.Kind] == nil && targetOK {
			entry.InstalledVersion = &version
			binaryHash := target.binaryHash
			entry.BinarySHA256 = &binaryHash
		} else {
			code := "ARTIFACT_HASH_MISMATCH"
			entry.ErrorCode, entry.Listener.ErrorCode = &code, &code
		}
		process := runtimeManager.processes[service.ServiceTag]
		if process != nil && process.cmd != nil && process.cmd.Process != nil {
			_, identityErr := inspectManagedServiceProcess(process)
			listeners, probeErr := []XrayObservedListener(nil), identityErr
			if identityErr == nil {
				listeners, probeErr = probeManagedXrayListeners(process.identity.PID, managedExpectedListener(service))
			}
			if probeErr == nil && len(listeners) == 1 && listeners[0].Status == XrayListenerReady && targetErrors[service.Kind] == nil && targetOK {
				pid := process.identity.PID
				entry.ProcessID = &pid
				entry.ServiceStatus = string(XrayServiceRunning)
				entry.RunningVersion = &version
				entry.Listener.Status = string(XrayListenerReady)
				entry.ErrorCode, entry.Listener.ErrorCode = nil, nil
			} else {
				code := "RUNTIME_NOT_READY"
				entry.ErrorCode, entry.Listener.ErrorCode = &code, &code
			}
		} else if code := runtimeManager.failures[service.ServiceID]; code != "" {
			entry.ErrorCode, entry.Listener.ErrorCode = &code, &code
		} else if entry.ErrorCode == nil {
			code := "RUNTIME_START_FAILED"
			entry.ErrorCode, entry.Listener.ErrorCode = &code, &code
		}
		observed.Services = append(observed.Services, entry)
	}
	sort.Slice(observed.Services, func(i, j int) bool { return observed.Services[i].ServiceID < observed.Services[j].ServiceID })
	return observed
}

func inspectManagedServiceTargetsForObserved(services []ManagedServiceDesired, inspect func(ManagedServiceDesired) (managedServiceTarget, error)) (map[string]managedServiceTarget, map[string]error) {
	targets := map[string]managedServiceTarget{}
	targetErrors := map[string]error{}
	for _, service := range services {
		if _, inspected := targets[service.Kind]; inspected || targetErrors[service.Kind] != nil {
			continue
		}
		target, err := inspect(service)
		if err != nil {
			targetErrors[service.Kind] = err
		} else {
			targets[service.Kind] = target
		}
	}
	return targets, targetErrors
}

func managedServicesObservedSignature(state ManagedServicesObservedState) string {
	state.ObservedAt = ""
	raw, err := json.Marshal(state)
	if err != nil {
		return ""
	}
	return hashManagedServicesBytes(raw)
}

type managedServicesHeartbeatReport struct {
	Signature         string
	State             *ManagedServicesObservedState
	requestGeneration uint64
}

var managedServicesHeartbeatState = struct {
	sync.Mutex
	lastSignature              string
	lastFullReportedAt         time.Time
	requestGeneration          uint64
	committedRequestGeneration uint64
}{}

func managedServicesStateForHeartbeatAt(now time.Time, force bool) managedServicesHeartbeatReport {
	state := managedServicesRuntimeManager.ObservedState(now)
	signature := managedServicesObservedSignature(state)
	managedServicesHeartbeatState.Lock()
	requestGeneration := managedServicesHeartbeatState.requestGeneration
	sendFull := force || signature != managedServicesHeartbeatState.lastSignature ||
		requestGeneration > managedServicesHeartbeatState.committedRequestGeneration || managedServicesHeartbeatState.lastFullReportedAt.IsZero() ||
		now.Sub(managedServicesHeartbeatState.lastFullReportedAt) >= managedServicesStateAuditInterval
	managedServicesHeartbeatState.Unlock()
	report := managedServicesHeartbeatReport{Signature: signature, requestGeneration: requestGeneration}
	if sendFull {
		copy := state
		report.State = &copy
	}
	return report
}

func appendManagedServicesHeartbeatState(payload map[string]any, now time.Time) managedServicesHeartbeatReport {
	report := managedServicesStateForHeartbeatAt(now, false)
	if report.Signature != "" {
		payload["managedServicesStateSignature"] = report.Signature
		if report.State != nil {
			payload["managedServicesState"] = report.State
		}
	}
	return report
}

func commitManagedServicesHeartbeatState(report managedServicesHeartbeatReport, reportedAt time.Time) {
	if report.Signature == "" || report.State == nil {
		return
	}
	managedServicesHeartbeatState.Lock()
	managedServicesHeartbeatState.lastSignature = report.Signature
	managedServicesHeartbeatState.lastFullReportedAt = reportedAt
	if report.requestGeneration > managedServicesHeartbeatState.committedRequestGeneration {
		managedServicesHeartbeatState.committedRequestGeneration = report.requestGeneration
	}
	managedServicesHeartbeatState.Unlock()
}

func requestManagedServicesStateUpload() {
	managedServicesHeartbeatState.Lock()
	managedServicesHeartbeatState.requestGeneration++
	managedServicesHeartbeatState.Unlock()
}

type managedServicesApplyJob struct {
	cfg     Config
	desired ManagedServicesDesiredState
	waiters []chan struct{}
}

var managedServicesApplyQueue = struct {
	sync.Mutex
	active  *managedServicesApplyJob
	pending *managedServicesApplyJob
}{}

func sameManagedServicesApplyIdentity(left, right ManagedServicesDesiredState) bool {
	return left.Generation == right.Generation && left.ConfigHash == right.ConfigHash
}

func closeManagedServicesApplyWaiters(job *managedServicesApplyJob) {
	if job == nil {
		return
	}
	for _, waiter := range job.waiters {
		close(waiter)
	}
}

func recordManagedServicesApplyFailure(desired ManagedServicesDesiredState) {
	managedServicesRuntimeManager.mu.Lock()
	for _, service := range desired.Services {
		if managedServicesRuntimeManager.failures[service.ServiceID] == "" {
			managedServicesRuntimeManager.failures[service.ServiceID] = "INTERNAL_ERROR"
		}
	}
	managedServicesRuntimeManager.mu.Unlock()
}

func runManagedServicesApplyQueue(first *managedServicesApplyJob) {
	job := first
	for job != nil {
		if err := managedServicesRuntimeManager.Apply(context.Background(), job.cfg, job.desired); err != nil {
			recordManagedServicesApplyFailure(job.desired)
		}
		requestManagedServicesStateUpload()
		wakeHeartbeat()

		managedServicesApplyQueue.Lock()
		closeManagedServicesApplyWaiters(job)
		job = managedServicesApplyQueue.pending
		managedServicesApplyQueue.pending = nil
		managedServicesApplyQueue.active = job
		managedServicesApplyQueue.Unlock()
	}
}

func syncManagedServicesDesiredState(cfg Config, desired *ManagedServicesDesiredState) <-chan struct{} {
	if desired == nil {
		return nil
	}
	waiter := make(chan struct{})
	job := &managedServicesApplyJob{cfg: cfg, desired: *desired, waiters: []chan struct{}{waiter}}
	managedServicesApplyQueue.Lock()
	if managedServicesApplyQueue.active == nil {
		managedServicesApplyQueue.active = job
		managedServicesApplyQueue.Unlock()
		go runManagedServicesApplyQueue(job)
		return waiter
	}
	if sameManagedServicesApplyIdentity(managedServicesApplyQueue.active.desired, job.desired) {
		managedServicesApplyQueue.active.waiters = append(managedServicesApplyQueue.active.waiters, waiter)
		managedServicesApplyQueue.Unlock()
		return waiter
	}
	if job.desired.Generation <= managedServicesApplyQueue.active.desired.Generation {
		managedServicesApplyQueue.Unlock()
		close(waiter)
		requestManagedServicesStateUpload()
		return waiter
	}
	if managedServicesApplyQueue.pending != nil {
		if sameManagedServicesApplyIdentity(managedServicesApplyQueue.pending.desired, job.desired) {
			managedServicesApplyQueue.pending.waiters = append(managedServicesApplyQueue.pending.waiters, waiter)
			managedServicesApplyQueue.Unlock()
			return waiter
		}
		if job.desired.Generation <= managedServicesApplyQueue.pending.desired.Generation {
			managedServicesApplyQueue.Unlock()
			close(waiter)
			requestManagedServicesStateUpload()
			return waiter
		}
		closeManagedServicesApplyWaiters(managedServicesApplyQueue.pending)
	}
	managedServicesApplyQueue.pending = job
	managedServicesApplyQueue.Unlock()
	return waiter
}

func restoreManagedServicesBeforePanelAuth() {
	if err := managedServicesRuntimeManager.RecoverLocal(); err != nil && !errors.Is(err, os.ErrNotExist) {
		logf("managed services local runtime recovery skipped: %v", err)
	}
}
