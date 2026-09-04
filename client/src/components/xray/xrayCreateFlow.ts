export type XrayHostUnavailableReason =
  | "AGENT_OFFLINE" | "HEARTBEAT_STALE" | "AGENT_UPGRADE_REQUIRED"
  | "PLATFORM_UNSUPPORTED" | "ARTIFACT_UNAVAILABLE" | "PUBLIC_IPV4_MISSING";

export type XrayHostOption = {
  id: number;
  name: string;
  publicIpv4: string | null;
  isOnline: boolean;
  canCreateXrayInbound: boolean;
  unavailableReasonCode: XrayHostUnavailableReason | null;
  os: string | null;
  arch: string | null;
};

export type XrayCreateProfileOption = {
  id: string;
  protocol: "VLESS" | "TROJAN" | "VMESS" | "SHADOWSOCKS" | "HYSTERIA2" | "WIREGUARD" | "HTTP" | "MIXED" | "TUNNEL";
  transport: "RAW" | "GRPC" | "WEBSOCKET" | "HTTP_UPGRADE" | "XHTTP" | "MKCP" | "HYSTERIA" | "NONE";
  security: "NONE" | "TLS" | "REALITY";
  clientFlow: "XTLS_RPRX_VISION" | "NONE";
  listenerNetworks: readonly ("TCP" | "UDP")[];
  clientCredentialType: string;
  shareFormat: string;
  testedCoreVersion: "v26.3.27";
  advisoryCode?: "CORE_DEPRECATED" | "WIREGUARD_BLOCKING_RISK" | "PLAINTEXT_PROXY_AUTH_RISK" | "PLAINTEXT_MIXED_AUTH_RISK" | null;
  isAvailable: boolean;
  unavailableReasonCode: "NOT_IMPLEMENTED" | "AGENT_UPGRADE_REQUIRED" | "TLS_CERTIFICATE_REQUIRED" | "UDP_CAPABILITY_REQUIRED" | null;
};

export const XRAY_CORE_DEPRECATED_WARNING = "兼容协议，固定 Xray 核心已标记 deprecated；新节点优先使用 VLESS/Trojan";
export const XRAY_WIREGUARD_BLOCKING_WARNING = "WireGuard 外层特征明显，可能被识别或封锁";
export const XRAY_HTTP_PLAINTEXT_AUTH_WARNING = "该 HTTP 代理未使用 TLS，Basic 用户名和密码可能被链路观察者读取；仅在受信网络或额外加密隧道中使用";
export const XRAY_MIXED_PLAINTEXT_AUTH_WARNING = "该 Mixed 代理未使用 TLS，SOCKS5 用户名/密码和 HTTP Basic 凭据可能被链路观察者读取；仅在受信网络或额外加密隧道中使用";

const XRAY_CREATE_VISIBLE_PROTOCOLS = new Set<XrayCreateProfileOption["protocol"]>([
  "VLESS",
  "TROJAN",
  "SHADOWSOCKS",
  "HTTP",
  "MIXED",
]);

export function availableXrayCreateProfiles(profiles: readonly XrayCreateProfileOption[]) {
  return profiles.filter((profile) => profile.isAvailable && XRAY_CREATE_VISIBLE_PROTOCOLS.has(profile.protocol));
}

export function listenerNetworkForXrayProfile(profile?: XrayCreateProfileOption | null): "TCP" | "UDP" {
  return profile?.listenerNetworks.length === 1 && profile.listenerNetworks[0] === "UDP" ? "UDP" : "TCP";
}

export function listenerNetworksMatch(
  left?: Pick<XrayCreateProfileOption, "listenerNetworks"> | null,
  right?: Pick<XrayCreateProfileOption, "listenerNetworks"> | null,
): boolean {
  const leftNetworks = left?.listenerNetworks ?? ["TCP"];
  const rightNetworks = right?.listenerNetworks ?? ["TCP"];
  return leftNetworks.length === rightNetworks.length
    && leftNetworks.every((network, index) => network === rightNetworks[index]);
}

export type XrayPortProbeState =
  | { phase: "IDLE" }
  | { phase: "QUEUED" | "RUNNING"; operationId: string }
  | { phase: "RESERVED"; operationId: string; selectedPort: number; reservationId: string; expiresAt: string }
  | { phase: "FAILED"; errorCode: string };

export type XrayCreateState = {
  hostId: number | null;
  name: string;
  publicAddress: string;
  portMode: "AUTO" | "MANUAL";
  manualPort: string;
  probe: XrayPortProbeState;
  secondaryProbe: XrayPortProbeState;
  replaceReservationIds: string[];
};

export type XrayCreateAction =
  | { type: "SELECT_HOST"; host: XrayHostOption }
  | { type: "SET_NAME"; value: string }
  | { type: "SET_PUBLIC_ADDRESS"; value: string }
  | { type: "SET_PORT_MODE"; mode: "AUTO" | "MANUAL" }
  | { type: "SET_MANUAL_PORT"; value: string }
  | { type: "RESET_PROBE" }
  | { type: "PROBE_QUEUED"; slot?: "PRIMARY" | "SECONDARY"; operationId: string }
  | { type: "PROBE_RUNNING"; slot?: "PRIMARY" | "SECONDARY"; operationId: string }
  | { type: "PROBE_RESERVED"; slot?: "PRIMARY" | "SECONDARY"; selectedPort: number; reservationId: string; expiresAt: string }
  | { type: "PROBE_FAILED"; slot?: "PRIMARY" | "SECONDARY"; errorCode: string };

export function initialXrayCreateState(): XrayCreateState {
  return {
    hostId: null,
    name: "",
    publicAddress: "",
    portMode: "AUTO",
    manualPort: "",
    probe: { phase: "IDLE" },
    secondaryProbe: { phase: "IDLE" },
    replaceReservationIds: [],
  };
}

function reservedProbeIds(state: XrayCreateState): string[] {
  return [state.probe, state.secondaryProbe]
    .filter((probe): probe is Extract<XrayPortProbeState, { phase: "RESERVED" }> => probe.phase === "RESERVED")
    .map((probe) => probe.reservationId);
}

function resetProbes(state: XrayCreateState, preserveReservations = true): XrayCreateState {
  return {
    ...state,
    probe: { phase: "IDLE" },
    secondaryProbe: { phase: "IDLE" },
    replaceReservationIds: preserveReservations
      ? [...new Set([...state.replaceReservationIds, ...reservedProbeIds(state)])]
      : [],
  };
}

export function currentXrayPortReplacementIds(state: XrayCreateState): string[] {
  return [...new Set([...state.replaceReservationIds, ...reservedProbeIds(state)])];
}

function replaceProbe(
  state: XrayCreateState,
  slot: "PRIMARY" | "SECONDARY" | undefined,
  probe: XrayPortProbeState,
): XrayCreateState {
  return slot === "SECONDARY" ? { ...state, secondaryProbe: probe } : { ...state, probe };
}

export function reduceXrayCreateState(state: XrayCreateState, action: XrayCreateAction): XrayCreateState {
  if (action.type === "SELECT_HOST") return resetProbes({
    ...state,
    hostId: action.host.id,
    publicAddress: action.host.publicIpv4 ?? state.publicAddress,
  }, false);
  if (action.type === "SET_NAME") return { ...state, name: action.value };
  if (action.type === "SET_PUBLIC_ADDRESS") return { ...state, publicAddress: action.value };
  if (action.type === "SET_PORT_MODE") return resetProbes({ ...state, portMode: action.mode });
  if (action.type === "SET_MANUAL_PORT") return resetProbes({ ...state, manualPort: action.value.replace(/\D/g, "").slice(0, 5) });
  if (action.type === "RESET_PROBE") return resetProbes(state);
  if (action.type === "PROBE_QUEUED") {
    const next = replaceProbe(state, action.slot, { phase: "QUEUED", operationId: action.operationId });
    return action.slot === "SECONDARY" ? next : { ...next, replaceReservationIds: [] };
  }
  if (action.type === "PROBE_RUNNING") return replaceProbe(state, action.slot, { phase: "RUNNING", operationId: action.operationId });
  if (action.type === "PROBE_RESERVED") {
    const currentProbe = action.slot === "SECONDARY" ? state.secondaryProbe : state.probe;
    const operationId = "operationId" in currentProbe ? currentProbe.operationId : "";
    return replaceProbe(state, action.slot, {
      phase: "RESERVED",
      operationId,
      selectedPort: action.selectedPort,
      reservationId: action.reservationId,
      expiresAt: action.expiresAt,
    });
  }
  return replaceProbe(state, action.slot, { phase: "FAILED", errorCode: action.errorCode });
}

export function xrayBasicSetupReady(state: XrayCreateState, hosts: readonly XrayHostOption[]): boolean {
  const selected = hosts.find((host) => host.id === state.hostId);
  return !!selected?.canCreateXrayInbound
    && state.name.trim().length > 0
    && state.name.trim().length <= 128
    && state.publicAddress.trim().length > 0
    && state.publicAddress.trim().length <= 253;
}

export function hostUnavailableMessage(host: XrayHostOption): string {
  if (host.canCreateXrayInbound) return `可用 · ${host.os ?? "未知系统"}/${host.arch ?? "未知架构"}`;
  if (host.unavailableReasonCode === "AGENT_OFFLINE") return "Agent 离线，无法检测端口或部署";
  if (host.unavailableReasonCode === "HEARTBEAT_STALE") return "Agent 心跳过期，运行状态未知";
  if (host.unavailableReasonCode === "AGENT_UPGRADE_REQUIRED") return "Agent 版本过低，请先升级 Agent";
  if (host.unavailableReasonCode === "PLATFORM_UNSUPPORTED") return "主机平台不受支持";
  if (host.unavailableReasonCode === "ARTIFACT_UNAVAILABLE") return `缺少 ${host.os ?? "未知"}-${host.arch ?? "未知"} Xray 制品`;
  if (host.unavailableReasonCode === "PUBLIC_IPV4_MISSING") return "缺少可用公网 IPv4，请先配置公网地址";
  return "主机当前不可用于 Xray 部署";
}

const probeErrorMessages: Record<string, string> = {
  HOST_OFFLINE: "Agent 离线，已保留表单，请恢复连接后重新探测。",
  AGENT_CAPABILITY_MISSING: "Agent 不支持端口探测，请先升级 Agent。",
  UDP_CAPABILITY_REQUIRED: "需要升级 Agent 以支持 UDP 端口探测和监听确认。",
  PORT_IN_USE: "端口已被占用，请更换端口后重新探测。",
  PORT_OUT_OF_RANGE: "端口不在主机允许的 1000–65535 范围内。",
  PORT_RESERVATION_EXPIRED: "端口预留已过期，请重新探测。",
};

export function xrayPortProbePresentation(probe: XrayPortProbeState, now: number) {
  if (probe.phase === "RESERVED" && Date.parse(probe.expiresAt) <= now) {
    return { phase: "EXPIRED" as const, label: "预留已过期", message: probeErrorMessages.PORT_RESERVATION_EXPIRED, canReprobe: true };
  }
  if (probe.phase === "QUEUED" || probe.phase === "RUNNING") {
    return { phase: probe.phase, label: probe.phase === "QUEUED" ? "等待检测" : "检测中", message: "等待 Agent 探测端口；请勿关闭网络连接。", canReprobe: false };
  }
  if (probe.phase === "RESERVED") {
    return { phase: "RESERVED" as const, label: "端口可用", message: `已短期预留 ${probe.selectedPort}，最终绑定仍可能冲突。`, canReprobe: true };
  }
  if (probe.phase === "FAILED") {
    return { phase: "FAILED" as const, label: "检测失败", message: probeErrorMessages[probe.errorCode] ?? "端口检测未完成，请重试。", canReprobe: true };
  }
  return { phase: "IDLE" as const, label: "等待检测", message: "探测结果是短期事实，创建前必须获得有效预留。", canReprobe: true };
}

export function portProbePresentation(state: XrayCreateState, now: number) {
  return xrayPortProbePresentation(state.probe, now);
}

export function portReservationsReady(
  state: XrayCreateState,
  listenerNetworks: readonly ("TCP" | "UDP")[],
  now: number,
): boolean {
  if (state.probe.phase !== "RESERVED" || Date.parse(state.probe.expiresAt) <= now) return false;
  if (listenerNetworks.length < 2) return true;
  return state.secondaryProbe.phase === "RESERVED"
    && Date.parse(state.secondaryProbe.expiresAt) > now
    && state.secondaryProbe.selectedPort === state.probe.selectedPort;
}

export function nextSecondaryPortProbeInput(
  state: XrayCreateState,
  listenerNetworks: readonly ("TCP" | "UDP")[],
  now: number,
): { hostId: number; mode: "MANUAL"; network: "UDP"; manualPort: number } | null {
  if (listenerNetworks.length !== 2 || listenerNetworks[0] !== "TCP" || listenerNetworks[1] !== "UDP"
    || !state.hostId || state.probe.phase !== "RESERVED" || state.secondaryProbe.phase !== "IDLE"
    || Date.parse(state.probe.expiresAt) <= now) return null;
  return {
    hostId: state.hostId,
    mode: "MANUAL",
    network: "UDP",
    manualPort: state.probe.selectedPort,
  };
}

export function validManualPort(state: XrayCreateState): boolean {
  const port = Number(state.manualPort);
  return state.portMode === "AUTO" || (Number.isInteger(port) && port >= 1000 && port <= 65535);
}
