import type { XrayCreateState } from "./xrayCreateFlow";
import { normalizeXrayTunnelTargetAddress } from "@shared/xrayProfiles";

export type XrayRealityCandidate = {
  target: string;
  host: string;
  resolvedIp: string;
  port: number;
  feasible: boolean;
  tls13: boolean;
  h2: boolean;
  x25519: boolean;
  certificateValid: boolean;
  serverNames: string[];
  latencyMs: number;
  reasonCode: string | null;
};

type ScanState =
  | { phase: "IDLE" }
  | { phase: "QUEUED" | "RUNNING"; operationId: string }
  | { phase: "SUCCESS"; results: XrayRealityCandidate[] }
  | { phase: "FAILED"; errorCode: string };

export type XrayClientDraft = { key: number; name: string };

export type XrayDeploymentState = {
  stage: "SETUP" | "REALITY" | "CLIENTS" | "CONFIRM";
  scanSource: "DEFAULT_CANDIDATES" | "ADMIN_DOMAINS";
  customTargets: string;
  scan: ScanState;
  selectedReality: XrayRealityCandidate | null;
  tlsCertificateId: number | null;
  tlsServerName: string;
  tunnelTargetAddress: string;
  tunnelTargetPort: string;
  clients: XrayClientDraft[];
  submitError: string | null;
};

export type XrayDeploymentAction =
  | { type: "RESET" } | { type: "ENTER_REALITY" } | { type: "BACK_SETUP" } | { type: "GO_CLIENTS" }
  | { type: "GO_CLIENTS_NONE" }
  | { type: "BACK_REALITY" } | { type: "GO_CONFIRM" } | { type: "BACK_CLIENTS" }
  | { type: "GO_CONFIRM_NONE" }
  | { type: "GO_CONFIRM_CREDENTIALLESS" }
  | { type: "SET_SCAN_SOURCE"; source: "DEFAULT_CANDIDATES" | "ADMIN_DOMAINS" }
  | { type: "SET_CUSTOM_TARGETS"; value: string }
  | { type: "SCAN_QUEUED"; operationId: string } | { type: "SCAN_RUNNING"; operationId: string }
  | { type: "SCAN_SUCCESS"; results: XrayRealityCandidate[] } | { type: "SCAN_FAILED"; errorCode: string }
  | { type: "SELECT_REALITY"; candidate: XrayRealityCandidate }
  | { type: "SELECT_TLS_CERTIFICATE"; certificateId: number | null }
  | { type: "SET_TLS_SERVER_NAME"; value: string }
  | { type: "SET_TUNNEL_TARGET_ADDRESS"; value: string }
  | { type: "SET_TUNNEL_TARGET_PORT"; value: string }
  | { type: "ADD_CLIENT" } | { type: "REMOVE_CLIENT"; key: number } | { type: "SET_CLIENT_NAME"; key: number; value: string }
  | { type: "SUBMIT_FAILED"; errorCode: string };

export function initialXrayDeploymentState(): XrayDeploymentState {
  return {
    stage: "SETUP", scanSource: "DEFAULT_CANDIDATES", customTargets: "", scan: { phase: "IDLE" },
    selectedReality: null, tlsCertificateId: null, tlsServerName: "",
    tunnelTargetAddress: "127.0.0.1", tunnelTargetPort: "",
    clients: [{ key: 1, name: "默认客户端" }], submitError: null,
  };
}

export function reduceXrayDeploymentState(state: XrayDeploymentState, action: XrayDeploymentAction): XrayDeploymentState {
  switch (action.type) {
    case "RESET": return initialXrayDeploymentState();
    case "ENTER_REALITY": return { ...state, stage: "REALITY", submitError: null };
    case "BACK_SETUP": return { ...state, stage: "SETUP" };
    case "GO_CLIENTS": return state.selectedReality || (state.tlsCertificateId && validTlsServerName(state.tlsServerName))
      ? { ...state, stage: "CLIENTS" } : state;
    case "GO_CLIENTS_NONE": return { ...state, stage: "CLIENTS" };
    case "BACK_REALITY": return { ...state, stage: "REALITY" };
    case "GO_CONFIRM": return (state.selectedReality || (state.tlsCertificateId && validTlsServerName(state.tlsServerName)))
      && validInitialClients(state.clients) ? { ...state, stage: "CONFIRM", submitError: null } : state;
    case "GO_CONFIRM_NONE": return validInitialClients(state.clients)
      ? { ...state, stage: "CONFIRM", submitError: null } : state;
    case "GO_CONFIRM_CREDENTIALLESS": return { ...state, stage: "CONFIRM", submitError: null };
    case "BACK_CLIENTS": return { ...state, stage: "CLIENTS" };
    case "SET_SCAN_SOURCE": return { ...state, scanSource: action.source, scan: { phase: "IDLE" }, selectedReality: null };
    case "SET_CUSTOM_TARGETS": return { ...state, customTargets: action.value.slice(0, 16_704), scan: { phase: "IDLE" }, selectedReality: null };
    case "SCAN_QUEUED": return { ...state, scan: { phase: "QUEUED", operationId: action.operationId }, selectedReality: null };
    case "SCAN_RUNNING": return { ...state, scan: { phase: "RUNNING", operationId: action.operationId } };
    case "SCAN_SUCCESS": return { ...state, scan: { phase: "SUCCESS", results: action.results }, selectedReality: null };
    case "SCAN_FAILED": return { ...state, scan: { phase: "FAILED", errorCode: action.errorCode }, selectedReality: null };
    case "SELECT_REALITY": {
      if (state.scan.phase !== "SUCCESS") return state;
      const candidate = state.scan.results.find((item) => item.target === action.candidate.target && item.feasible);
      return candidate ? { ...state, selectedReality: candidate } : state;
    }
    case "SELECT_TLS_CERTIFICATE": return {
      ...state,
      tlsCertificateId: action.certificateId && Number.isSafeInteger(action.certificateId) && action.certificateId > 0
        ? action.certificateId : null,
      submitError: null,
    };
    case "SET_TLS_SERVER_NAME": return { ...state, tlsServerName: action.value.slice(0, 253), submitError: null };
    case "SET_TUNNEL_TARGET_ADDRESS": return { ...state, tunnelTargetAddress: action.value.slice(0, 253), submitError: null };
    case "SET_TUNNEL_TARGET_PORT": return { ...state, tunnelTargetPort: action.value.replace(/\D/g, "").slice(0, 5), submitError: null };
    case "ADD_CLIENT": {
      if (state.clients.length >= 32) return state;
      const key = Math.max(0, ...state.clients.map((client) => client.key)) + 1;
      return { ...state, clients: [...state.clients, { key, name: "" }] };
    }
    case "REMOVE_CLIENT": return state.clients.length <= 1 ? state : { ...state, clients: state.clients.filter((client) => client.key !== action.key) };
    case "SET_CLIENT_NAME": return { ...state, clients: state.clients.map((client) => client.key === action.key ? { ...client, name: action.value.slice(0, 128) } : client) };
    case "SUBMIT_FAILED": return { ...state, submitError: action.errorCode };
  }
}

export function validInitialClients(clients: XrayClientDraft[]): boolean {
  if (clients.length < 1 || clients.length > 32) return false;
  const names = clients.map((client) => client.name.trim());
  return names.every((name) => name.length >= 1 && name.length <= 128)
    && new Set(names.map((name) => name.toLocaleLowerCase())).size === names.length;
}

export function normalizeTlsServerName(value: string): string | null {
  const input = value.trim();
  if (!input || input.includes("*") || /[^\x00-\x7f]/.test(input)) return null;
  const normalized = input.toLowerCase();
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(normalized)
    ? normalized
    : null;
}

export function validTlsServerName(value: string): boolean {
  return normalizeTlsServerName(value) !== null;
}

export function normalizedTunnelTarget(state: Pick<XrayDeploymentState, "tunnelTargetAddress" | "tunnelTargetPort">) {
  const targetAddress = normalizeXrayTunnelTargetAddress(state.tunnelTargetAddress);
  const targetPort = Number(state.tunnelTargetPort);
  return targetAddress && Number.isSafeInteger(targetPort) && targetPort >= 1 && targetPort <= 65535
    ? { targetAddress, targetPort }
    : null;
}

export function tlsCertificateCoversServerName(
  certificate: { dnsNames: readonly string[] } | undefined,
  value: string,
): boolean {
  const serverName = normalizeTlsServerName(value);
  if (!certificate || !serverName) return false;
  return certificate.dnsNames.some((candidate) => {
    const dnsName = candidate.toLowerCase();
    if (dnsName === serverName) return true;
    if (!dnsName.startsWith("*.")) return false;
    return serverName.endsWith(dnsName.slice(1)) && serverName.split(".").length === dnsName.split(".").length;
  });
}

export function parseAdminRealityTargets(value: string): string[] {
  const targets = value.split(/[\n,]+/).map((target) => target.trim()).filter(Boolean);
  return [...new Set(targets.map((target) => target.toLocaleLowerCase()))].slice(0, 64);
}

export function operationFailureNextStep(errorCode: string | null): string {
  if (errorCode === "HOST_OFFLINE") return "等待 Agent 恢复在线后，从运行环境重新同步；不要据此判断 Xray 已停止。";
  if (errorCode?.startsWith("ARTIFACT_") || errorCode === "XRAY_VERSION_MISMATCH") return "检查目标平台的固定版本制品状态，修复后重新部署。";
  if (errorCode === "CONFIG_INVALID" || errorCode === "GENERATION_HASH_CONFLICT") return "查看运行环境中的 generation/hash，修复冲突后重新同步。";
  if (errorCode === "RUNTIME_START_FAILED" || errorCode === "RUNTIME_NOT_READY") return "查看受管进程和监听器状态；last-good 会继续保留。";
  if (errorCode === "ROLLBACK_FAILED") return "立即查看运行环境的 last-good 与受管进程状态，再决定是否重新同步。";
  return "查看运行环境的脱敏状态与最近 operation，确认主机在线后再重试。";
}

export function buildXrayInboundCreateRequest(setup: XrayCreateState, deployment: XrayDeploymentState, now: number) {
  const { base, initialAccessEntries } = buildXrayInboundCreateBase(setup, deployment, now);
  const reality = deployment.selectedReality;
  if (!reality?.feasible || reality.serverNames.length !== 1 || reality.serverNames[0] !== reality.host) throw new Error("REALITY_TARGET_INVALID");
  return {
    ...base,
    reality: {
      targetHost: reality.host,
      targetPort: reality.port,
      serverName: reality.serverNames[0],
      fingerprint: "chrome" as const,
      spiderX: "/",
    },
    initialClients: initialAccessEntries.map((client) => ({ name: client.name, flow: "xtls-rprx-vision" as const })),
  };
}

export type XrayInboundCreateV2Profile =
  | { profileId: "VLESS_RAW_REALITY_VISION" }
  | { profileId: "VLESS_GRPC_REALITY"; serviceName: string }
  | { profileId: "VLESS_XHTTP_REALITY"; path: string }
  | { profileId: "TROJAN_RAW_REALITY" }
  | { profileId: "VLESS_RAW_TLS"; tlsCertificateId: number; serverName: string }
  | { profileId: "VLESS_RAW_TLS_VISION"; tlsCertificateId: number; serverName: string }
  | { profileId: "TROJAN_RAW_TLS"; tlsCertificateId: number; serverName: string }
  | { profileId: "VMESS_RAW_TLS"; tlsCertificateId: number; serverName: string }
  | { profileId: "SHADOWSOCKS_2022_RAW_NONE" }
  | { profileId: "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE" }
  | { profileId: "WIREGUARD_UDP_NONE" }
  | { profileId: "HTTP_RAW_NONE" }
  | { profileId: "MIXED_RAW_NONE" }
  | { profileId: "TUNNEL_TCP_LOCAL_NONE"; targetAddress: string; targetPort: number }
  | { profileId: "VLESS_WEBSOCKET_TLS"; path: string; tlsCertificateId: number; serverName: string }
  | { profileId: "TROJAN_WEBSOCKET_TLS"; path: string; tlsCertificateId: number; serverName: string }
  | { profileId: "VLESS_GRPC_TLS"; serviceName: string; tlsCertificateId: number; serverName: string }
  | { profileId: "TROJAN_GRPC_TLS"; serviceName: string; tlsCertificateId: number; serverName: string }
  | { profileId: "VLESS_HTTP_UPGRADE_TLS"; path: string; tlsCertificateId: number; serverName: string }
  | { profileId: "TROJAN_HTTP_UPGRADE_TLS"; path: string; tlsCertificateId: number; serverName: string }
  | { profileId: "VLESS_XHTTP_TLS"; path: string; tlsCertificateId: number; serverName: string }
  | { profileId: "TROJAN_XHTTP_TLS"; path: string; tlsCertificateId: number; serverName: string }
  | { profileId: "VLESS_MKCP_TLS"; tlsCertificateId: number; serverName: string }
  | { profileId: "TROJAN_MKCP_TLS"; tlsCertificateId: number; serverName: string }
  | { profileId: "HYSTERIA2_TLS"; tlsCertificateId: number; serverName: string };

function buildXrayInboundCreateBase(setup: XrayCreateState, deployment: XrayDeploymentState, now: number) {
  if (!setup.hostId || !setup.name.trim() || !setup.publicAddress.trim() || setup.probe.phase !== "RESERVED") {
    throw new Error("CREATE_DRAFT_INCOMPLETE");
  }
  if (Date.parse(setup.probe.expiresAt) <= now) throw new Error("PORT_RESERVATION_EXPIRED");
  if (!validInitialClients(deployment.clients)) throw new Error("CLIENTS_INVALID");
  return {
    base: {
      hostId: setup.hostId,
      name: setup.name.trim(),
      publicAddress: setup.publicAddress.trim(),
      portReservationId: setup.probe.reservationId,
      listenPort: setup.probe.selectedPort,
    },
    initialAccessEntries: deployment.clients.map((client) => ({ name: client.name.trim() })),
  };
}

function buildXrayInboundDualNetworkCreateBase(
  setup: XrayCreateState,
  deployment: XrayDeploymentState,
  now: number,
) {
  if (!setup.hostId || !setup.name.trim() || !setup.publicAddress.trim()
    || setup.probe.phase !== "RESERVED" || setup.secondaryProbe.phase !== "RESERVED") {
    throw new Error("CREATE_DRAFT_INCOMPLETE");
  }
  if (setup.probe.selectedPort !== setup.secondaryProbe.selectedPort) {
    throw new Error("PORT_RESERVATIONS_MISMATCH");
  }
  if (Date.parse(setup.probe.expiresAt) <= now || Date.parse(setup.secondaryProbe.expiresAt) <= now) {
    throw new Error("PORT_RESERVATION_EXPIRED");
  }
  if (!validInitialClients(deployment.clients)) throw new Error("CLIENTS_INVALID");
  return {
    base: {
      hostId: setup.hostId,
      name: setup.name.trim(),
      publicAddress: setup.publicAddress.trim(),
      listenPort: setup.probe.selectedPort,
      portReservations: {
        tcp: setup.probe.reservationId,
        udp: setup.secondaryProbe.reservationId,
      },
    },
    initialAccessEntries: deployment.clients.map((client) => ({ name: client.name.trim() })),
  };
}

export function buildXrayInboundCreateV2Request(
  setup: XrayCreateState,
  deployment: XrayDeploymentState,
  profile: XrayInboundCreateV2Profile,
  now: number,
) {
  if (profile.profileId === "TUNNEL_TCP_LOCAL_NONE") {
    if (!setup.hostId || !setup.name.trim() || setup.probe.phase !== "RESERVED") {
      throw new Error("CREATE_DRAFT_INCOMPLETE");
    }
    if (Date.parse(setup.probe.expiresAt) <= now) throw new Error("PORT_RESERVATION_EXPIRED");
    const targetAddress = normalizeXrayTunnelTargetAddress(profile.targetAddress);
    if (!targetAddress || !Number.isSafeInteger(profile.targetPort) || profile.targetPort < 1 || profile.targetPort > 65535) {
      throw new Error("INVALID_CONFIG_INPUT");
    }
    return {
      hostId: setup.hostId,
      name: setup.name.trim(),
      listenPort: setup.probe.selectedPort,
      portReservationId: setup.probe.reservationId,
      profileId: profile.profileId,
      spec: { targetAddress, targetPort: profile.targetPort },
      initialAccessEntries: [],
    };
  }
  if (profile.profileId === "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE") {
    const { base, initialAccessEntries } = buildXrayInboundDualNetworkCreateBase(setup, deployment, now);
    return { ...base, profileId: profile.profileId, spec: {}, initialAccessEntries };
  }
  if (profile.profileId === "SHADOWSOCKS_2022_RAW_NONE" || profile.profileId === "WIREGUARD_UDP_NONE"
    || profile.profileId === "HTTP_RAW_NONE" || profile.profileId === "MIXED_RAW_NONE") {
    const { base, initialAccessEntries } = buildXrayInboundCreateBase(setup, deployment, now);
    return { ...base, profileId: profile.profileId, spec: {}, initialAccessEntries };
  }
  if (profile.profileId === "VLESS_RAW_TLS"
    || profile.profileId === "VLESS_RAW_TLS_VISION"
    || profile.profileId === "TROJAN_RAW_TLS"
    || profile.profileId === "VMESS_RAW_TLS"
    || profile.profileId === "VLESS_WEBSOCKET_TLS"
    || profile.profileId === "TROJAN_WEBSOCKET_TLS"
    || profile.profileId === "VLESS_GRPC_TLS"
    || profile.profileId === "TROJAN_GRPC_TLS"
    || profile.profileId === "VLESS_HTTP_UPGRADE_TLS"
    || profile.profileId === "TROJAN_HTTP_UPGRADE_TLS"
    || profile.profileId === "VLESS_XHTTP_TLS"
    || profile.profileId === "TROJAN_XHTTP_TLS"
    || profile.profileId === "VLESS_MKCP_TLS"
    || profile.profileId === "TROJAN_MKCP_TLS"
    || profile.profileId === "HYSTERIA2_TLS") {
    const { base, initialAccessEntries } = buildXrayInboundCreateBase(setup, deployment, now);
    const serverName = normalizeTlsServerName(profile.serverName);
    const path = profile.profileId === "VLESS_WEBSOCKET_TLS"
      || profile.profileId === "TROJAN_WEBSOCKET_TLS"
      || profile.profileId === "VLESS_HTTP_UPGRADE_TLS"
      || profile.profileId === "TROJAN_HTTP_UPGRADE_TLS"
      || profile.profileId === "VLESS_XHTTP_TLS"
      || profile.profileId === "TROJAN_XHTTP_TLS"
      ? profile.path.trim()
      : null;
    const serviceName = profile.profileId === "VLESS_GRPC_TLS" || profile.profileId === "TROJAN_GRPC_TLS"
      ? profile.serviceName.trim()
      : null;
    if (!Number.isSafeInteger(profile.tlsCertificateId) || profile.tlsCertificateId <= 0 || !serverName) {
      throw new Error("INVALID_CONFIG_INPUT");
    }
    if (path !== null && !/^\/[A-Za-z0-9._~/-]{0,127}$/.test(path)) throw new Error("INVALID_CONFIG_INPUT");
    if (serviceName !== null && !/^[A-Za-z0-9._~-]{1,128}$/.test(serviceName)) throw new Error("INVALID_CONFIG_INPUT");
    const tlsBase = {
      ...base,
      tlsCertificateId: profile.tlsCertificateId,
      serverName,
      initialAccessEntries,
    };
    switch (profile.profileId) {
      case "VLESS_RAW_TLS": return { ...tlsBase, profileId: "VLESS_RAW_TLS" as const, spec: {} };
      case "VLESS_RAW_TLS_VISION": return { ...tlsBase, profileId: "VLESS_RAW_TLS_VISION" as const, spec: {} };
      case "TROJAN_RAW_TLS": return { ...tlsBase, profileId: "TROJAN_RAW_TLS" as const, spec: {} };
      case "VMESS_RAW_TLS": return { ...tlsBase, profileId: "VMESS_RAW_TLS" as const, spec: {} };
      case "VLESS_WEBSOCKET_TLS": return { ...tlsBase, profileId: "VLESS_WEBSOCKET_TLS" as const, spec: { path: profile.path.trim() } };
      case "TROJAN_WEBSOCKET_TLS": return { ...tlsBase, profileId: "TROJAN_WEBSOCKET_TLS" as const, spec: { path: profile.path.trim() } };
      case "VLESS_GRPC_TLS": return { ...tlsBase, profileId: "VLESS_GRPC_TLS" as const, spec: { serviceName: profile.serviceName.trim() } };
      case "TROJAN_GRPC_TLS": return { ...tlsBase, profileId: "TROJAN_GRPC_TLS" as const, spec: { serviceName: profile.serviceName.trim() } };
      case "VLESS_HTTP_UPGRADE_TLS": return { ...tlsBase, profileId: "VLESS_HTTP_UPGRADE_TLS" as const, spec: { path: profile.path.trim() } };
      case "TROJAN_HTTP_UPGRADE_TLS": return { ...tlsBase, profileId: "TROJAN_HTTP_UPGRADE_TLS" as const, spec: { path: profile.path.trim() } };
      case "VLESS_XHTTP_TLS": return { ...tlsBase, profileId: "VLESS_XHTTP_TLS" as const, spec: { path: profile.path.trim() } };
      case "TROJAN_XHTTP_TLS": return { ...tlsBase, profileId: "TROJAN_XHTTP_TLS" as const, spec: { path: profile.path.trim() } };
      case "VLESS_MKCP_TLS": return { ...tlsBase, profileId: "VLESS_MKCP_TLS" as const, spec: {} };
      case "TROJAN_MKCP_TLS": return { ...tlsBase, profileId: "TROJAN_MKCP_TLS" as const, spec: {} };
      case "HYSTERIA2_TLS": return { ...tlsBase, profileId: "HYSTERIA2_TLS" as const, spec: {} };
    }
  }
  const legacy = buildXrayInboundCreateRequest(setup, deployment, now);
  const { initialClients, ...base } = legacy;
  const initialAccessEntries = initialClients.map((client) => ({ name: client.name }));
  if (profile.profileId === "VLESS_RAW_REALITY_VISION") {
    return { ...base, profileId: profile.profileId, spec: {}, initialAccessEntries };
  }
  if (profile.profileId === "VLESS_GRPC_REALITY") {
    const serviceName = profile.serviceName.trim();
    if (!/^[A-Za-z0-9._~-]{1,128}$/.test(serviceName)) throw new Error("INVALID_CONFIG_INPUT");
    return {
      ...base,
      profileId: profile.profileId,
      spec: { serviceName },
      initialAccessEntries,
    };
  }
  if (profile.profileId === "TROJAN_RAW_REALITY") {
    return { ...base, profileId: profile.profileId, spec: {}, initialAccessEntries };
  }
  const path = profile.path.trim();
  if (!/^\/[A-Za-z0-9._~/-]{0,127}$/.test(path)) throw new Error("INVALID_CONFIG_INPUT");
  return { ...base, profileId: profile.profileId, spec: { path }, initialAccessEntries };
}
