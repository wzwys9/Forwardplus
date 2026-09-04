import crypto from "node:crypto";
import {
  normalizeXrayTunnelTargetAddress,
  resolveStoredXrayInboundDefinition,
  type XrayProfileSummary,
} from "../shared/xrayProfiles";
import { AGENT_VERSION } from "../shared/versions";
import { isForwardplusAgentVersionAtLeast } from "./agentRouteUtils";
import net from "node:net";

import { pushAgentRefresh } from "./agentEvents";
import { boolLiteral, quoteIdentifier } from "./dbCompat";
import { queryRaw } from "./dbRuntime";
import { generateXrayHostConfig } from "./xrayConfigGenerator";
import {
  withConsumedXrayPortReservation,
  withConsumedXrayPortReservations,
  XrayPortOperationError,
} from "./xrayPortOperations";
import { listXrayHostOptions } from "./xrayQueryService";
import { recordXrayMutationObservability } from "./xrayMutationObservability";
import { getHostById } from "./repositories/hostRepository";
import {
  createXrayInboundConfiguration,
  getXrayHostDeployment,
  getXrayRuntimeReport,
  updateXrayInboundConfiguration,
  XrayRepositoryError,
  type NewXrayClientRecord,
  type NewXrayGenericAccessRecord,
} from "./repositories/xrayRepository";
import {
  validateXrayRealityDestinationForCreate,
  XrayRealityOperationError,
} from "./xrayRealityOperations";
import {
  encryptXraySecret,
  fingerprintXraySecret,
  loadXrayMasterKeyFile,
  xrayAccessSecretContext,
  xrayClientShortIdContext,
  xrayClientUuidContext,
  xrayInboundSecretContext,
  xrayInboundPrivateKeyContext,
  XraySecretUnavailableError,
} from "./xraySecretCrypto";
import { repairXrayClientFingerprints } from "./xrayFingerprintMigration";
import { GlobalPortAllocationError } from "./globalPortAllocationService";
import {
  loadXrayExternalProxyMaterial,
  XrayExternalProxyServiceError,
} from "./xrayExternalProxyService";
import {
  getXrayTlsCertificateLocation,
  getXrayTlsCertificateMaterial,
  XrayTlsCertificateRepositoryError,
} from "./repositories/xrayTlsCertificateRepository";
import {
  validateXrayTlsCertificateInput,
  xrayTlsCertificateCoversServerName,
  XrayTlsCertificateValidationError,
} from "./xrayTlsCertificate";
import {
  generateXrayWireGuardKeyPair,
  generateXrayWireGuardPreSharedKey,
} from "./xrayWireGuard";

const hostnamePattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const nameControlPattern = /[\u0000-\u001f\u007f]/;

async function assertInboundNotManagedByQuickConfig(inboundId: number) {
  const q = quoteIdentifier;
  const rows = await queryRaw<{ id: unknown }>(
    `SELECT ${q("id")} FROM ${q("xray_quick_configs")} WHERE ${q("xrayInboundId")} = ? AND ${q("state")} <> 'REMOVED' LIMIT 1`,
    [inboundId],
  );
  if (rows[0]) throw new XrayInboundCreateError("OPERATION_CONFLICT");
}

export type XrayInboundCreateErrorCode =
  | "HOST_NOT_FOUND"
  | "HOST_OFFLINE"
  | "AGENT_CAPABILITY_MISSING"
  | "UDP_CAPABILITY_REQUIRED"
  | "INBOUND_NOT_FOUND"
  | "INBOUND_PENDING_DELETE"
  | "CONFIRMATION_MISMATCH"
  | "PLATFORM_UNSUPPORTED"
  | "ARTIFACT_UNAVAILABLE"
  | "PUBLIC_ADDRESS_REQUIRED"
  | "PORT_OUT_OF_RANGE"
  | "PORT_RESERVATION_EXPIRED"
  | "PORT_RESERVATION_MISMATCH"
  | "REALITY_TARGET_INVALID"
  | "REALITY_TARGET_BLOCKED"
  | "CONFIG_GENERATION_CONFLICT"
  | "OPERATION_CONFLICT"
  | "SENSITIVE_DATA_UNAVAILABLE"
  | "EXTERNAL_PROXY_NOT_FOUND"
  | "EXTERNAL_PROXY_UNSUPPORTED"
  | "EXTERNAL_PROXY_REFERENCE_INVALID"
  | "GLOBAL_PORT_CONFLICT"
  | "GLOBAL_PORT_LEGACY_CONFLICT"
  | "GLOBAL_PORT_SCAN_PENDING"
  | "GLOBAL_PORT_EXTERNAL_OCCUPIED"
  | "INVALID_CONFIG_INPUT";

export class XrayInboundCreateError extends Error {
  constructor(readonly code: XrayInboundCreateErrorCode) {
    super(code);
    this.name = "XrayInboundCreateError";
  }
}

export type CreateXrayInboundInput = {
  hostId: unknown;
  userId: unknown;
  name: unknown;
  publicAddress: unknown;
  portReservationId: unknown;
  listenPort: unknown;
  reality: {
    targetHost: unknown;
    targetPort: unknown;
    serverName: unknown;
    fingerprint: unknown;
    spiderX: unknown;
  };
  initialClients: Array<{ name: unknown; flow: unknown }>;
  profileId?: unknown;
  spec?: unknown;
};

export type CreateXrayInboundV2Input = Omit<CreateXrayInboundInput, "initialClients" | "reality" | "profileId" | "spec" | "portReservationId" | "publicAddress"> & {
  profileId: unknown;
  spec: unknown;
  publicAddress?: unknown;
  portReservationId?: unknown;
  portReservations?: { tcp: unknown; udp: unknown };
  reality?: CreateXrayInboundInput["reality"];
  tlsCertificateId?: unknown;
  serverName?: unknown;
  initialAccessEntries: Array<{ name: unknown }>;
};

export type CreateXrayInboundV2Dependencies = Readonly<{
  isProfileEnabledForInternalTest?: (profile: XrayProfileSummary) => boolean;
}>;

type NormalizedCreateProfile = {
  id: "VLESS_RAW_REALITY_VISION" | "VLESS_GRPC_REALITY" | "VLESS_XHTTP_REALITY" | "TROJAN_RAW_REALITY"
    | "VLESS_RAW_TLS" | "VLESS_RAW_TLS_VISION" | "TROJAN_RAW_TLS"
    | "VMESS_RAW_TLS"
    | "SHADOWSOCKS_2022_RAW_NONE" | "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE"
    | "VLESS_WEBSOCKET_TLS" | "TROJAN_WEBSOCKET_TLS" | "VLESS_GRPC_TLS" | "TROJAN_GRPC_TLS"
    | "VLESS_HTTP_UPGRADE_TLS" | "TROJAN_HTTP_UPGRADE_TLS" | "VLESS_XHTTP_TLS" | "TROJAN_XHTTP_TLS"
    | "VLESS_MKCP_TLS" | "TROJAN_MKCP_TLS" | "HYSTERIA2_TLS" | "WIREGUARD_UDP_NONE"
    | "HTTP_RAW_NONE" | "MIXED_RAW_NONE" | "TUNNEL_TCP_LOCAL_NONE";
  security: "REALITY" | "TLS" | "NONE";
  listenerNetworks: readonly ("TCP" | "UDP")[];
  clientFlow: "xtls-rprx-vision" | "";
  credentialType: "UUID_AND_SHORT_ID" | "UUID" | "PASSWORD" | "SHADOWSOCKS_KEY" | "HYSTERIA_AUTH" | "WIREGUARD_PEER" | "HTTP_BASIC" | "MIXED_USER_PASSWORD" | "NONE";
  specVersion: 1;
  specJson: string;
  explicit: boolean;
};

function positiveId(value: unknown, code: XrayInboundCreateErrorCode): number {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) throw new XrayInboundCreateError(code);
  return id;
}

function displayName(value: unknown): string {
  const name = String(value ?? "").trim();
  if (name.length < 1 || name.length > 128 || nameControlPattern.test(name)) {
    throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
  }
  return name;
}

function publicAddress(value: unknown): string {
  const address = String(value ?? "").trim().toLowerCase();
  if (address.length < 1 || address.length > 253 || nameControlPattern.test(address)) {
    throw new XrayInboundCreateError("PUBLIC_ADDRESS_REQUIRED");
  }
  if (net.isIP(address) || hostnamePattern.test(address)) return address;
  throw new XrayInboundCreateError("PUBLIC_ADDRESS_REQUIRED");
}

function listenPort(value: unknown): number {
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1000 || port > 65535) {
    throw new XrayInboundCreateError("PORT_OUT_OF_RANGE");
  }
  return port;
}

function spiderX(value: unknown): string {
  const normalized = String(value ?? "").trim();
  if (!normalized.startsWith("/") || normalized.length > 256 || nameControlPattern.test(normalized)) {
    throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
  }
  return normalized;
}

function normalizeCreateProfile(
  profileId: unknown,
  spec: unknown,
  dependencies: CreateXrayInboundV2Dependencies = {},
): NormalizedCreateProfile {
  if (profileId === undefined && spec === undefined) {
    return {
      id: "VLESS_RAW_REALITY_VISION",
      security: "REALITY",
      listenerNetworks: ["TCP"],
      clientFlow: "xtls-rprx-vision",
      credentialType: "UUID_AND_SHORT_ID",
      specVersion: 1,
      specJson: "{}",
      explicit: false,
    };
  }
  if (profileId === undefined || spec === undefined) throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
  const storage = profileId === "VLESS_RAW_REALITY_VISION"
    ? { protocol: "vless", transport: "tcp", security: "reality" }
    : profileId === "VLESS_GRPC_REALITY"
      ? { protocol: "vless", transport: "grpc", security: "reality" }
      : profileId === "VLESS_XHTTP_REALITY"
        ? { protocol: "vless", transport: "xhttp", security: "reality" }
      : profileId === "TROJAN_RAW_REALITY"
        ? { protocol: "trojan", transport: "tcp", security: "reality" }
      : profileId === "TROJAN_RAW_TLS"
        ? { protocol: "trojan", transport: "tcp", security: "tls" }
      : profileId === "VLESS_RAW_TLS" || profileId === "VLESS_RAW_TLS_VISION"
        ? { protocol: "vless", transport: "tcp", security: "tls" }
      : profileId === "VMESS_RAW_TLS"
        ? { protocol: "vmess", transport: "tcp", security: "tls" }
      : profileId === "SHADOWSOCKS_2022_RAW_NONE" || profileId === "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE"
        ? { protocol: "shadowsocks", transport: "tcp", security: "none" }
      : profileId === "TROJAN_WEBSOCKET_TLS"
        ? { protocol: "trojan", transport: "ws", security: "tls" }
      : profileId === "VLESS_WEBSOCKET_TLS"
        ? { protocol: "vless", transport: "ws", security: "tls" }
      : profileId === "TROJAN_GRPC_TLS"
        ? { protocol: "trojan", transport: "grpc", security: "tls" }
      : profileId === "VLESS_GRPC_TLS"
        ? { protocol: "vless", transport: "grpc", security: "tls" }
      : profileId === "TROJAN_HTTP_UPGRADE_TLS"
        ? { protocol: "trojan", transport: "httpupgrade", security: "tls" }
      : profileId === "VLESS_HTTP_UPGRADE_TLS"
        ? { protocol: "vless", transport: "httpupgrade", security: "tls" }
      : profileId === "TROJAN_XHTTP_TLS"
        ? { protocol: "trojan", transport: "xhttp", security: "tls" }
      : profileId === "VLESS_XHTTP_TLS"
        ? { protocol: "vless", transport: "xhttp", security: "tls" }
      : profileId === "TROJAN_MKCP_TLS"
        ? { protocol: "trojan", transport: "kcp", security: "tls" }
      : profileId === "VLESS_MKCP_TLS"
        ? { protocol: "vless", transport: "kcp", security: "tls" }
      : profileId === "HYSTERIA2_TLS"
        ? { protocol: "hysteria", transport: "hysteria", security: "tls" }
      : profileId === "WIREGUARD_UDP_NONE"
        ? { protocol: "wireguard", transport: "none", security: "none" }
      : profileId === "HTTP_RAW_NONE"
        ? { protocol: "http", transport: "tcp", security: "none" }
      : profileId === "MIXED_RAW_NONE"
        ? { protocol: "mixed", transport: "tcp", security: "none" }
      : profileId === "TUNNEL_TCP_LOCAL_NONE"
        ? { protocol: "tunnel", transport: "none", security: "none" }
      : null;
  if (!storage) throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
  let normalizedSpec = spec;
  if (profileId === "TUNNEL_TCP_LOCAL_NONE") {
    if (!spec || typeof spec !== "object" || Array.isArray(spec)
      || Object.keys(spec).sort().join(",") !== "targetAddress,targetPort") {
      throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
    }
    const targetAddress = normalizeXrayTunnelTargetAddress((spec as Record<string, unknown>).targetAddress);
    const targetPort = Number((spec as Record<string, unknown>).targetPort);
    if (!targetAddress || !Number.isSafeInteger(targetPort) || targetPort < 1 || targetPort > 65535) {
      throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
    }
    normalizedSpec = { targetAddress, targetPort };
  }
  let specJson: string;
  try {
    specJson = JSON.stringify(normalizedSpec);
  } catch {
    throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
  }
  const definition = resolveStoredXrayInboundDefinition({
    ...storage,
    profileId,
    specVersion: 1,
    specJson,
  });
  const isProfileEnabled = dependencies.isProfileEnabledForInternalTest
    ?? ((profile: XrayProfileSummary) => profile.status === "AVAILABLE");
  if (!definition || !isProfileEnabled(definition.profile)
    || (definition.profile.clientFlow !== "XTLS_RPRX_VISION" && definition.profile.clientFlow !== "NONE")) {
    throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
  }
  const listenerNetworks = definition.profile.listenerNetworks;
  if (listenerNetworks.length < 1 || listenerNetworks.length > 2
    || listenerNetworks.some((network) => network !== "TCP" && network !== "UDP")
    || new Set(listenerNetworks).size !== listenerNetworks.length) {
    throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
  }
  return {
    id: definition.profile.id as NormalizedCreateProfile["id"],
    security: definition.profile.security as NormalizedCreateProfile["security"],
    listenerNetworks,
    clientFlow: definition.profile.clientFlow === "XTLS_RPRX_VISION" ? "xtls-rprx-vision" : "",
    credentialType: definition.profile.clientCredentialType as NormalizedCreateProfile["credentialType"],
    specVersion: 1,
    specJson: JSON.stringify(definition.spec),
    explicit: true,
  };
}

function normalizeClients(value: CreateXrayInboundInput["initialClients"], expectedFlow: NormalizedCreateProfile["clientFlow"]) {
  if (!Array.isArray(value) || value.length < 1 || value.length > 32) {
    throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
  }
  const clients = value.map((client) => ({ name: displayName(client?.name), flow: String(client?.flow ?? "") }));
  if (clients.some((client) => client.flow !== expectedFlow)) {
    throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
  }
  const identities = clients.map((client) => client.name.toLocaleLowerCase());
  if (new Set(identities).size !== identities.length) throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
  return clients;
}

function normalizeInitialAccessEntries(
  value: CreateXrayInboundV2Input["initialAccessEntries"],
): Array<{ name: string }> {
  if (!Array.isArray(value) || value.length < 1 || value.length > 32) {
    throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
  }
  const entries = value.map((entry) => ({ name: displayName(entry?.name) }));
  const identities = entries.map((entry) => entry.name.toLocaleLowerCase());
  if (new Set(identities).size !== identities.length) throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
  return entries;
}

function tlsServerName(value: unknown): string {
  const input = String(value ?? "").trim();
  if (!input || input.includes("*") || net.isIP(input) !== 0 || /[^\x00-\x7f]/.test(input)) {
    throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
  }
  const normalized = input.toLowerCase().replace(/\.$/, "");
  if (Buffer.byteLength(normalized, "utf8") > 253 || !hostnamePattern.test(normalized)) {
    throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
  }
  return normalized;
}

async function requireTlsCertificateForCreate(input: {
  certificateId: number;
  hostId: number;
  serverName: string;
  keyring: ReturnType<typeof loadXrayMasterKeyFile>;
}) {
  try {
    const location = await getXrayTlsCertificateLocation(input.certificateId);
    if (location.hostId !== input.hostId) throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
    const material = await getXrayTlsCertificateMaterial(input.certificateId, { keyring: input.keyring });
    validateXrayTlsCertificateInput({
      certificatePem: material.certificateChainPem,
      privateKeyPem: material.privateKeyPem,
    });
    if (material.hostId !== input.hostId
      || !xrayTlsCertificateCoversServerName(material.certificateChainPem, input.serverName)) {
      throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
    }
    return material;
  } catch (error) {
    if (error instanceof XrayInboundCreateError || error instanceof XraySecretUnavailableError) throw error;
    if (error instanceof XrayTlsCertificateRepositoryError || error instanceof XrayTlsCertificateValidationError) {
      throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
    }
    throw error;
  }
}

async function requireEligibleHost(hostId: number) {
  const host = await getHostById(hostId);
  if (!host) throw new XrayInboundCreateError("HOST_NOT_FOUND");
  if (!host.isOnline) throw new XrayInboundCreateError("HOST_OFFLINE");
  const option = (await listXrayHostOptions()).find((candidate) => candidate.id === hostId);
  if (!option) throw new XrayInboundCreateError("HOST_NOT_FOUND");
  switch (option.unavailableReasonCode) {
    case null:
      return option;
    case "AGENT_OFFLINE":
    case "HEARTBEAT_STALE":
      throw new XrayInboundCreateError("HOST_OFFLINE");
    case "AGENT_UPGRADE_REQUIRED":
      throw new XrayInboundCreateError("AGENT_CAPABILITY_MISSING");
    case "PLATFORM_UNSUPPORTED":
      throw new XrayInboundCreateError("PLATFORM_UNSUPPORTED");
    case "ARTIFACT_UNAVAILABLE":
      throw new XrayInboundCreateError("ARTIFACT_UNAVAILABLE");
    case "PUBLIC_IPV4_MISSING":
      throw new XrayInboundCreateError("PUBLIC_ADDRESS_REQUIRED");
  }
}

async function requireProfileListenerCapabilities(hostId: number, profile: NormalizedCreateProfile) {
  if (!profile.listenerNetworks.includes("UDP")) return;
  const runtime = await getXrayRuntimeReport(hostId);
  if (!runtime || runtime.capabilitySchemaVersion !== 1
    || runtime.supportsUdpPortProbe !== true || runtime.supportsUdpListenerReadiness !== true) {
    throw new XrayInboundCreateError("UDP_CAPABILITY_REQUIRED");
  }
}

function mapError(error: unknown): never {
  if (error instanceof XrayInboundCreateError) throw error;
  if (error instanceof XrayExternalProxyServiceError) {
    if (error.code === "EXTERNAL_PROXY_NOT_FOUND" || error.code === "EXTERNAL_PROXY_REFERENCE_INVALID"
      || error.code === "SENSITIVE_DATA_UNAVAILABLE") {
      throw new XrayInboundCreateError(error.code);
    }
    throw new XrayInboundCreateError("EXTERNAL_PROXY_REFERENCE_INVALID");
  }
  if (error instanceof XrayPortOperationError || error instanceof XrayRealityOperationError
    || error instanceof XrayRepositoryError || error instanceof XraySecretUnavailableError) {
    throw new XrayInboundCreateError(error.code as XrayInboundCreateErrorCode);
  }
  if (error instanceof GlobalPortAllocationError) {
    if (error.code === "GLOBAL_PORT_LEGACY_CONFLICT" || error.code === "GLOBAL_PORT_SCAN_PENDING"
      || error.code === "GLOBAL_PORT_EXTERNAL_OCCUPIED") {
      throw new XrayInboundCreateError(error.code);
    }
    throw new XrayInboundCreateError("GLOBAL_PORT_CONFLICT");
  }
  throw error;
}

function databaseBoolean(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || value === "true";
}

function generation(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new XrayInboundCreateError("CONFIG_GENERATION_CONFLICT");
  return parsed;
}

async function inboundMutationRow(inboundId: number) {
  const q = quoteIdentifier;
  const rows = await queryRaw<Record<string, unknown>>(
    `SELECT ${["id", "hostId", "name", "publicAddress", "listenPort", "protocol", "transport", "security",
      "profileId", "specVersion", "specJson", "externalProxyNodeId", "isEnabled", "pendingDelete"].map(q).join(", ")}
       FROM ${q("xray_inbounds")} WHERE ${q("id")} = ? LIMIT 1`,
    [inboundId],
  );
  const row = rows[0];
  if (!row) throw new XrayInboundCreateError("INBOUND_NOT_FOUND");
  if (databaseBoolean(row.pendingDelete)) throw new XrayInboundCreateError("INBOUND_PENDING_DELETE");
  const definition = resolveStoredXrayInboundDefinition(row);
  const listenerNetworks = definition?.profile.listenerNetworks;
  if (!definition || !listenerNetworks || listenerNetworks.length < 1
    || listenerNetworks.some((network) => network !== "TCP" && network !== "UDP")
    || new Set(listenerNetworks).size !== listenerNetworks.length) {
    throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
  }
  return {
    inboundId,
    hostId: positiveId(row.hostId, "HOST_NOT_FOUND"),
    profileId: definition.profile.id,
    name: String(row.name ?? ""),
    publicAddress: String(row.publicAddress ?? ""),
    listenPort: listenPort(row.listenPort),
    isEnabled: databaseBoolean(row.isEnabled),
    externalProxyNodeId: row.externalProxyNodeId === null || row.externalProxyNodeId === undefined
      ? null
      : positiveId(row.externalProxyNodeId, "EXTERNAL_PROXY_REFERENCE_INVALID"),
    listenerNetworks,
  };
}

async function requireWritableHost(hostId: number, listenerNetworks: readonly ("TCP" | "UDP")[]) {
  const host = await getHostById(hostId);
  if (!host) throw new XrayInboundCreateError("HOST_NOT_FOUND");
  if (!host.isOnline) throw new XrayInboundCreateError("HOST_OFFLINE");
  const runtime = await getXrayRuntimeReport(hostId);
  if (!isForwardplusAgentVersionAtLeast(host.agentVersion, host.agentDistribution, AGENT_VERSION) || !runtime || runtime.capabilitySchemaVersion !== 1
    || runtime.supportedOS !== "linux" || (runtime.supportedArch !== "amd64" && runtime.supportedArch !== "arm64")
    || !runtime.supportsArtifactInstall || !runtime.supportsPortProbe || !runtime.supportsRealityScan) {
    throw new XrayInboundCreateError("AGENT_CAPABILITY_MISSING");
  }
  if (listenerNetworks.includes("UDP")
    && (!runtime.supportsUdpPortProbe || !runtime.supportsUdpListenerReadiness)) {
    throw new XrayInboundCreateError("UDP_CAPABILITY_REQUIRED");
  }
}

async function activeInboundCount(hostId: number) {
  const q = quoteIdentifier;
  const rows = await queryRaw<{ count: unknown }>(
    `SELECT COUNT(*) AS ${q("count")} FROM ${q("xray_inbounds")}
      WHERE ${q("hostId")} = ? AND ${q("pendingDelete")} = ${boolLiteral(false)}`,
    [hostId],
  );
  return Number(rows[0]?.count ?? 0);
}

export async function removeXrayInbound(input: {
  id: unknown;
  userId: unknown;
  expectedGeneration: unknown;
  confirmName: unknown;
}) {
  try {
    const inboundId = positiveId(input.id, "INBOUND_NOT_FOUND");
    const userId = positiveId(input.userId, "OPERATION_CONFLICT");
    const expectedGeneration = generation(input.expectedGeneration);
    const current = await inboundMutationRow(inboundId);
    const confirmName = String(input.confirmName ?? "");
    if (confirmName !== current.name) throw new XrayInboundCreateError("CONFIRMATION_MISMATCH");
    await assertInboundNotManagedByQuickConfig(inboundId);
    await requireWritableHost(current.hostId, current.listenerNetworks);
    let lastInbound = false;
    const removed = await updateXrayInboundConfiguration({
      id: inboundId,
      expectedGeneration,
      createdByUserId: userId,
      patch: { pendingDelete: true },
      precondition: async () => {
        const latest = await inboundMutationRow(inboundId);
        if (latest.hostId !== current.hostId) throw new XrayInboundCreateError("INBOUND_NOT_FOUND");
        if (confirmName !== latest.name) throw new XrayInboundCreateError("CONFIRMATION_MISMATCH");
        await requireWritableHost(current.hostId, latest.listenerNetworks);
        lastInbound = await activeInboundCount(current.hostId) === 1;
      },
      finalize: async () => {
        const generated = await generateXrayHostConfig(current.hostId);
        return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
      },
    });
    try {
      pushAgentRefresh(current.hostId, "xray-inbound-remove", { urgent: true });
    } catch {
      // Heartbeat fallback will deliver the committed desired state.
    }
    await recordXrayMutationObservability({
      event: "INBOUND_DELETE_REQUESTED",
      resourceType: "xray_inbound",
      resourceId: inboundId,
      hostId: current.hostId,
      action: "delete",
      before: { userId, hostId: current.hostId, inboundId, generation: expectedGeneration },
      fields: {
        userId, hostId: current.hostId, inboundId, operationId: removed.operationId,
        generation: removed.desiredGeneration, status: "QUEUED",
      },
    });
    return { ...removed, pendingDelete: true as const, mayRemainActive: true as const, lastInbound };
  } catch (error) {
    mapError(error);
  }
}

export async function updateXrayInbound(input: {
  id: unknown;
  userId: unknown;
  expectedGeneration: unknown;
  name?: unknown;
  publicAddress?: unknown;
  listenPort?: unknown;
  portReservationId?: unknown;
}) {
  try {
    const inboundId = positiveId(input.id, "INBOUND_NOT_FOUND");
    const createdByUserId = positiveId(input.userId, "OPERATION_CONFLICT");
    const expectedGeneration = generation(input.expectedGeneration);
    const current = await inboundMutationRow(inboundId);
    await requireWritableHost(current.hostId, current.listenerNetworks);
    const patch: { name?: string; publicAddress?: string; listenPort?: number } = {};
    if (input.name !== undefined) patch.name = displayName(input.name);
    if (input.publicAddress !== undefined) {
      if (current.profileId === "TUNNEL_TCP_LOCAL_NONE") throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
      patch.publicAddress = publicAddress(input.publicAddress);
    }
    if (input.listenPort !== undefined) patch.listenPort = listenPort(input.listenPort);
    if (Object.keys(patch).length === 0) throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
    if (patch.publicAddress !== undefined || patch.listenPort !== undefined) {
      await assertInboundNotManagedByQuickConfig(inboundId);
    }
    if (patch.listenPort !== undefined && current.listenerNetworks.length !== 1) {
      throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
    }

    const mutate = async () => {
      const updated = await updateXrayInboundConfiguration({
        id: inboundId,
        expectedGeneration,
        createdByUserId,
        patch,
        precondition: async () => {
          const latest = await inboundMutationRow(inboundId);
          if (latest.hostId !== current.hostId) throw new XrayInboundCreateError("INBOUND_NOT_FOUND");
          await requireWritableHost(current.hostId, latest.listenerNetworks);
        },
        finalize: async () => {
          const generated = await generateXrayHostConfig(current.hostId);
          return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
        },
      });
      try {
        pushAgentRefresh(current.hostId, "xray-inbound-update", { urgent: true });
      } catch {
        // Heartbeat fallback will deliver the committed desired state.
      }
      await recordXrayMutationObservability({
        event: "INBOUND_UPDATED",
        resourceType: "xray_inbound",
        resourceId: inboundId,
        hostId: current.hostId,
        action: "update",
        before: {
          userId: createdByUserId,
          hostId: current.hostId,
          inboundId,
          generation: expectedGeneration,
          name: current.name,
          publicAddress: current.publicAddress,
          port: current.listenPort,
        },
        fields: {
          userId: createdByUserId,
          hostId: current.hostId,
          inboundId,
          operationId: updated.operationId,
          generation: updated.desiredGeneration,
          name: patch.name ?? current.name,
          publicAddress: patch.publicAddress ?? current.publicAddress,
          port: patch.listenPort ?? current.listenPort,
          status: "QUEUED",
        },
      });
      return updated;
    };

    if (patch.listenPort === undefined) {
      if (input.portReservationId !== undefined) throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
      return await mutate();
    }
    if (input.portReservationId === undefined) throw new XrayInboundCreateError("PORT_RESERVATION_EXPIRED");
    return await withConsumedXrayPortReservation({
      reservationId: input.portReservationId,
      hostId: current.hostId,
      userId: createdByUserId,
      port: patch.listenPort,
      network: current.listenerNetworks[0].toLowerCase(),
    }, mutate);
  } catch (error) {
    mapError(error);
  }
}

export async function setXrayInboundEnabled(input: {
  id: unknown;
  userId: unknown;
  expectedGeneration: unknown;
  isEnabled: unknown;
}) {
  try {
    const inboundId = positiveId(input.id, "INBOUND_NOT_FOUND");
    const createdByUserId = positiveId(input.userId, "OPERATION_CONFLICT");
    const expectedGeneration = generation(input.expectedGeneration);
    if (typeof input.isEnabled !== "boolean") throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
    const current = await inboundMutationRow(inboundId);
    if (!input.isEnabled) await assertInboundNotManagedByQuickConfig(inboundId);
    await requireWritableHost(current.hostId, current.listenerNetworks);
    const updated = await updateXrayInboundConfiguration({
      id: inboundId,
      expectedGeneration,
      createdByUserId,
      patch: { isEnabled: input.isEnabled },
      precondition: async () => {
        const latest = await inboundMutationRow(inboundId);
        if (latest.hostId !== current.hostId) throw new XrayInboundCreateError("INBOUND_NOT_FOUND");
        await requireWritableHost(current.hostId, latest.listenerNetworks);
      },
      finalize: async () => {
        const generated = await generateXrayHostConfig(current.hostId);
        return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
      },
    });
    try {
      pushAgentRefresh(current.hostId, "xray-inbound-set-enabled", { urgent: true });
    } catch {
      // Heartbeat fallback will deliver the committed desired state.
    }
    await recordXrayMutationObservability({
      event: input.isEnabled ? "INBOUND_ENABLED" : "INBOUND_DISABLED",
      resourceType: "xray_inbound",
      resourceId: inboundId,
      hostId: current.hostId,
      action: "update",
      before: {
        userId: createdByUserId,
        hostId: current.hostId,
        inboundId,
        generation: expectedGeneration,
        isEnabled: current.isEnabled,
      },
      fields: {
        userId: createdByUserId,
        hostId: current.hostId,
        inboundId,
        operationId: updated.operationId,
        generation: updated.desiredGeneration,
        isEnabled: input.isEnabled,
        status: "QUEUED",
      },
    });
    return updated;
  } catch (error) {
    mapError(error);
  }
}

export async function setXrayInboundExternalProxy(input: {
  inboundId: unknown;
  externalProxyNodeId: unknown;
  userId: unknown;
  expectedGeneration: unknown;
}) {
  try {
    const inboundId = positiveId(input.inboundId, "INBOUND_NOT_FOUND");
    const createdByUserId = positiveId(input.userId, "OPERATION_CONFLICT");
    const expectedGeneration = generation(input.expectedGeneration);
    const externalProxyNodeId = input.externalProxyNodeId === null
      ? null
      : positiveId(input.externalProxyNodeId, "EXTERNAL_PROXY_NOT_FOUND");
    const current = await inboundMutationRow(inboundId);
    if (current.profileId === "TUNNEL_TCP_LOCAL_NONE"
      || current.listenerNetworks.length !== 1 || current.listenerNetworks[0] !== "TCP") {
      throw new XrayInboundCreateError("EXTERNAL_PROXY_UNSUPPORTED");
    }
    if (current.externalProxyNodeId === externalProxyNodeId) {
      throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
    }
    await requireWritableHost(current.hostId, current.listenerNetworks);
    const keyring = externalProxyNodeId === null ? undefined : loadXrayMasterKeyFile();
    if (externalProxyNodeId !== null) {
      await loadXrayExternalProxyMaterial(externalProxyNodeId, { keyring });
    }
    const updated = await updateXrayInboundConfiguration({
      id: inboundId,
      expectedGeneration,
      createdByUserId,
      patch: { externalProxyNodeId },
      precondition: async () => {
        const latest = await inboundMutationRow(inboundId);
        if (latest.hostId !== current.hostId) throw new XrayInboundCreateError("INBOUND_NOT_FOUND");
        if (latest.profileId === "TUNNEL_TCP_LOCAL_NONE"
          || latest.listenerNetworks.length !== 1 || latest.listenerNetworks[0] !== "TCP") {
          throw new XrayInboundCreateError("EXTERNAL_PROXY_UNSUPPORTED");
        }
        await requireWritableHost(current.hostId, latest.listenerNetworks);
        if (externalProxyNodeId !== null) {
          await loadXrayExternalProxyMaterial(externalProxyNodeId, { keyring });
        }
      },
      finalize: async () => {
        const generated = await generateXrayHostConfig(current.hostId, keyring);
        return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
      },
    });
    try {
      pushAgentRefresh(current.hostId, "xray-inbound-external-proxy", { urgent: true });
    } catch {
      // Heartbeat fallback will deliver the committed desired state.
    }
    await recordXrayMutationObservability({
      event: "INBOUND_EXTERNAL_PROXY_UPDATED",
      resourceType: "xray_inbound",
      resourceId: inboundId,
      hostId: current.hostId,
      action: "update",
      before: {
        userId: createdByUserId,
        hostId: current.hostId,
        inboundId,
        generation: expectedGeneration,
        externalProxyNodeId: current.externalProxyNodeId,
      },
      fields: {
        userId: createdByUserId,
        hostId: current.hostId,
        inboundId,
        operationId: updated.operationId,
        generation: updated.desiredGeneration,
        externalProxyNodeId,
        status: "QUEUED",
      },
    });
    return { ...updated, externalProxyNodeId };
  } catch (error) {
    mapError(error);
  }
}

export async function createXrayInbound(input: CreateXrayInboundInput): Promise<{
  inboundId: number;
  operationId: string;
  desiredGeneration: number;
}> {
  try {
    const hostId = positiveId(input.hostId, "HOST_NOT_FOUND");
    const userId = positiveId(input.userId, "OPERATION_CONFLICT");
    const name = displayName(input.name);
    const endpoint = publicAddress(input.publicAddress);
    const port = listenPort(input.listenPort);
    const profile = normalizeCreateProfile(input.profileId, input.spec);
    if (!input.reality || input.reality.fingerprint !== "chrome") throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
    const normalizedSpiderX = spiderX(input.reality.spiderX);
    const clients = normalizeClients(input.initialClients, profile.clientFlow);

    await requireEligibleHost(hostId);
    const reality = await validateXrayRealityDestinationForCreate({
      hostId,
      userId,
      targetHost: input.reality.targetHost,
      targetPort: input.reality.targetPort,
      serverName: input.reality.serverName,
    });
    const keyring = loadXrayMasterKeyFile();
    if (profile.credentialType === "UUID_AND_SHORT_ID") await repairXrayClientFingerprints({ keyring });
    const keyVersion = Number(keyring.currentKeyId);
    if (!Number.isSafeInteger(keyVersion) || keyVersion <= 0) throw new XrayInboundCreateError("SENSITIVE_DATA_UNAVAILABLE");
    const deployment = await getXrayHostDeployment(hostId);
    const expectedGeneration = deployment?.desiredGeneration ?? 0;
    const runtimeTag = `forwardx-inbound-${crypto.randomUUID()}`;
    const realityKeyPair = crypto.generateKeyPairSync("x25519");
    const privateJwk = realityKeyPair.privateKey.export({ format: "jwk" });
    const publicJwk = realityKeyPair.publicKey.export({ format: "jwk" });
    const realityPrivateKey = String(privateJwk.d ?? "");
    const realityPublicKey = String(publicJwk.x ?? "");
    if (!/^[A-Za-z0-9_-]{43}$/.test(realityPrivateKey) || !/^[A-Za-z0-9_-]{43}$/.test(realityPublicKey)) {
      throw new XrayInboundCreateError("SENSITIVE_DATA_UNAVAILABLE");
    }
    const clientRecords: NewXrayClientRecord[] = profile.credentialType === "UUID_AND_SHORT_ID" ? clients.map((client, index) => {
      const statsKey = `forwardx-client-${crypto.randomUUID()}`;
      const uuid = crypto.randomUUID();
      const shortId = crypto.randomBytes(8).toString("hex");
      return {
        name: client.name,
        uuidEncrypted: encryptXraySecret(uuid, xrayClientUuidContext(statsKey), keyring),
        uuidFingerprint: fingerprintXraySecret(uuid, xrayClientUuidContext(statsKey), keyring),
        shortIdEncrypted: encryptXraySecret(shortId, xrayClientShortIdContext(statsKey), keyring),
        shortIdFingerprint: fingerprintXraySecret(shortId, xrayClientShortIdContext(statsKey), keyring),
        statsKey,
        flow: profile.clientFlow,
        isEnabled: true,
        sortOrder: index,
      };
    }) : [];
    const genericAccessEntries: NewXrayGenericAccessRecord[] = profile.credentialType === "PASSWORD" ? clients.map((client, index) => {
      const statsKey = `forwardx-access-${crypto.randomUUID()}`;
      const password = crypto.randomBytes(32).toString("base64url");
      const shortId = crypto.randomBytes(8).toString("hex");
      return {
        name: client.name,
        credentialType: "PASSWORD",
        settingsJson: '{"schemaVersion":1}',
        statsKey,
        isEnabled: true,
        sortOrder: index,
        secrets: [{
          kind: "PASSWORD",
          encryptedValue: encryptXraySecret(password, xrayAccessSecretContext(statsKey, "PASSWORD"), keyring),
          fingerprint: fingerprintXraySecret(password, xrayAccessSecretContext(statsKey, "PASSWORD"), keyring),
        }, {
          kind: "SHORT_ID",
          encryptedValue: encryptXraySecret(shortId, xrayAccessSecretContext(statsKey, "SHORT_ID"), keyring),
          fingerprint: fingerprintXraySecret(shortId, xrayAccessSecretContext(statsKey, "SHORT_ID"), keyring),
        }],
      };
    }) : [];

    return await withConsumedXrayPortReservation({
      reservationId: input.portReservationId,
      hostId,
      userId,
      port,
    }, async () => {
      const created = await createXrayInboundConfiguration({
        hostId,
        expectedGeneration,
        createdByUserId: userId,
        inbound: {
          ...(profile.explicit ? { profile: { id: profile.id, specVersion: profile.specVersion, specJson: profile.specJson } } : {}),
          name,
          runtimeTag,
          publicAddress: endpoint,
          listenAddress: "0.0.0.0",
          listenPort: port,
          realityTargetHost: reality.targetHost,
          realityTargetPort: reality.targetPort,
          realityServerName: reality.serverName,
          realityPublicKey,
          realityPrivateKeyEncrypted: encryptXraySecret(
            realityPrivateKey,
            xrayInboundPrivateKeyContext(runtimeTag),
            keyring,
          ),
          realityPrivateKeyFingerprint: fingerprintXraySecret(
            realityPrivateKey,
            xrayInboundPrivateKeyContext(runtimeTag),
            keyring,
          ),
          secretKeyVersion: keyVersion,
          fingerprint: "chrome",
          spiderX: normalizedSpiderX,
          isEnabled: true,
        },
        ...(profile.credentialType === "UUID_AND_SHORT_ID"
          ? { clients: clientRecords }
          : { genericAccessEntries }),
        precondition: async () => {
          await requireEligibleHost(hostId);
          await validateXrayRealityDestinationForCreate({
            hostId,
            userId,
            targetHost: reality.targetHost,
            targetPort: reality.targetPort,
            serverName: reality.serverName,
          });
        },
        finalize: async () => {
          const generated = await generateXrayHostConfig(hostId, keyring);
          return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
        },
      });
      try {
        pushAgentRefresh(hostId, "xray-inbound-create", { urgent: true });
      } catch {
        // The committed desired state is durable and heartbeat fallback will
        // deliver it even if the best-effort SSE wake cannot be emitted.
      }
      await recordXrayMutationObservability({
        event: "INBOUND_CREATED",
        resourceType: "xray_inbound",
        resourceId: created.inboundId,
        hostId,
        action: "create",
        fields: {
          userId, hostId, inboundId: created.inboundId, operationId: created.operationId,
          generation: created.desiredGeneration, runtimeTag, port, status: "QUEUED",
        },
      });
      return {
        inboundId: created.inboundId,
        operationId: created.operationId,
        desiredGeneration: created.desiredGeneration,
      };
    });
  } catch (error) {
    mapError(error);
  }
}

async function createXrayTlsInbound(
  input: CreateXrayInboundV2Input,
  profile: NormalizedCreateProfile,
): Promise<{ inboundId: number; operationId: string; desiredGeneration: number }> {
  try {
    if (profile.security !== "TLS"
      || (profile.credentialType !== "UUID" && profile.credentialType !== "PASSWORD"
        && profile.credentialType !== "HYSTERIA_AUTH")
      || input.reality !== undefined || input.tlsCertificateId === undefined || input.serverName === undefined
      || input.portReservations !== undefined) {
      throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
    }
    const hostId = positiveId(input.hostId, "HOST_NOT_FOUND");
    const userId = positiveId(input.userId, "OPERATION_CONFLICT");
    const name = displayName(input.name);
    const endpoint = publicAddress(input.publicAddress);
    const port = listenPort(input.listenPort);
    const certificateId = positiveId(input.tlsCertificateId, "INVALID_CONFIG_INPUT");
    const serverName = tlsServerName(input.serverName);
    const entries = normalizeInitialAccessEntries(input.initialAccessEntries);

    await requireEligibleHost(hostId);
    await requireProfileListenerCapabilities(hostId, profile);
    const keyring = loadXrayMasterKeyFile();
    await requireTlsCertificateForCreate({ certificateId, hostId, serverName, keyring });
    const keyVersion = Number(keyring.currentKeyId);
    if (!Number.isSafeInteger(keyVersion) || keyVersion <= 0) {
      throw new XrayInboundCreateError("SENSITIVE_DATA_UNAVAILABLE");
    }
    const deployment = await getXrayHostDeployment(hostId);
    const expectedGeneration = deployment?.desiredGeneration ?? 0;
    const runtimeTag = `forwardx-inbound-${crypto.randomUUID()}`;
    const flow = profile.clientFlow === "xtls-rprx-vision" ? "XTLS_RPRX_VISION" : "NONE";
    const genericAccessEntries: NewXrayGenericAccessRecord[] = entries.map((entry, index) => {
      const statsKey = `forwardx-access-${crypto.randomUUID()}`;
      if (profile.credentialType === "HYSTERIA_AUTH") {
        const auth = crypto.randomBytes(32).toString("base64url");
        const context = xrayAccessSecretContext(statsKey, "HYSTERIA_AUTH");
        return {
          name: entry.name,
          credentialType: "HYSTERIA_AUTH",
          settingsJson: '{"schemaVersion":1}',
          statsKey,
          isEnabled: true,
          sortOrder: index,
          secrets: [{
            kind: "HYSTERIA_AUTH",
            encryptedValue: encryptXraySecret(auth, context, keyring),
            fingerprint: fingerprintXraySecret(auth, context, keyring),
          }],
        };
      }
      if (profile.credentialType === "PASSWORD") {
        const password = crypto.randomBytes(32).toString("base64url");
        const context = xrayAccessSecretContext(statsKey, "PASSWORD");
        return {
          name: entry.name,
          credentialType: "PASSWORD",
          settingsJson: '{"schemaVersion":1}',
          statsKey,
          isEnabled: true,
          sortOrder: index,
          secrets: [{
            kind: "PASSWORD",
            encryptedValue: encryptXraySecret(password, context, keyring),
            fingerprint: fingerprintXraySecret(password, context, keyring),
          }],
        };
      }
      const uuid = crypto.randomUUID();
      const context = xrayAccessSecretContext(statsKey, "UUID");
      return {
        name: entry.name,
        credentialType: "UUID",
        settingsJson: JSON.stringify(profile.id === "VMESS_RAW_TLS"
          ? { schemaVersion: 1, flow: "NONE", security: "AUTO" }
          : { schemaVersion: 2, protocol: "VLESS", encryption: "NONE", flow }),
        statsKey,
        isEnabled: true,
        sortOrder: index,
        secrets: [{
          kind: "UUID",
          encryptedValue: encryptXraySecret(uuid, context, keyring),
          fingerprint: fingerprintXraySecret(uuid, context, keyring),
        }],
      };
    });

    const listenerNetwork = profile.listenerNetworks.length === 1 ? profile.listenerNetworks[0] : null;
    if (!listenerNetwork) throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
    return await withConsumedXrayPortReservation({
      reservationId: input.portReservationId,
      hostId,
      userId,
      port,
      network: listenerNetwork,
    }, async () => {
      const created = await createXrayInboundConfiguration({
        hostId,
        expectedGeneration,
        createdByUserId: userId,
        inbound: {
          profile: { id: profile.id, specVersion: profile.specVersion, specJson: profile.specJson },
          name,
          runtimeTag,
          publicAddress: endpoint,
          listenAddress: "0.0.0.0",
          listenPort: port,
          tlsCertificateId: certificateId,
          realityTargetHost: "",
          realityTargetPort: 443,
          realityServerName: serverName,
          realityPublicKey: "",
          realityPrivateKeyEncrypted: "",
          secretKeyVersion: keyVersion,
          fingerprint: "chrome",
          spiderX: "/",
          isEnabled: true,
        },
        genericAccessEntries,
        precondition: async () => {
          await requireEligibleHost(hostId);
          await requireProfileListenerCapabilities(hostId, profile);
          await requireTlsCertificateForCreate({ certificateId, hostId, serverName, keyring });
        },
        finalize: async () => {
          const generated = await generateXrayHostConfig(hostId, keyring);
          return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
        },
      });
      try {
        pushAgentRefresh(hostId, "xray-inbound-create", { urgent: true });
      } catch {
        // The committed desired state remains available through heartbeat fallback.
      }
      await recordXrayMutationObservability({
        event: "INBOUND_CREATED",
        resourceType: "xray_inbound",
        resourceId: created.inboundId,
        hostId,
        action: "create",
        fields: {
          userId, hostId, inboundId: created.inboundId, operationId: created.operationId,
          generation: created.desiredGeneration, runtimeTag, port, status: "QUEUED",
        },
      });
      return {
        inboundId: created.inboundId,
        operationId: created.operationId,
        desiredGeneration: created.desiredGeneration,
      };
    });
  } catch (error) {
    mapError(error);
  }
}

async function createXrayUserPasswordProxyInbound(
  input: CreateXrayInboundV2Input,
  profile: NormalizedCreateProfile,
): Promise<{ inboundId: number; operationId: string; desiredGeneration: number }> {
  try {
    const isHttp = profile.id === "HTTP_RAW_NONE" && profile.credentialType === "HTTP_BASIC";
    const isMixed = profile.id === "MIXED_RAW_NONE" && profile.credentialType === "MIXED_USER_PASSWORD";
    if ((!isHttp && !isMixed) || profile.security !== "NONE" || input.reality !== undefined
      || input.tlsCertificateId !== undefined || input.serverName !== undefined
      || input.portReservations !== undefined) {
      throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
    }
    if (input.portReservationId === undefined) throw new XrayInboundCreateError("PORT_RESERVATION_EXPIRED");
    const hostId = positiveId(input.hostId, "HOST_NOT_FOUND");
    const userId = positiveId(input.userId, "OPERATION_CONFLICT");
    const name = displayName(input.name);
    const endpoint = publicAddress(input.publicAddress);
    const port = listenPort(input.listenPort);
    const entries = normalizeInitialAccessEntries(input.initialAccessEntries);

    await requireEligibleHost(hostId);
    await requireProfileListenerCapabilities(hostId, profile);
    const keyring = loadXrayMasterKeyFile();
    const keyVersion = Number(keyring.currentKeyId);
    if (!Number.isSafeInteger(keyVersion) || keyVersion <= 0) {
      throw new XrayInboundCreateError("SENSITIVE_DATA_UNAVAILABLE");
    }
    const deployment = await getXrayHostDeployment(hostId);
    const expectedGeneration = deployment?.desiredGeneration ?? 0;
    const runtimeTag = `forwardx-inbound-${crypto.randomUUID()}`;
    const credentialType = isHttp ? "HTTP_BASIC" as const : "MIXED_USER_PASSWORD" as const;
    const usernames = new Set<string>();
    const passwords = new Set<string>();
    const generateUniqueToken = (bytes: number, allocated: Set<string>) => {
      let token: string;
      do token = crypto.randomBytes(bytes).toString("base64url"); while (allocated.has(token));
      allocated.add(token);
      return token;
    };
    const genericAccessEntries: NewXrayGenericAccessRecord[] = entries.map((entry, index) => {
      const statsKey = `forwardx-access-${crypto.randomUUID()}`;
      const username = generateUniqueToken(16, usernames);
      const password = generateUniqueToken(32, passwords);
      const usernameContext = xrayAccessSecretContext(statsKey, "USERNAME");
      const passwordContext = xrayAccessSecretContext(statsKey, "PASSWORD");
      return {
        name: entry.name,
        credentialType,
        settingsJson: '{"schemaVersion":1}',
        statsKey,
        isEnabled: true,
        sortOrder: index,
        secrets: [{
          kind: "USERNAME",
          encryptedValue: encryptXraySecret(username, usernameContext, keyring),
          fingerprint: fingerprintXraySecret(username, usernameContext, keyring),
        }, {
          kind: "PASSWORD",
          encryptedValue: encryptXraySecret(password, passwordContext, keyring),
          fingerprint: fingerprintXraySecret(password, passwordContext, keyring),
        }],
      };
    });

    return await withConsumedXrayPortReservation({
      reservationId: input.portReservationId,
      hostId,
      userId,
      port,
      network: "tcp",
    }, async () => {
      const created = await createXrayInboundConfiguration({
        hostId,
        expectedGeneration,
        createdByUserId: userId,
        inbound: {
          profile: { id: profile.id, specVersion: profile.specVersion, specJson: profile.specJson },
          name,
          runtimeTag,
          publicAddress: endpoint,
          listenAddress: "0.0.0.0",
          listenPort: port,
          tlsCertificateId: null,
          realityTargetHost: "",
          realityTargetPort: 443,
          realityServerName: "",
          realityPublicKey: "",
          realityPrivateKeyEncrypted: "",
          secretKeyVersion: keyVersion,
          fingerprint: "chrome",
          spiderX: "/",
          isEnabled: true,
        },
        genericAccessEntries,
        precondition: async () => {
          await requireEligibleHost(hostId);
          await requireProfileListenerCapabilities(hostId, profile);
        },
        finalize: async () => {
          const generated = await generateXrayHostConfig(hostId, keyring);
          return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
        },
      });
      try {
        pushAgentRefresh(hostId, "xray-inbound-create", { urgent: true });
      } catch {
        // The committed desired state remains available through heartbeat fallback.
      }
      await recordXrayMutationObservability({
        event: "INBOUND_CREATED",
        resourceType: "xray_inbound",
        resourceId: created.inboundId,
        hostId,
        action: "create",
        fields: {
          userId, hostId, inboundId: created.inboundId, operationId: created.operationId,
          generation: created.desiredGeneration, runtimeTag, port, status: "QUEUED",
        },
      });
      return {
        inboundId: created.inboundId,
        operationId: created.operationId,
        desiredGeneration: created.desiredGeneration,
      };
    });
  } catch (error) {
    mapError(error);
  }
}

async function createXrayTunnelInbound(
  input: CreateXrayInboundV2Input,
  profile: NormalizedCreateProfile,
): Promise<{ inboundId: number; operationId: string; desiredGeneration: number }> {
  try {
    if (profile.id !== "TUNNEL_TCP_LOCAL_NONE" || profile.security !== "NONE"
      || profile.credentialType !== "NONE" || input.publicAddress !== undefined
      || input.reality !== undefined || input.tlsCertificateId !== undefined
      || input.serverName !== undefined || input.portReservations !== undefined
      || !Array.isArray(input.initialAccessEntries) || input.initialAccessEntries.length !== 0) {
      throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
    }
    if (input.portReservationId === undefined) throw new XrayInboundCreateError("PORT_RESERVATION_EXPIRED");
    const hostId = positiveId(input.hostId, "HOST_NOT_FOUND");
    const userId = positiveId(input.userId, "OPERATION_CONFLICT");
    const name = displayName(input.name);
    const port = listenPort(input.listenPort);

    await requireEligibleHost(hostId);
    await requireProfileListenerCapabilities(hostId, profile);
    const deployment = await getXrayHostDeployment(hostId);
    const expectedGeneration = deployment?.desiredGeneration ?? 0;
    const runtimeTag = `forwardx-inbound-${crypto.randomUUID()}`;

    return await withConsumedXrayPortReservation({
      reservationId: input.portReservationId,
      hostId,
      userId,
      port,
      network: "tcp",
    }, async () => {
      const created = await createXrayInboundConfiguration({
        hostId,
        expectedGeneration,
        createdByUserId: userId,
        inbound: {
          profile: { id: profile.id, specVersion: profile.specVersion, specJson: profile.specJson },
          name,
          runtimeTag,
          publicAddress: "127.0.0.1",
          listenAddress: "127.0.0.1",
          listenPort: port,
          tlsCertificateId: null,
          realityTargetHost: "",
          realityTargetPort: 443,
          realityServerName: "",
          realityPublicKey: "",
          realityPrivateKeyEncrypted: "",
          secretKeyVersion: 1,
          fingerprint: "chrome",
          spiderX: "/",
          isEnabled: true,
        },
        precondition: async () => {
          await requireEligibleHost(hostId);
          await requireProfileListenerCapabilities(hostId, profile);
        },
        finalize: async () => {
          const generated = await generateXrayHostConfig(hostId);
          return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
        },
      });
      try {
        pushAgentRefresh(hostId, "xray-inbound-create", { urgent: true });
      } catch {
        // The committed desired state remains available through heartbeat fallback.
      }
      await recordXrayMutationObservability({
        event: "INBOUND_CREATED",
        resourceType: "xray_inbound",
        resourceId: created.inboundId,
        hostId,
        action: "create",
        fields: {
          userId, hostId, inboundId: created.inboundId, operationId: created.operationId,
          generation: created.desiredGeneration, runtimeTag, port, status: "QUEUED",
        },
      });
      return {
        inboundId: created.inboundId,
        operationId: created.operationId,
        desiredGeneration: created.desiredGeneration,
      };
    });
  } catch (error) {
    mapError(error);
  }
}

async function createXrayWireGuardInbound(
  input: CreateXrayInboundV2Input,
  profile: NormalizedCreateProfile,
): Promise<{ inboundId: number; operationId: string; desiredGeneration: number }> {
  try {
    if (profile.id !== "WIREGUARD_UDP_NONE" || profile.security !== "NONE"
      || profile.credentialType !== "WIREGUARD_PEER" || input.reality !== undefined
      || input.tlsCertificateId !== undefined || input.serverName !== undefined
      || input.portReservations !== undefined) {
      throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
    }
    if (input.portReservationId === undefined) throw new XrayInboundCreateError("PORT_RESERVATION_EXPIRED");
    const hostId = positiveId(input.hostId, "HOST_NOT_FOUND");
    const userId = positiveId(input.userId, "OPERATION_CONFLICT");
    const name = displayName(input.name);
    const endpoint = publicAddress(input.publicAddress);
    const port = listenPort(input.listenPort);
    const entries = normalizeInitialAccessEntries(input.initialAccessEntries);

    await requireEligibleHost(hostId);
    await requireProfileListenerCapabilities(hostId, profile);
    const keyring = loadXrayMasterKeyFile();
    const keyVersion = Number(keyring.currentKeyId);
    if (!Number.isSafeInteger(keyVersion) || keyVersion <= 0) {
      throw new XrayInboundCreateError("SENSITIVE_DATA_UNAVAILABLE");
    }
    const deployment = await getXrayHostDeployment(hostId);
    const expectedGeneration = deployment?.desiredGeneration ?? 0;
    const runtimeTag = `forwardx-inbound-${crypto.randomUUID()}`;
    const allocatedPrivateKeys = new Set<string>();
    const allocatedPreSharedKeys = new Set<string>();
    const allocateKeyPair = () => {
      let keyPair: ReturnType<typeof generateXrayWireGuardKeyPair>;
      do keyPair = generateXrayWireGuardKeyPair(); while (allocatedPrivateKeys.has(keyPair.privateKey));
      allocatedPrivateKeys.add(keyPair.privateKey);
      return keyPair;
    };
    const allocatePreSharedKey = () => {
      let key: string;
      do key = generateXrayWireGuardPreSharedKey(); while (allocatedPreSharedKeys.has(key));
      allocatedPreSharedKeys.add(key);
      return key;
    };
    const serverPrivateKey = allocateKeyPair().privateKey;
    const serverContext = xrayInboundSecretContext(runtimeTag, "PRIVATE_KEY");
    const genericAccessEntries: NewXrayGenericAccessRecord[] = entries.map((entry, index) => {
      const statsKey = `forwardx-access-${crypto.randomUUID()}`;
      const privateKey = allocateKeyPair().privateKey;
      const preSharedKey = allocatePreSharedKey();
      const privateKeyContext = xrayAccessSecretContext(statsKey, "PRIVATE_KEY");
      const preSharedKeyContext = xrayAccessSecretContext(statsKey, "PRE_SHARED_KEY");
      return {
        name: entry.name,
        credentialType: "WIREGUARD_PEER",
        settingsJson: JSON.stringify({ schemaVersion: 2, address: `10.0.0.${index + 2}/32` }),
        statsKey,
        isEnabled: true,
        sortOrder: index,
        secrets: [{
          kind: "PRIVATE_KEY",
          encryptedValue: encryptXraySecret(privateKey, privateKeyContext, keyring),
          fingerprint: fingerprintXraySecret(privateKey, privateKeyContext, keyring),
        }, {
          kind: "PRE_SHARED_KEY",
          encryptedValue: encryptXraySecret(preSharedKey, preSharedKeyContext, keyring),
          fingerprint: fingerprintXraySecret(preSharedKey, preSharedKeyContext, keyring),
        }],
      };
    });

    return await withConsumedXrayPortReservation({
      reservationId: input.portReservationId,
      hostId,
      userId,
      port,
      network: "udp",
    }, async () => {
      const created = await createXrayInboundConfiguration({
        hostId,
        expectedGeneration,
        createdByUserId: userId,
        inbound: {
          profile: { id: profile.id, specVersion: profile.specVersion, specJson: profile.specJson },
          name,
          runtimeTag,
          publicAddress: endpoint,
          listenAddress: "0.0.0.0",
          listenPort: port,
          tlsCertificateId: null,
          realityTargetHost: "",
          realityTargetPort: 443,
          realityServerName: "",
          realityPublicKey: "",
          realityPrivateKeyEncrypted: "",
          secretKeyVersion: keyVersion,
          fingerprint: "chrome",
          spiderX: "/",
          isEnabled: true,
        },
        inboundSecrets: [{
          kind: "PRIVATE_KEY",
          encryptedValue: encryptXraySecret(serverPrivateKey, serverContext, keyring),
          fingerprint: fingerprintXraySecret(serverPrivateKey, serverContext, keyring),
        }],
        genericAccessEntries,
        precondition: async () => {
          await requireEligibleHost(hostId);
          await requireProfileListenerCapabilities(hostId, profile);
        },
        finalize: async () => {
          const generated = await generateXrayHostConfig(hostId, keyring);
          return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
        },
      });
      try {
        pushAgentRefresh(hostId, "xray-inbound-create", { urgent: true });
      } catch {
        // The committed desired state remains available through heartbeat fallback.
      }
      await recordXrayMutationObservability({
        event: "INBOUND_CREATED",
        resourceType: "xray_inbound",
        resourceId: created.inboundId,
        hostId,
        action: "create",
        fields: {
          userId, hostId, inboundId: created.inboundId, operationId: created.operationId,
          generation: created.desiredGeneration, runtimeTag, port, status: "QUEUED",
        },
      });
      return {
        inboundId: created.inboundId,
        operationId: created.operationId,
        desiredGeneration: created.desiredGeneration,
      };
    });
  } catch (error) {
    mapError(error);
  }
}

async function createXrayShadowsocksInbound(
  input: CreateXrayInboundV2Input,
  profile: NormalizedCreateProfile,
): Promise<{ inboundId: number; operationId: string; desiredGeneration: number }> {
  try {
    if ((profile.id !== "SHADOWSOCKS_2022_RAW_NONE"
        && profile.id !== "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE")
      || profile.security !== "NONE"
      || profile.credentialType !== "SHADOWSOCKS_KEY" || input.reality !== undefined
      || input.tlsCertificateId !== undefined || input.serverName !== undefined) {
      throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
    }
    const hostId = positiveId(input.hostId, "HOST_NOT_FOUND");
    const userId = positiveId(input.userId, "OPERATION_CONFLICT");
    const name = displayName(input.name);
    const endpoint = publicAddress(input.publicAddress);
    const port = listenPort(input.listenPort);
    const entries = normalizeInitialAccessEntries(input.initialAccessEntries);
    const isDualNetwork = profile.id === "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE";
    let dualReservations: { tcp: string; udp: string } | null = null;
    if (isDualNetwork) {
      const value = input.portReservations;
      if (input.portReservationId !== undefined || !value || typeof value !== "object" || Array.isArray(value)
        || Object.keys(value).sort().join(",") !== "tcp,udp"
        || typeof value.tcp !== "string" || !/^[A-Za-z0-9._:-]{1,64}$/.test(value.tcp)
        || typeof value.udp !== "string" || !/^[A-Za-z0-9._:-]{1,64}$/.test(value.udp)) {
        throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
      }
      dualReservations = { tcp: value.tcp, udp: value.udp };
    } else if (input.portReservations !== undefined) {
      throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
    }

    await requireEligibleHost(hostId);
    await requireProfileListenerCapabilities(hostId, profile);
    const keyring = loadXrayMasterKeyFile();
    const keyVersion = Number(keyring.currentKeyId);
    if (!Number.isSafeInteger(keyVersion) || keyVersion <= 0) {
      throw new XrayInboundCreateError("SENSITIVE_DATA_UNAVAILABLE");
    }
    const deployment = await getXrayHostDeployment(hostId);
    const expectedGeneration = deployment?.desiredGeneration ?? 0;
    const runtimeTag = `forwardx-inbound-${crypto.randomUUID()}`;
    const allocatedKeys = new Set<string>();
    const allocateKey = () => {
      let key: string;
      do key = crypto.randomBytes(32).toString("base64"); while (allocatedKeys.has(key));
      allocatedKeys.add(key);
      return key;
    };
    const serverKey = allocateKey();
    const serverContext = xrayInboundSecretContext(runtimeTag, "SHADOWSOCKS_SERVER_KEY");
    const genericAccessEntries: NewXrayGenericAccessRecord[] = entries.map((entry, index) => {
      const statsKey = `forwardx-access-${crypto.randomUUID()}`;
      const userKey = allocateKey();
      const context = xrayAccessSecretContext(statsKey, "SHADOWSOCKS_KEY");
      return {
        name: entry.name,
        credentialType: "SHADOWSOCKS_KEY",
        settingsJson: '{"schemaVersion":1}',
        statsKey,
        isEnabled: true,
        sortOrder: index,
        secrets: [{
          kind: "SHADOWSOCKS_KEY",
          encryptedValue: encryptXraySecret(userKey, context, keyring),
          fingerprint: fingerprintXraySecret(userKey, context, keyring),
        }],
      };
    });

    const create = async () => {
      const created = await createXrayInboundConfiguration({
        hostId,
        expectedGeneration,
        createdByUserId: userId,
        inbound: {
          profile: { id: profile.id, specVersion: profile.specVersion, specJson: profile.specJson },
          name,
          runtimeTag,
          publicAddress: endpoint,
          listenAddress: "0.0.0.0",
          listenPort: port,
          tlsCertificateId: null,
          realityTargetHost: "",
          realityTargetPort: 443,
          realityServerName: "",
          realityPublicKey: "",
          realityPrivateKeyEncrypted: "",
          secretKeyVersion: keyVersion,
          fingerprint: "chrome",
          spiderX: "/",
          isEnabled: true,
        },
        inboundSecrets: [{
          kind: "SHADOWSOCKS_SERVER_KEY",
          encryptedValue: encryptXraySecret(serverKey, serverContext, keyring),
          fingerprint: fingerprintXraySecret(serverKey, serverContext, keyring),
        }],
        genericAccessEntries,
        precondition: async () => {
          await requireEligibleHost(hostId);
          await requireProfileListenerCapabilities(hostId, profile);
        },
        finalize: async () => {
          const generated = await generateXrayHostConfig(hostId, keyring);
          return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
        },
      });
      try {
        pushAgentRefresh(hostId, "xray-inbound-create", { urgent: true });
      } catch {
        // The committed desired state remains available through heartbeat fallback.
      }
      await recordXrayMutationObservability({
        event: "INBOUND_CREATED",
        resourceType: "xray_inbound",
        resourceId: created.inboundId,
        hostId,
        action: "create",
        fields: {
          userId, hostId, inboundId: created.inboundId, operationId: created.operationId,
          generation: created.desiredGeneration, runtimeTag, port, status: "QUEUED",
        },
      });
      return {
        inboundId: created.inboundId,
        operationId: created.operationId,
        desiredGeneration: created.desiredGeneration,
      };
    };
    return dualReservations
      ? await withConsumedXrayPortReservations({
        tcpReservationId: dualReservations.tcp,
        udpReservationId: dualReservations.udp,
        hostId,
        userId,
        port,
      }, create)
      : await withConsumedXrayPortReservation({
        reservationId: input.portReservationId,
        hostId,
        userId,
        port,
        network: "tcp",
      }, create);
  } catch (error) {
    mapError(error);
  }
}

export function createXrayInboundV2(
  input: CreateXrayInboundV2Input,
  dependencies: CreateXrayInboundV2Dependencies = {},
) {
  const profile = normalizeCreateProfile(input.profileId, input.spec, dependencies);
  if (profile.security === "TLS") return createXrayTlsInbound(input, profile);
  if (profile.id === "TUNNEL_TCP_LOCAL_NONE") return createXrayTunnelInbound(input, profile);
  if (profile.id === "HTTP_RAW_NONE" || profile.id === "MIXED_RAW_NONE") {
    return createXrayUserPasswordProxyInbound(input, profile);
  }
  if (profile.id === "WIREGUARD_UDP_NONE") return createXrayWireGuardInbound(input, profile);
  if (profile.security === "NONE") return createXrayShadowsocksInbound(input, profile);
  if (input.tlsCertificateId !== undefined || input.serverName !== undefined || !input.reality
    || input.portReservations !== undefined) {
    throw new XrayInboundCreateError("INVALID_CONFIG_INPUT");
  }
  if (input.portReservationId === undefined) throw new XrayInboundCreateError("PORT_RESERVATION_EXPIRED");
  const entries = normalizeInitialAccessEntries(input.initialAccessEntries);
  const { initialAccessEntries: _initialAccessEntries, tlsCertificateId: _tlsCertificateId,
    serverName: _serverName, portReservations: _portReservations, ...rest } = input;
  return createXrayInbound({
    ...rest,
    publicAddress: input.publicAddress,
    portReservationId: input.portReservationId,
    reality: input.reality,
    initialClients: entries.map((entry) => ({ name: entry.name, flow: profile.clientFlow })),
  });
}
