import crypto from "node:crypto";

import {
  buildXrayHttpProxyUri,
  buildXrayMixedProxyEndpoints,
  buildXrayHysteria2Uri,
  buildXrayShadowsocks2022Uri,
  buildXrayTrojanRealityUri,
  buildXrayTrojanTlsUri,
  buildXrayVlessTlsUri,
  buildXrayVmessTlsUri,
} from "../shared/xrayShare";
import { parseStoredXrayAccessSettings } from "../shared/xrayAccess";
import { resolveStoredXrayInboundDefinition } from "../shared/xrayProfiles";
import { AGENT_VERSION } from "../shared/versions";
import { isForwardplusAgentVersionAtLeast } from "./agentRouteUtils";
import { pushAgentRefresh } from "./agentEvents";
import { boolLiteral, quoteIdentifier } from "./dbCompat";
import { queryRaw } from "./dbRuntime";
import { generateXrayHostConfig, XrayConfigGenerationError } from "./xrayConfigGenerator";
import { loadGenericPasswordAccessEntryById } from "./xrayGenericAccessProjection";
import { loadGenericUuidAccessEntryById } from "./xrayGenericUuidAccessProjection";
import { loadHysteriaAccessEntryById } from "./xrayHysteriaAccessProjection";
import {
  loadHttpBasicAccessEntryById,
  loadMixedUserPasswordAccessEntryById,
} from "./xrayHttpAccessProjection";
import {
  loadShadowsocksAccessEntryById,
  loadShadowsocksServerKeyByInboundId,
} from "./xrayShadowsocksAccessProjection";
import { getXrayInboundDetail } from "./xrayQueryService";
import { getHostById } from "./repositories/hostRepository";
import { recordXrayMutationObservability } from "./xrayMutationObservability";
import {
  createXrayGenericAccessConfiguration,
  getXrayRuntimeReport,
  updateXrayGenericAccessConfiguration,
  XrayRepositoryError,
  type NewXrayGenericAccessRecord,
} from "./repositories/xrayRepository";
import {
  decryptXraySecret,
  encryptXraySecret,
  fingerprintXraySecret,
  loadXrayMasterKeyFile,
  xrayAccessSecretContext,
  xrayInboundSecretContext,
  XraySecretUnavailableError,
} from "./xraySecretCrypto";
import {
  xrayTlsCertificateCoversServerName,
  xrayTlsCertificateLeafFingerprintSha256,
} from "./xrayTlsCertificate";
import {
  loadWireGuardAccessEntryById,
  loadWireGuardServerPrivateKeyByInboundId,
} from "./xrayWireGuardAccessProjection";
import {
  buildXrayWireGuardClientConfig,
  generateXrayWireGuardKeyPair,
  generateXrayWireGuardPreSharedKey,
} from "./xrayWireGuard";

const MAX_ACCESS_ENTRIES_PER_INBOUND = 32;
const nameControlPattern = /[\u0000-\u001f\u007f]/;
type SupportedGenericAccessProfileId =
  | "TROJAN_RAW_REALITY"
  | "TROJAN_RAW_TLS"
  | "VLESS_RAW_TLS"
  | "VLESS_RAW_TLS_VISION"
  | "VMESS_RAW_TLS"
  | "SHADOWSOCKS_2022_RAW_NONE"
  | "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE"
  | "TROJAN_WEBSOCKET_TLS"
  | "VLESS_WEBSOCKET_TLS"
  | "TROJAN_GRPC_TLS"
  | "VLESS_GRPC_TLS"
  | "TROJAN_HTTP_UPGRADE_TLS"
  | "VLESS_HTTP_UPGRADE_TLS"
  | "TROJAN_XHTTP_TLS"
  | "VLESS_XHTTP_TLS"
  | "TROJAN_MKCP_TLS"
  | "VLESS_MKCP_TLS"
  | "HYSTERIA2_TLS"
  | "WIREGUARD_UDP_NONE"
  | "HTTP_RAW_NONE"
  | "MIXED_RAW_NONE";

export type XrayAccessServiceErrorCode =
  | "HOST_NOT_FOUND"
  | "HOST_OFFLINE"
  | "AGENT_CAPABILITY_MISSING"
  | "UDP_CAPABILITY_REQUIRED"
  | "INBOUND_NOT_FOUND"
  | "CLIENT_NOT_FOUND"
  | "CLIENT_PENDING_DELETE"
  | "CLIENT_LIMIT_REACHED"
  | "DUPLICATE_CLIENT_NAME"
  | "CONFIG_GENERATION_CONFLICT"
  | "OPERATION_CONFLICT"
  | "SENSITIVE_DATA_UNAVAILABLE"
  | "LAST_ACTIVE_ACCESS_REQUIRED"
  | "INVALID_CONFIG_INPUT";

export class XrayAccessServiceError extends Error {
  constructor(readonly code: XrayAccessServiceErrorCode) {
    super(code);
    this.name = "XrayAccessServiceError";
  }
}

function positiveId(value: unknown, code: XrayAccessServiceErrorCode): number {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) throw new XrayAccessServiceError(code);
  return id;
}

function generation(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new XrayAccessServiceError("CONFIG_GENERATION_CONFLICT");
  return parsed;
}

function accessName(value: unknown): string {
  const name = String(value ?? "").trim();
  if (!name || name.length > 128 || nameControlPattern.test(name)) throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
  return name;
}

function databaseBoolean(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || value === "true";
}

function supportedGenericAccessProfileId(value: unknown): SupportedGenericAccessProfileId | null {
  return value === "TROJAN_RAW_REALITY" || value === "TROJAN_RAW_TLS"
    || value === "VLESS_RAW_TLS" || value === "VLESS_RAW_TLS_VISION"
    || value === "VMESS_RAW_TLS"
    || value === "SHADOWSOCKS_2022_RAW_NONE" || value === "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE"
    || value === "TROJAN_WEBSOCKET_TLS" || value === "VLESS_WEBSOCKET_TLS"
    || value === "TROJAN_GRPC_TLS" || value === "VLESS_GRPC_TLS"
    || value === "TROJAN_HTTP_UPGRADE_TLS" || value === "VLESS_HTTP_UPGRADE_TLS"
    || value === "TROJAN_XHTTP_TLS" || value === "VLESS_XHTTP_TLS"
    || value === "TROJAN_MKCP_TLS" || value === "VLESS_MKCP_TLS"
    || value === "HYSTERIA2_TLS"
    || value === "WIREGUARD_UDP_NONE"
    || value === "HTTP_RAW_NONE" || value === "MIXED_RAW_NONE"
    ? value
    : null;
}

async function mutationRow(accessEntryId: number) {
  const q = quoteIdentifier;
  const rows = await queryRaw<Record<string, unknown>>(
    `SELECT a.${q("id")} AS ${q("id")}, a.${q("inboundId")} AS ${q("inboundId")}, a.${q("name")} AS ${q("name")},
            a.${q("isEnabled")} AS ${q("isEnabled")}, a.${q("pendingDelete")} AS ${q("pendingDelete")},
            i.${q("hostId")} AS ${q("hostId")}, i.${q("protocol")} AS ${q("protocol")},
            i.${q("transport")} AS ${q("transport")}, i.${q("security")} AS ${q("security")},
            i.${q("profileId")} AS ${q("profileId")}, i.${q("specVersion")} AS ${q("specVersion")},
            i.${q("specJson")} AS ${q("specJson")}, i.${q("pendingDelete")} AS ${q("inboundPendingDelete")},
            i.${q("isEnabled")} AS ${q("inboundEnabled")}
       FROM ${q("xray_access_entries")} a
       JOIN ${q("xray_inbounds")} i ON i.${q("id")} = a.${q("inboundId")}
      WHERE a.${q("id")} = ? AND a.${q("legacyClientId")} IS NULL LIMIT 1`,
    [accessEntryId],
  );
  const row = rows[0];
  if (!row) throw new XrayAccessServiceError("CLIENT_NOT_FOUND");
  const definition = resolveStoredXrayInboundDefinition({
    protocol: row.protocol,
    transport: row.transport,
    security: row.security,
    profileId: row.profileId,
    specVersion: row.specVersion,
    specJson: row.specJson,
  });
  const profileId = supportedGenericAccessProfileId(definition?.profile.id);
  if (!profileId || databaseBoolean(row.inboundPendingDelete)) {
    throw new XrayAccessServiceError("INBOUND_NOT_FOUND");
  }
  return {
    id: accessEntryId,
    inboundId: positiveId(row.inboundId, "INBOUND_NOT_FOUND"),
    hostId: positiveId(row.hostId, "HOST_NOT_FOUND"),
    name: String(row.name ?? ""),
    isEnabled: databaseBoolean(row.isEnabled),
    pendingDelete: databaseBoolean(row.pendingDelete),
    inboundEnabled: databaseBoolean(row.inboundEnabled),
    profileId,
  };
}

async function inboundRow(inboundId: number) {
  const q = quoteIdentifier;
  const rows = await queryRaw<Record<string, unknown>>(
    `SELECT ${["id", "hostId", "protocol", "transport", "security", "profileId", "specVersion", "specJson", "pendingDelete"]
      .map(q).join(", ")} FROM ${q("xray_inbounds")} WHERE ${q("id")} = ? LIMIT 1`,
    [inboundId],
  );
  const row = rows[0];
  if (!row || databaseBoolean(row.pendingDelete)) throw new XrayAccessServiceError("INBOUND_NOT_FOUND");
  const definition = resolveStoredXrayInboundDefinition(row);
  const profileId = supportedGenericAccessProfileId(definition?.profile.id);
  if (!profileId) throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
  return { inboundId, hostId: positiveId(row.hostId, "HOST_NOT_FOUND"), profileId };
}

async function requireWritableHost(hostId: number, profileId: SupportedGenericAccessProfileId) {
  const host = await getHostById(hostId);
  if (!host) throw new XrayAccessServiceError("HOST_NOT_FOUND");
  if (!host.isOnline) throw new XrayAccessServiceError("HOST_OFFLINE");
  const runtime = await getXrayRuntimeReport(hostId);
  if (!isForwardplusAgentVersionAtLeast(host.agentVersion, host.agentDistribution, AGENT_VERSION) || !runtime || runtime.capabilitySchemaVersion !== 1
    || runtime.supportedOS !== "linux" || (runtime.supportedArch !== "amd64" && runtime.supportedArch !== "arm64")
    || !runtime.supportsArtifactInstall || !runtime.supportsPortProbe || !runtime.supportsRealityScan) {
    throw new XrayAccessServiceError("AGENT_CAPABILITY_MISSING");
  }
  if ((profileId === "HYSTERIA2_TLS" || profileId === "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE"
      || profileId === "WIREGUARD_UDP_NONE")
    && (!runtime.supportsUdpPortProbe || !runtime.supportsUdpListenerReadiness)) {
    throw new XrayAccessServiceError("UDP_CAPABILITY_REQUIRED");
  }
}

async function activeRows(inboundId: number) {
  const q = quoteIdentifier;
  return queryRaw<Record<string, unknown>>(
    `SELECT ${["id", "name", "sortOrder", "isEnabled"].map(q).join(", ")} FROM ${q("xray_access_entries")}
      WHERE ${q("inboundId")} = ? AND ${q("legacyClientId")} IS NULL
        AND ${q("pendingDelete")} = ${boolLiteral(false)} ORDER BY ${q("sortOrder")} ASC, ${q("id")} ASC`,
    [inboundId],
  );
}

async function assertRequiredActiveAccessPreserved(current: Awaited<ReturnType<typeof mutationRow>>) {
  if ((current.profileId !== "SHADOWSOCKS_2022_RAW_NONE"
      && current.profileId !== "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE"
      && current.profileId !== "HYSTERIA2_TLS" && current.profileId !== "WIREGUARD_UDP_NONE"
      && current.profileId !== "HTTP_RAW_NONE" && current.profileId !== "MIXED_RAW_NONE")
    || !current.inboundEnabled || !current.isEnabled) return;
  const rows = await activeRows(current.inboundId);
  if (rows.filter((row) => databaseBoolean(row.isEnabled)).length <= 1) {
    throw new XrayAccessServiceError("LAST_ACTIVE_ACCESS_REQUIRED");
  }
}

async function assertNameAvailable(inboundId: number, name: string, exceptId?: number) {
  const identity = name.toLocaleLowerCase();
  const rows = await activeRows(inboundId);
  if (rows.some((row) => Number(row.id) !== exceptId && String(row.name ?? "").trim().toLocaleLowerCase() === identity)) {
    throw new XrayAccessServiceError("DUPLICATE_CLIENT_NAME");
  }
  return rows;
}

async function allocateWireGuardPeerAddress(inboundId: number): Promise<string> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Record<string, unknown>>(
    `SELECT ${q("credentialType")}, ${q("settingsJson")} FROM ${q("xray_access_entries")}
      WHERE ${q("inboundId")} = ? AND ${q("legacyClientId")} IS NULL ORDER BY ${q("id")} ASC`,
    [inboundId],
  );
  const used = new Set<string>();
  for (const row of rows) {
    const settings = parseStoredXrayAccessSettings({
      credentialType: row.credentialType,
      settingsJson: row.settingsJson,
    });
    if (settings?.credentialType !== "WIREGUARD_PEER" || settings.schemaVersion !== 2
      || used.has(settings.address)) throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
    used.add(settings.address);
  }
  for (let suffix = 2; suffix <= 254; suffix += 1) {
    const address = `10.0.0.${suffix}/32`;
    if (!used.has(address)) return address;
  }
  throw new XrayAccessServiceError("CLIENT_LIMIT_REACHED");
}

function wakeAgent(hostId: number, reason: string) {
  try {
    pushAgentRefresh(hostId, reason, { urgent: true });
  } catch {
    // The durable desired state will be delivered by heartbeat fallback.
  }
}

function mapError(error: unknown): never {
  if (error instanceof XrayAccessServiceError) throw error;
  if (error instanceof XrayRepositoryError || error instanceof XraySecretUnavailableError) {
    throw new XrayAccessServiceError(error.code as XrayAccessServiceErrorCode);
  }
  if (error instanceof XrayConfigGenerationError) throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
  throw error;
}

export async function createXrayAccessEntryForInbound(input: {
  inboundId: unknown;
  userId: unknown;
  name: unknown;
  expectedGeneration: unknown;
}) {
  try {
    const inboundId = positiveId(input.inboundId, "INBOUND_NOT_FOUND");
    const userId = positiveId(input.userId, "OPERATION_CONFLICT");
    const name = accessName(input.name);
    const expectedGeneration = generation(input.expectedGeneration);
    const inbound = await inboundRow(inboundId);
    await requireWritableHost(inbound.hostId, inbound.profileId);
    const existing = await assertNameAvailable(inboundId, name);
    if (existing.length >= MAX_ACCESS_ENTRIES_PER_INBOUND) throw new XrayAccessServiceError("CLIENT_LIMIT_REACHED");
    const keyring = loadXrayMasterKeyFile();
    const statsKey = `forwardx-access-${crypto.randomUUID()}`;
    const sortOrder = existing.reduce((maximum, row) => Math.max(maximum, Number(row.sortOrder) || 0), -1) + 1;
    let access: NewXrayGenericAccessRecord | ((context: {
      desiredGeneration: number;
    }) => Promise<NewXrayGenericAccessRecord>);
    if (inbound.profileId === "TROJAN_RAW_REALITY") {
      const password = crypto.randomBytes(32).toString("base64url");
      const shortId = crypto.randomBytes(8).toString("hex");
      access = {
        name,
        credentialType: "PASSWORD",
        settingsJson: '{"schemaVersion":1}',
        statsKey,
        isEnabled: true,
        sortOrder,
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
    } else if (inbound.profileId === "TROJAN_RAW_TLS"
      || inbound.profileId === "TROJAN_WEBSOCKET_TLS"
      || inbound.profileId === "TROJAN_GRPC_TLS"
      || inbound.profileId === "TROJAN_HTTP_UPGRADE_TLS"
      || inbound.profileId === "TROJAN_XHTTP_TLS"
      || inbound.profileId === "TROJAN_MKCP_TLS") {
      const password = crypto.randomBytes(32).toString("base64url");
      const passwordContext = xrayAccessSecretContext(statsKey, "PASSWORD");
      access = {
        name,
        credentialType: "PASSWORD",
        settingsJson: '{"schemaVersion":1}',
        statsKey,
        isEnabled: true,
        sortOrder,
        secrets: [{
          kind: "PASSWORD",
          encryptedValue: encryptXraySecret(password, passwordContext, keyring),
          fingerprint: fingerprintXraySecret(password, passwordContext, keyring),
        }],
      };
    } else if (inbound.profileId === "HTTP_RAW_NONE" || inbound.profileId === "MIXED_RAW_NONE") {
      const username = crypto.randomBytes(16).toString("base64url");
      const password = crypto.randomBytes(32).toString("base64url");
      const usernameContext = xrayAccessSecretContext(statsKey, "USERNAME");
      const passwordContext = xrayAccessSecretContext(statsKey, "PASSWORD");
      access = {
        name,
        credentialType: inbound.profileId === "HTTP_RAW_NONE" ? "HTTP_BASIC" : "MIXED_USER_PASSWORD",
        settingsJson: '{"schemaVersion":1}',
        statsKey,
        isEnabled: true,
        sortOrder,
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
    } else if (inbound.profileId === "SHADOWSOCKS_2022_RAW_NONE"
      || inbound.profileId === "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE") {
      const shadowsocksKey = crypto.randomBytes(32).toString("base64");
      const context = xrayAccessSecretContext(statsKey, "SHADOWSOCKS_KEY");
      access = {
        name,
        credentialType: "SHADOWSOCKS_KEY",
        settingsJson: '{"schemaVersion":1}',
        statsKey,
        isEnabled: true,
        sortOrder,
        secrets: [{
          kind: "SHADOWSOCKS_KEY",
          encryptedValue: encryptXraySecret(shadowsocksKey, context, keyring),
          fingerprint: fingerprintXraySecret(shadowsocksKey, context, keyring),
        }],
      };
    } else if (inbound.profileId === "HYSTERIA2_TLS") {
      const auth = crypto.randomBytes(32).toString("base64url");
      const context = xrayAccessSecretContext(statsKey, "HYSTERIA_AUTH");
      access = {
        name,
        credentialType: "HYSTERIA_AUTH",
        settingsJson: '{"schemaVersion":1}',
        statsKey,
        isEnabled: true,
        sortOrder,
        secrets: [{
          kind: "HYSTERIA_AUTH",
          encryptedValue: encryptXraySecret(auth, context, keyring),
          fingerprint: fingerprintXraySecret(auth, context, keyring),
        }],
      };
    } else if (inbound.profileId === "WIREGUARD_UDP_NONE") {
      const privateKey = generateXrayWireGuardKeyPair().privateKey;
      const preSharedKey = generateXrayWireGuardPreSharedKey();
      const privateKeyContext = xrayAccessSecretContext(statsKey, "PRIVATE_KEY");
      const preSharedKeyContext = xrayAccessSecretContext(statsKey, "PRE_SHARED_KEY");
      access = async () => {
        const currentRows = await activeRows(inboundId);
        if (currentRows.length >= MAX_ACCESS_ENTRIES_PER_INBOUND) {
          throw new XrayAccessServiceError("CLIENT_LIMIT_REACHED");
        }
        const address = await allocateWireGuardPeerAddress(inboundId);
        const currentSortOrder = currentRows.reduce(
          (maximum, row) => Math.max(maximum, Number(row.sortOrder) || 0),
          -1,
        ) + 1;
        return {
          name,
          credentialType: "WIREGUARD_PEER",
          settingsJson: JSON.stringify({ schemaVersion: 2, address }),
          statsKey,
          isEnabled: true,
          sortOrder: currentSortOrder,
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
      };
    } else {
      const uuid = crypto.randomUUID();
      const uuidContext = xrayAccessSecretContext(statsKey, "UUID");
      access = {
        name,
        credentialType: "UUID",
        settingsJson: JSON.stringify(inbound.profileId === "VMESS_RAW_TLS"
          ? { schemaVersion: 1, flow: "NONE", security: "AUTO" }
          : {
            schemaVersion: 2,
            protocol: "VLESS",
            encryption: "NONE",
            flow: inbound.profileId === "VLESS_RAW_TLS_VISION" ? "XTLS_RPRX_VISION" : "NONE",
          }),
        statsKey,
        isEnabled: true,
        sortOrder,
        secrets: [{
          kind: "UUID",
          encryptedValue: encryptXraySecret(uuid, uuidContext, keyring),
          fingerprint: fingerprintXraySecret(uuid, uuidContext, keyring),
        }],
      };
    }
    const created = await createXrayGenericAccessConfiguration({
      inboundId,
      expectedGeneration,
      createdByUserId: userId,
      access,
      precondition: async () => {
        const current = await inboundRow(inboundId);
        if (current.hostId !== inbound.hostId) throw new XrayAccessServiceError("INBOUND_NOT_FOUND");
        await requireWritableHost(inbound.hostId, current.profileId);
        await assertNameAvailable(inboundId, name);
      },
      finalize: async () => {
        const generated = await generateXrayHostConfig(inbound.hostId, keyring);
        return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
      },
    });
    wakeAgent(inbound.hostId, "xray-access-create");
    await recordXrayMutationObservability({
      event: "ACCESS_ENTRY_CREATED",
      resourceType: "xray_access_entry",
      resourceId: created.accessEntryId,
      hostId: inbound.hostId,
      action: "create",
      fields: {
        userId, hostId: inbound.hostId, inboundId, accessEntryId: created.accessEntryId,
        operationId: created.operationId, generation: created.desiredGeneration, status: "QUEUED",
      },
    });
    return created;
  } catch (error) {
    mapError(error);
  }
}

export async function updateXrayAccessEntryForInbound(input: {
  id: unknown;
  userId: unknown;
  name?: unknown;
  isEnabled?: unknown;
  expectedGeneration: unknown;
}) {
  try {
    const id = positiveId(input.id, "CLIENT_NOT_FOUND");
    const userId = positiveId(input.userId, "OPERATION_CONFLICT");
    const expectedGeneration = generation(input.expectedGeneration);
    const current = await mutationRow(id);
    if (current.pendingDelete) throw new XrayAccessServiceError("CLIENT_PENDING_DELETE");
    const patch: { name?: string; isEnabled?: boolean } = {};
    if (input.name !== undefined) patch.name = accessName(input.name);
    if (input.isEnabled !== undefined) {
      if (typeof input.isEnabled !== "boolean") throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
      patch.isEnabled = input.isEnabled;
    }
    if (Object.keys(patch).length === 0) throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
    await requireWritableHost(current.hostId, current.profileId);
    if (patch.name) await assertNameAvailable(current.inboundId, patch.name, id);
    const keyring = loadXrayMasterKeyFile();
    const updated = await updateXrayGenericAccessConfiguration({
      id,
      expectedGeneration,
      createdByUserId: userId,
      patch,
      precondition: async () => {
        const latest = await mutationRow(id);
        if (latest.hostId !== current.hostId || latest.inboundId !== current.inboundId || latest.pendingDelete) {
          throw new XrayAccessServiceError("CLIENT_PENDING_DELETE");
        }
        await requireWritableHost(current.hostId, latest.profileId);
        if (patch.name) await assertNameAvailable(current.inboundId, patch.name, id);
        if (patch.isEnabled === false) await assertRequiredActiveAccessPreserved(latest);
      },
      finalize: async () => {
        const generated = await generateXrayHostConfig(current.hostId, keyring);
        return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
      },
    });
    wakeAgent(current.hostId, "xray-access-update");
    await recordXrayMutationObservability({
      event: "ACCESS_ENTRY_UPDATED",
      resourceType: "xray_access_entry",
      resourceId: id,
      hostId: current.hostId,
      action: "update",
      before: { userId, hostId: current.hostId, inboundId: current.inboundId, accessEntryId: id, generation: expectedGeneration },
      fields: {
        userId, hostId: current.hostId, inboundId: current.inboundId, accessEntryId: id,
        operationId: updated.operationId, generation: updated.desiredGeneration, status: "QUEUED",
      },
    });
    return updated;
  } catch (error) {
    mapError(error);
  }
}

export async function removeXrayAccessEntryForInbound(input: {
  id: unknown;
  userId: unknown;
  expectedGeneration: unknown;
}) {
  try {
    const id = positiveId(input.id, "CLIENT_NOT_FOUND");
    const userId = positiveId(input.userId, "OPERATION_CONFLICT");
    const expectedGeneration = generation(input.expectedGeneration);
    const current = await mutationRow(id);
    if (current.pendingDelete) throw new XrayAccessServiceError("CLIENT_PENDING_DELETE");
    await requireWritableHost(current.hostId, current.profileId);
    const keyring = loadXrayMasterKeyFile();
    const removed = await updateXrayGenericAccessConfiguration({
      id,
      expectedGeneration,
      createdByUserId: userId,
      patch: { pendingDelete: true },
      precondition: async () => {
        const latest = await mutationRow(id);
        if (latest.pendingDelete) throw new XrayAccessServiceError("CLIENT_PENDING_DELETE");
        await requireWritableHost(current.hostId, latest.profileId);
        await assertRequiredActiveAccessPreserved(latest);
      },
      finalize: async () => {
        const generated = await generateXrayHostConfig(current.hostId, keyring);
        return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
      },
    });
    wakeAgent(current.hostId, "xray-access-remove");
    await recordXrayMutationObservability({
      event: "ACCESS_ENTRY_DELETE_REQUESTED",
      resourceType: "xray_access_entry",
      resourceId: id,
      hostId: current.hostId,
      action: "delete",
      before: { userId, hostId: current.hostId, inboundId: current.inboundId, accessEntryId: id, generation: expectedGeneration },
      fields: {
        userId, hostId: current.hostId, inboundId: current.inboundId, accessEntryId: id,
        operationId: removed.operationId, generation: removed.desiredGeneration, status: "QUEUED",
      },
    });
    return { ...removed, pendingDelete: true as const };
  } catch (error) {
    mapError(error);
  }
}

export async function getXrayAccessEntryShare(
  accessEntryIdValue: unknown,
  format: "TROJAN_URI" | "VLESS_URI" | "VMESS_URI" | "SHADOWSOCKS_URI" | "HYSTERIA2_URI" | "WIREGUARD_CONFIG" | "HTTP_PROXY_URI" | "MIXED_PROXY_ENDPOINTS",
) {
  try {
    const accessEntryId = positiveId(accessEntryIdValue, "CLIENT_NOT_FOUND");
    const q = quoteIdentifier;
    const rows = await queryRaw<Record<string, unknown>>(
      `SELECT i.${q("id")} AS ${q("inboundId")}, i.${q("hostId")} AS ${q("hostId")},
              i.${q("runtimeTag")} AS ${q("runtimeTag")},
              i.${q("protocol")} AS ${q("protocol")}, i.${q("transport")} AS ${q("transport")},
              i.${q("security")} AS ${q("security")}, i.${q("profileId")} AS ${q("profileId")},
              i.${q("specVersion")} AS ${q("specVersion")}, i.${q("specJson")} AS ${q("specJson")},
              i.${q("publicAddress")} AS ${q("publicAddress")}, i.${q("listenPort")} AS ${q("listenPort")},
              i.${q("realityServerName")} AS ${q("realityServerName")},
              i.${q("realityPublicKey")} AS ${q("realityPublicKey")}, i.${q("fingerprint")} AS ${q("fingerprint")},
              i.${q("spiderX")} AS ${q("spiderX")}, i.${q("isEnabled")} AS ${q("isEnabled")},
              i.${q("pendingDelete")} AS ${q("pendingDelete")}, i.${q("tlsCertificateId")} AS ${q("tlsCertificateId")},
              c.${q("hostId")} AS ${q("certificateHostId")},
              c.${q("certificateChainPem")} AS ${q("certificateChainPem")},
              c.${q("leafFingerprintSha256")} AS ${q("leafFingerprintSha256")}
         FROM ${q("xray_access_entries")} a
         JOIN ${q("xray_inbounds")} i ON i.${q("id")} = a.${q("inboundId")}
         LEFT JOIN ${q("xray_tls_certificates")} c ON c.${q("id")} = i.${q("tlsCertificateId")}
        WHERE a.${q("id")} = ? AND a.${q("legacyClientId")} IS NULL LIMIT 1`,
      [accessEntryId],
    );
    if (!rows[0]) throw new XrayAccessServiceError("INBOUND_NOT_FOUND");
    const row = rows[0];
    const definition = resolveStoredXrayInboundDefinition(row);
    const profileId = supportedGenericAccessProfileId(definition?.profile.id);
    if (!profileId) throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
    const keyring = loadXrayMasterKeyFile();
    let access: Awaited<ReturnType<typeof loadGenericPasswordAccessEntryById>>
      | Awaited<ReturnType<typeof loadGenericUuidAccessEntryById>>
      | Awaited<ReturnType<typeof loadShadowsocksAccessEntryById>>
      | Awaited<ReturnType<typeof loadHysteriaAccessEntryById>>
      | Awaited<ReturnType<typeof loadWireGuardAccessEntryById>>
      | Awaited<ReturnType<typeof loadHttpBasicAccessEntryById>>
      | Awaited<ReturnType<typeof loadMixedUserPasswordAccessEntryById>>;
    let uri: string | null = null;
    let wireGuardConfig: Readonly<{ content: string; fileName: string }> | null = null;
    let mixedProxyEndpoints: Readonly<{ socks5Uri: string; httpUri: string }> | null = null;
    if (profileId === "HTTP_RAW_NONE" || profileId === "MIXED_RAW_NONE") {
      const isHttp = profileId === "HTTP_RAW_NONE";
      if (format !== (isHttp ? "HTTP_PROXY_URI" : "MIXED_PROXY_ENDPOINTS")) {
        throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
      }
      access = isHttp
        ? await loadHttpBasicAccessEntryById(accessEntryId)
        : await loadMixedUserPasswordAccessEntryById(accessEntryId);
      const usernameContext = xrayAccessSecretContext(access.statsKey, "USERNAME");
      const passwordContext = xrayAccessSecretContext(access.statsKey, "PASSWORD");
      const username = decryptXraySecret(access.usernameEncrypted, usernameContext, keyring);
      const password = decryptXraySecret(access.passwordEncrypted, passwordContext, keyring);
      if (fingerprintXraySecret(username, usernameContext, keyring) !== access.usernameFingerprint
        || fingerprintXraySecret(password, passwordContext, keyring) !== access.passwordFingerprint) {
        throw new XraySecretUnavailableError();
      }
      try {
        const proxyInput = {
          username,
          password,
          publicAddress: String(row.publicAddress ?? ""),
          listenPort: Number(row.listenPort),
        };
        if (isHttp) uri = buildXrayHttpProxyUri(proxyInput);
        else mixedProxyEndpoints = buildXrayMixedProxyEndpoints(proxyInput);
      } catch {
        throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
      }
    } else if (profileId === "WIREGUARD_UDP_NONE") {
      if (format !== "WIREGUARD_CONFIG") throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
      access = await loadWireGuardAccessEntryById(accessEntryId);
      const serverSecret = await loadWireGuardServerPrivateKeyByInboundId(access.inboundId);
      const privateKeyContext = xrayAccessSecretContext(access.statsKey, "PRIVATE_KEY");
      const preSharedKeyContext = xrayAccessSecretContext(access.statsKey, "PRE_SHARED_KEY");
      const serverContext = xrayInboundSecretContext(String(row.runtimeTag ?? ""), "PRIVATE_KEY");
      const peerPrivateKey = decryptXraySecret(access.privateKeyEncrypted, privateKeyContext, keyring);
      const preSharedKey = decryptXraySecret(access.preSharedKeyEncrypted, preSharedKeyContext, keyring);
      const serverPrivateKey = decryptXraySecret(serverSecret.encryptedValue, serverContext, keyring);
      if (fingerprintXraySecret(peerPrivateKey, privateKeyContext, keyring) !== access.privateKeyFingerprint
        || fingerprintXraySecret(preSharedKey, preSharedKeyContext, keyring) !== access.preSharedKeyFingerprint
        || fingerprintXraySecret(serverPrivateKey, serverContext, keyring) !== serverSecret.fingerprint) {
        throw new XraySecretUnavailableError();
      }
      try {
        wireGuardConfig = buildXrayWireGuardClientConfig({
          peerPrivateKey,
          peerAddress: access.address,
          serverPrivateKey,
          preSharedKey,
          publicAddress: String(row.publicAddress ?? ""),
          listenPort: Number(row.listenPort),
          displayName: access.name,
        });
      } catch {
        throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
      }
    } else if (profileId === "HYSTERIA2_TLS") {
      if (format !== "HYSTERIA2_URI") throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
      access = await loadHysteriaAccessEntryById(accessEntryId);
      const authContext = xrayAccessSecretContext(access.statsKey, "HYSTERIA_AUTH");
      const auth = decryptXraySecret(access.authEncrypted, authContext, keyring);
      if (fingerprintXraySecret(auth, authContext, keyring) !== access.authFingerprint) {
        throw new XraySecretUnavailableError();
      }
      const certificateChainPem = String(row.certificateChainPem ?? "");
      const leafFingerprintSha256 = String(row.leafFingerprintSha256 ?? "");
      if (positiveId(row.hostId, "HOST_NOT_FOUND") !== positiveId(row.certificateHostId, "INVALID_CONFIG_INPUT")
        || xrayTlsCertificateLeafFingerprintSha256(certificateChainPem) !== leafFingerprintSha256
        || !xrayTlsCertificateCoversServerName(certificateChainPem, String(row.realityServerName ?? ""))) {
        throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
      }
      try {
        uri = buildXrayHysteria2Uri({
          auth,
          publicAddress: String(row.publicAddress ?? ""),
          listenPort: Number(row.listenPort),
          serverName: String(row.realityServerName ?? ""),
          leafFingerprintSha256,
          displayName: access.name,
        });
      } catch {
        throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
      }
    } else if (profileId === "SHADOWSOCKS_2022_RAW_NONE"
      || profileId === "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE") {
      if (format !== "SHADOWSOCKS_URI") throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
      access = await loadShadowsocksAccessEntryById(accessEntryId);
      const serverSecret = await loadShadowsocksServerKeyByInboundId(access.inboundId);
      const userContext = xrayAccessSecretContext(access.statsKey, "SHADOWSOCKS_KEY");
      const serverContext = xrayInboundSecretContext(String(row.runtimeTag ?? ""), "SHADOWSOCKS_SERVER_KEY");
      const userKey = decryptXraySecret(access.userKeyEncrypted, userContext, keyring);
      const serverKey = decryptXraySecret(serverSecret.encryptedValue, serverContext, keyring);
      if (fingerprintXraySecret(userKey, userContext, keyring) !== access.userKeyFingerprint
        || fingerprintXraySecret(serverKey, serverContext, keyring) !== serverSecret.fingerprint) {
        throw new XraySecretUnavailableError();
      }
      try {
        uri = buildXrayShadowsocks2022Uri({
          serverKey,
          userKey,
          publicAddress: String(row.publicAddress ?? ""),
          listenPort: Number(row.listenPort),
          displayName: access.name,
        });
      } catch {
        throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
      }
    } else if (profileId === "TROJAN_RAW_REALITY") {
      if (format !== "TROJAN_URI") throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
      access = await loadGenericPasswordAccessEntryById(accessEntryId);
      if (access.profileId !== "TROJAN_RAW_REALITY") throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
      const passwordContext = xrayAccessSecretContext(access.statsKey, "PASSWORD");
      const shortIdContext = xrayAccessSecretContext(access.statsKey, "SHORT_ID");
      const password = decryptXraySecret(access.passwordEncrypted, passwordContext, keyring);
      const shortId = decryptXraySecret(access.shortIdEncrypted, shortIdContext, keyring);
      if (fingerprintXraySecret(password, passwordContext, keyring) !== access.passwordFingerprint
        || fingerprintXraySecret(shortId, shortIdContext, keyring) !== access.shortIdFingerprint) {
        throw new XraySecretUnavailableError();
      }
      try {
        uri = buildXrayTrojanRealityUri({
          password,
          publicAddress: String(row.publicAddress ?? ""),
          listenPort: Number(row.listenPort),
          serverName: String(row.realityServerName ?? ""),
          realityPublicKey: String(row.realityPublicKey ?? ""),
          shortId,
          fingerprint: row.fingerprint as "chrome",
          spiderX: String(row.spiderX ?? ""),
          displayName: access.name,
        });
      } catch {
        throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
      }
    } else if (profileId === "TROJAN_RAW_TLS"
      || profileId === "TROJAN_WEBSOCKET_TLS"
      || profileId === "TROJAN_GRPC_TLS"
      || profileId === "TROJAN_HTTP_UPGRADE_TLS"
      || profileId === "TROJAN_XHTTP_TLS"
      || profileId === "TROJAN_MKCP_TLS") {
      if (format !== "TROJAN_URI") throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
      access = await loadGenericPasswordAccessEntryById(accessEntryId);
      if (access.profileId !== profileId) throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
      const passwordContext = xrayAccessSecretContext(access.statsKey, "PASSWORD");
      const password = decryptXraySecret(access.passwordEncrypted, passwordContext, keyring);
      if (fingerprintXraySecret(password, passwordContext, keyring) !== access.passwordFingerprint) {
        throw new XraySecretUnavailableError();
      }
      const certificateChainPem = String(row.certificateChainPem ?? "");
      const leafFingerprintSha256 = String(row.leafFingerprintSha256 ?? "");
      if (positiveId(row.hostId, "HOST_NOT_FOUND") !== positiveId(row.certificateHostId, "INVALID_CONFIG_INPUT")
        || xrayTlsCertificateLeafFingerprintSha256(certificateChainPem) !== leafFingerprintSha256
        || !xrayTlsCertificateCoversServerName(certificateChainPem, String(row.realityServerName ?? ""))) {
        throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
      }
      try {
        const shareBase = {
          password,
          publicAddress: String(row.publicAddress ?? ""),
          listenPort: Number(row.listenPort),
          serverName: String(row.realityServerName ?? ""),
          fingerprint: row.fingerprint as "chrome",
          leafFingerprintSha256,
          displayName: access.name,
        };
        uri = profileId === "TROJAN_WEBSOCKET_TLS"
          || profileId === "TROJAN_HTTP_UPGRADE_TLS"
          || profileId === "TROJAN_XHTTP_TLS"
          ? buildXrayTrojanTlsUri({ ...shareBase, profileId, path: String(definition?.spec.path ?? "") })
          : profileId === "TROJAN_GRPC_TLS"
            ? buildXrayTrojanTlsUri({ ...shareBase, profileId, serviceName: String(definition?.spec.serviceName ?? "") })
            : buildXrayTrojanTlsUri({ ...shareBase, profileId });
      } catch {
        throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
      }
    } else {
      const isVmess = profileId === "VMESS_RAW_TLS";
      if (format !== (isVmess ? "VMESS_URI" : "VLESS_URI")) {
        throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
      }
      access = await loadGenericUuidAccessEntryById(accessEntryId);
      const uuidContext = xrayAccessSecretContext(access.statsKey, "UUID");
      const uuid = decryptXraySecret(access.uuidEncrypted, uuidContext, keyring);
      if (fingerprintXraySecret(uuid, uuidContext, keyring) !== access.uuidFingerprint) {
        throw new XraySecretUnavailableError();
      }
      const certificateChainPem = String(row.certificateChainPem ?? "");
      const leafFingerprintSha256 = String(row.leafFingerprintSha256 ?? "");
      if (positiveId(row.hostId, "HOST_NOT_FOUND") !== positiveId(row.certificateHostId, "INVALID_CONFIG_INPUT")
        || xrayTlsCertificateLeafFingerprintSha256(certificateChainPem) !== leafFingerprintSha256
        || !xrayTlsCertificateCoversServerName(certificateChainPem, String(row.realityServerName ?? ""))) {
        throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
      }
      try {
        const shareBase = {
          uuid,
          publicAddress: String(row.publicAddress ?? ""),
          listenPort: Number(row.listenPort),
          serverName: String(row.realityServerName ?? ""),
          fingerprint: row.fingerprint as "chrome",
          leafFingerprintSha256,
          displayName: access.name,
        };
        uri = isVmess
          ? buildXrayVmessTlsUri(shareBase)
          : profileId === "VLESS_WEBSOCKET_TLS"
          || profileId === "VLESS_HTTP_UPGRADE_TLS"
          || profileId === "VLESS_XHTTP_TLS"
          ? buildXrayVlessTlsUri({ ...shareBase, profileId, path: String(definition?.spec.path ?? "") })
          : profileId === "VLESS_GRPC_TLS"
            ? buildXrayVlessTlsUri({ ...shareBase, profileId, serviceName: String(definition?.spec.serviceName ?? "") })
            : buildXrayVlessTlsUri({ ...shareBase, profileId });
      } catch {
        throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
      }
    }
    const detail = await getXrayInboundDetail(access.inboundId);
    if (!detail) throw new XrayAccessServiceError("INBOUND_NOT_FOUND");
    const deploymentStatus = access.pendingDelete || databaseBoolean(row.pendingDelete)
      ? "PENDING_DELETE"
      : !access.isEnabled || !databaseBoolean(row.isEnabled)
        ? "DISABLED"
        : detail.deployment.status;
    if (wireGuardConfig) {
      return {
        format: "WIREGUARD_CONFIG" as const,
        content: wireGuardConfig.content,
        fileName: wireGuardConfig.fileName,
        displayName: access.name,
        deploymentStatus,
      };
    }
    if (mixedProxyEndpoints) {
      return {
        format: "MIXED_PROXY_ENDPOINTS" as const,
        ...mixedProxyEndpoints,
        displayName: access.name,
        deploymentStatus,
      };
    }
    if (uri === null) throw new XrayAccessServiceError("INVALID_CONFIG_INPUT");
    return {
      ...(profileId === "HTTP_RAW_NONE" ? { format: "HTTP_PROXY_URI" as const } : {}),
      uri,
      displayName: access.name,
      generatedAt: new Date(),
      deploymentStatus,
    };
  } catch (error) {
    mapError(error);
  }
}
