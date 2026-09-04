import crypto from "node:crypto";
import { AGENT_VERSION } from "../shared/versions";
import { isForwardplusAgentVersionAtLeast } from "./agentRouteUtils";

import { buildXrayVlessRealityUri } from "../shared/xrayShare";
import { resolveStoredXrayInboundDefinition } from "../shared/xrayProfiles";
import { pushAgentRefresh } from "./agentEvents";
import { boolLiteral, quoteIdentifier } from "./dbCompat";
import { queryRaw } from "./dbRuntime";
import { generateXrayHostConfig, XrayConfigGenerationError } from "./xrayConfigGenerator";
import { loadLegacyVlessAccessEntryByClientId } from "./xrayLegacyAccessProjection";
import { getXrayInboundDetail } from "./xrayQueryService";
import { recordXrayMutationObservability } from "./xrayMutationObservability";
import { getHostById } from "./repositories/hostRepository";
import {
  createXrayClientConfiguration,
  getXrayInbound,
  getXrayRuntimeReport,
  listXrayClientsByInbound,
  updateXrayClientConfiguration,
  XrayRepositoryError,
} from "./repositories/xrayRepository";
import {
  decryptXraySecret,
  encryptXraySecret,
  fingerprintXraySecret,
  loadXrayMasterKeyFile,
  xrayClientShortIdContext,
  xrayClientUuidContext,
  XraySecretUnavailableError,
} from "./xraySecretCrypto";
import { repairXrayClientFingerprints } from "./xrayFingerprintMigration";

const MAX_CLIENTS_PER_INBOUND = 32;
const nameControlPattern = /[\u0000-\u001f\u007f]/;

export type XrayClientServiceErrorCode =
  | "HOST_NOT_FOUND"
  | "HOST_OFFLINE"
  | "AGENT_CAPABILITY_MISSING"
  | "INBOUND_NOT_FOUND"
  | "CLIENT_NOT_FOUND"
  | "CLIENT_PENDING_DELETE"
  | "CLIENT_LIMIT_REACHED"
  | "DUPLICATE_CLIENT_NAME"
  | "CONFIG_GENERATION_CONFLICT"
  | "OPERATION_CONFLICT"
  | "SENSITIVE_DATA_UNAVAILABLE"
  | "INVALID_CONFIG_INPUT";

export class XrayClientServiceError extends Error {
  constructor(readonly code: XrayClientServiceErrorCode) {
    super(code);
    this.name = "XrayClientServiceError";
  }
}

type ClientMutationRow = Record<string, unknown> & {
  id: unknown;
  inboundId: unknown;
  hostId: unknown;
  name: unknown;
  isEnabled: unknown;
  pendingDelete: unknown;
};

function positiveId(value: unknown, code: XrayClientServiceErrorCode): number {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) throw new XrayClientServiceError(code);
  return id;
}

function generation(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new XrayClientServiceError("CONFIG_GENERATION_CONFLICT");
  return parsed;
}

function clientName(value: unknown): string {
  const name = String(value ?? "").trim();
  if (!name || name.length > 128 || nameControlPattern.test(name)) {
    throw new XrayClientServiceError("INVALID_CONFIG_INPUT");
  }
  return name;
}

function databaseBoolean(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || value === "true";
}

async function inboundMutationRow(inboundId: number) {
  const q = quoteIdentifier;
  const rows = await queryRaw<Record<string, unknown>>(
    `SELECT ${["id", "hostId", "pendingDelete", "protocol", "transport", "security", "profileId", "specVersion", "specJson"].map(q).join(", ")}
       FROM ${q("xray_inbounds")} WHERE ${q("id")} = ? LIMIT 1`,
    [inboundId],
  );
  const row = rows[0];
  if (!row) throw new XrayClientServiceError("INBOUND_NOT_FOUND");
  if (databaseBoolean(row.pendingDelete)) throw new XrayClientServiceError("INBOUND_NOT_FOUND");
  return {
    inboundId,
    hostId: positiveId(row.hostId, "HOST_NOT_FOUND"),
    flow: inboundClientStorageFlow(row),
  };
}

function inboundClientStorageFlow(row: Record<string, unknown>): "xtls-rprx-vision" | "" {
  const definition = resolveStoredXrayInboundDefinition({
    protocol: row.protocol ?? row.inboundProtocol,
    transport: row.transport ?? row.inboundTransport,
    security: row.security ?? row.inboundSecurity,
    profileId: row.profileId ?? row.inboundProfileId,
    specVersion: row.specVersion ?? row.inboundSpecVersion,
    specJson: row.specJson ?? row.inboundSpecJson,
  });
  if (definition?.profile.id === "VLESS_RAW_REALITY_VISION") return "xtls-rprx-vision";
  if (definition?.profile.id === "VLESS_GRPC_REALITY" || definition?.profile.id === "VLESS_XHTTP_REALITY") return "";
  throw new XrayClientServiceError("INVALID_CONFIG_INPUT");
}

async function clientMutationRow(clientId: number): Promise<ClientMutationRow> {
  const q = quoteIdentifier;
  const rows = await queryRaw<ClientMutationRow>(
    `SELECT c.${q("id")} AS ${q("id")}, c.${q("inboundId")} AS ${q("inboundId")},
            i.${q("hostId")} AS ${q("hostId")}, c.${q("name")} AS ${q("name")},
            c.${q("isEnabled")} AS ${q("isEnabled")}, c.${q("pendingDelete")} AS ${q("pendingDelete")},
            i.${q("protocol")} AS ${q("inboundProtocol")}, i.${q("transport")} AS ${q("inboundTransport")},
            i.${q("security")} AS ${q("inboundSecurity")}, i.${q("profileId")} AS ${q("inboundProfileId")},
            i.${q("specVersion")} AS ${q("inboundSpecVersion")}, i.${q("specJson")} AS ${q("inboundSpecJson")}
       FROM ${q("xray_clients")} c
       JOIN ${q("xray_inbounds")} i ON i.${q("id")} = c.${q("inboundId")}
      WHERE c.${q("id")} = ? AND i.${q("pendingDelete")} = ${boolLiteral(false)} LIMIT 1`,
    [clientId],
  );
  if (!rows[0]) throw new XrayClientServiceError("CLIENT_NOT_FOUND");
  return rows[0];
}

async function requireWritableHost(hostId: number) {
  const host = await getHostById(hostId);
  if (!host) throw new XrayClientServiceError("HOST_NOT_FOUND");
  if (!host.isOnline) throw new XrayClientServiceError("HOST_OFFLINE");
  const runtime = await getXrayRuntimeReport(hostId);
  if (!isForwardplusAgentVersionAtLeast(host.agentVersion, host.agentDistribution, AGENT_VERSION) || !runtime || runtime.capabilitySchemaVersion !== 1
    || runtime.supportedOS !== "linux" || (runtime.supportedArch !== "amd64" && runtime.supportedArch !== "arm64")
    || !runtime.supportsArtifactInstall || !runtime.supportsPortProbe || !runtime.supportsRealityScan) {
    throw new XrayClientServiceError("AGENT_CAPABILITY_MISSING");
  }
}

async function activeClientRows(inboundId: number) {
  const q = quoteIdentifier;
  return queryRaw<Record<string, unknown>>(
    `SELECT ${["id", "name", "sortOrder"].map(q).join(", ")}
       FROM ${q("xray_clients")}
      WHERE ${q("inboundId")} = ? AND ${q("pendingDelete")} = ${boolLiteral(false)}
      ORDER BY ${q("sortOrder")} ASC, ${q("id")} ASC`,
    [inboundId],
  );
}

async function assertClientNameAvailable(inboundId: number, name: string, exceptClientId?: number) {
  const identity = name.toLowerCase();
  const rows = await activeClientRows(inboundId);
  if (rows.some((row) => Number(row.id) !== exceptClientId && String(row.name ?? "").trim().toLowerCase() === identity)) {
    throw new XrayClientServiceError("DUPLICATE_CLIENT_NAME");
  }
  return rows;
}

async function finalizeHostConfig(hostId: number, keyring: ReturnType<typeof loadXrayMasterKeyFile>) {
  const generated = await generateXrayHostConfig(hostId, keyring);
  return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
}

function wakeAgent(hostId: number, reason: string) {
  try {
    pushAgentRefresh(hostId, reason, { urgent: true });
  } catch {
    // Heartbeat fallback will deliver the committed desired state.
  }
}

function mapError(error: unknown): never {
  if (error instanceof XrayClientServiceError) throw error;
  if (error instanceof XrayRepositoryError || error instanceof XraySecretUnavailableError) {
    throw new XrayClientServiceError(error.code as XrayClientServiceErrorCode);
  }
  if (error instanceof XrayConfigGenerationError) throw new XrayClientServiceError("INVALID_CONFIG_INPUT");
  throw error;
}

export async function listXrayClients(inboundIdValue: unknown) {
  const inboundId = positiveId(inboundIdValue, "INBOUND_NOT_FOUND");
  if (!await getXrayInbound(inboundId)) throw new XrayClientServiceError("INBOUND_NOT_FOUND");
  return listXrayClientsByInbound(inboundId);
}

export async function createXrayClient(input: {
  inboundId: unknown;
  userId: unknown;
  name: unknown;
  flow: unknown;
  expectedGeneration: unknown;
}) {
  try {
    const inboundId = positiveId(input.inboundId, "INBOUND_NOT_FOUND");
    const userId = positiveId(input.userId, "OPERATION_CONFLICT");
    const name = clientName(input.name);
    const expectedGeneration = generation(input.expectedGeneration);
    const inbound = await inboundMutationRow(inboundId);
    if (input.flow !== inbound.flow) throw new XrayClientServiceError("INVALID_CONFIG_INPUT");
    await requireWritableHost(inbound.hostId);
    const existing = await assertClientNameAvailable(inboundId, name);
    if (existing.length >= MAX_CLIENTS_PER_INBOUND) throw new XrayClientServiceError("CLIENT_LIMIT_REACHED");
    const keyring = loadXrayMasterKeyFile();
    await repairXrayClientFingerprints({ keyring });
    const statsKey = `forwardx-client-${crypto.randomUUID()}`;
    const uuid = crypto.randomUUID();
    const shortId = crypto.randomBytes(8).toString("hex");
    const sortOrder = existing.reduce((maximum, row) => Math.max(maximum, Number(row.sortOrder) || 0), -1) + 1;
    if (!Number.isSafeInteger(sortOrder)) throw new XrayClientServiceError("INVALID_CONFIG_INPUT");
    const created = await createXrayClientConfiguration({
      inboundId,
      expectedGeneration,
      createdByUserId: userId,
      client: {
        name,
        uuidEncrypted: encryptXraySecret(uuid, xrayClientUuidContext(statsKey), keyring),
        uuidFingerprint: fingerprintXraySecret(uuid, xrayClientUuidContext(statsKey), keyring),
        shortIdEncrypted: encryptXraySecret(shortId, xrayClientShortIdContext(statsKey), keyring),
        shortIdFingerprint: fingerprintXraySecret(shortId, xrayClientShortIdContext(statsKey), keyring),
        statsKey,
        flow: inbound.flow,
        isEnabled: true,
        sortOrder,
      },
      precondition: async () => {
        const current = await inboundMutationRow(inboundId);
        if (current.hostId !== inbound.hostId) throw new XrayClientServiceError("INBOUND_NOT_FOUND");
        await requireWritableHost(inbound.hostId);
        const rows = await assertClientNameAvailable(inboundId, name);
        if (rows.length >= MAX_CLIENTS_PER_INBOUND) throw new XrayClientServiceError("CLIENT_LIMIT_REACHED");
      },
      finalize: () => finalizeHostConfig(inbound.hostId, keyring),
    });
    wakeAgent(inbound.hostId, "xray-client-create");
    await recordXrayMutationObservability({
      event: "CLIENT_CREATED",
      resourceType: "xray_client",
      resourceId: created.clientId,
      hostId: inbound.hostId,
      action: "create",
      fields: {
        userId, hostId: inbound.hostId, inboundId, clientId: created.clientId,
        operationId: created.operationId, generation: created.desiredGeneration, status: "QUEUED",
      },
    });
    return created;
  } catch (error) {
    mapError(error);
  }
}

export async function updateXrayClient(input: {
  id: unknown;
  userId: unknown;
  name?: unknown;
  flow?: unknown;
  isEnabled?: unknown;
  expectedGeneration: unknown;
}) {
  try {
    const clientId = positiveId(input.id, "CLIENT_NOT_FOUND");
    const userId = positiveId(input.userId, "OPERATION_CONFLICT");
    const expectedGeneration = generation(input.expectedGeneration);
    const hasName = input.name !== undefined;
    const hasFlow = input.flow !== undefined;
    const hasEnabled = input.isEnabled !== undefined;
    if (!hasName && !hasFlow && !hasEnabled) throw new XrayClientServiceError("INVALID_CONFIG_INPUT");
    if (hasEnabled && typeof input.isEnabled !== "boolean") throw new XrayClientServiceError("INVALID_CONFIG_INPUT");
    const name = hasName ? clientName(input.name) : undefined;
    const current = await clientMutationRow(clientId);
    if (databaseBoolean(current.pendingDelete)) throw new XrayClientServiceError("CLIENT_PENDING_DELETE");
    const currentFlow = inboundClientStorageFlow(current);
    if (hasFlow && input.flow !== currentFlow) throw new XrayClientServiceError("INVALID_CONFIG_INPUT");
    const inboundId = positiveId(current.inboundId, "INBOUND_NOT_FOUND");
    const hostId = positiveId(current.hostId, "HOST_NOT_FOUND");
    await requireWritableHost(hostId);
    if (name) await assertClientNameAvailable(inboundId, name, clientId);
    const keyring = loadXrayMasterKeyFile();
    const patch: { name?: string; flow?: "xtls-rprx-vision" | ""; isEnabled?: boolean } = {};
    if (name !== undefined) patch.name = name;
    if (hasFlow) patch.flow = currentFlow;
    if (hasEnabled) patch.isEnabled = input.isEnabled as boolean;
    const updated = await updateXrayClientConfiguration({
      id: clientId,
      expectedGeneration,
      createdByUserId: userId,
      patch,
      precondition: async () => {
        const latest = await clientMutationRow(clientId);
        if (Number(latest.inboundId) !== inboundId || Number(latest.hostId) !== hostId) {
          throw new XrayClientServiceError("CLIENT_NOT_FOUND");
        }
        if (databaseBoolean(latest.pendingDelete)) throw new XrayClientServiceError("CLIENT_PENDING_DELETE");
        if (inboundClientStorageFlow(latest) !== currentFlow) throw new XrayClientServiceError("INVALID_CONFIG_INPUT");
        await requireWritableHost(hostId);
        if (name) await assertClientNameAvailable(inboundId, name, clientId);
      },
      finalize: () => finalizeHostConfig(hostId, keyring),
    });
    wakeAgent(hostId, "xray-client-update");
    await recordXrayMutationObservability({
      event: "CLIENT_UPDATED",
      resourceType: "xray_client",
      resourceId: clientId,
      hostId,
      action: "update",
      before: { userId, hostId, inboundId, clientId, generation: expectedGeneration, status: "CURRENT" },
      fields: {
        userId, hostId, inboundId, clientId, operationId: updated.operationId,
        generation: updated.desiredGeneration, status: "QUEUED",
      },
    });
    return updated;
  } catch (error) {
    mapError(error);
  }
}

export async function removeXrayClient(input: {
  id: unknown;
  userId: unknown;
  expectedGeneration: unknown;
}) {
  try {
    const clientId = positiveId(input.id, "CLIENT_NOT_FOUND");
    const userId = positiveId(input.userId, "OPERATION_CONFLICT");
    const expectedGeneration = generation(input.expectedGeneration);
    const current = await clientMutationRow(clientId);
    if (databaseBoolean(current.pendingDelete)) throw new XrayClientServiceError("CLIENT_PENDING_DELETE");
    const inboundId = positiveId(current.inboundId, "INBOUND_NOT_FOUND");
    const hostId = positiveId(current.hostId, "HOST_NOT_FOUND");
    await requireWritableHost(hostId);
    const keyring = loadXrayMasterKeyFile();
    const removed = await updateXrayClientConfiguration({
      id: clientId,
      expectedGeneration,
      createdByUserId: userId,
      patch: { pendingDelete: true },
      precondition: async () => {
        const latest = await clientMutationRow(clientId);
        if (Number(latest.inboundId) !== inboundId || Number(latest.hostId) !== hostId) {
          throw new XrayClientServiceError("CLIENT_NOT_FOUND");
        }
        if (databaseBoolean(latest.pendingDelete)) throw new XrayClientServiceError("CLIENT_PENDING_DELETE");
        await requireWritableHost(hostId);
      },
      finalize: () => finalizeHostConfig(hostId, keyring),
    });
    wakeAgent(hostId, "xray-client-remove");
    await recordXrayMutationObservability({
      event: "CLIENT_DELETE_REQUESTED",
      resourceType: "xray_client",
      resourceId: clientId,
      hostId,
      action: "delete",
      before: { userId, hostId, inboundId, clientId, generation: expectedGeneration },
      fields: {
        userId, hostId, inboundId, clientId, operationId: removed.operationId,
        generation: removed.desiredGeneration, status: "QUEUED",
      },
    });
    return { ...removed, pendingDelete: true as const, mayRemainActive: true as const };
  } catch (error) {
    mapError(error);
  }
}

export async function getXrayClientShare(clientIdValue: unknown) {
  try {
    const clientId = positiveId(clientIdValue, "CLIENT_NOT_FOUND");
    const q = quoteIdentifier;
    const rows = await queryRaw<Record<string, unknown>>(
      `SELECT c.${q("id")} AS ${q("clientId")}, c.${q("inboundId")} AS ${q("inboundId")},
              i.${q("publicAddress")} AS ${q("publicAddress")}, i.${q("listenPort")} AS ${q("listenPort")},
              i.${q("realityServerName")} AS ${q("realityServerName")}, i.${q("realityPublicKey")} AS ${q("realityPublicKey")},
              i.${q("fingerprint")} AS ${q("fingerprint")}, i.${q("spiderX")} AS ${q("spiderX")},
              i.${q("protocol")} AS ${q("protocol")}, i.${q("transport")} AS ${q("transport")},
              i.${q("security")} AS ${q("security")}, i.${q("profileId")} AS ${q("profileId")},
              i.${q("specVersion")} AS ${q("specVersion")}, i.${q("specJson")} AS ${q("specJson")},
              i.${q("isEnabled")} AS ${q("inboundEnabled")}, i.${q("pendingDelete")} AS ${q("inboundPendingDelete")}
         FROM ${q("xray_clients")} c
         JOIN ${q("xray_inbounds")} i ON i.${q("id")} = c.${q("inboundId")}
        WHERE c.${q("id")} = ? LIMIT 1`,
      [clientId],
    );
    const row = rows[0];
    if (!row) throw new XrayClientServiceError("CLIENT_NOT_FOUND");
    const access = await loadLegacyVlessAccessEntryByClientId(clientId);
    if (access.inboundId !== positiveId(row.inboundId, "INBOUND_NOT_FOUND")) {
      throw new XrayClientServiceError("SENSITIVE_DATA_UNAVAILABLE");
    }
    const statsKey = access.statsKey;
    const keyring = loadXrayMasterKeyFile();
    const uuid = decryptXraySecret(access.uuidEncrypted, xrayClientUuidContext(statsKey), keyring);
    const shortId = decryptXraySecret(access.shortIdEncrypted, xrayClientShortIdContext(statsKey), keyring);
    const displayName = clientName(access.name);
    let uri: string;
    try {
      const definition = resolveStoredXrayInboundDefinition({
        protocol: row.protocol,
        transport: row.transport,
        security: row.security,
        profileId: row.profileId,
        specVersion: row.specVersion,
        specJson: row.specJson,
      });
      const common = {
        uuid,
        publicAddress: String(row.publicAddress ?? ""),
        listenPort: Number(row.listenPort),
        serverName: String(row.realityServerName ?? ""),
        realityPublicKey: String(row.realityPublicKey ?? ""),
        shortId,
        fingerprint: row.fingerprint as "chrome",
        spiderX: String(row.spiderX ?? ""),
        displayName,
      };
      if (definition?.profile.id === "VLESS_RAW_REALITY_VISION" && access.flow === "xtls-rprx-vision") {
        uri = buildXrayVlessRealityUri({ ...common, transport: "tcp", flow: "xtls-rprx-vision" });
      } else if (definition?.profile.id === "VLESS_GRPC_REALITY" && access.flow === ""
        && typeof definition.spec.serviceName === "string") {
        uri = buildXrayVlessRealityUri({
          ...common,
          transport: "grpc",
          flow: "",
          serviceName: definition.spec.serviceName,
        });
      } else if (definition?.profile.id === "VLESS_XHTTP_REALITY" && access.flow === ""
        && typeof definition.spec.path === "string") {
        uri = buildXrayVlessRealityUri({
          ...common,
          transport: "xhttp",
          flow: "",
          path: definition.spec.path,
        });
      } else {
        throw new Error("Invalid Xray share profile");
      }
    } catch {
      throw new XrayClientServiceError("SENSITIVE_DATA_UNAVAILABLE");
    }
    const detail = await getXrayInboundDetail(positiveId(row.inboundId, "INBOUND_NOT_FOUND"));
    if (!detail) throw new XrayClientServiceError("INBOUND_NOT_FOUND");
    const deploymentStatus = access.pendingDelete || databaseBoolean(row.inboundPendingDelete)
      ? "PENDING_DELETE"
      : !access.isEnabled || !databaseBoolean(row.inboundEnabled)
        ? "DISABLED"
        : detail.deployment.status;
    return { uri, displayName, generatedAt: new Date(), deploymentStatus };
  } catch (error) {
    mapError(error);
  }
}
