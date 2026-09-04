import crypto from "node:crypto";
import {
  accessSecretPolicyForCredentialType,
  parseStoredXrayAccessSettings,
  type XrayAccessCredentialType,
  type XrayAccessSecretKind,
  type XrayInboundSecretKind,
} from "../../shared/xrayAccess";
import { resolveStoredXrayInboundDefinition } from "../../shared/xrayProfiles";
import {
  executeRaw,
  insertAndGetId,
  nowDate,
  queryRaw,
  rawAffectedRows,
  withDatabaseTransaction,
} from "../dbRuntime";
import { boolLiteral, quoteIdentifier } from "../dbCompat";
import { withKeyedTaskLock } from "../keyedTaskLock";
import { inspectXraySecretEnvelope } from "../xraySecretCrypto";
import {
  activateReservedGlobalPortAllocation,
  inspectGlobalPortReferenceAllocation,
  promoteStagedGlobalPortOwningReference,
  releaseGlobalPortReferenceAfterRuntimeCleanup,
  reserveGlobalPortAllocation,
  type GlobalPortReferenceInput,
} from "../globalPortAllocationService";
import {
  toXrayArtifactDto,
  toXrayClientDto,
  toXrayHostDeploymentDto,
  toXrayInboundDto,
  toXrayOperationDto,
  toXrayRuntimeReportDto,
  type XrayArtifactDto,
  type XrayClientDto,
  type XrayHostDeploymentDto,
  type XrayInboundDto,
  type XrayOperationDto,
  type XrayRuntimeReportDto,
} from "../xrayDtos";

export type XrayRepositoryErrorCode =
  | "HOST_NOT_FOUND"
  | "INBOUND_NOT_FOUND"
  | "CLIENT_NOT_FOUND"
  | "CONFIG_GENERATION_CONFLICT"
  | "OPERATION_CONFLICT";

const errorMessages: Record<XrayRepositoryErrorCode, string> = {
  HOST_NOT_FOUND: "Xray host was not found",
  INBOUND_NOT_FOUND: "Xray inbound was not found",
  CLIENT_NOT_FOUND: "Xray client was not found",
  CONFIG_GENERATION_CONFLICT: "Xray configuration generation conflict",
  OPERATION_CONFLICT: "Xray operation conflict",
};

export class XrayRepositoryError extends Error {
  constructor(readonly code: XrayRepositoryErrorCode) {
    super(errorMessages[code]);
    this.name = "XrayRepositoryError";
  }
}

function globalListenerNetwork(networks: readonly string[]): "TCP" | "UDP" | "BOTH" {
  if (networks.length === 1 && networks[0] === "TCP") return "TCP";
  if (networks.length === 1 && networks[0] === "UDP") return "UDP";
  if (networks.length === 2 && networks.includes("TCP") && networks.includes("UDP")) return "BOTH";
  throw new XrayRepositoryError("OPERATION_CONFLICT");
}

function xrayPortReference(input: {
  inboundId: number;
  hostId: number;
  network: "TCP" | "UDP" | "BOTH";
  role: "PUBLIC_LISTENER" | "OWNERSHIP";
}): GlobalPortReferenceInput {
  return {
    resourceType: "XRAY_INBOUND",
    resourceId: input.inboundId,
    hostId: input.hostId,
    network: input.network,
    role: input.role,
    isOwning: true,
  };
}

export type NewXrayInboundRecord = {
  profile?: {
    id: string;
    specVersion: number;
    specJson: string;
  };
  name: string;
  runtimeTag: string;
  publicAddress: string;
  listenAddress: string;
  listenPort: number;
  tlsCertificateId?: number | null;
  realityTargetHost: string;
  realityTargetPort: number;
  realityServerName: string;
  realityPublicKey: string;
  realityPrivateKeyEncrypted: string;
  realityPrivateKeyFingerprint?: string;
  secretKeyVersion: number;
  fingerprint: string;
  spiderX: string;
  isEnabled?: boolean;
};

export type NewXrayClientRecord = {
  name: string;
  uuidEncrypted: string;
  uuidFingerprint: string;
  shortIdEncrypted: string;
  shortIdFingerprint: string;
  statsKey: string;
  flow: string;
  ownerUserId?: number | null;
  isEnabled?: boolean;
  sortOrder?: number;
};

export type NewXrayGenericAccessRecord = {
  name: string;
  credentialType: XrayAccessCredentialType;
  settingsJson: string;
  statsKey: string;
  ownerUserId?: number | null;
  isEnabled?: boolean;
  sortOrder?: number;
  secrets: Array<{
    kind: XrayAccessSecretKind;
    encryptedValue: string;
    fingerprint: string;
  }>;
};

export type NewXrayInboundSecretRecord = {
  kind: XrayInboundSecretKind;
  encryptedValue: string;
  fingerprint: string;
};

export type XrayInboundPatch = Partial<Pick<NewXrayInboundRecord,
  | "name"
  | "publicAddress"
  | "listenAddress"
  | "listenPort"
  | "realityTargetHost"
  | "realityTargetPort"
  | "realityServerName"
  | "realityPublicKey"
  | "realityPrivateKeyEncrypted"
  | "secretKeyVersion"
  | "fingerprint"
  | "spiderX"
  | "isEnabled"
>> & { realityPrivateKeyFingerprint?: string; pendingDelete?: boolean; externalProxyNodeId?: number | null };

export type XrayClientPatch = Partial<Pick<NewXrayClientRecord,
  | "name"
  | "uuidEncrypted"
  | "uuidFingerprint"
  | "shortIdEncrypted"
  | "shortIdFingerprint"
  | "flow"
  | "ownerUserId"
  | "isEnabled"
  | "sortOrder"
>> & { pendingDelete?: boolean };

export type XrayGenericAccessPatch = Partial<Pick<NewXrayGenericAccessRecord,
  "name" | "ownerUserId" | "isEnabled" | "sortOrder"
>> & { pendingDelete?: boolean };

type HostMutationResult<T> = T & {
  operationId: string;
  desiredGeneration: number;
};

type MutationWorkResult<T> = {
  value: T;
  inboundId?: number | null;
  deployment?: XrayMutationDeployment;
};

type XrayMutationDeployment = {
  targetVersion: string;
  desiredConfigHash: string;
};

function positiveId(value: unknown, code: XrayRepositoryErrorCode): number {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) throw new XrayRepositoryError(code);
  return id;
}

function generationValue(value: unknown): number {
  const generation = Number(value);
  if (!Number.isSafeInteger(generation) || generation < 0) {
    throw new XrayRepositoryError("CONFIG_GENERATION_CONFLICT");
  }
  return generation;
}

function newOperationId(value?: string): string {
  const operationId = value ?? crypto.randomUUID();
  if (!/^[A-Za-z0-9._:-]{1,64}$/.test(operationId)) throw new XrayRepositoryError("OPERATION_CONFLICT");
  return operationId;
}

function isUniqueConstraintError(error: unknown): boolean {
  const code = String((error as { code?: unknown })?.code ?? "").toUpperCase();
  const errno = Number((error as { errno?: unknown })?.errno ?? 0);
  return code === "23505"
    || code === "ER_DUP_ENTRY"
    || code.startsWith("SQLITE_CONSTRAINT")
    || errno === 1062;
}

async function hostExists(hostId: number): Promise<boolean> {
  const q = quoteIdentifier;
  const rows = await queryRaw(`SELECT ${q("id")} FROM ${q("hosts")} WHERE ${q("id")} = ? LIMIT 1`, [hostId]);
  return rows.length === 1;
}

async function currentHostGeneration(hostId: number): Promise<{ id: number; generation: number } | null> {
  const q = quoteIdentifier;
  const rows = await queryRaw<{ id: number; desiredGeneration: number }>(
    `SELECT ${q("id")}, ${q("desiredGeneration")} FROM ${q("xray_host_deployments")} WHERE ${q("hostId")} = ? LIMIT 1`,
    [hostId],
  );
  if (!rows[0]) return null;
  return { id: Number(rows[0].id), generation: Number(rows[0].desiredGeneration || 0) };
}

async function runHostConfigurationMutation<T>(input: {
  hostId: number;
  expectedGeneration: number;
  createdByUserId: number;
  operationId?: string;
  work: (nextGeneration: number) => Promise<MutationWorkResult<T>>;
}): Promise<HostMutationResult<T>> {
  const hostId = positiveId(input.hostId, "HOST_NOT_FOUND");
  const createdByUserId = positiveId(input.createdByUserId, "OPERATION_CONFLICT");
  const expectedGeneration = generationValue(input.expectedGeneration);
  const operationId = newOperationId(input.operationId);

  return withKeyedTaskLock(`xray-host:${hostId}`, () => withDatabaseTransaction(async () => {
    if (!await hostExists(hostId)) throw new XrayRepositoryError("HOST_NOT_FOUND");
    const deployment = await currentHostGeneration(hostId);
    const currentGeneration = deployment?.generation ?? 0;
    if (currentGeneration !== expectedGeneration) throw new XrayRepositoryError("CONFIG_GENERATION_CONFLICT");
    const desiredGeneration = currentGeneration + 1;
    if (!Number.isSafeInteger(desiredGeneration)) throw new XrayRepositoryError("CONFIG_GENERATION_CONFLICT");

    const change = await input.work(desiredGeneration);
    const now = nowDate();
    try {
      await insertAndGetId("xray_operations", {
        operationId,
        hostId,
        inboundId: change.inboundId ?? null,
        type: "SYNC",
        requestedGeneration: desiredGeneration,
        status: "QUEUED",
        attemptCount: 0,
        createdByUserId,
        createdAt: now,
        updatedAt: now,
      });
    } catch (error) {
      if (isUniqueConstraintError(error)) throw new XrayRepositoryError("OPERATION_CONFLICT");
      throw error;
    }

    if (deployment) {
      const q = quoteIdentifier;
      const result = change.deployment
        ? await executeRaw(
            `UPDATE ${q("xray_host_deployments")}
                SET ${q("targetVersion")} = ?, ${q("desiredGeneration")} = ?, ${q("desiredConfigHash")} = ?,
                    ${q("lastOperationId")} = ?, ${q("updatedAt")} = ?
              WHERE ${q("id")} = ? AND ${q("desiredGeneration")} = ?`,
            [change.deployment.targetVersion, desiredGeneration, change.deployment.desiredConfigHash,
              operationId, now, deployment.id, currentGeneration],
          )
        : await executeRaw(
            `UPDATE ${q("xray_host_deployments")}
                SET ${q("desiredGeneration")} = ?, ${q("desiredConfigHash")} = NULL,
                    ${q("lastOperationId")} = ?, ${q("updatedAt")} = ?
              WHERE ${q("id")} = ? AND ${q("desiredGeneration")} = ?`,
            [desiredGeneration, operationId, now, deployment.id, currentGeneration],
          );
      if (rawAffectedRows(result) !== 1) throw new XrayRepositoryError("CONFIG_GENERATION_CONFLICT");
    } else {
      try {
        await insertAndGetId("xray_host_deployments", {
          hostId,
          targetVersion: change.deployment?.targetVersion ?? null,
          desiredGeneration,
          desiredConfigHash: change.deployment?.desiredConfigHash ?? null,
          lastOperationId: operationId,
          createdAt: now,
          updatedAt: now,
        });
      } catch (error) {
        if (isUniqueConstraintError(error)) throw new XrayRepositoryError("CONFIG_GENERATION_CONFLICT");
        throw error;
      }
    }
    return { ...change.value, operationId, desiredGeneration };
  }));
}

export async function mutateXrayHostConfigurationResource<T>(input: {
  hostId: number;
  expectedGeneration: number;
  createdByUserId: number;
  precondition?: () => Promise<void>;
  mutate: (desiredGeneration: number) => Promise<T>;
  finalize: (updated: { desiredGeneration: number; value: T }) => Promise<XrayMutationDeployment>;
}): Promise<HostMutationResult<T>> {
  return runHostConfigurationMutation({
    hostId: input.hostId,
    expectedGeneration: input.expectedGeneration,
    createdByUserId: input.createdByUserId,
    work: async (desiredGeneration) => {
      await input.precondition?.();
      const value = await input.mutate(desiredGeneration);
      const deployment = await input.finalize({ desiredGeneration, value });
      return { value, deployment };
    },
  });
}

function inboundProfileInsertValues(profile: NewXrayInboundRecord["profile"]) {
  if (profile === undefined) {
    return { protocol: "vless", transport: "tcp", security: "reality" };
  }
  const storage = profile.id === "VLESS_RAW_REALITY_VISION"
    ? { protocol: "vless", transport: "tcp", security: "reality" }
    : profile.id === "VLESS_GRPC_REALITY"
      ? { protocol: "vless", transport: "grpc", security: "reality" }
    : profile.id === "VLESS_XHTTP_REALITY"
        ? { protocol: "vless", transport: "xhttp", security: "reality" }
      : profile.id === "TROJAN_RAW_REALITY"
        ? { protocol: "trojan", transport: "tcp", security: "reality" }
      : profile.id === "TROJAN_RAW_TLS"
        ? { protocol: "trojan", transport: "tcp", security: "tls" }
      : profile.id === "VLESS_RAW_TLS" || profile.id === "VLESS_RAW_TLS_VISION"
        ? { protocol: "vless", transport: "tcp", security: "tls" }
      : profile.id === "VMESS_RAW_TLS"
        ? { protocol: "vmess", transport: "tcp", security: "tls" }
      : profile.id === "SHADOWSOCKS_2022_RAW_NONE" || profile.id === "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE"
        ? { protocol: "shadowsocks", transport: "tcp", security: "none" }
      : profile.id === "TROJAN_WEBSOCKET_TLS"
        ? { protocol: "trojan", transport: "ws", security: "tls" }
      : profile.id === "VLESS_WEBSOCKET_TLS"
        ? { protocol: "vless", transport: "ws", security: "tls" }
      : profile.id === "TROJAN_GRPC_TLS"
        ? { protocol: "trojan", transport: "grpc", security: "tls" }
      : profile.id === "VLESS_GRPC_TLS"
        ? { protocol: "vless", transport: "grpc", security: "tls" }
      : profile.id === "TROJAN_HTTP_UPGRADE_TLS"
        ? { protocol: "trojan", transport: "httpupgrade", security: "tls" }
      : profile.id === "VLESS_HTTP_UPGRADE_TLS"
        ? { protocol: "vless", transport: "httpupgrade", security: "tls" }
      : profile.id === "TROJAN_XHTTP_TLS"
        ? { protocol: "trojan", transport: "xhttp", security: "tls" }
      : profile.id === "VLESS_XHTTP_TLS"
        ? { protocol: "vless", transport: "xhttp", security: "tls" }
      : profile.id === "TROJAN_MKCP_TLS"
        ? { protocol: "trojan", transport: "kcp", security: "tls" }
      : profile.id === "VLESS_MKCP_TLS"
        ? { protocol: "vless", transport: "kcp", security: "tls" }
      : profile.id === "HYSTERIA2_TLS"
        ? { protocol: "hysteria", transport: "hysteria", security: "tls" }
      : profile.id === "WIREGUARD_UDP_NONE"
        ? { protocol: "wireguard", transport: "none", security: "none" }
      : profile.id === "HTTP_RAW_NONE"
        ? { protocol: "http", transport: "tcp", security: "none" }
      : profile.id === "MIXED_RAW_NONE"
        ? { protocol: "mixed", transport: "tcp", security: "none" }
      : profile.id === "TUNNEL_TCP_LOCAL_NONE"
        ? { protocol: "tunnel", transport: "none", security: "none" }
      : null;
  if (!storage) throw new XrayRepositoryError("OPERATION_CONFLICT");
  const resolved = resolveStoredXrayInboundDefinition({
    ...storage,
    profileId: profile.id,
    specVersion: profile.specVersion,
    specJson: profile.specJson,
  });
  if (!resolved || resolved.profile.id !== profile.id) throw new XrayRepositoryError("OPERATION_CONFLICT");
  return {
    ...storage,
    profileId: resolved.profile.id,
    specVersion: resolved.specVersion,
    specJson: JSON.stringify(resolved.spec),
  };
}

function inboundInsertValues(
  input: NewXrayInboundRecord,
  hostId: number,
  generation: number,
  userId: number,
): Record<string, unknown> & {
  protocol: string;
  transport: string;
  security: string;
  profileId?: unknown;
  specVersion?: unknown;
  specJson?: unknown;
} {
  const now = nowDate();
  return {
    hostId,
    name: input.name,
    runtimeTag: input.runtimeTag,
    publicAddress: input.publicAddress,
    listenAddress: input.listenAddress,
    listenPort: input.listenPort,
    ...inboundProfileInsertValues(input.profile),
    tlsCertificateId: input.tlsCertificateId ?? null,
    realityTargetHost: input.realityTargetHost,
    realityTargetPort: input.realityTargetPort,
    realityServerName: input.realityServerName,
    realityPublicKey: input.realityPublicKey,
    realityPrivateKeyEncrypted: input.realityPrivateKeyEncrypted,
    secretKeyVersion: input.secretKeyVersion,
    fingerprint: input.fingerprint,
    spiderX: input.spiderX,
    isEnabled: input.isEnabled ?? true,
    pendingDelete: false,
    desiredGeneration: generation,
    createdByUserId: userId,
    createdAt: now,
    updatedAt: now,
  };
}

function clientInsertValues(input: NewXrayClientRecord, inboundId: number, generation: number) {
  const now = nowDate();
  return {
    inboundId,
    name: input.name,
    uuidEncrypted: input.uuidEncrypted,
    uuidFingerprint: input.uuidFingerprint,
    shortIdEncrypted: input.shortIdEncrypted,
    shortIdFingerprint: input.shortIdFingerprint,
    statsKey: input.statsKey,
    flow: input.flow,
    ownerUserId: input.ownerUserId ?? null,
    isEnabled: input.isEnabled ?? true,
    pendingDelete: false,
    desiredGeneration: generation,
    sortOrder: input.sortOrder ?? 0,
    createdAt: now,
    updatedAt: now,
  };
}

const VLESS_VISION_ACCESS_SETTINGS_JSON = '{"schemaVersion":1,"flow":"XTLS_RPRX_VISION"}';
const VLESS_NONE_ACCESS_SETTINGS_JSON = '{"schemaVersion":1,"flow":"NONE"}';

function requiredSecretFingerprint(value: string): string {
  if (!/^[0-9a-f]{64}$/.test(value)) throw new XrayRepositoryError("OPERATION_CONFLICT");
  return value;
}

function legacyVlessSettings(flow: string): string {
  if (flow === "xtls-rprx-vision") return VLESS_VISION_ACCESS_SETTINGS_JSON;
  if (flow === "") return VLESS_NONE_ACCESS_SETTINGS_JSON;
  throw new XrayRepositoryError("OPERATION_CONFLICT");
}

async function insertAccessSecret(input: {
  accessEntryId: number;
  kind: "UUID" | "SHORT_ID";
  encryptedValue: string;
  fingerprint: string;
  now: Date;
}) {
  const envelope = inspectXraySecretEnvelope(input.encryptedValue);
  await insertAndGetId("xray_access_secrets", {
    accessEntryId: input.accessEntryId,
    kind: input.kind,
    encryptedValue: input.encryptedValue,
    fingerprint: requiredSecretFingerprint(input.fingerprint),
    keyVersion: envelope.version,
    createdAt: input.now,
    updatedAt: input.now,
  });
}

async function insertClientRecord(input: NewXrayClientRecord, inboundId: number, generation: number) {
  try {
    const clientId = await insertAndGetId("xray_clients", clientInsertValues(input, inboundId, generation));
    const now = nowDate();
    const accessEntryId = await insertAndGetId("xray_access_entries", {
      inboundId,
      legacyClientId: clientId,
      name: input.name,
      credentialType: "UUID_AND_SHORT_ID",
      settingsJson: legacyVlessSettings(input.flow),
      statsKey: input.statsKey,
      ownerUserId: input.ownerUserId ?? null,
      isEnabled: input.isEnabled ?? true,
      pendingDelete: false,
      desiredGeneration: generation,
      sortOrder: input.sortOrder ?? 0,
      createdAt: now,
      updatedAt: now,
    });
    await insertAccessSecret({
      accessEntryId,
      kind: "UUID",
      encryptedValue: input.uuidEncrypted,
      fingerprint: input.uuidFingerprint,
      now,
    });
    await insertAccessSecret({
      accessEntryId,
      kind: "SHORT_ID",
      encryptedValue: input.shortIdEncrypted,
      fingerprint: input.shortIdFingerprint,
      now,
    });
    return clientId;
  } catch (error) {
    if (isUniqueConstraintError(error)) throw new XrayRepositoryError("OPERATION_CONFLICT");
    throw error;
  }
}

async function insertGenericAccessRecord(input: NewXrayGenericAccessRecord, inboundId: number, generation: number) {
  const parsed = parseStoredXrayAccessSettings({ credentialType: input.credentialType, settingsJson: input.settingsJson });
  const policy = accessSecretPolicyForCredentialType(input.credentialType);
  const name = String(input.name ?? "").trim();
  if (!parsed || !policy || parsed.credentialType !== input.credentialType || !name || name.length > 128
    || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(input.statsKey) || !Array.isArray(input.secrets)) {
    throw new XrayRepositoryError("OPERATION_CONFLICT");
  }
  const allowed = new Set([...policy.required, ...policy.optional]);
  const kinds = new Set<XrayAccessSecretKind>();
  for (const secret of input.secrets) {
    if (!allowed.has(secret.kind) || kinds.has(secret.kind)) throw new XrayRepositoryError("OPERATION_CONFLICT");
    inspectXraySecretEnvelope(secret.encryptedValue);
    requiredSecretFingerprint(secret.fingerprint);
    kinds.add(secret.kind);
  }
  if (policy.required.some((kind) => !kinds.has(kind))) throw new XrayRepositoryError("OPERATION_CONFLICT");
  const now = nowDate();
  const accessEntryId = await insertAndGetId("xray_access_entries", {
    inboundId,
    legacyClientId: null,
    name,
    credentialType: parsed.credentialType,
    settingsJson: JSON.stringify(Object.fromEntries(Object.entries(parsed).filter(([key]) => key !== "credentialType"))),
    statsKey: input.statsKey,
    ownerUserId: input.ownerUserId ?? null,
    isEnabled: input.isEnabled ?? true,
    pendingDelete: false,
    desiredGeneration: generation,
    sortOrder: input.sortOrder ?? 0,
    createdAt: now,
    updatedAt: now,
  });
  for (const secret of [...input.secrets].sort((left, right) => left.kind.localeCompare(right.kind))) {
    const envelope = inspectXraySecretEnvelope(secret.encryptedValue);
    await insertAndGetId("xray_access_secrets", {
      accessEntryId,
      kind: secret.kind,
      encryptedValue: secret.encryptedValue,
      fingerprint: requiredSecretFingerprint(secret.fingerprint),
      keyVersion: envelope.version,
      createdAt: now,
      updatedAt: now,
    });
  }
  return accessEntryId;
}

export async function createXrayInboundConfiguration(input: {
  hostId: number;
  expectedGeneration: number;
  createdByUserId: number;
  operationId?: string;
  inbound: NewXrayInboundRecord;
  client?: NewXrayClientRecord;
  clients?: NewXrayClientRecord[];
  genericAccessEntries?: NewXrayGenericAccessRecord[];
  inboundSecrets?: NewXrayInboundSecretRecord[];
  precondition?: () => Promise<void>;
  finalize?: (created: { inboundId: number; clientIds: number[]; accessEntryIds: number[]; desiredGeneration: number }) => Promise<{
    targetVersion: string;
    desiredConfigHash: string;
  }>;
}): Promise<HostMutationResult<{ inboundId: number; clientId: number; clientIds: number[]; accessEntryIds: number[] }>> {
  const initialStorage = inboundProfileInsertValues(input.inbound.profile);
  const initialDefinition = resolveStoredXrayInboundDefinition(initialStorage);
  if (!initialDefinition) throw new XrayRepositoryError("OPERATION_CONFLICT");
  const listenerNetwork = globalListenerNetwork(initialDefinition.profile.listenerNetworks);
  const allocationOwner = { type: "XRAY_INBOUND" as const, stableIdentity: input.inbound.runtimeTag };
  const allocationReservation = await reserveGlobalPortAllocation({
    port: input.inbound.listenPort,
    owner: allocationOwner,
  });
  return runHostConfigurationMutation({
    ...input,
    work: async (generation) => {
      await input.precondition?.();
      const clients = input.clients ?? (input.client ? [input.client] : []);
      const genericAccessEntries = input.genericAccessEntries ?? [];
      const inboundSecrets = input.inboundSecrets ?? [];
      if (clients.length > 0 && genericAccessEntries.length > 0) {
        throw new XrayRepositoryError("OPERATION_CONFLICT");
      }
      const inboundValues = inboundInsertValues(input.inbound, input.hostId, generation, input.createdByUserId);
      const definition = resolveStoredXrayInboundDefinition({
        protocol: inboundValues.protocol,
        transport: inboundValues.transport,
        security: inboundValues.security,
        profileId: inboundValues.profileId,
        specVersion: inboundValues.specVersion,
        specJson: inboundValues.specJson,
      });
      if (!definition) throw new XrayRepositoryError("OPERATION_CONFLICT");
      if (definition.profile.clientCredentialType === "NONE") {
        if (definition.profile.id !== "TUNNEL_TCP_LOCAL_NONE"
          || clients.length !== 0 || genericAccessEntries.length !== 0) {
          throw new XrayRepositoryError("OPERATION_CONFLICT");
        }
      } else if (definition.profile.clientCredentialType === "UUID_AND_SHORT_ID") {
        const expectedFlow = definition.profile.clientFlow === "XTLS_RPRX_VISION" ? "xtls-rprx-vision" : "";
        if (clients.length < 1 || genericAccessEntries.length > 0
          || clients.some((client) => client.flow !== expectedFlow)) {
          throw new XrayRepositoryError("OPERATION_CONFLICT");
        }
      } else {
        if (clients.length > 0 || genericAccessEntries.length < 1) throw new XrayRepositoryError("OPERATION_CONFLICT");
        for (const access of genericAccessEntries) {
          const settings = parseStoredXrayAccessSettings({
            credentialType: access.credentialType,
            settingsJson: access.settingsJson,
          });
          if (!settings || settings.credentialType !== definition.profile.clientCredentialType) {
            throw new XrayRepositoryError("OPERATION_CONFLICT");
          }
          if (definition.profile.clientCredentialType === "UUID"
            && settings.credentialType === "UUID") {
            const validSettings = definition.profile.id === "VMESS_RAW_TLS"
              ? settings.schemaVersion === 1 && settings.flow === "NONE" && settings.security === "AUTO"
              : settings.schemaVersion === 2 && settings.protocol === "VLESS"
                && settings.encryption === "NONE" && settings.flow === definition.profile.clientFlow;
            if (!validSettings) throw new XrayRepositoryError("OPERATION_CONFLICT");
          }
          if (definition.profile.clientCredentialType === "PASSWORD") {
            const kinds = new Set(access.secrets.map((secret) => secret.kind));
            const requiresShortId = definition.profile.security === "REALITY";
            if (settings.credentialType !== "PASSWORD" || settings.schemaVersion !== 1
              || kinds.has("SHORT_ID") !== requiresShortId) {
              throw new XrayRepositoryError("OPERATION_CONFLICT");
            }
          }
          if (definition.profile.id === "WIREGUARD_UDP_NONE"
            && (settings.credentialType !== "WIREGUARD_PEER" || settings.schemaVersion !== 2)) {
            throw new XrayRepositoryError("OPERATION_CONFLICT");
          }
          if (definition.profile.id === "HTTP_RAW_NONE"
            && (settings.credentialType !== "HTTP_BASIC" || settings.schemaVersion !== 1)) {
            throw new XrayRepositoryError("OPERATION_CONFLICT");
          }
          if (definition.profile.id === "MIXED_RAW_NONE"
            && (settings.credentialType !== "MIXED_USER_PASSWORD" || settings.schemaVersion !== 1)) {
            throw new XrayRepositoryError("OPERATION_CONFLICT");
          }
        }
      }
      if (definition.profile.security === "TLS") {
        const certificateId = positiveId(input.inbound.tlsCertificateId, "OPERATION_CONFLICT");
        inboundValues.tlsCertificateId = certificateId;
        const q = quoteIdentifier;
        const certificateRows = await queryRaw<{ hostId: unknown }>(
          `SELECT ${q("hostId")} FROM ${q("xray_tls_certificates")} WHERE ${q("id")} = ? LIMIT 1`,
          [certificateId],
        );
        if (Number(certificateRows[0]?.hostId) !== input.hostId
          || input.inbound.realityTargetHost !== "" || input.inbound.realityTargetPort !== 443
          || input.inbound.realityPublicKey !== "" || input.inbound.realityPrivateKeyEncrypted !== ""
          || input.inbound.realityPrivateKeyFingerprint !== undefined
          || input.inbound.fingerprint !== "chrome" || input.inbound.spiderX !== "/"
          || inboundSecrets.length !== 0) {
          throw new XrayRepositoryError("OPERATION_CONFLICT");
        }
      } else if (definition.profile.security === "REALITY") {
        if (input.inbound.tlsCertificateId !== undefined && input.inbound.tlsCertificateId !== null) {
          throw new XrayRepositoryError("OPERATION_CONFLICT");
        }
        if (inboundSecrets.length !== 0) throw new XrayRepositoryError("OPERATION_CONFLICT");
      } else if (definition.profile.id === "SHADOWSOCKS_2022_RAW_NONE"
        || definition.profile.id === "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE") {
        if ((input.inbound.tlsCertificateId !== undefined && input.inbound.tlsCertificateId !== null)
          || input.inbound.realityTargetHost !== "" || input.inbound.realityTargetPort !== 443
          || input.inbound.realityServerName !== "" || input.inbound.realityPublicKey !== ""
          || input.inbound.realityPrivateKeyEncrypted !== "" || input.inbound.realityPrivateKeyFingerprint !== undefined
          || input.inbound.fingerprint !== "chrome" || input.inbound.spiderX !== "/"
          || inboundSecrets.length !== 1 || inboundSecrets[0].kind !== "SHADOWSOCKS_SERVER_KEY") {
          throw new XrayRepositoryError("OPERATION_CONFLICT");
        }
        const envelope = inspectXraySecretEnvelope(inboundSecrets[0].encryptedValue);
        requiredSecretFingerprint(inboundSecrets[0].fingerprint);
        if (input.inbound.secretKeyVersion !== envelope.version) throw new XrayRepositoryError("OPERATION_CONFLICT");
      } else if (definition.profile.id === "WIREGUARD_UDP_NONE") {
        if ((input.inbound.tlsCertificateId !== undefined && input.inbound.tlsCertificateId !== null)
          || input.inbound.realityTargetHost !== "" || input.inbound.realityTargetPort !== 443
          || input.inbound.realityServerName !== "" || input.inbound.realityPublicKey !== ""
          || input.inbound.realityPrivateKeyEncrypted !== "" || input.inbound.realityPrivateKeyFingerprint !== undefined
          || input.inbound.fingerprint !== "chrome" || input.inbound.spiderX !== "/"
          || inboundSecrets.length !== 1 || inboundSecrets[0].kind !== "PRIVATE_KEY") {
          throw new XrayRepositoryError("OPERATION_CONFLICT");
        }
        const envelope = inspectXraySecretEnvelope(inboundSecrets[0].encryptedValue);
        requiredSecretFingerprint(inboundSecrets[0].fingerprint);
        if (input.inbound.secretKeyVersion !== envelope.version) throw new XrayRepositoryError("OPERATION_CONFLICT");
      } else if (definition.profile.id === "HTTP_RAW_NONE" || definition.profile.id === "MIXED_RAW_NONE") {
        if ((input.inbound.tlsCertificateId !== undefined && input.inbound.tlsCertificateId !== null)
          || input.inbound.realityTargetHost !== "" || input.inbound.realityTargetPort !== 443
          || input.inbound.realityServerName !== "" || input.inbound.realityPublicKey !== ""
          || input.inbound.realityPrivateKeyEncrypted !== "" || input.inbound.realityPrivateKeyFingerprint !== undefined
          || input.inbound.fingerprint !== "chrome" || input.inbound.spiderX !== "/"
          || inboundSecrets.length !== 0) {
          throw new XrayRepositoryError("OPERATION_CONFLICT");
        }
      } else if (definition.profile.id === "TUNNEL_TCP_LOCAL_NONE") {
        if ((input.inbound.tlsCertificateId !== undefined && input.inbound.tlsCertificateId !== null)
          || input.inbound.publicAddress !== "127.0.0.1" || input.inbound.listenAddress !== "127.0.0.1"
          || input.inbound.realityTargetHost !== "" || input.inbound.realityTargetPort !== 443
          || input.inbound.realityServerName !== "" || input.inbound.realityPublicKey !== ""
          || input.inbound.realityPrivateKeyEncrypted !== "" || input.inbound.realityPrivateKeyFingerprint !== undefined
          || input.inbound.secretKeyVersion !== 1
          || input.inbound.fingerprint !== "chrome" || input.inbound.spiderX !== "/"
          || inboundSecrets.length !== 0 || clients.length !== 0 || genericAccessEntries.length !== 0) {
          throw new XrayRepositoryError("OPERATION_CONFLICT");
        }
      } else {
        throw new XrayRepositoryError("OPERATION_CONFLICT");
      }
      const inboundId = await insertAndGetId(
        "xray_inbounds",
        inboundValues,
      );
      await activateReservedGlobalPortAllocation({
        allocationId: allocationReservation.allocationId,
        expectedVersion: allocationReservation.version,
        owner: allocationOwner,
        reservationToken: allocationReservation.reservationToken,
        references: [xrayPortReference({
          inboundId,
          hostId: input.hostId,
          network: listenerNetwork,
          role: "PUBLIC_LISTENER",
        })],
      });
      if (definition.profile.security === "REALITY") {
        const privateEnvelope = inspectXraySecretEnvelope(input.inbound.realityPrivateKeyEncrypted);
        await insertAndGetId("xray_inbound_secrets", {
          inboundId,
          kind: "REALITY_PRIVATE_KEY",
          encryptedValue: input.inbound.realityPrivateKeyEncrypted,
          fingerprint: requiredSecretFingerprint(input.inbound.realityPrivateKeyFingerprint ?? ""),
          keyVersion: privateEnvelope.version,
          createdAt: nowDate(),
          updatedAt: nowDate(),
        });
      } else {
        for (const secret of inboundSecrets) {
          const envelope = inspectXraySecretEnvelope(secret.encryptedValue);
          await insertAndGetId("xray_inbound_secrets", {
            inboundId,
            kind: secret.kind,
            encryptedValue: secret.encryptedValue,
            fingerprint: requiredSecretFingerprint(secret.fingerprint),
            keyVersion: envelope.version,
            createdAt: nowDate(),
            updatedAt: nowDate(),
          });
        }
      }
      const clientIds: number[] = [];
      for (const client of clients) {
        clientIds.push(await insertClientRecord(client, inboundId, generation));
      }
      const accessEntryIds: number[] = [];
      for (const access of genericAccessEntries) {
        accessEntryIds.push(await insertGenericAccessRecord(access, inboundId, generation));
      }
      const deployment = await input.finalize?.({ inboundId, clientIds, accessEntryIds, desiredGeneration: generation });
      return { value: { inboundId, clientId: clientIds[0], clientIds, accessEntryIds }, inboundId, deployment };
    },
  });
}

async function inboundHostId(inboundId: number): Promise<number> {
  const q = quoteIdentifier;
  const rows = await queryRaw<{ hostId: number }>(
    `SELECT ${q("hostId")} FROM ${q("xray_inbounds")} WHERE ${q("id")} = ? LIMIT 1`,
    [inboundId],
  );
  if (!rows[0]) throw new XrayRepositoryError("INBOUND_NOT_FOUND");
  return Number(rows[0].hostId);
}

async function inboundGlobalPortIdentity(inboundId: number): Promise<{
  hostId: number;
  runtimeTag: string;
  listenPort: number;
  network: "TCP" | "UDP" | "BOTH";
}> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Record<string, unknown>>(
    `SELECT ${["hostId", "runtimeTag", "listenPort", "protocol", "transport", "security", "profileId", "specVersion", "specJson"].map(q).join(", ")}
       FROM ${q("xray_inbounds")} WHERE ${q("id")} = ? LIMIT 1`,
    [inboundId],
  );
  const row = rows[0];
  if (!row) throw new XrayRepositoryError("INBOUND_NOT_FOUND");
  const definition = resolveStoredXrayInboundDefinition(row);
  const hostId = positiveId(row.hostId, "HOST_NOT_FOUND");
  const listenPort = Number(row.listenPort);
  if (!definition || !Number.isSafeInteger(listenPort) || listenPort < 1 || listenPort > 65_535) {
    throw new XrayRepositoryError("OPERATION_CONFLICT");
  }
  const runtimeTag = String(row.runtimeTag ?? "");
  if (!runtimeTag) throw new XrayRepositoryError("OPERATION_CONFLICT");
  return {
    hostId,
    runtimeTag,
    listenPort,
    network: globalListenerNetwork(definition.profile.listenerNetworks),
  };
}

async function updateRecord(table: string, id: number, values: Record<string, unknown>) {
  const q = quoteIdentifier;
  const columns = Object.keys(values);
  const result = await executeRaw(
    `UPDATE ${q(table)} SET ${columns.map((column) => `${q(column)} = ?`).join(", ")} WHERE ${q("id")} = ?`,
    [...columns.map((column) => values[column]), id],
  );
  return rawAffectedRows(result);
}

function inboundPatchValues(patch: XrayInboundPatch, generation: number): Record<string, unknown> {
  const values: Record<string, unknown> = {};
  for (const key of [
    "name", "publicAddress", "listenAddress", "listenPort", "realityTargetHost", "realityTargetPort",
    "realityServerName", "realityPublicKey", "realityPrivateKeyEncrypted", "secretKeyVersion", "fingerprint",
    "spiderX", "isEnabled", "pendingDelete", "externalProxyNodeId",
  ] as const) {
    if (patch[key] !== undefined) values[key] = patch[key];
  }
  if (Object.keys(values).length === 0) throw new XrayRepositoryError("OPERATION_CONFLICT");
  return { ...values, desiredGeneration: generation, updatedAt: nowDate() };
}

async function syncInboundSecretPatch(inboundId: number, patch: XrayInboundPatch) {
  const hasEnvelope = patch.realityPrivateKeyEncrypted !== undefined;
  const hasFingerprint = patch.realityPrivateKeyFingerprint !== undefined;
  if (hasEnvelope !== hasFingerprint) throw new XrayRepositoryError("OPERATION_CONFLICT");
  if (!hasEnvelope) return;
  const encryptedValue = patch.realityPrivateKeyEncrypted as string;
  const fingerprint = requiredSecretFingerprint(patch.realityPrivateKeyFingerprint as string);
  const envelope = inspectXraySecretEnvelope(encryptedValue);
  const q = quoteIdentifier;
  const result = await executeRaw(
    `UPDATE ${q("xray_inbound_secrets")}
        SET ${q("encryptedValue")} = ?, ${q("fingerprint")} = ?, ${q("keyVersion")} = ?, ${q("updatedAt")} = ?
      WHERE ${q("inboundId")} = ? AND ${q("kind")} = ?`,
    [encryptedValue, fingerprint, envelope.version, nowDate(), inboundId, "REALITY_PRIVATE_KEY"],
  );
  if (rawAffectedRows(result) !== 1) throw new XrayRepositoryError("OPERATION_CONFLICT");
}

export async function updateXrayInboundConfiguration(input: {
  id: number;
  expectedGeneration: number;
  createdByUserId: number;
  operationId?: string;
  patch: XrayInboundPatch;
  precondition?: () => Promise<void>;
  finalize?: (updated: { inboundId: number; desiredGeneration: number }) => Promise<XrayMutationDeployment>;
}): Promise<HostMutationResult<{ inboundId: number }>> {
  const inboundId = positiveId(input.id, "INBOUND_NOT_FOUND");
  const identity = await inboundGlobalPortIdentity(inboundId);
  const hostId = identity.hostId;
  const nextPort = input.patch.listenPort === undefined ? identity.listenPort : Number(input.patch.listenPort);
  const portChanged = nextPort !== identity.listenPort;
  const allocationOwner = { type: "XRAY_INBOUND" as const, stableIdentity: identity.runtimeTag };
  const allocationReservation = portChanged
    ? await reserveGlobalPortAllocation({ port: nextPort, owner: allocationOwner })
    : null;
  return runHostConfigurationMutation({
    hostId,
    expectedGeneration: input.expectedGeneration,
    createdByUserId: input.createdByUserId,
    operationId: input.operationId,
    work: async (generation) => {
      await input.precondition?.();
      if (await inboundHostId(inboundId) !== hostId) throw new XrayRepositoryError("INBOUND_NOT_FOUND");
      if (await updateRecord("xray_inbounds", inboundId, inboundPatchValues(input.patch, generation)) !== 1) {
        throw new XrayRepositoryError("INBOUND_NOT_FOUND");
      }
      if (allocationReservation) {
        await activateReservedGlobalPortAllocation({
          allocationId: allocationReservation.allocationId,
          expectedVersion: allocationReservation.version,
          owner: allocationOwner,
          reservationToken: allocationReservation.reservationToken,
          references: [xrayPortReference({
            inboundId,
            hostId,
            network: identity.network,
            role: "OWNERSHIP",
          })],
        });
      }
      await syncInboundSecretPatch(inboundId, input.patch);
      const deployment = await input.finalize?.({ inboundId, desiredGeneration: generation });
      return { value: { inboundId }, inboundId, deployment };
    },
  });
}

export async function createXrayClientConfiguration(input: {
  inboundId: number;
  expectedGeneration: number;
  createdByUserId: number;
  operationId?: string;
  client: NewXrayClientRecord;
  precondition?: () => Promise<void>;
  finalize?: (created: { inboundId: number; clientId: number; desiredGeneration: number }) => Promise<XrayMutationDeployment>;
}): Promise<HostMutationResult<{ inboundId: number; clientId: number }>> {
  const inboundId = positiveId(input.inboundId, "INBOUND_NOT_FOUND");
  const hostId = await inboundHostId(inboundId);
  return runHostConfigurationMutation({
    hostId,
    expectedGeneration: input.expectedGeneration,
    createdByUserId: input.createdByUserId,
    operationId: input.operationId,
    work: async (generation) => {
      await input.precondition?.();
      if (await inboundHostId(inboundId) !== hostId) throw new XrayRepositoryError("INBOUND_NOT_FOUND");
      const clientId = await insertClientRecord(input.client, inboundId, generation);
      const deployment = await input.finalize?.({ inboundId, clientId, desiredGeneration: generation });
      return { value: { inboundId, clientId }, inboundId, deployment };
    },
  });
}

async function clientLocation(clientId: number): Promise<{ inboundId: number; hostId: number }> {
  const q = quoteIdentifier;
  const rows = await queryRaw<{ inboundId: number; hostId: number }>(
    `SELECT c.${q("inboundId")} AS ${q("inboundId")}, i.${q("hostId")} AS ${q("hostId")}
       FROM ${q("xray_clients")} c
       JOIN ${q("xray_inbounds")} i ON i.${q("id")} = c.${q("inboundId")}
      WHERE c.${q("id")} = ? LIMIT 1`,
    [clientId],
  );
  if (!rows[0]) throw new XrayRepositoryError("CLIENT_NOT_FOUND");
  return { inboundId: Number(rows[0].inboundId), hostId: Number(rows[0].hostId) };
}

function clientPatchValues(patch: XrayClientPatch, generation: number): Record<string, unknown> {
  const values: Record<string, unknown> = {};
  for (const key of [
    "name", "uuidEncrypted", "uuidFingerprint", "shortIdEncrypted", "shortIdFingerprint", "flow",
    "ownerUserId", "isEnabled", "sortOrder", "pendingDelete",
  ] as const) {
    if (patch[key] !== undefined) values[key] = patch[key];
  }
  if (Object.keys(values).length === 0) throw new XrayRepositoryError("OPERATION_CONFLICT");
  return { ...values, desiredGeneration: generation, updatedAt: nowDate() };
}

async function accessEntryIdForLegacyClient(clientId: number): Promise<number> {
  const q = quoteIdentifier;
  const rows = await queryRaw<{ id: unknown }>(
    `SELECT ${q("id")} FROM ${q("xray_access_entries")} WHERE ${q("legacyClientId")} = ? LIMIT 1`,
    [clientId],
  );
  if (!rows[0]) throw new XrayRepositoryError("OPERATION_CONFLICT");
  return positiveId(rows[0].id, "OPERATION_CONFLICT");
}

async function syncAccessSecretPatch(input: {
  accessEntryId: number;
  kind: "UUID" | "SHORT_ID";
  encryptedValue?: string;
  fingerprint?: string;
}) {
  const hasEnvelope = input.encryptedValue !== undefined;
  const hasFingerprint = input.fingerprint !== undefined;
  if (hasEnvelope !== hasFingerprint) throw new XrayRepositoryError("OPERATION_CONFLICT");
  if (!hasEnvelope) return;
  const envelope = inspectXraySecretEnvelope(input.encryptedValue as string);
  const q = quoteIdentifier;
  const result = await executeRaw(
    `UPDATE ${q("xray_access_secrets")}
        SET ${q("encryptedValue")} = ?, ${q("fingerprint")} = ?, ${q("keyVersion")} = ?, ${q("updatedAt")} = ?
      WHERE ${q("accessEntryId")} = ? AND ${q("kind")} = ?`,
    [input.encryptedValue, requiredSecretFingerprint(input.fingerprint as string), envelope.version,
      nowDate(), input.accessEntryId, input.kind],
  );
  if (rawAffectedRows(result) !== 1) throw new XrayRepositoryError("OPERATION_CONFLICT");
}

async function syncAccessEntryPatch(clientId: number, patch: XrayClientPatch, generation: number) {
  const accessEntryId = await accessEntryIdForLegacyClient(clientId);
  const values: Record<string, unknown> = { desiredGeneration: generation, updatedAt: nowDate() };
  for (const key of ["name", "ownerUserId", "isEnabled", "sortOrder", "pendingDelete"] as const) {
    if (patch[key] !== undefined) values[key] = patch[key];
  }
  if (patch.flow !== undefined) values.settingsJson = legacyVlessSettings(patch.flow);
  if (await updateRecord("xray_access_entries", accessEntryId, values) !== 1) {
    throw new XrayRepositoryError("OPERATION_CONFLICT");
  }
  await syncAccessSecretPatch({
    accessEntryId,
    kind: "UUID",
    encryptedValue: patch.uuidEncrypted,
    fingerprint: patch.uuidFingerprint,
  });
  await syncAccessSecretPatch({
    accessEntryId,
    kind: "SHORT_ID",
    encryptedValue: patch.shortIdEncrypted,
    fingerprint: patch.shortIdFingerprint,
  });
}

export async function updateXrayClientConfiguration(input: {
  id: number;
  expectedGeneration: number;
  createdByUserId: number;
  operationId?: string;
  patch: XrayClientPatch;
  precondition?: () => Promise<void>;
  finalize?: (updated: { inboundId: number; clientId: number; desiredGeneration: number }) => Promise<XrayMutationDeployment>;
}): Promise<HostMutationResult<{ inboundId: number; clientId: number }>> {
  const clientId = positiveId(input.id, "CLIENT_NOT_FOUND");
  const location = await clientLocation(clientId);
  return runHostConfigurationMutation({
    hostId: location.hostId,
    expectedGeneration: input.expectedGeneration,
    createdByUserId: input.createdByUserId,
    operationId: input.operationId,
    work: async (generation) => {
      await input.precondition?.();
      const current = await clientLocation(clientId);
      if (current.hostId !== location.hostId || current.inboundId !== location.inboundId) {
        throw new XrayRepositoryError("CLIENT_NOT_FOUND");
      }
      if (await updateRecord("xray_clients", clientId, clientPatchValues(input.patch, generation)) !== 1) {
        throw new XrayRepositoryError("CLIENT_NOT_FOUND");
      }
      await syncAccessEntryPatch(clientId, input.patch, generation);
      const deployment = await input.finalize?.({
        inboundId: location.inboundId,
        clientId,
        desiredGeneration: generation,
      });
      return { value: { inboundId: location.inboundId, clientId }, inboundId: location.inboundId, deployment };
    },
  });
}

async function genericAccessLocation(accessEntryId: number): Promise<{ inboundId: number; hostId: number }> {
  const q = quoteIdentifier;
  const rows = await queryRaw<{ inboundId: unknown; hostId: unknown }>(
    `SELECT a.${q("inboundId")} AS ${q("inboundId")}, i.${q("hostId")} AS ${q("hostId")}
       FROM ${q("xray_access_entries")} a
       JOIN ${q("xray_inbounds")} i ON i.${q("id")} = a.${q("inboundId")}
      WHERE a.${q("id")} = ? AND a.${q("legacyClientId")} IS NULL LIMIT 1`,
    [accessEntryId],
  );
  if (!rows[0]) throw new XrayRepositoryError("CLIENT_NOT_FOUND");
  return {
    inboundId: positiveId(rows[0].inboundId, "INBOUND_NOT_FOUND"),
    hostId: positiveId(rows[0].hostId, "HOST_NOT_FOUND"),
  };
}

export async function createXrayGenericAccessConfiguration(input: {
  inboundId: number;
  expectedGeneration: number;
  createdByUserId: number;
  operationId?: string;
  access: NewXrayGenericAccessRecord | ((context: {
    desiredGeneration: number;
  }) => Promise<NewXrayGenericAccessRecord>);
  precondition?: () => Promise<void>;
  finalize?: (created: { inboundId: number; accessEntryId: number; desiredGeneration: number }) => Promise<XrayMutationDeployment>;
}): Promise<HostMutationResult<{ inboundId: number; accessEntryId: number }>> {
  const inboundId = positiveId(input.inboundId, "INBOUND_NOT_FOUND");
  const hostId = await inboundHostId(inboundId);
  return runHostConfigurationMutation({
    hostId,
    expectedGeneration: input.expectedGeneration,
    createdByUserId: input.createdByUserId,
    operationId: input.operationId,
    work: async (generation) => {
      await input.precondition?.();
      if (await inboundHostId(inboundId) !== hostId) throw new XrayRepositoryError("INBOUND_NOT_FOUND");
      const access = typeof input.access === "function"
        ? await input.access({ desiredGeneration: generation })
        : input.access;
      const accessEntryId = await insertGenericAccessRecord(access, inboundId, generation);
      const deployment = await input.finalize?.({ inboundId, accessEntryId, desiredGeneration: generation });
      return { value: { inboundId, accessEntryId }, inboundId, deployment };
    },
  });
}

function genericAccessPatchValues(patch: XrayGenericAccessPatch, generation: number) {
  const values: Record<string, unknown> = {};
  for (const key of ["name", "ownerUserId", "isEnabled", "sortOrder", "pendingDelete"] as const) {
    if (patch[key] !== undefined) values[key] = patch[key];
  }
  if (Object.keys(values).length === 0) throw new XrayRepositoryError("OPERATION_CONFLICT");
  return { ...values, desiredGeneration: generation, updatedAt: nowDate() };
}

export async function updateXrayGenericAccessConfiguration(input: {
  id: number;
  expectedGeneration: number;
  createdByUserId: number;
  operationId?: string;
  patch: XrayGenericAccessPatch;
  precondition?: () => Promise<void>;
  finalize?: (updated: { inboundId: number; accessEntryId: number; desiredGeneration: number }) => Promise<XrayMutationDeployment>;
}): Promise<HostMutationResult<{ inboundId: number; accessEntryId: number }>> {
  const accessEntryId = positiveId(input.id, "CLIENT_NOT_FOUND");
  const location = await genericAccessLocation(accessEntryId);
  return runHostConfigurationMutation({
    hostId: location.hostId,
    expectedGeneration: input.expectedGeneration,
    createdByUserId: input.createdByUserId,
    operationId: input.operationId,
    work: async (generation) => {
      await input.precondition?.();
      const current = await genericAccessLocation(accessEntryId);
      if (current.hostId !== location.hostId || current.inboundId !== location.inboundId) {
        throw new XrayRepositoryError("CLIENT_NOT_FOUND");
      }
      if (await updateRecord("xray_access_entries", accessEntryId, genericAccessPatchValues(input.patch, generation)) !== 1) {
        throw new XrayRepositoryError("CLIENT_NOT_FOUND");
      }
      const deployment = await input.finalize?.({
        inboundId: location.inboundId,
        accessEntryId,
        desiredGeneration: generation,
      });
      return { value: { inboundId: location.inboundId, accessEntryId }, inboundId: location.inboundId, deployment };
    },
  });
}

async function deleteGenericAccessEntryIds(accessEntryIds: number[]) {
  if (accessEntryIds.length === 0) return;
  const q = quoteIdentifier;
  const accessPlaceholders = accessEntryIds.map(() => "?").join(", ");
  await executeRaw(
    `DELETE FROM ${q("xray_access_secrets")} WHERE ${q("accessEntryId")} IN (${accessPlaceholders})`,
    accessEntryIds,
  );
  await executeRaw(
    `DELETE FROM ${q("xray_access_entries")} WHERE ${q("id")} IN (${accessPlaceholders})`,
    accessEntryIds,
  );
}

async function deleteGenericAccessEntriesBy(column: "inboundId" | "legacyClientId", ids: number[]) {
  if (ids.length === 0) return;
  const q = quoteIdentifier;
  const placeholders = ids.map(() => "?").join(", ");
  const rows = await queryRaw<{ id: unknown }>(
    `SELECT ${q("id")} FROM ${q("xray_access_entries")} WHERE ${q(column)} IN (${placeholders})`,
    ids,
  );
  const accessEntryIds = rows.map((row) => positiveId(row.id, "OPERATION_CONFLICT"));
  await deleteGenericAccessEntryIds(accessEntryIds);
}

export async function reconcileAppliedXrayInboundGlobalPortsWithinHostLock(
  hostIdValue: unknown,
  appliedGenerationValue: unknown,
) {
  const hostId = positiveId(hostIdValue, "HOST_NOT_FOUND");
  const appliedGeneration = generationValue(appliedGenerationValue);
  const q = quoteIdentifier;
  return withDatabaseTransaction(async () => {
    const rows = await queryRaw<{ id: unknown }>(
      `SELECT ${q("id")} FROM ${q("xray_inbounds")}
        WHERE ${q("hostId")} = ? AND ${q("pendingDelete")} = ${boolLiteral(false)}
          AND ${q("desiredGeneration")} <= ? ORDER BY ${q("id")} ASC`,
      [hostId, appliedGeneration],
    );
    let promotedCount = 0;
    for (const row of rows) {
      const inboundId = positiveId(row.id, "INBOUND_NOT_FOUND");
      const identity = await inboundGlobalPortIdentity(inboundId);
      const stagedReference = xrayPortReference({
        inboundId,
        hostId,
        network: identity.network,
        role: "OWNERSHIP",
      });
      const staged = await inspectGlobalPortReferenceAllocation(stagedReference);
      if (!staged) continue;
      if (staged.port !== identity.listenPort) throw new XrayRepositoryError("OPERATION_CONFLICT");
      const publicReference = xrayPortReference({
        inboundId,
        hostId,
        network: identity.network,
        role: "PUBLIC_LISTENER",
      });
      const publicAllocation = await inspectGlobalPortReferenceAllocation(publicReference);
      if (!publicAllocation || publicAllocation.port === identity.listenPort) {
        throw new XrayRepositoryError("OPERATION_CONFLICT");
      }
      await promoteStagedGlobalPortOwningReference({
        owner: { type: "XRAY_INBOUND", stableIdentity: identity.runtimeTag },
        publicReference,
        stagedReference,
      });
      promotedCount += 1;
    }
    return promotedCount;
  });
}

export async function deleteAppliedPendingXrayRecordsWithinHostLock(hostIdValue: unknown, appliedGenerationValue: unknown) {
  const hostId = positiveId(hostIdValue, "HOST_NOT_FOUND");
  const appliedGeneration = generationValue(appliedGenerationValue);
  const q = quoteIdentifier;
  return withDatabaseTransaction(async () => {
    const inboundRows = await queryRaw<{ id: number }>(
      `SELECT ${q("id")} FROM ${q("xray_inbounds")}
        WHERE ${q("hostId")} = ? AND ${q("pendingDelete")} = ${boolLiteral(true)} AND ${q("desiredGeneration")} <= ?
        ORDER BY ${q("id")} ASC`,
      [hostId, appliedGeneration],
    );
    const inboundIds = inboundRows.map((row) => Number(row.id)).filter((id) => Number.isSafeInteger(id) && id > 0);
    let clientCount = 0;
    for (let offset = 0; offset < inboundIds.length; offset += 100) {
      const chunk = inboundIds.slice(offset, offset + 100);
      for (const inboundId of chunk) {
        const identity = await inboundGlobalPortIdentity(inboundId);
        for (const role of ["PUBLIC_LISTENER", "OWNERSHIP"] as const) {
          await releaseGlobalPortReferenceAfterRuntimeCleanup({
            reference: xrayPortReference({
              inboundId,
              hostId,
              network: identity.network,
              role,
            }),
          });
        }
      }
      await deleteGenericAccessEntriesBy("inboundId", chunk);
      await executeRaw(
        `DELETE FROM ${q("xray_inbound_secrets")} WHERE ${q("inboundId")} IN (${chunk.map(() => "?").join(", ")})`,
        chunk,
      );
      const result = await executeRaw(
        `DELETE FROM ${q("xray_clients")} WHERE ${q("inboundId")} IN (${chunk.map(() => "?").join(", ")})`,
        chunk,
      );
      clientCount += rawAffectedRows(result);
      await executeRaw(
        `DELETE FROM ${q("xray_inbounds")} WHERE ${q("id")} IN (${chunk.map(() => "?").join(", ")})`,
        chunk,
      );
    }

    const clientRows = await queryRaw<{ id: number }>(
      `SELECT c.${q("id")} AS ${q("id")}
         FROM ${q("xray_clients")} c
         JOIN ${q("xray_inbounds")} i ON i.${q("id")} = c.${q("inboundId")}
        WHERE i.${q("hostId")} = ? AND c.${q("pendingDelete")} = ${boolLiteral(true)} AND c.${q("desiredGeneration")} <= ?
        ORDER BY c.${q("id")} ASC`,
      [hostId, appliedGeneration],
    );
    const clientIds = clientRows.map((row) => Number(row.id)).filter((id) => Number.isSafeInteger(id) && id > 0);
    for (let offset = 0; offset < clientIds.length; offset += 100) {
      const chunk = clientIds.slice(offset, offset + 100);
      await deleteGenericAccessEntriesBy("legacyClientId", chunk);
      await executeRaw(
        `DELETE FROM ${q("xray_clients")} WHERE ${q("id")} IN (${chunk.map(() => "?").join(", ")})`,
        chunk,
      );
    }
    const genericRows = await queryRaw<{ id: unknown }>(
      `SELECT a.${q("id")} AS ${q("id")}
         FROM ${q("xray_access_entries")} a
         JOIN ${q("xray_inbounds")} i ON i.${q("id")} = a.${q("inboundId")}
        WHERE i.${q("hostId")} = ? AND a.${q("legacyClientId")} IS NULL
          AND a.${q("pendingDelete")} = ${boolLiteral(true)} AND a.${q("desiredGeneration")} <= ?
        ORDER BY a.${q("id")} ASC`,
      [hostId, appliedGeneration],
    );
    const genericIds = genericRows.map((row) => positiveId(row.id, "OPERATION_CONFLICT"));
    for (let offset = 0; offset < genericIds.length; offset += 100) {
      await deleteGenericAccessEntryIds(genericIds.slice(offset, offset + 100));
    }
    return { inboundCount: inboundIds.length, clientCount: clientCount + clientIds.length + genericIds.length };
  });
}

export async function deleteAppliedPendingXrayClientsWithinHostLock(hostIdValue: unknown, appliedGenerationValue: unknown) {
  const removed = await deleteAppliedPendingXrayRecordsWithinHostLock(hostIdValue, appliedGenerationValue);
  return removed.clientCount;
}

function inboundSafeColumns() {
  const q = quoteIdentifier;
  return `${["id", "hostId", "name", "runtimeTag", "publicAddress", "listenAddress", "listenPort", "protocol", "transport", "security",
    "realityTargetHost", "realityTargetPort", "realityServerName", "realityPublicKey", "fingerprint", "spiderX", "isEnabled",
    "pendingDelete", "desiredGeneration", "createdByUserId", "createdAt", "updatedAt"].map((column) => q(column)).join(", ")},
    CASE WHEN ${q("realityPrivateKeyEncrypted")} IS NOT NULL AND ${q("realityPrivateKeyEncrypted")} <> '' THEN 1 ELSE 0 END AS ${q("hasRealityPrivateKey")}`;
}

function clientSafeColumns() {
  const q = quoteIdentifier;
  return `${["id", "inboundId", "name", "statsKey", "flow", "ownerUserId", "isEnabled", "pendingDelete", "desiredGeneration", "sortOrder", "createdAt", "updatedAt"]
    .map((column) => q(column)).join(", ")},
    CASE WHEN ${q("uuidEncrypted")} IS NOT NULL AND ${q("uuidEncrypted")} <> '' THEN 1 ELSE 0 END AS ${q("hasUuid")},
    CASE WHEN ${q("shortIdEncrypted")} IS NOT NULL AND ${q("shortIdEncrypted")} <> '' THEN 1 ELSE 0 END AS ${q("hasShortId")}`;
}

async function oneDto<T>(sql: string, params: unknown[], mapper: (row: Record<string, unknown>) => T): Promise<T | null> {
  const rows = await queryRaw<Record<string, unknown>>(sql, params);
  return rows[0] ? mapper(rows[0]) : null;
}

export async function getXrayInbound(id: number): Promise<XrayInboundDto | null> {
  const q = quoteIdentifier;
  return oneDto(`SELECT ${inboundSafeColumns()} FROM ${q("xray_inbounds")} WHERE ${q("id")} = ? LIMIT 1`, [id], toXrayInboundDto);
}

export async function listXrayInboundsByHost(hostId: number): Promise<XrayInboundDto[]> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Record<string, unknown>>(
    `SELECT ${inboundSafeColumns()} FROM ${q("xray_inbounds")} WHERE ${q("hostId")} = ? ORDER BY ${q("updatedAt")} DESC, ${q("id")} DESC`,
    [hostId],
  );
  return rows.map(toXrayInboundDto);
}

export async function getXrayClient(id: number): Promise<XrayClientDto | null> {
  const q = quoteIdentifier;
  return oneDto(`SELECT ${clientSafeColumns()} FROM ${q("xray_clients")} WHERE ${q("id")} = ? LIMIT 1`, [id], toXrayClientDto);
}

export async function listXrayClientsByInbound(inboundId: number): Promise<XrayClientDto[]> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Record<string, unknown>>(
    `SELECT ${clientSafeColumns()} FROM ${q("xray_clients")} WHERE ${q("inboundId")} = ? ORDER BY ${q("sortOrder")} ASC, ${q("id")} ASC`,
    [inboundId],
  );
  return rows.map(toXrayClientDto);
}

export async function getXrayHostDeployment(hostId: number): Promise<XrayHostDeploymentDto | null> {
  const q = quoteIdentifier;
  const columns = ["id", "hostId", "targetVersion", "desiredGeneration", "desiredConfigHash", "lastOperationId", "createdAt", "updatedAt"]
    .map((column) => q(column)).join(", ");
  return oneDto(`SELECT ${columns} FROM ${q("xray_host_deployments")} WHERE ${q("hostId")} = ? LIMIT 1`, [hostId], toXrayHostDeploymentDto);
}

export async function getXrayRuntimeReport(hostId: number): Promise<XrayRuntimeReportDto | null> {
  const q = quoteIdentifier;
  const columns = ["id", "hostId", "capabilitySchemaVersion", "supportedOS", "supportedArch", "supportsArtifactInstall", "supportsPortProbe",
    "supportsUdpPortProbe", "supportsUdpListenerReadiness", "supportsRealityScan", "capabilityErrorCode", "isInstalled", "installedVersion", "runningVersion", "serviceStatus", "processId",
    "appliedGeneration", "appliedConfigHash", "binarySha256", "lastErrorCode", "lastErrorMessage", "reportedAt", "updatedAt"]
    .map((column) => q(column)).join(", ");
  return oneDto(`SELECT ${columns} FROM ${q("xray_runtime_reports")} WHERE ${q("hostId")} = ? LIMIT 1`, [hostId], toXrayRuntimeReportDto);
}

export async function listXrayArtifacts(): Promise<XrayArtifactDto[]> {
  const q = quoteIdentifier;
  const columns = ["id", "version", "os", "arch", "packageFormat", "sha256", "fileSize", "status", "verifiedAt", "createdAt", "updatedAt"]
    .map((column) => q(column)).join(", ");
  const rows = await queryRaw<Record<string, unknown>>(
    `SELECT ${columns} FROM ${q("xray_artifacts")} ORDER BY ${q("version")} DESC, ${q("os")} ASC, ${q("arch")} ASC`,
  );
  return rows.map(toXrayArtifactDto);
}

export async function getXrayOperation(operationId: string): Promise<XrayOperationDto | null> {
  const q = quoteIdentifier;
  const columns = ["id", "operationId", "hostId", "inboundId", "type", "requestedGeneration", "status", "errorCode", "errorMessage",
    "attemptCount", "createdByUserId", "createdAt", "startedAt", "finishedAt", "expiresAt", "updatedAt"]
    .map((column) => q(column)).join(", ");
  return oneDto(`SELECT ${columns} FROM ${q("xray_operations")} WHERE ${q("operationId")} = ? LIMIT 1`, [operationId], toXrayOperationDto);
}
