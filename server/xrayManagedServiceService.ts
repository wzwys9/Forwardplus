import crypto from "node:crypto";
import net from "node:net";

import {
  XrayManagedServicesCapabilitySchema,
  XrayManagedServiceDesiredServicesSchema,
  XrayManagedServicesDesiredStateSchema,
  XrayManagedServicesObservedStateSchema,
  type XrayManagedServicesCapability,
  type XrayManagedServicesDesiredState,
  type XrayManagedServicesObservedState,
} from "../shared/xrayTypes";
import { boolLiteral, quoteIdentifier } from "./dbCompat";
import {
  executeRaw,
  insertAndGetId,
  nowDate,
  queryRaw,
  rawAffectedRows,
  withDatabaseTransaction,
} from "./dbRuntime";
import { pushAgentRefresh } from "./agentEvents";
import { HOST_ONLINE_TTL_MS } from "./hostHeartbeatPolicy";
import { withKeyedTaskLock } from "./keyedTaskLock";
import { recordXrayMutationObservability } from "./xrayMutationObservability";
import {
  MTPROTO_DEFAULT_VERSION,
  MTPROTO_MANAGED_SERVICE_KIND,
  findVerifiedMtprotoArtifact,
} from "./xrayManagedServiceArtifacts";
import {
  decryptXraySecret,
  encryptXraySecret,
  fingerprintXraySecret,
  inspectXraySecretEnvelope,
  loadXrayMasterKeyFile,
  xrayManagedServiceAccountSecretContext,
  xrayManagedServiceInstanceSecretContext,
  type XrayManagedServiceAccountSecretKind,
  type XrayManagedServiceInstanceSecretKind,
  type XraySecretKeyring,
} from "./xraySecretCrypto";
import {
  allocateAmneziaWgPeerAddress,
  AMNEZIAWG_DNS,
  AMNEZIAWG_HEADER_PROTECTION_KEY,
  AMNEZIAWG_MANAGED_SERVICE_KIND,
  AMNEZIAWG_MAX_PEERS,
  AMNEZIAWG_MTU,
  AMNEZIAWG_PEER_PRE_SHARED_KEY,
  AMNEZIAWG_PEER_PRIVATE_KEY,
  AMNEZIAWG_SERVER_PRIVATE_KEY,
  AMNEZIAWG_SUBNET,
  AMNEZIAWG_TARGET_VERSION,
  buildAmneziaWgClientShare,
  generateAmneziaWgPeerMaterial,
  generateAmneziaWgServiceMaterial,
  parseAmneziaWgPeerSettings,
  parseAmneziaWgStoredSpec,
} from "./xrayAmneziaWgService";
import { canonicalXrayWireGuardKey, canonicalXrayWireGuardPrivateKey, deriveXrayWireGuardPublicKey } from "./xrayWireGuard";

export const XRAY_MANAGED_SERVICE_ERROR_CODES = [
  "HOST_NOT_FOUND",
  "HOST_OFFLINE",
  "MANAGED_SERVICE_NOT_FOUND",
  "MANAGED_SERVICE_ACCOUNT_NOT_FOUND",
  "MANAGED_SERVICE_CAPABILITY_MISSING",
  "MANAGED_SERVICE_ARTIFACT_UNAVAILABLE",
  "MANAGED_SERVICE_GENERATION_CONFLICT",
  "LAST_ACTIVE_ACCOUNT_REQUIRED",
  "INVALID_MANAGED_SERVICE_INPUT",
  "PORT_RESERVATION_EXPIRED",
  "PORT_RESERVATION_MISMATCH",
  "SENSITIVE_DATA_UNAVAILABLE",
] as const;

export type XrayManagedServiceErrorCode = (typeof XRAY_MANAGED_SERVICE_ERROR_CODES)[number];

export class XrayManagedServiceError extends Error {
  constructor(readonly code: XrayManagedServiceErrorCode) {
    super(code);
    this.name = "XrayManagedServiceError";
  }
}

type Row = Record<string, unknown>;
type MtprotoServiceSpec = { fakeTlsDomain: string };
type ManagedKind = typeof MTPROTO_MANAGED_SERVICE_KIND | typeof AMNEZIAWG_MANAGED_SERVICE_KIND;

const namePattern = /\S/;
const hostnamePattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function positiveId(value: unknown, code: XrayManagedServiceErrorCode): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new XrayManagedServiceError(code);
  return parsed;
}

function generationValue(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new XrayManagedServiceError("MANAGED_SERVICE_GENERATION_CONFLICT");
  return parsed;
}

function databaseBoolean(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || value === "true";
}

function dateValue(value: unknown): Date | null {
  if (value == null || value === "") return null;
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value : null;
  const text = String(value);
  const numeric = /^\d+(?:\.\d+)?$/.test(text) ? Number(text) : NaN;
  const parsed = Number.isFinite(numeric) ? new Date(numeric < 10_000_000_000 ? numeric * 1000 : numeric) : new Date(text);
  return Number.isFinite(parsed.getTime()) ? parsed : null;
}

function displayName(value: unknown): string {
  const result = String(value ?? "").trim();
  if (!namePattern.test(result) || result.length > 128) throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
  return result;
}

function publicAddress(value: unknown): string {
  const input = String(value ?? "").trim().replace(/^\[|\]$/g, "");
  if (!input || input.length > 253 || /[^\x00-\x7f]/.test(input)) {
    throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
  }
  if (net.isIP(input)) return input.toLowerCase();
  const normalized = input.toLowerCase().replace(/\.$/, "");
  if (!hostnamePattern.test(normalized)) throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
  return normalized;
}

function fakeTlsDomain(value: unknown): string {
  const normalized = String(value ?? "").trim().toLowerCase().replace(/\.$/, "");
  if (!hostnamePattern.test(normalized)) throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
  return normalized;
}

function listenPort(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1000 || parsed > 65535) {
    throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
  }
  return parsed;
}

function serviceSpec(row: Row): MtprotoServiceSpec {
  try {
    const parsed = JSON.parse(String(row.specJson ?? ""));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)
      || Object.keys(parsed).length !== 1 || typeof parsed.fakeTlsDomain !== "string") throw new Error();
    return { fakeTlsDomain: fakeTlsDomain(parsed.fakeTlsDomain) };
  } catch {
    throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
  }
}

function managedKind(value: unknown): ManagedKind {
  if (value === MTPROTO_MANAGED_SERVICE_KIND || value === AMNEZIAWG_MANAGED_SERVICE_KIND) return value;
  throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
}

function amneziaStoredSpec(value: unknown) {
  try { return parseAmneziaWgStoredSpec(value); } catch { throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT"); }
}

function amneziaPeerSettings(settingsVersion: unknown, settingsJson: unknown) {
  try { return parseAmneziaWgPeerSettings(settingsVersion, settingsJson); } catch {
    throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
  }
}

function mtprotoSecret(domain: string): string {
  return `ee${crypto.randomBytes(16).toString("hex")}${Buffer.from(domain, "utf8").toString("hex")}`;
}

function decryptManagedServiceSecret(row: Row, accountTag: string, domain: string, keyring: XraySecretKeyring): string {
  try {
    if (row.kind !== "MTPROTO_SECRET" || !/^[0-9a-f]{64}$/.test(String(row.fingerprint ?? ""))) throw new Error();
    const context = xrayManagedServiceAccountSecretContext(accountTag);
    const encryptedValue = String(row.encryptedValue ?? "");
    if (inspectXraySecretEnvelope(encryptedValue).version !== Number(row.keyVersion)) throw new Error();
    const plaintext = decryptXraySecret(encryptedValue, context, keyring);
    const domainHex = Buffer.from(domain, "utf8").toString("hex");
    if (!/^ee[0-9a-f]+$/.test(plaintext) || plaintext.length !== 2 + 32 + domainHex.length
      || !plaintext.endsWith(domainHex)
      || fingerprintXraySecret(plaintext, context, keyring) !== row.fingerprint) {
      throw new Error();
    }
    return plaintext;
  } catch {
    throw new XrayManagedServiceError("SENSITIVE_DATA_UNAVAILABLE");
  }
}

function decryptTypedSecret(input: {
  row: Row | undefined; resourceTag: string; kind: XrayManagedServiceAccountSecretKind | XrayManagedServiceInstanceSecretKind;
  scope: "account" | "service"; keyring: XraySecretKeyring; privateKey?: boolean;
}) {
  try {
    if (!input.row || input.row.kind !== input.kind || !/^[0-9a-f]{64}$/.test(String(input.row.fingerprint ?? ""))) throw new Error();
    const context = input.scope === "account"
      ? xrayManagedServiceAccountSecretContext(input.resourceTag, input.kind as XrayManagedServiceAccountSecretKind)
      : xrayManagedServiceInstanceSecretContext(input.resourceTag, input.kind as XrayManagedServiceInstanceSecretKind);
    const encryptedValue = String(input.row.encryptedValue ?? "");
    if (inspectXraySecretEnvelope(encryptedValue).version !== Number(input.row.keyVersion)) throw new Error();
    const plaintext = decryptXraySecret(encryptedValue, context, input.keyring);
    if (fingerprintXraySecret(plaintext, context, input.keyring) !== input.row.fingerprint) throw new Error();
    return input.privateKey ? canonicalXrayWireGuardPrivateKey(plaintext) : canonicalXrayWireGuardKey(plaintext);
  } catch {
    throw new XrayManagedServiceError("SENSITIVE_DATA_UNAVAILABLE");
  }
}

async function insertEncryptedSecret(input: {
  table: "xray_managed_service_secrets" | "xray_managed_service_instance_secrets";
  foreignKey: "accountId" | "serviceId"; foreignId: number; resourceTag: string;
  kind: XrayManagedServiceAccountSecretKind | XrayManagedServiceInstanceSecretKind; plaintext: string;
  scope: "account" | "service"; keyring: XraySecretKeyring; now: Date;
}) {
  const context = input.scope === "account"
    ? xrayManagedServiceAccountSecretContext(input.resourceTag, input.kind as XrayManagedServiceAccountSecretKind)
    : xrayManagedServiceInstanceSecretContext(input.resourceTag, input.kind as XrayManagedServiceInstanceSecretKind);
  const encryptedValue = encryptXraySecret(input.plaintext, context, input.keyring);
  await insertAndGetId(input.table, {
    [input.foreignKey]: input.foreignId, kind: input.kind, encryptedValue,
    fingerprint: fingerprintXraySecret(input.plaintext, context, input.keyring),
    keyVersion: inspectXraySecretEnvelope(encryptedValue).version, createdAt: input.now, updatedAt: input.now,
  });
}

function uniqueAccountNames(values: unknown): Array<{ name: string }> {
  if (!Array.isArray(values) || values.length < 1 || values.length > 32) {
    throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
  }
  const entries = values.map((entry) => ({ name: displayName((entry as { name?: unknown })?.name) }));
  if (new Set(entries.map((entry) => entry.name.toLocaleLowerCase())).size !== entries.length) {
    throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
  }
  return entries;
}

function stateHash(services: XrayManagedServicesDesiredState["services"]): string {
  return crypto.createHash("sha256").update(JSON.stringify(services), "utf8").digest("hex");
}

function observedSignature(state: XrayManagedServicesObservedState): string {
  const services = [...state.services].sort((left, right) => left.serviceId - right.serviceId);
  return crypto.createHash("sha256").update(JSON.stringify({
    schemaVersion: state.schemaVersion,
    appliedGeneration: state.appliedGeneration,
    appliedConfigHash: state.appliedConfigHash,
    services,
    observedAt: "",
  }), "utf8").digest("hex");
}

async function runtimeReport(hostId: number): Promise<Row | null> {
  const q = quoteIdentifier;
  return (await queryRaw<Row>(
    `SELECT * FROM ${q("xray_managed_service_runtime_reports")} WHERE ${q("hostId")} = ? LIMIT 1`, [hostId],
  ))[0] ?? null;
}

function parsedCapability(row: Row | null): XrayManagedServicesCapability | null {
  try {
    const parsed = XrayManagedServicesCapabilitySchema.safeParse(JSON.parse(String(row?.capabilityJson ?? "")));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

function parsedObserved(row: Row | null): XrayManagedServicesObservedState | null {
  try {
    const parsed = XrayManagedServicesObservedStateSchema.safeParse(JSON.parse(String(row?.stateJson ?? "")));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

function supportsMtprotoCapability(capability: XrayManagedServicesCapability | null): capability is XrayManagedServicesCapability {
  return !!capability
    && capability.supportedKinds.includes(MTPROTO_MANAGED_SERVICE_KIND)
    && capability.supportsArtifactInstall
    && capability.runsAsDedicatedUser
    && capability.supportedOS === "linux"
    && (capability.supportedArch === "amd64" || capability.supportedArch === "arm64");
}

function supportsAmneziaWgCapability(capability: XrayManagedServicesCapability | null): capability is XrayManagedServicesCapability {
  const kind = capability?.kindCapabilities?.find((item) => item.kind === AMNEZIAWG_MANAGED_SERVICE_KIND);
  return !!capability && !!kind && kind.supervisor === "AGENT_CHILD" && !kind.supportsArtifactInstall
    && kind.runsAsDedicatedUser && kind.network === "udp" && capability.supportedOS === "linux"
    && (capability.supportedArch === "amd64" || capability.supportedArch === "arm64");
}

function supportsKind(capability: XrayManagedServicesCapability | null, kind: ManagedKind) {
  return kind === MTPROTO_MANAGED_SERVICE_KIND ? supportsMtprotoCapability(capability) : supportsAmneziaWgCapability(capability);
}

async function hostRow(hostId: number): Promise<Row> {
  const q = quoteIdentifier;
  const row = (await queryRaw<Row>(
    `SELECT ${["id", "name", "ip", "ipv4", "isOnline", "lastHeartbeat"].map(q).join(", ")}
       FROM ${q("hosts")} WHERE ${q("id")} = ? LIMIT 1`, [hostId],
  ))[0];
  if (!row) throw new XrayManagedServiceError("HOST_NOT_FOUND");
  return row;
}

function hostIsOnline(row: Row): boolean {
  const heartbeat = dateValue(row.lastHeartbeat);
  return databaseBoolean(row.isOnline) && !!heartbeat && Date.now() - heartbeat.getTime() <= HOST_ONLINE_TTL_MS;
}

async function requireOnlineCapability(hostId: number, kind: ManagedKind = MTPROTO_MANAGED_SERVICE_KIND) {
  const host = await hostRow(hostId);
  if (!hostIsOnline(host)) throw new XrayManagedServiceError("HOST_OFFLINE");
  const capability = parsedCapability(await runtimeReport(hostId));
  if (!capability || !supportsKind(capability, kind)) {
    throw new XrayManagedServiceError("MANAGED_SERVICE_CAPABILITY_MISSING");
  }
  return { host, capability };
}

async function requireCapability(hostId: number, kind: ManagedKind) {
  const { host, capability } = await requireOnlineCapability(hostId, kind);
  if (kind === AMNEZIAWG_MANAGED_SERVICE_KIND) return { host, capability, artifact: null };
  const artifact = await findVerifiedMtprotoArtifact(capability.supportedOS, capability.supportedArch);
  if (!artifact) throw new XrayManagedServiceError("MANAGED_SERVICE_ARTIFACT_UNAVAILABLE");
  return { host, capability, artifact };
}

async function deployment(hostId: number): Promise<Row | null> {
  const q = quoteIdentifier;
  return (await queryRaw<Row>(
    `SELECT * FROM ${q("xray_managed_service_deployments")} WHERE ${q("hostId")} = ? LIMIT 1`, [hostId],
  ))[0] ?? null;
}

async function serviceRow(serviceId: number): Promise<Row> {
  const q = quoteIdentifier;
  const row = (await queryRaw<Row>(
    `SELECT * FROM ${q("xray_managed_services")} WHERE ${q("id")} = ? LIMIT 1`, [serviceId],
  ))[0];
  if (!row || databaseBoolean(row.pendingDelete)) throw new XrayManagedServiceError("MANAGED_SERVICE_NOT_FOUND");
  return row;
}

async function accountRow(accountId: number): Promise<Row> {
  const q = quoteIdentifier;
  const row = (await queryRaw<Row>(
    `SELECT a.*, s.${q("hostId")}, s.${q("kind")}, s.${q("serviceTag")}, s.${q("publicAddress")}, s.${q("listenPort")},
            s.${q("specVersion")}, s.${q("specJson")}, s.${q("targetVersion")},
            s.${q("isEnabled")} AS ${q("serviceEnabled")}, s.${q("pendingDelete")} AS ${q("servicePendingDelete")}
       FROM ${q("xray_managed_service_accounts")} a
       JOIN ${q("xray_managed_services")} s ON s.${q("id")} = a.${q("serviceId")}
      WHERE a.${q("id")} = ? LIMIT 1`, [accountId],
  ))[0];
  if (!row || databaseBoolean(row.pendingDelete) || databaseBoolean(row.servicePendingDelete)) {
    throw new XrayManagedServiceError("MANAGED_SERVICE_ACCOUNT_NOT_FOUND");
  }
  return row;
}

async function activeAccountCount(serviceId: number): Promise<number> {
  const q = quoteIdentifier;
  const row = (await queryRaw<Row>(
    `SELECT COUNT(*) AS ${q("count")} FROM ${q("xray_managed_service_accounts")}
      WHERE ${q("serviceId")} = ? AND ${q("pendingDelete")} = ${boolLiteral(false)} AND ${q("isEnabled")} = ${boolLiteral(true)}`,
    [serviceId],
  ))[0];
  return Number(row?.count ?? 0);
}

async function assertManagedServicePortAvailable(hostId: number, port: number, excludeServiceId?: number) {
  const q = quoteIdentifier;
  const params: unknown[] = [hostId, port];
  const exclusion = excludeServiceId === undefined ? "" : ` AND ${q("id")}<>?`;
  if (excludeServiceId !== undefined) params.push(excludeServiceId);
  const conflict = await queryRaw<Row>(
    `SELECT ${q("id")} FROM ${q("xray_managed_services")}
      WHERE ${q("hostId")}=? AND ${q("listenPort")}=? AND ${q("pendingDelete")}=${boolLiteral(false)}${exclusion} LIMIT 1`, params,
  );
  if (conflict.length) throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
}

async function desiredServices(hostId: number, keyring: XraySecretKeyring, capability: XrayManagedServicesCapability) {
  const q = quoteIdentifier;
  const services = await queryRaw<Row>(
    `SELECT * FROM ${q("xray_managed_services")}
      WHERE ${q("hostId")} = ? AND ${q("pendingDelete")} = ${boolLiteral(false)} AND ${q("isEnabled")} = ${boolLiteral(true)}
      ORDER BY ${q("serviceTag")} ASC`, [hostId],
  );
  const result: XrayManagedServicesDesiredState["services"] = [];
  for (const row of services) {
    const kind = managedKind(row.kind);
    if (!supportsKind(capability, kind) || row.listenAddress !== "0.0.0.0" || Number(row.specVersion) !== 1) {
      throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
    }
    if (kind === MTPROTO_MANAGED_SERVICE_KIND) {
      if (row.targetVersion !== MTPROTO_DEFAULT_VERSION) throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
      const artifact = await findVerifiedMtprotoArtifact(capability.supportedOS, capability.supportedArch);
      if (!artifact) throw new XrayManagedServiceError("MANAGED_SERVICE_ARTIFACT_UNAVAILABLE");
      const spec = serviceSpec(row);
      const accounts = await queryRaw<Row>(
        `SELECT a.${q("accountTag")}, x.${q("kind")}, x.${q("encryptedValue")}, x.${q("fingerprint")}, x.${q("keyVersion")}
           FROM ${q("xray_managed_service_accounts")} a
           JOIN ${q("xray_managed_service_secrets")} x ON x.${q("accountId")} = a.${q("id")}
          WHERE a.${q("serviceId")} = ? AND a.${q("pendingDelete")} = ${boolLiteral(false)}
            AND a.${q("isEnabled")} = ${boolLiteral(true)} AND x.${q("kind")} = ?
          ORDER BY a.${q("accountTag")} ASC`, [Number(row.id), "MTPROTO_SECRET"],
      );
      if (accounts.length < 1) throw new XrayManagedServiceError("LAST_ACTIVE_ACCOUNT_REQUIRED");
      result.push({ kind, serviceId: positiveId(row.id, "MANAGED_SERVICE_NOT_FOUND"), serviceTag: String(row.serviceTag),
        targetVersion: MTPROTO_DEFAULT_VERSION, artifact, listenAddress: "0.0.0.0", listenPort: listenPort(row.listenPort),
        fakeTlsDomain: spec.fakeTlsDomain, accounts: accounts.map((account) => ({ accountTag: String(account.accountTag),
          secret: decryptManagedServiceSecret(account, String(account.accountTag), spec.fakeTlsDomain, keyring) })) });
      continue;
    }
    if (row.targetVersion !== AMNEZIAWG_TARGET_VERSION) throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
    const storedSpec = amneziaStoredSpec(row.specJson);
    const instanceSecrets = await queryRaw<Row>(
      `SELECT ${["kind", "encryptedValue", "fingerprint", "keyVersion"].map(q).join(", ")} FROM ${q("xray_managed_service_instance_secrets")}
        WHERE ${q("serviceId")}=? ORDER BY ${q("kind")} ASC`, [Number(row.id)],
    );
    const serviceTag = String(row.serviceTag);
    if (instanceSecrets.length !== 2
      || ![AMNEZIAWG_SERVER_PRIVATE_KEY, AMNEZIAWG_HEADER_PROTECTION_KEY].every((kind) => instanceSecrets.some((item) => item.kind === kind))) {
      throw new XrayManagedServiceError("SENSITIVE_DATA_UNAVAILABLE");
    }
    const serverPrivateKey = decryptTypedSecret({ row: instanceSecrets.find((item) => item.kind === AMNEZIAWG_SERVER_PRIVATE_KEY),
      resourceTag: serviceTag, kind: AMNEZIAWG_SERVER_PRIVATE_KEY, scope: "service", keyring, privateKey: true });
    const headerProtectionKey = decryptTypedSecret({ row: instanceSecrets.find((item) => item.kind === AMNEZIAWG_HEADER_PROTECTION_KEY),
      resourceTag: serviceTag, kind: AMNEZIAWG_HEADER_PROTECTION_KEY, scope: "service", keyring });
    const peerRows = await queryRaw<Row>(
      `SELECT a.${q("id")}, a.${q("accountTag")}, a.${q("settingsVersion")}, a.${q("settingsJson")},
              x.${q("kind")}, x.${q("encryptedValue")}, x.${q("fingerprint")}, x.${q("keyVersion")}
         FROM ${q("xray_managed_service_accounts")} a JOIN ${q("xray_managed_service_secrets")} x ON x.${q("accountId")}=a.${q("id")}
        WHERE a.${q("serviceId")}=? AND a.${q("pendingDelete")}=${boolLiteral(false)} AND a.${q("isEnabled")}=${boolLiteral(true)}
        ORDER BY a.${q("accountTag")} ASC, x.${q("kind")} ASC`, [Number(row.id)],
    );
    const peerGroups = new Map<number, Row[]>();
    for (const peerRow of peerRows) peerGroups.set(Number(peerRow.id), [...(peerGroups.get(Number(peerRow.id)) ?? []), peerRow]);
    if (peerGroups.size < 1 || peerGroups.size > AMNEZIAWG_MAX_PEERS) throw new XrayManagedServiceError("LAST_ACTIVE_ACCOUNT_REQUIRED");
    const peers = [...peerGroups.values()].map((secretRows) => {
      if (secretRows.length !== 2
        || ![AMNEZIAWG_PEER_PRIVATE_KEY, AMNEZIAWG_PEER_PRE_SHARED_KEY].every((kind) => secretRows.some((item) => item.kind === kind))) {
        throw new XrayManagedServiceError("SENSITIVE_DATA_UNAVAILABLE");
      }
      const peer = secretRows[0];
      const privateKey = decryptTypedSecret({ row: secretRows.find((item) => item.kind === AMNEZIAWG_PEER_PRIVATE_KEY),
        resourceTag: String(peer.accountTag), kind: AMNEZIAWG_PEER_PRIVATE_KEY, scope: "account", keyring, privateKey: true });
      if (privateKey === serverPrivateKey) throw new XrayManagedServiceError("SENSITIVE_DATA_UNAVAILABLE");
      const settings = amneziaPeerSettings(peer.settingsVersion, peer.settingsJson);
      if (deriveXrayWireGuardPublicKey(privateKey) !== settings.publicKey) throw new XrayManagedServiceError("SENSITIVE_DATA_UNAVAILABLE");
      const preSharedKey = decryptTypedSecret({ row: secretRows.find((item) => item.kind === AMNEZIAWG_PEER_PRE_SHARED_KEY),
        resourceTag: String(peer.accountTag), kind: AMNEZIAWG_PEER_PRE_SHARED_KEY, scope: "account", keyring });
      if (Buffer.from(preSharedKey, "base64").every((byte) => byte === 0)) throw new XrayManagedServiceError("SENSITIVE_DATA_UNAVAILABLE");
      return { accountTag: String(peer.accountTag), address: settings.address, publicKey: settings.publicKey, preSharedKey };
    });
    result.push({ kind, serviceId: positiveId(row.id, "MANAGED_SERVICE_NOT_FOUND"), serviceTag,
      targetVersion: AMNEZIAWG_TARGET_VERSION, listenAddress: "0.0.0.0", listenPort: listenPort(row.listenPort),
      publicAddress: publicAddress(row.publicAddress),
      subnet: AMNEZIAWG_SUBNET, mtu: AMNEZIAWG_MTU, dns: [AMNEZIAWG_DNS[0], AMNEZIAWG_DNS[1]], serverPrivateKey,
      obfuscation: { ...storedSpec, headerProtectionKey }, peers });
  }
  try {
    const parsed = XrayManagedServiceDesiredServicesSchema.parse(result);
    XrayManagedServicesDesiredStateSchema.parse({
      schemaVersion: 1,
      generation: 0,
      issuedAt: new Date(0).toISOString(),
      configHash: "0".repeat(64),
      services: parsed,
    });
    return parsed;
  } catch (error) {
    if (error instanceof XrayManagedServiceError) throw error;
    throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
  }
}

async function writeDeployment(hostId: number, current: Row | null, desiredGeneration: number, desiredConfigHash: string,
  services: XrayManagedServicesDesiredState["services"]) {
  const now = nowDate();
  const versions = new Set(services.map((service) => service.targetVersion));
  const targetVersion = versions.size === 0 ? (current?.targetVersion ?? MTPROTO_DEFAULT_VERSION)
    : versions.size === 1 ? [...versions][0] : null;
  if (current) {
    const q = quoteIdentifier;
    const changed = await executeRaw(
      `UPDATE ${q("xray_managed_service_deployments")}
          SET ${q("targetVersion")}=?, ${q("desiredGeneration")}=?, ${q("desiredConfigHash")}=?, ${q("updatedAt")}=?
        WHERE ${q("id")}=? AND ${q("desiredGeneration")}=?`,
      [targetVersion, desiredGeneration, desiredConfigHash, now, Number(current.id), Number(current.desiredGeneration ?? 0)],
    );
    if (rawAffectedRows(changed) !== 1) throw new XrayManagedServiceError("MANAGED_SERVICE_GENERATION_CONFLICT");
  } else {
    await insertAndGetId("xray_managed_service_deployments", {
      hostId, targetVersion, desiredGeneration, desiredConfigHash, createdAt: now, updatedAt: now,
    });
  }
}

async function mutateHost<T>(input: {
  hostId: number;
  kind: ManagedKind;
  expectedGeneration?: number;
  work: (nextGeneration: number, keyring: XraySecretKeyring) => Promise<T>;
}) {
  return withKeyedTaskLock(`xray-managed-service-host:${input.hostId}`, () => withDatabaseTransaction(async () => {
    const { capability } = await requireCapability(input.hostId, input.kind);
    const current = await deployment(input.hostId);
    const currentGeneration = generationValue(current?.desiredGeneration ?? 0);
    if (input.expectedGeneration !== undefined && generationValue(input.expectedGeneration) !== currentGeneration) {
      throw new XrayManagedServiceError("MANAGED_SERVICE_GENERATION_CONFLICT");
    }
    const nextGeneration = currentGeneration + 1;
    if (!Number.isSafeInteger(nextGeneration)) throw new XrayManagedServiceError("MANAGED_SERVICE_GENERATION_CONFLICT");
    const keyring = loadXrayMasterKeyFile();
    const value = await input.work(nextGeneration, keyring);
    const services = await desiredServices(input.hostId, keyring, capability);
    const configHash = stateHash(services);
    await writeDeployment(input.hostId, current, nextGeneration, configHash, services);
    return { ...value, desiredGeneration: nextGeneration, desiredConfigHash: configHash };
  }));
}

function scheduleRefresh(hostId: number, reason: string) {
  try { pushAgentRefresh(hostId, reason, { urgent: true }); } catch { /* heartbeat fallback */ }
}

async function auditManagedServiceMutation(input: {
  event: string;
  resourceType: "xray_managed_service" | "xray_managed_service_account";
  resourceId: number;
  hostId: number;
  userId: number;
  action: "create" | "update" | "delete";
  generation: number;
  status: string;
  port?: number;
  beforeGeneration?: number;
}) {
  await recordXrayMutationObservability({
    event: input.event,
    resourceType: input.resourceType,
    resourceId: input.resourceId,
    hostId: input.hostId,
    action: input.action,
    before: input.beforeGeneration === undefined ? undefined : {
      userId: input.userId,
      hostId: input.hostId,
      managedServiceId: input.resourceType === "xray_managed_service" ? input.resourceId : undefined,
      managedServiceAccountId: input.resourceType === "xray_managed_service_account" ? input.resourceId : undefined,
      generation: input.beforeGeneration,
    },
    fields: {
      userId: input.userId,
      hostId: input.hostId,
      managedServiceId: input.resourceType === "xray_managed_service" ? input.resourceId : undefined,
      managedServiceAccountId: input.resourceType === "xray_managed_service_account" ? input.resourceId : undefined,
      generation: input.generation,
      status: input.status,
      port: input.port,
    },
  });
}

function safeServiceStatus(service: Row, observed: XrayManagedServicesObservedState | null, desired: Row | null) {
  if (databaseBoolean(service.pendingDelete)) return "PENDING_DELETE" as const;
  if (!databaseBoolean(service.isEnabled)) return "DISABLED" as const;
  const state = observed?.services.find((candidate) => candidate.serviceId === Number(service.id));
  if (state?.serviceStatus === "ERROR" || state?.listener.status === "MISSING" || state?.listener.status === "WRONG_PROCESS") return "ERROR" as const;
  if (observed && desired && observed.appliedGeneration === Number(desired.desiredGeneration)
    && observed.appliedConfigHash === desired.desiredConfigHash && state?.serviceStatus === "RUNNING"
    && state.listener.status === "READY") return "RUNNING" as const;
  return "WAITING_SYNC" as const;
}

async function safeProjection(row: Row) {
  const hostId = Number(row.hostId);
  const [report, desired, accounts, secrets] = await Promise.all([
    runtimeReport(hostId),
    deployment(hostId),
    queryRaw<Row>(
      `SELECT ${["id", "name", "accountTag", "settingsVersion", "settingsJson", "isEnabled", "pendingDelete", "sortOrder", "updatedAt"].map(quoteIdentifier).join(", ")}
         FROM ${quoteIdentifier("xray_managed_service_accounts")} WHERE ${quoteIdentifier("serviceId")} = ?
         ORDER BY ${quoteIdentifier("sortOrder")} ASC, ${quoteIdentifier("id")} ASC`, [Number(row.id)],
    ),
    queryRaw<Row>(
      `SELECT x.${quoteIdentifier("accountId")}, x.${quoteIdentifier("kind")} FROM ${quoteIdentifier("xray_managed_service_secrets")} x
         JOIN ${quoteIdentifier("xray_managed_service_accounts")} a ON a.${quoteIdentifier("id")} = x.${quoteIdentifier("accountId")}
        WHERE a.${quoteIdentifier("serviceId")} = ?`, [Number(row.id)],
    ),
  ]);
  const observed = parsedObserved(report);
  const capability = parsedCapability(report);
  const kind = managedKind(row.kind);
  const artifactAvailable = kind === MTPROTO_MANAGED_SERVICE_KIND && supportsMtprotoCapability(capability)
    && !!await findVerifiedMtprotoArtifact(capability.supportedOS, capability.supportedArch).catch(() => null);
  const serviceObserved = observed?.services.find((item) => item.serviceId === Number(row.id)) ?? null;
  const common = {
    id: Number(row.id),
    hostId,
    hostName: String(row.hostName ?? ""),
    name: String(row.name),
    publicAddress: String(row.publicAddress),
    listenAddress: "0.0.0.0" as const,
    listenPort: Number(row.listenPort),
    targetVersion: String(row.targetVersion),
    isEnabled: databaseBoolean(row.isEnabled),
    pendingDelete: databaseBoolean(row.pendingDelete),
    status: safeServiceStatus(row, observed, desired),
    desiredGeneration: Number(desired?.desiredGeneration ?? 0),
    appliedGeneration: observed?.appliedGeneration ?? 0,
    desiredConfigHash: desired?.desiredConfigHash ? String(desired.desiredConfigHash) : null,
    appliedConfigHash: observed?.appliedConfigHash ?? null,
    observed: serviceObserved,
    isHostOnline: hostIsOnline(row),
    capabilityAvailable: supportsKind(capability, kind) && (kind === AMNEZIAWG_MANAGED_SERVICE_KIND || artifactAvailable),
    artifactAvailable,
    accounts: accounts.filter((account) => !databaseBoolean(account.pendingDelete)).map((account) => ({
      id: Number(account.id), name: String(account.name), accountTag: String(account.accountTag),
      isEnabled: databaseBoolean(account.isEnabled),
      secretConfigured: kind === MTPROTO_MANAGED_SERVICE_KIND
        ? secrets.some((secret) => Number(secret.accountId) === Number(account.id) && secret.kind === "MTPROTO_SECRET")
        : [AMNEZIAWG_PEER_PRIVATE_KEY, AMNEZIAWG_PEER_PRE_SHARED_KEY].every((secretKind) =>
          secrets.some((secret) => Number(secret.accountId) === Number(account.id) && secret.kind === secretKind)),
      ...(kind === AMNEZIAWG_MANAGED_SERVICE_KIND
        ? (() => { const settings = amneziaPeerSettings(account.settingsVersion, account.settingsJson);
          return { address: settings.address }; })()
        : {}),
      sortOrder: Number(account.sortOrder ?? 0),
      updatedAt: dateValue(account.updatedAt),
    })),
    createdAt: dateValue(row.createdAt),
    updatedAt: dateValue(row.updatedAt),
  };
  if (kind === MTPROTO_MANAGED_SERVICE_KIND) return { ...common, kind: MTPROTO_MANAGED_SERVICE_KIND,
    fakeTlsDomain: serviceSpec(row).fakeTlsDomain };
  amneziaStoredSpec(row.specJson);
  return { ...common, kind: AMNEZIAWG_MANAGED_SERVICE_KIND, subnet: AMNEZIAWG_SUBNET, mtu: AMNEZIAWG_MTU, dns: AMNEZIAWG_DNS };
}

async function serviceWithHost(serviceId: number) {
  const q = quoteIdentifier;
  const row = (await queryRaw<Row>(
    `SELECT s.*, h.${q("name")} AS ${q("hostName")}, h.${q("isOnline")}, h.${q("lastHeartbeat")}
       FROM ${q("xray_managed_services")} s JOIN ${q("hosts")} h ON h.${q("id")} = s.${q("hostId")}
      WHERE s.${q("id")} = ? LIMIT 1`, [serviceId],
  ))[0];
  if (!row) throw new XrayManagedServiceError("MANAGED_SERVICE_NOT_FOUND");
  return row;
}

export function getXrayManagedServiceCatalog() {
  return [
    { kind: MTPROTO_MANAGED_SERVICE_KIND, name: "MTProto（Telegram FakeTLS）", status: "AVAILABLE" as const, targetVersion: MTPROTO_DEFAULT_VERSION, network: "TCP" as const, privilege: "DEDICATED_UNPRIVILEGED_USER" as const, unavailableReasonCode: null },
    { kind: "TUN", name: "TUN", status: "NOT_IMPLEMENTED" as const, targetVersion: null, network: null, privilege: "REQUIRES_SEPARATE_CAP_NET_ADMIN_DESIGN" as const, unavailableReasonCode: "NOT_IMPLEMENTED" as const },
    { kind: AMNEZIAWG_MANAGED_SERVICE_KIND, name: "AmneziaWG", status: "AVAILABLE" as const, targetVersion: AMNEZIAWG_TARGET_VERSION, network: "UDP" as const, privilege: "DEDICATED_UNPRIVILEGED_USER" as const, unavailableReasonCode: null },
  ];
}

export async function listXrayManagedServiceHostOptions() {
  const q = quoteIdentifier;
  const hosts = await queryRaw<Row>(
    `SELECT ${["id", "name", "ip", "ipv4", "isOnline", "lastHeartbeat"].map(q).join(", ")} FROM ${q("hosts")} ORDER BY ${q("name")} ASC`,
  );
  return Promise.all(hosts.map(async (host) => {
    const report = await runtimeReport(Number(host.id));
    const capability = parsedCapability(report);
    const artifact = capability ? await findVerifiedMtprotoArtifact(capability.supportedOS, capability.supportedArch).catch(() => null) : null;
    const online = hostIsOnline(host);
    const supported = supportsMtprotoCapability(capability);
    return {
      id: Number(host.id), name: String(host.name), isOnline: online, lastHeartbeat: dateValue(host.lastHeartbeat),
      publicAddress: String(host.ipv4 || host.ip || ""), os: capability?.supportedOS ?? null, arch: capability?.supportedArch ?? null,
      canCreateMtproto: online && supported && !!artifact,
      canCreateAmneziawg: online && supportsAmneziaWgCapability(capability),
      amneziawgUnavailableReasonCode: !online ? "HOST_OFFLINE" as const
        : !supportsAmneziaWgCapability(capability) ? "MANAGED_SERVICE_CAPABILITY_MISSING" as const : null,
      unavailableReasonCode: !online ? "HOST_OFFLINE" as const
        : !supported ? "MANAGED_SERVICE_CAPABILITY_MISSING" as const
          : !artifact ? "MANAGED_SERVICE_ARTIFACT_UNAVAILABLE" as const : null,
    };
  }));
}

export async function listXrayManagedServices(input: { page?: number; pageSize?: number; search?: string; hostId?: number; status?: string }) {
  const q = quoteIdentifier;
  const page = Math.max(1, Number(input.page ?? 1));
  const pageSize = Math.min(100, Math.max(1, Number(input.pageSize ?? 20)));
  const params: unknown[] = [];
  const where: string[] = [];
  if (input.hostId) { where.push(`s.${q("hostId")} = ?`); params.push(input.hostId); }
  const search = String(input.search ?? "").trim().toLowerCase();
  const rows = await queryRaw<Row>(
    `SELECT s.*, h.${q("name")} AS ${q("hostName")}, h.${q("isOnline")}, h.${q("lastHeartbeat")}
       FROM ${q("xray_managed_services")} s JOIN ${q("hosts")} h ON h.${q("id")} = s.${q("hostId")}
      ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
      ORDER BY s.${q("updatedAt")} DESC, s.${q("id")} DESC`, params,
  );
  const projected = await Promise.all(rows.map(safeProjection));
  const searched = search ? projected.filter((service) => service.name.toLowerCase().includes(search)) : projected;
  const filtered = input.status ? searched.filter((service) => service.status === input.status) : searched;
  const offset = (page - 1) * pageSize;
  return { items: filtered.slice(offset, offset + pageSize), page, pageSize, total: filtered.length, totalPages: Math.max(1, Math.ceil(filtered.length / pageSize)) };
}

export async function getXrayManagedServiceDetail(idValue: unknown) {
  return safeProjection(await serviceWithHost(positiveId(idValue, "MANAGED_SERVICE_NOT_FOUND")));
}

export async function createXrayMtprotoService(input: {
  hostId: unknown; userId: unknown; name: unknown; publicAddress: unknown; listenPort: unknown;
  fakeTlsDomain: unknown; initialAccounts: unknown;
}) {
  const hostId = positiveId(input.hostId, "HOST_NOT_FOUND");
  const userId = positiveId(input.userId, "INVALID_MANAGED_SERVICE_INPUT");
  const name = displayName(input.name);
  const address = publicAddress(input.publicAddress);
  const port = listenPort(input.listenPort);
  const domain = fakeTlsDomain(input.fakeTlsDomain);
  const initialAccounts = uniqueAccountNames(input.initialAccounts);
  const created = await mutateHost({ hostId, kind: MTPROTO_MANAGED_SERVICE_KIND, work: async (nextGeneration, keyring) => {
    const now = nowDate();
    await assertManagedServicePortAvailable(hostId, port);
    const serviceTag = `forwardx-mtproto-${crypto.randomUUID()}`;
    const serviceId = await insertAndGetId("xray_managed_services", {
      hostId, name, serviceTag, kind: MTPROTO_MANAGED_SERVICE_KIND, publicAddress: address,
      listenAddress: "0.0.0.0", listenPort: port, specVersion: 1,
      specJson: JSON.stringify({ fakeTlsDomain: domain }), targetVersion: MTPROTO_DEFAULT_VERSION,
      isEnabled: true, pendingDelete: false, desiredGeneration: nextGeneration,
      createdByUserId: Number(input.userId), createdAt: now, updatedAt: now,
    });
    const accountIds: number[] = [];
    for (let index = 0; index < initialAccounts.length; index += 1) {
      const accountTag = `forwardx-mtproto-account-${crypto.randomUUID()}`;
      const accountId = await insertAndGetId("xray_managed_service_accounts", {
        serviceId, name: initialAccounts[index].name, accountTag, settingsVersion: 1, settingsJson: "{}", isEnabled: true, pendingDelete: false,
        desiredGeneration: nextGeneration, sortOrder: index, createdAt: now, updatedAt: now,
      });
      const secret = mtprotoSecret(domain);
      const context = xrayManagedServiceAccountSecretContext(accountTag);
      const encryptedValue = encryptXraySecret(secret, context, keyring);
      const envelope = inspectXraySecretEnvelope(encryptedValue);
      await insertAndGetId("xray_managed_service_secrets", {
        accountId, kind: "MTPROTO_SECRET", encryptedValue,
        fingerprint: fingerprintXraySecret(secret, context, keyring), keyVersion: envelope.version,
        createdAt: now, updatedAt: now,
      });
      accountIds.push(accountId);
    }
    return { serviceId, accountIds };
  } });
  scheduleRefresh(hostId, "xray-managed-service-create");
  await auditManagedServiceMutation({
    event: "MANAGED_SERVICE_CREATED", resourceType: "xray_managed_service", resourceId: created.serviceId,
    hostId, userId, action: "create", generation: created.desiredGeneration, status: "QUEUED", port,
  });
  return created;
}

export async function createXrayAmneziaWgService(input: {
  hostId: unknown; userId: unknown; name: unknown; publicAddress: unknown; listenPort: unknown; initialPeers: unknown;
}) {
  const hostId = positiveId(input.hostId, "HOST_NOT_FOUND");
  const userId = positiveId(input.userId, "INVALID_MANAGED_SERVICE_INPUT");
  const name = displayName(input.name);
  const address = publicAddress(input.publicAddress);
  const port = listenPort(input.listenPort);
  const initialPeers = uniqueAccountNames(input.initialPeers);
  const created = await mutateHost({ hostId, kind: AMNEZIAWG_MANAGED_SERVICE_KIND, work: async (nextGeneration, keyring) => {
    const now = nowDate();
    await assertManagedServicePortAvailable(hostId, port);
    const serviceTag = `forwardx-amneziawg-${crypto.randomUUID()}`;
    const material = generateAmneziaWgServiceMaterial();
    const serviceId = await insertAndGetId("xray_managed_services", {
      hostId, name, serviceTag, kind: AMNEZIAWG_MANAGED_SERVICE_KIND, publicAddress: address,
      listenAddress: "0.0.0.0", listenPort: port, specVersion: 1, specJson: JSON.stringify(material.storedSpec),
      targetVersion: AMNEZIAWG_TARGET_VERSION, isEnabled: true, pendingDelete: false, desiredGeneration: nextGeneration,
      createdByUserId: userId, createdAt: now, updatedAt: now,
    });
    await insertEncryptedSecret({ table: "xray_managed_service_instance_secrets", foreignKey: "serviceId", foreignId: serviceId,
      resourceTag: serviceTag, kind: AMNEZIAWG_SERVER_PRIVATE_KEY, plaintext: material.serverPrivateKey,
      scope: "service", keyring, now });
    await insertEncryptedSecret({ table: "xray_managed_service_instance_secrets", foreignKey: "serviceId", foreignId: serviceId,
      resourceTag: serviceTag, kind: AMNEZIAWG_HEADER_PROTECTION_KEY, plaintext: material.headerProtectionKey,
      scope: "service", keyring, now });
    const accountIds: number[] = [];
    for (let index = 0; index < initialPeers.length; index += 1) {
      const peer = generateAmneziaWgPeerMaterial();
      const accountTag = `forwardx-amneziawg-peer-${crypto.randomUUID()}`;
      const accountId = await insertAndGetId("xray_managed_service_accounts", {
        serviceId, name: initialPeers[index].name, accountTag, settingsVersion: 1,
        settingsJson: JSON.stringify({ address: `10.8.1.${index + 2}/32`, publicKey: peer.publicKey }),
        isEnabled: true, pendingDelete: false, desiredGeneration: nextGeneration, sortOrder: index, createdAt: now, updatedAt: now,
      });
      await insertEncryptedSecret({ table: "xray_managed_service_secrets", foreignKey: "accountId", foreignId: accountId,
        resourceTag: accountTag, kind: AMNEZIAWG_PEER_PRIVATE_KEY, plaintext: peer.privateKey, scope: "account", keyring, now });
      await insertEncryptedSecret({ table: "xray_managed_service_secrets", foreignKey: "accountId", foreignId: accountId,
        resourceTag: accountTag, kind: AMNEZIAWG_PEER_PRE_SHARED_KEY, plaintext: peer.preSharedKey, scope: "account", keyring, now });
      accountIds.push(accountId);
    }
    return { serviceId, accountIds };
  } });
  scheduleRefresh(hostId, "xray-amneziawg-service-create");
  await auditManagedServiceMutation({ event: "MANAGED_SERVICE_CREATED", resourceType: "xray_managed_service",
    resourceId: created.serviceId, hostId, userId, action: "create", generation: created.desiredGeneration, status: "QUEUED", port });
  return created;
}

export async function updateXrayAmneziaWgService(input: {
  id: unknown; userId: unknown; expectedGeneration: unknown; name?: unknown; publicAddress?: unknown;
  listenPort?: unknown; hostId?: unknown;
}) {
  const userId = positiveId(input.userId, "INVALID_MANAGED_SERVICE_INPUT");
  const id = positiveId(input.id, "MANAGED_SERVICE_NOT_FOUND");
  const current = await serviceRow(id);
  if (managedKind(current.kind) !== AMNEZIAWG_MANAGED_SERVICE_KIND) throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
  const hostId = Number(current.hostId);
  if (input.listenPort !== undefined && positiveId(input.hostId, "HOST_NOT_FOUND") !== hostId) {
    throw new XrayManagedServiceError("PORT_RESERVATION_MISMATCH");
  }
  const patch: Row = {};
  if (input.name !== undefined) patch.name = displayName(input.name);
  if (input.publicAddress !== undefined) patch.publicAddress = publicAddress(input.publicAddress);
  if (input.listenPort !== undefined) patch.listenPort = listenPort(input.listenPort);
  if (!Object.keys(patch).length) throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
  const updated = await mutateHost({ hostId, kind: AMNEZIAWG_MANAGED_SERVICE_KIND,
    expectedGeneration: generationValue(input.expectedGeneration), work: async (nextGeneration) => {
      if (patch.listenPort !== undefined) await assertManagedServicePortAvailable(hostId, Number(patch.listenPort), id);
      patch.desiredGeneration = nextGeneration; patch.updatedAt = nowDate();
      const q = quoteIdentifier; const columns = Object.keys(patch);
      const result = await executeRaw(
        `UPDATE ${q("xray_managed_services")} SET ${columns.map((key) => `${q(key)}=?`).join(", ")}
          WHERE ${q("id")}=? AND ${q("pendingDelete")}=${boolLiteral(false)} AND ${q("kind")}=?`,
        [...columns.map((key) => patch[key]), id, AMNEZIAWG_MANAGED_SERVICE_KIND],
      );
      if (rawAffectedRows(result) !== 1) throw new XrayManagedServiceError("MANAGED_SERVICE_NOT_FOUND");
      return { serviceId: id };
    } });
  scheduleRefresh(hostId, "xray-amneziawg-service-update");
  await auditManagedServiceMutation({ event: "MANAGED_SERVICE_UPDATED", resourceType: "xray_managed_service", resourceId: id,
    hostId, userId, action: "update", beforeGeneration: generationValue(input.expectedGeneration), generation: updated.desiredGeneration,
    status: "QUEUED", ...(patch.listenPort === undefined ? {} : { port: Number(patch.listenPort) }) });
  return updated;
}

export async function updateXrayManagedService(input: {
  id: unknown; userId: unknown; expectedGeneration: unknown; name?: unknown; publicAddress?: unknown;
  fakeTlsDomain?: unknown; listenPort?: unknown; hostId?: unknown;
}) {
  const userId = positiveId(input.userId, "INVALID_MANAGED_SERVICE_INPUT");
  const id = positiveId(input.id, "MANAGED_SERVICE_NOT_FOUND");
  const current = await serviceRow(id);
  if (managedKind(current.kind) !== MTPROTO_MANAGED_SERVICE_KIND) throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
  const hostId = Number(current.hostId);
  if (input.listenPort !== undefined && positiveId(input.hostId, "HOST_NOT_FOUND") !== hostId) {
    throw new XrayManagedServiceError("PORT_RESERVATION_MISMATCH");
  }
  const patch: Row = {};
  if (input.name !== undefined) patch.name = displayName(input.name);
  if (input.publicAddress !== undefined) patch.publicAddress = publicAddress(input.publicAddress);
  if (input.listenPort !== undefined) patch.listenPort = listenPort(input.listenPort);
  if (input.fakeTlsDomain !== undefined) {
    const domain = fakeTlsDomain(input.fakeTlsDomain);
    patch.specJson = JSON.stringify({ fakeTlsDomain: domain });
  }
  if (Object.keys(patch).length === 0) throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
  const updated = await mutateHost({ hostId, kind: MTPROTO_MANAGED_SERVICE_KIND, expectedGeneration: generationValue(input.expectedGeneration), work: async (nextGeneration, keyring) => {
    if (patch.listenPort !== undefined) await assertManagedServicePortAvailable(hostId, Number(patch.listenPort), id);
    patch.desiredGeneration = nextGeneration;
    patch.updatedAt = nowDate();
    const q = quoteIdentifier;
    const columns = Object.keys(patch);
    const result = await executeRaw(
      `UPDATE ${q("xray_managed_services")} SET ${columns.map((key) => `${q(key)}=?`).join(", ")} WHERE ${q("id")}=? AND ${q("pendingDelete")}=${boolLiteral(false)}`,
      [...columns.map((key) => patch[key]), id],
    );
    if (rawAffectedRows(result) !== 1) throw new XrayManagedServiceError("MANAGED_SERVICE_NOT_FOUND");
    if (patch.specJson !== undefined) {
      const domain = serviceSpec({ specJson: patch.specJson }).fakeTlsDomain;
      const accounts = await queryRaw<Row>(
        `SELECT a.${q("id")}, a.${q("accountTag")} FROM ${q("xray_managed_service_accounts")} a
          WHERE a.${q("serviceId")}=? AND a.${q("pendingDelete")}=${boolLiteral(false)}`,
        [id],
      );
      for (const account of accounts) {
        const accountTag = String(account.accountTag);
        const context = xrayManagedServiceAccountSecretContext(accountTag);
        const secret = mtprotoSecret(domain);
        const encryptedValue = encryptXraySecret(secret, context, keyring);
        const envelope = inspectXraySecretEnvelope(encryptedValue);
        const changedSecret = await executeRaw(
          `UPDATE ${q("xray_managed_service_secrets")}
              SET ${q("encryptedValue")}=?, ${q("fingerprint")}=?, ${q("keyVersion")}=?, ${q("updatedAt")}=?
            WHERE ${q("accountId")}=? AND ${q("kind")}=?`,
          [encryptedValue, fingerprintXraySecret(secret, context, keyring), envelope.version, nowDate(), Number(account.id), "MTPROTO_SECRET"],
        );
        if (rawAffectedRows(changedSecret) !== 1) throw new XrayManagedServiceError("SENSITIVE_DATA_UNAVAILABLE");
      }
    }
    return { serviceId: id };
  } });
  scheduleRefresh(hostId, "xray-managed-service-update");
  await auditManagedServiceMutation({
    event: "MANAGED_SERVICE_UPDATED", resourceType: "xray_managed_service", resourceId: id,
    hostId, userId, action: "update", beforeGeneration: generationValue(input.expectedGeneration),
    generation: updated.desiredGeneration, status: "QUEUED", ...(patch.listenPort === undefined ? {} : { port: Number(patch.listenPort) }),
  });
  return updated;
}

export async function setXrayManagedServiceEnabled(input: { id: unknown; userId: unknown; isEnabled: unknown; expectedGeneration: unknown }) {
  const userId = positiveId(input.userId, "INVALID_MANAGED_SERVICE_INPUT");
  if (typeof input.isEnabled !== "boolean") throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
  const id = positiveId(input.id, "MANAGED_SERVICE_NOT_FOUND");
  const current = await serviceRow(id);
  const hostId = Number(current.hostId);
  const kind = managedKind(current.kind);
  const changed = await mutateHost({ hostId, kind, expectedGeneration: generationValue(input.expectedGeneration), work: async (nextGeneration) => {
    await serviceRow(id);
    if (input.isEnabled && await activeAccountCount(id) < 1) throw new XrayManagedServiceError("LAST_ACTIVE_ACCOUNT_REQUIRED");
    const q = quoteIdentifier;
    const result = await executeRaw(
      `UPDATE ${q("xray_managed_services")} SET ${q("isEnabled")}=?, ${q("desiredGeneration")}=?, ${q("updatedAt")}=?
        WHERE ${q("id")}=? AND ${q("pendingDelete")}=${boolLiteral(false)}`,
      [input.isEnabled, nextGeneration, nowDate(), id],
    );
    if (rawAffectedRows(result) !== 1) throw new XrayManagedServiceError("MANAGED_SERVICE_NOT_FOUND");
    return { serviceId: id, isEnabled: input.isEnabled };
  } });
  scheduleRefresh(hostId, "xray-managed-service-enable");
  await auditManagedServiceMutation({
    event: "MANAGED_SERVICE_ENABLED_CHANGED", resourceType: "xray_managed_service", resourceId: id,
    hostId, userId, action: "update", beforeGeneration: generationValue(input.expectedGeneration),
    generation: changed.desiredGeneration, status: input.isEnabled ? "ENABLED" : "DISABLED",
  });
  return changed;
}

export async function removeXrayManagedService(input: { id: unknown; userId: unknown; expectedGeneration: unknown; confirmName: unknown }) {
  const userId = positiveId(input.userId, "INVALID_MANAGED_SERVICE_INPUT");
  const id = positiveId(input.id, "MANAGED_SERVICE_NOT_FOUND");
  const current = await serviceRow(id);
  const confirmName = String(input.confirmName ?? "");
  const hostId = Number(current.hostId);
  const kind = managedKind(current.kind);
  const changed = await mutateHost({ hostId, kind, expectedGeneration: generationValue(input.expectedGeneration), work: async (nextGeneration) => {
    const currentService = await serviceRow(id);
    if (Number(currentService.hostId) !== hostId) throw new XrayManagedServiceError("MANAGED_SERVICE_NOT_FOUND");
    if (confirmName !== String(currentService.name)) throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
    const q = quoteIdentifier;
    const result = await executeRaw(
      `UPDATE ${q("xray_managed_services")} SET ${q("pendingDelete")}=${boolLiteral(true)}, ${q("isEnabled")}=${boolLiteral(false)}, ${q("desiredGeneration")}=?, ${q("updatedAt")}=?
        WHERE ${q("id")}=? AND ${q("pendingDelete")}=${boolLiteral(false)}`,
      [nextGeneration, nowDate(), id],
    );
    if (rawAffectedRows(result) !== 1) throw new XrayManagedServiceError("MANAGED_SERVICE_NOT_FOUND");
    return { serviceId: id, pendingDelete: true as const };
  } });
  scheduleRefresh(hostId, "xray-managed-service-remove");
  await auditManagedServiceMutation({
    event: "MANAGED_SERVICE_DELETE_REQUESTED", resourceType: "xray_managed_service", resourceId: id,
    hostId, userId, action: "delete", beforeGeneration: generationValue(input.expectedGeneration),
    generation: changed.desiredGeneration, status: "PENDING_DELETE",
  });
  return changed;
}

export async function createXrayManagedServiceAccount(input: { serviceId: unknown; userId: unknown; name: unknown; expectedGeneration: unknown }) {
  const userId = positiveId(input.userId, "INVALID_MANAGED_SERVICE_INPUT");
  const serviceId = positiveId(input.serviceId, "MANAGED_SERVICE_NOT_FOUND");
  const service = await serviceRow(serviceId);
  const name = displayName(input.name);
  const hostId = Number(service.hostId);
  const kind = managedKind(service.kind);
  const created = await mutateHost({ hostId, kind, expectedGeneration: generationValue(input.expectedGeneration), work: async (nextGeneration, keyring) => {
    const currentService = await serviceRow(serviceId);
    if (Number(currentService.hostId) !== hostId) throw new XrayManagedServiceError("MANAGED_SERVICE_NOT_FOUND");
    const q = quoteIdentifier;
    const duplicates = await queryRaw<Row>(
      `SELECT ${q("id")} FROM ${q("xray_managed_service_accounts")} WHERE ${q("serviceId")}=? AND LOWER(${q("name")})=? AND ${q("pendingDelete")}=${boolLiteral(false)} LIMIT 1`,
      [serviceId, name.toLocaleLowerCase()],
    );
    if (duplicates.length) throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
    const existing = await queryRaw<Row>(
      `SELECT ${q("settingsVersion")}, ${q("settingsJson")} FROM ${q("xray_managed_service_accounts")} WHERE ${q("serviceId")}=?`, [serviceId],
    );
    if (existing.length >= (kind === AMNEZIAWG_MANAGED_SERVICE_KIND ? AMNEZIAWG_MAX_PEERS : 64)) {
      throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
    }
    const now = nowDate();
    const accountTag = kind === MTPROTO_MANAGED_SERVICE_KIND
      ? `forwardx-mtproto-account-${crypto.randomUUID()}` : `forwardx-amneziawg-peer-${crypto.randomUUID()}`;
    const peer = kind === AMNEZIAWG_MANAGED_SERVICE_KIND ? generateAmneziaWgPeerMaterial() : null;
    let peerAddress: string | null = null;
    if (peer) {
      try { peerAddress = allocateAmneziaWgPeerAddress(existing); } catch {
        throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
      }
    }
    const accountId = await insertAndGetId("xray_managed_service_accounts", {
      serviceId, name, accountTag, settingsVersion: 1,
      settingsJson: peer ? JSON.stringify({ address: peerAddress, publicKey: peer.publicKey }) : "{}",
      isEnabled: true, pendingDelete: false, desiredGeneration: nextGeneration,
      sortOrder: 0, createdAt: now, updatedAt: now,
    });
    if (peer) {
      await insertEncryptedSecret({ table: "xray_managed_service_secrets", foreignKey: "accountId", foreignId: accountId,
        resourceTag: accountTag, kind: AMNEZIAWG_PEER_PRIVATE_KEY, plaintext: peer.privateKey, scope: "account", keyring, now });
      await insertEncryptedSecret({ table: "xray_managed_service_secrets", foreignKey: "accountId", foreignId: accountId,
        resourceTag: accountTag, kind: AMNEZIAWG_PEER_PRE_SHARED_KEY, plaintext: peer.preSharedKey, scope: "account", keyring, now });
    } else {
      const secret = mtprotoSecret(serviceSpec(currentService).fakeTlsDomain);
      await insertEncryptedSecret({ table: "xray_managed_service_secrets", foreignKey: "accountId", foreignId: accountId,
        resourceTag: accountTag, kind: "MTPROTO_SECRET", plaintext: secret, scope: "account", keyring, now });
    }
    return { serviceId, accountId };
  } });
  scheduleRefresh(hostId, "xray-managed-service-account-create");
  await auditManagedServiceMutation({
    event: "MANAGED_SERVICE_ACCOUNT_CREATED", resourceType: "xray_managed_service_account", resourceId: created.accountId,
    hostId, userId, action: "create", generation: created.desiredGeneration, status: "QUEUED",
  });
  return created;
}

export async function updateXrayManagedServiceAccount(input: { id: unknown; userId: unknown; name?: unknown; isEnabled?: unknown; expectedGeneration: unknown }) {
  const userId = positiveId(input.userId, "INVALID_MANAGED_SERVICE_INPUT");
  const id = positiveId(input.id, "MANAGED_SERVICE_ACCOUNT_NOT_FOUND");
  const account = await accountRow(id);
  const hostId = Number(account.hostId);
  const kind = managedKind(account.kind);
  if (input.isEnabled !== undefined && typeof input.isEnabled !== "boolean") throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
  const name = input.name === undefined ? undefined : displayName(input.name);
  if (name === undefined && input.isEnabled === undefined) throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
  const changed = await mutateHost({ hostId, kind, expectedGeneration: generationValue(input.expectedGeneration), work: async (nextGeneration) => {
    const currentAccount = await accountRow(id);
    if (Number(currentAccount.hostId) !== hostId) throw new XrayManagedServiceError("MANAGED_SERVICE_ACCOUNT_NOT_FOUND");
    if (input.isEnabled === false && databaseBoolean(currentAccount.isEnabled)
      && await activeAccountCount(Number(currentAccount.serviceId)) <= 1) {
      throw new XrayManagedServiceError("LAST_ACTIVE_ACCOUNT_REQUIRED");
    }
    const patch: Row = { desiredGeneration: nextGeneration, updatedAt: nowDate() };
    if (name !== undefined) patch.name = name;
    if (input.isEnabled !== undefined) patch.isEnabled = input.isEnabled;
    const q = quoteIdentifier;
    if (name !== undefined) {
      const duplicate = await queryRaw<Row>(
        `SELECT ${q("id")} FROM ${q("xray_managed_service_accounts")}
          WHERE ${q("serviceId")}=? AND ${q("id")}<>? AND LOWER(${q("name")})=?
            AND ${q("pendingDelete")}=${boolLiteral(false)} LIMIT 1`,
        [Number(currentAccount.serviceId), id, name.toLowerCase()],
      );
      if (duplicate.length) throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
    }
    const columns = Object.keys(patch);
    const result = await executeRaw(
      `UPDATE ${q("xray_managed_service_accounts")} SET ${columns.map((key) => `${q(key)}=?`).join(", ")}
        WHERE ${q("id")}=? AND ${q("pendingDelete")}=${boolLiteral(false)}`,
      [...columns.map((key) => patch[key]), id],
    );
    if (rawAffectedRows(result) !== 1) throw new XrayManagedServiceError("MANAGED_SERVICE_ACCOUNT_NOT_FOUND");
    return { serviceId: Number(currentAccount.serviceId), accountId: id };
  } });
  scheduleRefresh(hostId, "xray-managed-service-account-update");
  await auditManagedServiceMutation({
    event: "MANAGED_SERVICE_ACCOUNT_UPDATED", resourceType: "xray_managed_service_account", resourceId: id,
    hostId, userId, action: "update", beforeGeneration: generationValue(input.expectedGeneration),
    generation: changed.desiredGeneration, status: input.isEnabled === undefined ? "UPDATED" : input.isEnabled ? "ENABLED" : "DISABLED",
  });
  return changed;
}

export async function removeXrayManagedServiceAccount(input: { id: unknown; userId: unknown; expectedGeneration: unknown }) {
  const userId = positiveId(input.userId, "INVALID_MANAGED_SERVICE_INPUT");
  const id = positiveId(input.id, "MANAGED_SERVICE_ACCOUNT_NOT_FOUND");
  const account = await accountRow(id);
  const hostId = Number(account.hostId);
  const kind = managedKind(account.kind);
  const changed = await mutateHost({ hostId, kind, expectedGeneration: generationValue(input.expectedGeneration), work: async (nextGeneration) => {
    const currentAccount = await accountRow(id);
    if (Number(currentAccount.hostId) !== hostId) throw new XrayManagedServiceError("MANAGED_SERVICE_ACCOUNT_NOT_FOUND");
    if (databaseBoolean(currentAccount.isEnabled)
      && await activeAccountCount(Number(currentAccount.serviceId)) <= 1) {
      throw new XrayManagedServiceError("LAST_ACTIVE_ACCOUNT_REQUIRED");
    }
    const q = quoteIdentifier;
    const result = await executeRaw(
      `UPDATE ${q("xray_managed_service_accounts")} SET ${q("pendingDelete")}=${boolLiteral(true)}, ${q("isEnabled")}=${boolLiteral(false)}, ${q("desiredGeneration")}=?, ${q("updatedAt")}=?
        WHERE ${q("id")}=? AND ${q("pendingDelete")}=${boolLiteral(false)}`,
      [nextGeneration, nowDate(), id],
    );
    if (rawAffectedRows(result) !== 1) throw new XrayManagedServiceError("MANAGED_SERVICE_ACCOUNT_NOT_FOUND");
    return { serviceId: Number(currentAccount.serviceId), accountId: id, pendingDelete: true as const };
  } });
  scheduleRefresh(hostId, "xray-managed-service-account-remove");
  await auditManagedServiceMutation({
    event: "MANAGED_SERVICE_ACCOUNT_DELETE_REQUESTED", resourceType: "xray_managed_service_account", resourceId: id,
    hostId, userId, action: "delete", beforeGeneration: generationValue(input.expectedGeneration),
    generation: changed.desiredGeneration, status: "PENDING_DELETE",
  });
  return changed;
}

export async function getXrayManagedServiceShare(accountIdValue: unknown) {
  const accountId = positiveId(accountIdValue, "MANAGED_SERVICE_ACCOUNT_NOT_FOUND");
  const account = await accountRow(accountId);
  const hostId = Number(account.hostId);
  return withKeyedTaskLock(`xray-managed-service-host:${hostId}`, async () => {
    const currentAccount = await accountRow(accountId);
    if (Number(currentAccount.hostId) !== hostId) throw new XrayManagedServiceError("MANAGED_SERVICE_ACCOUNT_NOT_FOUND");
    const kind = managedKind(currentAccount.kind);
    await requireOnlineCapability(hostId, kind);
    if (!databaseBoolean(currentAccount.serviceEnabled) || !databaseBoolean(currentAccount.isEnabled)) {
      throw new XrayManagedServiceError("INVALID_MANAGED_SERVICE_INPUT");
    }
    const q = quoteIdentifier;
    const secretRows = await queryRaw<Row>(
      `SELECT ${["kind", "encryptedValue", "fingerprint", "keyVersion"].map(q).join(", ")}
         FROM ${q("xray_managed_service_secrets")} WHERE ${q("accountId")}=?`, [accountId],
    );
    const keyring = loadXrayMasterKeyFile();
    const server = String(currentAccount.publicAddress);
    const port = Number(currentAccount.listenPort);
    if (kind === AMNEZIAWG_MANAGED_SERVICE_KIND) {
      const instanceSecrets = await queryRaw<Row>(
        `SELECT ${["kind", "encryptedValue", "fingerprint", "keyVersion"].map(q).join(", ")}
           FROM ${q("xray_managed_service_instance_secrets")} WHERE ${q("serviceId")}=?`, [Number(currentAccount.serviceId)],
      );
      if (secretRows.length !== 2 || instanceSecrets.length !== 2) throw new XrayManagedServiceError("SENSITIVE_DATA_UNAVAILABLE");
      const resourceTag = String(currentAccount.accountTag);
      const privateKey = decryptTypedSecret({ row: secretRows.find((row) => row.kind === AMNEZIAWG_PEER_PRIVATE_KEY),
        resourceTag, kind: AMNEZIAWG_PEER_PRIVATE_KEY, scope: "account", keyring, privateKey: true });
      const preSharedKey = decryptTypedSecret({ row: secretRows.find((row) => row.kind === AMNEZIAWG_PEER_PRE_SHARED_KEY),
        resourceTag, kind: AMNEZIAWG_PEER_PRE_SHARED_KEY, scope: "account", keyring });
      if (Buffer.from(preSharedKey, "base64").every((byte) => byte === 0)) throw new XrayManagedServiceError("SENSITIVE_DATA_UNAVAILABLE");
      const serverPrivateKey = decryptTypedSecret({ row: instanceSecrets.find((row) => row.kind === AMNEZIAWG_SERVER_PRIVATE_KEY),
        resourceTag: String(currentAccount.serviceTag), kind: AMNEZIAWG_SERVER_PRIVATE_KEY, scope: "service", keyring, privateKey: true });
      const headerProtectionKey = decryptTypedSecret({ row: instanceSecrets.find((row) => row.kind === AMNEZIAWG_HEADER_PROTECTION_KEY),
        resourceTag: String(currentAccount.serviceTag), kind: AMNEZIAWG_HEADER_PROTECTION_KEY, scope: "service", keyring });
      const settings = amneziaPeerSettings(currentAccount.settingsVersion, currentAccount.settingsJson);
      if (deriveXrayWireGuardPublicKey(privateKey) !== settings.publicKey) throw new XrayManagedServiceError("SENSITIVE_DATA_UNAVAILABLE");
      return buildAmneziaWgClientShare({ name: String(currentAccount.name), peerPrivateKey: privateKey,
        peerAddress: settings.address, preSharedKey, serverPrivateKey, publicAddress: server, listenPort: port,
        obfuscation: { ...amneziaStoredSpec(currentAccount.specJson), headerProtectionKey } });
    }
    const secretRow = secretRows.find((row) => row.kind === "MTPROTO_SECRET");
    if (!secretRow) throw new XrayManagedServiceError("SENSITIVE_DATA_UNAVAILABLE");
    const secret = decryptManagedServiceSecret(secretRow, String(currentAccount.accountTag), serviceSpec(currentAccount).fakeTlsDomain, keyring);
    const query = new URLSearchParams({ server, port: String(port), secret });
    return { kind: "MTPROTO_PROXY" as const, uri: `tg://proxy?${query}`, server, port, secret };
  });
}

export async function processXrayManagedServicesHeartbeatReport(input: {
  hostId: unknown; managedServicesCapability?: unknown; managedServicesStateSignature?: unknown; managedServicesState?: unknown;
}) {
  const hostId = positiveId(input.hostId, "HOST_NOT_FOUND");
  return withKeyedTaskLock(`xray-managed-service-host:${hostId}`, async () => {
    let report = await runtimeReport(hostId);
    if (input.managedServicesCapability !== undefined) {
      const parsed = XrayManagedServicesCapabilitySchema.safeParse(input.managedServicesCapability);
      const capabilityJson = parsed.success ? JSON.stringify(parsed.data) : null;
      const now = nowDate();
      if (report) {
        await executeRaw(
          `UPDATE ${quoteIdentifier("xray_managed_service_runtime_reports")} SET ${quoteIdentifier("capabilityJson")}=?, ${quoteIdentifier("updatedAt")}=? WHERE ${quoteIdentifier("id")}=?`,
          [capabilityJson, now, Number(report.id)],
        );
      } else {
        await insertAndGetId("xray_managed_service_runtime_reports", { hostId, capabilityJson, updatedAt: now });
      }
      report = await runtimeReport(hostId);
    }
    const capability = parsedCapability(report);
    if (!capability) return { compatible: false, requestManagedServicesState: false, managedServicesStateSignature: "", observedState: null };
    const signature = String(input.managedServicesStateSignature ?? "");
    if (!/^[0-9a-f]{64}$/.test(signature)) return { compatible: true, requestManagedServicesState: true, managedServicesStateSignature: "", observedState: null };
    if (input.managedServicesState === undefined) {
      const cached = report?.stateSignature === signature ? parsedObserved(report) : null;
      return { compatible: true, requestManagedServicesState: !cached, managedServicesStateSignature: signature, observedState: cached };
    }
    const parsed = XrayManagedServicesObservedStateSchema.safeParse(input.managedServicesState);
    if (!parsed.success || observedSignature(parsed.data) !== signature) {
      return { compatible: true, requestManagedServicesState: true, managedServicesStateSignature: signature, observedState: null };
    }
    const now = nowDate();
    await executeRaw(
      `UPDATE ${quoteIdentifier("xray_managed_service_runtime_reports")}
          SET ${quoteIdentifier("stateJson")}=?, ${quoteIdentifier("stateSignature")}=?, ${quoteIdentifier("reportedAt")}=?, ${quoteIdentifier("updatedAt")}=?
        WHERE ${quoteIdentifier("hostId")}=?`,
      [JSON.stringify(parsed.data), signature, new Date(parsed.data.observedAt), now, hostId],
    );
    const desired = await deployment(hostId);
    if (desired && parsed.data.appliedGeneration === Number(desired.desiredGeneration)
      && parsed.data.appliedConfigHash === desired.desiredConfigHash) {
      await withDatabaseTransaction(async () => {
        const q = quoteIdentifier;
        const observedServiceIds = parsed.data.services.map((service) => service.serviceId);
        const absentFromObserved = observedServiceIds.length
          ? ` AND s.${q("id")} NOT IN (${observedServiceIds.map(() => "?").join(", ")})`
          : "";
        const serviceAbsentFromObserved = observedServiceIds.length
          ? ` AND ${q("id")} NOT IN (${observedServiceIds.map(() => "?").join(", ")})`
          : "";
        await executeRaw(
          `DELETE FROM ${q("xray_managed_service_secrets")} WHERE ${q("accountId")} IN
            (SELECT a.${q("id")} FROM ${q("xray_managed_service_accounts")} a
              JOIN ${q("xray_managed_services")} s ON s.${q("id")} = a.${q("serviceId")}
             WHERE s.${q("hostId")}=? AND
               ((s.${q("pendingDelete")}=${boolLiteral(true)} AND s.${q("desiredGeneration")}<=?${absentFromObserved})
                OR (a.${q("pendingDelete")}=${boolLiteral(true)} AND a.${q("desiredGeneration")}<=?)))`,
          [hostId, parsed.data.appliedGeneration, ...observedServiceIds, parsed.data.appliedGeneration],
        );
        await executeRaw(
          `DELETE FROM ${q("xray_managed_service_accounts")} WHERE ${q("serviceId")} IN
            (SELECT s.${q("id")} FROM ${q("xray_managed_services")} s WHERE s.${q("hostId")}=?
              AND s.${q("pendingDelete")}=${boolLiteral(true)} AND s.${q("desiredGeneration")}<=?${absentFromObserved})`,
          [hostId, parsed.data.appliedGeneration, ...observedServiceIds],
        );
        await executeRaw(
          `DELETE FROM ${q("xray_managed_service_accounts")} WHERE ${q("serviceId")} IN
            (SELECT ${q("id")} FROM ${q("xray_managed_services")} WHERE ${q("hostId")}=? )
            AND ${q("pendingDelete")}=${boolLiteral(true)} AND ${q("desiredGeneration")}<=?`,
          [hostId, parsed.data.appliedGeneration],
        );
        await executeRaw(
          `DELETE FROM ${q("xray_managed_service_instance_secrets")} WHERE ${q("serviceId")} IN
            (SELECT ${q("id")} FROM ${q("xray_managed_services")} WHERE ${q("hostId")}=?
              AND ${q("pendingDelete")}=${boolLiteral(true)} AND ${q("desiredGeneration")}<=?${serviceAbsentFromObserved})`,
          [hostId, parsed.data.appliedGeneration, ...observedServiceIds],
        );
        await executeRaw(
          `DELETE FROM ${q("xray_managed_services")} WHERE ${q("hostId")}=?
              AND ${q("pendingDelete")}=${boolLiteral(true)} AND ${q("desiredGeneration")}<=?${serviceAbsentFromObserved}`,
          [hostId, parsed.data.appliedGeneration, ...observedServiceIds],
        );
      });
    }
    return { compatible: true, requestManagedServicesState: false, managedServicesStateSignature: signature, observedState: parsed.data };
  });
}

export async function buildXrayManagedServicesDesiredState(
  hostIdValue: unknown,
  options: { keyring?: XraySecretKeyring; issuedAt?: Date } = {},
): Promise<XrayManagedServicesDesiredState | null> {
  const hostId = positiveId(hostIdValue, "HOST_NOT_FOUND");
  return withKeyedTaskLock(`xray-managed-service-host:${hostId}`, async () => {
    const current = await deployment(hostId);
    if (!current) return null;
    const capability = parsedCapability(await runtimeReport(hostId));
    if (!capability || (!supportsMtprotoCapability(capability) && !supportsAmneziaWgCapability(capability))) return null;
    const services = await desiredServices(hostId, options.keyring ?? loadXrayMasterKeyFile(), capability);
    const configHash = stateHash(services);
    if (current.desiredConfigHash && current.desiredConfigHash !== configHash) {
      throw new Error("Managed service desired config hash conflicts with structured state");
    }
    if (!current.desiredConfigHash) {
      await executeRaw(
        `UPDATE ${quoteIdentifier("xray_managed_service_deployments")} SET ${quoteIdentifier("desiredConfigHash")}=?, ${quoteIdentifier("updatedAt")}=? WHERE ${quoteIdentifier("id")}=?`,
        [configHash, nowDate(), Number(current.id)],
      );
    }
    return XrayManagedServicesDesiredStateSchema.parse({
      schemaVersion: 1,
      generation: generationValue(current.desiredGeneration),
      issuedAt: (options.issuedAt ?? new Date()).toISOString(),
      configHash,
      services,
    });
  });
}

export function xrayManagedServicesStateSignature(value: unknown) {
  return observedSignature(XrayManagedServicesObservedStateSchema.parse(value));
}

export function isXrayManagedServicesDesiredApplied(
  desired: XrayManagedServicesDesiredState | null | undefined,
  observed: XrayManagedServicesObservedState | null | undefined,
) {
  if (!desired) return true;
  if (!observed || observed.appliedGeneration !== desired.generation || observed.appliedConfigHash !== desired.configHash) return false;
  if (observed.services.length !== desired.services.length) return false;
  return desired.services.every((service) => {
    const actual = observed.services.find((candidate) => candidate.serviceId === service.serviceId);
    return !!actual && actual.kind === service.kind && actual.serviceTag === service.serviceTag
      && actual.installedVersion === service.targetVersion && actual.runningVersion === service.targetVersion
      && actual.serviceStatus === "RUNNING" && !!actual.processId && !!actual.binarySha256
      && actual.listener.network === (service.kind === AMNEZIAWG_MANAGED_SERVICE_KIND ? "udp" : "tcp")
      && actual.listener.port === service.listenPort && actual.listener.status === "READY";
  });
}
