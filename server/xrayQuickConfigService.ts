import crypto from "node:crypto";
import { domainToASCII } from "node:url";
import { isIP } from "node:net";

import {
  resolveStoredXrayInboundDefinition,
  type XrayProfileShareFormat,
} from "../shared/xrayProfiles";
import {
  normalizeXrayExternalProxyAddress,
  type XrayExternalProxyProtocol,
} from "../shared/xrayExternalProxy";
import { XrayObservedListenerSchema } from "../shared/xrayTypes";
import { quoteIdentifier } from "./dbCompat";
import { queryRaw } from "./dbRuntime";
import { computeXrayQuickConfigDnsTupleHash } from "./xrayQuickConfigDnsTuple";
import {
  DnsProviderAccountServiceError,
  getGlobalDnsProviderAccountService,
  listGlobalDnsProviderZonesService,
} from "./dnsProviderAccountService";
import {
  DnsPodProviderClient,
  DnsPodProviderError,
  type DnsPodCredentials,
  type DnsPodRecord,
  type DnsPodZone,
} from "./dnsPodProviderClient";
import { ENV } from "./env";
import { HOST_ONLINE_TTL_MS } from "./hostHeartbeatPolicy";
import {
  DnsProviderRepositoryError,
  loadGlobalDnsProviderCredentials,
  type DnsProviderZoneSafeDto,
} from "./repositories/dnsProviderRepository";
import {
  listXrayExternalProxyNodes,
  XrayExternalProxyServiceError,
  type XrayExternalProxySafeDto,
} from "./xrayExternalProxyService";

export const QUICK_CONFIG_SERVICE_ERROR_CODES = [
  "DOMAIN_INVALID",
  "DOMAIN_CHECK_INVALID",
  "DOMAIN_CHECK_EXPIRED",
  "DOMAIN_CONFIRMATION_INVALID",
  "DOMAIN_CONFIRMATION_EXPIRED",
  "DOMAIN_CONFIRMATION_REQUIRED",
  "DOMAIN_CONFLICT_CHANGED",
  "DOMAIN_ALREADY_MANAGED",
  "QUICK_CONFIG_TARGET_UNSUPPORTED",
  "QUICK_CONFIG_TARGET_CHANGED",
  "DNS_PROVIDER_NOT_CONFIGURED",
  "DNS_PROVIDER_INVALID",
  "DNS_PROVIDER_VALIDATION_STALE",
  "DNS_PROVIDER_CATALOG_STALE",
  "DNS_PROVIDER_LINE_MISSING",
  "DNS_PROVIDER_LINE_AMBIGUOUS",
  "DNS_PROVIDER_NO_ZONES",
  "DNS_PROVIDER_CONFLICT",
  "SENSITIVE_DATA_UNAVAILABLE",
] as const;

export type QuickConfigServiceErrorCode = typeof QUICK_CONFIG_SERVICE_ERROR_CODES[number];

export class XrayQuickConfigServiceError extends Error {
  constructor(readonly code: QuickConfigServiceErrorCode) {
    super(code);
    this.name = "XrayQuickConfigServiceError";
  }
}

export type QuickConfigTargetType = "XRAY_INBOUND" | "EXTERNAL_PROXY_NODE";
export type QuickConfigShareCapability = "VLESS_URI" | "SHADOWSOCKS_URI" | "SOCKS5_ENDPOINT" | "NONE";

export type QuickConfigTarget =
  | Readonly<{
      targetType: "XRAY_INBOUND";
      targetId: number;
      targetVersion: string;
      name: string;
      protocol: string;
      profileId: string;
      host: { id: number; name: string };
      endpoint: { address: string; port: number };
      eligible: boolean;
      disabledReasonCode: string | null;
      shareCapability: QuickConfigShareCapability;
    }>
  | Readonly<{
      targetType: "EXTERNAL_PROXY_NODE";
      targetId: number;
      targetVersion: string;
      name: string;
      protocol: XrayExternalProxyProtocol;
      endpoint: { address: string; port: number };
      eligible: boolean;
      disabledReasonCode: string | null;
      shareCapability: Exclude<QuickConfigShareCapability, "NONE">;
    }>;

export type DomainRecordProjection = Readonly<{
  recordRef: string;
  recordType: "A" | "AAAA" | "CNAME" | "TXT" | "MX" | "CAA" | "OTHER";
  providerLineId: string;
  lineName: string;
  value: string;
  ttl: number;
}>;

export type DomainCheckDto = Readonly<{
  fqdn: string;
  conflicts: DomainRecordProjection[];
  preservedRecords: DomainRecordProjection[];
  ownedRecordRefs?: string[];
  allowedActions: Array<"USE_UNUSED_NAME" | "REPLACE_CONFLICTING_RECORDS">;
  confirmationHash: string;
  domainCheckToken: string;
  expiresAt: string;
}>;

type Row = Record<string, unknown>;
type QuickConfigTargetRef = Readonly<{
  targetType: QuickConfigTargetType;
  targetId: number;
  targetVersion: string;
}>;
export type QuickConfigEditIdentity = Readonly<{
  quickConfigId: number;
  expectedRevision: number;
}>;
type DomainAction = "USE_UNUSED_NAME" | "REPLACE_CONFLICTING_RECORDS";
type TokenKind = "DOMAIN_CHECK" | "DOMAIN_CONFIRMED";

type DomainTokenPayload = Readonly<{
  v: 1;
  kind: TokenKind;
  nonce: string;
  userId: number;
  accountId: number;
  accountRevision: number;
  bindingRevision: number;
  zoneId: number;
  relativeName: string;
  fqdn: string;
  targetType: QuickConfigTargetType;
  targetId: number;
  targetVersion: string;
  editQuickConfigId?: number;
  editExpectedRevision?: number;
  recordSetHash: string;
  confirmationHash: string;
  action?: DomainAction;
  issuedAt: number;
  expiresAt: number;
}>;

type QuickConfigServiceOptions = Readonly<{
  now?: () => Date;
  tokenSecret?: string;
  dnsPodClientFactory?: (credentials: DnsPodCredentials) => Pick<DnsPodProviderClient, "listRecords">;
}>;

export type ResolvedQuickConfigDomain = Readonly<{
  userId: number;
  accountId: number;
  accountRevision: number;
  bindingRevision: number;
  zoneId: number;
  zone: DnsProviderZoneSafeDto;
  relativeName: string;
  fqdn: string;
  target: QuickConfigTarget;
  targetRef: QuickConfigTargetRef;
  editIdentity: QuickConfigEditIdentity | null;
  recordSetHash: string;
  confirmationHash: string;
  action: DomainAction;
  conflicts: DomainRecordProjection[];
  ownedRecordRefs: string[];
  preservedRecords: DomainRecordProjection[];
}>;

const DOMAIN_CHECK_TTL_MS = 5 * 60 * 1_000;
const DOMAIN_CONFIRMED_TTL_MS = 10 * 60 * 1_000;
const MAX_DOMAIN_RECORDS = 512;
const MAX_TOKEN_BYTES = 4_096;
const HEX_64 = /^[a-f0-9]{64}$/;
const TOKEN_PART = /^[A-Za-z0-9_-]+$/;
const RELATIVE_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const TOKEN_CONTEXT = "forwardx-xray-quick-config-domain-token:v1";
const RECORD_REF_CONTEXT = "forwardx-xray-quick-config-record-ref:v1";

function fail(code: QuickConfigServiceErrorCode): never {
  throw new XrayQuickConfigServiceError(code);
}

function positiveSafeInteger(value: unknown, code: QuickConfigServiceErrorCode = "DOMAIN_CHECK_INVALID"): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) fail(code);
  return parsed;
}

function safePort(value: unknown): number | null {
  const port = Number(value);
  return Number.isSafeInteger(port) && port >= 1 && port <= 65535 ? port : null;
}

function safeText(value: unknown, maximumBytes: number): string | null {
  if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > maximumBytes
    || /[\u0000-\u001f\u007f]/.test(value)) return null;
  return value;
}

function dateValue(value: unknown): Date | null {
  if (value == null || value === "") return null;
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? new Date(value) : null;
  const text = String(value);
  const numeric = /^\d+(?:\.\d+)?$/.test(text) ? Number(text) : NaN;
  const date = Number.isFinite(numeric) ? new Date(numeric < 10_000_000_000 ? numeric * 1_000 : numeric) : new Date(text);
  return Number.isFinite(date.getTime()) ? date : null;
}

function booleanValue(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || String(value ?? "").toLowerCase() === "true";
}

function stableValue(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(stableValue);
  if (!value || typeof value !== "object") fail("DOMAIN_CHECK_INVALID");
  const output: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    const entry = (value as Record<string, unknown>)[key];
    if (entry === undefined) fail("DOMAIN_CHECK_INVALID");
    output[key] = stableValue(entry);
  }
  return output;
}

function stableJson(value: unknown): string {
  return JSON.stringify(stableValue(value));
}

function sha256(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function hmacHex(key: Buffer, value: string): string {
  return crypto.createHmac("sha256", key).update(value, "utf8").digest("hex");
}

function tokenKey(secret = ENV.cookieSecret): Buffer {
  if (typeof secret !== "string" || Buffer.byteLength(secret, "utf8") < 16) fail("SENSITIVE_DATA_UNAVAILABLE");
  return crypto.createHmac("sha256", secret).update(TOKEN_CONTEXT, "utf8").digest();
}

function hashEqual(left: unknown, right: unknown): boolean {
  if (typeof left !== "string" || typeof right !== "string" || !HEX_64.test(left) || !HEX_64.test(right)) return false;
  return crypto.timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function canonicalTargetVersion(value: unknown): string {
  return sha256(stableJson(value));
}

function ipv4Number(address: string): number {
  return address.split(".").reduce((result, part) => result * 256 + Number(part), 0) >>> 0;
}

function publicIpv4(address: string): boolean {
  const value = ipv4Number(address);
  const inRange = (base: string, prefix: number) => {
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return (value & mask) === (ipv4Number(base) & mask);
  };
  return ![
    ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
    ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
    ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
  ].some(([base, prefix]) => inRange(base as string, prefix as number));
}

function publicIpv6(address: string): boolean {
  const lower = address.toLowerCase();
  return lower !== "::" && lower !== "::1" && !lower.startsWith("fc") && !lower.startsWith("fd")
    && !/^fe[89ab]/.test(lower) && !lower.startsWith("ff") && !lower.startsWith("2001:db8:")
    && !lower.startsWith("100:");
}

function publicEndpointAddress(value: unknown): string | null {
  let address: string;
  try {
    address = normalizeXrayExternalProxyAddress(value);
  } catch {
    return null;
  }
  const family = isIP(address);
  if (family === 4) return publicIpv4(address) ? address : null;
  if (family === 6) return publicIpv6(address) ? address : null;
  const ascii = domainToASCII(address).toLowerCase();
  if (ascii !== address || !ascii.includes(".") || ascii.endsWith(".local") || ascii.endsWith(".localhost")
    || ascii.endsWith(".internal") || ascii.endsWith(".invalid") || ascii.endsWith(".test")
    || ascii.endsWith(".example")) return null;
  return ascii;
}

function hostOnline(row: Row, now: Date): boolean {
  const heartbeat = dateValue(row.lastHeartbeat);
  return booleanValue(row.hostOnline) && !!heartbeat && now.getTime() - heartbeat.getTime() <= HOST_ONLINE_TTL_MS;
}

function listenersInSync(row: Row): boolean {
  try {
    const raw = JSON.parse(String(row.listenersJson ?? "[]"));
    if (!Array.isArray(raw) || raw.length > 256) return false;
    return raw.some((value) => {
      const parsed = XrayObservedListenerSchema.safeParse(value);
      return parsed.success && parsed.data.runtimeTag === row.runtimeTag && parsed.data.network === "tcp"
        && parsed.data.port === Number(row.listenPort) && parsed.data.status === "READY";
    });
  } catch {
    return false;
  }
}

function profileShareCapability(format: XrayProfileShareFormat): QuickConfigShareCapability {
  if (format === "VLESS_URI" || format === "SHADOWSOCKS_URI") return format;
  if (format === "MIXED_PROXY_ENDPOINTS") return "SOCKS5_ENDPOINT";
  return "NONE";
}

async function listInboundTargets(now: Date): Promise<QuickConfigTarget[]> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Row>(
    `SELECT i.*, h.${q("name")} AS ${q("hostName")}, h.${q("isOnline")} AS ${q("hostOnline")},
       h.${q("lastHeartbeat")} AS ${q("lastHeartbeat")}, d.${q("desiredGeneration")} AS ${q("deploymentDesiredGeneration")},
       d.${q("desiredConfigHash")} AS ${q("desiredConfigHash")}, r.${q("appliedGeneration")} AS ${q("appliedGeneration")},
       r.${q("appliedConfigHash")} AS ${q("appliedConfigHash")}, r.${q("serviceStatus")} AS ${q("runtimeServiceStatus")},
       r.${q("listenersJson")} AS ${q("listenersJson")}
     FROM ${q("xray_inbounds")} i
     JOIN ${q("hosts")} h ON h.${q("id")} = i.${q("hostId")}
     LEFT JOIN ${q("xray_host_deployments")} d ON d.${q("hostId")} = i.${q("hostId")}
     LEFT JOIN ${q("xray_runtime_reports")} r ON r.${q("hostId")} = i.${q("hostId")}`,
  );
  return rows.map((row) => {
    const targetId = positiveSafeInteger(row.id, "QUICK_CONFIG_TARGET_UNSUPPORTED");
    const hostId = positiveSafeInteger(row.hostId, "QUICK_CONFIG_TARGET_UNSUPPORTED");
    const name = safeText(row.name, 128) ?? "";
    const hostName = safeText(row.hostName, 128) ?? "";
    const protocol = (safeText(row.protocol, 32) ?? "").toUpperCase();
    const endpointAddress = publicEndpointAddress(row.publicAddress);
    const endpointPort = safePort(row.listenPort);
    const definition = resolveStoredXrayInboundDefinition({
      protocol: row.protocol,
      transport: row.transport,
      security: row.security,
      profileId: row.profileId,
      specVersion: row.specVersion,
      specJson: row.specJson,
    });
    const enabled = booleanValue(row.isEnabled);
    const pendingDelete = booleanValue(row.pendingDelete);
    const online = hostOnline(row, now);
    const tcpSupported = definition?.profile.listenerNetworks.includes("TCP") === true
      && definition.profile.id !== "TUNNEL_TCP_LOCAL_NONE";
    const synchronized = Number(row.deploymentDesiredGeneration) === Number(row.appliedGeneration)
      && Number(row.desiredGeneration) <= Number(row.appliedGeneration)
      && typeof row.desiredConfigHash === "string" && row.desiredConfigHash.length === 64
      && row.desiredConfigHash === row.appliedConfigHash && row.runtimeServiceStatus === "RUNNING"
      && listenersInSync(row);
    const disabledReasonCode = !enabled ? "TARGET_DISABLED"
      : pendingDelete ? "TARGET_PENDING_DELETE"
        : !definition ? "TARGET_PROFILE_INVALID"
          : !tcpSupported ? "TARGET_TCP_UNSUPPORTED"
            : !endpointAddress || !endpointPort ? "TARGET_ENDPOINT_INVALID"
              : !online ? "TARGET_HOST_OFFLINE"
                : !synchronized ? "TARGET_NOT_SYNCED" : null;
    const eligible = disabledReasonCode === null;
    const specHash = definition ? sha256(stableJson(definition.spec)) : sha256(String(row.specJson ?? ""));
    const profileId = definition?.profile.id ?? safeText(row.profileId, 128) ?? "";
    const targetVersion = canonicalTargetVersion({
      schema: "quick-config-target:xray-inbound:v1",
      targetType: "XRAY_INBOUND",
      targetId,
      runtimeTag: safeText(row.runtimeTag, 128) ?? "",
      hostId,
      publicAddress: endpointAddress ?? "",
      listenPort: endpointPort ?? 0,
      protocol: safeText(row.protocol, 32) ?? "",
      transport: safeText(row.transport, 32) ?? "",
      security: safeText(row.security, 32) ?? "",
      profileId,
      specVersion: definition?.specVersion ?? (Number(row.specVersion) || 0),
      specHash,
      enabled,
      pendingDelete,
      eligible,
      disabledReasonCode,
    });
    return {
      targetType: "XRAY_INBOUND" as const,
      targetId,
      targetVersion,
      name,
      protocol,
      profileId,
      host: { id: hostId, name: hostName },
      endpoint: { address: endpointAddress ?? "", port: endpointPort ?? 0 },
      eligible,
      disabledReasonCode,
      shareCapability: definition ? profileShareCapability(definition.profile.shareFormat) : "NONE",
    };
  });
}

async function listAllExternalNodes(): Promise<XrayExternalProxySafeDto[]> {
  const output: XrayExternalProxySafeDto[] = [];
  for (let page = 1; page <= 10_000; page += 1) {
    const result = await listXrayExternalProxyNodes({ page, pageSize: 100 });
    output.push(...result.items);
    if (output.length >= result.total || result.items.length === 0) return output;
  }
  fail("QUICK_CONFIG_TARGET_UNSUPPORTED");
}

async function listExternalTargets(): Promise<QuickConfigTarget[]> {
  const nodes = await listAllExternalNodes();
  if (nodes.length === 0) return [];
  const q = quoteIdentifier;
  const tags = new Map<number, string>();
  for (let offset = 0; offset < nodes.length; offset += 200) {
    const ids = nodes.slice(offset, offset + 200).map((node) => node.id);
    const rows = await queryRaw<Row>(
      `SELECT ${q("id")}, ${q("nodeTag")} FROM ${q("xray_external_proxy_nodes")} WHERE ${q("id")} IN (${ids.map(() => "?").join(", ")})`,
      ids,
    );
    for (const row of rows) tags.set(Number(row.id), safeText(row.nodeTag, 128) ?? "");
  }
  return nodes.map((node) => {
    const address = publicEndpointAddress(node.address);
    const nodeTag = tags.get(node.id) ?? "";
    const eligible = !!address && !!safePort(node.port) && !!nodeTag && node.credentialsConfigured;
    const disabledReasonCode = eligible ? null : "TARGET_ENDPOINT_INVALID";
    const targetVersion = canonicalTargetVersion({
      schema: "quick-config-target:external-proxy:v1",
      targetType: "EXTERNAL_PROXY_NODE",
      targetId: node.id,
      nodeTag,
      protocol: node.protocol,
      address: address ?? "",
      port: node.port,
      specVersion: node.specVersion,
      specHash: sha256(stableJson(node.publicSettings)),
      eligible,
      disabledReasonCode,
    });
    const shareCapability = node.protocol === "VLESS_REALITY_VISION" ? "VLESS_URI"
      : node.protocol === "SHADOWSOCKS" ? "SHADOWSOCKS_URI" : "SOCKS5_ENDPOINT";
    return {
      targetType: "EXTERNAL_PROXY_NODE" as const,
      targetId: node.id,
      targetVersion,
      name: node.name,
      protocol: node.protocol,
      endpoint: { address: address ?? "", port: node.port },
      eligible,
      disabledReasonCode,
      shareCapability,
    };
  });
}

function resolvedNow(options: QuickConfigServiceOptions): Date {
  const value = options.now?.() ?? new Date();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) fail("DOMAIN_CHECK_INVALID");
  return new Date(value);
}

async function allTargets(now: Date): Promise<QuickConfigTarget[]> {
  const [inbounds, external] = await Promise.all([listInboundTargets(now), listExternalTargets()]);
  return [...inbounds, ...external];
}

export async function listQuickConfigTargets(input: {
  search?: string;
  targetType?: QuickConfigTargetType;
  page?: number;
  pageSize?: number;
} = {}, options: QuickConfigServiceOptions = {}) {
  try {
    const page = input.page ?? 1;
    const pageSize = input.pageSize ?? 20;
    if (!Number.isSafeInteger(page) || page < 1 || !Number.isSafeInteger(pageSize) || pageSize < 1 || pageSize > 100) {
      fail("QUICK_CONFIG_TARGET_UNSUPPORTED");
    }
    const search = String(input.search ?? "").trim().toLocaleLowerCase();
    if (Buffer.byteLength(search, "utf8") > 128) fail("QUICK_CONFIG_TARGET_UNSUPPORTED");
    let items = await allTargets(resolvedNow(options));
    if (input.targetType) items = items.filter((item) => item.targetType === input.targetType);
    if (search) items = items.filter((item) => {
      const fields = item.targetType === "XRAY_INBOUND"
        ? [item.name, item.host.name, item.endpoint.address]
        : [item.name, item.endpoint.address];
      return fields.some((field) => field.toLocaleLowerCase().includes(search));
    });
    items.sort((left, right) => left.targetType.localeCompare(right.targetType)
      || left.name.localeCompare(right.name) || left.targetId - right.targetId);
    const total = items.length;
    return { items: items.slice((page - 1) * pageSize, page * pageSize), total, page, pageSize };
  } catch (error) {
    serviceError(error);
  }
}

async function resolveTargetRef(ref: QuickConfigTargetRef, now: Date): Promise<QuickConfigTarget> {
  const target = (await allTargets(now)).find((item) => item.targetType === ref.targetType && item.targetId === ref.targetId);
  if (!target) fail("QUICK_CONFIG_TARGET_UNSUPPORTED");
  if (!hashEqual(target.targetVersion, ref.targetVersion)) fail("QUICK_CONFIG_TARGET_CHANGED");
  if (!target.eligible) fail("QUICK_CONFIG_TARGET_UNSUPPORTED");
  return target;
}

function normalizeRelativeName(value: unknown, zoneName: string): { relativeName: string; fqdn: string } {
  if (typeof value !== "string") fail("DOMAIN_INVALID");
  const relativeName = value.trim().toLowerCase();
  if (!relativeName || relativeName === "@" || relativeName.includes("*") || relativeName.includes(":")
    || relativeName.includes("/") || relativeName.includes("\\") || /[^\x21-\x7e]/.test(relativeName)
    || Buffer.byteLength(relativeName, "ascii") > 253) fail("DOMAIN_INVALID");
  const labels = relativeName.split(".");
  if (labels.some((label) => !RELATIVE_LABEL.test(label) || domainToASCII(label).toLowerCase() !== label)) fail("DOMAIN_INVALID");
  const fqdn = `${relativeName}.${zoneName}`;
  if (fqdn.length > 253 || fqdn.split(".").some((label) => label.length > 63)) fail("DOMAIN_INVALID");
  return { relativeName, fqdn };
}

async function assertDomainNotManaged(
  accountId: number,
  zoneId: number,
  relativeName: string,
  fqdn: string,
  exceptQuickConfigId?: number,
): Promise<void> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Row>(
    `SELECT ${q("id")} FROM ${q("xray_quick_configs")}
      WHERE ${q("dnsAccountId")} = ? AND ${q("zoneId")} = ? AND LOWER(${q("fqdn")}) = ? AND ${q("state")} <> 'REMOVED'
        ${exceptQuickConfigId === undefined ? "" : `AND ${q("id")} <> ?`} LIMIT 1`,
    exceptQuickConfigId === undefined ? [accountId, zoneId, fqdn] : [accountId, zoneId, fqdn, exceptQuickConfigId],
  );
  if (rows.length > 0) fail("DOMAIN_ALREADY_MANAGED");
  const claims = await queryRaw<Row>(
    `SELECT ${q("id")} FROM ${q("xray_quick_config_domain_claims")}
      WHERE ${q("dnsAccountId")} = ? AND ${q("zoneId")} = ? AND LOWER(${q("normalizedRelativeName")}) = ?
        ${exceptQuickConfigId === undefined ? "" : `AND ${q("quickConfigId")} <> ?`} LIMIT 1`,
    exceptQuickConfigId === undefined
      ? [accountId, zoneId, relativeName]
      : [accountId, zoneId, relativeName, exceptQuickConfigId],
  );
  if (claims.length > 0) fail("DOMAIN_ALREADY_MANAGED");
}

async function assertEditIdentity(
  identity: QuickConfigEditIdentity,
  targetRef: QuickConfigTargetRef,
): Promise<QuickConfigEditIdentity> {
  const quickConfigId = positiveSafeInteger(identity.quickConfigId, "DOMAIN_CHECK_INVALID");
  const expectedRevision = positiveSafeInteger(identity.expectedRevision, "DOMAIN_CHECK_INVALID");
  const q = quoteIdentifier;
  const [row] = await queryRaw<Row>(
    `SELECT ${q("revision")}, ${q("state")}, ${q("currentOperationId")}, ${q("targetType")},
            ${q("xrayInboundId")}, ${q("externalProxyNodeId")}, ${q("targetVersion")}, ${q("activeTopologyRevisionId")}
       FROM ${q("xray_quick_configs")} WHERE ${q("id")} = ? LIMIT 1`,
    [quickConfigId],
  );
  const targetId = targetRef.targetType === "XRAY_INBOUND" ? Number(row?.xrayInboundId) : Number(row?.externalProxyNodeId);
  if (!row || Number(row.revision) !== expectedRevision || row.state !== "ACTIVE"
    || row.currentOperationId !== null && row.currentOperationId !== undefined
    || !Number.isSafeInteger(Number(row.activeTopologyRevisionId)) || Number(row.activeTopologyRevisionId) <= 0
    || row.targetType !== targetRef.targetType || targetId !== targetRef.targetId
    || !hashEqual(row.targetVersion, targetRef.targetVersion)) fail("DOMAIN_CHECK_INVALID");
  return { quickConfigId, expectedRevision };
}

async function currentDnsContext(accountId: number, zoneId: number) {
  const account = await getGlobalDnsProviderAccountService();
  if (!account.configured) fail("DNS_PROVIDER_NOT_CONFIGURED");
  if (account.accountId !== accountId) fail("DNS_PROVIDER_CONFLICT");
  if (account.validationStatus !== "VALID") fail("DNS_PROVIDER_VALIDATION_STALE");
  const zones = await listGlobalDnsProviderZonesService({ refresh: false });
  const zone = zones.find((candidate) => candidate.zoneId === zoneId);
  if (!zone) fail("DOMAIN_INVALID");
  if (!zone.catalogUsable) fail(zone.catalogReasonCode ?? "DNS_PROVIDER_CATALOG_STALE");
  const credentials = await loadGlobalDnsProviderCredentials();
  if (credentials.accountId !== account.accountId || credentials.accountRevision !== account.accountRevision
    || credentials.bindingRevision !== account.bindingRevision) fail("DNS_PROVIDER_CONFLICT");
  return {
    accountId: account.accountId,
    accountRevision: account.accountRevision,
    bindingRevision: account.bindingRevision,
    credentials: { secretId: credentials.secretId, secretKey: credentials.secretKey },
    zone: { providerZoneId: zone.providerZoneId, name: zone.name, grade: "" } satisfies DnsPodZone,
    zoneCatalog: zone,
    zoneId: zone.zoneId,
  };
}

function exactDomainRecords(records: readonly DnsPodRecord[], relativeName: string): DnsPodRecord[] {
  if (records.length > MAX_DOMAIN_RECORDS) fail("DNS_PROVIDER_CATALOG_STALE");
  const exact = records.filter((record) => record.subdomain.trim().toLowerCase() === relativeName);
  if (exact.length > MAX_DOMAIN_RECORDS) fail("DNS_PROVIDER_CATALOG_STALE");
  return [...exact].sort((left, right) => left.providerRecordId.localeCompare(right.providerRecordId, "en", { numeric: true })
    || left.recordType.localeCompare(right.recordType) || left.providerLineId.localeCompare(right.providerLineId)
    || left.value.localeCompare(right.value) || left.ttl - right.ttl);
}

function projectedRecordType(value: string): DomainRecordProjection["recordType"] {
  const type = value.toUpperCase();
  return type === "A" || type === "AAAA" || type === "CNAME" || type === "TXT" || type === "MX" || type === "CAA"
    ? type : "OTHER";
}

function recordRef(record: DnsPodRecord, accountId: number, zoneId: number, key: Buffer): string {
  const tuple = stableJson({
    accountId,
    zoneId,
    providerRecordId: record.providerRecordId,
    subdomain: record.subdomain.trim().toLowerCase(),
    recordType: record.recordType.toUpperCase(),
    providerLineId: record.providerLineId,
    value: record.value,
    ttl: record.ttl,
  });
  return `drr_${crypto.createHmac("sha256", key).update(RECORD_REF_CONTEXT).update("\n").update(tuple).digest("base64url")}`;
}

function projectRecords(records: readonly DnsPodRecord[], accountId: number, zoneId: number, key: Buffer) {
  const all = records.map((record) => ({
    recordRef: recordRef(record, accountId, zoneId, key),
    recordType: projectedRecordType(record.recordType),
    providerLineId: record.providerLineId,
    lineName: record.lineName,
    value: record.value,
    ttl: record.ttl,
  }));
  return {
    conflicts: all.filter((record) => record.recordType === "A" || record.recordType === "AAAA" || record.recordType === "CNAME"),
    preservedRecords: all.filter((record) => record.recordType !== "A" && record.recordType !== "AAAA" && record.recordType !== "CNAME"),
  };
}

export function isQuickConfigDnsRecordOwned(record: DnsPodRecord, stored: Row, zoneName: string): boolean {
  if (record.recordType !== "A" && record.recordType !== "AAAA") return false;
  const fqdn = `${record.subdomain.trim().toLowerCase()}.${zoneName}`;
  return record.status === "ENABLE"
    && String(stored.providerRecordId) === record.providerRecordId
    && stored.fqdn === fqdn && stored.recordType === record.recordType
    && stored.providerLineId === record.providerLineId && stored.value === record.value
    && Number(stored.ttl) === record.ttl
    && stored.remoteTupleHash === computeXrayQuickConfigDnsTupleHash({
      fqdn, recordType: record.recordType, providerLineId: record.providerLineId, value: record.value, ttl: record.ttl,
    });
}

async function ownedDomainRecordRefs(input: {
  quickConfigId: number; accountId: number; zoneId: number; fqdn: string; zoneName: string;
  records: readonly DnsPodRecord[]; key: Buffer;
}): Promise<string[]> {
  const q = quoteIdentifier;
  const owned = await queryRaw<Row>(
    `SELECT r.* FROM ${q("xray_quick_config_dns_records")} r
      JOIN ${q("xray_quick_config_routes")} rt ON rt.${q("id")} = r.${q("routeId")}
      JOIN ${q("xray_quick_configs")} qc ON qc.${q("id")} = r.${q("quickConfigId")}
     WHERE qc.${q("id")} = ? AND r.${q("dnsAccountId")} = ? AND r.${q("zoneId")} = ?
       AND r.${q("fqdn")} = ? AND r.${q("status")} <> 'REMOVED'
       AND rt.${q("topologyRevisionId")} = qc.${q("activeTopologyRevisionId")}`,
    [input.quickConfigId, input.accountId, input.zoneId, input.fqdn],
  );
  const byId = new Map(owned.map(row => [String(row.providerRecordId), row]));
  return input.records.filter(record => {
    const stored = byId.get(record.providerRecordId);
    return stored && isQuickConfigDnsRecordOwned(record, stored, input.zoneName);
  }).map(record => recordRef(record, input.accountId, input.zoneId, input.key));
}

function exactRecordSetHash(records: readonly DnsPodRecord[]): string {
  return sha256(stableJson(records.map((record) => ({
    providerRecordId: record.providerRecordId,
    subdomain: record.subdomain.trim().toLowerCase(),
    recordType: record.recordType.toUpperCase(),
    providerLineId: record.providerLineId,
    lineName: record.lineName,
    value: record.value,
    ttl: record.ttl,
    status: record.status,
  }))));
}

function confirmationHash(fqdn: string, projection: ReturnType<typeof projectRecords>): string {
  return sha256(stableJson({ fqdn, conflicts: projection.conflicts, preservedRecords: projection.preservedRecords }));
}

function signDomainToken(payload: DomainTokenPayload, key: Buffer): string {
  const body = Buffer.from(stableJson(payload), "utf8").toString("base64url");
  const unsigned = `qc1.${body}`;
  return `${unsigned}.${crypto.createHmac("sha256", key).update(unsigned, "utf8").digest("base64url")}`;
}

function parseDomainToken(raw: string, kind: TokenKind, key: Buffer, now: Date): DomainTokenPayload {
  const invalidCode = kind === "DOMAIN_CHECK" ? "DOMAIN_CHECK_INVALID" : "DOMAIN_CONFIRMATION_INVALID";
  const expiredCode = kind === "DOMAIN_CHECK" ? "DOMAIN_CHECK_EXPIRED" : "DOMAIN_CONFIRMATION_EXPIRED";
  if (typeof raw !== "string" || Buffer.byteLength(raw, "utf8") > MAX_TOKEN_BYTES) fail(invalidCode);
  const parts = raw.split(".");
  if (parts.length !== 3 || parts[0] !== "qc1" || !TOKEN_PART.test(parts[1]) || !TOKEN_PART.test(parts[2])) fail(invalidCode);
  const unsigned = `${parts[0]}.${parts[1]}`;
  const expected = crypto.createHmac("sha256", key).update(unsigned, "utf8").digest();
  let actual: Buffer;
  try { actual = Buffer.from(parts[2], "base64url"); } catch { fail(invalidCode); }
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) fail(invalidCode);
  let payload: unknown;
  try { payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")); } catch { fail(invalidCode); }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) fail(invalidCode);
  const value = payload as Record<string, unknown>;
  const allowed = new Set([
    "v", "kind", "nonce", "userId", "accountId", "accountRevision", "bindingRevision", "zoneId", "relativeName", "fqdn",
    "targetType", "targetId", "targetVersion", "editQuickConfigId", "editExpectedRevision",
    "recordSetHash", "confirmationHash", "action", "issuedAt", "expiresAt",
  ]);
  if (Object.keys(value).some((field) => !allowed.has(field)) || value.v !== 1 || value.kind !== kind
    || typeof value.nonce !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(value.nonce)
    || (value.targetType !== "XRAY_INBOUND" && value.targetType !== "EXTERNAL_PROXY_NODE")
    || typeof value.relativeName !== "string" || typeof value.fqdn !== "string"
    || !HEX_64.test(String(value.targetVersion ?? "")) || !HEX_64.test(String(value.recordSetHash ?? ""))
    || !HEX_64.test(String(value.confirmationHash ?? ""))
    || (kind === "DOMAIN_CHECK" ? value.action !== undefined
      : value.action !== "USE_UNUSED_NAME" && value.action !== "REPLACE_CONFLICTING_RECORDS")) fail(invalidCode);
  for (const field of ["userId", "accountId", "accountRevision", "bindingRevision", "zoneId", "targetId", "issuedAt", "expiresAt"] as const) {
    if (!Number.isSafeInteger(value[field]) || Number(value[field]) <= 0) fail(invalidCode);
  }
  const hasEditId = value.editQuickConfigId !== undefined;
  const hasEditRevision = value.editExpectedRevision !== undefined;
  if (hasEditId !== hasEditRevision
    || hasEditId && (!Number.isSafeInteger(value.editQuickConfigId) || Number(value.editQuickConfigId) <= 0
      || !Number.isSafeInteger(value.editExpectedRevision) || Number(value.editExpectedRevision) <= 0)) fail(invalidCode);
  if (Number(value.expiresAt) <= now.getTime()) fail(expiredCode);
  if (Number(value.issuedAt) > now.getTime() + 30_000 || Number(value.expiresAt) - Number(value.issuedAt)
    > (kind === "DOMAIN_CHECK" ? DOMAIN_CHECK_TTL_MS : DOMAIN_CONFIRMED_TTL_MS)) fail(invalidCode);
  return value as unknown as DomainTokenPayload;
}

function dnsClient(credentials: DnsPodCredentials, options: QuickConfigServiceOptions) {
  return options.dnsPodClientFactory?.(credentials) ?? new DnsPodProviderClient({ credentials });
}

async function loadRemoteDomainRecords(
  credentials: DnsPodCredentials,
  zone: DnsPodZone,
  relativeName: string,
  options: QuickConfigServiceOptions,
): Promise<DnsPodRecord[]> {
  const records = await dnsClient(credentials, options).listRecords({ zone, subdomain: relativeName });
  return exactDomainRecords(records, relativeName);
}

function newTokenPayload(input: Omit<DomainTokenPayload, "v" | "nonce" | "issuedAt" | "expiresAt">, now: Date, ttlMs: number): DomainTokenPayload {
  return {
    v: 1,
    ...input,
    nonce: crypto.randomBytes(16).toString("base64url"),
    issuedAt: now.getTime(),
    expiresAt: now.getTime() + ttlMs,
  };
}

export async function createQuickConfigDomainCheck(input: {
  targetRef: QuickConfigTargetRef;
  accountId: number;
  zoneId: number;
  relativeName: string;
  userId: number;
  editIdentity?: QuickConfigEditIdentity;
}, options: QuickConfigServiceOptions = {}): Promise<DomainCheckDto> {
  try {
    const now = resolvedNow(options);
    const userId = positiveSafeInteger(input.userId);
    await resolveTargetRef(input.targetRef, now);
    const editIdentity = input.editIdentity ? await assertEditIdentity(input.editIdentity, input.targetRef) : null;
    const context = await currentDnsContext(input.accountId, input.zoneId);
    const domain = normalizeRelativeName(input.relativeName, context.zone.name);
    await assertDomainNotManaged(context.accountId, context.zoneId, domain.relativeName, domain.fqdn, editIdentity?.quickConfigId);
    const records = await loadRemoteDomainRecords(context.credentials, context.zone, domain.relativeName, options);
    const key = tokenKey(options.tokenSecret);
    const projection = projectRecords(records, context.accountId, context.zoneId, key);
    let ownedRecordRefs: string[] | undefined;
    if (editIdentity) {
      ownedRecordRefs = await ownedDomainRecordRefs({
        quickConfigId: editIdentity.quickConfigId, accountId: context.accountId, zoneId: context.zoneId,
        fqdn: domain.fqdn, zoneName: context.zone.name, records, key,
      });
    }
    const displayHash = confirmationHash(domain.fqdn, projection);
    const payload = newTokenPayload({
      kind: "DOMAIN_CHECK",
      userId,
      accountId: context.accountId,
      accountRevision: context.accountRevision,
      bindingRevision: context.bindingRevision,
      zoneId: context.zoneId,
      relativeName: domain.relativeName,
      fqdn: domain.fqdn,
      targetType: input.targetRef.targetType,
      targetId: input.targetRef.targetId,
      targetVersion: input.targetRef.targetVersion,
      ...(editIdentity ? {
        editQuickConfigId: editIdentity.quickConfigId,
        editExpectedRevision: editIdentity.expectedRevision,
      } : {}),
      recordSetHash: exactRecordSetHash(records),
      confirmationHash: displayHash,
    }, now, DOMAIN_CHECK_TTL_MS);
    return {
      fqdn: domain.fqdn,
      conflicts: projection.conflicts,
      preservedRecords: projection.preservedRecords,
      ...(ownedRecordRefs ? { ownedRecordRefs } : {}),
      allowedActions: projection.conflicts.length > 0 ? ["REPLACE_CONFLICTING_RECORDS"] : ["USE_UNUSED_NAME"],
      confirmationHash: displayHash,
      domainCheckToken: signDomainToken(payload, key),
      expiresAt: new Date(payload.expiresAt).toISOString(),
    };
  } catch (error) {
    serviceError(error);
  }
}

export async function confirmQuickConfigDomainCheck(input: {
  domainCheckToken: string;
  action: DomainAction;
  confirmationHash: string;
  userId: number;
}, options: QuickConfigServiceOptions = {}): Promise<{ confirmedDomainToken: string; expiresAt: string }> {
  try {
    const now = resolvedNow(options);
    const key = tokenKey(options.tokenSecret);
    const payload = parseDomainToken(input.domainCheckToken, "DOMAIN_CHECK", key, now);
    if (payload.userId !== positiveSafeInteger(input.userId) || !hashEqual(payload.confirmationHash, input.confirmationHash)) {
      fail("DOMAIN_CONFIRMATION_INVALID");
    }
    await resolveTargetRef({
      targetType: payload.targetType,
      targetId: payload.targetId,
      targetVersion: payload.targetVersion,
    }, now);
    const editIdentity = payload.editQuickConfigId === undefined ? null : await assertEditIdentity({
      quickConfigId: payload.editQuickConfigId,
      expectedRevision: payload.editExpectedRevision!,
    }, {
      targetType: payload.targetType,
      targetId: payload.targetId,
      targetVersion: payload.targetVersion,
    });
    const context = await currentDnsContext(payload.accountId, payload.zoneId);
    if (context.accountRevision !== payload.accountRevision || context.bindingRevision !== payload.bindingRevision) {
      fail("DOMAIN_CHECK_INVALID");
    }
    const domain = normalizeRelativeName(payload.relativeName, context.zone.name);
    if (domain.fqdn !== payload.fqdn) fail("DOMAIN_CHECK_INVALID");
    await assertDomainNotManaged(context.accountId, context.zoneId, domain.relativeName, domain.fqdn, editIdentity?.quickConfigId);
    const records = await loadRemoteDomainRecords(context.credentials, context.zone, domain.relativeName, options);
    if (!hashEqual(exactRecordSetHash(records), payload.recordSetHash)) fail("DOMAIN_CONFLICT_CHANGED");
    const projection = projectRecords(records, context.accountId, context.zoneId, key);
    if (!hashEqual(confirmationHash(domain.fqdn, projection), payload.confirmationHash)) fail("DOMAIN_CONFLICT_CHANGED");
    const hasConflicts = projection.conflicts.length > 0;
    if ((hasConflicts && input.action !== "REPLACE_CONFLICTING_RECORDS")
      || (!hasConflicts && input.action !== "USE_UNUSED_NAME")) fail("DOMAIN_CONFIRMATION_REQUIRED");
    const confirmed = newTokenPayload({
      kind: "DOMAIN_CONFIRMED",
      userId: payload.userId,
      accountId: payload.accountId,
      accountRevision: payload.accountRevision,
      bindingRevision: payload.bindingRevision,
      zoneId: payload.zoneId,
      relativeName: payload.relativeName,
      fqdn: payload.fqdn,
      targetType: payload.targetType,
      targetId: payload.targetId,
      targetVersion: payload.targetVersion,
      ...(editIdentity ? {
        editQuickConfigId: editIdentity.quickConfigId,
        editExpectedRevision: editIdentity.expectedRevision,
      } : {}),
      recordSetHash: payload.recordSetHash,
      confirmationHash: payload.confirmationHash,
      action: input.action,
    }, now, DOMAIN_CONFIRMED_TTL_MS);
    return {
      confirmedDomainToken: signDomainToken(confirmed, key),
      expiresAt: new Date(confirmed.expiresAt).toISOString(),
    };
  } catch (error) {
    serviceError(error);
  }
}

export async function resolveConfirmedQuickConfigDomain(input: {
  confirmedDomainToken: string;
  userId: number;
}, options: QuickConfigServiceOptions = {}): Promise<ResolvedQuickConfigDomain> {
  try {
    const now = resolvedNow(options);
    const key = tokenKey(options.tokenSecret);
    const payload = parseDomainToken(input.confirmedDomainToken, "DOMAIN_CONFIRMED", key, now);
    const userId = positiveSafeInteger(input.userId, "DOMAIN_CONFIRMATION_INVALID");
    if (payload.userId !== userId || !payload.action) fail("DOMAIN_CONFIRMATION_INVALID");
    const targetRef: QuickConfigTargetRef = {
      targetType: payload.targetType,
      targetId: payload.targetId,
      targetVersion: payload.targetVersion,
    };
    const target = await resolveTargetRef(targetRef, now);
    const editIdentity = payload.editQuickConfigId === undefined ? null : await assertEditIdentity({
      quickConfigId: payload.editQuickConfigId,
      expectedRevision: payload.editExpectedRevision!,
    }, targetRef);
    const context = await currentDnsContext(payload.accountId, payload.zoneId);
    if (context.accountRevision !== payload.accountRevision || context.bindingRevision !== payload.bindingRevision) {
      fail("DOMAIN_CONFIRMATION_INVALID");
    }
    const domain = normalizeRelativeName(payload.relativeName, context.zone.name);
    if (domain.fqdn !== payload.fqdn) fail("DOMAIN_CONFIRMATION_INVALID");
    await assertDomainNotManaged(context.accountId, context.zoneId, domain.relativeName, domain.fqdn, editIdentity?.quickConfigId);
    const records = await loadRemoteDomainRecords(context.credentials, context.zone, domain.relativeName, options);
    if (!hashEqual(exactRecordSetHash(records), payload.recordSetHash)) fail("DOMAIN_CONFLICT_CHANGED");
    const projection = projectRecords(records, context.accountId, context.zoneId, key);
    if (!hashEqual(confirmationHash(domain.fqdn, projection), payload.confirmationHash)) fail("DOMAIN_CONFLICT_CHANGED");
    const hasConflicts = projection.conflicts.length > 0;
    if ((hasConflicts && payload.action !== "REPLACE_CONFLICTING_RECORDS")
      || (!hasConflicts && payload.action !== "USE_UNUSED_NAME")) fail("DOMAIN_CONFIRMATION_REQUIRED");
    return {
      userId,
      accountId: context.accountId,
      accountRevision: context.accountRevision,
      bindingRevision: context.bindingRevision,
      zoneId: context.zoneId,
      zone: context.zoneCatalog,
      relativeName: domain.relativeName,
      fqdn: domain.fqdn,
      target,
      targetRef,
      editIdentity,
      recordSetHash: payload.recordSetHash,
      confirmationHash: payload.confirmationHash,
      action: payload.action,
      conflicts: projection.conflicts,
      ownedRecordRefs: editIdentity ? await ownedDomainRecordRefs({
        quickConfigId: editIdentity.quickConfigId, accountId: context.accountId, zoneId: context.zoneId,
        fqdn: domain.fqdn, zoneName: context.zone.name, records, key,
      }) : [],
      preservedRecords: projection.preservedRecords,
    };
  } catch (error) {
    serviceError(error);
  }
}

function serviceError(error: unknown): never {
  if (error instanceof XrayQuickConfigServiceError) throw error;
  if (error instanceof DnsProviderAccountServiceError) {
    if ((QUICK_CONFIG_SERVICE_ERROR_CODES as readonly string[]).includes(error.code)) {
      throw new XrayQuickConfigServiceError(error.code as QuickConfigServiceErrorCode);
    }
    throw new XrayQuickConfigServiceError("DNS_PROVIDER_INVALID");
  }
  if (error instanceof DnsProviderRepositoryError) {
    if (error.code === "SENSITIVE_DATA_UNAVAILABLE" || error.code === "DNS_PROVIDER_NOT_CONFIGURED"
      || error.code === "DNS_PROVIDER_CONFLICT" || error.code === "DNS_PROVIDER_INVALID") {
      throw new XrayQuickConfigServiceError(error.code);
    }
    throw new XrayQuickConfigServiceError("DNS_PROVIDER_INVALID");
  }
  if (error instanceof DnsPodProviderError) {
    throw new XrayQuickConfigServiceError(error.code === "DNS_PROVIDER_INVALID"
      ? "DNS_PROVIDER_INVALID" : "DNS_PROVIDER_CATALOG_STALE");
  }
  if (error instanceof XrayExternalProxyServiceError) {
    throw new XrayQuickConfigServiceError(error.code === "SENSITIVE_DATA_UNAVAILABLE"
      ? "SENSITIVE_DATA_UNAVAILABLE" : "QUICK_CONFIG_TARGET_UNSUPPORTED");
  }
  throw error;
}
