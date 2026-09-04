import crypto from "node:crypto";
import dns from "node:dns/promises";
import net from "node:net";
import { loadQuickConfigSegments } from "./xrayQuickConfigTopologyStore";
import { compileQuickConfigTopology, normalizeQuickConfigPath, serializeQuickConfigRelays, QuickConfigPathError, type QuickConfigPathEndpoint, type QuickConfigRelay } from "./xrayQuickConfigTopology";

import {
  XRAY_QUICK_CONFIG_FORWARD_ENGINES,
  quickConfigPathEngineCompatible,
  type XrayQuickConfigForwardEngine,
} from "../shared/xrayQuickConfigForwardEngines";

import { quoteIdentifier } from "./dbCompat";
import {
  executeRaw,
  insertAndGetId,
  nowDate,
  queryRaw,
  rawAffectedRows,
} from "./dbRuntime";
import { ENV } from "./env";
import {
  assertActiveXrayInboundPortTargetAlias,
  assertGlobalPortAvailable,
  GlobalPortAllocationError,
  inspectGlobalPortAllocation,
  type GlobalPortAllocationErrorCode,
} from "./globalPortAllocationService";
import { withKeyedTaskLock } from "./keyedTaskLock";
import { isPortAllowedByPolicy, portPolicyFrom } from "./portPolicy";
import { getHostById } from "./repositories/hostRepository";
import {
  resolveConfirmedQuickConfigDomain,
  XrayQuickConfigServiceError,
  type DomainRecordProjection,
  type QuickConfigTarget,
  type ResolvedQuickConfigDomain,
} from "./xrayQuickConfigService";
import {
  listXrayQuickConfigEntryHosts,
  type QuickConfigEntryHost,
  type QuickConfigEntryHostEndpoint,
} from "./xrayQuickConfigEntryHosts";
import { listXrayQuickConfigForwardEngines } from "./xrayQuickConfigForwardEngineService";
import { planQuickConfigDnsDiff } from "./xrayQuickConfigDnsDiff";
import {
  createXrayPortProbeOperation,
  getXrayPortProbeOperationResult,
  releaseXrayPortProbeReservations,
  validateXrayPortReservation,
  XrayPortOperationError,
} from "./xrayPortOperations";

export const QUICK_CONFIG_PLANNING_ERROR_CODES = [
  "QUICK_CONFIG_PREVIEW_INVALID",
  "QUICK_CONFIG_PREVIEW_EXPIRED",
  "QUICK_CONFIG_TARGET_CHANGED",
  "QUICK_CONFIG_TARGET_UNSUPPORTED",
  "QUICK_CONFIG_HOST_UNAVAILABLE",
  "QUICK_CONFIG_ADDRESS_UNAVAILABLE",
  "QUICK_CONFIG_PATH_ADDRESS_FAMILY_UNSUPPORTED",
  "FORWARD_PROTOCOL_DISABLED",
  "AGENT_CAPABILITY_MISSING",
  "HOST_OFFLINE",
  "UDP_CAPABILITY_REQUIRED",
  "GLOBAL_PORT_PROBE_FAILED",
  "GLOBAL_PORT_PROBE_EXPIRED",
  "SENSITIVE_DATA_UNAVAILABLE",
] as const;

export type QuickConfigPlanningErrorCode = typeof QUICK_CONFIG_PLANNING_ERROR_CODES[number];

export class XrayQuickConfigPlanningError extends Error {
  constructor(readonly code: QuickConfigPlanningErrorCode) {
    super(code);
    this.name = "XrayQuickConfigPlanningError";
  }
}

export const QUICK_CONFIG_CARRIERS = ["TELECOM", "UNICOM", "MOBILE", "EDUCATION"] as const;
export type QuickConfigCarrier = typeof QUICK_CONFIG_CARRIERS[number];
export type QuickConfigAddressFamily = "IPV4" | "IPV6";

export type QuickConfigCarrierRoutesInput = ReadonlyArray<Readonly<{
  carrier: QuickConfigCarrier;
  providerLineId: string;
  endpoints: ReadonlyArray<QuickConfigPathEndpoint>;
}>>;

export type QuickConfigPortChoice =
  | Readonly<{ mode: "TARGET_ORIGINAL" }>
  | Readonly<{ mode: "MANUAL"; port: number }>
  | Readonly<{ mode: "RECOMMENDED"; recommendationToken: string }>;

type GlobalConflictReason = Extract<GlobalPortAllocationErrorCode,
  "GLOBAL_PORT_CONFLICT" | "GLOBAL_PORT_LEGACY_CONFLICT" | "GLOBAL_PORT_SCAN_PENDING" | "GLOBAL_PORT_EXTERNAL_OCCUPIED">;

export type DefaultRouteCandidate = Readonly<{
  candidateId: string;
  sourceType: "LANDING" | "MANAGED_HOST";
  hostId: number | null;
  addressFamily: QuickConfigAddressFamily;
  address: string;
  label: string;
  recommended: boolean;
}>;

export type QuickConfigPortCheckStart =
  | Readonly<{ status: "RUNNING"; portCheckId: string }>
  | PortConflict;

export type QuickConfigPortCheckResult =
  | Readonly<{ status: "RUNNING"; completedHosts: number; totalHosts: number }>
  | Readonly<{
      status: "SUCCESS";
      selectedPort: number;
      rewritten: boolean;
      probeResultToken: string;
      expiresAt: string;
      defaultRouteCandidates: DefaultRouteCandidate[];
    }>
  | PortConflict
  | Readonly<{ status: "FAILED"; reasonCode: "HOST_OFFLINE" | "UDP_CAPABILITY_REQUIRED" | "GLOBAL_PORT_PROBE_FAILED" }>
  | Readonly<{ status: "EXPIRED"; reasonCode: "GLOBAL_PORT_PROBE_EXPIRED" }>;

type PortConflict =
  | Readonly<{ status: "CONFLICT"; resolution: "MANUAL"; reasonCode: GlobalConflictReason; requestedPort: number }>
  | Readonly<{
      status: "CONFLICT";
      resolution: "RECOMMENDED";
      reasonCode: GlobalConflictReason;
      requestedPort: number;
      recommendation: { port: number; recommendationToken: string; expiresAt: string };
    }>;

type ResolvedEndpoint = Readonly<{
  hostId: number;
  hostName: string;
  addressFamily: QuickConfigAddressFamily;
  address: string;
  relays?: ReadonlyArray<QuickConfigRelay & { hostName: string }>;
}>;

type ResolvedCarrierRoute = Readonly<{
  carrier: QuickConfigCarrier;
  providerLineId: string;
  endpoints: ResolvedEndpoint[];
}>;

type ProbeDescriptor = Readonly<{ hostId: number; network: "tcp" | "udp"; operationId: string }>;
type ProbeReservation = Readonly<{
  hostId: number;
  network: "tcp" | "udp";
  operationId: string;
  reservationId: string;
  expiresAt: string;
}>;

type PortCheckTokenPayload = Readonly<{
  v: 1;
  kind: "PORT_CHECK";
  nonce: string;
  runTag: string;
  userId: number;
  confirmedDomainToken: string;
  confirmedDomainTokenHash: string;
  targetType: QuickConfigTarget["targetType"];
  targetId: number;
  targetVersion: string;
  engine: XrayQuickConfigForwardEngine;
  selectedPort: number;
  rewritten: boolean;
  carrierRoutes: QuickConfigCarrierRoutesInput;
  carrierRoutesHash: string;
  hostSetHash: string;
  forwardHosts: ReadonlyArray<{ hostId: number; hostName: string }>;
  probes: ProbeDescriptor[];
  startFailureCode?: "HOST_OFFLINE" | "UDP_CAPABILITY_REQUIRED" | "GLOBAL_PORT_PROBE_FAILED" | "GLOBAL_PORT_CONFLICT";
  issuedAt: number;
  expiresAt: number;
}>;

type RecommendationTokenPayload = Readonly<{
  v: 1;
  kind: "PORT_RECOMMENDATION";
  nonce: string;
  userId: number;
  confirmedDomainTokenHash: string;
  targetVersion: string;
  engine: XrayQuickConfigForwardEngine;
  carrierRoutesHash: string;
  hostSetHash: string;
  recommendedPort: number;
  conflictingPort: number;
  reasonCode: GlobalConflictReason;
  issuedAt: number;
  expiresAt: number;
}>;

type ProbeResultTokenPayload = Readonly<{
  v: 1;
  kind: "PROBE_RESULT";
  nonce: string;
  runTag: string;
  userId: number;
  confirmedDomainTokenHash: string;
  targetType: QuickConfigTarget["targetType"];
  targetId: number;
  targetVersion: string;
  engine: XrayQuickConfigForwardEngine;
  selectedPort: number;
  rewritten: boolean;
  carrierRoutes: QuickConfigCarrierRoutesInput;
  carrierRoutesHash: string;
  hostSetHash: string;
  reservations: ProbeReservation[];
  candidates: DefaultRouteCandidate[];
  issuedAt: number;
  expiresAt: number;
}>;

type PreviewTokenPayload = Readonly<{
  v: 1;
  kind: "PREVIEW";
  nonce: string;
  userId: number;
  confirmedDomainToken: string;
  engine: XrayQuickConfigForwardEngine;
  carrierRoutes: QuickConfigCarrierRoutesInput;
  probeResultToken: string;
  defaultRoutes: ReadonlyArray<{ candidateId: string }>;
  planHash: string;
  editQuickConfigId?: number;
  editExpectedRevision?: number;
  fromTopologyRevisionId?: number;
  issuedAt: number;
  expiresAt: number;
}>;

type SignedPayload = PortCheckTokenPayload | RecommendationTokenPayload | ProbeResultTokenPayload | PreviewTokenPayload;

export type QuickConfigPreviewDto = Readonly<{
  fqdn: string;
  publicPort: number;
  target: {
    targetType: QuickConfigTarget["targetType"];
    targetId: number;
    targetName: string;
    address: string;
    port: number;
  };
  rules: ReadonlyArray<{
    ruleKey: string;
    action: "CREATE" | "REUSE";
    hostId: number;
    hostName: string;
    engine: XrayQuickConfigForwardEngine;
    listenPort: number;
    targetAddress: string;
    targetPort: number;
  }>;
  dnsRecords: ReadonlyArray<({ routeKind: "CARRIER"; carrier: QuickConfigCarrier }
    | { routeKind: "DEFAULT"; carrier: null }) & {
      providerLineId: string;
      recordType: "A" | "AAAA";
      value: string;
      ttl: number;
      action: "CREATE" | "REPLACE" | "REUSE";
    }>;
  conflictingRecords: ReadonlyArray<DomainRecordProjection & { action: "REPLACE" | "DELETE" }>;
  preservedRecords: DomainRecordProjection[];
  allocation: { port: number; mode: "TARGET_ALIAS" | "RESERVE_NEW"; rewritten: boolean };
  warnings: ReadonlyArray<{ code: string; message: string }>;
  previewToken: string;
  expiresAt: string;
}>;

export type QuickConfigImmutablePlan = Readonly<{
  engine: XrayQuickConfigForwardEngine;
  preview: Omit<QuickConfigPreviewDto, "previewToken" | "expiresAt">;
  domain: ResolvedQuickConfigDomain;
  carrierRoutes: ResolvedCarrierRoute[];
  defaultRoutes: DefaultRouteCandidate[];
  reservations: ProbeReservation[];
  confirmedDomainToken: string;
  probeResultToken: string;
  expiresAt: string;
}>;

type PlanningOptions = Readonly<{
  now?: () => Date;
  tokenSecret?: string;
  dnsLookup?: (hostname: string) => Promise<ReadonlyArray<{ address: string; family: number }>>;
}>;

type Row = Record<string, unknown>;
const PORT_CHECK_TTL_MS = 60_000;
const RECOMMENDATION_TTL_MS = 5 * 60_000;
const PREVIEW_TTL_MS = 5 * 60_000;
const DNS_LOOKUP_TIMEOUT_MS = 5_000;
const DNS_TTL = 600;
const MAX_TOKEN_BYTES = 64 * 1024;
const TOKEN_CONTEXT = "forwardx-xray-quick-config-planning-token:v1";
const CANDIDATE_CONTEXT = "forwardx-xray-quick-config-default-candidate:v1";
const HEX_64 = /^[a-f0-9]{64}$/;
const TOKEN_PART = /^[A-Za-z0-9_-]+$/;

function fail(code: QuickConfigPlanningErrorCode): never {
  throw new XrayQuickConfigPlanningError(code);
}

function resolvedNow(options: PlanningOptions): Date {
  const value = options.now?.() ?? new Date();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) fail("QUICK_CONFIG_PREVIEW_INVALID");
  return new Date(value);
}

function positiveInteger(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) fail("QUICK_CONFIG_PREVIEW_INVALID");
  return parsed;
}

function portNumber(value: unknown): number {
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1_000 || port > 65_535) fail("QUICK_CONFIG_PREVIEW_INVALID");
  return port;
}

function forwardEngine(value: unknown): XrayQuickConfigForwardEngine {
  if (typeof value !== "string"
    || !(XRAY_QUICK_CONFIG_FORWARD_ENGINES as readonly string[]).includes(value)) {
    fail("QUICK_CONFIG_PREVIEW_INVALID");
  }
  return value as XrayQuickConfigForwardEngine;
}

function databaseDate(value: unknown): Date | null {
  if (value == null || value === "") return null;
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? new Date(value) : null;
  const numeric = Number(value);
  const date = Number.isFinite(numeric)
    ? new Date(numeric < 10_000_000_000 ? numeric * 1_000 : numeric)
    : new Date(String(value));
  return Number.isFinite(date.getTime()) ? date : null;
}

function stableValue(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(stableValue);
  if (!value || typeof value !== "object") fail("QUICK_CONFIG_PREVIEW_INVALID");
  const output: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    const entry = (value as Record<string, unknown>)[key];
    if (entry === undefined) fail("QUICK_CONFIG_PREVIEW_INVALID");
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

function hashEqual(left: unknown, right: unknown): boolean {
  if (typeof left !== "string" || typeof right !== "string" || !HEX_64.test(left) || !HEX_64.test(right)) return false;
  return crypto.timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function tokenKey(secret = ENV.cookieSecret): Buffer {
  if (typeof secret !== "string" || Buffer.byteLength(secret, "utf8") < 16) fail("SENSITIVE_DATA_UNAVAILABLE");
  return crypto.createHmac("sha256", secret).update(TOKEN_CONTEXT, "utf8").digest();
}

function signToken(payload: SignedPayload, key: Buffer): string {
  const body = Buffer.from(stableJson(payload), "utf8").toString("base64url");
  const unsigned = `qcp1.${body}`;
  const signature = crypto.createHmac("sha256", key).update(unsigned, "utf8").digest("base64url");
  const token = `${unsigned}.${signature}`;
  if (Buffer.byteLength(token, "utf8") > MAX_TOKEN_BYTES) fail("QUICK_CONFIG_PREVIEW_INVALID");
  return token;
}

function parseSignedToken(raw: string, kind: SignedPayload["kind"], options: PlanningOptions): SignedPayload {
  const expiredCode = kind === "PREVIEW" ? "QUICK_CONFIG_PREVIEW_EXPIRED" : "GLOBAL_PORT_PROBE_EXPIRED";
  if (typeof raw !== "string" || Buffer.byteLength(raw, "utf8") > MAX_TOKEN_BYTES) fail("QUICK_CONFIG_PREVIEW_INVALID");
  const parts = raw.split(".");
  if (parts.length !== 3 || parts[0] !== "qcp1" || !TOKEN_PART.test(parts[1]) || !TOKEN_PART.test(parts[2])) {
    fail("QUICK_CONFIG_PREVIEW_INVALID");
  }
  const unsigned = `${parts[0]}.${parts[1]}`;
  const expected = crypto.createHmac("sha256", tokenKey(options.tokenSecret)).update(unsigned, "utf8").digest();
  const actual = Buffer.from(parts[2], "base64url");
  if (actual.toString("base64url") !== parts[2]
    || actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    fail("QUICK_CONFIG_PREVIEW_INVALID");
  }
  let parsed: unknown;
  try { parsed = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")); } catch { fail("QUICK_CONFIG_PREVIEW_INVALID"); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) fail("QUICK_CONFIG_PREVIEW_INVALID");
  const value = parsed as Record<string, unknown>;
  if (value.v !== 1 || value.kind !== kind || typeof value.nonce !== "string"
    || !/^[A-Za-z0-9_-]{22}$/.test(value.nonce) || !Number.isSafeInteger(value.userId)
    || !Number.isSafeInteger(value.issuedAt) || !Number.isSafeInteger(value.expiresAt)) fail("QUICK_CONFIG_PREVIEW_INVALID");
  const now = resolvedNow(options).getTime();
  if (Number(value.expiresAt) <= now) fail(expiredCode);
  if (Number(value.issuedAt) > now + 30_000 || Number(value.expiresAt) - Number(value.issuedAt) > PREVIEW_TTL_MS) {
    fail("QUICK_CONFIG_PREVIEW_INVALID");
  }
  return value as unknown as SignedPayload;
}

function nonce(): string {
  return crypto.randomBytes(16).toString("base64url");
}

function normalizeCarrierInput(input: QuickConfigCarrierRoutesInput): QuickConfigCarrierRoutesInput {
  if (!Array.isArray(input) || input.length !== QUICK_CONFIG_CARRIERS.length) fail("QUICK_CONFIG_PREVIEW_INVALID");
  const byCarrier = new Map<QuickConfigCarrier, QuickConfigCarrierRoutesInput[number]>();
  let endpointCount = 0;
  for (const route of input) {
    if (!route || !(QUICK_CONFIG_CARRIERS as readonly string[]).includes(route.carrier) || byCarrier.has(route.carrier)) {
      fail("QUICK_CONFIG_PREVIEW_INVALID");
    }
    if (typeof route.providerLineId !== "string" || !route.providerLineId || route.providerLineId.length > 128
      || /[\u0000-\u001f\u007f]/.test(route.providerLineId)
      || !Array.isArray(route.endpoints) || route.endpoints.length < 1 || route.endpoints.length > 32) {
      fail("QUICK_CONFIG_PREVIEW_INVALID");
    }
    const seen = new Set<string>();
    const endpoints = route.endpoints.map((endpoint: QuickConfigCarrierRoutesInput[number]["endpoints"][number]) => {
      const normalized = normalizeQuickConfigPath(endpoint);
      const { hostId, addressFamily } = normalized;
      const key = `${hostId}:${addressFamily}`;
      if (seen.has(key)) fail("QUICK_CONFIG_PREVIEW_INVALID");
      seen.add(key);
      return normalized;
    }).sort((left: { hostId: number; addressFamily: QuickConfigAddressFamily }, right: { hostId: number; addressFamily: QuickConfigAddressFamily }) => (
      left.hostId - right.hostId || left.addressFamily.localeCompare(right.addressFamily)
    ));
    endpointCount += endpoints.length;
    byCarrier.set(route.carrier, { carrier: route.carrier, providerLineId: route.providerLineId, endpoints });
  }
  if (endpointCount > 64) fail("QUICK_CONFIG_PREVIEW_INVALID");
  return QUICK_CONFIG_CARRIERS.map((carrier) => byCarrier.get(carrier)!);
}

function hostSetHash(hostIds: readonly number[]): string {
  return sha256(`forwardx-quick-config-port-host-set:v1\n${JSON.stringify([...new Set(hostIds)].sort((a, b) => a - b))}`);
}

async function resolveCarrierRoutes(
  domain: ResolvedQuickConfigDomain,
  input: QuickConfigCarrierRoutesInput,
): Promise<{ normalized: QuickConfigCarrierRoutesInput; resolved: ResolvedCarrierRoute[]; hosts: QuickConfigEntryHost[] }> {
  const normalized = normalizeCarrierInput(input);
  const hosts = (await listXrayQuickConfigEntryHosts()).items;
  const hostById = new Map(hosts.map((host) => [host.hostId, host]));
  const resolved = normalized.map((route) => {
    const line = domain.zone.carrierLines.find((candidate) => candidate.category === route.carrier);
    if (!line || line.status !== "AVAILABLE" || line.providerLineId !== route.providerLineId) {
      fail("QUICK_CONFIG_PREVIEW_INVALID");
    }
    const resolveHop = (endpoint: QuickConfigPathEndpoint) => {
      const host = hostById.get(endpoint.hostId);
      if (!host) fail("QUICK_CONFIG_HOST_UNAVAILABLE");
      if (!host.eligible) {
        if (host.disabledReasonCode === "HOST_OFFLINE") fail("HOST_OFFLINE");
        if (host.disabledReasonCode === "UDP_CAPABILITY_REQUIRED") fail("UDP_CAPABILITY_REQUIRED");
        fail("QUICK_CONFIG_HOST_UNAVAILABLE");
      }
      const selected = host.endpoints.find((candidate) => candidate.addressFamily === endpoint.addressFamily);
      if (!selected) fail("QUICK_CONFIG_HOST_UNAVAILABLE");
      return { hostId: host.hostId, hostName: host.name, addressFamily: selected.addressFamily, address: selected.address };
    };
    const endpoints = route.endpoints.map((endpoint) => {
      const hops = [endpoint, ...(endpoint.relays ?? [])];
      const landingHostId = domain.target.targetType === "XRAY_INBOUND" ? domain.target.host.id : null;
      if (hops.length > 1 && hops.some(hop => hop.hostId === landingHostId)) fail("QUICK_CONFIG_PREVIEW_INVALID");
      return { ...resolveHop(endpoint), ...(endpoint.relays?.length ? { relays: endpoint.relays.map(resolveHop) } : {}) };
    });
    return { carrier: route.carrier, providerLineId: route.providerLineId, endpoints };
  });
  return { normalized, resolved, hosts };
}

async function assertForwardEngineAvailable(
  engineValue: unknown,
  routes: QuickConfigCarrierRoutesInput,
  target: QuickConfigTarget,
  rewritten: boolean,
): Promise<XrayQuickConfigForwardEngine> {
  const engine = forwardEngine(engineValue);
  const directLandingHostId = !rewritten && target.targetType === "XRAY_INBOUND" ? target.host.id : undefined;
  if (!quickConfigPathEngineCompatible(engine, routes.flatMap(route => route.endpoints.map(endpoint => [endpoint, ...(endpoint.relays ?? [])])), target.endpoint.address, directLandingHostId)) fail("QUICK_CONFIG_PATH_ADDRESS_FAMILY_UNSUPPORTED");
  const entries = [...new Map(routes.flatMap(route => route.endpoints.flatMap(endpoint => [endpoint, ...(endpoint.relays ?? [])]))
    .map(endpoint => [`${endpoint.hostId}:${endpoint.addressFamily}`, { hostId: endpoint.hostId, addressFamily: endpoint.addressFamily }])).values()];
  const catalog = await listXrayQuickConfigForwardEngines({
    entries,
  });
  const item = catalog.items.find((candidate) => candidate.engine === engine);
  if (!item?.eligible) {
    const reason = item?.disabledReasonCode;
    if (reason === "FORWARD_PROTOCOL_DISABLED" || reason === "HOST_OFFLINE"
      || reason === "AGENT_CAPABILITY_MISSING" || reason === "UDP_CAPABILITY_REQUIRED"
      || reason === "QUICK_CONFIG_HOST_UNAVAILABLE" || reason === "QUICK_CONFIG_ADDRESS_UNAVAILABLE") {
      fail(reason);
    }
    fail("QUICK_CONFIG_HOST_UNAVAILABLE");
  }
  return engine;
}

function forwardHostsFor(
  target: QuickConfigTarget,
  rewritten: boolean,
  routes: readonly ResolvedCarrierRoute[],
  publicPort: number,
) {
  const landingHostId = target.targetType === "XRAY_INBOUND" ? target.host.id : null;
  const endpoints = routes.flatMap(route => route.endpoints);
  const names = new Map(endpoints.flatMap(endpoint => [endpoint, ...(endpoint.relays ?? [])]).map(hop => [hop.hostId, hop.hostName]));
  return compileQuickConfigTopology(endpoints.map(endpoint => ({
    hostId: endpoint.hostId,
    routeMode: !rewritten && landingHostId === endpoint.hostId ? "DIRECT" : "FORWARD",
    relayHopsJson: serializeQuickConfigRelays(endpoint.relays ?? []),
  })), { publicPort, targetAddress: target.endpoint.address, targetPort: target.endpoint.port })
    .map(segment => ({ ...segment, hostName: names.get(segment.hostId)! }));
}

function carrierSnapshotHash(carriers: { normalized: QuickConfigCarrierRoutesInput; resolved: ResolvedCarrierRoute[] }): string {
  return sha256(stableJson({ input: carriers.normalized, resolved: carriers.resolved }));
}

function conflictReason(error: unknown): GlobalConflictReason | null {
  if (!(error instanceof GlobalPortAllocationError)) return null;
  if (error.code === "GLOBAL_PORT_CONFLICT" || error.code === "GLOBAL_PORT_LEGACY_CONFLICT"
    || error.code === "GLOBAL_PORT_SCAN_PENDING" || error.code === "GLOBAL_PORT_EXTERNAL_OCCUPIED") return error.code;
  return null;
}

async function checkLedger(target: QuickConfigTarget, selectedPort: number, rewritten: boolean): Promise<GlobalConflictReason | null> {
  try {
    if (!rewritten && target.targetType === "XRAY_INBOUND") {
      await assertActiveXrayInboundPortTargetAlias({ inboundId: target.targetId, port: selectedPort });
      return null;
    }
    await assertGlobalPortAvailable(selectedPort);
    return null;
  } catch (error) {
    const reason = conflictReason(error);
    if (reason) return reason;
    throw error;
  }
}

type EditPlanningSnapshot = Readonly<{
  quickConfigId: number;
  expectedRevision: number;
  fromTopologyRevisionId: number;
  configTag: string;
  publicPort: number;
  allocationId: number;
  engine: XrayQuickConfigForwardEngine;
  rules: ReadonlyArray<Readonly<{
    ruleId: number;
    hostId: number;
    engine: XrayQuickConfigForwardEngine;
    listenPort: number;
    targetAddress: string;
    targetPort: number;
  }>>;
}>;

async function editPlanningSnapshot(domain: ResolvedQuickConfigDomain): Promise<EditPlanningSnapshot | null> {
  if (!domain.editIdentity) return null;
  const q = quoteIdentifier;
  const [row] = await queryRaw<Row>(
    `SELECT qc.${q("id")}, qc.${q("configTag")}, qc.${q("revision")}, qc.${q("state")}, qc.${q("currentOperationId")},
            qc.${q("activeTopologyRevisionId")}, t.${q("engine")}, t.${q("publicPort")}, t.${q("portAllocationId")},
            t.${q("targetAddress")}, t.${q("targetPort")}
       FROM ${q("xray_quick_configs")} qc
       JOIN ${q("xray_quick_config_topology_revisions")} t ON t.${q("id")} = qc.${q("activeTopologyRevisionId")}
      WHERE qc.${q("id")} = ? LIMIT 1`,
    [domain.editIdentity.quickConfigId],
  );
  if (!row || Number(row.revision) !== domain.editIdentity.expectedRevision || row.state !== "ACTIVE"
    || row.currentOperationId !== null && row.currentOperationId !== undefined
    || Number(row.id) !== domain.editIdentity.quickConfigId || String(row.targetAddress) !== domain.target.endpoint.address
    || Number(row.targetPort) !== domain.target.endpoint.port) fail("QUICK_CONFIG_PREVIEW_INVALID");
  const engine = forwardEngine(row.engine);
  const rules = await queryRaw<Row>(
    `SELECT fr.${q("id")}, fr.${q("hostId")}, fr.${q("forwardType")}, fr.${q("sourcePort")},
            fr.${q("targetIp")}, fr.${q("targetPort")}
       FROM ${q("xray_quick_config_rule_bindings")} b
       JOIN ${q("forward_rules")} fr ON fr.${q("id")} = b.${q("forwardRuleId")}
      WHERE b.${q("quickConfigId")} = ? AND b.${q("topologyRevisionId")} = ?
        AND b.${q("state")} = 'READY' AND fr.${q("xrayQuickConfigId")} = ?
        AND fr.${q("isEnabled")} = ? AND fr.${q("pendingDelete")} = ?`,
    [domain.editIdentity.quickConfigId, positiveInteger(row.activeTopologyRevisionId), domain.editIdentity.quickConfigId, true, false],
  );
  const expected = await loadQuickConfigSegments(domain.editIdentity.quickConfigId, positiveInteger(row.activeTopologyRevisionId), {
    publicPort: portNumber(row.publicPort), targetAddress: String(row.targetAddress), targetPort: portNumber(row.targetPort),
  });
  if (rules.length !== expected.length || expected.some(segment => !rules.some(rule =>
    Number(rule.hostId) === segment.hostId && rule.targetIp === segment.targetAddress && Number(rule.targetPort) === segment.targetPort
    && Number(rule.sourcePort) === Number(row.publicPort) && rule.forwardType === engine))) fail("QUICK_CONFIG_PREVIEW_INVALID");
  return {
    quickConfigId: domain.editIdentity.quickConfigId,
    expectedRevision: domain.editIdentity.expectedRevision,
    fromTopologyRevisionId: positiveInteger(row.activeTopologyRevisionId),
    configTag: String(row.configTag),
    publicPort: portNumber(row.publicPort),
    allocationId: positiveInteger(row.portAllocationId),
    engine,
    rules: rules.map((rule) => ({
      ruleId: positiveInteger(rule.id),
      hostId: positiveInteger(rule.hostId),
      engine: forwardEngine(rule.forwardType),
      listenPort: portNumber(rule.sourcePort),
      targetAddress: String(rule.targetIp),
      targetPort: portNumber(rule.targetPort),
    })),
  };
}

function matchingEditRule(snapshot: EditPlanningSnapshot | null, input: {
  hostId: number;
  engine: XrayQuickConfigForwardEngine;
  listenPort: number;
  targetAddress: string;
  targetPort: number;
}) {
  return snapshot?.rules.find((rule) => rule.hostId === input.hostId && rule.engine === input.engine
    && rule.listenPort === input.listenPort && rule.targetAddress === input.targetAddress
    && rule.targetPort === input.targetPort) ?? null;
}

async function editAwareLedgerConflict(
  domain: ResolvedQuickConfigDomain,
  selectedPort: number,
  rewritten: boolean,
  snapshot: EditPlanningSnapshot | null,
): Promise<GlobalConflictReason | null> {
  if (snapshot && snapshot.publicPort === selectedPort) {
    const allocation = await inspectGlobalPortAllocation(selectedPort);
    if (!allocation || allocation.status !== "ACTIVE" || allocation.allocationId !== snapshot.allocationId) {
      return "GLOBAL_PORT_CONFLICT";
    }
    if (allocation.primaryOwnerType === "QUICK_CONFIG" && allocation.primaryOwnerTag === snapshot.configTag) return null;
    if (!rewritten && domain.target.targetType === "XRAY_INBOUND" && allocation.primaryOwnerType === "XRAY_INBOUND") {
      return checkLedger(domain.target, selectedPort, rewritten);
    }
    return "GLOBAL_PORT_CONFLICT";
  }
  return checkLedger(domain.target, selectedPort, rewritten);
}

function editProbeHosts(
  domain: ResolvedQuickConfigDomain,
  engine: XrayQuickConfigForwardEngine,
  selectedPort: number,
  rewritten: boolean,
  routes: readonly ResolvedCarrierRoute[],
  snapshot: EditPlanningSnapshot | null,
) {
  return forwardHostsFor(domain.target, rewritten, routes, selectedPort).filter((host) => !matchingEditRule(snapshot, {
    hostId: host.hostId,
    engine,
    listenPort: selectedPort,
    targetAddress: host.targetAddress,
    targetPort: host.targetPort,
  })).map(({ hostId, hostName }) => ({ hostId, hostName }));
}

function editedListenerConflict(domain: ResolvedQuickConfigDomain, routes: readonly ResolvedCarrierRoute[], selectedPort: number, snapshot: EditPlanningSnapshot | null): boolean {
  if (!snapshot || snapshot.publicPort !== selectedPort) return false;
  return forwardHostsFor(domain.target, selectedPort !== domain.target.endpoint.port, routes, selectedPort).some(segment =>
    snapshot.rules.some(old => old.hostId === segment.hostId && (old.targetAddress !== segment.targetAddress || old.targetPort !== segment.targetPort)));
}

async function portAllowedForHosts(port: number, hosts: readonly { hostId: number }[]): Promise<boolean> {
  const rows = await Promise.all(hosts.map((host) => getHostById(host.hostId)));
  return rows.every((host) => !!host && isPortAllowedByPolicy(port, portPolicyFrom(host)));
}

async function recommendPort(hosts: readonly { hostId: number }[]): Promise<number> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Row>(`SELECT ${q("port")}, ${q("status")} FROM ${q("global_port_allocations")}`);
  const unavailable = new Set(rows.filter((row) => row.status !== "FREE").map((row) => Number(row.port)));
  const range = 65_535 - 1_000 + 1;
  const start = crypto.randomInt(0, range);
  for (let offset = 0; offset < range; offset += 1) {
    const candidate = 1_000 + ((start + offset) % range);
    if (unavailable.has(candidate)) continue;
    if (!await portAllowedForHosts(candidate, hosts)) continue;
    try {
      await assertGlobalPortAvailable(candidate);
      return candidate;
    } catch (error) {
      if (!conflictReason(error)) throw error;
    }
  }
  fail("GLOBAL_PORT_PROBE_FAILED");
}

function recommendationResponse(input: {
  target: QuickConfigTarget;
  userId: number;
  confirmedDomainTokenHash: string;
  engine: XrayQuickConfigForwardEngine;
  carrierRoutesHash: string;
  hostSetHash: string;
  forwardHosts: readonly { hostId: number }[];
  requestedPort: number;
  reasonCode: GlobalConflictReason;
  now: Date;
  key: Buffer;
}): Promise<PortConflict> {
  if (input.target.targetType === "XRAY_INBOUND") {
    return Promise.resolve({ status: "CONFLICT", resolution: "MANUAL", reasonCode: input.reasonCode, requestedPort: input.requestedPort });
  }
  return recommendPort(input.forwardHosts).then((port) => {
    const expiresAt = input.now.getTime() + RECOMMENDATION_TTL_MS;
    const token = signToken({
      v: 1,
      kind: "PORT_RECOMMENDATION",
      nonce: nonce(),
      userId: input.userId,
      confirmedDomainTokenHash: input.confirmedDomainTokenHash,
      targetVersion: input.target.targetVersion,
      engine: input.engine,
      carrierRoutesHash: input.carrierRoutesHash,
      hostSetHash: input.hostSetHash,
      recommendedPort: port,
      conflictingPort: input.requestedPort,
      reasonCode: input.reasonCode,
      issuedAt: input.now.getTime(),
      expiresAt,
    }, input.key);
    return {
      status: "CONFLICT" as const,
      resolution: "RECOMMENDED" as const,
      reasonCode: input.reasonCode,
      requestedPort: input.requestedPort,
      recommendation: { port, recommendationToken: token, expiresAt: new Date(expiresAt).toISOString() },
    };
  });
}

function validateRecommendation(input: {
  token: string;
  userId: number;
  confirmedDomainTokenHash: string;
  target: QuickConfigTarget;
  engine: XrayQuickConfigForwardEngine;
  carrierRoutesHash: string;
  hostSetHash: string;
  options: PlanningOptions;
}): number {
  const parsed = parseSignedToken(input.token, "PORT_RECOMMENDATION", input.options) as RecommendationTokenPayload;
  if (parsed.userId !== input.userId || input.target.targetType !== "EXTERNAL_PROXY_NODE"
    || !hashEqual(parsed.confirmedDomainTokenHash, input.confirmedDomainTokenHash)
    || !hashEqual(parsed.targetVersion, input.target.targetVersion)
    || parsed.engine !== input.engine
    || !hashEqual(parsed.carrierRoutesHash, input.carrierRoutesHash)
    || !hashEqual(parsed.hostSetHash, input.hostSetHash)) fail("QUICK_CONFIG_PREVIEW_INVALID");
  return portNumber(parsed.recommendedPort);
}

export function releaseQuickConfigProbeResultReservations(input: {
  token: string;
  userId: number;
  confirmedDomainTokenHash: string;
  target: QuickConfigTarget;
}, options: PlanningOptions = {}): void {
  const payload = parseSignedToken(input.token, "PROBE_RESULT", options) as ProbeResultTokenPayload;
  if (payload.userId !== input.userId
    || !hashEqual(payload.confirmedDomainTokenHash, input.confirmedDomainTokenHash)
    || payload.targetType !== input.target.targetType || payload.targetId !== input.target.targetId
    || !hashEqual(payload.targetVersion, input.target.targetVersion)
    || !Array.isArray(payload.reservations) || payload.reservations.length > 128) {
    fail("QUICK_CONFIG_PREVIEW_INVALID");
  }
  const selectedPort = portNumber(payload.selectedPort);
  const reservations = payload.reservations.map((reservation) => {
    if (!reservation || typeof reservation !== "object") fail("QUICK_CONFIG_PREVIEW_INVALID");
    const hostId = positiveInteger(reservation.hostId);
    const network = reservation.network;
    const reservationId = String(reservation.reservationId ?? "");
    if ((network !== "tcp" && network !== "udp")
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(reservationId)) {
      fail("QUICK_CONFIG_PREVIEW_INVALID");
    }
    return { reservationId, hostId, port: selectedPort, network };
  });
  if (reservations.length === 0) return;
  try {
    releaseXrayPortProbeReservations({ userId: input.userId, reservations });
  } catch {
    fail("QUICK_CONFIG_PREVIEW_INVALID");
  }
}

async function createProbeRun(input: {
  userId: number;
  port: number;
  hostSetHash: string;
  hostCount: number;
  now: Date;
}): Promise<{ runTag: string; runId: number; expiresAt: Date }> {
  const runTag = `quick-config-candidate:v1:${crypto.randomUUID()}`;
  const expiresAt = new Date(input.now.getTime() + PORT_CHECK_TTL_MS);
  const runId = await insertAndGetId("global_port_probe_runs", {
    probeTag: runTag,
    allocationId: null,
    allocationVersion: null,
    candidatePort: input.port,
    purpose: "CANDIDATE",
    status: "RUNNING",
    hostSetHash: input.hostSetHash,
    expectedHostCount: input.hostCount,
    createdByUserId: input.userId,
    startedAt: input.now,
    finishedAt: null,
    expiresAt,
    errorCode: null,
  });
  return { runTag, runId, expiresAt };
}

function probeStartFailure(error: unknown): PortCheckTokenPayload["startFailureCode"] {
  if (error instanceof XrayPortOperationError) {
    if (error.code === "HOST_OFFLINE" || error.code === "HOST_NOT_FOUND") return "HOST_OFFLINE";
    if (error.code === "UDP_CAPABILITY_REQUIRED" || error.code === "AGENT_CAPABILITY_MISSING") return "UDP_CAPABILITY_REQUIRED";
    if (error.code === "PORT_IN_USE") return "GLOBAL_PORT_CONFLICT";
  }
  return "GLOBAL_PORT_PROBE_FAILED";
}

async function startHostProbes(input: {
  hosts: readonly { hostId: number }[];
  userId: number;
  port: number;
  targetAlias?: Readonly<{ inboundId: number; port: number }>;
}): Promise<{ probes: ProbeDescriptor[]; failure?: PortCheckTokenPayload["startFailureCode"] }> {
  const settled = await Promise.all(input.hosts.flatMap((host) => (["tcp", "udp"] as const).map(async (network) => {
    try {
      const operation = await createXrayPortProbeOperation({
        hostId: host.hostId,
        userId: input.userId,
        mode: "MANUAL",
        manualPort: input.port,
        network,
        ...(input.targetAlias ? { targetAlias: input.targetAlias } : {}),
      });
      return { ok: true as const, probe: { hostId: host.hostId, network, operationId: operation.operationId } };
    } catch (error) {
      return { ok: false as const, failure: probeStartFailure(error) };
    }
  })));
  const probes = settled.flatMap((item) => item.ok ? [item.probe] : []);
  const failures = settled.flatMap((item) => item.ok ? [] : [item.failure]);
  const failure = failures.includes("HOST_OFFLINE") ? "HOST_OFFLINE"
    : failures.includes("UDP_CAPABILITY_REQUIRED") ? "UDP_CAPABILITY_REQUIRED"
      : failures.includes("GLOBAL_PORT_CONFLICT") ? "GLOBAL_PORT_CONFLICT"
        : failures.length > 0 ? "GLOBAL_PORT_PROBE_FAILED" : undefined;
  return { probes, failure };
}

export async function createQuickConfigPortCheck(input: {
  confirmedDomainToken: string;
  carrierRoutes: QuickConfigCarrierRoutesInput;
  engine: XrayQuickConfigForwardEngine;
  choice: QuickConfigPortChoice;
  userId: number;
  replaceProbeResultToken?: string;
}, options: PlanningOptions = {}): Promise<QuickConfigPortCheckStart> {
  try {
    const now = resolvedNow(options);
    const userId = positiveInteger(input.userId);
    const key = tokenKey(options.tokenSecret);
    const domain = await resolveConfirmedQuickConfigDomain({ confirmedDomainToken: input.confirmedDomainToken, userId });
    const carriers = await resolveCarrierRoutes(domain, input.carrierRoutes);
    const engine = forwardEngine(input.engine);
    const editSnapshot = await editPlanningSnapshot(domain);
    if (editSnapshot && editSnapshot.engine !== engine) fail("QUICK_CONFIG_PREVIEW_INVALID");
    const confirmedDomainTokenHash = sha256(input.confirmedDomainToken);
    const carrierRoutesHash = carrierSnapshotHash(carriers);
    const originalForwardHosts = editProbeHosts(domain, engine, domain.target.endpoint.port, false, carriers.resolved, editSnapshot);
    const originalHostSetHash = hostSetHash(originalForwardHosts.map((host) => host.hostId));

    let selectedPort: number;
    if (input.choice.mode === "TARGET_ORIGINAL") {
      selectedPort = domain.target.endpoint.port;
    } else if (input.choice.mode === "MANUAL") {
      if (domain.target.targetType !== "XRAY_INBOUND") fail("QUICK_CONFIG_PREVIEW_INVALID");
      selectedPort = portNumber(input.choice.port);
    } else {
      selectedPort = validateRecommendation({
        token: input.choice.recommendationToken,
        userId,
        confirmedDomainTokenHash,
        target: domain.target,
        engine,
        carrierRoutesHash,
        hostSetHash: originalHostSetHash,
        options,
      });
    }
    const rewritten = selectedPort !== domain.target.endpoint.port;
    await assertForwardEngineAvailable(engine, carriers.normalized, domain.target, rewritten);
    const forwardHosts = editProbeHosts(domain, engine, selectedPort, rewritten, carriers.resolved, editSnapshot);
    const cohortHash = hostSetHash(forwardHosts.map((host) => host.hostId));
    if (input.choice.mode === "RECOMMENDED") {
      const recommendation = parseSignedToken(input.choice.recommendationToken, "PORT_RECOMMENDATION", options) as RecommendationTokenPayload;
      if (!hashEqual(recommendation.hostSetHash, cohortHash)) fail("QUICK_CONFIG_PREVIEW_INVALID");
    }
    if (!await portAllowedForHosts(selectedPort, forwardHosts)) fail("QUICK_CONFIG_HOST_UNAVAILABLE");
    if (input.replaceProbeResultToken) {
      releaseQuickConfigProbeResultReservations({
        token: input.replaceProbeResultToken,
        userId,
        confirmedDomainTokenHash,
        target: domain.target,
      }, options);
    }
    const ledgerConflict = editedListenerConflict(domain, carriers.resolved, selectedPort, editSnapshot)
      ? "GLOBAL_PORT_CONFLICT" : await editAwareLedgerConflict(domain, selectedPort, rewritten, editSnapshot);
    if (ledgerConflict) {
      return recommendationResponse({
        target: domain.target,
        engine,
        userId,
        confirmedDomainTokenHash,
        carrierRoutesHash,
        hostSetHash: cohortHash,
        forwardHosts,
        requestedPort: selectedPort,
        reasonCode: ledgerConflict,
        now,
        key,
      });
    }

    const run = await createProbeRun({ userId, port: selectedPort, hostSetHash: cohortHash, hostCount: forwardHosts.length, now });
    const started = await startHostProbes({
      hosts: forwardHosts,
      userId,
      port: selectedPort,
      ...(!rewritten && domain.target.targetType === "XRAY_INBOUND"
        ? { targetAlias: { inboundId: domain.target.targetId, port: selectedPort } }
        : {}),
    });
    const payload: PortCheckTokenPayload = {
      v: 1,
      kind: "PORT_CHECK",
      nonce: nonce(),
      runTag: run.runTag,
      userId,
      confirmedDomainToken: input.confirmedDomainToken,
      confirmedDomainTokenHash,
      targetType: domain.target.targetType,
      targetId: domain.target.targetId,
      targetVersion: domain.target.targetVersion,
      engine,
      selectedPort,
      rewritten,
      carrierRoutes: carriers.normalized,
      carrierRoutesHash,
      hostSetHash: cohortHash,
      forwardHosts,
      probes: started.probes,
      ...(started.failure ? { startFailureCode: started.failure } : {}),
      issuedAt: now.getTime(),
      expiresAt: run.expiresAt.getTime(),
    };
    return { status: "RUNNING", portCheckId: signToken(payload, key) };
  } catch (error) {
    planningError(error);
  }
}

async function probeRun(payload: PortCheckTokenPayload): Promise<Row> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Row>(
    `SELECT * FROM ${q("global_port_probe_runs")} WHERE ${q("probeTag")} = ? LIMIT 1`,
    [payload.runTag],
  );
  const row = rows[0];
  if (!row || Number(row.createdByUserId) !== payload.userId || Number(row.candidatePort) !== payload.selectedPort
    || row.purpose !== "CANDIDATE" || row.hostSetHash !== payload.hostSetHash
    || Number(row.expectedHostCount) !== payload.forwardHosts.length) fail("QUICK_CONFIG_PREVIEW_INVALID");
  return row;
}

type ProbeOutcome =
  | { state: "RUNNING" }
  | { state: "FREE"; reservation: ProbeReservation }
  | { state: "CONFLICT" }
  | { state: "FAILED"; reason: "HOST_OFFLINE" | "UDP_CAPABILITY_REQUIRED" | "GLOBAL_PORT_PROBE_FAILED" }
  | { state: "EXPIRED" };

async function readProbe(descriptor: ProbeDescriptor, userId: number, port: number): Promise<ProbeOutcome> {
  const result = await getXrayPortProbeOperationResult(descriptor.operationId, userId);
  if (result.status === "QUEUED" || result.status === "RUNNING") return { state: "RUNNING" };
  if (result.status === "SUCCESS" && result.selectedPort === port && result.reservationId && result.expiresAt) {
    try {
      validateXrayPortReservation({
        reservationId: result.reservationId,
        hostId: descriptor.hostId,
        userId,
        port,
        network: descriptor.network,
      });
      return {
        state: "FREE",
        reservation: {
          ...descriptor,
          reservationId: result.reservationId,
          expiresAt: result.expiresAt,
        },
      };
    } catch {
      return { state: "EXPIRED" };
    }
  }
  if (result.status === "TIMEOUT" || result.errorCode === "TASK_EXPIRED") return { state: "EXPIRED" };
  if (result.errorCode === "PORT_IN_USE") return { state: "CONFLICT" };
  if (result.errorCode === "HOST_OFFLINE") return { state: "FAILED", reason: "HOST_OFFLINE" };
  if (result.errorCode === "UDP_CAPABILITY_REQUIRED" || result.errorCode === "AGENT_CAPABILITY_MISSING") {
    return { state: "FAILED", reason: "UDP_CAPABILITY_REQUIRED" };
  }
  return { state: "FAILED", reason: "GLOBAL_PORT_PROBE_FAILED" };
}

function probeStatus(outcome: ProbeOutcome): "FREE" | "OCCUPIED" | "OFFLINE" | "UNSUPPORTED" | "ERROR" | "EXPIRED" | null {
  if (outcome.state === "RUNNING") return null;
  if (outcome.state === "FREE") return "FREE";
  if (outcome.state === "CONFLICT") return "OCCUPIED";
  if (outcome.state === "EXPIRED") return "EXPIRED";
  if (outcome.reason === "HOST_OFFLINE") return "OFFLINE";
  if (outcome.reason === "UDP_CAPABILITY_REQUIRED") return "UNSUPPORTED";
  return "ERROR";
}

async function persistProbeOutcome(input: {
  runId: number;
  descriptor: ProbeDescriptor;
  outcome: ProbeOutcome;
  expiresAt: Date;
  now: Date;
}): Promise<void> {
  const status = probeStatus(input.outcome);
  if (!status) return;
  const outcomeExpiry = input.outcome.state === "FREE"
    ? databaseDate(input.outcome.reservation.expiresAt) ?? input.expiresAt
    : input.expiresAt;
  const q = quoteIdentifier;
  const updated = await executeRaw(
    `UPDATE ${q("global_port_probe_results")} SET ${q("status")} = ?, ${q("probedAt")} = ?, ${q("expiresAt")} = ?
      WHERE ${q("probeRunId")} = ? AND ${q("hostId")} = ? AND ${q("network")} = ? AND ${q("xrayOperationId")} = ?`,
    [status, input.now, outcomeExpiry, input.runId, input.descriptor.hostId, input.descriptor.network, input.descriptor.operationId],
  );
  if (rawAffectedRows(updated) > 0) return;
  try {
    await insertAndGetId("global_port_probe_results", {
      probeRunId: input.runId,
      hostId: input.descriptor.hostId,
      network: input.descriptor.network,
      xrayOperationId: input.descriptor.operationId,
      status,
      probedAt: input.now,
      expiresAt: outcomeExpiry,
    });
  } catch {
    const retried = await executeRaw(
      `UPDATE ${q("global_port_probe_results")} SET ${q("status")} = ?, ${q("probedAt")} = ?, ${q("expiresAt")} = ?
        WHERE ${q("probeRunId")} = ? AND ${q("hostId")} = ? AND ${q("network")} = ? AND ${q("xrayOperationId")} = ?`,
      [status, input.now, outcomeExpiry, input.runId, input.descriptor.hostId, input.descriptor.network, input.descriptor.operationId],
    );
    if (rawAffectedRows(retried) === 0) throw new Error("quick config probe result conflict");
  }
}

function ipv4Number(address: string): number {
  return address.split(".").reduce((value, part) => value * 256 + Number(part), 0) >>> 0;
}

function publicIpv4(value: string): boolean {
  const numeric = ipv4Number(value);
  const inCidr = (base: string, bits: number) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (numeric & mask) === (ipv4Number(base) & mask);
  };
  return ![
    ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
    ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
    ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
  ].some(([base, bits]) => inCidr(base as string, bits as number));
}

function ipv6Number(address: string): bigint | null {
  if (net.isIP(address) !== 6) return null;
  let normalized = address.toLowerCase();
  if (normalized.includes(".")) {
    const split = normalized.lastIndexOf(":");
    const ipv4 = normalized.slice(split + 1);
    if (net.isIP(ipv4) !== 4) return null;
    const value = ipv4Number(ipv4);
    normalized = `${normalized.slice(0, split)}:${(value >>> 16).toString(16)}:${(value & 0xffff).toString(16)}`;
  }
  const halves = normalized.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const omitted = 8 - left.length - right.length;
  if (omitted < 0 || (halves.length === 1 && omitted !== 0)) return null;
  const groups = [...left, ...Array.from({ length: omitted }, () => "0"), ...right];
  let result = 0n;
  for (const group of groups) result = result << 16n | BigInt(Number.parseInt(group || "0", 16));
  return result;
}

function publicIpv6(value: string): boolean {
  const address = ipv6Number(value);
  if (address === null) return false;
  const inCidr = (base: bigint, bits: number) => address >> BigInt(128 - bits) === base >> BigInt(128 - bits);
  return inCidr(0x20000000000000000000000000000000n, 3)
    && !inCidr(0x20010db8000000000000000000000000n, 32)
    && !inCidr(0x20010002000000000000000000000000n, 48);
}

async function lookupPublicAddresses(hostname: string, options: PlanningOptions): Promise<QuickConfigEntryHostEndpoint[]> {
  if (net.isIP(hostname) === 4) return publicIpv4(hostname) ? [{ addressFamily: "IPV4", address: hostname }] : [];
  if (net.isIP(hostname) === 6) return publicIpv6(hostname) ? [{ addressFamily: "IPV6", address: hostname.toLowerCase() }] : [];
  const lookup = options.dnsLookup ?? ((value: string) => dns.lookup(value, { all: true, verbatim: true }));
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const timeout = new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error("dns lookup timeout")), DNS_LOOKUP_TIMEOUT_MS);
      timer.unref?.();
    });
    const results = await Promise.race([lookup(hostname), timeout]);
    const seen = new Set<string>();
    return results.flatMap((entry) => {
      const address = String(entry.address ?? "").toLowerCase();
      const family = Number(entry.family);
      const valid = family === 4 ? publicIpv4(address) : family === 6 && publicIpv6(address);
      const key = `${family}:${address}`;
      if (!valid || seen.has(key)) return [];
      seen.add(key);
      return [{ addressFamily: family === 4 ? "IPV4" as const : "IPV6" as const, address }];
    }).sort((left, right) => left.addressFamily.localeCompare(right.addressFamily) || left.address.localeCompare(right.address));
  } catch {
    return [];
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function candidateId(candidate: Omit<DefaultRouteCandidate, "candidateId" | "label" | "recommended">, nonceValue: string, key: Buffer): string {
  return `qdc_${crypto.createHmac("sha256", key).update(CANDIDATE_CONTEXT).update("\n")
    .update(nonceValue).update("\n").update(stableJson(candidate)).digest("base64url")}`;
}

async function defaultCandidates(input: {
  target: QuickConfigTarget;
  rewritten: boolean;
  routes: readonly ResolvedCarrierRoute[];
  allHosts: readonly QuickConfigEntryHost[];
  nonce: string;
  key: Buffer;
  options: PlanningOptions;
}): Promise<DefaultRouteCandidate[]> {
  let candidates: Array<Omit<DefaultRouteCandidate, "candidateId" | "label" | "recommended">>;
  if (!input.rewritten) {
    const target = input.target;
    if (target.targetType === "XRAY_INBOUND") {
      const landing = input.allHosts.find((host) => host.hostId === target.host.id);
      candidates = (landing?.endpoints ?? []).map((endpoint) => ({
        sourceType: "LANDING" as const,
        hostId: target.host.id,
        addressFamily: endpoint.addressFamily,
        address: endpoint.address,
      }));
    } else {
      candidates = (await lookupPublicAddresses(target.endpoint.address, input.options)).map((endpoint) => ({
        sourceType: "LANDING" as const,
        hostId: null,
        addressFamily: endpoint.addressFamily,
        address: endpoint.address,
      }));
    }
  } else {
    const seen = new Set<string>();
    candidates = input.routes.flatMap((route) => route.endpoints).flatMap((endpoint) => {
      const id = `${endpoint.hostId}:${endpoint.addressFamily}:${endpoint.address}`;
      if (seen.has(id)) return [];
      seen.add(id);
      return [{
        sourceType: "MANAGED_HOST" as const,
        hostId: endpoint.hostId,
        addressFamily: endpoint.addressFamily,
        address: endpoint.address,
      }];
    });
  }
  if (candidates.length === 0) fail("QUICK_CONFIG_HOST_UNAVAILABLE");
  return candidates.map((candidate) => {
    const hostName = candidate.hostId === null ? input.target.name
      : input.allHosts.find((host) => host.hostId === candidate.hostId)?.name ?? `#${candidate.hostId}`;
    return {
      ...candidate,
      candidateId: candidateId(candidate, input.nonce, input.key),
      label: `${hostName} · ${candidate.addressFamily === "IPV4" ? "IPv4" : "IPv6"} · ${candidate.address}`,
      recommended: !input.rewritten,
    };
  }).sort((left, right) => (left.hostId ?? 0) - (right.hostId ?? 0)
    || left.addressFamily.localeCompare(right.addressFamily) || left.address.localeCompare(right.address));
}

async function markRun(input: { runTag: string; status: "SUCCESS" | "FAILED" | "EXPIRED"; errorCode: string | null; now: Date }) {
  const q = quoteIdentifier;
  await executeRaw(
    `UPDATE ${q("global_port_probe_runs")} SET ${q("status")} = ?, ${q("finishedAt")} = ?, ${q("errorCode")} = ?
      WHERE ${q("probeTag")} = ? AND ${q("purpose")} = 'CANDIDATE' AND ${q("status")} = 'RUNNING'`,
    [input.status, input.now, input.errorCode, input.runTag],
  );
}

export async function getQuickConfigPortCheckResult(input: {
  portCheckId: string;
  userId: number;
}, options: PlanningOptions = {}): Promise<QuickConfigPortCheckResult> {
  try {
    const now = resolvedNow(options);
    let payload: PortCheckTokenPayload;
    try {
      payload = parseSignedToken(input.portCheckId, "PORT_CHECK", options) as PortCheckTokenPayload;
    } catch (error) {
      if (error instanceof XrayQuickConfigPlanningError && error.code === "GLOBAL_PORT_PROBE_EXPIRED") {
        return { status: "EXPIRED", reasonCode: "GLOBAL_PORT_PROBE_EXPIRED" };
      }
      throw error;
    }
    if (payload.userId !== positiveInteger(input.userId)) fail("QUICK_CONFIG_PREVIEW_INVALID");
    return withKeyedTaskLock(`quick-config-port-result:${payload.runTag}`, async () => {
      if (!hashEqual(payload.confirmedDomainTokenHash, sha256(payload.confirmedDomainToken))) {
        fail("QUICK_CONFIG_PREVIEW_INVALID");
      }
      const domain = await resolveConfirmedQuickConfigDomain({
        confirmedDomainToken: payload.confirmedDomainToken,
        userId: payload.userId,
      });
      const carriers = await resolveCarrierRoutes(domain, payload.carrierRoutes);
      await assertForwardEngineAvailable(payload.engine, carriers.normalized, domain.target, payload.rewritten);
      const editSnapshot = await editPlanningSnapshot(domain);
      if (editSnapshot && editSnapshot.engine !== payload.engine) fail("QUICK_CONFIG_PREVIEW_INVALID");
      const currentForwardHosts = editProbeHosts(domain, payload.engine, payload.selectedPort, payload.rewritten, carriers.resolved, editSnapshot);
      if (domain.target.targetType !== payload.targetType || domain.target.targetId !== payload.targetId
        || !hashEqual(domain.target.targetVersion, payload.targetVersion)
        || !hashEqual(carrierSnapshotHash(carriers), payload.carrierRoutesHash)
        || !hashEqual(hostSetHash(currentForwardHosts.map((host) => host.hostId)), payload.hostSetHash)
        || stableJson(currentForwardHosts) !== stableJson(payload.forwardHosts)
        || ((payload.selectedPort !== domain.target.endpoint.port) !== payload.rewritten)) {
        fail("QUICK_CONFIG_TARGET_CHANGED");
      }
      const run = await probeRun(payload);
      const runId = positiveInteger(run.id);
      const runExpiry = databaseDate(run.expiresAt);
      if (!runExpiry || runExpiry.getTime() <= now.getTime()) {
        await markRun({ runTag: payload.runTag, status: "EXPIRED", errorCode: "GLOBAL_PORT_PROBE_EXPIRED", now });
        return { status: "EXPIRED", reasonCode: "GLOBAL_PORT_PROBE_EXPIRED" } as const;
      }
      if (payload.startFailureCode) {
        if (payload.startFailureCode === "GLOBAL_PORT_CONFLICT") {
          const response = await recommendationResponse({
            target: domain.target,
            engine: payload.engine,
            userId: payload.userId,
            confirmedDomainTokenHash: payload.confirmedDomainTokenHash,
            carrierRoutesHash: payload.carrierRoutesHash,
            hostSetHash: payload.hostSetHash,
            forwardHosts: payload.forwardHosts,
            requestedPort: payload.selectedPort,
            reasonCode: "GLOBAL_PORT_CONFLICT",
            now,
            key: tokenKey(options.tokenSecret),
          });
          await markRun({ runTag: payload.runTag, status: "FAILED", errorCode: "GLOBAL_PORT_CONFLICT", now });
          return response;
        }
        const reason = payload.startFailureCode;
        await markRun({ runTag: payload.runTag, status: "FAILED", errorCode: reason, now });
        return { status: "FAILED", reasonCode: reason } as const;
      }
      const outcomes = await Promise.all(payload.probes.map(async (descriptor) => ({
        descriptor,
        outcome: await readProbe(descriptor, payload.userId, payload.selectedPort),
      })));
      await Promise.all(outcomes.map(({ descriptor, outcome }) => persistProbeOutcome({
        runId,
        descriptor,
        outcome,
        expiresAt: runExpiry,
        now,
      })));
      const expectedProbeCount = payload.forwardHosts.length * 2;
      if (payload.probes.length !== expectedProbeCount) {
        await markRun({ runTag: payload.runTag, status: "FAILED", errorCode: "GLOBAL_PORT_PROBE_FAILED", now });
        return { status: "FAILED", reasonCode: "GLOBAL_PORT_PROBE_FAILED" };
      }
      const terminalHostIds = new Set(payload.forwardHosts.filter((host) => {
        const hostOutcomes = outcomes.filter((item) => item.descriptor.hostId === host.hostId);
        return hostOutcomes.length === 2 && hostOutcomes.every((item) => item.outcome.state !== "RUNNING");
      }).map((host) => host.hostId));
      if (outcomes.some((item) => item.outcome.state === "RUNNING")) {
        return { status: "RUNNING", completedHosts: terminalHostIds.size, totalHosts: payload.forwardHosts.length };
      }
      if (outcomes.some((item) => item.outcome.state === "EXPIRED")) {
        await markRun({ runTag: payload.runTag, status: "EXPIRED", errorCode: "GLOBAL_PORT_PROBE_EXPIRED", now });
        return { status: "EXPIRED", reasonCode: "GLOBAL_PORT_PROBE_EXPIRED" };
      }
      const failed = outcomes.find((item) => item.outcome.state === "FAILED")?.outcome;
      if (failed?.state === "FAILED") {
        await markRun({ runTag: payload.runTag, status: "FAILED", errorCode: failed.reason, now });
        return { status: "FAILED", reasonCode: failed.reason };
      }
      if (outcomes.some((item) => item.outcome.state === "CONFLICT")) {
        const response = await recommendationResponse({
          target: domain.target,
          engine: payload.engine,
          userId: payload.userId,
          confirmedDomainTokenHash: payload.confirmedDomainTokenHash,
          carrierRoutesHash: payload.carrierRoutesHash,
          hostSetHash: payload.hostSetHash,
          forwardHosts: payload.forwardHosts,
          requestedPort: payload.selectedPort,
          reasonCode: "GLOBAL_PORT_EXTERNAL_OCCUPIED",
          now,
          key: tokenKey(options.tokenSecret),
        });
        await markRun({ runTag: payload.runTag, status: "FAILED", errorCode: "GLOBAL_PORT_EXTERNAL_OCCUPIED", now });
        return response;
      }
      const reservations = outcomes.flatMap((item) => item.outcome.state === "FREE" ? [item.outcome.reservation] : []);
      const candidates = await defaultCandidates({
        target: domain.target,
        rewritten: payload.rewritten,
        routes: carriers.resolved,
        allHosts: carriers.hosts,
        nonce: payload.nonce,
        key: tokenKey(options.tokenSecret),
        options,
      });
      const expiresAt = Math.min(runExpiry.getTime(), ...reservations.map((reservation) => new Date(reservation.expiresAt).getTime()));
      const probeToken: ProbeResultTokenPayload = {
        v: 1,
        kind: "PROBE_RESULT",
        nonce: payload.nonce,
        runTag: payload.runTag,
        userId: payload.userId,
        confirmedDomainTokenHash: payload.confirmedDomainTokenHash,
        targetType: payload.targetType,
        targetId: payload.targetId,
        targetVersion: payload.targetVersion,
        engine: payload.engine,
        selectedPort: payload.selectedPort,
        rewritten: payload.rewritten,
        carrierRoutes: payload.carrierRoutes,
        carrierRoutesHash: payload.carrierRoutesHash,
        hostSetHash: payload.hostSetHash,
        reservations,
        candidates,
        issuedAt: now.getTime(),
        expiresAt,
      };
      await markRun({ runTag: payload.runTag, status: "SUCCESS", errorCode: null, now });
      return {
        status: "SUCCESS",
        selectedPort: payload.selectedPort,
        rewritten: payload.rewritten,
        probeResultToken: signToken(probeToken, tokenKey(options.tokenSecret)),
        expiresAt: new Date(expiresAt).toISOString(),
        defaultRouteCandidates: candidates,
      };
    });
  } catch (error) {
    planningError(error);
  }
}

async function validateProbePayload(input: {
  probeResultToken: string;
  confirmedDomainToken: string;
  domain: ResolvedQuickConfigDomain;
  carriers: { normalized: QuickConfigCarrierRoutesInput; resolved: ResolvedCarrierRoute[] };
  engine: XrayQuickConfigForwardEngine;
  userId: number;
  options: PlanningOptions;
}): Promise<ProbeResultTokenPayload> {
  const payload = parseSignedToken(input.probeResultToken, "PROBE_RESULT", input.options) as ProbeResultTokenPayload;
  const carrierHash = carrierSnapshotHash(input.carriers);
  const editSnapshot = await editPlanningSnapshot(input.domain);
  if (editSnapshot && editSnapshot.engine !== input.engine) fail("QUICK_CONFIG_PREVIEW_INVALID");
  const forwardHosts = editProbeHosts(input.domain, input.engine, payload.selectedPort, payload.rewritten, input.carriers.resolved, editSnapshot);
  if (payload.userId !== input.userId || !hashEqual(payload.confirmedDomainTokenHash, sha256(input.confirmedDomainToken))
    || payload.targetType !== input.domain.target.targetType || payload.targetId !== input.domain.target.targetId
    || !hashEqual(payload.targetVersion, input.domain.target.targetVersion)
    || payload.engine !== input.engine
    || !hashEqual(payload.carrierRoutesHash, carrierHash)
    || !hashEqual(payload.hostSetHash, hostSetHash(forwardHosts.map((host) => host.hostId)))
    || stableJson(payload.carrierRoutes) !== stableJson(input.carriers.normalized)
    || ((payload.selectedPort !== input.domain.target.endpoint.port) !== payload.rewritten)
    || payload.reservations.length !== forwardHosts.length * 2) fail("QUICK_CONFIG_PREVIEW_INVALID");
  for (const reservation of payload.reservations) {
    validateXrayPortReservation({
      reservationId: reservation.reservationId,
      hostId: reservation.hostId,
      userId: payload.userId,
      port: payload.selectedPort,
      network: reservation.network,
    });
  }
  return payload;
}

function selectedCandidates(payload: ProbeResultTokenPayload, input: ReadonlyArray<{ candidateId: string }>) {
  if (!Array.isArray(input) || input.length < 1 || input.length > 64) fail("QUICK_CONFIG_PREVIEW_INVALID");
  const seen = new Set<string>();
  const byId = new Map(payload.candidates.map((candidate) => [candidate.candidateId, candidate]));
  return input.map(({ candidateId: id }) => {
    if (typeof id !== "string" || !/^qdc_[A-Za-z0-9_-]{43}$/.test(id) || seen.has(id)) fail("QUICK_CONFIG_PREVIEW_INVALID");
    seen.add(id);
    const candidate = byId.get(id);
    if (!candidate) fail("QUICK_CONFIG_PREVIEW_INVALID");
    return candidate;
  });
}

async function previewWithoutToken(input: {
  domain: ResolvedQuickConfigDomain;
  carriers: ResolvedCarrierRoute[];
  selectedDefaults: DefaultRouteCandidate[];
  probe: ProbeResultTokenPayload;
  engine: XrayQuickConfigForwardEngine;
}): Promise<Omit<QuickConfigPreviewDto, "previewToken" | "expiresAt">> {
  const target = input.domain.target;
  const forwardHosts = forwardHostsFor(target, input.probe.rewritten, input.carriers, input.probe.selectedPort);
  const editSnapshot = await editPlanningSnapshot(input.domain);
  const rules = forwardHosts.map((host) => ({
    ruleKey: sha256(stableJson({ schema: "quick-config-rule:v1", hostId: host.hostId, engine: input.engine,
      listenPort: input.probe.selectedPort, targetAddress: host.targetAddress, targetPort: host.targetPort })),
    action: matchingEditRule(editSnapshot, {
      hostId: host.hostId,
      engine: input.engine,
      listenPort: input.probe.selectedPort,
      targetAddress: host.targetAddress,
      targetPort: host.targetPort,
    }) ? "REUSE" as const : "CREATE" as const,
    hostId: host.hostId,
    hostName: host.hostName,
    engine: input.engine,
    listenPort: input.probe.selectedPort,
    targetAddress: host.targetAddress,
    targetPort: host.targetPort,
  }));
  const carrierRecords = input.carriers.flatMap((route) => route.endpoints.map((endpoint) => {
    const recordType = endpoint.addressFamily === "IPV4" ? "A" as const : "AAAA" as const;
    return {
      routeKind: "CARRIER" as const,
      carrier: route.carrier,
      providerLineId: route.providerLineId,
      recordType,
      value: endpoint.address,
      ttl: DNS_TTL,
    };
  }));
  const defaultLine = input.domain.zone.carrierLines.find((line) => line.category === "DEFAULT");
  if (!defaultLine || defaultLine.status !== "AVAILABLE") fail("QUICK_CONFIG_PREVIEW_INVALID");
  const defaultRecords = input.selectedDefaults.map((candidate) => {
    const recordType = candidate.addressFamily === "IPV4" ? "A" as const : "AAAA" as const;
    return {
      routeKind: "DEFAULT" as const,
      carrier: null,
      providerLineId: defaultLine.providerLineId,
      recordType,
      value: candidate.address,
      ttl: DNS_TTL,
    };
  });
  const desiredRecords = [...carrierRecords, ...defaultRecords];
  const { dnsRecords, conflictingRecords } = input.domain.editIdentity
    ? planQuickConfigDnsDiff(desiredRecords, input.domain.conflicts, input.domain.ownedRecordRefs)
    : {
      dnsRecords: desiredRecords.map(record => ({ ...record, action: input.domain.conflicts.some(previous =>
        previous.recordType === record.recordType && previous.providerLineId === record.providerLineId)
        ? "REPLACE" as const : "CREATE" as const })),
      conflictingRecords: input.domain.conflicts.map(record => ({ ...record,
        action: record.recordType === "CNAME" ? "DELETE" as const : "REPLACE" as const })),
    };
  const warnings: Array<{ code: string; message: string }> = [];
  if (input.probe.rewritten) warnings.push({ code: "PUBLIC_PORT_REWRITTEN", message: "The public port differs from the target port." });
  if (conflictingRecords.length > 0) warnings.push({ code: "DNS_RECORDS_WILL_CHANGE", message: "Confirmed DNS records will be replaced or removed during apply." });
  return {
    fqdn: input.domain.fqdn,
    publicPort: input.probe.selectedPort,
    target: {
      targetType: target.targetType,
      targetId: target.targetId,
      targetName: target.name,
      address: target.endpoint.address,
      port: target.endpoint.port,
    },
    rules,
    dnsRecords,
    conflictingRecords,
    preservedRecords: input.domain.preservedRecords,
    allocation: {
      port: input.probe.selectedPort,
      mode: target.targetType === "XRAY_INBOUND" && !input.probe.rewritten ? "TARGET_ALIAS" : "RESERVE_NEW",
      rewritten: input.probe.rewritten,
    },
    warnings,
  };
}

async function buildImmutablePlan(input: {
  confirmedDomainToken: string;
  carrierRoutes: QuickConfigCarrierRoutesInput;
  engine: XrayQuickConfigForwardEngine;
  probeResultToken: string;
  defaultRoutes: ReadonlyArray<{ candidateId: string }>;
  userId: number;
}, options: PlanningOptions): Promise<QuickConfigImmutablePlan> {
  const userId = positiveInteger(input.userId);
  const domain = await resolveConfirmedQuickConfigDomain({ confirmedDomainToken: input.confirmedDomainToken, userId });
  const carriers = await resolveCarrierRoutes(domain, input.carrierRoutes);
  const engine = forwardEngine(input.engine);
  const probe = await validateProbePayload({
    probeResultToken: input.probeResultToken,
    confirmedDomainToken: input.confirmedDomainToken,
    domain,
    carriers,
    engine,
    userId,
    options,
  });
  await assertForwardEngineAvailable(engine, carriers.normalized, domain.target, probe.rewritten);
  const expectedCandidates = await defaultCandidates({
    target: domain.target,
    rewritten: probe.rewritten,
    routes: carriers.resolved,
    allHosts: carriers.hosts,
    nonce: probe.nonce,
    key: tokenKey(options.tokenSecret),
    options,
  });
  if (stableJson(expectedCandidates) !== stableJson(probe.candidates)) fail("QUICK_CONFIG_PREVIEW_INVALID");
  const defaults = selectedCandidates(probe, input.defaultRoutes);
  const editSnapshot = await editPlanningSnapshot(domain);
  if (editedListenerConflict(domain, carriers.resolved, probe.selectedPort, editSnapshot)) fail("QUICK_CONFIG_PREVIEW_INVALID");
  const ledgerConflict = await editAwareLedgerConflict(domain, probe.selectedPort, probe.rewritten, editSnapshot);
  if (ledgerConflict) fail("QUICK_CONFIG_PREVIEW_INVALID");
  const preview = await previewWithoutToken({ domain, carriers: carriers.resolved, selectedDefaults: defaults, probe, engine });
  return {
    engine,
    preview,
    domain,
    carrierRoutes: carriers.resolved,
    defaultRoutes: defaults,
    reservations: probe.reservations,
    confirmedDomainToken: input.confirmedDomainToken,
    probeResultToken: input.probeResultToken,
    expiresAt: new Date(probe.expiresAt).toISOString(),
  };
}

export async function previewQuickConfig(input: {
  confirmedDomainToken: string;
  carrierRoutes: QuickConfigCarrierRoutesInput;
  engine: XrayQuickConfigForwardEngine;
  probeResultToken: string;
  defaultRoutes: ReadonlyArray<{ candidateId: string }>;
  userId: number;
}, options: PlanningOptions = {}): Promise<QuickConfigPreviewDto> {
  try {
    const now = resolvedNow(options);
    const plan = await buildImmutablePlan(input, options);
    if (plan.domain.editIdentity) fail("QUICK_CONFIG_PREVIEW_INVALID");
    const expiresAt = Math.min(now.getTime() + PREVIEW_TTL_MS, new Date(plan.expiresAt).getTime());
    const planHash = sha256(stableJson(plan.preview));
    const payload: PreviewTokenPayload = {
      v: 1,
      kind: "PREVIEW",
      nonce: nonce(),
      userId: positiveInteger(input.userId),
      confirmedDomainToken: input.confirmedDomainToken,
      engine: forwardEngine(input.engine),
      carrierRoutes: normalizeCarrierInput(input.carrierRoutes),
      probeResultToken: input.probeResultToken,
      defaultRoutes: input.defaultRoutes,
      planHash,
      issuedAt: now.getTime(),
      expiresAt,
    };
    return {
      ...plan.preview,
      previewToken: signToken(payload, tokenKey(options.tokenSecret)),
      expiresAt: new Date(expiresAt).toISOString(),
    };
  } catch (error) {
    planningError(error);
  }
}

export async function previewQuickConfigEdit(input: {
  quickConfigId: number;
  expectedRevision: number;
  confirmedDomainToken: string;
  carrierRoutes: QuickConfigCarrierRoutesInput;
  engine: XrayQuickConfigForwardEngine;
  probeResultToken: string;
  defaultRoutes: ReadonlyArray<{ candidateId: string }>;
  userId: number;
}, options: PlanningOptions = {}): Promise<QuickConfigPreviewDto> {
  try {
    const now = resolvedNow(options);
    const plan = await buildImmutablePlan(input, options);
    const identity = plan.domain.editIdentity;
    if (!identity || identity.quickConfigId !== positiveInteger(input.quickConfigId)
      || identity.expectedRevision !== positiveInteger(input.expectedRevision)) fail("QUICK_CONFIG_PREVIEW_INVALID");
    const snapshot = await editPlanningSnapshot(plan.domain);
    if (!snapshot) fail("QUICK_CONFIG_PREVIEW_INVALID");
    const expiresAt = Math.min(now.getTime() + PREVIEW_TTL_MS, new Date(plan.expiresAt).getTime());
    const payload: PreviewTokenPayload = {
      v: 1,
      kind: "PREVIEW",
      nonce: nonce(),
      userId: positiveInteger(input.userId),
      confirmedDomainToken: input.confirmedDomainToken,
      engine: forwardEngine(input.engine),
      carrierRoutes: normalizeCarrierInput(input.carrierRoutes),
      probeResultToken: input.probeResultToken,
      defaultRoutes: input.defaultRoutes,
      planHash: sha256(stableJson(plan.preview)),
      editQuickConfigId: identity.quickConfigId,
      editExpectedRevision: identity.expectedRevision,
      fromTopologyRevisionId: snapshot.fromTopologyRevisionId,
      issuedAt: now.getTime(),
      expiresAt,
    };
    return { ...plan.preview, previewToken: signToken(payload, tokenKey(options.tokenSecret)), expiresAt: new Date(expiresAt).toISOString() };
  } catch (error) {
    planningError(error);
  }
}

/**
 * Server-only 057M hand-off. It reconstructs the plan from signed inputs and
 * repeats domain, target, carrier, probe reservation, DNS resolution and ledger
 * checks before returning an immutable canonical plan.
 */
export async function validateQuickConfigPreviewToken(input: {
  previewToken: string;
  userId: number;
}, options: PlanningOptions = {}): Promise<QuickConfigImmutablePlan> {
  try {
    const payload = parseSignedToken(input.previewToken, "PREVIEW", options) as PreviewTokenPayload;
    const userId = positiveInteger(input.userId);
    if (payload.userId !== userId) fail("QUICK_CONFIG_PREVIEW_INVALID");
    if (payload.editQuickConfigId !== undefined || payload.editExpectedRevision !== undefined
      || payload.fromTopologyRevisionId !== undefined) fail("QUICK_CONFIG_PREVIEW_INVALID");
    const plan = await buildImmutablePlan({
      confirmedDomainToken: payload.confirmedDomainToken,
      engine: payload.engine,
      carrierRoutes: payload.carrierRoutes,
      probeResultToken: payload.probeResultToken,
      defaultRoutes: payload.defaultRoutes,
      userId,
    }, options);
    if (!hashEqual(payload.planHash, sha256(stableJson(plan.preview)))) fail("QUICK_CONFIG_PREVIEW_INVALID");
    return Object.freeze(plan);
  } catch (error) {
    planningError(error);
  }
}

export async function validateQuickConfigEditPreviewToken(input: {
  previewToken: string;
  userId: number;
}, options: PlanningOptions = {}): Promise<QuickConfigImmutablePlan & Readonly<{
  editIdentity: { quickConfigId: number; expectedRevision: number; fromTopologyRevisionId: number };
}>> {
  try {
    const payload = parseSignedToken(input.previewToken, "PREVIEW", options) as PreviewTokenPayload;
    const userId = positiveInteger(input.userId);
    if (payload.userId !== userId || payload.editQuickConfigId === undefined
      || payload.editExpectedRevision === undefined || payload.fromTopologyRevisionId === undefined) {
      fail("QUICK_CONFIG_PREVIEW_INVALID");
    }
    const plan = await buildImmutablePlan({
      confirmedDomainToken: payload.confirmedDomainToken,
      engine: payload.engine,
      carrierRoutes: payload.carrierRoutes,
      probeResultToken: payload.probeResultToken,
      defaultRoutes: payload.defaultRoutes,
      userId,
    }, options);
    const identity = plan.domain.editIdentity;
    const snapshot = await editPlanningSnapshot(plan.domain);
    if (!identity || !snapshot || identity.quickConfigId !== positiveInteger(payload.editQuickConfigId)
      || identity.expectedRevision !== positiveInteger(payload.editExpectedRevision)
      || snapshot.fromTopologyRevisionId !== positiveInteger(payload.fromTopologyRevisionId)
      || !hashEqual(payload.planHash, sha256(stableJson(plan.preview)))) fail("QUICK_CONFIG_PREVIEW_INVALID");
    return Object.freeze({
      ...plan,
      editIdentity: {
        quickConfigId: identity.quickConfigId,
        expectedRevision: identity.expectedRevision,
        fromTopologyRevisionId: snapshot.fromTopologyRevisionId,
      },
    });
  } catch (error) {
    planningError(error);
  }
}

function planningError(error: unknown): never {
  if (error instanceof QuickConfigPathError) fail("QUICK_CONFIG_PREVIEW_INVALID");
  if (error instanceof XrayQuickConfigPlanningError) throw error;
  if (error instanceof XrayQuickConfigServiceError) throw error;
  if (error instanceof GlobalPortAllocationError) {
    if (error.code === "GLOBAL_PORT_RESERVATION_EXPIRED") fail("GLOBAL_PORT_PROBE_EXPIRED");
    fail("QUICK_CONFIG_PREVIEW_INVALID");
  }
  if (error instanceof XrayPortOperationError) {
    if (error.code === "PORT_RESERVATION_EXPIRED") fail("GLOBAL_PORT_PROBE_EXPIRED");
    if (error.code === "HOST_OFFLINE") fail("HOST_OFFLINE");
    if (error.code === "UDP_CAPABILITY_REQUIRED" || error.code === "AGENT_CAPABILITY_MISSING") fail("UDP_CAPABILITY_REQUIRED");
    fail("GLOBAL_PORT_PROBE_FAILED");
  }
  throw error;
}
