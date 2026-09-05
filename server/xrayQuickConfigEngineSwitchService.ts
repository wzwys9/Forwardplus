import crypto from "node:crypto";
import { quickConfigPathEngineCompatible } from "../shared/xrayQuickConfigForwardEngines";
import { listXrayQuickConfigEntryHosts } from "./xrayQuickConfigEntryHosts";
import { compileQuickConfigTopology, parseQuickConfigRelays, serializeQuickConfigRelays } from "./xrayQuickConfigTopology";

import {
  XRAY_QUICK_CONFIG_FORWARD_ENGINES,
  type XrayQuickConfigForwardEngine,
} from "../shared/xrayQuickConfigForwardEngines";
import { pushAgentRefresh } from "./agentEvents";
import { boolValue, inList, quoteIdentifier } from "./dbCompat";
import {
  afterDatabaseCommit,
  executeRaw,
  insertAndGetId,
  nowDate,
  queryRaw,
  rawAffectedRows,
  withDatabaseTransaction,
} from "./dbRuntime";
import { ENV } from "./env";
import { getForwardProtocolSettings } from "./forwardProtocolSettings";
import { withKeyedTaskLock } from "./keyedTaskLock";
import { listXrayQuickConfigForwardEngines } from "./xrayQuickConfigForwardEngineService";
import { assignQuickConfigRulePortResource } from "./quickConfigPortResourceService";

type Row = Record<string, unknown>;
type AddressFamily = "IPV4" | "IPV6";

export const XRAY_QUICK_CONFIG_ENGINE_SWITCH_ERROR_CODES = [
  "QUICK_CONFIG_NOT_FOUND",
  "QUICK_CONFIG_REVISION_CONFLICT",
  "QUICK_CONFIG_OPERATION_CONFLICT",
  "QUICK_CONFIG_PREVIEW_INVALID",
  "QUICK_CONFIG_PREVIEW_EXPIRED",
  "FORWARD_PROTOCOL_DISABLED",
  "HOST_OFFLINE",
  "AGENT_CAPABILITY_MISSING",
  "UDP_CAPABILITY_REQUIRED",
  "QUICK_CONFIG_HOST_UNAVAILABLE",
  "QUICK_CONFIG_ADDRESS_UNAVAILABLE",
  "QUICK_CONFIG_PATH_ADDRESS_FAMILY_UNSUPPORTED",
  "RULE_APPLY_FAILED",
  "RULE_CLEANUP_FAILED",
  "SENSITIVE_DATA_UNAVAILABLE",
] as const;

export type XrayQuickConfigEngineSwitchErrorCode =
  typeof XRAY_QUICK_CONFIG_ENGINE_SWITCH_ERROR_CODES[number];

export class XrayQuickConfigEngineSwitchError extends Error {
  constructor(readonly code: XrayQuickConfigEngineSwitchErrorCode) {
    super(code);
    this.name = "XrayQuickConfigEngineSwitchError";
  }
}

type SwitchOptions = Readonly<{
  now?: () => Date;
  tokenSecret?: string;
}>;

type SwitchRoute = Readonly<{
  relayHopsJson: string | null;
  id: number;
  lineCategory: string;
  providerLineId: string;
  sourceType: string;
  hostId: number | null;
  addressFamily: AddressFamily;
  address: string;
  routeMode: "DIRECT" | "FORWARD";
  sortOrder: number;
}>;

type SwitchRule = Readonly<{
  bindingId: number;
  ruleId: number;
  hostId: number;
  hostName: string;
  forwardType: XrayQuickConfigForwardEngine;
  isEnabled: boolean;
  isRunning: boolean;
}>;

type SwitchSnapshot = Readonly<{
  quickConfigId: number;
  configTag: string;
  revision: number;
  topologyId: number;
  topologyRevisionNumber: number;
  fromEngine: XrayQuickConfigForwardEngine;
  targetAddress: string;
  targetPort: number;
  publicPort: number;
  portAllocationId: number;
  routes: SwitchRoute[];
  rules: SwitchRule[];
  snapshotHash: string;
}>;

type SwitchTokenPayload = Readonly<{
  v: 1;
  kind: "ENGINE_SWITCH";
  nonce: string;
  userId: number;
  quickConfigId: number;
  expectedRevision: number;
  fromTopologyRevisionId: number;
  fromEngine: XrayQuickConfigForwardEngine;
  toEngine: XrayQuickConfigForwardEngine;
  publicPort: number;
  snapshotHash: string;
  issuedAt: number;
  expiresAt: number;
}>;

export type XrayQuickConfigEngineSwitchPreview = Readonly<{
  quickConfigId: number;
  revision: number;
  fromEngine: XrayQuickConfigForwardEngine;
  toEngine: XrayQuickConfigForwardEngine;
  publicPort: number;
  affectedHosts: Array<Readonly<{ hostId: number; name: string }>>;
  warnings: Array<Readonly<{ code: "ENGINE_SWITCH_DOWNTIME"; message: string }>>;
  switchToken: string;
  expiresAt: string;
}>;

const TOKEN_CONTEXT = "forwardx-xray-quick-config-engine-switch-token:v1";
const TOKEN_TTL_MS = 5 * 60_000;
const MAX_TOKEN_BYTES = 8_192;
const TOKEN_PART = /^[A-Za-z0-9_-]+$/;
const PHASE_TIMEOUT_MS = 120_000;

function fail(code: XrayQuickConfigEngineSwitchErrorCode): never {
  throw new XrayQuickConfigEngineSwitchError(code);
}

function positiveInteger(value: unknown, code: XrayQuickConfigEngineSwitchErrorCode = "QUICK_CONFIG_PREVIEW_INVALID") {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) fail(code);
  return parsed;
}

function port(value: unknown) {
  const parsed = positiveInteger(value);
  if (parsed > 65_535) fail("QUICK_CONFIG_PREVIEW_INVALID");
  return parsed;
}

function boundedText(value: unknown, maxBytes: number) {
  if (typeof value !== "string" || !value || Buffer.byteLength(value, "utf8") > maxBytes) {
    fail("QUICK_CONFIG_PREVIEW_INVALID");
  }
  return value;
}

function databaseBoolean(value: unknown) {
  return value === true || value === 1 || value === "1" || value === "true";
}

function databaseDate(value: unknown): Date | null {
  if (value instanceof Date && Number.isFinite(value.getTime())) return value;
  const numeric = Number(value);
  const parsed = Number.isFinite(numeric)
    ? new Date(numeric < 10_000_000_000 ? numeric * 1_000 : numeric)
    : new Date(String(value ?? ""));
  return Number.isFinite(parsed.getTime()) ? parsed : null;
}

function engine(value: unknown): XrayQuickConfigForwardEngine {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (!(XRAY_QUICK_CONFIG_FORWARD_ENGINES as readonly string[]).includes(normalized)) {
    fail("QUICK_CONFIG_PREVIEW_INVALID");
  }
  return normalized as XrayQuickConfigForwardEngine;
}

function resolvedNow(options: SwitchOptions) {
  const value = options.now?.() ?? new Date();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) fail("QUICK_CONFIG_PREVIEW_INVALID");
  return new Date(value);
}

function stableValue(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(stableValue);
  if (!value || typeof value !== "object") fail("QUICK_CONFIG_PREVIEW_INVALID");
  const output: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    const item = (value as Record<string, unknown>)[key];
    if (item === undefined) fail("QUICK_CONFIG_PREVIEW_INVALID");
    output[key] = stableValue(item);
  }
  return output;
}

function stableJson(value: unknown) {
  return JSON.stringify(stableValue(value));
}

function sha256(value: string) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function secureHashEqual(left: unknown, right: unknown) {
  if (typeof left !== "string" || typeof right !== "string"
    || !/^[a-f0-9]{64}$/.test(left) || !/^[a-f0-9]{64}$/.test(right)) return false;
  return crypto.timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function tokenKey(secret = ENV.cookieSecret) {
  if (typeof secret !== "string" || Buffer.byteLength(secret, "utf8") < 16) {
    fail("SENSITIVE_DATA_UNAVAILABLE");
  }
  return crypto.createHmac("sha256", secret).update(TOKEN_CONTEXT, "utf8").digest();
}

function signToken(payload: SwitchTokenPayload, options: SwitchOptions) {
  const body = Buffer.from(stableJson(payload), "utf8").toString("base64url");
  const unsigned = `qce1.${body}`;
  const signature = crypto.createHmac("sha256", tokenKey(options.tokenSecret))
    .update(unsigned, "utf8").digest("base64url");
  const token = `${unsigned}.${signature}`;
  if (Buffer.byteLength(token, "utf8") > MAX_TOKEN_BYTES) fail("QUICK_CONFIG_PREVIEW_INVALID");
  return token;
}

function parseToken(raw: unknown, options: SwitchOptions): SwitchTokenPayload {
  if (typeof raw !== "string" || Buffer.byteLength(raw, "utf8") > MAX_TOKEN_BYTES) {
    fail("QUICK_CONFIG_PREVIEW_INVALID");
  }
  const parts = raw.split(".");
  if (parts.length !== 3 || parts[0] !== "qce1" || !TOKEN_PART.test(parts[1]) || !TOKEN_PART.test(parts[2])) {
    fail("QUICK_CONFIG_PREVIEW_INVALID");
  }
  const unsigned = `${parts[0]}.${parts[1]}`;
  const expected = crypto.createHmac("sha256", tokenKey(options.tokenSecret)).update(unsigned, "utf8").digest();
  const actual = Buffer.from(parts[2], "base64url");
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    fail("QUICK_CONFIG_PREVIEW_INVALID");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    fail("QUICK_CONFIG_PREVIEW_INVALID");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) fail("QUICK_CONFIG_PREVIEW_INVALID");
  const value = parsed as Record<string, unknown>;
  const fromEngine = engine(value.fromEngine);
  const toEngine = engine(value.toEngine);
  if (value.v !== 1 || value.kind !== "ENGINE_SWITCH" || typeof value.nonce !== "string"
    || !/^[A-Za-z0-9_-]{22}$/.test(value.nonce) || !Number.isSafeInteger(value.userId)
    || !Number.isSafeInteger(value.quickConfigId) || !Number.isSafeInteger(value.expectedRevision)
    || !Number.isSafeInteger(value.fromTopologyRevisionId) || !Number.isSafeInteger(value.publicPort)
    || typeof value.snapshotHash !== "string" || !Number.isSafeInteger(value.issuedAt)
    || !Number.isSafeInteger(value.expiresAt)) fail("QUICK_CONFIG_PREVIEW_INVALID");
  const now = resolvedNow(options).getTime();
  if (Number(value.expiresAt) <= now) fail("QUICK_CONFIG_PREVIEW_EXPIRED");
  if (Number(value.issuedAt) > now + 30_000 || Number(value.expiresAt) - Number(value.issuedAt) !== TOKEN_TTL_MS) {
    fail("QUICK_CONFIG_PREVIEW_INVALID");
  }
  return {
    v: 1,
    kind: "ENGINE_SWITCH",
    nonce: value.nonce,
    userId: positiveInteger(value.userId),
    quickConfigId: positiveInteger(value.quickConfigId),
    expectedRevision: positiveInteger(value.expectedRevision),
    fromTopologyRevisionId: positiveInteger(value.fromTopologyRevisionId),
    fromEngine,
    toEngine,
    publicPort: port(value.publicPort),
    snapshotHash: boundedText(value.snapshotHash, 64),
    issuedAt: Number(value.issuedAt),
    expiresAt: Number(value.expiresAt),
  };
}

function snapshotProjection(input: Omit<SwitchSnapshot, "snapshotHash">) {
  return {
    quickConfigId: input.quickConfigId,
    revision: input.revision,
    topologyId: input.topologyId,
    topologyRevisionNumber: input.topologyRevisionNumber,
    fromEngine: input.fromEngine,
    targetAddress: input.targetAddress,
    targetPort: input.targetPort,
    publicPort: input.publicPort,
    portAllocationId: input.portAllocationId,
    routes: input.routes.map((route) => ({
      id: route.id,
      lineCategory: route.lineCategory,
      providerLineId: route.providerLineId,
      sourceType: route.sourceType,
      hostId: route.hostId,
      addressFamily: route.addressFamily,
      address: route.address,
      routeMode: route.routeMode,
      relayHopsJson: route.relayHopsJson,
      sortOrder: route.sortOrder,
    })),
    rules: input.rules.map((rule) => ({
      bindingId: rule.bindingId,
      ruleId: rule.ruleId,
      hostId: rule.hostId,
      forwardType: rule.forwardType,
    })),
  };
}

async function loadSnapshot(quickConfigId: number, expectedRevision?: number): Promise<SwitchSnapshot> {
  const q = quoteIdentifier;
  const [row] = await queryRaw<Row>(
    `SELECT qc.${q("id")}, qc.${q("configTag")}, qc.${q("revision")}, qc.${q("state")},
            qc.${q("currentOperationId")}, qc.${q("activeTopologyRevisionId")},
            t.${q("revisionNumber")}, t.${q("engine")}, t.${q("targetAddress")}, t.${q("targetPort")},
            t.${q("publicPort")}, t.${q("portAllocationId")}, t.${q("state")} AS ${q("topologyState")},
            t.${q("activeSlot")}
       FROM ${q("xray_quick_configs")} qc
       LEFT JOIN ${q("xray_quick_config_topology_revisions")} t
         ON t.${q("id")} = qc.${q("activeTopologyRevisionId")}
      WHERE qc.${q("id")} = ? LIMIT 1`,
    [quickConfigId],
  );
  if (!row) fail("QUICK_CONFIG_NOT_FOUND");
  const revision = positiveInteger(row.revision, "QUICK_CONFIG_REVISION_CONFLICT");
  if ((expectedRevision !== undefined && revision !== expectedRevision) || row.state !== "ACTIVE"
    || row.currentOperationId !== null && row.currentOperationId !== undefined
    || row.activeTopologyRevisionId === null || row.activeTopologyRevisionId === undefined
    || row.topologyState !== "APPLIED" || Number(row.activeSlot) !== 1) {
    fail("QUICK_CONFIG_REVISION_CONFLICT");
  }
  const topologyId = positiveInteger(row.activeTopologyRevisionId, "QUICK_CONFIG_REVISION_CONFLICT");
  const routesRows = await queryRaw<Row>(
    `SELECT ${q("id")}, ${q("lineCategory")}, ${q("providerLineId")}, ${q("sourceType")}, ${q("hostId")},
            ${q("addressFamily")}, ${q("address")}, ${q("routeMode")}, ${q("relayHopsJson")}, ${q("sortOrder")}
       FROM ${q("xray_quick_config_routes")}
      WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ? AND ${q("state")} <> 'RETIRED'
      ORDER BY ${q("sortOrder")} ASC, ${q("id")} ASC`,
    [quickConfigId, topologyId],
  );
  const routes: SwitchRoute[] = routesRows.map((route) => {
    const addressFamily = String(route.addressFamily);
    const routeMode = String(route.routeMode);
    if ((addressFamily !== "IPV4" && addressFamily !== "IPV6")
      || (routeMode !== "DIRECT" && routeMode !== "FORWARD")) fail("QUICK_CONFIG_REVISION_CONFLICT");
    const hostId = route.hostId === null || route.hostId === undefined
      ? null : positiveInteger(route.hostId, "QUICK_CONFIG_REVISION_CONFLICT");
    if (routeMode === "FORWARD" && hostId === null) fail("QUICK_CONFIG_REVISION_CONFLICT");
    return {
      id: positiveInteger(route.id, "QUICK_CONFIG_REVISION_CONFLICT"),
      lineCategory: boundedText(route.lineCategory, 32),
      providerLineId: boundedText(route.providerLineId, 128),
      sourceType: boundedText(route.sourceType, 32),
      hostId,
      addressFamily,
      address: boundedText(route.address, 512),
      relayHopsJson: serializeQuickConfigRelays(parseQuickConfigRelays(route.relayHopsJson)),
      routeMode,
      sortOrder: Number(route.sortOrder) || 0,
    };
  });
  const ruleRows = await queryRaw<Row>(
    `SELECT b.${q("id")} AS ${q("bindingId")}, b.${q("forwardRuleId")}, r.${q("hostId")},
            r.${q("sourcePort")}, r.${q("targetIp")}, r.${q("targetPort")}, r.${q("protocol")}, r.${q("gostMode")},
            r.${q("forwardType")}, r.${q("isEnabled")}, r.${q("isRunning")}, r.${q("pendingDelete")},
            r.${q("xrayQuickConfigId")}, h.${q("name")} AS ${q("hostName")}
       FROM ${q("xray_quick_config_rule_bindings")} b
       LEFT JOIN ${q("forward_rules")} r ON r.${q("id")} = b.${q("forwardRuleId")}
       LEFT JOIN ${q("hosts")} h ON h.${q("id")} = r.${q("hostId")}
      WHERE b.${q("quickConfigId")} = ? AND b.${q("topologyRevisionId")} = ? AND b.${q("state")} <> 'REMOVED'
      ORDER BY b.${q("id")} ASC`,
    [quickConfigId, topologyId],
  );
  const fromEngine = engine(row.engine);
  const rules: SwitchRule[] = ruleRows.map((rule) => {
    if (!rule.forwardRuleId || Number(rule.xrayQuickConfigId) !== quickConfigId
      || databaseBoolean(rule.pendingDelete) || engine(rule.forwardType) !== fromEngine) {
      fail("QUICK_CONFIG_REVISION_CONFLICT");
    }
    return {
      bindingId: positiveInteger(rule.bindingId, "QUICK_CONFIG_REVISION_CONFLICT"),
      ruleId: positiveInteger(rule.forwardRuleId, "QUICK_CONFIG_REVISION_CONFLICT"),
      hostId: positiveInteger(rule.hostId, "QUICK_CONFIG_REVISION_CONFLICT"),
      hostName: boundedText(rule.hostName, 256),
      forwardType: fromEngine,
      isEnabled: databaseBoolean(rule.isEnabled),
      isRunning: databaseBoolean(rule.isRunning),
    };
  });
  const segments = compileQuickConfigTopology(routes, { publicPort: port(row.publicPort), targetAddress: boundedText(row.targetAddress, 512), targetPort: port(row.targetPort) });
  const routeHosts = new Set(segments.map(segment => segment.hostId));
  const ruleHosts = new Set(rules.map((rule) => rule.hostId));
  if (rules.length !== segments.length || routeHosts.size !== ruleHosts.size || [...routeHosts].some((hostId) => !ruleHosts.has(hostId!))
    || segments.some(segment => !ruleRows.some(rule => Number(rule.hostId) === segment.hostId
      && rule.protocol === "tcp" && rule.gostMode === "direct" && Number(rule.sourcePort) === Number(row.publicPort)
      && rule.targetIp === segment.targetAddress && Number(rule.targetPort) === segment.targetPort))) {
    fail("QUICK_CONFIG_REVISION_CONFLICT");
  }
  const withoutHash: Omit<SwitchSnapshot, "snapshotHash"> = {
    quickConfigId,
    configTag: boundedText(row.configTag, 128),
    revision,
    topologyId,
    topologyRevisionNumber: positiveInteger(row.revisionNumber, "QUICK_CONFIG_REVISION_CONFLICT"),
    fromEngine,
    targetAddress: boundedText(row.targetAddress, 512),
    targetPort: port(row.targetPort),
    publicPort: port(row.publicPort),
    portAllocationId: positiveInteger(row.portAllocationId, "QUICK_CONFIG_REVISION_CONFLICT"),
    routes,
    rules,
  };
  return { ...withoutHash, snapshotHash: sha256(stableJson(snapshotProjection(withoutHash))) };
}

async function assertEngineEligible(snapshot: SwitchSnapshot, toEngine: XrayQuickConfigForwardEngine) {
  const paths = snapshot.routes.filter(route => route.routeMode === "FORWARD").map(route => [{ hostId: route.hostId!, addressFamily: route.addressFamily }, ...parseQuickConfigRelays(route.relayHopsJson)]);
  if (!quickConfigPathEngineCompatible(toEngine, paths, snapshot.targetAddress, undefined, (await listXrayQuickConfigEntryHosts()).items)) fail("QUICK_CONFIG_PATH_ADDRESS_FAMILY_UNSUPPORTED");
  if (snapshot.routes.every((route) => route.routeMode === "DIRECT")) {
    const settings = await getForwardProtocolSettings();
    if (settings[toEngine] === false) fail("FORWARD_PROTOCOL_DISABLED");
    return;
  }
  let catalog: Awaited<ReturnType<typeof listXrayQuickConfigForwardEngines>>;
  try {
    catalog = await listXrayQuickConfigForwardEngines({
      entries: [...new Map(snapshot.routes.filter((route) => route.routeMode === "FORWARD").flatMap((route) => [{
        hostId: route.hostId,
        addressFamily: route.addressFamily,
      }, ...parseQuickConfigRelays(route.relayHopsJson)]).map(hop => [`${hop.hostId}:${hop.addressFamily}`, hop])).values()],
    });
  } catch {
    fail("QUICK_CONFIG_HOST_UNAVAILABLE");
  }
  const item = catalog.items.find((candidate) => candidate.engine === toEngine);
  if (!item?.eligible) fail(item?.disabledReasonCode ?? "QUICK_CONFIG_HOST_UNAVAILABLE");
}

export async function previewXrayQuickConfigEngineSwitch(input: {
  id: unknown;
  expectedRevision: unknown;
  engine: unknown;
  userId: unknown;
}, options: SwitchOptions = {}): Promise<XrayQuickConfigEngineSwitchPreview> {
  const quickConfigId = positiveInteger(input.id);
  const expectedRevision = positiveInteger(input.expectedRevision);
  const userId = positiveInteger(input.userId);
  const toEngine = engine(input.engine);
  const snapshot = await loadSnapshot(quickConfigId, expectedRevision);
  if (snapshot.fromEngine === toEngine) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  await assertEngineEligible(snapshot, toEngine);
  const now = resolvedNow(options);
  const expiresAt = new Date(now.getTime() + TOKEN_TTL_MS);
  const payload: SwitchTokenPayload = {
    v: 1,
    kind: "ENGINE_SWITCH",
    nonce: crypto.randomBytes(16).toString("base64url"),
    userId,
    quickConfigId,
    expectedRevision,
    fromTopologyRevisionId: snapshot.topologyId,
    fromEngine: snapshot.fromEngine,
    toEngine,
    publicPort: snapshot.publicPort,
    snapshotHash: snapshot.snapshotHash,
    issuedAt: now.getTime(),
    expiresAt: expiresAt.getTime(),
  };
  const hosts = new Map<number, string>();
  for (const rule of snapshot.rules) hosts.set(rule.hostId, rule.hostName);
  return {
    quickConfigId,
    revision: snapshot.revision,
    fromEngine: snapshot.fromEngine,
    toEngine,
    publicPort: snapshot.publicPort,
    affectedHosts: [...hosts].map(([hostId, name]) => ({ hostId, name }))
      .sort((left, right) => left.hostId - right.hostId),
    warnings: [{
      code: "ENGINE_SWITCH_DOWNTIME",
      message: snapshot.rules.length
        ? "切换采用先停旧引擎、再启用新引擎的方式，入口会有短暂中断。"
        : "当前拓扑没有转发规则，切换不会中断入口转发。",
    }],
    switchToken: signToken(payload, options),
    expiresAt: expiresAt.toISOString(),
  };
}

async function insertStep(input: {
  operationId: number;
  operationTag: string;
  key: string;
  kind: "RULE_DELETE" | "RULE_VERIFY";
  ruleId: number;
  now: Date;
}) {
  await insertAndGetId("xray_quick_config_operation_steps", {
    operationId: input.operationId,
    stepKey: input.key,
    kind: input.kind,
    subjectType: "RULE",
    subjectId: String(input.ruleId),
    status: "PENDING",
    attemptCount: 0,
    idempotencyKey: `${input.operationTag}:${input.key}`,
    requestSummaryJson: "{}",
    resultSummaryJson: null,
    errorCode: null,
    startedAt: null,
    finishedAt: null,
    updatedAt: input.now,
  });
}

export async function applyXrayQuickConfigEngineSwitch(input: {
  switchToken: unknown;
  userId: unknown;
}, options: SwitchOptions = {}): Promise<{
  quickConfigId: number;
  operationId: number;
  state: "UPDATING";
}> {
  const payload = parseToken(input.switchToken, options);
  const userId = positiveInteger(input.userId);
  if (payload.userId !== userId) fail("QUICK_CONFIG_PREVIEW_INVALID");
  const snapshot = await loadSnapshot(payload.quickConfigId, payload.expectedRevision);
  if (snapshot.topologyId !== payload.fromTopologyRevisionId || snapshot.fromEngine !== payload.fromEngine
    || snapshot.publicPort !== payload.publicPort || !secureHashEqual(snapshot.snapshotHash, payload.snapshotHash)) {
    fail("QUICK_CONFIG_REVISION_CONFLICT");
  }
  await assertEngineEligible(snapshot, payload.toEngine);
  const q = quoteIdentifier;
  const now = nowDate();
  const operationTag = `quick-config-operation:${crypto.randomUUID()}`;
  const created = await withDatabaseTransaction(async () => {
    const [fresh] = await queryRaw<Row>(
      `SELECT ${q("revision")}, ${q("state")}, ${q("currentOperationId")}, ${q("activeTopologyRevisionId")}
         FROM ${q("xray_quick_configs")} WHERE ${q("id")} = ? LIMIT 1`,
      [snapshot.quickConfigId],
    );
    if (!fresh || Number(fresh.revision) !== snapshot.revision || fresh.state !== "ACTIVE"
      || fresh.currentOperationId !== null && fresh.currentOperationId !== undefined
      || Number(fresh.activeTopologyRevisionId) !== snapshot.topologyId) fail("QUICK_CONFIG_REVISION_CONFLICT");
    const [maxRevision] = await queryRaw<Row>(
      `SELECT MAX(${q("revisionNumber")}) AS ${q("maxRevision")} FROM ${q("xray_quick_config_topology_revisions")} WHERE ${q("quickConfigId")} = ?`,
      [snapshot.quickConfigId],
    );
    const revisionNumber = positiveInteger(maxRevision?.maxRevision, "QUICK_CONFIG_REVISION_CONFLICT") + 1;
    const topologyRevisionId = await insertAndGetId("xray_quick_config_topology_revisions", {
      quickConfigId: snapshot.quickConfigId,
      revisionNumber,
      engine: payload.toEngine,
      targetAddress: snapshot.targetAddress,
      targetPort: snapshot.targetPort,
      publicPort: snapshot.publicPort,
      portAllocationId: snapshot.portAllocationId,
      state: "APPLYING",
      activeSlot: null,
      createdByUserId: userId,
      createdAt: now,
      updatedAt: now,
    });
    for (const [index, route] of snapshot.routes.entries()) {
      await insertAndGetId("xray_quick_config_routes", {
        routeTag: `${snapshot.configTag}:switch:${revisionNumber}:route:${index + 1}`,
        quickConfigId: snapshot.quickConfigId,
        topologyRevisionId,
        lineCategory: route.lineCategory,
        providerLineId: route.providerLineId,
        sourceType: route.sourceType,
        hostId: route.hostId,
        addressFamily: route.addressFamily,
        address: route.address,
        relayHopsJson: route.relayHopsJson,
        routeMode: route.routeMode,
        sortOrder: route.sortOrder,
        state: "APPLYING",
        createdAt: now,
        updatedAt: now,
      });
    }
    for (const [index, rule] of snapshot.rules.entries()) {
      await insertAndGetId("xray_quick_config_rule_bindings", {
        bindingTag: `${snapshot.configTag}:switch:${revisionNumber}:rule:${index + 1}`,
        quickConfigId: snapshot.quickConfigId,
        topologyRevisionId,
        forwardRuleId: rule.ruleId,
        state: "APPLYING",
        createdAt: now,
        updatedAt: now,
      });
    }
    const operationId = await insertAndGetId("xray_quick_config_operations", {
      operationTag,
      quickConfigId: snapshot.quickConfigId,
      type: "EDIT",
      status: "QUEUED",
      phase: "RULES_REMOVING",
      activeSlot: 1,
      revision: 1,
      expectedRevision: snapshot.revision,
      fromTopologyRevisionId: snapshot.topologyId,
      toTopologyRevisionId: topologyRevisionId,
      requestSummaryJson: stableJson({ kind: "ENGINE_SWITCH", fromEngine: snapshot.fromEngine, toEngine: payload.toEngine }),
      retryOfOperationId: null,
      executionOwnerId: null,
      executionLeaseUntil: null,
      executionFence: 1,
      errorCode: null,
      errorMessage: null,
      createdByUserId: userId,
      startedAt: null,
      finishedAt: null,
      createdAt: now,
      updatedAt: now,
    });
    for (const rule of snapshot.rules) {
      await insertStep({ operationId, operationTag, key: `switch-stop-old-${rule.ruleId}`, kind: "RULE_DELETE", ruleId: rule.ruleId, now });
      await insertStep({ operationId, operationTag, key: `switch-start-new-${rule.ruleId}`, kind: "RULE_VERIFY", ruleId: rule.ruleId, now });
      await insertStep({ operationId, operationTag, key: `switch-rollback-stop-new-${rule.ruleId}`, kind: "RULE_DELETE", ruleId: rule.ruleId, now });
      await insertStep({ operationId, operationTag, key: `switch-rollback-start-old-${rule.ruleId}`, kind: "RULE_VERIFY", ruleId: rule.ruleId, now });
    }
    const changed = await executeRaw(
      `UPDATE ${q("xray_quick_configs")} SET ${q("state")} = 'UPDATING', ${q("desiredTopologyRevisionId")} = ?,
          ${q("currentOperationId")} = ?, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("revision")} = ? AND ${q("state")} = 'ACTIVE' AND ${q("currentOperationId")} IS NULL`,
      [topologyRevisionId, operationId, now, snapshot.quickConfigId, snapshot.revision],
    );
    if (rawAffectedRows(changed) !== 1) fail("QUICK_CONFIG_REVISION_CONFLICT");
    await afterDatabaseCommit(() => import("./xrayQuickConfigOperationService")
      .then(({ kickQuickConfigOperationWorker }) => kickQuickConfigOperationWorker()));
    return { operationId };
  });
  return { quickConfigId: snapshot.quickConfigId, operationId: created.operationId, state: "UPDATING" };
}

type EngineSwitchOperationSummary =
  | Readonly<{
    kind: "ENGINE_SWITCH";
    fromEngine: XrayQuickConfigForwardEngine;
    toEngine: XrayQuickConfigForwardEngine;
  }>
  | Readonly<{
    kind: "ENGINE_SWITCH_ROLLBACK_RETRY";
    fromEngine: XrayQuickConfigForwardEngine;
    toEngine: XrayQuickConfigForwardEngine;
  }>;

function operationSummary(operation: Row): EngineSwitchOperationSummary | null {
  try {
    const parsed = JSON.parse(String(operation.requestSummaryJson ?? "")) as Record<string, unknown>;
    if (operation.type === "EDIT" && parsed.kind === "ENGINE_SWITCH") {
      return { kind: "ENGINE_SWITCH", fromEngine: engine(parsed.fromEngine), toEngine: engine(parsed.toEngine) };
    }
    if (operation.type === "RETRY" && parsed.kind === "ENGINE_SWITCH_ROLLBACK_RETRY") {
      return {
        kind: "ENGINE_SWITCH_ROLLBACK_RETRY",
        fromEngine: engine(parsed.fromEngine),
        toEngine: engine(parsed.toEngine),
      };
    }
    return null;
  } catch {
    return null;
  }
}

export async function isXrayQuickConfigEngineSwitchOperation(operation: Row): Promise<boolean> {
  return operationSummary(operation) !== null;
}

async function rootEngineSwitchOperation(source: Row): Promise<{
  root: Row;
  summary: EngineSwitchOperationSummary & { kind: "ENGINE_SWITCH" };
}> {
  let current = source;
  const seen = new Set<number>();
  for (let depth = 0; depth < 32; depth += 1) {
    const id = positiveInteger(current.id, "QUICK_CONFIG_OPERATION_CONFLICT");
    if (seen.has(id)) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    seen.add(id);
    if (current.type === "EDIT") {
      const summary = operationSummary(current);
      if (!summary || summary.kind !== "ENGINE_SWITCH") fail("QUICK_CONFIG_OPERATION_CONFLICT");
      return { root: current, summary };
    }
    if (current.type !== "RETRY") fail("QUICK_CONFIG_OPERATION_CONFLICT");
    const retryOfOperationId = positiveInteger(current.retryOfOperationId, "QUICK_CONFIG_OPERATION_CONFLICT");
    const [parent] = await queryRaw<Row>(
      `SELECT * FROM ${quoteIdentifier("xray_quick_config_operations")} WHERE ${quoteIdentifier("id")} = ? LIMIT 1`,
      [retryOfOperationId],
    );
    if (!parent || Number(parent.quickConfigId) !== Number(source.quickConfigId)) {
      fail("QUICK_CONFIG_OPERATION_CONFLICT");
    }
    current = parent;
  }
  fail("QUICK_CONFIG_OPERATION_CONFLICT");
}

export async function retryXrayQuickConfigEngineSwitchRollback(input: {
  operationId: unknown;
  expectedOperationRevision: unknown;
  userId: unknown;
}): Promise<{ operationId: number; operationRevision: 1 }> {
  const sourceOperationId = positiveInteger(input.operationId, "QUICK_CONFIG_NOT_FOUND");
  const expectedOperationRevision = positiveInteger(input.expectedOperationRevision, "QUICK_CONFIG_REVISION_CONFLICT");
  const userId = positiveInteger(input.userId);
  const q = quoteIdentifier;
  const now = nowDate();
  const operationTag = `quick-config-operation:${crypto.randomUUID()}`;

  return withDatabaseTransaction(async () => {
    const [source] = await queryRaw<Row>(
      `SELECT * FROM ${q("xray_quick_config_operations")} WHERE ${q("id")} = ? LIMIT 1`,
      [sourceOperationId],
    );
    if (!source) fail("QUICK_CONFIG_NOT_FOUND");
    if (Number(source.revision) !== expectedOperationRevision) fail("QUICK_CONFIG_REVISION_CONFLICT");
    if (source.status !== "PARTIAL_FAILURE" || source.activeSlot !== null && source.activeSlot !== undefined) {
      fail("QUICK_CONFIG_OPERATION_CONFLICT");
    }
    const { root, summary } = await rootEngineSwitchOperation(source);
    const quickConfigId = positiveInteger(root.quickConfigId, "QUICK_CONFIG_NOT_FOUND");
    const fromTopologyRevisionId = positiveInteger(root.fromTopologyRevisionId, "QUICK_CONFIG_OPERATION_CONFLICT");
    const toTopologyRevisionId = positiveInteger(root.toTopologyRevisionId, "QUICK_CONFIG_OPERATION_CONFLICT");
    if (Number(source.quickConfigId) !== quickConfigId
      || Number(source.fromTopologyRevisionId) !== fromTopologyRevisionId
      || Number(source.toTopologyRevisionId) !== toTopologyRevisionId) {
      fail("QUICK_CONFIG_OPERATION_CONFLICT");
    }

    const [config] = await queryRaw<Row>(
      `SELECT ${q("revision")}, ${q("state")}, ${q("currentOperationId")},
              ${q("activeTopologyRevisionId")}, ${q("desiredTopologyRevisionId")}
         FROM ${q("xray_quick_configs")} WHERE ${q("id")} = ? LIMIT 1`,
      [quickConfigId],
    );
    if (!config) fail("QUICK_CONFIG_NOT_FOUND");
    const configRevision = positiveInteger(config.revision, "QUICK_CONFIG_REVISION_CONFLICT");
    if (config.state !== "PARTIAL_FAILURE"
      || config.currentOperationId !== null && config.currentOperationId !== undefined
      || Number(config.activeTopologyRevisionId) !== fromTopologyRevisionId
      || Number(config.desiredTopologyRevisionId) !== toTopologyRevisionId) {
      fail("QUICK_CONFIG_OPERATION_CONFLICT");
    }

    const topologies = await queryRaw<Row>(
      `SELECT ${q("id")}, ${q("engine")}, ${q("targetAddress")}, ${q("targetPort")}, ${q("publicPort")},
              ${q("portAllocationId")}, ${q("state")}, ${q("activeSlot")}
         FROM ${q("xray_quick_config_topology_revisions")}
        WHERE ${q("quickConfigId")} = ? AND ${q("id")} IN (?, ?) ORDER BY ${q("id")} ASC`,
      [quickConfigId, fromTopologyRevisionId, toTopologyRevisionId],
    );
    const fromTopology = topologies.find((row) => Number(row.id) === fromTopologyRevisionId);
    const toTopology = topologies.find((row) => Number(row.id) === toTopologyRevisionId);
    if (!fromTopology || !toTopology || engine(fromTopology.engine) !== summary.fromEngine
      || engine(toTopology.engine) !== summary.toEngine || fromTopology.state !== "APPLIED"
      || Number(fromTopology.activeSlot) !== 1 || toTopology.state !== "ROLLBACK_PENDING"
      || toTopology.activeSlot !== null && toTopology.activeSlot !== undefined
      || fromTopology.targetAddress !== toTopology.targetAddress
      || Number(fromTopology.targetPort) !== Number(toTopology.targetPort)
      || Number(fromTopology.publicPort) !== Number(toTopology.publicPort)
      || Number(fromTopology.portAllocationId) !== Number(toTopology.portAllocationId)) {
      fail("QUICK_CONFIG_OPERATION_CONFLICT");
    }

    const ruleRows = await queryRaw<Row>(
      `SELECT b.${q("forwardRuleId")}, b.${q("state")} AS ${q("bindingState")}, r.${q("hostId")},
              r.${q("forwardType")}, r.${q("pendingDelete")}, r.${q("xrayQuickConfigId")}
         FROM ${q("xray_quick_config_rule_bindings")} b
         LEFT JOIN ${q("forward_rules")} r ON r.${q("id")} = b.${q("forwardRuleId")}
        WHERE b.${q("quickConfigId")} = ? AND b.${q("topologyRevisionId")} = ?
          AND b.${q("state")} <> 'REMOVED' ORDER BY b.${q("id")} ASC`,
      [quickConfigId, toTopologyRevisionId],
    );
    const ruleIds = new Set<number>();
    for (const row of ruleRows) {
      const ruleId = positiveInteger(row.forwardRuleId, "RULE_CLEANUP_FAILED");
      const currentEngine = engine(row.forwardType);
      if (ruleIds.has(ruleId) || row.bindingState !== "FAILED" || Number(row.xrayQuickConfigId) !== quickConfigId
        || databaseBoolean(row.pendingDelete)
        || currentEngine !== summary.fromEngine && currentEngine !== summary.toEngine) {
        fail("RULE_CLEANUP_FAILED");
      }
      positiveInteger(row.hostId, "RULE_CLEANUP_FAILED");
      ruleIds.add(ruleId);
    }
    const oldBindingRows = await queryRaw<Row>(
      `SELECT ${q("forwardRuleId")}, ${q("state")} FROM ${q("xray_quick_config_rule_bindings")}
        WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ? AND ${q("state")} <> 'REMOVED'`,
      [quickConfigId, fromTopologyRevisionId],
    );
    if (oldBindingRows.some((row) => row.state !== "READY")) fail("RULE_CLEANUP_FAILED");
    const oldRuleIds = new Set(oldBindingRows.map((row) => positiveInteger(row.forwardRuleId, "RULE_CLEANUP_FAILED")));
    if (oldRuleIds.size !== ruleIds.size || [...oldRuleIds].some((ruleId) => !ruleIds.has(ruleId))) {
      fail("RULE_CLEANUP_FAILED");
    }

    const operationId = await insertAndGetId("xray_quick_config_operations", {
      operationTag,
      quickConfigId,
      type: "RETRY",
      status: "QUEUED",
      phase: "REMOVING_NEW_RULES",
      activeSlot: 1,
      revision: 1,
      expectedRevision: configRevision,
      fromTopologyRevisionId,
      toTopologyRevisionId,
      requestSummaryJson: stableJson({
        kind: "ENGINE_SWITCH_ROLLBACK_RETRY",
        fromEngine: summary.fromEngine,
        toEngine: summary.toEngine,
        rootOperationId: positiveInteger(root.id, "QUICK_CONFIG_OPERATION_CONFLICT"),
      }),
      retryOfOperationId: sourceOperationId,
      executionOwnerId: null,
      executionLeaseUntil: null,
      executionFence: 1,
      errorCode: null,
      errorMessage: null,
      createdByUserId: userId,
      startedAt: null,
      finishedAt: null,
      createdAt: now,
      updatedAt: now,
    });
    for (const ruleId of ruleIds) {
      await insertStep({
        operationId,
        operationTag,
        key: `switch-rollback-stop-new-${ruleId}`,
        kind: "RULE_DELETE",
        ruleId,
        now,
      });
      await insertStep({
        operationId,
        operationTag,
        key: `switch-rollback-start-old-${ruleId}`,
        kind: "RULE_VERIFY",
        ruleId,
        now,
      });
    }
    const configChanged = await executeRaw(
      `UPDATE ${q("xray_quick_configs")} SET ${q("state")} = 'COMPENSATING',
          ${q("currentOperationId")} = ?, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("revision")} = ? AND ${q("state")} = 'PARTIAL_FAILURE'
          AND ${q("currentOperationId")} IS NULL AND ${q("activeTopologyRevisionId")} = ?
          AND ${q("desiredTopologyRevisionId")} = ?`,
      [operationId, now, quickConfigId, configRevision, fromTopologyRevisionId, toTopologyRevisionId],
    );
    if (rawAffectedRows(configChanged) !== 1) fail("QUICK_CONFIG_REVISION_CONFLICT");
    await afterDatabaseCommit(() => import("./xrayQuickConfigOperationService")
      .then(({ kickQuickConfigOperationWorker }) => kickQuickConfigOperationWorker()));
    return { operationId, operationRevision: 1 as const };
  });
}

type OperationFence = Readonly<{
  operationId: number;
  quickConfigId: number;
  owner: string;
  fence: number;
}>;

function operationFence(operation: Row): OperationFence {
  return {
    operationId: positiveInteger(operation.id, "QUICK_CONFIG_OPERATION_CONFLICT"),
    quickConfigId: positiveInteger(operation.quickConfigId, "QUICK_CONFIG_OPERATION_CONFLICT"),
    owner: boundedText(operation.executionOwnerId, 128),
    fence: positiveInteger(operation.executionFence, "QUICK_CONFIG_OPERATION_CONFLICT"),
  };
}

async function assertFence(fence: OperationFence) {
  const q = quoteIdentifier;
  const [row] = await queryRaw<Row>(
    `SELECT o.${q("status")}, o.${q("executionLeaseUntil")}, qc.${q("currentOperationId")}
       FROM ${q("xray_quick_config_operations")} o
       JOIN ${q("xray_quick_configs")} qc ON qc.${q("id")} = o.${q("quickConfigId")}
      WHERE o.${q("id")} = ? AND o.${q("quickConfigId")} = ? AND o.${q("executionOwnerId")} = ?
        AND o.${q("executionFence")} = ? LIMIT 1`,
    [fence.operationId, fence.quickConfigId, fence.owner, fence.fence],
  );
  const lease = databaseDate(row?.executionLeaseUntil);
  if (!row || !["RUNNING", "COMPENSATING"].includes(String(row.status))
    || Number(row.currentOperationId) !== fence.operationId || !lease
    || lease.getTime() <= Date.now()) fail("QUICK_CONFIG_OPERATION_CONFLICT");
}

function fenceExistsSql(fence: OperationFence, now = nowDate()) {
  const q = quoteIdentifier;
  return {
    sql: `EXISTS (
      SELECT 1 FROM ${q("xray_quick_config_operations")} owned
      JOIN ${q("xray_quick_configs")} owned_qc ON owned_qc.${q("id")} = owned.${q("quickConfigId")}
      WHERE owned.${q("id")} = ? AND owned.${q("quickConfigId")} = ?
        AND owned.${q("executionOwnerId")} = ? AND owned.${q("executionFence")} = ?
        AND owned.${q("executionLeaseUntil")} > ? AND owned.${q("status")} IN ('RUNNING', 'COMPENSATING')
        AND owned_qc.${q("currentOperationId")} = owned.${q("id")}
    )`,
    params: [fence.operationId, fence.quickConfigId, fence.owner, fence.fence, now],
  };
}

async function loadOperationRules(fence: OperationFence, summary: NonNullable<ReturnType<typeof operationSummary>>) {
  const q = quoteIdentifier;
  const rows = await queryRaw<Row>(
    `SELECT b.${q("forwardRuleId")}, r.${q("hostId")}, r.${q("forwardType")}, r.${q("isEnabled")},
            r.${q("isRunning")}, r.${q("pendingDelete")}, r.${q("xrayQuickConfigId")}
       FROM ${q("xray_quick_config_rule_bindings")} b
       LEFT JOIN ${q("forward_rules")} r ON r.${q("id")} = b.${q("forwardRuleId")}
      WHERE b.${q("quickConfigId")} = ? AND b.${q("topologyRevisionId")} = ? AND b.${q("state")} <> 'REMOVED'
      ORDER BY b.${q("id")} ASC`,
    [fence.quickConfigId, positiveInteger((await queryRaw<Row>(
      `SELECT ${q("toTopologyRevisionId")} FROM ${q("xray_quick_config_operations")} WHERE ${q("id")} = ? LIMIT 1`,
      [fence.operationId],
    ))[0]?.toTopologyRevisionId, "QUICK_CONFIG_OPERATION_CONFLICT")],
  );
  return rows.map((row) => {
    if (!row.forwardRuleId || Number(row.xrayQuickConfigId) !== fence.quickConfigId || databaseBoolean(row.pendingDelete)) {
      fail("RULE_CLEANUP_FAILED");
    }
    const currentEngine = engine(row.forwardType);
    if (currentEngine !== summary.fromEngine && currentEngine !== summary.toEngine) fail("RULE_CLEANUP_FAILED");
    return {
      ruleId: positiveInteger(row.forwardRuleId, "RULE_CLEANUP_FAILED"),
      hostId: positiveInteger(row.hostId, "RULE_CLEANUP_FAILED"),
      engine: currentEngine,
      isEnabled: databaseBoolean(row.isEnabled),
      isRunning: databaseBoolean(row.isRunning),
    };
  });
}

type SwitchRuleRuntime = Readonly<{
  ruleId: number;
  hostId: number;
  engine: XrayQuickConfigForwardEngine;
  isEnabled: boolean;
  isRunning: boolean;
}>;

type StepExpectation = Readonly<{
  expectedEngine: XrayQuickConfigForwardEngine;
  expectedRunning: boolean;
  minIssuedAt: number;
}>;

function parseStepExpectation(value: unknown): StepExpectation | null {
  try {
    const parsed = JSON.parse(String(value ?? "")) as Record<string, unknown>;
    const expectedEngine = engine(parsed.expectedEngine);
    if (typeof parsed.expectedRunning !== "boolean" || !Number.isSafeInteger(parsed.minIssuedAt)
      || Number(parsed.minIssuedAt) <= 0) return null;
    return { expectedEngine, expectedRunning: parsed.expectedRunning, minIssuedAt: Number(parsed.minIssuedAt) };
  } catch {
    return null;
  }
}

async function beginExpectedSteps(
  fence: OperationFence,
  keyPrefix: string,
  rules: readonly SwitchRuleRuntime[],
  expectedEngine: XrayQuickConfigForwardEngine | ((rule: SwitchRuleRuntime) => XrayQuickConfigForwardEngine),
  expectedRunning: boolean,
) {
  const q = quoteIdentifier;
  const issuedAt = Date.now();
  for (const rule of rules) {
    const stepKey = `${keyPrefix}${rule.ruleId}`;
    const [step] = await queryRaw<Row>(
      `SELECT ${q("id")}, ${q("status")}, ${q("requestSummaryJson")} FROM ${q("xray_quick_config_operation_steps")}
        WHERE ${q("operationId")} = ? AND ${q("stepKey")} = ? AND ${q("subjectType")} = 'RULE'
          AND ${q("subjectId")} = ? LIMIT 1`,
      [fence.operationId, stepKey, String(rule.ruleId)],
    );
    if (!step || !["PENDING", "RUNNING", "SUCCESS"].includes(String(step.status))) {
      fail("QUICK_CONFIG_OPERATION_CONFLICT");
    }
    const selectedEngine = typeof expectedEngine === "function" ? expectedEngine(rule) : expectedEngine;
    if (step.status === "PENDING") {
      const now = nowDate();
      const owned = fenceExistsSql(fence, now);
      const changed = await executeRaw(
        `UPDATE ${q("xray_quick_config_operation_steps")} SET ${q("status")} = 'RUNNING',
            ${q("attemptCount")} = ${q("attemptCount")} + 1, ${q("requestSummaryJson")} = ?,
            ${q("resultSummaryJson")} = NULL, ${q("errorCode")} = NULL,
            ${q("startedAt")} = COALESCE(${q("startedAt")}, ?), ${q("finishedAt")} = NULL, ${q("updatedAt")} = ?
          WHERE ${q("id")} = ? AND ${q("operationId")} = ? AND ${q("status")} = 'PENDING' AND ${owned.sql}`,
        [stableJson({ expectedEngine: selectedEngine, expectedRunning, minIssuedAt: issuedAt }), now, now,
          positiveInteger(step.id, "QUICK_CONFIG_OPERATION_CONFLICT"), fence.operationId, ...owned.params],
      );
      if (rawAffectedRows(changed) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
      continue;
    }
    const expectation = parseStepExpectation(step.requestSummaryJson);
    if (!expectation || expectation.expectedEngine !== selectedEngine
      || expectation.expectedRunning !== expectedRunning) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  }
}

async function failExpectedSteps(
  fence: OperationFence,
  keyPrefix: string,
  errorCode: "RULE_APPLY_FAILED" | "RULE_CLEANUP_FAILED",
) {
  const q = quoteIdentifier;
  const candidates = await queryRaw<Row>(
    `SELECT ${q("id")} FROM ${q("xray_quick_config_operation_steps")}
      WHERE ${q("operationId")} = ? AND ${q("stepKey")} LIKE ? AND ${q("status")} IN ('PENDING', 'RUNNING')`,
    [fence.operationId, `${keyPrefix}%`],
  );
  if (candidates.length === 0) return;
  const now = nowDate();
  const owned = fenceExistsSql(fence, now);
  const changed = await executeRaw(
    `UPDATE ${q("xray_quick_config_operation_steps")} SET ${q("status")} = 'FAILED',
        ${q("errorCode")} = ?, ${q("finishedAt")} = ?, ${q("updatedAt")} = ?
      WHERE ${q("operationId")} = ? AND ${q("stepKey")} LIKE ? AND ${q("status")} IN ('PENDING', 'RUNNING')
        AND ${owned.sql}`,
    [errorCode, now, now, fence.operationId, `${keyPrefix}%`, ...owned.params],
  );
  if (rawAffectedRows(changed) !== candidates.length) fail("QUICK_CONFIG_OPERATION_CONFLICT");
}

async function allExpectedStepsAcknowledged(
  fence: OperationFence,
  keyPrefix: string,
  rules: readonly SwitchRuleRuntime[],
) {
  await assertFence(fence);
  if (rules.length === 0) return true;
  const q = quoteIdentifier;
  const ids = inList(rules.map((rule) => String(rule.ruleId)));
  const rows = await queryRaw<Row>(
    `SELECT ${q("subjectId")}, ${q("status")} FROM ${q("xray_quick_config_operation_steps")}
      WHERE ${q("operationId")} = ? AND ${q("stepKey")} LIKE ? AND ${q("subjectId")} IN ${ids.sql}`,
    [fence.operationId, `${keyPrefix}%`, ...ids.params],
  );
  await assertFence(fence);
  return rows.length === rules.length && rows.every((row) => row.status === "SUCCESS");
}

const ACK_STEP_PREFIX_BY_PHASE = {
  RULES_REMOVING: "switch-stop-old-",
  CREATING_RULES: "switch-start-new-",
  WAITING_RULES_READY: "switch-start-new-",
  REMOVING_NEW_RULES: "switch-rollback-stop-new-",
  RESTORING_DNS: "switch-rollback-start-old-",
} as const;

export async function recordXrayQuickConfigEngineSwitchRuleAck(input: {
  quickConfigId: unknown;
  ruleId: unknown;
  hostId: unknown;
  forwardType: unknown;
  isRunning: unknown;
  issuedAt: unknown;
}): Promise<boolean> {
  const quickConfigId = Number(input.quickConfigId);
  const ruleId = Number(input.ruleId);
  const hostId = Number(input.hostId);
  const issuedAt = Number(input.issuedAt);
  const reportedEngine = String(input.forwardType ?? "").trim().toLowerCase();
  if (!Number.isSafeInteger(quickConfigId) || quickConfigId <= 0 || !Number.isSafeInteger(ruleId) || ruleId <= 0
    || !Number.isSafeInteger(hostId) || hostId <= 0 || !Number.isSafeInteger(issuedAt) || issuedAt <= 0
    || !(XRAY_QUICK_CONFIG_FORWARD_ENGINES as readonly string[]).includes(reportedEngine)) return false;
  const q = quoteIdentifier;
  const rows = await queryRaw<Row>(
    `SELECT s.${q("id")} AS ${q("stepId")}, s.${q("stepKey")}, s.${q("status")} AS ${q("stepStatus")},
            s.${q("requestSummaryJson")}, o.${q("id")} AS ${q("operationId")}, o.${q("phase")}
       FROM ${q("xray_quick_configs")} qc
       JOIN ${q("xray_quick_config_operations")} o ON o.${q("id")} = qc.${q("currentOperationId")}
       JOIN ${q("xray_quick_config_operation_steps")} s ON s.${q("operationId")} = o.${q("id")}
       JOIN ${q("forward_rules")} r ON r.${q("id")} = ? AND r.${q("xrayQuickConfigId")} = qc.${q("id")}
      WHERE qc.${q("id")} = ? AND r.${q("hostId")} = ? AND r.${q("forwardType")} = ?
        AND o.${q("type")} IN ('EDIT', 'RETRY') AND o.${q("status")} IN ('RUNNING', 'COMPENSATING')
        AND o.${q("activeSlot")} = 1 AND s.${q("subjectType")} = 'RULE' AND s.${q("subjectId")} = ?
        AND s.${q("status")} = 'RUNNING' ORDER BY s.${q("id")} ASC`,
    [ruleId, quickConfigId, hostId, reportedEngine, String(ruleId)],
  );
  const step = rows.find((candidate) => {
    const prefix = ACK_STEP_PREFIX_BY_PHASE[String(candidate.phase) as keyof typeof ACK_STEP_PREFIX_BY_PHASE];
    return !!prefix && String(candidate.stepKey) === `${prefix}${ruleId}`;
  });
  const expectation = step ? parseStepExpectation(step.requestSummaryJson) : null;
  if (!step || !expectation || expectation.expectedEngine !== reportedEngine
    || expectation.expectedRunning !== (input.isRunning === true) || issuedAt < expectation.minIssuedAt) return false;
  const prefix = ACK_STEP_PREFIX_BY_PHASE[String(step.phase) as keyof typeof ACK_STEP_PREFIX_BY_PHASE];
  const now = nowDate();
  const changed = await executeRaw(
    `UPDATE ${q("xray_quick_config_operation_steps")} SET ${q("status")} = 'SUCCESS',
        ${q("resultSummaryJson")} = ?, ${q("errorCode")} = NULL, ${q("finishedAt")} = ?, ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("operationId")} = ? AND ${q("stepKey")} = ? AND ${q("status")} = 'RUNNING'
        AND EXISTS (SELECT 1 FROM ${q("xray_quick_configs")} qc
          JOIN ${q("xray_quick_config_operations")} o ON o.${q("id")} = qc.${q("currentOperationId")}
          JOIN ${q("forward_rules")} r ON r.${q("id")} = ? AND r.${q("xrayQuickConfigId")} = qc.${q("id")}
          WHERE qc.${q("id")} = ? AND o.${q("id")} = ? AND o.${q("phase")} = ?
            AND o.${q("status")} IN ('RUNNING', 'COMPENSATING') AND o.${q("activeSlot")} = 1
            AND r.${q("hostId")} = ? AND r.${q("forwardType")} = ?)`,
    [stableJson({ acknowledged: true }), now, now, positiveInteger(step.stepId, "QUICK_CONFIG_OPERATION_CONFLICT"),
      positiveInteger(step.operationId, "QUICK_CONFIG_OPERATION_CONFLICT"), `${prefix}${ruleId}`, ruleId,
      quickConfigId, positiveInteger(step.operationId, "QUICK_CONFIG_OPERATION_CONFLICT"), String(step.phase), hostId, reportedEngine],
  );
  return rawAffectedRows(changed) === 1;
}

async function phaseTimedOut(operationId: number, keyPrefix: string) {
  const q = quoteIdentifier;
  const [row] = await queryRaw<Row>(
    `SELECT MIN(${q("startedAt")}) AS ${q("startedAt")} FROM ${q("xray_quick_config_operation_steps")}
      WHERE ${q("operationId")} = ? AND ${q("stepKey")} LIKE ?`,
    [operationId, `${keyPrefix}%`],
  );
  if (!row?.startedAt) return false;
  const startedAt = databaseDate(row.startedAt);
  return startedAt !== null && Date.now() - startedAt.getTime() >= PHASE_TIMEOUT_MS;
}

async function setOperationPhase(fence: OperationFence, phase: string, status?: "RUNNING" | "COMPENSATING", errorCode?: string | null) {
  const q = quoteIdentifier;
  const now = nowDate();
  const changed = await executeRaw(
    `UPDATE ${q("xray_quick_config_operations")} SET ${q("phase")} = ?,
        ${q("status")} = COALESCE(?, ${q("status")}), ${q("errorCode")} = COALESCE(?, ${q("errorCode")}),
        ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("executionOwnerId")} = ?
        AND ${q("executionFence")} = ? AND ${q("executionLeaseUntil")} > ?
        AND ${q("status")} IN ('RUNNING', 'COMPENSATING')
        AND EXISTS (SELECT 1 FROM ${q("xray_quick_configs")} qc
          WHERE qc.${q("id")} = ? AND qc.${q("currentOperationId")} = ?)`,
    [phase, status ?? null, errorCode ?? null, now, fence.operationId, fence.quickConfigId,
      fence.owner, fence.fence, now, fence.quickConfigId, fence.operationId],
  );
  if (rawAffectedRows(changed) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
}

function refreshRules(rules: readonly { hostId: number }[], reason: string) {
  for (const hostId of new Set(rules.map((rule) => rule.hostId))) {
    pushAgentRefresh(hostId, reason, { urgent: true });
  }
}

async function updateRuleDesiredState(
  fence: OperationFence,
  rules: readonly { ruleId: number }[],
  values: { enabled: boolean; engine?: XrayQuickConfigForwardEngine },
) {
  if (rules.length === 0) return;
  const q = quoteIdentifier;
  const ids = inList(rules.map((rule) => rule.ruleId));
  const engineSet = values.engine ? `, ${q("forwardType")} = ?` : "";
  const desiredEnabled = boolValue(values.enabled);
  const now = nowDate();
  const owned = fenceExistsSql(fence, now);
  const existing = await queryRaw<Row>(
    `SELECT ${q("id")}, ${q("isEnabled")}, ${q("forwardType")} FROM ${q("forward_rules")}
      WHERE ${q("id")} IN ${ids.sql} AND ${q("xrayQuickConfigId")} = ? AND ${q("pendingDelete")} = ?
        AND ${owned.sql}`,
    [...ids.params, fence.quickConfigId, boolValue(false), ...owned.params],
  );
  if (existing.length !== rules.length) fail("RULE_CLEANUP_FAILED");
  const needsChange = existing.filter((row) => databaseBoolean(row.isEnabled) !== values.enabled
    || values.engine !== undefined && String(row.forwardType) !== values.engine);
  if (needsChange.length === 0) return;
  const changedIds = inList(needsChange.map((row) => positiveInteger(row.id, "RULE_CLEANUP_FAILED")));
  const params: unknown[] = [desiredEnabled];
  if (values.engine) params.push(values.engine);
  params.push(now, ...changedIds.params, fence.quickConfigId, boolValue(false), ...owned.params);
  const changed = await executeRaw(
    `UPDATE ${q("forward_rules")} SET ${q("isEnabled")} = ?${engineSet}, ${q("updatedAt")} = ?
      WHERE ${q("id")} IN ${changedIds.sql} AND ${q("xrayQuickConfigId")} = ? AND ${q("pendingDelete")} = ?
        AND ${owned.sql}`,
    params,
  );
  if (rawAffectedRows(changed) !== needsChange.length) fail("RULE_CLEANUP_FAILED");
  for (const row of needsChange) {
    await assignQuickConfigRulePortResource(positiveInteger(row.id, "RULE_CLEANUP_FAILED"));
  }
}

async function finishSwitch(
  fence: OperationFence,
  status: "SUCCESS" | "FAILED" | "PARTIAL_FAILURE",
  errorCode: string | null,
  resolution: "SWITCHED" | "RESTORED" = "SWITCHED",
) {
  const q = quoteIdentifier;
  const now = nowDate();
  await withDatabaseTransaction(async () => {
    await assertFence(fence);
    const [operation] = await queryRaw<Row>(
      `SELECT ${q("fromTopologyRevisionId")}, ${q("toTopologyRevisionId")} FROM ${q("xray_quick_config_operations")} WHERE ${q("id")} = ? LIMIT 1`,
      [fence.operationId],
    );
    const fromId = positiveInteger(operation?.fromTopologyRevisionId, "QUICK_CONFIG_OPERATION_CONFLICT");
    const toId = positiveInteger(operation?.toTopologyRevisionId, "QUICK_CONFIG_OPERATION_CONFLICT");
    const switched = status === "SUCCESS" && resolution === "SWITCHED";
    const restored = status === "FAILED" || status === "SUCCESS" && resolution === "RESTORED";
    if (switched) {
      await executeRaw(`UPDATE ${q("xray_quick_config_topology_revisions")} SET ${q("state")} = 'RETIRED', ${q("activeSlot")} = NULL, ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ?`, [now, fromId, fence.quickConfigId]);
      await executeRaw(`UPDATE ${q("xray_quick_config_routes")} SET ${q("state")} = 'RETIRED', ${q("updatedAt")} = ? WHERE ${q("topologyRevisionId")} = ? AND ${q("quickConfigId")} = ?`, [now, fromId, fence.quickConfigId]);
      await executeRaw(`UPDATE ${q("xray_quick_config_rule_bindings")} SET ${q("state")} = 'REMOVED', ${q("updatedAt")} = ? WHERE ${q("topologyRevisionId")} = ? AND ${q("quickConfigId")} = ?`, [now, fromId, fence.quickConfigId]);
      await executeRaw(`UPDATE ${q("xray_quick_config_topology_revisions")} SET ${q("state")} = 'APPLIED', ${q("activeSlot")} = 1, ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ?`, [now, toId, fence.quickConfigId]);
      await executeRaw(`UPDATE ${q("xray_quick_config_routes")} SET ${q("state")} = 'APPLIED', ${q("updatedAt")} = ? WHERE ${q("topologyRevisionId")} = ? AND ${q("quickConfigId")} = ?`, [now, toId, fence.quickConfigId]);
      await executeRaw(`UPDATE ${q("xray_quick_config_rule_bindings")} SET ${q("state")} = 'READY', ${q("updatedAt")} = ? WHERE ${q("topologyRevisionId")} = ? AND ${q("quickConfigId")} = ?`, [now, toId, fence.quickConfigId]);
    } else if (restored) {
      await executeRaw(`UPDATE ${q("xray_quick_config_topology_revisions")} SET ${q("state")} = 'ABANDONED', ${q("activeSlot")} = NULL, ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ?`, [now, toId, fence.quickConfigId]);
      await executeRaw(`UPDATE ${q("xray_quick_config_routes")} SET ${q("state")} = 'RETIRED', ${q("updatedAt")} = ? WHERE ${q("topologyRevisionId")} = ? AND ${q("quickConfigId")} = ?`, [now, toId, fence.quickConfigId]);
      await executeRaw(`UPDATE ${q("xray_quick_config_rule_bindings")} SET ${q("state")} = 'REMOVED', ${q("updatedAt")} = ? WHERE ${q("topologyRevisionId")} = ? AND ${q("quickConfigId")} = ?`, [now, toId, fence.quickConfigId]);
    } else {
      await executeRaw(`UPDATE ${q("xray_quick_config_topology_revisions")} SET ${q("state")} = 'ROLLBACK_PENDING', ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ?`, [now, toId, fence.quickConfigId]);
      await executeRaw(`UPDATE ${q("xray_quick_config_rule_bindings")} SET ${q("state")} = 'FAILED', ${q("updatedAt")} = ? WHERE ${q("topologyRevisionId")} = ? AND ${q("quickConfigId")} = ?`, [now, toId, fence.quickConfigId]);
    }
    const configChanged = switched
      ? await executeRaw(
        `UPDATE ${q("xray_quick_configs")} SET ${q("state")} = 'ACTIVE', ${q("activeTopologyRevisionId")} = ?,
            ${q("desiredTopologyRevisionId")} = NULL, ${q("currentOperationId")} = NULL,
            ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ?
          WHERE ${q("id")} = ? AND ${q("currentOperationId")} = ?`,
        [toId, now, fence.quickConfigId, fence.operationId],
      )
      : restored
        ? await executeRaw(
          `UPDATE ${q("xray_quick_configs")} SET ${q("state")} = 'ACTIVE', ${q("activeTopologyRevisionId")} = ?,
              ${q("desiredTopologyRevisionId")} = NULL, ${q("currentOperationId")} = NULL,
              ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ?
            WHERE ${q("id")} = ? AND ${q("currentOperationId")} = ?`,
          [fromId, now, fence.quickConfigId, fence.operationId],
        )
        : await executeRaw(
          `UPDATE ${q("xray_quick_configs")} SET ${q("state")} = 'PARTIAL_FAILURE', ${q("currentOperationId")} = NULL,
              ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ?
            WHERE ${q("id")} = ? AND ${q("currentOperationId")} = ?`,
          [now, fence.quickConfigId, fence.operationId],
        );
    if (rawAffectedRows(configChanged) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    const operationChanged = await executeRaw(
      `UPDATE ${q("xray_quick_config_operations")} SET ${q("status")} = ?, ${q("phase")} = 'COMPLETED',
          ${q("activeSlot")} = NULL, ${q("revision")} = ${q("revision")} + 1, ${q("errorCode")} = ?,
          ${q("errorMessage")} = NULL, ${q("executionOwnerId")} = NULL, ${q("executionLeaseUntil")} = NULL,
          ${q("finishedAt")} = ?, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("executionOwnerId")} = ? AND ${q("executionFence")} = ?`,
      [status, errorCode, now, now, fence.operationId, fence.owner, fence.fence],
    );
    if (rawAffectedRows(operationChanged) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  });
}

async function beginCompensation(
  fence: OperationFence,
  rules: readonly SwitchRuleRuntime[],
  errorCode: "RULE_APPLY_FAILED" | "RULE_CLEANUP_FAILED",
) {
  await failExpectedSteps(fence, "switch-start-new-", errorCode);
  await beginExpectedSteps(fence, "switch-rollback-stop-new-", rules, (rule) => rule.engine, false);
  await updateRuleDesiredState(fence, rules, { enabled: false });
  await setOperationPhase(fence, "REMOVING_NEW_RULES", "COMPENSATING", errorCode);
  refreshRules(rules, "xray-quick-config-engine-switch-rollback-stop");
}

async function processSwitch(operation: Row) {
  const fence = operationFence(operation);
  const summary = operationSummary(operation);
  if (!summary) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  await assertFence(fence);
  const rules = await loadOperationRules(fence, summary);
  const phase = String(operation.phase);
  const rollbackRetry = summary.kind === "ENGINE_SWITCH_ROLLBACK_RETRY";
  if (rules.length === 0) {
    await finishSwitch(fence, "SUCCESS", null, rollbackRetry ? "RESTORED" : "SWITCHED");
    return;
  }
  if (rollbackRetry && phase !== "REMOVING_NEW_RULES" && phase !== "RESTORING_DNS") {
    fail("QUICK_CONFIG_OPERATION_CONFLICT");
  }
  if (phase === "RULES_REMOVING") {
    await beginExpectedSteps(fence, "switch-stop-old-", rules, summary.fromEngine, false);
    await updateRuleDesiredState(fence, rules, { enabled: false });
    refreshRules(rules, "xray-quick-config-engine-switch-stop-old");
    if (!await allExpectedStepsAcknowledged(fence, "switch-stop-old-", rules)) {
      if (await phaseTimedOut(fence.operationId, "switch-stop-old-")) {
        await failExpectedSteps(fence, "switch-stop-old-", "RULE_CLEANUP_FAILED");
        await beginCompensation(fence, rules, "RULE_CLEANUP_FAILED");
      }
      return;
    }
    await beginExpectedSteps(fence, "switch-start-new-", rules, summary.toEngine, true);
    await updateRuleDesiredState(fence, rules, { enabled: true, engine: summary.toEngine });
    await setOperationPhase(fence, "WAITING_RULES_READY", "RUNNING");
    refreshRules(rules, "xray-quick-config-engine-switch-start-new");
    return;
  }
  if (phase === "CREATING_RULES" || phase === "WAITING_RULES_READY") {
    if (await allExpectedStepsAcknowledged(fence, "switch-start-new-", rules)) {
      await finishSwitch(fence, "SUCCESS", null);
      return;
    }
    if (await phaseTimedOut(fence.operationId, "switch-start-new-")) {
      await beginCompensation(fence, rules, "RULE_APPLY_FAILED");
    }
    return;
  }
  if (phase === "REMOVING_NEW_RULES") {
    await beginExpectedSteps(fence, "switch-rollback-stop-new-", rules, (rule) => rule.engine, false);
    await updateRuleDesiredState(fence, rules, { enabled: false });
    refreshRules(rules, "xray-quick-config-engine-switch-rollback-stop");
    if (!await allExpectedStepsAcknowledged(fence, "switch-rollback-stop-new-", rules)) {
      if (await phaseTimedOut(fence.operationId, "switch-rollback-stop-new-")) {
        await failExpectedSteps(fence, "switch-rollback-stop-new-", "RULE_CLEANUP_FAILED");
        await finishSwitch(fence, "PARTIAL_FAILURE", "RULE_CLEANUP_FAILED");
      }
      return;
    }
    await beginExpectedSteps(fence, "switch-rollback-start-old-", rules, summary.fromEngine, true);
    await updateRuleDesiredState(fence, rules, { enabled: true, engine: summary.fromEngine });
    await setOperationPhase(fence, "RESTORING_DNS", "COMPENSATING");
    refreshRules(rules, "xray-quick-config-engine-switch-restore-old");
    return;
  }
  if (phase === "RESTORING_DNS") {
    if (await allExpectedStepsAcknowledged(fence, "switch-rollback-start-old-", rules)) {
      if (rollbackRetry) await finishSwitch(fence, "SUCCESS", null, "RESTORED");
      else await finishSwitch(fence, "FAILED", String(operation.errorCode || "RULE_APPLY_FAILED"));
      return;
    }
    if (await phaseTimedOut(fence.operationId, "switch-rollback-start-old-")) {
      await failExpectedSteps(fence, "switch-rollback-start-old-", "RULE_CLEANUP_FAILED");
      await finishSwitch(fence, "PARTIAL_FAILURE", "RULE_CLEANUP_FAILED");
    }
    return;
  }
  fail("QUICK_CONFIG_OPERATION_CONFLICT");
}

export async function processXrayQuickConfigEngineSwitchOperation(operation: Row): Promise<void> {
  const operationId = positiveInteger(operation.id, "QUICK_CONFIG_OPERATION_CONFLICT");
  await withKeyedTaskLock(`xray-quick-config-engine-switch:${operationId}`, async () => {
    try {
      await processSwitch(operation);
    } catch (error) {
      const fence = operationFence(operation);
      const summary = operationSummary(operation);
      if (!summary) return;
      const code = error instanceof XrayQuickConfigEngineSwitchError ? error.code : "RULE_CLEANUP_FAILED";
      if (String(operation.status) === "COMPENSATING"
        || String(operation.phase) === "REMOVING_NEW_RULES" || String(operation.phase) === "RESTORING_DNS") {
        await finishSwitch(fence, "PARTIAL_FAILURE", code).catch(() => undefined);
        return;
      }
      const rules = await loadOperationRules(fence, summary).catch(() => []);
      if (rules.length === 0) {
        await finishSwitch(fence, "PARTIAL_FAILURE", code).catch(() => undefined);
        return;
      }
      await beginCompensation(fence, rules, code === "RULE_APPLY_FAILED" ? code : "RULE_CLEANUP_FAILED")
        .catch(() => finishSwitch(fence, "PARTIAL_FAILURE", code).catch(() => undefined));
    }
  });
}
