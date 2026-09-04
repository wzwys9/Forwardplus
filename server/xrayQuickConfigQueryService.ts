import { parseQuickConfigRelays, type QuickConfigRelay } from "./xrayQuickConfigTopology";
import {
  resolveStoredXrayInboundDefinition,
  type XrayProfileShareFormat,
} from "../shared/xrayProfiles";
import {
  XRAY_QUICK_CONFIG_FORWARD_ENGINES,
  type XrayQuickConfigForwardEngine,
} from "../shared/xrayQuickConfigForwardEngines";
import { inList, quoteIdentifier } from "./dbCompat";
import { queryRaw } from "./dbRuntime";

type Row = Record<string, unknown>;

const QUICK_CONFIG_TARGET_TYPES = ["XRAY_INBOUND", "EXTERNAL_PROXY_NODE"] as const;
const QUICK_CONFIG_STATES = [
  "APPLYING", "ACTIVE", "UPDATING", "DELETING", "COMPENSATING", "PARTIAL_FAILURE", "FAILED", "REMOVED",
] as const;
const TOPOLOGY_STATES = [
  "STAGED", "APPLYING", "APPLIED", "RETIRING", "RETIRED", "ROLLBACK_PENDING", "ABANDONED",
] as const;
const LINE_CATEGORIES = ["DEFAULT", "TELECOM", "UNICOM", "MOBILE", "EDUCATION"] as const;
const ADDRESS_FAMILIES = ["IPV4", "IPV6"] as const;
const ROUTE_SOURCE_TYPES = ["MANAGED_HOST", "LANDING"] as const;
const ROUTE_MODES = ["DIRECT", "FORWARD"] as const;
const ROUTE_STATES = ["PLANNED", "APPLYING", "APPLIED", "RETIRING", "RETIRED", "FAILED"] as const;
const BINDING_STATES = ["PLANNED", "APPLYING", "READY", "RETIRING", "REMOVED", "FAILED"] as const;
const DNS_RECORD_TYPES = ["A", "AAAA"] as const;
const DNS_RECORD_STATES = ["DESIRED", "APPLIED", "DELETE_PENDING", "REMOVED", "DRIFTED", "UNKNOWN"] as const;
const OPERATION_TYPES = ["APPLY", "EDIT", "REMOVE", "RETRY"] as const;
const OPERATION_STATUSES = [
  "QUEUED", "RUNNING", "COMPENSATING", "SUCCESS", "FAILED", "PARTIAL_FAILURE", "CANCELLED",
] as const;
const OPERATION_PHASES = [
  "RECHECKING_DOMAIN", "RESERVING_PORT", "CREATING_RULES", "WAITING_RULES_READY", "APPLYING_DNS",
  "VERIFYING_DNS", "FINALIZING", "DNS_REMOVING", "DNS_REMOVED", "RULES_REMOVING", "RULES_REMOVED",
  "PORT_RELEASING", "RESTORING_DNS", "REMOVING_NEW_RULES", "RELEASING_REFERENCES", "COMPLETED",
] as const;
const STEP_KINDS = [
  "DOMAIN_RECHECK", "PORT_RESERVE", "RULE_CREATE", "RULE_VERIFY", "DNS_CREATE", "DNS_REPLACE", "DNS_DELETE",
  "DNS_VERIFY", "DNS_RESTORE", "RULE_DELETE", "RULE_VERIFY_REMOVED", "REFERENCE_RELEASE",
] as const;
const STEP_SUBJECT_TYPES = ["DOMAIN", "PORT", "RULE", "DNS_RECORD", "ALLOCATION", "TOPOLOGY"] as const;
const STEP_STATUSES = ["PENDING", "RUNNING", "SUCCESS", "FAILED", "SKIPPED", "COMPENSATED"] as const;

export type QuickConfigTargetType = typeof QUICK_CONFIG_TARGET_TYPES[number];
export type QuickConfigState = typeof QUICK_CONFIG_STATES[number];
export type QuickConfigLineCategory = typeof LINE_CATEGORIES[number];
export type QuickConfigBindingState = typeof BINDING_STATES[number];
export type QuickConfigRuntimeStatus = "running" | "degraded" | "pending" | "disabled" | "unknown";
export type QuickConfigShareCapability = "VLESS_URI" | "SHADOWSOCKS_URI" | "SOCKS5_ENDPOINT" | "NONE";

export type QuickConfigSummary = Readonly<{
  id: number;
  revision: number;
  dnsAccountId: number;
  zoneId: number;
  relativeName: string;
  fqdn: string;
  targetType: QuickConfigTargetType;
  targetId: number;
  targetName: string;
  publicPort: number;
  engine: XrayQuickConfigForwardEngine;
  state: QuickConfigState;
  currentOperationId: number | null;
  createdAt: string;
  updatedAt: string;
}>;

export type QuickConfigRouteDto = Readonly<{
  relays: QuickConfigRelay[];
  routeId: number;
  lineCategory: QuickConfigLineCategory;
  providerLineId: string;
  sourceType: typeof ROUTE_SOURCE_TYPES[number];
  hostId: number | null;
  addressFamily: typeof ADDRESS_FAMILIES[number];
  address: string;
  routeMode: typeof ROUTE_MODES[number];
  state: typeof ROUTE_STATES[number];
}>;

export type QuickConfigTopologyDto = Readonly<{
  topologyRevisionId: number;
  revisionNumber: number;
  state: typeof TOPOLOGY_STATES[number];
  publicPort: number;
  targetAddress: string;
  targetPort: number;
  routes: QuickConfigRouteDto[];
}>;

export type QuickConfigOperationStepDto = Readonly<{
  stepKey: string;
  kind: typeof STEP_KINDS[number];
  subjectType: typeof STEP_SUBJECT_TYPES[number];
  subjectSafeId: string | null;
  status: typeof STEP_STATUSES[number];
  attemptCount: number;
  errorCode: string | null;
}>;

export type QuickConfigOperationDto = Readonly<{
  operationId: number;
  quickConfigId: number;
  type: typeof OPERATION_TYPES[number];
  status: typeof OPERATION_STATUSES[number];
  phase: typeof OPERATION_PHASES[number];
  operationRevision: number;
  retryOfOperationId: number | null;
  startedAt: string | null;
  finishedAt: string | null;
  errorCode: string | null;
  steps: QuickConfigOperationStepDto[];
}>;

export type QuickConfigDetail = QuickConfigSummary & Readonly<{
  target: Readonly<{
    host?: { id: number; name: string };
    targetVersion: string;
    protocol: string;
    endpoint: Readonly<{ address: string; port: number }>;
    shareCapability: QuickConfigShareCapability;
  }>;
  activeTopology: QuickConfigTopologyDto | null;
  desiredTopology: QuickConfigTopologyDto | null;
  rules: Array<Readonly<{
    ruleId: number;
    hostId: number;
    name: string;
    forwardType: XrayQuickConfigForwardEngine;
    isEnabled: boolean;
    pendingDelete: boolean;
    bindingState: QuickConfigBindingState;
    runtimeStatus: QuickConfigRuntimeStatus;
    lineCategories: QuickConfigLineCategory[];
  }>>;
  dnsRecords: Array<Readonly<{
    recordRef: string;
    routeId: number;
    recordType: typeof DNS_RECORD_TYPES[number];
    providerLineId: string;
    value: string;
    ttl: number;
    status: typeof DNS_RECORD_STATES[number];
    lastVerifiedAt: string | null;
  }>>;
  currentOperation: QuickConfigOperationDto | null;
  lastOperation: QuickConfigOperationDto | null;
}>;

export class XrayQuickConfigQueryError extends Error {
  readonly code = "QUICK_CONFIG_NOT_FOUND" as const;

  constructor() {
    super("QUICK_CONFIG_NOT_FOUND");
    this.name = "XrayQuickConfigQueryError";
  }
}

function invalidProjection(): never {
  throw new Error("Quick-config data is not available");
}

function enumValue<const T extends readonly string[]>(value: unknown, allowed: T): T[number] {
  if (typeof value !== "string" || !(allowed as readonly string[]).includes(value)) invalidProjection();
  return value as T[number];
}

function positiveInteger(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) invalidProjection();
  return parsed;
}

function optionalPositiveInteger(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null;
  return positiveInteger(value);
}

function nonNegativeInteger(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) invalidProjection();
  return parsed;
}

function port(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 65535) invalidProjection();
  return parsed;
}

function boundedText(value: unknown, maximumBytes: number, allowEmpty = false): string {
  if (typeof value !== "string" || (!allowEmpty && value.length === 0)
    || Buffer.byteLength(value, "utf8") > maximumBytes || /[\u0000-\u001f\u007f]/.test(value)) {
    invalidProjection();
  }
  return value;
}

function databaseBoolean(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || value === "true";
}

function dateValue(value: unknown): Date | null {
  if (value === null || value === undefined || value === "") return null;
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value : null;
  const text = String(value);
  const numeric = /^\d+(?:\.\d+)?$/.test(text) ? Number(text) : Number.NaN;
  const parsed = Number.isFinite(numeric)
    ? new Date(numeric < 10_000_000_000 ? numeric * 1_000 : numeric)
    : new Date(text);
  return Number.isFinite(parsed.getTime()) ? parsed : null;
}

function requiredIso(value: unknown): string {
  const parsed = dateValue(value);
  if (!parsed) invalidProjection();
  return parsed.toISOString();
}

function optionalIso(value: unknown): string | null {
  return dateValue(value)?.toISOString() ?? null;
}

function stableErrorCode(value: unknown): string | null {
  if (value === null || value === undefined || value === "") return null;
  return typeof value === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(value) ? value : null;
}

function queryPositiveInteger(value: unknown, fallback: number, maximum?: number): number {
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0 || maximum !== undefined && parsed > maximum) {
    throw new TypeError("Invalid quick-config query input");
  }
  return parsed;
}

function optionalQueryId(value: unknown): number | undefined {
  if (value === undefined) return undefined;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new TypeError("Invalid quick-config query input");
  return parsed;
}

function querySearch(value: unknown): string {
  const search = String(value ?? "").trim().toLowerCase();
  if (Buffer.byteLength(search, "utf8") > 128 || /[\u0000-\u001f\u007f]/.test(search)) {
    throw new TypeError("Invalid quick-config query input");
  }
  return search;
}

function profileShareCapability(format: XrayProfileShareFormat): QuickConfigShareCapability {
  if (format === "VLESS_URI" || format === "SHADOWSOCKS_URI") return format;
  if (format === "MIXED_PROXY_ENDPOINTS") return "SOCKS5_ENDPOINT";
  return "NONE";
}

function externalShareCapability(protocol: string): QuickConfigShareCapability {
  if (protocol === "VLESS_REALITY_VISION") return "VLESS_URI";
  if (protocol === "SHADOWSOCKS") return "SHADOWSOCKS_URI";
  return protocol === "SOCKS5" ? "SOCKS5_ENDPOINT" : "NONE";
}

function targetTypeAndId(row: Row): { targetType: QuickConfigTargetType; targetId: number } {
  const targetType = enumValue(row.targetType, QUICK_CONFIG_TARGET_TYPES);
  const targetId = targetType === "XRAY_INBOUND"
    ? positiveInteger(row.xrayInboundId)
    : positiveInteger(row.externalProxyNodeId);
  return { targetType, targetId };
}

type SummaryTopology = {
  publicPort: number;
  engine: XrayQuickConfigForwardEngine;
  targetAddress: string;
  targetPort: number;
};

function topologySummary(row: Row): SummaryTopology | null {
  if (row.summaryPublicPort === null || row.summaryPublicPort === undefined) return null;
  const engine = enumValue(boundedText(row.summaryEngine, 32).toLowerCase(), XRAY_QUICK_CONFIG_FORWARD_ENGINES);
  return {
    publicPort: port(row.summaryPublicPort),
    engine,
    targetAddress: boundedText(row.summaryTargetAddress, 512),
    targetPort: port(row.summaryTargetPort),
  };
}

function summaryFromRow(row: Row, fallback: SummaryTopology | null): QuickConfigSummary {
  const target = targetTypeAndId(row);
  const selectedTopology = topologySummary(row) ?? fallback;
  if (!selectedTopology) invalidProjection();
  const targetNameRaw = target.targetType === "XRAY_INBOUND" ? row.inboundName : row.externalName;
  const targetName = targetNameRaw === null || targetNameRaw === undefined
    ? "已删除的落地节点"
    : boundedText(targetNameRaw, 128);
  return {
    id: positiveInteger(row.id),
    revision: positiveInteger(row.revision),
    dnsAccountId: positiveInteger(row.dnsAccountId),
    zoneId: positiveInteger(row.zoneId),
    relativeName: boundedText(row.relativeName, 253),
    fqdn: boundedText(row.fqdn, 253),
    ...target,
    targetName,
    publicPort: selectedTopology.publicPort,
    engine: selectedTopology.engine,
    state: enumValue(row.state, QUICK_CONFIG_STATES),
    currentOperationId: optionalPositiveInteger(row.currentOperationId),
    createdAt: requiredIso(row.createdAt),
    updatedAt: requiredIso(row.updatedAt),
  };
}

async function fallbackTopologySummaries(quickConfigIds: number[]): Promise<Map<number, SummaryTopology>> {
  if (quickConfigIds.length === 0) return new Map();
  const q = quoteIdentifier;
  const ids = inList(quickConfigIds);
  const rows = await queryRaw<Row>(
    `SELECT ${q("quickConfigId")}, ${q("publicPort")}, ${q("engine")}, ${q("targetAddress")}, ${q("targetPort")},
            ${q("revisionNumber")}, ${q("id")}
       FROM ${q("xray_quick_config_topology_revisions")}
      WHERE ${q("quickConfigId")} IN ${ids.sql}
      ORDER BY ${q("quickConfigId")} ASC, ${q("revisionNumber")} DESC, ${q("id")} DESC`,
    ids.params,
  );
  const output = new Map<number, SummaryTopology>();
  for (const row of rows) {
    const quickConfigId = positiveInteger(row.quickConfigId);
    if (output.has(quickConfigId)) continue;
    const engine = enumValue(boundedText(row.engine, 32).toLowerCase(), XRAY_QUICK_CONFIG_FORWARD_ENGINES);
    output.set(quickConfigId, {
      publicPort: port(row.publicPort),
      engine,
      targetAddress: boundedText(row.targetAddress, 512),
      targetPort: port(row.targetPort),
    });
  }
  return output;
}

const summarySelect = (where: string) => {
  const q = quoteIdentifier;
  return `SELECT qc.${q("id")}, qc.${q("revision")}, qc.${q("dnsAccountId")}, qc.${q("zoneId")},
                 qc.${q("relativeName")}, qc.${q("fqdn")},
                 qc.${q("targetType")}, qc.${q("xrayInboundId")}, qc.${q("externalProxyNodeId")},
                 qc.${q("state")}, qc.${q("currentOperationId")}, qc.${q("createdAt")}, qc.${q("updatedAt")},
                 qc.${q("targetVersion")}, qc.${q("activeTopologyRevisionId")}, qc.${q("desiredTopologyRevisionId")},
                 xi.${q("hostId")} AS ${q("inboundHostId")}, xi.${q("name")} AS ${q("inboundName")}, xi.${q("publicAddress")} AS ${q("inboundAddress")},
                 xi.${q("listenPort")} AS ${q("inboundPort")}, xi.${q("protocol")} AS ${q("inboundProtocol")},
                 xi.${q("transport")} AS ${q("inboundTransport")}, xi.${q("security")} AS ${q("inboundSecurity")},
                 xi.${q("profileId")} AS ${q("inboundProfileId")}, xi.${q("specVersion")} AS ${q("inboundSpecVersion")},
                 xi.${q("specJson")} AS ${q("inboundSpecJson")},
                 ep.${q("name")} AS ${q("externalName")}, ep.${q("address")} AS ${q("externalAddress")},
                 ep.${q("port")} AS ${q("externalPort")}, ep.${q("protocol")} AS ${q("externalProtocol")},
                 CASE WHEN qc.${q("state")} = 'PARTIAL_FAILURE'
                   THEN COALESCE(at.${q("publicPort")}, dt.${q("publicPort")})
                   ELSE COALESCE(dt.${q("publicPort")}, at.${q("publicPort")}) END AS ${q("summaryPublicPort")},
                 CASE WHEN qc.${q("state")} = 'PARTIAL_FAILURE'
                   THEN COALESCE(at.${q("engine")}, dt.${q("engine")})
                   ELSE COALESCE(dt.${q("engine")}, at.${q("engine")}) END AS ${q("summaryEngine")},
                 CASE WHEN qc.${q("state")} = 'PARTIAL_FAILURE'
                   THEN COALESCE(at.${q("targetAddress")}, dt.${q("targetAddress")})
                   ELSE COALESCE(dt.${q("targetAddress")}, at.${q("targetAddress")}) END AS ${q("summaryTargetAddress")},
                 CASE WHEN qc.${q("state")} = 'PARTIAL_FAILURE'
                   THEN COALESCE(at.${q("targetPort")}, dt.${q("targetPort")})
                   ELSE COALESCE(dt.${q("targetPort")}, at.${q("targetPort")}) END AS ${q("summaryTargetPort")}
            FROM ${q("xray_quick_configs")} qc
       LEFT JOIN ${q("xray_inbounds")} xi ON xi.${q("id")} = qc.${q("xrayInboundId")}
       LEFT JOIN ${q("xray_external_proxy_nodes")} ep ON ep.${q("id")} = qc.${q("externalProxyNodeId")}
       LEFT JOIN ${q("xray_quick_config_topology_revisions")} at ON at.${q("id")} = qc.${q("activeTopologyRevisionId")}
       LEFT JOIN ${q("xray_quick_config_topology_revisions")} dt ON dt.${q("id")} = qc.${q("desiredTopologyRevisionId")}${where}`;
};

export async function listXrayQuickConfigs(input: {
  search?: unknown;
  state?: unknown;
  targetType?: unknown;
  accountId?: unknown;
  page?: unknown;
  pageSize?: unknown;
} = {}): Promise<{ items: QuickConfigSummary[]; total: number; page: number; pageSize: number }> {
  const page = queryPositiveInteger(input.page, 1);
  const pageSize = queryPositiveInteger(input.pageSize, 20, 100);
  if (!Number.isSafeInteger((page - 1) * pageSize)) throw new TypeError("Invalid quick-config query input");
  const search = querySearch(input.search);
  const state = input.state === undefined ? undefined : enumValue(input.state, QUICK_CONFIG_STATES);
  const targetType = input.targetType === undefined ? undefined : enumValue(input.targetType, QUICK_CONFIG_TARGET_TYPES);
  const accountId = optionalQueryId(input.accountId);
  const q = quoteIdentifier;
  const clauses: string[] = [];
  const params: unknown[] = [];
  if (search) {
    clauses.push(`(LOWER(qc.${q("fqdn")}) LIKE ? OR LOWER(COALESCE(xi.${q("name")}, ep.${q("name")}, '')) LIKE ?)`);
    params.push(`%${search}%`, `%${search}%`);
  }
  if (state) {
    clauses.push(`qc.${q("state")} = ?`);
    params.push(state);
  }
  if (targetType) {
    clauses.push(`qc.${q("targetType")} = ?`);
    params.push(targetType);
  }
  if (accountId !== undefined) {
    clauses.push(`qc.${q("dnsAccountId")} = ?`);
    params.push(accountId);
  }
  const where = clauses.length ? ` WHERE ${clauses.join(" AND ")}` : "";
  const countRows = await queryRaw<Row>(
    `SELECT COUNT(*) AS ${q("count")} FROM ${q("xray_quick_configs")} qc
       LEFT JOIN ${q("xray_inbounds")} xi ON xi.${q("id")} = qc.${q("xrayInboundId")}
       LEFT JOIN ${q("xray_external_proxy_nodes")} ep ON ep.${q("id")} = qc.${q("externalProxyNodeId")}${where}`,
    params,
  );
  const total = nonNegativeInteger(countRows[0]?.count ?? 0);
  const rows = await queryRaw<Row>(
    `${summarySelect(where)} ORDER BY qc.${q("updatedAt")} DESC, qc.${q("id")} DESC LIMIT ? OFFSET ?`,
    [...params, pageSize, (page - 1) * pageSize],
  );
  const fallback = await fallbackTopologySummaries(rows.map((row) => positiveInteger(row.id)));
  return {
    items: rows.map((row) => summaryFromRow(row, fallback.get(positiveInteger(row.id)) ?? null)),
    total,
    page,
    pageSize,
  };
}

async function loadTopology(topologyRevisionId: number | null, quickConfigId: number): Promise<QuickConfigTopologyDto | null> {
  if (topologyRevisionId === null) return null;
  const q = quoteIdentifier;
  const [row] = await queryRaw<Row>(
    `SELECT ${q("id")}, ${q("quickConfigId")}, ${q("revisionNumber")}, ${q("state")}, ${q("publicPort")},
            ${q("targetAddress")}, ${q("targetPort")}
       FROM ${q("xray_quick_config_topology_revisions")}
      WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? LIMIT 1`,
    [topologyRevisionId, quickConfigId],
  );
  if (!row) invalidProjection();
  const routes = await queryRaw<Row>(
    `SELECT ${q("id")}, ${q("lineCategory")}, ${q("providerLineId")}, ${q("sourceType")}, ${q("hostId")},
            ${q("addressFamily")}, ${q("address")}, ${q("routeMode")}, ${q("relayHopsJson")}, ${q("state")}
       FROM ${q("xray_quick_config_routes")}
      WHERE ${q("topologyRevisionId")} = ? AND ${q("quickConfigId")} = ?
      ORDER BY ${q("sortOrder")} ASC, ${q("id")} ASC`,
    [topologyRevisionId, quickConfigId],
  );
  return {
    topologyRevisionId: positiveInteger(row.id),
    revisionNumber: positiveInteger(row.revisionNumber),
    state: enumValue(row.state, TOPOLOGY_STATES),
    publicPort: port(row.publicPort),
    targetAddress: boundedText(row.targetAddress, 512),
    targetPort: port(row.targetPort),
    routes: routes.map((route) => ({
      relays: parseQuickConfigRelays(route.relayHopsJson),
      routeId: positiveInteger(route.id),
      lineCategory: enumValue(route.lineCategory, LINE_CATEGORIES),
      providerLineId: boundedText(route.providerLineId, 128),
      sourceType: enumValue(route.sourceType, ROUTE_SOURCE_TYPES),
      hostId: optionalPositiveInteger(route.hostId),
      addressFamily: enumValue(route.addressFamily, ADDRESS_FAMILIES),
      address: boundedText(route.address, 512),
      routeMode: enumValue(route.routeMode, ROUTE_MODES),
      state: enumValue(route.state, ROUTE_STATES),
    })),
  };
}

function runtimeStatus(row: Row, bindingState: QuickConfigBindingState): QuickConfigRuntimeStatus {
  if (databaseBoolean(row.pendingDelete) || bindingState === "RETIRING" || bindingState === "REMOVED") return "pending";
  if (!databaseBoolean(row.isEnabled) || databaseBoolean(row.disabledByUser) || databaseBoolean(row.disabledByTunnel)
    || databaseBoolean(row.disabledByGroup) || String(row.protocolBlockReason ?? "").trim()) return "disabled";
  if (databaseBoolean(row.isRunning)) return "running";
  if (bindingState === "READY" || bindingState === "FAILED") return "degraded";
  if (bindingState === "PLANNED" || bindingState === "APPLYING") return "pending";
  return "unknown";
}

async function loadRules(
  quickConfigId: number,
  activeTopologyRevisionId: number | null,
  desiredTopologyRevisionId: number | null,
  preferActiveTopology = false,
): Promise<QuickConfigDetail["rules"]> {
  const topologyIds = [...new Set([desiredTopologyRevisionId, activeTopologyRevisionId].filter((id): id is number => id !== null))];
  if (topologyIds.length === 0) return [];
  const q = quoteIdentifier;
  const ids = inList(topologyIds);
  const rows = await queryRaw<Row>(
    `SELECT b.${q("id")} AS ${q("bindingId")}, b.${q("topologyRevisionId")}, b.${q("forwardRuleId")},
            b.${q("state")} AS ${q("bindingState")}, fr.${q("hostId")}, fr.${q("name")}, fr.${q("isEnabled")},
            fr.${q("forwardType")}, fr.${q("isRunning")}, fr.${q("pendingDelete")},
            fr.${q("disabledByUser")}, fr.${q("disabledByTunnel")},
            fr.${q("disabledByGroup")}, fr.${q("protocolBlockReason")}
       FROM ${q("xray_quick_config_rule_bindings")} b
       LEFT JOIN ${q("forward_rules")} fr ON fr.${q("id")} = b.${q("forwardRuleId")}
      WHERE b.${q("quickConfigId")} = ? AND b.${q("topologyRevisionId")} IN ${ids.sql}
      ORDER BY b.${q("id")} DESC`,
    [quickConfigId, ...ids.params],
  );
  const routeRows = await queryRaw<Row>(
    `SELECT ${q("topologyRevisionId")}, ${q("hostId")}, ${q("lineCategory")}, ${q("relayHopsJson")}
       FROM ${q("xray_quick_config_routes")}
      WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} IN ${ids.sql}
        AND ${q("routeMode")} = 'FORWARD'
      ORDER BY ${q("sortOrder")} ASC, ${q("id")} ASC`,
    [quickConfigId, ...ids.params],
  );
  const linesByTopologyHost = new Map<string, Set<QuickConfigLineCategory>>();
  for (const route of routeRows) {
    const topologyId = positiveInteger(route.topologyRevisionId);
    const hostId = optionalPositiveInteger(route.hostId);
    if (hostId === null) continue;
    for (const hopHostId of [hostId, ...parseQuickConfigRelays(route.relayHopsJson).map(hop => hop.hostId)]) {
      const key = `${topologyId}:${hopHostId}`;
      const lines = linesByTopologyHost.get(key) ?? new Set<QuickConfigLineCategory>();
      lines.add(enumValue(route.lineCategory, LINE_CATEGORIES));
      linesByTopologyHost.set(key, lines);
    }
  }
  const priority = (topologyId: number) => preferActiveTopology
    ? topologyId === activeTopologyRevisionId ? 2 : topologyId === desiredTopologyRevisionId ? 1 : 0
    : topologyId === desiredTopologyRevisionId ? 2 : topologyId === activeTopologyRevisionId ? 1 : 0;
  rows.sort((left, right) => priority(positiveInteger(right.topologyRevisionId)) - priority(positiveInteger(left.topologyRevisionId))
    || positiveInteger(right.bindingId) - positiveInteger(left.bindingId));
  const seen = new Set<number>();
  const output: QuickConfigDetail["rules"] = [];
  for (const row of rows) {
    const ruleId = positiveInteger(row.forwardRuleId);
    if (seen.has(ruleId) || row.hostId === null || row.hostId === undefined || row.name === null || row.name === undefined) continue;
    seen.add(ruleId);
    const topologyId = positiveInteger(row.topologyRevisionId);
    const hostId = positiveInteger(row.hostId);
    const bindingState = enumValue(row.bindingState, BINDING_STATES);
    const lineSet = linesByTopologyHost.get(`${topologyId}:${hostId}`) ?? new Set<QuickConfigLineCategory>();
    output.push({
      ruleId,
      hostId,
      name: boundedText(row.name, 256),
      forwardType: enumValue(boundedText(row.forwardType, 32).toLowerCase(), XRAY_QUICK_CONFIG_FORWARD_ENGINES),
      isEnabled: databaseBoolean(row.isEnabled),
      pendingDelete: databaseBoolean(row.pendingDelete),
      bindingState,
      runtimeStatus: runtimeStatus(row, bindingState),
      lineCategories: LINE_CATEGORIES.filter((line) => lineSet.has(line)),
    });
  }
  return output.sort((left, right) => left.hostId - right.hostId || left.ruleId - right.ruleId);
}

async function loadDnsRecords(quickConfigId: number): Promise<QuickConfigDetail["dnsRecords"]> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Row>(
    `SELECT ${q("routeId")}, ${q("recordTag")}, ${q("recordType")}, ${q("providerLineId")}, ${q("value")},
            ${q("ttl")}, ${q("status")}, ${q("lastVerifiedAt")}
       FROM ${q("xray_quick_config_dns_records")}
      WHERE ${q("quickConfigId")} = ? ORDER BY ${q("id")} ASC`,
    [quickConfigId],
  );
  return rows.map((row) => ({
    recordRef: boundedText(row.recordTag, 128),
    routeId: positiveInteger(row.routeId),
    recordType: enumValue(row.recordType, DNS_RECORD_TYPES),
    providerLineId: boundedText(row.providerLineId, 128),
    value: boundedText(row.value, 512),
    ttl: positiveInteger(row.ttl),
    status: enumValue(row.status, DNS_RECORD_STATES),
    lastVerifiedAt: optionalIso(row.lastVerifiedAt),
  }));
}

function numericSubject(value: unknown): string | null {
  if (typeof value !== "string" && typeof value !== "number") return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? String(parsed) : null;
}

async function operationDto(row: Row): Promise<QuickConfigOperationDto> {
  const operationId = positiveInteger(row.id);
  const quickConfigId = positiveInteger(row.quickConfigId);
  const q = quoteIdentifier;
  const steps = await queryRaw<Row>(
    `SELECT ${q("stepKey")}, ${q("kind")}, ${q("subjectType")}, ${q("subjectId")}, ${q("status")},
            ${q("attemptCount")}, ${q("errorCode")}
       FROM ${q("xray_quick_config_operation_steps")}
      WHERE ${q("operationId")} = ? ORDER BY ${q("id")} ASC`,
    [operationId],
  );
  const dnsRows = await queryRaw<Row>(
    `SELECT ${q("id")}, ${q("recordTag")} FROM ${q("xray_quick_config_dns_records")}
      WHERE ${q("quickConfigId")} = ? ORDER BY ${q("id")} ASC`,
    [quickConfigId],
  );
  const dnsRefs = new Map<string, string>();
  for (const dnsRow of dnsRows) {
    const id = String(positiveInteger(dnsRow.id));
    const ref = boundedText(dnsRow.recordTag, 128);
    dnsRefs.set(id, ref);
    dnsRefs.set(ref, ref);
  }
  const fqdn = boundedText(row.fqdn, 253);
  return {
    operationId,
    quickConfigId,
    type: enumValue(row.type, OPERATION_TYPES),
    status: enumValue(row.status, OPERATION_STATUSES),
    phase: enumValue(row.phase, OPERATION_PHASES),
    operationRevision: positiveInteger(row.revision),
    retryOfOperationId: optionalPositiveInteger(row.retryOfOperationId),
    startedAt: optionalIso(row.startedAt),
    finishedAt: optionalIso(row.finishedAt),
    errorCode: stableErrorCode(row.errorCode),
    steps: steps.map((step) => {
      const subjectType = enumValue(step.subjectType, STEP_SUBJECT_TYPES);
      let subjectSafeId: string | null = null;
      if (subjectType === "DOMAIN") subjectSafeId = fqdn;
      else if (subjectType === "DNS_RECORD") subjectSafeId = dnsRefs.get(String(step.subjectId ?? "")) ?? null;
      else if (subjectType === "PORT") {
        const value = Number(step.subjectId);
        subjectSafeId = Number.isSafeInteger(value) && value >= 1 && value <= 65535 ? String(value) : null;
      } else subjectSafeId = numericSubject(step.subjectId);
      return {
        stepKey: boundedText(step.stepKey, 128),
        kind: enumValue(step.kind, STEP_KINDS),
        subjectType,
        subjectSafeId,
        status: enumValue(step.status, STEP_STATUSES),
        attemptCount: nonNegativeInteger(step.attemptCount),
        errorCode: stableErrorCode(step.errorCode),
      };
    }),
  };
}

const operationSelect = () => {
  const q = quoteIdentifier;
  return `SELECT op.${q("id")}, op.${q("quickConfigId")}, op.${q("type")}, op.${q("status")}, op.${q("phase")},
                 op.${q("revision")}, op.${q("retryOfOperationId")}, op.${q("startedAt")}, op.${q("finishedAt")},
                 op.${q("errorCode")}, op.${q("fromTopologyRevisionId")}, op.${q("toTopologyRevisionId")},
                 op.${q("requestSummaryJson")}, qc.${q("fqdn")}
            FROM ${q("xray_quick_config_operations")} op
            JOIN ${q("xray_quick_configs")} qc ON qc.${q("id")} = op.${q("quickConfigId")}`;
};

async function loadOperationById(operationId: number, expectedQuickConfigId?: number): Promise<QuickConfigOperationDto | null> {
  const q = quoteIdentifier;
  const params: unknown[] = [operationId];
  let where = ` WHERE op.${q("id")} = ?`;
  if (expectedQuickConfigId !== undefined) {
    where += ` AND op.${q("quickConfigId")} = ?`;
    params.push(expectedQuickConfigId);
  }
  const [row] = await queryRaw<Row>(`${operationSelect()}${where} LIMIT 1`, params);
  return row ? operationDto(row) : null;
}

export async function getXrayQuickConfigOperation(operationIdValue: unknown): Promise<QuickConfigOperationDto> {
  const operationId = optionalQueryId(operationIdValue);
  if (operationId === undefined) throw new TypeError("Invalid quick-config query input");
  const operation = await loadOperationById(operationId);
  if (!operation) throw new XrayQuickConfigQueryError();
  return operation;
}

function targetDetail(
  row: Row,
  summary: QuickConfigSummary,
  fallbackTopology: SummaryTopology,
  activeTopology: QuickConfigTopologyDto | null,
  desiredTopology: QuickConfigTopologyDto | null,
): QuickConfigDetail["target"] {
  const fallbackAddress = desiredTopology?.targetAddress ?? activeTopology?.targetAddress ?? fallbackTopology.targetAddress;
  const fallbackPort = desiredTopology?.targetPort ?? activeTopology?.targetPort ?? fallbackTopology.targetPort;
  let protocol = "UNKNOWN";
  let address = fallbackAddress;
  let endpointPort = fallbackPort;
  let shareCapability: QuickConfigShareCapability = "NONE";
  if (summary.targetType === "XRAY_INBOUND" && row.inboundName !== null && row.inboundName !== undefined) {
    protocol = boundedText(row.inboundProtocol, 32).toUpperCase();
    address = boundedText(row.inboundAddress, 512);
    endpointPort = port(row.inboundPort);
    const definition = resolveStoredXrayInboundDefinition({
      protocol: row.inboundProtocol,
      transport: row.inboundTransport,
      security: row.inboundSecurity,
      profileId: row.inboundProfileId,
      specVersion: row.inboundSpecVersion,
      specJson: row.inboundSpecJson,
    });
    shareCapability = definition ? profileShareCapability(definition.profile.shareFormat) : "NONE";
  } else if (summary.targetType === "EXTERNAL_PROXY_NODE" && row.externalName !== null && row.externalName !== undefined) {
    protocol = boundedText(row.externalProtocol, 32).toUpperCase();
    address = boundedText(row.externalAddress, 512);
    endpointPort = port(row.externalPort);
    shareCapability = externalShareCapability(protocol);
  }
  return {
    targetVersion: boundedText(row.targetVersion, 64),
    ...(summary.targetType === "XRAY_INBOUND" && row.inboundHostId != null ? { host: { id: positiveInteger(row.inboundHostId), name: `Host #${positiveInteger(row.inboundHostId)}` } } : {}),
    protocol,
    endpoint: { address, port: endpointPort },
    shareCapability,
  };
}

export async function getXrayQuickConfigDetail(idValue: unknown): Promise<QuickConfigDetail> {
  const id = optionalQueryId(idValue);
  if (id === undefined) throw new TypeError("Invalid quick-config query input");
  const q = quoteIdentifier;
  const [row] = await queryRaw<Row>(`${summarySelect(` WHERE qc.${q("id")} = ?`)} LIMIT 1`, [id]);
  if (!row) throw new XrayQuickConfigQueryError();
  const fallback = await fallbackTopologySummaries([id]);
  const fallbackSummary = fallback.get(id) ?? null;
  const summary = summaryFromRow(row, fallbackSummary);
  if (!fallbackSummary) invalidProjection();
  const activeTopologyRevisionId = optionalPositiveInteger(row.activeTopologyRevisionId);
  let desiredTopologyRevisionId = optionalPositiveInteger(row.desiredTopologyRevisionId);
  const [lastOperationRow] = await queryRaw<Row>(
    `${operationSelect()} WHERE op.${q("quickConfigId")} = ? ORDER BY op.${q("createdAt")} DESC, op.${q("id")} DESC LIMIT 1`,
    [id],
  );
  if (row.state === "PARTIAL_FAILURE" && lastOperationRow
    && (lastOperationRow.type === "EDIT" || lastOperationRow.type === "RETRY")) {
    try {
      const requestSummary = JSON.parse(String(lastOperationRow.requestSummaryJson ?? "")) as Record<string, unknown>;
      if (requestSummary.kind === "TOPOLOGY_EDIT") {
        const fromTopologyRevisionId = optionalPositiveInteger(lastOperationRow.fromTopologyRevisionId);
        const toTopologyRevisionId = optionalPositiveInteger(lastOperationRow.toTopologyRevisionId);
        if (activeTopologyRevisionId === toTopologyRevisionId && fromTopologyRevisionId !== activeTopologyRevisionId) {
          desiredTopologyRevisionId = fromTopologyRevisionId;
        } else if (activeTopologyRevisionId === fromTopologyRevisionId && toTopologyRevisionId !== activeTopologyRevisionId) {
          desiredTopologyRevisionId = toTopologyRevisionId;
        }
      }
    } catch {
      // Unknown operation metadata must not be interpreted as topology edit.
    }
  }
  const [activeTopology, desiredTopology, rules, dnsRecords] = await Promise.all([
    loadTopology(activeTopologyRevisionId, id),
    loadTopology(desiredTopologyRevisionId, id),
    loadRules(id, activeTopologyRevisionId, desiredTopologyRevisionId, row.state === "PARTIAL_FAILURE"),
    loadDnsRecords(id),
  ]);
  const currentOperationId = summary.currentOperationId;
  const [currentOperation, lastOperation] = await Promise.all([
    currentOperationId === null ? Promise.resolve(null) : loadOperationById(currentOperationId, id),
    lastOperationRow ? operationDto(lastOperationRow) : Promise.resolve(null),
  ]);
  if (currentOperationId !== null && !currentOperation) invalidProjection();
  return {
    ...summary,
    target: targetDetail(row, summary, fallbackSummary, activeTopology, desiredTopology),
    activeTopology,
    desiredTopology,
    rules,
    dnsRecords,
    currentOperation,
    lastOperation,
  };
}
