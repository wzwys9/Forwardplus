import { loadQuickConfigSegments } from "./xrayQuickConfigTopologyStore";
import {
  DnsPodProviderClient,
  DnsPodProviderError,
  type DnsPodCredentials,
  type DnsPodRecord,
  type DnsPodRecordLine,
  type DnsPodRecordWriteInput,
  type DnsPodZone,
} from "./dnsPodProviderClient";
import { quoteIdentifier } from "./dbCompat";
import { executeRaw, nowDate, queryRaw, rawAffectedRows, withDatabaseTransaction } from "./dbRuntime";
import { withKeyedTaskLock } from "./keyedTaskLock";
import { loadGlobalDnsProviderCredentials } from "./repositories/dnsProviderRepository";
import {
  computeXrayQuickConfigDnsTupleHash,
  type XrayQuickConfigDnsTuple,
} from "./xrayQuickConfigDnsTuple";
import { XRAY_QUICK_CONFIG_FORWARD_ENGINES } from "../shared/xrayQuickConfigForwardEngines";

type Row = Record<string, unknown>;
export type QuickConfigDnsLineCategory = "DEFAULT" | "TELECOM" | "UNICOM" | "MOBILE" | "EDUCATION";
type DnsWriteIntent = { kind: "DNS_CREATE" | "DNS_REPLACE"; status: string };
type ManagedRecord = {
  id: number;
  routeId: number;
  lineCategory: QuickConfigDnsLineCategory;
  providerRecordId: string | null;
  tuple: XrayQuickConfigDnsTuple;
  tupleHash: string;
  status: "DESIRED" | "APPLIED" | "UNKNOWN";
  line: DnsPodRecordLine;
};
type BackupRecord = {
  id: number;
  providerRecordId: string;
  tuple: XrayQuickConfigDnsTuple;
  tupleHash: string;
  snapshotOrder: number;
  state: "CAPTURED" | "RESTORING" | "RESTORED" | "SKIPPED_DRIFTED" | "FAILED";
  line: DnsPodRecordLine;
};
type AppliedChange =
  | { kind: "CREATED"; record: ManagedRecord; providerRecordId: string }
  | { kind: "REPLACED"; record: ManagedRecord; backup: BackupRecord; providerRecordId: string }
  | { kind: "DELETED_BACKUP"; backup: BackupRecord };
type DnsStepKind = "DNS_CREATE" | "DNS_REPLACE" | "DNS_DELETE" | "DNS_VERIFY" | "DNS_RESTORE";
type DnsStep = {
  id: number;
  kind: DnsStepKind;
  status: "PENDING" | "RUNNING" | "SUCCESS" | "FAILED" | "COMPENSATED";
  context: DnsExecutionContext;
};

export type QuickConfigDnsApplyResult =
  | Readonly<{
      status: "SUCCESS";
      operationId: number;
      quickConfigId: number;
      appliedRecordCount: number;
      verifiedRecordCount: number;
    }>
  | Readonly<{
      status: "FAILED" | "PARTIAL_FAILURE";
      operationId: number;
      quickConfigId: number | null;
      errorCode: string;
      compensatedRecordCount: number;
      compensationComplete?: boolean;
    }>;

type DnsClient = Pick<DnsPodProviderClient, "listRecords" | "getRecord" | "createRecord" | "updateRecord" | "deleteRecord">;
export type QuickConfigDnsApplyOptions = Readonly<{
  clientFactory?: (credentials: DnsPodCredentials) => DnsClient;
  now?: () => Date;
}>;

export type QuickConfigDnsExecutionFence = Readonly<{
  executionOwnerId: string;
  executionFence: number;
}>;

class DnsApplyError extends Error {
  constructor(readonly code: string, readonly quickConfigId: number | null = null) {
    super(code);
    this.name = "XrayQuickConfigDnsApplyError";
  }
}

const q = quoteIdentifier;
function fail(code: string, quickConfigId: number | null = null): never {
  throw new DnsApplyError(code, quickConfigId);
}

function positiveInteger(value: unknown, code = "QUICK_CONFIG_OPERATION_CONFLICT"): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) fail(code);
  return parsed;
}

function optionalPositiveInteger(value: unknown): number | null {
  return value === null || value === undefined || value === "" ? null : positiveInteger(value);
}

function boundedText(value: unknown, maxBytes: number): string {
  if (typeof value !== "string" || !value || Buffer.byteLength(value, "utf8") > maxBytes
    || /[\u0000-\u001f\u007f]/.test(value)) fail("DNS_RECORD_DRIFT");
  return value;
}

function databaseBoolean(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || value === "true";
}

function databaseDate(value: unknown): Date | null {
  if (value === null || value === undefined || value === "") return null;
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value : null;
  const numeric = Number(value);
  const parsed = Number.isFinite(numeric)
    ? new Date(numeric < 10_000_000_000 ? numeric * 1_000 : numeric)
    : new Date(String(value));
  return Number.isFinite(parsed.getTime()) ? parsed : null;
}

function validNow(options: QuickConfigDnsApplyOptions): Date {
  const now = options.now?.() ?? new Date();
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  return new Date(now);
}

function stableProviderError(error: unknown): string {
  if (error instanceof DnsApplyError) return error.code;
  if (error instanceof DnsPodProviderError) {
    if (error.code === "DNS_PROVIDER_INVALID") return "DNS_PROVIDER_INVALID";
    if (error.code === "DNS_PROVIDER_RECORD_NOT_FOUND") return "DNS_RECORD_DRIFT";
    return "DNS_PROVIDER_CATALOG_STALE";
  }
  const code = String((error as { code?: unknown } | null)?.code ?? "");
  if (code === "DNS_PROVIDER_NOT_CONFIGURED" || code === "DNS_PROVIDER_CONFLICT"
    || code === "SENSITIVE_DATA_UNAVAILABLE") return code;
  return "DNS_PROVIDER_CATALOG_STALE";
}

function isFenceLoss(error: unknown): boolean {
  return error instanceof DnsApplyError && error.code === "QUICK_CONFIG_OPERATION_CONFLICT";
}

function recordType(value: unknown, backup = false): "A" | "AAAA" | "CNAME" {
  if (value === "A" || value === "AAAA" || backup && value === "CNAME") return value;
  fail("DNS_RECORD_DRIFT");
}

function managedLineCategory(value: unknown): QuickConfigDnsLineCategory {
  if (value === "DEFAULT" || value === "TELECOM" || value === "UNICOM"
    || value === "MOBILE" || value === "EDUCATION") return value;
  fail("DNS_RECORD_DRIFT");
}

export function orderQuickConfigDnsWrites<T extends { lineCategory: QuickConfigDnsLineCategory }>(
  records: readonly T[],
): T[] {
  return [
    ...records.filter((record) => record.lineCategory === "DEFAULT"),
    ...records.filter((record) => record.lineCategory !== "DEFAULT"),
  ];
}

export function hasQuickConfigDnsCreateOwnershipEvidence(input: {
  currentIntent: DnsWriteIntent | null;
  sourceCreateStatus: string | null;
}): boolean {
  const currentAttempted = input.currentIntent?.kind === "DNS_CREATE"
    && (input.currentIntent.status === "RUNNING" || input.currentIntent.status === "SUCCESS");
  const sourceAttempted = input.sourceCreateStatus === "RUNNING"
    || input.sourceCreateStatus === "SUCCESS"
    || input.sourceCreateStatus === "FAILED";
  return currentAttempted || sourceAttempted;
}

const DNSPOD_VISIBILITY_DELAYS_MS = [500, 1_000, 2_000, 4_000, 7_500, 15_000] as const;

export async function waitForQuickConfigDnsVisibility<T>(
  read: () => Promise<T | null>,
  options: {
    delaysMs?: readonly number[];
    sleep?: (milliseconds: number) => Promise<void>;
  } = {},
): Promise<T | null> {
  const delays = options.delaysMs ?? DNSPOD_VISIBILITY_DELAYS_MS;
  const sleep = options.sleep ?? ((milliseconds: number) => new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
  let visible = await read();
  for (const delay of delays) {
    if (visible !== null) break;
    await sleep(delay);
    visible = await read();
  }
  return visible;
}

function ttl(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 604_800) fail("DNS_RECORD_DRIFT");
  return parsed;
}

function providerRecordId(value: unknown): string {
  const id = boundedText(value, 128);
  if (!/^[1-9]\d*$/.test(id)) fail("DNS_RECORD_DRIFT");
  return id;
}

function expectedTuple(row: Row, backup = false): XrayQuickConfigDnsTuple {
  const tuple: XrayQuickConfigDnsTuple = {
    fqdn: boundedText(row.fqdn, 253).toLowerCase(),
    recordType: recordType(row.recordType, backup),
    providerLineId: boundedText(row.providerLineId, 128),
    value: boundedText(row.value, 2_048),
    ttl: ttl(row.ttl),
  };
  const storedHash = boundedText(row.remoteTupleHash, 64);
  if (!/^[a-f0-9]{64}$/.test(storedHash) || computeXrayQuickConfigDnsTupleHash(tuple) !== storedHash) {
    fail("DNS_RECORD_DRIFT");
  }
  return tuple;
}

function remoteTuple(record: DnsPodRecord, fqdn: string): XrayQuickConfigDnsTuple | null {
  const type = String(record.recordType ?? "").toUpperCase();
  if (type !== "A" && type !== "AAAA" && type !== "CNAME") return null;
  return {
    fqdn,
    recordType: type,
    providerLineId: String(record.providerLineId ?? ""),
    value: String(record.value ?? ""),
    ttl: Number(record.ttl),
  };
}

function tupleMatches(record: DnsPodRecord, tuple: XrayQuickConfigDnsTuple, relativeName: string): boolean {
  const remote = remoteTuple(record, tuple.fqdn);
  return record.subdomain.trim().toLowerCase() === relativeName
    && !!remote
    && computeXrayQuickConfigDnsTupleHash(remote) === computeXrayQuickConfigDnsTupleHash(tuple);
}

function writeInput(zone: DnsPodZone, relativeName: string, line: DnsPodRecordLine, tuple: XrayQuickConfigDnsTuple): DnsPodRecordWriteInput {
  return {
    zone,
    subdomain: relativeName,
    recordType: tuple.recordType,
    line,
    value: tuple.value,
    ttl: tuple.ttl,
  };
}

async function remoteRecord(client: DnsClient, zone: DnsPodZone, id: string): Promise<DnsPodRecord | null> {
  try {
    return await client.getRecord({ zone, providerRecordId: id });
  } catch (error) {
    if (error instanceof DnsPodProviderError && error.code === "DNS_PROVIDER_RECORD_NOT_FOUND") return null;
    throw error;
  }
}

type DnsExecutionContext = Awaited<ReturnType<typeof loadContext>>;

async function assertStillActive(context: {
  operationId: number;
  quickConfigId: number;
  executionOwnerId: string;
  executionFence: number;
}): Promise<void> {
  const [row] = await queryRaw<Row>(
    `SELECT o.${q("status")}, o.${q("activeSlot")}, o.${q("executionLeaseUntil")},
            qc.${q("currentOperationId")}
       FROM ${q("xray_quick_config_operations")} o
       JOIN ${q("xray_quick_configs")} qc ON qc.${q("id")} = o.${q("quickConfigId")}
      WHERE o.${q("id")} = ? AND o.${q("quickConfigId")} = ? AND o.${q("executionOwnerId")} = ?
        AND o.${q("executionFence")} = ? LIMIT 1`,
    [context.operationId, context.quickConfigId, context.executionOwnerId, context.executionFence],
  );
  if (!row || !["RUNNING", "COMPENSATING"].includes(String(row.status))
    || Number(row.activeSlot) !== 1 || Number(row.currentOperationId) !== context.operationId) {
    fail("QUICK_CONFIG_OPERATION_CONFLICT", context.quickConfigId);
  }
  const leaseUntil = databaseDate(row.executionLeaseUntil);
  if (!leaseUntil || leaseUntil.getTime() <= Date.now()) fail("QUICK_CONFIG_OPERATION_CONFLICT", context.quickConfigId);
}

function fencedDnsClient(client: DnsClient, context: DnsExecutionContext): DnsClient {
  const guarded = async <T>(call: () => Promise<T>): Promise<T> => {
    await assertStillActive(context);
    try {
      return await call();
    } finally {
      await assertStillActive(context);
    }
  };
  return {
    listRecords: (input) => guarded(() => client.listRecords(input)),
    getRecord: (input) => guarded(() => client.getRecord(input)),
    createRecord: (input) => guarded(() => client.createRecord(input)),
    updateRecord: (input) => guarded(() => client.updateRecord(input)),
    deleteRecord: (input) => guarded(() => client.deleteRecord(input)),
  };
}

function fenceExistsSql(context: {
  operationId: number;
  quickConfigId: number;
  executionOwnerId: string;
  executionFence: number;
}) {
  return {
    sql: `EXISTS (
      SELECT 1 FROM ${q("xray_quick_config_operations")} owned
      JOIN ${q("xray_quick_configs")} owned_qc ON owned_qc.${q("id")} = owned.${q("quickConfigId")}
      WHERE owned.${q("id")} = ? AND owned.${q("quickConfigId")} = ?
        AND owned.${q("executionOwnerId")} = ? AND owned.${q("executionFence")} = ?
        AND owned.${q("status")} IN ('RUNNING', 'COMPENSATING')
        AND owned_qc.${q("currentOperationId")} = owned.${q("id")}
    )`,
    params: [context.operationId, context.quickConfigId, context.executionOwnerId, context.executionFence],
  };
}

async function loadContext(operationId: number, expectedFence: QuickConfigDnsExecutionFence, now: Date) {
  const [row] = await queryRaw<Row>(
    `SELECT o.${q("id")} AS ${q("operationId")}, o.${q("quickConfigId")}, o.${q("type")}, o.${q("status")},
            o.${q("phase")}, o.${q("activeSlot")}, o.${q("toTopologyRevisionId")}, o.${q("executionOwnerId")},
            o.${q("executionFence")}, o.${q("requestSummaryJson")}, o.${q("retryOfOperationId")},
            o.${q("executionLeaseUntil")}, qc.${q("currentOperationId")}, qc.${q("dnsAccountId")}, qc.${q("zoneId")},
            qc.${q("relativeName")}, qc.${q("fqdn")}, qc.${q("desiredTopologyRevisionId")},
            t.${q("engine")} AS ${q("engine")},
            z.${q("providerZoneId")}, z.${q("name")} AS ${q("zoneName")}, z.${q("status")} AS ${q("zoneStatus")},
            z.${q("expiresAt")} AS ${q("zoneExpiresAt")}, a.${q("verificationStatus")},
            a.${q("verificationExpiresAt")}, a.${q("isDisabled")}
       FROM ${q("xray_quick_config_operations")} o
       JOIN ${q("xray_quick_configs")} qc ON qc.${q("id")} = o.${q("quickConfigId")}
       JOIN ${q("xray_quick_config_topology_revisions")} t ON t.${q("id")} = qc.${q("desiredTopologyRevisionId")}
       JOIN ${q("dns_provider_zones")} z ON z.${q("id")} = qc.${q("zoneId")} AND z.${q("accountId")} = qc.${q("dnsAccountId")}
       JOIN ${q("dns_provider_accounts")} a ON a.${q("id")} = qc.${q("dnsAccountId")}
      WHERE o.${q("id")} = ? AND o.${q("executionOwnerId")} = ? AND o.${q("executionFence")} = ? LIMIT 1`,
    [operationId, expectedFence.executionOwnerId, expectedFence.executionFence],
  );
  if (!row) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  const quickConfigId = positiveInteger(row.quickConfigId);
  const desiredTopologyId = positiveInteger(row.desiredTopologyRevisionId);
  const toTopologyId = optionalPositiveInteger(row.toTopologyRevisionId);
  const retryOfOperationId = optionalPositiveInteger(row.retryOfOperationId);
  const operationType = String(row.type);
  const leaseUntil = databaseDate(row.executionLeaseUntil);
  if (!["APPLY", "EDIT", "RETRY"].includes(operationType)
    || !["RUNNING", "COMPENSATING"].includes(String(row.status))
    || !["APPLYING_DNS", "VERIFYING_DNS", "RESTORING_DNS"].includes(String(row.phase))
    || Number(row.activeSlot) !== 1 || Number(row.currentOperationId) !== operationId
    || toTopologyId !== null && toTopologyId !== desiredTopologyId
    || row.executionOwnerId !== expectedFence.executionOwnerId
    || Number(row.executionFence) !== expectedFence.executionFence
    || (operationType === "RETRY") !== (retryOfOperationId !== null)
    || !leaseUntil || leaseUntil.getTime() <= now.getTime()) {
    fail("QUICK_CONFIG_OPERATION_CONFLICT", quickConfigId);
  }
  let genericEdit = false;
  if (row.type === "EDIT" || row.type === "RETRY") {
    try {
      const summary = JSON.parse(String(row.requestSummaryJson ?? "")) as Record<string, unknown>;
      genericEdit = summary.kind === "TOPOLOGY_EDIT";
    } catch {
      fail("QUICK_CONFIG_OPERATION_CONFLICT", quickConfigId);
    }
  }
  if (genericEdit) {
    const desiredIdentities = await queryRaw<Row>(
      `SELECT DISTINCT dr.${q("dnsAccountId")}, dr.${q("zoneId")}, dr.${q("fqdn")},
              z.${q("providerZoneId")}, z.${q("name")} AS ${q("zoneName")}, z.${q("status")} AS ${q("zoneStatus")},
              z.${q("expiresAt")} AS ${q("zoneExpiresAt")}, a.${q("verificationStatus")},
              a.${q("verificationExpiresAt")}, a.${q("isDisabled")}
         FROM ${q("xray_quick_config_dns_records")} dr
         JOIN ${q("xray_quick_config_routes")} r ON r.${q("id")} = dr.${q("routeId")}
         JOIN ${q("dns_provider_zones")} z ON z.${q("id")} = dr.${q("zoneId")} AND z.${q("accountId")} = dr.${q("dnsAccountId")}
         JOIN ${q("dns_provider_accounts")} a ON a.${q("id")} = dr.${q("dnsAccountId")}
        WHERE dr.${q("quickConfigId")} = ? AND r.${q("topologyRevisionId")} = ?`,
      [quickConfigId, desiredTopologyId],
    );
    if (desiredIdentities.length !== 1) fail("DNS_RECORD_DRIFT", quickConfigId);
    Object.assign(row, desiredIdentities[0]);
    const desiredFqdn = boundedText(row.fqdn, 253).toLowerCase();
    const desiredZoneName = boundedText(row.zoneName, 253).toLowerCase();
    if (!desiredFqdn.endsWith(`.${desiredZoneName}`)) fail("DNS_RECORD_DRIFT", quickConfigId);
    row.relativeName = desiredFqdn.slice(0, -(desiredZoneName.length + 1));
  }
  if (databaseBoolean(row.isDisabled) || row.verificationStatus !== "VALID"
    || row.zoneStatus !== "AVAILABLE" || (databaseDate(row.verificationExpiresAt)?.getTime() ?? 0) <= now.getTime()
    || (databaseDate(row.zoneExpiresAt)?.getTime() ?? 0) <= now.getTime()) {
    fail("DNS_PROVIDER_VALIDATION_STALE", quickConfigId);
  }
  const accountId = positiveInteger(row.dnsAccountId, "DNS_PROVIDER_CONFLICT");
  const zoneId = positiveInteger(row.zoneId, "DNS_PROVIDER_CONFLICT");
  const relativeName = boundedText(row.relativeName, 253).toLowerCase();
  const fqdn = boundedText(row.fqdn, 253).toLowerCase();
  const engine = boundedText(row.engine, 32).toLowerCase();
  const zoneName = boundedText(row.zoneName, 253).toLowerCase();
  if (`${relativeName}.${zoneName}` !== fqdn
    || !(XRAY_QUICK_CONFIG_FORWARD_ENGINES as readonly string[]).includes(engine)) {
    fail("DNS_RECORD_DRIFT", quickConfigId);
  }
  return {
    operationId,
    quickConfigId,
    executionOwnerId: expectedFence.executionOwnerId,
    executionFence: expectedFence.executionFence,
    accountId,
    zoneId,
    topologyId: desiredTopologyId,
    engine,
    phase: String(row.phase) as "APPLYING_DNS" | "VERIFYING_DNS" | "RESTORING_DNS",
    relativeName,
    fqdn,
    compensationOnly: row.status === "COMPENSATING" || row.phase === "RESTORING_DNS",
    genericEdit,
    operationType: operationType as "APPLY" | "EDIT" | "RETRY",
    retryOfOperationId,
    zone: {
      providerZoneId: boundedText(row.providerZoneId, 128),
      name: zoneName,
      grade: "",
    } satisfies DnsPodZone,
  };
}

async function assertRulesReady(context: Awaited<ReturnType<typeof loadContext>>): Promise<void> {
  const forwardRoutes = await loadQuickConfigSegments(context.quickConfigId, context.topologyId);
  for (const route of forwardRoutes) {
    const hostId = positiveInteger(route.hostId, "RULE_APPLY_FAILED");
    const [ready] = await queryRaw<Row>(
      `SELECT b.${q("id")} FROM ${q("xray_quick_config_rule_bindings")} b
         JOIN ${q("forward_rules")} fr ON fr.${q("id")} = b.${q("forwardRuleId")}
        WHERE b.${q("quickConfigId")} = ? AND b.${q("topologyRevisionId")} = ? AND b.${q("state")} = 'READY'
          AND fr.${q("xrayQuickConfigId")} = ? AND fr.${q("hostId")} = ? AND fr.${q("forwardType")} = ?
          AND fr.${q("targetIp")} = ? AND fr.${q("targetPort")} = ? AND fr.${q("sourcePort")} = ?
          AND fr.${q("isEnabled")} = ? AND fr.${q("isRunning")} = ? AND fr.${q("pendingDelete")} = ? LIMIT 1`,
      [context.quickConfigId, context.topologyId, context.quickConfigId, hostId, context.engine, route.targetAddress, route.targetPort, route.listenPort, true, true, false],
    );
    if (!ready) fail("RULE_APPLY_FAILED", context.quickConfigId);
  }
}

async function loadLines(zoneId: number, now: Date): Promise<Map<string, DnsPodRecordLine>> {
  const rows = await queryRaw<Row>(
    `SELECT ${q("providerLineId")}, ${q("name")}, ${q("status")}, ${q("expiresAt")}
       FROM ${q("dns_provider_record_lines")} WHERE ${q("zoneId")} = ? ORDER BY ${q("id")} ASC`,
    [zoneId],
  );
  const lines = new Map<string, DnsPodRecordLine>();
  const currentTime = now.getTime();
  for (const row of rows) {
    const id = boundedText(row.providerLineId, 128);
    if (row.status !== "AVAILABLE" || (databaseDate(row.expiresAt)?.getTime() ?? 0) <= currentTime || lines.has(id)) continue;
    lines.set(id, { providerLineId: id, name: boundedText(row.name, 128) });
  }
  return lines;
}

async function loadManagedRecords(context: Awaited<ReturnType<typeof loadContext>>, lines: Map<string, DnsPodRecordLine>): Promise<ManagedRecord[]> {
  const rows = await queryRaw<Row>(
    `SELECT dr.${q("id")}, dr.${q("routeId")}, dr.${q("providerRecordId")}, dr.${q("fqdn")}, dr.${q("recordType")},
            dr.${q("providerLineId")}, dr.${q("value")}, dr.${q("ttl")}, dr.${q("status")}, dr.${q("remoteTupleHash")},
            r.${q("topologyRevisionId")}, r.${q("lineCategory")},
            r.${q("providerLineId")} AS ${q("routeProviderLineId")},
            r.${q("addressFamily")}, r.${q("address")}
       FROM ${q("xray_quick_config_dns_records")} dr
       JOIN ${q("xray_quick_config_routes")} r ON r.${q("id")} = dr.${q("routeId")}
      WHERE dr.${q("quickConfigId")} = ? AND r.${q("topologyRevisionId")} = ?
        AND dr.${q("dnsAccountId")} = ? AND dr.${q("zoneId")} = ?
        AND dr.${q("status")} IN ('DESIRED', 'APPLIED', 'UNKNOWN') ORDER BY dr.${q("id")} ASC`,
    [context.quickConfigId, context.topologyId, context.accountId, context.zoneId],
  );
  if (rows.length > 64 || rows.length < 1 && !context.compensationOnly) fail("DNS_RECORD_DRIFT", context.quickConfigId);
  return rows.map((row) => {
    const tuple = expectedTuple(row);
    const id = positiveInteger(row.id, "DNS_RECORD_DRIFT");
    const routeId = positiveInteger(row.routeId, "DNS_RECORD_DRIFT");
    const lineCategory = managedLineCategory(row.lineCategory);
    const line = lines.get(tuple.providerLineId);
    const expectedType = row.addressFamily === "IPV4" ? "A" : row.addressFamily === "IPV6" ? "AAAA" : null;
    if (!line || Number(row.topologyRevisionId) !== context.topologyId || row.routeProviderLineId !== tuple.providerLineId
      || expectedType !== tuple.recordType || row.address !== tuple.value || tuple.fqdn !== context.fqdn) {
      fail("DNS_RECORD_DRIFT", context.quickConfigId);
    }
    const status = String(row.status);
    if (status !== "DESIRED" && status !== "APPLIED" && status !== "UNKNOWN") fail("DNS_RECORD_DRIFT", context.quickConfigId);
    return {
      id,
      routeId,
      lineCategory,
      providerRecordId: row.providerRecordId == null ? null : providerRecordId(row.providerRecordId),
      tuple,
      tupleHash: computeXrayQuickConfigDnsTupleHash(tuple),
      status,
      line,
    };
  });
}

async function loadBackups(context: Awaited<ReturnType<typeof loadContext>>, lines: Map<string, DnsPodRecordLine>): Promise<BackupRecord[]> {
  const rows = await queryRaw<Row>(
    `SELECT ${q("id")}, ${q("providerRecordId")}, ${q("fqdn")}, ${q("recordType")}, ${q("providerLineId")},
            ${q("value")}, ${q("ttl")}, ${q("remoteTupleHash")}, ${q("snapshotOrder")}, ${q("state")},
            ${q("dnsAccountId")}, ${q("zoneId")}
       FROM ${q("xray_quick_config_dns_record_backups")}
      WHERE ${q("operationId")} = ? ORDER BY ${q("snapshotOrder")} ASC, ${q("id")} ASC`,
    [context.operationId],
  );
  if (rows.length > 64) fail("DNS_RECORD_DRIFT", context.quickConfigId);
  const orders = new Set<number>();
  return rows.map((row) => {
    const tuple = expectedTuple(row, true);
    const order = Number(row.snapshotOrder);
    const state = String(row.state);
    const line = lines.get(tuple.providerLineId);
    if (Number(row.dnsAccountId) !== context.accountId || Number(row.zoneId) !== context.zoneId
      || tuple.fqdn !== context.fqdn || !Number.isSafeInteger(order) || order < 0 || order >= 64 || orders.has(order)
      || !line || !["CAPTURED", "RESTORING", "RESTORED", "SKIPPED_DRIFTED", "FAILED"].includes(state)) {
      fail("DNS_RECORD_DRIFT", context.quickConfigId);
    }
    orders.add(order);
    return {
      id: positiveInteger(row.id, "DNS_RECORD_DRIFT"),
      providerRecordId: providerRecordId(row.providerRecordId),
      tuple,
      tupleHash: computeXrayQuickConfigDnsTupleHash(tuple),
      snapshotOrder: order,
      state: state as BackupRecord["state"],
      line,
    };
  });
}

async function loadPersistedDnsIntents(operationId: number): Promise<{
  writes: Map<number, DnsWriteIntent>;
  deletes: Array<{ status: string }>;
}> {
  const rows = await queryRaw<Row>(
    `SELECT ${q("kind")}, ${q("subjectId")}, ${q("status")} FROM ${q("xray_quick_config_operation_steps")}
      WHERE ${q("operationId")} = ? AND ${q("kind")} IN ('DNS_CREATE', 'DNS_REPLACE', 'DNS_DELETE')
      ORDER BY ${q("id")} ASC`,
    [operationId],
  );
  const writes = new Map<number, DnsWriteIntent>();
  const deletes: Array<{ status: string }> = [];
  for (const row of rows) {
    const kind = String(row.kind);
    const status = String(row.status);
    if (!["PENDING", "RUNNING", "SUCCESS", "FAILED", "COMPENSATED"].includes(status)) {
      fail("QUICK_CONFIG_OPERATION_CONFLICT");
    }
    if (kind === "DNS_DELETE") {
      deletes.push({ status });
      continue;
    }
    if (kind !== "DNS_CREATE" && kind !== "DNS_REPLACE") fail("QUICK_CONFIG_OPERATION_CONFLICT");
    const subjectId = Number(row.subjectId);
    if (!Number.isSafeInteger(subjectId) || subjectId <= 0 || writes.has(subjectId)) {
      fail("QUICK_CONFIG_OPERATION_CONFLICT");
    }
    writes.set(subjectId, { kind, status });
  }
  return { writes, deletes };
}

async function loadSourceDnsCreateIntents(
  context: Awaited<ReturnType<typeof loadContext>>,
): Promise<Map<number, string>> {
  if (context.operationType !== "RETRY") return new Map();
  const [source] = await queryRaw<Row>(
    `SELECT ${q("quickConfigId")}, ${q("status")} FROM ${q("xray_quick_config_operations")}
      WHERE ${q("id")} = ? LIMIT 1`,
    [context.retryOfOperationId],
  );
  if (!source || Number(source.quickConfigId) !== context.quickConfigId
    || !["FAILED", "PARTIAL_FAILURE"].includes(String(source.status))) {
    fail("QUICK_CONFIG_OPERATION_CONFLICT", context.quickConfigId);
  }
  const rows = await queryRaw<Row>(
    `SELECT ${q("subjectId")}, ${q("status")} FROM ${q("xray_quick_config_operation_steps")}
      WHERE ${q("operationId")} = ? AND ${q("kind")} = 'DNS_CREATE'
        AND ${q("subjectType")} = 'DNS_RECORD' ORDER BY ${q("id")} ASC`,
    [context.retryOfOperationId],
  );
  if (rows.length > 64) fail("QUICK_CONFIG_OPERATION_CONFLICT", context.quickConfigId);
  const intents = new Map<number, string>();
  for (const row of rows) {
    const subjectId = positiveInteger(row.subjectId);
    const status = String(row.status);
    if (intents.has(subjectId) || !["PENDING", "RUNNING", "SUCCESS", "FAILED", "COMPENSATED"].includes(status)) {
      fail("QUICK_CONFIG_OPERATION_CONFLICT", context.quickConfigId);
    }
    intents.set(subjectId, status);
  }
  return intents;
}

async function beginDnsStep(input: {
  context: Awaited<ReturnType<typeof loadContext>>;
  kinds: readonly DnsStepKind[];
  subjectId?: number;
  ordinal?: number;
}): Promise<DnsStep> {
  await assertStillActive(input.context);
  const placeholders = input.kinds.map(() => "?").join(", ");
  const params: unknown[] = [input.context.operationId, ...input.kinds];
  let subject = "";
  if (input.subjectId !== undefined) {
    subject = ` AND ${q("subjectType")} = 'DNS_RECORD' AND ${q("subjectId")} = ?`;
    params.push(String(input.subjectId));
  }
  const rows = await queryRaw<Row>(
    `SELECT ${q("id")}, ${q("kind")}, ${q("status")} FROM ${q("xray_quick_config_operation_steps")}
      WHERE ${q("operationId")} = ? AND ${q("kind")} IN (${placeholders})${subject} ORDER BY ${q("id")} ASC`,
    params,
  );
  const row = rows[input.ordinal ?? 0];
  if (!row || !input.kinds.includes(String(row.kind) as DnsStepKind)
    || !["PENDING", "RUNNING", "SUCCESS", "FAILED", "COMPENSATED"].includes(String(row.status))) {
    fail("QUICK_CONFIG_OPERATION_CONFLICT", input.context.quickConfigId);
  }
  const step: DnsStep = {
    id: positiveInteger(row.id),
    kind: String(row.kind) as DnsStepKind,
    status: String(row.status) as DnsStep["status"],
    context: input.context,
  };
  if (step.status === "FAILED") fail("QUICK_CONFIG_OPERATION_CONFLICT", input.context.quickConfigId);
  if (step.status !== "PENDING") return step;
  const now = nowDate();
  const owned = fenceExistsSql(input.context);
  const updated = await executeRaw(
    `UPDATE ${q("xray_quick_config_operation_steps")}
        SET ${q("status")} = 'RUNNING', ${q("attemptCount")} = ${q("attemptCount")} + 1,
            ${q("startedAt")} = COALESCE(${q("startedAt")}, ?), ${q("finishedAt")} = NULL,
            ${q("errorCode")} = NULL, ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("operationId")} = ? AND ${q("status")} = 'PENDING'
        AND ${owned.sql}`,
    [now, now, step.id, input.context.operationId, ...owned.params],
  );
  if (rawAffectedRows(updated) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT", input.context.quickConfigId);
  step.status = "RUNNING";
  return step;
}

async function finishDnsStep(step: DnsStep, status: "SUCCESS" | "FAILED" | "COMPENSATED", errorCode: string | null = null): Promise<void> {
  if (step.status === status || step.status === "COMPENSATED") return;
  if (step.status === "SUCCESS" && status !== "COMPENSATED") return;
  if (step.status !== "RUNNING" && !(step.status === "SUCCESS" && status === "COMPENSATED")) {
    fail("QUICK_CONFIG_OPERATION_CONFLICT");
  }
  const now = nowDate();
  const owned = fenceExistsSql(step.context);
  const updated = await executeRaw(
    `UPDATE ${q("xray_quick_config_operation_steps")}
        SET ${q("status")} = ?, ${q("finishedAt")} = ?, ${q("errorCode")} = ?, ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("operationId")} = ? AND ${q("status")} = ? AND ${owned.sql}`,
    [status, now, errorCode, now, step.id, step.context.operationId, step.status, ...owned.params],
  );
  if (rawAffectedRows(updated) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  step.status = status;
}

async function markRecordWriteCompensated(context: Awaited<ReturnType<typeof loadContext>>, recordId: number): Promise<void> {
  const now = nowDate();
  const owned = fenceExistsSql(context);
  const result = await executeRaw(
    `UPDATE ${q("xray_quick_config_operation_steps")}
        SET ${q("status")} = 'COMPENSATED', ${q("finishedAt")} = ?, ${q("errorCode")} = NULL, ${q("updatedAt")} = ?
      WHERE ${q("operationId")} = ? AND ${q("subjectType")} = 'DNS_RECORD' AND ${q("subjectId")} = ?
        AND ${q("kind")} IN ('DNS_CREATE', 'DNS_REPLACE') AND ${q("status")} IN ('RUNNING', 'SUCCESS', 'FAILED')
        AND ${owned.sql}`,
    [now, now, context.operationId, String(recordId), ...owned.params],
  );
  if (rawAffectedRows(result) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT", context.quickConfigId);
}

async function markManagedApplied(context: Awaited<ReturnType<typeof loadContext>>, record: ManagedRecord, id: string, now: Date): Promise<void> {
  await assertStillActive(context);
  await withDatabaseTransaction(async () => {
    const owned = fenceExistsSql(context);
    if (context.genericEdit) {
      const conflicting = await queryRaw<Row>(
        `SELECT ${q("id")}, ${q("quickConfigId")}, ${q("status")} FROM ${q("xray_quick_config_dns_records")}
          WHERE ${q("dnsAccountId")} = ? AND ${q("providerRecordId")} = ? AND ${q("id")} <> ? LIMIT 1`,
        [context.accountId, id, record.id],
      );
      const previous = conflicting[0];
      if (previous) {
        if (Number(previous.quickConfigId) !== context.quickConfigId
          || !["APPLIED", "UNKNOWN", "DELETE_PENDING"].includes(String(previous.status))) {
          fail("DNS_RECORD_DRIFT", context.quickConfigId);
        }
        const released = await executeRaw(
          `UPDATE ${q("xray_quick_config_dns_records")}
              SET ${q("providerRecordId")} = NULL, ${q("status")} = 'DELETE_PENDING', ${q("updatedAt")} = ?
            WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("providerRecordId")} = ?
              AND ${q("status")} IN ('APPLIED', 'UNKNOWN', 'DELETE_PENDING') AND ${owned.sql}`,
          [now, positiveInteger(previous.id), context.quickConfigId, id, ...owned.params],
        );
        if (rawAffectedRows(released) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT", context.quickConfigId);
      }
    }
    const currentFence = fenceExistsSql(context);
    const result = await executeRaw(
      `UPDATE ${q("xray_quick_config_dns_records")}
          SET ${q("providerRecordId")} = ?, ${q("status")} = 'APPLIED', ${q("lastVerifiedAt")} = ?, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("remoteTupleHash")} = ?
          AND ${q("status")} IN ('DESIRED', 'APPLIED', 'UNKNOWN') AND ${currentFence.sql}`,
      [id, now, now, record.id, context.quickConfigId, record.tupleHash, ...currentFence.params],
    );
    if (rawAffectedRows(result) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT", context.quickConfigId);
  });
  record.providerRecordId = id;
  record.status = "APPLIED";
}

async function resetManagedRecord(context: Awaited<ReturnType<typeof loadContext>>, record: ManagedRecord, drifted: boolean): Promise<void> {
  const now = nowDate();
  const owned = fenceExistsSql(context);
  const result = await executeRaw(
    `UPDATE ${q("xray_quick_config_dns_records")}
        SET ${q("providerRecordId")} = NULL, ${q("status")} = ?, ${q("lastVerifiedAt")} = NULL, ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("remoteTupleHash")} = ? AND ${owned.sql}`,
    [drifted ? "DRIFTED" : "DESIRED", now, record.id, context.quickConfigId, record.tupleHash, ...owned.params],
  );
  if (rawAffectedRows(result) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT", context.quickConfigId);
  record.providerRecordId = null;
  if (!drifted) record.status = "DESIRED";
}

async function markManagedRecordUnknown(context: Awaited<ReturnType<typeof loadContext>>, record: ManagedRecord): Promise<void> {
  const now = nowDate();
  const owned = fenceExistsSql(context);
  const result = await executeRaw(
    `UPDATE ${q("xray_quick_config_dns_records")}
        SET ${q("status")} = 'UNKNOWN', ${q("lastVerifiedAt")} = NULL, ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("providerRecordId")} = ?
        AND ${q("remoteTupleHash")} = ? AND ${owned.sql}`,
    [now, record.id, context.quickConfigId, record.providerRecordId, record.tupleHash, ...owned.params],
  );
  if (rawAffectedRows(result) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT", context.quickConfigId);
  record.status = "UNKNOWN";
}

async function markBackup(context: DnsExecutionContext, backup: BackupRecord, state: BackupRecord["state"]): Promise<void> {
  const now = nowDate();
  const owned = fenceExistsSql(context);
  const result = await executeRaw(
    `UPDATE ${q("xray_quick_config_dns_record_backups")} SET ${q("state")} = ?, ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("operationId")} = ? AND ${owned.sql}`,
    [state, now, backup.id, context.operationId, ...owned.params],
  );
  if (rawAffectedRows(result) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  backup.state = state;
}

async function updateBackupProviderRecordId(
  context: DnsExecutionContext,
  backup: BackupRecord,
  restoredProviderRecordId: string,
): Promise<void> {
  const restoredId = providerRecordId(restoredProviderRecordId);
  if (restoredId === backup.providerRecordId) return;
  const now = nowDate();
  const owned = fenceExistsSql(context);
  const changed = await executeRaw(
    `UPDATE ${q("xray_quick_config_dns_record_backups")}
        SET ${q("providerRecordId")} = ?, ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("operationId")} = ? AND ${q("providerRecordId")} = ?
        AND ${q("remoteTupleHash")} = ? AND ${q("state")} = 'RESTORING' AND ${owned.sql}`,
    [restoredId, now, backup.id, context.operationId, backup.providerRecordId, backup.tupleHash, ...owned.params],
  );
  if (rawAffectedRows(changed) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT", context.quickConfigId);
  backup.providerRecordId = restoredId;
}

async function updateAndVerify(
  client: DnsClient,
  context: Awaited<ReturnType<typeof loadContext>>,
  id: string,
  line: DnsPodRecordLine,
  tuple: XrayQuickConfigDnsTuple,
): Promise<DnsPodRecord> {
  await assertStillActive(context);
  try {
    const response = await client.updateRecord({ ...writeInput(context.zone, context.relativeName, line, tuple), providerRecordId: id });
    if (response.providerRecordId !== id) fail("DNS_RECORD_DRIFT", context.quickConfigId);
  } catch (error) {
    if (!(error instanceof DnsPodProviderError) || !error.ambiguousWrite) throw error;
  }
  const remote = await remoteRecord(client, context.zone, id);
  if (!remote || !tupleMatches(remote, tuple, context.relativeName)) fail("DNS_RECORD_DRIFT", context.quickConfigId);
  return remote;
}

async function deleteAndVerify(
  client: DnsClient,
  context: Awaited<ReturnType<typeof loadContext>>,
  id: string,
  tuple: XrayQuickConfigDnsTuple,
): Promise<void> {
  const current = await remoteRecord(client, context.zone, id);
  if (!current) return;
  if (!tupleMatches(current, tuple, context.relativeName)) fail("DNS_RECORD_DRIFT", context.quickConfigId);
  await assertStillActive(context);
  try {
    await client.deleteRecord({ zone: context.zone, providerRecordId: id });
  } catch (error) {
    if (!(error instanceof DnsPodProviderError) || !error.ambiguousWrite) throw error;
  }
  if (await remoteRecord(client, context.zone, id)) fail("DNS_RECORD_DRIFT", context.quickConfigId);
}

async function listedManagedRecord(
  client: DnsClient,
  context: Awaited<ReturnType<typeof loadContext>>,
  record: ManagedRecord,
  expectedProviderRecordId: string | null,
): Promise<DnsPodRecord | null> {
  const exact = (await client.listRecords({ zone: context.zone, subdomain: context.relativeName }))
    .filter((candidate) => tupleMatches(candidate, record.tuple, context.relativeName));
  if (exact.length > 1) fail("DNS_RECORD_DRIFT", context.quickConfigId);
  if (exact.length === 0) return null;
  const id = providerRecordId(exact[0].providerRecordId);
  if (expectedProviderRecordId !== null && id !== expectedProviderRecordId) {
    fail("DNS_RECORD_DRIFT", context.quickConfigId);
  }
  return exact[0];
}

async function createAndVerify(
  client: DnsClient,
  context: Awaited<ReturnType<typeof loadContext>>,
  record: ManagedRecord,
): Promise<string> {
  await assertStillActive(context);
  let createdId: string | null = null;
  try {
    createdId = (await client.createRecord(writeInput(context.zone, context.relativeName, record.line, record.tuple))).providerRecordId;
  } catch (error) {
    if (!(error instanceof DnsPodProviderError) || !error.ambiguousWrite) throw error;
  }
  const expectedId = createdId === null ? null : providerRecordId(createdId);
  const visible = await waitForQuickConfigDnsVisibility(
    () => listedManagedRecord(client, context, record, expectedId),
  );
  if (!visible) fail("DNS_RECORD_DRIFT", context.quickConfigId);
  return providerRecordId(visible.providerRecordId);
}

async function restoreBackup(
  client: DnsClient,
  context: Awaited<ReturnType<typeof loadContext>>,
  backup: BackupRecord,
  desiredByProviderId: Map<string, ManagedRecord>,
): Promise<"RESTORED" | "DRIFTED" | "FAILED"> {
  await markBackup(context, backup, "RESTORING");
  try {
    const originalProviderRecordId = backup.providerRecordId;
    const desired = desiredByProviderId.get(originalProviderRecordId);
    const current = await remoteRecord(client, context.zone, originalProviderRecordId);
    if (current && tupleMatches(current, backup.tuple, context.relativeName)) {
      if (desired) await resetManagedRecord(context, desired, false);
      await markBackup(context, backup, "RESTORED");
      return "RESTORED";
    }
    if (current) {
      if (!desired || !tupleMatches(current, desired.tuple, context.relativeName)) {
        await markBackup(context, backup, "SKIPPED_DRIFTED");
        return "DRIFTED";
      }
      await updateAndVerify(client, context, originalProviderRecordId, backup.line, backup.tuple);
      await resetManagedRecord(context, desired, false);
      await markBackup(context, backup, "RESTORED");
      return "RESTORED";
    }
    const existing = (await client.listRecords({ zone: context.zone, subdomain: context.relativeName }))
      .filter((candidate) => tupleMatches(candidate, backup.tuple, context.relativeName));
    if (existing.length > 1) {
      await markBackup(context, backup, "SKIPPED_DRIFTED");
      return "DRIFTED";
    }
    let restoredId = existing.length === 1 ? providerRecordId(existing[0].providerRecordId) : null;
    if (!restoredId) {
      try {
        restoredId = (await client.createRecord(writeInput(context.zone, context.relativeName, backup.line, backup.tuple))).providerRecordId;
      } catch (error) {
        if (!(error instanceof DnsPodProviderError) || !error.ambiguousWrite) throw error;
      }
      if (restoredId) {
        const restored = await remoteRecord(client, context.zone, restoredId);
        if (!restored || !tupleMatches(restored, backup.tuple, context.relativeName)) fail("DNS_RECORD_DRIFT");
      } else {
        const retried = (await client.listRecords({ zone: context.zone, subdomain: context.relativeName }))
          .filter((candidate) => tupleMatches(candidate, backup.tuple, context.relativeName));
        if (retried.length !== 1) fail("DNS_RECORD_DRIFT");
        restoredId = providerRecordId(retried[0].providerRecordId);
      }
    }
    if (!restoredId) fail("DNS_RECORD_DRIFT", context.quickConfigId);
    await updateBackupProviderRecordId(context, backup, restoredId);
    if (desired) await resetManagedRecord(context, desired, false);
    await markBackup(context, backup, "RESTORED");
    return "RESTORED";
  } catch (error) {
    if (isFenceLoss(error)) throw error;
    if (error instanceof DnsApplyError && error.code === "DNS_RECORD_DRIFT") {
      await markBackup(context, backup, "SKIPPED_DRIFTED").catch(() => undefined);
      return "DRIFTED";
    }
    await markBackup(context, backup, "FAILED").catch(() => undefined);
    return "FAILED";
  }
}

async function compensate(
  client: DnsClient,
  context: Awaited<ReturnType<typeof loadContext>>,
  managed: ManagedRecord[],
  backups: BackupRecord[],
  changes: AppliedChange[],
  compensateAll: boolean,
): Promise<{ partial: boolean; count: number }> {
  let partial = false;
  let count = 0;
  const changedCreated = new Map<number, Extract<AppliedChange, { kind: "CREATED" }>>();
  const changedBackups = new Map<number, BackupRecord>();
  for (const change of changes) {
    if (change.kind === "CREATED") changedCreated.set(change.record.id, change);
    else changedBackups.set(change.backup.id, change.backup);
  }
  if (compensateAll) {
    for (const record of managed) {
      if (!record.providerRecordId || backups.some((backup) => backup.providerRecordId === record.providerRecordId)) continue;
      changedCreated.set(record.id, { kind: "CREATED", record, providerRecordId: record.providerRecordId });
    }
    for (const backup of backups) changedBackups.set(backup.id, backup);
  }
  let restoreOrdinal = 0;
  for (const change of [...changedCreated.values()].reverse()) {
    let restoreStep: DnsStep | null = null;
    try {
      restoreStep = await beginDnsStep({ context, kinds: ["DNS_RESTORE"], ordinal: restoreOrdinal });
      restoreOrdinal += 1;
      const current = await remoteRecord(client, context.zone, change.providerRecordId);
      if (restoreStep.status === "SUCCESS") {
        if (current) fail("DNS_RECORD_DRIFT", context.quickConfigId);
        await resetManagedRecord(context, change.record, false);
        await markRecordWriteCompensated(context, change.record.id);
        count += 1;
        continue;
      }
      if (current && !tupleMatches(current, change.record.tuple, context.relativeName)) {
        await resetManagedRecord(context, change.record, true);
        await finishDnsStep(restoreStep, "FAILED", "DNS_RECORD_DRIFT").catch(() => undefined);
        partial = true;
        continue;
      }
      if (current) await deleteAndVerify(client, context, change.providerRecordId, change.record.tuple);
      await resetManagedRecord(context, change.record, false);
      await markRecordWriteCompensated(context, change.record.id);
      await finishDnsStep(restoreStep, "SUCCESS");
      count += 1;
    } catch (error) {
      if (isFenceLoss(error)) throw error;
      if (restoreStep) await finishDnsStep(restoreStep, "FAILED", stableProviderError(error)).catch(() => undefined);
      // A transient/ambiguous provider failure must retain the provider identity so a
      // later compensation retry can prove exactly which managed record it may remove.
      await markManagedRecordUnknown(context, change.record).catch(() => undefined);
      partial = true;
    }
  }
  const desiredByProviderId = new Map(managed.flatMap((record) => record.providerRecordId ? [[record.providerRecordId, record] as const] : []));
  for (const backup of [...changedBackups.values()].sort((left, right) => right.snapshotOrder - left.snapshotOrder)) {
    let restoreStep: DnsStep | null = null;
    try {
      restoreStep = await beginDnsStep({ context, kinds: ["DNS_RESTORE"], ordinal: restoreOrdinal });
      restoreOrdinal += 1;
      if (restoreStep.status === "SUCCESS") {
        const current = await remoteRecord(client, context.zone, backup.providerRecordId);
        const exact = current && tupleMatches(current, backup.tuple, context.relativeName)
          ? [current]
          : (await client.listRecords({ zone: context.zone, subdomain: context.relativeName }))
            .filter((candidate) => tupleMatches(candidate, backup.tuple, context.relativeName));
        if (exact.length !== 1) fail("DNS_RECORD_DRIFT", context.quickConfigId);
        await markBackup(context, backup, "RESTORED");
        count += 1;
        continue;
      }
      const desired = desiredByProviderId.get(backup.providerRecordId);
      const restored = await restoreBackup(client, context, backup, desiredByProviderId);
      if (restored === "RESTORED") {
        if (desired) await markRecordWriteCompensated(context, desired.id);
        await finishDnsStep(restoreStep, "SUCCESS");
        count += 1;
      } else {
        await finishDnsStep(restoreStep, "FAILED", restored === "DRIFTED" ? "DNS_RECORD_DRIFT" : "DNS_COMPENSATION_FAILED")
          .catch(() => undefined);
        partial = true;
      }
    } catch (error) {
      if (isFenceLoss(error)) throw error;
      if (restoreStep) await finishDnsStep(restoreStep, "FAILED", stableProviderError(error)).catch(() => undefined);
      partial = true;
    }
  }
  return { partial, count };
}

async function executeApply(
  context: Awaited<ReturnType<typeof loadContext>>,
  client: DnsClient,
  managed: ManagedRecord[],
  backups: BackupRecord[],
  now: Date,
): Promise<QuickConfigDnsApplyResult> {
  const changes: AppliedChange[] = [];
  const orderedManaged = orderQuickConfigDnsWrites(managed);
  const remote = await client.listRecords({ zone: context.zone, subdomain: context.relativeName });
  const byId = new Map(remote.map((record) => [record.providerRecordId, record]));
  const managedIds = new Map<string, ManagedRecord>();
  for (const record of managed) if (record.providerRecordId) managedIds.set(record.providerRecordId, record);
  const backupById = new Map(backups.map((backup) => [backup.providerRecordId, backup]));
  const intents = await loadPersistedDnsIntents(context.operationId);
  const sourceCreateIntents = await loadSourceDnsCreateIntents(context);
  const claimedRows = await queryRaw<Row>(
    `SELECT dr.${q("id")}, dr.${q("providerRecordId")}, dr.${q("quickConfigId")}, r.${q("topologyRevisionId")}
       FROM ${q("xray_quick_config_dns_records")} dr
       JOIN ${q("xray_quick_config_routes")} r ON r.${q("id")} = dr.${q("routeId")}
      WHERE dr.${q("dnsAccountId")} = ? AND dr.${q("providerRecordId")} IS NOT NULL`,
    [context.accountId],
  );
  const claimed = new Map(claimedRows.map((row) => [String(row.providerRecordId), {
    recordId: Number(row.id),
    quickConfigId: Number(row.quickConfigId),
    topologyRevisionId: Number(row.topologyRevisionId),
  }]));
  const recoverableRecords = new Set<number>();
  for (const current of remote) {
    if (current.recordType !== "A" && current.recordType !== "AAAA" && current.recordType !== "CNAME") continue;
    const currentId = providerRecordId(current.providerRecordId);
    const backup = backupById.get(currentId);
    const desired = managedIds.get(currentId);
    if (backup && (tupleMatches(current, backup.tuple, context.relativeName)
      || !!desired && tupleMatches(current, desired.tuple, context.relativeName))) continue;
    if (desired && tupleMatches(current, desired.tuple, context.relativeName)) continue;
    const candidates = managed.filter((record) => {
      if (record.providerRecordId || recoverableRecords.has(record.id)
        || !tupleMatches(current, record.tuple, context.relativeName)) return false;
      const intent = intents.writes.get(record.id);
      return intent?.kind === "DNS_CREATE" && hasQuickConfigDnsCreateOwnershipEvidence({
        currentIntent: intent,
        sourceCreateStatus: sourceCreateIntents.get(record.id) ?? null,
      });
    });
    const owner = claimed.get(currentId);
    if (candidates.length !== 1 || owner !== undefined && owner.recordId !== candidates[0].id) {
      fail("DNS_RECORD_DRIFT", context.quickConfigId);
    }
    recoverableRecords.add(candidates[0].id);
  }

  const deleteBackups = backups.filter((backup) => !managedIds.has(backup.providerRecordId));

  for (const backup of backups) {
    const current = byId.get(backup.providerRecordId);
    if (!current) {
      const deleteOrdinal = deleteBackups.findIndex((candidate) => candidate.id === backup.id);
      const deleteIntent = deleteOrdinal >= 0 ? intents.deletes[deleteOrdinal] : undefined;
      if (!deleteIntent || deleteIntent.status !== "RUNNING" && deleteIntent.status !== "SUCCESS") {
        fail("DNS_RECORD_DRIFT", context.quickConfigId);
      }
      continue;
    }
    const desired = managedIds.get(backup.providerRecordId);
    if (!tupleMatches(current, backup.tuple, context.relativeName)
      && (!desired || !tupleMatches(current, desired.tuple, context.relativeName))) {
      fail("DNS_RECORD_DRIFT", context.quickConfigId);
    }
  }
  for (const record of managed) {
    if (!record.providerRecordId) continue;
    const current = byId.get(record.providerRecordId);
    const backup = backupById.get(record.providerRecordId);
    if (!current) fail("DNS_RECORD_DRIFT", context.quickConfigId);
    if (current && !tupleMatches(current, record.tuple, context.relativeName)
      && (!backup || !tupleMatches(current, backup.tuple, context.relativeName))) {
      fail("DNS_RECORD_DRIFT", context.quickConfigId);
    }
  }

  const availableBackups = backups.filter((backup) => {
    const current = byId.get(backup.providerRecordId);
    return !!current && tupleMatches(current, backup.tuple, context.relativeName);
  });
  const usedBackupIds = new Set<number>();
  const protectedProviderIds = new Set<string>();
  // Do not let an earlier replacement consume a later exact record. This is
  // derived from the live snapshot, never from the browser's preview action.
  const exactProviderIds = new Set(context.genericEdit ? remote.filter(candidate => managed.some(record =>
    tupleMatches(candidate, record.tuple, context.relativeName))).map(candidate => candidate.providerRecordId) : []);

  try {
    for (const record of orderedManaged) {
      const writeStep = await beginDnsStep({ context, kinds: ["DNS_CREATE", "DNS_REPLACE"], subjectId: record.id });
      let id = record.providerRecordId;
      try {
        const current = id ? await remoteRecord(client, context.zone, id) : null;
        if (current && tupleMatches(current, record.tuple, context.relativeName)) {
          protectedProviderIds.add(id!);
          const matchingBackup = backupById.get(id!);
          if (matchingBackup) usedBackupIds.add(matchingBackup.id);
        } else {
          const exact = (await client.listRecords({ zone: context.zone, subdomain: context.relativeName }))
            .filter((candidate) => tupleMatches(candidate, record.tuple, context.relativeName));
          if (exact.length > 1) fail("DNS_RECORD_DRIFT", context.quickConfigId);
          if (exact.length === 1) {
            const exactId = providerRecordId(exact[0].providerRecordId);
            const owner = claimed.get(exactId);
            const provenEditReplacement = context.genericEdit && writeStep.kind === "DNS_REPLACE"
              && backupById.has(exactId) && owner?.quickConfigId === context.quickConfigId
              && owner.topologyRevisionId !== context.topologyId;
            const provenCreate = writeStep.kind === "DNS_CREATE" && hasQuickConfigDnsCreateOwnershipEvidence({
              currentIntent: intents.writes.get(record.id) ?? null,
              sourceCreateStatus: sourceCreateIntents.get(record.id) ?? null,
            });
            if (exactId !== id && !provenEditReplacement
              && !provenCreate) {
              fail("DNS_RECORD_DRIFT", context.quickConfigId);
            }
            id = exactId;
            if (owner !== undefined && owner.recordId !== record.id && !provenEditReplacement) {
              fail("DNS_RECORD_DRIFT", context.quickConfigId);
            }
            protectedProviderIds.add(id);
            const matchingBackup = backupById.get(id);
            if (matchingBackup) usedBackupIds.add(matchingBackup.id);
          } else if (writeStep.status === "SUCCESS") {
            fail("DNS_RECORD_DRIFT", context.quickConfigId);
          } else if (writeStep.kind === "DNS_REPLACE") {
            const candidates = availableBackups.filter(candidate => !usedBackupIds.has(candidate.id)
              && (!context.genericEdit || (!exactProviderIds.has(candidate.providerRecordId)
                && candidate.tuple.recordType === record.tuple.recordType)));
            const backup = (id ? backupById.get(id) : undefined)
              ?? (context.genericEdit ? candidates.find(candidate => candidate.tuple.providerLineId === record.tuple.providerLineId) : undefined)
              ?? candidates[0];
            if (!backup || exactProviderIds.has(backup.providerRecordId)) fail("DNS_RECORD_DRIFT", context.quickConfigId);
            const source = await remoteRecord(client, context.zone, backup.providerRecordId);
            if (!source || !tupleMatches(source, backup.tuple, context.relativeName)) fail("DNS_RECORD_DRIFT", context.quickConfigId);
            await updateAndVerify(client, context, backup.providerRecordId, record.line, record.tuple);
            id = backup.providerRecordId;
            usedBackupIds.add(backup.id);
            protectedProviderIds.add(id);
            changes.push({ kind: "REPLACED", record, backup, providerRecordId: id });
          } else {
            id = await createAndVerify(client, context, record);
            const owner = claimed.get(id);
            if (owner !== undefined && owner.recordId !== record.id) fail("DNS_RECORD_DRIFT", context.quickConfigId);
            protectedProviderIds.add(id);
            changes.push({ kind: "CREATED", record, providerRecordId: id });
          }
        }
        await finishDnsStep(writeStep, "SUCCESS");
      } catch (error) {
        await finishDnsStep(writeStep, "FAILED", stableProviderError(error)).catch(() => undefined);
        throw error;
      }
      const verifyStep = await beginDnsStep({ context, kinds: ["DNS_VERIFY"], subjectId: record.id });
      try {
        if (!id) fail("DNS_RECORD_DRIFT", context.quickConfigId);
        const verified = await listedManagedRecord(client, context, record, id);
        if (!verified) fail("DNS_RECORD_DRIFT", context.quickConfigId);
        await markManagedApplied(context, record, id, now);
        await finishDnsStep(verifyStep, "SUCCESS");
      } catch (error) {
        await finishDnsStep(verifyStep, "FAILED", stableProviderError(error)).catch(() => undefined);
        throw error;
      }
    }
    let deleteOrdinal = 0;
    for (const backup of backups) {
      if (protectedProviderIds.has(backup.providerRecordId)) continue;
      const deleteStep = await beginDnsStep({ context, kinds: ["DNS_DELETE"], ordinal: deleteOrdinal });
      deleteOrdinal += 1;
      try {
        const current = await remoteRecord(client, context.zone, backup.providerRecordId);
        if (current && deleteStep.status === "SUCCESS") fail("DNS_RECORD_DRIFT", context.quickConfigId);
        if (current) await deleteAndVerify(client, context, backup.providerRecordId, backup.tuple);
        changes.push({ kind: "DELETED_BACKUP", backup });
        await finishDnsStep(deleteStep, "SUCCESS");
      } catch (error) {
        await finishDnsStep(deleteStep, "FAILED", stableProviderError(error)).catch(() => undefined);
        throw error;
      }
    }
    await assertStillActive(context);
    for (const record of managed) {
      const id = record.providerRecordId;
      if (!id) fail("DNS_RECORD_DRIFT", context.quickConfigId);
      const verified = await listedManagedRecord(client, context, record, id);
      if (!verified) fail("DNS_RECORD_DRIFT", context.quickConfigId);
      await markManagedApplied(context, record, id, now);
    }
    return {
      status: "SUCCESS",
      operationId: context.operationId,
      quickConfigId: context.quickConfigId,
      appliedRecordCount: managed.length,
      verifiedRecordCount: managed.length,
    };
  } catch (error) {
    if (isFenceLoss(error)) throw error;
    const compensation = await compensate(client, context, managed, backups, changes, true);
    return {
      status: compensation.partial ? "PARTIAL_FAILURE" : "FAILED",
      operationId: context.operationId,
      quickConfigId: context.quickConfigId,
      errorCode: compensation.partial ? "DNS_COMPENSATION_FAILED" : stableProviderError(error),
      compensatedRecordCount: compensation.count,
    };
  }
}

export async function applyQuickConfigDnsOperation(
  operationIdValue: unknown,
  expectedFenceValue: QuickConfigDnsExecutionFence,
  options: QuickConfigDnsApplyOptions = {},
): Promise<QuickConfigDnsApplyResult> {
  let operationId: number;
  let expectedFence: QuickConfigDnsExecutionFence;
  try {
    operationId = positiveInteger(operationIdValue);
    const executionOwnerId = boundedText(expectedFenceValue?.executionOwnerId, 128);
    expectedFence = {
      executionOwnerId,
      executionFence: positiveInteger(expectedFenceValue?.executionFence),
    };
  } catch (error) {
    return { status: "FAILED", operationId: 0, quickConfigId: null, errorCode: stableProviderError(error), compensatedRecordCount: 0 };
  }
  return withKeyedTaskLock(`xray-quick-config-dns:${operationId}`, async () => {
    let quickConfigId: number | null = null;
    try {
      const now = validNow(options);
      const context = await loadContext(operationId, expectedFence, now);
      quickConfigId = context.quickConfigId;
      if (!context.compensationOnly) await assertRulesReady(context);
      const credentials = await loadGlobalDnsProviderCredentials();
      if (credentials.accountId !== context.accountId) fail("DNS_PROVIDER_CONFLICT", context.quickConfigId);
      const lines = await loadLines(context.zoneId, now);
      const [managed, backups] = await Promise.all([
        loadManagedRecords(context, lines),
        loadBackups(context, lines),
      ]);
      const rawClient = options.clientFactory?.({ secretId: credentials.secretId, secretKey: credentials.secretKey })
        ?? new DnsPodProviderClient({ credentials: { secretId: credentials.secretId, secretKey: credentials.secretKey } });
      const client = fencedDnsClient(rawClient, context);
      if (context.compensationOnly) {
        const compensation = await compensate(client, context, managed, backups, [], true);
        return {
          status: compensation.partial ? "PARTIAL_FAILURE" : "FAILED",
          operationId,
          quickConfigId,
          errorCode: compensation.partial ? "DNS_COMPENSATION_FAILED" : "DNS_PROVIDER_CATALOG_STALE",
          compensatedRecordCount: compensation.count,
          compensationComplete: !compensation.partial,
        };
      }
      return await executeApply(context, client, managed, backups, now);
    } catch (error) {
      return {
        status: "FAILED",
        operationId,
        quickConfigId: error instanceof DnsApplyError ? error.quickConfigId ?? quickConfigId : quickConfigId,
        errorCode: stableProviderError(error),
        compensatedRecordCount: 0,
      };
    }
  });
}
