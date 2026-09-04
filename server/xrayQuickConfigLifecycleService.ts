import crypto from "node:crypto";

import { pushAgentRefresh } from "./agentEvents";
import { quoteIdentifier } from "./dbCompat";
import {
  afterDatabaseCommit,
  executeRaw,
  insertAndGetId,
  nowDate,
  queryRaw,
  rawAffectedRows,
  withDatabaseTransaction,
} from "./dbRuntime";
import { DnsPodProviderClient, DnsPodProviderError, type DnsPodRecord, type DnsPodZone } from "./dnsPodProviderClient";
import { ENV } from "./env";
import { releaseGlobalPortReferenceAfterRuntimeCleanup, type GlobalPortReferenceInput } from "./globalPortAllocationService";
import { withKeyedTaskLock } from "./keyedTaskLock";
import { finalizeForwardRuleDelete, markForwardRulePendingDelete } from "./repositories/forwardRuleRepository";
import { loadGlobalDnsProviderCredentials } from "./repositories/dnsProviderRepository";
import { computeXrayQuickConfigDnsTupleHash, type XrayQuickConfigDnsTuple } from "./xrayQuickConfigDnsTuple";
import { listXrayQuickConfigEntryHosts } from "./xrayQuickConfigEntryHosts";

type Row = Record<string, unknown>;
type RemoveRecord = {
  id: number;
  recordRef: string;
  providerRecordId: string;
  recordType: "A" | "AAAA";
  providerLineId: string;
  value: string;
  ttl: number;
  tupleHash: string;
};
type RemoveRule = { ruleId: number; hostId: number; name: string };
type RemoveSnapshot = {
  id: number;
  revision: number;
  fqdn: string;
  relativeName: string;
  configTag: string;
  dnsAccountId: number;
  zoneId: number;
  topologyId: number;
  allocationId: number;
  allocationVersion: number;
  allocationNextState: "RELEASING" | "ACTIVE";
  records: RemoveRecord[];
  rules: RemoveRule[];
  planHash: string;
};
type RemoveTokenPayload = {
  v: 1;
  kind: "REMOVE";
  nonce: string;
  userId: number;
  quickConfigId: number;
  revision: number;
  fqdn: string;
  planHash: string;
  issuedAt: number;
  expiresAt: number;
};
type DnsDeleteIntent = Readonly<{
  kind: "QUICK_CONFIG_DNS_DELETE";
  providerRecordId: string;
  tupleHash: string;
}>;

export type QuickConfigRemovePreview = Readonly<{
  quickConfigId: number;
  revision: number;
  fqdn: string;
  dnsRecords: Array<Readonly<{
    recordRef: string;
    recordType: "A" | "AAAA";
    providerLineId: string;
    value: string;
    action: "DELETE";
  }>>;
  rules: Array<Readonly<{ ruleId: number; hostId: number; name: string; action: "REMOVE" }>>;
  allocation: Readonly<{ port: number; nextState: "RELEASING" | "ACTIVE" }>;
  warnings: Array<Readonly<{ code: string; message: string }>>;
  removeToken: string;
  expiresAt: string;
}>;

export const QUICK_CONFIG_LIFECYCLE_ERROR_CODES = [
  "QUICK_CONFIG_NOT_FOUND",
  "QUICK_CONFIG_REVISION_CONFLICT",
  "QUICK_CONFIG_OPERATION_CONFLICT",
  "QUICK_CONFIG_REMOVE_TOKEN_INVALID",
  "QUICK_CONFIG_REMOVE_TOKEN_EXPIRED",
  "DNS_RECORD_DRIFT",
  "DNS_PROVIDER_CONFLICT",
  "DNS_PROVIDER_VALIDATION_STALE",
  "SENSITIVE_DATA_UNAVAILABLE",
  "HOST_OFFLINE",
  "AGENT_CAPABILITY_MISSING",
  "UDP_CAPABILITY_REQUIRED",
  "QUICK_CONFIG_HOST_UNAVAILABLE",
  "RULE_CLEANUP_FAILED",
  "DNS_COMPENSATION_FAILED",
] as const;
export type QuickConfigLifecycleErrorCode = typeof QUICK_CONFIG_LIFECYCLE_ERROR_CODES[number];

export class XrayQuickConfigLifecycleError extends Error {
  constructor(readonly code: QuickConfigLifecycleErrorCode) {
    super(code);
    this.name = "XrayQuickConfigLifecycleError";
  }
}

type LifecycleOptions = Readonly<{ now?: () => Date; tokenSecret?: string }>;
const q = quoteIdentifier;
const REMOVE_TOKEN_TTL_MS = 5 * 60_000;
const MAX_TOKEN_BYTES = 32 * 1024;
const TOKEN_CONTEXT = "forwardx-xray-quick-config-remove-token:v1";
const TOKEN_PART = /^[A-Za-z0-9_-]+$/;

function fail(code: QuickConfigLifecycleErrorCode): never {
  throw new XrayQuickConfigLifecycleError(code);
}

function positiveInteger(value: unknown, code: QuickConfigLifecycleErrorCode = "QUICK_CONFIG_NOT_FOUND"): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) fail(code);
  return parsed;
}

function nullablePositiveInteger(value: unknown): number | null {
  return value === null || value === undefined || value === "" ? null : positiveInteger(value, "QUICK_CONFIG_OPERATION_CONFLICT");
}

function boundedText(value: unknown, maximum: number, code: QuickConfigLifecycleErrorCode): string {
  if (typeof value !== "string" || !value || Buffer.byteLength(value, "utf8") > maximum
    || /[\u0000-\u001f\u007f]/.test(value)) fail(code);
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

function resolvedNow(options: LifecycleOptions): Date {
  const value = options.now?.() ?? new Date();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) fail("QUICK_CONFIG_REMOVE_TOKEN_INVALID");
  return new Date(value);
}

function stableValue(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(stableValue);
  if (!value || typeof value !== "object") fail("QUICK_CONFIG_REMOVE_TOKEN_INVALID");
  const output: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    const entry = (value as Record<string, unknown>)[key];
    if (entry === undefined) fail("QUICK_CONFIG_REMOVE_TOKEN_INVALID");
    output[key] = stableValue(entry);
  }
  return output;
}

function stableJson(value: unknown): string {
  return JSON.stringify(stableValue(value));
}

function dnsDeleteIntent(record: RemoveRecord): DnsDeleteIntent {
  return {
    kind: "QUICK_CONFIG_DNS_DELETE",
    providerRecordId: record.providerRecordId,
    tupleHash: record.tupleHash,
  };
}

function parseDnsDeleteIntent(value: unknown, record: RemoveRecord): DnsDeleteIntent | null {
  try {
    const parsed = JSON.parse(String(value ?? "")) as Record<string, unknown>;
    if (parsed.kind !== "QUICK_CONFIG_DNS_DELETE"
      || parsed.providerRecordId !== record.providerRecordId
      || !secureHashEqual(parsed.tupleHash, record.tupleHash)) return null;
    return dnsDeleteIntent(record);
  } catch {
    return null;
  }
}

function sha256(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function secureHashEqual(left: unknown, right: unknown): boolean {
  if (typeof left !== "string" || typeof right !== "string" || !/^[a-f0-9]{64}$/.test(left)
    || !/^[a-f0-9]{64}$/.test(right)) return false;
  return crypto.timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function tokenKey(secret = ENV.cookieSecret): Buffer {
  if (typeof secret !== "string" || Buffer.byteLength(secret, "utf8") < 16) fail("SENSITIVE_DATA_UNAVAILABLE");
  return crypto.createHmac("sha256", secret).update(TOKEN_CONTEXT, "utf8").digest();
}

function signRemoveToken(payload: RemoveTokenPayload, options: LifecycleOptions): string {
  const body = Buffer.from(stableJson(payload), "utf8").toString("base64url");
  const unsigned = `qcr1.${body}`;
  const signature = crypto.createHmac("sha256", tokenKey(options.tokenSecret)).update(unsigned, "utf8").digest("base64url");
  const token = `${unsigned}.${signature}`;
  if (Buffer.byteLength(token, "utf8") > MAX_TOKEN_BYTES) fail("QUICK_CONFIG_REMOVE_TOKEN_INVALID");
  return token;
}

function parseRemoveToken(raw: unknown, options: LifecycleOptions): RemoveTokenPayload {
  if (typeof raw !== "string" || Buffer.byteLength(raw, "utf8") > MAX_TOKEN_BYTES) fail("QUICK_CONFIG_REMOVE_TOKEN_INVALID");
  const parts = raw.split(".");
  if (parts.length !== 3 || parts[0] !== "qcr1" || !TOKEN_PART.test(parts[1]) || !TOKEN_PART.test(parts[2])) {
    fail("QUICK_CONFIG_REMOVE_TOKEN_INVALID");
  }
  const unsigned = `${parts[0]}.${parts[1]}`;
  const expected = crypto.createHmac("sha256", tokenKey(options.tokenSecret)).update(unsigned, "utf8").digest();
  const actual = Buffer.from(parts[2], "base64url");
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) fail("QUICK_CONFIG_REMOVE_TOKEN_INVALID");
  let parsed: unknown;
  try { parsed = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")); } catch { fail("QUICK_CONFIG_REMOVE_TOKEN_INVALID"); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) fail("QUICK_CONFIG_REMOVE_TOKEN_INVALID");
  const value = parsed as Record<string, unknown>;
  if (value.v !== 1 || value.kind !== "REMOVE" || typeof value.nonce !== "string"
    || !/^[A-Za-z0-9_-]{22}$/.test(value.nonce) || !Number.isSafeInteger(value.userId)
    || !Number.isSafeInteger(value.quickConfigId) || !Number.isSafeInteger(value.revision)
    || typeof value.fqdn !== "string" || typeof value.planHash !== "string"
    || !Number.isSafeInteger(value.issuedAt) || !Number.isSafeInteger(value.expiresAt)) {
    fail("QUICK_CONFIG_REMOVE_TOKEN_INVALID");
  }
  const now = resolvedNow(options).getTime();
  if (Number(value.expiresAt) <= now) fail("QUICK_CONFIG_REMOVE_TOKEN_EXPIRED");
  if (Number(value.issuedAt) > now + 30_000 || Number(value.expiresAt) - Number(value.issuedAt) > REMOVE_TOKEN_TTL_MS
    || !/^[a-f0-9]{64}$/.test(String(value.planHash))) fail("QUICK_CONFIG_REMOVE_TOKEN_INVALID");
  return value as unknown as RemoveTokenPayload;
}

function recordTuple(row: Row): XrayQuickConfigDnsTuple {
  const recordType = row.recordType === "A" || row.recordType === "AAAA" ? row.recordType : fail("DNS_RECORD_DRIFT");
  const tuple = {
    fqdn: boundedText(row.fqdn, 253, "DNS_RECORD_DRIFT").toLowerCase(),
    recordType,
    providerLineId: boundedText(row.providerLineId, 128, "DNS_RECORD_DRIFT"),
    value: boundedText(row.value, 2_048, "DNS_RECORD_DRIFT"),
    ttl: positiveInteger(row.ttl, "DNS_RECORD_DRIFT"),
  } satisfies XrayQuickConfigDnsTuple;
  if (tuple.ttl > 604_800 || !secureHashEqual(row.remoteTupleHash, computeXrayQuickConfigDnsTupleHash(tuple))) {
    fail("DNS_RECORD_DRIFT");
  }
  return tuple;
}

async function loadRemoveSnapshot(
  id: number,
  expectedRevision?: number,
  activeOperationId?: number,
): Promise<RemoveSnapshot & { port: number }> {
  const [config] = await queryRaw<Row>(
    `SELECT qc.*, t.${q("id")} AS ${q("snapshotTopologyId")}, t.${q("portAllocationId")}, a.${q("port")}, a.${q("version")} AS ${q("allocationVersion")},
            a.${q("primaryOwnerType")}, a.${q("primaryOwnerTag")}
       FROM ${q("xray_quick_configs")} qc
       JOIN ${q("xray_quick_config_topology_revisions")} t
         ON t.${q("id")} = COALESCE(qc.${q("activeTopologyRevisionId")}, qc.${q("desiredTopologyRevisionId")})
       JOIN ${q("global_port_allocations")} a ON a.${q("id")} = t.${q("portAllocationId")}
      WHERE qc.${q("id")} = ? LIMIT 1`,
    [id],
  );
  if (!config || config.state === "REMOVED") fail("QUICK_CONFIG_NOT_FOUND");
  const revision = positiveInteger(config.revision, "QUICK_CONFIG_REVISION_CONFLICT");
  if (expectedRevision !== undefined && revision !== expectedRevision) fail("QUICK_CONFIG_REVISION_CONFLICT");
  if (activeOperationId === undefined) {
    if (config.currentOperationId !== null && config.currentOperationId !== undefined
      || !["ACTIVE", "FAILED", "PARTIAL_FAILURE"].includes(String(config.state))) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    if (config.state === "PARTIAL_FAILURE") {
      const [lastOperation] = await queryRaw<Row>(
        `SELECT ${q("errorCode")} FROM ${q("xray_quick_config_operations")}
          WHERE ${q("quickConfigId")} = ? ORDER BY ${q("createdAt")} DESC, ${q("id")} DESC LIMIT 1`,
        [id],
      );
      if (lastOperation?.errorCode === "DNS_COMPENSATION_FAILED") fail("DNS_COMPENSATION_FAILED");
    }
  } else if (Number(config.currentOperationId) !== activeOperationId || config.state !== "DELETING") {
    fail("QUICK_CONFIG_OPERATION_CONFLICT");
  }
  const quickConfigId = positiveInteger(config.id);
  const topologyId = positiveInteger(config.snapshotTopologyId, "QUICK_CONFIG_OPERATION_CONFLICT");
  const recordRows = await queryRaw<Row>(
    `SELECT ${q("id")}, ${q("recordTag")}, ${q("providerRecordId")}, ${q("recordType")}, ${q("providerLineId")},
            ${q("fqdn")}, ${q("value")}, ${q("ttl")}, ${q("remoteTupleHash")}
       FROM ${q("xray_quick_config_dns_records")}
      WHERE ${q("quickConfigId")} = ? AND ${q("providerRecordId")} IS NOT NULL
        AND ${q("status")} IN ('APPLIED', 'UNKNOWN', 'DELETE_PENDING', 'DRIFTED')
      ORDER BY ${q("id")} ASC`,
    [quickConfigId],
  );
  if (recordRows.length > 64) fail("DNS_RECORD_DRIFT");
  const records = recordRows.map((row): RemoveRecord => {
    const tuple = recordTuple(row);
    const providerRecordId = boundedText(row.providerRecordId, 128, "DNS_RECORD_DRIFT");
    if (!/^[1-9]\d*$/.test(providerRecordId)) fail("DNS_RECORD_DRIFT");
    return {
      id: positiveInteger(row.id),
      recordRef: boundedText(row.recordTag, 128, "DNS_RECORD_DRIFT"),
      providerRecordId,
      recordType: tuple.recordType as "A" | "AAAA",
      providerLineId: tuple.providerLineId,
      value: tuple.value,
      ttl: tuple.ttl,
      tupleHash: computeXrayQuickConfigDnsTupleHash(tuple),
    };
  });
  const ruleRows = await queryRaw<Row>(
    `SELECT DISTINCT fr.${q("id")}, fr.${q("hostId")}, fr.${q("name")}
       FROM ${q("xray_quick_config_rule_bindings")} b
       JOIN ${q("forward_rules")} fr ON fr.${q("id")} = b.${q("forwardRuleId")}
      WHERE b.${q("quickConfigId")} = ? AND fr.${q("xrayQuickConfigId")} = ? ORDER BY fr.${q("id")} ASC`,
    [quickConfigId, quickConfigId],
  );
  const rules = ruleRows.map((row): RemoveRule => ({
    ruleId: positiveInteger(row.id),
    hostId: positiveInteger(row.hostId, "QUICK_CONFIG_OPERATION_CONFLICT"),
    name: boundedText(row.name, 256, "QUICK_CONFIG_OPERATION_CONFLICT"),
  }));
  const configTag = boundedText(config.configTag, 128, "QUICK_CONFIG_OPERATION_CONFLICT");
  const allocationNextState = config.primaryOwnerType === "QUICK_CONFIG" && config.primaryOwnerTag === configTag
    ? "RELEASING" as const : "ACTIVE" as const;
  const stablePlan = {
    quickConfigId,
    revision,
    fqdn: boundedText(config.fqdn, 253, "QUICK_CONFIG_OPERATION_CONFLICT").toLowerCase(),
    topologyId,
    allocationId: positiveInteger(config.portAllocationId, "QUICK_CONFIG_OPERATION_CONFLICT"),
    allocationVersion: positiveInteger(config.allocationVersion, "QUICK_CONFIG_OPERATION_CONFLICT"),
    allocationNextState,
    records: records.map((record) => ({ id: record.id, recordRef: record.recordRef, tupleHash: record.tupleHash })),
    rules,
  };
  return {
    id: quickConfigId,
    revision,
    fqdn: stablePlan.fqdn,
    relativeName: boundedText(config.relativeName, 253, "QUICK_CONFIG_OPERATION_CONFLICT").toLowerCase(),
    configTag,
    dnsAccountId: positiveInteger(config.dnsAccountId, "DNS_PROVIDER_CONFLICT"),
    zoneId: positiveInteger(config.zoneId, "DNS_PROVIDER_CONFLICT"),
    topologyId,
    allocationId: stablePlan.allocationId,
    allocationVersion: stablePlan.allocationVersion,
    allocationNextState,
    records,
    rules,
    planHash: sha256(stableJson(stablePlan)),
    port: positiveInteger(config.port, "QUICK_CONFIG_OPERATION_CONFLICT"),
  };
}

async function assertHostsAvailable(snapshot: RemoveSnapshot): Promise<void> {
  const candidates = await listXrayQuickConfigEntryHosts();
  const byId = new Map(candidates.items.map((host) => [host.hostId, host]));
  for (const rule of snapshot.rules) {
    const host = byId.get(rule.hostId);
    if (!host?.eligible) {
      const code = host?.disabledReasonCode;
      if (code === "HOST_OFFLINE" || code === "AGENT_CAPABILITY_MISSING" || code === "UDP_CAPABILITY_REQUIRED"
        || code === "QUICK_CONFIG_HOST_UNAVAILABLE") fail(code);
      fail("QUICK_CONFIG_HOST_UNAVAILABLE");
    }
  }
}

async function dnsContext(snapshot: RemoveSnapshot) {
  const credentials = await loadGlobalDnsProviderCredentials().catch((error) => {
    const code = String((error as { code?: unknown })?.code ?? "");
    if (code === "SENSITIVE_DATA_UNAVAILABLE") fail("SENSITIVE_DATA_UNAVAILABLE");
    if (code === "DNS_PROVIDER_NOT_CONFIGURED") fail("DNS_PROVIDER_CONFLICT");
    throw error;
  });
  if (credentials.accountId !== snapshot.dnsAccountId) fail("DNS_PROVIDER_CONFLICT");
  const [zone] = await queryRaw<Row>(
    `SELECT ${q("providerZoneId")}, ${q("name")}, ${q("status")}, ${q("expiresAt")}
       FROM ${q("dns_provider_zones")} WHERE ${q("id")} = ? AND ${q("accountId")} = ? LIMIT 1`,
    [snapshot.zoneId, snapshot.dnsAccountId],
  );
  if (!zone || zone.status !== "AVAILABLE" || (databaseDate(zone.expiresAt)?.getTime() ?? 0) <= Date.now()) {
    fail("DNS_PROVIDER_VALIDATION_STALE");
  }
  const dnsZone = {
    providerZoneId: boundedText(zone.providerZoneId, 128, "DNS_PROVIDER_CONFLICT"),
    name: boundedText(zone.name, 253, "DNS_PROVIDER_CONFLICT").toLowerCase(),
    grade: "",
  } satisfies DnsPodZone;
  if (`${snapshot.relativeName}.${dnsZone.name}` !== snapshot.fqdn) fail("DNS_RECORD_DRIFT");
  return { credentials, zone: dnsZone };
}

function remoteMatches(record: DnsPodRecord, snapshot: RemoveSnapshot, desired: RemoveRecord): boolean {
  if (record.subdomain.trim().toLowerCase() !== snapshot.relativeName) return false;
  const type = record.recordType === "A" || record.recordType === "AAAA" ? record.recordType : null;
  if (!type) return false;
  return computeXrayQuickConfigDnsTupleHash({
    fqdn: snapshot.fqdn,
    recordType: type,
    providerLineId: record.providerLineId,
    value: record.value,
    ttl: record.ttl,
  }) === desired.tupleHash;
}

async function recoverableMissingRecords(snapshot: RemoveSnapshot, priorOperationId?: number): Promise<Set<number>> {
  if (priorOperationId === undefined || snapshot.records.length === 0) return new Set();
  const rows = await queryRaw<Row>(
    `SELECT ${q("subjectId")}, ${q("status")}, ${q("requestSummaryJson")}
       FROM ${q("xray_quick_config_operation_steps")}
      WHERE ${q("operationId")} = ? AND ${q("kind")} = 'DNS_DELETE'
        AND ${q("subjectType")} = 'DNS_RECORD' AND ${q("status")} IN ('RUNNING', 'SUCCESS')`,
    [priorOperationId],
  );
  const records = new Map(snapshot.records.map((record) => [record.id, record]));
  const recoverable = new Set<number>();
  for (const row of rows) {
    const id = Number(row.subjectId);
    const record = records.get(id);
    if (!record || !parseDnsDeleteIntent(row.requestSummaryJson, record) || recoverable.has(id)) continue;
    recoverable.add(id);
  }
  return recoverable;
}

async function verifyRemoteRecords(snapshot: RemoveSnapshot, priorOperationId?: number): Promise<Set<number>> {
  const context = await dnsContext(snapshot);
  const client = new DnsPodProviderClient({ credentials: context.credentials });
  const intendedMissing = await recoverableMissingRecords(snapshot, priorOperationId);
  const confirmedMissing = new Set<number>();
  for (const record of snapshot.records) {
    let remote: DnsPodRecord;
    try {
      remote = await client.getRecord({ zone: context.zone, providerRecordId: record.providerRecordId });
    } catch (error) {
      if (error instanceof DnsPodProviderError && error.code === "DNS_PROVIDER_RECORD_NOT_FOUND") {
        if (!intendedMissing.has(record.id)) fail("DNS_RECORD_DRIFT");
        confirmedMissing.add(record.id);
        continue;
      }
      fail("DNS_PROVIDER_VALIDATION_STALE");
    }
    if (!remoteMatches(remote, snapshot, record)) fail("DNS_RECORD_DRIFT");
  }
  return confirmedMissing;
}

export async function previewQuickConfigRemove(input: {
  id: unknown;
  expectedRevision: unknown;
  userId: unknown;
}, options: LifecycleOptions = {}): Promise<QuickConfigRemovePreview> {
  const id = positiveInteger(input.id);
  const expectedRevision = positiveInteger(input.expectedRevision, "QUICK_CONFIG_REVISION_CONFLICT");
  const userId = positiveInteger(input.userId, "QUICK_CONFIG_REMOVE_TOKEN_INVALID");
  const snapshot = await loadRemoveSnapshot(id, expectedRevision);
  const now = resolvedNow(options);
  const expiresAt = new Date(now.getTime() + REMOVE_TOKEN_TTL_MS);
  const token = signRemoveToken({
    v: 1,
    kind: "REMOVE",
    nonce: crypto.randomBytes(16).toString("base64url"),
    userId,
    quickConfigId: snapshot.id,
    revision: snapshot.revision,
    fqdn: snapshot.fqdn,
    planHash: snapshot.planHash,
    issuedAt: now.getTime(),
    expiresAt: expiresAt.getTime(),
  }, options);
  return {
    quickConfigId: snapshot.id,
    revision: snapshot.revision,
    fqdn: snapshot.fqdn,
    dnsRecords: snapshot.records.map((record) => ({
      recordRef: record.recordRef,
      recordType: record.recordType,
      providerLineId: record.providerLineId,
      value: record.value,
      action: "DELETE" as const,
    })),
    rules: snapshot.rules.map((rule) => ({ ...rule, action: "REMOVE" as const })),
    allocation: { port: snapshot.port, nextState: snapshot.allocationNextState },
    warnings: snapshot.records.length === 0
      ? [{ code: "NO_MANAGED_DNS_RECORDS", message: "No active managed DNS records remain; removal will continue with rule cleanup." }]
      : [],
    removeToken: token,
    expiresAt: expiresAt.toISOString(),
  };
}

async function insertStep(input: {
  operationId: number;
  operationTag: string;
  key: string;
  kind: string;
  subjectType: string;
  subjectId: string | null;
  requestSummaryJson?: string;
  now: Date;
}) {
  await insertAndGetId("xray_quick_config_operation_steps", {
    operationId: input.operationId,
    stepKey: input.key,
    kind: input.kind,
    subjectType: input.subjectType,
    subjectId: input.subjectId,
    status: "PENDING",
    attemptCount: 0,
    idempotencyKey: `${input.operationTag}:${input.key}`,
    requestSummaryJson: input.requestSummaryJson ?? "{}",
    resultSummaryJson: null,
    errorCode: null,
    startedAt: null,
    finishedAt: null,
    updatedAt: input.now,
  });
}

async function createRemoveOperation(input: {
  snapshot: RemoveSnapshot;
  userId: number;
  type: "REMOVE" | "RETRY";
  retryOfOperationId: number | null;
  retrySource?: Readonly<{ operationId: number; expectedRevision: number }>;
  recoverableMissingRecordIds?: ReadonlySet<number>;
}): Promise<{ operationId: number; operationRevision: 1 }> {
  const now = nowDate();
  const operationTag = `quick-config-operation:${crypto.randomUUID()}`;
  return withDatabaseTransaction(async () => {
    if (input.retrySource) {
      const [source] = await queryRaw<Row>(
        `SELECT ${q("status")}, ${q("revision")} FROM ${q("xray_quick_config_operations")} WHERE ${q("id")} = ? LIMIT 1`,
        [input.retrySource.operationId],
      );
      if (!source || Number(source.revision) !== input.retrySource.expectedRevision
        || !["FAILED", "PARTIAL_FAILURE"].includes(String(source.status))) {
        fail("QUICK_CONFIG_REVISION_CONFLICT");
      }
    }
    const [fresh] = await queryRaw<Row>(
      `SELECT ${q("revision")}, ${q("currentOperationId")}, ${q("state")}, ${q("activeTopologyRevisionId")}, ${q("desiredTopologyRevisionId")}
         FROM ${q("xray_quick_configs")} WHERE ${q("id")} = ? LIMIT 1`,
      [input.snapshot.id],
    );
    if (!fresh || Number(fresh.revision) !== input.snapshot.revision
      || fresh.currentOperationId !== null && fresh.currentOperationId !== undefined
      || Number(fresh.activeTopologyRevisionId ?? fresh.desiredTopologyRevisionId) !== input.snapshot.topologyId
      || !["ACTIVE", "FAILED", "PARTIAL_FAILURE"].includes(String(fresh.state))) {
      fail("QUICK_CONFIG_REVISION_CONFLICT");
    }
    const operationId = await insertAndGetId("xray_quick_config_operations", {
      operationTag,
      quickConfigId: input.snapshot.id,
      type: input.type,
      status: "QUEUED",
      phase: "DNS_REMOVING",
      activeSlot: 1,
      revision: 1,
      expectedRevision: input.snapshot.revision,
      fromTopologyRevisionId: input.snapshot.topologyId,
      toTopologyRevisionId: null,
      requestSummaryJson: "{}",
      retryOfOperationId: input.retryOfOperationId,
      executionOwnerId: null,
      executionLeaseUntil: null,
      executionFence: 1,
      errorCode: null,
      errorMessage: null,
      createdByUserId: input.userId,
      startedAt: null,
      finishedAt: null,
      createdAt: now,
      updatedAt: now,
    });
    for (const record of input.snapshot.records) {
      await insertStep({
        operationId,
        operationTag,
        key: `dns-remove-${record.id}`,
        kind: "DNS_DELETE",
        subjectType: "DNS_RECORD",
        subjectId: String(record.id),
        requestSummaryJson: input.recoverableMissingRecordIds?.has(record.id)
          ? stableJson(dnsDeleteIntent(record))
          : undefined,
        now,
      });
    }
    for (const rule of input.snapshot.rules) {
      await insertStep({ operationId, operationTag, key: `rule-remove-${rule.ruleId}`, kind: "RULE_DELETE", subjectType: "RULE", subjectId: String(rule.ruleId), now });
      await insertStep({ operationId, operationTag, key: `rule-verify-removed-${rule.ruleId}`, kind: "RULE_VERIFY_REMOVED", subjectType: "RULE", subjectId: String(rule.ruleId), now });
    }
    await insertStep({ operationId, operationTag, key: "release-references", kind: "REFERENCE_RELEASE", subjectType: "ALLOCATION", subjectId: String(input.snapshot.allocationId), now });
    const changed = await executeRaw(
      `UPDATE ${q("xray_quick_configs")} SET ${q("state")} = 'DELETING', ${q("currentOperationId")} = ?, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("revision")} = ? AND ${q("currentOperationId")} IS NULL`,
      [operationId, now, input.snapshot.id, input.snapshot.revision],
    );
    if (rawAffectedRows(changed) !== 1) fail("QUICK_CONFIG_REVISION_CONFLICT");
    await afterDatabaseCommit(() => import("./xrayQuickConfigOperationService")
      .then(({ kickQuickConfigOperationWorker }) => kickQuickConfigOperationWorker()));
    return { operationId, operationRevision: 1 as const };
  });
}

export async function applyQuickConfigRemove(input: {
  removeToken: unknown;
  confirmFqdn: unknown;
  userId: unknown;
}, options: LifecycleOptions = {}): Promise<{ quickConfigId: number; operationId: number; state: "DELETING" }> {
  const payload = parseRemoveToken(input.removeToken, options);
  const userId = positiveInteger(input.userId, "QUICK_CONFIG_REMOVE_TOKEN_INVALID");
  const confirmFqdn = boundedText(input.confirmFqdn, 253, "QUICK_CONFIG_REMOVE_TOKEN_INVALID").trim().toLowerCase();
  if (payload.userId !== userId || payload.fqdn !== confirmFqdn) fail("QUICK_CONFIG_REMOVE_TOKEN_INVALID");
  const snapshot = await loadRemoveSnapshot(payload.quickConfigId, payload.revision);
  if (snapshot.fqdn !== payload.fqdn || !secureHashEqual(snapshot.planHash, payload.planHash)) fail("QUICK_CONFIG_REVISION_CONFLICT");
  await assertHostsAvailable(snapshot);
  await verifyRemoteRecords(snapshot);
  const operation = await createRemoveOperation({ snapshot, userId, type: "REMOVE", retryOfOperationId: null });
  return { quickConfigId: snapshot.id, operationId: operation.operationId, state: "DELETING" };
}

async function removeRootOperation(operationId: number): Promise<Row> {
  let id = operationId;
  const seen = new Set<number>();
  for (let depth = 0; depth < 32; depth += 1) {
    if (seen.has(id)) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    seen.add(id);
    const [row] = await queryRaw<Row>(
      `SELECT ${q("id")}, ${q("quickConfigId")}, ${q("type")}, ${q("retryOfOperationId")} FROM ${q("xray_quick_config_operations")} WHERE ${q("id")} = ? LIMIT 1`,
      [id],
    );
    if (!row) fail("QUICK_CONFIG_NOT_FOUND");
    if (row.type === "REMOVE") return row;
    if (row.type !== "RETRY") fail("QUICK_CONFIG_OPERATION_CONFLICT");
    id = positiveInteger(row.retryOfOperationId, "QUICK_CONFIG_OPERATION_CONFLICT");
  }
  fail("QUICK_CONFIG_OPERATION_CONFLICT");
}

export async function retryQuickConfigRemoveOperation(input: {
  operationId: unknown;
  expectedOperationRevision: unknown;
  userId: unknown;
}): Promise<{ operationId: number; operationRevision: 1 }> {
  const operationId = positiveInteger(input.operationId);
  const expectedRevision = positiveInteger(input.expectedOperationRevision, "QUICK_CONFIG_REVISION_CONFLICT");
  const userId = positiveInteger(input.userId, "QUICK_CONFIG_OPERATION_CONFLICT");
  const [operation] = await queryRaw<Row>(
    `SELECT ${q("id")}, ${q("quickConfigId")}, ${q("status")}, ${q("revision")} FROM ${q("xray_quick_config_operations")} WHERE ${q("id")} = ? LIMIT 1`,
    [operationId],
  );
  if (!operation) fail("QUICK_CONFIG_NOT_FOUND");
  if (Number(operation.revision) !== expectedRevision) fail("QUICK_CONFIG_REVISION_CONFLICT");
  if (operation.status !== "FAILED" && operation.status !== "PARTIAL_FAILURE") fail("QUICK_CONFIG_OPERATION_CONFLICT");
  const root = await removeRootOperation(operationId);
  if (Number(root.quickConfigId) !== Number(operation.quickConfigId)) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  const snapshot = await loadRemoveSnapshot(positiveInteger(operation.quickConfigId));
  await assertHostsAvailable(snapshot);
  const recoverableMissingRecordIds = await verifyRemoteRecords(snapshot, operationId);
  return createRemoveOperation({
    snapshot,
    userId,
    type: "RETRY",
    retryOfOperationId: operationId,
    retrySource: { operationId, expectedRevision },
    recoverableMissingRecordIds,
  });
}

export async function isQuickConfigRemoveOperation(operation: Row): Promise<boolean> {
  if (operation.type === "REMOVE") return true;
  if (operation.type !== "RETRY") return false;
  if (isDnsCompensationRecovery(operation)) return true;
  try {
    await removeRootOperation(positiveInteger(operation.id));
    return true;
  } catch {
    return false;
  }
}

function operationFence(operation: Row) {
  return {
    operationId: positiveInteger(operation.id, "QUICK_CONFIG_OPERATION_CONFLICT"),
    quickConfigId: positiveInteger(operation.quickConfigId, "QUICK_CONFIG_OPERATION_CONFLICT"),
    owner: boundedText(operation.executionOwnerId, 128, "QUICK_CONFIG_OPERATION_CONFLICT"),
    fence: positiveInteger(operation.executionFence, "QUICK_CONFIG_OPERATION_CONFLICT"),
  };
}

async function assertFence(operation: Row): Promise<void> {
  const fence = operationFence(operation);
  const [row] = await queryRaw<Row>(
    `SELECT ${q("status")}, ${q("executionLeaseUntil")}, ${q("currentOperationId")}
       FROM ${q("xray_quick_config_operations")} o
       JOIN ${q("xray_quick_configs")} qc ON qc.${q("id")} = o.${q("quickConfigId")}
      WHERE o.${q("id")} = ? AND o.${q("quickConfigId")} = ? AND o.${q("executionOwnerId")} = ?
        AND o.${q("executionFence")} = ? LIMIT 1`,
    [fence.operationId, fence.quickConfigId, fence.owner, fence.fence],
  );
  if (!row || !["RUNNING", "COMPENSATING"].includes(String(row.status))
    || Number(row.currentOperationId) !== fence.operationId
    || (databaseDate(row.executionLeaseUntil)?.getTime() ?? 0) <= Date.now()) fail("QUICK_CONFIG_OPERATION_CONFLICT");
}

async function beginStep(operation: Row, kind: string, subjectId: number | null) {
  await assertFence(operation);
  const fence = operationFence(operation);
  const params: unknown[] = [fence.operationId, kind];
  const subject = subjectId === null ? "" : ` AND ${q("subjectId")} = ?`;
  if (subjectId !== null) params.push(String(subjectId));
  const [row] = await queryRaw<Row>(
    `SELECT ${q("id")}, ${q("status")}, ${q("requestSummaryJson")} FROM ${q("xray_quick_config_operation_steps")}
      WHERE ${q("operationId")} = ? AND ${q("kind")} = ?${subject} ORDER BY ${q("id")} ASC LIMIT 1`,
    params,
  );
  if (!row || !["PENDING", "RUNNING", "SUCCESS"].includes(String(row.status))) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  const step = {
    id: positiveInteger(row.id),
    previousStatus: String(row.status),
    requestSummaryJson: String(row.requestSummaryJson ?? "{}"),
  };
  if (step.previousStatus === "PENDING") {
    const now = nowDate();
    const changed = await executeRaw(
      `UPDATE ${q("xray_quick_config_operation_steps")} SET ${q("status")} = 'RUNNING',
          ${q("attemptCount")} = ${q("attemptCount")} + 1, ${q("startedAt")} = COALESCE(${q("startedAt")}, ?),
          ${q("finishedAt")} = NULL, ${q("errorCode")} = NULL, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("status")} = 'PENDING'`,
      [now, now, step.id],
    );
    if (rawAffectedRows(changed) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  }
  return step;
}

async function finishStep(stepId: number, status: "SUCCESS" | "FAILED", errorCode: string | null = null) {
  const now = nowDate();
  await executeRaw(
    `UPDATE ${q("xray_quick_config_operation_steps")} SET ${q("status")} = ?, ${q("resultSummaryJson")} = ?,
        ${q("errorCode")} = ?, ${q("finishedAt")} = ?, ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("status")} <> 'SUCCESS'`,
    [status, status === "SUCCESS" ? "{}" : null, errorCode, now, now, stepId],
  );
}

async function persistDnsDeleteIntent(operation: Row, stepId: number, record: RemoveRecord): Promise<DnsDeleteIntent> {
  await assertFence(operation);
  const fence = operationFence(operation);
  const intent = dnsDeleteIntent(record);
  const now = nowDate();
  const changed = await executeRaw(
    `UPDATE ${q("xray_quick_config_operation_steps")}
        SET ${q("requestSummaryJson")} = ?, ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("operationId")} = ? AND ${q("status")} = 'RUNNING'
        AND EXISTS (
          SELECT 1
            FROM ${q("xray_quick_config_operations")} o
            JOIN ${q("xray_quick_configs")} qc ON qc.${q("id")} = o.${q("quickConfigId")}
           WHERE o.${q("id")} = ? AND o.${q("quickConfigId")} = ?
             AND o.${q("executionOwnerId")} = ? AND o.${q("executionFence")} = ?
             AND o.${q("status")} IN ('RUNNING', 'COMPENSATING')
             AND o.${q("executionLeaseUntil")} > ?
             AND qc.${q("currentOperationId")} = o.${q("id")}
        )`,
    [stableJson(intent), now, stepId, fence.operationId, fence.operationId, fence.quickConfigId,
      fence.owner, fence.fence, now],
  );
  if (rawAffectedRows(changed) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  return intent;
}

async function markDnsRecordDeletePending(operation: Row, record: RemoveRecord): Promise<void> {
  await assertFence(operation);
  const fence = operationFence(operation);
  const now = nowDate();
  const changed = await executeRaw(
    `UPDATE ${q("xray_quick_config_dns_records")}
        SET ${q("status")} = 'DELETE_PENDING', ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("providerRecordId")} = ?
        AND ${q("remoteTupleHash")} = ? AND ${q("status")} IN ('APPLIED', 'DELETE_PENDING', 'UNKNOWN', 'DRIFTED')
        AND EXISTS (
          SELECT 1
            FROM ${q("xray_quick_config_operations")} o
            JOIN ${q("xray_quick_configs")} qc ON qc.${q("id")} = o.${q("quickConfigId")}
           WHERE o.${q("id")} = ? AND o.${q("quickConfigId")} = ?
             AND o.${q("executionOwnerId")} = ? AND o.${q("executionFence")} = ?
             AND o.${q("status")} IN ('RUNNING', 'COMPENSATING')
             AND o.${q("executionLeaseUntil")} > ?
             AND qc.${q("currentOperationId")} = o.${q("id")}
        )`,
    [now, record.id, fence.quickConfigId, record.providerRecordId, record.tupleHash,
      fence.operationId, fence.quickConfigId, fence.owner, fence.fence, now],
  );
  if (rawAffectedRows(changed) !== 1) fail("DNS_RECORD_DRIFT");
}

async function markDnsRecordRemoved(operation: Row, record: RemoveRecord): Promise<void> {
  await assertFence(operation);
  const fence = operationFence(operation);
  const now = nowDate();
  const changed = await executeRaw(
    `UPDATE ${q("xray_quick_config_dns_records")}
        SET ${q("status")} = 'REMOVED', ${q("lastVerifiedAt")} = ?, ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("providerRecordId")} = ?
        AND ${q("remoteTupleHash")} = ? AND ${q("status")} = 'DELETE_PENDING'
        AND EXISTS (
          SELECT 1
            FROM ${q("xray_quick_config_operations")} o
            JOIN ${q("xray_quick_configs")} qc ON qc.${q("id")} = o.${q("quickConfigId")}
           WHERE o.${q("id")} = ? AND o.${q("quickConfigId")} = ?
             AND o.${q("executionOwnerId")} = ? AND o.${q("executionFence")} = ?
             AND o.${q("status")} IN ('RUNNING', 'COMPENSATING')
             AND o.${q("executionLeaseUntil")} > ?
             AND qc.${q("currentOperationId")} = o.${q("id")}
        )`,
    [now, now, record.id, fence.quickConfigId, record.providerRecordId, record.tupleHash,
      fence.operationId, fence.quickConfigId, fence.owner, fence.fence, now],
  );
  if (rawAffectedRows(changed) !== 1) fail("DNS_RECORD_DRIFT");
}

async function finishRemoveOperation(operation: Row, status: "SUCCESS" | "FAILED" | "PARTIAL_FAILURE", errorCode: string | null) {
  const fence = operationFence(operation);
  const now = nowDate();
  await withDatabaseTransaction(async () => {
    const configState = status === "SUCCESS" ? "REMOVED" : status === "FAILED" ? "FAILED" : "PARTIAL_FAILURE";
    if (status === "SUCCESS") {
      await executeRaw(
        `UPDATE ${q("xray_quick_config_topology_revisions")} SET ${q("state")} = 'RETIRED', ${q("activeSlot")} = NULL, ${q("updatedAt")} = ?
          WHERE ${q("quickConfigId")} = ? AND ${q("activeSlot")} IS NOT NULL`,
        [now, fence.quickConfigId],
      );
      await executeRaw(`DELETE FROM ${q("xray_quick_config_domain_claims")} WHERE ${q("quickConfigId")} = ?`, [fence.quickConfigId]);
      await executeRaw(`DELETE FROM ${q("xray_quick_config_rule_bindings")} WHERE ${q("quickConfigId")} = ?`, [fence.quickConfigId]);
      await executeRaw(`DELETE FROM ${q("xray_quick_config_routes")} WHERE ${q("quickConfigId")} = ?`, [fence.quickConfigId]);
    }
    const changed = status === "SUCCESS"
      ? await executeRaw(
        `UPDATE ${q("xray_quick_configs")} SET ${q("state")} = ?, ${q("activeTopologyRevisionId")} = NULL,
            ${q("desiredTopologyRevisionId")} = NULL, ${q("currentOperationId")} = NULL,
            ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ?
          WHERE ${q("id")} = ? AND ${q("currentOperationId")} = ?`,
        [configState, now, fence.quickConfigId, fence.operationId],
      )
      : await executeRaw(
        `UPDATE ${q("xray_quick_configs")} SET ${q("state")} = ?, ${q("currentOperationId")} = NULL,
            ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ?
          WHERE ${q("id")} = ? AND ${q("currentOperationId")} = ?`,
        [configState, now, fence.quickConfigId, fence.operationId],
      );
    if (rawAffectedRows(changed) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
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

function isDnsCompensationRecovery(operation: Row): boolean {
  if (operation.type !== "RETRY" || operation.phase !== "RESTORING_DNS") return false;
  try {
    const summary = JSON.parse(String(operation.requestSummaryJson ?? "")) as Record<string, unknown>;
    return summary.kind === "DNS_COMPENSATION_RECOVERY";
  } catch {
    return false;
  }
}

async function finishDnsCompensationRecoveryPartial(operation: Row): Promise<void> {
  const fence = operationFence(operation);
  const now = nowDate();
  await withDatabaseTransaction(async () => {
    await assertFence(operation);
    const operationChanged = await executeRaw(
      `UPDATE ${q("xray_quick_config_operations")}
          SET ${q("status")} = 'PARTIAL_FAILURE', ${q("phase")} = 'COMPLETED', ${q("activeSlot")} = NULL,
              ${q("revision")} = ${q("revision")} + 1, ${q("errorCode")} = 'DNS_COMPENSATION_FAILED',
              ${q("errorMessage")} = NULL, ${q("finishedAt")} = ?, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("executionOwnerId")} = ?
          AND ${q("executionFence")} = ? AND ${q("status")} IN ('RUNNING', 'COMPENSATING')
          AND EXISTS (SELECT 1 FROM ${q("xray_quick_configs")} qc
            WHERE qc.${q("id")} = ? AND qc.${q("currentOperationId")} = ?)`,
      [now, now, fence.operationId, fence.quickConfigId, fence.owner, fence.fence,
        fence.quickConfigId, fence.operationId],
    );
    if (rawAffectedRows(operationChanged) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    const configChanged = await executeRaw(
      `UPDATE ${q("xray_quick_configs")}
          SET ${q("state")} = 'PARTIAL_FAILURE', ${q("currentOperationId")} = NULL,
              ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("currentOperationId")} = ?
          AND EXISTS (SELECT 1 FROM ${q("xray_quick_config_operations")} o
            WHERE o.${q("id")} = ? AND o.${q("executionOwnerId")} = ? AND o.${q("executionFence")} = ?
              AND o.${q("status")} = 'PARTIAL_FAILURE')`,
      [now, fence.quickConfigId, fence.operationId, fence.operationId, fence.owner, fence.fence],
    );
    if (rawAffectedRows(configChanged) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    const released = await executeRaw(
      `UPDATE ${q("xray_quick_config_operations")}
          SET ${q("executionOwnerId")} = NULL, ${q("executionLeaseUntil")} = NULL, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("executionOwnerId")} = ?
          AND ${q("executionFence")} = ? AND ${q("status")} = 'PARTIAL_FAILURE'`,
      [now, fence.operationId, fence.quickConfigId, fence.owner, fence.fence],
    );
    if (rawAffectedRows(released) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  });
}

async function processDnsCompensationRecovery(operation: Row): Promise<void> {
  const fence = operationFence(operation);
  try {
    await assertFence(operation);
    const startedAt = nowDate();
    const started = await executeRaw(
      `UPDATE ${q("xray_quick_config_operations")}
          SET ${q("status")} = 'COMPENSATING', ${q("phase")} = 'RESTORING_DNS',
              ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("executionOwnerId")} = ?
          AND ${q("executionFence")} = ? AND ${q("status")} IN ('RUNNING', 'COMPENSATING')
          AND ${q("phase")} = 'RESTORING_DNS' AND ${q("executionLeaseUntil")} > ?
          AND EXISTS (SELECT 1 FROM ${q("xray_quick_configs")} qc
            WHERE qc.${q("id")} = ? AND qc.${q("currentOperationId")} = ?)`,
      [startedAt, fence.operationId, fence.quickConfigId, fence.owner, fence.fence, startedAt,
        fence.quickConfigId, fence.operationId],
    );
    if (rawAffectedRows(started) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    const { applyQuickConfigDnsOperation } = await import("./xrayQuickConfigDnsApplyService");
    const result = await applyQuickConfigDnsOperation(fence.operationId, {
      executionOwnerId: fence.owner,
      executionFence: fence.fence,
    });
    await assertFence(operation);
    if (result.status !== "FAILED" || result.compensationComplete !== true) {
      await finishDnsCompensationRecoveryPartial(operation);
      return;
    }
    const now = nowDate();
    const operationChanged = await executeRaw(
      `UPDATE ${q("xray_quick_config_operations")}
          SET ${q("status")} = 'COMPENSATING', ${q("phase")} = 'REMOVING_NEW_RULES',
              ${q("revision")} = ${q("revision")} + 1, ${q("errorCode")} = 'DNS_APPLY_FAILED',
              ${q("errorMessage")} = NULL, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("executionOwnerId")} = ?
          AND ${q("executionFence")} = ? AND ${q("status")} IN ('RUNNING', 'COMPENSATING')
          AND ${q("phase")} = 'RESTORING_DNS'
          AND EXISTS (SELECT 1 FROM ${q("xray_quick_configs")} qc
            WHERE qc.${q("id")} = ? AND qc.${q("currentOperationId")} = ?)`,
      [now, fence.operationId, fence.quickConfigId, fence.owner, fence.fence,
        fence.quickConfigId, fence.operationId],
    );
    if (rawAffectedRows(operationChanged) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    const configChanged = await executeRaw(
      `UPDATE ${q("xray_quick_configs")} SET ${q("state")} = 'COMPENSATING', ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("currentOperationId")} = ?
          AND EXISTS (SELECT 1 FROM ${q("xray_quick_config_operations")} o
            WHERE o.${q("id")} = ? AND o.${q("executionOwnerId")} = ? AND o.${q("executionFence")} = ?
              AND o.${q("status")} = 'COMPENSATING' AND o.${q("phase")} = 'REMOVING_NEW_RULES')`,
      [now, fence.quickConfigId, fence.operationId, fence.operationId, fence.owner, fence.fence],
    );
    if (rawAffectedRows(configChanged) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  } catch {
    await finishDnsCompensationRecoveryPartial(operation).catch(() => undefined);
  }
}

async function processDnsRemoval(operation: Row, snapshot: RemoveSnapshot) {
  const context = await dnsContext(snapshot);
  const client = new DnsPodProviderClient({ credentials: context.credentials });
  for (const record of snapshot.records) {
    const step = await beginStep(operation, "DNS_DELETE", record.id);
    let intent = parseDnsDeleteIntent(step.requestSummaryJson, record);
    let remote: DnsPodRecord | null = null;
    try {
      remote = await client.getRecord({ zone: context.zone, providerRecordId: record.providerRecordId });
    } catch (error) {
      if (!(error instanceof DnsPodProviderError) || error.code !== "DNS_PROVIDER_RECORD_NOT_FOUND") {
        await finishStep(step.id, "FAILED", "DNS_PROVIDER_VALIDATION_STALE");
        throw error;
      }
    }
    if (step.previousStatus === "SUCCESS") {
      if (remote || !intent) fail("DNS_RECORD_DRIFT");
      await markDnsRecordDeletePending(operation, record);
      await markDnsRecordRemoved(operation, record);
      continue;
    }
    if (!remote) {
      if (!intent) fail("DNS_RECORD_DRIFT");
      await markDnsRecordDeletePending(operation, record);
    } else {
      if (!remoteMatches(remote, snapshot, record)) {
        await executeRaw(`UPDATE ${q("xray_quick_config_dns_records")} SET ${q("status")} = 'DRIFTED', ${q("updatedAt")} = ? WHERE ${q("id")} = ?`, [nowDate(), record.id]);
        await finishStep(step.id, "FAILED", "DNS_RECORD_DRIFT");
        fail("DNS_RECORD_DRIFT");
      }
      if (!intent) intent = await persistDnsDeleteIntent(operation, step.id, record);
      await markDnsRecordDeletePending(operation, record);
      try {
        await client.deleteRecord({ zone: context.zone, providerRecordId: record.providerRecordId });
      } catch (error) {
        if (!(error instanceof DnsPodProviderError) || !error.ambiguousWrite) throw error;
      }
      await assertFence(operation);
      try {
        const remained = await client.getRecord({ zone: context.zone, providerRecordId: record.providerRecordId });
        if (remained) fail("DNS_RECORD_DRIFT");
      } catch (error) {
        if (!(error instanceof DnsPodProviderError) || error.code !== "DNS_PROVIDER_RECORD_NOT_FOUND") throw error;
      }
    }
    if (!intent) fail("DNS_RECORD_DRIFT");
    await markDnsRecordRemoved(operation, record);
    await finishStep(step.id, "SUCCESS");
  }
  const fence = operationFence(operation);
  const changed = await executeRaw(
    `UPDATE ${q("xray_quick_config_operations")} SET ${q("phase")} = 'DNS_REMOVED', ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("executionOwnerId")} = ? AND ${q("executionFence")} = ?`,
    [nowDate(), fence.operationId, fence.owner, fence.fence],
  );
  if (rawAffectedRows(changed) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
}

async function processRuleRemoval(operation: Row, snapshot: RemoveSnapshot): Promise<boolean> {
  let waiting = false;
  for (const rule of snapshot.rules) {
    const deleteStep = await beginStep(operation, "RULE_DELETE", rule.ruleId);
    const [current] = await queryRaw<Row>(
      `SELECT ${q("id")}, ${q("hostId")}, ${q("pendingDelete")}, ${q("isRunning")} FROM ${q("forward_rules")} WHERE ${q("id")} = ? AND ${q("xrayQuickConfigId")} = ? LIMIT 1`,
      [rule.ruleId, snapshot.id],
    );
    if (current && !databaseBoolean(current.pendingDelete)) {
      await markForwardRulePendingDelete(rule.ruleId);
      pushAgentRefresh(rule.hostId, "xray-quick-config-remove", { urgent: true });
    }
    await executeRaw(
      `UPDATE ${q("xray_quick_config_rule_bindings")} SET ${q("state")} = 'RETIRING', ${q("updatedAt")} = ? WHERE ${q("quickConfigId")} = ? AND ${q("forwardRuleId")} = ? AND ${q("state")} <> 'REMOVED'`,
      [nowDate(), snapshot.id, rule.ruleId],
    );
    await finishStep(deleteStep.id, "SUCCESS");
    let [after] = await queryRaw<Row>(
      `SELECT ${q("id")}, ${q("isRunning")}, ${q("pendingDelete")} FROM ${q("forward_rules")} WHERE ${q("id")} = ? LIMIT 1`,
      [rule.ruleId],
    );
    if (after && databaseBoolean(after.pendingDelete) && !databaseBoolean(after.isRunning)) {
      await finalizeForwardRuleDelete(rule.ruleId);
      [after] = await queryRaw<Row>(`SELECT ${q("id")} FROM ${q("forward_rules")} WHERE ${q("id")} = ? LIMIT 1`, [rule.ruleId]);
    }
    const verifyStep = await beginStep(operation, "RULE_VERIFY_REMOVED", rule.ruleId);
    if (after) {
      waiting = true;
      continue;
    }
    await executeRaw(
      `UPDATE ${q("xray_quick_config_rule_bindings")} SET ${q("state")} = 'REMOVED', ${q("updatedAt")} = ? WHERE ${q("quickConfigId")} = ? AND ${q("forwardRuleId")} = ?`,
      [nowDate(), snapshot.id, rule.ruleId],
    );
    await finishStep(verifyStep.id, "SUCCESS");
  }
  return waiting;
}

function portReference(row: Row): GlobalPortReferenceInput {
  const resourceType = String(row.resourceType);
  const network = String(row.network);
  const role = String(row.role);
  if (!["XRAY_INBOUND", "FORWARD_RULE", "MANAGED_SERVICE", "TUNNEL", "TUNNEL_EXIT_NODE", "TUNNEL_HOP", "FORWARD_RULE_TUNNEL_EXIT", "QUICK_CONFIG"].includes(resourceType)
    || !["TCP", "UDP", "BOTH", "NONE"].includes(network) || !["TARGET", "PUBLIC_LISTENER", "OWNERSHIP", "MIMIC"].includes(role)) {
    fail("QUICK_CONFIG_OPERATION_CONFLICT");
  }
  return {
    resourceType: resourceType as GlobalPortReferenceInput["resourceType"],
    resourceId: positiveInteger(row.resourceId, "QUICK_CONFIG_OPERATION_CONFLICT"),
    hostId: nullablePositiveInteger(row.hostId),
    network: network as GlobalPortReferenceInput["network"],
    role: role as GlobalPortReferenceInput["role"],
    isOwning: databaseBoolean(row.isOwning),
  };
}

async function releaseReferences(operation: Row, snapshot: RemoveSnapshot) {
  const step = await beginStep(operation, "REFERENCE_RELEASE", snapshot.allocationId);
  const rows = await queryRaw<Row>(
    `SELECT ${q("resourceType")}, ${q("resourceId")}, ${q("hostId")}, ${q("network")}, ${q("role")}, ${q("isOwning")}
       FROM ${q("global_port_allocation_references")} WHERE ${q("allocationId")} = ? AND ${q("ownerGroupTag")} = ? ORDER BY ${q("id")} ASC`,
    [snapshot.allocationId, snapshot.configTag],
  );
  for (const row of rows) {
    await assertFence(operation);
    await releaseGlobalPortReferenceAfterRuntimeCleanup({ reference: portReference(row) });
  }
  const remaining = await queryRaw<Row>(
    `SELECT ${q("id")} FROM ${q("global_port_allocation_references")} WHERE ${q("allocationId")} = ? AND ${q("ownerGroupTag")} = ? LIMIT 1`,
    [snapshot.allocationId, snapshot.configTag],
  );
  if (remaining.length) fail("RULE_CLEANUP_FAILED");
  await finishStep(step.id, "SUCCESS");
}

async function operationMayHaveRemovalSideEffects(operationId: number): Promise<boolean> {
  const rows = await queryRaw<Row>(
    `SELECT ${q("id")} FROM ${q("xray_quick_config_operation_steps")}
      WHERE ${q("operationId")} = ? AND ${q("kind")} IN ('DNS_DELETE', 'RULE_DELETE', 'REFERENCE_RELEASE')
        AND ${q("status")} IN ('RUNNING', 'SUCCESS') LIMIT 1`,
    [operationId],
  );
  return rows.length > 0;
}

export async function processQuickConfigRemoveOperation(operation: Row): Promise<void> {
  await withKeyedTaskLock(`xray-quick-config-remove:${positiveInteger(operation.id)}`, async () => {
    if (isDnsCompensationRecovery(operation)) {
      await processDnsCompensationRecovery(operation);
      return;
    }
    const fence = operationFence(operation);
    try {
      await assertFence(operation);
      const snapshot = await loadRemoveSnapshot(fence.quickConfigId, undefined, fence.operationId);
      if (String(operation.phase) === "DNS_REMOVING") await processDnsRemoval(operation, snapshot);
      const [fresh] = await queryRaw<Row>(`SELECT ${q("phase")} FROM ${q("xray_quick_config_operations")} WHERE ${q("id")} = ? LIMIT 1`, [fence.operationId]);
      if (fresh?.phase === "DNS_REMOVED" || fresh?.phase === "RULES_REMOVING") {
        const rulesStarted = await executeRaw(
          `UPDATE ${q("xray_quick_config_operations")} SET ${q("phase")} = 'RULES_REMOVING', ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ?
            WHERE ${q("id")} = ? AND ${q("executionOwnerId")} = ? AND ${q("executionFence")} = ?`,
          [nowDate(), fence.operationId, fence.owner, fence.fence],
        );
        if (rawAffectedRows(rulesStarted) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
        if (await processRuleRemoval(operation, snapshot)) return;
        const rulesRemoved = await executeRaw(
          `UPDATE ${q("xray_quick_config_operations")} SET ${q("phase")} = 'RULES_REMOVED', ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ?
            WHERE ${q("id")} = ? AND ${q("executionOwnerId")} = ? AND ${q("executionFence")} = ?`,
          [nowDate(), fence.operationId, fence.owner, fence.fence],
        );
        if (rawAffectedRows(rulesRemoved) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
      }
      const [releasePhase] = await queryRaw<Row>(`SELECT ${q("phase")} FROM ${q("xray_quick_config_operations")} WHERE ${q("id")} = ? LIMIT 1`, [fence.operationId]);
      if (releasePhase?.phase === "RULES_REMOVED" || releasePhase?.phase === "PORT_RELEASING") {
        const portStarted = await executeRaw(
          `UPDATE ${q("xray_quick_config_operations")} SET ${q("phase")} = 'PORT_RELEASING', ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ?
            WHERE ${q("id")} = ? AND ${q("executionOwnerId")} = ? AND ${q("executionFence")} = ?`,
          [nowDate(), fence.operationId, fence.owner, fence.fence],
        );
        if (rawAffectedRows(portStarted) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
        await releaseReferences(operation, snapshot);
        await finishRemoveOperation(operation, "SUCCESS", null);
      }
    } catch (error) {
      const code = error instanceof XrayQuickConfigLifecycleError ? error.code
        : error instanceof DnsPodProviderError ? "DNS_PROVIDER_VALIDATION_STALE"
          : "RULE_CLEANUP_FAILED";
      const partial = code === "DNS_RECORD_DRIFT"
        || await operationMayHaveRemovalSideEffects(fence.operationId).catch(() => true);
      await finishRemoveOperation(operation, partial ? "PARTIAL_FAILURE" : "FAILED", code).catch(() => undefined);
    }
  });
}
