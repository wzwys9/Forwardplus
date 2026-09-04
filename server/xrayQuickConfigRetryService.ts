import crypto from "node:crypto";
import { compileQuickConfigTopology } from "./xrayQuickConfigTopology";

import { XRAY_QUICK_CONFIG_FORWARD_ENGINES, type XrayQuickConfigForwardEngine } from "../shared/xrayQuickConfigForwardEngines";
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
import { addActiveGlobalPortOwningReference, type GlobalPortReferenceInput } from "./globalPortAllocationService";
import {
  createForwardRule,
  finalizeForwardRuleDelete,
} from "./repositories/forwardRuleRepository";
import { assignQuickConfigRulePortResource, ensureQuickConfigPortResource } from "./quickConfigPortResourceService";
import {
  retryQuickConfigRemoveOperation,
} from "./xrayQuickConfigLifecycleService";
import { computeXrayQuickConfigDnsTupleHash } from "./xrayQuickConfigDnsTuple";

type Row = Record<string, unknown>;

export const XRAY_QUICK_CONFIG_RETRY_ERROR_CODES = [
  "QUICK_CONFIG_NOT_FOUND",
  "QUICK_CONFIG_REVISION_CONFLICT",
  "QUICK_CONFIG_OPERATION_CONFLICT",
  "DNS_RECORD_DRIFT",
  "GLOBAL_PORT_CONFLICT",
] as const;

export type XrayQuickConfigRetryErrorCode = typeof XRAY_QUICK_CONFIG_RETRY_ERROR_CODES[number];

export class XrayQuickConfigRetryError extends Error {
  constructor(readonly code: XrayQuickConfigRetryErrorCode) {
    super(code);
    this.name = "XrayQuickConfigRetryError";
  }
}

type RetryConfig = Readonly<{
  id: number;
  configTag: string;
  revision: number;
  dnsAccountId: number;
  zoneId: number;
  fqdn: string;
  topologyId: number;
  engine: XrayQuickConfigForwardEngine;
  targetAddress: string;
  targetPort: number;
  publicPort: number;
  allocationId: number;
  allocationVersion: number;
  allocationOwnerType: "QUICK_CONFIG" | "XRAY_INBOUND";
  allocationOwnerTag: string;
}>;

type ManagedDnsRecord = Readonly<{
  id: number;
  providerRecordId: string | null;
  status: "DESIRED" | "APPLIED" | "UNKNOWN";
  remoteTupleHash: string;
}>;

type DnsBackup = Readonly<{
  dnsAccountId: number;
  zoneId: number;
  providerRecordId: string;
  fqdn: string;
  recordType: "A" | "AAAA" | "CNAME";
  providerLineId: string;
  value: string;
  ttl: number;
  remoteTupleHash: string;
  snapshotOrder: number;
}>;

const q = quoteIdentifier;

function fail(code: XrayQuickConfigRetryErrorCode): never {
  throw new XrayQuickConfigRetryError(code);
}

function positiveInteger(value: unknown, code: XrayQuickConfigRetryErrorCode = "QUICK_CONFIG_OPERATION_CONFLICT"): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) fail(code);
  return parsed;
}

function port(value: unknown): number {
  const parsed = positiveInteger(value);
  if (parsed > 65_535) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  return parsed;
}

function boundedText(value: unknown, maximum: number, code: XrayQuickConfigRetryErrorCode): string {
  if (typeof value !== "string" || !value || Buffer.byteLength(value, "utf8") > maximum
    || /[\u0000-\u001f\u007f]/.test(value)) fail(code);
  return value;
}

function databaseBoolean(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || value === "true";
}

function engine(value: unknown): XrayQuickConfigForwardEngine {
  if (!XRAY_QUICK_CONFIG_FORWARD_ENGINES.includes(value as XrayQuickConfigForwardEngine)) {
    fail("QUICK_CONFIG_OPERATION_CONFLICT");
  }
  return value as XrayQuickConfigForwardEngine;
}

async function rootOperation(operationId: number): Promise<Row> {
  let currentId = operationId;
  const seen = new Set<number>();
  for (let depth = 0; depth < 32; depth += 1) {
    if (seen.has(currentId)) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    seen.add(currentId);
    const [row] = await queryRaw<Row>(
      `SELECT ${q("id")}, ${q("quickConfigId")}, ${q("type")}, ${q("toTopologyRevisionId")}, ${q("retryOfOperationId")},
              ${q("requestSummaryJson")}
         FROM ${q("xray_quick_config_operations")} WHERE ${q("id")} = ? LIMIT 1`,
      [currentId],
    );
    if (!row) fail("QUICK_CONFIG_NOT_FOUND");
    if (row.type === "APPLY" || row.type === "EDIT" || row.type === "REMOVE") return row;
    if (row.type !== "RETRY") fail("QUICK_CONFIG_OPERATION_CONFLICT");
    currentId = positiveInteger(row.retryOfOperationId);
  }
  fail("QUICK_CONFIG_OPERATION_CONFLICT");
}

async function loadConfig(quickConfigId: number, topologyId: number): Promise<RetryConfig> {
  const [row] = await queryRaw<Row>(
    `SELECT qc.${q("id")}, qc.${q("configTag")}, qc.${q("revision")}, qc.${q("state")},
            qc.${q("currentOperationId")}, qc.${q("desiredTopologyRevisionId")}, qc.${q("dnsAccountId")},
            qc.${q("zoneId")}, qc.${q("fqdn")}, t.${q("id")} AS ${q("topologyId")}, t.${q("engine")},
            t.${q("targetAddress")}, t.${q("targetPort")}, t.${q("publicPort")}, t.${q("portAllocationId")},
            t.${q("state")} AS ${q("topologyState")}, a.${q("status")} AS ${q("allocationStatus")},
            a.${q("version")} AS ${q("allocationVersion")}, a.${q("port")} AS ${q("allocationPort")},
            a.${q("primaryOwnerType")} AS ${q("allocationOwnerType")},
            a.${q("primaryOwnerTag")} AS ${q("allocationOwnerTag")}
       FROM ${q("xray_quick_configs")} qc
       JOIN ${q("xray_quick_config_topology_revisions")} t ON t.${q("id")} = qc.${q("desiredTopologyRevisionId")}
       JOIN ${q("global_port_allocations")} a ON a.${q("id")} = t.${q("portAllocationId")}
      WHERE qc.${q("id")} = ? AND t.${q("id")} = ? LIMIT 1`,
    [quickConfigId, topologyId],
  );
  if (!row) fail("QUICK_CONFIG_NOT_FOUND");
  if (row.state !== "FAILED" || row.currentOperationId !== null && row.currentOperationId !== undefined
    || Number(row.desiredTopologyRevisionId) !== topologyId
    || !["APPLYING", "ABANDONED"].includes(String(row.topologyState))
    || row.allocationStatus !== "ACTIVE" || Number(row.allocationPort) !== Number(row.publicPort)) {
    fail("QUICK_CONFIG_OPERATION_CONFLICT");
  }
  const configTag = boundedText(row.configTag, 128, "QUICK_CONFIG_OPERATION_CONFLICT");
  const ownerType = row.allocationOwnerType;
  const ownerTag = boundedText(row.allocationOwnerTag, 128, "GLOBAL_PORT_CONFLICT");
  if ((ownerType !== "QUICK_CONFIG" && ownerType !== "XRAY_INBOUND")
    || ownerType === "QUICK_CONFIG" && ownerTag !== configTag) fail("GLOBAL_PORT_CONFLICT");
  return {
    id: positiveInteger(row.id, "QUICK_CONFIG_NOT_FOUND"),
    configTag,
    revision: positiveInteger(row.revision, "QUICK_CONFIG_REVISION_CONFLICT"),
    dnsAccountId: positiveInteger(row.dnsAccountId),
    zoneId: positiveInteger(row.zoneId),
    fqdn: boundedText(row.fqdn, 253, "DNS_RECORD_DRIFT").toLowerCase(),
    topologyId: positiveInteger(row.topologyId),
    engine: engine(row.engine),
    targetAddress: boundedText(row.targetAddress, 2_048, "QUICK_CONFIG_OPERATION_CONFLICT"),
    targetPort: port(row.targetPort),
    publicPort: port(row.publicPort),
    allocationId: positiveInteger(row.portAllocationId, "GLOBAL_PORT_CONFLICT"),
    allocationVersion: positiveInteger(row.allocationVersion, "GLOBAL_PORT_CONFLICT"),
    allocationOwnerType: ownerType,
    allocationOwnerTag: ownerTag,
  };
}

async function forwardRouteSegments(config: RetryConfig) {
  const rows = await queryRaw<Row>(
    `SELECT ${q("hostId")}, ${q("routeMode")}, ${q("relayHopsJson")}, ${q("state")} FROM ${q("xray_quick_config_routes")}
      WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ?
      ORDER BY ${q("sortOrder")} ASC, ${q("id")} ASC`,
    [config.id, config.topologyId],
  );
  for (const row of rows) {
    if (row.state !== "APPLYING" && row.state !== "RETIRED") fail("QUICK_CONFIG_OPERATION_CONFLICT");
  }
  return compileQuickConfigTopology(rows.map(row => ({ hostId: row.hostId, routeMode: row.routeMode, relayHopsJson: row.relayHopsJson })), config);
}

async function currentAllocationVersion(config: RetryConfig): Promise<number> {
  const [row] = await queryRaw<Row>(
    `SELECT ${q("version")}, ${q("status")}, ${q("primaryOwnerType")}, ${q("primaryOwnerTag")}
       FROM ${q("global_port_allocations")} WHERE ${q("id")} = ? AND ${q("port")} = ? LIMIT 1`,
    [config.allocationId, config.publicPort],
  );
  if (!row || row.status !== "ACTIVE" || row.primaryOwnerType !== config.allocationOwnerType
    || row.primaryOwnerTag !== config.allocationOwnerTag) fail("GLOBAL_PORT_CONFLICT");
  return positiveInteger(row.version, "GLOBAL_PORT_CONFLICT");
}

async function managedDnsRecords(config: RetryConfig): Promise<ManagedDnsRecord[]> {
  const rows = await queryRaw<Row>(
    `SELECT dr.${q("id")}, dr.${q("providerRecordId")}, dr.${q("fqdn")}, dr.${q("recordType")},
            dr.${q("providerLineId")}, dr.${q("value")}, dr.${q("ttl")}, dr.${q("status")},
            dr.${q("remoteTupleHash")}, r.${q("topologyRevisionId")}, r.${q("providerLineId")} AS ${q("routeLineId")},
            r.${q("addressFamily")}, r.${q("address")}, r.${q("state")} AS ${q("routeState")}
       FROM ${q("xray_quick_config_dns_records")} dr
       JOIN ${q("xray_quick_config_routes")} r ON r.${q("id")} = dr.${q("routeId")}
      WHERE dr.${q("quickConfigId")} = ? AND r.${q("topologyRevisionId")} = ?
      ORDER BY dr.${q("id")} ASC`,
    [config.id, config.topologyId],
  );
  if (rows.length < 1 || rows.length > 64) fail("DNS_RECORD_DRIFT");
  return rows.map((row) => {
    const recordType = row.recordType === "A" || row.recordType === "AAAA" ? row.recordType : fail("DNS_RECORD_DRIFT");
    const providerLineId = boundedText(row.providerLineId, 128, "DNS_RECORD_DRIFT");
    const value = boundedText(row.value, 2_048, "DNS_RECORD_DRIFT");
    const ttl = positiveInteger(row.ttl, "DNS_RECORD_DRIFT");
    const expectedType = row.addressFamily === "IPV4" ? "A" : row.addressFamily === "IPV6" ? "AAAA" : null;
    const tupleHash = computeXrayQuickConfigDnsTupleHash({ fqdn: config.fqdn, recordType, providerLineId, value, ttl });
    const status = String(row.status);
    if (!expectedType || expectedType !== recordType || Number(row.topologyRevisionId) !== config.topologyId
      || row.routeLineId !== providerLineId || row.address !== value || row.fqdn !== config.fqdn
      || row.routeState !== "APPLYING" && row.routeState !== "RETIRED"
      || row.remoteTupleHash !== tupleHash || ttl > 604_800
      || !["DESIRED", "APPLIED", "UNKNOWN"].includes(status)) fail("DNS_RECORD_DRIFT");
    const providerRecordId = row.providerRecordId == null
      ? null : boundedText(row.providerRecordId, 128, "DNS_RECORD_DRIFT");
    return {
      id: positiveInteger(row.id, "DNS_RECORD_DRIFT"),
      providerRecordId,
      status: status as ManagedDnsRecord["status"],
      remoteTupleHash: tupleHash,
    };
  });
}

async function rootBackups(rootOperationId: number, config: RetryConfig): Promise<DnsBackup[]> {
  const rows = await queryRaw<Row>(
    `SELECT ${q("dnsAccountId")}, ${q("zoneId")}, ${q("providerRecordId")}, ${q("fqdn")}, ${q("recordType")},
            ${q("providerLineId")}, ${q("value")}, ${q("ttl")}, ${q("remoteTupleHash")}, ${q("snapshotOrder")}, ${q("state")}
       FROM ${q("xray_quick_config_dns_record_backups")} WHERE ${q("operationId")} = ?
      ORDER BY ${q("snapshotOrder")} ASC, ${q("id")} ASC`,
    [rootOperationId],
  );
  if (rows.length > 64) fail("DNS_RECORD_DRIFT");
  const orders = new Set<number>();
  return rows.map((row) => {
    const recordType = row.recordType === "A" || row.recordType === "AAAA" || row.recordType === "CNAME"
      ? row.recordType : fail("DNS_RECORD_DRIFT");
    const providerLineId = boundedText(row.providerLineId, 128, "DNS_RECORD_DRIFT");
    const value = boundedText(row.value, 2_048, "DNS_RECORD_DRIFT");
    const ttl = positiveInteger(row.ttl, "DNS_RECORD_DRIFT");
    const fqdn = boundedText(row.fqdn, 253, "DNS_RECORD_DRIFT").toLowerCase();
    const remoteTupleHash = computeXrayQuickConfigDnsTupleHash({ fqdn, recordType, providerLineId, value, ttl });
    const snapshotOrder = Number(row.snapshotOrder);
    if (Number(row.dnsAccountId) !== config.dnsAccountId || Number(row.zoneId) !== config.zoneId
      || fqdn !== config.fqdn || row.remoteTupleHash !== remoteTupleHash || ttl > 604_800
      || !Number.isSafeInteger(snapshotOrder) || snapshotOrder < 0 || snapshotOrder >= 64 || orders.has(snapshotOrder)
      || !["CAPTURED", "RESTORED"].includes(String(row.state))) fail("DNS_RECORD_DRIFT");
    orders.add(snapshotOrder);
    return {
      dnsAccountId: config.dnsAccountId,
      zoneId: config.zoneId,
      providerRecordId: boundedText(row.providerRecordId, 128, "DNS_RECORD_DRIFT"),
      fqdn,
      recordType,
      providerLineId,
      value,
      ttl,
      remoteTupleHash,
      snapshotOrder,
    };
  });
}

async function insertStep(input: {
  operationId: number;
  operationTag: string;
  stepKey: string;
  kind: string;
  subjectType: string;
  subjectId: string | null;
  status?: "PENDING" | "SUCCESS";
  requestSummaryJson?: string;
  now: Date;
}) {
  const status = input.status ?? "PENDING";
  await insertAndGetId("xray_quick_config_operation_steps", {
    operationId: input.operationId,
    stepKey: input.stepKey,
    kind: input.kind,
    subjectType: input.subjectType,
    subjectId: input.subjectId,
    status,
    attemptCount: status === "SUCCESS" ? 1 : 0,
    idempotencyKey: `${input.operationTag}:${input.stepKey}`,
    requestSummaryJson: input.requestSummaryJson ?? "{}",
    resultSummaryJson: status === "SUCCESS" ? "{}" : null,
    errorCode: null,
    startedAt: status === "SUCCESS" ? input.now : null,
    finishedAt: status === "SUCCESS" ? input.now : null,
    updatedAt: input.now,
  });
}

async function createDnsCompensationRetry(input: {
  sourceOperationId: number;
  expectedOperationRevision: number;
  userId: number;
  root: Row;
}): Promise<{ operationId: number; operationRevision: 1 }> {
  const quickConfigId = positiveInteger(input.root.quickConfigId, "QUICK_CONFIG_NOT_FOUND");
  const topologyId = positiveInteger(input.root.toTopologyRevisionId);
  const now = nowDate();
  const operationTag = `quick-config-operation:${crypto.randomUUID()}`;

  return withDatabaseTransaction(async () => {
    const [source] = await queryRaw<Row>(
      `SELECT ${q("quickConfigId")}, ${q("status")}, ${q("revision")}, ${q("errorCode")}, ${q("activeSlot")}
         FROM ${q("xray_quick_config_operations")} WHERE ${q("id")} = ? LIMIT 1`,
      [input.sourceOperationId],
    );
    if (!source || Number(source.quickConfigId) !== quickConfigId
      || Number(source.revision) !== input.expectedOperationRevision) fail("QUICK_CONFIG_REVISION_CONFLICT");
    if (source.status !== "PARTIAL_FAILURE" || source.errorCode !== "DNS_COMPENSATION_FAILED"
      || source.activeSlot !== null && source.activeSlot !== undefined) fail("QUICK_CONFIG_OPERATION_CONFLICT");

    const [config] = await queryRaw<Row>(
      `SELECT qc.${q("revision")}, qc.${q("state")}, qc.${q("currentOperationId")},
              qc.${q("desiredTopologyRevisionId")}, t.${q("state")} AS ${q("topologyState")}
         FROM ${q("xray_quick_configs")} qc
         JOIN ${q("xray_quick_config_topology_revisions")} t
           ON t.${q("id")} = qc.${q("desiredTopologyRevisionId")}
        WHERE qc.${q("id")} = ? AND t.${q("id")} = ? LIMIT 1`,
      [quickConfigId, topologyId],
    );
    if (!config || config.state !== "PARTIAL_FAILURE"
      || config.currentOperationId !== null && config.currentOperationId !== undefined
      || Number(config.desiredTopologyRevisionId) !== topologyId
      || config.topologyState !== "APPLYING") fail("QUICK_CONFIG_OPERATION_CONFLICT");
    const configRevision = positiveInteger(config.revision, "QUICK_CONFIG_REVISION_CONFLICT");

    const backups = await queryRaw<Row>(
      `SELECT ${q("dnsAccountId")}, ${q("zoneId")}, ${q("providerRecordId")}, ${q("fqdn")},
              ${q("recordType")}, ${q("providerLineId")}, ${q("value")}, ${q("ttl")},
              ${q("remoteTupleHash")}, ${q("snapshotOrder")}
         FROM ${q("xray_quick_config_dns_record_backups")}
        WHERE ${q("operationId")} = ? AND ${q("state")} IN ('CAPTURED', 'RESTORING', 'FAILED', 'SKIPPED_DRIFTED')
        ORDER BY ${q("snapshotOrder")} ASC, ${q("id")} ASC`,
      [input.sourceOperationId],
    );
    if (backups.length > 64) fail("DNS_RECORD_DRIFT");
    const backupProviderIds = new Set(backups.map((row) => boundedText(row.providerRecordId, 128, "DNS_RECORD_DRIFT")));
    const managed = await queryRaw<Row>(
      `SELECT dr.${q("id")}, dr.${q("providerRecordId")}
         FROM ${q("xray_quick_config_dns_records")} dr
         JOIN ${q("xray_quick_config_routes")} r ON r.${q("id")} = dr.${q("routeId")}
        WHERE dr.${q("quickConfigId")} = ? AND r.${q("topologyRevisionId")} = ?
          AND dr.${q("providerRecordId")} IS NOT NULL AND dr.${q("status")} IN ('DESIRED', 'APPLIED', 'UNKNOWN')
        ORDER BY dr.${q("id")} ASC`,
      [quickConfigId, topologyId],
    );
    if (managed.length > 64) fail("DNS_RECORD_DRIFT");
    const createdManaged = managed.filter((row) => !backupProviderIds.has(boundedText(row.providerRecordId, 128, "DNS_RECORD_DRIFT")));
    if (backups.length === 0 && createdManaged.length === 0) fail("DNS_RECORD_DRIFT");

    const operationId = await insertAndGetId("xray_quick_config_operations", {
      operationTag,
      quickConfigId,
      type: "RETRY",
      status: "QUEUED",
      phase: "RESTORING_DNS",
      activeSlot: 1,
      revision: 1,
      expectedRevision: configRevision,
      fromTopologyRevisionId: null,
      toTopologyRevisionId: topologyId,
      requestSummaryJson: JSON.stringify({ kind: "DNS_COMPENSATION_RECOVERY" }),
      retryOfOperationId: input.sourceOperationId,
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

    for (const [index, backup] of backups.entries()) {
      const recordType = String(backup.recordType);
      const snapshotOrder = Number(backup.snapshotOrder);
      if (!Number.isSafeInteger(snapshotOrder) || snapshotOrder < 0 || snapshotOrder >= 64
        || !["A", "AAAA", "CNAME"].includes(recordType)) fail("DNS_RECORD_DRIFT");
      await insertAndGetId("xray_quick_config_dns_record_backups", {
        operationId,
        dnsAccountId: positiveInteger(backup.dnsAccountId, "DNS_RECORD_DRIFT"),
        zoneId: positiveInteger(backup.zoneId, "DNS_RECORD_DRIFT"),
        providerRecordId: boundedText(backup.providerRecordId, 128, "DNS_RECORD_DRIFT"),
        fqdn: boundedText(backup.fqdn, 253, "DNS_RECORD_DRIFT").toLowerCase(),
        recordType,
        providerLineId: boundedText(backup.providerLineId, 128, "DNS_RECORD_DRIFT"),
        value: boundedText(backup.value, 2_048, "DNS_RECORD_DRIFT"),
        ttl: positiveInteger(backup.ttl, "DNS_RECORD_DRIFT"),
        remoteTupleHash: boundedText(backup.remoteTupleHash, 64, "DNS_RECORD_DRIFT"),
        snapshotOrder: index,
        state: "CAPTURED",
        createdAt: now,
        updatedAt: now,
      });
    }
    for (const row of managed) {
      await insertStep({
        operationId,
        operationTag,
        stepKey: `dns-recovery-owned-${positiveInteger(row.id, "DNS_RECORD_DRIFT")}`,
        kind: "DNS_CREATE",
        subjectType: "DNS_RECORD",
        subjectId: String(positiveInteger(row.id, "DNS_RECORD_DRIFT")),
        status: "SUCCESS",
        now,
      });
    }
    for (let index = 0; index < createdManaged.length + backups.length; index += 1) {
      await insertStep({
        operationId,
        operationTag,
        stepKey: `dns-recovery-restore-${index + 1}`,
        kind: "DNS_RESTORE",
        subjectType: "DNS_RECORD",
        subjectId: null,
        now,
      });
    }
    const changed = await executeRaw(
      `UPDATE ${q("xray_quick_configs")} SET ${q("state")} = 'COMPENSATING',
          ${q("currentOperationId")} = ?, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("revision")} = ? AND ${q("state")} = 'PARTIAL_FAILURE'
          AND ${q("currentOperationId")} IS NULL AND ${q("desiredTopologyRevisionId")} = ?`,
      [operationId, now, quickConfigId, configRevision, topologyId],
    );
    if (rawAffectedRows(changed) !== 1) fail("QUICK_CONFIG_REVISION_CONFLICT");
    await afterDatabaseCommit(() => import("./xrayQuickConfigOperationService")
      .then(({ kickQuickConfigOperationWorker }) => kickQuickConfigOperationWorker()));
    return { operationId, operationRevision: 1 as const };
  });
}

function forwardRuleReference(ruleId: number, hostId: number): GlobalPortReferenceInput {
  return {
    resourceType: "FORWARD_RULE",
    resourceId: ruleId,
    hostId,
    network: "TCP",
    role: "PUBLIC_LISTENER",
    isOwning: true,
  };
}

async function createApplyRetry(input: {
  sourceOperationId: number;
  expectedOperationRevision: number;
  userId: number;
  root: Row;
}): Promise<{ operationId: number; operationRevision: 1 }> {
  const quickConfigId = positiveInteger(input.root.quickConfigId, "QUICK_CONFIG_NOT_FOUND");
  const topologyId = positiveInteger(input.root.toTopologyRevisionId);
  const rootOperationId = positiveInteger(input.root.id);
  const now = nowDate();
  const operationTag = `quick-config-operation:${crypto.randomUUID()}`;

  return withDatabaseTransaction(async () => {
    const [source] = await queryRaw<Row>(
      `SELECT ${q("quickConfigId")}, ${q("status")}, ${q("revision")} FROM ${q("xray_quick_config_operations")}
        WHERE ${q("id")} = ? LIMIT 1`,
      [input.sourceOperationId],
    );
    if (!source || Number(source.quickConfigId) !== quickConfigId
      || Number(source.revision) !== input.expectedOperationRevision) fail("QUICK_CONFIG_REVISION_CONFLICT");
    if (source.status !== "FAILED") fail("QUICK_CONFIG_OPERATION_CONFLICT");

    const config = await loadConfig(quickConfigId, topologyId);
    const segments = await forwardRouteSegments(config);
    const hostIds = segments.map(segment => segment.hostId);
    const dnsRecords = await managedDnsRecords(config);
    const backups = await rootBackups(rootOperationId, config);
    const pendingCleanup = await queryRaw<Row>(
      `SELECT ${q("id")} FROM ${q("forward_rules")}
        WHERE ${q("xrayQuickConfigId")} = ? AND ${q("pendingDelete")} = ? AND ${q("isRunning")} = ?
        ORDER BY ${q("id")} ASC`,
      [config.id, true, false],
    );
    for (const row of pendingCleanup) await finalizeForwardRuleDelete(positiveInteger(row.id));

    const bindingRows = await queryRaw<Row>(
      `SELECT b.${q("id")} AS ${q("bindingId")}, b.${q("state")} AS ${q("bindingState")},
              r.${q("id")} AS ${q("ruleId")}, r.${q("hostId")}, r.${q("forwardType")}, r.${q("protocol")},
              r.${q("gostMode")}, r.${q("sourcePort")}, r.${q("targetIp")}, r.${q("targetPort")},
              r.${q("targetExternalProxyNodeId")}, r.${q("xrayQuickConfigId")}, r.${q("isEnabled")},
              r.${q("isRunning")}, r.${q("pendingDelete")}, r.${q("disabledByTunnel")},
              r.${q("disabledByGroup")}, r.${q("disabledByUser")}
         FROM ${q("xray_quick_config_rule_bindings")} b
         LEFT JOIN ${q("forward_rules")} r ON r.${q("id")} = b.${q("forwardRuleId")}
        WHERE b.${q("quickConfigId")} = ? AND b.${q("topologyRevisionId")} = ?
        ORDER BY b.${q("id")} ASC`,
      [config.id, config.topologyId],
    );

    const operationId = await insertAndGetId("xray_quick_config_operations", {
      operationTag,
      quickConfigId: config.id,
      type: "RETRY",
      status: "QUEUED",
      phase: "WAITING_RULES_READY",
      activeSlot: 1,
      revision: 1,
      expectedRevision: config.revision,
      fromTopologyRevisionId: null,
      toTopologyRevisionId: config.topologyId,
      requestSummaryJson: "{}",
      retryOfOperationId: input.sourceOperationId,
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

    const topologyChanged = await executeRaw(
      `UPDATE ${q("xray_quick_config_topology_revisions")} SET ${q("state")} = 'APPLYING', ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("activeSlot")} IS NULL
          AND ${q("state")} IN ('APPLYING', 'ABANDONED')
          AND EXISTS (
            SELECT 1 FROM ${q("xray_quick_configs")} qc
             WHERE qc.${q("id")} = ? AND qc.${q("revision")} = ? AND qc.${q("state")} = 'FAILED'
               AND qc.${q("currentOperationId")} IS NULL AND qc.${q("desiredTopologyRevisionId")} = ?
          )`,
      [now, config.topologyId, config.id, config.id, config.revision, config.topologyId],
    );
    if (rawAffectedRows(topologyChanged) !== 1) fail("QUICK_CONFIG_REVISION_CONFLICT");
    const routesChanged = await executeRaw(
      `UPDATE ${q("xray_quick_config_routes")} SET ${q("state")} = 'APPLYING', ${q("updatedAt")} = ?
        WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ? AND ${q("state")} IN ('APPLYING', 'RETIRED')`,
      [now, config.id, config.topologyId],
    );
    if (rawAffectedRows(routesChanged) < 1) fail("QUICK_CONFIG_REVISION_CONFLICT");

    const expectedHosts = new Set(hostIds);
    const reusableRules = new Map<number, number>();
    for (const row of bindingRows) {
      const bindingId = positiveInteger(row.bindingId);
      const ruleId = Number(row.ruleId);
      const pending = !Number.isSafeInteger(ruleId) || ruleId <= 0 || databaseBoolean(row.pendingDelete);
      if (pending) {
        if (row.bindingState !== "REMOVED") {
          const removed = await executeRaw(
            `UPDATE ${q("xray_quick_config_rule_bindings")} SET ${q("state")} = 'REMOVED', ${q("updatedAt")} = ?
              WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ? AND ${q("state")} <> 'REMOVED'`,
            [now, bindingId, config.id, config.topologyId],
          );
          if (rawAffectedRows(removed) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
        }
        continue;
      }
      const hostId = positiveInteger(row.hostId);
      const segment = segments.find(candidate => candidate.hostId === hostId);
      if (!expectedHosts.has(hostId) || reusableRules.has(hostId)
        || row.forwardType !== config.engine || row.protocol !== "tcp" || row.gostMode !== "direct"
        || Number(row.sourcePort) !== config.publicPort || row.targetIp !== segment?.targetAddress
        || Number(row.targetPort) !== segment?.targetPort || row.targetExternalProxyNodeId != null
        || Number(row.xrayQuickConfigId) !== config.id || !databaseBoolean(row.isEnabled)
        || databaseBoolean(row.disabledByTunnel) || databaseBoolean(row.disabledByGroup)
        || databaseBoolean(row.disabledByUser)) fail("QUICK_CONFIG_OPERATION_CONFLICT");
      reusableRules.set(hostId, positiveInteger(ruleId));
      const reset = await executeRaw(
        `UPDATE ${q("xray_quick_config_rule_bindings")} SET ${q("state")} = 'APPLYING', ${q("updatedAt")} = ?
          WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ?`,
        [now, bindingId, config.id, config.topologyId],
      );
      if (rawAffectedRows(reset) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    }

    let allocationVersion = await currentAllocationVersion(config);
    const ruleIds: Array<{ id: number; hostId: number }> = [];
    for (const [index, hostId] of hostIds.entries()) {
      const segment = segments[index];
      let ruleId = reusableRules.get(hostId);
      if (!ruleId) {
        const portResource = await ensureQuickConfigPortResource({
          userId: input.userId,
          hostId,
          engine: config.engine,
        });
        ruleId = await createForwardRule({
          hostId,
          name: `[快速配置] ${config.fqdn}（重试 ${index + 1}）`,
          forwardType: config.engine,
          protocol: "tcp",
          gostMode: "direct",
          sourcePort: config.publicPort,
          targetIp: segment.targetAddress,
          targetPort: segment.targetPort,
          targetExternalProxyNodeId: null,
          xrayQuickConfigId: config.id,
          portResourceGroupId: portResource.groupId,
          proxyProtocolReceive: false,
          proxyProtocolSend: false,
          proxyProtocolExitReceive: false,
          proxyProtocolExitSend: false,
          isEnabled: true,
          isRunning: false,
          pendingDelete: false,
          userId: input.userId,
          createdAt: now,
          updatedAt: now,
        });
        await insertAndGetId("xray_quick_config_rule_bindings", {
          bindingTag: `${operationTag}:rule:${hostId}`,
          quickConfigId: config.id,
          topologyRevisionId: config.topologyId,
          forwardRuleId: ruleId,
          state: "APPLYING",
          createdAt: now,
          updatedAt: now,
        });
        if (config.allocationOwnerType === "QUICK_CONFIG") {
          const allocation = await addActiveGlobalPortOwningReference({
            allocationId: config.allocationId,
            expectedVersion: allocationVersion,
            owner: { type: "QUICK_CONFIG", stableIdentity: config.configTag },
            reference: forwardRuleReference(ruleId, hostId),
            now,
          });
          allocationVersion = allocation.version;
        }
      }
      await assignQuickConfigRulePortResource(ruleId);
      ruleIds.push({ id: ruleId, hostId });
    }

    for (const record of dnsRecords) {
      const changed = await executeRaw(
        `UPDATE ${q("xray_quick_config_dns_records")} SET ${q("status")} = 'DESIRED', ${q("updatedAt")} = ?
          WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("remoteTupleHash")} = ?
            AND ${q("status")} IN ('DESIRED', 'APPLIED', 'UNKNOWN')`,
        [now, record.id, config.id, record.remoteTupleHash],
      );
      if (rawAffectedRows(changed) !== 1) fail("DNS_RECORD_DRIFT");
    }

    for (const backup of backups) {
      await insertAndGetId("xray_quick_config_dns_record_backups", {
        operationId,
        ...backup,
        state: "CAPTURED",
        createdAt: now,
        updatedAt: now,
      });
    }

    await insertStep({ operationId, operationTag, stepKey: "domain-recheck", kind: "DOMAIN_RECHECK", subjectType: "DOMAIN", subjectId: config.fqdn, status: "SUCCESS", now });
    await insertStep({ operationId, operationTag, stepKey: "port-reserve", kind: "PORT_RESERVE", subjectType: "ALLOCATION", subjectId: String(config.allocationId), status: "SUCCESS", now });
    for (const { id } of ruleIds) {
      await insertStep({ operationId, operationTag, stepKey: `rule-create-${id}`, kind: "RULE_CREATE", subjectType: "RULE", subjectId: String(id), status: "SUCCESS", now });
      await insertStep({ operationId, operationTag, stepKey: `rule-verify-${id}`, kind: "RULE_VERIFY", subjectType: "RULE", subjectId: String(id), now });
    }
    for (const record of dnsRecords) {
      await insertStep({
        operationId,
        operationTag,
        stepKey: `dns-apply-${record.id}`,
        kind: "DNS_CREATE",
        subjectType: "DNS_RECORD",
        subjectId: String(record.id),
        now,
      });
      await insertStep({ operationId, operationTag, stepKey: `dns-verify-${record.id}`, kind: "DNS_VERIFY", subjectType: "DNS_RECORD", subjectId: String(record.id), now });
    }
    for (const [index] of backups.entries()) {
      await insertStep({ operationId, operationTag, stepKey: `dns-delete-${index + 1}`, kind: "DNS_DELETE", subjectType: "DNS_RECORD", subjectId: null, now });
    }
    for (let index = 0; index < dnsRecords.length + backups.length; index += 1) {
      await insertStep({ operationId, operationTag, stepKey: `dns-restore-${index + 1}`, kind: "DNS_RESTORE", subjectType: "DNS_RECORD", subjectId: null, now });
    }

    const configChanged = await executeRaw(
      `UPDATE ${q("xray_quick_configs")} SET ${q("state")} = 'APPLYING', ${q("currentOperationId")} = ?, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("revision")} = ? AND ${q("state")} = 'FAILED'
          AND ${q("currentOperationId")} IS NULL AND ${q("desiredTopologyRevisionId")} = ?`,
      [operationId, now, config.id, config.revision, config.topologyId],
    );
    if (rawAffectedRows(configChanged) !== 1) fail("QUICK_CONFIG_REVISION_CONFLICT");

    await afterDatabaseCommit(() => {
      for (const hostId of hostIds) pushAgentRefresh(hostId, "xray-quick-config-apply-retry", { urgent: true });
      void import("./xrayQuickConfigOperationService")
        .then(({ kickQuickConfigOperationWorker }) => kickQuickConfigOperationWorker());
    });
    return { operationId, operationRevision: 1 as const };
  });
}

export async function retryQuickConfigOperation(input: {
  operationId: unknown;
  expectedOperationRevision: unknown;
  userId: unknown;
}): Promise<{ operationId: number; operationRevision: 1 }> {
  const operationId = positiveInteger(input.operationId, "QUICK_CONFIG_NOT_FOUND");
  const expectedOperationRevision = positiveInteger(input.expectedOperationRevision, "QUICK_CONFIG_REVISION_CONFLICT");
  const userId = positiveInteger(input.userId);
  const [source] = await queryRaw<Row>(
    `SELECT ${q("quickConfigId")}, ${q("status")}, ${q("revision")}, ${q("errorCode")} FROM ${q("xray_quick_config_operations")}
      WHERE ${q("id")} = ? LIMIT 1`,
    [operationId],
  );
  if (!source) fail("QUICK_CONFIG_NOT_FOUND");
  if (Number(source.revision) !== expectedOperationRevision) fail("QUICK_CONFIG_REVISION_CONFLICT");
  const root = await rootOperation(operationId);
  if (Number(root.quickConfigId) !== Number(source.quickConfigId)) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  if (root.type === "REMOVE") {
    return retryQuickConfigRemoveOperation({ operationId, expectedOperationRevision, userId });
  }
  if (root.type === "EDIT") {
    try {
      const requestSummary = JSON.parse(String(root.requestSummaryJson ?? "")) as Record<string, unknown>;
      if (requestSummary.kind === "TOPOLOGY_EDIT") {
        const { retryQuickConfigTopologyEditOperation } = await import("./xrayQuickConfigEditService");
        return retryQuickConfigTopologyEditOperation({ operationId, expectedOperationRevision, userId });
      }
    } catch (error) {
      if (error instanceof XrayQuickConfigRetryError) throw error;
      fail("QUICK_CONFIG_OPERATION_CONFLICT");
    }
    const { retryXrayQuickConfigEngineSwitchRollback } = await import("./xrayQuickConfigEngineSwitchService");
    return retryXrayQuickConfigEngineSwitchRollback({ operationId, expectedOperationRevision, userId });
  }
  if (root.type === "APPLY" && source.status === "PARTIAL_FAILURE" && source.errorCode === "DNS_COMPENSATION_FAILED") {
    return createDnsCompensationRetry({
      sourceOperationId: operationId,
      expectedOperationRevision,
      userId,
      root,
    });
  }
  if (root.type !== "APPLY" || source.status !== "FAILED") fail("QUICK_CONFIG_OPERATION_CONFLICT");
  return createApplyRetry({ sourceOperationId: operationId, expectedOperationRevision, userId, root });
}
