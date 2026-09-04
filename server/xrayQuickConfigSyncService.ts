import crypto from "node:crypto";
import { compileQuickConfigTopology } from "./xrayQuickConfigTopology";
import { loadQuickConfigSegments } from "./xrayQuickConfigTopologyStore";

import {
  DnsPodProviderClient,
  DnsPodProviderError,
  type DnsPodRecord,
  type DnsPodRecordLine,
  type DnsPodZone,
} from "./dnsPodProviderClient";
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
import {
  addActiveGlobalPortOwningReference,
  type GlobalPortReferenceInput,
} from "./globalPortAllocationService";
import { withKeyedTaskLock } from "./keyedTaskLock";
import { ensureQuickConfigPortResource, assignQuickConfigRulePortResource } from "./quickConfigPortResourceService";
import { loadGlobalDnsProviderCredentials } from "./repositories/dnsProviderRepository";
import { createForwardRule, updateForwardRule } from "./repositories/forwardRuleRepository";
import { computeXrayQuickConfigDnsTupleHash, type XrayQuickConfigDnsTuple } from "./xrayQuickConfigDnsTuple";
import { XRAY_QUICK_CONFIG_FORWARD_ENGINES, type XrayQuickConfigForwardEngine } from "../shared/xrayQuickConfigForwardEngines";

export const XRAY_QUICK_CONFIG_SYNC_ERROR_CODES = [
  "QUICK_CONFIG_NOT_FOUND",
  "QUICK_CONFIG_REVISION_CONFLICT",
  "QUICK_CONFIG_OPERATION_CONFLICT",
  "QUICK_CONFIG_SYNC_CONFLICT",
  "GLOBAL_PORT_CONFLICT",
  "RULE_APPLY_FAILED",
  "DNS_PROVIDER_VALIDATION_STALE",
  "DNS_PROVIDER_UNAVAILABLE",
  "DNS_PROVIDER_INVALID_RESPONSE",
  "DNS_PROVIDER_REQUEST_REJECTED",
  "DNS_RECORD_DRIFT",
  "SENSITIVE_DATA_UNAVAILABLE",
] as const;

export type XrayQuickConfigSyncErrorCode = typeof XRAY_QUICK_CONFIG_SYNC_ERROR_CODES[number];

export class XrayQuickConfigSyncError extends Error {
  constructor(readonly code: XrayQuickConfigSyncErrorCode) {
    super(code);
    this.name = "XrayQuickConfigSyncError";
  }
}

type Row = Record<string, unknown>;
type SyncFence = Readonly<{
  operationId: number;
  quickConfigId: number;
  executionOwnerId: string;
  executionFence: number;
}>;

export type QuickConfigDnsSyncExpected = Readonly<{
  providerRecordId: string | null;
  relativeName: string;
  recordType: "A" | "AAAA";
  providerLineId: string;
  value: string;
  ttl: number;
}>;

export type QuickConfigDnsSyncAction = "KEEP" | "REPAIR" | "CREATE" | "ADOPT_CREATED" | "CONFLICT";

const q = quoteIdentifier;
const RULE_READY_TIMEOUT_MS = 120_000;
const SYNC_SUMMARY = JSON.stringify({ kind: "CONFIG_SYNC", schemaVersion: 1 });

function fail(code: XrayQuickConfigSyncErrorCode): never {
  throw new XrayQuickConfigSyncError(code);
}

function positiveInteger(value: unknown, code: XrayQuickConfigSyncErrorCode = "QUICK_CONFIG_SYNC_CONFLICT"): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) fail(code);
  return parsed;
}

function port(value: unknown): number {
  const parsed = positiveInteger(value);
  if (parsed > 65_535) fail("QUICK_CONFIG_SYNC_CONFLICT");
  return parsed;
}

function boundedText(value: unknown, maximum: number, code: XrayQuickConfigSyncErrorCode = "QUICK_CONFIG_SYNC_CONFLICT"): string {
  if (typeof value !== "string" || !value || Buffer.byteLength(value, "utf8") > maximum
    || /[\u0000-\u001f\u007f]/.test(value)) fail(code);
  return value;
}

function optionalProviderRecordId(value: unknown): string | null {
  if (value === null || value === undefined || value === "") return null;
  const id = boundedText(String(value), 128, "DNS_RECORD_DRIFT");
  if (!/^[1-9]\d*$/.test(id) || !Number.isSafeInteger(Number(id))) fail("DNS_RECORD_DRIFT");
  return id;
}

function databaseBoolean(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || value === "true";
}

function databaseDate(value: unknown): Date | null {
  if (value === null || value === undefined || value === "") return null;
  if (value instanceof Date && Number.isFinite(value.getTime())) return value;
  const number = Number(value);
  const date = Number.isFinite(number)
    ? new Date(number < 10_000_000_000 ? number * 1_000 : number)
    : new Date(String(value));
  return Number.isFinite(date.getTime()) ? date : null;
}

function engine(value: unknown): XrayQuickConfigForwardEngine {
  const normalized = boundedText(value, 32).toLowerCase();
  if (!(XRAY_QUICK_CONFIG_FORWARD_ENGINES as readonly string[]).includes(normalized)) {
    fail("QUICK_CONFIG_SYNC_CONFLICT");
  }
  return normalized as XrayQuickConfigForwardEngine;
}

function sameDnsTuple(record: DnsPodRecord, expected: QuickConfigDnsSyncExpected): boolean {
  return record.subdomain.toLowerCase() === expected.relativeName.toLowerCase()
    && record.recordType === expected.recordType
    && record.providerLineId === expected.providerLineId
    && record.value === expected.value
    && record.ttl === expected.ttl
    && record.status !== "DISABLE";
}

export function decideQuickConfigDnsSyncAction(input: {
  expected: QuickConfigDnsSyncExpected;
  current: DnsPodRecord | null;
  exactMatches: readonly DnsPodRecord[];
  createIntentRunning: boolean;
}): QuickConfigDnsSyncAction {
  if (input.current) {
    if (input.current.subdomain.toLowerCase() !== input.expected.relativeName.toLowerCase()) return "CONFLICT";
    if (input.exactMatches.some((record) => record.providerRecordId !== input.current!.providerRecordId)) return "CONFLICT";
    return sameDnsTuple(input.current, input.expected) ? "KEEP" : "REPAIR";
  }
  if (input.exactMatches.length === 0) return "CREATE";
  if (input.exactMatches.length === 1 && input.createIntentRunning) return "ADOPT_CREATED";
  return "CONFLICT";
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

export function isQuickConfigRuleSynchronized(row: Row, input: {
  quickConfigId: number;
  userId: number;
  hostId: number;
  engine: XrayQuickConfigForwardEngine;
  publicPort: number;
  targetAddress: string;
  targetPort: number;
}): boolean {
  return Number(row.xrayQuickConfigId) === input.quickConfigId
    && Number(row.userId) === input.userId
    && Number(row.hostId) === input.hostId
    && String(row.forwardType) === input.engine
    && row.protocol === "tcp"
    && row.gostMode === "direct"
    && Number(row.sourcePort) === input.publicPort
    && row.targetIp === input.targetAddress
    && Number(row.targetPort) === input.targetPort
    && row.targetExternalProxyNodeId == null
    && row.gostRelayHost == null
    && row.gostRelayPort == null
    && row.tunnelId == null
    && row.tunnelExitPort == null
    && row.forwardGroupId == null
    && row.forwardGroupRuleId == null
    && row.forwardGroupMemberId == null
    && !databaseBoolean(row.isForwardGroupTemplate)
    && !databaseBoolean(row.telegramErrorNotifyEnabled)
    && databaseBoolean(row.isEnabled)
    && !databaseBoolean(row.pendingDelete)
    && !databaseBoolean(row.disabledByTunnel)
    && !databaseBoolean(row.disabledByGroup)
    && !databaseBoolean(row.disabledByUser)
    && !String(row.protocolBlockReason ?? "").trim()
    && !databaseBoolean(row.proxyProtocolReceive)
    && !databaseBoolean(row.proxyProtocolSend)
    && !databaseBoolean(row.proxyProtocolExitReceive)
    && !databaseBoolean(row.proxyProtocolExitSend)
    && Number(row.proxyProtocolVersion ?? 1) === 1
    && !databaseBoolean(row.blockHttp)
    && !databaseBoolean(row.blockSocks)
    && !databaseBoolean(row.blockTls)
    && !databaseBoolean(row.tcpFastOpen)
    && !databaseBoolean(row.zeroCopy)
    && !databaseBoolean(row.udpOverTcp)
    && row.udpOverTcpPort == null
    && !databaseBoolean(row.failoverEnabled)
    && row.failoverStrategy === "fallback"
    && row.failoverTargets == null
    && Number(row.failoverSeconds ?? 60) === 60
    && Number(row.recoverSeconds ?? 120) === 120
    && databaseBoolean(row.autoFailback);
}

async function insertStep(input: {
  operationId: number;
  operationTag: string;
  stepKey: string;
  kind: "RULE_CREATE" | "RULE_VERIFY" | "DNS_CREATE" | "DNS_VERIFY";
  subjectType: "RULE" | "DNS_RECORD";
  subjectId: number;
  status?: "PENDING" | "SUCCESS";
  now: Date;
}) {
  await insertAndGetId("xray_quick_config_operation_steps", {
    operationId: input.operationId,
    stepKey: input.stepKey,
    kind: input.kind,
    subjectType: input.subjectType,
    subjectId: String(input.subjectId),
    status: input.status ?? "PENDING",
    attemptCount: input.status === "SUCCESS" ? 1 : 0,
    idempotencyKey: `${input.operationTag}:${input.stepKey}`,
    requestSummaryJson: "{}",
    resultSummaryJson: null,
    errorCode: null,
    startedAt: input.status === "SUCCESS" ? input.now : null,
    finishedAt: input.status === "SUCCESS" ? input.now : null,
    updatedAt: input.now,
  });
}

async function loadStartSnapshot(quickConfigId: number, expectedRevision: number) {
  const [config] = await queryRaw<Row>(
    `SELECT qc.${q("id")}, qc.${q("configTag")}, qc.${q("revision")}, qc.${q("state")},
            qc.${q("currentOperationId")}, qc.${q("activeTopologyRevisionId")}, qc.${q("desiredTopologyRevisionId")},
            qc.${q("dnsAccountId")}, qc.${q("zoneId")}, qc.${q("relativeName")}, qc.${q("fqdn")}, qc.${q("createdByUserId")},
            t.${q("id")} AS ${q("topologyId")}, t.${q("state")} AS ${q("topologyState")},
            t.${q("activeSlot")} AS ${q("topologyActiveSlot")}, t.${q("engine")}, t.${q("targetAddress")},
            t.${q("targetPort")}, t.${q("publicPort")}, t.${q("portAllocationId")},
            a.${q("status")} AS ${q("allocationStatus")}, a.${q("version")} AS ${q("allocationVersion")},
            a.${q("port")} AS ${q("allocationPort")}, a.${q("primaryOwnerType")} AS ${q("allocationOwnerType")},
            a.${q("primaryOwnerTag")} AS ${q("allocationOwnerTag")}
       FROM ${q("xray_quick_configs")} qc
       LEFT JOIN ${q("xray_quick_config_topology_revisions")} t ON t.${q("id")} = qc.${q("activeTopologyRevisionId")}
       LEFT JOIN ${q("global_port_allocations")} a ON a.${q("id")} = t.${q("portAllocationId")}
      WHERE qc.${q("id")} = ? LIMIT 1`,
    [quickConfigId],
  );
  if (!config) fail("QUICK_CONFIG_NOT_FOUND");
  if (Number(config.revision) !== expectedRevision) fail("QUICK_CONFIG_REVISION_CONFLICT");
  if (config.state !== "ACTIVE" || config.currentOperationId != null || config.desiredTopologyRevisionId != null
    || Number(config.activeTopologyRevisionId) !== Number(config.topologyId)
    || config.topologyState !== "APPLIED" || Number(config.topologyActiveSlot) !== 1) {
    fail("QUICK_CONFIG_OPERATION_CONFLICT");
  }
  const publicPort = port(config.publicPort);
  const allocationOwnerType = String(config.allocationOwnerType);
  const configTag = boundedText(config.configTag, 128);
  if (config.allocationStatus !== "ACTIVE" || Number(config.allocationPort) !== publicPort
    || (allocationOwnerType !== "QUICK_CONFIG" && allocationOwnerType !== "XRAY_INBOUND")
    || allocationOwnerType === "QUICK_CONFIG" && config.allocationOwnerTag !== configTag) {
    fail("GLOBAL_PORT_CONFLICT");
  }
  return {
    id: quickConfigId,
    revision: expectedRevision,
    ownerUserId: positiveInteger(config.createdByUserId),
    configTag,
    topologyId: positiveInteger(config.topologyId),
    dnsAccountId: positiveInteger(config.dnsAccountId),
    zoneId: positiveInteger(config.zoneId),
    relativeName: boundedText(config.relativeName, 253, "DNS_RECORD_DRIFT").toLowerCase(),
    fqdn: boundedText(config.fqdn, 253, "DNS_RECORD_DRIFT").toLowerCase(),
    engine: engine(config.engine),
    targetAddress: boundedText(config.targetAddress, 2_048),
    targetPort: port(config.targetPort),
    publicPort,
    allocationId: positiveInteger(config.portAllocationId, "GLOBAL_PORT_CONFLICT"),
    allocationVersion: positiveInteger(config.allocationVersion, "GLOBAL_PORT_CONFLICT"),
    allocationOwnerType,
  };
}

async function validateManagedDnsRows(config: Awaited<ReturnType<typeof loadStartSnapshot>>) {
  const rows = await queryRaw<Row>(
    `SELECT dr.${q("id")}, dr.${q("providerRecordId")}, dr.${q("fqdn")}, dr.${q("recordType")},
            dr.${q("providerLineId")}, dr.${q("value")}, dr.${q("ttl")}, dr.${q("status")},
            dr.${q("remoteTupleHash")}, r.${q("providerLineId")} AS ${q("routeLineId")},
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
    const tuple: XrayQuickConfigDnsTuple = { fqdn: config.fqdn, recordType, providerLineId, value, ttl };
    const expectedType = row.addressFamily === "IPV4" ? "A" : row.addressFamily === "IPV6" ? "AAAA" : null;
    if (!expectedType || expectedType !== recordType || row.routeLineId !== providerLineId || row.address !== value
      || row.fqdn !== config.fqdn || row.routeState !== "APPLIED" || ttl > 604_800
      || row.remoteTupleHash !== computeXrayQuickConfigDnsTupleHash(tuple)
      || !["DESIRED", "APPLIED", "UNKNOWN", "DRIFTED"].includes(String(row.status))) {
      fail("DNS_RECORD_DRIFT");
    }
    return { id: positiveInteger(row.id), providerRecordId: optionalProviderRecordId(row.providerRecordId), tuple };
  });
}

export async function createXrayQuickConfigSync(input: {
  id: unknown;
  expectedRevision: unknown;
  userId: unknown;
}): Promise<{ quickConfigId: number; operationId: number; state: "UPDATING" }> {
  const quickConfigId = positiveInteger(input.id, "QUICK_CONFIG_NOT_FOUND");
  const expectedRevision = positiveInteger(input.expectedRevision, "QUICK_CONFIG_REVISION_CONFLICT");
  const userId = positiveInteger(input.userId);
  return withKeyedTaskLock(`xray-quick-config-sync:${quickConfigId}`, async () => withDatabaseTransaction(async () => {
    const config = await loadStartSnapshot(quickConfigId, expectedRevision);
    const routes = await queryRaw<Row>(
      `SELECT ${q("hostId")}, ${q("routeMode")}, ${q("relayHopsJson")}, ${q("state")} FROM ${q("xray_quick_config_routes")}
        WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ? ORDER BY ${q("sortOrder")} ASC, ${q("id")} ASC`,
      [config.id, config.topologyId],
    );
    if (routes.length < 1 || routes.some((row) => row.state !== "APPLIED")) fail("QUICK_CONFIG_SYNC_CONFLICT");
    const segments = compileQuickConfigTopology(routes.map(row => ({ hostId: row.hostId, routeMode: row.routeMode, relayHopsJson: row.relayHopsJson })), config);
    const expectedHosts = segments.map(segment => segment.hostId);
    const dnsRecords = await validateManagedDnsRows(config);
    const ownedRules = await queryRaw<Row>(
      `SELECT * FROM ${q("forward_rules")} WHERE ${q("xrayQuickConfigId")} = ? ORDER BY ${q("id")} ASC`,
      [config.id],
    );
    const bindings = await queryRaw<Row>(
      `SELECT ${q("id")}, ${q("forwardRuleId")}, ${q("state")} FROM ${q("xray_quick_config_rule_bindings")}
        WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ? ORDER BY ${q("id")} ASC`,
      [config.id, config.topologyId],
    );
    const expectedHostSet = new Set(expectedHosts);
    if (ownedRules.some((row) => !expectedHostSet.has(positiveInteger(row.hostId)))) fail("QUICK_CONFIG_SYNC_CONFLICT");
    const operationTag = `quick-config-sync:${crypto.randomUUID()}`;
    const now = nowDate();
    const rulePlans: Array<{ ruleId: number; hostId: number; ready: boolean }> = [];
    let allocationVersion = config.allocationVersion;
    const ownedRuleIds = new Set(ownedRules.map((row) => positiveInteger(row.id)));
    for (const binding of bindings) {
      if (ownedRuleIds.has(Number(binding.forwardRuleId)) || binding.state === "REMOVED") continue;
      await executeRaw(
        `UPDATE ${q("xray_quick_config_rule_bindings")} SET ${q("state")} = 'REMOVED', ${q("updatedAt")} = ?
          WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ?`,
        [now, positiveInteger(binding.id), config.id, config.topologyId],
      );
      binding.state = "REMOVED";
    }

    for (const [index, hostId] of expectedHosts.entries()) {
      const segment = segments[index];
      const candidates = ownedRules.filter((row) => Number(row.hostId) === hostId);
      if (candidates.length > 1) fail("QUICK_CONFIG_SYNC_CONFLICT");
      let row = candidates[0];
      let ruleId: number;
      if (!row) {
        const portResource = await ensureQuickConfigPortResource({ userId: config.ownerUserId, hostId, engine: config.engine });
        ruleId = await createForwardRule({
          hostId,
          name: `[快速配置] ${config.fqdn} #${index + 1}`,
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
          userId: config.ownerUserId,
          createdAt: now,
          updatedAt: now,
        });
        row = { id: ruleId, hostId, xrayQuickConfigId: config.id, isRunning: false };
      } else {
        ruleId = positiveInteger(row.id);
        if (!isQuickConfigRuleSynchronized(row, { quickConfigId: config.id, userId: config.ownerUserId, hostId, engine: config.engine, publicPort: config.publicPort,
          targetAddress: segment.targetAddress, targetPort: segment.targetPort })) {
          await updateForwardRule(ruleId, {
            hostId,
            forwardType: config.engine,
            protocol: "tcp",
            gostMode: "direct",
            sourcePort: config.publicPort,
            targetIp: segment.targetAddress,
            targetPort: segment.targetPort,
            targetExternalProxyNodeId: null,
            xrayQuickConfigId: config.id,
            userId: config.ownerUserId,
            gostRelayHost: null,
            gostRelayPort: null,
            tunnelId: null,
            tunnelExitPort: null,
            forwardGroupId: null,
            forwardGroupRuleId: null,
            forwardGroupMemberId: null,
            isForwardGroupTemplate: false,
            telegramErrorNotifyEnabled: false,
            proxyProtocolReceive: false,
            proxyProtocolSend: false,
            proxyProtocolExitReceive: false,
            proxyProtocolExitSend: false,
            isEnabled: true,
            isRunning: false,
            pendingDelete: false,
            disabledByTunnel: false,
            disabledByGroup: false,
            disabledByUser: false,
            protocolBlockReason: null,
            proxyProtocolVersion: 1,
            blockHttp: false,
            blockSocks: false,
            blockTls: false,
            tcpFastOpen: false,
            zeroCopy: false,
            udpOverTcp: false,
            udpOverTcpPort: null,
            failoverEnabled: false,
            failoverStrategy: "fallback",
            failoverTargets: null,
            failoverSeconds: 60,
            recoverSeconds: 120,
            autoFailback: true,
          });
          row = { ...row, isRunning: false };
        }
      }
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
      await assignQuickConfigRulePortResource(ruleId);
      const matchingBindings = bindings.filter((binding) => Number(binding.forwardRuleId) === ruleId);
      if (matchingBindings.length > 1) fail("QUICK_CONFIG_SYNC_CONFLICT");
      if (matchingBindings.length === 0) {
        await insertAndGetId("xray_quick_config_rule_bindings", {
          bindingTag: `${operationTag}:rule:${hostId}`,
          quickConfigId: config.id,
          topologyRevisionId: config.topologyId,
          forwardRuleId: ruleId,
          state: databaseBoolean(row.isRunning) ? "READY" : "APPLYING",
          createdAt: now,
          updatedAt: now,
        });
      } else {
        await executeRaw(
          `UPDATE ${q("xray_quick_config_rule_bindings")} SET ${q("state")} = ?, ${q("updatedAt")} = ? WHERE ${q("id")} = ?`,
          [databaseBoolean(row.isRunning) ? "READY" : "APPLYING", now, positiveInteger(matchingBindings[0].id)],
        );
      }
      rulePlans.push({ ruleId, hostId, ready: databaseBoolean(row.isRunning) });
    }
    const selectedRuleIds = new Set(rulePlans.map((item) => item.ruleId));
    if (bindings.some((binding) => binding.state !== "REMOVED" && !selectedRuleIds.has(Number(binding.forwardRuleId)))) {
      fail("QUICK_CONFIG_SYNC_CONFLICT");
    }

    const operationId = await insertAndGetId("xray_quick_config_operations", {
      operationTag,
      quickConfigId: config.id,
      type: "EDIT",
      status: "QUEUED",
      phase: "WAITING_RULES_READY",
      activeSlot: 1,
      revision: 1,
      expectedRevision,
      fromTopologyRevisionId: config.topologyId,
      toTopologyRevisionId: config.topologyId,
      requestSummaryJson: SYNC_SUMMARY,
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
    for (const rule of rulePlans) {
      await insertStep({ operationId, operationTag, stepKey: `rule-create-${rule.ruleId}`, kind: "RULE_CREATE", subjectType: "RULE", subjectId: rule.ruleId, status: "SUCCESS", now });
      await insertStep({ operationId, operationTag, stepKey: `rule-verify-${rule.ruleId}`, kind: "RULE_VERIFY", subjectType: "RULE", subjectId: rule.ruleId, status: rule.ready ? "SUCCESS" : "PENDING", now });
    }
    for (const record of dnsRecords) {
      await executeRaw(
        `UPDATE ${q("xray_quick_config_dns_records")} SET ${q("status")} = 'DESIRED', ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ?`,
        [now, record.id, config.id],
      );
      await insertStep({ operationId, operationTag, stepKey: `dns-sync-${record.id}`, kind: "DNS_CREATE", subjectType: "DNS_RECORD", subjectId: record.id, now });
      await insertStep({ operationId, operationTag, stepKey: `dns-verify-${record.id}`, kind: "DNS_VERIFY", subjectType: "DNS_RECORD", subjectId: record.id, now });
    }
    const changed = await executeRaw(
      `UPDATE ${q("xray_quick_configs")} SET ${q("state")} = 'UPDATING', ${q("desiredTopologyRevisionId")} = ?,
          ${q("currentOperationId")} = ?, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("revision")} = ? AND ${q("state")} = 'ACTIVE'
          AND ${q("currentOperationId")} IS NULL AND ${q("desiredTopologyRevisionId")} IS NULL`,
      [config.topologyId, operationId, now, config.id, expectedRevision],
    );
    if (rawAffectedRows(changed) !== 1) fail("QUICK_CONFIG_REVISION_CONFLICT");
    await afterDatabaseCommit(() => {
      for (const rule of rulePlans) if (!rule.ready) pushAgentRefresh(rule.hostId, "xray-quick-config-sync", { urgent: true });
      void import("./xrayQuickConfigOperationService").then(({ kickQuickConfigOperationWorker }) => kickQuickConfigOperationWorker());
    });
    return { quickConfigId: config.id, operationId, state: "UPDATING" as const };
  }));
}

function syncSummary(operation: Row): boolean {
  if (operation.type !== "EDIT") return false;
  try {
    const summary = JSON.parse(String(operation.requestSummaryJson ?? "")) as Record<string, unknown>;
    return summary.kind === "CONFIG_SYNC" && summary.schemaVersion === 1
      && Object.keys(summary).length === 2
      && Object.keys(summary).every((key) => key === "kind" || key === "schemaVersion");
  } catch {
    return false;
  }
}

export function isXrayQuickConfigSyncOperation(operation: Row): boolean {
  return syncSummary(operation);
}

function fenceFrom(operation: Row): SyncFence {
  return {
    operationId: positiveInteger(operation.id),
    quickConfigId: positiveInteger(operation.quickConfigId),
    executionOwnerId: boundedText(operation.executionOwnerId, 128, "QUICK_CONFIG_OPERATION_CONFLICT"),
    executionFence: positiveInteger(operation.executionFence, "QUICK_CONFIG_OPERATION_CONFLICT"),
  };
}

function fenceExistsSql(fence: SyncFence) {
  return {
    sql: `EXISTS (SELECT 1 FROM ${q("xray_quick_config_operations")} owned
      JOIN ${q("xray_quick_configs")} owned_qc ON owned_qc.${q("id")} = owned.${q("quickConfigId")}
      WHERE owned.${q("id")} = ? AND owned.${q("quickConfigId")} = ?
        AND owned.${q("executionOwnerId")} = ? AND owned.${q("executionFence")} = ?
        AND owned.${q("status")} = 'RUNNING' AND owned_qc.${q("currentOperationId")} = owned.${q("id")})`,
    params: [fence.operationId, fence.quickConfigId, fence.executionOwnerId, fence.executionFence],
  };
}

async function assertFence(fence: SyncFence) {
  const [row] = await queryRaw<Row>(
    `SELECT o.${q("status")}, o.${q("executionLeaseUntil")}, qc.${q("currentOperationId")}
       FROM ${q("xray_quick_config_operations")} o JOIN ${q("xray_quick_configs")} qc ON qc.${q("id")} = o.${q("quickConfigId")}
      WHERE o.${q("id")} = ? AND o.${q("quickConfigId")} = ? AND o.${q("executionOwnerId")} = ?
        AND o.${q("executionFence")} = ? LIMIT 1`,
    [fence.operationId, fence.quickConfigId, fence.executionOwnerId, fence.executionFence],
  );
  if (!row || row.status !== "RUNNING" || Number(row.currentOperationId) !== fence.operationId
    || (databaseDate(row.executionLeaseUntil)?.getTime() ?? 0) <= Date.now()) {
    fail("QUICK_CONFIG_OPERATION_CONFLICT");
  }
}

async function finishSyncOperation(fence: SyncFence, status: "SUCCESS" | "FAILED" | "PARTIAL_FAILURE", errorCode: string | null) {
  await withDatabaseTransaction(async () => {
    await assertFence(fence);
    const now = nowDate();
    const operationChanged = await executeRaw(
      `UPDATE ${q("xray_quick_config_operations")} SET ${q("status")} = ?, ${q("phase")} = 'COMPLETED',
          ${q("revision")} = ${q("revision")} + 1, ${q("errorCode")} = ?, ${q("errorMessage")} = NULL,
          ${q("finishedAt")} = ?, ${q("activeSlot")} = NULL, ${q("executionOwnerId")} = NULL,
          ${q("executionLeaseUntil")} = NULL, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("executionOwnerId")} = ?
          AND ${q("executionFence")} = ? AND ${q("status")} = 'RUNNING'`,
      [status, errorCode, now, now, fence.operationId, fence.quickConfigId, fence.executionOwnerId, fence.executionFence],
    );
    if (rawAffectedRows(operationChanged) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    const configChanged = await executeRaw(
      `UPDATE ${q("xray_quick_configs")} SET ${q("state")} = 'ACTIVE', ${q("desiredTopologyRevisionId")} = NULL,
          ${q("currentOperationId")} = NULL, ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("currentOperationId")} = ? AND ${q("activeTopologyRevisionId")} IS NOT NULL`,
      [now, fence.quickConfigId, fence.operationId],
    );
    if (rawAffectedRows(configChanged) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  });
}

async function loadRuntimeContext(fence: SyncFence) {
  const [row] = await queryRaw<Row>(
    `SELECT o.${q("phase")}, o.${q("createdAt")}, o.${q("toTopologyRevisionId")},
            qc.${q("state")}, qc.${q("activeTopologyRevisionId")}, qc.${q("desiredTopologyRevisionId")},
            qc.${q("dnsAccountId")}, qc.${q("zoneId")}, qc.${q("relativeName")}, qc.${q("fqdn")}, qc.${q("createdByUserId")},
            t.${q("engine")}, t.${q("targetAddress")}, t.${q("targetPort")}, t.${q("publicPort")},
            a.${q("verificationStatus")}, a.${q("verificationExpiresAt")}, a.${q("isDisabled")},
            z.${q("providerZoneId")}, z.${q("name")} AS ${q("zoneName")}, z.${q("status")} AS ${q("zoneStatus")},
            z.${q("expiresAt")} AS ${q("zoneExpiresAt")}
       FROM ${q("xray_quick_config_operations")} o
       JOIN ${q("xray_quick_configs")} qc ON qc.${q("id")} = o.${q("quickConfigId")}
       JOIN ${q("xray_quick_config_topology_revisions")} t ON t.${q("id")} = qc.${q("activeTopologyRevisionId")}
       JOIN ${q("dns_provider_accounts")} a ON a.${q("id")} = qc.${q("dnsAccountId")}
       JOIN ${q("dns_provider_zones")} z ON z.${q("id")} = qc.${q("zoneId")} AND z.${q("accountId")} = qc.${q("dnsAccountId")}
      WHERE o.${q("id")} = ? AND o.${q("quickConfigId")} = ? LIMIT 1`,
    [fence.operationId, fence.quickConfigId],
  );
  const topologyId = positiveInteger(row?.activeTopologyRevisionId);
  if (!row || row.state !== "UPDATING" || Number(row.desiredTopologyRevisionId) !== topologyId
    || Number(row.toTopologyRevisionId) !== topologyId || !["WAITING_RULES_READY", "APPLYING_DNS"].includes(String(row.phase))) {
    fail("QUICK_CONFIG_OPERATION_CONFLICT");
  }
  const now = Date.now();
  if (databaseBoolean(row.isDisabled) || row.verificationStatus !== "VALID" || row.zoneStatus !== "AVAILABLE"
    || (databaseDate(row.verificationExpiresAt)?.getTime() ?? 0) <= now
    || (databaseDate(row.zoneExpiresAt)?.getTime() ?? 0) <= now) fail("DNS_PROVIDER_VALIDATION_STALE");
  const relativeName = boundedText(row.relativeName, 253, "DNS_RECORD_DRIFT").toLowerCase();
  const fqdn = boundedText(row.fqdn, 253, "DNS_RECORD_DRIFT").toLowerCase();
  const zoneName = boundedText(row.zoneName, 253, "DNS_RECORD_DRIFT").toLowerCase();
  if (`${relativeName}.${zoneName}` !== fqdn) fail("DNS_RECORD_DRIFT");
  return {
    topologyId,
    phase: String(row.phase),
    createdAt: databaseDate(row.createdAt) ?? nowDate(),
    ownerUserId: positiveInteger(row.createdByUserId),
    accountId: positiveInteger(row.dnsAccountId),
    zoneId: positiveInteger(row.zoneId),
    relativeName,
    fqdn,
    engine: engine(row.engine),
    targetAddress: boundedText(row.targetAddress, 2_048),
    targetPort: port(row.targetPort),
    publicPort: port(row.publicPort),
    zone: { providerZoneId: boundedText(row.providerZoneId, 128), name: zoneName, grade: "" } satisfies DnsPodZone,
  };
}

async function markStepRunning(fence: SyncFence, kind: "DNS_VERIFY", subjectId: number) {
  const [step] = await queryRaw<Row>(
    `SELECT ${q("id")}, ${q("status")} FROM ${q("xray_quick_config_operation_steps")}
      WHERE ${q("operationId")} = ? AND ${q("kind")} = ? AND ${q("subjectId")} = ? LIMIT 1`,
    [fence.operationId, kind, String(subjectId)],
  );
  if (!step || !["PENDING", "RUNNING", "SUCCESS"].includes(String(step.status))) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  if (step.status !== "PENDING") return { id: positiveInteger(step.id), previousStatus: String(step.status) };
  const now = nowDate();
  const owned = fenceExistsSql(fence);
  const changed = await executeRaw(
    `UPDATE ${q("xray_quick_config_operation_steps")} SET ${q("status")} = 'RUNNING',
        ${q("attemptCount")} = ${q("attemptCount")} + 1, ${q("startedAt")} = COALESCE(${q("startedAt")}, ?),
        ${q("errorCode")} = NULL, ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("status")} = 'PENDING' AND ${owned.sql}`,
    [now, now, positiveInteger(step.id), ...owned.params],
  );
  if (rawAffectedRows(changed) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  return { id: positiveInteger(step.id), previousStatus: "PENDING" };
}

type DnsWriteIntent = Readonly<{
  schemaVersion: 1;
  kind: "DNS_SYNC_INTENT";
  preexistingExactProviderRecordIds: readonly string[];
}>;

function normalizeProviderRecordIds(values: readonly string[]): string[] {
  if (values.length > 64) fail("DNS_RECORD_DRIFT");
  const ids = [...new Set(values.map((value) => optionalProviderRecordId(value) ?? fail("DNS_RECORD_DRIFT")))];
  return ids.sort((left, right) => Number(left) - Number(right));
}

function parseDnsWriteIntent(value: unknown): DnsWriteIntent {
  let parsed: unknown;
  try {
    parsed = JSON.parse(String(value ?? ""));
  } catch {
    fail("QUICK_CONFIG_OPERATION_CONFLICT");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  const summary = parsed as Record<string, unknown>;
  if (summary.schemaVersion !== 1 || summary.kind !== "DNS_SYNC_INTENT"
    || !Array.isArray(summary.preexistingExactProviderRecordIds)
    || summary.preexistingExactProviderRecordIds.some((id) => typeof id !== "string")
    || Object.keys(summary).some((key) => !["schemaVersion", "kind", "preexistingExactProviderRecordIds"].includes(key))) {
    fail("QUICK_CONFIG_OPERATION_CONFLICT");
  }
  return {
    schemaVersion: 1,
    kind: "DNS_SYNC_INTENT",
    preexistingExactProviderRecordIds: normalizeProviderRecordIds(summary.preexistingExactProviderRecordIds as string[]),
  };
}

async function beginDnsWriteStep(fence: SyncFence, subjectId: number, preexistingExactProviderRecordIds: readonly string[]) {
  const [step] = await queryRaw<Row>(
    `SELECT ${q("id")}, ${q("status")}, ${q("requestSummaryJson")} FROM ${q("xray_quick_config_operation_steps")}
      WHERE ${q("operationId")} = ? AND ${q("kind")} = 'DNS_CREATE' AND ${q("subjectId")} = ? LIMIT 1`,
    [fence.operationId, String(subjectId)],
  );
  if (!step || !["PENDING", "RUNNING", "SUCCESS"].includes(String(step.status))) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  const stepId = positiveInteger(step.id);
  if (step.status === "SUCCESS") {
    return { id: stepId, previousStatus: "SUCCESS" as const, preexistingExactProviderRecordIds: new Set<string>() };
  }
  if (step.status === "RUNNING") {
    const intent = parseDnsWriteIntent(step.requestSummaryJson);
    return {
      id: stepId,
      previousStatus: "RUNNING" as const,
      preexistingExactProviderRecordIds: new Set(intent.preexistingExactProviderRecordIds),
    };
  }
  const intent: DnsWriteIntent = {
    schemaVersion: 1,
    kind: "DNS_SYNC_INTENT",
    preexistingExactProviderRecordIds: normalizeProviderRecordIds(preexistingExactProviderRecordIds),
  };
  const now = nowDate();
  const owned = fenceExistsSql(fence);
  const changed = await executeRaw(
    `UPDATE ${q("xray_quick_config_operation_steps")} SET ${q("status")} = 'RUNNING',
        ${q("attemptCount")} = ${q("attemptCount")} + 1, ${q("startedAt")} = COALESCE(${q("startedAt")}, ?),
        ${q("requestSummaryJson")} = ?, ${q("errorCode")} = NULL, ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("status")} = 'PENDING' AND ${owned.sql}`,
    [now, JSON.stringify(intent), now, stepId, ...owned.params],
  );
  if (rawAffectedRows(changed) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  return {
    id: stepId,
    previousStatus: "PENDING" as const,
    preexistingExactProviderRecordIds: new Set(intent.preexistingExactProviderRecordIds),
  };
}

async function finishStep(fence: SyncFence, stepId: number, status: "SUCCESS" | "FAILED", errorCode: string | null = null) {
  const now = nowDate();
  const owned = fenceExistsSql(fence);
  const acceptedStatus = status === "SUCCESS" ? `IN ('RUNNING', 'SUCCESS')` : `= 'RUNNING'`;
  const changed = await executeRaw(
    `UPDATE ${q("xray_quick_config_operation_steps")} SET ${q("status")} = ?, ${q("errorCode")} = ?,
        ${q("finishedAt")} = ?, ${q("updatedAt")} = ? WHERE ${q("id")} = ?
        AND ${q("status")} ${acceptedStatus} AND ${owned.sql}`,
    [status, errorCode, now, now, stepId, ...owned.params],
  );
  if (rawAffectedRows(changed) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
}

function providerErrorCode(error: unknown): XrayQuickConfigSyncErrorCode {
  if (error instanceof XrayQuickConfigSyncError) return error.code;
  if (error instanceof DnsPodProviderError) {
    if (error.code === "DNS_PROVIDER_UNAVAILABLE" || error.code === "DNS_PROVIDER_INVALID_RESPONSE"
      || error.code === "DNS_PROVIDER_REQUEST_REJECTED") return error.code;
  }
  const code = String((error as { code?: unknown })?.code ?? "");
  if (code === "SENSITIVE_DATA_UNAVAILABLE") return code;
  return "DNS_PROVIDER_UNAVAILABLE";
}

async function getRemoteRecord(client: DnsPodProviderClient, zone: DnsPodZone, id: string | null): Promise<DnsPodRecord | null> {
  if (!id) return null;
  try {
    return await client.getRecord({ zone, providerRecordId: id });
  } catch (error) {
    if (error instanceof DnsPodProviderError && error.code === "DNS_PROVIDER_RECORD_NOT_FOUND") return null;
    throw error;
  }
}

async function reconcileDns(fence: SyncFence, context: Awaited<ReturnType<typeof loadRuntimeContext>>) {
  const credentials = await loadGlobalDnsProviderCredentials();
  if (credentials.accountId !== context.accountId) fail("DNS_RECORD_DRIFT");
  const lineRows = await queryRaw<Row>(
    `SELECT ${q("providerLineId")}, ${q("name")}, ${q("status")}, ${q("expiresAt")}
       FROM ${q("dns_provider_record_lines")} WHERE ${q("zoneId")} = ? ORDER BY ${q("id")} ASC`,
    [context.zoneId],
  );
  const lines = new Map<string, DnsPodRecordLine>();
  for (const row of lineRows) {
    if (row.status !== "AVAILABLE" || (databaseDate(row.expiresAt)?.getTime() ?? 0) <= Date.now()) continue;
    const providerLineId = boundedText(row.providerLineId, 128, "DNS_RECORD_DRIFT");
    if (lines.has(providerLineId)) fail("DNS_RECORD_DRIFT");
    lines.set(providerLineId, { providerLineId, name: boundedText(row.name, 128, "DNS_RECORD_DRIFT") });
  }
  const rows = await queryRaw<Row>(
    `SELECT dr.${q("id")}, dr.${q("providerRecordId")}, dr.${q("providerLineId")}, dr.${q("fqdn")},
            dr.${q("recordType")}, dr.${q("value")}, dr.${q("ttl")}, dr.${q("remoteTupleHash")},
            r.${q("lineCategory")}, r.${q("providerLineId")} AS ${q("routeLineId")}, r.${q("addressFamily")}, r.${q("address")}
       FROM ${q("xray_quick_config_dns_records")} dr JOIN ${q("xray_quick_config_routes")} r ON r.${q("id")} = dr.${q("routeId")}
      WHERE dr.${q("quickConfigId")} = ? AND r.${q("topologyRevisionId")} = ?
        AND dr.${q("status")} IN ('DESIRED', 'APPLIED', 'UNKNOWN', 'DRIFTED') ORDER BY CASE WHEN r.${q("lineCategory")} = 'DEFAULT' THEN 0 ELSE 1 END, dr.${q("id")} ASC`,
    [fence.quickConfigId, context.topologyId],
  );
  if (rows.length < 1 || rows.length > 64) fail("DNS_RECORD_DRIFT");
  const client = new DnsPodProviderClient({ credentials: { secretId: credentials.secretId, secretKey: credentials.secretKey } });
  let remoteList = await client.listRecords({ zone: context.zone, subdomain: context.relativeName });
  for (const row of rows) {
    await assertFence(fence);
    const id = positiveInteger(row.id);
    const recordType = row.recordType === "A" || row.recordType === "AAAA" ? row.recordType : fail("DNS_RECORD_DRIFT");
    const providerLineId = boundedText(row.providerLineId, 128, "DNS_RECORD_DRIFT");
    const value = boundedText(row.value, 2_048, "DNS_RECORD_DRIFT");
    const ttl = positiveInteger(row.ttl, "DNS_RECORD_DRIFT");
    const tuple: XrayQuickConfigDnsTuple = { fqdn: context.fqdn, recordType, providerLineId, value, ttl };
    const expectedType = row.addressFamily === "IPV4" ? "A" : row.addressFamily === "IPV6" ? "AAAA" : null;
    const line = lines.get(providerLineId);
    if (!line || expectedType !== recordType || row.routeLineId !== providerLineId || row.address !== value
      || row.fqdn !== context.fqdn || row.remoteTupleHash !== computeXrayQuickConfigDnsTupleHash(tuple)) fail("DNS_RECORD_DRIFT");
    const expected: QuickConfigDnsSyncExpected = {
      providerRecordId: optionalProviderRecordId(row.providerRecordId),
      relativeName: context.relativeName,
      recordType,
      providerLineId,
      value,
      ttl,
    };
    let writeStepId: number | null = null;
    try {
      let providerId = expected.providerRecordId;
      const exactMatches = remoteList.filter((candidate) => sameDnsTuple(candidate, expected));
      const writeStep = await beginDnsWriteStep(
        fence,
        id,
        exactMatches.map((record) => record.providerRecordId),
      );
      writeStepId = writeStep.id;
      let current = await getRemoteRecord(client, context.zone, providerId);
      const mayAdoptCreatedRecord = writeStep.previousStatus === "RUNNING"
        && exactMatches.length === 1
        && !writeStep.preexistingExactProviderRecordIds.has(exactMatches[0].providerRecordId);
      const action = decideQuickConfigDnsSyncAction({
        expected,
        current,
        exactMatches,
        createIntentRunning: mayAdoptCreatedRecord,
      });
      if (writeStep.previousStatus === "SUCCESS" && action !== "KEEP") fail("DNS_RECORD_DRIFT");
      if (action === "CONFLICT") fail("DNS_RECORD_DRIFT");
      if (action === "REPAIR") {
        if (!providerId || !current) fail("DNS_RECORD_DRIFT");
        try {
          const result = await client.updateRecord({ zone: context.zone, subdomain: context.relativeName, recordType, line, value, ttl, providerRecordId: providerId });
          if (result.providerRecordId !== providerId) fail("DNS_RECORD_DRIFT");
        } catch (error) {
          if (!(error instanceof DnsPodProviderError) || !error.ambiguousWrite) throw error;
        }
      } else if (action === "CREATE") {
        let createdId: string | null = null;
        try {
          createdId = (await client.createRecord({ zone: context.zone, subdomain: context.relativeName, recordType, line, value, ttl })).providerRecordId;
        } catch (error) {
          if (!(error instanceof DnsPodProviderError) || !error.ambiguousWrite) throw error;
        }
        if (createdId) {
          providerId = optionalProviderRecordId(createdId);
          if (providerId && writeStep.preexistingExactProviderRecordIds.has(providerId)) fail("DNS_RECORD_DRIFT");
        }
        else {
          remoteList = await client.listRecords({ zone: context.zone, subdomain: context.relativeName });
          const created = remoteList.filter((candidate) => sameDnsTuple(candidate, expected));
          if (created.length !== 1 || writeStep.preexistingExactProviderRecordIds.has(created[0].providerRecordId)) {
            fail("DNS_RECORD_DRIFT");
          }
          providerId = optionalProviderRecordId(created[0].providerRecordId);
        }
      } else if (action === "ADOPT_CREATED") {
        providerId = optionalProviderRecordId(exactMatches[0].providerRecordId);
      }
      if (!providerId) fail("DNS_RECORD_DRIFT");
      current = await getRemoteRecord(client, context.zone, providerId);
      if (!current || !sameDnsTuple(current, expected)) fail("DNS_RECORD_DRIFT");
      if (action === "CREATE" || action === "REPAIR") {
        remoteList = await client.listRecords({ zone: context.zone, subdomain: context.relativeName });
        const verifiedMatches = remoteList.filter((candidate) => sameDnsTuple(candidate, expected));
        if (verifiedMatches.length !== 1 || verifiedMatches[0].providerRecordId !== providerId) fail("DNS_RECORD_DRIFT");
      }
      const [claimed] = await queryRaw<Row>(
        `SELECT ${q("id")} FROM ${q("xray_quick_config_dns_records")}
          WHERE ${q("dnsAccountId")} = ? AND ${q("providerRecordId")} = ? AND ${q("id")} <> ? LIMIT 1`,
        [context.accountId, providerId, id],
      );
      if (claimed) fail("DNS_RECORD_DRIFT");
      const owned = fenceExistsSql(fence);
      const changed = await executeRaw(
        `UPDATE ${q("xray_quick_config_dns_records")} SET ${q("providerRecordId")} = ?, ${q("status")} = 'APPLIED',
            ${q("lastVerifiedAt")} = ?, ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ?
            AND ${q("remoteTupleHash")} = ? AND ${owned.sql}`,
        [providerId, nowDate(), nowDate(), id, fence.quickConfigId, computeXrayQuickConfigDnsTupleHash(tuple), ...owned.params],
      );
      if (rawAffectedRows(changed) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
      await finishStep(fence, writeStep.id, "SUCCESS");
      const verifyStep = await markStepRunning(fence, "DNS_VERIFY", id);
      if (verifyStep.previousStatus !== "SUCCESS") await finishStep(fence, verifyStep.id, "SUCCESS");
      remoteList = remoteList.filter((record) => record.providerRecordId !== providerId);
      remoteList.push(current);
    } catch (error) {
      const code = providerErrorCode(error);
      if (writeStepId !== null) await finishStep(fence, writeStepId, "FAILED", code).catch(() => undefined);
      const owned = fenceExistsSql(fence);
      await executeRaw(
        `UPDATE ${q("xray_quick_config_dns_records")} SET ${q("status")} = 'UNKNOWN', ${q("lastVerifiedAt")} = NULL,
            ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${owned.sql}`,
        [nowDate(), id, fence.quickConfigId, ...owned.params],
      ).catch(() => undefined);
      return code;
    }
  }
  return null;
}

async function reconcileRules(fence: SyncFence, context: Awaited<ReturnType<typeof loadRuntimeContext>>) {
  const segments = await loadQuickConfigSegments(fence.quickConfigId, context.topologyId, context);
  const hostIds = segments.map(segment => segment.hostId);
  const rules = await queryRaw<Row>(
    `SELECT fr.*, b.${q("id")} AS ${q("bindingId")}, b.${q("state")} AS ${q("bindingState")}
       FROM ${q("xray_quick_config_rule_bindings")} b
       JOIN ${q("forward_rules")} fr ON fr.${q("id")} = b.${q("forwardRuleId")}
      WHERE b.${q("quickConfigId")} = ? AND b.${q("topologyRevisionId")} = ? AND b.${q("state")} <> 'REMOVED'
      ORDER BY fr.${q("hostId")} ASC, fr.${q("id")} ASC`,
    [fence.quickConfigId, context.topologyId],
  );
  const ready = hostIds.length === rules.length && hostIds.every((hostId, index) => {
    const row = rules[index];
    return isQuickConfigRuleSynchronized(row, { quickConfigId: fence.quickConfigId, userId: context.ownerUserId, hostId, engine: context.engine,
      publicPort: context.publicPort, targetAddress: segments[index].targetAddress, targetPort: segments[index].targetPort })
      && databaseBoolean(row.isRunning);
  });
  if (!ready) {
    for (const hostId of hostIds) pushAgentRefresh(hostId, "xray-quick-config-sync-wait", { urgent: true });
    if (Date.now() - context.createdAt.getTime() < RULE_READY_TIMEOUT_MS) return false;
    const owned = fenceExistsSql(fence);
    await executeRaw(
      `UPDATE ${q("xray_quick_config_operation_steps")} SET ${q("status")} = 'FAILED', ${q("errorCode")} = 'RULE_APPLY_FAILED',
          ${q("finishedAt")} = ?, ${q("updatedAt")} = ? WHERE ${q("operationId")} = ? AND ${q("kind")} = 'RULE_VERIFY'
          AND ${q("status")} <> 'SUCCESS' AND ${owned.sql}`,
      [nowDate(), nowDate(), fence.operationId, ...owned.params],
    );
    await finishSyncOperation(fence, "PARTIAL_FAILURE", "RULE_APPLY_FAILED");
    return false;
  }
  const now = nowDate();
  const owned = fenceExistsSql(fence);
  await executeRaw(
    `UPDATE ${q("xray_quick_config_operation_steps")} SET ${q("status")} = 'SUCCESS',
        ${q("attemptCount")} = CASE WHEN ${q("attemptCount")} < 1 THEN 1 ELSE ${q("attemptCount")} END,
        ${q("startedAt")} = COALESCE(${q("startedAt")}, ?), ${q("finishedAt")} = ?, ${q("errorCode")} = NULL,
        ${q("updatedAt")} = ? WHERE ${q("operationId")} = ? AND ${q("kind")} = 'RULE_VERIFY'
        AND ${q("status")} <> 'SUCCESS' AND ${owned.sql}`,
    [now, now, now, fence.operationId, ...owned.params],
  );
  await executeRaw(
    `UPDATE ${q("xray_quick_config_rule_bindings")} SET ${q("state")} = 'READY', ${q("updatedAt")} = ?
      WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ? AND ${q("state")} <> 'READY' AND ${owned.sql}`,
    [now, fence.quickConfigId, context.topologyId, ...owned.params],
  );
  const phaseChanged = await executeRaw(
    `UPDATE ${q("xray_quick_config_operations")} SET ${q("phase")} = 'APPLYING_DNS',
        ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ? WHERE ${q("id")} = ?
        AND ${q("quickConfigId")} = ? AND ${q("executionOwnerId")} = ? AND ${q("executionFence")} = ? AND ${q("status")} = 'RUNNING'`,
    [now, fence.operationId, fence.quickConfigId, fence.executionOwnerId, fence.executionFence],
  );
  if (rawAffectedRows(phaseChanged) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  return true;
}

export async function processXrayQuickConfigSyncOperation(operation: Row): Promise<void> {
  if (!syncSummary(operation)) return;
  const fence = fenceFrom(operation);
  try {
    await assertFence(fence);
    let context = await loadRuntimeContext(fence);
    if (context.phase === "WAITING_RULES_READY") {
      if (!await reconcileRules(fence, context)) return;
      context = await loadRuntimeContext(fence);
    }
    const dnsError = await reconcileDns(fence, context);
    await finishSyncOperation(fence, dnsError ? "PARTIAL_FAILURE" : "SUCCESS", dnsError);
  } catch (error) {
    const code = providerErrorCode(error);
    await finishSyncOperation(fence, "PARTIAL_FAILURE", code).catch(() => undefined);
  }
}
