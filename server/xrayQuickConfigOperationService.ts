import crypto from "node:crypto";

import type { DnsPodRecord, DnsPodZone } from "./dnsPodProviderClient";
import { DnsPodProviderClient } from "./dnsPodProviderClient";
import { afterDatabaseCommit, executeRaw, insertAndGetId, nowDate, queryRaw, rawAffectedRows, withDatabaseTransaction } from "./dbRuntime";
import { quoteIdentifier } from "./dbCompat";
import {
  activateReservedGlobalPortAllocation,
  addActiveGlobalPortOwningReference,
  attachGlobalPortTargetAlias,
  inspectGlobalPortAllocation,
  reserveGlobalPortAllocation,
  type GlobalPortAllocationDto,
  type GlobalPortReferenceInput,
} from "./globalPortAllocationService";
import { pushAgentRefresh } from "./agentEvents";
import { loadGlobalDnsProviderCredentials } from "./repositories/dnsProviderRepository";
import { createForwardRule } from "./repositories/forwardRuleRepository";
import { ensureQuickConfigPortResource } from "./quickConfigPortResourceService";
import {
  validateQuickConfigPreviewToken,
  type QuickConfigImmutablePlan,
} from "./xrayQuickConfigPlanningService";
import { computeXrayQuickConfigDnsTupleHash } from "./xrayQuickConfigDnsTuple";

export const QUICK_CONFIG_OPERATION_ERROR_CODES = [
  "QUICK_CONFIG_APPLY_INVALID",
  "QUICK_CONFIG_APPLY_CONFLICT",
  "DOMAIN_ALREADY_MANAGED",
  "DNS_PROVIDER_CONFLICT_CHANGED",
  "RULE_APPLY_FAILED",
  "RULE_CLEANUP_TIMEOUT",
  "DNS_APPLY_FAILED",
] as const;

export type QuickConfigOperationErrorCode = typeof QUICK_CONFIG_OPERATION_ERROR_CODES[number];

export class XrayQuickConfigOperationError extends Error {
  constructor(readonly code: QuickConfigOperationErrorCode) {
    super(code);
    this.name = "XrayQuickConfigOperationError";
  }
}

type Row = Record<string, unknown>;
type MutableDnsRecord = DnsPodRecord & { recordType: "A" | "AAAA" | "CNAME" };
type OperationFence = Readonly<{
  operationId: number;
  quickConfigId: number;
  executionOwnerId: string;
  executionFence: number;
}>;

const WORKER_ID = `quick-config-worker:${process.pid}:${crypto.randomUUID()}`;
const WORKER_LEASE_MS = 10 * 60_000;
const RULE_READY_TIMEOUT_MS = 120_000;
const RULE_CLEANUP_TIMEOUT_MS = 10 * 60_000;
let workerRunning = false;
let workerKickScheduled = false;

function positiveInteger(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new XrayQuickConfigOperationError("QUICK_CONFIG_APPLY_INVALID");
  return parsed;
}

function databaseDate(value: unknown): Date {
  if (value instanceof Date && Number.isFinite(value.getTime())) return value;
  const number = Number(value);
  const parsed = Number.isFinite(number)
    ? new Date(number < 10_000_000_000 ? number * 1_000 : number)
    : new Date(String(value ?? ""));
  if (!Number.isFinite(parsed.getTime())) throw new XrayQuickConfigOperationError("QUICK_CONFIG_APPLY_INVALID");
  return parsed;
}

class QuickConfigOperationFenceLostError extends Error {
  constructor() {
    super("QUICK_CONFIG_OPERATION_FENCE_LOST");
    this.name = "QuickConfigOperationFenceLostError";
  }
}

function operationFence(operation: Row): OperationFence {
  const executionOwnerId = String(operation.executionOwnerId ?? "");
  if (!executionOwnerId || Buffer.byteLength(executionOwnerId, "utf8") > 128) {
    throw new QuickConfigOperationFenceLostError();
  }
  return {
    operationId: positiveInteger(operation.id),
    quickConfigId: positiveInteger(operation.quickConfigId),
    executionOwnerId,
    executionFence: positiveInteger(operation.executionFence),
  };
}

async function ownsOperationFence(fence: OperationFence): Promise<boolean> {
  const q = quoteIdentifier;
  const [row] = await queryRaw<Row>(
    `SELECT o.${q("status")}, o.${q("executionLeaseUntil")}, qc.${q("currentOperationId")}
       FROM ${q("xray_quick_config_operations")} o
       JOIN ${q("xray_quick_configs")} qc ON qc.${q("id")} = o.${q("quickConfigId")}
      WHERE o.${q("id")} = ? AND o.${q("quickConfigId")} = ? AND o.${q("executionOwnerId")} = ?
        AND o.${q("executionFence")} = ? LIMIT 1`,
    [fence.operationId, fence.quickConfigId, fence.executionOwnerId, fence.executionFence],
  );
  if (!row || !["RUNNING", "COMPENSATING"].includes(String(row.status))
    || Number(row.currentOperationId) !== fence.operationId) return false;
  try {
    return databaseDate(row.executionLeaseUntil).getTime() > Date.now();
  } catch {
    return false;
  }
}

async function assertOperationFence(fence: OperationFence): Promise<void> {
  if (!await ownsOperationFence(fence)) throw new QuickConfigOperationFenceLostError();
}

function operationFenceExistsSql(fence: OperationFence): { sql: string; params: unknown[] } {
  const q = quoteIdentifier;
  return {
    sql: `EXISTS (
      SELECT 1 FROM ${q("xray_quick_config_operations")} owned
      JOIN ${q("xray_quick_configs")} owned_qc ON owned_qc.${q("id")} = owned.${q("quickConfigId")}
      WHERE owned.${q("id")} = ? AND owned.${q("quickConfigId")} = ?
        AND owned.${q("executionOwnerId")} = ? AND owned.${q("executionFence")} = ?
        AND owned.${q("status")} IN ('RUNNING', 'COMPENSATING')
        AND owned_qc.${q("currentOperationId")} = owned.${q("id")}
    )`,
    params: [fence.operationId, fence.quickConfigId, fence.executionOwnerId, fence.executionFence],
  };
}

function sha256(value: string): string {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

function domainClaimKey(accountTag: string, providerZoneId: string, fqdn: string): string {
  return sha256(canonical({ schema: "quick-config-domain-claim:v1", provider: "DNSPOD", accountTag, providerZoneId, fqdn }));
}

function quickConfigReference(input: {
  quickConfigId: number;
  hostId: number | null;
  role: "TARGET" | "PUBLIC_LISTENER" | "OWNERSHIP";
  isOwning: boolean;
  network?: "TCP" | "BOTH" | "NONE";
}): GlobalPortReferenceInput {
  return {
    resourceType: "QUICK_CONFIG",
    resourceId: input.quickConfigId,
    hostId: input.hostId,
    network: input.network ?? (input.role === "PUBLIC_LISTENER" ? "TCP" : "NONE"),
    role: input.role,
    isOwning: input.isOwning,
  };
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

function projectedRemoteSet(records: readonly DnsPodRecord[]) {
  return records.map((record) => ({
    recordType: record.recordType === "A" || record.recordType === "AAAA" || record.recordType === "CNAME"
      || record.recordType === "TXT" || record.recordType === "MX" || record.recordType === "CAA"
      ? record.recordType : "OTHER",
    providerLineId: record.providerLineId,
    lineName: record.lineName,
    value: record.value,
    ttl: record.ttl,
  })).sort((a, b) => canonical(a).localeCompare(canonical(b)));
}

function projectedPlanSet(plan: QuickConfigImmutablePlan) {
  return [...plan.domain.conflicts, ...plan.domain.preservedRecords].map(({ recordRef: _recordRef, ...record }) => record)
    .sort((a, b) => canonical(a).localeCompare(canonical(b)));
}

async function loadReplacementSnapshots(plan: QuickConfigImmutablePlan): Promise<{
  accountTag: string;
  credentials: { secretId: string; secretKey: string };
  zone: DnsPodZone;
  records: MutableDnsRecord[];
}> {
  const credentials = await loadGlobalDnsProviderCredentials();
  if (credentials.accountId !== plan.domain.accountId
    || credentials.accountRevision !== plan.domain.accountRevision
    || credentials.bindingRevision !== plan.domain.bindingRevision) {
    throw new XrayQuickConfigOperationError("QUICK_CONFIG_APPLY_CONFLICT");
  }
  const q = quoteIdentifier;
  const accountRows = await queryRaw<Row>(
    `SELECT ${q("accountTag")} FROM ${q("dns_provider_accounts")} WHERE ${q("id")} = ? LIMIT 1`,
    [credentials.accountId],
  );
  const accountTag = String(accountRows[0]?.accountTag ?? "");
  if (!accountTag || Buffer.byteLength(accountTag, "utf8") > 128) {
    throw new XrayQuickConfigOperationError("QUICK_CONFIG_APPLY_INVALID");
  }
  const zone: DnsPodZone = {
    providerZoneId: plan.domain.zone.providerZoneId,
    name: plan.domain.zone.name,
    grade: "",
  };
  const client = new DnsPodProviderClient({ credentials });
  const remote = (await client.listRecords({ zone, subdomain: plan.domain.relativeName }))
    .filter((record) => record.subdomain.trim().toLowerCase() === plan.domain.relativeName);
  if (canonical(projectedRemoteSet(remote)) !== canonical(projectedPlanSet(plan))) {
    throw new XrayQuickConfigOperationError("DNS_PROVIDER_CONFLICT_CHANGED");
  }
  const mutable = remote.filter((record): record is MutableDnsRecord => (
    record.recordType === "A" || record.recordType === "AAAA" || record.recordType === "CNAME"
  ));
  if (mutable.length > 64 || (mutable.length > 0 && plan.domain.action !== "REPLACE_CONFLICTING_RECORDS")) {
    throw new XrayQuickConfigOperationError("DNS_PROVIDER_CONFLICT_CHANGED");
  }
  return {
    accountTag,
    credentials: { secretId: credentials.secretId, secretKey: credentials.secretKey },
    zone,
    records: mutable,
  };
}

type RouteDraft = {
  lineCategory: "DEFAULT" | "TELECOM" | "UNICOM" | "MOBILE" | "EDUCATION";
  providerLineId: string;
  sourceType: "LANDING" | "MANAGED_HOST";
  hostId: number | null;
  addressFamily: "IPV4" | "IPV6";
  address: string;
  routeMode: "DIRECT" | "FORWARD";
};

function routeDrafts(plan: QuickConfigImmutablePlan): RouteDraft[] {
  const directLanding = plan.domain.target.targetType === "XRAY_INBOUND" && !plan.preview.allocation.rewritten;
  const carrier = plan.carrierRoutes.flatMap((route) => route.endpoints.map((endpoint) => {
    const isLanding = directLanding && endpoint.hostId === plan.domain.target.host.id;
    return {
      lineCategory: route.carrier,
      providerLineId: route.providerLineId,
      sourceType: isLanding ? "LANDING" as const : "MANAGED_HOST" as const,
      hostId: endpoint.hostId,
      addressFamily: endpoint.addressFamily,
      address: endpoint.address,
      routeMode: isLanding ? "DIRECT" as const : "FORWARD" as const,
    };
  }));
  const defaultLine = plan.domain.zone.carrierLines.find((line) => line.category === "DEFAULT");
  if (!defaultLine || defaultLine.status !== "AVAILABLE") {
    throw new XrayQuickConfigOperationError("QUICK_CONFIG_APPLY_INVALID");
  }
  const defaults = plan.defaultRoutes.map((candidate) => ({
    lineCategory: "DEFAULT" as const,
    providerLineId: defaultLine.providerLineId,
    sourceType: candidate.sourceType,
    hostId: candidate.hostId,
    addressFamily: candidate.addressFamily,
    address: candidate.address,
    routeMode: candidate.sourceType === "LANDING" ? "DIRECT" as const : "FORWARD" as const,
  }));
  const seen = new Set<string>();
  return [...carrier, ...defaults].filter((route) => {
    const key = canonical(route);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function dnsRouteKey(lineCategory: string, providerLineId: string, recordType: string, value: string) {
  return `${lineCategory}\u0000${providerLineId}\u0000${recordType}\u0000${value}`;
}

async function insertOperationStep(input: {
  operationId: number;
  operationTag: string;
  stepKey: string;
  kind: string;
  subjectType: string;
  subjectId: string | null;
  status?: "PENDING" | "SUCCESS";
  now: Date;
}) {
  await insertAndGetId("xray_quick_config_operation_steps", {
    operationId: input.operationId,
    stepKey: input.stepKey,
    kind: input.kind,
    subjectType: input.subjectType,
    subjectId: input.subjectId,
    status: input.status ?? "PENDING",
    attemptCount: input.status === "SUCCESS" ? 1 : 0,
    idempotencyKey: `${input.operationTag}:${input.stepKey}`,
    requestSummaryJson: "{}",
    resultSummaryJson: input.status === "SUCCESS" ? "{}" : null,
    errorCode: null,
    startedAt: input.status === "SUCCESS" ? input.now : null,
    finishedAt: input.status === "SUCCESS" ? input.now : null,
    updatedAt: input.now,
  });
}

export async function applyQuickConfigPreview(input: {
  previewToken: string;
  userId: number;
}): Promise<{ quickConfigId: number; operationId: number; state: "APPLYING" }> {
  const userId = positiveInteger(input.userId);
  const plan = await validateQuickConfigPreviewToken({ previewToken: input.previewToken, userId });
  const replacement = await loadReplacementSnapshots(plan);
  const configTag = `quick-config:${crypto.randomUUID()}`;
  const operationTag = `quick-config-operation:${crypto.randomUUID()}`;
  const now = nowDate();
  const drafts = routeDrafts(plan);
  const assignedReplacementIndexes = new Set<number>();
  const replacementByDesiredIndex = new Map<number, MutableDnsRecord>();
  for (const [desiredIndex, desired] of plan.preview.dnsRecords.entries()) {
    let replacementIndex = replacement.records.findIndex((record, index) => (
      !assignedReplacementIndexes.has(index)
      && record.recordType !== "CNAME"
      && record.recordType === desired.recordType
      && record.providerLineId === desired.providerLineId
    ));
    if (replacementIndex < 0) {
      replacementIndex = replacement.records.findIndex((record, index) => (
        !assignedReplacementIndexes.has(index)
        && record.recordType !== "CNAME"
        && record.recordType === desired.recordType
      ));
    }
    if (replacementIndex < 0) continue;
    assignedReplacementIndexes.add(replacementIndex);
    replacementByDesiredIndex.set(desiredIndex, replacement.records[replacementIndex]);
  }

  const created = await withDatabaseTransaction(async () => {
    const q = quoteIdentifier;
    const existing = await queryRaw<Row>(
      `SELECT ${q("id")} FROM ${q("xray_quick_configs")} WHERE ${q("dnsAccountId")} = ? AND ${q("zoneId")} = ? AND ${q("fqdn")} = ? AND ${q("state")} <> 'REMOVED' LIMIT 1`,
      [plan.domain.accountId, plan.domain.zoneId, plan.domain.fqdn],
    );
    if (existing[0]) throw new XrayQuickConfigOperationError("DOMAIN_ALREADY_MANAGED");

    const quickConfigId = await insertAndGetId("xray_quick_configs", {
      configTag,
      targetType: plan.preview.target.targetType,
      xrayInboundId: plan.preview.target.targetType === "XRAY_INBOUND" ? plan.preview.target.targetId : null,
      externalProxyNodeId: plan.preview.target.targetType === "EXTERNAL_PROXY_NODE" ? plan.preview.target.targetId : null,
      targetVersion: plan.domain.target.targetVersion,
      dnsAccountId: plan.domain.accountId,
      zoneId: plan.domain.zoneId,
      relativeName: plan.domain.relativeName,
      fqdn: plan.domain.fqdn,
      state: "APPLYING",
      revision: 1,
      activeTopologyRevisionId: null,
      desiredTopologyRevisionId: null,
      currentOperationId: null,
      createdByUserId: userId,
      createdAt: now,
      updatedAt: now,
    });
    await insertAndGetId("xray_quick_config_domain_claims", {
      claimKey: domainClaimKey(replacement.accountTag, replacement.zone.providerZoneId, plan.domain.fqdn),
      dnsAccountId: plan.domain.accountId,
      zoneId: plan.domain.zoneId,
      normalizedRelativeName: plan.domain.relativeName,
      quickConfigId,
      revision: 1,
      createdAt: now,
      updatedAt: now,
    });

    const owner = { type: "QUICK_CONFIG" as const, stableIdentity: configTag };
    let allocation: GlobalPortAllocationDto;
    if (plan.preview.allocation.mode === "RESERVE_NEW") {
      const reserved = await reserveGlobalPortAllocation({ port: plan.preview.publicPort, owner, now });
      const refs: GlobalPortReferenceInput[] = [quickConfigReference({
        quickConfigId, hostId: null, role: "OWNERSHIP", network: "NONE", isOwning: true,
      })];
      for (const rule of plan.preview.rules) refs.push(quickConfigReference({
        quickConfigId, hostId: rule.hostId, role: "PUBLIC_LISTENER", network: "TCP", isOwning: true,
      }));
      allocation = await activateReservedGlobalPortAllocation({
        allocationId: reserved.allocationId,
        expectedVersion: reserved.version,
        reservationToken: reserved.reservationToken,
        owner,
        references: refs,
        now,
      });
    } else {
      const current = await inspectGlobalPortAllocation(plan.preview.publicPort);
      if (!current || current.status !== "ACTIVE" || plan.domain.target.targetType !== "XRAY_INBOUND") {
        throw new XrayQuickConfigOperationError("QUICK_CONFIG_APPLY_CONFLICT");
      }
      const inboundRows = await queryRaw<Row>(
        `SELECT ${q("runtimeTag")} FROM ${q("xray_inbounds")} WHERE ${q("id")} = ? LIMIT 1`,
        [plan.domain.target.targetId],
      );
      const runtimeTag = String(inboundRows[0]?.runtimeTag ?? "");
      if (!runtimeTag || Buffer.byteLength(runtimeTag, "utf8") > 128) {
        throw new XrayQuickConfigOperationError("QUICK_CONFIG_APPLY_CONFLICT");
      }
      const sourceOwner = { type: "XRAY_INBOUND" as const, stableIdentity: runtimeTag };
      allocation = await attachGlobalPortTargetAlias({
        allocationId: current.allocationId,
        expectedVersion: current.version,
        sourceOwner,
        aliasOwner: owner,
        reference: quickConfigReference({
          quickConfigId, hostId: plan.domain.target.host.id, role: "TARGET", network: "NONE", isOwning: false,
        }),
        now,
      });
      for (const rule of plan.preview.rules) {
        allocation = await attachGlobalPortTargetAlias({
          allocationId: allocation.allocationId,
          expectedVersion: allocation.version,
          sourceOwner,
          aliasOwner: owner,
          reference: quickConfigReference({
            quickConfigId, hostId: rule.hostId, role: "PUBLIC_LISTENER", network: "TCP", isOwning: false,
          }),
          now,
        });
      }
    }

    const topologyRevisionId = await insertAndGetId("xray_quick_config_topology_revisions", {
      quickConfigId,
      revisionNumber: 1,
      engine: plan.engine,
      targetAddress: plan.preview.target.address,
      targetPort: plan.preview.target.port,
      publicPort: plan.preview.publicPort,
      portAllocationId: allocation.allocationId,
      state: "APPLYING",
      activeSlot: null,
      createdByUserId: userId,
      createdAt: now,
      updatedAt: now,
    });

    const routeIds = new Map<string, number>();
    for (const [index, route] of drafts.entries()) {
      const routeId = await insertAndGetId("xray_quick_config_routes", {
        routeTag: `${configTag}:route:${index + 1}`,
        quickConfigId,
        topologyRevisionId,
        ...route,
        sortOrder: index,
        state: "APPLYING",
        createdAt: now,
        updatedAt: now,
      });
      const recordType = route.addressFamily === "IPV4" ? "A" : "AAAA";
      routeIds.set(dnsRouteKey(route.lineCategory, route.providerLineId, recordType, route.address), routeId);
    }

    const ruleIds: Array<{ id: number; hostId: number }> = [];
    for (const [index, rule] of plan.preview.rules.entries()) {
      const portResource = await ensureQuickConfigPortResource({
        userId,
        hostId: rule.hostId,
        engine: rule.engine,
      });
      const id = await createForwardRule({
        hostId: rule.hostId,
        name: `[快速配置] ${plan.domain.fqdn} #${index + 1}`,
        forwardType: rule.engine,
        protocol: "tcp",
        gostMode: "direct",
        sourcePort: rule.listenPort,
        targetIp: rule.targetAddress,
        targetPort: rule.targetPort,
        targetExternalProxyNodeId: null,
        xrayQuickConfigId: quickConfigId,
        portResourceGroupId: portResource.groupId,
        proxyProtocolReceive: false,
        proxyProtocolSend: false,
        proxyProtocolExitReceive: false,
        proxyProtocolExitSend: false,
        isEnabled: true,
        isRunning: false,
        pendingDelete: false,
        userId,
        createdAt: now,
        updatedAt: now,
      });
      ruleIds.push({ id, hostId: rule.hostId });
      await insertAndGetId("xray_quick_config_rule_bindings", {
        bindingTag: `${configTag}:rule:${index + 1}`,
        quickConfigId,
        topologyRevisionId,
        forwardRuleId: id,
        state: "APPLYING",
        createdAt: now,
        updatedAt: now,
      });
      if (plan.preview.allocation.mode === "RESERVE_NEW") {
        allocation = await addActiveGlobalPortOwningReference({
          allocationId: allocation.allocationId,
          expectedVersion: allocation.version,
          owner,
          reference: forwardRuleReference(id, rule.hostId),
          now,
        });
      }
    }

    const desiredRecordIds: Array<{ id: number; replacement: MutableDnsRecord | null }> = [];
    for (const [index, record] of plan.preview.dnsRecords.entries()) {
      const lineCategory = record.routeKind === "DEFAULT" ? "DEFAULT" : record.carrier;
      const routeId = routeIds.get(dnsRouteKey(lineCategory, record.providerLineId, record.recordType, record.value));
      if (!routeId) throw new XrayQuickConfigOperationError("QUICK_CONFIG_APPLY_INVALID");
      const id = await insertAndGetId("xray_quick_config_dns_records", {
        quickConfigId,
        routeId,
        dnsAccountId: plan.domain.accountId,
        zoneId: plan.domain.zoneId,
        recordTag: `${configTag}:dns:${index + 1}`,
        providerRecordId: replacementByDesiredIndex.get(index)?.providerRecordId ?? null,
        providerLineId: record.providerLineId,
        fqdn: plan.domain.fqdn,
        recordType: record.recordType,
        value: record.value,
        ttl: record.ttl,
        status: "DESIRED",
        appliedRevision: 1,
        remoteTupleHash: computeXrayQuickConfigDnsTupleHash({
          fqdn: plan.domain.fqdn,
          recordType: record.recordType,
          providerLineId: record.providerLineId,
          value: record.value,
          ttl: record.ttl,
        }),
        lastVerifiedAt: null,
        createdAt: now,
        updatedAt: now,
      });
      desiredRecordIds.push({ id, replacement: replacementByDesiredIndex.get(index) ?? null });
    }

    const operationId = await insertAndGetId("xray_quick_config_operations", {
      operationTag,
      quickConfigId,
      type: "APPLY",
      status: "QUEUED",
      phase: "RECHECKING_DOMAIN",
      activeSlot: 1,
      revision: 1,
      expectedRevision: 1,
      fromTopologyRevisionId: null,
      toTopologyRevisionId: topologyRevisionId,
      requestSummaryJson: "{}",
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

    for (const [index, record] of replacement.records.entries()) {
      await insertAndGetId("xray_quick_config_dns_record_backups", {
        operationId,
        dnsAccountId: plan.domain.accountId,
        zoneId: plan.domain.zoneId,
        providerRecordId: record.providerRecordId,
        fqdn: plan.domain.fqdn,
        recordType: record.recordType,
        providerLineId: record.providerLineId,
        value: record.value,
        ttl: record.ttl,
        remoteTupleHash: computeXrayQuickConfigDnsTupleHash({
          fqdn: plan.domain.fqdn,
          recordType: record.recordType,
          providerLineId: record.providerLineId,
          value: record.value,
          ttl: record.ttl,
        }),
        snapshotOrder: index,
        state: "CAPTURED",
        createdAt: now,
        updatedAt: now,
      });
    }

    await insertOperationStep({ operationId, operationTag, stepKey: "domain-recheck", kind: "DOMAIN_RECHECK", subjectType: "DOMAIN", subjectId: plan.domain.fqdn, status: "SUCCESS", now });
    await insertOperationStep({ operationId, operationTag, stepKey: "port-reserve", kind: "PORT_RESERVE", subjectType: "ALLOCATION", subjectId: String(allocation.allocationId), status: "SUCCESS", now });
    for (const { id } of ruleIds) {
      await insertOperationStep({ operationId, operationTag, stepKey: `rule-create-${id}`, kind: "RULE_CREATE", subjectType: "RULE", subjectId: String(id), status: "SUCCESS", now });
      await insertOperationStep({ operationId, operationTag, stepKey: `rule-verify-${id}`, kind: "RULE_VERIFY", subjectType: "RULE", subjectId: String(id), now });
    }
    for (const record of desiredRecordIds) {
      await insertOperationStep({ operationId, operationTag, stepKey: `dns-apply-${record.id}`, kind: record.replacement ? "DNS_REPLACE" : "DNS_CREATE", subjectType: "DNS_RECORD", subjectId: String(record.id), now });
      await insertOperationStep({ operationId, operationTag, stepKey: `dns-verify-${record.id}`, kind: "DNS_VERIFY", subjectType: "DNS_RECORD", subjectId: String(record.id), now });
    }
    for (const [index] of replacement.records.entries()) {
      if (assignedReplacementIndexes.has(index)) continue;
      await insertOperationStep({ operationId, operationTag, stepKey: `dns-delete-${index + 1}`, kind: "DNS_DELETE", subjectType: "DNS_RECORD", subjectId: null, now });
    }
    for (let index = 0; index < desiredRecordIds.length + replacement.records.length; index += 1) {
      await insertOperationStep({ operationId, operationTag, stepKey: `dns-restore-${index + 1}`, kind: "DNS_RESTORE", subjectType: "DNS_RECORD", subjectId: null, now });
    }
    await executeRaw(
      `UPDATE ${q("xray_quick_configs")} SET ${q("desiredTopologyRevisionId")} = ?, ${q("currentOperationId")} = ?, ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("revision")} = 1`,
      [topologyRevisionId, operationId, now, quickConfigId],
    );
    await afterDatabaseCommit(() => {
      for (const rule of ruleIds) pushAgentRefresh(rule.hostId, "xray-quick-config-apply", { urgent: true });
      kickQuickConfigOperationWorker();
    });
    return { quickConfigId, operationId };
  });
  return { ...created, state: "APPLYING" };
}

async function claimOperation(operationId: number): Promise<Row | null> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Row>(
    `SELECT * FROM ${q("xray_quick_config_operations")} WHERE ${q("id")} = ? LIMIT 1`,
    [operationId],
  );
  const row = rows[0];
  if (!row || !["QUEUED", "RUNNING", "COMPENSATING"].includes(String(row.status))) return null;
  const now = nowDate();
  const revision = positiveInteger(row.revision);
  const changed = await executeRaw(
    `UPDATE ${q("xray_quick_config_operations")}
        SET ${q("status")} = CASE WHEN ${q("status")} = 'QUEUED' THEN 'RUNNING' ELSE ${q("status")} END,
            ${q("executionOwnerId")} = ?, ${q("executionLeaseUntil")} = ?,
            ${q("executionFence")} = ${q("executionFence")} + 1,
            ${q("revision")} = ${q("revision")} + 1,
            ${q("startedAt")} = COALESCE(${q("startedAt")}, ?), ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("revision")} = ?
        AND ${q("status")} IN ('QUEUED', 'RUNNING', 'COMPENSATING')
        AND EXISTS (SELECT 1 FROM ${q("xray_quick_configs")} qc
          WHERE qc.${q("id")} = ${q("xray_quick_config_operations")}.${q("quickConfigId")}
            AND qc.${q("currentOperationId")} = ${q("xray_quick_config_operations")}.${q("id")})
        AND (${q("executionOwnerId")} IS NULL OR ${q("executionOwnerId")} = ? OR ${q("executionLeaseUntil")} IS NULL OR ${q("executionLeaseUntil")} <= ?)`,
    [WORKER_ID, new Date(now.getTime() + WORKER_LEASE_MS), now, now, operationId, revision, WORKER_ID, now],
  );
  if (rawAffectedRows(changed) !== 1) return null;
  return (await queryRaw<Row>(
    `SELECT o.* FROM ${q("xray_quick_config_operations")} o
      JOIN ${q("xray_quick_configs")} qc ON qc.${q("id")} = o.${q("quickConfigId")}
      WHERE o.${q("id")} = ? AND o.${q("executionOwnerId")} = ?
        AND qc.${q("currentOperationId")} = o.${q("id")} LIMIT 1`,
    [operationId, WORKER_ID],
  ))[0] ?? null;
}

async function terminalOperation(input: {
  fence: OperationFence;
  status: "SUCCESS" | "FAILED" | "PARTIAL_FAILURE";
  errorCode: string | null;
}) {
  const q = quoteIdentifier;
  const now = nowDate();
  await withDatabaseTransaction(async () => {
    await assertOperationFence(input.fence);
    const owned = operationFenceExistsSql(input.fence);
    let appliedTopologyId: number | null = null;
    if (input.status === "SUCCESS") {
      const configs = await queryRaw<Row>(
        `SELECT qc.${q("desiredTopologyRevisionId")} FROM ${q("xray_quick_configs")} qc
          WHERE qc.${q("id")} = ? AND qc.${q("currentOperationId")} = ? AND ${owned.sql} LIMIT 1`,
        [input.fence.quickConfigId, input.fence.operationId, ...owned.params],
      );
      const topologyId = positiveInteger(configs[0]?.desiredTopologyRevisionId);
      appliedTopologyId = topologyId;
      const topologyChanged = await executeRaw(
        `UPDATE ${q("xray_quick_config_topology_revisions")} SET ${q("state")} = 'APPLIED', ${q("activeSlot")} = 1, ${q("updatedAt")} = ?
          WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${owned.sql}`,
        [now, topologyId, input.fence.quickConfigId, ...owned.params],
      );
      if (rawAffectedRows(topologyChanged) !== 1) throw new QuickConfigOperationFenceLostError();
      const routesToChange = await queryRaw<Row>(
        `SELECT ${q("id")} FROM ${q("xray_quick_config_routes")}
          WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ? AND ${q("state")} <> 'APPLIED'`,
        [input.fence.quickConfigId, topologyId],
      );
      const routesChanged = await executeRaw(
        `UPDATE ${q("xray_quick_config_routes")} SET ${q("state")} = 'APPLIED', ${q("updatedAt")} = ?
          WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ? AND ${q("state")} <> 'APPLIED'
            AND ${owned.sql}`,
        [now, input.fence.quickConfigId, topologyId, ...owned.params],
      );
      if (rawAffectedRows(routesChanged) !== routesToChange.length) {
        throw new XrayQuickConfigOperationError("QUICK_CONFIG_APPLY_CONFLICT");
      }
      const bindingsToChange = await queryRaw<Row>(
        `SELECT ${q("id")} FROM ${q("xray_quick_config_rule_bindings")}
          WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ? AND ${q("state")} <> 'READY'`,
        [input.fence.quickConfigId, topologyId],
      );
      const bindingsChanged = await executeRaw(
        `UPDATE ${q("xray_quick_config_rule_bindings")} SET ${q("state")} = 'READY', ${q("updatedAt")} = ?
          WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ? AND ${q("state")} <> 'READY'
            AND ${owned.sql}`,
        [now, input.fence.quickConfigId, topologyId, ...owned.params],
      );
      await assertOperationFence(input.fence);
      if (rawAffectedRows(bindingsChanged) !== bindingsToChange.length) {
        throw new XrayQuickConfigOperationError("QUICK_CONFIG_APPLY_CONFLICT");
      }
    }
    const operationChanged = await executeRaw(
      `UPDATE ${q("xray_quick_config_operations")} SET ${q("status")} = ?, ${q("phase")} = 'COMPLETED',
          ${q("revision")} = ${q("revision")} + 1, ${q("errorCode")} = ?, ${q("errorMessage")} = NULL,
          ${q("finishedAt")} = ?, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("executionOwnerId")} = ?
          AND ${q("executionFence")} = ? AND ${q("status")} IN ('RUNNING', 'COMPENSATING')
          AND EXISTS (SELECT 1 FROM ${q("xray_quick_configs")} qc
            WHERE qc.${q("id")} = ? AND qc.${q("currentOperationId")} = ?)`,
      [input.status, input.errorCode, now, now, input.fence.operationId, input.fence.quickConfigId,
        input.fence.executionOwnerId, input.fence.executionFence, input.fence.quickConfigId, input.fence.operationId],
    );
    if (rawAffectedRows(operationChanged) !== 1) throw new QuickConfigOperationFenceLostError();
    const configChanged = input.status === "SUCCESS"
      ? await executeRaw(
        `UPDATE ${q("xray_quick_configs")} SET ${q("state")} = 'ACTIVE', ${q("activeTopologyRevisionId")} = ?,
            ${q("desiredTopologyRevisionId")} = NULL, ${q("currentOperationId")} = NULL,
            ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ?
          WHERE ${q("id")} = ? AND ${q("currentOperationId")} = ?
            AND EXISTS (SELECT 1 FROM ${q("xray_quick_config_operations")} o WHERE o.${q("id")} = ?
              AND o.${q("executionOwnerId")} = ? AND o.${q("executionFence")} = ? AND o.${q("status")} = ?)`,
        [positiveInteger(appliedTopologyId), now, input.fence.quickConfigId,
          input.fence.operationId, input.fence.operationId, input.fence.executionOwnerId, input.fence.executionFence, input.status],
      )
      : await executeRaw(
        `UPDATE ${q("xray_quick_configs")} SET ${q("state")} = ?, ${q("currentOperationId")} = NULL,
            ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ?
          WHERE ${q("id")} = ? AND ${q("currentOperationId")} = ?
            AND EXISTS (SELECT 1 FROM ${q("xray_quick_config_operations")} o WHERE o.${q("id")} = ?
              AND o.${q("executionOwnerId")} = ? AND o.${q("executionFence")} = ? AND o.${q("status")} = ?)`,
        [input.status === "FAILED" ? "FAILED" : "PARTIAL_FAILURE", now, input.fence.quickConfigId,
          input.fence.operationId, input.fence.operationId, input.fence.executionOwnerId, input.fence.executionFence, input.status],
      );
    if (rawAffectedRows(configChanged) !== 1) throw new QuickConfigOperationFenceLostError();
    const released = await executeRaw(
      `UPDATE ${q("xray_quick_config_operations")} SET ${q("activeSlot")} = NULL, ${q("executionOwnerId")} = NULL,
          ${q("executionLeaseUntil")} = NULL, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("executionOwnerId")} = ?
          AND ${q("executionFence")} = ? AND ${q("status")} = ?`,
      [now, input.fence.operationId, input.fence.quickConfigId, input.fence.executionOwnerId,
        input.fence.executionFence, input.status],
    );
    if (rawAffectedRows(released) !== 1) throw new QuickConfigOperationFenceLostError();
  });
}

function databaseBoolean(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || value === "true";
}

async function beginApplyRuleCompensation(
  fence: OperationFence,
  rules: readonly Row[],
  errorCode: string,
): Promise<void> {
  const q = quoteIdentifier;
  const now = nowDate();
  const phaseChanged = await executeRaw(
    `UPDATE ${q("xray_quick_config_operations")} SET ${q("status")} = 'COMPENSATING',
        ${q("phase")} = 'REMOVING_NEW_RULES', ${q("revision")} = ${q("revision")} + 1,
        ${q("errorCode")} = ?, ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("executionOwnerId")} = ?
        AND ${q("executionFence")} = ? AND ${q("status")} IN ('RUNNING', 'COMPENSATING')
        AND EXISTS (SELECT 1 FROM ${q("xray_quick_configs")} qc
          WHERE qc.${q("id")} = ? AND qc.${q("currentOperationId")} = ?)`,
    [errorCode, now, fence.operationId, fence.quickConfigId, fence.executionOwnerId,
      fence.executionFence, fence.quickConfigId, fence.operationId],
  );
  if (rawAffectedRows(phaseChanged) !== 1) throw new QuickConfigOperationFenceLostError();
  const configChanged = await executeRaw(
    `UPDATE ${q("xray_quick_configs")} SET ${q("state")} = 'COMPENSATING', ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("currentOperationId")} = ?
        AND EXISTS (SELECT 1 FROM ${q("xray_quick_config_operations")} o
          WHERE o.${q("id")} = ? AND o.${q("executionOwnerId")} = ? AND o.${q("executionFence")} = ?
            AND o.${q("status")} = 'COMPENSATING')`,
    [now, fence.quickConfigId, fence.operationId, fence.operationId,
      fence.executionOwnerId, fence.executionFence],
  );
  if (rawAffectedRows(configChanged) !== 1) throw new QuickConfigOperationFenceLostError();
  const owned = operationFenceExistsSql(fence);
  await executeRaw(
    `UPDATE ${q("xray_quick_config_operation_steps")} SET ${q("status")} = 'FAILED',
        ${q("errorCode")} = ?, ${q("finishedAt")} = ?, ${q("updatedAt")} = ?
      WHERE ${q("operationId")} = ? AND ${q("kind")} = 'RULE_VERIFY'
        AND ${q("status")} <> 'SUCCESS' AND ${owned.sql}`,
    [errorCode, now, now, fence.operationId, ...owned.params],
  );
  const hosts = new Set<number>();
  for (const rule of rules) {
    const ruleId = Number(rule.id);
    const hostId = Number(rule.hostId);
    if (ruleId > 0) {
      const currentFence = operationFenceExistsSql(fence);
      const changed = await executeRaw(
        `UPDATE ${q("forward_rules")} SET ${q("isEnabled")} = ?, ${q("isRunning")} = ?,
            ${q("pendingDelete")} = ?, ${q("updatedAt")} = ?
          WHERE ${q("id")} = ? AND ${q("xrayQuickConfigId")} = ? AND ${currentFence.sql}`,
        [false, true, true, now, ruleId, fence.quickConfigId, ...currentFence.params],
      );
      if (rawAffectedRows(changed) !== 1) throw new QuickConfigOperationFenceLostError();
    }
    if (hostId > 0) hosts.add(hostId);
  }
  await executeRaw(
    `UPDATE ${q("xray_quick_config_rule_bindings")} SET ${q("state")} = 'RETIRING', ${q("updatedAt")} = ?
      WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} =
        (SELECT ${q("toTopologyRevisionId")} FROM ${q("xray_quick_config_operations")} WHERE ${q("id")} = ?)
        AND ${q("state")} <> 'REMOVED' AND ${owned.sql}`,
    [now, fence.quickConfigId, fence.operationId, ...owned.params],
  );
  for (const hostId of hosts) {
    pushAgentRefresh(hostId, "xray-quick-config-rule-compensation", { urgent: true });
  }
}

async function finishApplyRuleCompensation(
  fence: OperationFence,
  topologyId: number,
  errorCode: string,
): Promise<void> {
  const q = quoteIdentifier;
  const now = nowDate();
  const owned = operationFenceExistsSql(fence);
  await executeRaw(
    `UPDATE ${q("xray_quick_config_rule_bindings")} SET ${q("state")} = 'REMOVED', ${q("updatedAt")} = ?
      WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ? AND ${owned.sql}`,
    [now, fence.quickConfigId, topologyId, ...owned.params],
  );
  await assertOperationFence(fence);
  const remainingBindings = await queryRaw<Row>(
    `SELECT ${q("id")} FROM ${q("xray_quick_config_rule_bindings")}
      WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ? AND ${q("state")} <> 'REMOVED'`,
    [fence.quickConfigId, topologyId],
  );
  if (remainingBindings.length > 0) throw new XrayQuickConfigOperationError("QUICK_CONFIG_APPLY_CONFLICT");
  const topologyChanged = await executeRaw(
    `UPDATE ${q("xray_quick_config_topology_revisions")} SET ${q("state")} = 'ABANDONED',
        ${q("activeSlot")} = NULL, ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${owned.sql}`,
    [now, topologyId, fence.quickConfigId, ...owned.params],
  );
  if (rawAffectedRows(topologyChanged) !== 1) throw new QuickConfigOperationFenceLostError();
  await executeRaw(
    `UPDATE ${q("xray_quick_config_routes")} SET ${q("state")} = 'RETIRED', ${q("updatedAt")} = ?
      WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ? AND ${owned.sql}`,
    [now, fence.quickConfigId, topologyId, ...owned.params],
  );
  await terminalOperation({ fence, status: "FAILED", errorCode });
}

async function processOperation(operation: Row) {
  const configSync = await import("./xrayQuickConfigSyncService");
  if (configSync.isXrayQuickConfigSyncOperation(operation)) {
    await configSync.processXrayQuickConfigSyncOperation(operation);
    return;
  }
  const engineSwitch = await import("./xrayQuickConfigEngineSwitchService");
  if (await engineSwitch.isXrayQuickConfigEngineSwitchOperation(operation)) {
    await engineSwitch.processXrayQuickConfigEngineSwitchOperation(operation);
    return;
  }
  const topologyEdit = await import("./xrayQuickConfigEditService");
  if (await topologyEdit.isQuickConfigTopologyEditOperation(operation)) {
    await topologyEdit.processQuickConfigTopologyEditOperation(operation);
    return;
  }
  const lifecycle = await import("./xrayQuickConfigLifecycleService");
  if (await lifecycle.isQuickConfigRemoveOperation(operation)) {
    await lifecycle.processQuickConfigRemoveOperation(operation);
    return;
  }
  const q = quoteIdentifier;
  const fence = operationFence(operation);
  const operationId = fence.operationId;
  const quickConfigId = fence.quickConfigId;
  await assertOperationFence(fence);
  const rules = await queryRaw<Row>(
    `SELECT r.${q("id")}, r.${q("hostId")}, r.${q("isRunning")}, r.${q("pendingDelete")}
       FROM ${q("xray_quick_config_rule_bindings")} b
       LEFT JOIN ${q("forward_rules")} r ON r.${q("id")} = b.${q("forwardRuleId")}
      WHERE b.${q("quickConfigId")} = ? AND b.${q("topologyRevisionId")} = ? AND b.${q("state")} <> 'REMOVED'`,
    [quickConfigId, positiveInteger(operation.toTopologyRevisionId)],
  );
  const topologyId = positiveInteger(operation.toTopologyRevisionId);
  if (operation.status === "COMPENSATING" && operation.phase === "REMOVING_NEW_RULES") {
    const existing = rules.filter((rule) => Number(rule.id) > 0);
    if (existing.length > 0) {
      if (Date.now() - databaseDate(operation.createdAt).getTime() >= RULE_CLEANUP_TIMEOUT_MS) {
        await terminalOperation({ fence, status: "PARTIAL_FAILURE", errorCode: "RULE_CLEANUP_TIMEOUT" });
        return;
      }
      await beginApplyRuleCompensation(fence, existing, String(operation.errorCode || "RULE_APPLY_FAILED"));
      return;
    }
    await finishApplyRuleCompensation(fence, topologyId, String(operation.errorCode || "RULE_APPLY_FAILED"));
    return;
  }
  const missingOrDeleting = rules.some((rule) => !rule.id || rule.pendingDelete === true || rule.pendingDelete === 1 || rule.pendingDelete === "1");
  const allRunning = !missingOrDeleting && rules.every((rule) => databaseBoolean(rule.isRunning));
  const now = nowDate();
  if (!allRunning) {
    if (now.getTime() - databaseDate(operation.createdAt).getTime() < RULE_READY_TIMEOUT_MS && !missingOrDeleting) {
      const phaseChanged = await executeRaw(
        `UPDATE ${q("xray_quick_config_operations")} SET ${q("phase")} = 'WAITING_RULES_READY',
            ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ?
          WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("executionOwnerId")} = ?
            AND ${q("executionFence")} = ? AND ${q("status")} IN ('RUNNING', 'COMPENSATING')
            AND EXISTS (SELECT 1 FROM ${q("xray_quick_configs")} qc
              WHERE qc.${q("id")} = ? AND qc.${q("currentOperationId")} = ?)`,
        [now, operationId, quickConfigId, fence.executionOwnerId, fence.executionFence,
          quickConfigId, operationId],
      );
      if (rawAffectedRows(phaseChanged) !== 1) throw new QuickConfigOperationFenceLostError();
      return;
    }
    await beginApplyRuleCompensation(fence, rules, "RULE_APPLY_FAILED");
    return;
  }
  const owned = operationFenceExistsSql(fence);
  const stepsChanged = await executeRaw(
    `UPDATE ${q("xray_quick_config_operation_steps")} SET ${q("status")} = 'SUCCESS',
        ${q("attemptCount")} = ${q("attemptCount")} + 1, ${q("resultSummaryJson")} = '{}',
        ${q("errorCode")} = NULL, ${q("startedAt")} = COALESCE(${q("startedAt")}, ?),
        ${q("finishedAt")} = ?, ${q("updatedAt")} = ?
      WHERE ${q("operationId")} = ? AND ${q("kind")} = 'RULE_VERIFY'
        AND ${q("status")} <> 'SUCCESS' AND ${owned.sql}`,
    [now, now, now, operationId, ...owned.params],
  );
  await assertOperationFence(fence);
  const pendingSteps = await queryRaw<Row>(
    `SELECT ${q("id")} FROM ${q("xray_quick_config_operation_steps")}
      WHERE ${q("operationId")} = ? AND ${q("kind")} = 'RULE_VERIFY' AND ${q("status")} <> 'SUCCESS'`,
    [operationId],
  );
  if (pendingSteps.length > 0 || rawAffectedRows(stepsChanged) > rules.length) {
    throw new XrayQuickConfigOperationError("QUICK_CONFIG_APPLY_CONFLICT");
  }
  const bindingsChanged = await executeRaw(
    `UPDATE ${q("xray_quick_config_rule_bindings")} SET ${q("state")} = 'READY', ${q("updatedAt")} = ?
      WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ? AND ${q("state")} = 'APPLYING'
        AND ${owned.sql}`,
    [now, quickConfigId, topologyId, ...owned.params],
  );
  await assertOperationFence(fence);
  const pendingBindings = await queryRaw<Row>(
    `SELECT ${q("id")} FROM ${q("xray_quick_config_rule_bindings")}
      WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ? AND ${q("state")} = 'APPLYING'`,
    [quickConfigId, topologyId],
  );
  if (pendingBindings.length > 0 || rawAffectedRows(bindingsChanged) > rules.length) {
    throw new XrayQuickConfigOperationError("QUICK_CONFIG_APPLY_CONFLICT");
  }
  const phaseChanged = await executeRaw(
    `UPDATE ${q("xray_quick_config_operations")} SET ${q("phase")} = 'APPLYING_DNS',
        ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("executionOwnerId")} = ?
        AND ${q("executionFence")} = ? AND ${q("status")} IN ('RUNNING', 'COMPENSATING')
        AND EXISTS (SELECT 1 FROM ${q("xray_quick_configs")} qc
          WHERE qc.${q("id")} = ? AND qc.${q("currentOperationId")} = ?)`,
    [now, operationId, quickConfigId, fence.executionOwnerId, fence.executionFence, quickConfigId, operationId],
  );
  if (rawAffectedRows(phaseChanged) !== 1) throw new QuickConfigOperationFenceLostError();
  const { applyQuickConfigDnsOperation } = await import("./xrayQuickConfigDnsApplyService");
  const dnsResult = await applyQuickConfigDnsOperation(operationId, {
    executionOwnerId: fence.executionOwnerId,
    executionFence: fence.executionFence,
  });
  await assertOperationFence(fence);
  if (dnsResult.status !== "SUCCESS") {
    if (dnsResult.status === "PARTIAL_FAILURE") {
      await terminalOperation({ fence, status: "PARTIAL_FAILURE", errorCode: dnsResult.errorCode || "DNS_APPLY_FAILED" });
    } else {
      await beginApplyRuleCompensation(fence, rules, dnsResult.errorCode || "DNS_APPLY_FAILED");
    }
    return;
  }
  const finalizingChanged = await executeRaw(
    `UPDATE ${q("xray_quick_config_operations")} SET ${q("phase")} = 'FINALIZING',
        ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("executionOwnerId")} = ?
        AND ${q("executionFence")} = ? AND ${q("status")} IN ('RUNNING', 'COMPENSATING')
        AND EXISTS (SELECT 1 FROM ${q("xray_quick_configs")} qc
          WHERE qc.${q("id")} = ? AND qc.${q("currentOperationId")} = ?)`,
    [nowDate(), operationId, quickConfigId, fence.executionOwnerId, fence.executionFence,
      quickConfigId, operationId],
  );
  if (rawAffectedRows(finalizingChanged) !== 1) throw new QuickConfigOperationFenceLostError();
  await terminalOperation({ fence, status: "SUCCESS", errorCode: null });
}

export async function runQuickConfigOperationSweep(limitValue = 8): Promise<number> {
  if (workerRunning) return 0;
  workerRunning = true;
  try {
    const limit = Math.max(1, Math.min(32, Math.floor(Number(limitValue) || 8)));
    const q = quoteIdentifier;
    const rows = await queryRaw<Row>(
      `SELECT ${q("id")} FROM ${q("xray_quick_config_operations")} WHERE ${q("status")} IN ('QUEUED', 'RUNNING', 'COMPENSATING') ORDER BY ${q("createdAt")} ASC, ${q("id")} ASC LIMIT ?`,
      [limit],
    );
    let processed = 0;
    for (const row of rows) {
      const operation = await claimOperation(positiveInteger(row.id));
      if (!operation) continue;
      processed += 1;
      try {
        await processOperation(operation);
      } catch (error) {
        const fence = operationFence(operation);
        if (error instanceof QuickConfigOperationFenceLostError || !await ownsOperationFence(fence)) continue;
        await terminalOperation({
          fence,
          status: "PARTIAL_FAILURE",
          errorCode: "DNS_APPLY_FAILED",
        }).catch(() => undefined);
      }
    }
    return processed;
  } finally {
    workerRunning = false;
  }
}

export function kickQuickConfigOperationWorker() {
  if (workerKickScheduled) return;
  workerKickScheduled = true;
  setImmediate(() => {
    workerKickScheduled = false;
    void runQuickConfigOperationSweep();
  });
}
