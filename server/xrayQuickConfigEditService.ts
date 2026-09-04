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
import {
  activateReservedGlobalPortAllocation,
  addActiveGlobalPortOwningReference,
  attachGlobalPortTargetAlias,
  inspectGlobalPortAllocation,
  releaseGlobalPortReferenceAfterRuntimeCleanup,
  reserveGlobalPortAllocation,
  type GlobalPortAllocationDto,
  type GlobalPortReferenceInput,
} from "./globalPortAllocationService";
import { finalizeForwardRuleDelete, markForwardRulePendingDelete, createForwardRule } from "./repositories/forwardRuleRepository";
import { loadGlobalDnsProviderCredentials } from "./repositories/dnsProviderRepository";
import { assignQuickConfigRulePortResource, ensureQuickConfigPortResource } from "./quickConfigPortResourceService";
import { computeXrayQuickConfigDnsTupleHash } from "./xrayQuickConfigDnsTuple";
import { matchQuickConfigDnsRecords } from "./xrayQuickConfigDnsDiff";
import {
  validateQuickConfigEditPreviewToken,
  type QuickConfigImmutablePlan,
} from "./xrayQuickConfigPlanningService";

type Row = Record<string, unknown>;
type Engine = QuickConfigImmutablePlan["engine"];
type MutableRecord = DnsPodRecord & { recordType: "A" | "AAAA" | "CNAME" };

export const XRAY_QUICK_CONFIG_EDIT_ERROR_CODES = [
  "QUICK_CONFIG_NOT_FOUND",
  "QUICK_CONFIG_PREVIEW_INVALID",
  "QUICK_CONFIG_REVISION_CONFLICT",
  "QUICK_CONFIG_OPERATION_CONFLICT",
  "DNS_PROVIDER_CONFLICT_CHANGED",
  "DNS_RECORD_DRIFT",
  "RULE_APPLY_FAILED",
  "RULE_CLEANUP_TIMEOUT",
  "DNS_APPLY_FAILED",
  "DNS_COMPENSATION_FAILED",
] as const;

export class XrayQuickConfigEditError extends Error {
  constructor(readonly code: typeof XRAY_QUICK_CONFIG_EDIT_ERROR_CODES[number]) {
    super(code);
    this.name = "XrayQuickConfigEditError";
  }
}

type EditSnapshot = Readonly<{
  quickConfigId: number;
  expectedRevision: number;
  configTag: string;
  targetType: "XRAY_INBOUND" | "EXTERNAL_PROXY_NODE";
  targetId: number;
  targetVersion: string;
  oldDnsAccountId: number;
  oldZoneId: number;
  oldRelativeName: string;
  oldFqdn: string;
  fromTopologyId: number;
  fromTopologyRevision: number;
  engine: Engine;
  targetAddress: string;
  targetPort: number;
  publicPort: number;
  allocationId: number;
  rules: Array<Readonly<{
    ruleId: number;
    hostId: number;
    engine: Engine;
    sourcePort: number;
    targetAddress: string;
    targetPort: number;
  }>>;
}>;

type OperationSummary = Readonly<{
  kind: "TOPOLOGY_EDIT";
  oldDnsAccountId: number;
  oldZoneId: number;
  oldRelativeName: string;
  oldFqdn: string;
}>;

const READY_TIMEOUT_MS = 120_000;
const CLEANUP_TIMEOUT_MS = 10 * 60_000;

function fail(code: typeof XRAY_QUICK_CONFIG_EDIT_ERROR_CODES[number]): never {
  throw new XrayQuickConfigEditError(code);
}

function positiveInteger(value: unknown, code: typeof XRAY_QUICK_CONFIG_EDIT_ERROR_CODES[number] = "QUICK_CONFIG_OPERATION_CONFLICT") {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) fail(code);
  return parsed;
}

function port(value: unknown) {
  const parsed = positiveInteger(value);
  if (parsed > 65_535) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  return parsed;
}

function bool(value: unknown) {
  return value === true || value === 1 || value === "1" || value === "true";
}

function date(value: unknown): Date {
  if (value instanceof Date && Number.isFinite(value.getTime())) return value;
  const numeric = Number(value);
  const parsed = Number.isFinite(numeric) ? new Date(numeric < 10_000_000_000 ? numeric * 1_000 : numeric) : new Date(String(value ?? ""));
  if (!Number.isFinite(parsed.getTime())) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  return parsed;
}

function stable(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object") return `{${Object.entries(value as Record<string, unknown>)
    .sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => `${JSON.stringify(key)}:${stable(item)}`).join(",")}}`;
  return JSON.stringify(value);
}

function sha256(value: string) {
  return crypto.createHash("sha256").update(value, "utf8").digest("hex");
}

function domainClaimKey(accountTag: string, providerZoneId: string, fqdn: string) {
  return sha256(stable({ schema: "quick-config-domain-claim:v1", provider: "DNSPOD", accountTag, providerZoneId, fqdn }));
}

function engine(value: unknown): Engine {
  const text = String(value ?? "");
  if (!["iptables", "nftables", "realm", "socat", "gost", "nginx"].includes(text)) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  return text as Engine;
}

function quickReference(input: {
  quickConfigId: number;
  hostId: number | null;
  role: "TARGET" | "PUBLIC_LISTENER" | "OWNERSHIP";
  owning: boolean;
}): GlobalPortReferenceInput {
  return {
    resourceType: "QUICK_CONFIG",
    resourceId: input.quickConfigId,
    hostId: input.hostId,
    network: input.role === "PUBLIC_LISTENER" ? "TCP" : "NONE",
    role: input.role,
    isOwning: input.owning,
  };
}

function ruleReference(ruleId: number, hostId: number): GlobalPortReferenceInput {
  return { resourceType: "FORWARD_RULE", resourceId: ruleId, hostId, network: "TCP", role: "PUBLIC_LISTENER", isOwning: true };
}

function rowReference(row: Row): GlobalPortReferenceInput {
  const resourceType = String(row.resourceType) as GlobalPortReferenceInput["resourceType"];
  const network = String(row.network) as GlobalPortReferenceInput["network"];
  const role = String(row.role) as GlobalPortReferenceInput["role"];
  if (!["XRAY_INBOUND", "FORWARD_RULE", "MANAGED_SERVICE", "TUNNEL", "TUNNEL_EXIT_NODE", "TUNNEL_HOP", "FORWARD_RULE_TUNNEL_EXIT", "QUICK_CONFIG"].includes(resourceType)
    || !["TCP", "UDP", "BOTH", "NONE"].includes(network) || !["TARGET", "PUBLIC_LISTENER", "OWNERSHIP", "MIMIC"].includes(role)) {
    fail("QUICK_CONFIG_OPERATION_CONFLICT");
  }
  return {
    resourceType,
    resourceId: positiveInteger(row.resourceId),
    hostId: row.hostId === null || row.hostId === undefined ? null : positiveInteger(row.hostId),
    network,
    role,
    isOwning: bool(row.isOwning),
  };
}

function targetId(row: Row) {
  return row.targetType === "XRAY_INBOUND" ? positiveInteger(row.xrayInboundId) : positiveInteger(row.externalProxyNodeId);
}

async function loadSnapshot(quickConfigId: number, expectedRevision: number): Promise<EditSnapshot> {
  const q = quoteIdentifier;
  const [row] = await queryRaw<Row>(
    `SELECT qc.*, t.${q("revisionNumber")} AS ${q("topologyRevisionNumber")}, t.${q("engine")},
            t.${q("targetAddress")}, t.${q("targetPort")}, t.${q("publicPort")}, t.${q("portAllocationId")}
       FROM ${q("xray_quick_configs")} qc
       JOIN ${q("xray_quick_config_topology_revisions")} t ON t.${q("id")} = qc.${q("activeTopologyRevisionId")}
      WHERE qc.${q("id")} = ? LIMIT 1`,
    [quickConfigId],
  );
  if (!row || Number(row.revision) !== expectedRevision || row.state !== "ACTIVE"
    || row.currentOperationId !== null && row.currentOperationId !== undefined
    || (row.targetType !== "XRAY_INBOUND" && row.targetType !== "EXTERNAL_PROXY_NODE")) {
    fail("QUICK_CONFIG_REVISION_CONFLICT");
  }
  const fromTopologyId = positiveInteger(row.activeTopologyRevisionId);
  const rules = await queryRaw<Row>(
    `SELECT fr.${q("id")}, fr.${q("hostId")}, fr.${q("forwardType")}, fr.${q("sourcePort")},
            fr.${q("targetIp")}, fr.${q("targetPort")}
       FROM ${q("xray_quick_config_rule_bindings")} b
       JOIN ${q("forward_rules")} fr ON fr.${q("id")} = b.${q("forwardRuleId")}
      WHERE b.${q("quickConfigId")} = ? AND b.${q("topologyRevisionId")} = ? AND b.${q("state")} = 'READY'
        AND fr.${q("xrayQuickConfigId")} = ? AND fr.${q("isEnabled")} = ? AND fr.${q("pendingDelete")} = ?`,
    [quickConfigId, fromTopologyId, quickConfigId, true, false],
  );
  return {
    quickConfigId,
    expectedRevision,
    configTag: String(row.configTag),
    targetType: row.targetType,
    targetId: targetId(row),
    targetVersion: String(row.targetVersion),
    oldDnsAccountId: positiveInteger(row.dnsAccountId),
    oldZoneId: positiveInteger(row.zoneId),
    oldRelativeName: String(row.relativeName),
    oldFqdn: String(row.fqdn),
    fromTopologyId,
    fromTopologyRevision: positiveInteger(row.topologyRevisionNumber),
    engine: engine(row.engine),
    targetAddress: String(row.targetAddress),
    targetPort: port(row.targetPort),
    publicPort: port(row.publicPort),
    allocationId: positiveInteger(row.portAllocationId),
    rules: rules.map((rule) => ({
      ruleId: positiveInteger(rule.id), hostId: positiveInteger(rule.hostId), engine: engine(rule.forwardType),
      sourcePort: port(rule.sourcePort), targetAddress: String(rule.targetIp), targetPort: port(rule.targetPort),
    })),
  };
}

function projectedRemote(records: readonly DnsPodRecord[]) {
  return records.map((record) => ({
    recordType: ["A", "AAAA", "CNAME", "TXT", "MX", "CAA"].includes(record.recordType) ? record.recordType : "OTHER",
    providerLineId: record.providerLineId, lineName: record.lineName, value: record.value, ttl: record.ttl,
  })).sort((a, b) => stable(a).localeCompare(stable(b)));
}

async function replacementRecords(plan: QuickConfigImmutablePlan) {
  const credentials = await loadGlobalDnsProviderCredentials();
  if (credentials.accountId !== plan.domain.accountId || credentials.accountRevision !== plan.domain.accountRevision
    || credentials.bindingRevision !== plan.domain.bindingRevision) fail("QUICK_CONFIG_REVISION_CONFLICT");
  const q = quoteIdentifier;
  const [account] = await queryRaw<Row>(`SELECT ${q("accountTag")} FROM ${q("dns_provider_accounts")} WHERE ${q("id")} = ? LIMIT 1`, [plan.domain.accountId]);
  const accountTag = String(account?.accountTag ?? "");
  if (!accountTag || Buffer.byteLength(accountTag, "utf8") > 128) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  const zone: DnsPodZone = { providerZoneId: plan.domain.zone.providerZoneId, name: plan.domain.zone.name, grade: "" };
  const records = (await new DnsPodProviderClient({ credentials }).listRecords({ zone, subdomain: plan.domain.relativeName }))
    .filter((record) => record.subdomain.trim().toLowerCase() === plan.domain.relativeName);
  const expected = [...plan.domain.conflicts, ...plan.domain.preservedRecords]
    .map(({ recordRef: _recordRef, ...record }) => record).sort((a, b) => stable(a).localeCompare(stable(b)));
  if (stable(projectedRemote(records)) !== stable(expected)) fail("DNS_PROVIDER_CONFLICT_CHANGED");
  const mutable = records.filter((record): record is MutableRecord => record.recordType === "A" || record.recordType === "AAAA" || record.recordType === "CNAME");
  if (mutable.length > 64 || mutable.length > 0 && plan.domain.action !== "REPLACE_CONFLICTING_RECORDS") fail("DNS_PROVIDER_CONFLICT_CHANGED");
  return { accountTag, zone, mutable };
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
  const direct = plan.domain.target.targetType === "XRAY_INBOUND" && !plan.preview.allocation.rewritten;
  const carrier = plan.carrierRoutes.flatMap((route) => route.endpoints.map((endpoint) => {
    const landing = direct && endpoint.hostId === plan.domain.target.host.id;
    return {
      lineCategory: route.carrier,
      providerLineId: route.providerLineId,
      sourceType: landing ? "LANDING" as const : "MANAGED_HOST" as const,
      hostId: endpoint.hostId,
      addressFamily: endpoint.addressFamily,
      address: endpoint.address,
      routeMode: landing ? "DIRECT" as const : "FORWARD" as const,
    };
  }));
  const defaultLine = plan.domain.zone.carrierLines.find((line) => line.category === "DEFAULT" && line.status === "AVAILABLE");
  if (!defaultLine || !("providerLineId" in defaultLine)) fail("QUICK_CONFIG_PREVIEW_INVALID");
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
    const key = stable(route);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function routeDnsKey(category: string, line: string, type: string, value: string) {
  return `${category}\0${line}\0${type}\0${value}`;
}

function matchingRule(snapshot: EditSnapshot, planned: QuickConfigImmutablePlan["preview"]["rules"][number]) {
  return snapshot.rules.find((rule) => rule.hostId === planned.hostId && rule.engine === planned.engine
    && rule.sourcePort === planned.listenPort && rule.targetAddress === planned.targetAddress
    && rule.targetPort === planned.targetPort) ?? null;
}

async function insertStep(input: {
  operationId: number;
  operationTag: string;
  key: string;
  kind: string;
  subjectType: string;
  subjectId: string | null;
  status?: "PENDING" | "SUCCESS";
  now: Date;
}) {
  await insertAndGetId("xray_quick_config_operation_steps", {
    operationId: input.operationId,
    stepKey: input.key,
    kind: input.kind,
    subjectType: input.subjectType,
    subjectId: input.subjectId,
    status: input.status ?? "PENDING",
    attemptCount: input.status === "SUCCESS" ? 1 : 0,
    idempotencyKey: `${input.operationTag}:${input.key}`,
    requestSummaryJson: "{}",
    resultSummaryJson: input.status === "SUCCESS" ? "{}" : null,
    errorCode: null,
    startedAt: input.status === "SUCCESS" ? input.now : null,
    finishedAt: input.status === "SUCCESS" ? input.now : null,
    updatedAt: input.now,
  });
}

async function prepareAllocation(plan: QuickConfigImmutablePlan, snapshot: EditSnapshot, now: Date): Promise<GlobalPortAllocationDto> {
  const owner = { type: "QUICK_CONFIG" as const, stableIdentity: snapshot.configTag };
  if (plan.preview.publicPort === snapshot.publicPort) {
    let current = await inspectGlobalPortAllocation(snapshot.publicPort);
    if (!current || current.status !== "ACTIVE" || current.allocationId !== snapshot.allocationId) fail("QUICK_CONFIG_REVISION_CONFLICT");
    if (current.primaryOwnerType === "QUICK_CONFIG" && current.primaryOwnerTag === snapshot.configTag) {
      for (const rule of plan.preview.rules) {
        current = await addActiveGlobalPortOwningReference({
          allocationId: current.allocationId,
          expectedVersion: current.version,
          owner,
          reference: quickReference({
            quickConfigId: snapshot.quickConfigId,
            hostId: rule.hostId,
            role: "PUBLIC_LISTENER",
            owning: true,
          }),
          now,
        });
      }
      return current;
    }
    if (plan.domain.target.targetType !== "XRAY_INBOUND" || current.primaryOwnerType !== "XRAY_INBOUND") {
      fail("QUICK_CONFIG_REVISION_CONFLICT");
    }
    const q = quoteIdentifier;
    const [inbound] = await queryRaw<Row>(
      `SELECT ${q("runtimeTag")} FROM ${q("xray_inbounds")} WHERE ${q("id")} = ? LIMIT 1`,
      [plan.domain.target.targetId],
    );
    const runtimeTag = String(inbound?.runtimeTag ?? "");
    if (!runtimeTag || current.primaryOwnerTag !== runtimeTag) fail("QUICK_CONFIG_REVISION_CONFLICT");
    const sourceOwner = { type: "XRAY_INBOUND" as const, stableIdentity: runtimeTag };
    current = await attachGlobalPortTargetAlias({
      allocationId: current.allocationId,
      expectedVersion: current.version,
      sourceOwner,
      aliasOwner: owner,
      reference: quickReference({
        quickConfigId: snapshot.quickConfigId,
        hostId: plan.domain.target.host.id,
        role: "TARGET",
        owning: false,
      }),
      now,
    });
    for (const rule of plan.preview.rules) {
      current = await attachGlobalPortTargetAlias({
        allocationId: current.allocationId,
        expectedVersion: current.version,
        sourceOwner,
        aliasOwner: owner,
        reference: quickReference({
          quickConfigId: snapshot.quickConfigId,
          hostId: rule.hostId,
          role: "PUBLIC_LISTENER",
          owning: false,
        }),
        now,
      });
    }
    return current;
  }
  if (plan.preview.allocation.mode === "RESERVE_NEW") {
    const reserved = await reserveGlobalPortAllocation({ port: plan.preview.publicPort, owner, now });
    const references: GlobalPortReferenceInput[] = [quickReference({ quickConfigId: snapshot.quickConfigId, hostId: null, role: "OWNERSHIP", owning: true })];
    for (const rule of plan.preview.rules) references.push(quickReference({ quickConfigId: snapshot.quickConfigId, hostId: rule.hostId, role: "PUBLIC_LISTENER", owning: true }));
    return activateReservedGlobalPortAllocation({
      allocationId: reserved.allocationId,
      expectedVersion: reserved.version,
      reservationToken: reserved.reservationToken,
      owner,
      references,
      now,
    });
  }
  if (plan.domain.target.targetType !== "XRAY_INBOUND") fail("QUICK_CONFIG_PREVIEW_INVALID");
  const current = await inspectGlobalPortAllocation(plan.preview.publicPort);
  const q = quoteIdentifier;
  const [inbound] = await queryRaw<Row>(`SELECT ${q("runtimeTag")} FROM ${q("xray_inbounds")} WHERE ${q("id")} = ? LIMIT 1`, [plan.domain.target.targetId]);
  const runtimeTag = String(inbound?.runtimeTag ?? "");
  if (!current || current.status !== "ACTIVE" || current.primaryOwnerType !== "XRAY_INBOUND" || current.primaryOwnerTag !== runtimeTag) {
    fail("QUICK_CONFIG_REVISION_CONFLICT");
  }
  const sourceOwner = { type: "XRAY_INBOUND" as const, stableIdentity: runtimeTag };
  let allocation = await attachGlobalPortTargetAlias({
    allocationId: current.allocationId, expectedVersion: current.version, sourceOwner, aliasOwner: owner,
    reference: quickReference({ quickConfigId: snapshot.quickConfigId, hostId: plan.domain.target.host.id, role: "TARGET", owning: false }), now,
  });
  for (const rule of plan.preview.rules) {
    allocation = await attachGlobalPortTargetAlias({
      allocationId: allocation.allocationId, expectedVersion: allocation.version, sourceOwner, aliasOwner: owner,
      reference: quickReference({ quickConfigId: snapshot.quickConfigId, hostId: rule.hostId, role: "PUBLIC_LISTENER", owning: false }), now,
    });
  }
  return allocation;
}

export async function applyQuickConfigEditPreview(input: { previewToken: string; userId: number }): Promise<{
  quickConfigId: number;
  operationId: number;
  state: "UPDATING";
}> {
  const userId = positiveInteger(input.userId, "QUICK_CONFIG_PREVIEW_INVALID");
  const plan = await validateQuickConfigEditPreviewToken({ previewToken: input.previewToken, userId });
  const snapshot = await loadSnapshot(plan.editIdentity.quickConfigId, plan.editIdentity.expectedRevision);
  if (snapshot.fromTopologyId !== plan.editIdentity.fromTopologyRevisionId || snapshot.targetType !== plan.preview.target.targetType
    || snapshot.targetId !== plan.preview.target.targetId || snapshot.targetVersion !== plan.domain.target.targetVersion
    || snapshot.engine !== plan.engine || snapshot.targetAddress !== plan.preview.target.address || snapshot.targetPort !== plan.preview.target.port) {
    fail("QUICK_CONFIG_REVISION_CONFLICT");
  }
  const replacement = await replacementRecords(plan);
  const now = nowDate();
  const operationTag = `quick-config-operation:${crypto.randomUUID()}`;
  const drafts = routeDrafts(plan);
  const created = await withDatabaseTransaction(async () => {
    const q = quoteIdentifier;
    const [fresh] = await queryRaw<Row>(
      `SELECT ${q("revision")}, ${q("state")}, ${q("currentOperationId")}, ${q("activeTopologyRevisionId")}
         FROM ${q("xray_quick_configs")} WHERE ${q("id")} = ? LIMIT 1`,
      [snapshot.quickConfigId],
    );
    if (!fresh || Number(fresh.revision) !== snapshot.expectedRevision || fresh.state !== "ACTIVE"
      || fresh.currentOperationId !== null && fresh.currentOperationId !== undefined
      || Number(fresh.activeTopologyRevisionId) !== snapshot.fromTopologyId) fail("QUICK_CONFIG_REVISION_CONFLICT");
    const duplicate = await queryRaw<Row>(
      `SELECT ${q("id")} FROM ${q("xray_quick_configs")} WHERE ${q("dnsAccountId")} = ? AND ${q("zoneId")} = ?
        AND LOWER(${q("fqdn")}) = ? AND ${q("state")} <> 'REMOVED' AND ${q("id")} <> ? LIMIT 1`,
      [plan.domain.accountId, plan.domain.zoneId, plan.domain.fqdn, snapshot.quickConfigId],
    );
    if (duplicate.length) fail("QUICK_CONFIG_REVISION_CONFLICT");
    let allocation = await prepareAllocation(plan, snapshot, now);
    const [maximum] = await queryRaw<Row>(
      `SELECT MAX(${q("revisionNumber")}) AS ${q("maximum")} FROM ${q("xray_quick_config_topology_revisions")} WHERE ${q("quickConfigId")} = ?`,
      [snapshot.quickConfigId],
    );
    const revisionNumber = positiveInteger(maximum?.maximum) + 1;
    const topologyId = await insertAndGetId("xray_quick_config_topology_revisions", {
      quickConfigId: snapshot.quickConfigId,
      revisionNumber,
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
        routeTag: `${snapshot.configTag}:edit:${revisionNumber}:route:${index + 1}`,
        quickConfigId: snapshot.quickConfigId,
        topologyRevisionId: topologyId,
        ...route,
        sortOrder: index,
        state: "APPLYING",
        createdAt: now,
        updatedAt: now,
      });
      routeIds.set(routeDnsKey(route.lineCategory, route.providerLineId, route.addressFamily === "IPV4" ? "A" : "AAAA", route.address), routeId);
    }
    const createdRules: Array<{ ruleId: number; hostId: number }> = [];
    const reusedRules = new Set<number>();
    for (const [index, rule] of plan.preview.rules.entries()) {
      const reused = matchingRule(snapshot, rule);
      let ruleId: number;
      if (reused) {
        ruleId = reused.ruleId;
        reusedRules.add(ruleId);
      } else {
        const portResource = await ensureQuickConfigPortResource({
          userId,
          hostId: rule.hostId,
          engine: rule.engine,
        });
        ruleId = await createForwardRule({
          hostId: rule.hostId,
          name: `[快速配置] ${plan.domain.fqdn} #${index + 1}`,
          forwardType: rule.engine,
          protocol: "tcp",
          gostMode: "direct",
          sourcePort: rule.listenPort,
          targetIp: rule.targetAddress,
          targetPort: rule.targetPort,
          targetExternalProxyNodeId: null,
          xrayQuickConfigId: snapshot.quickConfigId,
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
        createdRules.push({ ruleId, hostId: rule.hostId });
      }
      await assignQuickConfigRulePortResource(ruleId);
      await insertAndGetId("xray_quick_config_rule_bindings", {
        bindingTag: `${snapshot.configTag}:edit:${revisionNumber}:rule:${index + 1}`,
        quickConfigId: snapshot.quickConfigId,
        topologyRevisionId: topologyId,
        forwardRuleId: ruleId,
        state: reused ? "READY" : "APPLYING",
        createdAt: now,
        updatedAt: now,
      });
      if (!reused) {
        if (allocation.primaryOwnerType === "QUICK_CONFIG") {
          allocation = await addActiveGlobalPortOwningReference({
            allocationId: allocation.allocationId,
            expectedVersion: allocation.version,
            owner: { type: "QUICK_CONFIG", stableIdentity: snapshot.configTag },
            reference: ruleReference(ruleId, rule.hostId),
            now,
          });
        }
      }
    }
    const desired: Array<{ id: number; replacement: MutableRecord | null }> = [];
    const { matches, removed } = matchQuickConfigDnsRecords(plan.preview.dnsRecords, replacement.mutable);
    for (const [index, { record, previous: prior }] of matches.entries()) {
      const category = record.routeKind === "DEFAULT" ? "DEFAULT" : record.carrier;
      const routeId = routeIds.get(routeDnsKey(category, record.providerLineId, record.recordType, record.value));
      if (!routeId) fail("QUICK_CONFIG_OPERATION_CONFLICT");
      const id = await insertAndGetId("xray_quick_config_dns_records", {
        quickConfigId: snapshot.quickConfigId,
        routeId,
        dnsAccountId: plan.domain.accountId,
        zoneId: plan.domain.zoneId,
        recordTag: `${snapshot.configTag}:edit:${revisionNumber}:dns:${index + 1}`,
        providerRecordId: null,
        providerLineId: record.providerLineId,
        fqdn: plan.domain.fqdn,
        recordType: record.recordType,
        value: record.value,
        ttl: record.ttl,
        status: "DESIRED",
        appliedRevision: revisionNumber,
        remoteTupleHash: computeXrayQuickConfigDnsTupleHash({
          fqdn: plan.domain.fqdn, recordType: record.recordType, providerLineId: record.providerLineId, value: record.value, ttl: record.ttl,
        }),
        lastVerifiedAt: null,
        createdAt: now,
        updatedAt: now,
      });
      desired.push({ id, replacement: prior });
    }
    const operationId = await insertAndGetId("xray_quick_config_operations", {
      operationTag,
      quickConfigId: snapshot.quickConfigId,
      type: "EDIT",
      status: "QUEUED",
      phase: "RECHECKING_DOMAIN",
      activeSlot: 1,
      revision: 1,
      expectedRevision: snapshot.expectedRevision,
      fromTopologyRevisionId: snapshot.fromTopologyId,
      toTopologyRevisionId: topologyId,
      requestSummaryJson: stable({
        kind: "TOPOLOGY_EDIT",
        oldDnsAccountId: snapshot.oldDnsAccountId,
        oldZoneId: snapshot.oldZoneId,
        oldRelativeName: snapshot.oldRelativeName,
        oldFqdn: snapshot.oldFqdn,
      } satisfies OperationSummary),
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
    for (const [index, record] of replacement.mutable.entries()) {
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
          fqdn: plan.domain.fqdn, recordType: record.recordType, providerLineId: record.providerLineId, value: record.value, ttl: record.ttl,
        }),
        snapshotOrder: index,
        state: "CAPTURED",
        createdAt: now,
        updatedAt: now,
      });
    }
    await insertStep({ operationId, operationTag, key: "domain-recheck", kind: "DOMAIN_RECHECK", subjectType: "DOMAIN", subjectId: plan.domain.fqdn, status: "SUCCESS", now });
    await insertStep({ operationId, operationTag, key: "port-reserve", kind: "PORT_RESERVE", subjectType: "ALLOCATION", subjectId: String(allocation.allocationId), status: "SUCCESS", now });
    for (const rule of plan.preview.rules) {
      const reused = matchingRule(snapshot, rule);
      const createdRule = reused ?? createdRules.find((candidate) => candidate.hostId === rule.hostId);
      if (!createdRule) fail("QUICK_CONFIG_OPERATION_CONFLICT");
      await insertStep({ operationId, operationTag, key: `rule-create-${createdRule.ruleId}`, kind: "RULE_CREATE", subjectType: "RULE", subjectId: String(createdRule.ruleId), status: "SUCCESS", now });
      await insertStep({ operationId, operationTag, key: `rule-verify-${createdRule.ruleId}`, kind: "RULE_VERIFY", subjectType: "RULE", subjectId: String(createdRule.ruleId), status: reused ? "SUCCESS" : undefined, now });
    }
    for (const record of desired) {
      await insertStep({ operationId, operationTag, key: `dns-apply-${record.id}`, kind: record.replacement ? "DNS_REPLACE" : "DNS_CREATE", subjectType: "DNS_RECORD", subjectId: String(record.id), now });
      await insertStep({ operationId, operationTag, key: `dns-verify-${record.id}`, kind: "DNS_VERIFY", subjectType: "DNS_RECORD", subjectId: String(record.id), now });
    }
    for (const [index] of replacement.mutable.entries()) {
      if (removed.includes(replacement.mutable[index])) await insertStep({ operationId, operationTag, key: `dns-delete-${index + 1}`, kind: "DNS_DELETE", subjectType: "DNS_RECORD", subjectId: null, now });
    }
    for (let index = 0; index < desired.length + replacement.mutable.length; index += 1) {
      await insertStep({ operationId, operationTag, key: `dns-restore-${index + 1}`, kind: "DNS_RESTORE", subjectType: "DNS_RECORD", subjectId: null, now });
    }
    for (const oldRule of snapshot.rules.filter((candidate) => !reusedRules.has(candidate.ruleId))) {
      await insertStep({ operationId, operationTag, key: `edit-remove-old-rule-${oldRule.ruleId}`, kind: "RULE_DELETE", subjectType: "RULE", subjectId: String(oldRule.ruleId), now });
      await insertStep({ operationId, operationTag, key: `edit-verify-old-rule-${oldRule.ruleId}`, kind: "RULE_VERIFY_REMOVED", subjectType: "RULE", subjectId: String(oldRule.ruleId), now });
    }
    const claimChanged = await executeRaw(
      `UPDATE ${q("xray_quick_config_domain_claims")} SET ${q("claimKey")} = ?, ${q("dnsAccountId")} = ?, ${q("zoneId")} = ?,
          ${q("normalizedRelativeName")} = ?, ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ?
        WHERE ${q("quickConfigId")} = ?`,
      [domainClaimKey(replacement.accountTag, replacement.zone.providerZoneId, plan.domain.fqdn),
        plan.domain.accountId, plan.domain.zoneId, plan.domain.relativeName, now, snapshot.quickConfigId],
    );
    if (rawAffectedRows(claimChanged) !== 1) fail("QUICK_CONFIG_REVISION_CONFLICT");
    const changed = await executeRaw(
      `UPDATE ${q("xray_quick_configs")} SET ${q("state")} = 'UPDATING', ${q("desiredTopologyRevisionId")} = ?,
          ${q("currentOperationId")} = ?, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("revision")} = ? AND ${q("state")} = 'ACTIVE' AND ${q("currentOperationId")} IS NULL`,
      [topologyId, operationId, now, snapshot.quickConfigId, snapshot.expectedRevision],
    );
    if (rawAffectedRows(changed) !== 1) fail("QUICK_CONFIG_REVISION_CONFLICT");
    await afterDatabaseCommit(() => {
      for (const rule of createdRules) pushAgentRefresh(rule.hostId, "xray-quick-config-edit", { urgent: true });
      void import("./xrayQuickConfigOperationService").then(({ kickQuickConfigOperationWorker }) => kickQuickConfigOperationWorker());
    });
    return { operationId };
  });
  return { quickConfigId: snapshot.quickConfigId, operationId: created.operationId, state: "UPDATING" };
}

function summary(operation: Row): OperationSummary | null {
  if (operation.type !== "EDIT" && operation.type !== "RETRY") return null;
  try {
    const parsed = JSON.parse(String(operation.requestSummaryJson ?? "")) as Record<string, unknown>;
    if (parsed.kind !== "TOPOLOGY_EDIT" || typeof parsed.oldRelativeName !== "string" || typeof parsed.oldFqdn !== "string") return null;
    return {
      kind: "TOPOLOGY_EDIT",
      oldDnsAccountId: positiveInteger(parsed.oldDnsAccountId),
      oldZoneId: positiveInteger(parsed.oldZoneId),
      oldRelativeName: parsed.oldRelativeName,
      oldFqdn: parsed.oldFqdn,
    };
  } catch {
    return null;
  }
}

export async function isQuickConfigTopologyEditOperation(operation: Row): Promise<boolean> {
  return summary(operation) !== null;
}

function fence(operation: Row) {
  const owner = String(operation.executionOwnerId ?? "");
  if (!owner || Buffer.byteLength(owner, "utf8") > 128) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  return {
    operationId: positiveInteger(operation.id),
    quickConfigId: positiveInteger(operation.quickConfigId),
    owner,
    value: positiveInteger(operation.executionFence),
  };
}

async function assertFence(operation: Row) {
  const current = fence(operation);
  const q = quoteIdentifier;
  const [row] = await queryRaw<Row>(
    `SELECT o.${q("status")}, o.${q("executionLeaseUntil")}, qc.${q("currentOperationId")}
       FROM ${q("xray_quick_config_operations")} o JOIN ${q("xray_quick_configs")} qc ON qc.${q("id")} = o.${q("quickConfigId")}
      WHERE o.${q("id")} = ? AND o.${q("quickConfigId")} = ? AND o.${q("executionOwnerId")} = ? AND o.${q("executionFence")} = ? LIMIT 1`,
    [current.operationId, current.quickConfigId, current.owner, current.value],
  );
  if (!row || !["RUNNING", "COMPENSATING"].includes(String(row.status))
    || Number(row.currentOperationId) !== current.operationId || date(row.executionLeaseUntil).getTime() <= Date.now()) {
    fail("QUICK_CONFIG_OPERATION_CONFLICT");
  }
}

function fenceSql(operation: Row) {
  const current = fence(operation);
  const q = quoteIdentifier;
  return {
    sql: `EXISTS (SELECT 1 FROM ${q("xray_quick_config_operations")} owned
      JOIN ${q("xray_quick_configs")} owned_qc ON owned_qc.${q("id")} = owned.${q("quickConfigId")}
      WHERE owned.${q("id")} = ? AND owned.${q("quickConfigId")} = ? AND owned.${q("executionOwnerId")} = ?
        AND owned.${q("executionFence")} = ? AND owned.${q("status")} IN ('RUNNING','COMPENSATING')
        AND owned_qc.${q("currentOperationId")} = owned.${q("id")})`,
    params: [current.operationId, current.quickConfigId, current.owner, current.value],
  };
}

async function setPhase(operation: Row, phase: string, status?: "RUNNING" | "COMPENSATING") {
  const current = fence(operation);
  const changed = await executeRaw(
    `UPDATE ${quoteIdentifier("xray_quick_config_operations")} SET ${quoteIdentifier("phase")} = ?,
        ${quoteIdentifier("status")} = COALESCE(?, ${quoteIdentifier("status")}),
        ${quoteIdentifier("revision")} = ${quoteIdentifier("revision")} + 1, ${quoteIdentifier("updatedAt")} = ?
      WHERE ${quoteIdentifier("id")} = ? AND ${quoteIdentifier("executionOwnerId")} = ? AND ${quoteIdentifier("executionFence")} = ?`,
    [phase, status ?? null, nowDate(), current.operationId, current.owner, current.value],
  );
  if (rawAffectedRows(changed) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
}

async function finishOperation(operation: Row, status: "SUCCESS" | "FAILED" | "PARTIAL_FAILURE", errorCode: string | null, restoreOld: boolean) {
  const current = fence(operation);
  const parsed = summary(operation);
  if (!parsed) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  const q = quoteIdentifier;
  const now = nowDate();
  await withDatabaseTransaction(async () => {
    await assertFence(operation);
    if (restoreOld) {
      await executeRaw(
        `UPDATE ${q("xray_quick_configs")} SET ${q("dnsAccountId")} = ?, ${q("zoneId")} = ?, ${q("relativeName")} = ?, ${q("fqdn")} = ?
          WHERE ${q("id")} = ? AND ${q("currentOperationId")} = ?`,
        [parsed.oldDnsAccountId, parsed.oldZoneId, parsed.oldRelativeName, parsed.oldFqdn, current.quickConfigId, current.operationId],
      );
      if (status === "FAILED") {
        const [oldIdentity] = await queryRaw<Row>(
          `SELECT a.${q("accountTag")}, z.${q("providerZoneId")}
             FROM ${q("dns_provider_accounts")} a JOIN ${q("dns_provider_zones")} z ON z.${q("accountId")} = a.${q("id")}
            WHERE a.${q("id")} = ? AND z.${q("id")} = ? LIMIT 1`,
          [parsed.oldDnsAccountId, parsed.oldZoneId],
        );
        if (!oldIdentity) fail("QUICK_CONFIG_OPERATION_CONFLICT");
        const claimChanged = await executeRaw(
          `UPDATE ${q("xray_quick_config_domain_claims")} SET ${q("claimKey")} = ?, ${q("dnsAccountId")} = ?, ${q("zoneId")} = ?,
              ${q("normalizedRelativeName")} = ?, ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ?
            WHERE ${q("quickConfigId")} = ?`,
          [domainClaimKey(String(oldIdentity.accountTag), String(oldIdentity.providerZoneId), parsed.oldFqdn),
            parsed.oldDnsAccountId, parsed.oldZoneId, parsed.oldRelativeName, now, current.quickConfigId],
        );
        if (rawAffectedRows(claimChanged) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
      }
    }
    const configChanged = await executeRaw(
      `UPDATE ${q("xray_quick_configs")} SET ${q("state")} = ?,
          ${q("desiredTopologyRevisionId")} = ${status === "PARTIAL_FAILURE" ? q("desiredTopologyRevisionId") : "NULL"},
          ${q("currentOperationId")} = NULL, ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("currentOperationId")} = ?`,
      [status === "SUCCESS" || restoreOld && status === "FAILED" ? "ACTIVE" : "PARTIAL_FAILURE", now, current.quickConfigId, current.operationId],
    );
    if (rawAffectedRows(configChanged) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    const operationChanged = await executeRaw(
      `UPDATE ${q("xray_quick_config_operations")} SET ${q("status")} = ?, ${q("phase")} = 'COMPLETED', ${q("activeSlot")} = NULL,
          ${q("revision")} = ${q("revision")} + 1, ${q("errorCode")} = ?, ${q("errorMessage")} = NULL,
          ${q("executionOwnerId")} = NULL, ${q("executionLeaseUntil")} = NULL, ${q("finishedAt")} = ?, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("executionOwnerId")} = ? AND ${q("executionFence")} = ?`,
      [status, errorCode, now, now, current.operationId, current.owner, current.value],
    );
    if (rawAffectedRows(operationChanged) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  });
}

async function restoreOldDnsRows(operation: Row, complete: boolean) {
  const current = fence(operation);
  const q = quoteIdentifier;
  const fromId = positiveInteger(operation.fromTopologyRevisionId);
  const toId = positiveInteger(operation.toTopologyRevisionId);
  const now = nowDate();
  await withDatabaseTransaction(async () => {
    const owned = fenceSql(operation);
    const oldRows = await queryRaw<Row>(
      `SELECT dr.${q("id")}, dr.${q("providerRecordId")}, dr.${q("remoteTupleHash")}
         FROM ${q("xray_quick_config_dns_records")} dr
         JOIN ${q("xray_quick_config_routes")} r ON r.${q("id")} = dr.${q("routeId")}
        WHERE dr.${q("quickConfigId")} = ? AND r.${q("topologyRevisionId")} = ? ORDER BY dr.${q("id")} ASC`,
      [current.quickConfigId, fromId],
    );
    const backups = await queryRaw<Row>(
      `SELECT ${q("providerRecordId")}, ${q("remoteTupleHash")} FROM ${q("xray_quick_config_dns_record_backups")}
        WHERE ${q("operationId")} = ? AND ${q("state")} = 'RESTORED'
        ORDER BY ${q("snapshotOrder")} ASC, ${q("id")} ASC`,
      [current.operationId],
    );
    const available = new Map<string, string[]>();
    for (const backup of backups) {
      const hash = String(backup.remoteTupleHash ?? "");
      const providerRecordId = String(backup.providerRecordId ?? "");
      if (!hash || !providerRecordId) continue;
      const values = available.get(hash) ?? [];
      values.push(providerRecordId);
      available.set(hash, values);
    }
    for (const row of oldRows) {
      if (row.providerRecordId !== null && row.providerRecordId !== undefined) continue;
      const values = available.get(String(row.remoteTupleHash ?? ""));
      const providerRecordId = values?.shift();
      if (!providerRecordId) continue;
      // A restored provider id can only move after its desired row releases
      // the schema-level unique ownership. In partial compensation we touch
      // only ids proven RESTORED and leave unresolved rows UNKNOWN.
      await executeRaw(
        `UPDATE ${q("xray_quick_config_dns_records")} SET ${q("providerRecordId")} = NULL, ${q("status")} = 'REMOVED', ${q("updatedAt")} = ?
          WHERE ${q("quickConfigId")} = ? AND ${q("providerRecordId")} = ? AND ${q("routeId")} IN
            (SELECT ${q("id")} FROM ${q("xray_quick_config_routes")} WHERE ${q("topologyRevisionId")} = ?) AND ${owned.sql}`,
        [now, current.quickConfigId, providerRecordId, toId, ...owned.params],
      );
      const restored = await executeRaw(
        `UPDATE ${q("xray_quick_config_dns_records")} SET ${q("providerRecordId")} = ?, ${q("status")} = 'APPLIED', ${q("updatedAt")} = ?
          WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${owned.sql}`,
        [providerRecordId, now, positiveInteger(row.id), current.quickConfigId, ...owned.params],
      );
      if (rawAffectedRows(restored) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    }
    if (complete) {
      await executeRaw(
        `UPDATE ${q("xray_quick_config_dns_records")} SET ${q("providerRecordId")} = NULL, ${q("status")} = 'REMOVED', ${q("updatedAt")} = ?
          WHERE ${q("quickConfigId")} = ? AND ${q("routeId")} IN
            (SELECT ${q("id")} FROM ${q("xray_quick_config_routes")} WHERE ${q("topologyRevisionId")} = ?) AND ${owned.sql}`,
        [now, current.quickConfigId, toId, ...owned.params],
      );
    }
  });
}

async function releaseAllocationReferences(
  operation: Row,
  allocationId: number,
  keepRuleIds: ReadonlySet<number>,
  preserveTopologyRevisionId: number | null = positiveInteger(operation.toTopologyRevisionId),
) {
  const current = fence(operation);
  const q = quoteIdentifier;
  const [config] = await queryRaw<Row>(`SELECT ${q("configTag")} FROM ${q("xray_quick_configs")} WHERE ${q("id")} = ? LIMIT 1`, [current.quickConfigId]);
  const rows = await queryRaw<Row>(
    `SELECT ${q("resourceType")}, ${q("resourceId")}, ${q("hostId")}, ${q("network")}, ${q("role")}, ${q("isOwning")}
       FROM ${q("global_port_allocation_references")} WHERE ${q("allocationId")} = ? AND ${q("ownerGroupTag")} = ? ORDER BY ${q("id")} ASC`,
    [allocationId, String(config?.configTag ?? "")],
  );
  const [preservedTopology] = preserveTopologyRevisionId === null ? [] : await queryRaw<Row>(
    `SELECT ${q("portAllocationId")} FROM ${q("xray_quick_config_topology_revisions")} WHERE ${q("id")} = ? LIMIT 1`,
    [preserveTopologyRevisionId],
  );
  const sameAllocation = preserveTopologyRevisionId !== null && allocationId === Number(preservedTopology?.portAllocationId);
  const desiredHosts = sameAllocation ? new Set((await queryRaw<Row>(
    `SELECT DISTINCT fr.${q("hostId")} FROM ${q("xray_quick_config_rule_bindings")} b
       JOIN ${q("forward_rules")} fr ON fr.${q("id")} = b.${q("forwardRuleId")}
      WHERE b.${q("quickConfigId")} = ? AND b.${q("topologyRevisionId")} = ? AND b.${q("state")} = 'READY'`,
    [current.quickConfigId, preserveTopologyRevisionId],
  )).map((row) => positiveInteger(row.hostId))) : new Set<number>();
  for (const row of rows) {
    if (row.resourceType === "FORWARD_RULE" && keepRuleIds.has(Number(row.resourceId))) continue;
    if (sameAllocation && row.resourceType === "QUICK_CONFIG"
      && (row.role === "OWNERSHIP" || row.role === "TARGET"
        || row.role === "PUBLIC_LISTENER" && row.hostId !== null && desiredHosts.has(Number(row.hostId)))) continue;
    await assertFence(operation);
    await releaseGlobalPortReferenceAfterRuntimeCleanup({ reference: rowReference(row) });
  }
}

async function beginCompensation(operation: Row, errorCode: string) {
  const current = fence(operation);
  const q = quoteIdentifier;
  await setPhase(operation, "REMOVING_NEW_RULES", "COMPENSATING");
  await executeRaw(
    `UPDATE ${q("xray_quick_configs")} SET ${q("state")} = 'COMPENSATING', ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("currentOperationId")} = ?`,
    [nowDate(), current.quickConfigId, current.operationId],
  );
  await executeRaw(
    `UPDATE ${q("xray_quick_config_operations")} SET ${q("errorCode")} = ? WHERE ${q("id")} = ? AND ${q("executionOwnerId")} = ? AND ${q("executionFence")} = ?`,
    [errorCode, current.operationId, current.owner, current.value],
  );
}

async function processCompensation(operation: Row) {
  const current = fence(operation);
  const q = quoteIdentifier;
  const toId = positiveInteger(operation.toTopologyRevisionId);
  const fromId = positiveInteger(operation.fromTopologyRevisionId);
  const rules = await queryRaw<Row>(
    `SELECT fr.${q("id")}, fr.${q("hostId")}, fr.${q("pendingDelete")}, fr.${q("isRunning")}
       FROM ${q("xray_quick_config_rule_bindings")} b JOIN ${q("forward_rules")} fr ON fr.${q("id")} = b.${q("forwardRuleId")}
      WHERE b.${q("quickConfigId")} = ? AND b.${q("topologyRevisionId")} = ?
        AND NOT EXISTS (SELECT 1 FROM ${q("xray_quick_config_rule_bindings")} oldb
          WHERE oldb.${q("topologyRevisionId")} = ? AND oldb.${q("forwardRuleId")} = b.${q("forwardRuleId")})`,
    [current.quickConfigId, toId, fromId],
  );
  for (const rule of rules) {
    if (!bool(rule.pendingDelete)) {
      await assertFence(operation);
      await markForwardRulePendingDelete(positiveInteger(rule.id));
      pushAgentRefresh(positiveInteger(rule.hostId), "xray-quick-config-edit-rollback", { urgent: true });
    }
  }
  let waiting = false;
  for (const rule of rules) {
    let [fresh] = await queryRaw<Row>(`SELECT ${q("id")}, ${q("pendingDelete")}, ${q("isRunning")} FROM ${q("forward_rules")} WHERE ${q("id")} = ? LIMIT 1`, [positiveInteger(rule.id)]);
    if (fresh && bool(fresh.pendingDelete) && !bool(fresh.isRunning)) {
      await assertFence(operation);
      await finalizeForwardRuleDelete(positiveInteger(rule.id));
      [fresh] = await queryRaw<Row>(`SELECT ${q("id")} FROM ${q("forward_rules")} WHERE ${q("id")} = ? LIMIT 1`, [positiveInteger(rule.id)]);
    }
    if (fresh) waiting = true;
  }
  if (waiting) {
    if (Date.now() - date(operation.createdAt).getTime() >= CLEANUP_TIMEOUT_MS) {
      await finishOperation(operation, "PARTIAL_FAILURE", "RULE_CLEANUP_TIMEOUT", true);
    }
    return;
  }
  await restoreOldDnsRows(operation, true);
  await executeRaw(`UPDATE ${q("xray_quick_config_rule_bindings")} SET ${q("state")} = 'REMOVED', ${q("updatedAt")} = ? WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ?`, [nowDate(), current.quickConfigId, toId]);
  await executeRaw(`UPDATE ${q("xray_quick_config_routes")} SET ${q("state")} = 'RETIRED', ${q("updatedAt")} = ? WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ?`, [nowDate(), current.quickConfigId, toId]);
  await executeRaw(`UPDATE ${q("xray_quick_config_topology_revisions")} SET ${q("state")} = 'ABANDONED', ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ?`, [nowDate(), toId, current.quickConfigId]);
  const [toTopology] = await queryRaw<Row>(`SELECT ${q("portAllocationId")} FROM ${q("xray_quick_config_topology_revisions")} WHERE ${q("id")} = ? LIMIT 1`, [toId]);
  const [fromTopology] = await queryRaw<Row>(`SELECT ${q("portAllocationId")} FROM ${q("xray_quick_config_topology_revisions")} WHERE ${q("id")} = ? LIMIT 1`, [fromId]);
  if (!toTopology || !fromTopology) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  if (Number(toTopology.portAllocationId) !== Number(fromTopology.portAllocationId)) {
    await releaseAllocationReferences(operation, positiveInteger(toTopology.portAllocationId), new Set(), null);
  } else {
    const oldRuleRows = await queryRaw<Row>(
      `SELECT ${q("forwardRuleId")} FROM ${q("xray_quick_config_rule_bindings")} WHERE ${q("topologyRevisionId")} = ?`,
      [fromId],
    );
    await releaseAllocationReferences(
      operation,
      positiveInteger(fromTopology.portAllocationId),
      new Set(oldRuleRows.map((row) => positiveInteger(row.forwardRuleId))),
      fromId,
    );
  }
  await finishOperation(operation, "FAILED", String(operation.errorCode || "RULE_APPLY_FAILED"), true);
}

async function oldDnsRecords(operation: Row) {
  const current = fence(operation);
  const q = quoteIdentifier;
  return queryRaw<Row>(
    `SELECT dr.${q("id")}, dr.${q("providerRecordId")}, dr.${q("fqdn")}, dr.${q("recordType")}, dr.${q("providerLineId")},
            dr.${q("value")}, dr.${q("ttl")}, dr.${q("remoteTupleHash")}, dr.${q("status")}
       FROM ${q("xray_quick_config_dns_records")} dr JOIN ${q("xray_quick_config_routes")} r ON r.${q("id")} = dr.${q("routeId")}
      WHERE dr.${q("quickConfigId")} = ? AND r.${q("topologyRevisionId")} = ? AND dr.${q("status")} <> 'REMOVED' ORDER BY dr.${q("id")} ASC`,
    [current.quickConfigId, positiveInteger(operation.fromTopologyRevisionId)],
  );
}

async function removeOldDns(operation: Row, parsed: OperationSummary) {
  const current = fence(operation);
  const credentials = await loadGlobalDnsProviderCredentials();
  if (credentials.accountId !== parsed.oldDnsAccountId) fail("DNS_RECORD_DRIFT");
  const q = quoteIdentifier;
  const [zoneRow] = await queryRaw<Row>(
    `SELECT ${q("providerZoneId")}, ${q("name")} FROM ${q("dns_provider_zones")} WHERE ${q("id")} = ? AND ${q("accountId")} = ? LIMIT 1`,
    [parsed.oldZoneId, parsed.oldDnsAccountId],
  );
  if (!zoneRow) fail("DNS_RECORD_DRIFT");
  const zone: DnsPodZone = { providerZoneId: String(zoneRow.providerZoneId), name: String(zoneRow.name), grade: "" };
  const client = new DnsPodProviderClient({ credentials });
  for (const record of await oldDnsRecords(operation)) {
    if (record.providerRecordId === null || record.providerRecordId === undefined) {
      await executeRaw(`UPDATE ${q("xray_quick_config_dns_records")} SET ${q("status")} = 'REMOVED', ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ?`, [nowDate(), positiveInteger(record.id), current.quickConfigId]);
      continue;
    }
    const providerId = String(record.providerRecordId);
    await assertFence(operation);
    const owned = fenceSql(operation);
    const intent = await executeRaw(
      `UPDATE ${q("xray_quick_config_dns_records")} SET ${q("status")} = 'DELETE_PENDING', ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("providerRecordId")} = ?
          AND ${q("status")} <> 'REMOVED' AND ${owned.sql}`,
      [nowDate(), positiveInteger(record.id), current.quickConfigId, providerId, ...owned.params],
    );
    if (rawAffectedRows(intent) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    let remote: DnsPodRecord | null = null;
    try { remote = await client.getRecord({ zone, providerRecordId: providerId }); }
    catch (error) {
      if (!(error instanceof DnsPodProviderError) || error.code !== "DNS_PROVIDER_RECORD_NOT_FOUND") throw error;
    }
    if (remote) {
      const expectedHash = computeXrayQuickConfigDnsTupleHash({
        fqdn: String(record.fqdn).toLowerCase(),
        recordType: String(record.recordType) as "A" | "AAAA",
        providerLineId: String(record.providerLineId),
        value: String(record.value),
        ttl: Number(record.ttl),
      });
      const remoteHash = computeXrayQuickConfigDnsTupleHash({
        fqdn: `${remote.subdomain.trim().toLowerCase()}.${zone.name.toLowerCase()}`,
        recordType: remote.recordType as "A" | "AAAA",
        providerLineId: remote.providerLineId,
        value: remote.value,
        ttl: remote.ttl,
      });
      if (record.remoteTupleHash !== expectedHash || remoteHash !== expectedHash) fail("DNS_RECORD_DRIFT");
      try { await client.deleteRecord({ zone, providerRecordId: providerId }); }
      catch (error) { if (!(error instanceof DnsPodProviderError) || !error.ambiguousWrite) throw error; }
      await assertFence(operation);
      try {
        const remained = await client.getRecord({ zone, providerRecordId: providerId });
        if (remained) fail("DNS_RECORD_DRIFT");
      } catch (error) {
        if (!(error instanceof DnsPodProviderError) || error.code !== "DNS_PROVIDER_RECORD_NOT_FOUND") throw error;
      }
    }
    await executeRaw(
      `UPDATE ${q("xray_quick_config_dns_records")} SET ${q("providerRecordId")} = NULL, ${q("status")} = 'REMOVED',
          ${q("lastVerifiedAt")} = ?, ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ? AND ${q("providerRecordId")} = ?`,
      [nowDate(), nowDate(), positiveInteger(record.id), current.quickConfigId, providerId],
    );
  }
}

async function activateNewTopology(operation: Row) {
  const current = fence(operation);
  const q = quoteIdentifier;
  const now = nowDate();
  const fromId = positiveInteger(operation.fromTopologyRevisionId);
  const toId = positiveInteger(operation.toTopologyRevisionId);
  await withDatabaseTransaction(async () => {
    await assertFence(operation);
    const desiredIdentities = await queryRaw<Row>(
      `SELECT DISTINCT dr.${q("dnsAccountId")}, dr.${q("zoneId")}, dr.${q("fqdn")}, z.${q("name")} AS ${q("zoneName")},
              a.${q("accountTag")}, z.${q("providerZoneId")}
         FROM ${q("xray_quick_config_dns_records")} dr
         JOIN ${q("xray_quick_config_routes")} r ON r.${q("id")} = dr.${q("routeId")}
         JOIN ${q("dns_provider_accounts")} a ON a.${q("id")} = dr.${q("dnsAccountId")}
         JOIN ${q("dns_provider_zones")} z ON z.${q("id")} = dr.${q("zoneId")} AND z.${q("accountId")} = dr.${q("dnsAccountId")}
        WHERE dr.${q("quickConfigId")} = ? AND r.${q("topologyRevisionId")} = ?`,
      [current.quickConfigId, toId],
    );
    if (desiredIdentities.length !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    const desired = desiredIdentities[0];
    const fqdn = String(desired.fqdn).toLowerCase();
    const zoneName = String(desired.zoneName).toLowerCase();
    if (!fqdn.endsWith(`.${zoneName}`)) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    const relativeName = fqdn.slice(0, -(zoneName.length + 1));
    const [claim] = await queryRaw<Row>(
      `SELECT ${q("claimKey")}, ${q("dnsAccountId")}, ${q("zoneId")}, ${q("normalizedRelativeName")}
         FROM ${q("xray_quick_config_domain_claims")} WHERE ${q("quickConfigId")} = ? LIMIT 1`,
      [current.quickConfigId],
    );
    if (!claim || claim.claimKey !== domainClaimKey(String(desired.accountTag), String(desired.providerZoneId), fqdn)
      || Number(claim.dnsAccountId) !== Number(desired.dnsAccountId) || Number(claim.zoneId) !== Number(desired.zoneId)
      || String(claim.normalizedRelativeName) !== relativeName) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    await executeRaw(`UPDATE ${q("xray_quick_config_topology_revisions")} SET ${q("state")} = 'RETIRING', ${q("activeSlot")} = NULL, ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ?`, [now, fromId, current.quickConfigId]);
    const applied = await executeRaw(`UPDATE ${q("xray_quick_config_topology_revisions")} SET ${q("state")} = 'APPLIED', ${q("activeSlot")} = 1, ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ?`, [now, toId, current.quickConfigId]);
    if (rawAffectedRows(applied) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    await executeRaw(`UPDATE ${q("xray_quick_config_routes")} SET ${q("state")} = 'RETIRING', ${q("updatedAt")} = ? WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ?`, [now, current.quickConfigId, fromId]);
    await executeRaw(`UPDATE ${q("xray_quick_config_routes")} SET ${q("state")} = 'APPLIED', ${q("updatedAt")} = ? WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ?`, [now, current.quickConfigId, toId]);
    await executeRaw(`UPDATE ${q("xray_quick_config_rule_bindings")} SET ${q("state")} = 'RETIRING', ${q("updatedAt")} = ? WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ?`, [now, current.quickConfigId, fromId]);
    await executeRaw(`UPDATE ${q("xray_quick_config_rule_bindings")} SET ${q("state")} = 'READY', ${q("updatedAt")} = ? WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ?`, [now, current.quickConfigId, toId]);
    const configChanged = await executeRaw(
      `UPDATE ${q("xray_quick_configs")} SET ${q("dnsAccountId")} = ?, ${q("zoneId")} = ?, ${q("relativeName")} = ?,
          ${q("fqdn")} = ?, ${q("activeTopologyRevisionId")} = ?, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("currentOperationId")} = ?`,
      [positiveInteger(desired.dnsAccountId), positiveInteger(desired.zoneId), relativeName, fqdn,
        toId, now, current.quickConfigId, current.operationId],
    );
    if (rawAffectedRows(configChanged) !== 1) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  });
}

async function processOldRuleCleanup(operation: Row): Promise<boolean> {
  const current = fence(operation);
  const q = quoteIdentifier;
  const fromId = positiveInteger(operation.fromTopologyRevisionId);
  const toId = positiveInteger(operation.toTopologyRevisionId);
  const rules = await queryRaw<Row>(
    `SELECT fr.${q("id")}, fr.${q("hostId")}, fr.${q("pendingDelete")}, fr.${q("isRunning")}
       FROM ${q("xray_quick_config_rule_bindings")} oldb JOIN ${q("forward_rules")} fr ON fr.${q("id")} = oldb.${q("forwardRuleId")}
      WHERE oldb.${q("quickConfigId")} = ? AND oldb.${q("topologyRevisionId")} = ?
        AND NOT EXISTS (SELECT 1 FROM ${q("xray_quick_config_rule_bindings")} newb
          WHERE newb.${q("topologyRevisionId")} = ? AND newb.${q("forwardRuleId")} = oldb.${q("forwardRuleId")})`,
    [current.quickConfigId, fromId, toId],
  );
  let waiting = false;
  for (const rule of rules) {
    const ruleId = positiveInteger(rule.id);
    if (!bool(rule.pendingDelete)) {
      await assertFence(operation);
      await markForwardRulePendingDelete(ruleId);
      pushAgentRefresh(positiveInteger(rule.hostId), "xray-quick-config-edit-cleanup", { urgent: true });
    }
    let [fresh] = await queryRaw<Row>(`SELECT ${q("id")}, ${q("pendingDelete")}, ${q("isRunning")} FROM ${q("forward_rules")} WHERE ${q("id")} = ? LIMIT 1`, [ruleId]);
    if (fresh && bool(fresh.pendingDelete) && !bool(fresh.isRunning)) {
      await assertFence(operation);
      await finalizeForwardRuleDelete(ruleId);
      [fresh] = await queryRaw<Row>(`SELECT ${q("id")} FROM ${q("forward_rules")} WHERE ${q("id")} = ? LIMIT 1`, [ruleId]);
    }
    if (fresh) waiting = true;
  }
  return waiting;
}

async function finishSuccess(operation: Row) {
  const current = fence(operation);
  const q = quoteIdentifier;
  const fromId = positiveInteger(operation.fromTopologyRevisionId);
  const toId = positiveInteger(operation.toTopologyRevisionId);
  const [fromTopology] = await queryRaw<Row>(`SELECT ${q("portAllocationId")} FROM ${q("xray_quick_config_topology_revisions")} WHERE ${q("id")} = ? LIMIT 1`, [fromId]);
  const [toTopology] = await queryRaw<Row>(`SELECT ${q("portAllocationId")} FROM ${q("xray_quick_config_topology_revisions")} WHERE ${q("id")} = ? LIMIT 1`, [toId]);
  const keepRows = await queryRaw<Row>(`SELECT ${q("forwardRuleId")} FROM ${q("xray_quick_config_rule_bindings")} WHERE ${q("topologyRevisionId")} = ? AND ${q("state")} = 'READY'`, [toId]);
  const keep = new Set(keepRows.map((row) => positiveInteger(row.forwardRuleId)));
  if (!fromTopology || !toTopology) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  await releaseAllocationReferences(operation, positiveInteger(fromTopology.portAllocationId), keep);
  await assertFence(operation);
  const now = nowDate();
  await executeRaw(`UPDATE ${q("xray_quick_config_rule_bindings")} SET ${q("state")} = 'REMOVED', ${q("updatedAt")} = ? WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ?`, [now, current.quickConfigId, fromId]);
  await executeRaw(`UPDATE ${q("xray_quick_config_routes")} SET ${q("state")} = 'RETIRED', ${q("updatedAt")} = ? WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ?`, [now, current.quickConfigId, fromId]);
  await executeRaw(`UPDATE ${q("xray_quick_config_topology_revisions")} SET ${q("state")} = 'RETIRED', ${q("activeSlot")} = NULL, ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ?`, [now, fromId, current.quickConfigId]);
  await finishOperation(operation, "SUCCESS", null, false);
}

async function rootTopologyEditOperation(source: Row): Promise<{ root: Row; parsed: OperationSummary }> {
  let current = source;
  const seen = new Set<number>();
  for (let depth = 0; depth < 32; depth += 1) {
    const currentId = positiveInteger(current.id);
    if (seen.has(currentId)) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    seen.add(currentId);
    if (current.type === "EDIT") {
      const parsed = summary(current);
      if (!parsed) fail("QUICK_CONFIG_OPERATION_CONFLICT");
      return { root: current, parsed };
    }
    if (current.type !== "RETRY") fail("QUICK_CONFIG_OPERATION_CONFLICT");
    const retryOf = positiveInteger(current.retryOfOperationId);
    const [parent] = await queryRaw<Row>(
      `SELECT * FROM ${quoteIdentifier("xray_quick_config_operations")} WHERE ${quoteIdentifier("id")} = ? LIMIT 1`,
      [retryOf],
    );
    if (!parent || Number(parent.quickConfigId) !== Number(source.quickConfigId)) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    current = parent;
  }
  fail("QUICK_CONFIG_OPERATION_CONFLICT");
}

async function retryEvidenceOperationId(source: Row, root: Row): Promise<number> {
  let current = source;
  const q = quoteIdentifier;
  const seen = new Set<number>();
  for (let depth = 0; depth < 32; depth += 1) {
    const id = positiveInteger(current.id);
    if (seen.has(id)) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    seen.add(id);
    const [count] = await queryRaw<Row>(
      `SELECT COUNT(*) AS ${q("count")} FROM ${q("xray_quick_config_dns_record_backups")} WHERE ${q("operationId")} = ?`,
      [id],
    );
    if (Number(count?.count ?? 0) > 0) return id;
    if (id === Number(root.id)) return id;
    const retryOf = positiveInteger(current.retryOfOperationId);
    const [parent] = await queryRaw<Row>(
      `SELECT * FROM ${q("xray_quick_config_operations")} WHERE ${q("id")} = ? LIMIT 1`,
      [retryOf],
    );
    if (!parent) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    current = parent;
  }
  fail("QUICK_CONFIG_OPERATION_CONFLICT");
}

export async function retryQuickConfigTopologyEditOperation(input: {
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
    const { root, parsed } = await rootTopologyEditOperation(source);
    const quickConfigId = positiveInteger(root.quickConfigId, "QUICK_CONFIG_NOT_FOUND");
    const fromTopologyRevisionId = positiveInteger(root.fromTopologyRevisionId);
    const toTopologyRevisionId = positiveInteger(root.toTopologyRevisionId);
    if (Number(source.quickConfigId) !== quickConfigId
      || Number(source.fromTopologyRevisionId) !== fromTopologyRevisionId
      || Number(source.toTopologyRevisionId) !== toTopologyRevisionId) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    const [config] = await queryRaw<Row>(
      `SELECT ${q("revision")}, ${q("state")}, ${q("currentOperationId")}, ${q("activeTopologyRevisionId")},
              ${q("desiredTopologyRevisionId")}
         FROM ${q("xray_quick_configs")} WHERE ${q("id")} = ? LIMIT 1`,
      [quickConfigId],
    );
    if (!config) fail("QUICK_CONFIG_NOT_FOUND");
    if (config.state !== "PARTIAL_FAILURE" || config.currentOperationId !== null && config.currentOperationId !== undefined) {
      fail("QUICK_CONFIG_OPERATION_CONFLICT");
    }
    const activeTopologyRevisionId = positiveInteger(config.activeTopologyRevisionId);
    const beforeActivation = activeTopologyRevisionId === fromTopologyRevisionId;
    if (!beforeActivation && activeTopologyRevisionId !== toTopologyRevisionId) fail("QUICK_CONFIG_OPERATION_CONFLICT");
    const errorCode = String(source.errorCode ?? "");
    let phase: "RESTORING_DNS" | "REMOVING_NEW_RULES" | "DNS_REMOVING" | "RULES_REMOVING";
    if (beforeActivation) {
      // The durable active pointer proves that traffic never switched, but it
      // does not prove that the provider write had no side effects. Always run
      // exact compensation first; it is idempotent even when DNS was untouched.
      phase = "RESTORING_DNS";
    } else {
      const [oldDns] = await queryRaw<Row>(
        `SELECT dr.${q("id")} FROM ${q("xray_quick_config_dns_records")} dr
           JOIN ${q("xray_quick_config_routes")} r ON r.${q("id")} = dr.${q("routeId")}
          WHERE dr.${q("quickConfigId")} = ? AND r.${q("topologyRevisionId")} = ?
            AND dr.${q("status")} <> 'REMOVED' LIMIT 1`,
        [quickConfigId, fromTopologyRevisionId],
      );
      phase = oldDns ? "DNS_REMOVING" : "RULES_REMOVING";
    }
    const operationId = await insertAndGetId("xray_quick_config_operations", {
      operationTag,
      quickConfigId,
      type: "RETRY",
      status: "QUEUED",
      phase,
      activeSlot: 1,
      revision: 1,
      expectedRevision: positiveInteger(config.revision),
      fromTopologyRevisionId,
      toTopologyRevisionId,
      requestSummaryJson: stable(parsed),
      retryOfOperationId: sourceOperationId,
      executionOwnerId: null,
      executionLeaseUntil: null,
      executionFence: 1,
      errorCode: errorCode || null,
      errorMessage: null,
      createdByUserId: userId,
      startedAt: null,
      finishedAt: null,
      createdAt: now,
      updatedAt: now,
    });
    if (phase === "RESTORING_DNS") {
      const evidenceId = await retryEvidenceOperationId(source, root);
      const backups = await queryRaw<Row>(
        `SELECT ${q("dnsAccountId")}, ${q("zoneId")}, ${q("providerRecordId")}, ${q("fqdn")}, ${q("recordType")},
                ${q("providerLineId")}, ${q("value")}, ${q("ttl")}, ${q("remoteTupleHash")}, ${q("snapshotOrder")}
           FROM ${q("xray_quick_config_dns_record_backups")} WHERE ${q("operationId")} = ?
          ORDER BY ${q("snapshotOrder")} ASC, ${q("id")} ASC`,
        [evidenceId],
      );
      for (const backup of backups) {
        await insertAndGetId("xray_quick_config_dns_record_backups", {
          operationId,
          dnsAccountId: positiveInteger(backup.dnsAccountId),
          zoneId: positiveInteger(backup.zoneId),
          providerRecordId: String(backup.providerRecordId),
          fqdn: String(backup.fqdn),
          recordType: String(backup.recordType),
          providerLineId: String(backup.providerLineId),
          value: String(backup.value),
          ttl: positiveInteger(backup.ttl),
          remoteTupleHash: String(backup.remoteTupleHash),
          snapshotOrder: Number(backup.snapshotOrder),
          state: "CAPTURED",
          createdAt: now,
          updatedAt: now,
        });
      }
      const managedRows = await queryRaw<Row>(
        `SELECT dr.${q("id")}, dr.${q("providerRecordId")} FROM ${q("xray_quick_config_dns_records")} dr
           JOIN ${q("xray_quick_config_routes")} r ON r.${q("id")} = dr.${q("routeId")}
          WHERE dr.${q("quickConfigId")} = ? AND r.${q("topologyRevisionId")} = ?
            AND dr.${q("status")} IN ('DESIRED','APPLIED','UNKNOWN') ORDER BY dr.${q("id")} ASC`,
        [quickConfigId, toTopologyRevisionId],
      );
      const backupProviderIds = new Set(backups.map((backup) => String(backup.providerRecordId)));
      for (const record of managedRows) {
        const providerId = record.providerRecordId === null || record.providerRecordId === undefined
          ? null : String(record.providerRecordId);
        await insertStep({
          operationId,
          operationTag,
          key: `dns-compensate-${positiveInteger(record.id)}`,
          kind: providerId && backupProviderIds.has(providerId) ? "DNS_REPLACE" : "DNS_CREATE",
          subjectType: "DNS_RECORD",
          subjectId: String(positiveInteger(record.id)),
          status: "SUCCESS",
          now,
        });
      }
      const restoreSteps = managedRows.length + backups.length;
      for (let index = 0; index < restoreSteps; index += 1) {
        await insertStep({
          operationId,
          operationTag,
          key: `dns-restore-${index + 1}`,
          kind: "DNS_RESTORE",
          subjectType: "DNS_RECORD",
          subjectId: null,
          now,
        });
      }
    }
    const changed = await executeRaw(
      `UPDATE ${q("xray_quick_configs")} SET ${q("state")} = ?, ${q("desiredTopologyRevisionId")} = ?,
          ${q("currentOperationId")} = ?, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("revision")} = ? AND ${q("state")} = 'PARTIAL_FAILURE'
          AND ${q("currentOperationId")} IS NULL`,
      [beforeActivation ? "COMPENSATING" : "UPDATING", toTopologyRevisionId, operationId, now,
        quickConfigId, positiveInteger(config.revision)],
    );
    if (rawAffectedRows(changed) !== 1) fail("QUICK_CONFIG_REVISION_CONFLICT");
    await afterDatabaseCommit(() => {
      void import("./xrayQuickConfigOperationService")
        .then(({ kickQuickConfigOperationWorker }) => kickQuickConfigOperationWorker());
    });
    return { operationId, operationRevision: 1 as const };
  });
}

export async function processQuickConfigTopologyEditOperation(operation: Row): Promise<void> {
  const parsed = summary(operation);
  if (!parsed) fail("QUICK_CONFIG_OPERATION_CONFLICT");
  await assertFence(operation);
  if (operation.phase === "RESTORING_DNS") {
    const current = fence(operation);
    const { applyQuickConfigDnsOperation } = await import("./xrayQuickConfigDnsApplyService");
    const result = await applyQuickConfigDnsOperation(current.operationId, {
      executionOwnerId: current.owner,
      executionFence: current.value,
    });
    await assertFence(operation);
    if (result.status === "PARTIAL_FAILURE"
      || result.status !== "FAILED" || result.compensationComplete !== true) {
      await restoreOldDnsRows(operation, false);
      const errorCode = result.status === "SUCCESS" ? "DNS_COMPENSATION_FAILED" : result.errorCode;
      await finishOperation(operation, "PARTIAL_FAILURE", errorCode || "DNS_COMPENSATION_FAILED", true);
      return;
    }
    await beginCompensation(operation, String(operation.errorCode || "DNS_APPLY_FAILED"));
    await processCompensation(operation);
    return;
  }
  if (operation.status === "COMPENSATING" || operation.phase === "REMOVING_NEW_RULES") {
    await processCompensation(operation);
    return;
  }
  const current = fence(operation);
  const q = quoteIdentifier;
  const toId = positiveInteger(operation.toTopologyRevisionId);
  if (["RECHECKING_DOMAIN", "RESERVING_PORT", "CREATING_RULES", "WAITING_RULES_READY"].includes(String(operation.phase))) {
    const rules = await queryRaw<Row>(
      `SELECT fr.${q("id")}, fr.${q("isRunning")}, fr.${q("pendingDelete")}
         FROM ${q("xray_quick_config_rule_bindings")} b JOIN ${q("forward_rules")} fr ON fr.${q("id")} = b.${q("forwardRuleId")}
        WHERE b.${q("quickConfigId")} = ? AND b.${q("topologyRevisionId")} = ? AND b.${q("state")} <> 'REMOVED'`,
      [current.quickConfigId, toId],
    );
    const ready = rules.every((rule) => bool(rule.isRunning) && !bool(rule.pendingDelete));
    if (!ready) {
      if (Date.now() - date(operation.createdAt).getTime() < READY_TIMEOUT_MS) {
        await setPhase(operation, "WAITING_RULES_READY");
        return;
      }
      await beginCompensation(operation, "RULE_APPLY_FAILED");
      return;
    }
    await executeRaw(`UPDATE ${q("xray_quick_config_rule_bindings")} SET ${q("state")} = 'READY', ${q("updatedAt")} = ? WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ?`, [nowDate(), current.quickConfigId, toId]);
    await executeRaw(`UPDATE ${q("xray_quick_config_operation_steps")} SET ${q("status")} = 'SUCCESS', ${q("attemptCount")} = ${q("attemptCount")} + 1, ${q("resultSummaryJson")} = '{}', ${q("finishedAt")} = ?, ${q("updatedAt")} = ? WHERE ${q("operationId")} = ? AND ${q("kind")} = 'RULE_VERIFY' AND ${q("status")} <> 'SUCCESS'`, [nowDate(), nowDate(), current.operationId]);
    await setPhase(operation, "APPLYING_DNS");
  }
  const [dnsPhase] = await queryRaw<Row>(
    `SELECT o.${q("phase")}, qc.${q("activeTopologyRevisionId")}, t.${q("state")} AS ${q("toTopologyState")}
       FROM ${q("xray_quick_config_operations")} o
       JOIN ${q("xray_quick_configs")} qc ON qc.${q("id")} = o.${q("quickConfigId")}
       JOIN ${q("xray_quick_config_topology_revisions")} t ON t.${q("id")} = o.${q("toTopologyRevisionId")}
      WHERE o.${q("id")} = ? LIMIT 1`,
    [current.operationId],
  );
  if (dnsPhase && ["APPLYING_DNS", "VERIFYING_DNS"].includes(String(dnsPhase.phase))) {
    if (Number(dnsPhase.activeTopologyRevisionId) === toId && dnsPhase.toTopologyState === "APPLIED") {
      await setPhase(operation, "DNS_REMOVING");
    } else {
    const { applyQuickConfigDnsOperation } = await import("./xrayQuickConfigDnsApplyService");
    const result = await applyQuickConfigDnsOperation(current.operationId, { executionOwnerId: current.owner, executionFence: current.value });
    await assertFence(operation);
    if (result.status === "PARTIAL_FAILURE") {
      await restoreOldDnsRows(operation, false);
      await finishOperation(operation, "PARTIAL_FAILURE", result.errorCode || "DNS_COMPENSATION_FAILED", true);
      return;
    }
    if (result.status === "FAILED") {
      await beginCompensation(operation, result.errorCode || "DNS_APPLY_FAILED");
      return;
    }
    await activateNewTopology(operation);
    await setPhase(operation, "DNS_REMOVING");
    }
  }
  const [phaseRow] = await queryRaw<Row>(`SELECT ${q("phase")} FROM ${q("xray_quick_config_operations")} WHERE ${q("id")} = ? LIMIT 1`, [current.operationId]);
  if (phaseRow?.phase === "DNS_REMOVING") {
    try {
      await removeOldDns(operation, parsed);
    } catch {
      await finishOperation(operation, "PARTIAL_FAILURE", "DNS_RECORD_DRIFT", false);
      return;
    }
    await setPhase(operation, "RULES_REMOVING");
  }
  const [cleanupPhase] = await queryRaw<Row>(`SELECT ${q("phase")} FROM ${q("xray_quick_config_operations")} WHERE ${q("id")} = ? LIMIT 1`, [current.operationId]);
  if (cleanupPhase?.phase === "RULES_REMOVING") {
    const waiting = await processOldRuleCleanup(operation);
    if (waiting) {
      if (Date.now() - date(operation.createdAt).getTime() >= CLEANUP_TIMEOUT_MS) {
        await finishOperation(operation, "PARTIAL_FAILURE", "RULE_CLEANUP_TIMEOUT", false);
      }
      return;
    }
    await setPhase(operation, "PORT_RELEASING");
  }
  const [finalPhase] = await queryRaw<Row>(`SELECT ${q("phase")} FROM ${q("xray_quick_config_operations")} WHERE ${q("id")} = ? LIMIT 1`, [current.operationId]);
  if (finalPhase?.phase === "PORT_RELEASING") await finishSuccess(operation);
}
