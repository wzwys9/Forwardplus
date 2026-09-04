import { resolveStoredXrayInboundDefinition } from "../shared/xrayProfiles";
import { quoteIdentifier } from "./dbCompat";
import {
  executeRaw,
  insertAndGetId,
  nowDate,
  queryRaw,
  withDatabaseTransaction,
} from "./dbRuntime";

export type GlobalPortResourceType =
  | "XRAY_INBOUND"
  | "FORWARD_RULE"
  | "MANAGED_SERVICE"
  | "TUNNEL"
  | "TUNNEL_EXIT_NODE"
  | "TUNNEL_HOP"
  | "FORWARD_RULE_TUNNEL_EXIT"
  | "QUICK_CONFIG";

export type GlobalPortReferenceNetwork = "TCP" | "UDP" | "BOTH" | "NONE";
export type GlobalPortReferenceRole = "TARGET" | "PUBLIC_LISTENER" | "OWNERSHIP" | "MIMIC";
export type GlobalPortPrimaryOwnerType = "XRAY_INBOUND" | "FORWARD_RULE" | "MANAGED_SERVICE" | "TUNNEL" | "QUICK_CONFIG";
export type TaggedGlobalPortPrimaryOwnerType = "XRAY_INBOUND" | "MANAGED_SERVICE" | "QUICK_CONFIG";
export type NumericGlobalPortPrimaryOwnerType = "FORWARD_RULE" | "TUNNEL";

type Row = Record<string, unknown>;

type HistoricalListenerReference = {
  port: number;
  referenceKey: string;
  resourceType: GlobalPortResourceType;
  resourceId: number;
  ownerGroupTag: string;
  ownerType: GlobalPortPrimaryOwnerType;
  hostId: number;
  network: GlobalPortReferenceNetwork;
  role: GlobalPortReferenceRole;
  slot?: "PRIMARY" | "MAPPED";
};

type AllocationRow = Row & {
  id: unknown;
  port: unknown;
  status: unknown;
  primaryOwnerType: unknown;
  primaryOwnerTag: unknown;
};

type ReferenceRow = Row & {
  referenceKey: unknown;
  allocationId: unknown;
  resourceType: unknown;
  resourceId: unknown;
  ownerGroupTag: unknown;
  hostId: unknown;
  network: unknown;
  role: unknown;
  isOwning: unknown;
};

const RESOURCE_OWNER_PREFIX: Record<NumericGlobalPortPrimaryOwnerType, string> = {
  FORWARD_RULE: "forward-rule",
  TUNNEL: "tunnel",
};

function databaseBoolean(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || value === "true";
}

function positiveId(value: unknown, label: string): number {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) throw new Error(`GLOBAL_PORT_BACKFILL_INVALID_${label}`);
  return id;
}

function listenerPort(value: unknown, label: string): number {
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new Error(`GLOBAL_PORT_BACKFILL_INVALID_${label}_PORT`);
  }
  return port;
}

function optionalListenerPort(value: unknown, label: string): number | null {
  if (value === null || value === undefined || value === "" || Number(value) === 0) return null;
  return listenerPort(value, label);
}

function forwardRuleNetwork(value: unknown): GlobalPortReferenceNetwork {
  const protocol = String(value ?? "").trim().toLowerCase();
  if (protocol === "tcp") return "TCP";
  if (protocol === "udp") return "UDP";
  if (protocol === "both") return "BOTH";
  throw new Error("GLOBAL_PORT_BACKFILL_INVALID_FORWARD_RULE_PROTOCOL");
}

function tunnelNetwork(row: Row): "TCP" | "UDP" {
  return String(row.mode ?? "").trim().toLowerCase() === "forwardx"
    && String(row.forwardxVersion ?? "").trim().toLowerCase() === "v2"
    ? "UDP"
    : "TCP";
}

export function globalPortPrimaryOwnerTypeForResource(resourceType: unknown): GlobalPortPrimaryOwnerType | null {
  if (resourceType === "TUNNEL" || resourceType === "TUNNEL_EXIT_NODE" || resourceType === "TUNNEL_HOP") return "TUNNEL";
  if (resourceType === "FORWARD_RULE" || resourceType === "FORWARD_RULE_TUNNEL_EXIT") return "FORWARD_RULE";
  if (resourceType === "XRAY_INBOUND" || resourceType === "MANAGED_SERVICE" || resourceType === "QUICK_CONFIG") return resourceType;
  return null;
}

export function buildGlobalPortOwnerGroupTag(ownerType: NumericGlobalPortPrimaryOwnerType, stableIdentity: number): string;
export function buildGlobalPortOwnerGroupTag(ownerType: TaggedGlobalPortPrimaryOwnerType, stableIdentity: string): string;
export function buildGlobalPortOwnerGroupTag(
  ownerType: GlobalPortPrimaryOwnerType,
  stableIdentity: number | string,
): string {
  if (ownerType === "FORWARD_RULE" || ownerType === "TUNNEL") {
    return `${RESOURCE_OWNER_PREFIX[ownerType]}:${positiveId(stableIdentity, "OWNER")}`;
  }
  const tag = String(stableIdentity ?? "");
  if (!tag || tag.length > 128 || tag !== tag.trim() || !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(tag)) {
    throw new Error("GLOBAL_PORT_BACKFILL_INVALID_OWNER_TAG");
  }
  return tag;
}

export const globalPortOwnerGroupTag = buildGlobalPortOwnerGroupTag;

export function buildGlobalPortReferenceKey(input: {
  resourceType: GlobalPortResourceType;
  resourceId: number;
  hostId: number | null;
  network: GlobalPortReferenceNetwork;
  role: GlobalPortReferenceRole;
  slot?: "PRIMARY" | "MAPPED";
}): string {
  const base = [
    "global-port-ref",
    "v1",
    input.resourceType,
    positiveId(input.resourceId, "RESOURCE"),
    input.hostId === null ? "host-none" : `host-${positiveId(input.hostId, "HOST")}`,
    input.network,
    input.role,
  ].join(":");
  return input.slot ? `${base}:${input.slot}` : base;
}

export const globalPortReferenceKey = buildGlobalPortReferenceKey;

function appendReference(
  references: HistoricalListenerReference[],
  input: Omit<HistoricalListenerReference, "referenceKey"> & { slot?: "PRIMARY" | "MAPPED" },
) {
  references.push({
    ...input,
    referenceKey: globalPortReferenceKey(input),
  });
}

async function collectHistoricalListenerReferences(): Promise<HistoricalListenerReference[]> {
  const q = quoteIdentifier;
  const [inbounds, rules, managedServices, tunnels, exitNodes, hops, mappedExits] = await Promise.all([
    queryRaw<Row>(`SELECT ${[
      "id", "hostId", "runtimeTag", "listenPort", "protocol", "transport", "security", "profileId", "specVersion", "specJson",
      "isEnabled", "pendingDelete",
    ].map(q).join(", ")} FROM ${q("xray_inbounds")}`),
    queryRaw<Row>(`SELECT ${[
      "id", "hostId", "protocol", "tunnelId", "tunnelExitPort", "forwardGroupRuleId", "isForwardGroupTemplate",
      "sourcePort", "isEnabled", "pendingDelete", "xrayQuickConfigId",
    ].map(q).join(", ")} FROM ${q("forward_rules")}`),
    queryRaw<Row>(`SELECT ${[
      "id", "hostId", "serviceTag", "kind", "listenPort", "isEnabled", "pendingDelete",
    ].map(q).join(", ")} FROM ${q("xray_managed_services")}`),
    queryRaw<Row>(`SELECT ${[
      "id", "exitHostId", "mode", "forwardxVersion", "listenPort", "mimicPort", "isEnabled",
    ].map(q).join(", ")} FROM ${q("tunnels")}`),
    queryRaw<Row>(`SELECT ${[
      "id", "tunnelId", "hostId", "listenPort", "mimicPort", "isEnabled",
    ].map(q).join(", ")} FROM ${q("tunnel_exit_nodes")}`),
    queryRaw<Row>(`SELECT ${[
      "id", "tunnelId", "hostId", "listenPort", "mimicPort",
    ].map(q).join(", ")} FROM ${q("tunnel_hops")}`),
    queryRaw<Row>(`SELECT ${[
      "id", "ruleId", "tunnelId", "exitNodeId", "exitHostId", "tunnelExitPort",
    ].map(q).join(", ")} FROM ${q("forward_rule_tunnel_exits")}`),
  ]);

  const references: HistoricalListenerReference[] = [];
  // Port ownership follows the persisted resource lifetime, not its enabled
  // flag. Disabled resources and tombstones must retain their port until the
  // later delete/reclaim lifecycle removes the final reference.
  const tunnelById = new Map<number, Row>();
  for (const row of tunnels) {
    const id = positiveId(row.id, "TUNNEL");
    tunnelById.set(id, row);
  }

  const ownedRuleById = new Map<number, Row>();
  for (const row of rules) {
    if (databaseBoolean(row.isForwardGroupTemplate) || row.xrayQuickConfigId !== null) continue;
    const id = positiveId(row.id, "FORWARD_RULE");
    const hostId = positiveId(row.hostId, "FORWARD_RULE_HOST");
    const ownerId = row.forwardGroupRuleId === null || row.forwardGroupRuleId === undefined
      ? id
      : positiveId(row.forwardGroupRuleId, "FORWARD_GROUP_RULE");
    const ownerGroupTag = globalPortOwnerGroupTag("FORWARD_RULE", ownerId);
    const network = forwardRuleNetwork(row.protocol);
    ownedRuleById.set(id, row);
    appendReference(references, {
      port: listenerPort(row.sourcePort, "FORWARD_RULE"),
      resourceType: "FORWARD_RULE",
      resourceId: id,
      ownerGroupTag,
      ownerType: "FORWARD_RULE",
      hostId,
      network,
      role: "PUBLIC_LISTENER",
    });

    const tunnelId = row.tunnelId === null || row.tunnelId === undefined ? null : positiveId(row.tunnelId, "RULE_TUNNEL");
    const primaryExitPort = optionalListenerPort(row.tunnelExitPort, "FORWARD_RULE_TUNNEL_EXIT");
    const tunnel = tunnelId ? tunnelById.get(tunnelId) : undefined;
    if (primaryExitPort && tunnel) {
      appendReference(references, {
        port: primaryExitPort,
        resourceType: "FORWARD_RULE",
        resourceId: id,
        ownerGroupTag,
        ownerType: "FORWARD_RULE",
        hostId: positiveId(tunnel.exitHostId, "TUNNEL_EXIT_HOST"),
        network,
        role: "PUBLIC_LISTENER",
        slot: "PRIMARY",
      });
    }
  }

  for (const row of inbounds) {
    const id = positiveId(row.id, "XRAY_INBOUND");
    const definition = resolveStoredXrayInboundDefinition({
      protocol: row.protocol,
      transport: row.transport,
      security: row.security,
      profileId: row.profileId,
      specVersion: row.specVersion,
      specJson: row.specJson,
    });
    if (!definition) throw new Error("GLOBAL_PORT_BACKFILL_INVALID_XRAY_PROFILE");
    const ownerGroupTag = globalPortOwnerGroupTag("XRAY_INBOUND", String(row.runtimeTag ?? ""));
    for (const network of definition.profile.listenerNetworks) {
      appendReference(references, {
        port: listenerPort(row.listenPort, "XRAY_INBOUND"),
        resourceType: "XRAY_INBOUND",
        resourceId: id,
        ownerGroupTag,
        ownerType: "XRAY_INBOUND",
        hostId: positiveId(row.hostId, "XRAY_INBOUND_HOST"),
        network,
        role: "PUBLIC_LISTENER",
      });
    }
  }

  for (const row of managedServices) {
    const id = positiveId(row.id, "MANAGED_SERVICE");
    const kind = String(row.kind ?? "");
    const network = kind === "MTPROTO_FAKE_TLS" ? "TCP" : kind === "AMNEZIAWG" ? "UDP" : null;
    if (!network) throw new Error("GLOBAL_PORT_BACKFILL_INVALID_MANAGED_SERVICE_KIND");
    appendReference(references, {
      port: listenerPort(row.listenPort, "MANAGED_SERVICE"),
      resourceType: "MANAGED_SERVICE",
      resourceId: id,
      ownerGroupTag: globalPortOwnerGroupTag("MANAGED_SERVICE", String(row.serviceTag ?? "")),
      ownerType: "MANAGED_SERVICE",
      hostId: positiveId(row.hostId, "MANAGED_SERVICE_HOST"),
      network,
      role: "PUBLIC_LISTENER",
    });
  }

  for (const [tunnelId, row] of tunnelById) {
    const ownerGroupTag = globalPortOwnerGroupTag("TUNNEL", tunnelId);
    appendReference(references, {
      port: listenerPort(row.listenPort, "TUNNEL"),
      resourceType: "TUNNEL",
      resourceId: tunnelId,
      ownerGroupTag,
      ownerType: "TUNNEL",
      hostId: positiveId(row.exitHostId, "TUNNEL_EXIT_HOST"),
      network: tunnelNetwork(row),
      role: "PUBLIC_LISTENER",
    });
    const mimicPort = optionalListenerPort(row.mimicPort, "TUNNEL_MIMIC");
    if (mimicPort) appendReference(references, {
      port: mimicPort,
      resourceType: "TUNNEL",
      resourceId: tunnelId,
      ownerGroupTag,
      ownerType: "TUNNEL",
      hostId: positiveId(row.exitHostId, "TUNNEL_EXIT_HOST"),
      network: "UDP",
      role: "MIMIC",
    });
  }

  for (const row of exitNodes) {
    const tunnelId = positiveId(row.tunnelId, "TUNNEL_EXIT_NODE_TUNNEL");
    const tunnel = tunnelById.get(tunnelId);
    if (!tunnel) continue;
    const id = positiveId(row.id, "TUNNEL_EXIT_NODE");
    const hostId = positiveId(row.hostId, "TUNNEL_EXIT_NODE_HOST");
    const ownerGroupTag = globalPortOwnerGroupTag("TUNNEL", tunnelId);
    appendReference(references, {
      port: listenerPort(row.listenPort, "TUNNEL_EXIT_NODE"),
      resourceType: "TUNNEL_EXIT_NODE",
      resourceId: id,
      ownerGroupTag,
      ownerType: "TUNNEL",
      hostId,
      network: tunnelNetwork(tunnel),
      role: "PUBLIC_LISTENER",
    });
    const mimicPort = optionalListenerPort(row.mimicPort, "TUNNEL_EXIT_NODE_MIMIC");
    if (mimicPort) appendReference(references, {
      port: mimicPort,
      resourceType: "TUNNEL_EXIT_NODE",
      resourceId: id,
      ownerGroupTag,
      ownerType: "TUNNEL",
      hostId,
      network: "UDP",
      role: "MIMIC",
    });
  }

  for (const row of hops) {
    const tunnelId = positiveId(row.tunnelId, "TUNNEL_HOP_TUNNEL");
    const tunnel = tunnelById.get(tunnelId);
    if (!tunnel) continue;
    const id = positiveId(row.id, "TUNNEL_HOP");
    const hostId = positiveId(row.hostId, "TUNNEL_HOP_HOST");
    const ownerGroupTag = globalPortOwnerGroupTag("TUNNEL", tunnelId);
    const listenPort = optionalListenerPort(row.listenPort, "TUNNEL_HOP");
    if (listenPort) appendReference(references, {
      port: listenPort,
      resourceType: "TUNNEL_HOP",
      resourceId: id,
      ownerGroupTag,
      ownerType: "TUNNEL",
      hostId,
      network: tunnelNetwork(tunnel),
      role: "PUBLIC_LISTENER",
    });
    const mimicPort = optionalListenerPort(row.mimicPort, "TUNNEL_HOP_MIMIC");
    if (mimicPort) appendReference(references, {
      port: mimicPort,
      resourceType: "TUNNEL_HOP",
      resourceId: id,
      ownerGroupTag,
      ownerType: "TUNNEL",
      hostId,
      network: "UDP",
      role: "MIMIC",
    });
  }

  for (const row of mappedExits) {
    const ruleId = positiveId(row.ruleId, "MAPPED_EXIT_RULE");
    const rule = ownedRuleById.get(ruleId);
    const tunnelId = positiveId(row.tunnelId, "MAPPED_EXIT_TUNNEL");
    if (!rule || !tunnelById.has(tunnelId)) continue;
    const ownerId = rule.forwardGroupRuleId === null || rule.forwardGroupRuleId === undefined
      ? ruleId
      : positiveId(rule.forwardGroupRuleId, "MAPPED_EXIT_FORWARD_GROUP_RULE");
    appendReference(references, {
      port: listenerPort(row.tunnelExitPort, "MAPPED_EXIT"),
      resourceType: "FORWARD_RULE_TUNNEL_EXIT",
      resourceId: positiveId(row.id, "MAPPED_EXIT"),
      ownerGroupTag: globalPortOwnerGroupTag("FORWARD_RULE", ownerId),
      ownerType: "FORWARD_RULE",
      hostId: positiveId(row.exitHostId, "MAPPED_EXIT_HOST"),
      network: forwardRuleNetwork(rule.protocol),
      role: "PUBLIC_LISTENER",
      slot: "MAPPED",
    });
  }

  const unique = new Map<string, HistoricalListenerReference>();
  for (const reference of references) {
    const existing = unique.get(reference.referenceKey);
    if (existing && JSON.stringify(existing) !== JSON.stringify(reference)) {
      throw new Error("GLOBAL_PORT_BACKFILL_REFERENCE_COLLISION");
    }
    unique.set(reference.referenceKey, reference);
  }
  return Array.from(unique.values()).sort((left, right) => (
    left.port - right.port || (left.referenceKey < right.referenceKey ? -1 : left.referenceKey > right.referenceKey ? 1 : 0)
  ));
}

function allocationOwner(ownerTypes: ReadonlyMap<string, GlobalPortPrimaryOwnerType>) {
  const owners = Array.from(ownerTypes.entries());
  return owners.length === 1
    ? { status: "ACTIVE" as const, primaryOwnerType: owners[0][1], primaryOwnerTag: owners[0][0] }
    : { status: "LEGACY_CONFLICT" as const, primaryOwnerType: null, primaryOwnerTag: null };
}

function sameReference(row: ReferenceRow, expected: HistoricalListenerReference, allocationId: number) {
  return Number(row.allocationId) === allocationId
    && String(row.resourceType) === expected.resourceType
    && Number(row.resourceId) === expected.resourceId
    && String(row.ownerGroupTag) === expected.ownerGroupTag
    && Number(row.hostId) === expected.hostId
    && String(row.network) === expected.network
    && String(row.role) === expected.role
    && databaseBoolean(row.isOwning);
}

function stagedReferenceKeyForDesired(expected: HistoricalListenerReference) {
  const tunnelDerived = expected.resourceType === "TUNNEL"
    || expected.resourceType === "TUNNEL_EXIT_NODE"
    || expected.resourceType === "TUNNEL_HOP";
  const slot = tunnelDerived
    ? expected.role === "MIMIC" ? "MAPPED" as const : "PRIMARY" as const
    : expected.slot;
  return buildGlobalPortReferenceKey({
    ...expected,
    role: "OWNERSHIP",
    ...(slot ? { slot } : {}),
  });
}

function sameStagedReference(row: ReferenceRow, expected: HistoricalListenerReference, allocationId: number) {
  return String(row.referenceKey) === stagedReferenceKeyForDesired(expected)
    && Number(row.allocationId) === allocationId
    && String(row.resourceType) === expected.resourceType
    && Number(row.resourceId) === expected.resourceId
    && String(row.ownerGroupTag) === expected.ownerGroupTag
    && Number(row.hostId) === expected.hostId
    && String(row.network) === expected.network
    && String(row.role) === "OWNERSHIP"
    && databaseBoolean(row.isOwning);
}

export async function backfillGlobalPortAllocations(): Promise<{
  allocationsCreated: number;
  referencesCreated: number;
  allocationsUpdated: number;
}> {
  return withDatabaseTransaction(async () => {
    const q = quoteIdentifier;
    // The fixed reclaim row doubles as a cross-process serialization point for
    // schema-time backfill. SQLite is already protected by BEGIN IMMEDIATE;
    // MySQL and PostgreSQL hold this UPDATE row lock until commit.
    await executeRaw(
      `UPDATE ${q("global_port_scan_leases")} SET ${q("updatedAt")} = ${q("updatedAt")}
        WHERE ${q("scopeKey")} = ?`,
      ["GLOBAL_PORT_RECLAIM"],
    );
    const desired = await collectHistoricalListenerReferences();
    const desiredByPort = new Map<number, HistoricalListenerReference[]>();
    for (const reference of desired) {
      const rows = desiredByPort.get(reference.port) || [];
      rows.push(reference);
      desiredByPort.set(reference.port, rows);
    }

    const allocationRows = await queryRaw<AllocationRow>(
      `SELECT ${["id", "port", "status", "primaryOwnerType", "primaryOwnerTag"].map(q).join(", ")}
         FROM ${q("global_port_allocations")}`,
    );
    const allocationByPort = new Map<number, AllocationRow>(allocationRows.map((row) => [Number(row.port), row]));
    const referenceRows = await queryRaw<ReferenceRow>(
      `SELECT ${[
        "referenceKey", "allocationId", "resourceType", "resourceId", "ownerGroupTag", "hostId", "network", "role", "isOwning",
      ].map(q).join(", ")} FROM ${q("global_port_allocation_references")}`,
    );
    const referenceByKey = new Map(referenceRows.map((row) => [String(row.referenceKey), row]));
    const allocationById = new Map(allocationRows.map((row) => [Number(row.id), row]));
    const existingOwnersByAllocationId = new Map<number, Map<string, GlobalPortPrimaryOwnerType>>();
    const addExistingOwner = (allocationId: number, ownerGroupTag: string, ownerType: GlobalPortPrimaryOwnerType) => {
      const owners = existingOwnersByAllocationId.get(allocationId) || new Map<string, GlobalPortPrimaryOwnerType>();
      const existingType = owners.get(ownerGroupTag);
      if (existingType && existingType !== ownerType) throw new Error("GLOBAL_PORT_BACKFILL_OWNER_MISMATCH");
      owners.set(ownerGroupTag, ownerType);
      existingOwnersByAllocationId.set(allocationId, owners);
    };
    const ownerTypeHints = new Map<string, GlobalPortPrimaryOwnerType>();
    for (const allocation of allocationRows) {
      const ownerGroupTag = String(allocation.primaryOwnerTag ?? "");
      const ownerType = globalPortPrimaryOwnerTypeForResource(allocation.primaryOwnerType);
      if (ownerGroupTag && ownerType) ownerTypeHints.set(ownerGroupTag, ownerType);
    }
    for (const row of referenceRows) {
      const ownerGroupTag = String(row.ownerGroupTag ?? "");
      const ownerType = globalPortPrimaryOwnerTypeForResource(row.resourceType);
      if (!ownerGroupTag || !ownerType) continue;
      if (ownerType === "QUICK_CONFIG" || !ownerTypeHints.has(ownerGroupTag)) ownerTypeHints.set(ownerGroupTag, ownerType);
    }
    for (const row of referenceRows) {
      if (!databaseBoolean(row.isOwning)) continue;
      const allocationId = positiveId(row.allocationId, "REFERENCE_ALLOCATION");
      const allocation = allocationById.get(allocationId);
      if (!allocation) throw new Error("GLOBAL_PORT_BACKFILL_DANGLING_REFERENCE");
      const ownerGroupTag = String(row.ownerGroupTag ?? "");
      const ownerType = String(allocation.primaryOwnerTag ?? "") === ownerGroupTag
        ? globalPortPrimaryOwnerTypeForResource(allocation.primaryOwnerType)
        : ownerTypeHints.get(ownerGroupTag) ?? globalPortPrimaryOwnerTypeForResource(row.resourceType);
      if (!ownerGroupTag || !ownerType) throw new Error("GLOBAL_PORT_BACKFILL_INVALID_OWNER");
      addExistingOwner(allocationId, ownerGroupTag, ownerType);
    }
    for (const allocation of allocationRows) {
      const ownerGroupTag = String(allocation.primaryOwnerTag ?? "");
      const ownerType = globalPortPrimaryOwnerTypeForResource(allocation.primaryOwnerType);
      if (!!ownerGroupTag !== !!ownerType) throw new Error("GLOBAL_PORT_BACKFILL_INVALID_PRIMARY_OWNER");
      if (ownerGroupTag && ownerType) addExistingOwner(positiveId(allocation.id, "ALLOCATION"), ownerGroupTag, ownerType);
    }

    let allocationsCreated = 0;
    let referencesCreated = 0;
    let allocationsUpdated = 0;
    const now = nowDate();

    for (const [port, references] of Array.from(desiredByPort.entries()).sort((a, b) => a[0] - b[0])) {
      let allocation = allocationByPort.get(port);
      const ownerTypes = new Map<string, GlobalPortPrimaryOwnerType>(
        allocation ? existingOwnersByAllocationId.get(positiveId(allocation.id, "ALLOCATION")) : [],
      );
      for (const reference of references) {
        const existingType = ownerTypes.get(reference.ownerGroupTag);
        if (existingType && existingType !== reference.ownerType) throw new Error("GLOBAL_PORT_BACKFILL_OWNER_MISMATCH");
        ownerTypes.set(reference.ownerGroupTag, reference.ownerType);
      }
      const owner = allocationOwner(ownerTypes);
      let created = false;
      if (!allocation) {
        const id = await insertAndGetId("global_port_allocations", {
          allocationTag: `global-port:v1:${port}`,
          port,
          status: owner.status,
          primaryOwnerType: owner.primaryOwnerType,
          primaryOwnerTag: owner.primaryOwnerTag,
          reservationTokenHash: null,
          reservedUntil: null,
          scanNotBefore: null,
          lastScanStartedAt: null,
          lastScanFinishedAt: null,
          lastErrorCode: null,
          version: 1,
          createdAt: now,
          updatedAt: now,
        });
        allocation = { id, port, ...owner };
        allocationByPort.set(port, allocation);
        allocationsCreated += 1;
        created = true;
      }
      const allocationId = positiveId(allocation.id, "ALLOCATION");
      for (const reference of references) {
        const existing = referenceByKey.get(reference.referenceKey);
        if (existing) {
          if (!sameReference(existing, reference, allocationId)) {
            const staged = referenceByKey.get(stagedReferenceKeyForDesired(reference));
            if (!staged || !sameStagedReference(staged, reference, allocationId)) {
              throw new Error("GLOBAL_PORT_BACKFILL_REFERENCE_MISMATCH");
            }
          }
          continue;
        }
        const staged = referenceByKey.get(stagedReferenceKeyForDesired(reference));
        if (staged) {
          if (!sameStagedReference(staged, reference, allocationId)) {
            throw new Error("GLOBAL_PORT_BACKFILL_REFERENCE_MISMATCH");
          }
          continue;
        }
        await insertAndGetId("global_port_allocation_references", {
          referenceKey: reference.referenceKey,
          allocationId,
          resourceType: reference.resourceType,
          resourceId: reference.resourceId,
          ownerGroupTag: reference.ownerGroupTag,
          hostId: reference.hostId,
          network: reference.network,
          role: reference.role,
          isOwning: true,
          createdAt: now,
          updatedAt: now,
        });
        referencesCreated += 1;
      }

      if (created || (String(allocation.status) === owner.status
        && (allocation.primaryOwnerType ?? null) === owner.primaryOwnerType
        && (allocation.primaryOwnerTag ?? null) === owner.primaryOwnerTag)) continue;
      await executeRaw(
        `UPDATE ${q("global_port_allocations")}
            SET ${q("status")} = ?, ${q("primaryOwnerType")} = ?, ${q("primaryOwnerTag")} = ?,
                ${q("reservationTokenHash")} = NULL, ${q("reservedUntil")} = NULL,
                ${q("scanNotBefore")} = NULL, ${q("lastErrorCode")} = NULL,
                ${q("version")} = ${q("version")} + 1, ${q("updatedAt")} = ?
          WHERE ${q("id")} = ?`,
        [owner.status, owner.primaryOwnerType, owner.primaryOwnerTag, now, allocationId],
      );
      allocationsUpdated += 1;
    }
    return { allocationsCreated, referencesCreated, allocationsUpdated };
  });
}
