import { quoteIdentifier } from "./dbCompat";
import { queryRaw, withDatabaseTransaction } from "./dbRuntime";
import { buildGlobalPortReferenceKey, type GlobalPortReferenceNetwork, type GlobalPortReferenceRole, type GlobalPortResourceType } from "./globalPortBackfill";
import {
  acquireGlobalPortOwningReference,
  inspectGlobalPortReferenceAllocation,
  promoteOrphanedStagedGlobalPortOwningReference,
  promoteStagedGlobalPortOwningReference,
  releaseGlobalPortReferenceAfterRuntimeCleanup,
  type GlobalPortOwner,
  type GlobalPortReferenceInput,
} from "./globalPortAllocationService";

type Row = Record<string, unknown>;

type DesiredTunnelPortReference = Readonly<{
  port: number;
  owner: GlobalPortOwner;
  reference: GlobalPortReferenceInput;
}>;

export type ReportedTunnelListener = Readonly<{
  port: number;
  tunnelId: number;
  udpPort?: number;
}>;

export type ReportedTunnelRuleListener = Readonly<{
  port: number;
  ruleId: number;
}>;

function positiveInteger(value: unknown): number {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : 0;
}

function databaseBoolean(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || value === "true";
}

function listenerPort(value: unknown): number {
  const parsed = positiveInteger(value);
  return parsed <= 65_535 ? parsed : 0;
}

function ruleNetwork(value: unknown): GlobalPortReferenceNetwork {
  const protocol = String(value ?? "").trim().toLowerCase();
  if (protocol === "tcp") return "TCP";
  if (protocol === "udp") return "UDP";
  if (protocol === "both") return "BOTH";
  throw new Error("GLOBAL_PORT_INVALID");
}

function tunnelNetwork(row: Row): GlobalPortReferenceNetwork {
  return String(row.mode ?? "").trim().toLowerCase() === "forwardx"
    && String(row.forwardxVersion ?? "").trim().toLowerCase() === "v2"
    ? "UDP"
    : "TCP";
}

function tunnelOwner(tunnelId: number): GlobalPortOwner {
  return { type: "TUNNEL", stableIdentity: tunnelId };
}

function ruleOwner(rule: Row): GlobalPortOwner {
  return {
    type: "FORWARD_RULE",
    stableIdentity: positiveInteger(rule.forwardGroupRuleId) || positiveInteger(rule.id),
  };
}

function reference(input: Omit<GlobalPortReferenceInput, "isOwning">): GlobalPortReferenceInput {
  return { ...input, isOwning: true };
}

function appendDesired(
  output: DesiredTunnelPortReference[],
  portValue: unknown,
  owner: GlobalPortOwner,
  portReference: GlobalPortReferenceInput,
) {
  const port = listenerPort(portValue);
  if (port > 0) output.push({ port, owner, reference: portReference });
}

async function loadDesiredTunnelPortReferences(filter: { tunnelId?: number; hostId?: number } = {}) {
  const q = quoteIdentifier;
  const tunnelId = positiveInteger(filter.tunnelId);
  const hostId = positiveInteger(filter.hostId);
  const tunnelWhere = tunnelId > 0 ? ` WHERE ${q("id")} = ?` : hostId > 0 ? ` WHERE ${q("exitHostId")} = ?` : "";
  const childWhere = tunnelId > 0 ? ` WHERE ${q("tunnelId")} = ?` : hostId > 0 ? ` WHERE ${q("hostId")} = ?` : "";
  const relationWhere = tunnelId > 0
    ? ` WHERE r.${q("tunnelId")} = ?`
    : hostId > 0 ? ` WHERE t.${q("exitHostId")} = ?` : "";
  const mappedWhere = tunnelId > 0
    ? ` WHERE m.${q("tunnelId")} = ?`
    : hostId > 0 ? ` WHERE m.${q("exitHostId")} = ?` : "";
  const params = (value: number) => value > 0 ? [value] : [];
  const [tunnels, exitNodes, hops, rules, mappedExits] = await Promise.all([
    queryRaw<Row>(
      `SELECT ${["id", "exitHostId", "mode", "forwardxVersion", "listenPort", "mimicPort"].map(q).join(", ")}
         FROM ${q("tunnels")}${tunnelWhere}`,
      params(tunnelId || hostId),
    ),
    queryRaw<Row>(
      `SELECT ${["id", "tunnelId", "hostId", "listenPort", "mimicPort"].map(q).join(", ")}
         FROM ${q("tunnel_exit_nodes")}${childWhere}`,
      params(tunnelId || hostId),
    ),
    queryRaw<Row>(
      `SELECT ${["id", "tunnelId", "hostId", "listenPort", "mimicPort"].map(q).join(", ")}
         FROM ${q("tunnel_hops")}${childWhere}`,
      params(tunnelId || hostId),
    ),
    queryRaw<Row>(
      `SELECT r.${q("id")}, r.${q("protocol")}, r.${q("forwardGroupRuleId")}, r.${q("isForwardGroupTemplate")},
              r.${q("xrayQuickConfigId")}, r.${q("tunnelExitPort")}, t.${q("exitHostId")}
         FROM ${q("forward_rules")} r
         JOIN ${q("tunnels")} t ON t.${q("id")} = r.${q("tunnelId")}${relationWhere}`,
      params(tunnelId || hostId),
    ),
    queryRaw<Row>(
      `SELECT m.${q("id")}, m.${q("ruleId")}, m.${q("tunnelId")}, m.${q("exitHostId")}, m.${q("tunnelExitPort")},
              r.${q("protocol")}, r.${q("forwardGroupRuleId")}, r.${q("isForwardGroupTemplate")}, r.${q("xrayQuickConfigId")}
         FROM ${q("forward_rule_tunnel_exits")} m
         JOIN ${q("forward_rules")} r ON r.${q("id")} = m.${q("ruleId")}${mappedWhere}`,
      params(tunnelId || hostId),
    ),
  ]);

  const tunnelById = new Map<number, Row>();
  if (tunnelId > 0) {
    for (const row of tunnels) tunnelById.set(positiveInteger(row.id), row);
  } else {
    const relatedIds = Array.from(new Set([
      ...exitNodes.map((row) => positiveInteger(row.tunnelId)),
      ...hops.map((row) => positiveInteger(row.tunnelId)),
      ...mappedExits.map((row) => positiveInteger(row.tunnelId)),
    ].filter(Boolean)));
    const missingIds = relatedIds.filter((id) => !tunnelById.has(id));
    for (const row of tunnels) tunnelById.set(positiveInteger(row.id), row);
    if (missingIds.length > 0) {
      const placeholders = missingIds.map(() => "?").join(", ");
      const rows = await queryRaw<Row>(
        `SELECT ${["id", "exitHostId", "mode", "forwardxVersion", "listenPort", "mimicPort"].map(q).join(", ")}
           FROM ${q("tunnels")} WHERE ${q("id")} IN (${placeholders})`,
        missingIds,
      );
      for (const row of rows) tunnelById.set(positiveInteger(row.id), row);
    }
  }

  const output: DesiredTunnelPortReference[] = [];
  for (const row of tunnels) {
    const id = positiveInteger(row.id);
    const owner = tunnelOwner(id);
    const network = tunnelNetwork(row);
    const actualHostId = positiveInteger(row.exitHostId);
    appendDesired(output, row.listenPort, owner, reference({
      resourceType: "TUNNEL", resourceId: id, hostId: actualHostId, network, role: "PUBLIC_LISTENER",
    }));
    appendDesired(output, row.mimicPort, owner, reference({
      resourceType: "TUNNEL", resourceId: id, hostId: actualHostId, network: "UDP", role: "MIMIC",
    }));
  }
  for (const [resourceType, rows] of [["TUNNEL_EXIT_NODE", exitNodes], ["TUNNEL_HOP", hops]] as const) {
    for (const row of rows) {
      const id = positiveInteger(row.id);
      const owner = tunnelOwner(positiveInteger(row.tunnelId));
      const tunnel = tunnelById.get(positiveInteger(row.tunnelId));
      if (!tunnel) continue;
      const actualHostId = positiveInteger(row.hostId);
      appendDesired(output, row.listenPort, owner, reference({
        resourceType, resourceId: id, hostId: actualHostId, network: tunnelNetwork(tunnel), role: "PUBLIC_LISTENER",
      }));
      appendDesired(output, row.mimicPort, owner, reference({
        resourceType, resourceId: id, hostId: actualHostId, network: "UDP", role: "MIMIC",
      }));
    }
  }
  const ownedRule = (row: Row) => !databaseBoolean(row.isForwardGroupTemplate) && row.xrayQuickConfigId == null;
  for (const row of rules) {
    if (!ownedRule(row)) continue;
    appendDesired(output, row.tunnelExitPort, ruleOwner(row), reference({
      resourceType: "FORWARD_RULE", resourceId: positiveInteger(row.id), hostId: positiveInteger(row.exitHostId),
      network: ruleNetwork(row.protocol), role: "PUBLIC_LISTENER", slot: "PRIMARY",
    }));
  }
  for (const row of mappedExits) {
    if (!ownedRule(row)) continue;
    appendDesired(output, row.tunnelExitPort, ruleOwner({ ...row, id: row.ruleId }), reference({
      resourceType: "FORWARD_RULE_TUNNEL_EXIT", resourceId: positiveInteger(row.id), hostId: positiveInteger(row.exitHostId),
      network: ruleNetwork(row.protocol), role: "PUBLIC_LISTENER", slot: "MAPPED",
    }));
  }
  return output.filter((item) => item.reference.resourceId > 0 && (item.reference.hostId ?? 0) > 0);
}

function stagedReferenceFor(desired: GlobalPortReferenceInput): GlobalPortReferenceInput {
  return {
    ...desired,
    role: "OWNERSHIP",
    slot: desired.role === "MIMIC" ? "MAPPED" : desired.slot ?? "PRIMARY",
  };
}

/** Adds every currently persisted listener for a tunnel to the global ledger. */
export async function ensureTunnelDerivedGlobalPortReferences(tunnelIdValue: unknown) {
  const tunnelId = positiveInteger(tunnelIdValue);
  if (!tunnelId) throw new Error("GLOBAL_PORT_INVALID");
  return withDatabaseTransaction(async () => {
    const desired = await loadDesiredTunnelPortReferences({ tunnelId });
    for (const item of desired) {
      const current = await inspectGlobalPortReferenceAllocation(item.reference);
      if (current && current.port !== item.port) {
        await acquireGlobalPortOwningReference({
          port: item.port,
          owner: item.owner,
          reference: stagedReferenceFor(item.reference),
        });
        continue;
      }
      await acquireGlobalPortOwningReference(item);
    }
    return desired.length;
  });
}

function rowReference(row: Row): GlobalPortReferenceInput | null {
  const resourceType = String(row.resourceType) as GlobalPortResourceType;
  const network = String(row.network) as GlobalPortReferenceNetwork;
  const role = String(row.role) as GlobalPortReferenceRole;
  if (!["TUNNEL", "TUNNEL_EXIT_NODE", "TUNNEL_HOP", "FORWARD_RULE", "FORWARD_RULE_TUNNEL_EXIT"].includes(resourceType)
    || !["TCP", "UDP", "BOTH", "NONE"].includes(network)
    || !["PUBLIC_LISTENER", "MIMIC", "OWNERSHIP"].includes(role)) return null;
  const key = String(row.referenceKey ?? "");
  const slot = key.endsWith(":PRIMARY") ? "PRIMARY" as const : key.endsWith(":MAPPED") ? "MAPPED" as const : undefined;
  const result = reference({
    resourceType,
    resourceId: positiveInteger(row.resourceId),
    hostId: positiveInteger(row.hostId),
    network,
    role,
    ...(slot ? { slot } : {}),
  });
  return result.resourceId > 0 && (result.hostId ?? 0) > 0
    && buildGlobalPortReferenceKey(result) === key ? result : null;
}

function tunnelIdFromOwnerTag(value: unknown): number {
  const match = /^tunnel:([1-9][0-9]*)$/.exec(String(value ?? ""));
  return match ? positiveInteger(match[1]) : 0;
}

/**
 * Reconciles only after an Agent supplied a complete local runtime snapshot.
 * Cached/partial snapshots must never release a listener allocation.
 */
export async function reconcileTunnelGlobalPortsAfterRuntimeSnapshot(input: {
  hostId: number;
  completeSnapshot: boolean;
  tunnels: readonly ReportedTunnelListener[];
  rules: readonly ReportedTunnelRuleListener[];
}) {
  const hostId = positiveInteger(input.hostId);
  if (!hostId || !input.completeSnapshot) return { promoted: 0, released: 0 };
  const q = quoteIdentifier;
  const desired = await loadDesiredTunnelPortReferences({ hostId });
  const desiredByKey = new Map(desired.map((item) => [buildGlobalPortReferenceKey(item.reference), item]));
  const rows = await queryRaw<Row>(
    `SELECT r.${q("referenceKey")}, r.${q("resourceType")}, r.${q("resourceId")}, r.${q("ownerGroupTag")},
            r.${q("hostId")}, r.${q("network")}, r.${q("role")}, r.${q("isOwning")},
            a.${q("port")}, a.${q("status")}
       FROM ${q("global_port_allocation_references")} r
       JOIN ${q("global_port_allocations")} a ON a.${q("id")} = r.${q("allocationId")}
      WHERE r.${q("hostId")} = ?
        AND r.${q("resourceType")} IN ('TUNNEL','TUNNEL_EXIT_NODE','TUNNEL_HOP','FORWARD_RULE','FORWARD_RULE_TUNNEL_EXIT')`,
    [hostId],
  );
  const runtimePorts = new Set([
    ...input.tunnels.map((item) => listenerPort(item.port)),
    ...input.rules.map((item) => listenerPort(item.port)),
  ].filter(Boolean));
  const reportedUdpPorts = new Set(input.tunnels.map((item) => listenerPort(item.udpPort)).filter(Boolean));
  const reportedTunnelIds = new Set(input.tunnels.map((item) => positiveInteger(item.tunnelId)).filter(Boolean));
  let promoted = 0;
  let released = 0;

  for (const row of rows) {
    if (String(row.role) !== "OWNERSHIP" || String(row.status) !== "ACTIVE") continue;
    const staged = rowReference(row);
    if (!staged || !staged.slot) continue;
    const targetRole = staged.slot === "MAPPED" && String(row.resourceType) !== "FORWARD_RULE_TUNNEL_EXIT"
      ? "MIMIC" as const
      : "PUBLIC_LISTENER" as const;
    const { slot: _stagedSlot, ...stagedIdentity } = staged;
    const keepsSlot = staged.resourceType === "FORWARD_RULE" || staged.resourceType === "FORWARD_RULE_TUNNEL_EXIT";
    const targetReference: GlobalPortReferenceInput = {
      ...stagedIdentity,
      role: targetRole,
      ...(keepsSlot ? { slot: staged.slot } : {}),
    };
    const target = desiredByKey.get(buildGlobalPortReferenceKey(targetReference));
    const nextPort = listenerPort(row.port);
    if (!target || target.port !== nextPort) {
      const ownerTunnelId = tunnelIdFromOwnerTag(row.ownerGroupTag);
      const unknownMimicState = targetRole === "MIMIC" && ownerTunnelId > 0
        && reportedTunnelIds.has(ownerTunnelId)
        && !input.tunnels.some((item) => positiveInteger(item.tunnelId) === ownerTunnelId && item.udpPort !== undefined);
      const stillRunning = targetRole === "MIMIC" ? reportedUdpPorts.has(nextPort) : runtimePorts.has(nextPort);
      if (!unknownMimicState && !stillRunning) {
        await releaseGlobalPortReferenceAfterRuntimeCleanup({ reference: staged });
        released += 1;
      }
      continue;
    }
    const previous = await inspectGlobalPortReferenceAllocation(targetReference);
    if (previous?.port === nextPort) continue;
    const newPresent = targetRole === "MIMIC" ? reportedUdpPorts.has(nextPort) : runtimePorts.has(nextPort);
    if (!newPresent) continue;
    if (!previous) {
      await promoteOrphanedStagedGlobalPortOwningReference({
        owner: target.owner,
        nextPublicReference: targetReference,
        stagedReference: staged,
      });
      promoted += 1;
      continue;
    }
    const oldAbsent = targetRole === "MIMIC" ? !reportedUdpPorts.has(previous.port) : !runtimePorts.has(previous.port);
    if (!oldAbsent) continue;
    await promoteStagedGlobalPortOwningReference({
      owner: target.owner,
      publicReference: targetReference,
      nextPublicReference: targetReference,
      stagedReference: staged,
    });
    promoted += 1;
  }

  for (const row of rows) {
    if ((String(row.role) !== "PUBLIC_LISTENER" && String(row.role) !== "MIMIC") || String(row.status) !== "ACTIVE") continue;
    const existing = rowReference(row);
    if (!existing) continue;
    // FORWARD_RULE without a slot is the rule's source listener. Its lifecycle
    // belongs to forwardRuleRepository and must never be inferred from tunnel
    // exit runtime state.
    if (existing.resourceType === "FORWARD_RULE" && !existing.slot) continue;
    const desiredReference = desiredByKey.get(String(row.referenceKey));
    const port = listenerPort(row.port);
    if (desiredReference?.port === port) continue;
    if (existing.role === "MIMIC") {
      const ownerTunnelId = tunnelIdFromOwnerTag(row.ownerGroupTag);
      if (reportedUdpPorts.has(port) || (ownerTunnelId > 0 && reportedTunnelIds.has(ownerTunnelId)
        && !input.tunnels.some((item) => positiveInteger(item.tunnelId) === ownerTunnelId && item.udpPort !== undefined))) continue;
    } else if (runtimePorts.has(port)) {
      continue;
    }
    await releaseGlobalPortReferenceAfterRuntimeCleanup({ reference: existing });
    released += 1;
  }
  return { promoted, released };
}
