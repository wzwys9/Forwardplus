import { quoteIdentifier as q } from "./dbCompat";
import { queryRaw } from "./dbRuntime";
import { compileQuickConfigTopology, parseQuickConfigRelays, type QuickConfigTopologyRoute } from "./xrayQuickConfigTopology";

export async function loadQuickConfigSegments(quickConfigId: number, topologyId: number,
  target?: { publicPort: number; targetAddress: string; targetPort: number }) {
  if (!target) {
    const [row] = await queryRaw<Record<string, unknown>>(`SELECT ${q("publicPort")}, ${q("targetAddress")}, ${q("targetPort")}
      FROM ${q("xray_quick_config_topology_revisions")} WHERE ${q("id")} = ? AND ${q("quickConfigId")} = ?`, [topologyId, quickConfigId]);
    target = { publicPort: Number(row?.publicPort), targetAddress: String(row?.targetAddress ?? ""), targetPort: Number(row?.targetPort) };
  }
  const routes = await queryRaw<QuickConfigTopologyRoute & Record<string, unknown>>(
    `SELECT ${q("hostId")}, ${q("routeMode")}, ${q("relayHopsJson")} FROM ${q("xray_quick_config_routes")}
      WHERE ${q("quickConfigId")} = ? AND ${q("topologyRevisionId")} = ? ORDER BY ${q("sortOrder")}, ${q("id")}`,
    [quickConfigId, topologyId],
  );
  const listenPort = target.publicPort;
  return compileQuickConfigTopology(routes, target).map(segment => ({ ...segment, listenPort }));
}

/** Retained active/staged paths protect even a relay whose physical rule is missing. */
export async function quickConfigReferencesHost(hostId: number): Promise<boolean> {
  for (let offset = 0; ; offset += 200) {
    const rows = await queryRaw<Record<string, unknown>>(
      `SELECT r.${q("hostId")}, r.${q("relayHopsJson")} FROM ${q("xray_quick_config_routes")} r
       JOIN ${q("xray_quick_configs")} qc ON qc.${q("id")} = r.${q("quickConfigId")}
       WHERE qc.${q("state")} <> 'REMOVED' AND r.${q("state")} <> 'RETIRED'
       ORDER BY r.${q("id")} LIMIT 200 OFFSET ?`, [offset],
    );
    if (rows.some(row => Number(row.hostId) === hostId || parseQuickConfigRelays(row.relayHopsJson).some(hop => hop.hostId === hostId))) return true;
    if (rows.length < 200) return false;
  }
}
