import { quoteIdentifier as q } from "./dbCompat";
import { queryRaw } from "./dbRuntime";

// Include both sides of an edit until its DNS cleanup and operation finish.
// UNION deduplicates names before returning them; no per-record database queries.
export async function listDnsProviderUsedNames(accountId: number, zoneId: number, zoneName: string): Promise<Set<string>> {
  const active = "('QUEUED', 'RUNNING', 'COMPENSATING')";
  const rows = await queryRaw<{ fqdn: string | null; relativeName: string | null }>(
    `SELECT ${q("fqdn")}, NULL AS ${q("relativeName")} FROM ${q("xray_quick_configs")}
      WHERE ${q("dnsAccountId")} = ? AND ${q("zoneId")} = ? AND ${q("state")} <> 'REMOVED'
     UNION
     SELECT NULL AS ${q("fqdn")}, c.${q("normalizedRelativeName")} AS ${q("relativeName")}
       FROM ${q("xray_quick_config_domain_claims")} c
       JOIN ${q("xray_quick_configs")} qc ON qc.${q("id")} = c.${q("quickConfigId")}
      WHERE c.${q("dnsAccountId")} = ? AND c.${q("zoneId")} = ? AND qc.${q("state")} <> 'REMOVED'
     UNION
     SELECT r.${q("fqdn")}, NULL AS ${q("relativeName")} FROM ${q("xray_quick_config_dns_records")} r
      WHERE r.${q("dnsAccountId")} = ? AND r.${q("zoneId")} = ?
        AND (r.${q("status")} <> 'REMOVED' OR EXISTS (
          SELECT 1 FROM ${q("xray_quick_config_operations")} o
          JOIN ${q("xray_quick_config_routes")} rt ON rt.${q("quickConfigId")} = o.${q("quickConfigId")}
          WHERE rt.${q("id")} = r.${q("routeId")} AND o.${q("status")} IN ${active}
            AND (rt.${q("topologyRevisionId")} = o.${q("fromTopologyRevisionId")}
              OR rt.${q("topologyRevisionId")} = o.${q("toTopologyRevisionId")})))
     UNION
     SELECT b.${q("fqdn")}, NULL AS ${q("relativeName")} FROM ${q("xray_quick_config_dns_record_backups")} b
       JOIN ${q("xray_quick_config_operations")} o ON o.${q("id")} = b.${q("operationId")}
      WHERE b.${q("dnsAccountId")} = ? AND b.${q("zoneId")} = ? AND o.${q("status")} IN ${active}`,
    [accountId, zoneId, accountId, zoneId, accountId, zoneId, accountId, zoneId],
  );
  return new Set(rows.map((row) => (row.fqdn
    ?? (row.relativeName === "@" ? zoneName : `${row.relativeName}.${zoneName}`)).trim().toLowerCase()));
}
