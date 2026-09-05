import type { inferRouterInputs } from "@trpc/server";
import type { AppRouter } from "../../../server/routers";

type AppRouterInputs = inferRouterInputs<AppRouter>;

export type DnsRecordItem = Readonly<{
  providerRecordId: string; subdomain: string; fqdn: string; recordType: string;
  providerLineId: string; lineName: string; value: string; ttl: number;
  status: string | null; recordRevision: string; inUse: boolean;
}>;
export type DnsRecordValues = Omit<AppRouterInputs["xray"]["dnsRecords"]["create"], "zoneId">;
export type DnsRecordDraft = Readonly<{
  key: string;
  original: DnsRecordItem | null;
  values: DnsRecordValues;
  deleted: boolean;
}>;

export function createDnsRecordDeletionDrafts(
  records: readonly DnsRecordItem[], fqdn: string,
  lines: readonly { lineId: number; providerLineId: string }[],
): DnsRecordDraft[] {
  return records.flatMap(record => {
    if (record.fqdn !== fqdn || record.inUse) throw new Error("DNS_SUBDOMAIN_IN_USE");
    const recordType = record.recordType;
    if (recordType !== "A" && recordType !== "AAAA" && recordType !== "CNAME") return [];
    return [{ key: record.providerRecordId, original: record, deleted: true, values: {
      subdomain: record.subdomain, recordType, value: record.value, ttl: record.ttl,
      // Delete uses only the original ID/revision, even if its line has retired.
      lineId: lines.find(line => line.providerLineId === record.providerLineId)?.lineId ?? 0,
    } }];
  });
}

export function stageDnsRecordDraft(
  drafts: readonly DnsRecordDraft[],
  draft: DnsRecordDraft,
  lines: readonly { lineId: number; providerLineId: string }[],
): DnsRecordDraft[] {
  const previous = drafts.find(item => item.key === draft.key);
  const original = previous ? previous.original : draft.original;
  const values = { ...draft.values, subdomain: draft.values.subdomain.trim().toLowerCase(), value: draft.values.value.trim() };
  const unchanged = original && !draft.deleted && original.subdomain === values.subdomain
    && original.recordType === values.recordType && original.value === values.value && original.ttl === values.ttl
    && original.providerLineId === lines.find(line => line.lineId === values.lineId)?.providerLineId;
  if (unchanged || (!original && draft.deleted)) return drafts.filter(item => item.key !== draft.key);
  const next = { ...draft, original, values };
  return previous ? drafts.map(item => item.key === draft.key ? next : item) : [...drafts, next];
}

type Writers = {
  create: (input: AppRouterInputs["xray"]["dnsRecords"]["create"]) => Promise<unknown>;
  update: (input: AppRouterInputs["xray"]["dnsRecords"]["update"]) => Promise<unknown>;
  remove: (input: AppRouterInputs["xray"]["dnsRecords"]["remove"]) => Promise<unknown>;
};

/** Only called by the explicit Save action. Never retry an uncertain DNS write. */
export async function saveDnsRecordDrafts(
  drafts: readonly DnsRecordDraft[], zoneId: number, writers: Writers, onApplied: (key: string) => void,
): Promise<{ status: "SUCCESS" } | { status: "FAILED"; failedKey: string; error: unknown }> {
  for (const draft of drafts) {
    try {
      if (draft.original) {
        const identity = { zoneId, providerRecordId: draft.original.providerRecordId, expectedRecordRevision: draft.original.recordRevision };
        if (draft.deleted) await writers.remove(identity);
        else await writers.update({ ...draft.values, ...identity });
      } else if (!draft.deleted) {
        await writers.create({ ...draft.values, zoneId });
      }
      onApplied(draft.key);
    } catch (error) {
      return { status: "FAILED", failedKey: draft.key, error };
    }
  }
  return { status: "SUCCESS" };
}
