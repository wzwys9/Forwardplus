import type { DomainRecordProjection } from "./xrayQuickConfigService";

type DnsTuple = { recordType: string; providerLineId: string; value: string; ttl: number };

function sameTuple(a: DnsTuple, b: DnsTuple): boolean {
  return a.recordType === b.recordType && a.providerLineId === b.providerLineId
    && a.value === b.value && a.ttl === b.ttl;
}

/** Both collections must already be restricted to the same verified zone/name. */
export function matchQuickConfigDnsRecords<D extends DnsTuple, E extends DnsTuple>(desired: readonly D[], existing: readonly E[]) {
  const remaining = new Set(existing);
  const matches = desired.map(record => {
    const previous = existing.find(candidate => remaining.has(candidate) && sameTuple(candidate, record)) ?? null;
    if (previous) remaining.delete(previous);
    return { record, previous, exact: previous !== null };
  });
  // Reserve every exact tuple first, including those later in the requested order.
  for (const match of matches) {
    if (match.previous) continue;
    match.previous = existing.find(candidate => remaining.has(candidate)
      && candidate.recordType === match.record.recordType && candidate.providerLineId === match.record.providerLineId)
      ?? existing.find(candidate => remaining.has(candidate) && candidate.recordType === match.record.recordType) ?? null;
    if (match.previous) remaining.delete(match.previous);
  }
  return { matches, removed: [...remaining] };
}

export function planQuickConfigDnsDiff<D extends DnsTuple>(desired: readonly D[], existing: readonly DomainRecordProjection[], ownedRecordRefs: readonly string[]) {
  const owned = new Set(ownedRecordRefs);
  const { matches } = matchQuickConfigDnsRecords(desired, existing);
  const reused = new Set<DomainRecordProjection>();
  const replaced = new Set<DomainRecordProjection>();
  const dnsRecords = matches.map(({ record, previous, exact }) => {
    const reuse = previous && exact && owned.has(previous.recordRef)
      && existing.filter(candidate => sameTuple(candidate, record)).length === 1;
    if (reuse) reused.add(previous);
    else if (previous) replaced.add(previous);
    const action: "CREATE" | "REPLACE" | "REUSE" = reuse ? "REUSE" : previous ? "REPLACE" : "CREATE";
    return { ...record, action };
  });
  const conflictingRecords = existing.filter(record => !reused.has(record)).map(record => ({
    ...record,
    action: replaced.has(record) ? "REPLACE" as const : "DELETE" as const,
  }));
  return { dnsRecords, conflictingRecords };
}
