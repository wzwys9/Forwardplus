import assert from "node:assert/strict";
import test from "node:test";
import { planQuickConfigDnsDiff } from "./xrayQuickConfigDnsDiff";

const record = (recordRef: string, value: string, providerLineId = "0", ttl = 600) => ({
  recordRef, value, providerLineId, ttl, recordType: "A" as const, lineName: providerLineId,
});

test("edit reuses ten owned A records and creates only the additional AAAA", () => {
  const existing = ["0", "10=0", "10=1", "10=2", "10=3"].flatMap((line, i) =>
    [record(`${i}-a`, "192.0.2.1", line), record(`${i}-b`, "192.0.2.2", line)]);
  const added = { ...record("new", "2001:db8::1", "10=0"), recordType: "AAAA" as const };
  const diff = planQuickConfigDnsDiff([...existing].reverse(), existing, existing.map(r => r.recordRef));
  assert.equal(diff.dnsRecords.filter(r => r.action === "REUSE").length, 10);
  assert.deepEqual(diff.conflictingRecords, []);
  const extended = planQuickConfigDnsDiff([...existing.slice(0, 3), added, ...existing.slice(3)], existing, existing.map(r => r.recordRef));
  assert.equal(extended.dnsRecords.filter(r => r.action === "REUSE").length, 10);
  assert.equal(extended.dnsRecords.filter(r => r.action === "CREATE").length, 1);
  assert.deepEqual(extended.conflictingRecords, []);
});

test("changed records cannot consume a later unchanged record; removed records are explicit", () => {
  const kept = record("keep", "192.0.2.1");
  const changed = record("change", "192.0.2.2");
  const removed = record("remove", "192.0.2.3");
  const diff = planQuickConfigDnsDiff([record("new", "192.0.2.4"), kept], [kept, changed, removed], ["keep", "change", "remove"]);
  assert.deepEqual(diff.dnsRecords.map(r => r.action), ["REPLACE", "REUSE"]);
  assert.deepEqual(diff.conflictingRecords.map(r => [r.recordRef, r.action]), [["change", "REPLACE"], ["remove", "DELETE"]]);
});

test("third-party, changed TTL or line, and removed CNAME must not be called reuse", () => {
  const owned = record("owned", "192.0.2.1");
  for (const desired of [record("desired", owned.value, "0", 300), record("desired", owned.value, "10=0")]) {
    assert.equal(planQuickConfigDnsDiff([desired], [owned], ["owned"]).dnsRecords[0].action, "REPLACE");
  }
  assert.equal(planQuickConfigDnsDiff([owned], [owned], []).dnsRecords[0].action, "REPLACE");
  const duplicate = record("duplicate", owned.value);
  assert.equal(planQuickConfigDnsDiff([owned], [owned, duplicate], ["owned"]).dnsRecords[0].action, "REPLACE");
  const cname = { ...record("alias", "example.net"), recordType: "CNAME" as const };
  const diff = planQuickConfigDnsDiff([owned], [cname], []);
  assert.equal(diff.dnsRecords[0].action, "CREATE");
  assert.equal(diff.conflictingRecords[0].action, "DELETE");
});
