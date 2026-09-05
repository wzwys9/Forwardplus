import assert from "node:assert/strict";
import test from "node:test";
import { stageDnsRecordDraft, saveDnsRecordDrafts, createDnsRecordDeletionDrafts, type DnsRecordDraft } from "./dnsRecordDraft";

const lines = [{ lineId: 1, providerLineId: "0", name: "默认" }];
const original = { providerRecordId: "123", subdomain: "www", fqdn: "www.example.com", recordType: "A", providerLineId: "0", lineName: "默认", value: "192.0.2.1", ttl: 600, status: "ENABLE", recordRevision: "original-revision", inUse: false };
const draft = (key = "123"): DnsRecordDraft => ({ key, original, values: { subdomain: "www", recordType: "A", lineId: 1, value: "192.0.2.2", ttl: 600 }, deleted: false });

test("bulk deletion stages only exact-name address records and retains their revisions until Save", async () => {
  const records = ["A", "AAAA", "CNAME", "TXT", "MX", "NS"].map((recordType, index) => ({
    ...original, recordType, providerRecordId: String(index + 1), recordRevision: `revision-${index}`,
  }));
  const staged = createDnsRecordDeletionDrafts(records, original.fqdn, lines);
  assert.equal(staged.length, 3);
  assert.ok(staged.every(draft => draft.deleted));
  assert.deepEqual(records.map(record => record.recordType), ["A", "AAAA", "CNAME", "TXT", "MX", "NS"]);
  assert.throws(() => createDnsRecordDeletionDrafts([{ ...original, fqdn: "other.example.com" }], original.fqdn, lines));
  assert.throws(() => createDnsRecordDeletionDrafts([{ ...original, inUse: true }], original.fqdn, lines));
  const calls: unknown[] = [];
  await saveDnsRecordDrafts(staged, 42, {
    create: async () => assert.fail("no creates"), update: async () => assert.fail("no updates"),
    remove: async input => { calls.push(input); },
  }, () => undefined);
  assert.deepEqual(calls, [0, 1, 2].map(index => ({ zoneId: 42, providerRecordId: String(index + 1), expectedRecordRevision: `revision-${index}` })));
});

test("DNS drafts skip unchanged records, merge repeated edits and retain the original revision", () => {
  const unchanged = { ...draft(), values: { ...draft().values, subdomain: " WWW ", value: " 192.0.2.1 " } };
  assert.deepEqual(stageDnsRecordDraft([], unchanged, lines), []);
  const first = stageDnsRecordDraft([], draft(), lines);
  const next = stageDnsRecordDraft(first, { ...draft(), original: { ...original, recordRevision: "new-revision" }, values: { ...draft().values, ttl: 300 } }, lines);
  assert.equal(next.length, 1);
  assert.equal(next[0].original?.recordRevision, "original-revision");
  assert.deepEqual(stageDnsRecordDraft(next, unchanged, lines), []);
});

test("new DNS records can be edited or discarded before save without any remote calls", () => {
  const created = { ...draft("new:1"), original: null };
  const staged = stageDnsRecordDraft([], created, lines);
  assert.equal(staged.length, 1);
  assert.deepEqual(stageDnsRecordDraft(staged, { ...created, deleted: true }, lines), []);
  assert.equal(original.value, "192.0.2.1");
});

test("one explicit save sends only the draft differences with original revision", async () => {
  const calls: unknown[] = [];
  const writers = {
    create: async (input: unknown) => { calls.push(["create", input]); },
    update: async (input: unknown) => { calls.push(["update", input]); },
    remove: async (input: unknown) => { calls.push(["remove", input]); },
  };
  assert.equal((await saveDnsRecordDrafts([], 1, writers, () => undefined)).status, "SUCCESS");
  assert.equal(calls.length, 0);
  const result = await saveDnsRecordDrafts([draft()], 1, writers, () => undefined);
  assert.equal(result.status, "SUCCESS");
  assert.deepEqual(calls, [["update", { zoneId: 1, ...draft().values, providerRecordId: "123", expectedRecordRevision: "original-revision" }]]);
});

test("save stops at the first error, preserves unattempted changes and never retries writes", async () => {
  const calls: string[] = [];
  const applied: string[] = [];
  const result = await saveDnsRecordDrafts([draft("first"), { ...draft("second"), original: null }, draft("third")], 1, {
    update: async () => { calls.push("update"); },
    create: async () => { calls.push("create"); throw new Error("DNS_WRITE_UNCERTAIN"); },
    remove: async () => { calls.push("remove"); },
  }, key => applied.push(key));
  assert.deepEqual(calls, ["update", "create"]);
  assert.deepEqual(applied, ["first"]);
  assert.equal(result.status, "FAILED");
  if (result.status === "FAILED") assert.equal(result.failedKey, "second");
});

test("deletion remains a reversible draft until Save and uses the original record revision", async () => {
  const staged = stageDnsRecordDraft([], { ...draft(), deleted: true }, lines);
  assert.equal(staged[0].deleted, true);
  const calls: unknown[] = [];
  const result = await saveDnsRecordDrafts(staged, 1, {
    create: async () => assert.fail("must not create"), update: async () => assert.fail("must not update"),
    remove: async input => { calls.push(input); },
  }, () => undefined);
  assert.equal(result.status, "SUCCESS");
  assert.deepEqual(calls, [{ zoneId: 1, providerRecordId: "123", expectedRecordRevision: "original-revision" }]);
  assert.equal(original.value, "192.0.2.1");
});
