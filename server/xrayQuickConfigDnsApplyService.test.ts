import assert from "node:assert/strict";
import test from "node:test";

import {
  hasQuickConfigDnsCreateOwnershipEvidence,
  orderQuickConfigDnsWrites,
  waitForQuickConfigDnsVisibility,
} from "./xrayQuickConfigDnsApplyService";

test("DNSPod writes default records before carrier records without changing persisted order", () => {
  const persisted = [
    { id: 1, lineCategory: "TELECOM" },
    { id: 2, lineCategory: "DEFAULT" },
    { id: 3, lineCategory: "UNICOM" },
    { id: 4, lineCategory: "DEFAULT" },
    { id: 5, lineCategory: "MOBILE" },
    { id: 6, lineCategory: "EDUCATION" },
  ] as const;

  const ordered = orderQuickConfigDnsWrites(persisted);

  assert.deepEqual(ordered.map((record) => record.id), [2, 4, 1, 3, 5, 6]);
  assert.deepEqual(persisted.map((record) => record.id), [1, 2, 3, 4, 5, 6]);
});

test("DNSPod create verification waits for a newly indexed record without another write", async () => {
  const sleeps: number[] = [];
  let reads = 0;

  const visible = await waitForQuickConfigDnsVisibility(
    async () => {
      reads += 1;
      return reads === 3 ? { providerRecordId: "700" } : null;
    },
    {
      delaysMs: [5, 10, 20],
      sleep: async (milliseconds) => { sleeps.push(milliseconds); },
    },
  );

  assert.deepEqual(visible, { providerRecordId: "700" });
  assert.equal(reads, 3);
  assert.deepEqual(sleeps, [5, 10]);
});

test("retry adopts an unowned exact DNS record only with a prior attempted create", () => {
  assert.equal(hasQuickConfigDnsCreateOwnershipEvidence({
    currentIntent: { kind: "DNS_CREATE", status: "PENDING" },
    sourceCreateStatus: "FAILED",
  }), true);
  assert.equal(hasQuickConfigDnsCreateOwnershipEvidence({
    currentIntent: { kind: "DNS_CREATE", status: "PENDING" },
    sourceCreateStatus: null,
  }), false);
  assert.equal(hasQuickConfigDnsCreateOwnershipEvidence({
    currentIntent: { kind: "DNS_CREATE", status: "PENDING" },
    sourceCreateStatus: "COMPENSATED",
  }), false);
  assert.equal(hasQuickConfigDnsCreateOwnershipEvidence({
    currentIntent: { kind: "DNS_CREATE", status: "RUNNING" },
    sourceCreateStatus: null,
  }), true);
});
