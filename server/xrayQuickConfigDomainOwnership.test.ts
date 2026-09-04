import assert from "node:assert/strict";
import test from "node:test";
import { isQuickConfigDnsRecordOwned } from "./xrayQuickConfigService";
import { computeXrayQuickConfigDnsTupleHash } from "./xrayQuickConfigDnsTuple";

test("original-domain confirmation only recognizes matching managed record IDs and complete DNS tuples", () => {
  const remote = {
    providerRecordId: "123", subdomain: "edge", recordType: "A", providerLineId: "0",
    lineName: "默认", value: "1.1.1.1", ttl: 600, status: "ENABLE",
  };
  const stored = {
    providerRecordId: "123", fqdn: "edge.example.com", recordType: "A" as const,
    providerLineId: "0", value: "1.1.1.1", ttl: 600,
    remoteTupleHash: computeXrayQuickConfigDnsTupleHash({
      fqdn: "edge.example.com", recordType: "A", providerLineId: "0", value: "1.1.1.1", ttl: 600,
    }),
  };
  assert.equal(isQuickConfigDnsRecordOwned(remote, stored, "example.com"), true);
  for (const drift of [
    { providerRecordId: "999" }, { subdomain: "other" }, { recordType: "CNAME" },
    { providerLineId: "10=0" }, { value: "8.8.8.8" }, { ttl: 120 }, { status: "DISABLE" },
  ]) assert.equal(isQuickConfigDnsRecordOwned({ ...remote, ...drift }, stored, "example.com"), false);
  assert.equal(isQuickConfigDnsRecordOwned(remote, { ...stored, remoteTupleHash: "bad" }, "example.com"), false);
  assert.equal(isQuickConfigDnsRecordOwned(remote, stored, "other.example.com"), false);
});
