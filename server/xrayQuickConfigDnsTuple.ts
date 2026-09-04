import { createHash } from "node:crypto";

export type XrayQuickConfigDnsTuple = {
  fqdn: string;
  recordType: "A" | "AAAA" | "CNAME";
  providerLineId: string;
  value: string;
  ttl: number;
};

export function computeXrayQuickConfigDnsTupleHash(tuple: XrayQuickConfigDnsTuple): string {
  return createHash("sha256")
    .update(JSON.stringify({
      schema: "quick-config-dns-tuple:v1",
      fqdn: tuple.fqdn,
      recordType: tuple.recordType,
      providerLineId: tuple.providerLineId,
      value: tuple.value,
      ttl: tuple.ttl,
    }), "utf8")
    .digest("hex");
}
