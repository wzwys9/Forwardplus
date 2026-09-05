import assert from "node:assert/strict";
import test from "node:test";
import { filterQuickConfigPathEngines, quickConfigPathEngineCompatible } from "./xrayQuickConfigForwardEngines";
test("kernel forwarding rejects cross-family hops while process engines retain dual-stack paths", () => {
  const hops = [[{ hostId: 1, addressFamily: "IPV4" as const }, { hostId: 2, addressFamily: "IPV6" as const }]];
  for (const engine of ["iptables", "nftables"] as const) {
    assert.equal(quickConfigPathEngineCompatible(engine, hops, "2606:4700::1111"), false);
    assert.equal(quickConfigPathEngineCompatible(engine, [hops[0].slice(1)], "2606:4700::1111"), true);
    assert.equal(quickConfigPathEngineCompatible(engine, [hops[0].slice(0, 1)], "landing.example.com"), false);
  }
  for (const engine of ["realm", "gost", "socat", "nginx"] as const) assert.equal(quickConfigPathEngineCompatible(engine, hops, "8.8.8.8"), true);
});

test("kernel policy exempts only a genuinely direct landing path, not a rewritten listener", () => {
  const direct = [{ hostId: 1, addressFamily: "IPV6" as const }];
  const forwarded = [{ hostId: 2, addressFamily: "IPV4" as const }];
  for (const engine of ["iptables", "nftables"] as const) {
    const catalog = { defaultEngine: "realm" as const, items: [{ engine, label: engine, isDefault: false, eligible: true, disabledReasonCode: null }] };
    assert.equal(filterQuickConfigPathEngines(catalog, [direct], "landing.example.com", 1)?.items[0].eligible, true);
    assert.equal(filterQuickConfigPathEngines(catalog, [direct, forwarded], "8.8.8.8", 1)?.items[0].eligible, true);
    assert.equal(filterQuickConfigPathEngines(catalog, [direct, forwarded], "landing.example.com", 1)?.items[0].eligible, false);
    assert.equal(filterQuickConfigPathEngines(catalog, [direct, forwarded], "8.8.8.8")?.items[0].eligible, false);
  }
});
test("registered addresses bound outbound family and allow a dual-stack bridge", () => {
  const hosts = [
    { hostId: 1, endpoints: [{ addressFamily: "IPV4" as const }] },
    { hostId: 2, endpoints: [{ addressFamily: "IPV4" as const }, { addressFamily: "IPV6" as const }] },
  ];
  const v4 = { hostId: 1, addressFamily: "IPV4" as const };
  const bridge = { hostId: 2, addressFamily: "IPV4" as const };
  assert.equal(quickConfigPathEngineCompatible("realm", [[v4]], "2606:4700::1111", undefined, hosts), false);
  assert.equal(quickConfigPathEngineCompatible("realm", [[v4, bridge]], "2606:4700::1111", undefined, hosts), true);
  assert.equal(quickConfigPathEngineCompatible("nftables", [[v4, bridge]], "2606:4700::1111", undefined, hosts), false);
  assert.equal(quickConfigPathEngineCompatible("realm", [[{ ...v4, addressFamily: "IPV6" }]], "8.8.8.8", undefined, hosts), false);
});
