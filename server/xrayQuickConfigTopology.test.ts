import assert from "node:assert/strict";
import test from "node:test";
import { compileQuickConfigTopology, parseQuickConfigRelays, serializeQuickConfigRelays } from "./xrayQuickConfigTopology";

const hop = (hostId: number, address = `8.8.8.${hostId}`) => ({ hostId, addressFamily: (address.includes(":") ? "IPV6" : "IPV4") as "IPV4" | "IPV6", address });
const route = (hostId: number, relays: ReturnType<typeof hop>[] = []) => ({ ...hop(hostId), routeMode: "FORWARD", relayHopsJson: serializeQuickConfigRelays(relays) });
const target = { publicPort: 5326, targetAddress: "9.9.9.9", targetPort: 443 };

test("compiles shared carrier/default paths once, preserving intermediate IPv6 and landing port", () => {
  const routes = [route(1, [hop(2, "2606:4700::1111"), hop(3)]), route(4, [hop(2, "2606:4700::1111"), hop(3)])];
  assert.deepEqual(compileQuickConfigTopology([...routes, routes[0]], target), [
    { hostId: 1, targetAddress: "2606:4700::1111", targetPort: 5326 },
    { hostId: 2, targetAddress: "8.8.8.3", targetPort: 5326 },
    { hostId: 3, targetAddress: "9.9.9.9", targetPort: 443 },
    { hostId: 4, targetAddress: "2606:4700::1111", targetPort: 5326 },
  ]);
});
test("legacy direct-to-landing and local direct retain their semantics", () => {
  assert.deepEqual(parseQuickConfigRelays(null), []);
  assert.deepEqual(compileQuickConfigTopology([{ ...hop(1), routeMode: "FORWARD" }, { ...hop(9), routeMode: "DIRECT" }], target), [
    { hostId: 1, targetAddress: "9.9.9.9", targetPort: 443 },
  ]);
});
test("rejects conflicting shared listeners, cycles, invalid and oversized persisted paths", () => {
  assert.throws(() => compileQuickConfigTopology([], target));
  assert.throws(() => compileQuickConfigTopology(Array(129).fill(route(1)), target));
  assert.throws(() => compileQuickConfigTopology([route(1)], { ...target, targetAddress: "bad\nname" }));
  assert.throws(() => compileQuickConfigTopology([{ hostId: "bad", routeMode: "DIRECT" }], target));
  for (const routes of [[route(1, [hop(2)]), route(1)], [route(1, [hop(2), hop(1)])], [route(1, [hop(2)]), route(2, [hop(1)])]]) {
    assert.throws(() => compileQuickConfigTopology(routes, target), /QUICK_CONFIG_PATH_INVALID/);
  }
  assert.throws(() => compileQuickConfigTopology([{ ...route(1, [hop(2)]), routeMode: "DIRECT" }], target));
  for (const json of ["null", "{}", "broken", JSON.stringify([{ ...hop(2), argv: "no" }]), JSON.stringify([hop(2, "::1")]), JSON.stringify(Array.from({ length: 9 }, (_, n) => hop(n + 1)))]) {
    assert.throws(() => parseQuickConfigRelays(json));
  }
});
