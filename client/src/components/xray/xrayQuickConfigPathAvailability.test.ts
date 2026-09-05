import assert from "node:assert/strict";
import test from "node:test";
import { quickConfigPathActionReason, inspectQuickConfigPathDraft } from "./xrayQuickConfigPathAvailability";
import { emptyQuickConfigPaths } from "./xrayQuickConfigPaths";
import type { XrayQuickConfigEntryHost, XrayQuickConfigTarget } from "./xrayQuickConfigFlow";

const hosts: XrayQuickConfigEntryHost[] = [1, 2, 3, 4].map(hostId => ({ hostId, name: `Host ${hostId}`, eligible: true, disabledReasonCode: null,
  endpoints: [{ addressFamily: "IPV4", address: `8.8.8.${hostId}` }, ...(hostId === 2 ? [{ addressFamily: "IPV6" as const, address: "2606:4700::1111" }] : [])] }));
const target: XrayQuickConfigTarget = { targetType: "EXTERNAL_PROXY_NODE", targetId: 1, targetVersion: "v", name: "landing", protocol: "VLESS", eligible: true, disabledReasonCode: null, shareCapability: "NONE", endpoint: { address: "9.9.9.9", port: 443 } };

test("candidates explain conflicts in other carriers and unlock after removal", () => {
  const paths = emptyQuickConfigPaths();
  paths.TELECOM = [{ id: "t", hops: ["1:IPV4", "2:IPV4"] }];
  paths.UNICOM = [{ id: "u", hops: [null] }];
  const action = { type: "SET" as const, index: 0, endpointKey: "1:IPV4" };
  assert.match(quickConfigPathActionReason(paths, "UNICOM", "u", action, hosts, target, "realm")!, /电信.*路径 1/);
  paths.TELECOM = [];
  assert.equal(quickConfigPathActionReason(paths, "UNICOM", "u", action, hosts, target, "realm"), null);
  paths.UNICOM[0].hops = ["1:IPV4", null];
  assert.match(quickConfigPathActionReason(paths, "UNICOM", "u", { ...action, index: 1 }, hosts, target, "realm")!, /重复/);
});

test("IPv4-only entry can be selected while a dual-stack bridge is still needed, but cannot submit yet", () => {
  const paths = emptyQuickConfigPaths();
  paths.TELECOM = [{ id: "t", hops: [null] }];
  const v6Target = { ...target, endpoint: { address: "2606:4700::2222", port: 443 } };
  const action = { type: "SET" as const, index: 0, endpointKey: "1:IPV4" };
  assert.equal(quickConfigPathActionReason(paths, "TELECOM", "t", action, hosts, v6Target, "realm"), null);
  assert.ok(quickConfigPathActionReason(paths, "TELECOM", "t", action, hosts, v6Target, "nftables"));
  paths.TELECOM[0].hops = ["1:IPV4"];
  assert.ok(inspectQuickConfigPathDraft(paths, hosts, v6Target, "realm").issues.some(issue => issue.code === "ADDRESS_FAMILY_UNSUPPORTED"));
  paths.TELECOM[0].hops.push("2:IPV4");
  assert.equal(inspectQuickConfigPathDraft(paths, hosts, v6Target, "realm").issues.some(issue => issue.pathId === "t"), false);
});

test("repairing one of three conflicting paths is allowed while the other two remain invalid", () => {
  const paths = emptyQuickConfigPaths();
  paths.TELECOM = [{ id: "t", hops: ["1:IPV4", "2:IPV4"] }];
  paths.UNICOM = [{ id: "u", hops: ["1:IPV4", "3:IPV4"] }];
  paths.MOBILE = [{ id: "m", hops: ["1:IPV4", "4:IPV4"] }];
  const extra = { ...hosts[0], hostId: 5, name: "Host 5" };
  assert.equal(quickConfigPathActionReason(paths, "TELECOM", "t", { type: "SET", index: 0, endpointKey: "5:IPV4" }, [...hosts, extra], target, "realm"), null);
});
