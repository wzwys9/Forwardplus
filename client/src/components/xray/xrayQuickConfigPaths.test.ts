import assert from "node:assert/strict";
import test from "node:test";
import {
  changeQuickConfigPath, copyQuickConfigPath, emptyQuickConfigPaths,
  inspectQuickConfigPaths, type QuickConfigPath,
} from "./xrayQuickConfigPaths";
import type { XrayQuickConfigEntryHost } from "./xrayQuickConfigFlow";

const hosts: XrayQuickConfigEntryHost[] = [1, 2, 3, 4].map((hostId) => ({
  hostId, name: `服务器 ${hostId}`, eligible: true, disabledReasonCode: null,
  endpoints: [{ addressFamily: "IPV4", address: `192.0.2.${hostId}` },
    { addressFamily: "IPV6", address: `2001:db8::${hostId}` }],
}));

test("路径增删改与触控排序不修改入口或原草稿，复制后独立编辑", () => {
  const original: QuickConfigPath = { id: "one", hops: ["1:IPV4", "2:IPV4", "3:IPV6"] };
  const copied = copyQuickConfigPath(original, "two");
  const moved = changeQuickConfigPath(copied, { type: "MOVE", index: 2, direction: -1 });
  assert.deepEqual(moved.hops, ["1:IPV4", "3:IPV6", "2:IPV4"]);
  assert.deepEqual(original.hops, ["1:IPV4", "2:IPV4", "3:IPV6"]);
  assert.equal(changeQuickConfigPath(moved, { type: "MOVE", index: 1, direction: -1 }), moved);
  assert.equal(changeQuickConfigPath(moved, { type: "REMOVE", index: 0 }), moved);
  const added = changeQuickConfigPath(moved, { type: "ADD" });
  assert.equal(added.hops.at(-1), null);
  const selected = changeQuickConfigPath(added, { type: "SET", index: 3, endpointKey: "4:IPV6" });
  assert.equal(selected.hops[3], "4:IPV6");
  assert.equal(changeQuickConfigPath(selected, { type: "REMOVE", index: 3 }).hops.length, 3);
  const full = { id: "full", hops: Array.from({ length: 9 }, () => null) };
  assert.equal(changeQuickConfigPath(full, { type: "ADD" }), full);
});

test("相同路径跨运营商复用合法，DNS 示意只取入口", () => {
  const paths = emptyQuickConfigPaths();
  for (const carrier of Object.keys(paths) as Array<keyof typeof paths>) {
    paths[carrier] = [{ id: carrier, hops: ["1:IPV4", "2:IPV6", "3:IPV4"] }];
  }
  const result = inspectQuickConfigPaths(paths, hosts, 4);
  assert.deepEqual(result.issues, []);
  assert.equal(result.uniqueForwardHostCount, 3);
  assert.deepEqual(result.dnsEntries.map((entry) => entry.address), Array(4).fill("192.0.2.1"));
});

test("同主机双地址族不同下一跳、跨路径环路均标记冲突", () => {
  const paths = emptyQuickConfigPaths();
  paths.TELECOM = [{ id: "t", hops: ["1:IPV4", "2:IPV4"] }];
  paths.UNICOM = [{ id: "u", hops: ["1:IPV6", "3:IPV4"] }];
  let issues = inspectQuickConfigPaths(paths, hosts, 4).issues;
  assert.ok(issues.some((issue) => issue.pathId === "t" && issue.code === "NEXT_HOP_CONFLICT"));
  assert.ok(issues.some((issue) => issue.pathId === "u" && issue.code === "NEXT_HOP_CONFLICT"));
  paths.UNICOM[0].hops = ["2:IPV4", "1:IPV4"];
  issues = inspectQuickConfigPaths(paths, hosts, 4).issues;
  assert.ok(issues.some((issue) => issue.code === "NEXT_HOP_CONFLICT"));
});

test("未填、主机下线、地址消失、重复主机和落地回环不会显示设计通过", () => {
  const paths = emptyQuickConfigPaths();
  paths.TELECOM = [{ id: "missing", hops: [null] }, { id: "stale", hops: ["9:IPV4"] }];
  paths.UNICOM = [{ id: "loop", hops: ["1:IPV4", "1:IPV6"] }];
  paths.MOBILE = [{ id: "landing", hops: ["2:IPV4", "4:IPV4"] }];
  paths.EDUCATION = [{ id: "offline", hops: ["3:IPV4"] }];
  const unavailable = hosts.map((host) => host.hostId === 3 ? { ...host, eligible: false } : host);
  const codes = inspectQuickConfigPaths(paths, unavailable, 4).issues.map((issue) => issue.code);
  for (const code of ["MISSING_ENDPOINT", "ENDPOINT_UNAVAILABLE", "REPEATED_HOST", "LANDING_AS_RELAY"]) {
    assert.ok(codes.includes(code as typeof codes[number]), code);
  }
  assert.equal(inspectQuickConfigPaths(emptyQuickConfigPaths(), hosts, 4).issues.length, 4);
});
