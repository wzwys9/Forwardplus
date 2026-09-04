import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";

import { XrayInboundList } from "./XrayInboundList";
import type { XrayInboundSummary } from "./xrayInboundPresentation";

const items: XrayInboundSummary[] = [
  {
    id: 1, name: "离线节点", host: { id: 1, name: "edge-01", isOnline: false, lastHeartbeat: null },
    publicAddress: "2001:db8::8", listenPort: 443, protocol: "VLESS", security: "REALITY", clientCount: 2,
    externalProxy: { id: 9, name: "美国 A", protocol: "VLESS_REALITY_VISION", address: "us.example.com", port: 443 },
    desiredEnabled: true, pendingDelete: false, deploymentStatus: "HOST_OFFLINE", lastErrorCode: null, activeOperationId: null, activeOperationType: null,
    updatedAt: new Date("2026-09-01T00:00:00Z"),
  },
  {
    id: 2, name: "失败节点", host: { id: 2, name: "edge-02", isOnline: true, lastHeartbeat: new Date("2026-09-01T00:00:00Z") },
    publicAddress: "example.com", listenPort: 8443, protocol: "VLESS", security: "REALITY", clientCount: 1,
    desiredEnabled: true, pendingDelete: false, deploymentStatus: "ERROR", lastErrorCode: "CONFIG_TEST_FAILED", activeOperationId: null, activeOperationType: null,
    updatedAt: new Date("2026-09-01T00:00:00Z"),
  },
  {
    id: 3, name: "Hysteria 节点", host: { id: 3, name: "edge-03", isOnline: true, lastHeartbeat: new Date("2026-09-01T00:00:00Z") },
    publicAddress: "hy.example.com", listenPort: 443, protocol: "HYSTERIA", security: "TLS", clientCount: 1,
    desiredEnabled: true, pendingDelete: false, deploymentStatus: "RUNNING", lastErrorCode: null, activeOperationId: null, activeOperationType: null,
    updatedAt: new Date("2026-09-01T00:00:00Z"),
  },
];

test("node list renders desktop and mobile layouts with textual statuses and error action", () => {
  const markup = renderToStaticMarkup(
    <XrayInboundList items={items} page={1} totalPages={2} totalItems={14} onPageChange={() => undefined} onInspectError={() => undefined} onOpenDetail={() => undefined} onOpenOperation={() => undefined} />,
  );
  assert.match(markup, /hidden overflow-x-auto xl:block/);
  assert.match(markup, /grid gap-3[^\"]*xl:hidden/);
  assert.match(markup, /flex flex-col items-start gap-3 sm:flex-row/);
  assert.match(markup, /Agent 离线，Xray 运行状态未知/);
  assert.doesNotMatch(markup, /Agent 离线[^<]*已停止/);
  assert.match(markup, /应用失败/);
  assert.match(markup, /错误码：CONFIG_TEST_FAILED/);
  assert.match(markup, /查看错误/);
  assert.match(markup, /查看详情/);
  assert.match(markup, /\[2001:db8::8\]:443/);
  assert.match(markup, /Hysteria 2 · TLS/);
  assert.match(markup, /美国 A（VLESS_REALITY_VISION）/);
  assert.match(markup, />直连</);
  assert.match(markup, /第 1 \/ 2 页/);
  assert.match(markup, /aria-label="上一页"[^>]*disabled/);
});
