import assert from "node:assert/strict";
import test from "node:test";

import {
  formatXrayEndpoint,
  inboundStatusPresentation,
  type XrayInboundSummary,
} from "./xrayInboundPresentation";

function inbound(overrides: Partial<XrayInboundSummary> = {}): XrayInboundSummary {
  return {
    id: 1,
    name: "香港 Reality",
    host: { id: 7, name: "香港-01", isOnline: true, lastHeartbeat: new Date("2026-09-01T00:00:00Z") },
    publicAddress: "203.0.113.8",
    listenPort: 443,
    protocol: "VLESS",
    security: "REALITY",
    clientCount: 2,
    desiredEnabled: true,
    pendingDelete: false,
    deploymentStatus: "RUNNING",
    lastErrorCode: null,
    activeOperationId: null,
    activeOperationType: null,
    updatedAt: new Date("2026-09-01T00:00:00Z"),
    ...overrides,
  };
}

test("inbound status presentation never describes an offline Agent as stopped", () => {
  const view = inboundStatusPresentation(inbound({
    host: { id: 7, name: "香港-01", isOnline: false, lastHeartbeat: new Date("2026-09-01T00:00:00Z") },
    deploymentStatus: "RUNNING",
  }));
  assert.equal(view.label, "运行状态未知");
  assert.equal(view.detail, "Agent 离线，Xray 运行状态未知");
  assert.doesNotMatch(`${view.label}${view.detail}`, /已停止/);
});

test("inbound status presentation exposes a safe operation-error entry", () => {
  const view = inboundStatusPresentation(inbound({ deploymentStatus: "ERROR", lastErrorCode: "CONFIG_TEST_FAILED" }));
  assert.equal(view.label, "应用失败");
  assert.equal(view.detail, "错误码：CONFIG_TEST_FAILED");
  assert.equal(view.canInspectError, true);
  assert.equal(inboundStatusPresentation(inbound()).canInspectError, false);
});

test("endpoint presentation brackets bare IPv6 addresses", () => {
  assert.equal(formatXrayEndpoint("2001:db8::8", 8443), "[2001:db8::8]:8443");
  assert.equal(formatXrayEndpoint("[2001:db8::8]", 8443), "[2001:db8::8]:8443");
  assert.equal(formatXrayEndpoint("example.com", 443), "example.com:443");
});
