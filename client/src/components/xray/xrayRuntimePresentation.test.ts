import assert from "node:assert/strict";
import test from "node:test";

import { runtimeActionPresentation, runtimeServicePresentation, runtimeVersionPresentation } from "./xrayRuntimePresentation";

const base = {
  isAgentOnline: true,
  installedVersion: "v26.3.27",
  targetVersion: "v26.3.27",
  serviceStatus: "RUNNING",
  hasUpgrade: false,
  isNewerThanTarget: false,
  unavailableReasonCode: null,
} as const;

test("runtime version presentation distinguishes all approved version states", () => {
  assert.equal(runtimeVersionPresentation({ ...base, installedVersion: null }).kind, "UNINSTALLED");
  assert.equal(runtimeVersionPresentation(base).kind, "CURRENT");
  assert.equal(runtimeVersionPresentation({ ...base, installedVersion: "v25.1.1", hasUpgrade: true }).kind, "UPGRADE_AVAILABLE");
  assert.equal(runtimeVersionPresentation({ ...base, installedVersion: "v27.1.1", isNewerThanTarget: true }).kind, "NEWER_THAN_TARGET");
  assert.equal(runtimeVersionPresentation({ ...base, unavailableReasonCode: "ARTIFACT_UNAVAILABLE" }).artifactLabel, "缺少已验证制品");
});

test("offline Agent is always presented as unknown rather than stopped", () => {
  assert.deepEqual(runtimeServicePresentation({ ...base, isAgentOnline: false, serviceStatus: "STOPPED" }), {
    label: "运行状态未知",
    detail: "Agent 离线，Xray 运行状态未知",
    tone: "warning",
  });
  assert.equal(runtimeServicePresentation({ ...base, serviceStatus: "STOPPED" }).label, "已停止");
});

test("runtime actions never auto-upgrade or downgrade and gate unsafe host states", () => {
  assert.deepEqual(runtimeActionPresentation({ ...base, installedVersion: null, serviceStatus: "STOPPED", activeOperationId: null }).map((action) => action.type), ["INSTALL"]);
  assert.deepEqual(runtimeActionPresentation({ ...base, installedVersion: "v25.1.1", hasUpgrade: true, activeOperationId: null }).map((action) => action.type), ["UPGRADE"]);
  assert.deepEqual(runtimeActionPresentation({ ...base, activeOperationId: null }).map((action) => action.type), ["SYNC", "RESTART"]);
  assert.deepEqual(runtimeActionPresentation({ ...base, installedVersion: "v27.1.1", isNewerThanTarget: true, activeOperationId: null }).map((action) => action.type), ["RESTART"]);
  assert.equal(runtimeActionPresentation({ ...base, isAgentOnline: false, activeOperationId: null })[0]?.disabledReason, "HOST_OFFLINE");
  assert.equal(runtimeActionPresentation({ ...base, activeOperationId: "busy-1" })[0]?.disabledReason, "OPERATION_CONFLICT");
  assert.equal(runtimeActionPresentation({ ...base, installedVersion: null, serviceStatus: "STOPPED", unavailableReasonCode: "ARTIFACT_UNAVAILABLE", activeOperationId: null })[0]?.disabledReason, "ARTIFACT_UNAVAILABLE");
});
