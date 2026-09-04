import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";

import { XrayRuntimeList } from "./XrayRuntimeList";

const runtime = (overrides: Record<string, unknown>) => ({
  hostId: 1,
  hostName: "edge-current",
  isAgentOnline: true,
  capabilityVersion: 1,
  canManageXray: true,
  unavailableReasonCode: null,
  installedVersion: "v26.3.27",
  runningVersion: "v26.3.27",
  targetVersion: "v26.3.27",
  serviceStatus: "RUNNING",
  desiredGeneration: 3,
  appliedGeneration: 3,
  configInSync: true,
  inboundCount: 2,
  hasUpgrade: false,
  isNewerThanTarget: false,
  lastReportedAt: new Date("2026-09-01T00:00:00Z"),
  lastErrorCode: null,
  lastErrorMessage: null,
  activeOperationId: null,
  activeOperationType: null,
  ...overrides,
});

test("runtime list renders catalog and all approved version states in desktop and mobile layouts", () => {
  const items = [
    runtime({ hostId: 1, hostName: "uninstalled", installedVersion: null, runningVersion: null, serviceStatus: "STOPPED" }),
    runtime({ hostId: 2, hostName: "current" }),
    runtime({ hostId: 3, hostName: "upgrade", installedVersion: "v25.1.1", runningVersion: "v25.1.1", hasUpgrade: true }),
    runtime({ hostId: 4, hostName: "newer", installedVersion: "v27.1.1", runningVersion: "v27.1.1", isNewerThanTarget: true }),
    runtime({ hostId: 5, hostName: "missing", unavailableReasonCode: "ARTIFACT_UNAVAILABLE", canManageXray: false }),
    runtime({ hostId: 6, hostName: "offline", isAgentOnline: false, serviceStatus: "STOPPED" }),
  ];
  const markup = renderToStaticMarkup(
    <XrayRuntimeList
      items={items as never}
      catalog={{ defaultVersion: "v26.3.27", artifacts: [{ os: "linux", arch: "amd64", verified: true }, { os: "linux", arch: "arm64", verified: false }] }}
      page={1}
      totalPages={2}
      totalItems={6}
      onPageChange={() => undefined}
      onAction={() => undefined}
      onOpenOperation={() => undefined}
    />,
  );
  for (const text of ["默认版本", "v26.3.27", "linux/amd64", "已验证", "linux/arm64", "缺失", "未安装", "当前版本", "可升级", "高于目标版本", "不自动降级", "缺少已验证制品"]) {
    assert.match(markup, new RegExp(text));
  }
  assert.match(markup, /Agent 离线，Xray 运行状态未知/);
  assert.match(markup, /grid gap-3[^\"]*xl:hidden/);
  assert.match(markup, /hidden overflow-x-auto xl:block/);
  assert.match(markup, /第 1 \/ 2 页/);
  assert.match(markup, />安装</);
  assert.match(markup, /升级至 v26\.3\.27/);
  assert.match(markup, />同步配置</);
  assert.match(markup, />重启</);
  assert.doesNotMatch(markup, /强制降级/);
});

test("runtime list exposes persistent active operation progress and disables offline actions", () => {
  const markup = renderToStaticMarkup(
    <XrayRuntimeList
      items={[
        runtime({ hostId: 1, hostName: "busy", activeOperationId: "upgrade-1", activeOperationType: "UPGRADE" }),
        runtime({ hostId: 2, hostName: "offline", isAgentOnline: false }),
      ] as never}
      catalog={{ defaultVersion: "v26.3.27", artifacts: [] }}
      page={1}
      totalPages={1}
      totalItems={2}
      onPageChange={() => undefined}
      onAction={() => undefined}
      onOpenOperation={() => undefined}
    />,
  );
  assert.match(markup, />查看进度</);
  assert.match(markup, /title="Agent 离线时不可操作"/);
  assert.match(markup, /disabled=""/);
});
