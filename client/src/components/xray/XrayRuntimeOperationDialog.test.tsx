import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";

import { XrayRuntimeOperationConfirmation, type XrayRuntimeActionSelection } from "./XrayRuntimeOperationDialog";

const runtime = {
  hostId: 7, hostName: "edge-upgrade", isAgentOnline: true, capabilityVersion: 1, canManageXray: true,
  unavailableReasonCode: null, installedVersion: "v25.1.1", runningVersion: "v25.1.1", targetVersion: "v26.3.27",
  serviceStatus: "RUNNING", desiredGeneration: 4, appliedGeneration: 4, configInSync: true, inboundCount: 2,
  hasUpgrade: true, isNewerThanTarget: false, activeOperationId: null, activeOperationType: null,
  lastReportedAt: new Date("2026-09-01T00:00:00Z"), lastErrorCode: null, lastErrorMessage: null,
} as const;

function render(action: XrayRuntimeActionSelection["action"], confirmation = "") {
  return renderToStaticMarkup(
    <XrayRuntimeOperationConfirmation
      selection={{ runtime: runtime as never, action }}
      confirmation={confirmation}
      onConfirmationChange={() => undefined}
      onSubmit={() => undefined}
      pending={false}
      errorCode={null}
    />,
  );
}

test("runtime mutation confirmation requires the exact host name and explains version safety", () => {
  const upgrade = render("UPGRADE");
  assert.match(upgrade, /此操作会改变远端运行环境/);
  assert.match(upgrade, /edge-upgrade/);
  assert.match(upgrade, /v25\.1\.1/);
  assert.match(upgrade, /v26\.3\.27/);
  assert.match(upgrade, /disabled=""/);
  assert.doesNotMatch(render("UPGRADE", "edge-upgrade"), /disabled=""/);
  assert.match(render("SYNC"), /普通同步不会安装新版本，也不会降级更高版本/);
  assert.match(render("RESTART"), /只重启 ForwardX 管理的 Xray 子进程/);
});
