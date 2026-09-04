import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";

import { XrayHostRuntimeLink } from "./XrayHostRuntimeLink";

const runtime = {
  hostId: 7,
  hostName: "edge-07",
  isAgentOnline: true,
  capabilityVersion: 1,
  canManageXray: true,
  unavailableReasonCode: null,
  installedVersion: "v26.3.27",
  runningVersion: "v26.3.27",
  targetVersion: "v26.3.27",
  serviceStatus: "RUNNING",
  desiredGeneration: 4,
  appliedGeneration: 4,
  configInSync: true,
  inboundCount: 4,
  hasUpgrade: false,
  isNewerThanTarget: false,
  lastReportedAt: new Date("2026-09-01T00:00:00Z"),
  lastErrorCode: null,
  lastErrorMessage: null,
};

test("host card Xray summary is a compact link to the filtered runtime page", () => {
  const markup = renderToStaticMarkup(<XrayHostRuntimeLink runtime={runtime as never} />);
  assert.match(markup, /Xray：v26\.3\.27 · 运行中 · 4 个节点/);
  assert.match(markup, /href="\/xray\?tab=runtime&amp;hostId=7"/);
  assert.doesNotMatch(markup, /安装|升级|重启|重新同步/);
});

test("host card never presents an offline Agent as stopped", () => {
  const markup = renderToStaticMarkup(
    <XrayHostRuntimeLink runtime={{ ...runtime, isAgentOnline: false, serviceStatus: "STOPPED" } as never} />,
  );
  assert.match(markup, /运行状态未知/);
  assert.doesNotMatch(markup, /已停止/);
});
