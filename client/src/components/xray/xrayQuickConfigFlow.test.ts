import assert from "node:assert/strict";
import test from "node:test";

import {
  activeXrayQuickConfigReplacementProbeToken,
  initialXrayQuickConfigFlowState,
  reduceXrayQuickConfigFlow,
  xrayQuickConfigEditIdentity,
  type XrayQuickConfigFlowState,
  type XrayQuickConfigPortSuccess,
} from "./xrayQuickConfigFlow";

const success = {
  status: "SUCCESS",
  selectedPort: 14000,
  rewritten: false,
  probeResultToken: "qcp1.old.signature",
  expiresAt: "2099-01-01T00:00:00.000Z",
  defaultRouteCandidates: [],
} satisfies XrayQuickConfigPortSuccess;

function successfulState(): XrayQuickConfigFlowState {
  return reduceXrayQuickConfigFlow({
    ...initialXrayQuickConfigFlowState(),
    confirmedDomainToken: "confirmed-domain-token",
    confirmedDomainExpiresAt: "2099-01-01T00:00:00.000Z",
    carrierEndpoints: {
      TELECOM: ["1:IPV4"],
      UNICOM: ["1:IPV4"],
      MOBILE: ["1:IPV4"],
      EDUCATION: ["1:IPV4"],
    },
    engine: "realm",
    step: "PORT",
    furthestStepIndex: 3,
  }, { type: "PORT_CHECK_FINISHED", result: success });
}

test("quick config keeps the previous signed probe result while engine changes and clears it after a new check starts", () => {
  const changed = reduceXrayQuickConfigFlow(successfulState(), { type: "SET_ENGINE", engine: "gost" });
  assert.equal(changed.portResult, null);
  assert.deepEqual(changed.replaceProbeResult, {
    token: success.probeResultToken,
    expiresAt: success.expiresAt,
  });
  assert.equal(activeXrayQuickConfigReplacementProbeToken(changed, Date.parse("2098-01-01T00:00:00.000Z")), success.probeResultToken);
  assert.equal(activeXrayQuickConfigReplacementProbeToken(changed, Date.parse(success.expiresAt)), undefined);

  const started = reduceXrayQuickConfigFlow(changed, { type: "PORT_CHECK_STARTED", portCheckId: "new-port-check" });
  assert.equal(started.replaceProbeResult, null);
});

test("quick config retains the last probe token when the port check is explicitly cleared", () => {
  const cleared = reduceXrayQuickConfigFlow(successfulState(), { type: "CLEAR_PORT_CHECK" });
  assert.deepEqual(cleared.replaceProbeResult, {
    token: success.probeResultToken,
    expiresAt: success.expiresAt,
  });
});

test("quick config domain checks send only the strict edit identity", () => {
  assert.deepEqual(xrayQuickConfigEditIdentity({
    quickConfigId: 9,
    expectedRevision: 3,
    zoneId: 4,
    relativeName: "edge",
    carrierEndpoints: { TELECOM: [], UNICOM: [], MOBILE: [], EDUCATION: [] },
    engine: "realm",
    publicPort: 5326,
    defaultRoutes: [],
  }), {
    quickConfigId: 9,
    expectedRevision: 3,
  });
});

test("editing domain modes invalidate authorization and probes while preserving the user's route draft", () => {
  const state = { ...successfulState(), editDomainMode: "KEEP" as const, manualPort: "5326" };
  const changed = reduceXrayQuickConfigFlow(state, {
    type: "SET_DOMAIN_MODE", mode: "CHANGE", zoneId: 4, relativeName: "new",
  });
  assert.equal(changed.editDomainMode, "CHANGE");
  assert.equal(changed.confirmedDomainToken, null);
  assert.equal(changed.portResult, null);
  assert.equal(changed.preview, null);
  assert.deepEqual(changed.carrierEndpoints, state.carrierEndpoints);
  assert.equal(changed.engine, state.engine);
  assert.equal(changed.manualPort, "5326");
  const restored = reduceXrayQuickConfigFlow(changed, {
    type: "SET_DOMAIN_MODE", mode: "KEEP", zoneId: 4, relativeName: "original",
  });
  assert.equal(restored.relativeName, "original");
  assert.equal(restored.confirmedDomainToken, null);
  assert.deepEqual(restored.carrierEndpoints, state.carrierEndpoints);
});
