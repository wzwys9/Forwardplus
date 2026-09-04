import assert from "node:assert/strict";
import test from "node:test";

import {
  activeXrayQuickConfigReplacementProbeToken,
  initialXrayQuickConfigFlowState,
  reduceXrayQuickConfigFlow,
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
