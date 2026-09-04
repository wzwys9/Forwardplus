import assert from "node:assert/strict";
import test from "node:test";

import { isXrayUiFeatureEnabled } from "./xrayFeature";

test("pre-policy installations open the admin Xray UI even when an old installer wrote zero", () => {
  for (const value of [undefined, null, "", "0", "false", "off", "yes", true, 1]) {
    assert.equal(isXrayUiFeatureEnabled(value, false), true, String(value));
  }
});

test("the current default-on policy still honors a later explicit disable", () => {
  assert.equal(isXrayUiFeatureEnabled(undefined, true), true);
  for (const value of ["1", "true", "TRUE", "on", " ON "]) {
    assert.equal(isXrayUiFeatureEnabled(value, true), true, String(value));
  }
  for (const value of [null, "", "0", "false", "off", "yes", true, 1]) {
    assert.equal(isXrayUiFeatureEnabled(value, true), false, String(value));
  }
});
