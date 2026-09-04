import assert from "node:assert/strict";
import test from "node:test";

import { isXrayUiFeatureEnabled } from "./xrayFeature";

test("the Xray UI feature flag is fail-closed and accepts only explicit true values", () => {
  for (const value of [undefined, null, "", "0", "false", "off", "yes", true, 1]) {
    assert.equal(isXrayUiFeatureEnabled(value), false, String(value));
  }
  for (const value of ["1", "true", "TRUE", "on", " ON "]) {
    assert.equal(isXrayUiFeatureEnabled(value), true, String(value));
  }
});
