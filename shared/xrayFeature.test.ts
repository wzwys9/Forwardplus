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

test("a durable ForwardX migration marker recovers only a missing Xray UI flag", () => {
  assert.equal(isXrayUiFeatureEnabled(undefined, true), true);
  assert.equal(isXrayUiFeatureEnabled(undefined, false), false);

  for (const explicitValue of [null, "", "0", "false", "off", "yes", true, 1]) {
    assert.equal(
      isXrayUiFeatureEnabled(explicitValue, true),
      false,
      `explicit ${String(explicitValue)} must override the migration fallback`,
    );
  }
});
