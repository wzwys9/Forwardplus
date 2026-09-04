import assert from "node:assert/strict";
import test from "node:test";
import { agentDistributionLabel, formatBytes, isAgentUpgradeNeeded } from "./hostDisplay";

test("formatBytes clamps values at the largest supported unit", () => {
  assert.equal(formatBytes(1024 ** 5), "1 PB");
  assert.equal(formatBytes(1024 ** 6), "1024 PB");
});

test("formatBytes handles non-finite values", () => {
  assert.equal(formatBytes(Number.POSITIVE_INFINITY), "0 B");
  assert.equal(formatBytes(Number.NaN), "0 B");
});

test("Agent update display keeps the real version separate from distribution migration", () => {
  assert.equal(isAgentUpgradeNeeded({ agentVersion: "9.0.0", agentDistribution: null }, "2.3.0"), true);
  assert.equal(isAgentUpgradeNeeded({ agentVersion: "2.3.0", agentDistribution: "forwardplus" }, "2.3.0"), false);
  assert.equal(agentDistributionLabel(null), "来源未确认");
  assert.equal(agentDistributionLabel("forwardplus"), "Forwardplus");
});
