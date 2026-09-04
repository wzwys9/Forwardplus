import assert from "node:assert/strict";
import test from "node:test";
import {
  FORWARDPLUS_AGENT_DISTRIBUTION,
  doesAgentNeedUpgrade,
  isAgentUpgradeSatisfied,
  normalizeAgentBuildId,
  normalizeAgentDistribution,
} from "./agentIdentity";

test("distribution mismatch requires migration even when the real version is higher", () => {
  assert.equal(doesAgentNeedUpgrade({
    version: "9.0.0",
    distribution: null,
    targetVersion: "2.3.0",
  }), true);
  assert.equal(doesAgentNeedUpgrade({
    version: "9.0.0",
    distribution: "forwardx",
    targetVersion: "2.3.0",
  }), true);
});

test("current distribution still requires an upgrade when its real version is behind", () => {
  assert.equal(doesAgentNeedUpgrade({
    version: "2.2.192",
    distribution: FORWARDPLUS_AGENT_DISTRIBUTION,
    targetVersion: "2.3.0",
  }), true);
  assert.equal(doesAgentNeedUpgrade({
    version: "2.3.0",
    distribution: FORWARDPLUS_AGENT_DISTRIBUTION,
    targetVersion: "2.3.0",
  }), false);
});

test("upgrade completion requires both the target distribution and version", () => {
  assert.equal(isAgentUpgradeSatisfied({
    version: "9.0.0",
    distribution: null,
    targetVersion: "2.3.0",
  }), false);
  assert.equal(isAgentUpgradeSatisfied({
    version: "2.3.0",
    distribution: FORWARDPLUS_AGENT_DISTRIBUTION,
    targetVersion: "2.3.0",
  }), true);
});

test("identity normalization accepts only bounded canonical values", () => {
  assert.equal(normalizeAgentDistribution(" FORWARDPLUS "), FORWARDPLUS_AGENT_DISTRIBUTION);
  assert.equal(normalizeAgentDistribution("other-build"), null);
  assert.equal(normalizeAgentBuildId(" 0123456789ab "), "0123456789ab");
  assert.equal(normalizeAgentBuildId("bad build id"), null);
  assert.equal(normalizeAgentBuildId("a".repeat(65)), null);
});
