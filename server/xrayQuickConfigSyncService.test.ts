import assert from "node:assert/strict";
import test from "node:test";

import {
  decideQuickConfigDnsSyncAction,
  isQuickConfigRuleSynchronized,
  isXrayQuickConfigSyncOperation,
} from "./xrayQuickConfigSyncService";

const expected = {
  providerRecordId: "101",
  relativeName: "fdafa",
  recordType: "A" as const,
  providerLineId: "0",
  value: "82.109.96.234",
  ttl: 600,
};

test("quick-config DNS sync keeps, repairs and recreates only provably owned records", () => {
  assert.equal(decideQuickConfigDnsSyncAction({
    expected,
    current: { ...expected, subdomain: expected.relativeName, lineName: "默认", status: "ENABLE" },
    exactMatches: [],
    createIntentRunning: false,
  }), "KEEP");

  assert.equal(decideQuickConfigDnsSyncAction({
    expected,
    current: { ...expected, subdomain: expected.relativeName, lineName: "默认", status: "ENABLE", value: "203.0.113.7" },
    exactMatches: [],
    createIntentRunning: false,
  }), "REPAIR");

  assert.equal(decideQuickConfigDnsSyncAction({
    expected,
    current: null,
    exactMatches: [],
    createIntentRunning: false,
  }), "CREATE");
});

test("quick-config DNS sync does not adopt unrelated records or overwrite a moved record", () => {
  const unrelatedExact = { ...expected, providerRecordId: "202", subdomain: expected.relativeName, lineName: "默认", status: "ENABLE" };
  assert.equal(decideQuickConfigDnsSyncAction({
    expected,
    current: null,
    exactMatches: [unrelatedExact],
    createIntentRunning: false,
  }), "CONFLICT");

  assert.equal(decideQuickConfigDnsSyncAction({
    expected,
    current: { ...expected, subdomain: "other", lineName: "默认", status: "ENABLE" },
    exactMatches: [],
    createIntentRunning: false,
  }), "CONFLICT");

  assert.equal(decideQuickConfigDnsSyncAction({
    expected,
    current: null,
    exactMatches: [unrelatedExact],
    createIntentRunning: true,
  }), "ADOPT_CREATED");

  assert.equal(decideQuickConfigDnsSyncAction({
    expected,
    current: { ...expected, subdomain: expected.relativeName, lineName: "默认", status: "ENABLE" },
    exactMatches: [
      { ...expected, subdomain: expected.relativeName, lineName: "默认", status: "ENABLE" },
      { ...expected, providerRecordId: "303", subdomain: expected.relativeName, lineName: "默认", status: "ENABLE" },
    ],
    createIntentRunning: false,
  }), "CONFLICT");
});

test("quick-config rule sync requires the complete controlled rule shape", () => {
  const rule = {
    xrayQuickConfigId: 7, userId: 1, hostId: 2, forwardType: "realm", protocol: "tcp", gostMode: "direct",
    sourcePort: 5326, targetIp: "82.109.96.231", targetPort: 63518, targetExternalProxyNodeId: null,
    gostRelayHost: null, gostRelayPort: null, tunnelId: null, tunnelExitPort: null, forwardGroupId: null,
    forwardGroupRuleId: null, forwardGroupMemberId: null, isForwardGroupTemplate: false, telegramErrorNotifyEnabled: false,
    isEnabled: true, pendingDelete: false, disabledByTunnel: false, disabledByGroup: false, disabledByUser: false,
    protocolBlockReason: null, proxyProtocolReceive: false, proxyProtocolSend: false,
    proxyProtocolExitReceive: false, proxyProtocolExitSend: false, proxyProtocolVersion: 1,
    blockHttp: false, blockSocks: false, blockTls: false, tcpFastOpen: false, zeroCopy: false,
    udpOverTcp: false, udpOverTcpPort: null, failoverEnabled: false, failoverStrategy: "fallback",
    failoverTargets: null, failoverSeconds: 60, recoverSeconds: 120, autoFailback: true,
  };
  const expectedRule = { quickConfigId: 7, userId: 1, hostId: 2, engine: "realm" as const, publicPort: 5326,
    targetAddress: "82.109.96.231", targetPort: 63518 };
  assert.equal(isQuickConfigRuleSynchronized(rule, expectedRule), true);
  assert.equal(isQuickConfigRuleSynchronized({ ...rule, targetPort: 443 }, expectedRule), false);
  assert.equal(isQuickConfigRuleSynchronized({ ...rule, failoverEnabled: true }, expectedRule), false);
  assert.equal(isQuickConfigRuleSynchronized({ ...rule, userId: 2 }, expectedRule), false);
});

test("quick-config sync operation discriminator rejects unapproved summary fields", () => {
  assert.equal(isXrayQuickConfigSyncOperation({
    type: "EDIT", requestSummaryJson: JSON.stringify({ kind: "CONFIG_SYNC", schemaVersion: 1 }),
  }), true);
  assert.equal(isXrayQuickConfigSyncOperation({
    type: "EDIT", requestSummaryJson: JSON.stringify({ kind: "CONFIG_SYNC", schemaVersion: 1, payload: "unexpected" }),
  }), false);
});
