import assert from "node:assert/strict";
import test from "node:test";

import {
  XRAY_ACCESS_SETTINGS_MAX_BYTES,
  accessSecretPolicyForCredentialType,
  isXrayInboundSecretKind,
  parseStoredXrayAccessSettings,
} from "./xrayAccess";

test("access settings accept only versioned strict shapes for every credential type", () => {
  const valid = [
    ["UUID_AND_SHORT_ID", { schemaVersion: 1, flow: "XTLS_RPRX_VISION" }],
    ["UUID", { schemaVersion: 1, flow: "NONE", security: "AUTO" }],
    ["UUID", { schemaVersion: 2, protocol: "VLESS", encryption: "NONE", flow: "NONE" }],
    ["UUID", { schemaVersion: 2, protocol: "VLESS", encryption: "NONE", flow: "XTLS_RPRX_VISION" }],
    ["PASSWORD", { schemaVersion: 1 }],
    ["SHADOWSOCKS_KEY", { schemaVersion: 1 }],
    ["HYSTERIA_AUTH", { schemaVersion: 1 }],
    ["HTTP_BASIC", { schemaVersion: 1 }],
    ["MIXED_USER_PASSWORD", { schemaVersion: 1 }],
    ["WIREGUARD_PEER", { schemaVersion: 1 }],
    ["WIREGUARD_PEER", { schemaVersion: 2, address: "10.0.0.2/32" }],
  ] as const;

  for (const [credentialType, settings] of valid) {
    assert.deepEqual(
      parseStoredXrayAccessSettings({ credentialType, settingsJson: JSON.stringify(settings) }),
      { credentialType, ...settings },
    );
  }
});

test("access settings reject mismatched, unknown, arbitrary Xray, and oversized input", () => {
  const invalid = [
    { credentialType: "UNKNOWN", settingsJson: '{"schemaVersion":1}' },
    { credentialType: "UUID", settingsJson: '{"schemaVersion":1,"flow":"XTLS_RPRX_VISION","security":"AUTO"}' },
    { credentialType: "UUID", settingsJson: '{"schemaVersion":2,"protocol":"VMESS","encryption":"NONE","flow":"NONE"}' },
    { credentialType: "UUID", settingsJson: '{"schemaVersion":2,"protocol":"VLESS","encryption":"AUTO","flow":"NONE"}' },
    { credentialType: "UUID", settingsJson: '{"schemaVersion":2,"protocol":"VLESS","encryption":"NONE","flow":"NONE","security":"AUTO"}' },
    { credentialType: "UUID", settingsJson: '{"schemaVersion":2,"protocol":"VLESS","encryption":"NONE","flow":"VISION"}' },
    { credentialType: "PASSWORD", settingsJson: '{"schemaVersion":1,"password":"plaintext"}' },
    { credentialType: "PASSWORD", settingsJson: '{"schemaVersion":1,"inbounds":[]}' },
    { credentialType: "PASSWORD", settingsJson: "not-json" },
    { credentialType: "PASSWORD", settingsJson: "{}".padEnd(XRAY_ACCESS_SETTINGS_MAX_BYTES + 1, " ") },
    { credentialType: "HTTP_BASIC", settingsJson: '{"schemaVersion":1,"username":"plaintext"}' },
    { credentialType: "MIXED_USER_PASSWORD", settingsJson: '{"schemaVersion":1,"udp":true}' },
    { credentialType: "WIREGUARD_PEER", settingsJson: '{"schemaVersion":2,"address":"10.0.0.1/32"}' },
    { credentialType: "WIREGUARD_PEER", settingsJson: '{"schemaVersion":2,"address":"10.0.0.02/32"}' },
  ];

  for (const input of invalid) assert.equal(parseStoredXrayAccessSettings(input), null);
});

test("credential policies define exact required and optional secret kinds", () => {
  assert.deepEqual(accessSecretPolicyForCredentialType("UUID_AND_SHORT_ID"), {
    required: ["UUID", "SHORT_ID"],
    optional: [],
  });
  assert.deepEqual(accessSecretPolicyForCredentialType("PASSWORD"), {
    required: ["PASSWORD"],
    optional: ["SHORT_ID"],
  });
  assert.deepEqual(accessSecretPolicyForCredentialType("SHADOWSOCKS_KEY"), {
    required: ["SHADOWSOCKS_KEY"],
    optional: [],
  });
  assert.deepEqual(accessSecretPolicyForCredentialType("WIREGUARD_PEER"), {
    required: ["PRIVATE_KEY", "PRE_SHARED_KEY"],
    optional: [],
  });
  assert.deepEqual(accessSecretPolicyForCredentialType("HTTP_BASIC"), {
    required: ["USERNAME", "PASSWORD"],
    optional: [],
  });
  assert.deepEqual(accessSecretPolicyForCredentialType("MIXED_USER_PASSWORD"), {
    required: ["USERNAME", "PASSWORD"],
    optional: [],
  });
  assert.equal(isXrayInboundSecretKind("SHADOWSOCKS_SERVER_KEY"), true);
  assert.equal(accessSecretPolicyForCredentialType("UNKNOWN"), null);
});
