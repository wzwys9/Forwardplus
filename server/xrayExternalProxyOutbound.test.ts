import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import type { XrayExternalProxyDefinition } from "../shared/xrayExternalProxy";
import {
  generateDeterministicXrayConfig,
  type XrayConfigInboundInput,
  type XrayExternalProxyBindingInput,
} from "./xrayConfigGenerator";

const privateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const publicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

function inbound(id: number): XrayConfigInboundInput {
  return {
    id,
    runtimeTag: `forwardx-inbound-external-${id}`,
    listenAddress: "0.0.0.0",
    listenPort: 24000 + id,
    protocol: "vless",
    transport: "tcp",
    security: "reality",
    profileId: "VLESS_RAW_REALITY_VISION",
    specVersion: 1,
    specJson: "{}",
    realityTargetHost: "www.microsoft.com",
    realityTargetPort: 443,
    realityServerName: "www.microsoft.com",
    realityPrivateKey: privateKey,
    isEnabled: true,
    pendingDelete: false,
    clients: [{
      id: 100 + id,
      uuid: `00000000-0000-4000-8000-${String(id).padStart(12, "0")}`,
      shortId: id.toString(16).padStart(2, "0"),
      statsKey: `forwardx-client-external-${id}`,
      flow: "xtls-rprx-vision",
      isEnabled: true,
      pendingDelete: false,
      sortOrder: 0,
    }],
  };
}

const vless: XrayExternalProxyDefinition = {
  protocol: "VLESS_REALITY_VISION",
  address: "vless.example.com",
  port: 443,
  displayName: "VLESS A",
  specVersion: 1,
  spec: { serverName: "cdn.example.com", fingerprint: "random", publicKey, spiderX: "/news" },
  credentials: { uuid: "00000000-0000-4000-8000-000000000501", shortId: "12ab" },
};
const shadowsocks: XrayExternalProxyDefinition = {
  protocol: "SHADOWSOCKS",
  address: "ss.example.com",
  port: 8388,
  displayName: "SS A",
  specVersion: 1,
  spec: { method: "aes-256-gcm" },
  credentials: { password: "secret" },
};
const socks: XrayExternalProxyDefinition = {
  protocol: "SOCKS5",
  address: "socks.example.com",
  port: 1080,
  displayName: "SOCKS A",
  specVersion: 1,
  spec: {},
  credentials: { username: "user", password: "pass" },
};

const tags = {
  vless: "forwardx-external-11111111-1111-4111-8111-111111111111",
  shadowsocks: "forwardx-external-22222222-2222-4222-8222-222222222222",
  socks: "forwardx-external-33333333-3333-4333-8333-333333333333",
};

function bindings(): XrayExternalProxyBindingInput[] {
  return [
    { inboundId: 1, nodeTag: tags.vless, definition: vless },
    { inboundId: 2, nodeTag: tags.vless, definition: vless },
    { inboundId: 3, nodeTag: tags.shadowsocks, definition: shadowsocks },
    { inboundId: 4, nodeTag: tags.socks, definition: socks },
  ];
}

test("external proxies compile once and route each bound inbound deterministically", () => {
  const inputs = [inbound(4), inbound(2), inbound(1), inbound(3)];
  const generated = generateDeterministicXrayConfig(inputs, bindings().reverse());
  const repeated = generateDeterministicXrayConfig([...inputs].reverse(), bindings());
  assert.equal(repeated.configJson, generated.configJson);
  assert.equal(repeated.configHash, generated.configHash);

  const config = JSON.parse(generated.configJson);
  assert.deepEqual(config.outbounds.map((outbound: { tag: string }) => outbound.tag), [
    "direct", tags.vless, tags.shadowsocks, tags.socks,
  ]);
  assert.deepEqual(config.routing.rules, [
    { type: "field", inboundTag: ["forwardx-inbound-external-1"], outboundTag: tags.vless },
    { type: "field", inboundTag: ["forwardx-inbound-external-2"], outboundTag: tags.vless },
    { type: "field", inboundTag: ["forwardx-inbound-external-3"], outboundTag: tags.shadowsocks },
    { type: "field", inboundTag: ["forwardx-inbound-external-4"], outboundTag: tags.socks },
  ]);
  assert.deepEqual(config.outbounds[1], {
    tag: tags.vless,
    protocol: "vless",
    settings: { vnext: [{ address: "vless.example.com", port: 443, users: [{
      id: vless.credentials.uuid, encryption: "none", flow: "xtls-rprx-vision",
    }] }] },
    streamSettings: {
      network: "tcp",
      security: "reality",
      realitySettings: {
        serverName: "cdn.example.com", fingerprint: "random", publicKey,
        shortId: "12ab", spiderX: "/news",
      },
    },
  });
  assert.deepEqual(config.outbounds[2].settings.servers, [{
    address: "ss.example.com", port: 8388, method: "aes-256-gcm", password: "secret",
  }]);
  assert.deepEqual(config.outbounds[3].settings.servers, [{
    address: "socks.example.com", port: 1080, users: [{ user: "user", pass: "pass" }],
  }]);
  assert.equal(config.outbounds.length, 4);
});

test("external proxy bindings fail closed for dangling, duplicate, and mutated identities", () => {
  const input = inbound(1);
  assert.throws(() => generateDeterministicXrayConfig([input], [{ ...bindings()[0], inboundId: 99 }]));
  assert.throws(() => generateDeterministicXrayConfig([input], [bindings()[0], bindings()[0]]));
  assert.throws(() => generateDeterministicXrayConfig([input], [{ ...bindings()[0], nodeTag: "direct" }]));
  assert.throws(() => generateDeterministicXrayConfig([input], [{
    ...bindings()[0],
    definition: { ...vless, spec: { ...vless.spec, fingerprint: "firefox" as "random" } },
  }]));
});

test("external proxy fixture passes the fixed Xray config test when a binary is provided", (t) => {
  const binary = process.env.XRAY_TEST_BINARY;
  if (!binary) return t.skip("XRAY_TEST_BINARY is not configured");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-external-outbound-"));
  const configPath = path.join(directory, "config.json");
  try {
    fs.writeFileSync(configPath, generateDeterministicXrayConfig(
      [inbound(1), inbound(2), inbound(3), inbound(4)], bindings(),
    ).configJson, { mode: 0o600 });
    const result = spawnSync(binary, ["run", "-test", "-config", configPath], { encoding: "utf8", timeout: 15_000 });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
