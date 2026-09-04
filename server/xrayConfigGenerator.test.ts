import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  generateDeterministicXrayConfig,
  type XrayConfigInboundInput,
} from "./xrayConfigGenerator";

const privateKeyA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const privateKeyB = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";

function fixtures(): XrayConfigInboundInput[] {
  return [
    {
      id: 20,
      runtimeTag: "forwardx-inbound-b",
      listenAddress: "0.0.0.0",
      listenPort: 24444,
      protocol: "vless",
      transport: "tcp",
      security: "reality",
      realityTargetHost: "www.cloudflare.com",
      realityTargetPort: 443,
      realityServerName: "www.cloudflare.com",
      realityPrivateKey: privateKeyB,
      isEnabled: true,
      pendingDelete: false,
      clients: [
        {
          id: 202,
          uuid: "00000000-0000-4000-8000-000000000202",
          shortId: "0202",
          statsKey: "fwdx-client-202",
          flow: "xtls-rprx-vision",
          isEnabled: false,
          pendingDelete: false,
          sortOrder: 0,
        },
        {
          id: 201,
          uuid: "00000000-0000-4000-8000-000000000201",
          shortId: "0201",
          statsKey: "fwdx-client-201",
          flow: "xtls-rprx-vision",
          isEnabled: true,
          pendingDelete: false,
          sortOrder: 10,
        },
      ],
    },
    {
      id: 10,
      runtimeTag: "forwardx-inbound-a",
      listenAddress: "0.0.0.0",
      listenPort: 23456,
      protocol: "vless",
      transport: "tcp",
      security: "reality",
      realityTargetHost: "www.microsoft.com",
      realityTargetPort: 443,
      realityServerName: "www.microsoft.com",
      realityPrivateKey: privateKeyA,
      isEnabled: true,
      pendingDelete: false,
      clients: [
        {
          id: 102,
          uuid: "00000000-0000-4000-8000-000000000102",
          shortId: "0102",
          statsKey: "fwdx-client-102",
          flow: "xtls-rprx-vision",
          isEnabled: true,
          pendingDelete: true,
          sortOrder: 0,
        },
        {
          id: 103,
          uuid: "00000000-0000-4000-8000-000000000103",
          shortId: "0103",
          statsKey: "fwdx-client-103",
          flow: "xtls-rprx-vision",
          isEnabled: true,
          pendingDelete: false,
          sortOrder: 20,
        },
        {
          id: 101,
          uuid: "00000000-0000-4000-8000-000000000101",
          shortId: "0101",
          statsKey: "fwdx-client-101",
          flow: "xtls-rprx-vision",
          isEnabled: true,
          pendingDelete: false,
          sortOrder: 10,
        },
      ],
    },
    {
      id: 30,
      runtimeTag: "forwardx-inbound-deleted",
      listenAddress: "0.0.0.0",
      listenPort: 25555,
      protocol: "vless",
      transport: "tcp",
      security: "reality",
      realityTargetHost: "deleted.example.com",
      realityTargetPort: 443,
      realityServerName: "deleted.example.com",
      realityPrivateKey: "deleted-private-key-marker",
      isEnabled: true,
      pendingDelete: true,
      clients: [],
    },
  ];
}

function grpcFixture(): XrayConfigInboundInput {
  return {
    id: 40,
    runtimeTag: "forwardx-inbound-grpc",
    listenAddress: "0.0.0.0",
    listenPort: 26666,
    protocol: "vless",
    transport: "grpc",
    security: "reality",
    profileId: "VLESS_GRPC_REALITY",
    specVersion: 1,
    specJson: '{"serviceName":"forwardx-grpc"}',
    realityTargetHost: "www.cloudflare.com",
    realityTargetPort: 443,
    realityServerName: "www.cloudflare.com",
    realityPrivateKey: privateKeyB,
    isEnabled: true,
    pendingDelete: false,
    clients: [{
      id: 401,
      uuid: "00000000-0000-4000-8000-000000000401",
      shortId: "0401",
      statsKey: "fwdx-client-401",
      flow: "",
      isEnabled: true,
      pendingDelete: false,
      sortOrder: 0,
    }],
  };
}

function xhttpFixture(): XrayConfigInboundInput {
  return {
    id: 50,
    runtimeTag: "forwardx-inbound-xhttp",
    listenAddress: "0.0.0.0",
    listenPort: 27777,
    protocol: "vless",
    transport: "xhttp",
    security: "reality",
    profileId: "VLESS_XHTTP_REALITY",
    specVersion: 1,
    specJson: '{"path":"/forwardx/xhttp-v1"}',
    realityTargetHost: "www.cloudflare.com",
    realityTargetPort: 443,
    realityServerName: "www.cloudflare.com",
    realityPrivateKey: privateKeyA,
    isEnabled: true,
    pendingDelete: false,
    clients: [{
      id: 501,
      uuid: "00000000-0000-4000-8000-000000000501",
      shortId: "0501",
      statsKey: "fwdx-client-501",
      flow: "",
      isEnabled: true,
      pendingDelete: false,
      sortOrder: 0,
    }],
  };
}

function trojanFixture(): XrayConfigInboundInput {
  return {
    id: 60,
    runtimeTag: "forwardx-inbound-trojan",
    listenAddress: "0.0.0.0",
    listenPort: 28888,
    protocol: "trojan",
    transport: "tcp",
    security: "reality",
    profileId: "TROJAN_RAW_REALITY",
    specVersion: 1,
    specJson: '{}',
    realityTargetHost: "www.cloudflare.com",
    realityTargetPort: 443,
    realityServerName: "www.cloudflare.com",
    realityPrivateKey: privateKeyB,
    isEnabled: true,
    pendingDelete: false,
    clients: [{
      id: 601,
      credentialType: "PASSWORD",
      password: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      shortId: "0601",
      statsKey: "fwdx-client-601",
      isEnabled: true,
      pendingDelete: false,
      sortOrder: 0,
    }],
  };
}

test("VLESS gRPC Reality compiles without Vision and coexists in a deterministic host snapshot", () => {
  const result = generateDeterministicXrayConfig([grpcFixture(), fixtures()[0]]);
  const parsed = JSON.parse(result.configJson);
  const grpc = parsed.inbounds.find((inbound: { tag: string }) => inbound.tag === "forwardx-inbound-grpc");
  assert.deepEqual(grpc.settings.clients, [{
    id: "00000000-0000-4000-8000-000000000401",
    email: "fwdx-client-401",
  }]);
  assert.deepEqual(grpc.streamSettings, {
    network: "grpc",
    security: "reality",
    realitySettings: {
      show: false,
      dest: "www.cloudflare.com:443",
      xver: 0,
      serverNames: ["www.cloudflare.com"],
      privateKey: privateKeyB,
      shortIds: ["0401"],
    },
    grpcSettings: { serviceName: "forwardx-grpc", multiMode: false },
  });
  assert.equal(result.configJson.includes("\"flow\": \"\""), false);
  assert.deepEqual(result.expectedListeners.map((listener) => listener.port), [24444, 26666]);

  for (const inbound of [
    { ...grpcFixture(), profileId: null, specVersion: null, specJson: null },
    { ...grpcFixture(), clients: [{ ...grpcFixture().clients[0], flow: "xtls-rprx-vision" }] },
    { ...grpcFixture(), specJson: '{"serviceName":"bad/name"}' },
  ]) {
    assert.throws(() => generateDeterministicXrayConfig([inbound as XrayConfigInboundInput]), /Xray configuration input is invalid/);
  }
});

test("VLESS XHTTP Reality compiles only the fixed auto-mode profile", () => {
  const result = generateDeterministicXrayConfig([xhttpFixture(), grpcFixture(), fixtures()[0]]);
  const parsed = JSON.parse(result.configJson);
  const inbound = parsed.inbounds.find((entry: { tag: string }) => entry.tag === "forwardx-inbound-xhttp");
  assert.deepEqual(inbound.settings.clients, [{
    id: "00000000-0000-4000-8000-000000000501",
    email: "fwdx-client-501",
  }]);
  assert.deepEqual(inbound.streamSettings, {
    network: "xhttp",
    security: "reality",
    realitySettings: {
      show: false,
      dest: "www.cloudflare.com:443",
      xver: 0,
      serverNames: ["www.cloudflare.com"],
      privateKey: privateKeyA,
      shortIds: ["0501"],
    },
    xhttpSettings: { path: "/forwardx/xhttp-v1", mode: "auto" },
  });
  assert.deepEqual(result.expectedListeners.map((listener) => listener.port), [24444, 26666, 27777]);
  for (const specJson of [
    '{"path":"relative"}',
    '{"path":"/ok","mode":"packet-up"}',
  ]) {
    assert.throws(() => generateDeterministicXrayConfig([{ ...xhttpFixture(), specJson }]), /Xray configuration input is invalid/);
  }
});

test("Trojan RAW Reality compiles generic password accounts without VLESS fields", () => {
  const result = generateDeterministicXrayConfig([trojanFixture(), xhttpFixture(), fixtures()[0]]);
  const parsed = JSON.parse(result.configJson);
  const inbound = parsed.inbounds.find((entry: { tag: string }) => entry.tag === "forwardx-inbound-trojan");
  assert.deepEqual(inbound.settings.clients, [{
    password: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    email: "fwdx-client-601",
  }]);
  assert.equal(inbound.protocol, "trojan");
  assert.equal(inbound.streamSettings.network, "tcp");
  assert.deepEqual(inbound.streamSettings.realitySettings.shortIds, ["0601"]);
  assert.equal(result.configJson.includes('"id": "BBBB'), false);
  assert.equal(result.configJson.includes('"flow"'), true);
  for (const clients of [
    [{ ...trojanFixture().clients[0], password: "short" }],
    [{ ...trojanFixture().clients[0], credentialType: "UUID_AND_SHORT_ID", uuid: "00000000-0000-4000-8000-000000000601", flow: "" }],
  ]) {
    assert.throws(() => generateDeterministicXrayConfig([{ ...trojanFixture(), clients } as XrayConfigInboundInput]), /Xray configuration input is invalid/);
  }
});

test("Xray config generation is byte-stable and excludes disabled or pending records", () => {
  const first = generateDeterministicXrayConfig(fixtures());
  const reversed = fixtures().reverse().map((inbound) => ({ ...inbound, clients: [...inbound.clients].reverse() }));
  const second = generateDeterministicXrayConfig(reversed);

  assert.equal(first.targetVersion, "v26.3.27");
  assert.equal(first.configJson, second.configJson);
  assert.equal(first.configHash, second.configHash);
  assert.equal(first.configHash, crypto.createHash("sha256").update(first.configJson, "utf8").digest("hex"));
  assert.ok(first.configJson.endsWith("\n"));
  assert.equal(Buffer.byteLength(first.configJson, "utf8") <= 1024 * 1024, true);
  assert.equal(first.configJson.includes("deleted-private-key-marker"), false);
  assert.equal(first.configJson.includes("00000000-0000-4000-8000-000000000102"), false);
  assert.equal(first.configJson.includes("00000000-0000-4000-8000-000000000202"), false);

  const parsed = JSON.parse(first.configJson);
  assert.deepEqual(parsed.log, { loglevel: "warning" });
  assert.deepEqual(parsed.inbounds.map((inbound: { tag: string }) => inbound.tag), [
    "forwardx-inbound-a",
    "forwardx-inbound-b",
  ]);
  assert.deepEqual(parsed.inbounds[0].settings.clients, [
    { id: "00000000-0000-4000-8000-000000000101", email: "fwdx-client-101", flow: "xtls-rprx-vision" },
    { id: "00000000-0000-4000-8000-000000000103", email: "fwdx-client-103", flow: "xtls-rprx-vision" },
  ]);
  assert.deepEqual(parsed.inbounds[0].streamSettings.realitySettings, {
    show: false,
    dest: "www.microsoft.com:443",
    xver: 0,
    serverNames: ["www.microsoft.com"],
    privateKey: privateKeyA,
    shortIds: ["0101", "0103"],
  });
  assert.deepEqual(parsed.outbounds, [{ tag: "direct", protocol: "freedom" }]);
  assert.deepEqual(first.expectedListeners, [
    { inboundId: 10, runtimeTag: "forwardx-inbound-a", network: "tcp", listenAddress: "0.0.0.0", port: 23456 },
    { inboundId: 20, runtimeTag: "forwardx-inbound-b", network: "tcp", listenAddress: "0.0.0.0", port: 24444 },
  ]);
});

test("Xray config generation rejects unsupported or ambiguous structured values", () => {
  const base = fixtures()[0];
  const invalid = [
    { ...base, protocol: "vmess" },
    { ...base, transport: "ws" },
    { ...base, security: "none" },
    { ...base, listenAddress: "127.0.0.1" },
    { ...base, listenPort: 999 },
    { ...base, realityTargetPort: 0 },
    { ...base, runtimeTag: "bad tag" },
    { ...base, realityTargetHost: "http://example.com" },
    { ...base, realityServerName: "*.example.com" },
    { ...base, realityPrivateKey: "not-a-key" },
    { ...base, realityPrivateKey: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" },
    { ...base, clients: [{ ...base.clients[1], uuid: "not-a-uuid" }] },
    { ...base, clients: [{ ...base.clients[1], shortId: "abc" }] },
    { ...base, clients: [{ ...base.clients[1], statsKey: "secret@example.com" }] },
    { ...base, clients: [{ ...base.clients[1], flow: "none" }] },
  ];
  for (const inbound of invalid) {
    assert.throws(() => generateDeterministicXrayConfig([inbound as XrayConfigInboundInput]), /Xray configuration input is invalid/);
  }
  assert.throws(() => generateDeterministicXrayConfig([base, { ...base }]), /Xray configuration input is invalid/);
  assert.throws(() => generateDeterministicXrayConfig([{ ...base, clients: [base.clients[1], { ...base.clients[1] }] }]), /Xray configuration input is invalid/);
});

test("an enabled inbound remains deterministic when all clients are disabled", () => {
  const inbound = fixtures()[0];
  const result = generateDeterministicXrayConfig([{ ...inbound, clients: inbound.clients.map((client) => ({ ...client, isEnabled: false })) }]);
  const parsed = JSON.parse(result.configJson);
  assert.deepEqual(parsed.inbounds[0].settings.clients, []);
  assert.deepEqual(parsed.inbounds[0].streamSettings.realitySettings.shortIds, [""]);
  assert.equal(result.expectedListeners.length, 1);
});

test("an empty host produces a valid stopped-state config identity", () => {
  const result = generateDeterministicXrayConfig([]);
  assert.deepEqual(JSON.parse(result.configJson).inbounds, []);
  assert.deepEqual(result.expectedListeners, []);
  assert.match(result.configHash, /^[0-9a-f]{64}$/);
});

test("host config loading decrypts only active records with stable AAD", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-config-generator-"));
  const databasePath = path.join(directory, "config.db");
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const secrets = await import(moduleUrl("server/xraySecretCrypto.ts"));
    const accessMigration = await import(moduleUrl("server/xrayAccessMigration.ts"));
    const generator = await import(moduleUrl("server/xrayConfigGenerator.ts"));
    const keyring = secrets.createXraySecretKeyring({ currentKeyId: "1", keys: { "1": Buffer.alloc(32, 7) } });
    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, userId) VALUES (10, 'edge', '192.0.2.10', 1)");
      const inboundContext = generator.xrayInboundPrivateKeyContext("forwardx-inbound-db");
      const privateEnvelope = secrets.encryptXraySecret(${JSON.stringify(privateKeyA)}, inboundContext, keyring);
      const disabledPrivateEnvelope = secrets.encryptXraySecret("disabled-private-key-marker", generator.xrayInboundPrivateKeyContext("forwardx-inbound-disabled"), keyring);
      await runtime.executeRaw("INSERT INTO xray_inbounds (id, hostId, name, runtimeTag, publicAddress, listenPort, realityTargetHost, realityServerName, realityPublicKey, realityPrivateKeyEncrypted, createdByUserId) VALUES (100, 10, 'active', 'forwardx-inbound-db', '203.0.113.10', 23456, 'www.microsoft.com', 'www.microsoft.com', 'public', ?, 1), (101, 10, 'disabled', 'forwardx-inbound-disabled', '203.0.113.10', 23457, 'www.microsoft.com', 'www.microsoft.com', 'public', ?, 1)", [privateEnvelope, disabledPrivateEnvelope]);
      const uuid = "00000000-0000-4000-8000-000000000111";
      const shortId = "a1b2c3d4";
      const uuidEnvelope = secrets.encryptXraySecret(uuid, generator.xrayClientUuidContext("fwdx-client-db"), keyring);
      const shortEnvelope = secrets.encryptXraySecret(shortId, generator.xrayClientShortIdContext("fwdx-client-db"), keyring);
      const disabledUuid = "00000000-0000-4000-8000-000000000112";
      const disabledShortId = "b1c2d3e4";
      const disabledUuidEnvelope = secrets.encryptXraySecret(disabledUuid, generator.xrayClientUuidContext("fwdx-client-disabled"), keyring);
      const disabledShortEnvelope = secrets.encryptXraySecret(disabledShortId, generator.xrayClientShortIdContext("fwdx-client-disabled"), keyring);
      await runtime.executeRaw("INSERT INTO xray_clients (id, inboundId, name, uuidEncrypted, uuidFingerprint, shortIdEncrypted, shortIdFingerprint, statsKey, isEnabled, sortOrder) VALUES (200, 100, 'active', ?, ?, ?, ?, 'fwdx-client-db', 1, 0), (201, 100, 'disabled', ?, ?, ?, ?, 'fwdx-client-disabled', 0, 1)", [uuidEnvelope, secrets.fingerprintXraySecret(uuid, generator.xrayClientUuidContext("fwdx-client-db"), keyring), shortEnvelope, secrets.fingerprintXraySecret(shortId, generator.xrayClientShortIdContext("fwdx-client-db"), keyring), disabledUuidEnvelope, secrets.fingerprintXraySecret(disabledUuid, generator.xrayClientUuidContext("fwdx-client-disabled"), keyring), disabledShortEnvelope, secrets.fingerprintXraySecret(disabledShortId, generator.xrayClientShortIdContext("fwdx-client-disabled"), keyring)]);
      await runtime.executeRaw("UPDATE xray_inbounds SET isEnabled = 0 WHERE id = 101");
      await accessMigration.backfillLegacyXrayAccessEntries({ keyring });
      const legacy = await generator.generateXrayHostConfig(10, keyring);
      await runtime.executeRaw("UPDATE xray_inbounds SET profileId = ?, specVersion = ?, specJson = ? WHERE id = 100", ["VLESS_RAW_REALITY_VISION", 1, "{}"]);
      const result = await generator.generateXrayHostConfig(10, keyring);
      assert.equal(result.configJson, legacy.configJson);
      assert.equal(result.configHash, legacy.configHash);
      assert.equal(result.configJson.includes(uuid), true);
      assert.equal(result.configJson.includes(shortId), true);
      assert.equal(result.configJson.includes("invalid-disabled-envelope"), false);
      assert.deepEqual(result.expectedListeners, [{ inboundId: 100, runtimeTag: "forwardx-inbound-db", network: "tcp", listenAddress: "0.0.0.0", port: 23456 }]);
      await runtime.executeRaw("UPDATE xray_access_entries SET settingsJson = ? WHERE legacyClientId = 200", ['{"schemaVersion":1,"flow":"NONE"}']);
      await assert.rejects(generator.generateXrayHostConfig(10, keyring), /sensitive data is unavailable/i);
      await runtime.executeRaw("UPDATE xray_access_entries SET settingsJson = ? WHERE legacyClientId = 200", ['{"schemaVersion":1,"flow":"XTLS_RPRX_VISION"}']);
      await runtime.executeRaw("UPDATE xray_inbounds SET specJson = ? WHERE id = 100", ['{"inbounds":[]}']);
      await assert.rejects(generator.generateXrayHostConfig(10, keyring), /Xray configuration input is invalid/);
    } finally {
      await runtime.closeDatabase();
    }
  `;
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: { ...process.env, DATABASE_TYPE: "sqlite", FORWARDX_TEST_DB: databasePath, JWT_SECRET: "xray-config-test-secret" },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("generated fixture passes the fixed Xray config test when a binary is provided", (t) => {
  const binary = process.env.XRAY_TEST_BINARY;
  if (!binary) return t.skip("XRAY_TEST_BINARY is not configured");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-real-config-"));
  const configPath = path.join(directory, "config.json");
  try {
    fs.writeFileSync(configPath, generateDeterministicXrayConfig(fixtures()).configJson, { encoding: "utf8", mode: 0o600 });
    let result = spawnSync(binary, ["run", "-test", "-config", configPath], { encoding: "utf8", timeout: 15_000 });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    const inbound = fixtures()[0];
    fs.writeFileSync(configPath, generateDeterministicXrayConfig([{ ...inbound, clients: [] }]).configJson, { encoding: "utf8", mode: 0o600 });
    result = spawnSync(binary, ["run", "-test", "-config", configPath], { encoding: "utf8", timeout: 15_000 });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    fs.writeFileSync(configPath, generateDeterministicXrayConfig([]).configJson, { encoding: "utf8", mode: 0o600 });
    result = spawnSync(binary, ["run", "-test", "-config", configPath], { encoding: "utf8", timeout: 15_000 });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    fs.writeFileSync(configPath, generateDeterministicXrayConfig([grpcFixture(), fixtures()[0]]).configJson, { encoding: "utf8", mode: 0o600 });
    result = spawnSync(binary, ["run", "-test", "-config", configPath], { encoding: "utf8", timeout: 15_000 });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    fs.writeFileSync(configPath, generateDeterministicXrayConfig([xhttpFixture(), grpcFixture(), fixtures()[0]]).configJson, { encoding: "utf8", mode: 0o600 });
    result = spawnSync(binary, ["run", "-test", "-config", configPath], { encoding: "utf8", timeout: 15_000 });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    fs.writeFileSync(configPath, generateDeterministicXrayConfig([trojanFixture(), xhttpFixture(), fixtures()[0]]).configJson, { encoding: "utf8", mode: 0o600 });
    result = spawnSync(binary, ["run", "-test", "-config", configPath], { encoding: "utf8", timeout: 15_000 });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
