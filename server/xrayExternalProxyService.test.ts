import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("external proxy CRUD encrypts credentials and enforces stable references", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-external-proxy-"));
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const runtime = await load("server/dbRuntime.ts");
    const schema = await load("server/dbSchema.ts");
    const secrets = await load("server/xraySecretCrypto.ts");
    const service = await load("server/xrayExternalProxyService.ts");
    const { xrayRouter } = await load("server/routers/xray.ts");
    const publicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const uuid = "00000000-0000-4000-8000-000000000101";
    const expectCode = async (promise, code) => assert.rejects(promise, (error) => error?.code === code || error?.message === code);
    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      await schema.ensureDatabaseSchema();
      const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, ipv4, userId) VALUES (1, 'relay', '203.0.113.10', '203.0.113.10', 1)");

      const headers = new Map();
      const adminCaller = xrayRouter.createCaller({
        req: { headers: {} }, res: { clearCookie() {}, setHeader(name, value) { headers.set(name, value); } },
        user: { id: 1, username: "admin", role: "admin", accountEnabled: true }, authSession: null, authFailureReason: null,
      });
      const userCaller = xrayRouter.createCaller({
        req: { headers: {} }, res: { clearCookie() {}, setHeader() {} },
        user: { id: 2, username: "user", role: "user", accountEnabled: true }, authSession: null, authFailureReason: null,
      });

      const vlessUri = "vless://" + uuid + "@edge.example.com:443/?type=tcp&encryption=none&flow=xtls-rprx-vision&sni=cdn.example.com&fp=random&security=reality&pbk=" + publicKey + "&sid=12ab#Imported";
      await assert.rejects(userCaller.externalProxyNodes.previewImport({ uri: vlessUri }), (error) => error?.code === "FORBIDDEN");
      await adminCaller.externalProxyNodes.previewImport({ uri: vlessUri });
      assert.equal(headers.get("Cache-Control"), "private, no-store, max-age=0");
      const preview = service.previewXrayExternalProxyImport(vlessUri);
      assert.deepEqual(preview, {
        protocol: "VLESS_REALITY_VISION", suggestedName: "Imported", address: "edge.example.com", port: 443,
        specVersion: 1,
        publicSettings: { serverName: "cdn.example.com", fingerprint: "random", publicKey, spiderX: "/" },
        credentialsConfigured: true,
      });
      assert.equal(JSON.stringify(preview).includes(uuid), false);
      assert.equal(JSON.stringify(preview).includes("12ab"), false);

      const created = await service.createXrayExternalProxyNode({ name: "US A", uri: vlessUri, createdByUserId: 1 }, { keyring });
      assert.equal(created.name, "US A");
      assert.equal(created.inboundCount, 0);
      assert.equal(created.ruleCount, 0);
      assert.equal(JSON.stringify(created).includes(uuid), false);
      assert.equal(JSON.stringify(created).includes("encryptedValue"), false);

      const [nodeRow] = await runtime.queryRaw("SELECT * FROM xray_external_proxy_nodes WHERE id = ?", [created.id]);
      const secretRows = await runtime.queryRaw("SELECT * FROM xray_external_proxy_secrets WHERE externalProxyNodeId = ? ORDER BY kind", [created.id]);
      assert.match(nodeRow.nodeTag, /^forwardx-external-[0-9a-f-]{36}$/);
      assert.equal(nodeRow.specJson, JSON.stringify(preview.publicSettings));
      assert.equal(JSON.parse(nodeRow.specJson).fingerprint, "random");
      assert.deepEqual(secretRows.map((row) => row.kind), ["VLESS_SHORT_ID", "VLESS_UUID"]);
      assert.equal(JSON.stringify(nodeRow).includes(uuid), false);
      assert.equal(JSON.stringify(secretRows).includes(uuid), false);
      assert.match(secretRows[0].encryptedValue, /^fwdx-secret:v1:1:/);
      assert.throws(() => secrets.decryptXraySecret(secretRows[0].encryptedValue,
        secrets.xrayExternalProxySecretContext(nodeRow.nodeTag + "-wrong", secretRows[0].kind), keyring));

      const definition = await service.loadXrayExternalProxyDefinition(created.id, { keyring });
      assert.equal(definition.credentials.uuid, uuid);
      assert.equal(definition.spec.fingerprint, "random");
      assert.equal(await service.buildXrayExternalProxyShare(created.id, undefined, { keyring }),
        "vless://" + uuid + "@edge.example.com:443?type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&sni=cdn.example.com&fp=random&pbk=" + publicKey + "&sid=12ab&spx=%2F#US%20A");

      const ssKey = Buffer.alloc(32, 1).toString("base64");
      const ssInfo = Buffer.from("2022-blake3-aes-256-gcm:" + ssKey, "utf8").toString("base64url");
      const ss = await service.createXrayExternalProxyNode({ name: "SS A", uri: "ss://" + ssInfo + "@ss.example.com:8388", createdByUserId: 1 }, { keyring });
      const socks = await service.createXrayExternalProxyNode({ name: "SOCKS A", uri: "socks5://u:p@socks.example.com:1080", createdByUserId: 1 }, { keyring });
      assert.deepEqual((await service.listXrayExternalProxyNodes({ page: 1, pageSize: 20 })).items.map((item) => item.name), ["SOCKS A", "SS A", "US A"]);
      assert.equal((await service.listXrayExternalProxyNodes({ search: "ss.example" })).total, 1);

      const renamed = await service.renameXrayExternalProxyNode({ id: created.id, name: "US Primary" });
      assert.equal(renamed.name, "US Primary");
      await runtime.executeRaw("INSERT INTO xray_inbounds (hostId, name, runtimeTag, publicAddress, listenPort, realityTargetHost, realityServerName, realityPublicKey, realityPrivateKeyEncrypted, createdByUserId, externalProxyNodeId) VALUES (1, 'inbound', 'inbound-tag', '203.0.113.10', 24443, 'cdn.example.com', 'cdn.example.com', 'public', 'encrypted', 1, ?)", [created.id]);
      await expectCode(service.removeXrayExternalProxyNode({ id: created.id, confirmName: "US Primary" }), "EXTERNAL_PROXY_IN_USE");
      await expectCode(service.replaceXrayExternalProxyNode({ id: created.id, uri: "socks5://other.example.com:1080" }, { keyring }), "EXTERNAL_PROXY_IN_USE");
      assert.equal((await service.getXrayExternalProxyNodeDetail(created.id)).inboundCount, 1);
      await runtime.executeRaw("UPDATE xray_inbounds SET externalProxyNodeId = NULL WHERE externalProxyNodeId = ?", [created.id]);

      await service.replaceXrayExternalProxyNode({ id: created.id, uri: "socks5://other.example.com:1080" }, { keyring });
      assert.equal((await service.getXrayExternalProxyNodeDetail(created.id)).protocol, "SOCKS5");
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_external_proxy_secrets WHERE externalProxyNodeId = ?", [created.id]))[0].count, 0);

      await runtime.executeRaw("INSERT INTO forward_rules (hostId, name, forwardType, protocol, sourcePort, targetIp, targetPort, targetExternalProxyNodeId, userId) VALUES (1, 'relay rule', 'realm', 'tcp', 31080, 'socks.example.com', 1080, ?, 1)", [socks.id]);
      await expectCode(service.removeXrayExternalProxyNode({ id: socks.id, confirmName: "SOCKS A" }), "EXTERNAL_PROXY_IN_USE");
      assert.equal((await service.getXrayExternalProxyNodeDetail(socks.id)).ruleCount, 1);

      await service.removeXrayExternalProxyNode({ id: ss.id, confirmName: "SS A" });
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_external_proxy_nodes WHERE id = ?", [ss.id]))[0].count, 0);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_external_proxy_secrets WHERE externalProxyNodeId = ?", [ss.id]))[0].count, 0);

      await runtime.executeRaw("UPDATE xray_external_proxy_secrets SET fingerprint = ? WHERE externalProxyNodeId = ?", ["0".repeat(64), socks.id]);
      await expectCode(service.loadXrayExternalProxyDefinition(socks.id, { keyring }), "SENSITIVE_DATA_UNAVAILABLE");
      await expectCode(service.removeXrayExternalProxyNode({ id: created.id, confirmName: "wrong" }), "CONFIRMATION_MISMATCH");
    } finally {
      await runtime.closeDatabase();
    }
  `;

  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        DATABASE_TYPE: "sqlite",
        FORWARDX_TEST_DB: path.join(directory, "panel.db"),
        XRAY_MASTER_KEY_PATH: path.join(directory, "xray-master.key"),
      },
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
