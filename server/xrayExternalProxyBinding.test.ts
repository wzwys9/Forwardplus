import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("Xray inbound external proxy binding is atomic, visible, and fail-closed", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-external-binding-"));
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const db = await load("server/dbRuntime.ts");
    const schema = await load("server/dbSchema.ts");
    const secrets = await load("server/xraySecretCrypto.ts");
    const accessMigration = await load("server/xrayAccessMigration.ts");
    const artifacts = await load("server/xrayArtifacts.ts");
    const generator = await load("server/xrayConfigGenerator.ts");
    const external = await load("server/xrayExternalProxyService.ts");
    const inboundService = await load("server/xrayInboundService.ts");
    const { xrayRouter } = await load("server/routers/xray.ts");
    const context = (user) => ({ req: { headers: {} }, res: { clearCookie() {}, setHeader() {} }, user, authSession: null, authFailureReason: null });
    const admin = { id: 1, username: "admin", role: "admin", accountEnabled: true };
    const member = { id: 2, username: "member", role: "user", accountEnabled: true };
    const now = Math.floor(Date.now() / 1000);
    const publicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const expectCode = async (promise, code) => assert.rejects(promise, (error) => error?.code === code || error?.message === code);
    try {
      await db.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
      await db.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin'), (2, 'member', 'hash', 'user')");
      await db.executeRaw("INSERT INTO hosts (id, name, ip, ipv4, isOnline, lastHeartbeat, agentVersion, userId) VALUES (1, 'edge', '8.8.8.8', '8.8.8.8', 1, ?, '2.2.192', 1)", [now]);
      await db.executeRaw("INSERT INTO xray_runtime_reports (hostId, capabilitySchemaVersion, supportedOS, supportedArch, supportsArtifactInstall, supportsPortProbe, supportsRealityScan, isInstalled, installedVersion, runningVersion, serviceStatus, processId, appliedGeneration, binarySha256, listenersJson, reportedAt) VALUES (1, 1, 'linux', 'amd64', 1, 1, 1, 1, ?, ?, 'RUNNING', 4242, 1, ?, '[]', ?)", [artifacts.XRAY_DEFAULT_VERSION, artifacts.XRAY_DEFAULT_VERSION, "b".repeat(64), now]);

      const runtimeTag = "forwardx-inbound-external-binding";
      await db.insertAndGetId("xray_inbounds", {
        id: 10, hostId: 1, name: "entry", runtimeTag, publicAddress: "8.8.8.8", listenAddress: "0.0.0.0", listenPort: 24443,
        protocol: "vless", transport: "tcp", security: "reality", profileId: "VLESS_RAW_REALITY_VISION", specVersion: 1, specJson: "{}",
        realityTargetHost: "www.microsoft.com", realityTargetPort: 443, realityServerName: "www.microsoft.com", realityPublicKey: publicKey,
        realityPrivateKeyEncrypted: secrets.encryptXraySecret(publicKey, secrets.xrayInboundPrivateKeyContext(runtimeTag), keyring),
        secretKeyVersion: 1, fingerprint: "chrome", spiderX: "/", isEnabled: true, pendingDelete: false, desiredGeneration: 1, createdByUserId: 1,
      });
      const statsKey = "forwardx-client-external-binding";
      const uuid = "00000000-0000-4000-8000-000000000101";
      const shortId = "1234";
      await db.insertAndGetId("xray_clients", {
        inboundId: 10, name: "client", statsKey, flow: "xtls-rprx-vision", isEnabled: true, pendingDelete: false, desiredGeneration: 1, sortOrder: 0,
        uuidEncrypted: secrets.encryptXraySecret(uuid, secrets.xrayClientUuidContext(statsKey), keyring),
        uuidFingerprint: secrets.fingerprintXraySecret(uuid, secrets.xrayClientUuidContext(statsKey), keyring),
        shortIdEncrypted: secrets.encryptXraySecret(shortId, secrets.xrayClientShortIdContext(statsKey), keyring),
        shortIdFingerprint: secrets.fingerprintXraySecret(shortId, secrets.xrayClientShortIdContext(statsKey), keyring),
      });
      await accessMigration.backfillLegacyXrayAccessEntries({ keyring });
      const initial = await generator.generateXrayHostConfig(1, keyring);
      await db.insertAndGetId("xray_operations", { operationId: "initial", hostId: 1, type: "SYNC", requestedGeneration: 1, status: "SUCCESS", attemptCount: 1, createdByUserId: 1 });
      await db.insertAndGetId("xray_host_deployments", { hostId: 1, targetVersion: initial.targetVersion, desiredGeneration: 1, desiredConfigHash: initial.configHash, lastOperationId: "initial" });

      const uri = "vless://00000000-0000-4000-8000-000000000501@upstream.example.com:443/?sid=12ab&pbk=" + publicKey + "&fp=random&sni=cdn.example.com&flow=xtls-rprx-vision&encryption=none&security=reality&type=tcp#US";
      const node = await external.createXrayExternalProxyNode({ name: "US A", uri, createdByUserId: 1 }, { keyring });
      const badNode = await external.createXrayExternalProxyNode({ name: "Broken", uri: "socks5://user:pass@socks.example.com:1080", createdByUserId: 1 }, { keyring });
      await db.executeRaw("UPDATE xray_external_proxy_secrets SET fingerprint = ? WHERE externalProxyNodeId = ?", ["f".repeat(64), badNode.id]);

      const adminCaller = xrayRouter.createCaller(context(admin));
      const memberCaller = xrayRouter.createCaller(context(member));
      await assert.rejects(() => memberCaller.inbounds.setExternalProxy({ inboundId: 10, externalProxyNodeId: node.id, expectedGeneration: 1 }), (error) => error?.code === "FORBIDDEN");

      const bound = await adminCaller.inbounds.setExternalProxy({ inboundId: 10, externalProxyNodeId: node.id, expectedGeneration: 1 });
      assert.equal(bound.desiredGeneration, 2);
      assert.equal(bound.externalProxyNodeId, node.id);
      const boundConfig = await generator.generateXrayHostConfig(1, keyring);
      const parsed = JSON.parse(boundConfig.configJson);
      assert.deepEqual(parsed.routing.rules, [{ type: "field", inboundTag: [runtimeTag], outboundTag: (await db.queryRaw("SELECT nodeTag FROM xray_external_proxy_nodes WHERE id = ?", [node.id]))[0].nodeTag }]);
      assert.equal(parsed.outbounds.length, 2);
      assert.equal(parsed.outbounds[1].streamSettings.realitySettings.fingerprint, "random");
      const detail = await adminCaller.inbounds.detail({ id: 10 });
      assert.deepEqual(detail.inbound.externalProxy, { id: node.id, name: "US A", protocol: "VLESS_REALITY_VISION", address: "upstream.example.com", port: 443 });
      assert.equal((await adminCaller.inbounds.list({ page: 1, pageSize: 12, search: "US A", sortBy: "updatedAt", sortOrder: "desc" })).items[0].externalProxy.name, "US A");

      await db.executeRaw("UPDATE xray_operations SET status = 'SUCCESS' WHERE operationId = ?", [bound.operationId]);
      await expectCode(inboundService.setXrayInboundExternalProxy({ inboundId: 10, externalProxyNodeId: badNode.id, userId: 1, expectedGeneration: 2 }), "SENSITIVE_DATA_UNAVAILABLE");
      assert.equal(Number((await db.queryRaw("SELECT externalProxyNodeId FROM xray_inbounds WHERE id = 10"))[0].externalProxyNodeId), node.id);
      assert.equal(Number((await db.queryRaw("SELECT desiredGeneration FROM xray_host_deployments WHERE hostId = 1"))[0].desiredGeneration), 2);

      const unbound = await adminCaller.inbounds.setExternalProxy({ inboundId: 10, externalProxyNodeId: null, expectedGeneration: 2 });
      assert.equal(unbound.desiredGeneration, 3);
      assert.deepEqual(JSON.parse((await generator.generateXrayHostConfig(1, keyring)).configJson).outbounds, [{ tag: "direct", protocol: "freedom" }]);
      assert.equal(JSON.parse((await generator.generateXrayHostConfig(1, keyring)).configJson).routing, undefined);
      await db.executeRaw("UPDATE xray_operations SET status = 'SUCCESS' WHERE operationId = ?", [unbound.operationId]);

      await db.insertAndGetId("xray_inbounds", {
        id: 11, hostId: 1, name: "local tunnel", runtimeTag: "forwardx-inbound-tunnel-external", publicAddress: "127.0.0.1", listenAddress: "127.0.0.1", listenPort: 24444,
        protocol: "tunnel", transport: "none", security: "none", profileId: "TUNNEL_TCP_LOCAL_NONE", specVersion: 1,
        specJson: '{"targetAddress":"example.com","targetPort":443}', realityTargetHost: "", realityTargetPort: 443, realityServerName: "", realityPublicKey: "", realityPrivateKeyEncrypted: "", secretKeyVersion: 1, fingerprint: "", spiderX: "/", isEnabled: false, pendingDelete: false, desiredGeneration: 3, createdByUserId: 1,
      });
      await expectCode(inboundService.setXrayInboundExternalProxy({ inboundId: 11, externalProxyNodeId: node.id, userId: 1, expectedGeneration: 3 }), "EXTERNAL_PROXY_UNSUPPORTED");
      await db.executeRaw("UPDATE hosts SET isOnline = 0 WHERE id = 1");
      await expectCode(inboundService.setXrayInboundExternalProxy({ inboundId: 10, externalProxyNodeId: node.id, userId: 1, expectedGeneration: 3 }), "HOST_OFFLINE");
      assert.equal(Number((await db.queryRaw("SELECT desiredGeneration FROM xray_host_deployments WHERE hostId = 1"))[0].desiredGeneration), 3);
    } finally {
      await db.closeDatabase().catch(() => undefined);
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
        JWT_SECRET: "xray-external-binding-test",
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
