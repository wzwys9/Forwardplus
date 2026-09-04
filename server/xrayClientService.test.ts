import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("Xray client CRUD isolates credentials, defers deletion, and shares only no-store URI material", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-client-service-"));
  const databasePath = path.join(directory, "clients.db");
  const keyPath = path.join(directory, "xray-master.key");
  const script = String.raw`
    import assert from "node:assert/strict";
    import crypto from "node:crypto";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const secrets = await import(moduleUrl("server/xraySecretCrypto.ts"));
    const accessMigration = await import(moduleUrl("server/xrayAccessMigration.ts"));
    const generator = await import(moduleUrl("server/xrayConfigGenerator.ts"));
    const artifacts = await import(moduleUrl("server/xrayArtifacts.ts"));
    const heartbeat = await import(moduleUrl("server/xrayHeartbeatState.ts"));
    const { xrayRouter } = await import(moduleUrl("server/routers/xray.ts"));

    const responseHeaders = new Map();
    const admin = { id: 1, username: "admin", role: "admin", accountEnabled: true };
    const context = {
      req: { headers: {} },
      res: { clearCookie() {}, setHeader(name, value) { responseHeaders.set(String(name).toLowerCase(), String(value)); } },
      user: admin, authSession: null, authFailureReason: null,
    };
    const caller = xrayRouter.createCaller(context);
    const memberCaller = xrayRouter.createCaller({
      ...context,
      user: { id: 2, username: "member", role: "user", accountEnabled: true },
    });
    const expectXrayCode = async (promise, code) => assert.rejects(promise, (error) =>
      error?.cause?.code === code || error?.message === code || error?.message === String(code));
    const clientRows = () => runtime.queryRaw("SELECT * FROM xray_clients ORDER BY id");
    const deployment = async () => (await runtime.queryRaw("SELECT * FROM xray_host_deployments WHERE hostId = 1"))[0];

    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
      const keyring = secrets.loadXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
      const assertStoredConfigHash = async () => {
        const generated = await generator.generateXrayHostConfig(1, keyring);
        assert.equal((await deployment()).desiredConfigHash, generated.configHash);
        return generated;
      };
      const now = Math.floor(Date.now() / 1000);
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (2, 'member', 'hash', 'user')");
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, ipv4, isOnline, lastHeartbeat, agentVersion, userId) VALUES (1, 'edge', '8.8.8.8', '8.8.8.8', 1, ?, '2.3.1', 1)", [now]);
      await runtime.executeRaw("INSERT INTO xray_runtime_reports (hostId, capabilitySchemaVersion, supportedOS, supportedArch, supportsArtifactInstall, supportsPortProbe, supportsRealityScan, isInstalled, installedVersion, runningVersion, serviceStatus, appliedGeneration) VALUES (1, 1, 'linux', 'amd64', 1, 1, 1, 1, ?, ?, 'RUNNING', 1)", [artifacts.XRAY_DEFAULT_VERSION, artifacts.XRAY_DEFAULT_VERSION]);

      const runtimeTag = "forwardx-inbound-client-test";
      const inboundId = await runtime.insertAndGetId("xray_inbounds", {
        hostId: 1, name: "IPv6 Reality", runtimeTag, publicAddress: "2001:db8::1234",
        listenAddress: "0.0.0.0", listenPort: 23456, protocol: "vless", transport: "tcp", security: "reality",
        realityTargetHost: "www.microsoft.com", realityTargetPort: 443, realityServerName: "www.microsoft.com",
        realityPublicKey: "A".repeat(43),
        realityPrivateKeyEncrypted: secrets.encryptXraySecret("A".repeat(43), secrets.xrayInboundPrivateKeyContext(runtimeTag), keyring),
        secretKeyVersion: 1, fingerprint: "chrome", spiderX: "/news?a=b c", isEnabled: true,
        pendingDelete: false, desiredGeneration: 1, createdByUserId: 1,
      });
      const makeClient = async (name, suffix, sortOrder) => {
        const statsKey = "forwardx-client-test-" + suffix;
        const uuid = "00000000-0000-4000-8000-000000000" + suffix;
        const shortId = String(suffix).padStart(16, "0");
        return runtime.insertAndGetId("xray_clients", {
          inboundId, name, statsKey, flow: "xtls-rprx-vision", isEnabled: true, pendingDelete: false,
          desiredGeneration: 1, sortOrder,
          uuidEncrypted: secrets.encryptXraySecret(uuid, secrets.xrayClientUuidContext(statsKey), keyring),
          uuidFingerprint: secrets.fingerprintXraySecret(uuid, secrets.xrayClientUuidContext(statsKey), keyring),
          shortIdEncrypted: secrets.encryptXraySecret(shortId, secrets.xrayClientShortIdContext(statsKey), keyring),
          shortIdFingerprint: secrets.fingerprintXraySecret(shortId, secrets.xrayClientShortIdContext(statsKey), keyring),
        });
      };
      const phoneId = await makeClient("phone", "101", 0);
      await makeClient("laptop", "102", 1);
      await makeClient("router", "103", 2);
      await accessMigration.backfillLegacyXrayAccessEntries({ keyring });
      const initialGenerated = await generator.generateXrayHostConfig(1, keyring);
      await runtime.insertAndGetId("xray_operations", {
        operationId: "client-initial-sync", hostId: 1, inboundId, type: "SYNC", requestedGeneration: 1,
        status: "SUCCESS", attemptCount: 1, createdByUserId: 1,
      });
      await runtime.insertAndGetId("xray_host_deployments", {
        hostId: 1, targetVersion: initialGenerated.targetVersion, desiredGeneration: 1,
        desiredConfigHash: initialGenerated.configHash, lastOperationId: "client-initial-sync",
      });
      await runtime.executeRaw("UPDATE xray_runtime_reports SET appliedConfigHash = ?, listenersJson = '[]' WHERE hostId = 1", [initialGenerated.configHash]);

      const beforeDenied = await clientRows();
      await assert.rejects(memberCaller.clients.create({ inboundId, name: "member", flow: "xtls-rprx-vision", expectedGeneration: 1 }), (error) => error?.code === "FORBIDDEN");
      assert.deepEqual(await clientRows(), beforeDenied);
      await assert.rejects(memberCaller.clients.share({ clientId: phoneId, format: "VLESS_URI" }), (error) => error?.code === "FORBIDDEN");

      await runtime.executeRaw("UPDATE hosts SET isOnline = 0 WHERE id = 1");
      await expectXrayCode(caller.clients.create({ inboundId, name: "offline", flow: "xtls-rprx-vision", expectedGeneration: 1 }), "HOST_OFFLINE");
      assert.equal((await deployment()).desiredGeneration, 1);
      assert.deepEqual(await clientRows(), beforeDenied);
      await runtime.executeRaw("UPDATE hosts SET isOnline = 1, lastHeartbeat = ? WHERE id = 1", [Math.floor(Date.now() / 1000) - 3600]);
      await expectXrayCode(caller.clients.create({ inboundId, name: "stale", flow: "xtls-rprx-vision", expectedGeneration: 1 }), "HOST_OFFLINE");
      await runtime.executeRaw("UPDATE hosts SET isOnline = 1, lastHeartbeat = ? WHERE id = 1", [Math.floor(Date.now() / 1000)]);

      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsRealityScan = 0 WHERE hostId = 1");
      await expectXrayCode(caller.clients.create({ inboundId, name: "unsupported", flow: "xtls-rprx-vision", expectedGeneration: 1 }), "AGENT_CAPABILITY_MISSING");
      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsRealityScan = 1 WHERE hostId = 1");

      const beforeCreate = await clientRows();
      const created = await caller.clients.create({ inboundId, name: "tablet", flow: "xtls-rprx-vision", expectedGeneration: 1 });
      assert.ok(created.clientId > 0);
      assert.equal(created.desiredGeneration, 2);
      assert.match(created.operationId, /^[A-Za-z0-9._:-]{1,64}$/);
      const afterCreate = await clientRows();
      assert.equal(afterCreate.length, 4);
      assert.deepEqual(afterCreate.filter((row) => row.id !== created.clientId), beforeCreate);
      const createdRow = afterCreate.find((row) => row.id === created.clientId);
      const createdUuid = secrets.decryptXraySecret(createdRow.uuidEncrypted, secrets.xrayClientUuidContext(createdRow.statsKey), keyring);
      const createdShortId = secrets.decryptXraySecret(createdRow.shortIdEncrypted, secrets.xrayClientShortIdContext(createdRow.statsKey), keyring);
      assert.match(createdUuid, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
      assert.match(createdShortId, /^[0-9a-f]{16}$/);
      assert.equal(new Set(afterCreate.map((row) => row.uuidFingerprint)).size, 4);
      assert.equal(new Set(afterCreate.map((row) => row.shortIdFingerprint)).size, 4);
      assert.equal(new Set(afterCreate.map((row) => row.statsKey)).size, 4);
      await assertStoredConfigHash();

      await expectXrayCode(caller.clients.update({ id: created.clientId, name: "PHONE", expectedGeneration: 2 }), "DUPLICATE_CLIENT_NAME");
      assert.equal((await deployment()).desiredGeneration, 2);
      const beforeUpdate = await clientRows();
      const updated = await caller.clients.update({ id: created.clientId, name: "tablet renamed", isEnabled: false, expectedGeneration: 2 });
      assert.equal(updated.desiredGeneration, 3);
      let changed = (await clientRows()).find((row) => row.id === created.clientId);
      assert.equal(changed.name, "tablet renamed");
      assert.equal(Number(changed.isEnabled), 0);
      assert.equal(changed.uuidEncrypted, createdRow.uuidEncrypted);
      assert.equal(changed.shortIdEncrypted, createdRow.shortIdEncrypted);
      assert.deepEqual((await clientRows()).filter((row) => row.id !== created.clientId), beforeUpdate.filter((row) => row.id !== created.clientId));
      await assertStoredConfigHash();

      const enabled = await caller.clients.update({ id: created.clientId, isEnabled: true, expectedGeneration: 3 });
      assert.equal(enabled.desiredGeneration, 4);
      changed = (await clientRows()).find((row) => row.id === created.clientId);
      assert.equal(Number(changed.isEnabled), 1);
      const generationFour = await heartbeat.buildXrayHeartbeatDesiredState(1, { keyring });
      assert.equal(generationFour.generation, 4);

      const phoneBeforeDelete = (await clientRows()).find((row) => row.id === phoneId);
      const removed = await caller.clients.remove({ id: phoneId, expectedGeneration: 4 });
      assert.equal(removed.desiredGeneration, 5);
      assert.equal(removed.pendingDelete, true);
      assert.equal(removed.mayRemainActive, true);
      const pendingPhone = (await clientRows()).find((row) => row.id === phoneId);
      assert.equal(Number(pendingPhone.pendingDelete), 1);
      assert.equal(pendingPhone.uuidEncrypted, phoneBeforeDelete.uuidEncrypted);
      assert.equal(pendingPhone.shortIdEncrypted, phoneBeforeDelete.shortIdEncrypted);
      const listed = await caller.clients.list({ inboundId });
      assert.equal(listed.length, 4);
      assert.equal(listed.find((client) => client.id === phoneId).pendingDelete, true);
      assert.equal(JSON.stringify(listed).includes(phoneBeforeDelete.uuidEncrypted), false);
      await assertStoredConfigHash();

      responseHeaders.clear();
      const pendingShare = await caller.clients.share({ clientId: phoneId, format: "VLESS_URI" });
      assert.equal(pendingShare.deploymentStatus, "PENDING_DELETE");
      assert.equal(responseHeaders.get("cache-control"), "private, no-store, max-age=0");
      assert.equal(responseHeaders.get("pragma"), "no-cache");

      const observedGenerationFour = {
        schemaVersion: 1, isInstalled: true, installedVersion: artifacts.XRAY_DEFAULT_VERSION,
        runningVersion: artifacts.XRAY_DEFAULT_VERSION, serviceStatus: "RUNNING", processId: 4242,
        binarySha256: "b".repeat(64), appliedGeneration: generationFour.generation,
        appliedConfigHash: generationFour.configHash,
        listeners: generationFour.expectedListeners.map((listener) => ({ runtimeTag: listener.runtimeTag, network: "tcp", port: listener.port, status: "READY", errorCode: null })),
        lastError: null, observedAt: new Date().toISOString(),
      };
      await heartbeat.processXrayHeartbeatReport({
        hostId: 1,
        xrayStateSignature: heartbeat.xrayObservedStateSignature(observedGenerationFour),
        xrayState: observedGenerationFour,
      });
      assert.equal((await clientRows()).some((row) => row.id === phoneId), true);
      assert.equal(Number((await clientRows()).find((row) => row.id === phoneId).pendingDelete), 1);

      const desired = await heartbeat.buildXrayHeartbeatDesiredState(1, { keyring });
      assert.equal(desired.generation, 5);
      assert.equal(JSON.parse(desired.configJson).inbounds[0].settings.clients.length, 3);
      const observed = {
        schemaVersion: 1, isInstalled: true, installedVersion: artifacts.XRAY_DEFAULT_VERSION,
        runningVersion: artifacts.XRAY_DEFAULT_VERSION, serviceStatus: "RUNNING", processId: 4242,
        binarySha256: "b".repeat(64), appliedGeneration: desired.generation, appliedConfigHash: desired.configHash,
        listeners: desired.expectedListeners.map((listener) => ({ runtimeTag: listener.runtimeTag, network: "tcp", port: listener.port, status: "READY", errorCode: null })),
        lastError: null, observedAt: new Date().toISOString(),
      };
      await heartbeat.processXrayHeartbeatReport({
        hostId: 1, xrayStateSignature: heartbeat.xrayObservedStateSignature(observed), xrayState: observed,
      });
      assert.equal((await clientRows()).some((row) => row.id === phoneId), false);
      assert.equal((await clientRows()).length, 3);
      assert.equal((await runtime.queryRaw("SELECT status FROM xray_operations WHERE operationId = ?", [removed.operationId]))[0].status, "SUCCESS");

      responseHeaders.clear();
      const shared = await caller.clients.share({ clientId: created.clientId, format: "VLESS_URI" });
      assert.equal(shared.displayName, "tablet renamed");
      assert.equal(shared.deploymentStatus, "RUNNING");
      assert.ok(shared.generatedAt instanceof Date);
      assert.equal(responseHeaders.get("cache-control"), "private, no-store, max-age=0");
      const parsed = new URL(shared.uri);
      assert.equal(parsed.protocol, "vless:");
      assert.equal(parsed.username, createdUuid);
      assert.equal(parsed.hostname, "[2001:db8::1234]");
      assert.equal(parsed.searchParams.get("security"), "reality");
      assert.equal(parsed.searchParams.get("type"), "tcp");
      assert.equal(parsed.searchParams.get("pbk"), "A".repeat(43));
      assert.equal(parsed.searchParams.get("sid"), createdShortId);
      assert.equal(parsed.searchParams.get("spx"), "/news?a=b c");
      assert.equal(parsed.searchParams.get("flow"), "xtls-rprx-vision");
      assert.equal(shared.uri.includes("private"), false);
      await assert.rejects(caller.clients.share({ clientId: phoneId, format: "VLESS_URI" }), (error) => error?.code === "NOT_FOUND");
      await runtime.executeRaw("UPDATE xray_access_entries SET name = 'drifted-name' WHERE legacyClientId = ?", [created.clientId]);
      await expectXrayCode(caller.clients.share({ clientId: created.clientId, format: "VLESS_URI" }), "SENSITIVE_DATA_UNAVAILABLE");
      await runtime.executeRaw("UPDATE xray_access_entries SET name = 'tablet renamed' WHERE legacyClientId = ?", [created.clientId]);
      await runtime.executeRaw("UPDATE xray_inbounds SET realityPublicKey = 'share-private-secret-marker' WHERE id = ?", [inboundId]);
      await assert.rejects(caller.clients.share({ clientId: created.clientId, format: "VLESS_URI" }), (error) => {
        assert.equal(error?.cause?.code === "SENSITIVE_DATA_UNAVAILABLE" || error?.message === "SENSITIVE_DATA_UNAVAILABLE", true);
        assert.equal(JSON.stringify(error).includes("share-private-secret-marker"), false);
        return true;
      });
      assert.equal(responseHeaders.get("cache-control"), "private, no-store, max-age=0");
      assert.equal(JSON.stringify(await runtime.queryRaw("SELECT * FROM xray_operations")).includes("vless://"), false);
      assert.equal(JSON.stringify(await runtime.queryRaw("SELECT * FROM xray_clients")).includes("vless://"), false);
    } finally {
      await runtime.closeDatabase().catch(() => undefined);
    }
  `;
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        DATABASE_TYPE: "sqlite",
        FORWARDX_TEST_DB: databasePath,
        JWT_SECRET: "xray-client-service-test-secret",
        XRAY_MASTER_KEY_PATH: keyPath,
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
