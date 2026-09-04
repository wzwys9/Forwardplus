import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("Xray inbound deletion stays pending until exact apply and the last inbound stops without uninstalling", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-inbound-lifecycle-"));
  const databasePath = path.join(directory, "lifecycle.db");
  const keyPath = path.join(directory, "xray-master.key");
  const script = String.raw`
    import assert from "node:assert/strict";
    import fs from "node:fs";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const db = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const secrets = await import(moduleUrl("server/xraySecretCrypto.ts"));
    const accessMigration = await import(moduleUrl("server/xrayAccessMigration.ts"));
    const generator = await import(moduleUrl("server/xrayConfigGenerator.ts"));
    const heartbeat = await import(moduleUrl("server/xrayHeartbeatState.ts"));
    const artifacts = await import(moduleUrl("server/xrayArtifacts.ts"));
    const { xrayRouter } = await import(moduleUrl("server/routers/xray.ts"));
    const context = (user) => ({ req: { headers: {} }, res: { clearCookie() {} }, user, authSession: null, authFailureReason: null });
    const admin = { id: 1, username: "admin", role: "admin", accountEnabled: true };
    const member = { id: 2, username: "member", role: "user", accountEnabled: true };
    const now = Math.floor(Date.now() / 1000);
    try {
      await db.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
      const keyring = secrets.loadXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
      await db.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin'), (2, 'member', 'hash', 'user')");
      await db.executeRaw("INSERT INTO hosts (id, name, ip, ipv4, isOnline, lastHeartbeat, agentVersion, agentDistribution, userId) VALUES (1, 'edge-delete', '8.8.8.8', '8.8.8.8', 1, ?, '2.3.278', 'forwardplus', 1)", [now]);
      await db.executeRaw("INSERT INTO xray_runtime_reports (hostId, capabilitySchemaVersion, supportedOS, supportedArch, supportsArtifactInstall, supportsPortProbe, supportsRealityScan, isInstalled, installedVersion, runningVersion, serviceStatus, processId, appliedGeneration, binarySha256, listenersJson, reportedAt) VALUES (1, 1, 'linux', 'amd64', 1, 1, 1, 1, ?, ?, 'RUNNING', 4242, 1, ?, '[]', ?)", [artifacts.XRAY_DEFAULT_VERSION, artifacts.XRAY_DEFAULT_VERSION, "b".repeat(64), now]);
      const addInbound = async (id, name, port) => {
        const runtimeTag = "forwardx-inbound-delete-" + id;
        await db.insertAndGetId("xray_inbounds", {
          id, hostId: 1, name, runtimeTag, publicAddress: "8.8.8.8", listenAddress: "0.0.0.0", listenPort: port,
          protocol: "vless", transport: "tcp", security: "reality", realityTargetHost: "www.microsoft.com", realityTargetPort: 443,
          realityServerName: "www.microsoft.com", realityPublicKey: "A".repeat(43),
          realityPrivateKeyEncrypted: secrets.encryptXraySecret("A".repeat(43), secrets.xrayInboundPrivateKeyContext(runtimeTag), keyring),
          secretKeyVersion: 1, fingerprint: "chrome", spiderX: "/", isEnabled: true, pendingDelete: false, desiredGeneration: 1, createdByUserId: 1,
        });
        const statsKey = "forwardx-client-delete-" + id;
        await db.insertAndGetId("xray_clients", {
          inboundId: id, name: "client-" + id, statsKey, flow: "xtls-rprx-vision", isEnabled: true, pendingDelete: false,
          desiredGeneration: 1, sortOrder: 0,
          uuidEncrypted: secrets.encryptXraySecret("00000000-0000-4000-8000-00000000000" + id, secrets.xrayClientUuidContext(statsKey), keyring),
          uuidFingerprint: secrets.fingerprintXraySecret("00000000-0000-4000-8000-00000000000" + id, secrets.xrayClientUuidContext(statsKey), keyring),
          shortIdEncrypted: secrets.encryptXraySecret(String(id).padStart(16, "0"), secrets.xrayClientShortIdContext(statsKey), keyring),
          shortIdFingerprint: secrets.fingerprintXraySecret(String(id).padStart(16, "0"), secrets.xrayClientShortIdContext(statsKey), keyring),
        });
      };
      await addInbound(1, "first", 21001);
      await addInbound(2, "last", 21002);
      await accessMigration.backfillLegacyXrayAccessEntries({ keyring });
      const initial = await generator.generateXrayHostConfig(1, keyring);
      await db.insertAndGetId("xray_operations", { operationId: "initial-sync", hostId: 1, type: "SYNC", requestedGeneration: 1, status: "SUCCESS", attemptCount: 1, createdByUserId: 1 });
      await db.insertAndGetId("xray_host_deployments", { hostId: 1, targetVersion: initial.targetVersion, desiredGeneration: 1, desiredConfigHash: initial.configHash, lastOperationId: "initial-sync" });
      await db.executeRaw("UPDATE xray_runtime_reports SET appliedConfigHash = ?, listenersJson = ? WHERE hostId = 1", [initial.configHash, JSON.stringify(initial.expectedListeners.map((listener) => ({ runtimeTag: listener.runtimeTag, network: "tcp", port: listener.port, status: "READY", errorCode: null })))]);

      const caller = xrayRouter.createCaller(context(admin));
      const memberCaller = xrayRouter.createCaller(context(member));
      await assert.rejects(() => memberCaller.inbounds.remove({ id: 1, expectedGeneration: 1, confirmName: "first" }), (error) => error?.code === "FORBIDDEN");
      await assert.rejects(() => caller.inbounds.remove({ id: 1, expectedGeneration: 1, confirmName: "First" }), (error) => error?.message === "CONFIRMATION_MISMATCH");
      await db.executeRaw("UPDATE hosts SET isOnline = 0 WHERE id = 1");
      await assert.rejects(() => caller.inbounds.remove({ id: 1, expectedGeneration: 1, confirmName: "first" }), (error) => error?.message === "HOST_OFFLINE");
      assert.equal(Number((await db.queryRaw("SELECT pendingDelete FROM xray_inbounds WHERE id = 1"))[0].pendingDelete), 0);
      await db.executeRaw("UPDATE hosts SET isOnline = 1, lastHeartbeat = ? WHERE id = 1", [now]);

      const first = await caller.inbounds.remove({ id: 1, expectedGeneration: 1, confirmName: "first" });
      assert.equal(first.pendingDelete, true);
      assert.equal(first.mayRemainActive, true);
      assert.equal(first.lastInbound, false);
      const firstDesired = await heartbeat.buildXrayHeartbeatDesiredState(1, { keyring });
      assert.equal(firstDesired.generation, 2);
      assert.deepEqual(firstDesired.expectedListeners.map((listener) => listener.port), [21002]);
      const oldObserved = {
        schemaVersion: 1, isInstalled: true, installedVersion: artifacts.XRAY_DEFAULT_VERSION, runningVersion: artifacts.XRAY_DEFAULT_VERSION,
        serviceStatus: "RUNNING", processId: 4242, binarySha256: "b".repeat(64), appliedGeneration: 1, appliedConfigHash: initial.configHash,
        listeners: initial.expectedListeners.map((listener) => ({ runtimeTag: listener.runtimeTag, network: "tcp", port: listener.port, status: "READY", errorCode: null })),
        lastError: null, observedAt: new Date().toISOString(),
      };
      await heartbeat.processXrayHeartbeatReport({ hostId: 1, xrayStateSignature: heartbeat.xrayObservedStateSignature(oldObserved), xrayState: oldObserved });
      assert.equal((await db.queryRaw("SELECT COUNT(*) AS count FROM xray_inbounds WHERE id = 1"))[0].count, 1);
      const failedObserved = {
        ...oldObserved,
        lastError: { code: "CONFIG_INVALID", message: "sensitive detail must not persist", generation: 2, occurredAt: new Date().toISOString() },
      };
      await heartbeat.processXrayHeartbeatReport({ hostId: 1, xrayStateSignature: heartbeat.xrayObservedStateSignature(failedObserved), xrayState: failedObserved });
      assert.equal((await db.queryRaw("SELECT COUNT(*) AS count FROM xray_inbounds WHERE id = 1"))[0].count, 1);
      const failedOperation = (await db.queryRaw("SELECT status, errorCode, errorMessage FROM xray_operations WHERE requestedGeneration = 2"))[0];
      assert.equal(failedOperation.status, "FAILED");
      assert.equal(failedOperation.errorCode, "CONFIG_INVALID");
      assert.equal(failedOperation.errorMessage, "Managed Xray runtime reported an error");
      const firstApplied = { ...oldObserved, appliedGeneration: 2, appliedConfigHash: firstDesired.configHash, listeners: firstDesired.expectedListeners.map((listener) => ({ runtimeTag: listener.runtimeTag, network: "tcp", port: listener.port, status: "READY", errorCode: null })) };
      await heartbeat.processXrayHeartbeatReport({ hostId: 1, xrayStateSignature: heartbeat.xrayObservedStateSignature(firstApplied), xrayState: firstApplied });
      assert.equal((await db.queryRaw("SELECT COUNT(*) AS count FROM xray_inbounds WHERE id = 1"))[0].count, 0);
      assert.equal((await db.queryRaw("SELECT COUNT(*) AS count FROM xray_clients WHERE inboundId = 1"))[0].count, 0);
      assert.equal((await db.queryRaw("SELECT COUNT(*) AS count FROM xray_access_entries WHERE inboundId = 1"))[0].count, 0);
      assert.equal((await db.queryRaw("SELECT COUNT(*) AS count FROM xray_inbound_secrets WHERE inboundId = 1"))[0].count, 0);
      assert.equal((await db.queryRaw("SELECT COUNT(*) AS count FROM xray_inbounds WHERE id = 2"))[0].count, 1);

      fs.unlinkSync(process.env.XRAY_MASTER_KEY_PATH);
      const last = await caller.inbounds.remove({ id: 2, expectedGeneration: 2, confirmName: "last" });
      assert.equal(last.lastInbound, true);
      const stoppedDesired = await heartbeat.buildXrayHeartbeatDesiredState(1, { keyring });
      assert.deepEqual(stoppedDesired.expectedListeners, []);
      assert.equal(JSON.parse(stoppedDesired.configJson).inbounds.length, 0);
      assert.equal((await caller.inbounds.detail({ id: 2 })).inbound.pendingDelete, true);
      const stoppedObserved = {
        ...oldObserved, runningVersion: null, serviceStatus: "STOPPED", processId: null, appliedGeneration: 3,
        appliedConfigHash: stoppedDesired.configHash, listeners: [],
      };
      await heartbeat.processXrayHeartbeatReport({ hostId: 1, xrayStateSignature: heartbeat.xrayObservedStateSignature(stoppedObserved), xrayState: stoppedObserved });
      assert.equal((await db.queryRaw("SELECT COUNT(*) AS count FROM xray_inbounds WHERE hostId = 1"))[0].count, 0);
      assert.equal((await db.queryRaw("SELECT COUNT(*) AS count FROM xray_clients"))[0].count, 0);
      const report = (await db.queryRaw("SELECT isInstalled, installedVersion, serviceStatus FROM xray_runtime_reports WHERE hostId = 1"))[0];
      assert.equal(Number(report.isInstalled), 1);
      assert.equal(report.installedVersion, artifacts.XRAY_DEFAULT_VERSION);
      assert.equal(report.serviceStatus, "STOPPED");
      assert.equal((await db.queryRaw("SELECT COUNT(*) AS count FROM xray_host_deployments WHERE hostId = 1"))[0].count, 1);
      await assert.rejects(() => caller.inbounds.detail({ id: 2 }), (error) => error?.code === "NOT_FOUND");
    } finally {
      await db.closeDatabase().catch(() => undefined);
    }
  `;
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: { ...process.env, DATABASE_TYPE: "sqlite", FORWARDX_TEST_DB: databasePath, XRAY_MASTER_KEY_PATH: keyPath, JWT_SECRET: "xray-inbound-lifecycle-test" },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
