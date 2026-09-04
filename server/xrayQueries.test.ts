import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("Xray admin read APIs derive availability and runtime state without exposing secrets", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-queries-"));
  const databasePath = path.join(directory, "queries.db");
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const artifacts = await import(moduleUrl("server/xrayArtifacts.ts"));
    const versions = await import(moduleUrl("shared/versions.ts"));
    const { xrayRouter } = await import(moduleUrl("server/routers/xray.ts"));
    const context = (user) => ({
      req: { headers: {} }, res: { clearCookie() {} }, user,
      authSession: null, authFailureReason: null,
    });
    const admin = { id: 1, username: "admin", role: "admin", accountEnabled: true };
    const member = { id: 2, username: "member", role: "user", accountEnabled: true };
    const now = Math.floor(Date.now() / 1000);
    const hash = "a".repeat(64);
    const binaryHash = "b".repeat(64);
    const secretMarker = "xray-query-secret-marker";
    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin'), (2, 'member', 'hash', 'user')");
      const hostRows = [
        [1, "ready", "8.8.8.8", "8.8.8.8", 1, now, versions.AGENT_VERSION],
        [2, "offline", "1.1.1.1", "1.1.1.1", 0, now, versions.AGENT_VERSION],
        [3, "stale", "9.9.9.9", "9.9.9.9", 1, now - 600, versions.AGENT_VERSION],
        [4, "old-agent", "8.8.4.4", "8.8.4.4", 1, now, "2.2.1"],
        [5, "unsupported", "4.2.2.2", "4.2.2.2", 1, now, versions.AGENT_VERSION],
        [6, "no-artifact", "208.67.222.222", "208.67.222.222", 1, now, versions.AGENT_VERSION],
        [7, "no-ipv4", "example.invalid", null, 1, now, versions.AGENT_VERSION],
      ];
      for (const row of hostRows) {
        await runtime.executeRaw("INSERT INTO hosts (id, name, ip, ipv4, isOnline, lastHeartbeat, agentVersion, agentDistribution, userId) VALUES (?, ?, ?, ?, ?, ?, ?, 'forwardplus', 1)", row);
      }
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, ipv4, isOnline, lastHeartbeat, agentVersion, userId) VALUES (8, 'original-high-version', '8.8.8.9', '8.8.8.9', 1, ?, '9.0.0', 1)", [now]);
      for (const hostId of [1, 2, 3, 6, 7]) {
        const arch = hostId === 6 ? "arm64" : "amd64";
        await runtime.executeRaw("INSERT INTO xray_runtime_reports (hostId, capabilitySchemaVersion, supportedOS, supportedArch, supportsArtifactInstall, supportsPortProbe, supportsRealityScan) VALUES (?, 1, 'linux', ?, 1, 1, 1)", [hostId, arch]);
      }
      await runtime.executeRaw("INSERT INTO xray_runtime_reports (hostId, capabilitySchemaVersion, supportedOS, supportedArch, capabilityErrorCode) VALUES (5, 0, 'freebsd', 'amd64', 'HOST_PLATFORM_UNSUPPORTED')");
      const artifact = artifacts.XRAY_ARTIFACT_MANIFEST.find((entry) => entry.arch === "amd64");
      await runtime.executeRaw("INSERT INTO xray_artifacts (version, os, arch, packageFormat, storageKey, sha256, fileSize, status, source, verifiedAt) VALUES (?, ?, ?, ?, ?, ?, ?, 'VERIFIED', ?, ?)", [artifact.version, artifact.os, artifact.arch, artifact.packageFormat, artifact.storageKey, artifact.sha256, artifact.fileSize, artifact.source, now]);

      const inboundSql = "INSERT INTO xray_inbounds (id, hostId, name, runtimeTag, publicAddress, listenPort, realityTargetHost, realityServerName, realityPublicKey, realityPrivateKeyEncrypted, isEnabled, pendingDelete, desiredGeneration, createdByUserId, updatedAt) VALUES (?, ?, ?, ?, ?, ?, 'www.microsoft.com', 'www.microsoft.com', 'public-key', ?, ?, ?, ?, 1, ?)";
      await runtime.executeRaw(inboundSql, [100, 1, "running-node", "forwardx-inbound-running", "8.8.8.8", 23456, secretMarker, 1, 0, 3, now - 4]);
      await runtime.executeRaw(inboundSql, [101, 1, "disabled-node", "forwardx-inbound-disabled", "8.8.8.8", 23457, secretMarker, 0, 0, 3, now - 3]);
      await runtime.executeRaw(inboundSql, [102, 2, "offline-node", "forwardx-inbound-offline", "1.1.1.1", 23458, secretMarker, 1, 0, 1, now - 2]);
      await runtime.executeRaw(inboundSql, [103, 1, "pending-node", "forwardx-inbound-pending", "8.8.8.8", 23459, secretMarker, 1, 1, 3, now - 1]);
      await runtime.executeRaw("INSERT INTO xray_clients (id, inboundId, name, uuidEncrypted, uuidFingerprint, shortIdEncrypted, shortIdFingerprint, statsKey, desiredGeneration) VALUES (200, 100, 'primary-client', ?, ?, ?, ?, 'stats-safe', 3)", [secretMarker, "c".repeat(64), secretMarker, "d".repeat(64)]);
      await runtime.executeRaw("INSERT INTO xray_host_deployments (hostId, targetVersion, desiredGeneration, desiredConfigHash, lastOperationId) VALUES (1, 'v26.3.27', 3, ?, 'sync-success'), (2, 'v26.3.27', 1, ?, 'sync-offline')", [hash, hash]);
      await runtime.executeRaw("UPDATE xray_runtime_reports SET isInstalled = 1, installedVersion = 'v26.3.27', runningVersion = 'v26.3.27', serviceStatus = 'RUNNING', processId = 4321, appliedGeneration = 3, appliedConfigHash = ?, binarySha256 = ?, listenersJson = ?, reportSignature = ?, reportedAt = ? WHERE hostId = 1", [hash, binaryHash, JSON.stringify([{ runtimeTag: "forwardx-inbound-running", network: "tcp", port: 23456, status: "READY", errorCode: null }]), "e".repeat(64), now]);
      await runtime.executeRaw("INSERT INTO xray_operations (operationId, hostId, inboundId, type, requestedGeneration, status, errorCode, errorMessage, resultJson, createdByUserId, createdAt, updatedAt) VALUES ('sync-success', 1, 100, 'SYNC', 3, 'SUCCESS', NULL, NULL, NULL, 1, ?, ?), ('sync-offline', 2, 102, 'SYNC', 1, 'RUNNING', NULL, NULL, NULL, 1, ?, ?), ('unsafe-operation', 1, 100, 'SYNC', 4, 'FAILED', 'UNKNOWN_SECRET_CODE', ?, ?, 1, ?, ?)", [now - 20, now - 20, now - 10, now - 10, secretMarker, JSON.stringify({ secret: secretMarker }), now, now]);

      const caller = xrayRouter.createCaller(context(admin));
      const options = await caller.hosts.options();
      assert.deepEqual(Object.fromEntries(options.map((item) => [item.id, item.unavailableReasonCode ?? null])), {
        1: null,
        2: "AGENT_OFFLINE",
        3: "HEARTBEAT_STALE",
        4: "AGENT_UPGRADE_REQUIRED",
        5: "PLATFORM_UNSUPPORTED",
        6: "ARTIFACT_UNAVAILABLE",
        7: "PUBLIC_IPV4_MISSING",
        8: "AGENT_UPGRADE_REQUIRED",
      });
      assert.equal(options.find((item) => item.id === 1).canCreateXrayInbound, true);
      assert.equal(options.find((item) => item.id === 5).os, "freebsd");
      assert.equal(JSON.stringify(options).includes("osInfo"), false);

      const page = await caller.inbounds.list({ page: 1, pageSize: 2, search: "node", sortBy: "updatedAt", sortOrder: "desc" });
      assert.deepEqual(page.items.map((item) => item.id), [103, 102]);
      assert.equal(page.totalItems, 4);
      const statuses = Object.fromEntries((await caller.inbounds.list({ page: 1, pageSize: 100, sortBy: "updatedAt", sortOrder: "desc" })).items.map((item) => [item.id, item.deploymentStatus]));
      assert.deepEqual(statuses, { 100: "RUNNING", 101: "DISABLED", 102: "HOST_OFFLINE", 103: "PENDING_DELETE" });
      const runningOnly = await caller.inbounds.list({ page: 1, pageSize: 10, status: "RUNNING", sortBy: "updatedAt", sortOrder: "desc" });
      assert.deepEqual(runningOnly.items.map((item) => item.id), [100]);
      await assert.rejects(
        () => caller.inbounds.list({ page: 1, unexpected: secretMarker }),
        (error) => error?.code === "BAD_REQUEST",
      );

      const detail = await caller.inbounds.detail({ id: 100 });
      assert.equal(detail.inbound.hasRealityPrivateKey, true);
      assert.equal(detail.clients[0].credentials.uuidConfigured, true);
      assert.equal(detail.deployment.configInSync, true);
      assert.equal(detail.deployment.status, "RUNNING");
      assert.equal(JSON.stringify(detail).includes(secretMarker), false);
      await assert.rejects(() => caller.inbounds.detail({ id: 999 }), (error) => error?.code === "NOT_FOUND");

      const runtimes = await caller.runtimes.list({ page: 1, pageSize: 100, sortBy: "hostName", sortOrder: "asc" });
      const readyRuntime = runtimes.items.find((item) => item.hostId === 1);
      assert.equal(readyRuntime.configInSync, true);
      assert.equal(readyRuntime.canManageXray, true);
      assert.equal(readyRuntime.inboundCount, 3);
      assert.equal(readyRuntime.hasUpgrade, false);
      assert.equal(runtimes.items.find((item) => item.hostId === 6).unavailableReasonCode, "ARTIFACT_UNAVAILABLE");
      const hostRuntime = await caller.runtimes.list({ page: 1, pageSize: 20, hostId: 1 });
      assert.deepEqual(hostRuntime.items.map((item) => item.hostId), [1]);
      const selectedRuntimes = await caller.runtimes.list({ page: 1, pageSize: 100, hostIds: [6, 1] });
      assert.deepEqual(selectedRuntimes.items.map((item) => item.hostId), [6, 1]);
      await assert.rejects(
        () => caller.runtimes.list({ page: 1, hostId: 1, hostIds: [1] }),
        (error) => error?.code === "BAD_REQUEST",
      );
      const catalog = await caller.runtimes.catalog();
      assert.equal(catalog.defaultVersion, "v26.3.27");
      assert.deepEqual(catalog.artifacts, [
        { os: "linux", arch: "amd64", verified: true },
        { os: "linux", arch: "arm64", verified: false },
      ]);
      assert.equal(JSON.stringify(catalog).includes("storageKey"), false);
      assert.equal(JSON.stringify(catalog).includes("source"), false);

      const operation = await caller.operations.get({ operationId: "unsafe-operation" });
      assert.equal(operation.errorCode, "INTERNAL_ERROR");
      assert.equal(operation.stage, "VALIDATING_CONFIG");
      assert.equal(operation.errorMessage.includes(secretMarker), false);
      assert.equal(JSON.stringify(operation).includes(secretMarker), false);
      const operationPage = await caller.operations.list({ page: 1, pageSize: 2, hostId: 1, sortOrder: "desc" });
      assert.deepEqual(operationPage.items.map((item) => item.operationId), ["unsafe-operation", "sync-success"]);

      const memberCaller = xrayRouter.createCaller(context(member));
      await assert.rejects(() => memberCaller.hosts.options(), (error) => error?.code === "FORBIDDEN");
      await assert.rejects(() => memberCaller.runtimes.catalog(), (error) => error?.code === "FORBIDDEN");
    } finally {
      await runtime.closeDatabase().catch(() => undefined);
    }
  `;
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: { ...process.env, DATABASE_TYPE: "sqlite", FORWARDX_TEST_DB: databasePath, JWT_SECRET: "xray-query-test-secret" },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
