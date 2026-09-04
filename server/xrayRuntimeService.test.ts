import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("Xray runtime operations enforce version, host, task, and observed-state boundaries", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-runtime-service-"));
  const databasePath = path.join(directory, "runtime.db");
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const db = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const artifacts = await import(moduleUrl("server/xrayArtifacts.ts"));
    const heartbeat = await import(moduleUrl("server/xrayHeartbeatState.ts"));
    const runtimeOps = await import(moduleUrl("server/xrayRuntimeOperations.ts"));
    const runtimeService = await import(moduleUrl("server/xrayRuntimeService.ts"));
    const { xrayRouter } = await import(moduleUrl("server/routers/xray.ts"));
    const context = (user) => ({ req: { headers: {} }, res: { clearCookie() {} }, user, authSession: null, authFailureReason: null });
    const admin = { id: 1, username: "admin", role: "admin", accountEnabled: true };
    const member = { id: 2, username: "member", role: "user", accountEnabled: true };
    const now = Math.floor(Date.now() / 1000);
    try {
      await db.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      await db.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin'), (2, 'member', 'hash', 'user')");
      for (const [id, name, online] of [[1, "sync-host", 1], [2, "upgrade-host", 1], [3, "newer-host", 1], [4, "offline-host", 0], [5, "install-host", 1], [6, "restart-host", 1], [7, "rollback-host", 1]]) {
        await db.executeRaw("INSERT INTO hosts (id, name, ip, ipv4, isOnline, lastHeartbeat, agentVersion, agentDistribution, userId) VALUES (?, ?, '8.8.8.8', '8.8.8.8', ?, ?, '2.3.278', 'forwardplus', 1)", [id, name, online, now]);
        await db.executeRaw("INSERT INTO xray_runtime_reports (hostId, capabilitySchemaVersion, supportedOS, supportedArch, supportsArtifactInstall, supportsPortProbe, supportsRealityScan, isInstalled, installedVersion, runningVersion, serviceStatus, appliedGeneration, reportedAt) VALUES (?, 1, 'linux', 'amd64', 1, 1, 1, ?, ?, ?, ?, ?, ?)", [
          id,
          id === 5 ? 0 : 1,
          id === 5 ? null : id === 2 || id === 7 ? "v25.1.1" : id === 3 ? "v27.1.1" : "v26.3.27",
          id === 6 ? "v26.3.27" : null,
          id === 6 ? "RUNNING" : "STOPPED",
          id === 2 || id === 3 || id === 7 ? 2 : 0,
          now,
        ]);
      }
      const artifact = artifacts.XRAY_ARTIFACT_MANIFEST.find((entry) => entry.arch === "amd64");
      await db.executeRaw("INSERT INTO xray_artifacts (version, os, arch, packageFormat, storageKey, sha256, fileSize, status, source, verifiedAt) VALUES (?, ?, ?, ?, ?, ?, ?, 'VERIFIED', ?, ?)", [artifact.version, artifact.os, artifact.arch, artifact.packageFormat, artifact.storageKey, artifact.sha256, artifact.fileSize, artifact.source, now]);
      for (const hostId of [1, 2, 3, 6, 7]) {
        await db.executeRaw("INSERT INTO xray_host_deployments (hostId, targetVersion, desiredGeneration, desiredConfigHash) VALUES (?, 'v26.3.27', ?, NULL)", [hostId, hostId === 2 || hostId === 3 || hostId === 7 ? 2 : 0]);
        const desired = await heartbeat.buildXrayHeartbeatDesiredState(hostId);
        await db.executeRaw("UPDATE xray_runtime_reports SET appliedConfigHash = ? WHERE hostId = ?", [desired.configHash, hostId]);
      }

      const caller = xrayRouter.createCaller(context(admin));
      const sync = await caller.runtimes.sync({ hostId: 1 });
      assert.equal(sync.desiredGeneration, 1);
      assert.equal((await caller.operations.get({ operationId: sync.operationId })).type, "SYNC");
      assert.deepEqual(await runtimeOps.takeXrayRuntimeTasks(1, 4), []);
      const syncDesired = await heartbeat.buildXrayHeartbeatDesiredState(1);
      const syncObserved = {
        schemaVersion: 1, isInstalled: true, installedVersion: "v26.3.27", runningVersion: null,
        serviceStatus: "STOPPED", processId: null, binarySha256: "b".repeat(64),
        appliedGeneration: syncDesired.generation, appliedConfigHash: syncDesired.configHash, listeners: [], lastError: null,
        observedAt: new Date().toISOString(),
      };
      await heartbeat.processXrayHeartbeatReport({ hostId: 1, xrayStateSignature: heartbeat.xrayObservedStateSignature(syncObserved), xrayState: syncObserved });
      assert.equal((await caller.operations.get({ operationId: sync.operationId })).status, "SUCCESS");

      await assert.rejects(() => caller.runtimes.sync({ hostId: 2 }), (error) => error?.message === "XRAY_VERSION_MISMATCH");
      const upgrade = await caller.runtimes.upgrade({ hostId: 2, targetVersion: "v26.3.27", expectedInstalledVersion: "v25.1.1" });
      const [upgradeTask] = await runtimeOps.takeXrayRuntimeTasks(2, 1);
      assert.equal(upgradeTask.type, "UPGRADE");
      await assert.rejects(() => caller.runtimes.upgrade({ hostId: 2, targetVersion: "v26.3.27", expectedInstalledVersion: "v25.1.1" }), (error) => error?.message === "OPERATION_CONFLICT");
      await runtimeOps.completeXrayRuntimeTask(2, {
        schemaVersion: 1, taskId: upgradeTask.taskId, type: "UPGRADE", status: "SUCCESS",
        startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(), error: null,
        result: { previousVersion: "v25.1.1", installedVersion: "v26.3.27", binarySha256: "c".repeat(64), rolledBack: false },
      });
      const upgradedDesired = await heartbeat.buildXrayHeartbeatDesiredState(2);
      const upgradedObserved = { ...syncObserved, appliedGeneration: upgradedDesired.generation, appliedConfigHash: upgradedDesired.configHash };
      await heartbeat.processXrayHeartbeatReport({ hostId: 2, xrayStateSignature: heartbeat.xrayObservedStateSignature(upgradedObserved), xrayState: upgradedObserved });
      assert.equal((await caller.operations.get({ operationId: upgrade.operationId })).status, "SUCCESS");

      await assert.rejects(
        () => caller.runtimes.upgrade({ hostId: 3, targetVersion: "v26.3.27", expectedInstalledVersion: "v27.1.1" }),
        (error) => error?.message === "DOWNGRADE_NOT_ALLOWED",
      );
      await assert.rejects(() => caller.runtimes.restart({ hostId: 4, confirmHostName: "offline-host" }), (error) => error?.message === "HOST_OFFLINE");

      const install = await caller.runtimes.install({ hostId: 5 });
      const [installTask] = await runtimeOps.takeXrayRuntimeTasks(5, 1);
      assert.equal(installTask.type, "INSTALL");
      assert.equal(installTask.taskId, install.operationId);
      await runtimeOps.completeXrayRuntimeTask(5, {
        schemaVersion: 1, taskId: installTask.taskId, type: "INSTALL", status: "SUCCESS",
        startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(), error: null,
        result: { installedVersion: "v26.3.27", binarySha256: "d".repeat(64), reused: false },
      });
      assert.equal((await caller.operations.get({ operationId: install.operationId })).status, "SUCCESS");

      await assert.rejects(() => caller.runtimes.restart({ hostId: 6, confirmHostName: "wrong-name" }), (error) => error?.message === "CONFIRMATION_MISMATCH");
      const restart = await caller.runtimes.restart({ hostId: 6, confirmHostName: "restart-host" });
      const [restartTask] = await runtimeOps.takeXrayRuntimeTasks(6, 1);
      assert.equal(restartTask.type, "RESTART");
      await runtimeOps.completeXrayRuntimeTask(6, {
        schemaVersion: 1, taskId: restartTask.taskId, type: "RESTART", status: "SUCCESS",
        startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(), error: null,
        result: { previousVersion: "v26.3.27", runningVersion: "v26.3.27", serviceStatus: "RUNNING", readyListenerCount: 0 },
      });
      assert.equal((await caller.operations.get({ operationId: restart.operationId })).status, "SUCCESS");

      const rollback = await caller.runtimes.upgrade({ hostId: 7, targetVersion: "v26.3.27", expectedInstalledVersion: "v25.1.1" });
      const [rollbackTask] = await runtimeOps.takeXrayRuntimeTasks(7, 1);
      await runtimeOps.completeXrayRuntimeTask(7, {
        schemaVersion: 1, taskId: rollbackTask.taskId, type: "UPGRADE", status: "SUCCESS",
        startedAt: new Date().toISOString(), finishedAt: new Date().toISOString(), error: null,
        result: { previousVersion: "v25.1.1", installedVersion: "v26.3.27", binarySha256: "e".repeat(64), rolledBack: false },
      });
      const rollbackDesired = await heartbeat.buildXrayHeartbeatDesiredState(7);
      const rolledBackObserved = {
        ...syncObserved,
        installedVersion: "v25.1.1", appliedGeneration: rollbackDesired.generation, appliedConfigHash: rollbackDesired.configHash,
        lastError: { code: "RUNTIME_START_FAILED", message: "Managed Xray could not be started", generation: rollbackDesired.generation, occurredAt: new Date().toISOString() },
      };
      await heartbeat.processXrayHeartbeatReport({ hostId: 7, xrayStateSignature: heartbeat.xrayObservedStateSignature(rolledBackObserved), xrayState: rolledBackObserved });
      const rollbackOperation = await caller.operations.get({ operationId: rollback.operationId });
      assert.equal(rollbackOperation.status, "FAILED");
      assert.equal(rollbackOperation.errorCode, "RUNTIME_START_FAILED");
      assert.equal(rollbackOperation.stage, "RESTARTING_RUNTIME");
      const rollbackRuntime = (await caller.runtimes.list({ hostId: 7, page: 1, pageSize: 1 })).items[0];
      assert.equal(rollbackRuntime.installedVersion, "v25.1.1");
      assert.equal(rollbackRuntime.hasUpgrade, true);
      assert.equal(rollbackRuntime.lastErrorCode, "RUNTIME_START_FAILED");

      const memberCaller = xrayRouter.createCaller(context(member));
      await assert.rejects(() => memberCaller.runtimes.install({ hostId: 5 }), (error) => error?.code === "FORBIDDEN");
      const serialized = JSON.stringify(await caller.operations.list({ page: 1, pageSize: 100 }));
      for (const forbidden of ["configJson", "storageKey", "privateKey", "token"]) assert.equal(serialized.includes(forbidden), false);
    } finally {
      await db.closeDatabase().catch(() => undefined);
    }
  `;
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: { ...process.env, DATABASE_TYPE: "sqlite", FORWARDX_TEST_DB: databasePath, JWT_SECRET: "xray-runtime-service-test" },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
