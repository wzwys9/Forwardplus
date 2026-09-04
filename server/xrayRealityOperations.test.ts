import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("Xray Reality operations enforce panel policy and persist only structured safe results", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-reality-operations-"));
  const databasePath = path.join(directory, "operations.db");
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const candidates = await import(moduleUrl("server/xrayRealityCandidates.ts"));
    const operations = await import(moduleUrl("server/xrayRealityOperations.ts"));
    const { xrayRouter } = await import(moduleUrl("server/routers/xray.ts"));
    const expectCode = async (promise, code) => assert.rejects(promise, (error) => error?.code === code);
    const nowIso = () => new Date().toISOString();
    const resolverCalls = [];
    const resolveHost = async (host) => {
      resolverCalls.push(host);
      if (host === "blocked.example.com") return ["169.254.169.254"];
      if (host === "mixed.example.com") return ["1.1.1.1", "10.0.0.1"];
      if (host === "many.example.com") return Array.from({ length: 17 }, (_, index) => "1.1.1." + (index + 1));
      if (host === "missing.example.com") throw new Error("NXDOMAIN private resolver detail");
      return host.includes("microsoft") ? ["8.8.8.8"] : ["1.1.1.1"];
    };
    const create = (input) => operations.createXrayRealityScanOperation(input, { resolveHost });
    const successfulResult = (task) => ({
      schemaVersion: 1,
      taskId: task.taskId,
      type: "REALITY_SCAN",
      status: "SUCCESS",
      startedAt: nowIso(),
      finishedAt: nowIso(),
      result: {
        results: [...task.payload.targets].reverse().map((target, index) => {
          const [host, rawPort] = target.split(":");
          const feasible = index !== 0 || task.payload.targets.length === 1;
          return {
            target,
            host,
            resolvedIp: host.includes("microsoft") ? "8.8.8.8" : "1.1.1.1",
            port: Number(rawPort),
            feasible,
            tls13: true,
            h2: feasible,
            x25519: true,
            certificateValid: true,
            serverNames: feasible ? [host] : [],
            latencyMs: feasible ? 10 : 5,
            reasonCode: feasible ? null : "REALITY_TLS_UNSUPPORTED",
            ...(feasible ? {} : { reasonMessage: "private route 10.0.0.1 and raw certificate output" }),
          };
        }),
        observedAt: nowIso(),
      },
      error: null,
    });

    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      const heartbeat = Math.floor(Date.now() / 1000);
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin-a', 'hash', 'admin'), (2, 'admin-b', 'hash', 'admin')");
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, isOnline, lastHeartbeat, userId) VALUES (10, 'edge-a', '192.0.2.10', 1, ?, 1), (11, 'edge-b', '192.0.2.11', 1, ?, 1)", [heartbeat, heartbeat]);
      await runtime.executeRaw("INSERT INTO xray_runtime_reports (hostId, capabilitySchemaVersion, supportsRealityScan) VALUES (10, 1, 1), (11, 1, 1)");

      assert.equal(candidates.XRAY_REALITY_CANDIDATE_LIST_VERSION, "v2");
      assert.deepEqual(candidates.XRAY_REALITY_DEFAULT_CANDIDATES, [
        "www.cloudflare.com:443",
        "www.amazon.com:443",
        "aws.amazon.com:443",
        "www.samsung.com:443",
        "www.nvidia.com:443",
        "www.amd.com:443",
        "www.intel.com:443",
        "www.sony.com:443",
        "dl.google.com:443",
      ]);
      assert.deepEqual(operations.normalizeXrayRealityTargets(["GOOD.Example.com:443", "good.example.com:443"]), ["good.example.com:443"]);
      for (const invalid of ["10.0.0.0/8", "https://example.com", "user@example.com:443", "example.com:0", "localhost:443"] ) {
        await expectCode(Promise.resolve().then(() => operations.normalizeXrayRealityTargets([invalid])), "REALITY_TARGET_INVALID");
      }
      assert.equal(operations.isAllowedXrayRealityAddressText("1.1.1.1"), true);
      assert.equal(operations.isAllowedXrayRealityAddressText("2606:4700:4700::1111"), true);
      for (const blocked of ["127.0.0.1", "169.254.169.254", "168.63.129.16", "192.0.2.1", "::1", "fc00::1", "2001:db8::1", "4000::1"]) {
        assert.equal(operations.isAllowedXrayRealityAddressText(blocked), false, blocked);
      }
      const tooManyTargets = Array.from({ length: 65 }, (_, index) => "host-" + index + ".example.com:443");
      await expectCode(Promise.resolve().then(() => operations.normalizeXrayRealityTargets(tooManyTargets)), "REALITY_TARGET_INVALID");

      await runtime.executeRaw("UPDATE hosts SET isOnline = 0 WHERE id = 10");
      await expectCode(create({ hostId: 10, userId: 1, source: "ADMIN_DOMAINS", targets: ["good.example.com:443"] }), "HOST_OFFLINE");
      assert.equal(resolverCalls.length, 0);
      await runtime.executeRaw("UPDATE hosts SET isOnline = 1, lastHeartbeat = ? WHERE id = 10", [Math.floor(Date.now() / 1000) - 3600]);
      await expectCode(create({ hostId: 10, userId: 1, source: "ADMIN_DOMAINS", targets: ["good.example.com:443"] }), "HOST_OFFLINE");
      await runtime.executeRaw("UPDATE hosts SET isOnline = 1, lastHeartbeat = ? WHERE id = 10", [Math.floor(Date.now() / 1000)]);
      await runtime.executeRaw("UPDATE xray_runtime_reports SET capabilitySchemaVersion = 0 WHERE hostId = 10");
      await expectCode(create({ hostId: 10, userId: 1, source: "ADMIN_DOMAINS", targets: ["good.example.com:443"] }), "AGENT_CAPABILITY_MISSING");
      await runtime.executeRaw("UPDATE xray_runtime_reports SET capabilitySchemaVersion = 1 WHERE hostId = 10");
      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsRealityScan = 0 WHERE hostId = 10");
      await expectCode(create({ hostId: 10, userId: 1, source: "ADMIN_DOMAINS", targets: ["good.example.com:443"] }), "AGENT_CAPABILITY_MISSING");
      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsRealityScan = 1 WHERE hostId = 10");
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_operations"))[0].count, 0);

      for (const [target, code] of [["blocked.example.com:443", "REALITY_TARGET_BLOCKED"], ["mixed.example.com:443", "REALITY_TARGET_BLOCKED"], ["many.example.com:443", "REALITY_TARGET_BLOCKED"], ["missing.example.com:443", "REALITY_TARGET_INVALID"]]) {
        const before = (await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_operations"))[0].count;
        await expectCode(create({ hostId: 10, userId: 1, source: "ADMIN_DOMAINS", targets: [target] }), code);
        assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_operations"))[0].count, before);
      }

      const legacyVersionOperation = await create({ hostId: 10, userId: 1, source: "DEFAULT_CANDIDATES" });
      const [legacyVersionRow] = await runtime.queryRaw("SELECT requestMetaJson FROM xray_operations WHERE operationId = ?", [legacyVersionOperation.operationId]);
      const legacyVersionMeta = JSON.parse(legacyVersionRow.requestMetaJson);
      legacyVersionMeta.candidateListVersion = "v1";
      await runtime.executeRaw("UPDATE xray_operations SET requestMetaJson = ? WHERE operationId = ?", [JSON.stringify(legacyVersionMeta), legacyVersionOperation.operationId]);
      assert.deepEqual(await operations.takeXrayRealityScanTasks(10, 1), []);
      const legacyVersionStatus = await operations.getXrayRealityScanOperationResult(legacyVersionOperation.operationId, 1);
      assert.equal(legacyVersionStatus.status, "FAILED");
      assert.equal(legacyVersionStatus.errorCode, "INVALID_PAYLOAD");

      const defaultOperation = await create({ hostId: 10, userId: 1, source: "DEFAULT_CANDIDATES" });
      const adminOperation = await create({ hostId: 10, userId: 1, source: "ADMIN_DOMAINS", targets: ["GOOD.Example.com:443"] });
      await expectCode(create({ hostId: 10, userId: 1, source: "ADMIN_DOMAINS", targets: ["third.example.com:443"] }), "OPERATION_CONFLICT");
      assert.equal(await operations.hasQueuedXrayRealityScanTasks(10), true);
      const tasks = await operations.takeXrayRealityScanTasks(10, 4);
      assert.equal(tasks.length, 2);
      assert.deepEqual(tasks[0].payload.targets, candidates.XRAY_REALITY_DEFAULT_CANDIDATES);
      assert.deepEqual(tasks[1].payload.targets, ["good.example.com:443"]);
      assert.equal(tasks.every((task) => task.payload.timeoutMs === 10000 && task.payload.maxConcurrency === 16), true);

      await Promise.all(tasks.map((task) => operations.completeXrayRealityScanTask(10, successfulResult(task))));
      const defaultResult = await operations.getXrayRealityScanOperationResult(defaultOperation.operationId, 1);
      const adminResult = await operations.getXrayRealityScanOperationResult(adminOperation.operationId, 1);
      assert.equal(defaultResult.status, "SUCCESS");
      assert.equal(defaultResult.candidateListVersion, "v2");
      assert.equal(defaultResult.results.length, 9);
      assert.equal(defaultResult.results.slice(0, 8).every((item) => item.feasible), true);
      assert.equal(defaultResult.results[8].feasible, false);
      assert.equal("reasonMessage" in defaultResult.results[8], false);
      assert.deepEqual(adminResult.results.map((item) => item.target), ["good.example.com:443"]);
      const persisted = JSON.stringify((await runtime.queryRaw("SELECT requestMetaJson, resultJson, errorMessage FROM xray_operations WHERE type = 'REALITY_SCAN'")));
      for (const forbidden of ["private route", "raw certificate", "10.0.0.1", "privateKey", "uuid", "token"]) {
        assert.equal(persisted.toLowerCase().includes(forbidden.toLowerCase()), false, forbidden);
      }
      assert.deepEqual(await operations.acceptXrayRealityTaskResults(10, [successfulResult(tasks[0])]), [tasks[0].taskId]);

      const invalidOperation = await create({ hostId: 10, userId: 1, source: "ADMIN_DOMAINS", targets: ["invalid-result.example.com:443"] });
      const [invalidTask] = await operations.takeXrayRealityScanTasks(10, 1);
      const invalidResult = successfulResult(invalidTask);
      invalidResult.result.results[0].resolvedIp = "10.0.0.1";
      assert.deepEqual(await operations.acceptXrayRealityTaskResults(10, [invalidResult]), [invalidTask.taskId]);
      const invalidStatus = await operations.getXrayRealityScanOperationResult(invalidOperation.operationId, 1);
      assert.equal(invalidStatus.status, "FAILED");
      assert.equal(invalidStatus.errorCode, "INVALID_PAYLOAD");
      assert.equal(JSON.stringify(await runtime.queryRaw("SELECT resultJson, errorMessage FROM xray_operations WHERE operationId = ?", [invalidOperation.operationId])).includes("10.0.0.1"), false);

      const mismatchOperation = await create({ hostId: 10, userId: 1, source: "ADMIN_DOMAINS", targets: ["mismatch.example.com:443"] });
      const [mismatchTask] = await operations.takeXrayRealityScanTasks(10, 1);
      assert.deepEqual(await operations.acceptXrayRealityTaskResults(11, [successfulResult(mismatchTask)]), []);
      assert.equal((await operations.getXrayRealityScanOperationResult(mismatchOperation.operationId, 1)).status, "RUNNING");
      await operations.completeXrayRealityScanTask(10, successfulResult(mismatchTask));

      const tamperedOperation = await create({ hostId: 10, userId: 1, source: "ADMIN_DOMAINS", targets: ["tampered.example.com:443"] });
      const [tamperedTask] = await operations.takeXrayRealityScanTasks(10, 1);
      await operations.completeXrayRealityScanTask(10, successfulResult(tamperedTask));
      const [storedTampered] = await runtime.queryRaw("SELECT resultJson FROM xray_operations WHERE operationId = ?", [tamperedOperation.operationId]);
      const tamperedJson = JSON.parse(storedTampered.resultJson);
      tamperedJson.results[0].resolvedIp = "169.254.169.254";
      await runtime.executeRaw("UPDATE xray_operations SET resultJson = ? WHERE operationId = ?", [JSON.stringify(tamperedJson), tamperedOperation.operationId]);
      await expectCode(operations.getXrayRealityScanOperationResult(tamperedOperation.operationId, 1), "OPERATION_CONFLICT");

      const failedOperation = await create({ hostId: 10, userId: 1, source: "ADMIN_DOMAINS", targets: ["failed.example.com:443"] });
      const [failedTask] = await operations.takeXrayRealityScanTasks(10, 1);
      await operations.completeXrayRealityScanTask(10, {
        schemaVersion: 1, taskId: failedTask.taskId, type: "REALITY_SCAN", status: "FAILED",
        startedAt: nowIso(), finishedAt: nowIso(), result: null,
        error: { code: "PRIVATE_KEY_LEAK", message: "uuid-secret-marker", retryable: false },
      });
      const failedResult = await operations.getXrayRealityScanOperationResult(failedOperation.operationId, 1);
      assert.equal(failedResult.errorCode, "INTERNAL_ERROR");
      assert.equal(JSON.stringify(await runtime.queryRaw("SELECT errorCode, errorMessage FROM xray_operations WHERE operationId = ?", [failedOperation.operationId])).includes("uuid-secret-marker"), false);
      await runtime.executeRaw("UPDATE xray_operations SET errorCode = ? WHERE operationId = ?", ["PRIVATE_KEY_LEAK", failedOperation.operationId]);
      assert.equal((await operations.getXrayRealityScanOperationResult(failedOperation.operationId, 1)).errorCode, "INTERNAL_ERROR");

      const timeoutOperation = await create({ hostId: 10, userId: 1, source: "ADMIN_DOMAINS", targets: ["timeout.example.com:443"] });
      await runtime.executeRaw("UPDATE xray_operations SET expiresAt = 0 WHERE operationId = ?", [timeoutOperation.operationId]);
      assert.deepEqual(await operations.takeXrayRealityScanTasks(10, 1), []);
      const timeoutResult = await operations.getXrayRealityScanOperationResult(timeoutOperation.operationId, 1);
      assert.equal(timeoutResult.status, "TIMEOUT");
      assert.equal(timeoutResult.errorCode, "TASK_EXPIRED");
      await expectCode(operations.getXrayRealityScanOperationResult(timeoutOperation.operationId, 2), "OPERATION_CONFLICT");

      const context = (user) => ({ req: { headers: {} }, res: { clearCookie() {} }, user, authSession: null, authFailureReason: null });
      const caller = xrayRouter.createCaller(context({ id: 1, username: "admin-a", role: "admin", accountEnabled: true }));
      const memberCaller = xrayRouter.createCaller(context({ id: 2, username: "member", role: "user", accountEnabled: true }));
      await assert.rejects(() => memberCaller.realityScans.create({ hostId: 10, source: "DEFAULT_CANDIDATES" }), (error) => error?.code === "FORBIDDEN");
      await assert.rejects(() => caller.realityScans.create({ hostId: 10, source: "DEFAULT_CANDIDATES", targets: ["unexpected.example.com:443"] }), (error) => error?.code === "BAD_REQUEST");
      const routedResult = await caller.realityScans.result({ operationId: defaultOperation.operationId });
      assert.equal(routedResult.status, "SUCCESS");
      assert.equal(routedResult.results[0].feasible, true);
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
        FORWARDX_TEST_DB: databasePath,
        JWT_SECRET: "xray-reality-operations-test-secret",
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
