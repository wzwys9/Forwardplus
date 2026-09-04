import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("Xray history cleanup preserves active/referenced operations and current/last-good artifacts", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-cleanup-"));
  const script = String.raw`
    import assert from "node:assert/strict";
    import fs from "node:fs";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const runtime = await load("server/dbRuntime.ts");
    const schema = await load("server/dbSchema.ts");
    const cleanup = await load("server/xrayHistoryCleanup.ts");
    const old = new Date("2025-01-01T00:00:00.000Z");
    const recent = new Date("2026-08-31T00:00:00.000Z");
    const insertArtifact = (id, version, arch = "amd64", updatedAt = old) => runtime.insertAndGetId("xray_artifacts", {
      id, version, os: "linux", arch, packageFormat: "zip", storageKey: "xray/artifacts/" + version + "/" + arch + ".zip",
      sha256: String(id).padStart(64, "0"), fileSize: 100 + id, status: "VERIFIED", createdAt: updatedAt, updatedAt,
    });
    const insertOperation = (id, operationId, status, updatedAt, requestMetaJson = null) => runtime.insertAndGetId("xray_operations", {
      id, operationId, hostId: 1, inboundId: null, type: "SYNC", status, requestMetaJson,
      attemptCount: 0, createdByUserId: 1, createdAt: old, updatedAt,
    });
    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, userId) VALUES (1, 'edge', '127.0.0.1', 1)");
      await insertArtifact(1, "v26.3.27");
      await insertArtifact(2, "v25.1.1");
      await insertArtifact(3, "v24.1.1");
      await insertArtifact(4, "v23.1.1");
      await insertArtifact(5, "v22.1.1", "amd64", recent);
      await insertArtifact(6, "v21.1.1");
      const unsafePath = path.join(process.env.FORWARDX_TEST_DATA, "xray/artifacts/v21.1.1/amd64.zip");
      fs.mkdirSync(path.dirname(unsafePath), { recursive: true });
      fs.symlinkSync(process.env.FORWARDX_TEST_DB, unsafePath);
      await insertOperation(1, "active-queued", "QUEUED", old);
      await insertOperation(2, "active-running", "RUNNING", old, JSON.stringify({ version: "v24.1.1" }));
      await insertOperation(3, "referenced-terminal", "SUCCESS", old);
      await insertOperation(4, "recent-terminal", "FAILED", recent);
      await insertOperation(5, "expired-terminal", "TIMEOUT", old);
      await runtime.insertAndGetId("xray_host_deployments", {
        hostId: 1, targetVersion: "v26.3.27", desiredGeneration: 1, lastOperationId: "referenced-terminal",
        createdAt: old, updatedAt: old,
      });
      await runtime.insertAndGetId("xray_runtime_reports", {
        hostId: 1, capabilitySchemaVersion: 1, isInstalled: true, installedVersion: "v25.1.1",
        runningVersion: "v25.1.1", serviceStatus: "RUNNING", appliedGeneration: 1,
        updatedAt: old,
      });
      const result = await cleanup.cleanOldXrayHistory({
        now: new Date("2026-09-01T00:00:00.000Z"), retainDays: 30, artifactDataDirectory: process.env.FORWARDX_TEST_DATA,
      });
      assert.equal(result.deletedOperations, 1);
      assert.deepEqual(
        (await runtime.queryRaw("SELECT operationId FROM xray_operations ORDER BY id")).map((row) => row.operationId),
        ["active-queued", "active-running", "referenced-terminal", "recent-terminal"],
      );
      assert.deepEqual(
        (await runtime.queryRaw("SELECT version FROM xray_artifacts ORDER BY id")).map((row) => row.version),
        ["v26.3.27", "v25.1.1", "v24.1.1", "v22.1.1", "v21.1.1"],
      );
      assert.equal(result.deletedArtifacts, 1);
      assert.equal(result.skippedArtifactFiles, 1);
    } finally {
      await runtime.closeDatabase();
    }
  `;
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: {
        ...process.env, DATABASE_TYPE: "sqlite", FORWARDX_TEST_DB: path.join(directory, "panel.db"),
        FORWARDX_TEST_DATA: path.join(directory, "data"),
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
