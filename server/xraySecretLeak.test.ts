import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("Xray secret leak target scans panel logs, audit, operation, API error, and generated support bundle", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-secret-leak-"));
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const db = await load("server/dbRuntime.ts");
    const schema = await load("server/dbSchema.ts");
    const hosts = await load("server/repositories/hostRepository.ts");
    const repository = await load("server/repositories/xrayRepository.ts");
    const queries = await load("server/xrayQueryService.ts");
    const audit = await load("server/configAudit.ts");
    const observability = await load("server/xrayMutationObservability.ts");
    const panelLogger = await load("server/_core/panelLogger.ts");
    const support = await load("server/supportBundle.ts");
    const inboundService = await load("server/xrayInboundService.ts");
    const wireGuardPrivateKey = "ICEhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4=";
    const wireGuardPsk = "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8=";
    const secrets = {
      token: "xray-token-UNIQUE-031-target",
      uuid: "03103103-1031-4031-8031-031031031031",
      privateKey: "PRIVATEKEYUNIQUE031-target",
      shortId: "0310310310310310",
      configJson: "CONFIGJSONUNIQUE031-target",
      shareUri: "vless://03103103-1031-4031-8031-031031031031@example.com:443?sid=0310310310310310",
      httpUsername: "HTTPUSERNAMEUNIQUE052",
      httpPassword: "HTTPPASSWORDUNIQUE052",
      httpProxyUri: "http://HTTPUSERNAMEUNIQUE052:HTTPPASSWORDUNIQUE052@example.com:3128",
      wireGuardPrivateKey,
      wireGuardPsk,
      wireGuardConfig: [
        "[Interface]",
        "PrivateKey = " + wireGuardPrivateKey,
        "Address = 10.0.0.2/32",
        "",
        "[Peer]",
        "PresharedKey = " + wireGuardPsk,
        "Endpoint = edge.example.com:51820",
      ].join("\n"),
    };
    try {
      await db.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      const hostId = await hosts.createHost({ name: "edge", ip: "127.0.0.1", userId: 1, agentToken: secrets.token });
      await observability.recordXrayMutationObservability({
        event: "SECRET_LEAK_TARGET",
        resourceType: "xray_runtime",
        resourceId: hostId,
        hostId,
        action: "dispatch",
        fields: { userId: 1, hostId, generation: 31, status: "FAILED", ...secrets },
      });
      const now = db.nowDate();
      await db.insertAndGetId("xray_operations", {
        operationId: "operation-secret-leak-target", hostId, inboundId: null, type: "SYNC",
        requestedGeneration: 31, status: "FAILED", errorCode: "CONFIG_INVALID",
        errorMessage: secrets.privateKey, resultJson: JSON.stringify(secrets), attemptCount: 1,
        createdByUserId: 1, createdAt: now, updatedAt: now,
      });
      const operation = await repository.getXrayOperation("operation-secret-leak-target");
      const apiOperation = await queries.getXrayOperationSummary("operation-secret-leak-target");
      const apiError = new inboundService.XrayInboundCreateError("INVALID_CONFIG_INPUT");
      const task = support.createSupportBundleTask([{ id: hostId, name: "edge", isOnline: true, agentToken: secrets.token }]);
      assert.equal(support.completeSupportBundleHost(task.taskId, hostId, {
        diagnostics: {
          xrayRuntime: {
            installedVersion: "26.7.28", serviceStatus: "RUNNING", configHashPrefix: "aaaaaaaaaaaa",
            listeners: [{ runtimeTag: "forwardx-inbound-safe", port: 443, status: "READY", network: "tcp" }],
            processId: 3131, generation: 31, ...secrets,
          },
          wireGuardDiagnostics: {
            wireGuardPrivateKey: secrets.wireGuardPrivateKey,
            wireGuardPsk: secrets.wireGuardPsk,
            wireGuardConfig: secrets.wireGuardConfig,
          },
          commands: [{ output: "Authorization: Bearer " + secrets.token + " uuid=" + secrets.uuid + "\n" + secrets.wireGuardConfig }],
        },
      }), true);
      const bundle = await support.getSupportBundleTask(task.taskId);
      const surfaces = {
        logs: await panelLogger.formatPanelLogsForExport("all"),
        audits: await audit.listRecentConfigAuditEvents(),
        operation,
        apiOperation,
        apiError: { code: apiError.code, message: apiError.message },
        supportBundle: bundle?.download?.content,
      };
      const scan = JSON.stringify(surfaces);
      for (const [surface, value] of Object.entries(surfaces)) {
        const serialized = JSON.stringify(value);
        for (const [name, secret] of Object.entries(secrets)) {
          assert.equal(serialized.includes(secret), false, surface + ":" + name);
        }
      }
      assert.match(scan, /forwardx-inbound-safe/);
      assert.match(scan, /aaaaaaaaaaaa/);
    } finally {
      await db.closeDatabase();
    }
  `;
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        DATABASE_TYPE: "sqlite",
        FORWARDX_TEST_DB: path.join(directory, "panel.db"),
        FORWARDX_LOG_DIR: path.join(directory, "logs"),
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
