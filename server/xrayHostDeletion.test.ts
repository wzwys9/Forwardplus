import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("host deletion removes panel-owned Xray state but preserves shared artifacts", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-host-delete-"));
  const databasePath = path.join(directory, "host-delete.db");
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const db = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const hosts = await import(moduleUrl("server/repositories/hostRepository.ts"));
    try {
      await db.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      await db.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await db.executeRaw("INSERT INTO hosts (id, name, ip, isOnline, userId) VALUES (1, 'edge-orphan', '8.8.8.8', 0, 1)");
      await db.insertAndGetId("xray_artifacts", { version: "26.7.28", os: "linux", arch: "amd64", packageFormat: "zip", storageKey: "xray/shared.zip", sha256: "a".repeat(64), fileSize: 1, status: "VERIFIED" });
      const certificateId = await db.insertAndGetId("xray_tls_certificates", { hostId: 1, name: "delete-cert", certificateTag: "forwardx-cert-11111111-1111-4111-8111-111111111111", certificateChainPem: "certificate", privateKeyEncrypted: "encrypted-key", privateKeyFingerprint: "e".repeat(64), keyVersion: 1, leafFingerprintSha256: "f".repeat(64), dnsNamesJson: '["delete.example.com"]', subject: "CN=delete.example.com", issuer: "CN=delete.example.com", serialNumber: "01", notBefore: new Date(Date.now() - 1000), notAfter: new Date(Date.now() + 86400000), keyAlgorithm: "RSA_2048_4096", createdByUserId: 1 });
      await db.insertAndGetId("xray_inbounds", { id: 1, hostId: 1, name: "delete", runtimeTag: "forwardx-inbound-host-delete", publicAddress: "8.8.8.8", listenAddress: "0.0.0.0", listenPort: 22001, protocol: "vless", transport: "tcp", security: "reality", tlsCertificateId: certificateId, realityTargetHost: "www.microsoft.com", realityTargetPort: 443, realityServerName: "www.microsoft.com", realityPublicKey: "A".repeat(43), realityPrivateKeyEncrypted: "encrypted-private", secretKeyVersion: 1, fingerprint: "chrome", spiderX: "/", isEnabled: true, pendingDelete: false, desiredGeneration: 1, createdByUserId: 1 });
      const clientId = await db.insertAndGetId("xray_clients", { inboundId: 1, name: "client", uuidEncrypted: "encrypted-uuid", uuidFingerprint: "b".repeat(64), shortIdEncrypted: "encrypted-short", shortIdFingerprint: "c".repeat(64), statsKey: "forwardx-client-host-delete", flow: "xtls-rprx-vision", isEnabled: true, pendingDelete: false, desiredGeneration: 1, sortOrder: 0 });
      const accessId = await db.insertAndGetId("xray_access_entries", { inboundId: 1, legacyClientId: clientId, name: "client", credentialType: "UUID_AND_SHORT_ID", settingsJson: '{"schemaVersion":1,"flow":"XTLS_RPRX_VISION"}', statsKey: "forwardx-client-host-delete", isEnabled: true, pendingDelete: false, desiredGeneration: 1, sortOrder: 0 });
      await db.insertAndGetId("xray_access_secrets", { accessEntryId: accessId, kind: "UUID", encryptedValue: "generic-encrypted-uuid", fingerprint: "b".repeat(64), keyVersion: 1 });
      await db.insertAndGetId("xray_inbound_secrets", { inboundId: 1, kind: "REALITY_PRIVATE_KEY", encryptedValue: "generic-encrypted-private", fingerprint: "d".repeat(64), keyVersion: 1 });
      await db.insertAndGetId("xray_operations", { operationId: "host-delete-op", hostId: 1, inboundId: 1, type: "SYNC", requestedGeneration: 1, status: "SUCCESS", attemptCount: 1, createdByUserId: 1 });
      await db.insertAndGetId("xray_host_deployments", { hostId: 1, targetVersion: "26.7.28", desiredGeneration: 1, desiredConfigHash: "d".repeat(64), lastOperationId: "host-delete-op" });
      await db.insertAndGetId("xray_runtime_reports", { hostId: 1, capabilitySchemaVersion: 1, supportedOS: "linux", supportedArch: "amd64", supportsArtifactInstall: true, supportsPortProbe: true, supportsRealityScan: true, isInstalled: true, installedVersion: "26.7.28", runningVersion: "26.7.28", serviceStatus: "RUNNING", processId: 1234, appliedGeneration: 1, appliedConfigHash: "d".repeat(64), binarySha256: "a".repeat(64), listenersJson: "[]" });

      await hosts.deleteHost(1);
      for (const table of ["hosts", "xray_clients", "xray_inbounds", "xray_access_entries", "xray_access_secrets", "xray_inbound_secrets", "xray_tls_certificates", "xray_operations", "xray_host_deployments", "xray_runtime_reports"]) {
        assert.equal(Number((await db.queryRaw('SELECT COUNT(*) AS count FROM "' + table + '"'))[0].count), 0, table);
      }
      assert.equal(Number((await db.queryRaw("SELECT COUNT(*) AS count FROM xray_artifacts"))[0].count), 1);
    } finally {
      await db.closeDatabase().catch(() => undefined);
    }
  `;
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: { ...process.env, DATABASE_TYPE: "sqlite", FORWARDX_TEST_DB: databasePath, JWT_SECRET: "xray-host-delete-test" },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
