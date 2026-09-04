import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("legacy Xray client fingerprints are recomputed with the current cross-record scope", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-fingerprint-"));
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const runtime = await load("server/dbRuntime.ts");
    const schema = await load("server/dbSchema.ts");
    const secrets = await load("server/xraySecretCrypto.ts");
    const migration = await load("server/xrayFingerprintMigration.ts");
    const accessMigration = await load("server/xrayAccessMigration.ts");
    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, userId) VALUES (1, 'edge', '127.0.0.1', 1)");
      await runtime.executeRaw("INSERT INTO xray_inbounds (id, hostId, name, runtimeTag, publicAddress, listenPort, realityTargetHost, realityServerName, realityPublicKey, realityPrivateKeyEncrypted, createdByUserId) VALUES (1, 1, 'node', 'forwardx-inbound-fingerprint', '203.0.113.1', 24443, 'example.com', 'example.com', 'public', ?, 1)", [secrets.encryptXraySecret('private', secrets.xrayInboundPrivateKeyContext('forwardx-inbound-fingerprint'), keyring)]);
      const fixtures = [
        { id: 1, statsKey: "forwardx-client-fingerprint-a", uuid: "00000000-0000-4000-8000-000000000001", shortId: "0000000000000001", oldUuid: "a", oldShort: "b" },
        { id: 2, statsKey: "forwardx-client-fingerprint-b", uuid: "00000000-0000-4000-8000-000000000002", shortId: "0000000000000002", oldUuid: "c", oldShort: "d" },
      ];
      for (const item of fixtures) {
        const uuidContext = secrets.xrayClientUuidContext(item.statsKey);
        const shortContext = secrets.xrayClientShortIdContext(item.statsKey);
        await runtime.executeRaw("INSERT INTO xray_clients (id, inboundId, name, uuidEncrypted, uuidFingerprint, shortIdEncrypted, shortIdFingerprint, statsKey) VALUES (?, 1, ?, ?, ?, ?, ?, ?)", [item.id, item.statsKey, secrets.encryptXraySecret(item.uuid, uuidContext, keyring), item.oldUuid.repeat(64), secrets.encryptXraySecret(item.shortId, shortContext, keyring), item.oldShort.repeat(64), item.statsKey]);
      }
      assert.equal(await migration.repairXrayClientFingerprints({ keyring }), 2);
      const rows = await runtime.queryRaw("SELECT id, uuidFingerprint, shortIdFingerprint FROM xray_clients ORDER BY id");
      for (const [index, row] of rows.entries()) {
        const item = fixtures[index];
        assert.equal(row.uuidFingerprint, secrets.fingerprintXraySecret(item.uuid, secrets.xrayClientUuidContext(item.statsKey), keyring));
        assert.equal(row.shortIdFingerprint, secrets.fingerprintXraySecret(item.shortId, secrets.xrayClientShortIdContext(item.statsKey), keyring));
      }
      assert.equal(await migration.repairXrayClientFingerprints({ keyring }), 0);
      await accessMigration.backfillLegacyXrayAccessEntries({ keyring });
      await runtime.executeRaw("UPDATE xray_access_secrets SET fingerprint = ?", ["c".repeat(64)]);
      await runtime.executeRaw("UPDATE xray_inbound_secrets SET fingerprint = ?", ["d".repeat(64)]);
      assert.equal(await migration.repairXrayClientFingerprints({ keyring, force: true }), 2);
      const genericRows = await runtime.queryRaw("SELECT a.legacyClientId, s.kind, s.fingerprint FROM xray_access_secrets s JOIN xray_access_entries a ON a.id = s.accessEntryId ORDER BY a.legacyClientId, s.kind");
      for (const row of genericRows) {
        const item = fixtures.find((fixture) => fixture.id === row.legacyClientId);
        const plaintext = row.kind === "UUID" ? item.uuid : item.shortId;
        const context = secrets.xrayAccessSecretContext(item.statsKey, row.kind);
        assert.equal(row.fingerprint, secrets.fingerprintXraySecret(plaintext, context, keyring));
      }
      assert.equal(
        (await runtime.queryRaw("SELECT fingerprint FROM xray_inbound_secrets WHERE inboundId = 1"))[0].fingerprint,
        secrets.fingerprintXraySecret("private", secrets.xrayInboundSecretContext("forwardx-inbound-fingerprint", "REALITY_PRIVATE_KEY"), keyring),
      );
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
