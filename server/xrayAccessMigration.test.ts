import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("legacy VLESS access and inbound secrets backfill atomically and idempotently", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-access-migration-"));
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const runtime = await load("server/dbRuntime.ts");
    const schema = await load("server/dbSchema.ts");
    const secrets = await load("server/xraySecretCrypto.ts");
    const migration = await load("server/xrayAccessMigration.ts");
    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, userId) VALUES (1, 'edge', '127.0.0.1', 1)");
      const fixtures = [];
      for (const id of [1, 2]) {
        const runtimeTag = "forwardx-inbound-migrate-" + id;
        const statsKey = "forwardx-client-migrate-" + id;
        const privateKey = "private-key-" + id;
        const uuid = "00000000-0000-4000-8000-00000000000" + id;
        const shortId = String(id).padStart(16, "0");
        const inboundContext = secrets.xrayInboundPrivateKeyContext(runtimeTag);
        const uuidContext = secrets.xrayClientUuidContext(statsKey);
        const shortContext = secrets.xrayClientShortIdContext(statsKey);
        const privateEnvelope = secrets.encryptXraySecret(privateKey, inboundContext, keyring);
        const uuidEnvelope = secrets.encryptXraySecret(uuid, uuidContext, keyring);
        const shortEnvelope = secrets.encryptXraySecret(shortId, shortContext, keyring);
        fixtures.push({ id, runtimeTag, statsKey, privateKey, privateEnvelope, uuid, uuidEnvelope, shortId, shortEnvelope });
        await runtime.executeRaw("INSERT INTO xray_inbounds (id, hostId, name, runtimeTag, publicAddress, listenPort, realityTargetHost, realityServerName, realityPublicKey, realityPrivateKeyEncrypted, createdByUserId) VALUES (?, 1, ?, ?, '203.0.113.1', ?, 'example.com', 'example.com', 'public', ?, 1)", [id, "node-" + id, runtimeTag, 24000 + id, privateEnvelope]);
        await runtime.executeRaw("INSERT INTO xray_clients (id, inboundId, name, uuidEncrypted, uuidFingerprint, shortIdEncrypted, shortIdFingerprint, statsKey, flow, desiredGeneration, sortOrder) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'xtls-rprx-vision', ?, ?)", [id, id, "client-" + id, uuidEnvelope, secrets.fingerprintXraySecret(uuid, uuidContext, keyring), shortEnvelope, secrets.fingerprintXraySecret(shortId, shortContext, keyring), statsKey, id, id - 1]);
      }

      assert.deepEqual(await migration.backfillLegacyXrayAccessEntries({ keyring }), {
        accessEntries: 2,
        accessSecrets: 4,
        inboundSecrets: 2,
      });
      assert.deepEqual(await migration.backfillLegacyXrayAccessEntries({ keyring }), {
        accessEntries: 0,
        accessSecrets: 0,
        inboundSecrets: 0,
      });
      const accessRows = await runtime.queryRaw("SELECT * FROM xray_access_entries ORDER BY legacyClientId");
      assert.deepEqual(accessRows.map((row) => ({
        legacyClientId: row.legacyClientId,
        inboundId: row.inboundId,
        credentialType: row.credentialType,
        settingsJson: row.settingsJson,
        statsKey: row.statsKey,
      })), fixtures.map((item) => ({
        legacyClientId: item.id,
        inboundId: item.id,
        credentialType: "UUID_AND_SHORT_ID",
        settingsJson: '{"schemaVersion":1,"flow":"XTLS_RPRX_VISION"}',
        statsKey: item.statsKey,
      })));
      const accessSecrets = await runtime.queryRaw("SELECT e.legacyClientId, s.kind, s.encryptedValue, s.keyVersion FROM xray_access_secrets s JOIN xray_access_entries e ON e.id = s.accessEntryId ORDER BY e.legacyClientId, s.kind");
      for (const fixture of fixtures) {
        const rows = accessSecrets.filter((row) => row.legacyClientId === fixture.id);
        assert.deepEqual(rows.map((row) => row.kind), ["SHORT_ID", "UUID"]);
        assert.equal(rows.find((row) => row.kind === "UUID").encryptedValue, fixture.uuidEnvelope);
        assert.equal(rows.find((row) => row.kind === "SHORT_ID").encryptedValue, fixture.shortEnvelope);
        assert.equal(rows.every((row) => row.keyVersion === 1), true);
      }
      const inboundSecrets = await runtime.queryRaw("SELECT inboundId, kind, encryptedValue, fingerprint FROM xray_inbound_secrets ORDER BY inboundId");
      assert.deepEqual(inboundSecrets.map((row, index) => ({
        inboundId: row.inboundId,
        kind: row.kind,
        encryptedValue: row.encryptedValue,
        fingerprint: row.fingerprint,
      })), fixtures.map((fixture) => ({
        inboundId: fixture.id,
        kind: "REALITY_PRIVATE_KEY",
        encryptedValue: fixture.privateEnvelope,
        fingerprint: secrets.fingerprintXraySecret(fixture.privateKey, secrets.xrayInboundPrivateKeyContext(fixture.runtimeTag), keyring),
      })));

      await runtime.executeRaw("DELETE FROM xray_access_secrets");
      await runtime.executeRaw("DELETE FROM xray_access_entries");
      await runtime.executeRaw("DELETE FROM xray_inbound_secrets");
      await runtime.executeRaw("UPDATE xray_clients SET uuidEncrypted = 'invalid-envelope' WHERE id = 2");
      await assert.rejects(migration.backfillLegacyXrayAccessEntries({ keyring }));
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_access_entries"))[0].count, 0);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_access_secrets"))[0].count, 0);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_inbound_secrets"))[0].count, 0);
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
