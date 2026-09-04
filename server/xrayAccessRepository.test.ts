import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("generic Xray access repository validates, encrypts, updates, and returns safe DTOs transactionally", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-access-repository-"));
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const runtime = await load("server/dbRuntime.ts");
    const schema = await load("server/dbSchema.ts");
    const secrets = await load("server/xraySecretCrypto.ts");
    const repository = await load("server/repositories/xrayAccessRepository.ts");
    const firstSecret = "repository-password-secret-first";
    const secondSecret = "repository-password-secret-second";
    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, userId) VALUES (1, 'edge', '127.0.0.1', 1)");
      await runtime.executeRaw("INSERT INTO xray_inbounds (id, hostId, name, runtimeTag, publicAddress, listenPort, realityTargetHost, realityServerName, realityPublicKey, realityPrivateKeyEncrypted, createdByUserId) VALUES (1, 1, 'node', 'runtime-access', '203.0.113.1', 24443, 'example.com', 'example.com', 'public', 'legacy-envelope', 1)");

      const created = await repository.createXrayAccessEntry({
        inboundId: 1,
        name: "trojan-user",
        credentialType: "PASSWORD",
        settingsJson: '{"schemaVersion":1}',
        statsKey: "forwardx-access-password-a",
        desiredGeneration: 1,
        secrets: [{ kind: "PASSWORD", plaintext: firstSecret }],
      }, { keyring });
      assert.equal(created.id, 1);
      assert.deepEqual(created.secretStatus, { requiredConfigured: true, configuredKinds: ["PASSWORD"] });
      const serializedCreated = JSON.stringify(created);
      for (const forbidden of [firstSecret, "encryptedValue", "fingerprint", "keyId"]) {
        assert.equal(serializedCreated.includes(forbidden), false);
      }

      const [storedSecret] = await runtime.queryRaw("SELECT * FROM xray_access_secrets WHERE accessEntryId = 1");
      assert.equal(storedSecret.encryptedValue.includes(firstSecret), false);
      assert.match(storedSecret.encryptedValue, /^fwdx-secret:v1:1:/);
      assert.match(storedSecret.fingerprint, /^[0-9a-f]{64}$/);
      assert.equal(storedSecret.keyVersion, 1);

      await assert.rejects(repository.createXrayAccessEntry({
        inboundId: 1,
        name: "missing-secret",
        credentialType: "PASSWORD",
        settingsJson: '{"schemaVersion":1}',
        statsKey: "forwardx-access-missing",
        desiredGeneration: 1,
        secrets: [],
      }, { keyring }), (error) => error.code === "INVALID_ACCESS_DATA");
      await assert.rejects(repository.createXrayAccessEntry({
        inboundId: 1,
        name: "arbitrary-json",
        credentialType: "PASSWORD",
        settingsJson: '{"schemaVersion":1,"inbounds":[]}',
        statsKey: "forwardx-access-arbitrary",
        desiredGeneration: 1,
        secrets: [{ kind: "PASSWORD", plaintext: "secret" }],
      }, { keyring }), (error) => error.code === "INVALID_ACCESS_DATA");
      await assert.rejects(repository.createXrayAccessEntry({
        inboundId: 1,
        name: "duplicate-stats",
        credentialType: "PASSWORD",
        settingsJson: '{"schemaVersion":1}',
        statsKey: "forwardx-access-password-a",
        desiredGeneration: 1,
        secrets: [{ kind: "PASSWORD", plaintext: "must-roll-back" }],
      }, { keyring }), (error) => error.code === "ACCESS_CONFLICT");
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_access_entries"))[0].count, 1);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_access_secrets"))[0].count, 1);

      const updated = await repository.updateXrayAccessEntry({
        id: created.id,
        patch: { name: "trojan-user-updated", isEnabled: false, desiredGeneration: 2 },
        secrets: [{ kind: "PASSWORD", plaintext: secondSecret }],
      }, { keyring });
      assert.equal(updated.name, "trojan-user-updated");
      assert.equal(updated.isEnabled, false);
      assert.equal(updated.desiredGeneration, 2);
      assert.equal(JSON.stringify(updated).includes(secondSecret), false);
      const [rotatedSecret] = await runtime.queryRaw("SELECT encryptedValue FROM xray_access_secrets WHERE accessEntryId = 1");
      assert.notEqual(rotatedSecret.encryptedValue, storedSecret.encryptedValue);
      assert.equal(secrets.decryptXraySecret(
        rotatedSecret.encryptedValue,
        secrets.xrayAccessSecretContext("forwardx-access-password-a", "PASSWORD"),
        keyring,
      ), secondSecret);

      assert.deepEqual((await repository.listXrayAccessEntries(1)).map((entry) => entry.id), [created.id]);
      await runtime.executeRaw("UPDATE xray_access_entries SET settingsJson = ? WHERE id = ?", ['{"schemaVersion":1,"password":"leak"}', created.id]);
      await assert.rejects(repository.getXrayAccessEntry(created.id), (error) => error.code === "INVALID_ACCESS_DATA");
      await runtime.executeRaw("UPDATE xray_access_entries SET settingsJson = ? WHERE id = ?", ['{"schemaVersion":1}', created.id]);
      await runtime.executeRaw("UPDATE xray_access_secrets SET kind = 'UNKNOWN' WHERE accessEntryId = ?", [created.id]);
      await assert.rejects(repository.getXrayAccessEntry(created.id), (error) => error.code === "INVALID_ACCESS_DATA");
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
