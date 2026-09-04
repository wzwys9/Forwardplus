import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("Xray host mutations serialize generation checks, commit one operation, and expose only safe DTOs", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-repository-"));
  const databasePath = path.join(directory, "repository.db");
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const repository = await import(moduleUrl("server/repositories/xrayRepository.ts"));
    const secrets = await import(moduleUrl("server/xraySecretCrypto.ts"));
    const keyring = secrets.createXraySecretKeyring({ currentKeyId: "1", keys: { "1": Buffer.alloc(32, 7) } });
    const privateSecret = "repository-private-secret-marker";
    const uuidSecret = "repository-uuid-secret-marker";
    const shortSecret = "repository-short-secret-marker";
    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, userId) VALUES (10, 'edge', '192.0.2.10', 1)");

      const input = (suffix) => ({
        hostId: 10,
        expectedGeneration: 0,
        createdByUserId: 1,
        inbound: {
          name: "inbound-" + suffix,
          runtimeTag: "runtime-" + suffix,
          publicAddress: "203.0.113.10",
          listenAddress: "0.0.0.0",
          listenPort: suffix === "a" ? 24443 : 24444,
          realityTargetHost: "example.com",
          realityTargetPort: 443,
          realityServerName: "example.com",
          realityPublicKey: "public-" + suffix,
          realityPrivateKeyEncrypted: secrets.encryptXraySecret(privateSecret + suffix, secrets.xrayInboundPrivateKeyContext("runtime-" + suffix), keyring),
          realityPrivateKeyFingerprint: (suffix === "a" ? "e" : "f").repeat(64),
          secretKeyVersion: 1,
          fingerprint: "chrome",
          spiderX: "/",
        },
        client: {
          name: "client-" + suffix,
          uuidEncrypted: secrets.encryptXraySecret(uuidSecret + suffix, secrets.xrayClientUuidContext("stats-" + suffix), keyring),
          uuidFingerprint: (suffix === "a" ? "a" : "b").repeat(64),
          shortIdEncrypted: secrets.encryptXraySecret(shortSecret + suffix, secrets.xrayClientShortIdContext("stats-" + suffix), keyring),
          shortIdFingerprint: (suffix === "a" ? "c" : "d").repeat(64),
          statsKey: "stats-" + suffix,
          flow: "xtls-rprx-vision",
        },
      });

      const concurrent = await Promise.allSettled([
        repository.createXrayInboundConfiguration(input("a")),
        repository.createXrayInboundConfiguration(input("b")),
      ]);
      assert.equal(concurrent.filter((result) => result.status === "fulfilled").length, 1);
      const rejected = concurrent.find((result) => result.status === "rejected");
      assert.equal(rejected.reason.code, "CONFIG_GENERATION_CONFLICT");
      const created = concurrent.find((result) => result.status === "fulfilled").value;
      assert.equal(created.desiredGeneration, 1);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_inbounds"))[0].count, 1);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_clients"))[0].count, 1);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_access_entries"))[0].count, 1);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_access_secrets"))[0].count, 2);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_inbound_secrets"))[0].count, 1);
      assert.deepEqual(
        await runtime.queryRaw("SELECT credentialType, settingsJson, legacyClientId FROM xray_access_entries"),
        [{ credentialType: "UUID_AND_SHORT_ID", settingsJson: '{"schemaVersion":1,"flow":"XTLS_RPRX_VISION"}', legacyClientId: created.clientId }],
      );
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_operations"))[0].count, 1);
      assert.equal((await runtime.queryRaw("SELECT desiredGeneration FROM xray_host_deployments WHERE hostId = 10"))[0].desiredGeneration, 1);

      await assert.rejects(
        repository.updateXrayInboundConfiguration({
          id: created.inboundId,
          expectedGeneration: 0,
          createdByUserId: 1,
          patch: { name: "stale-write" },
        }),
        (error) => error.code === "CONFIG_GENERATION_CONFLICT",
      );
      const updated = await repository.updateXrayInboundConfiguration({
        id: created.inboundId,
        expectedGeneration: 1,
        createdByUserId: 1,
        patch: { name: "updated-name", isEnabled: false },
      });
      assert.equal(updated.desiredGeneration, 2);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_operations"))[0].count, 2);
      assert.deepEqual(
        await runtime.queryRaw("SELECT requestedGeneration, status, type FROM xray_operations ORDER BY requestedGeneration"),
        [
          { requestedGeneration: 1, status: "QUEUED", type: "SYNC" },
          { requestedGeneration: 2, status: "QUEUED", type: "SYNC" },
        ],
      );

      await assert.rejects(repository.updateXrayInboundConfiguration({
        id: created.inboundId,
        expectedGeneration: 2,
        createdByUserId: 1,
        operationId: updated.operationId,
        patch: { name: "must-roll-back" },
      }), (error) => error.code === "OPERATION_CONFLICT");
      assert.equal((await runtime.queryRaw("SELECT desiredGeneration FROM xray_host_deployments WHERE hostId = 10"))[0].desiredGeneration, 2);
      assert.equal((await runtime.queryRaw("SELECT name FROM xray_inbounds WHERE id = ?", [created.inboundId]))[0].name, "updated-name");

      const existingClient = (await runtime.queryRaw("SELECT * FROM xray_clients LIMIT 1"))[0];
      await assert.rejects(repository.updateXrayClientConfiguration({
        id: existingClient.id,
        expectedGeneration: 2,
        createdByUserId: 1,
        patch: { statsKey: "must-remain-stable" },
      }), (error) => error.code === "OPERATION_CONFLICT");
      assert.equal((await runtime.queryRaw("SELECT statsKey FROM xray_clients WHERE id = ?", [existingClient.id]))[0].statsKey, existingClient.statsKey);
      assert.equal((await runtime.queryRaw("SELECT desiredGeneration FROM xray_host_deployments WHERE hostId = 10"))[0].desiredGeneration, 2);
      await assert.rejects(repository.createXrayClientConfiguration({
        inboundId: created.inboundId,
        expectedGeneration: 2,
        createdByUserId: 1,
        client: {
          name: "duplicate",
          uuidEncrypted: secrets.encryptXraySecret(uuidSecret + "duplicate", secrets.xrayClientUuidContext("stats-duplicate"), keyring),
          uuidFingerprint: existingClient.uuidFingerprint,
          shortIdEncrypted: secrets.encryptXraySecret(shortSecret + "duplicate", secrets.xrayClientShortIdContext("stats-duplicate"), keyring),
          shortIdFingerprint: "e".repeat(64),
          statsKey: "stats-duplicate",
          flow: "xtls-rprx-vision",
        },
      }));
      assert.equal((await runtime.queryRaw("SELECT desiredGeneration FROM xray_host_deployments WHERE hostId = 10"))[0].desiredGeneration, 2);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_operations"))[0].count, 2);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_clients"))[0].count, 1);

      const clientUpdated = await repository.updateXrayClientConfiguration({
        id: existingClient.id,
        expectedGeneration: 2,
        createdByUserId: 1,
        patch: { name: "updated-client", isEnabled: false },
      });
      assert.equal(clientUpdated.desiredGeneration, 3);
      assert.deepEqual(
        await runtime.queryRaw("SELECT name, isEnabled, desiredGeneration FROM xray_access_entries WHERE legacyClientId = ?", [existingClient.id]),
        [{ name: "updated-client", isEnabled: 0, desiredGeneration: 3 }],
      );

      const inbounds = await repository.listXrayInboundsByHost(10);
      const clients = await repository.listXrayClientsByInbound(created.inboundId);
      const deployment = await repository.getXrayHostDeployment(10);
      const operation = await repository.getXrayOperation(updated.operationId);
      const ordinaryJson = JSON.stringify({ inbounds, clients, deployment, operation });
      for (const secret of [privateSecret, uuidSecret, shortSecret]) assert.equal(ordinaryJson.includes(secret), false);
      for (const forbidden of ["Encrypted", "uuidFingerprint", "shortIdFingerprint", "requestMetaJson", "resultJson"]) {
        assert.equal(ordinaryJson.includes(forbidden), false, forbidden);
      }
      assert.equal(inbounds[0].hasRealityPrivateKey, true);
      assert.equal(clients[0].credentials.uuidConfigured, true);
      assert.equal(inbounds[0].name, "updated-name");
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
        JWT_SECRET: "xray-repository-test-secret",
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
