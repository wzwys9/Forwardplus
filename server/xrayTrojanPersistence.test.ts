import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("Trojan Reality stays generic-only through config, CRUD, share, and tombstone cleanup", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-trojan-persistence-"));
  const databasePath = path.join(directory, "trojan.db");
  const keyPath = path.join(directory, "xray-master.key");
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const repository = await import(moduleUrl("server/repositories/xrayRepository.ts"));
    const generator = await import(moduleUrl("server/xrayConfigGenerator.ts"));
    const { xrayRouter } = await import(moduleUrl("server/routers/xray.ts"));
    const secrets = await import(moduleUrl("server/xraySecretCrypto.ts"));
    const versions = await import(moduleUrl("shared/versions.ts"));
    const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
    const responseHeaders = new Map();
    const caller = xrayRouter.createCaller({
      req: { headers: {} },
      res: { clearCookie() {}, setHeader(name, value) { responseHeaders.set(name, value); } },
      user: { id: 1, username: "admin", role: "admin", accountEnabled: true },
      authSession: null,
      authFailureReason: null,
    });
    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, ipv4, isOnline, lastHeartbeat, agentVersion, agentDistribution, userId) VALUES (10, 'edge', '192.0.2.10', '192.0.2.10', 1, ?, ?, 'forwardplus', 1)", [Math.floor(Date.now() / 1000), versions.AGENT_VERSION]);
      await runtime.executeRaw("INSERT INTO xray_runtime_reports (hostId, capabilitySchemaVersion, supportedOS, supportedArch, supportsArtifactInstall, supportsPortProbe, supportsRealityScan) VALUES (10, 1, 'linux', 'amd64', 1, 1, 1)");
      const runtimeTag = "forwardx-inbound-trojan-db";
      const statsKey = "forwardx-access-trojan-db";
      const privateKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
      const password = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
      const shortId = "0123456789abcdef";
      const privateContext = secrets.xrayInboundPrivateKeyContext(runtimeTag);
      const passwordContext = secrets.xrayAccessSecretContext(statsKey, "PASSWORD");
      const shortIdContext = secrets.xrayAccessSecretContext(statsKey, "SHORT_ID");
      const created = await repository.createXrayInboundConfiguration({
        hostId: 10,
        expectedGeneration: 0,
        createdByUserId: 1,
        inbound: {
          profile: { id: "TROJAN_RAW_REALITY", specVersion: 1, specJson: '{}' },
          name: "Trojan Reality",
          runtimeTag,
          publicAddress: "203.0.113.10",
          listenAddress: "0.0.0.0",
          listenPort: 28888,
          realityTargetHost: "www.cloudflare.com",
          realityTargetPort: 443,
          realityServerName: "www.cloudflare.com",
          realityPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          realityPrivateKeyEncrypted: secrets.encryptXraySecret(privateKey, privateContext, keyring),
          realityPrivateKeyFingerprint: secrets.fingerprintXraySecret(privateKey, privateContext, keyring),
          secretKeyVersion: 1,
          fingerprint: "chrome",
          spiderX: "/",
        },
        genericAccessEntries: [{
          name: "phone",
          credentialType: "PASSWORD",
          settingsJson: '{"schemaVersion":1}',
          statsKey,
          secrets: [{
            kind: "PASSWORD",
            encryptedValue: secrets.encryptXraySecret(password, passwordContext, keyring),
            fingerprint: secrets.fingerprintXraySecret(password, passwordContext, keyring),
          }, {
            kind: "SHORT_ID",
            encryptedValue: secrets.encryptXraySecret(shortId, shortIdContext, keyring),
            fingerprint: secrets.fingerprintXraySecret(shortId, shortIdContext, keyring),
          }],
        }],
        finalize: async () => {
          const generated = await generator.generateXrayHostConfig(10, keyring);
          return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
        },
      });
      assert.equal(created.clientIds.length, 0);
      assert.equal(created.accessEntryIds.length, 1);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_clients"))[0].count, 0);
      assert.deepEqual(await runtime.queryRaw("SELECT legacyClientId, credentialType, settingsJson FROM xray_access_entries"), [{
        legacyClientId: null, credentialType: "PASSWORD", settingsJson: '{"schemaVersion":1}',
      }]);
      const generated = JSON.parse((await generator.generateXrayHostConfig(10, keyring)).configJson);
      assert.equal(generated.inbounds[0].protocol, "trojan");
      assert.deepEqual(generated.inbounds[0].settings.clients, [{ password, email: statsKey }]);
      assert.deepEqual(generated.inbounds[0].streamSettings.realitySettings.shortIds, [shortId]);

      const detail = await caller.inbounds.detail({ id: created.inboundId });
      assert.equal(detail.clients.length, 0);
      assert.equal(detail.accessEntries.length, 1);
      assert.equal(detail.accessEntries[0].credentialType, "PASSWORD");
      assert.deepEqual(detail.accessEntries[0].secretStatus, {
        requiredConfigured: true,
        configuredKinds: ["PASSWORD", "SHORT_ID"],
      });
      assert.equal(detail.accessEntries[0].legacyClientId, null);
      assert.equal(JSON.stringify(detail).includes(password), false);
      assert.equal(JSON.stringify(detail).includes(shortId), false);

      const second = await caller.accessEntries.create({
        inboundId: created.inboundId,
        name: "laptop",
        expectedGeneration: 1,
      });
      assert.equal(second.desiredGeneration, 2);
      const shared = new URL((await caller.accessEntries.share({ accessEntryId: second.accessEntryId, format: "TROJAN_URI" })).uri);
      assert.equal(shared.protocol, "trojan:");
      assert.equal(shared.searchParams.get("type"), "tcp");
      assert.equal(shared.searchParams.has("flow"), false);
      assert.equal(responseHeaders.get("Cache-Control"), "private, no-store, max-age=0");
      assert.equal((await caller.accessEntries.update({
        id: second.accessEntryId,
        name: "laptop-renamed",
        isEnabled: false,
        expectedGeneration: 2,
      })).desiredGeneration, 3);
      assert.equal((await caller.accessEntries.remove({
        id: second.accessEntryId,
        expectedGeneration: 3,
      })).desiredGeneration, 4);
      assert.equal((await caller.accessEntries.share({ accessEntryId: second.accessEntryId, format: "TROJAN_URI" })).deploymentStatus, "PENDING_DELETE");
      assert.deepEqual(await repository.deleteAppliedPendingXrayRecordsWithinHostLock(10, 4), { inboundCount: 0, clientCount: 1 });
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_access_entries"))[0].count, 1);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_clients"))[0].count, 0);
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
        JWT_SECRET: "xray-trojan-persistence-test",
        XRAY_MASTER_KEY_PATH: keyPath,
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
