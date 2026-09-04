import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("gRPC and XHTTP Reality persist profile/spec and generic NONE-flow access atomically", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-grpc-persistence-"));
  const databasePath = path.join(directory, "grpc.db");
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
    const migration = await import(moduleUrl("server/xrayAccessMigration.ts"));
    const clientService = await import(moduleUrl("server/xrayClientService.ts"));
    const secrets = await import(moduleUrl("server/xraySecretCrypto.ts"));
    const versions = await import(moduleUrl("shared/versions.ts"));
    const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, ipv4, isOnline, lastHeartbeat, agentVersion, agentDistribution, userId) VALUES (10, 'edge', '192.0.2.10', '192.0.2.10', 1, ?, ?, 'forwardplus', 1)", [Math.floor(Date.now() / 1000), versions.AGENT_VERSION]);
      await runtime.executeRaw("INSERT INTO xray_runtime_reports (hostId, capabilitySchemaVersion, supportedOS, supportedArch, supportsArtifactInstall, supportsPortProbe, supportsRealityScan) VALUES (10, 1, 'linux', 'amd64', 1, 1, 1)");
      const runtimeTag = "forwardx-inbound-grpc-db";
      const statsKey = "forwardx-client-grpc-db";
      const privateKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
      const uuid = "00000000-0000-4000-8000-000000000501";
      const shortId = "0501";
      const privateContext = secrets.xrayInboundPrivateKeyContext(runtimeTag);
      const uuidContext = secrets.xrayClientUuidContext(statsKey);
      const shortIdContext = secrets.xrayClientShortIdContext(statsKey);
      const created = await repository.createXrayInboundConfiguration({
        hostId: 10,
        expectedGeneration: 0,
        createdByUserId: 1,
        inbound: {
          profile: { id: "VLESS_GRPC_REALITY", specVersion: 1, specJson: '{"serviceName":"forwardx-grpc"}' },
          name: "gRPC Reality",
          runtimeTag,
          publicAddress: "203.0.113.10",
          listenAddress: "0.0.0.0",
          listenPort: 26666,
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
        client: {
          name: "phone",
          uuidEncrypted: secrets.encryptXraySecret(uuid, uuidContext, keyring),
          uuidFingerprint: secrets.fingerprintXraySecret(uuid, uuidContext, keyring),
          shortIdEncrypted: secrets.encryptXraySecret(shortId, shortIdContext, keyring),
          shortIdFingerprint: secrets.fingerprintXraySecret(shortId, shortIdContext, keyring),
          statsKey,
          flow: "",
        },
        finalize: async () => {
          const generated = await generator.generateXrayHostConfig(10, keyring);
          return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
        },
      });
      assert.deepEqual(await runtime.queryRaw("SELECT protocol, transport, security, profileId, specVersion, specJson FROM xray_inbounds WHERE id = ?", [created.inboundId]), [{
        protocol: "vless", transport: "grpc", security: "reality", profileId: "VLESS_GRPC_REALITY",
        specVersion: 1, specJson: '{"serviceName":"forwardx-grpc"}',
      }]);
      assert.deepEqual(await runtime.queryRaw("SELECT credentialType, settingsJson FROM xray_access_entries WHERE legacyClientId = ?", [created.clientId]), [{
        credentialType: "UUID_AND_SHORT_ID", settingsJson: '{"schemaVersion":1,"flow":"NONE"}',
      }]);
      const generated = await generator.generateXrayHostConfig(10, keyring);
      const inbound = JSON.parse(generated.configJson).inbounds[0];
      assert.equal(inbound.streamSettings.network, "grpc");
      assert.equal("flow" in inbound.settings.clients[0], false);
      assert.deepEqual(await migration.backfillLegacyXrayAccessEntries({ keyring }), {
        accessEntries: 0, accessSecrets: 0, inboundSecrets: 0,
      });
      const second = await clientService.createXrayClient({
        inboundId: created.inboundId,
        userId: 1,
        name: "laptop",
        flow: "",
        expectedGeneration: 1,
      });
      assert.equal(second.desiredGeneration, 2);
      const shared = await clientService.getXrayClientShare(second.clientId);
      const uri = new URL(shared.uri);
      assert.equal(uri.searchParams.get("type"), "grpc");
      assert.equal(uri.searchParams.get("serviceName"), "forwardx-grpc");
      assert.equal(uri.searchParams.has("flow"), false);
      const updated = await clientService.updateXrayClient({
        id: second.clientId,
        userId: 1,
        name: "laptop-renamed",
        flow: "",
        expectedGeneration: 2,
      });
      assert.equal(updated.desiredGeneration, 3);
      const removed = await clientService.removeXrayClient({
        id: second.clientId,
        userId: 1,
        expectedGeneration: 3,
      });
      assert.equal(removed.desiredGeneration, 4);
      assert.equal((await clientService.getXrayClientShare(second.clientId)).deploymentStatus, "PENDING_DELETE");

      const xhttpRuntimeTag = "forwardx-inbound-xhttp-db";
      const xhttpStatsKey = "forwardx-client-xhttp-db";
      const xhttpUuid = "00000000-0000-4000-8000-000000000601";
      const xhttpShortId = "0601";
      const xhttpPrivateContext = secrets.xrayInboundPrivateKeyContext(xhttpRuntimeTag);
      const xhttpUuidContext = secrets.xrayClientUuidContext(xhttpStatsKey);
      const xhttpShortIdContext = secrets.xrayClientShortIdContext(xhttpStatsKey);
      const xhttpCreated = await repository.createXrayInboundConfiguration({
        hostId: 10,
        expectedGeneration: 4,
        createdByUserId: 1,
        inbound: {
          profile: { id: "VLESS_XHTTP_REALITY", specVersion: 1, specJson: '{"path":"/forwardx/xhttp-v1"}' },
          name: "XHTTP Reality",
          runtimeTag: xhttpRuntimeTag,
          publicAddress: "203.0.113.10",
          listenAddress: "0.0.0.0",
          listenPort: 27777,
          realityTargetHost: "www.cloudflare.com",
          realityTargetPort: 443,
          realityServerName: "www.cloudflare.com",
          realityPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          realityPrivateKeyEncrypted: secrets.encryptXraySecret(privateKey, xhttpPrivateContext, keyring),
          realityPrivateKeyFingerprint: secrets.fingerprintXraySecret(privateKey, xhttpPrivateContext, keyring),
          secretKeyVersion: 1,
          fingerprint: "chrome",
          spiderX: "/",
        },
        client: {
          name: "tablet",
          uuidEncrypted: secrets.encryptXraySecret(xhttpUuid, xhttpUuidContext, keyring),
          uuidFingerprint: secrets.fingerprintXraySecret(xhttpUuid, xhttpUuidContext, keyring),
          shortIdEncrypted: secrets.encryptXraySecret(xhttpShortId, xhttpShortIdContext, keyring),
          shortIdFingerprint: secrets.fingerprintXraySecret(xhttpShortId, xhttpShortIdContext, keyring),
          statsKey: xhttpStatsKey,
          flow: "",
        },
        finalize: async () => {
          const next = await generator.generateXrayHostConfig(10, keyring);
          return { targetVersion: next.targetVersion, desiredConfigHash: next.configHash };
        },
      });
      assert.deepEqual(await runtime.queryRaw("SELECT protocol, transport, security, profileId, specVersion, specJson FROM xray_inbounds WHERE id = ?", [xhttpCreated.inboundId]), [{
        protocol: "vless", transport: "xhttp", security: "reality", profileId: "VLESS_XHTTP_REALITY",
        specVersion: 1, specJson: '{"path":"/forwardx/xhttp-v1"}',
      }]);
      const mixed = JSON.parse((await generator.generateXrayHostConfig(10, keyring)).configJson);
      assert.deepEqual(mixed.inbounds.map((item) => item.streamSettings.network), ["grpc", "xhttp"]);
      const xhttpSecond = await clientService.createXrayClient({
        inboundId: xhttpCreated.inboundId,
        userId: 1,
        name: "router",
        flow: "",
        expectedGeneration: 5,
      });
      const xhttpShare = new URL((await clientService.getXrayClientShare(xhttpSecond.clientId)).uri);
      assert.equal(xhttpShare.searchParams.get("type"), "xhttp");
      assert.equal(xhttpShare.searchParams.get("path"), "/forwardx/xhttp-v1");
      assert.equal(xhttpShare.searchParams.get("mode"), "auto");
      assert.equal(xhttpShare.searchParams.has("flow"), false);
      assert.equal((await clientService.updateXrayClient({
        id: xhttpSecond.clientId,
        userId: 1,
        name: "router-renamed",
        flow: "",
        expectedGeneration: 6,
      })).desiredGeneration, 7);
      assert.equal((await clientService.removeXrayClient({
        id: xhttpSecond.clientId,
        userId: 1,
        expectedGeneration: 7,
      })).desiredGeneration, 8);
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
        JWT_SECRET: "xray-grpc-persistence-test",
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
