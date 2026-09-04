import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("RAW VLESS, VMess, and Shadowsocks access supports safe CRUD, sharing, and tombstones", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-raw-tls-access-"));
  const certificatePath = path.join(directory, "certificate.pem");
  const privateKeyPath = path.join(directory, "private-key.pem");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
    "-subj", "/CN=tls.example.com", "-keyout", privateKeyPath, "-out", certificatePath,
    "-addext", "basicConstraints=critical,CA:FALSE",
    "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
    "-addext", "extendedKeyUsage=serverAuth",
    "-addext", "subjectAltName=DNS:tls.example.com",
  ], { stdio: "ignore" });

  const script = String.raw`
    import assert from "node:assert/strict";
    import fs from "node:fs";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const runtime = await load("server/dbRuntime.ts");
    const schema = await load("server/dbSchema.ts");
    const repository = await load("server/repositories/xrayRepository.ts");
    const certificateRepository = await load("server/repositories/xrayTlsCertificateRepository.ts");
    const generator = await load("server/xrayConfigGenerator.ts");
    const secrets = await load("server/xraySecretCrypto.ts");
    const versions = await load("shared/versions.ts");
    const { xrayRouter } = await load("server/routers/xray.ts");
    const certificatePem = fs.readFileSync(process.env.FORWARDX_TEST_CERT_PATH, "utf8");
    const privateKeyPem = fs.readFileSync(process.env.FORWARDX_TEST_KEY_PATH, "utf8");
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
      const now = Math.floor(Date.now() / 1000);
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw(
        "INSERT INTO hosts (id, name, ip, ipv4, isOnline, lastHeartbeat, agentVersion, userId) VALUES (10, 'edge', '203.0.113.10', '203.0.113.10', 1, ?, ?, 1)",
        [now, versions.AGENT_VERSION],
      );
      await runtime.executeRaw(
        "INSERT INTO xray_runtime_reports (hostId, capabilitySchemaVersion, supportedOS, supportedArch, supportsArtifactInstall, supportsPortProbe, supportsRealityScan) VALUES (10, 1, 'linux', 'amd64', 1, 1, 1)",
      );
      const certificate = await certificateRepository.createXrayTlsCertificate({
        hostId: 10, name: "Edge TLS", certificatePem, privateKeyPem, createdByUserId: 1,
      }, { keyring });
      const initialStatsKey = "forwardx-raw-tls-access-initial";
      const initialUuid = "00000000-0000-4000-8000-0000000000a1";
      const initialContext = secrets.xrayAccessSecretContext(initialStatsKey, "UUID");
      const createdInbound = await repository.createXrayInboundConfiguration({
        hostId: 10,
        expectedGeneration: 0,
        createdByUserId: 1,
        inbound: {
          profile: { id: "VLESS_RAW_TLS_VISION", specVersion: 1, specJson: "{}" },
          name: "Vision TLS",
          runtimeTag: "forwardx-raw-tls-access",
          publicAddress: "203.0.113.10",
          listenAddress: "0.0.0.0",
          listenPort: 28911,
          tlsCertificateId: certificate.id,
          realityTargetHost: "",
          realityTargetPort: 443,
          realityServerName: "tls.example.com",
          realityPublicKey: "",
          realityPrivateKeyEncrypted: "",
          secretKeyVersion: 1,
          fingerprint: "chrome",
          spiderX: "/",
        },
        genericAccessEntries: [{
          name: "phone",
          credentialType: "UUID",
          settingsJson: '{"schemaVersion":2,"protocol":"VLESS","encryption":"NONE","flow":"XTLS_RPRX_VISION"}',
          statsKey: initialStatsKey,
          secrets: [{
            kind: "UUID",
            encryptedValue: secrets.encryptXraySecret(initialUuid, initialContext, keyring),
            fingerprint: secrets.fingerprintXraySecret(initialUuid, initialContext, keyring),
          }],
        }],
        finalize: async () => {
          const generated = await generator.generateXrayHostConfig(10, keyring);
          return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
        },
      });

      const second = await caller.accessEntries.create({
        inboundId: createdInbound.inboundId,
        name: "laptop",
        expectedGeneration: 1,
      });
      assert.equal(second.desiredGeneration, 2);
      const [secondRow] = await runtime.queryRaw(
        "SELECT id, legacyClientId, credentialType, settingsJson, statsKey FROM xray_access_entries WHERE id = ?",
        [second.accessEntryId],
      );
      assert.equal(secondRow.legacyClientId, null);
      assert.equal(secondRow.credentialType, "UUID");
      assert.equal(secondRow.settingsJson, '{"schemaVersion":2,"protocol":"VLESS","encryption":"NONE","flow":"XTLS_RPRX_VISION"}');
      const secondSecrets = await runtime.queryRaw(
        "SELECT kind, encryptedValue, fingerprint FROM xray_access_secrets WHERE accessEntryId = ?",
        [second.accessEntryId],
      );
      assert.equal(secondSecrets.length, 1);
      assert.equal(secondSecrets[0].kind, "UUID");
      const secondUuid = secrets.decryptXraySecret(
        secondSecrets[0].encryptedValue,
        secrets.xrayAccessSecretContext(secondRow.statsKey, "UUID"),
        keyring,
      );
      assert.match(secondUuid, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);

      const shareResult = await caller.accessEntries.share({
        accessEntryId: second.accessEntryId,
        format: "VLESS_URI",
      });
      const shared = new URL(shareResult.uri);
      assert.equal(shared.protocol, "vless:");
      assert.equal(shared.username, secondUuid);
      assert.equal(shared.searchParams.get("type"), "tcp");
      assert.equal(shared.searchParams.get("security"), "tls");
      assert.equal(shared.searchParams.get("sni"), "tls.example.com");
      assert.equal(shared.searchParams.get("fp"), "chrome");
      assert.equal(shared.searchParams.get("pcs"), certificate.leafFingerprintSha256);
      assert.equal(shared.searchParams.get("encryption"), "none");
      assert.equal(shared.searchParams.get("flow"), "xtls-rprx-vision");
      assert.equal(shared.searchParams.has("sid"), false);
      assert.equal(shared.searchParams.has("pbk"), false);
      assert.equal(shared.searchParams.has("allowInsecure"), false);
      assert.equal(responseHeaders.get("Cache-Control"), "private, no-store, max-age=0");
      const storedCertificateChain = (await runtime.queryRaw(
        "SELECT certificateChainPem FROM xray_tls_certificates WHERE id = ?",
        [certificate.id],
      ))[0].certificateChainPem;
      await runtime.executeRaw("UPDATE xray_tls_certificates SET certificateChainPem = 'corrupt' WHERE id = ?", [certificate.id]);
      await assert.rejects(caller.accessEntries.share({
        accessEntryId: second.accessEntryId,
        format: "VLESS_URI",
      }), (error) => error?.message === "INVALID_CONFIG_INPUT");
      await runtime.executeRaw("UPDATE xray_tls_certificates SET certificateChainPem = ? WHERE id = ?", [
        storedCertificateChain,
        certificate.id,
      ]);
      await runtime.executeRaw("UPDATE xray_tls_certificates SET leafFingerprintSha256 = ? WHERE id = ?", [
        "a".repeat(64),
        certificate.id,
      ]);
      await assert.rejects(caller.accessEntries.share({
        accessEntryId: second.accessEntryId,
        format: "VLESS_URI",
      }), (error) => error?.message === "INVALID_CONFIG_INPUT");
      await runtime.executeRaw("UPDATE xray_tls_certificates SET leafFingerprintSha256 = ? WHERE id = ?", [
        certificate.leafFingerprintSha256,
        certificate.id,
      ]);
      await assert.rejects(caller.accessEntries.share({
        accessEntryId: second.accessEntryId,
        format: "TROJAN_URI",
      }), (error) => error?.message === "INVALID_CONFIG_INPUT");

      const disabled = await caller.accessEntries.update({
        id: second.accessEntryId,
        name: "laptop-renamed",
        isEnabled: false,
        expectedGeneration: 2,
      });
      assert.equal(disabled.desiredGeneration, 3);
      let config = JSON.parse((await generator.generateXrayHostConfig(10, keyring)).configJson);
      assert.deepEqual(config.inbounds[0].settings.clients, [{
        id: initialUuid, email: initialStatsKey, flow: "xtls-rprx-vision",
      }]);
      const enabled = await caller.accessEntries.update({
        id: second.accessEntryId,
        isEnabled: true,
        expectedGeneration: 3,
      });
      assert.equal(enabled.desiredGeneration, 4);
      config = JSON.parse((await generator.generateXrayHostConfig(10, keyring)).configJson);
      assert.equal(config.inbounds[0].settings.clients.length, 2);

      const removed = await caller.accessEntries.remove({
        id: second.accessEntryId,
        expectedGeneration: 4,
      });
      assert.equal(removed.desiredGeneration, 5);
      assert.equal((await caller.accessEntries.share({
        accessEntryId: second.accessEntryId,
        format: "VLESS_URI",
      })).deploymentStatus, "PENDING_DELETE");
      assert.deepEqual(await repository.deleteAppliedPendingXrayRecordsWithinHostLock(10, 5), {
        inboundCount: 0,
        clientCount: 1,
      });
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_access_entries"))[0].count, 1);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_access_secrets"))[0].count, 1);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_clients"))[0].count, 0);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_inbound_secrets"))[0].count, 0);

      const vmessStatsKey = "forwardx-raw-tls-vmess-initial";
      const vmessUuid = "00000000-0000-4000-8000-0000000000b1";
      const vmessContext = secrets.xrayAccessSecretContext(vmessStatsKey, "UUID");
      const vmessInbound = await repository.createXrayInboundConfiguration({
        hostId: 10,
        expectedGeneration: 5,
        createdByUserId: 1,
        inbound: {
          profile: { id: "VMESS_RAW_TLS", specVersion: 1, specJson: "{}" },
          name: "VMess TLS",
          runtimeTag: "forwardx-raw-tls-vmess-access",
          publicAddress: "203.0.113.10",
          listenAddress: "0.0.0.0",
          listenPort: 28912,
          tlsCertificateId: certificate.id,
          realityTargetHost: "",
          realityTargetPort: 443,
          realityServerName: "tls.example.com",
          realityPublicKey: "",
          realityPrivateKeyEncrypted: "",
          secretKeyVersion: 1,
          fingerprint: "chrome",
          spiderX: "/",
        },
        genericAccessEntries: [{
          name: "phone",
          credentialType: "UUID",
          settingsJson: '{"schemaVersion":1,"flow":"NONE","security":"AUTO"}',
          statsKey: vmessStatsKey,
          secrets: [{
            kind: "UUID",
            encryptedValue: secrets.encryptXraySecret(vmessUuid, vmessContext, keyring),
            fingerprint: secrets.fingerprintXraySecret(vmessUuid, vmessContext, keyring),
          }],
        }],
        finalize: async () => {
          const generated = await generator.generateXrayHostConfig(10, keyring);
          return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
        },
      });
      assert.equal(vmessInbound.desiredGeneration, 6);
      const vmessSecond = await caller.accessEntries.create({
        inboundId: vmessInbound.inboundId,
        name: "router",
        expectedGeneration: 6,
      });
      const [vmessSecondRow] = await runtime.queryRaw(
        "SELECT settingsJson FROM xray_access_entries WHERE id = ?",
        [vmessSecond.accessEntryId],
      );
      assert.equal(vmessSecondRow.settingsJson, '{"schemaVersion":1,"flow":"NONE","security":"AUTO"}');
      const vmessShare = await caller.accessEntries.share({
        accessEntryId: vmessSecond.accessEntryId,
        format: "VMESS_URI",
      });
      const vmessPayload = JSON.parse(Buffer.from(vmessShare.uri.slice("vmess://".length), "base64").toString("utf8"));
      assert.deepEqual({
        v: vmessPayload.v,
        scy: vmessPayload.scy,
        net: vmessPayload.net,
        type: vmessPayload.type,
        tls: vmessPayload.tls,
        sni: vmessPayload.sni,
        fp: vmessPayload.fp,
        pcs: vmessPayload.pcs,
      }, {
        v: "2",
        scy: "auto",
        net: "tcp",
        type: "none",
        tls: "tls",
        sni: "tls.example.com",
        fp: "chrome",
        pcs: certificate.leafFingerprintSha256,
      });
      assert.equal("aid" in vmessPayload, false);
      await assert.rejects(caller.accessEntries.share({
        accessEntryId: vmessSecond.accessEntryId,
        format: "VLESS_URI",
      }), (error) => error?.message === "INVALID_CONFIG_INPUT");
      assert.equal((await caller.accessEntries.update({
        id: vmessSecond.accessEntryId,
        isEnabled: false,
        expectedGeneration: 7,
      })).desiredGeneration, 8);
      assert.equal((await caller.accessEntries.update({
        id: vmessSecond.accessEntryId,
        isEnabled: true,
        expectedGeneration: 8,
      })).desiredGeneration, 9);
      assert.equal((await caller.accessEntries.remove({
        id: vmessSecond.accessEntryId,
        expectedGeneration: 9,
      })).desiredGeneration, 10);
      assert.equal((await caller.accessEntries.share({
        accessEntryId: vmessSecond.accessEntryId,
        format: "VMESS_URI",
      })).deploymentStatus, "PENDING_DELETE");

      const shadowsocksRuntimeTag = "forwardx-shadowsocks-2022-access";
      const shadowsocksStatsKey = "forwardx-shadowsocks-2022-initial";
      const shadowsocksServerKey = Buffer.alloc(32, 0xfb).toString("base64");
      const shadowsocksUserKey = Buffer.alloc(32, 0xff).toString("base64");
      const serverContext = secrets.xrayInboundSecretContext(shadowsocksRuntimeTag, "SHADOWSOCKS_SERVER_KEY");
      const userContext = secrets.xrayAccessSecretContext(shadowsocksStatsKey, "SHADOWSOCKS_KEY");
      const shadowsocksInbound = await repository.createXrayInboundConfiguration({
        hostId: 10,
        expectedGeneration: 10,
        createdByUserId: 1,
        inbound: {
          profile: { id: "SHADOWSOCKS_2022_RAW_NONE", specVersion: 1, specJson: "{}" },
          name: "Shadowsocks 2022",
          runtimeTag: shadowsocksRuntimeTag,
          publicAddress: "203.0.113.10",
          listenAddress: "0.0.0.0",
          listenPort: 28913,
          tlsCertificateId: null,
          realityTargetHost: "",
          realityTargetPort: 443,
          realityServerName: "",
          realityPublicKey: "",
          realityPrivateKeyEncrypted: "",
          secretKeyVersion: 1,
          fingerprint: "chrome",
          spiderX: "/",
        },
        inboundSecrets: [{
          kind: "SHADOWSOCKS_SERVER_KEY",
          encryptedValue: secrets.encryptXraySecret(shadowsocksServerKey, serverContext, keyring),
          fingerprint: secrets.fingerprintXraySecret(shadowsocksServerKey, serverContext, keyring),
        }],
        genericAccessEntries: [{
          name: "desktop",
          credentialType: "SHADOWSOCKS_KEY",
          settingsJson: '{"schemaVersion":1}',
          statsKey: shadowsocksStatsKey,
          secrets: [{
            kind: "SHADOWSOCKS_KEY",
            encryptedValue: secrets.encryptXraySecret(shadowsocksUserKey, userContext, keyring),
            fingerprint: secrets.fingerprintXraySecret(shadowsocksUserKey, userContext, keyring),
          }],
        }],
        finalize: async () => {
          const generated = await generator.generateXrayHostConfig(10, keyring);
          return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
        },
      });
      assert.equal(shadowsocksInbound.desiredGeneration, 11);
      const shadowsocksSecond = await caller.accessEntries.create({
        inboundId: shadowsocksInbound.inboundId,
        name: "tablet",
        expectedGeneration: 11,
      });
      assert.equal(shadowsocksSecond.desiredGeneration, 12);
      const [shadowsocksSecondRow] = await runtime.queryRaw(
        "SELECT settingsJson, statsKey FROM xray_access_entries WHERE id = ?",
        [shadowsocksSecond.accessEntryId],
      );
      const [shadowsocksSecondSecret] = await runtime.queryRaw(
        "SELECT kind, encryptedValue FROM xray_access_secrets WHERE accessEntryId = ?",
        [shadowsocksSecond.accessEntryId],
      );
      assert.equal(shadowsocksSecondRow.settingsJson, '{"schemaVersion":1}');
      assert.equal(shadowsocksSecondSecret.kind, "SHADOWSOCKS_KEY");
      const shadowsocksSecondKey = secrets.decryptXraySecret(
        shadowsocksSecondSecret.encryptedValue,
        secrets.xrayAccessSecretContext(shadowsocksSecondRow.statsKey, "SHADOWSOCKS_KEY"),
        keyring,
      );
      assert.match(shadowsocksSecondKey, /^[A-Za-z0-9+/]{43}=$/);
      const shadowsocksShare = await caller.accessEntries.share({
        accessEntryId: shadowsocksSecond.accessEntryId,
        format: "SHADOWSOCKS_URI",
      });
      assert.equal(shadowsocksShare.uri,
        "ss://2022-blake3-aes-256-gcm:" + encodeURIComponent(shadowsocksServerKey) + ":" + encodeURIComponent(shadowsocksSecondKey)
        + "@203.0.113.10:28913#tablet");
      await assert.rejects(caller.accessEntries.share({
        accessEntryId: shadowsocksSecond.accessEntryId,
        format: "VMESS_URI",
      }), (error) => error?.message === "INVALID_CONFIG_INPUT");

      assert.equal((await caller.accessEntries.update({
        id: shadowsocksSecond.accessEntryId,
        isEnabled: false,
        expectedGeneration: 12,
      })).desiredGeneration, 13);
      await assert.rejects(caller.accessEntries.update({
        id: shadowsocksInbound.accessEntryIds[0],
        isEnabled: false,
        expectedGeneration: 13,
      }), (error) => error?.message === "LAST_ACTIVE_ACCESS_REQUIRED");
      assert.equal((await repository.getXrayHostDeployment(10)).desiredGeneration, 13);
      assert.equal((await caller.accessEntries.update({
        id: shadowsocksSecond.accessEntryId,
        isEnabled: true,
        expectedGeneration: 13,
      })).desiredGeneration, 14);
      assert.equal((await caller.accessEntries.remove({
        id: shadowsocksSecond.accessEntryId,
        expectedGeneration: 14,
      })).desiredGeneration, 15);
      await assert.rejects(caller.accessEntries.remove({
        id: shadowsocksInbound.accessEntryIds[0],
        expectedGeneration: 15,
      }), (error) => error?.message === "LAST_ACTIVE_ACCESS_REQUIRED");
      assert.equal((await caller.inbounds.setEnabled({
        id: shadowsocksInbound.inboundId,
        isEnabled: false,
        expectedGeneration: 15,
      })).desiredGeneration, 16);
      assert.equal((await caller.accessEntries.remove({
        id: shadowsocksInbound.accessEntryIds[0],
        expectedGeneration: 16,
      })).desiredGeneration, 17);
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
        FORWARDX_TEST_CERT_PATH: certificatePath,
        FORWARDX_TEST_KEY_PATH: privateKeyPath,
        XRAY_MASTER_KEY_PATH: path.join(directory, "xray-master.key"),
        JWT_SECRET: "xray-raw-tls-access-test-secret",
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
