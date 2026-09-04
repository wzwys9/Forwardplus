import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("RAW TLS persistence is generic-only, host-scoped, and atomic", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-raw-tls-persistence-"));
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
    import { spawnSync } from "node:child_process";
    import { pathToFileURL } from "node:url";
    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const runtime = await load("server/dbRuntime.ts");
    const schema = await load("server/dbSchema.ts");
    const repository = await load("server/repositories/xrayRepository.ts");
    const certificateRepository = await load("server/repositories/xrayTlsCertificateRepository.ts");
    const generator = await load("server/xrayConfigGenerator.ts");
    const secrets = await load("server/xraySecretCrypto.ts");
    const certificatePem = fs.readFileSync(process.env.FORWARDX_TEST_CERT_PATH, "utf8");
    const privateKeyPem = fs.readFileSync(process.env.FORWARDX_TEST_KEY_PATH, "utf8");
    const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });

    const inbound = (profileId, runtimeTag, listenPort, tlsCertificateId) => ({
      profile: { id: profileId, specVersion: 1, specJson: "{}" },
      name: runtimeTag,
      runtimeTag,
      publicAddress: "203.0.113.10",
      listenAddress: "0.0.0.0",
      listenPort,
      tlsCertificateId,
      realityTargetHost: "",
      realityTargetPort: 443,
      realityServerName: "tls.example.com",
      realityPublicKey: "",
      realityPrivateKeyEncrypted: "",
      secretKeyVersion: 1,
      fingerprint: "chrome",
      spiderX: "/",
    });
    const shadowsocksInbound = (runtimeTag, listenPort) => ({
      profile: { id: "SHADOWSOCKS_2022_RAW_NONE", specVersion: 1, specJson: "{}" },
      name: runtimeTag,
      runtimeTag,
      publicAddress: "203.0.113.10",
      listenAddress: "0.0.0.0",
      listenPort,
      tlsCertificateId: null,
      realityTargetHost: "",
      realityTargetPort: 443,
      realityServerName: "",
      realityPublicKey: "",
      realityPrivateKeyEncrypted: "",
      secretKeyVersion: 1,
      fingerprint: "chrome",
      spiderX: "/",
    });
    const access = (name, statsKey, uuid, flow, protocol = "VLESS") => {
      const context = secrets.xrayAccessSecretContext(statsKey, "UUID");
      return {
        name,
        credentialType: "UUID",
        settingsJson: JSON.stringify(protocol === "VMESS"
          ? { schemaVersion: 1, flow: "NONE", security: "AUTO" }
          : { schemaVersion: 2, protocol: "VLESS", encryption: "NONE", flow }),
        statsKey,
        secrets: [{
          kind: "UUID",
          encryptedValue: secrets.encryptXraySecret(uuid, context, keyring),
          fingerprint: secrets.fingerprintXraySecret(uuid, context, keyring),
        }],
      };
    };
    const shadowsocksAccess = (name, statsKey, userKey) => {
      const context = secrets.xrayAccessSecretContext(statsKey, "SHADOWSOCKS_KEY");
      return {
        name,
        credentialType: "SHADOWSOCKS_KEY",
        settingsJson: '{"schemaVersion":1}',
        statsKey,
        secrets: [{
          kind: "SHADOWSOCKS_KEY",
          encryptedValue: secrets.encryptXraySecret(userKey, context, keyring),
          fingerprint: secrets.fingerprintXraySecret(userKey, context, keyring),
        }],
      };
    };
    const hysteriaAccess = (name, statsKey, auth) => {
      const context = secrets.xrayAccessSecretContext(statsKey, "HYSTERIA_AUTH");
      return {
        name,
        credentialType: "HYSTERIA_AUTH",
        settingsJson: '{"schemaVersion":1}',
        statsKey,
        secrets: [{
          kind: "HYSTERIA_AUTH",
          encryptedValue: secrets.encryptXraySecret(auth, context, keyring),
          fingerprint: secrets.fingerprintXraySecret(auth, context, keyring),
        }],
      };
    };

    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, userId) VALUES (10, 'edge-a', '127.0.0.1', 1), (20, 'edge-b', '127.0.0.2', 1)");
      const sameHostCertificate = await certificateRepository.createXrayTlsCertificate({
        hostId: 10, name: "Edge TLS", certificatePem, privateKeyPem, createdByUserId: 1,
      }, { keyring });
      const otherHostCertificate = await certificateRepository.createXrayTlsCertificate({
        hostId: 20, name: "Other TLS", certificatePem, privateKeyPem, createdByUserId: 1,
      }, { keyring });

      const create = async (expectedGeneration, inboundInput, accessInput, inboundSecrets = []) => repository.createXrayInboundConfiguration({
        hostId: 10,
        expectedGeneration,
        createdByUserId: 1,
        inbound: inboundInput,
        genericAccessEntries: [accessInput],
        inboundSecrets,
        finalize: async () => {
          const generated = await generator.generateXrayHostConfig(10, keyring);
          return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
        },
      });

      const standardUuid = "00000000-0000-4000-8000-000000000091";
      const visionUuid = "00000000-0000-4000-8000-000000000092";
      const vmessUuid = "00000000-0000-4000-8000-000000000093";
      const standard = await create(
        0,
        inbound("VLESS_RAW_TLS", "forwardx-raw-tls-standard-create", 28901, sameHostCertificate.id),
        access("phone", "forwardx-raw-tls-standard-create", standardUuid, "NONE"),
      );
      const vision = await create(
        1,
        inbound("VLESS_RAW_TLS_VISION", "forwardx-raw-tls-vision-create", 28902, sameHostCertificate.id),
        access("laptop", "forwardx-raw-tls-vision-create", visionUuid, "XTLS_RPRX_VISION"),
      );
      const vmess = await create(
        2,
        inbound("VMESS_RAW_TLS", "forwardx-raw-tls-vmess-create", 28903, sameHostCertificate.id),
        access("router", "forwardx-raw-tls-vmess-create", vmessUuid, "NONE", "VMESS"),
      );
      const shadowsocksServerKey = Buffer.alloc(32, 0xfb).toString("base64");
      const shadowsocksUserKey = Buffer.alloc(32, 0xff).toString("base64");
      const shadowsocksRuntimeTag = "forwardx-shadowsocks-2022-create";
      const serverContext = secrets.xrayInboundSecretContext(shadowsocksRuntimeTag, "SHADOWSOCKS_SERVER_KEY");
      const shadowsocks = await create(
        3,
        shadowsocksInbound(shadowsocksRuntimeTag, 28904),
        shadowsocksAccess("desktop", "forwardx-shadowsocks-2022-create", shadowsocksUserKey),
        [{
          kind: "SHADOWSOCKS_SERVER_KEY",
          encryptedValue: secrets.encryptXraySecret(shadowsocksServerKey, serverContext, keyring),
          fingerprint: secrets.fingerprintXraySecret(shadowsocksServerKey, serverContext, keyring),
        }],
      );
      const hysteriaAuth = Buffer.alloc(32, 0xfa).toString("base64url");
      const hysteria = await create(
        4,
        inbound("HYSTERIA2_TLS", "forwardx-z-hysteria2-tls-create", 28905, sameHostCertificate.id),
        hysteriaAccess("phone", "forwardx-z-hysteria2-tls-create", hysteriaAuth),
      );
      assert.equal(standard.desiredGeneration, 1);
      assert.equal(vision.desiredGeneration, 2);
      assert.equal(vmess.desiredGeneration, 3);
      assert.equal(shadowsocks.desiredGeneration, 4);
      assert.equal(hysteria.desiredGeneration, 5);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT profileId, security, tlsCertificateId, realityTargetHost, realityTargetPort, realityServerName, realityPublicKey, realityPrivateKeyEncrypted, fingerprint, spiderX FROM xray_inbounds ORDER BY id",
      ), [{
        profileId: "VLESS_RAW_TLS", security: "tls", tlsCertificateId: sameHostCertificate.id,
        realityTargetHost: "", realityTargetPort: 443, realityServerName: "tls.example.com",
        realityPublicKey: "", realityPrivateKeyEncrypted: "", fingerprint: "chrome", spiderX: "/",
      }, {
        profileId: "VLESS_RAW_TLS_VISION", security: "tls", tlsCertificateId: sameHostCertificate.id,
        realityTargetHost: "", realityTargetPort: 443, realityServerName: "tls.example.com",
        realityPublicKey: "", realityPrivateKeyEncrypted: "", fingerprint: "chrome", spiderX: "/",
      }, {
        profileId: "VMESS_RAW_TLS", security: "tls", tlsCertificateId: sameHostCertificate.id,
        realityTargetHost: "", realityTargetPort: 443, realityServerName: "tls.example.com",
        realityPublicKey: "", realityPrivateKeyEncrypted: "", fingerprint: "chrome", spiderX: "/",
      }, {
        profileId: "SHADOWSOCKS_2022_RAW_NONE", security: "none", tlsCertificateId: null,
        realityTargetHost: "", realityTargetPort: 443, realityServerName: "",
        realityPublicKey: "", realityPrivateKeyEncrypted: "", fingerprint: "chrome", spiderX: "/",
      }, {
        profileId: "HYSTERIA2_TLS", security: "tls", tlsCertificateId: sameHostCertificate.id,
        realityTargetHost: "", realityTargetPort: 443, realityServerName: "tls.example.com",
        realityPublicKey: "", realityPrivateKeyEncrypted: "", fingerprint: "chrome", spiderX: "/",
      }]);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_clients"))[0].count, 0);
      assert.deepEqual(await runtime.queryRaw("SELECT kind FROM xray_inbound_secrets ORDER BY inboundId"), [
        { kind: "SHADOWSOCKS_SERVER_KEY" },
      ]);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT legacyClientId, credentialType, settingsJson FROM xray_access_entries ORDER BY id",
      ), [{
        legacyClientId: null,
        credentialType: "UUID",
        settingsJson: '{"schemaVersion":2,"protocol":"VLESS","encryption":"NONE","flow":"NONE"}',
      }, {
        legacyClientId: null,
        credentialType: "UUID",
        settingsJson: '{"schemaVersion":2,"protocol":"VLESS","encryption":"NONE","flow":"XTLS_RPRX_VISION"}',
      }, {
        legacyClientId: null,
        credentialType: "UUID",
        settingsJson: '{"schemaVersion":1,"flow":"NONE","security":"AUTO"}',
      }, {
        legacyClientId: null,
        credentialType: "SHADOWSOCKS_KEY",
        settingsJson: '{"schemaVersion":1}',
      }, {
        legacyClientId: null,
        credentialType: "HYSTERIA_AUTH",
        settingsJson: '{"schemaVersion":1}',
      }]);
      assert.deepEqual(await runtime.queryRaw("SELECT kind FROM xray_access_secrets ORDER BY accessEntryId"), [
        { kind: "UUID" }, { kind: "UUID" }, { kind: "UUID" }, { kind: "SHADOWSOCKS_KEY" }, { kind: "HYSTERIA_AUTH" },
      ]);

      const generated = await generator.generateXrayHostConfig(10, keyring);
      const config = JSON.parse(generated.configJson);
      assert.deepEqual(config.inbounds[0].settings.clients, [{
        id: standardUuid, email: "forwardx-raw-tls-standard-create",
      }]);
      assert.deepEqual(config.inbounds[1].settings.clients, [{
        id: visionUuid, email: "forwardx-raw-tls-vision-create", flow: "xtls-rprx-vision",
      }]);
      assert.deepEqual(config.inbounds[2].settings.clients, [{
        id: vmessUuid, email: "forwardx-raw-tls-vmess-create", security: "auto",
      }]);
      assert.deepEqual(config.inbounds[3].settings, {
        method: "2022-blake3-aes-256-gcm",
        password: shadowsocksServerKey,
        network: "tcp",
        clients: [{ password: shadowsocksUserKey, email: "forwardx-shadowsocks-2022-create" }],
      });
      assert.deepEqual(config.inbounds[4].settings, {
        version: 2,
        clients: [{ auth: hysteriaAuth, email: "forwardx-z-hysteria2-tls-create" }],
      });
      assert.equal(config.inbounds[4].streamSettings.network, "hysteria");
      if (process.env.XRAY_TEST_BINARY) {
        const configPath = path.join(path.dirname(process.env.FORWARDX_TEST_DB), "generated.json");
        fs.writeFileSync(configPath, generated.configJson, { mode: 0o600 });
        const checked = spawnSync(process.env.XRAY_TEST_BINARY, ["run", "-test", "-config", configPath], {
          encoding: "utf8", timeout: 10_000,
        });
        assert.equal(checked.status, 0, checked.stderr || checked.stdout);
      }

      const beforeFailure = {
        inbounds: (await runtime.queryRaw("SELECT COUNT(*) count FROM xray_inbounds"))[0].count,
        access: (await runtime.queryRaw("SELECT COUNT(*) count FROM xray_access_entries"))[0].count,
        secrets: (await runtime.queryRaw("SELECT COUNT(*) count FROM xray_access_secrets"))[0].count,
        operations: (await runtime.queryRaw("SELECT COUNT(*) count FROM xray_operations"))[0].count,
        generation: (await runtime.queryRaw("SELECT desiredGeneration FROM xray_host_deployments WHERE hostId = 10"))[0].desiredGeneration,
      };
      await assert.rejects(create(
        5,
        inbound("VLESS_RAW_TLS", "forwardx-raw-tls-cross-host", 28906, otherHostCertificate.id),
        access("tablet", "forwardx-raw-tls-cross-host", "00000000-0000-4000-8000-000000000094", "NONE"),
      ), (error) => error?.code === "OPERATION_CONFLICT");
      assert.deepEqual({
        inbounds: (await runtime.queryRaw("SELECT COUNT(*) count FROM xray_inbounds"))[0].count,
        access: (await runtime.queryRaw("SELECT COUNT(*) count FROM xray_access_entries"))[0].count,
        secrets: (await runtime.queryRaw("SELECT COUNT(*) count FROM xray_access_secrets"))[0].count,
        operations: (await runtime.queryRaw("SELECT COUNT(*) count FROM xray_operations"))[0].count,
        generation: (await runtime.queryRaw("SELECT desiredGeneration FROM xray_host_deployments WHERE hostId = 10"))[0].desiredGeneration,
      }, beforeFailure);
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
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
