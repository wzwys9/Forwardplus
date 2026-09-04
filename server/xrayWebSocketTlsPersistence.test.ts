import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("available VLESS and Trojan TLS profiles share one generic, deterministic snapshot", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-ws-tls-persistence-"));
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

    const inbound = (profileId, runtimeTag, listenPort, tlsCertificateId, spec = { path: "/forwardx/ws" }) => ({
      profile: { id: profileId, specVersion: 1, specJson: JSON.stringify(spec) },
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
    const uuidAccess = (statsKey, uuid, flow = "NONE") => {
      const context = secrets.xrayAccessSecretContext(statsKey, "UUID");
      return {
        name: "vless-phone",
        credentialType: "UUID",
        settingsJson: JSON.stringify({ schemaVersion: 2, protocol: "VLESS", encryption: "NONE", flow }),
        statsKey,
        secrets: [{
          kind: "UUID",
          encryptedValue: secrets.encryptXraySecret(uuid, context, keyring),
          fingerprint: secrets.fingerprintXraySecret(uuid, context, keyring),
        }],
      };
    };
    const passwordAccess = (statsKey, password, shortId) => {
      const passwordContext = secrets.xrayAccessSecretContext(statsKey, "PASSWORD");
      const values = [{
        kind: "PASSWORD",
        encryptedValue: secrets.encryptXraySecret(password, passwordContext, keyring),
        fingerprint: secrets.fingerprintXraySecret(password, passwordContext, keyring),
      }];
      if (shortId !== undefined) {
        const shortIdContext = secrets.xrayAccessSecretContext(statsKey, "SHORT_ID");
        values.push({
          kind: "SHORT_ID",
          encryptedValue: secrets.encryptXraySecret(shortId, shortIdContext, keyring),
          fingerprint: secrets.fingerprintXraySecret(shortId, shortIdContext, keyring),
        });
      }
      return {
        name: "trojan-phone",
        credentialType: "PASSWORD",
        settingsJson: '{"schemaVersion":1}',
        statsKey,
        secrets: values,
      };
    };

    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      const now = Math.floor(Date.now() / 1000);
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, isOnline, lastHeartbeat, agentVersion, agentDistribution, userId) VALUES (10, 'edge-a', '127.0.0.1', 1, ?, ?, 'forwardplus', 1), (20, 'edge-b', '127.0.0.2', 1, ?, ?, 'forwardplus', 1)", [now, versions.AGENT_VERSION, now, versions.AGENT_VERSION]);
      await runtime.executeRaw("INSERT INTO xray_runtime_reports (hostId, capabilitySchemaVersion, supportedOS, supportedArch, supportsArtifactInstall, supportsPortProbe, supportsRealityScan) VALUES (10, 1, 'linux', 'amd64', 1, 1, 1)");
      const sameHostCertificate = await certificateRepository.createXrayTlsCertificate({
        hostId: 10, name: "Edge TLS", certificatePem, privateKeyPem, createdByUserId: 1,
      }, { keyring });
      const otherHostCertificate = await certificateRepository.createXrayTlsCertificate({
        hostId: 20, name: "Other TLS", certificatePem, privateKeyPem, createdByUserId: 1,
      }, { keyring });
      const create = (expectedGeneration, inboundInput, accessInput) => repository.createXrayInboundConfiguration({
        hostId: 10,
        expectedGeneration,
        createdByUserId: 1,
        inbound: inboundInput,
        genericAccessEntries: [accessInput],
        finalize: async () => {
          const generated = await generator.generateXrayHostConfig(10, keyring);
          return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
        },
      });

      const vlessUuid = "00000000-0000-4000-8000-000000000101";
      const trojanPassword = "C".repeat(43);
      const vless = await create(
        0,
        inbound("VLESS_WEBSOCKET_TLS", "forwardx-ws-tls-vless", 29001, sameHostCertificate.id, { path: "/forwardx/vless-ws" }),
        uuidAccess("forwardx-ws-tls-vless-access", vlessUuid),
      );
      const trojan = await create(
        1,
        inbound("TROJAN_WEBSOCKET_TLS", "forwardx-ws-tls-trojan", 29002, sameHostCertificate.id, { path: "/forwardx/trojan-ws" }),
        passwordAccess("forwardx-ws-tls-trojan-access", trojanPassword),
      );
      const vlessGrpcUuid = "00000000-0000-4000-8000-000000000103";
      const trojanGrpcPassword = "D".repeat(43);
      const vlessGrpc = await create(
        2,
        inbound("VLESS_GRPC_TLS", "forwardx-grpc-tls-vless", 29003, sameHostCertificate.id, { serviceName: "forwardx-vless-grpc" }),
        uuidAccess("forwardx-grpc-tls-vless-access", vlessGrpcUuid),
      );
      const trojanGrpc = await create(
        3,
        inbound("TROJAN_GRPC_TLS", "forwardx-grpc-tls-trojan", 29004, sameHostCertificate.id, { serviceName: "forwardx-trojan-grpc" }),
        passwordAccess("forwardx-grpc-tls-trojan-access", trojanGrpcPassword),
      );
      const vlessHttpUpgradeUuid = "00000000-0000-4000-8000-000000000105";
      const trojanHttpUpgradePassword = "E".repeat(43);
      const vlessHttpUpgrade = await create(
        4,
        inbound("VLESS_HTTP_UPGRADE_TLS", "forwardx-httpupgrade-tls-vless", 29005, sameHostCertificate.id, { path: "/forwardx/vless-httpupgrade" }),
        uuidAccess("forwardx-httpupgrade-tls-vless-access", vlessHttpUpgradeUuid),
      );
      const trojanHttpUpgrade = await create(
        5,
        inbound("TROJAN_HTTP_UPGRADE_TLS", "forwardx-httpupgrade-tls-trojan", 29006, sameHostCertificate.id, { path: "/forwardx/trojan-httpupgrade" }),
        passwordAccess("forwardx-httpupgrade-tls-trojan-access", trojanHttpUpgradePassword),
      );
      const vlessXhttpUuid = "00000000-0000-4000-8000-000000000107";
      const trojanXhttpPassword = "F".repeat(43);
      const vlessXhttp = await create(
        6,
        inbound("VLESS_XHTTP_TLS", "forwardx-xhttp-tls-vless", 29007, sameHostCertificate.id, { path: "/forwardx/vless-xhttp" }),
        uuidAccess("forwardx-xhttp-tls-vless-access", vlessXhttpUuid),
      );
      const trojanXhttp = await create(
        7,
        inbound("TROJAN_XHTTP_TLS", "forwardx-xhttp-tls-trojan", 29008, sameHostCertificate.id, { path: "/forwardx/trojan-xhttp" }),
        passwordAccess("forwardx-xhttp-tls-trojan-access", trojanXhttpPassword),
      );
      const vlessMkcpUuid = "00000000-0000-4000-8000-000000000109";
      const trojanMkcpPassword = "G".repeat(43);
      const vlessMkcp = await create(
        8,
        inbound("VLESS_MKCP_TLS", "forwardx-mkcp-tls-vless", 29009, sameHostCertificate.id, {}),
        uuidAccess("forwardx-mkcp-tls-vless-access", vlessMkcpUuid),
      );
      const trojanMkcp = await create(
        9,
        inbound("TROJAN_MKCP_TLS", "forwardx-mkcp-tls-trojan", 29010, sameHostCertificate.id, {}),
        passwordAccess("forwardx-mkcp-tls-trojan-access", trojanMkcpPassword),
      );
      const vlessRawUuid = "00000000-0000-4000-8000-000000000115";
      const vlessRawVisionUuid = "00000000-0000-4000-8000-000000000116";
      const trojanRawPassword = "J".repeat(43);
      const vlessRaw = await create(
        10,
        inbound("VLESS_RAW_TLS", "forwardx-raw-tls-vless", 29015, sameHostCertificate.id, {}),
        uuidAccess("forwardx-raw-tls-vless-access", vlessRawUuid),
      );
      const vlessRawVision = await create(
        11,
        inbound("VLESS_RAW_TLS_VISION", "forwardx-raw-tls-vless-vision", 29016, sameHostCertificate.id, {}),
        uuidAccess("forwardx-raw-tls-vless-vision-access", vlessRawVisionUuid, "XTLS_RPRX_VISION"),
      );
      const trojanRaw = await create(
        12,
        inbound("TROJAN_RAW_TLS", "forwardx-raw-tls-trojan", 29017, sameHostCertificate.id, {}),
        passwordAccess("forwardx-raw-tls-trojan-access", trojanRawPassword),
      );
      assert.equal(vless.desiredGeneration, 1);
      assert.equal(trojan.desiredGeneration, 2);
      assert.equal(vlessGrpc.desiredGeneration, 3);
      assert.equal(trojanGrpc.desiredGeneration, 4);
      assert.equal(vlessHttpUpgrade.desiredGeneration, 5);
      assert.equal(trojanHttpUpgrade.desiredGeneration, 6);
      assert.equal(vlessXhttp.desiredGeneration, 7);
      assert.equal(trojanXhttp.desiredGeneration, 8);
      assert.equal(vlessMkcp.desiredGeneration, 9);
      assert.equal(trojanMkcp.desiredGeneration, 10);
      assert.equal(vlessRaw.desiredGeneration, 11);
      assert.equal(vlessRawVision.desiredGeneration, 12);
      assert.equal(trojanRaw.desiredGeneration, 13);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT profileId, protocol, transport, security, specJson, tlsCertificateId, realityTargetHost, realityPublicKey, realityPrivateKeyEncrypted FROM xray_inbounds ORDER BY id",
      ), [{
        profileId: "VLESS_WEBSOCKET_TLS", protocol: "vless", transport: "ws", security: "tls",
        specJson: '{"path":"/forwardx/vless-ws"}', tlsCertificateId: sameHostCertificate.id,
        realityTargetHost: "", realityPublicKey: "", realityPrivateKeyEncrypted: "",
      }, {
        profileId: "TROJAN_WEBSOCKET_TLS", protocol: "trojan", transport: "ws", security: "tls",
        specJson: '{"path":"/forwardx/trojan-ws"}', tlsCertificateId: sameHostCertificate.id,
        realityTargetHost: "", realityPublicKey: "", realityPrivateKeyEncrypted: "",
      }, {
        profileId: "VLESS_GRPC_TLS", protocol: "vless", transport: "grpc", security: "tls",
        specJson: '{"serviceName":"forwardx-vless-grpc"}', tlsCertificateId: sameHostCertificate.id,
        realityTargetHost: "", realityPublicKey: "", realityPrivateKeyEncrypted: "",
      }, {
        profileId: "TROJAN_GRPC_TLS", protocol: "trojan", transport: "grpc", security: "tls",
        specJson: '{"serviceName":"forwardx-trojan-grpc"}', tlsCertificateId: sameHostCertificate.id,
        realityTargetHost: "", realityPublicKey: "", realityPrivateKeyEncrypted: "",
      }, {
        profileId: "VLESS_HTTP_UPGRADE_TLS", protocol: "vless", transport: "httpupgrade", security: "tls",
        specJson: '{"path":"/forwardx/vless-httpupgrade"}', tlsCertificateId: sameHostCertificate.id,
        realityTargetHost: "", realityPublicKey: "", realityPrivateKeyEncrypted: "",
      }, {
        profileId: "TROJAN_HTTP_UPGRADE_TLS", protocol: "trojan", transport: "httpupgrade", security: "tls",
        specJson: '{"path":"/forwardx/trojan-httpupgrade"}', tlsCertificateId: sameHostCertificate.id,
        realityTargetHost: "", realityPublicKey: "", realityPrivateKeyEncrypted: "",
      }, {
        profileId: "VLESS_XHTTP_TLS", protocol: "vless", transport: "xhttp", security: "tls",
        specJson: '{"path":"/forwardx/vless-xhttp"}', tlsCertificateId: sameHostCertificate.id,
        realityTargetHost: "", realityPublicKey: "", realityPrivateKeyEncrypted: "",
      }, {
        profileId: "TROJAN_XHTTP_TLS", protocol: "trojan", transport: "xhttp", security: "tls",
        specJson: '{"path":"/forwardx/trojan-xhttp"}', tlsCertificateId: sameHostCertificate.id,
        realityTargetHost: "", realityPublicKey: "", realityPrivateKeyEncrypted: "",
      }, {
        profileId: "VLESS_MKCP_TLS", protocol: "vless", transport: "kcp", security: "tls",
        specJson: '{}', tlsCertificateId: sameHostCertificate.id,
        realityTargetHost: "", realityPublicKey: "", realityPrivateKeyEncrypted: "",
      }, {
        profileId: "TROJAN_MKCP_TLS", protocol: "trojan", transport: "kcp", security: "tls",
        specJson: '{}', tlsCertificateId: sameHostCertificate.id,
        realityTargetHost: "", realityPublicKey: "", realityPrivateKeyEncrypted: "",
      }, {
        profileId: "VLESS_RAW_TLS", protocol: "vless", transport: "tcp", security: "tls",
        specJson: '{}', tlsCertificateId: sameHostCertificate.id,
        realityTargetHost: "", realityPublicKey: "", realityPrivateKeyEncrypted: "",
      }, {
        profileId: "VLESS_RAW_TLS_VISION", protocol: "vless", transport: "tcp", security: "tls",
        specJson: '{}', tlsCertificateId: sameHostCertificate.id,
        realityTargetHost: "", realityPublicKey: "", realityPrivateKeyEncrypted: "",
      }, {
        profileId: "TROJAN_RAW_TLS", protocol: "trojan", transport: "tcp", security: "tls",
        specJson: '{}', tlsCertificateId: sameHostCertificate.id,
        realityTargetHost: "", realityPublicKey: "", realityPrivateKeyEncrypted: "",
      }]);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_clients"))[0].count, 0);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_inbound_secrets"))[0].count, 0);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT legacyClientId, credentialType, settingsJson FROM xray_access_entries ORDER BY id",
      ), [{
        legacyClientId: null, credentialType: "UUID",
        settingsJson: '{"schemaVersion":2,"protocol":"VLESS","encryption":"NONE","flow":"NONE"}',
      }, {
        legacyClientId: null, credentialType: "PASSWORD", settingsJson: '{"schemaVersion":1}',
      }, {
        legacyClientId: null, credentialType: "UUID",
        settingsJson: '{"schemaVersion":2,"protocol":"VLESS","encryption":"NONE","flow":"NONE"}',
      }, {
        legacyClientId: null, credentialType: "PASSWORD", settingsJson: '{"schemaVersion":1}',
      }, {
        legacyClientId: null, credentialType: "UUID",
        settingsJson: '{"schemaVersion":2,"protocol":"VLESS","encryption":"NONE","flow":"NONE"}',
      }, {
        legacyClientId: null, credentialType: "PASSWORD", settingsJson: '{"schemaVersion":1}',
      }, {
        legacyClientId: null, credentialType: "UUID",
        settingsJson: '{"schemaVersion":2,"protocol":"VLESS","encryption":"NONE","flow":"NONE"}',
      }, {
        legacyClientId: null, credentialType: "PASSWORD", settingsJson: '{"schemaVersion":1}',
      }, {
        legacyClientId: null, credentialType: "UUID",
        settingsJson: '{"schemaVersion":2,"protocol":"VLESS","encryption":"NONE","flow":"NONE"}',
      }, {
        legacyClientId: null, credentialType: "PASSWORD", settingsJson: '{"schemaVersion":1}',
      }, {
        legacyClientId: null, credentialType: "UUID",
        settingsJson: '{"schemaVersion":2,"protocol":"VLESS","encryption":"NONE","flow":"NONE"}',
      }, {
        legacyClientId: null, credentialType: "UUID",
        settingsJson: '{"schemaVersion":2,"protocol":"VLESS","encryption":"NONE","flow":"XTLS_RPRX_VISION"}',
      }, {
        legacyClientId: null, credentialType: "PASSWORD", settingsJson: '{"schemaVersion":1}',
      }]);
      assert.deepEqual(await runtime.queryRaw("SELECT kind FROM xray_access_secrets ORDER BY accessEntryId"), [
        { kind: "UUID" }, { kind: "PASSWORD" }, { kind: "UUID" }, { kind: "PASSWORD" },
        { kind: "UUID" }, { kind: "PASSWORD" }, { kind: "UUID" }, { kind: "PASSWORD" },
        { kind: "UUID" }, { kind: "PASSWORD" }, { kind: "UUID" }, { kind: "UUID" },
        { kind: "PASSWORD" },
      ]);

      const generated = await generator.generateXrayHostConfig(10, keyring);
      const config = JSON.parse(generated.configJson);
      assert.equal(config.inbounds.length, 13);
      const vlessConfig = config.inbounds.find((item) => item.tag === "forwardx-ws-tls-vless");
      const trojanConfig = config.inbounds.find((item) => item.tag === "forwardx-ws-tls-trojan");
      const vlessGrpcConfig = config.inbounds.find((item) => item.tag === "forwardx-grpc-tls-vless");
      const trojanGrpcConfig = config.inbounds.find((item) => item.tag === "forwardx-grpc-tls-trojan");
      const vlessHttpUpgradeConfig = config.inbounds.find((item) => item.tag === "forwardx-httpupgrade-tls-vless");
      const trojanHttpUpgradeConfig = config.inbounds.find((item) => item.tag === "forwardx-httpupgrade-tls-trojan");
      const vlessXhttpConfig = config.inbounds.find((item) => item.tag === "forwardx-xhttp-tls-vless");
      const trojanXhttpConfig = config.inbounds.find((item) => item.tag === "forwardx-xhttp-tls-trojan");
      const vlessMkcpConfig = config.inbounds.find((item) => item.tag === "forwardx-mkcp-tls-vless");
      const trojanMkcpConfig = config.inbounds.find((item) => item.tag === "forwardx-mkcp-tls-trojan");
      const vlessRawConfig = config.inbounds.find((item) => item.tag === "forwardx-raw-tls-vless");
      const vlessRawVisionConfig = config.inbounds.find((item) => item.tag === "forwardx-raw-tls-vless-vision");
      const trojanRawConfig = config.inbounds.find((item) => item.tag === "forwardx-raw-tls-trojan");
      assert.deepEqual(vlessConfig.settings.clients, [{ id: vlessUuid, email: "forwardx-ws-tls-vless-access" }]);
      assert.deepEqual(trojanConfig.settings.clients, [{ password: trojanPassword, email: "forwardx-ws-tls-trojan-access" }]);
      assert.deepEqual(vlessGrpcConfig.settings.clients, [{ id: vlessGrpcUuid, email: "forwardx-grpc-tls-vless-access" }]);
      assert.deepEqual(trojanGrpcConfig.settings.clients, [{ password: trojanGrpcPassword, email: "forwardx-grpc-tls-trojan-access" }]);
      assert.deepEqual(vlessHttpUpgradeConfig.settings.clients, [{ id: vlessHttpUpgradeUuid, email: "forwardx-httpupgrade-tls-vless-access" }]);
      assert.deepEqual(trojanHttpUpgradeConfig.settings.clients, [{ password: trojanHttpUpgradePassword, email: "forwardx-httpupgrade-tls-trojan-access" }]);
      assert.deepEqual(vlessXhttpConfig.settings.clients, [{ id: vlessXhttpUuid, email: "forwardx-xhttp-tls-vless-access" }]);
      assert.deepEqual(trojanXhttpConfig.settings.clients, [{ password: trojanXhttpPassword, email: "forwardx-xhttp-tls-trojan-access" }]);
      assert.deepEqual(vlessMkcpConfig.settings.clients, [{ id: vlessMkcpUuid, email: "forwardx-mkcp-tls-vless-access" }]);
      assert.deepEqual(trojanMkcpConfig.settings.clients, [{ password: trojanMkcpPassword, email: "forwardx-mkcp-tls-trojan-access" }]);
      assert.deepEqual(vlessRawConfig.settings.clients, [{ id: vlessRawUuid, email: "forwardx-raw-tls-vless-access" }]);
      assert.deepEqual(vlessRawVisionConfig.settings.clients, [{
        id: vlessRawVisionUuid, email: "forwardx-raw-tls-vless-vision-access", flow: "xtls-rprx-vision",
      }]);
      assert.deepEqual(trojanRawConfig.settings.clients, [{ password: trojanRawPassword, email: "forwardx-raw-tls-trojan-access" }]);
      assert.deepEqual(vlessConfig.streamSettings.wsSettings, { path: "/forwardx/vless-ws" });
      assert.deepEqual(trojanConfig.streamSettings.wsSettings, { path: "/forwardx/trojan-ws" });
      assert.deepEqual(vlessGrpcConfig.streamSettings.grpcSettings, { serviceName: "forwardx-vless-grpc", multiMode: false });
      assert.deepEqual(trojanGrpcConfig.streamSettings.grpcSettings, { serviceName: "forwardx-trojan-grpc", multiMode: false });
      assert.deepEqual(vlessGrpcConfig.streamSettings.tlsSettings.alpn, ["h2"]);
      assert.deepEqual(trojanGrpcConfig.streamSettings.tlsSettings.alpn, ["h2"]);
      assert.deepEqual(vlessHttpUpgradeConfig.streamSettings.httpupgradeSettings, { path: "/forwardx/vless-httpupgrade" });
      assert.deepEqual(trojanHttpUpgradeConfig.streamSettings.httpupgradeSettings, { path: "/forwardx/trojan-httpupgrade" });
      assert.deepEqual(vlessXhttpConfig.streamSettings.xhttpSettings, { path: "/forwardx/vless-xhttp", mode: "auto" });
      assert.deepEqual(trojanXhttpConfig.streamSettings.xhttpSettings, { path: "/forwardx/trojan-xhttp", mode: "auto" });
      assert.deepEqual(vlessMkcpConfig.streamSettings.kcpSettings, {});
      assert.deepEqual(trojanMkcpConfig.streamSettings.kcpSettings, {});
      assert.equal(vlessMkcpConfig.streamSettings.network, "kcp");
      assert.equal(trojanMkcpConfig.streamSettings.network, "kcp");
      assert.equal(vlessRawConfig.streamSettings.network, "tcp");
      assert.equal(vlessRawVisionConfig.streamSettings.network, "tcp");
      assert.equal(trojanRawConfig.streamSettings.network, "tcp");
      assert.deepEqual(generated.expectedListeners.find((item) => item.runtimeTag === "forwardx-mkcp-tls-vless"), {
        inboundId: vlessMkcp.inboundId, runtimeTag: "forwardx-mkcp-tls-vless",
        network: "udp", listenAddress: "0.0.0.0", port: 29009,
      });
      assert.deepEqual(generated.expectedListeners.find((item) => item.runtimeTag === "forwardx-mkcp-tls-trojan"), {
        inboundId: trojanMkcp.inboundId, runtimeTag: "forwardx-mkcp-tls-trojan",
        network: "udp", listenAddress: "0.0.0.0", port: 29010,
      });
      assert.equal(generated.configJson.includes("shortId"), false);
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
        13,
        inbound("VLESS_XHTTP_TLS", "forwardx-xhttp-tls-cross-host", 29011, otherHostCertificate.id, { path: "/forwardx/xhttp" }),
        uuidAccess("forwardx-xhttp-tls-cross-host", "00000000-0000-4000-8000-000000000111"),
      ), (error) => error?.code === "OPERATION_CONFLICT");
      await assert.rejects(create(
        13,
        inbound("TROJAN_XHTTP_TLS", "forwardx-xhttp-tls-extra-spec", 29012, sameHostCertificate.id, { path: "/xhttp", mode: "stream-up" }),
        passwordAccess("forwardx-xhttp-tls-extra-spec", "H".repeat(43)),
      ), (error) => error?.code === "OPERATION_CONFLICT");
      await assert.rejects(create(
        13,
        inbound("TROJAN_WEBSOCKET_TLS", "forwardx-ws-tls-short-id", 29013, sameHostCertificate.id),
        passwordAccess("forwardx-ws-tls-short-id", "I".repeat(43), "0123456789abcdef"),
      ), (error) => error?.code === "OPERATION_CONFLICT");
      await assert.rejects(create(
        13,
        inbound("VLESS_WEBSOCKET_TLS", "forwardx-ws-tls-flow", 29014, sameHostCertificate.id),
        uuidAccess("forwardx-ws-tls-flow", "00000000-0000-4000-8000-000000000114", "XTLS_RPRX_VISION"),
      ), (error) => error?.code === "OPERATION_CONFLICT");
      assert.deepEqual({
        inbounds: (await runtime.queryRaw("SELECT COUNT(*) count FROM xray_inbounds"))[0].count,
        access: (await runtime.queryRaw("SELECT COUNT(*) count FROM xray_access_entries"))[0].count,
        secrets: (await runtime.queryRaw("SELECT COUNT(*) count FROM xray_access_secrets"))[0].count,
        operations: (await runtime.queryRaw("SELECT COUNT(*) count FROM xray_operations"))[0].count,
        generation: (await runtime.queryRaw("SELECT desiredGeneration FROM xray_host_deployments WHERE hostId = 10"))[0].desiredGeneration,
      }, beforeFailure);

      const vlessSecond = await caller.accessEntries.create({
        inboundId: vlessXhttp.inboundId,
        name: "vless-laptop",
        expectedGeneration: 13,
      });
      assert.equal(vlessSecond.desiredGeneration, 14);
      const trojanSecond = await caller.accessEntries.create({
        inboundId: trojanXhttp.inboundId,
        name: "trojan-laptop",
        expectedGeneration: 14,
      });
      assert.equal(trojanSecond.desiredGeneration, 15);

      const vlessShare = await caller.accessEntries.share({
        accessEntryId: vlessSecond.accessEntryId,
        format: "VLESS_URI",
      });
      const vlessUri = new URL(vlessShare.uri);
      assert.equal(vlessUri.protocol, "vless:");
      assert.equal(vlessUri.searchParams.get("type"), "xhttp");
      assert.equal(vlessUri.searchParams.get("path"), "/forwardx/vless-xhttp");
      assert.equal(vlessUri.searchParams.get("mode"), "auto");
      assert.equal(vlessUri.searchParams.get("encryption"), "none");
      const trojanShare = await caller.accessEntries.share({
        accessEntryId: trojanSecond.accessEntryId,
        format: "TROJAN_URI",
      });
      const trojanUri = new URL(trojanShare.uri);
      assert.equal(trojanUri.protocol, "trojan:");
      assert.equal(trojanUri.searchParams.get("type"), "xhttp");
      assert.equal(trojanUri.searchParams.get("path"), "/forwardx/trojan-xhttp");
      assert.equal(trojanUri.searchParams.get("mode"), "auto");
      for (const uri of [vlessUri, trojanUri]) {
        assert.equal(uri.searchParams.get("security"), "tls");
        assert.equal(uri.searchParams.get("sni"), "tls.example.com");
        assert.equal(uri.searchParams.get("fp"), "chrome");
        assert.match(uri.searchParams.get("pcs") ?? "", /^[0-9a-f]{64}$/);
        for (const forbidden of ["flow", "sid", "pbk", "allowInsecure", "host", "ed", "padding", "xmux", "downloadSettings"]) {
          assert.equal(uri.searchParams.has(forbidden), false, forbidden);
        }
      }
      assert.equal(responseHeaders.get("Cache-Control"), "private, no-store, max-age=0");
      await assert.rejects(
        caller.accessEntries.share({ accessEntryId: vlessSecond.accessEntryId, format: "TROJAN_URI" }),
        (error) => error?.cause?.code === "INVALID_CONFIG_INPUT" || error?.message === "INVALID_CONFIG_INPUT",
      );
      await assert.rejects(
        caller.accessEntries.share({ accessEntryId: trojanSecond.accessEntryId, format: "VLESS_URI" }),
        (error) => error?.cause?.code === "INVALID_CONFIG_INPUT" || error?.message === "INVALID_CONFIG_INPUT",
      );
      assert.equal((await caller.accessEntries.update({
        id: vlessSecond.accessEntryId,
        name: "vless-laptop-renamed",
        isEnabled: false,
        expectedGeneration: 15,
      })).desiredGeneration, 16);
      assert.equal((await caller.accessEntries.update({
        id: trojanSecond.accessEntryId,
        name: "trojan-laptop-renamed",
        expectedGeneration: 16,
      })).desiredGeneration, 17);
      assert.equal((await caller.accessEntries.remove({
        id: vlessSecond.accessEntryId,
        expectedGeneration: 17,
      })).desiredGeneration, 18);
      assert.equal((await caller.accessEntries.share({
        accessEntryId: vlessSecond.accessEntryId,
        format: "VLESS_URI",
      })).deploymentStatus, "PENDING_DELETE");
      assert.deepEqual(await repository.deleteAppliedPendingXrayRecordsWithinHostLock(10, 18), {
        inboundCount: 0,
        clientCount: 1,
      });
      assert.deepEqual(await runtime.queryRaw(
        "SELECT a.name, s.kind FROM xray_access_entries a JOIN xray_access_secrets s ON s.accessEntryId = a.id ORDER BY a.id",
      ), [
        { name: "vless-phone", kind: "UUID" },
        { name: "trojan-phone", kind: "PASSWORD" },
        { name: "vless-phone", kind: "UUID" },
        { name: "trojan-phone", kind: "PASSWORD" },
        { name: "vless-phone", kind: "UUID" },
        { name: "trojan-phone", kind: "PASSWORD" },
        { name: "vless-phone", kind: "UUID" },
        { name: "trojan-phone", kind: "PASSWORD" },
        { name: "vless-phone", kind: "UUID" },
        { name: "trojan-phone", kind: "PASSWORD" },
        { name: "vless-phone", kind: "UUID" },
        { name: "vless-phone", kind: "UUID" },
        { name: "trojan-phone", kind: "PASSWORD" },
        { name: "trojan-laptop-renamed", kind: "PASSWORD" },
      ]);
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
