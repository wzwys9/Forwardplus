import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("createV2 is profile-gated, certificate-bound, and secret-safe", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-raw-tls-create-"));
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
    import { spawnSync } from "node:child_process";
    import fs from "node:fs";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const runtime = await load("server/dbRuntime.ts");
    const schema = await load("server/dbSchema.ts");
    const artifacts = await load("server/xrayArtifacts.ts");
    const ports = await load("server/xrayPortOperations.ts");
    const inboundService = await load("server/xrayInboundService.ts");
    const certificateRepository = await load("server/repositories/xrayTlsCertificateRepository.ts");
    const secrets = await load("server/xraySecretCrypto.ts");
    const versions = await load("shared/versions.ts");
    const { xrayRouter } = await load("server/routers/xray.ts");
    const certificatePem = fs.readFileSync(process.env.FORWARDX_TEST_CERT_PATH, "utf8");
    const privateKeyPem = fs.readFileSync(process.env.FORWARDX_TEST_KEY_PATH, "utf8");
    const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
    const response = { clearCookie() {}, setHeader() {} };
    const caller = xrayRouter.createCaller({
      req: { headers: {} }, res: response,
      user: { id: 1, username: "admin", role: "admin", accountEnabled: true },
      authSession: null, authFailureReason: null,
    });
    const nowIso = () => new Date().toISOString();
    const reserve = async (hostId, port) => {
      const operation = await ports.createXrayPortProbeOperation({ hostId, userId: 1, mode: "MANUAL", manualPort: port });
      const [task] = await ports.takeXrayPortProbeTasks(hostId, 1);
      await ports.completeXrayPortProbeTask(hostId, {
        schemaVersion: 1, taskId: task.taskId, type: "PORT_PROBE", status: "SUCCESS",
        startedAt: nowIso(), finishedAt: nowIso(), error: null,
        result: { ports: task.payload.ports.map((candidate) => ({ port: candidate, available: true, errorCode: null })), observedAt: nowIso() },
      });
      return ports.getXrayPortProbeOperationResult(operation.operationId, 1);
    };
    const input = (profileId, reservation, overrides = {}) => ({
      hostId: 10,
      name: profileId,
      publicAddress: "8.8.8.8",
      portReservationId: reservation.reservationId,
      listenPort: reservation.selectedPort,
      profileId,
      spec: overrides.spec ?? {},
      tlsCertificateId: overrides.tlsCertificateId,
      serverName: overrides.serverName ?? "tls.example.com",
      initialAccessEntries: [{ name: "phone" }, { name: "laptop" }],
    });
    const expectCode = async (promise, code) => assert.rejects(promise, (error) =>
      error?.cause?.code === code || error?.code === code || error?.message === code);

    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      const now = Math.floor(Date.now() / 1000);
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      for (const hostId of [10, 20]) {
        await runtime.executeRaw(
          "INSERT INTO hosts (id, name, ip, ipv4, isOnline, lastHeartbeat, agentVersion, agentDistribution, userId) VALUES (?, ?, '8.8.8.8', '8.8.8.8', 1, ?, ?, 'forwardplus', 1)",
          [hostId, 'edge-' + hostId, now, versions.AGENT_VERSION],
        );
        await runtime.executeRaw(
          "INSERT INTO xray_runtime_reports (hostId, capabilitySchemaVersion, supportedOS, supportedArch, supportsArtifactInstall, supportsPortProbe, supportsRealityScan) VALUES (?, 1, 'linux', 'amd64', 1, 1, 1)",
          [hostId],
        );
      }
      const artifact = artifacts.XRAY_ARTIFACT_MANIFEST.find((entry) => entry.arch === "amd64");
      await runtime.executeRaw(
        "INSERT INTO xray_artifacts (version, os, arch, packageFormat, storageKey, sha256, fileSize, status, source, verifiedAt) VALUES (?, ?, ?, ?, ?, ?, ?, 'VERIFIED', ?, ?)",
        [artifact.version, artifact.os, artifact.arch, artifact.packageFormat, artifact.storageKey, artifact.sha256, artifact.fileSize, artifact.source, now],
      );
      const certificate = await certificateRepository.createXrayTlsCertificate({
        hostId: 10, name: "Edge TLS", certificatePem, privateKeyPem, createdByUserId: 1,
      }, { keyring });
      const otherHostCertificate = await certificateRepository.createXrayTlsCertificate({
        hostId: 20, name: "Other TLS", certificatePem, privateKeyPem, createdByUserId: 1,
      }, { keyring });

      const standardReservation = await reserve(10, 29101);
      const standardInput = input("VLESS_RAW_TLS", standardReservation, { tlsCertificateId: certificate.id });
      await assert.rejects(caller.inbounds.createV2({ ...standardInput, reality: {
        targetHost: "www.microsoft.com", targetPort: 443, serverName: "www.microsoft.com", fingerprint: "chrome", spiderX: "/",
      } }));
      const standard = await caller.inbounds.createV2(standardInput);
      assert.equal(standard.desiredGeneration, 1);

      const visionReservation = await reserve(10, 29102);
      const vision = await caller.inbounds.createV2(
        input("VLESS_RAW_TLS_VISION", visionReservation, { tlsCertificateId: certificate.id }),
      );
      assert.equal(vision.desiredGeneration, 2);

      const trojanReservation = await reserve(10, 29106);
      const trojanInput = input("TROJAN_RAW_TLS", trojanReservation, { tlsCertificateId: certificate.id });
      const trojan = await caller.inbounds.createV2(trojanInput);
      assert.equal(trojan.desiredGeneration, 3);

      const rows = await runtime.queryRaw(
        "SELECT profileId, security, tlsCertificateId, realityTargetHost, realityTargetPort, realityServerName, realityPublicKey, realityPrivateKeyEncrypted FROM xray_inbounds ORDER BY id",
      );
      assert.deepEqual(rows, [{
        profileId: "VLESS_RAW_TLS", security: "tls", tlsCertificateId: certificate.id,
        realityTargetHost: "", realityTargetPort: 443, realityServerName: "tls.example.com",
        realityPublicKey: "", realityPrivateKeyEncrypted: "",
      }, {
        profileId: "VLESS_RAW_TLS_VISION", security: "tls", tlsCertificateId: certificate.id,
        realityTargetHost: "", realityTargetPort: 443, realityServerName: "tls.example.com",
        realityPublicKey: "", realityPrivateKeyEncrypted: "",
      }, {
        profileId: "TROJAN_RAW_TLS", security: "tls", tlsCertificateId: certificate.id,
        realityTargetHost: "", realityTargetPort: 443, realityServerName: "tls.example.com",
        realityPublicKey: "", realityPrivateKeyEncrypted: "",
      }]);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_clients"))[0].count, 0);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_inbound_secrets"))[0].count, 0);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_access_entries"))[0].count, 6);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_access_secrets"))[0].count, 6);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT credentialType, settingsJson FROM xray_access_entries ORDER BY id",
      ), [
        { credentialType: "UUID", settingsJson: '{"schemaVersion":2,"protocol":"VLESS","encryption":"NONE","flow":"NONE"}' },
        { credentialType: "UUID", settingsJson: '{"schemaVersion":2,"protocol":"VLESS","encryption":"NONE","flow":"NONE"}' },
        { credentialType: "UUID", settingsJson: '{"schemaVersion":2,"protocol":"VLESS","encryption":"NONE","flow":"XTLS_RPRX_VISION"}' },
        { credentialType: "UUID", settingsJson: '{"schemaVersion":2,"protocol":"VLESS","encryption":"NONE","flow":"XTLS_RPRX_VISION"}' },
        { credentialType: "PASSWORD", settingsJson: '{"schemaVersion":1}' },
        { credentialType: "PASSWORD", settingsJson: '{"schemaVersion":1}' },
      ]);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT s.kind FROM xray_access_entries a JOIN xray_access_secrets s ON s.accessEntryId = a.id WHERE a.inboundId = ? ORDER BY s.kind",
        [trojan.inboundId],
      ), [{ kind: "PASSWORD" }, { kind: "PASSWORD" }]);

      const detail = await caller.inbounds.detail({ id: standard.inboundId });
      assert.equal(detail.inbound.security, "tls");
      assert.equal(detail.inbound.profileId, "VLESS_RAW_TLS");
      assert.deepEqual(detail.inbound.tlsCertificate, { id: certificate.id, name: "Edge TLS", configured: true });
      assert.equal(detail.inbound.realityServerName, "tls.example.com");
      assert.deepEqual(detail.accessEntries.map((entry) => entry.name), ["phone", "laptop"]);
      const detailKeys = [];
      const serializedDetail = JSON.stringify(detail, (key, value) => {
        if (key) detailKeys.push(key);
        return value;
      });
      for (const forbiddenKey of [
        "certificatePem", "certificateChainPem", "privateKeyPem", "privateKeyEncrypted",
        "encryptedValue", "uuid", "uuidEncrypted", "uuidFingerprint", "shortId",
        "shortIdEncrypted", "shortIdFingerprint", "leafFingerprintSha256",
      ]) assert.equal(detailKeys.includes(forbiddenKey), false, forbiddenKey);
      assert.equal(serializedDetail.includes(certificatePem.trim()), false);

      const vlessWebSocketReservation = await reserve(10, 29107);
      const vlessWebSocketInput = input("VLESS_WEBSOCKET_TLS", vlessWebSocketReservation, {
        tlsCertificateId: certificate.id,
        spec: { path: "/forwardx/vless-ws" },
      });
      assert.equal((await caller.inbounds.createV2(vlessWebSocketInput)).desiredGeneration, 4);

      const trojanWebSocketReservation = await reserve(10, 29108);
      const trojanWebSocketInput = input("TROJAN_WEBSOCKET_TLS", trojanWebSocketReservation, {
        tlsCertificateId: certificate.id,
        spec: { path: "/forwardx/trojan-ws" },
      });
      assert.equal((await caller.inbounds.createV2(trojanWebSocketInput)).desiredGeneration, 5);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT profileId, specJson FROM xray_inbounds WHERE profileId IN ('VLESS_WEBSOCKET_TLS', 'TROJAN_WEBSOCKET_TLS') ORDER BY id",
      ), [
        { profileId: "VLESS_WEBSOCKET_TLS", specJson: '{"path":"/forwardx/vless-ws"}' },
        { profileId: "TROJAN_WEBSOCKET_TLS", specJson: '{"path":"/forwardx/trojan-ws"}' },
      ]);

      const vlessGrpcReservation = await reserve(10, 29109);
      const vlessGrpcInput = input("VLESS_GRPC_TLS", vlessGrpcReservation, {
        tlsCertificateId: certificate.id,
        spec: { serviceName: "forwardx.vless-grpc" },
      });
      assert.equal((await caller.inbounds.createV2(vlessGrpcInput)).desiredGeneration, 6);

      const trojanGrpcReservation = await reserve(10, 29110);
      const trojanGrpcInput = input("TROJAN_GRPC_TLS", trojanGrpcReservation, {
        tlsCertificateId: certificate.id,
        spec: { serviceName: "forwardx.trojan-grpc" },
      });
      assert.equal((await caller.inbounds.createV2(trojanGrpcInput)).desiredGeneration, 7);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT profileId, specJson FROM xray_inbounds WHERE profileId IN ('VLESS_GRPC_TLS', 'TROJAN_GRPC_TLS') ORDER BY id",
      ), [
        { profileId: "VLESS_GRPC_TLS", specJson: '{"serviceName":"forwardx.vless-grpc"}' },
        { profileId: "TROJAN_GRPC_TLS", specJson: '{"serviceName":"forwardx.trojan-grpc"}' },
      ]);

      const vlessHttpUpgradeReservation = await reserve(10, 29111);
      const vlessHttpUpgradeInput = input("VLESS_HTTP_UPGRADE_TLS", vlessHttpUpgradeReservation, {
        tlsCertificateId: certificate.id,
        spec: { path: "/forwardx/vless-httpupgrade" },
      });
      assert.equal((await caller.inbounds.createV2(vlessHttpUpgradeInput)).desiredGeneration, 8);

      const trojanHttpUpgradeReservation = await reserve(10, 29112);
      const trojanHttpUpgradeInput = input("TROJAN_HTTP_UPGRADE_TLS", trojanHttpUpgradeReservation, {
        tlsCertificateId: certificate.id,
        spec: { path: "/forwardx/trojan-httpupgrade" },
      });
      assert.equal((await caller.inbounds.createV2(trojanHttpUpgradeInput)).desiredGeneration, 9);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT profileId, specJson FROM xray_inbounds WHERE profileId IN ('VLESS_HTTP_UPGRADE_TLS', 'TROJAN_HTTP_UPGRADE_TLS') ORDER BY id",
      ), [
        { profileId: "VLESS_HTTP_UPGRADE_TLS", specJson: '{"path":"/forwardx/vless-httpupgrade"}' },
        { profileId: "TROJAN_HTTP_UPGRADE_TLS", specJson: '{"path":"/forwardx/trojan-httpupgrade"}' },
      ]);

      const vlessXhttpReservation = await reserve(10, 29113);
      const vlessXhttpInput = input("VLESS_XHTTP_TLS", vlessXhttpReservation, {
        tlsCertificateId: certificate.id,
        spec: { path: "/forwardx/vless-xhttp" },
      });
      assert.equal((await caller.inbounds.createV2(vlessXhttpInput)).desiredGeneration, 10);

      const trojanXhttpReservation = await reserve(10, 29114);
      const trojanXhttpInput = input("TROJAN_XHTTP_TLS", trojanXhttpReservation, {
        tlsCertificateId: certificate.id,
        spec: { path: "/forwardx/trojan-xhttp" },
      });
      assert.equal((await caller.inbounds.createV2(trojanXhttpInput)).desiredGeneration, 11);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT profileId, specJson FROM xray_inbounds WHERE profileId IN ('VLESS_XHTTP_TLS', 'TROJAN_XHTTP_TLS') ORDER BY id",
      ), [
        { profileId: "VLESS_XHTTP_TLS", specJson: '{"path":"/forwardx/vless-xhttp"}' },
        { profileId: "TROJAN_XHTTP_TLS", specJson: '{"path":"/forwardx/trojan-xhttp"}' },
      ]);

      const catalog = await caller.profiles.catalog({});
      assert.deepEqual(catalog.filter((profile) => profile.security === "TLS").map((profile) => profile.id), [
        "VLESS_RAW_TLS", "VLESS_RAW_TLS_VISION", "TROJAN_RAW_TLS", "VLESS_WEBSOCKET_TLS", "TROJAN_WEBSOCKET_TLS",
        "VLESS_GRPC_TLS", "TROJAN_GRPC_TLS", "VLESS_HTTP_UPGRADE_TLS", "TROJAN_HTTP_UPGRADE_TLS",
        "VLESS_XHTTP_TLS", "TROJAN_XHTTP_TLS", "VLESS_MKCP_TLS", "TROJAN_MKCP_TLS", "VMESS_RAW_TLS", "HYSTERIA2_TLS",
      ]);

      const vmessReservation = await reserve(10, 29115);
      const vmessInput = input("VMESS_RAW_TLS", vmessReservation, { tlsCertificateId: certificate.id });
      const vmess = await caller.inbounds.createV2(vmessInput);
      assert.equal(vmess.desiredGeneration, 12);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT profileId, specJson, security, tlsCertificateId FROM xray_inbounds WHERE id = ?",
        [vmess.inboundId],
      ), [{ profileId: "VMESS_RAW_TLS", specJson: "{}", security: "tls", tlsCertificateId: certificate.id }]);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT credentialType, settingsJson FROM xray_access_entries WHERE inboundId = ? ORDER BY id",
        [vmess.inboundId],
      ), [{
        credentialType: "UUID", settingsJson: '{"schemaVersion":1,"flow":"NONE","security":"AUTO"}',
      }, {
        credentialType: "UUID", settingsJson: '{"schemaVersion":1,"flow":"NONE","security":"AUTO"}',
      }]);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT s.kind FROM xray_access_entries a JOIN xray_access_secrets s ON s.accessEntryId = a.id WHERE a.inboundId = ? ORDER BY s.kind",
        [vmess.inboundId],
      ), [{ kind: "UUID" }, { kind: "UUID" }]);

      const shadowsocksReservation = await reserve(10, 29116);
      const shadowsocksInput = {
        hostId: 10,
        name: "Shadowsocks 2022",
        publicAddress: "8.8.8.8",
        portReservationId: shadowsocksReservation.reservationId,
        listenPort: shadowsocksReservation.selectedPort,
        profileId: "SHADOWSOCKS_2022_RAW_NONE",
        spec: {},
        initialAccessEntries: [{ name: "phone" }, { name: "laptop" }],
      };
      await assert.rejects(caller.inbounds.createV2({ ...shadowsocksInput, serverName: "tls.example.com" }));
      assert.equal(ports.validateXrayPortReservation({
        reservationId: shadowsocksReservation.reservationId, hostId: 10, userId: 1, port: 29116,
      }).port, 29116);
      const shadowsocks = await caller.inbounds.createV2(shadowsocksInput);
      assert.equal(shadowsocks.desiredGeneration, 13);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT profileId, specJson, protocol, transport, security, tlsCertificateId, realityTargetHost, realityPublicKey, realityPrivateKeyEncrypted FROM xray_inbounds WHERE id = ?",
        [shadowsocks.inboundId],
      ), [{
        profileId: "SHADOWSOCKS_2022_RAW_NONE", specJson: "{}", protocol: "shadowsocks", transport: "tcp",
        security: "none", tlsCertificateId: null, realityTargetHost: "", realityPublicKey: "", realityPrivateKeyEncrypted: "",
      }]);
      const [shadowsocksServerSecret] = await runtime.queryRaw(
        "SELECT kind, encryptedValue, fingerprint FROM xray_inbound_secrets WHERE inboundId = ?",
        [shadowsocks.inboundId],
      );
      assert.equal(shadowsocksServerSecret.kind, "SHADOWSOCKS_SERVER_KEY");
      const [shadowsocksInboundRow] = await runtime.queryRaw(
        "SELECT runtimeTag FROM xray_inbounds WHERE id = ?", [shadowsocks.inboundId],
      );
      const shadowsocksServerContext = secrets.xrayInboundSecretContext(
        shadowsocksInboundRow.runtimeTag, "SHADOWSOCKS_SERVER_KEY",
      );
      const shadowsocksServerKey = secrets.decryptXraySecret(
        shadowsocksServerSecret.encryptedValue, shadowsocksServerContext, keyring,
      );
      assert.match(shadowsocksServerKey, /^[A-Za-z0-9+/]{43}=$/);
      const shadowsocksAccessRows = await runtime.queryRaw(
        "SELECT a.credentialType, a.settingsJson, a.statsKey, s.kind, s.encryptedValue FROM xray_access_entries a JOIN xray_access_secrets s ON s.accessEntryId = a.id WHERE a.inboundId = ? ORDER BY a.id",
        [shadowsocks.inboundId],
      );
      assert.equal(shadowsocksAccessRows.length, 2);
      const shadowsocksUserKeys = shadowsocksAccessRows.map((row) => {
        assert.equal(row.credentialType, "SHADOWSOCKS_KEY");
        assert.equal(row.settingsJson, '{"schemaVersion":1}');
        assert.equal(row.kind, "SHADOWSOCKS_KEY");
        const value = secrets.decryptXraySecret(
          row.encryptedValue, secrets.xrayAccessSecretContext(row.statsKey, "SHADOWSOCKS_KEY"), keyring,
        );
        assert.match(value, /^[A-Za-z0-9+/]{43}=$/);
        return value;
      });
      assert.equal(new Set([shadowsocksServerKey, ...shadowsocksUserKeys]).size, 3);

      const otherMaterialRows = await runtime.queryRaw(
        "SELECT privateKeyEncrypted FROM xray_tls_certificates WHERE id = ?", [otherHostCertificate.id],
      );
      const otherEnvelope = otherMaterialRows[0].privateKeyEncrypted.split(":");
      const otherCiphertextIndex = otherEnvelope.length - 1;
      otherEnvelope[otherCiphertextIndex] = (otherEnvelope[otherCiphertextIndex].startsWith("A") ? "B" : "A")
        + otherEnvelope[otherCiphertextIndex].slice(1);
      await runtime.executeRaw("UPDATE xray_tls_certificates SET privateKeyEncrypted = ? WHERE id = ?", [
        otherEnvelope.join(":"), otherHostCertificate.id,
      ]);
      const crossHostReservation = await reserve(10, 29103);
      await expectCode(inboundService.createXrayInboundV2({
        ...input("VLESS_RAW_TLS", crossHostReservation, { tlsCertificateId: otherHostCertificate.id }), userId: 1,
      }), "INVALID_CONFIG_INPUT");
      assert.equal(ports.validateXrayPortReservation({
        reservationId: crossHostReservation.reservationId, hostId: 10, userId: 1, port: 29103,
      }).port, 29103);
      ports.consumeXrayPortReservation({ reservationId: crossHostReservation.reservationId, hostId: 10, userId: 1, port: 29103 });

      const sanReservation = await reserve(10, 29104);
      await expectCode(inboundService.createXrayInboundV2({
        ...input("VLESS_RAW_TLS", sanReservation, { tlsCertificateId: certificate.id, serverName: "other.example.com" }), userId: 1,
      }), "INVALID_CONFIG_INPUT");
      assert.equal(ports.validateXrayPortReservation({
        reservationId: sanReservation.reservationId, hostId: 10, userId: 1, port: 29104,
      }).port, 29104);
      ports.consumeXrayPortReservation({ reservationId: sanReservation.reservationId, hostId: 10, userId: 1, port: 29104 });

      const materialRows = await runtime.queryRaw(
        "SELECT privateKeyEncrypted FROM xray_tls_certificates WHERE id = ?", [certificate.id],
      );
      const materialEnvelope = materialRows[0].privateKeyEncrypted.split(":");
      const ciphertextIndex = materialEnvelope.length - 1;
      materialEnvelope[ciphertextIndex] = (materialEnvelope[ciphertextIndex].startsWith("A") ? "B" : "A")
        + materialEnvelope[ciphertextIndex].slice(1);
      await runtime.executeRaw("UPDATE xray_tls_certificates SET privateKeyEncrypted = ? WHERE id = ?", [
        materialEnvelope.join(":"),
        certificate.id,
      ]);
      const corruptReservation = await reserve(10, 29105);
      await expectCode(inboundService.createXrayInboundV2({
        ...input("VLESS_RAW_TLS", corruptReservation, { tlsCertificateId: certificate.id }), userId: 1,
      }), "SENSITIVE_DATA_UNAVAILABLE");
      assert.equal(ports.validateXrayPortReservation({
        reservationId: corruptReservation.reservationId, hostId: 10, userId: 1, port: 29105,
      }).port, 29105);
      ports.consumeXrayPortReservation({ reservationId: corruptReservation.reservationId, hostId: 10, userId: 1, port: 29105 });

      if (process.env.XRAY_TEST_BINARY) {
        await runtime.executeRaw("UPDATE xray_tls_certificates SET privateKeyEncrypted = ? WHERE id = ?", [materialRows[0].privateKeyEncrypted, certificate.id]);
        const generator = await load("server/xrayConfigGenerator.ts");
        const generated = await generator.generateXrayHostConfig(10, keyring);
        const configPath = path.join(path.dirname(process.env.FORWARDX_TEST_DB), "generated.json");
        fs.writeFileSync(configPath, generated.configJson, { mode: 0o600 });
        const checked = spawnSync(process.env.XRAY_TEST_BINARY, ["run", "-test", "-config", configPath], {
          encoding: "utf8", timeout: 10_000,
        });
        assert.equal(checked.status, 0, checked.stderr || checked.stdout);
      }
    } finally {
      ports.clearXrayPortOperationStateForTest();
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
        JWT_SECRET: "xray-raw-tls-create-test-secret",
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
