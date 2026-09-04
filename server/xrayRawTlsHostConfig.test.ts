import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("RAW TLS host config loads only same-host certificates and generic UUID v2 access", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-raw-tls-host-"));
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
    const certificateRepository = await load("server/repositories/xrayTlsCertificateRepository.ts");
    const accessRepository = await load("server/repositories/xrayAccessRepository.ts");
    const generator = await load("server/xrayConfigGenerator.ts");
    const secrets = await load("server/xraySecretCrypto.ts");
    const certificatePem = fs.readFileSync(process.env.FORWARDX_TEST_CERT_PATH, "utf8");
    const privateKeyPem = fs.readFileSync(process.env.FORWARDX_TEST_KEY_PATH, "utf8");
    const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
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

      const createInbound = async (profileId, runtimeTag, port) => runtime.insertAndGetId("xray_inbounds", {
        hostId: 10,
        name: runtimeTag,
        runtimeTag,
        publicAddress: "203.0.113.10",
        listenAddress: "0.0.0.0",
        listenPort: port,
        protocol: "vless",
        transport: "tcp",
        security: "tls",
        tlsCertificateId: sameHostCertificate.id,
        profileId,
        specVersion: 1,
        specJson: "{}",
        realityTargetHost: "",
        realityTargetPort: 443,
        realityServerName: "tls.example.com",
        realityPublicKey: "",
        realityPrivateKeyEncrypted: "",
        secretKeyVersion: 1,
        fingerprint: "chrome",
        spiderX: "/",
        isEnabled: true,
        pendingDelete: false,
        desiredGeneration: 1,
        createdByUserId: 1,
      });
      const standardInboundId = await createInbound("VLESS_RAW_TLS", "forwardx-raw-tls-standard", 28781);
      const visionInboundId = await createInbound("VLESS_RAW_TLS_VISION", "forwardx-raw-tls-vision", 28782);
      const standardUuid = "00000000-0000-4000-8000-000000000081";
      const visionUuid = "00000000-0000-4000-8000-000000000082";
      const standardStatsKey = "fwdx-raw-tls-standard";
      const standardAccess = await accessRepository.createXrayAccessEntry({
        inboundId: standardInboundId,
        name: "phone",
        credentialType: "UUID",
        settingsJson: '{"schemaVersion":2,"protocol":"VLESS","encryption":"NONE","flow":"NONE"}',
        statsKey: standardStatsKey,
        desiredGeneration: 1,
        secrets: [{ kind: "UUID", plaintext: standardUuid }],
      }, { keyring });
      await accessRepository.createXrayAccessEntry({
        inboundId: visionInboundId,
        name: "laptop",
        credentialType: "UUID",
        settingsJson: '{"schemaVersion":2,"protocol":"VLESS","encryption":"NONE","flow":"XTLS_RPRX_VISION"}',
        statsKey: "fwdx-raw-tls-vision",
        desiredGeneration: 1,
        secrets: [{ kind: "UUID", plaintext: visionUuid }],
      }, { keyring });

      const generated = await generator.generateXrayHostConfig(10, keyring);
      const config = JSON.parse(generated.configJson);
      assert.deepEqual(config.inbounds.map((inbound) => inbound.tag), [
        "forwardx-raw-tls-standard", "forwardx-raw-tls-vision",
      ]);
      assert.deepEqual(config.inbounds[0].settings.clients, [{ id: standardUuid, email: standardStatsKey }]);
      assert.deepEqual(config.inbounds[1].settings.clients, [{
        id: visionUuid, email: "fwdx-raw-tls-vision", flow: "xtls-rprx-vision",
      }]);
      for (const inbound of config.inbounds) {
        assert.equal(inbound.streamSettings.security, "tls");
        assert.equal(inbound.streamSettings.tlsSettings.certificates.length, 1);
        assert.equal("realitySettings" in inbound.streamSettings, false);
      }
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_clients"))[0].count, 0);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_inbound_secrets"))[0].count, 0);
      assert.deepEqual(await runtime.queryRaw("SELECT kind FROM xray_access_secrets ORDER BY accessEntryId"), [
        { kind: "UUID" }, { kind: "UUID" },
      ]);
      assert.equal(generated.configJson.includes("realityPrivateKeyEncrypted"), false);

      if (process.env.XRAY_TEST_BINARY) {
        const configPath = path.join(path.dirname(process.env.FORWARDX_TEST_DB), "generated.json");
        fs.writeFileSync(configPath, generated.configJson, { mode: 0o600 });
        const checked = spawnSync(process.env.XRAY_TEST_BINARY, ["run", "-test", "-config", configPath], {
          encoding: "utf8", timeout: 10_000,
        });
        assert.equal(checked.status, 0, checked.stderr || checked.stdout);
      }

      await runtime.executeRaw("UPDATE xray_access_entries SET settingsJson = ? WHERE id = ?", [
        '{"schemaVersion":2,"protocol":"VLESS","encryption":"NONE","flow":"XTLS_RPRX_VISION"}',
        standardAccess.id,
      ]);
      await assert.rejects(generator.generateXrayHostConfig(10, keyring));
      await runtime.executeRaw("UPDATE xray_access_entries SET settingsJson = ? WHERE id = ?", [
        '{"schemaVersion":2,"protocol":"VLESS","encryption":"NONE","flow":"NONE"}',
        standardAccess.id,
      ]);

      const shortIdContext = secrets.xrayAccessSecretContext(standardStatsKey, "SHORT_ID");
      const hiddenShortId = "0102";
      const hiddenEnvelope = secrets.encryptXraySecret(hiddenShortId, shortIdContext, keyring);
      await runtime.insertAndGetId("xray_access_secrets", {
        accessEntryId: standardAccess.id,
        kind: "SHORT_ID",
        encryptedValue: hiddenEnvelope,
        fingerprint: secrets.fingerprintXraySecret(hiddenShortId, shortIdContext, keyring),
        keyVersion: secrets.inspectXraySecretEnvelope(hiddenEnvelope).version,
      });
      await assert.rejects(generator.generateXrayHostConfig(10, keyring));
      await runtime.executeRaw("DELETE FROM xray_access_secrets WHERE accessEntryId = ? AND kind = 'SHORT_ID'", [standardAccess.id]);

      await runtime.executeRaw("UPDATE xray_tls_certificates SET privateKeyEncrypted = 'corrupt' WHERE id = ?", [
        otherHostCertificate.id,
      ]);
      await runtime.executeRaw("UPDATE xray_inbounds SET tlsCertificateId = ? WHERE id = ?", [
        otherHostCertificate.id, standardInboundId,
      ]);
      await assert.rejects(generator.generateXrayHostConfig(10, keyring), (error) => error?.code === "INVALID_CONFIG_INPUT");
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
