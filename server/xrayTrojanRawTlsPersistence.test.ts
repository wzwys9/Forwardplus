import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("Trojan RAW TLS persistence and host snapshots stay password-only and host-scoped", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-trojan-raw-tls-persistence-"));
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

    const inbound = (runtimeTag, listenPort, tlsCertificateId) => ({
      profile: { id: "TROJAN_RAW_TLS", specVersion: 1, specJson: "{}" },
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
    const access = (statsKey, password, shortId) => {
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
        name: "phone",
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
      const password = "C".repeat(43);
      const created = await create(
        0,
        inbound("forwardx-trojan-raw-tls-create", 28911, sameHostCertificate.id),
        access("forwardx-trojan-raw-tls-access", password),
      );
      assert.equal(created.desiredGeneration, 1);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT profileId, security, tlsCertificateId, realityTargetHost, realityPublicKey, realityPrivateKeyEncrypted FROM xray_inbounds",
      ), [{
        profileId: "TROJAN_RAW_TLS", security: "tls", tlsCertificateId: sameHostCertificate.id,
        realityTargetHost: "", realityPublicKey: "", realityPrivateKeyEncrypted: "",
      }]);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_clients"))[0].count, 0);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_inbound_secrets"))[0].count, 0);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT legacyClientId, credentialType, settingsJson FROM xray_access_entries",
      ), [{ legacyClientId: null, credentialType: "PASSWORD", settingsJson: '{"schemaVersion":1}' }]);
      assert.deepEqual(await runtime.queryRaw("SELECT kind FROM xray_access_secrets"), [{ kind: "PASSWORD" }]);

      const generated = await generator.generateXrayHostConfig(10, keyring);
      const config = JSON.parse(generated.configJson);
      assert.deepEqual(config.inbounds[0].settings.clients, [{
        password, email: "forwardx-trojan-raw-tls-access",
      }]);
      assert.equal(config.inbounds[0].streamSettings.security, "tls");
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
        1,
        inbound("forwardx-trojan-raw-tls-short-id", 28912, sameHostCertificate.id),
        access("forwardx-trojan-raw-tls-short-id", "D".repeat(43), "0123456789abcdef"),
      ), (error) => error?.code === "OPERATION_CONFLICT");
      await assert.rejects(create(
        1,
        inbound("forwardx-trojan-raw-tls-cross-host", 28913, otherHostCertificate.id),
        access("forwardx-trojan-raw-tls-cross-host", "E".repeat(43)),
      ), (error) => error?.code === "OPERATION_CONFLICT");
      assert.deepEqual({
        inbounds: (await runtime.queryRaw("SELECT COUNT(*) count FROM xray_inbounds"))[0].count,
        access: (await runtime.queryRaw("SELECT COUNT(*) count FROM xray_access_entries"))[0].count,
        secrets: (await runtime.queryRaw("SELECT COUNT(*) count FROM xray_access_secrets"))[0].count,
        operations: (await runtime.queryRaw("SELECT COUNT(*) count FROM xray_operations"))[0].count,
        generation: (await runtime.queryRaw("SELECT desiredGeneration FROM xray_host_deployments WHERE hostId = 10"))[0].desiredGeneration,
      }, beforeFailure);

      const second = await caller.accessEntries.create({
        inboundId: created.inboundId,
        name: "laptop",
        expectedGeneration: 1,
      });
      assert.equal(second.desiredGeneration, 2);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT a.name, s.kind FROM xray_access_entries a JOIN xray_access_secrets s ON s.accessEntryId = a.id ORDER BY a.id",
      ), [{ name: "phone", kind: "PASSWORD" }, { name: "laptop", kind: "PASSWORD" }]);
      const sharedResult = await caller.accessEntries.share({ accessEntryId: second.accessEntryId, format: "TROJAN_URI" });
      const shared = new URL(sharedResult.uri);
      assert.equal(shared.protocol, "trojan:");
      assert.equal(shared.searchParams.get("type"), "tcp");
      assert.equal(shared.searchParams.get("security"), "tls");
      assert.equal(shared.searchParams.get("sni"), "tls.example.com");
      assert.equal(shared.searchParams.get("fp"), "chrome");
      assert.match(shared.searchParams.get("pcs") ?? "", /^[0-9a-f]{64}$/);
      for (const forbidden of ["flow", "sid", "pbk", "allowInsecure"]) {
        assert.equal(shared.searchParams.has(forbidden), false, forbidden);
      }
      assert.equal(responseHeaders.get("Cache-Control"), "private, no-store, max-age=0");
      await assert.rejects(
        caller.accessEntries.share({ accessEntryId: second.accessEntryId, format: "VLESS_URI" }),
        (error) => error?.cause?.code === "INVALID_CONFIG_INPUT" || error?.message === "INVALID_CONFIG_INPUT",
      );
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
      assert.equal((await caller.accessEntries.share({
        accessEntryId: second.accessEntryId,
        format: "TROJAN_URI",
      })).deploymentStatus, "PENDING_DELETE");
      assert.deepEqual(await repository.deleteAppliedPendingXrayRecordsWithinHostLock(10, 4), {
        inboundCount: 0,
        clientCount: 1,
      });
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_access_entries"))[0].count, 1);
      assert.deepEqual(await runtime.queryRaw("SELECT kind FROM xray_access_secrets"), [{ kind: "PASSWORD" }]);
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
