import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

function createFixture(directory: string, name: string) {
  const certificatePath = path.join(directory, `${name}.pem`);
  const privateKeyPath = path.join(directory, `${name}.key`);
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
    "-subj", `/CN=${name}.example.com`, "-keyout", privateKeyPath, "-out", certificatePath,
    "-addext", "basicConstraints=critical,CA:FALSE",
    "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
    "-addext", "extendedKeyUsage=serverAuth",
    "-addext", `subjectAltName=DNS:${name}.example.com`,
  ], { stdio: "ignore" });
  return { certificatePath, privateKeyPath };
}

test("managed TLS certificate API enforces admin, host, rotation, reference, and deletion boundaries", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-tls-service-"));
  const first = createFixture(directory, "first");
  const second = createFixture(directory, "second");
  const script = String.raw`
    import assert from "node:assert/strict";
    import fs from "node:fs";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const db = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const secrets = await import(moduleUrl("server/xraySecretCrypto.ts"));
    const versions = await import(moduleUrl("shared/versions.ts"));
    const { xrayRouter } = await import(moduleUrl("server/routers/xray.ts"));
    const context = (user) => ({ req: { headers: {} }, res: { clearCookie() {}, setHeader() {} }, user, authSession: null, authFailureReason: null });
    const admin = { id: 1, username: "admin", role: "admin", accountEnabled: true };
    const member = { id: 2, username: "member", role: "user", accountEnabled: true };
    const caller = xrayRouter.createCaller(context(admin));
    const memberCaller = xrayRouter.createCaller(context(member));
    const firstCertificatePem = fs.readFileSync(process.env.FORWARDX_TEST_CERT_1, "utf8");
    const firstPrivateKeyPem = fs.readFileSync(process.env.FORWARDX_TEST_KEY_1, "utf8");
    const secondCertificatePem = fs.readFileSync(process.env.FORWARDX_TEST_CERT_2, "utf8");
    const secondPrivateKeyPem = fs.readFileSync(process.env.FORWARDX_TEST_KEY_2, "utf8");
    const expectCode = (promise, code) => assert.rejects(promise, (error) => error?.message === code || error?.cause?.code === code);
    try {
      await db.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
      const now = Math.floor(Date.now() / 1000);
      await db.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin'), (2, 'member', 'hash', 'user')");
      await db.executeRaw("INSERT INTO hosts (id, name, ip, ipv4, isOnline, lastHeartbeat, agentVersion, userId) VALUES (1, 'edge-a', '8.8.8.8', '8.8.8.8', 1, ?, ?, 1), (2, 'edge-offline', '8.8.4.4', '8.8.4.4', 0, ?, ?, 1)", [now, versions.AGENT_VERSION, now, versions.AGENT_VERSION]);
      for (const hostId of [1, 2]) {
        await db.executeRaw("INSERT INTO xray_runtime_reports (hostId, capabilitySchemaVersion, supportedOS, supportedArch, supportsArtifactInstall, supportsPortProbe, supportsRealityScan, reportedAt) VALUES (?, 1, 'linux', 'amd64', 1, 1, 1, ?)", [hostId, now]);
      }

      await assert.rejects(() => memberCaller.certificates.import({
        hostId: 1, name: "member", certificatePem: firstCertificatePem, privateKeyPem: firstPrivateKeyPem,
      }), (error) => error?.code === "FORBIDDEN");
      await expectCode(caller.certificates.import({
        hostId: 2, name: "offline", certificatePem: firstCertificatePem, privateKeyPem: firstPrivateKeyPem,
      }), "HOST_OFFLINE");

      const imported = await caller.certificates.import({
        hostId: 1, name: "Edge certificate", certificatePem: firstCertificatePem, privateKeyPem: firstPrivateKeyPem,
      });
      assert.equal(imported.hostId, 1);
      assert.deepEqual(imported.dnsNames, ["first.example.com"]);
      assert.equal(imported.privateKeyConfigured, true);
      const serialized = JSON.stringify(imported);
      for (const forbidden of [firstPrivateKeyPem.trim(), "certificatePem", "privateKeyPem", "privateKeyEncrypted", "fingerprint", "keyVersion"]) {
        assert.equal(serialized.includes(forbidden), false);
      }
      assert.deepEqual((await caller.certificates.list({ hostId: 1, page: 1, pageSize: 20 })).items.map((item) => item.id), [imported.id]);

      const rotatedUnused = await caller.certificates.rotate({
        id: imported.id, certificatePem: secondCertificatePem, privateKeyPem: secondPrivateKeyPem, expectedGeneration: 0,
      });
      assert.equal(rotatedUnused.operationId, null);
      assert.equal(rotatedUnused.desiredGeneration, null);
      assert.deepEqual(rotatedUnused.certificate.dnsNames, ["second.example.com"]);

      await db.executeRaw("INSERT INTO xray_host_deployments (hostId, targetVersion, desiredGeneration) VALUES (1, 'v26.3.27', 0)");
      await db.executeRaw("INSERT INTO xray_inbounds (hostId, name, runtimeTag, publicAddress, listenPort, realityTargetHost, realityServerName, realityPublicKey, realityPrivateKeyEncrypted, createdByUserId, isEnabled, tlsCertificateId) VALUES (1, 'disabled-reference', 'runtime-disabled-tls-reference', '8.8.8.8', 24443, 'example.com', 'example.com', 'public', 'not-used-while-disabled', 1, 0, ?)", [imported.id]);

      await expectCode(caller.certificates.rotate({
        id: imported.id, certificatePem: firstCertificatePem, privateKeyPem: firstPrivateKeyPem, expectedGeneration: 9,
      }), "CONFIG_GENERATION_CONFLICT");
      const rotatedReferenced = await caller.certificates.rotate({
        id: imported.id, certificatePem: firstCertificatePem, privateKeyPem: firstPrivateKeyPem, expectedGeneration: 0,
      });
      assert.match(rotatedReferenced.operationId, /^[A-Za-z0-9._:-]{1,64}$/);
      assert.equal(rotatedReferenced.desiredGeneration, 1);
      assert.equal((await db.queryRaw("SELECT desiredGeneration FROM xray_host_deployments WHERE hostId = 1"))[0].desiredGeneration, 1);

      await expectCode(caller.certificates.remove({ id: imported.id, confirmName: "Edge certificate" }), "CERTIFICATE_IN_USE");
      await db.executeRaw("UPDATE xray_inbounds SET tlsCertificateId = NULL WHERE tlsCertificateId = ?", [imported.id]);
      await expectCode(caller.certificates.remove({ id: imported.id, confirmName: "wrong" }), "CONFIRMATION_MISMATCH");
      assert.deepEqual(await caller.certificates.remove({ id: imported.id, confirmName: "Edge certificate" }), { id: imported.id, removed: true });
      assert.equal((await db.queryRaw("SELECT COUNT(*) count FROM xray_tls_certificates"))[0].count, 0);
    } finally {
      await db.closeDatabase().catch(() => undefined);
    }
  `;

  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        DATABASE_TYPE: "sqlite",
        FORWARDX_TEST_DB: path.join(directory, "panel.db"),
        FORWARDX_TEST_CERT_1: first.certificatePath,
        FORWARDX_TEST_KEY_1: first.privateKeyPath,
        FORWARDX_TEST_CERT_2: second.certificatePath,
        FORWARDX_TEST_KEY_2: second.privateKeyPath,
        XRAY_MASTER_KEY_PATH: path.join(directory, "xray-master.key"),
        JWT_SECRET: "xray-tls-certificate-service-test",
      },
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
