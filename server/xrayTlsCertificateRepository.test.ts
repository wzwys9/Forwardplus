import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

function createFixture(directory: string) {
  const certificatePath = path.join(directory, "certificate.pem");
  const privateKeyPath = path.join(directory, "private-key.pem");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
    "-subj", "/CN=repository.example.com", "-keyout", privateKeyPath, "-out", certificatePath,
    "-addext", "basicConstraints=critical,CA:FALSE",
    "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
    "-addext", "extendedKeyUsage=serverAuth",
    "-addext", "subjectAltName=DNS:repository.example.com,DNS:*.repository.example.com",
  ], { stdio: "ignore" });
  return { certificatePath, privateKeyPath };
}

test("managed TLS certificate repository encrypts private keys and returns safe host-scoped DTOs", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-tls-repository-"));
  const fixture = createFixture(directory);
  const script = String.raw`
    import assert from "node:assert/strict";
    import fs from "node:fs";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const runtime = await load("server/dbRuntime.ts");
    const schema = await load("server/dbSchema.ts");
    const secrets = await load("server/xraySecretCrypto.ts");
    const repository = await load("server/repositories/xrayTlsCertificateRepository.ts");
    const certificatePem = fs.readFileSync(process.env.FORWARDX_TEST_CERT_PATH, "utf8");
    const privateKeyPem = fs.readFileSync(process.env.FORWARDX_TEST_KEY_PATH, "utf8");
    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, userId) VALUES (1, 'edge-a', '127.0.0.1', 1), (2, 'edge-b', '127.0.0.2', 1)");

      const created = await repository.createXrayTlsCertificate({
        hostId: 1,
        name: "Repository TLS",
        certificatePem,
        privateKeyPem,
        createdByUserId: 1,
      }, { keyring });
      assert.equal(created.hostId, 1);
      assert.equal(created.name, "Repository TLS");
      assert.deepEqual(created.dnsNames, ["*.repository.example.com", "repository.example.com"]);
      assert.equal(created.privateKeyConfigured, true);
      assert.equal(created.referenceCount, 0);
      const serialized = JSON.stringify(created);
      for (const forbidden of [privateKeyPem.trim(), "privateKeyEncrypted", "privateKeyFingerprint", "certificateChainPem", "certificateTag", "keyVersion"]) {
        assert.equal(serialized.includes(forbidden), false);
      }

      const [stored] = await runtime.queryRaw("SELECT * FROM xray_tls_certificates WHERE id = ?", [created.id]);
      assert.match(stored.certificateTag, /^forwardx-cert-[0-9a-f-]{36}$/);
      assert.match(stored.privateKeyEncrypted, /^fwdx-secret:v1:1:/);
      assert.equal(stored.privateKeyEncrypted.includes("BEGIN PRIVATE KEY"), false);
      assert.match(stored.privateKeyFingerprint, /^[0-9a-f]{64}$/);
      assert.equal(stored.keyVersion, 1);

      const material = await repository.getXrayTlsCertificateMaterial(created.id, { keyring });
      assert.equal(material.privateKeyPem, privateKeyPem);
      assert.equal(material.certificateChainPem, certificatePem);
      assert.equal(material.certificateTag, stored.certificateTag);

      assert.deepEqual((await repository.listXrayTlsCertificates({ hostId: 1 })).map((item) => item.id), [created.id]);
      assert.deepEqual(await repository.listXrayTlsCertificates({ hostId: 2 }), []);

      await assert.rejects(repository.createXrayTlsCertificate({
        hostId: 1,
        name: " repository tls ",
        certificatePem,
        privateKeyPem,
        createdByUserId: 1,
      }, { keyring }), (error) => error.code === "CERTIFICATE_CONFLICT");
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_tls_certificates"))[0].count, 1);

      await runtime.executeRaw("UPDATE xray_tls_certificates SET dnsNamesJson = ? WHERE id = ?", ['{"leak":true}', created.id]);
      await assert.rejects(repository.getXrayTlsCertificate(created.id), (error) => error.code === "INVALID_CERTIFICATE_DATA");
      await runtime.executeRaw("UPDATE xray_tls_certificates SET dnsNamesJson = ? WHERE id = ?", ['["*.repository.example.com","repository.example.com"]', created.id]);
      await runtime.executeRaw("UPDATE xray_tls_certificates SET privateKeyFingerprint = ? WHERE id = ?", ["0".repeat(64), created.id]);
      await assert.rejects(repository.getXrayTlsCertificateMaterial(created.id, { keyring }), (error) => error.code === "SENSITIVE_DATA_UNAVAILABLE");
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
        FORWARDX_TEST_CERT_PATH: fixture.certificatePath,
        FORWARDX_TEST_KEY_PATH: fixture.privateKeyPath,
        XRAY_MASTER_KEY_PATH: path.join(directory, "xray-master.key"),
      },
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
