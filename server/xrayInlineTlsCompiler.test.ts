import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { compileXrayInlineTlsSecurity } from "./xrayTransportSecurityCompiler";

test("managed TLS material compiles to inline Xray fields without Agent paths", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-inline-tls-"));
  const certificatePath = path.join(directory, "certificate.pem");
  const privateKeyPath = path.join(directory, "private-key.pem");
  try {
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
      "-subj", "/CN=tls.example.com", "-keyout", privateKeyPath, "-out", certificatePath,
      "-addext", "basicConstraints=critical,CA:FALSE",
      "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
      "-addext", "extendedKeyUsage=serverAuth",
      "-addext", "subjectAltName=DNS:tls.example.com",
    ], { stdio: "ignore" });

    const compiled = compileXrayInlineTlsSecurity({
      certificateChainPem: fs.readFileSync(certificatePath, "utf8"),
      privateKeyPem: fs.readFileSync(privateKeyPath, "utf8"),
    });
    assert.equal(compiled.security, "tls");
    assert.equal(compiled.tlsSettings.certificates.length, 1);
    assert.equal(compiled.tlsSettings.certificates[0].certificate[0], "-----BEGIN CERTIFICATE-----");
    assert.equal(compiled.tlsSettings.certificates[0].key[0], "-----BEGIN PRIVATE KEY-----");
    const serialized = JSON.stringify(compiled);
    assert.equal(serialized.includes("certificateFile"), false);
    assert.equal(serialized.includes("keyFile"), false);
    assert.equal(serialized.includes(directory), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
