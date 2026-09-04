import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  MAX_XRAY_TLS_CERTIFICATE_BYTES,
  XrayTlsCertificateValidationError,
  validateXrayTlsCertificateInput,
  xrayTlsCertificateCoversServerName,
} from "./xrayTlsCertificate";

type Fixture = { certificatePem: string; privateKeyPem: string };

function createCertificateFixture(directory: string, name: string, options: {
  key?: "rsa" | "p521";
  sans?: string[];
} = {}): Fixture {
  const certificatePath = path.join(directory, `${name}.crt`);
  const privateKeyPath = path.join(directory, `${name}.key`);
  const sans = options.sans ?? ["example.com", "*.example.com"];
  const keyArguments = options.key === "p521"
    ? ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:secp521r1"]
    : ["-newkey", "rsa:2048"];
  const argumentsList = [
    "req", "-x509", ...keyArguments, "-nodes", "-sha256", "-days", "2",
    "-subj", "/CN=example.com", "-keyout", privateKeyPath, "-out", certificatePath,
    "-addext", "basicConstraints=critical,CA:FALSE",
    "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
    "-addext", "extendedKeyUsage=serverAuth",
  ];
  if (sans.length > 0) argumentsList.push("-addext", `subjectAltName=${sans.map((item) => `DNS:${item}`).join(",")}`);
  execFileSync("openssl", argumentsList, { stdio: "ignore" });
  return {
    certificatePem: fs.readFileSync(certificatePath, "utf8"),
    privateKeyPem: fs.readFileSync(privateKeyPath, "utf8"),
  };
}

function validationCode(operation: () => unknown, expected: string) {
  assert.throws(operation, (error: unknown) => {
    assert.ok(error instanceof XrayTlsCertificateValidationError);
    assert.equal(error.code, expected);
    return true;
  });
}

test("TLS certificate validation normalizes an approved matching PEM pair", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-tls-validation-"));
  try {
    const fixture = createCertificateFixture(directory, "valid");
    const result = validateXrayTlsCertificateInput({
      certificatePem: fixture.certificatePem.replace(/\n/g, "\r\n"),
      privateKeyPem: fixture.privateKeyPem,
    });

    assert.deepEqual(result.dnsNames, ["*.example.com", "example.com"]);
    assert.equal(result.keyAlgorithm, "RSA_2048_4096");
    assert.match(result.leafFingerprintSha256, /^[0-9a-f]{64}$/);
    assert.match(result.certificateChainPem, /^-----BEGIN CERTIFICATE-----/);
    assert.match(result.privateKeyPem, /^-----BEGIN PRIVATE KEY-----/);
    assert.equal(result.certificateCount, 1);
    assert.equal(result.notBefore < result.notAfter, true);
    assert.equal(xrayTlsCertificateCoversServerName(result.certificateChainPem, "example.com"), true);
    assert.equal(xrayTlsCertificateCoversServerName(result.certificateChainPem, "api.example.com"), true);
    assert.equal(xrayTlsCertificateCoversServerName(result.certificateChainPem, "deep.api.example.com"), false);
    assert.equal(xrayTlsCertificateCoversServerName(result.certificateChainPem, "example.net"), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("TLS certificate validation rejects mismatched, expired, premature, oversized, and unsupported inputs", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-tls-invalid-"));
  try {
    const first = createCertificateFixture(directory, "first");
    const second = createCertificateFixture(directory, "second");
    const noSan = createCertificateFixture(directory, "no-san", { sans: [] });
    const p521 = createCertificateFixture(directory, "p521", { key: "p521" });
    const parsed = validateXrayTlsCertificateInput(first);

    validationCode(() => validateXrayTlsCertificateInput({
      certificatePem: first.certificatePem,
      privateKeyPem: second.privateKeyPem,
    }), "CERTIFICATE_KEY_MISMATCH");
    validationCode(() => validateXrayTlsCertificateInput({ ...first, now: new Date((parsed.notAfter + 60) * 1000) }), "CERTIFICATE_EXPIRED");
    validationCode(() => validateXrayTlsCertificateInput({ ...first, now: new Date((parsed.notBefore - 60) * 1000) }), "CERTIFICATE_NOT_YET_VALID");
    validationCode(() => validateXrayTlsCertificateInput(noSan), "CERTIFICATE_INVALID");
    validationCode(() => validateXrayTlsCertificateInput(p521), "PRIVATE_KEY_INVALID");
    validationCode(() => validateXrayTlsCertificateInput({
      certificatePem: `${first.certificatePem}${" ".repeat(MAX_XRAY_TLS_CERTIFICATE_BYTES)}`,
      privateKeyPem: first.privateKeyPem,
    }), "CERTIFICATE_INVALID");
    validationCode(() => validateXrayTlsCertificateInput({
      certificatePem: first.certificatePem,
      privateKeyPem: "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
    }), "PRIVATE_KEY_INVALID");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
