import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { buildXrayTrojanTlsUri } from "../shared/xrayShare";
import { generateDeterministicXrayConfig, type XrayConfigInboundInput } from "./xrayConfigGenerator";

function tlsMaterial() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-trojan-raw-tls-"));
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
  return {
    directory,
    certificateChainPem: fs.readFileSync(certificatePath, "utf8"),
    privateKeyPem: fs.readFileSync(privateKeyPath, "utf8"),
  };
}

function inbound(input: {
  certificateChainPem: string;
  privateKeyPem: string;
  shortId?: string;
}) {
  return {
    id: 81,
    runtimeTag: "forwardx-trojan-raw-tls-81",
    listenAddress: "0.0.0.0",
    listenPort: 28881,
    protocol: "trojan",
    transport: "tcp",
    security: "tls",
    profileId: "TROJAN_RAW_TLS",
    specVersion: 1,
    specJson: "{}",
    realityServerName: "tls.example.com",
    tlsCertificateChainPem: input.certificateChainPem,
    tlsPrivateKeyPem: input.privateKeyPem,
    isEnabled: true,
    pendingDelete: false,
    clients: [{
      id: 810,
      credentialType: "PASSWORD",
      password: "A".repeat(43),
      ...(input.shortId === undefined ? {} : { shortId: input.shortId }),
      statsKey: "forwardx-trojan-raw-tls-client-810",
      isEnabled: true,
      pendingDelete: false,
      sortOrder: 0,
    }],
  } as unknown as XrayConfigInboundInput;
}

test("Trojan RAW TLS compiles password-only clients and a pinned share URI", () => {
  const material = tlsMaterial();
  try {
    const generated = generateDeterministicXrayConfig([inbound(material)]);
    const config = JSON.parse(generated.configJson);
    assert.deepEqual(config.inbounds[0].settings, {
      clients: [{ password: "A".repeat(43), email: "forwardx-trojan-raw-tls-client-810" }],
    });
    assert.equal(config.inbounds[0].streamSettings.network, "tcp");
    assert.equal(config.inbounds[0].streamSettings.security, "tls");
    assert.equal(config.inbounds[0].streamSettings.tlsSettings.certificates.length, 1);
    for (const forbidden of ["certificateFile", "keyFile", "shortId", "flow", "realitySettings"]) {
      assert.equal(generated.configJson.includes(forbidden), false, forbidden);
    }

    const uri = buildXrayTrojanTlsUri({
      profileId: "TROJAN_RAW_TLS",
      password: "A".repeat(43),
      publicAddress: "edge.example.com",
      listenPort: 28881,
      serverName: "tls.example.com",
      fingerprint: "chrome",
      leafFingerprintSha256: "b".repeat(64),
      displayName: "Trojan TLS / phone",
    });
    const parsed = new URL(uri);
    assert.equal(parsed.protocol, "trojan:");
    assert.equal(parsed.username, "A".repeat(43));
    assert.deepEqual([...parsed.searchParams.entries()], [
      ["type", "tcp"], ["security", "tls"], ["sni", "tls.example.com"],
      ["fp", "chrome"], ["pcs", "b".repeat(64)],
    ]);
    for (const forbidden of ["allowInsecure", "flow=", "sid=", "pbk=", "encryption="]) {
      assert.equal(uri.includes(forbidden), false, forbidden);
    }

    const binary = process.env.XRAY_TEST_BINARY;
    if (binary) {
      const configPath = path.join(material.directory, "config.json");
      fs.writeFileSync(configPath, generated.configJson, { mode: 0o600 });
      const checked = spawnSync(binary, ["run", "-test", "-config", configPath], {
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(checked.status, 0, `${checked.stdout}\n${checked.stderr}`);
    }
  } finally {
    fs.rmSync(material.directory, { recursive: true, force: true });
  }
});

test("Trojan RAW TLS rejects Reality credentials and cross-profile fields", () => {
  const material = tlsMaterial();
  try {
    assert.throws(() => generateDeterministicXrayConfig([inbound({ ...material, shortId: "0102030405060708" })]));
    const valid = inbound(material);
    assert.throws(() => generateDeterministicXrayConfig([{
      ...valid,
      clients: [{ ...valid.clients[0], flow: "xtls-rprx-vision" }],
    } as unknown as XrayConfigInboundInput]));
    assert.throws(() => generateDeterministicXrayConfig([{
      ...valid,
      realityTargetHost: "www.example.com",
      realityTargetPort: 443,
      realityPrivateKey: "A".repeat(43),
    } as unknown as XrayConfigInboundInput]));
    assert.throws(() => buildXrayTrojanTlsUri({
      profileId: "TROJAN_RAW_REALITY" as "TROJAN_RAW_TLS",
      password: "A".repeat(43),
      publicAddress: "edge.example.com",
      listenPort: 28881,
      serverName: "tls.example.com",
      fingerprint: "chrome",
      leafFingerprintSha256: "b".repeat(64),
      displayName: "invalid",
    }));
  } finally {
    fs.rmSync(material.directory, { recursive: true, force: true });
  }
});
