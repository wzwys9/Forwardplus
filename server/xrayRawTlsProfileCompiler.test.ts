import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  generateDeterministicXrayConfig,
  type XrayConfigInboundInput,
} from "./xrayConfigGenerator";

function tlsMaterial() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-raw-tls-"));
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

function rawTlsInbound(input: {
  id: number;
  profileId: "VLESS_RAW_TLS" | "VLESS_RAW_TLS_VISION" | "VMESS_RAW_TLS";
  flow: "" | "xtls-rprx-vision";
  port: number;
  certificateChainPem: string;
  privateKeyPem: string;
}) {
  return {
    id: input.id,
    runtimeTag: `forwardx-raw-tls-${input.id}`,
    listenAddress: "0.0.0.0",
    listenPort: input.port,
    protocol: input.profileId === "VMESS_RAW_TLS" ? "vmess" : "vless",
    transport: "tcp",
    security: "tls",
    profileId: input.profileId,
    specVersion: 1,
    specJson: "{}",
    realityServerName: "tls.example.com",
    tlsCertificateChainPem: input.certificateChainPem,
    tlsPrivateKeyPem: input.privateKeyPem,
    isEnabled: true,
    pendingDelete: false,
    clients: [{
      id: input.id * 10,
      credentialType: "UUID",
      uuid: `00000000-0000-4000-8000-${String(input.id).padStart(12, "0")}`,
      statsKey: `fwdx-raw-tls-client-${input.id}`,
      flow: input.flow,
      isEnabled: true,
      pendingDelete: false,
      sortOrder: 0,
    }],
  } satisfies XrayConfigInboundInput;
}

function shadowsocksInbound(input: {
  id?: number;
  port?: number;
  profileId?: "SHADOWSOCKS_2022_RAW_NONE" | "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE";
} = {}) {
  const id = input.id ?? 74;
  return {
    id,
    runtimeTag: `forwardx-shadowsocks-2022-${id}`,
    listenAddress: "0.0.0.0",
    listenPort: input.port ?? 28774,
    protocol: "shadowsocks",
    transport: "tcp",
    security: "none",
    profileId: input.profileId ?? "SHADOWSOCKS_2022_RAW_NONE",
    specVersion: 1,
    specJson: "{}",
    shadowsocksServerKey: Buffer.alloc(32, id === 74 ? 0xfb : 0xfc).toString("base64"),
    isEnabled: true,
    pendingDelete: false,
    clients: [{
      id: id * 10,
      credentialType: "SHADOWSOCKS_KEY",
      shadowsocksKey: Buffer.alloc(32, id === 74 ? 0xff : 0xfd).toString("base64"),
      statsKey: `fwdx-shadowsocks-client-${id}`,
      isEnabled: true,
      pendingDelete: false,
      sortOrder: 0,
    }],
  } as unknown as XrayConfigInboundInput;
}

test("VLESS/VMess TLS and Shadowsocks 2022 compile strict RAW accounts", () => {
  const material = tlsMaterial();
  try {
    const inputs = [
      rawTlsInbound({ id: 71, profileId: "VLESS_RAW_TLS", flow: "", port: 28771, ...material }),
      rawTlsInbound({ id: 72, profileId: "VLESS_RAW_TLS_VISION", flow: "xtls-rprx-vision", port: 28772, ...material }),
      rawTlsInbound({ id: 73, profileId: "VMESS_RAW_TLS", flow: "", port: 28773, ...material }),
      shadowsocksInbound(),
      shadowsocksInbound({ id: 75, port: 28775, profileId: "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE" }),
    ];
    const generated = generateDeterministicXrayConfig(inputs);
    const repeated = generateDeterministicXrayConfig([...inputs].reverse());
    assert.equal(repeated.configJson, generated.configJson);
    assert.equal(repeated.configHash, generated.configHash);

    const config = JSON.parse(generated.configJson);
    const standard = config.inbounds.find((inbound: any) => inbound.tag === "forwardx-raw-tls-71");
    const vision = config.inbounds.find((inbound: any) => inbound.tag === "forwardx-raw-tls-72");
    const vmess = config.inbounds.find((inbound: any) => inbound.tag === "forwardx-raw-tls-73");
    const shadowsocks = config.inbounds.find((inbound: any) => inbound.tag === "forwardx-shadowsocks-2022-74");
    const shadowsocksTcpUdp = config.inbounds.find((inbound: any) => inbound.tag === "forwardx-shadowsocks-2022-75");
    assert.deepEqual(standard.settings, {
      clients: [{ id: "00000000-0000-4000-8000-000000000071", email: "fwdx-raw-tls-client-71" }],
      decryption: "none",
    });
    assert.deepEqual(vision.settings, {
      clients: [{ id: "00000000-0000-4000-8000-000000000072", email: "fwdx-raw-tls-client-72", flow: "xtls-rprx-vision" }],
      decryption: "none",
    });
    assert.equal(vmess.protocol, "vmess");
    assert.deepEqual(vmess.settings, {
      clients: [{ id: "00000000-0000-4000-8000-000000000073", email: "fwdx-raw-tls-client-73", security: "auto" }],
    });
    assert.equal(shadowsocks.protocol, "shadowsocks");
    assert.deepEqual(shadowsocks.settings, {
      method: "2022-blake3-aes-256-gcm",
      password: Buffer.alloc(32, 0xfb).toString("base64"),
      network: "tcp",
      clients: [{ password: Buffer.alloc(32, 0xff).toString("base64"), email: "fwdx-shadowsocks-client-74" }],
    });
    assert.deepEqual(shadowsocks.streamSettings, { network: "tcp" });
    assert.deepEqual(shadowsocksTcpUdp.settings, {
      method: "2022-blake3-aes-256-gcm",
      password: Buffer.alloc(32, 0xfc).toString("base64"),
      network: "tcp,udp",
      clients: [{ password: Buffer.alloc(32, 0xfd).toString("base64"), email: "fwdx-shadowsocks-client-75" }],
    });
    assert.deepEqual(shadowsocksTcpUdp.streamSettings, { network: "tcp" });
    for (const inbound of [standard, vision, vmess]) {
      assert.equal(inbound.streamSettings.network, "tcp");
      assert.equal(inbound.streamSettings.security, "tls");
      assert.equal(inbound.streamSettings.tlsSettings.certificates.length, 1);
      assert.equal(inbound.streamSettings.tlsSettings.certificates[0].certificate[0], "-----BEGIN CERTIFICATE-----");
      assert.equal(inbound.streamSettings.tlsSettings.certificates[0].key[0], "-----BEGIN PRIVATE KEY-----");
      assert.equal("realitySettings" in inbound.streamSettings, false);
    }
    assert.deepEqual(generated.expectedListeners.map(({ network, port }) => ({ network, port })), [
      { network: "tcp", port: 28771 },
      { network: "tcp", port: 28772 },
      { network: "tcp", port: 28773 },
      { network: "tcp", port: 28774 },
      { network: "tcp", port: 28775 },
      { network: "udp", port: 28775 },
    ]);
    for (const forbidden of ["certificateFile", "keyFile", "realitySettings", "shortId"]) {
      assert.equal(generated.configJson.includes(forbidden), false);
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

test("Shadowsocks 2022 rejects missing accounts, malformed PSKs, and cross-security fields", () => {
  const valid = shadowsocksInbound() as any;
  assert.throws(() => generateDeterministicXrayConfig([{ ...valid, clients: [] }]));
  assert.throws(() => generateDeterministicXrayConfig([{
    ...valid,
    shadowsocksServerKey: valid.shadowsocksServerKey.slice(0, -1),
  }]));
  assert.throws(() => generateDeterministicXrayConfig([{
    ...valid,
    clients: [{ ...valid.clients[0], shadowsocksKey: valid.shadowsocksServerKey }],
  }]));
  assert.throws(() => generateDeterministicXrayConfig([{
    ...valid,
    realityServerName: "tls.example.com",
    tlsCertificateChainPem: "certificate",
    tlsPrivateKeyPem: "private-key",
  }]));
});

test("VLESS RAW TLS rejects cross-profile fields and invalid TLS material", () => {
  const material = tlsMaterial();
  try {
    const standard = rawTlsInbound({ id: 73, profileId: "VLESS_RAW_TLS", flow: "", port: 28773, ...material });
    assert.throws(() => generateDeterministicXrayConfig([{
      ...standard,
      clients: [{ ...standard.clients[0], flow: "xtls-rprx-vision" }],
    } as unknown as XrayConfigInboundInput]));
    assert.throws(() => generateDeterministicXrayConfig([{
      ...standard,
      clients: [{ ...standard.clients[0], shortId: "0102" }],
    } as unknown as XrayConfigInboundInput]));
    assert.throws(() => generateDeterministicXrayConfig([{
      ...standard,
      realityServerName: "other.example.com",
    }]));
    assert.throws(() => generateDeterministicXrayConfig([{
      ...standard,
      realityTargetHost: "",
      realityTargetPort: 443,
      realityPrivateKey: "",
    } as unknown as XrayConfigInboundInput]));
    assert.throws(() => generateDeterministicXrayConfig([{
      ...standard,
      tlsPrivateKeyPem: "not-a-private-key",
    }]), (error: any) => error?.code === "INVALID_CONFIG_INPUT");
  } finally {
    fs.rmSync(material.directory, { recursive: true, force: true });
  }
});
