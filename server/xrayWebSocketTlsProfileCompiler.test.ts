import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { buildXrayTrojanTlsUri, buildXrayVlessTlsUri } from "../shared/xrayShare";
import { generateDeterministicXrayConfig, type XrayConfigInboundInput } from "./xrayConfigGenerator";

function tlsMaterial() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-ws-tls-"));
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

function webSocketTlsInbound(input: {
  id: number;
  protocol: "vless" | "trojan";
  profileId: "VLESS_WEBSOCKET_TLS" | "TROJAN_WEBSOCKET_TLS";
  certificateChainPem: string;
  privateKeyPem: string;
  specJson?: string;
}): XrayConfigInboundInput {
  const credential = input.protocol === "vless"
    ? {
      credentialType: "UUID" as const,
      uuid: `00000000-0000-4000-8000-${String(input.id).padStart(12, "0")}`,
      flow: "",
    }
    : {
      credentialType: "PASSWORD" as const,
      password: input.id % 2 === 0 ? "A".repeat(43) : "B".repeat(43),
    };
  return {
    id: input.id,
    runtimeTag: `forwardx-ws-tls-${input.id}`,
    listenAddress: "0.0.0.0",
    listenPort: 28900 + input.id,
    protocol: input.protocol,
    transport: "ws",
    security: "tls",
    profileId: input.profileId,
    specVersion: 1,
    specJson: input.specJson ?? JSON.stringify({ path: `/forwardx/ws-${input.id}` }),
    realityServerName: "tls.example.com",
    tlsCertificateChainPem: input.certificateChainPem,
    tlsPrivateKeyPem: input.privateKeyPem,
    isEnabled: true,
    pendingDelete: false,
    clients: [{
      id: input.id * 10,
      ...credential,
      statsKey: `forwardx-ws-tls-client-${input.id}`,
      isEnabled: true,
      pendingDelete: false,
      sortOrder: 0,
    }],
  };
}

test("VLESS and Trojan WebSocket TLS compile strict paths and pinned share URIs", () => {
  const material = tlsMaterial();
  try {
    const generated = generateDeterministicXrayConfig([
      webSocketTlsInbound({ id: 91, protocol: "vless", profileId: "VLESS_WEBSOCKET_TLS", ...material }),
      webSocketTlsInbound({ id: 92, protocol: "trojan", profileId: "TROJAN_WEBSOCKET_TLS", ...material }),
    ]);
    const config = JSON.parse(generated.configJson);
    const vless = config.inbounds.find((inbound: any) => inbound.tag === "forwardx-ws-tls-91");
    const trojan = config.inbounds.find((inbound: any) => inbound.tag === "forwardx-ws-tls-92");
    assert.deepEqual(vless.settings, {
      clients: [{ id: "00000000-0000-4000-8000-000000000091", email: "forwardx-ws-tls-client-91" }],
      decryption: "none",
    });
    assert.deepEqual(trojan.settings, {
      clients: [{ password: "A".repeat(43), email: "forwardx-ws-tls-client-92" }],
    });
    for (const [inbound, expectedPath] of [[vless, "/forwardx/ws-91"], [trojan, "/forwardx/ws-92"]]) {
      assert.equal(inbound.streamSettings.network, "ws");
      assert.equal(inbound.streamSettings.security, "tls");
      assert.deepEqual(inbound.streamSettings.wsSettings, { path: expectedPath });
      assert.equal(inbound.streamSettings.tlsSettings.certificates.length, 1);
    }
    for (const forbidden of ["flow", "shortId", "realitySettings", "certificateFile", "keyFile"]) {
      assert.equal(generated.configJson.includes(forbidden), false, forbidden);
    }

    const shareBase = {
      publicAddress: "edge.example.com",
      listenPort: 28991,
      serverName: "tls.example.com",
      fingerprint: "chrome" as const,
      leafFingerprintSha256: "b".repeat(64),
      path: "/forwardx/ws-share",
      displayName: "WebSocket TLS / phone",
    };
    const vlessUri = buildXrayVlessTlsUri({
      ...shareBase,
      profileId: "VLESS_WEBSOCKET_TLS",
      uuid: "00000000-0000-4000-8000-000000000091",
    });
    const trojanUri = buildXrayTrojanTlsUri({
      ...shareBase,
      profileId: "TROJAN_WEBSOCKET_TLS",
      password: "A".repeat(43),
    });
    assert.deepEqual([...new URL(vlessUri).searchParams.entries()], [
      ["type", "ws"], ["security", "tls"], ["sni", "tls.example.com"], ["fp", "chrome"],
      ["pcs", "b".repeat(64)], ["encryption", "none"], ["path", "/forwardx/ws-share"],
    ]);
    assert.deepEqual([...new URL(trojanUri).searchParams.entries()], [
      ["type", "ws"], ["security", "tls"], ["sni", "tls.example.com"], ["fp", "chrome"],
      ["pcs", "b".repeat(64)], ["path", "/forwardx/ws-share"],
    ]);
    for (const uri of [vlessUri, trojanUri]) {
      for (const forbidden of ["allowInsecure", "flow=", "sid=", "pbk=", "host=", "ed="]) {
        assert.equal(uri.includes(forbidden), false, forbidden);
      }
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

test("WebSocket TLS rejects flow, RAW profiles, and non-strict path specs", () => {
  const material = tlsMaterial();
  try {
    const valid = webSocketTlsInbound({ id: 93, protocol: "vless", profileId: "VLESS_WEBSOCKET_TLS", ...material });
    assert.throws(() => generateDeterministicXrayConfig([{
      ...valid,
      clients: [{ ...valid.clients[0], flow: "xtls-rprx-vision" }],
    } as unknown as XrayConfigInboundInput]));
    for (const specJson of [
      JSON.stringify({ path: "" }),
      JSON.stringify({ path: "forwardx/ws" }),
      JSON.stringify({ path: "/forwardx?ed=2048" }),
      JSON.stringify({ path: "/forwardx/ws", host: "hidden.example.com" }),
      JSON.stringify({ path: "/forwardx/ws", headers: {} }),
    ]) {
      assert.throws(() => generateDeterministicXrayConfig([{ ...valid, specJson }]));
    }
    assert.throws(() => buildXrayVlessTlsUri({
      profileId: "VLESS_WEBSOCKET_TLS",
      uuid: "00000000-0000-4000-8000-000000000093",
      publicAddress: "edge.example.com",
      listenPort: 28993,
      serverName: "tls.example.com",
      fingerprint: "chrome",
      leafFingerprintSha256: "b".repeat(64),
      path: "not/absolute",
      displayName: "invalid",
    }));
    assert.throws(() => buildXrayTrojanTlsUri({
      profileId: "TROJAN_RAW_TLS",
      password: "A".repeat(43),
      publicAddress: "edge.example.com",
      listenPort: 28993,
      serverName: "tls.example.com",
      fingerprint: "chrome",
      leafFingerprintSha256: "b".repeat(64),
      path: "/must-not-survive",
      displayName: "invalid",
    } as never));
  } finally {
    fs.rmSync(material.directory, { recursive: true, force: true });
  }
});
