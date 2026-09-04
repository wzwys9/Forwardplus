import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { buildXrayTrojanTlsUri, buildXrayVlessTlsUri } from "../shared/xrayShare";
import { generateDeterministicXrayConfig, type XrayConfigInboundInput } from "./xrayConfigGenerator";

const HYSTERIA_AUTH = Buffer.alloc(32, 0x46).toString("base64url");

function tlsMaterial() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-grpc-tls-"));
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

function grpcTlsInbound(input: {
  id: number;
  protocol: "vless" | "trojan";
  profileId: "VLESS_GRPC_TLS" | "TROJAN_GRPC_TLS";
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
    runtimeTag: `forwardx-grpc-tls-${input.id}`,
    listenAddress: "0.0.0.0",
    listenPort: 28900 + input.id,
    protocol: input.protocol,
    transport: "grpc",
    security: "tls",
    profileId: input.profileId,
    specVersion: 1,
    specJson: input.specJson ?? JSON.stringify({ serviceName: `forwardx-grpc-${input.id}` }),
    realityServerName: "tls.example.com",
    tlsCertificateChainPem: input.certificateChainPem,
    tlsPrivateKeyPem: input.privateKeyPem,
    isEnabled: true,
    pendingDelete: false,
    clients: [{
      id: input.id * 10,
      ...credential,
      statsKey: `forwardx-grpc-tls-client-${input.id}`,
      isEnabled: true,
      pendingDelete: false,
      sortOrder: 0,
    }],
  };
}

function httpUpgradeTlsInbound(input: {
  id: number;
  protocol: "vless" | "trojan";
  profileId: "VLESS_HTTP_UPGRADE_TLS" | "TROJAN_HTTP_UPGRADE_TLS";
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
      password: "C".repeat(43),
    };
  return {
    id: input.id,
    runtimeTag: `forwardx-httpupgrade-tls-${input.id}`,
    listenAddress: "0.0.0.0",
    listenPort: 28900 + input.id,
    protocol: input.protocol,
    transport: "httpupgrade",
    security: "tls",
    profileId: input.profileId,
    specVersion: 1,
    specJson: input.specJson ?? JSON.stringify({ path: `/forwardx/httpupgrade-${input.id}` }),
    realityServerName: "tls.example.com",
    tlsCertificateChainPem: input.certificateChainPem,
    tlsPrivateKeyPem: input.privateKeyPem,
    isEnabled: true,
    pendingDelete: false,
    clients: [{
      id: input.id * 10,
      ...credential,
      statsKey: `forwardx-httpupgrade-tls-client-${input.id}`,
      isEnabled: true,
      pendingDelete: false,
      sortOrder: 0,
    }],
  };
}

function xhttpTlsInbound(input: {
  id: number;
  protocol: "vless" | "trojan";
  profileId: "VLESS_XHTTP_TLS" | "TROJAN_XHTTP_TLS";
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
      password: "D".repeat(43),
    };
  return {
    id: input.id,
    runtimeTag: `forwardx-xhttp-tls-${input.id}`,
    listenAddress: "0.0.0.0",
    listenPort: 28900 + input.id,
    protocol: input.protocol,
    transport: "xhttp",
    security: "tls",
    profileId: input.profileId,
    specVersion: 1,
    specJson: input.specJson ?? JSON.stringify({ path: `/forwardx/xhttp-${input.id}` }),
    realityServerName: "tls.example.com",
    tlsCertificateChainPem: input.certificateChainPem,
    tlsPrivateKeyPem: input.privateKeyPem,
    isEnabled: true,
    pendingDelete: false,
    clients: [{
      id: input.id * 10,
      ...credential,
      statsKey: `forwardx-xhttp-tls-client-${input.id}`,
      isEnabled: true,
      pendingDelete: false,
      sortOrder: 0,
    }],
  };
}

function mkcpTlsInbound(input: {
  id: number;
  protocol: "vless" | "trojan";
  profileId: "VLESS_MKCP_TLS" | "TROJAN_MKCP_TLS";
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
      password: "E".repeat(43),
    };
  return {
    id: input.id,
    runtimeTag: `forwardx-mkcp-tls-${input.id}`,
    listenAddress: "0.0.0.0",
    listenPort: 28900 + input.id,
    protocol: input.protocol,
    transport: "kcp",
    security: "tls",
    profileId: input.profileId,
    specVersion: 1,
    specJson: input.specJson ?? "{}",
    realityServerName: "tls.example.com",
    tlsCertificateChainPem: input.certificateChainPem,
    tlsPrivateKeyPem: input.privateKeyPem,
    isEnabled: true,
    pendingDelete: false,
    clients: [{
      id: input.id * 10,
      ...credential,
      statsKey: `forwardx-mkcp-tls-client-${input.id}`,
      isEnabled: true,
      pendingDelete: false,
      sortOrder: 0,
    }],
  };
}

function hysteria2TlsInbound(input: {
  certificateChainPem: string;
  privateKeyPem: string;
  specJson?: string;
  auth?: string;
}): XrayConfigInboundInput {
  return {
    id: 101,
    runtimeTag: "forwardx-hysteria2-tls-101",
    listenAddress: "0.0.0.0",
    listenPort: 29001,
    protocol: "hysteria",
    transport: "hysteria",
    security: "tls",
    profileId: "HYSTERIA2_TLS",
    specVersion: 1,
    specJson: input.specJson ?? "{}",
    realityServerName: "tls.example.com",
    tlsCertificateChainPem: input.certificateChainPem,
    tlsPrivateKeyPem: input.privateKeyPem,
    isEnabled: true,
    pendingDelete: false,
    clients: [{
      id: 1010,
      credentialType: "HYSTERIA_AUTH",
      auth: input.auth ?? HYSTERIA_AUTH,
      statsKey: "forwardx-hysteria2-client-101",
      isEnabled: true,
      pendingDelete: false,
      sortOrder: 0,
    }],
  };
}

test("VLESS and Trojan gRPC/HTTPUpgrade/XHTTP/mKCP TLS compile strict settings and pinned share URIs", () => {
  const material = tlsMaterial();
  try {
    const vlessInput = grpcTlsInbound({ id: 93, protocol: "vless", profileId: "VLESS_GRPC_TLS", ...material });
    const trojanInput = grpcTlsInbound({ id: 94, protocol: "trojan", profileId: "TROJAN_GRPC_TLS", ...material });
    const vlessHttpUpgradeInput = httpUpgradeTlsInbound({
      id: 95, protocol: "vless", profileId: "VLESS_HTTP_UPGRADE_TLS", ...material,
    });
    const trojanHttpUpgradeInput = httpUpgradeTlsInbound({
      id: 96, protocol: "trojan", profileId: "TROJAN_HTTP_UPGRADE_TLS", ...material,
    });
    const vlessXhttpInput = xhttpTlsInbound({
      id: 97, protocol: "vless", profileId: "VLESS_XHTTP_TLS", ...material,
    });
    const trojanXhttpInput = xhttpTlsInbound({
      id: 98, protocol: "trojan", profileId: "TROJAN_XHTTP_TLS", ...material,
    });
    const vlessMkcpInput = mkcpTlsInbound({ id: 99, protocol: "vless", profileId: "VLESS_MKCP_TLS", ...material });
    const trojanMkcpInput = mkcpTlsInbound({ id: 100, protocol: "trojan", profileId: "TROJAN_MKCP_TLS", ...material });
    const generated = generateDeterministicXrayConfig([
      vlessInput, trojanInput, vlessHttpUpgradeInput, trojanHttpUpgradeInput, vlessXhttpInput, trojanXhttpInput,
      vlessMkcpInput, trojanMkcpInput,
    ]);
    const config = JSON.parse(generated.configJson);
    const vless = config.inbounds.find((inbound: any) => inbound.tag === "forwardx-grpc-tls-93");
    const trojan = config.inbounds.find((inbound: any) => inbound.tag === "forwardx-grpc-tls-94");
    assert.deepEqual(vless.settings, {
      clients: [{ id: "00000000-0000-4000-8000-000000000093", email: "forwardx-grpc-tls-client-93" }],
      decryption: "none",
    });
    assert.deepEqual(trojan.settings, {
      clients: [{ password: "A".repeat(43), email: "forwardx-grpc-tls-client-94" }],
    });
    for (const [inbound, serviceName] of [[vless, "forwardx-grpc-93"], [trojan, "forwardx-grpc-94"]]) {
      assert.equal(inbound.streamSettings.network, "grpc");
      assert.equal(inbound.streamSettings.security, "tls");
      assert.deepEqual(inbound.streamSettings.grpcSettings, { serviceName, multiMode: false });
      assert.deepEqual(inbound.streamSettings.tlsSettings.alpn, ["h2"]);
      assert.equal(inbound.streamSettings.tlsSettings.certificates.length, 1);
    }
    const vlessHttpUpgrade = config.inbounds.find((inbound: any) => inbound.tag === "forwardx-httpupgrade-tls-95");
    const trojanHttpUpgrade = config.inbounds.find((inbound: any) => inbound.tag === "forwardx-httpupgrade-tls-96");
    assert.deepEqual(vlessHttpUpgrade.settings, {
      clients: [{ id: "00000000-0000-4000-8000-000000000095", email: "forwardx-httpupgrade-tls-client-95" }],
      decryption: "none",
    });
    assert.deepEqual(trojanHttpUpgrade.settings, {
      clients: [{ password: "C".repeat(43), email: "forwardx-httpupgrade-tls-client-96" }],
    });
    for (const [inbound, path] of [
      [vlessHttpUpgrade, "/forwardx/httpupgrade-95"],
      [trojanHttpUpgrade, "/forwardx/httpupgrade-96"],
    ]) {
      assert.equal(inbound.streamSettings.network, "httpupgrade");
      assert.equal(inbound.streamSettings.security, "tls");
      assert.deepEqual(inbound.streamSettings.httpupgradeSettings, { path });
      assert.equal(inbound.streamSettings.tlsSettings.certificates.length, 1);
    }
    const vlessXhttp = config.inbounds.find((inbound: any) => inbound.tag === "forwardx-xhttp-tls-97");
    const trojanXhttp = config.inbounds.find((inbound: any) => inbound.tag === "forwardx-xhttp-tls-98");
    assert.deepEqual(vlessXhttp.settings, {
      clients: [{ id: "00000000-0000-4000-8000-000000000097", email: "forwardx-xhttp-tls-client-97" }],
      decryption: "none",
    });
    assert.deepEqual(trojanXhttp.settings, {
      clients: [{ password: "D".repeat(43), email: "forwardx-xhttp-tls-client-98" }],
    });
    for (const [inbound, path] of [
      [vlessXhttp, "/forwardx/xhttp-97"],
      [trojanXhttp, "/forwardx/xhttp-98"],
    ]) {
      assert.equal(inbound.streamSettings.network, "xhttp");
      assert.equal(inbound.streamSettings.security, "tls");
      assert.deepEqual(inbound.streamSettings.xhttpSettings, { path, mode: "auto" });
      assert.equal(inbound.streamSettings.tlsSettings.certificates.length, 1);
    }
    for (const forbidden of ["flow", "shortId", "realitySettings", "certificateFile", "keyFile", "authority"]) {
      assert.equal(generated.configJson.includes(forbidden), false, forbidden);
    }

    const shareBase = {
      publicAddress: "edge.example.com",
      listenPort: 28993,
      serverName: "tls.example.com",
      fingerprint: "chrome" as const,
      leafFingerprintSha256: "b".repeat(64),
      serviceName: "forwardx.grpc",
      displayName: "gRPC TLS / phone",
    };
    const vlessUri = buildXrayVlessTlsUri({
      ...shareBase,
      profileId: "VLESS_GRPC_TLS",
      uuid: "00000000-0000-4000-8000-000000000093",
    });
    const trojanUri = buildXrayTrojanTlsUri({
      ...shareBase,
      profileId: "TROJAN_GRPC_TLS",
      password: "A".repeat(43),
    });
    assert.deepEqual([...new URL(vlessUri).searchParams.entries()], [
      ["type", "grpc"], ["security", "tls"], ["sni", "tls.example.com"], ["fp", "chrome"],
      ["pcs", "b".repeat(64)], ["encryption", "none"], ["serviceName", "forwardx.grpc"], ["alpn", "h2"],
    ]);
    assert.deepEqual([...new URL(trojanUri).searchParams.entries()], [
      ["type", "grpc"], ["security", "tls"], ["sni", "tls.example.com"], ["fp", "chrome"],
      ["pcs", "b".repeat(64)], ["serviceName", "forwardx.grpc"], ["alpn", "h2"],
    ]);
    for (const uri of [vlessUri, trojanUri]) {
      for (const forbidden of ["allowInsecure", "flow=", "sid=", "pbk=", "authority=", "multiMode="]) {
        assert.equal(uri.includes(forbidden), false, forbidden);
      }
    }

    const httpUpgradeShareBase = {
      publicAddress: "edge.example.com",
      listenPort: 28995,
      serverName: "tls.example.com",
      fingerprint: "chrome" as const,
      leafFingerprintSha256: "b".repeat(64),
      path: "/forwardx/httpupgrade",
      displayName: "HTTPUpgrade TLS / phone",
    };
    const vlessHttpUpgradeUri = buildXrayVlessTlsUri({
      ...httpUpgradeShareBase,
      profileId: "VLESS_HTTP_UPGRADE_TLS",
      uuid: "00000000-0000-4000-8000-000000000095",
    });
    const trojanHttpUpgradeUri = buildXrayTrojanTlsUri({
      ...httpUpgradeShareBase,
      profileId: "TROJAN_HTTP_UPGRADE_TLS",
      password: "A".repeat(43),
    });
    assert.deepEqual([...new URL(vlessHttpUpgradeUri).searchParams.entries()], [
      ["type", "httpupgrade"], ["security", "tls"], ["sni", "tls.example.com"], ["fp", "chrome"],
      ["pcs", "b".repeat(64)], ["encryption", "none"], ["path", "/forwardx/httpupgrade"],
    ]);
    assert.deepEqual([...new URL(trojanHttpUpgradeUri).searchParams.entries()], [
      ["type", "httpupgrade"], ["security", "tls"], ["sni", "tls.example.com"], ["fp", "chrome"],
      ["pcs", "b".repeat(64)], ["path", "/forwardx/httpupgrade"],
    ]);
    for (const uri of [vlessHttpUpgradeUri, trojanHttpUpgradeUri]) {
      for (const forbidden of ["allowInsecure", "flow=", "sid=", "pbk=", "host=", "headers=", "earlyData="]) {
        assert.equal(uri.includes(forbidden), false, forbidden);
      }
    }

    const xhttpShareBase = {
      publicAddress: "edge.example.com",
      listenPort: 28997,
      serverName: "tls.example.com",
      fingerprint: "chrome" as const,
      leafFingerprintSha256: "b".repeat(64),
      path: "/forwardx/xhttp",
      displayName: "XHTTP TLS / phone",
    };
    const vlessXhttpUri = buildXrayVlessTlsUri({
      ...xhttpShareBase,
      profileId: "VLESS_XHTTP_TLS",
      uuid: "00000000-0000-4000-8000-000000000097",
    });
    const trojanXhttpUri = buildXrayTrojanTlsUri({
      ...xhttpShareBase,
      profileId: "TROJAN_XHTTP_TLS",
      password: "D".repeat(43),
    });
    assert.deepEqual([...new URL(vlessXhttpUri).searchParams.entries()], [
      ["type", "xhttp"], ["security", "tls"], ["sni", "tls.example.com"], ["fp", "chrome"],
      ["pcs", "b".repeat(64)], ["encryption", "none"], ["path", "/forwardx/xhttp"], ["mode", "auto"],
    ]);
    assert.deepEqual([...new URL(trojanXhttpUri).searchParams.entries()], [
      ["type", "xhttp"], ["security", "tls"], ["sni", "tls.example.com"], ["fp", "chrome"],
      ["pcs", "b".repeat(64)], ["path", "/forwardx/xhttp"], ["mode", "auto"],
    ]);
    for (const uri of [vlessXhttpUri, trojanXhttpUri]) {
      for (const forbidden of ["allowInsecure", "flow=", "sid=", "pbk=", "host=", "headers=", "padding=", "xmux="]) {
        assert.equal(uri.includes(forbidden), false, forbidden);
      }
    }

    const vlessMkcp = config.inbounds.find((inbound: any) => inbound.tag === "forwardx-mkcp-tls-99");
    const trojanMkcp = config.inbounds.find((inbound: any) => inbound.tag === "forwardx-mkcp-tls-100");
    assert.deepEqual(generated.expectedListeners.filter((listener) => listener.inboundId >= 99), [{
      inboundId: 100,
      runtimeTag: "forwardx-mkcp-tls-100",
      network: "udp",
      listenAddress: "0.0.0.0",
      port: 29000,
    }, {
      inboundId: 99,
      runtimeTag: "forwardx-mkcp-tls-99",
      network: "udp",
      listenAddress: "0.0.0.0",
      port: 28999,
    }]);
    assert.deepEqual(vlessMkcp.settings, {
      clients: [{ id: "00000000-0000-4000-8000-000000000099", email: "forwardx-mkcp-tls-client-99" }],
      decryption: "none",
    });
    assert.deepEqual(trojanMkcp.settings, {
      clients: [{ password: "E".repeat(43), email: "forwardx-mkcp-tls-client-100" }],
    });
    for (const inbound of [vlessMkcp, trojanMkcp]) {
      assert.equal(inbound.streamSettings.network, "kcp");
      assert.equal(inbound.streamSettings.security, "tls");
      assert.deepEqual(inbound.streamSettings.kcpSettings, {});
      assert.equal(inbound.streamSettings.tlsSettings.certificates.length, 1);
      for (const forbidden of ["mtu", "tti", "uplinkCapacity", "downlinkCapacity", "seed", "header", "finalmask"]) {
        assert.equal(forbidden in inbound.streamSettings, false, forbidden);
        assert.equal(forbidden in inbound.streamSettings.kcpSettings, false, forbidden);
      }
    }
    const mkcpShareBase = {
      publicAddress: "edge.example.com",
      listenPort: 28999,
      serverName: "tls.example.com",
      fingerprint: "chrome" as const,
      leafFingerprintSha256: "b".repeat(64),
      displayName: "mKCP TLS / phone",
    };
    const vlessMkcpUri = buildXrayVlessTlsUri({
      ...mkcpShareBase,
      profileId: "VLESS_MKCP_TLS",
      uuid: "00000000-0000-4000-8000-000000000099",
    });
    const trojanMkcpUri = buildXrayTrojanTlsUri({
      ...mkcpShareBase,
      profileId: "TROJAN_MKCP_TLS",
      password: "E".repeat(43),
    });
    assert.deepEqual([...new URL(vlessMkcpUri).searchParams.entries()], [
      ["type", "kcp"], ["security", "tls"], ["sni", "tls.example.com"], ["fp", "chrome"],
      ["pcs", "b".repeat(64)], ["encryption", "none"],
    ]);
    assert.deepEqual([...new URL(trojanMkcpUri).searchParams.entries()], [
      ["type", "kcp"], ["security", "tls"], ["sni", "tls.example.com"], ["fp", "chrome"],
      ["pcs", "b".repeat(64)],
    ]);
    for (const uri of [vlessMkcpUri, trojanMkcpUri]) {
      for (const forbidden of ["allowInsecure", "flow=", "sid=", "pbk=", "seed=", "headerType=", "mtu=", "tti=", "fm="]) {
        assert.equal(uri.includes(forbidden), false, forbidden);
      }
    }

    assert.throws(() => generateDeterministicXrayConfig([{ ...vlessInput, specJson: '{"serviceName":"bad/name"}' }]));
    assert.throws(() => generateDeterministicXrayConfig([{ ...trojanInput, specJson: '{"serviceName":"grpc","authority":"hidden.example"}' }]));
    assert.throws(() => generateDeterministicXrayConfig([{
      ...vlessInput,
      clients: [{ ...vlessInput.clients[0], flow: "xtls-rprx-vision" }],
    } as unknown as XrayConfigInboundInput]));
    assert.throws(() => buildXrayTrojanTlsUri({
      ...shareBase,
      profileId: "TROJAN_GRPC_TLS",
      password: "A".repeat(43),
      serviceName: "bad/name",
    } as never));
    assert.throws(() => generateDeterministicXrayConfig([{
      ...vlessHttpUpgradeInput,
      specJson: '{"path":"/httpupgrade","host":"hidden.example"}',
    }]));
    assert.throws(() => buildXrayVlessTlsUri({
      ...httpUpgradeShareBase,
      profileId: "VLESS_HTTP_UPGRADE_TLS",
      uuid: "00000000-0000-4000-8000-000000000095",
      path: "relative",
    } as never));
    assert.throws(() => generateDeterministicXrayConfig([{
      ...vlessXhttpInput,
      specJson: '{"path":"/xhttp","mode":"stream-up"}',
    }]));
    assert.throws(() => buildXrayTrojanTlsUri({
      ...xhttpShareBase,
      profileId: "TROJAN_XHTTP_TLS",
      password: "D".repeat(43),
      path: "/bad?query",
    } as never));
    assert.throws(() => generateDeterministicXrayConfig([{ ...vlessMkcpInput, specJson: '{"mtu":1350}' }]));
    assert.throws(() => buildXrayVlessTlsUri({
      ...mkcpShareBase,
      profileId: "VLESS_MKCP_TLS",
      uuid: "00000000-0000-4000-8000-000000000099",
      path: "/hidden",
    } as never));

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

test("Hysteria 2 TLS compiles one strict UDP listener and fixed version 2 settings", () => {
  const material = tlsMaterial();
  try {
    const input = hysteria2TlsInbound(material);
    const generated = generateDeterministicXrayConfig([input]);
    const config = JSON.parse(generated.configJson);
    assert.deepEqual(generated.expectedListeners, [{
      inboundId: 101,
      runtimeTag: "forwardx-hysteria2-tls-101",
      network: "udp",
      listenAddress: "0.0.0.0",
      port: 29001,
    }]);
    assert.deepEqual(config.inbounds[0].settings, {
      version: 2,
      clients: [{ auth: HYSTERIA_AUTH, email: "forwardx-hysteria2-client-101" }],
    });
    assert.deepEqual(config.inbounds[0].streamSettings, {
      network: "hysteria",
      security: "tls",
      tlsSettings: {
        certificates: [{
          certificate: material.certificateChainPem.trimEnd().split("\n"),
          key: material.privateKeyPem.trimEnd().split("\n"),
        }],
        alpn: ["h3"],
      },
      hysteriaSettings: { version: 2, udpIdleTimeout: 60 },
    });
    for (const forbidden of ["bandwidth", "congestion", "masquerade", "obfs", "ports", "finalmask", "allowInsecure"]) {
      assert.equal(generated.configJson.includes(forbidden), false, forbidden);
    }

    assert.throws(() => generateDeterministicXrayConfig([hysteria2TlsInbound({
      ...material,
      specJson: '{"udpIdleTimeout":30}',
    })]));
    assert.throws(() => generateDeterministicXrayConfig([hysteria2TlsInbound({
      ...material,
      auth: "not-canonical",
    })]));
    assert.throws(() => generateDeterministicXrayConfig([{ ...input, clients: [] }]));
    assert.throws(() => generateDeterministicXrayConfig([{
      ...input,
      security: "none",
      shadowsocksServerKey: "A".repeat(43) + "=",
      realityServerName: undefined,
      tlsCertificateChainPem: undefined,
      tlsPrivateKeyPem: undefined,
    } as unknown as XrayConfigInboundInput]));

    const binary = process.env.XRAY_TEST_BINARY;
    if (binary) {
      const configPath = path.join(material.directory, "hysteria2-config.json");
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
