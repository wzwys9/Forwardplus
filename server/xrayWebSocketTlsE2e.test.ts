import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFile, execFileSync, spawn, spawnSync, type ChildProcess } from "node:child_process";
import dgram from "node:dgram";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import {
  buildXrayHttpProxyUri,
  buildXrayMixedProxyEndpoints,
  buildXrayHysteria2Uri,
  buildXrayShadowsocks2022Uri,
  buildXrayTrojanTlsUri,
  buildXrayVlessTlsUri,
  buildXrayVmessTlsUri,
} from "../shared/xrayShare";
import { generateDeterministicXrayConfig, type XrayConfigInboundInput } from "./xrayConfigGenerator";
import {
  buildXrayWireGuardClientConfig,
  deriveXrayWireGuardPublicKey,
  generateXrayWireGuardKeyPair,
  generateXrayWireGuardPreSharedKey,
} from "./xrayWireGuard";

const execFileAsync = promisify(execFile);
const fixedXraySha256 = "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed";
const serverName = "tls.example.com";

type Profile =
  | { profileId: "VLESS_MKCP_TLS"; protocol: "vless" }
  | { profileId: "TROJAN_MKCP_TLS"; protocol: "trojan" }
  | { profileId: "VLESS_WEBSOCKET_TLS"; protocol: "vless"; path: string }
  | { profileId: "TROJAN_WEBSOCKET_TLS"; protocol: "trojan"; path: string }
  | { profileId: "VLESS_GRPC_TLS"; protocol: "vless"; serviceName: string }
  | { profileId: "TROJAN_GRPC_TLS"; protocol: "trojan"; serviceName: string }
  | { profileId: "VLESS_HTTP_UPGRADE_TLS"; protocol: "vless"; path: string }
  | { profileId: "TROJAN_HTTP_UPGRADE_TLS"; protocol: "trojan"; path: string }
  | { profileId: "VLESS_XHTTP_TLS"; protocol: "vless"; path: string }
  | { profileId: "TROJAN_XHTTP_TLS"; protocol: "trojan"; path: string }
  | { profileId: "VMESS_RAW_TLS"; protocol: "vmess" };

type TlsMaterial = {
  certificateChainPem: string;
  privateKeyPem: string;
  leafFingerprintSha256: string;
};

function profileTransport(profile: Profile): "tcp" | "kcp" | "ws" | "grpc" | "httpupgrade" | "xhttp" {
  if (profile.profileId === "VMESS_RAW_TLS") return "tcp";
  if (profile.profileId.endsWith("MKCP_TLS")) return "kcp";
  if (profile.profileId.endsWith("WEBSOCKET_TLS")) return "ws";
  if (profile.profileId.endsWith("GRPC_TLS")) return "grpc";
  return profile.profileId.includes("HTTP_UPGRADE") ? "httpupgrade" : "xhttp";
}

async function freeUdpPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket("udp4");
    socket.once("error", reject);
    socket.bind(0, "127.0.0.1", () => {
      const address = socket.address();
      socket.close(() => resolve(address.port));
    });
  });
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") return reject(new Error("No test port"));
      server.close((error) => error ? reject(error) : resolve(address.port));
    });
  });
}

async function freeTcpUdpPort(): Promise<number> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const tcpPort = await freePort();
    const udpAvailable = await new Promise<boolean>((resolve) => {
      const socket = dgram.createSocket("udp4");
      socket.once("error", () => resolve(false));
      socket.bind(tcpPort, "127.0.0.1", () => socket.close(() => resolve(true)));
    });
    if (udpAvailable) return tcpPort;
  }
  throw new Error("No shared TCP/UDP test port");
}

function localNonLoopbackIpv4(): string {
  for (const addresses of Object.values(os.networkInterfaces())) {
    for (const address of addresses ?? []) {
      if (address.family === "IPv4" && !address.internal && net.isIPv4(address.address)) return address.address;
    }
  }
  throw new Error("No non-loopback IPv4 address for WireGuard end-to-end origin");
}

async function waitForPort(port: number, process: ChildProcess, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (process.exitCode !== null) throw new Error(`Xray exited before listening: ${process.exitCode}`);
    const connected = await new Promise<boolean>((resolve) => {
      const socket = net.connect({ host: "127.0.0.1", port });
      socket.once("connect", () => { socket.destroy(); resolve(true); });
      socket.once("error", () => resolve(false));
    });
    if (connected) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Timed out waiting for Xray port ${port}`);
}

async function waitForUdpPort(port: number, process: ChildProcess, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (process.exitCode !== null) throw new Error(`Xray exited before listening: ${process.exitCode}`);
    const listening = await new Promise<boolean>((resolve, reject) => {
      const socket = dgram.createSocket("udp4");
      socket.once("error", (error: NodeJS.ErrnoException) => {
        socket.close();
        if (error.code === "EADDRINUSE") resolve(true);
        else reject(error);
      });
      socket.bind(port, "127.0.0.1", () => socket.close(() => resolve(false)));
    });
    if (listening) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Timed out waiting for Xray UDP port ${port}`);
}

async function stopProcess(process: ChildProcess | null) {
  if (!process || process.exitCode !== null) return;
  process.kill("SIGTERM");
  await Promise.race([
    new Promise((resolve) => process.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, 2_000)),
  ]);
  if (process.exitCode === null) process.kill("SIGKILL");
}

function proxyAuthorization(username: string, password: string): string {
  return `Basic ${Buffer.from(`${username}:${password}`, "utf8").toString("base64")}`;
}

async function httpProxyRequest(input: {
  proxyPort: number;
  originPort: number;
  authorization?: string;
}): Promise<{ statusCode: number; body: string }> {
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: "127.0.0.1",
      port: input.proxyPort,
      method: "GET",
      path: `http://127.0.0.1:${input.originPort}/probe`,
      headers: {
        Host: `127.0.0.1:${input.originPort}`,
        ...(input.authorization ? { "Proxy-Authorization": input.authorization } : {}),
      },
    }, (response) => {
      const chunks: Buffer[] = [];
      response.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      response.once("end", () => resolve({
        statusCode: response.statusCode ?? 0,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    request.setTimeout(5_000, () => request.destroy(new Error("HTTP proxy request timed out")));
    request.once("error", reject);
    request.end();
  });
}

async function httpConnectRequest(input: {
  proxyPort: number;
  originPort: number;
  authorization: string;
}): Promise<{ statusCode: number; tunneledResponse: string }> {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: "127.0.0.1", port: input.proxyPort });
    let phase: "CONNECT" | "TUNNEL" = "CONNECT";
    let buffered = Buffer.alloc(0);
    let statusCode = 0;
    const timer = setTimeout(() => socket.destroy(new Error("HTTP CONNECT request timed out")), 5_000);
    socket.once("connect", () => socket.write(
      `CONNECT 127.0.0.1:${input.originPort} HTTP/1.1\r\n`
      + `Host: 127.0.0.1:${input.originPort}\r\n`
      + `Proxy-Authorization: ${input.authorization}\r\n\r\n`,
    ));
    socket.on("data", (chunk) => {
      buffered = Buffer.concat([buffered, Buffer.from(chunk)]);
      if (phase !== "CONNECT") return;
      const headerEnd = buffered.indexOf("\r\n\r\n");
      if (headerEnd < 0) return;
      const headers = buffered.subarray(0, headerEnd).toString("latin1");
      statusCode = Number(headers.match(/^HTTP\/1\.[01] (\d{3})/i)?.[1] ?? 0);
      buffered = buffered.subarray(headerEnd + 4);
      if (statusCode !== 200) {
        clearTimeout(timer);
        socket.destroy();
        resolve({ statusCode, tunneledResponse: buffered.toString("utf8") });
        return;
      }
      phase = "TUNNEL";
      socket.write(`GET /probe HTTP/1.1\r\nHost: 127.0.0.1:${input.originPort}\r\nConnection: close\r\n\r\n`);
    });
    socket.once("end", () => {
      clearTimeout(timer);
      resolve({ statusCode, tunneledResponse: buffered.toString("utf8") });
    });
    socket.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

function readExactly(socket: net.Socket, length: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      socket.off("readable", read);
      socket.off("end", ended);
      socket.off("error", failed);
    };
    const read = () => {
      const value = socket.read(length) as Buffer | null;
      if (!value) return;
      cleanup();
      resolve(value);
    };
    const ended = () => { cleanup(); reject(new Error(`SOCKS socket ended before ${length} bytes`)); };
    const failed = (error: Error) => { cleanup(); reject(error); };
    socket.on("readable", read);
    socket.once("end", ended);
    socket.once("error", failed);
    read();
  });
}

async function openSocket(port: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host: "127.0.0.1", port });
    socket.setTimeout(5_000, () => socket.destroy(new Error("SOCKS request timed out")));
    socket.once("connect", () => resolve(socket));
    socket.once("error", reject);
  });
}

async function socks5Method(proxyPort: number, methods: number[]): Promise<number> {
  const socket = await openSocket(proxyPort);
  try {
    socket.write(Buffer.from([0x05, methods.length, ...methods]));
    const response = await readExactly(socket, 2);
    assert.equal(response[0], 0x05);
    return response[1];
  } finally {
    socket.destroy();
  }
}

async function socks5ProxyRequest(input: {
  proxyPort: number;
  originPort: number;
  username: string;
  password: string;
}): Promise<{ method: number; authStatus: number; connectStatus: number; body: string }> {
  const socket = await openSocket(input.proxyPort);
  try {
    socket.write(Buffer.from([0x05, 0x01, 0x02]));
    const methodResponse = await readExactly(socket, 2);
    const method = methodResponse[1];
    if (method !== 0x02) return { method, authStatus: -1, connectStatus: -1, body: "" };
    const user = Buffer.from(input.username, "utf8");
    const password = Buffer.from(input.password, "utf8");
    socket.write(Buffer.concat([Buffer.from([0x01, user.length]), user, Buffer.from([password.length]), password]));
    const authResponse = await readExactly(socket, 2);
    const authStatus = authResponse[1];
    if (authStatus !== 0x00) return { method, authStatus, connectStatus: -1, body: "" };
    socket.write(Buffer.from([
      0x05, 0x01, 0x00, 0x01,
      127, 0, 0, 1,
      (input.originPort >> 8) & 0xff, input.originPort & 0xff,
    ]));
    const connectHeader = await readExactly(socket, 4);
    const connectStatus = connectHeader[1];
    const addressLength = connectHeader[3] === 0x01 ? 4
      : connectHeader[3] === 0x04 ? 16
        : (await readExactly(socket, 1))[0];
    await readExactly(socket, addressLength + 2);
    if (connectStatus !== 0x00) return { method, authStatus, connectStatus, body: "" };
    socket.write(`GET /probe HTTP/1.1\r\nHost: 127.0.0.1:${input.originPort}\r\nConnection: close\r\n\r\n`);
    const body = await new Promise<string>((resolve, reject) => {
      const chunks: Buffer[] = [];
      socket.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
      socket.once("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
      socket.once("error", reject);
    });
    return { method, authStatus, connectStatus, body };
  } finally {
    socket.destroy();
  }
}

async function socks4WasAccepted(proxyPort: number, originPort: number): Promise<boolean> {
  const socket = await openSocket(proxyPort);
  try {
    socket.write(Buffer.from([0x04, 0x01, (originPort >> 8) & 0xff, originPort & 0xff, 127, 0, 0, 1, 0x00]));
    return await new Promise<boolean>((resolve) => {
      const timer = setTimeout(() => { socket.destroy(); resolve(false); }, 1_000);
      socket.once("data", (response: Buffer) => {
        clearTimeout(timer);
        resolve(response.length >= 2 && response[1] === 0x5a);
      });
      socket.once("end", () => { clearTimeout(timer); resolve(false); });
      socket.once("error", () => { clearTimeout(timer); resolve(false); });
    });
  } finally {
    socket.destroy();
  }
}

async function canBindUdp(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = dgram.createSocket("udp4");
    socket.once("error", () => { socket.close(); resolve(false); });
    socket.bind(port, "127.0.0.1", () => socket.close(() => resolve(true)));
  });
}

function createTlsMaterial(directory: string, label: string): TlsMaterial {
  const certificatePath = path.join(directory, `${label}-certificate.pem`);
  const privateKeyPath = path.join(directory, `${label}-private-key.pem`);
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
    "-subj", `/CN=${serverName}`, "-keyout", privateKeyPath, "-out", certificatePath,
    "-addext", "basicConstraints=critical,CA:FALSE",
    "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
    "-addext", "extendedKeyUsage=serverAuth",
    "-addext", `subjectAltName=DNS:${serverName}`,
  ], { stdio: "ignore" });
  const certificateChainPem = fs.readFileSync(certificatePath, "utf8");
  return {
    certificateChainPem,
    privateKeyPem: fs.readFileSync(privateKeyPath, "utf8"),
    leafFingerprintSha256: crypto.createHash("sha256")
      .update(new crypto.X509Certificate(certificateChainPem).raw)
      .digest("hex"),
  };
}

function buildServerConfig(profile: Profile, port: number, credential: string, material: TlsMaterial): string {
  const transport = profileTransport(profile);
  const base = {
    id: 1,
    runtimeTag: `forwardx-${profile.protocol}-${transport}-tls-e2e`,
    listenAddress: "0.0.0.0",
    listenPort: port,
    security: "tls" as const,
    specVersion: 1,
    realityServerName: serverName,
    tlsCertificateChainPem: material.certificateChainPem,
    tlsPrivateKeyPem: material.privateKeyPem,
    isEnabled: true as const,
    pendingDelete: false as const,
  };
  const clientBase = {
    id: 1,
    statsKey: `forwardx-${profile.protocol}-ws-tls-e2e-client`,
    isEnabled: true as const,
    pendingDelete: false as const,
    sortOrder: 0,
  };
  let inbound: XrayConfigInboundInput;
  switch (profile.profileId) {
    case "VLESS_MKCP_TLS":
      inbound = { ...base, protocol: "vless", transport: "kcp", profileId: profile.profileId,
        specJson: "{}",
        clients: [{ ...clientBase, credentialType: "UUID", uuid: credential, flow: "" }] };
      break;
    case "TROJAN_MKCP_TLS":
      inbound = { ...base, protocol: "trojan", transport: "kcp", profileId: profile.profileId,
        specJson: "{}",
        clients: [{ ...clientBase, credentialType: "PASSWORD", password: credential }] };
      break;
    case "VLESS_WEBSOCKET_TLS":
      inbound = { ...base, protocol: "vless", transport: "ws", profileId: profile.profileId,
        specJson: JSON.stringify({ path: profile.path }),
        clients: [{ ...clientBase, credentialType: "UUID", uuid: credential, flow: "" }] };
      break;
    case "TROJAN_WEBSOCKET_TLS":
      inbound = { ...base, protocol: "trojan", transport: "ws", profileId: profile.profileId,
        specJson: JSON.stringify({ path: profile.path }),
        clients: [{ ...clientBase, credentialType: "PASSWORD", password: credential }] };
      break;
    case "VLESS_GRPC_TLS":
      inbound = { ...base, protocol: "vless", transport: "grpc", profileId: profile.profileId,
        specJson: JSON.stringify({ serviceName: profile.serviceName }),
        clients: [{ ...clientBase, credentialType: "UUID", uuid: credential, flow: "" }] };
      break;
    case "TROJAN_GRPC_TLS":
      inbound = { ...base, protocol: "trojan", transport: "grpc", profileId: profile.profileId,
        specJson: JSON.stringify({ serviceName: profile.serviceName }),
        clients: [{ ...clientBase, credentialType: "PASSWORD", password: credential }] };
      break;
    case "VLESS_HTTP_UPGRADE_TLS":
      inbound = { ...base, protocol: "vless", transport: "httpupgrade", profileId: profile.profileId,
        specJson: JSON.stringify({ path: profile.path }),
        clients: [{ ...clientBase, credentialType: "UUID", uuid: credential, flow: "" }] };
      break;
    case "TROJAN_HTTP_UPGRADE_TLS":
      inbound = { ...base, protocol: "trojan", transport: "httpupgrade", profileId: profile.profileId,
        specJson: JSON.stringify({ path: profile.path }),
        clients: [{ ...clientBase, credentialType: "PASSWORD", password: credential }] };
      break;
    case "VLESS_XHTTP_TLS":
      inbound = { ...base, protocol: "vless", transport: "xhttp", profileId: profile.profileId,
        specJson: JSON.stringify({ path: profile.path }),
        clients: [{ ...clientBase, credentialType: "UUID", uuid: credential, flow: "" }] };
      break;
    case "TROJAN_XHTTP_TLS":
      inbound = { ...base, protocol: "trojan", transport: "xhttp", profileId: profile.profileId,
        specJson: JSON.stringify({ path: profile.path }),
        clients: [{ ...clientBase, credentialType: "PASSWORD", password: credential }] };
      break;
    case "VMESS_RAW_TLS":
      inbound = { ...base, protocol: "vmess", transport: "tcp", profileId: profile.profileId,
        specJson: "{}",
        clients: [{ ...clientBase, credentialType: "UUID", uuid: credential, flow: "" }] };
      break;
  }
  return generateDeterministicXrayConfig([inbound]).configJson;
}

function buildShare(profile: Profile, port: number, credential: string, pin: string): string {
  const base = {
    publicAddress: "127.0.0.1",
    listenPort: port,
    serverName,
    fingerprint: "chrome" as const,
    leafFingerprintSha256: pin,
    displayName: `ForwardX ${profile.profileId}`,
  };
  switch (profile.profileId) {
    case "VLESS_MKCP_TLS":
      return buildXrayVlessTlsUri({ ...base, profileId: profile.profileId, uuid: credential });
    case "TROJAN_MKCP_TLS":
      return buildXrayTrojanTlsUri({ ...base, profileId: profile.profileId, password: credential });
    case "VLESS_WEBSOCKET_TLS":
      return buildXrayVlessTlsUri({ ...base, profileId: profile.profileId, path: profile.path, uuid: credential });
    case "TROJAN_WEBSOCKET_TLS":
      return buildXrayTrojanTlsUri({ ...base, profileId: profile.profileId, path: profile.path, password: credential });
    case "VLESS_GRPC_TLS":
      return buildXrayVlessTlsUri({ ...base, profileId: profile.profileId, serviceName: profile.serviceName, uuid: credential });
    case "TROJAN_GRPC_TLS":
      return buildXrayTrojanTlsUri({ ...base, profileId: profile.profileId, serviceName: profile.serviceName, password: credential });
    case "VLESS_HTTP_UPGRADE_TLS":
      return buildXrayVlessTlsUri({ ...base, profileId: profile.profileId, path: profile.path, uuid: credential });
    case "TROJAN_HTTP_UPGRADE_TLS":
      return buildXrayTrojanTlsUri({ ...base, profileId: profile.profileId, path: profile.path, password: credential });
    case "VLESS_XHTTP_TLS":
      return buildXrayVlessTlsUri({ ...base, profileId: profile.profileId, path: profile.path, uuid: credential });
    case "TROJAN_XHTTP_TLS":
      return buildXrayTrojanTlsUri({ ...base, profileId: profile.profileId, path: profile.path, password: credential });
    case "VMESS_RAW_TLS":
      return buildXrayVmessTlsUri({ ...base, uuid: credential });
  }
}

function buildClientConfig(profile: Profile, uri: string, socksPort: number): string {
  if (profile.protocol === "vmess") {
    assert.match(uri, /^vmess:\/\/[A-Za-z0-9+/]+=*$/);
    const payload = JSON.parse(Buffer.from(uri.slice("vmess://".length), "base64").toString("utf8"));
    assert.deepEqual(Object.keys(payload).sort(), ["add", "fp", "id", "net", "pcs", "port", "ps", "scy", "sni", "tls", "type", "v"].sort());
    assert.deepEqual({ v: payload.v, scy: payload.scy, net: payload.net, type: payload.type, tls: payload.tls }, {
      v: "2", scy: "auto", net: "tcp", type: "none", tls: "tls",
    });
    const config = {
      log: { loglevel: "warning" },
      inbounds: [{
        tag: "socks",
        listen: "127.0.0.1",
        port: socksPort,
        protocol: "socks",
        settings: { auth: "noauth", udp: false },
      }],
      outbounds: [{
        tag: "proxy",
        protocol: "vmess",
        settings: {
          vnext: [{ address: payload.add, port: Number(payload.port), users: [{ id: payload.id, security: payload.scy }] }],
        },
        streamSettings: {
          network: payload.net,
          security: payload.tls,
          tlsSettings: {
            serverName: payload.sni,
            fingerprint: payload.fp,
            pinnedPeerCertSha256: payload.pcs,
          },
        },
      }],
    };
    const serialized = `${JSON.stringify(config, null, 2)}\n`;
    for (const forbidden of ["allowInsecure", "\"alterId\"", "\"aid\"", "shortId", "flow", "realitySettings"]) {
      assert.equal(serialized.includes(forbidden), false, forbidden);
    }
    return serialized;
  }
  const parsed = new URL(uri);
  const transport = profileTransport(profile);
  assert.equal(parsed.searchParams.get("type"), transport);
  if (transport === "kcp") {
    assert.equal(parsed.searchParams.has("path"), false);
    assert.equal(parsed.searchParams.has("serviceName"), false);
    assert.equal(parsed.searchParams.has("seed"), false);
    assert.equal(parsed.searchParams.has("headerType"), false);
  } else if ("path" in profile) {
    assert.equal(parsed.searchParams.get("path"), profile.path);
    assert.equal(parsed.searchParams.has("serviceName"), false);
    if (transport === "xhttp") assert.equal(parsed.searchParams.get("mode"), "auto");
  } else if ("serviceName" in profile) {
    assert.equal(parsed.searchParams.get("serviceName"), profile.serviceName);
    assert.equal(parsed.searchParams.get("alpn"), "h2");
    assert.equal(parsed.searchParams.has("path"), false);
  }
  const settings = profile.protocol === "vless"
    ? {
      vnext: [{
        address: parsed.hostname,
        port: Number(parsed.port),
        users: [{ id: parsed.username, encryption: parsed.searchParams.get("encryption") }],
      }],
    }
    : {
      servers: [{ address: parsed.hostname, port: Number(parsed.port), password: parsed.username }],
    };
  const config = {
    log: { loglevel: "warning" },
    inbounds: [{
      tag: "socks",
      listen: "127.0.0.1",
      port: socksPort,
      protocol: "socks",
      settings: { auth: "noauth", udp: false },
    }],
    outbounds: [{
      tag: "proxy",
      protocol: profile.protocol,
      settings,
      streamSettings: {
        network: transport,
        security: parsed.searchParams.get("security"),
        ...(transport === "ws"
          ? { wsSettings: { path: parsed.searchParams.get("path") } }
          : transport === "kcp"
            ? { kcpSettings: {} }
          : transport === "httpupgrade"
            ? { httpupgradeSettings: { path: parsed.searchParams.get("path") } }
            : transport === "xhttp"
              ? { xhttpSettings: { path: parsed.searchParams.get("path"), mode: parsed.searchParams.get("mode") } }
              : { grpcSettings: { serviceName: parsed.searchParams.get("serviceName"), multiMode: false } }),
        tlsSettings: {
          serverName: parsed.searchParams.get("sni"),
          fingerprint: parsed.searchParams.get("fp"),
          pinnedPeerCertSha256: parsed.searchParams.get("pcs"),
          ...(transport === "grpc" ? { alpn: ["h2"] } : {}),
        },
      },
    }],
  };
  const serialized = `${JSON.stringify(config, null, 2)}\n`;
  for (const forbidden of ["allowInsecure", "\"alterId\"", "\"aid\"", "shortId", "flow", "realitySettings", "headers", "earlyData", "authority", "acceptProxyProtocol", "padding", "xmux", "downloadSettings", "seed", "headerType", "uplinkCapacity", "downlinkCapacity", "congestion", "readBufferSize", "writeBufferSize", "FinalMask"]) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
  return serialized;
}

function verifyConfig(binary: string, configPath: string) {
  const checked = spawnSync(binary, ["run", "-test", "-config", configPath], {
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.equal(checked.status, 0, `${checked.stdout}\n${checked.stderr}`);
}

function captureLogs(process: ChildProcess, label: string, logs: { value: string }) {
  for (const stream of [process.stdout, process.stderr]) {
    stream?.on("data", (chunk) => {
      logs.value = `${logs.value}${label}: ${String(chunk)}`.slice(-16_384);
    });
  }
}

async function requestThroughShare(input: {
  binary: string;
  directory: string;
  profile: Profile;
  uri: string;
  originPort: number;
  label: string;
  succeeds: boolean;
  logs: { value: string };
}) {
  const socksPort = await freePort();
  const configPath = path.join(input.directory, `${input.label}-client.json`);
  fs.writeFileSync(configPath, buildClientConfig(input.profile, input.uri, socksPort), { mode: 0o600 });
  verifyConfig(input.binary, configPath);
  const client = spawn(input.binary, ["run", "-config", configPath], { stdio: ["ignore", "pipe", "pipe"] });
  captureLogs(client, input.label, input.logs);
  try {
    await waitForPort(socksPort, client);
    await new Promise((resolve) => setTimeout(resolve, 150));
    const request = execFileAsync("curl", [
      "--silent", "--show-error", "--fail", "--max-time", "5", "--noproxy", "",
      "--socks5-hostname", `127.0.0.1:${socksPort}`,
      `http://127.0.0.1:${input.originPort}/probe`,
    ], { encoding: "utf8", timeout: 8_000 });
    if (input.succeeds) {
      const response = await request;
      assert.equal(response.stdout, "forwardx-transport-tls-ok\n", input.logs.value);
    } else {
      await assert.rejects(request, `request unexpectedly accepted rejected certificate pin\n${input.logs.value}`);
    }
  } finally {
    await stopProcess(client);
  }
}

function buildHysteria2ServerConfig(port: number, auth: string, material: TlsMaterial): string {
  const inbound: XrayConfigInboundInput = {
    id: 1,
    runtimeTag: "forwardx-hysteria2-tls-e2e",
    listenAddress: "0.0.0.0",
    listenPort: port,
    protocol: "hysteria",
    transport: "hysteria",
    security: "tls",
    profileId: "HYSTERIA2_TLS",
    specVersion: 1,
    specJson: "{}",
    realityServerName: serverName,
    tlsCertificateChainPem: material.certificateChainPem,
    tlsPrivateKeyPem: material.privateKeyPem,
    isEnabled: true,
    pendingDelete: false,
    clients: [{
      id: 1,
      credentialType: "HYSTERIA_AUTH",
      auth,
      statsKey: "forwardx-hysteria2-tls-e2e-client",
      isEnabled: true,
      pendingDelete: false,
      sortOrder: 0,
    }],
  };
  return generateDeterministicXrayConfig([inbound]).configJson;
}

function buildHysteria2ClientConfig(uri: string, socksPort: number): string {
  const parsed = new URL(uri);
  assert.equal(parsed.protocol, "hysteria2:");
  assert.deepEqual([...parsed.searchParams.keys()].sort(), ["pinSHA256", "sni"]);
  const pin = parsed.searchParams.get("pinSHA256");
  assert.match(pin ?? "", /^[0-9a-f]{64}$/);
  const config = {
    log: { loglevel: "warning" },
    inbounds: [{
      tag: "socks",
      listen: "127.0.0.1",
      port: socksPort,
      protocol: "socks",
      settings: { auth: "noauth", udp: false },
    }],
    outbounds: [{
      tag: "proxy",
      protocol: "hysteria",
      settings: {
        version: 2,
        address: parsed.hostname,
        port: Number(parsed.port),
      },
      streamSettings: {
        network: "hysteria",
        security: "tls",
        tlsSettings: {
          serverName: parsed.searchParams.get("sni"),
          alpn: ["h3"],
          pinnedPeerCertSha256: pin,
        },
        hysteriaSettings: { version: 2, auth: parsed.username, udpIdleTimeout: 60 },
      },
    }],
  };
  const serialized = `${JSON.stringify(config, null, 2)}\n`;
  for (const forbidden of [
    "allowInsecure", "insecure", "pcs", "fingerprint", "bandwidth", "congestion", "masquerade",
    "obfs", "ports", "FinalMask", "echConfigList",
  ]) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
  return serialized;
}

async function requestThroughHysteria2Share(input: {
  binary: string;
  directory: string;
  uri: string;
  originPort: number;
  label: string;
  succeeds: boolean;
  logs: { value: string };
}) {
  const socksPort = await freePort();
  const configPath = path.join(input.directory, `${input.label}-client.json`);
  fs.writeFileSync(configPath, buildHysteria2ClientConfig(input.uri, socksPort), { mode: 0o600 });
  verifyConfig(input.binary, configPath);
  const client = spawn(input.binary, ["run", "-config", configPath], { stdio: ["ignore", "pipe", "pipe"] });
  captureLogs(client, input.label, input.logs);
  try {
    await waitForPort(socksPort, client);
    await new Promise((resolve) => setTimeout(resolve, 150));
    const request = execFileAsync("curl", [
      "--silent", "--show-error", "--fail", "--max-time", "5", "--noproxy", "",
      "--socks5-hostname", `127.0.0.1:${socksPort}`,
      `http://127.0.0.1:${input.originPort}/probe`,
    ], { encoding: "utf8", timeout: 8_000 });
    if (input.succeeds) {
      const response = await request;
      assert.equal(response.stdout, "forwardx-hysteria2-ok\n", input.logs.value);
    } else {
      await assert.rejects(request, `request unexpectedly accepted invalid Hysteria credentials\n${input.logs.value}`);
    }
  } finally {
    await stopProcess(client);
  }
}

function buildShadowsocksServerConfig(port: number, serverKey: string, userKeys: readonly string[]): string {
  const inbound: XrayConfigInboundInput = {
    id: 1,
    runtimeTag: "forwardx-shadowsocks-2022-raw-e2e",
    listenAddress: "0.0.0.0",
    listenPort: port,
    protocol: "shadowsocks",
    transport: "tcp",
    security: "none",
    profileId: "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE",
    specVersion: 1,
    specJson: "{}",
    shadowsocksServerKey: serverKey,
    isEnabled: true,
    pendingDelete: false,
    clients: userKeys.map((shadowsocksKey, index) => ({
      id: index + 1,
      credentialType: "SHADOWSOCKS_KEY",
      shadowsocksKey,
      statsKey: `forwardx-shadowsocks-user-${index + 1}`,
      isEnabled: true,
      pendingDelete: false,
      sortOrder: index,
    })),
  };
  return generateDeterministicXrayConfig([inbound]).configJson;
}

function parseShadowsocksShare(uri: string) {
  assert.equal(uri.includes("?"), false);
  const withoutFragment = uri.split("#", 1)[0];
  const at = withoutFragment.lastIndexOf("@");
  assert.ok(at > "ss://".length);
  const userInfo = withoutFragment.slice("ss://".length, at).split(":").map(decodeURIComponent);
  assert.equal(userInfo.length, 3);
  assert.equal(userInfo[0], "2022-blake3-aes-256-gcm");
  for (const key of userInfo.slice(1)) assert.match(key, /^[A-Za-z0-9+/]{43}=$/);
  assert.equal(uri.includes(Buffer.from(userInfo.join(":"), "utf8").toString("base64")), false);
  const endpoint = new URL(`ss://${withoutFragment.slice(at + 1)}`);
  return { endpoint, method: userInfo[0], password: `${userInfo[1]}:${userInfo[2]}` };
}

function buildShadowsocksClientConfig(uri: string, socksPort: number): string {
  const { endpoint, method, password } = parseShadowsocksShare(uri);
  const config = {
    log: { loglevel: "warning" },
    inbounds: [{
      tag: "socks",
      listen: "127.0.0.1",
      port: socksPort,
      protocol: "socks",
      settings: { auth: "noauth", udp: false },
    }],
    outbounds: [{
      tag: "proxy",
      protocol: "shadowsocks",
      settings: {
        servers: [{
          address: endpoint.hostname,
          port: Number(endpoint.port),
          method,
          password,
        }],
      },
      streamSettings: { network: "tcp" },
    }],
  };
  const serialized = `${JSON.stringify(config, null, 2)}\n`;
  for (const forbidden of ["tlsSettings", "realitySettings", "allowInsecure", "flow", "shortId", "udpSettings"]) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
  return serialized;
}

function buildShadowsocksUdpClientConfig(uri: string, inboundPort: number, originPort: number): string {
  const { endpoint, method, password } = parseShadowsocksShare(uri);
  const config = {
    log: { loglevel: "warning" },
    inbounds: [{
      tag: "udp-probe",
      listen: "127.0.0.1",
      port: inboundPort,
      protocol: "dokodemo-door",
      settings: { address: "127.0.0.1", port: originPort, network: "udp" },
    }],
    outbounds: [{
      tag: "proxy",
      protocol: "shadowsocks",
      settings: { servers: [{ address: endpoint.hostname, port: Number(endpoint.port), method, password }] },
    }],
  };
  const serialized = `${JSON.stringify(config, null, 2)}\n`;
  for (const forbidden of ["tlsSettings", "realitySettings", "allowInsecure", "flow", "shortId", "uot", "udpOverTcp"]) {
    assert.equal(serialized.toLowerCase().includes(forbidden.toLowerCase()), false, forbidden);
  }
  return serialized;
}

async function requestThroughShadowsocksShare(input: {
  binary: string;
  directory: string;
  uri: string;
  originPort: number;
  label: string;
  succeeds: boolean;
  logs: { value: string };
}) {
  const socksPort = await freePort();
  const configPath = path.join(input.directory, `${input.label}-client.json`);
  fs.writeFileSync(configPath, buildShadowsocksClientConfig(input.uri, socksPort), { mode: 0o600 });
  verifyConfig(input.binary, configPath);
  const client = spawn(input.binary, ["run", "-config", configPath], { stdio: ["ignore", "pipe", "pipe"] });
  captureLogs(client, input.label, input.logs);
  try {
    await waitForPort(socksPort, client);
    await new Promise((resolve) => setTimeout(resolve, 150));
    const request = execFileAsync("curl", [
      "--silent", "--show-error", "--fail", "--max-time", "5", "--noproxy", "",
      "--socks5-hostname", `127.0.0.1:${socksPort}`,
      `http://127.0.0.1:${input.originPort}/probe`,
    ], { encoding: "utf8", timeout: 8_000 });
    if (input.succeeds) {
      const response = await request;
      assert.equal(response.stdout, "forwardx-shadowsocks-2022-ok\n", input.logs.value);
    } else {
      await assert.rejects(request, `request unexpectedly accepted mismatched Shadowsocks key\n${input.logs.value}`);
    }
  } finally {
    await stopProcess(client);
  }
}

async function requestUdpThroughShadowsocksShare(input: {
  binary: string;
  directory: string;
  uri: string;
  originPort: number;
  logs: { value: string };
}) {
  const inboundPort = await freeUdpPort();
  const configPath = path.join(input.directory, "shadowsocks-udp-client.json");
  fs.writeFileSync(configPath, buildShadowsocksUdpClientConfig(input.uri, inboundPort, input.originPort), { mode: 0o600 });
  verifyConfig(input.binary, configPath);
  const client = spawn(input.binary, ["run", "-config", configPath], { stdio: ["ignore", "pipe", "pipe"] });
  captureLogs(client, "shadowsocks-udp-client", input.logs);
  try {
    await waitForUdpPort(inboundPort, client);
    await new Promise((resolve) => setTimeout(resolve, 150));
    const response = await new Promise<string>((resolve, reject) => {
      const socket = dgram.createSocket("udp4");
      const timer = setTimeout(() => {
        socket.close();
        reject(new Error(`Timed out waiting for Shadowsocks native UDP response\n${input.logs.value}`));
      }, 5_000);
      socket.once("error", (error) => {
        clearTimeout(timer);
        socket.close();
        reject(error);
      });
      socket.once("message", (message) => {
        clearTimeout(timer);
        socket.close();
        resolve(message.toString("utf8"));
      });
      socket.send("forwardx-shadowsocks-udp-request", inboundPort, "127.0.0.1");
    });
    assert.equal(response, "forwardx-shadowsocks-udp-response");
  } finally {
    await stopProcess(client);
  }
}

type WireGuardClientMaterial = Readonly<{
  secretKey: string;
  address: string;
  publicKey: string;
  preSharedKey: string;
  endpoint: string;
  allowedIPs: string[];
  keepAlive: number;
  mtu: number;
}>;

function parseWireGuardClientConfig(content: string): WireGuardClientMaterial {
  const sectionEntries = new Map<string, Map<string, string>>();
  let section = "";
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const sectionMatch = line.match(/^\[([^\]]+)]$/);
    if (sectionMatch) {
      section = sectionMatch[1];
      if (sectionEntries.has(section)) throw new Error("Duplicate WireGuard config section");
      sectionEntries.set(section, new Map());
      continue;
    }
    const separator = line.indexOf("=");
    if (!section || separator < 1) throw new Error("Invalid WireGuard client config");
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    const entries = sectionEntries.get(section)!;
    if (!value || entries.has(key)) throw new Error("Invalid WireGuard client config entry");
    entries.set(key, value);
  }
  const interfaceEntries = sectionEntries.get("Interface");
  const peerEntries = sectionEntries.get("Peer");
  assert.ok(interfaceEntries);
  assert.ok(peerEntries);
  assert.deepEqual([...sectionEntries.keys()], ["Interface", "Peer"]);
  assert.deepEqual([...interfaceEntries.keys()], ["PrivateKey", "Address", "DNS", "MTU"]);
  assert.deepEqual([...peerEntries.keys()], ["PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"]);
  assert.equal(interfaceEntries.get("DNS"), "1.1.1.1, 1.0.0.1");
  return {
    secretKey: interfaceEntries.get("PrivateKey")!,
    address: interfaceEntries.get("Address")!,
    publicKey: peerEntries.get("PublicKey")!,
    preSharedKey: peerEntries.get("PresharedKey")!,
    endpoint: peerEntries.get("Endpoint")!,
    allowedIPs: peerEntries.get("AllowedIPs")!.split(",").map((value) => value.trim()),
    keepAlive: Number(peerEntries.get("PersistentKeepalive")),
    mtu: Number(interfaceEntries.get("MTU")),
  };
}

function buildWireGuardClientXrayConfig(input: {
  client: WireGuardClientMaterial;
  inboundPort: number;
  udpOriginHost?: string;
  udpOriginPort?: number;
}): string {
  const [host, portText] = input.client.endpoint.split(":");
  assert.equal(host, "127.0.0.1");
  const inbound = input.udpOriginPort === undefined
    ? {
        tag: "socks",
        listen: "127.0.0.1",
        port: input.inboundPort,
        protocol: "socks",
        settings: { auth: "noauth", udp: false },
      }
    : {
        tag: "udp-probe",
        listen: "127.0.0.1",
        port: input.inboundPort,
        protocol: "dokodemo-door",
        settings: { address: input.udpOriginHost, port: input.udpOriginPort, network: "udp" },
      };
  const config = {
    log: { loglevel: "warning" },
    inbounds: [inbound],
    outbounds: [{
      tag: "proxy",
      protocol: "wireguard",
      settings: {
        secretKey: input.client.secretKey,
        address: [input.client.address],
        peers: [{
          publicKey: input.client.publicKey,
          preSharedKey: input.client.preSharedKey,
          endpoint: input.client.endpoint,
          allowedIPs: input.client.allowedIPs,
          keepAlive: input.client.keepAlive,
        }],
        mtu: input.client.mtu,
        noKernelTun: true,
      },
    }],
  };
  assert.ok(Number.isSafeInteger(Number(portText)));
  return `${JSON.stringify(config, null, 2)}\n`;
}

async function requestThroughWireGuard(input: {
  binary: string;
  directory: string;
  client: WireGuardClientMaterial;
  originHost: string;
  originPort: number;
  label: string;
  succeeds: boolean;
  logs: { value: string };
}) {
  const socksPort = await freePort();
  const configPath = path.join(input.directory, `${input.label}-client.json`);
  fs.writeFileSync(configPath, buildWireGuardClientXrayConfig({ client: input.client, inboundPort: socksPort }), { mode: 0o600 });
  verifyConfig(input.binary, configPath);
  const client = spawn(input.binary, ["run", "-config", configPath], { stdio: ["ignore", "pipe", "pipe"] });
  captureLogs(client, input.label, input.logs);
  try {
    await waitForPort(socksPort, client);
    await new Promise((resolve) => setTimeout(resolve, 150));
    const request = execFileAsync("curl", [
      "--silent", "--show-error", "--fail", "--max-time", "5", "--noproxy", "",
      "--socks5-hostname", `127.0.0.1:${socksPort}`,
      `http://${input.originHost}:${input.originPort}/probe`,
    ], { encoding: "utf8", timeout: 8_000 });
    if (input.succeeds) {
      const response = await request.catch((error) => {
        throw new Error(`WireGuard request failed: ${String(error)}\n${input.logs.value}`);
      });
      assert.equal(response.stdout, "forwardx-wireguard-ok\n", input.logs.value);
    } else {
      await assert.rejects(request, `request unexpectedly accepted invalid WireGuard credentials\n${input.logs.value}`);
    }
  } finally {
    await stopProcess(client);
  }
}

async function requestUdpThroughWireGuard(input: {
  binary: string;
  directory: string;
  client: WireGuardClientMaterial;
  originHost: string;
  originPort: number;
  logs: { value: string };
}) {
  const inboundPort = await freeUdpPort();
  const configPath = path.join(input.directory, "wireguard-udp-client.json");
  fs.writeFileSync(configPath, buildWireGuardClientXrayConfig({
    client: input.client,
    inboundPort,
    udpOriginHost: input.originHost,
    udpOriginPort: input.originPort,
  }), { mode: 0o600 });
  verifyConfig(input.binary, configPath);
  const client = spawn(input.binary, ["run", "-config", configPath], { stdio: ["ignore", "pipe", "pipe"] });
  captureLogs(client, "wireguard-udp-client", input.logs);
  try {
    await waitForUdpPort(inboundPort, client);
    await new Promise((resolve) => setTimeout(resolve, 150));
    const response = await new Promise<string>((resolve, reject) => {
      const socket = dgram.createSocket("udp4");
      const timer = setTimeout(() => {
        socket.close();
        reject(new Error(`Timed out waiting for WireGuard UDP response\n${input.logs.value}`));
      }, 5_000);
      socket.once("error", (error) => {
        clearTimeout(timer);
        socket.close();
        reject(error);
      });
      socket.once("message", (message) => {
        clearTimeout(timer);
        socket.close();
        resolve(message.toString("utf8"));
      });
      socket.send("forwardx-wireguard-udp-request", inboundPort, "127.0.0.1");
    });
    assert.equal(response, "forwardx-wireguard-udp-response");
  } finally {
    await stopProcess(client);
  }
}

test("HTTP management proxy accepts authenticated HTTP and CONNECT while rejecting missing or wrong Basic auth", { timeout: 30_000 }, async (t) => {
  const binary = process.env.XRAY_TEST_BINARY;
  if (!binary) return t.skip("XRAY_TEST_BINARY is not configured");
  assert.equal(crypto.createHash("sha256").update(fs.readFileSync(binary)).digest("hex"), fixedXraySha256);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-http-proxy-e2e-"));
  const proxyPort = await freePort();
  const username = crypto.randomBytes(16).toString("base64url");
  const password = crypto.randomBytes(32).toString("base64url");
  const inbound: XrayConfigInboundInput = {
    id: 1,
    runtimeTag: "forwardx-http-proxy-e2e",
    listenAddress: "0.0.0.0",
    listenPort: proxyPort,
    protocol: "http",
    transport: "tcp",
    security: "none",
    profileId: "HTTP_RAW_NONE",
    specVersion: 1,
    specJson: "{}",
    isEnabled: true,
    pendingDelete: false,
    clients: [{
      id: 1,
      credentialType: "HTTP_BASIC",
      username,
      password,
      statsKey: "forwardx-http-proxy-account-1",
      isEnabled: true,
      pendingDelete: false,
      sortOrder: 0,
    }],
  };
  const generated = generateDeterministicXrayConfig([inbound]);
  assert.deepEqual(generated.expectedListeners, [{
    inboundId: 1,
    runtimeTag: "forwardx-http-proxy-e2e",
    network: "tcp",
    listenAddress: "0.0.0.0",
    port: proxyPort,
  }]);
  const compiledInbound = JSON.parse(generated.configJson).inbounds[0];
  assert.deepEqual(compiledInbound.settings, {
    accounts: [{ user: username, pass: password }],
    allowTransparent: false,
    userLevel: 0,
  });
  assert.deepEqual(compiledInbound.streamSettings, { network: "tcp" });
  for (const forbidden of ["tlsSettings", "realitySettings", "allowInsecure", "acceptProxyProtocol"]) {
    assert.equal(generated.configJson.includes(forbidden), false, forbidden);
  }
  const share = buildXrayHttpProxyUri({
    username,
    password,
    publicAddress: "127.0.0.1",
    listenPort: proxyPort,
  });
  const parsedShare = new URL(share);
  assert.equal(parsedShare.protocol, "http:");
  assert.equal(parsedShare.username, username);
  assert.equal(parsedShare.password, password);
  assert.equal(parsedShare.hash, "");
  assert.equal(parsedShare.search, "");

  const configPath = path.join(directory, "server.json");
  fs.writeFileSync(configPath, generated.configJson, { mode: 0o600 });
  verifyConfig(binary, configPath);
  const origin = http.createServer((_request, response) => response.end("forwardx-http-proxy-ok\n"));
  await new Promise<void>((resolve, reject) => {
    origin.once("error", reject);
    origin.listen(0, "127.0.0.1", resolve);
  });
  const originAddress = origin.address();
  if (!originAddress || typeof originAddress === "string") throw new Error("No origin test port");
  const logs = { value: "" };
  const server = spawn(binary, ["run", "-config", configPath], { stdio: ["ignore", "pipe", "pipe"] });
  captureLogs(server, "http-proxy-server", logs);
  try {
    await waitForPort(proxyPort, server);
    const authorization = proxyAuthorization(username, password);
    assert.deepEqual(await httpProxyRequest({ proxyPort, originPort: originAddress.port, authorization }), {
      statusCode: 200,
      body: "forwardx-http-proxy-ok\n",
    });
    const connected = await httpConnectRequest({ proxyPort, originPort: originAddress.port, authorization });
    assert.equal(connected.statusCode, 200, logs.value);
    assert.match(connected.tunneledResponse, /forwardx-http-proxy-ok\n$/, logs.value);

    assert.equal((await httpProxyRequest({ proxyPort, originPort: originAddress.port })).statusCode, 407);
    assert.equal((await httpProxyRequest({
      proxyPort,
      originPort: originAddress.port,
      authorization: proxyAuthorization(crypto.randomBytes(16).toString("base64url"), password),
    })).statusCode, 407);
    assert.equal((await httpProxyRequest({
      proxyPort,
      originPort: originAddress.port,
      authorization: proxyAuthorization(username, crypto.randomBytes(32).toString("base64url")),
    })).statusCode, 407);
  } finally {
    await stopProcess(server);
    await new Promise<void>((resolve, reject) => origin.close((error) => error ? reject(error) : resolve()));
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("Mixed management proxy authenticates SOCKS5, HTTP, and CONNECT on one TCP-only listener", { timeout: 30_000 }, async (t) => {
  const binary = process.env.XRAY_TEST_BINARY;
  if (!binary) return t.skip("XRAY_TEST_BINARY is not configured");
  assert.equal(crypto.createHash("sha256").update(fs.readFileSync(binary)).digest("hex"), fixedXraySha256);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-mixed-proxy-e2e-"));
  const proxyPort = await freeTcpUdpPort();
  const username = crypto.randomBytes(16).toString("base64url");
  const password = crypto.randomBytes(32).toString("base64url");
  const inbound: XrayConfigInboundInput = {
    id: 1,
    runtimeTag: "forwardx-mixed-proxy-e2e",
    listenAddress: "0.0.0.0",
    listenPort: proxyPort,
    protocol: "mixed",
    transport: "tcp",
    security: "none",
    profileId: "MIXED_RAW_NONE",
    specVersion: 1,
    specJson: "{}",
    isEnabled: true,
    pendingDelete: false,
    clients: [{
      id: 1,
      credentialType: "MIXED_USER_PASSWORD",
      username,
      password,
      statsKey: "forwardx-mixed-proxy-account-1",
      isEnabled: true,
      pendingDelete: false,
      sortOrder: 0,
    }],
  };
  const generated = generateDeterministicXrayConfig([inbound]);
  assert.deepEqual(generated.expectedListeners, [{
    inboundId: 1,
    runtimeTag: "forwardx-mixed-proxy-e2e",
    network: "tcp",
    listenAddress: "0.0.0.0",
    port: proxyPort,
  }]);
  const compiledInbound = JSON.parse(generated.configJson).inbounds[0];
  assert.deepEqual(compiledInbound.settings, {
    auth: "password",
    accounts: [{ user: username, pass: password }],
    udp: false,
    userLevel: 0,
  });
  assert.deepEqual(compiledInbound.streamSettings, { network: "tcp" });
  for (const forbidden of ["tlsSettings", "realitySettings", "allowInsecure", "acceptProxyProtocol", "udpSettings"]) {
    assert.equal(generated.configJson.includes(forbidden), false, forbidden);
  }
  assert.deepEqual(buildXrayMixedProxyEndpoints({
    username,
    password,
    publicAddress: "127.0.0.1",
    listenPort: proxyPort,
  }), {
    socks5Uri: `socks5://${username}:${password}@127.0.0.1:${proxyPort}`,
    httpUri: `http://${username}:${password}@127.0.0.1:${proxyPort}`,
  });

  const configPath = path.join(directory, "server.json");
  fs.writeFileSync(configPath, generated.configJson, { mode: 0o600 });
  verifyConfig(binary, configPath);
  const origin = http.createServer((_request, response) => response.end("forwardx-mixed-proxy-ok\n"));
  await new Promise<void>((resolve, reject) => {
    origin.once("error", reject);
    origin.listen(0, "127.0.0.1", resolve);
  });
  const originAddress = origin.address();
  if (!originAddress || typeof originAddress === "string") throw new Error("No origin test port");
  const logs = { value: "" };
  const server = spawn(binary, ["run", "-config", configPath], { stdio: ["ignore", "pipe", "pipe"] });
  captureLogs(server, "mixed-proxy-server", logs);
  try {
    await waitForPort(proxyPort, server);
    assert.equal(await canBindUdp(proxyPort), true, "Mixed must not bind UDP");
    const authorization = proxyAuthorization(username, password);
    assert.deepEqual(await httpProxyRequest({ proxyPort, originPort: originAddress.port, authorization }), {
      statusCode: 200,
      body: "forwardx-mixed-proxy-ok\n",
    });
    const connected = await httpConnectRequest({ proxyPort, originPort: originAddress.port, authorization });
    assert.equal(connected.statusCode, 200, logs.value);
    assert.match(connected.tunneledResponse, /forwardx-mixed-proxy-ok\n$/, logs.value);
    assert.equal((await httpProxyRequest({ proxyPort, originPort: originAddress.port })).statusCode, 407);
    assert.equal((await httpProxyRequest({
      proxyPort,
      originPort: originAddress.port,
      authorization: proxyAuthorization(username, crypto.randomBytes(32).toString("base64url")),
    })).statusCode, 407);

    const socks = await socks5ProxyRequest({ proxyPort, originPort: originAddress.port, username, password });
    assert.deepEqual({ method: socks.method, authStatus: socks.authStatus, connectStatus: socks.connectStatus }, {
      method: 0x02,
      authStatus: 0x00,
      connectStatus: 0x00,
    });
    assert.match(socks.body, /forwardx-mixed-proxy-ok\n$/, logs.value);
    assert.equal(await socks5Method(proxyPort, [0x00]), 0xff, "anonymous SOCKS5 must be rejected");
    const wrongSocks = await socks5ProxyRequest({
      proxyPort,
      originPort: originAddress.port,
      username,
      password: crypto.randomBytes(32).toString("base64url"),
    });
    assert.equal(wrongSocks.method, 0x02);
    assert.notEqual(wrongSocks.authStatus, 0x00);
    assert.equal(await socks4WasAccepted(proxyPort, originAddress.port), false, "password mode must reject SOCKS4/4a");
  } finally {
    await stopProcess(server);
    await new Promise<void>((resolve, reject) => origin.close((error) => error ? reject(error) : resolve()));
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("VLESS, Trojan, and VMess TLS profiles enforce share pins across managed certificate rotation", { timeout: 180_000 }, async (t) => {
  const binary = process.env.XRAY_TEST_BINARY;
  if (!binary) return t.skip("XRAY_TEST_BINARY is not configured");
  assert.equal(crypto.createHash("sha256").update(fs.readFileSync(binary)).digest("hex"), fixedXraySha256);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-transport-tls-e2e-"));
  const oldMaterial = createTlsMaterial(directory, "old");
  const newMaterial = createTlsMaterial(directory, "new");
  assert.notEqual(oldMaterial.leafFingerprintSha256, newMaterial.leafFingerprintSha256);
  const origin = http.createServer((_request, response) => response.end("forwardx-transport-tls-ok\n"));
  await new Promise<void>((resolve, reject) => {
    origin.once("error", reject);
    origin.listen(0, "127.0.0.1", resolve);
  });
  const originAddress = origin.address();
  if (!originAddress || typeof originAddress === "string") throw new Error("No origin test port");

  try {
    for (const profile of [
      { profileId: "VLESS_MKCP_TLS", protocol: "vless" },
      { profileId: "TROJAN_MKCP_TLS", protocol: "trojan" },
      { profileId: "VLESS_WEBSOCKET_TLS", protocol: "vless", path: "/forwardx/vless-ws" },
      { profileId: "TROJAN_WEBSOCKET_TLS", protocol: "trojan", path: "/forwardx/trojan-ws" },
      { profileId: "VLESS_GRPC_TLS", protocol: "vless", serviceName: "forwardx.vless-grpc" },
      { profileId: "TROJAN_GRPC_TLS", protocol: "trojan", serviceName: "forwardx.trojan-grpc" },
      { profileId: "VLESS_HTTP_UPGRADE_TLS", protocol: "vless", path: "/forwardx/vless-httpupgrade" },
      { profileId: "TROJAN_HTTP_UPGRADE_TLS", protocol: "trojan", path: "/forwardx/trojan-httpupgrade" },
      { profileId: "VLESS_XHTTP_TLS", protocol: "vless", path: "/forwardx/vless-xhttp" },
      { profileId: "TROJAN_XHTTP_TLS", protocol: "trojan", path: "/forwardx/trojan-xhttp" },
      { profileId: "VMESS_RAW_TLS", protocol: "vmess" },
    ] as const satisfies readonly Profile[]) {
      const transport = profileTransport(profile);
      const port = transport === "kcp" ? await freeUdpPort() : await freePort();
      const credential = profile.protocol === "trojan" ? crypto.randomBytes(32).toString("base64url") : crypto.randomUUID();
      const oldShare = buildShare(profile, port, credential, oldMaterial.leafFingerprintSha256);
      const wrongPinShare = buildShare(profile, port, credential, "0".repeat(64));
      const newShare = buildShare(profile, port, credential, newMaterial.leafFingerprintSha256);
      const serverConfigPath = path.join(directory, `${profile.protocol}-server.json`);
      const logs = { value: "" };
      let server: ChildProcess | null = null;

      const startServer = async (material: TlsMaterial, label: string) => {
        const config = buildServerConfig(profile, port, credential, material);
        for (const forbidden of ["certificateFile", "keyFile", directory, "\"alterId\"", "\"aid\"", "shortId", "flow", "realitySettings", "headers", "earlyData", "authority", "acceptProxyProtocol", "padding", "xmux", "downloadSettings"]) {
          assert.equal(config.includes(forbidden), false, `${profile.profileId}: ${forbidden}`);
        }
        const parsedConfig = JSON.parse(config);
        const compiledInbound = parsedConfig.inbounds[0];
        const streamSettings = compiledInbound.streamSettings;
        if (transport === "kcp") {
          assert.deepEqual(streamSettings.kcpSettings, {});
        }
        if (profile.profileId === "VMESS_RAW_TLS") {
          assert.deepEqual(Object.keys(compiledInbound.settings.clients[0]).sort(), ["email", "id", "security"]);
          assert.equal(compiledInbound.settings.clients[0].security, "auto");
        }
        if ("serviceName" in profile) {
          assert.deepEqual(streamSettings.grpcSettings, { serviceName: profile.serviceName, multiMode: false });
          assert.deepEqual(streamSettings.tlsSettings.alpn, ["h2"]);
        } else if (profileTransport(profile) === "httpupgrade") {
          assert.deepEqual(streamSettings.httpupgradeSettings, { path: profile.path });
        } else if (profileTransport(profile) === "xhttp") {
          assert.deepEqual(streamSettings.xhttpSettings, { path: profile.path, mode: "auto" });
        }
        fs.writeFileSync(serverConfigPath, config, { mode: 0o600 });
        verifyConfig(binary, serverConfigPath);
        server = spawn(binary, ["run", "-config", serverConfigPath], { stdio: ["ignore", "pipe", "pipe"] });
        captureLogs(server, `${profile.profileId}-${label}`, logs);
        if (transport === "kcp") await waitForUdpPort(port, server);
        else await waitForPort(port, server);
      };

      try {
        await startServer(oldMaterial, "old-server");
        await requestThroughShare({ binary, directory, profile, uri: oldShare, originPort: originAddress.port, label: `${profile.protocol}-old-pin`, succeeds: true, logs });
        await requestThroughShare({ binary, directory, profile, uri: wrongPinShare, originPort: originAddress.port, label: `${profile.protocol}-wrong-pin`, succeeds: false, logs });

        await stopProcess(server);
        server = null;
        await startServer(newMaterial, "new-server");
        await requestThroughShare({ binary, directory, profile, uri: oldShare, originPort: originAddress.port, label: `${profile.protocol}-rotated-old-pin`, succeeds: false, logs });
        await requestThroughShare({ binary, directory, profile, uri: newShare, originPort: originAddress.port, label: `${profile.protocol}-rotated-new-pin`, succeeds: true, logs });
      } finally {
        await stopProcess(server);
      }
    }
  } finally {
    await new Promise<void>((resolve, reject) => origin.close((error) => error ? reject(error) : resolve()));
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("Hysteria 2 production config and share enforce auth and the managed leaf pin", { timeout: 60_000 }, async (t) => {
  const binary = process.env.XRAY_TEST_BINARY;
  if (!binary) return t.skip("XRAY_TEST_BINARY is not configured");
  assert.equal(crypto.createHash("sha256").update(fs.readFileSync(binary)).digest("hex"), fixedXraySha256);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-hysteria2-e2e-"));
  const material = createTlsMaterial(directory, "managed");
  const port = await freeUdpPort();
  const auth = crypto.randomBytes(32).toString("base64url");
  const serverConfigPath = path.join(directory, "server.json");
  const serverConfig = buildHysteria2ServerConfig(port, auth, material);
  const compiledInbound = JSON.parse(serverConfig).inbounds[0];
  assert.deepEqual(compiledInbound.settings, {
    version: 2,
    clients: [{ auth, email: "forwardx-hysteria2-tls-e2e-client" }],
  });
  assert.deepEqual(compiledInbound.streamSettings.hysteriaSettings, { version: 2, udpIdleTimeout: 60 });
  assert.deepEqual(compiledInbound.streamSettings.tlsSettings.alpn, ["h3"]);
  for (const forbidden of [
    "certificateFile", "keyFile", directory, "allowInsecure", "bandwidth", "congestion", "masquerade",
    "obfs", "ports", "FinalMask", "echConfigList",
  ]) {
    assert.equal(serverConfig.includes(forbidden), false, forbidden);
  }
  fs.writeFileSync(serverConfigPath, serverConfig, { mode: 0o600 });
  verifyConfig(binary, serverConfigPath);

  const origin = http.createServer((_request, response) => response.end("forwardx-hysteria2-ok\n"));
  await new Promise<void>((resolve, reject) => {
    origin.once("error", reject);
    origin.listen(0, "127.0.0.1", resolve);
  });
  const originAddress = origin.address();
  if (!originAddress || typeof originAddress === "string") throw new Error("No origin test port");
  const share = buildXrayHysteria2Uri({
    auth,
    publicAddress: "127.0.0.1",
    listenPort: port,
    serverName,
    leafFingerprintSha256: material.leafFingerprintSha256,
    displayName: "ForwardX Hysteria 2",
  });
  const wrongAuthShare = buildXrayHysteria2Uri({
    auth: crypto.randomBytes(32).toString("base64url"),
    publicAddress: "127.0.0.1",
    listenPort: port,
    serverName,
    leafFingerprintSha256: material.leafFingerprintSha256,
    displayName: "ForwardX Hysteria 2 wrong auth",
  });
  const wrongPinShare = buildXrayHysteria2Uri({
    auth,
    publicAddress: "127.0.0.1",
    listenPort: port,
    serverName,
    leafFingerprintSha256: "0".repeat(64),
    displayName: "ForwardX Hysteria 2 wrong pin",
  });
  const logs = { value: "" };
  const server = spawn(binary, ["run", "-config", serverConfigPath], { stdio: ["ignore", "pipe", "pipe"] });
  captureLogs(server, "hysteria2-server", logs);
  try {
    await waitForUdpPort(port, server);
    await requestThroughHysteria2Share({
      binary, directory, uri: share, originPort: originAddress.port, label: "hysteria2-valid", succeeds: true, logs,
    });
    await requestThroughHysteria2Share({
      binary, directory, uri: wrongAuthShare, originPort: originAddress.port, label: "hysteria2-wrong-auth", succeeds: false, logs,
    });
    await requestThroughHysteria2Share({
      binary, directory, uri: wrongPinShare, originPort: originAddress.port, label: "hysteria2-wrong-pin", succeeds: false, logs,
    });
  } finally {
    await stopProcess(server);
    await new Promise<void>((resolve, reject) => origin.close((error) => error ? reject(error) : resolve()));
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("Shadowsocks 2022 RAW TCP plus native UDP supports two users and rejects mismatched server or user PSKs", { timeout: 60_000 }, async (t) => {
  const binary = process.env.XRAY_TEST_BINARY;
  if (!binary) return t.skip("XRAY_TEST_BINARY is not configured");
  assert.equal(crypto.createHash("sha256").update(fs.readFileSync(binary)).digest("hex"), fixedXraySha256);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-shadowsocks-2022-e2e-"));
  const port = await freeTcpUdpPort();
  const serverKey = crypto.randomBytes(32).toString("base64");
  const userKeys = [crypto.randomBytes(32).toString("base64"), crypto.randomBytes(32).toString("base64")];
  assert.equal(new Set([serverKey, ...userKeys]).size, 3);
  const serverConfigPath = path.join(directory, "server.json");
  const serverConfig = buildShadowsocksServerConfig(port, serverKey, userKeys);
  const parsedInbound = JSON.parse(serverConfig).inbounds[0];
  assert.deepEqual(parsedInbound.settings, {
    method: "2022-blake3-aes-256-gcm",
    password: serverKey,
    network: "tcp,udp",
    clients: userKeys.map((password, index) => ({ password, email: `forwardx-shadowsocks-user-${index + 1}` })),
  });
  assert.deepEqual(parsedInbound.streamSettings, { network: "tcp" });
  for (const forbidden of ["tlsSettings", "realitySettings", "allowInsecure", "flow", "shortId", "udpSettings"]) {
    assert.equal(serverConfig.includes(forbidden), false, forbidden);
  }
  fs.writeFileSync(serverConfigPath, serverConfig, { mode: 0o600 });
  verifyConfig(binary, serverConfigPath);

  const origin = http.createServer((_request, response) => response.end("forwardx-shadowsocks-2022-ok\n"));
  await new Promise<void>((resolve, reject) => {
    origin.once("error", reject);
    origin.listen(0, "127.0.0.1", resolve);
  });
  const originAddress = origin.address();
  if (!originAddress || typeof originAddress === "string") throw new Error("No origin test port");
  const udpOrigin = dgram.createSocket("udp4");
  udpOrigin.on("message", (_message, remote) => {
    udpOrigin.send("forwardx-shadowsocks-udp-response", remote.port, remote.address);
  });
  await new Promise<void>((resolve, reject) => {
    udpOrigin.once("error", reject);
    udpOrigin.bind(0, "127.0.0.1", resolve);
  });
  const udpOriginAddress = udpOrigin.address();
  const logs = { value: "" };
  const server = spawn(binary, ["run", "-config", serverConfigPath], { stdio: ["ignore", "pipe", "pipe"] });
  captureLogs(server, "shadowsocks-server", logs);
  try {
    await waitForPort(port, server);
    await waitForUdpPort(port, server);
    const shares = userKeys.map((userKey, index) => buildXrayShadowsocks2022Uri({
      serverKey,
      userKey,
      publicAddress: "127.0.0.1",
      listenPort: port,
      displayName: `ForwardX Shadowsocks user ${index + 1}`,
    }));
    for (let index = 0; index < shares.length; index += 1) {
      await requestThroughShadowsocksShare({
        binary, directory, uri: shares[index], originPort: originAddress.port,
        label: `shadowsocks-user-${index + 1}`, succeeds: true, logs,
      });
    }
    await requestUdpThroughShadowsocksShare({
      binary,
      directory,
      uri: shares[1],
      originPort: udpOriginAddress.port,
      logs,
    });
    const wrongServerShare = buildXrayShadowsocks2022Uri({
      serverKey: crypto.randomBytes(32).toString("base64"), userKey: userKeys[0],
      publicAddress: "127.0.0.1", listenPort: port, displayName: "wrong server key",
    });
    const wrongUserShare = buildXrayShadowsocks2022Uri({
      serverKey, userKey: crypto.randomBytes(32).toString("base64"),
      publicAddress: "127.0.0.1", listenPort: port, displayName: "wrong user key",
    });
    await requestThroughShadowsocksShare({
      binary, directory, uri: wrongServerShare, originPort: originAddress.port,
      label: "shadowsocks-wrong-server", succeeds: false, logs,
    });
    await requestThroughShadowsocksShare({
      binary, directory, uri: wrongUserShare, originPort: originAddress.port,
      label: "shadowsocks-wrong-user", succeeds: false, logs,
    });
  } finally {
    await stopProcess(server);
    await new Promise<void>((resolve, reject) => origin.close((error) => error ? reject(error) : resolve()));
    await new Promise<void>((resolve) => udpOrigin.close(() => resolve()));
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("WireGuard production config and standard client files carry TCP and UDP for two peers and reject wrong key or PSK", { timeout: 90_000 }, async (t) => {
  const binary = process.env.XRAY_TEST_BINARY;
  if (!binary) return t.skip("XRAY_TEST_BINARY is not configured");
  assert.equal(crypto.createHash("sha256").update(fs.readFileSync(binary)).digest("hex"), fixedXraySha256);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-wireguard-e2e-"));
  const port = await freeUdpPort();
  const serverKeys = generateXrayWireGuardKeyPair();
  const peers = [generateXrayWireGuardKeyPair(), generateXrayWireGuardKeyPair()].map((keyPair, index) => ({
    ...keyPair,
    preSharedKey: generateXrayWireGuardPreSharedKey(),
    address: `10.0.0.${index + 2}/32`,
    statsKey: `forwardx-wireguard-e2e-peer-${index + 1}`,
  }));
  assert.equal(new Set([serverKeys.privateKey, ...peers.flatMap((peer) => [peer.privateKey, peer.preSharedKey])]).size, 5);
  const inbound: XrayConfigInboundInput = {
    id: 1,
    runtimeTag: "forwardx-wireguard-e2e",
    listenAddress: "0.0.0.0",
    listenPort: port,
    protocol: "wireguard",
    transport: "none",
    security: "none",
    profileId: "WIREGUARD_UDP_NONE",
    specVersion: 1,
    specJson: "{}",
    wireguardServerPrivateKey: serverKeys.privateKey,
    isEnabled: true,
    pendingDelete: false,
    clients: peers.map((peer, index) => ({
      id: index + 1,
      credentialType: "WIREGUARD_PEER" as const,
      privateKey: peer.privateKey,
      preSharedKey: peer.preSharedKey,
      address: peer.address,
      statsKey: peer.statsKey,
      isEnabled: true,
      pendingDelete: false,
      sortOrder: index,
    })),
  };
  const generated = generateDeterministicXrayConfig([inbound]);
  assert.deepEqual(generated.expectedListeners, [{
    inboundId: 1,
    runtimeTag: "forwardx-wireguard-e2e",
    network: "udp",
    listenAddress: "0.0.0.0",
    port,
  }]);
  const parsedServerConfig = JSON.parse(generated.configJson);
  assert.deepEqual(parsedServerConfig.inbounds[0].settings.peers, peers.map((peer) => ({
    publicKey: deriveXrayWireGuardPublicKey(peer.privateKey),
    preSharedKey: peer.preSharedKey,
    allowedIPs: [peer.address],
  })));
  for (const peer of peers) assert.equal(generated.configJson.includes(peer.privateKey), false);
  const serverConfigPath = path.join(directory, "server.json");
  fs.writeFileSync(serverConfigPath, generated.configJson, { mode: 0o600 });
  verifyConfig(binary, serverConfigPath);

  const clientConfigs = peers.map((peer, index) => {
    const share = buildXrayWireGuardClientConfig({
      peerPrivateKey: peer.privateKey,
      peerAddress: peer.address,
      serverPrivateKey: serverKeys.privateKey,
      preSharedKey: peer.preSharedKey,
      publicAddress: "127.0.0.1",
      listenPort: port,
      displayName: `ForwardX WireGuard peer ${index + 1}`,
    });
    assert.match(share.fileName, /^forwardx-forwardx-wireguard-peer-[12]\.conf$/);
    const client = parseWireGuardClientConfig(share.content);
    assert.equal(client.secretKey, peer.privateKey);
    assert.equal(client.address, peer.address);
    assert.equal(client.publicKey, serverKeys.publicKey);
    assert.equal(client.preSharedKey, peer.preSharedKey);
    assert.equal(client.endpoint, `127.0.0.1:${port}`);
    assert.deepEqual(client.allowedIPs, ["0.0.0.0/0"]);
    assert.equal(client.keepAlive, 25);
    assert.equal(client.mtu, 1420);
    return client;
  });

  const originHost = localNonLoopbackIpv4();
  const origin = http.createServer((_request, response) => response.end("forwardx-wireguard-ok\n"));
  await new Promise<void>((resolve, reject) => {
    origin.once("error", reject);
    origin.listen(0, originHost, resolve);
  });
  const originAddress = origin.address();
  if (!originAddress || typeof originAddress === "string") throw new Error("No origin test port");
  const udpOrigin = dgram.createSocket("udp4");
  udpOrigin.on("message", (_message, remote) => {
    udpOrigin.send("forwardx-wireguard-udp-response", remote.port, remote.address);
  });
  await new Promise<void>((resolve, reject) => {
    udpOrigin.once("error", reject);
    udpOrigin.bind(0, originHost, resolve);
  });
  const udpOriginAddress = udpOrigin.address();
  const logs = { value: "" };
  const server = spawn(binary, ["run", "-config", serverConfigPath], { stdio: ["ignore", "pipe", "pipe"] });
  captureLogs(server, "wireguard-server", logs);
  try {
    await waitForUdpPort(port, server);
    for (let index = 0; index < clientConfigs.length; index += 1) {
      await requestThroughWireGuard({
        binary,
        directory,
        client: clientConfigs[index],
        originHost,
        originPort: originAddress.port,
        label: `wireguard-peer-${index + 1}`,
        succeeds: true,
        logs,
      });
    }
    await requestUdpThroughWireGuard({
      binary,
      directory,
      client: clientConfigs[1],
      originHost,
      originPort: udpOriginAddress.port,
      logs,
    });
    await requestThroughWireGuard({
      binary,
      directory,
      client: { ...clientConfigs[0], secretKey: generateXrayWireGuardKeyPair().privateKey },
      originHost,
      originPort: originAddress.port,
      label: "wireguard-wrong-private-key",
      succeeds: false,
      logs,
    });
    await requestThroughWireGuard({
      binary,
      directory,
      client: { ...clientConfigs[0], preSharedKey: generateXrayWireGuardPreSharedKey() },
      originHost,
      originPort: originAddress.port,
      label: "wireguard-wrong-psk",
      succeeds: false,
      logs,
    });
  } finally {
    await stopProcess(server);
    await new Promise<void>((resolve, reject) => origin.close((error) => error ? reject(error) : resolve()));
    await new Promise<void>((resolve) => udpOrigin.close(() => resolve()));
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
