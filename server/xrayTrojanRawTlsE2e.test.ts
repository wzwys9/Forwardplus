import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFile, execFileSync, spawn, spawnSync, type ChildProcess, type SpawnSyncReturns } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { buildXrayTrojanTlsUri } from "../shared/xrayShare";
import { generateDeterministicXrayConfig, type XrayConfigInboundInput } from "./xrayConfigGenerator";

const execFileAsync = promisify(execFile);
const fixedXraySha256 = "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed";
const serverName = "tls.example.com";

type TlsMaterial = {
  certificateChainPem: string;
  privateKeyPem: string;
  leafFingerprintSha256: string;
};

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

async function stopProcess(process: ChildProcess | null) {
  if (!process || process.exitCode !== null) return;
  process.kill("SIGTERM");
  await Promise.race([
    new Promise((resolve) => process.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, 2_000)),
  ]);
  if (process.exitCode === null) process.kill("SIGKILL");
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

function buildServerConfig(port: number, password: string, material: TlsMaterial): string {
  const inbound = {
    id: 1,
    runtimeTag: "forwardx-trojan-raw-tls-e2e",
    listenAddress: "0.0.0.0",
    listenPort: port,
    protocol: "trojan",
    transport: "tcp",
    security: "tls",
    profileId: "TROJAN_RAW_TLS",
    specVersion: 1,
    specJson: "{}",
    realityServerName: serverName,
    tlsCertificateChainPem: material.certificateChainPem,
    tlsPrivateKeyPem: material.privateKeyPem,
    isEnabled: true,
    pendingDelete: false,
    clients: [{
      id: 1,
      credentialType: "PASSWORD",
      password,
      statsKey: "forwardx-trojan-raw-tls-e2e-client",
      isEnabled: true,
      pendingDelete: false,
      sortOrder: 0,
    }],
  } satisfies XrayConfigInboundInput;
  return generateDeterministicXrayConfig([inbound]).configJson;
}

function buildShare(port: number, password: string, pin: string) {
  return buildXrayTrojanTlsUri({
    profileId: "TROJAN_RAW_TLS",
    password,
    publicAddress: "127.0.0.1",
    listenPort: port,
    serverName,
    fingerprint: "chrome",
    leafFingerprintSha256: pin,
    displayName: "ForwardX Trojan RAW TLS",
  });
}

function buildClientConfig(uri: string, socksPort: number): string {
  const parsed = new URL(uri);
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
      protocol: "trojan",
      settings: {
        servers: [{ address: parsed.hostname, port: Number(parsed.port), password: parsed.username }],
      },
      streamSettings: {
        network: parsed.searchParams.get("type"),
        security: parsed.searchParams.get("security"),
        tlsSettings: {
          serverName: parsed.searchParams.get("sni"),
          fingerprint: parsed.searchParams.get("fp"),
          pinnedPeerCertSha256: parsed.searchParams.get("pcs"),
        },
      },
    }],
  };
  const serialized = `${JSON.stringify(config, null, 2)}\n`;
  for (const forbidden of ["allowInsecure", "shortId", "flow", "realitySettings"]) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
  return serialized;
}

function verifyConfig(binary: string, configPath: string) {
  const checked: SpawnSyncReturns<string> = spawnSync(binary, ["run", "-test", "-config", configPath], {
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
  uri: string;
  originPort: number;
  label: string;
  succeeds: boolean;
  logs: { value: string };
}) {
  const socksPort = await freePort();
  const configPath = path.join(input.directory, `${input.label}-client.json`);
  fs.writeFileSync(configPath, buildClientConfig(input.uri, socksPort), { mode: 0o600 });
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
      assert.equal(response.stdout, "forwardx-trojan-raw-tls-ok\n", input.logs.value);
    } else {
      await assert.rejects(request, `request unexpectedly accepted rejected certificate pin\n${input.logs.value}`);
    }
  } finally {
    await stopProcess(client);
  }
}

test("Trojan RAW TLS enforces share pins across managed certificate rotation", { timeout: 60_000 }, async (t) => {
  const binary = process.env.XRAY_TEST_BINARY;
  if (!binary) return t.skip("XRAY_TEST_BINARY is not configured");
  assert.equal(crypto.createHash("sha256").update(fs.readFileSync(binary)).digest("hex"), fixedXraySha256);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-trojan-raw-tls-e2e-"));
  const serverConfigPath = path.join(directory, "server.json");
  const serverPort = await freePort();
  const password = crypto.randomBytes(32).toString("base64url");
  const oldMaterial = createTlsMaterial(directory, "old");
  const newMaterial = createTlsMaterial(directory, "new");
  assert.notEqual(oldMaterial.leafFingerprintSha256, newMaterial.leafFingerprintSha256);
  const oldShare = buildShare(serverPort, password, oldMaterial.leafFingerprintSha256);
  const wrongPinShare = buildShare(serverPort, password, "0".repeat(64));
  const newShare = buildShare(serverPort, password, newMaterial.leafFingerprintSha256);
  assert.equal(oldShare.includes("allowInsecure"), false);
  const origin = http.createServer((_request, response) => response.end("forwardx-trojan-raw-tls-ok\n"));
  await new Promise<void>((resolve, reject) => {
    origin.once("error", reject);
    origin.listen(0, "127.0.0.1", resolve);
  });
  const originAddress = origin.address();
  if (!originAddress || typeof originAddress === "string") throw new Error("No origin test port");
  const logs = { value: "" };
  let server: ChildProcess | null = null;

  const startServer = async (material: TlsMaterial, label: string) => {
    const config = buildServerConfig(serverPort, password, material);
    for (const forbidden of ["certificateFile", "keyFile", directory, "shortId", "flow", "realitySettings"]) {
      assert.equal(config.includes(forbidden), false, forbidden);
    }
    fs.writeFileSync(serverConfigPath, config, { mode: 0o600 });
    verifyConfig(binary, serverConfigPath);
    server = spawn(binary, ["run", "-config", serverConfigPath], { stdio: ["ignore", "pipe", "pipe"] });
    captureLogs(server, label, logs);
    await waitForPort(serverPort, server);
  };

  try {
    await startServer(oldMaterial, "old-server");
    await requestThroughShare({ binary, directory, uri: oldShare, originPort: originAddress.port, label: "old-pin", succeeds: true, logs });
    await requestThroughShare({ binary, directory, uri: wrongPinShare, originPort: originAddress.port, label: "wrong-pin", succeeds: false, logs });

    await stopProcess(server);
    server = null;
    await startServer(newMaterial, "new-server");
    await requestThroughShare({ binary, directory, uri: oldShare, originPort: originAddress.port, label: "rotated-old-pin", succeeds: false, logs });
    await requestThroughShare({ binary, directory, uri: newShare, originPort: originAddress.port, label: "rotated-new-pin", succeeds: true, logs });
  } finally {
    await stopProcess(server);
    await new Promise<void>((resolve, reject) => origin.close((error) => error ? reject(error) : resolve()));
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
