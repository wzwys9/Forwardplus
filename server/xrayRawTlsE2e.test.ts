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

import { buildXrayVlessTlsUri } from "../shared/xrayShare";
import { generateDeterministicXrayConfig, type XrayConfigInboundInput } from "./xrayConfigGenerator";

const execFileAsync = promisify(execFile);
const fixedXraySha256 = "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed";
const serverName = "tls.example.com";

type RawTlsProfile = {
  id: "VLESS_RAW_TLS" | "VLESS_RAW_TLS_VISION";
  flow: "" | "xtls-rprx-vision";
};

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

async function startOrigin(): Promise<{ server: http.Server; port: number }> {
  const server = http.createServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/plain" });
    response.end("forwardx-raw-tls-ok\n");
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("No origin test port");
  return { server, port: address.port };
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

async function stopServer(server: http.Server | null) {
  if (!server) return;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
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

function buildServerConfig(input: {
  profile: RawTlsProfile;
  port: number;
  uuid: string;
  material: TlsMaterial;
}): string {
  const inbound = {
    id: 1,
    runtimeTag: input.profile.flow ? "forwardx-raw-tls-vision-e2e" : "forwardx-raw-tls-standard-e2e",
    listenAddress: "0.0.0.0",
    listenPort: input.port,
    protocol: "vless",
    transport: "tcp",
    security: "tls",
    profileId: input.profile.id,
    specVersion: 1,
    specJson: "{}",
    realityServerName: serverName,
    tlsCertificateChainPem: input.material.certificateChainPem,
    tlsPrivateKeyPem: input.material.privateKeyPem,
    isEnabled: true,
    pendingDelete: false,
    clients: [{
      id: 1,
      credentialType: "UUID",
      uuid: input.uuid,
      flow: input.profile.flow,
      statsKey: "forwardx-raw-tls-e2e-client",
      isEnabled: true,
      pendingDelete: false,
      sortOrder: 0,
    }],
  } satisfies XrayConfigInboundInput;
  return generateDeterministicXrayConfig([inbound]).configJson;
}

function buildShareUri(input: {
  profile: RawTlsProfile;
  port: number;
  uuid: string;
  pin: string;
}): string {
  return buildXrayVlessTlsUri({
    profileId: input.profile.id,
    uuid: input.uuid,
    publicAddress: "127.0.0.1",
    listenPort: input.port,
    serverName,
    fingerprint: "chrome",
    leafFingerprintSha256: input.pin,
    displayName: `ForwardX ${input.profile.id}`,
  });
}

function buildClientConfig(uri: string, socksPort: number): string {
  const parsed = new URL(uri);
  const flow = parsed.searchParams.get("flow");
  const user = {
    id: parsed.username,
    encryption: parsed.searchParams.get("encryption"),
    ...(flow ? { flow } : {}),
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
      protocol: "vless",
      settings: {
        vnext: [{ address: parsed.hostname, port: Number(parsed.port), users: [user] }],
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
  assert.equal(serialized.includes("allowInsecure"), false);
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
  const clientConfigPath = path.join(input.directory, `${input.label}-client.json`);
  fs.writeFileSync(clientConfigPath, buildClientConfig(input.uri, socksPort), { mode: 0o600 });
  verifyConfig(input.binary, clientConfigPath);
  const client = spawn(input.binary, ["run", "-config", clientConfigPath], { stdio: ["ignore", "pipe", "pipe"] });
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
      assert.equal(response.stdout, "forwardx-raw-tls-ok\n", input.logs.value);
    } else {
      await assert.rejects(request, `request unexpectedly accepted rejected certificate pin\n${input.logs.value}`);
    }
  } finally {
    await stopProcess(client);
  }
}

test("VLESS RAW standard and Vision TLS enforce share pins across managed certificate rotation", { timeout: 120_000 }, async (t) => {
  const binary = process.env.XRAY_TEST_BINARY;
  if (!binary) return t.skip("XRAY_TEST_BINARY is not configured");
  assert.equal(crypto.createHash("sha256").update(fs.readFileSync(binary)).digest("hex"), fixedXraySha256);

  for (const profile of [
    { id: "VLESS_RAW_TLS", flow: "" },
    { id: "VLESS_RAW_TLS_VISION", flow: "xtls-rprx-vision" },
  ] as const satisfies readonly RawTlsProfile[]) {
    await t.test(profile.id, { timeout: 55_000 }, async () => {
      const directory = fs.mkdtempSync(path.join(os.tmpdir(), `forwardx-${profile.id.toLowerCase()}-e2e-`));
      const serverConfigPath = path.join(directory, "server.json");
      const serverPort = await freePort();
      const uuid = crypto.randomUUID();
      const oldMaterial = createTlsMaterial(directory, "old");
      const newMaterial = createTlsMaterial(directory, "new");
      assert.notEqual(oldMaterial.leafFingerprintSha256, newMaterial.leafFingerprintSha256);
      const oldShare = buildShareUri({ profile, port: serverPort, uuid, pin: oldMaterial.leafFingerprintSha256 });
      const wrongPinShare = buildShareUri({ profile, port: serverPort, uuid, pin: "0".repeat(64) });
      const newShare = buildShareUri({ profile, port: serverPort, uuid, pin: newMaterial.leafFingerprintSha256 });
      assert.equal(new URL(oldShare).searchParams.get("flow"), profile.flow || null);
      assert.equal(oldShare.includes("allowInsecure"), false);
      const origin = await startOrigin();
      const logs = { value: "" };
      let server: ChildProcess | null = null;

      const startServer = async (material: TlsMaterial, label: string) => {
        const config = buildServerConfig({ profile, port: serverPort, uuid, material });
        assert.equal(config.includes("certificateFile"), false);
        assert.equal(config.includes("keyFile"), false);
        assert.equal(config.includes(directory), false);
        fs.writeFileSync(serverConfigPath, config, { mode: 0o600 });
        verifyConfig(binary, serverConfigPath);
        server = spawn(binary, ["run", "-config", serverConfigPath], { stdio: ["ignore", "pipe", "pipe"] });
        captureLogs(server, label, logs);
        await waitForPort(serverPort, server);
      };

      try {
        await startServer(oldMaterial, "old-server");
        await requestThroughShare({ binary, directory, uri: oldShare, originPort: origin.port, label: "old-pin", succeeds: true, logs });
        await requestThroughShare({ binary, directory, uri: wrongPinShare, originPort: origin.port, label: "wrong-pin", succeeds: false, logs });

        await stopProcess(server);
        server = null;
        await startServer(newMaterial, "new-server");
        await requestThroughShare({ binary, directory, uri: oldShare, originPort: origin.port, label: "rotated-old-pin", succeeds: false, logs });
        await requestThroughShare({ binary, directory, uri: newShare, originPort: origin.port, label: "rotated-new-pin", succeeds: true, logs });
      } finally {
        await stopProcess(server);
        await stopServer(origin.server);
        fs.rmSync(directory, { recursive: true, force: true });
      }
    });
  }
});
