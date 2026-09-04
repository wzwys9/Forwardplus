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

import { compileXrayInlineTlsSecurity } from "./xrayTransportSecurityCompiler";

const execFileAsync = promisify(execFile);

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
    response.end("forwardx-inline-tls-ok\n");
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

test("managed inline TLS carries a real local request through fixed Xray", { timeout: 30_000 }, async (t) => {
  const binary = process.env.XRAY_TEST_BINARY;
  if (!binary) return t.skip("XRAY_TEST_BINARY is not configured");

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-tls-e2e-"));
  const certificatePath = path.join(directory, "certificate.pem");
  const privateKeyPath = path.join(directory, "private-key.pem");
  const serverConfigPath = path.join(directory, "server.json");
  const clientConfigPath = path.join(directory, "client.json");
  const serverPort = await freePort();
  const socksPort = await freePort();
  const uuid = crypto.randomUUID();
  let origin: http.Server | null = null;
  let serverProcess: ChildProcess | null = null;
  let clientProcess: ChildProcess | null = null;
  let runtimeLogs = "";
  const captureLogs = (process: ChildProcess, label: string) => {
    for (const stream of [process.stdout, process.stderr]) {
      stream?.on("data", (chunk) => {
        runtimeLogs = `${runtimeLogs}${label}: ${String(chunk)}`.slice(-16_384);
      });
    }
  };

  try {
    execFileSync("openssl", [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
      "-subj", "/CN=tls.example.com", "-keyout", privateKeyPath, "-out", certificatePath,
      "-addext", "basicConstraints=critical,CA:FALSE",
      "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
      "-addext", "extendedKeyUsage=serverAuth",
      "-addext", "subjectAltName=DNS:tls.example.com",
    ], { stdio: "ignore" });

    const certificatePem = fs.readFileSync(certificatePath, "utf8");
    const privateKeyPem = fs.readFileSync(privateKeyPath, "utf8");
    const compiledTls = compileXrayInlineTlsSecurity({
      certificateChainPem: certificatePem,
      privateKeyPem,
    });
    const certificateHash = crypto.createHash("sha256")
      .update(new crypto.X509Certificate(certificatePem).raw)
      .digest("hex");
    const startedOrigin = await startOrigin();
    origin = startedOrigin.server;

    const serverConfig = {
      log: { loglevel: "warning" },
      inbounds: [{
        tag: "forwardx-tls-e2e",
        listen: "127.0.0.1",
        port: serverPort,
        protocol: "vless",
        settings: {
          clients: [{ id: uuid }],
          decryption: "none",
        },
        streamSettings: { network: "tcp", ...compiledTls },
      }],
      outbounds: [{ tag: "direct", protocol: "freedom" }],
    };
    const clientConfig = {
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
          vnext: [{
            address: "127.0.0.1",
            port: serverPort,
            users: [{ id: uuid, encryption: "none" }],
          }],
        },
        streamSettings: {
          network: "tcp",
          security: "tls",
          tlsSettings: {
            serverName: "tls.example.com",
            fingerprint: "chrome",
            pinnedPeerCertSha256: certificateHash,
          },
        },
      }],
    };
    const serializedServerConfig = JSON.stringify(serverConfig, null, 2);
    const serializedClientConfig = JSON.stringify(clientConfig, null, 2);
    assert.equal(serializedServerConfig.includes("certificateFile"), false);
    assert.equal(serializedServerConfig.includes("keyFile"), false);
    assert.equal(serializedServerConfig.includes(directory), false);
    assert.equal(serializedClientConfig.includes("allowInsecure"), false);
    fs.writeFileSync(serverConfigPath, `${serializedServerConfig}\n`, { mode: 0o600 });
    fs.writeFileSync(clientConfigPath, `${serializedClientConfig}\n`, { mode: 0o600 });

    for (const configPath of [serverConfigPath, clientConfigPath]) {
      const checked: SpawnSyncReturns<string> = spawnSync(binary, ["run", "-test", "-config", configPath], {
        encoding: "utf8",
        timeout: 10_000,
      });
      assert.equal(checked.status, 0, `${checked.stdout}\n${checked.stderr}`);
    }

    serverProcess = spawn(binary, ["run", "-config", serverConfigPath], { stdio: ["ignore", "pipe", "pipe"] });
    captureLogs(serverProcess, "server");
    await waitForPort(serverPort, serverProcess);
    clientProcess = spawn(binary, ["run", "-config", clientConfigPath], { stdio: ["ignore", "pipe", "pipe"] });
    captureLogs(clientProcess, "client");
    await waitForPort(socksPort, clientProcess);
    await new Promise((resolve) => setTimeout(resolve, 250));

    try {
      const request = await execFileAsync("curl", [
        "--silent", "--show-error", "--fail", "--max-time", "12", "--noproxy", "",
        "--socks5-hostname", `127.0.0.1:${socksPort}`,
        `http://127.0.0.1:${startedOrigin.port}/probe`,
      ], { encoding: "utf8", timeout: 15_000 });
      assert.equal(request.stdout, "forwardx-inline-tls-ok\n");
    } catch (error) {
      throw new Error(`Local request through inline TLS failed: ${String(error)}\n${runtimeLogs}`, { cause: error });
    }
  } finally {
    await stopProcess(clientProcess);
    await stopProcess(serverProcess);
    await stopServer(origin);
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
