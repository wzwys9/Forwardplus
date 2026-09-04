import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawn, spawnSync, type ChildProcess, type SpawnSyncReturns } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { generateDeterministicXrayConfig, type XrayConfigInboundInput } from "./xrayConfigGenerator";

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

async function stop(process: ChildProcess | null) {
  if (!process || process.exitCode !== null) return;
  process.kill("SIGTERM");
  await Promise.race([
    new Promise((resolve) => process.once("exit", resolve)),
    new Promise((resolve) => setTimeout(resolve, 2_000)),
  ]);
  if (process.exitCode === null) process.kill("SIGKILL");
}

test("VLESS gRPC Reality carries a real HTTPS request through fixed Xray", { timeout: 30_000 }, async (t) => {
  const binary = process.env.XRAY_TEST_BINARY;
  if (!binary) return t.skip("XRAY_TEST_BINARY is not configured");
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-grpc-e2e-"));
  const serverConfigPath = path.join(directory, "server.json");
  const clientConfigPath = path.join(directory, "client.json");
  const serverPort = await freePort();
  const socksPort = await freePort();
  const uuid = crypto.randomUUID();
  const shortId = crypto.randomBytes(8).toString("hex");
  const keyPair = crypto.generateKeyPairSync("x25519");
  const privateKey = String(keyPair.privateKey.export({ format: "jwk" }).d ?? "");
  const publicKey = String(keyPair.publicKey.export({ format: "jwk" }).x ?? "");
  const inbound: XrayConfigInboundInput = {
    id: 1,
    runtimeTag: "forwardx-grpc-e2e",
    listenAddress: "0.0.0.0",
    listenPort: serverPort,
    protocol: "vless",
    transport: "grpc",
    security: "reality",
    profileId: "VLESS_GRPC_REALITY",
    specVersion: 1,
    specJson: '{"serviceName":"forwardx-grpc"}',
    realityTargetHost: "www.cloudflare.com",
    realityTargetPort: 443,
    realityServerName: "www.cloudflare.com",
    realityPrivateKey: privateKey,
    isEnabled: true,
    pendingDelete: false,
    clients: [{
      id: 1,
      uuid,
      shortId,
      statsKey: "forwardx-grpc-e2e-client",
      flow: "",
      isEnabled: true,
      pendingDelete: false,
      sortOrder: 0,
    }],
  };
  fs.writeFileSync(serverConfigPath, generateDeterministicXrayConfig([inbound]).configJson, { mode: 0o600 });
  fs.writeFileSync(clientConfigPath, `${JSON.stringify({
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
      settings: { vnext: [{ address: "127.0.0.1", port: serverPort, users: [{ id: uuid, encryption: "none" }] }] },
      streamSettings: {
        network: "grpc",
        security: "reality",
        realitySettings: {
          serverName: "www.cloudflare.com",
          fingerprint: "chrome",
          publicKey,
          shortId,
          spiderX: "/",
        },
        grpcSettings: { serviceName: "forwardx-grpc", multiMode: false },
      },
    }],
  }, null, 2)}\n`, { mode: 0o600 });

  let server: ChildProcess | null = null;
  let client: ChildProcess | null = null;
  let runtimeLogs = "";
  const captureLogs = (process: ChildProcess, label: string) => {
    for (const stream of [process.stdout, process.stderr]) {
      stream?.on("data", (chunk) => {
        runtimeLogs = `${runtimeLogs}${label}: ${String(chunk)}`.slice(-16_384);
      });
    }
  };
  try {
    for (const configPath of [serverConfigPath, clientConfigPath]) {
      const checked: SpawnSyncReturns<string> = spawnSync(binary, ["run", "-test", "-config", configPath], { encoding: "utf8", timeout: 10_000 });
      assert.equal(checked.status, 0, `${checked.stdout}\n${checked.stderr}`);
    }
    server = spawn(binary, ["run", "-config", serverConfigPath], { stdio: ["ignore", "pipe", "pipe"] });
    captureLogs(server, "server");
    await waitForPort(serverPort, server);
    client = spawn(binary, ["run", "-config", clientConfigPath], { stdio: ["ignore", "pipe", "pipe"] });
    captureLogs(client, "client");
    await waitForPort(socksPort, client);
    await new Promise((resolve) => setTimeout(resolve, 250));
    const request = spawnSync("curl", [
      "--silent", "--show-error", "--fail", "--max-time", "12",
      "--socks5-hostname", `127.0.0.1:${socksPort}`,
      "https://www.cloudflare.com/cdn-cgi/trace",
    ], { encoding: "utf8", timeout: 15_000 });
    assert.equal(request.status, 0, `${request.stderr || request.stdout}\n${runtimeLogs}`);
    assert.match(request.stdout, /^fl=/m);
  } finally {
    await stop(client);
    await stop(server);
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
