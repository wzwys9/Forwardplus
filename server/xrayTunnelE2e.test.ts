import assert from "node:assert/strict";
import crypto from "node:crypto";
import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import dgram from "node:dgram";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { generateDeterministicXrayConfig, type XrayConfigInboundInput } from "./xrayConfigGenerator";

const fixedXraySha256 = "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed";

async function freeTcpUdpPort(): Promise<number> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const port = await new Promise<number>((resolve, reject) => {
      const server = net.createServer();
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        const address = server.address();
        if (!address || typeof address === "string") return reject(new Error("No TCP test port"));
        server.close((error) => error ? reject(error) : resolve(address.port));
      });
    });
    const udpAvailable = await new Promise<boolean>((resolve) => {
      const socket = dgram.createSocket("udp4");
      socket.once("error", () => resolve(false));
      socket.bind(port, "127.0.0.1", () => socket.close(() => resolve(true)));
    });
    if (udpAvailable) return port;
  }
  throw new Error("No shared TCP/UDP test port");
}

async function waitForPort(port: number, process: ChildProcess) {
  const deadline = Date.now() + 10_000;
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

async function canBindUdp(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = dgram.createSocket("udp4");
    socket.once("error", () => resolve(false));
    socket.bind(port, "127.0.0.1", () => socket.close(() => resolve(true)));
  });
}

async function requestThroughTunnel(port: number): Promise<{ statusCode: number; body: string }> {
  return new Promise((resolve, reject) => {
    const request = http.get({ host: "127.0.0.1", port, path: "/tunnel-check", timeout: 3_000 }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { body += chunk; });
      response.on("end", () => resolve({ statusCode: response.statusCode ?? 0, body }));
    });
    request.once("timeout", () => request.destroy(new Error("Tunnel request timed out")));
    request.once("error", reject);
  });
}

async function stopProcess(process: ChildProcess) {
  if (process.exitCode !== null) return;
  process.kill("SIGTERM");
  await Promise.race([
    new Promise<void>((resolve) => process.once("exit", () => resolve())),
    new Promise<void>((resolve) => setTimeout(resolve, 3_000)),
  ]);
  if (process.exitCode === null) process.kill("SIGKILL");
}

test("loopback Tunnel forwards one TCP target with fixed Xray and never binds UDP", { timeout: 30_000 }, async (t) => {
  const binary = process.env.XRAY_TEST_BINARY;
  if (!binary) return t.skip("XRAY_TEST_BINARY is not configured");
  assert.equal(crypto.createHash("sha256").update(fs.readFileSync(binary)).digest("hex"), fixedXraySha256);

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-tunnel-e2e-"));
  const tunnelPort = await freeTcpUdpPort();
  const origin = http.createServer((_request, response) => response.end("forwardx-tunnel-ok\n"));
  await new Promise<void>((resolve, reject) => {
    origin.once("error", reject);
    origin.listen(0, "127.0.0.1", resolve);
  });
  const originAddress = origin.address();
  if (!originAddress || typeof originAddress === "string") throw new Error("No origin test port");

  const inbound: XrayConfigInboundInput = {
    id: 1,
    runtimeTag: "forwardx-tunnel-e2e",
    listenAddress: "127.0.0.1",
    listenPort: tunnelPort,
    protocol: "tunnel",
    transport: "none",
    security: "none",
    profileId: "TUNNEL_TCP_LOCAL_NONE",
    specVersion: 1,
    specJson: JSON.stringify({ targetAddress: "127.0.0.1", targetPort: originAddress.port }),
    isEnabled: true,
    pendingDelete: false,
    clients: [],
  };
  const generated = generateDeterministicXrayConfig([inbound]);
  assert.deepEqual(generated.expectedListeners, [{
    inboundId: 1,
    runtimeTag: "forwardx-tunnel-e2e",
    network: "tcp",
    listenAddress: "127.0.0.1",
    port: tunnelPort,
  }]);
  const compiled = JSON.parse(generated.configJson);
  assert.deepEqual(compiled.inbounds[0], {
    tag: "forwardx-tunnel-e2e",
    listen: "127.0.0.1",
    port: tunnelPort,
    protocol: "tunnel",
    settings: {
      address: "127.0.0.1",
      port: originAddress.port,
      network: "tcp",
      followRedirect: false,
      userLevel: 0,
    },
  });
  assert.deepEqual(compiled.outbounds, [{ tag: "direct", protocol: "freedom" }]);
  assert.throws(() => generateDeterministicXrayConfig([{ ...inbound, listenAddress: "0.0.0.0" }]));

  const configPath = path.join(directory, "server.json");
  fs.writeFileSync(configPath, generated.configJson, { mode: 0o600 });
  execFileSync(binary, ["run", "-test", "-config", configPath], { encoding: "utf8", timeout: 15_000 });
  const server = spawn(binary, ["run", "-config", configPath], { stdio: ["ignore", "pipe", "pipe"] });
  let logs = "";
  server.stdout?.on("data", (chunk) => { logs += String(chunk); });
  server.stderr?.on("data", (chunk) => { logs += String(chunk); });
  try {
    await waitForPort(tunnelPort, server);
    assert.equal(await canBindUdp(tunnelPort), true, "Tunnel must not bind UDP");
    assert.deepEqual(await requestThroughTunnel(tunnelPort), { statusCode: 200, body: "forwardx-tunnel-ok\n" });
    await new Promise<void>((resolve, reject) => origin.close((error) => error ? reject(error) : resolve()));
    await assert.rejects(requestThroughTunnel(tunnelPort));
  } catch (error) {
    assert.fail(`${error instanceof Error ? error.stack : String(error)}\n${logs}`);
  } finally {
    await stopProcess(server);
    if (origin.listening) await new Promise<void>((resolve) => origin.close(() => resolve()));
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
