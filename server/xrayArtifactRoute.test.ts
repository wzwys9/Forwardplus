import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("the authenticated Xray artifact route serves only the verified host platform without leaking tokens", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-artifact-route-"));
  const databasePath = path.join(directory, "route.db");
  const dataDirectory = path.join(directory, "data");
  const script = String.raw`
    import assert from "node:assert/strict";
    import crypto from "node:crypto";
    import fs from "node:fs/promises";
    import http from "node:http";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    import express from "express";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const artifacts = await import(moduleUrl("server/xrayArtifacts.ts"));
    const route = await import(moduleUrl("server/xrayArtifactRoute.ts"));
    const auth = await import(moduleUrl("server/agentAuth.ts"));
    const registeredRoutes = await import(moduleUrl("server/agentRoutes.ts"));
    const token = "artifact-agent-super-secret-token";
    const fixture = Buffer.from("verified route artifact fixture", "utf8");
    const fixtureSha256 = crypto.createHash("sha256").update(fixture).digest("hex");
    const fixturePath = path.join(process.env.FORWARDX_TEST_DATA, "route-fixture.zip");
    const logs = [];
    let server;
    let registeredServer;
    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw(
        "INSERT INTO hosts (id, name, ip, userId, agentToken) VALUES (7, 'artifact-edge', '192.0.2.7', 1, ?)",
        [token],
      );
      await runtime.executeRaw(
        "INSERT INTO xray_runtime_reports (hostId, capabilitySchemaVersion, supportedOS, supportedArch) VALUES (7, 1, 'linux', 'amd64')",
      );
      await fs.mkdir(path.dirname(fixturePath), { recursive: true });
      await fs.writeFile(fixturePath, fixture);

      const manifest = artifacts.XRAY_ARTIFACT_MANIFEST[0];
      const invalidArtifactId = await runtime.insertAndGetId("xray_artifacts", {
        version: manifest.version,
        os: manifest.os,
        arch: manifest.arch,
        packageFormat: manifest.packageFormat,
        storageKey: manifest.storageKey,
        sha256: manifest.sha256,
        fileSize: manifest.fileSize,
        status: "INVALID",
        source: manifest.source,
        verifiedAt: null,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      const resolveArtifact = async (input) => {
        if (input.artifactId !== 999) return artifacts.resolveVerifiedXrayArtifactDownload(input);
        if (input.os !== "linux" || input.arch !== "amd64") {
          throw new artifacts.XrayArtifactError("ARTIFACT_PLATFORM_MISMATCH");
        }
        return {
          artifactId: 999,
          version: "v26.3.27",
          os: "linux",
          arch: "amd64",
          archiveName: "Xray-linux-64.zip",
          filePath: fixturePath,
          fileSize: fixture.byteLength,
          sha256: fixtureSha256,
        };
      };

      const app = express();
      route.registerAgentXrayArtifactRoute(app, {
        dataDirectory: process.env.FORWARDX_TEST_DATA,
        resolveArtifact,
        log: (level, message) => logs.push({ level, message }),
      });
      server = http.createServer(app);
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", resolve);
      });
      const address = server.address();
      assert.ok(address && typeof address === "object");
      const baseUrl = "http://127.0.0.1:" + address.port;
      const request = (artifactId, options = {}) => fetch(
        baseUrl + "/api/agent/artifacts/xray/" + artifactId + (options.query || ""),
        {
          headers: {
            ...(options.token === null ? {} : { Authorization: "Bearer " + (options.token || token) }),
            ...(options.os === null ? {} : { "X-ForwardX-Xray-OS": options.os || "linux" }),
            ...(options.arch === null ? {} : { "X-ForwardX-Xray-Arch": options.arch || "amd64" }),
            ...(options.range ? { Range: options.range } : {}),
          },
        },
      );

      const unauthorized = await request(999, { token: "wrong-token" });
      assert.equal(unauthorized.status, 401);
      assert.equal(unauthorized.headers.get(auth.AGENT_AUTH_RESULT_HEADER), auth.AGENT_AUTH_RESULT_REJECTED);
      assert.equal((await unauthorized.text()).includes("wrong-token"), false);

      for (const options of [{ os: null }, { arch: null }, { os: "windows" }, { arch: "riscv64" }]) {
        const response = await request(999, options);
        assert.equal(response.status, 400);
        assert.equal(response.headers.get(auth.AGENT_AUTH_RESULT_HEADER), auth.AGENT_AUTH_RESULT_ACCEPTED);
      }

      const traversalQuery = await request(999, { query: "?path=../../etc/passwd&url=https://attacker.invalid/xray.zip" });
      assert.equal(traversalQuery.status, 400);
      const traversalPath = await request("..%2F..%2Fetc%2Fpasswd");
      assert.equal([400, 404].includes(traversalPath.status), true);

      const invalid = await request(invalidArtifactId);
      assert.equal(invalid.status, 404);
      assert.equal(invalid.headers.get(auth.AGENT_AUTH_RESULT_HEADER), auth.AGENT_AUTH_RESULT_ACCEPTED);

      await runtime.executeRaw(
        "UPDATE xray_artifacts SET storageKey = '/tmp/arbitrary.zip', status = 'VERIFIED', verifiedAt = ? WHERE id = ?",
        [new Date(), invalidArtifactId],
      );
      const tamperedPath = await request(invalidArtifactId);
      assert.equal(tamperedPath.status, 404);
      assert.equal((await tamperedPath.text()).includes("/tmp/arbitrary.zip"), false);
      const repaired = (await runtime.queryRaw("SELECT storageKey, status FROM xray_artifacts WHERE id = ?", [invalidArtifactId]))[0];
      assert.deepEqual(repaired, { storageKey: manifest.storageKey, status: "INVALID" });

      const mismatch = await request(invalidArtifactId, { arch: "arm64" });
      assert.equal(mismatch.status, 403);
      assert.equal(mismatch.headers.get(auth.AGENT_AUTH_RESULT_HEADER), auth.AGENT_AUTH_RESULT_ACCEPTED);

      const spoofedPlatform = await request(999, { arch: "arm64" });
      assert.equal(spoofedPlatform.status, 403);

      const ranged = await request(999, { range: "bytes=0-3" });
      assert.equal(ranged.status, 416);
      assert.equal(ranged.headers.get("accept-ranges"), "none");

      const success = await request(999);
      assert.equal(success.status, 200);
      assert.equal(success.headers.get(auth.AGENT_AUTH_RESULT_HEADER), auth.AGENT_AUTH_RESULT_ACCEPTED);
      assert.equal(success.headers.get("content-type"), "application/octet-stream");
      assert.equal(success.headers.get("content-length"), String(fixture.byteLength));
      assert.equal(success.headers.get("etag"), '"sha256:' + fixtureSha256 + '"');
      assert.equal(success.headers.get("x-forwardx-artifact-sha256"), fixtureSha256);
      assert.equal(success.headers.get("x-forwardx-artifact-version"), "v26.3.27");
      assert.equal(success.headers.get("x-forwardx-artifact-os"), "linux");
      assert.equal(success.headers.get("x-forwardx-artifact-arch"), "amd64");
      assert.equal(success.headers.get("cache-control"), "private, no-store, max-age=0");
      assert.equal(success.headers.get("accept-ranges"), "none");
      assert.match(success.headers.get("content-disposition") || "", /^attachment; filename="Xray-linux-64\.zip"$/);
      assert.deepEqual(Buffer.from(await success.arrayBuffer()), fixture);

      const serializedLogs = JSON.stringify(logs);
      assert.equal(serializedLogs.includes(token), false);
      assert.equal(serializedLogs.includes("wrong-token"), false);
      assert.match(serializedLogs, /host=7/);
      assert.match(serializedLogs, /artifact=999/);
      assert.match(serializedLogs, /bytes=/);

      const registeredApp = express();
      registeredApp.use(registeredRoutes.agentRouter);
      registeredServer = http.createServer(registeredApp);
      await new Promise((resolve, reject) => {
        registeredServer.once("error", reject);
        registeredServer.listen(0, "127.0.0.1", resolve);
      });
      const registeredAddress = registeredServer.address();
      assert.ok(registeredAddress && typeof registeredAddress === "object");
      const registeredResponse = await fetch(
        "http://127.0.0.1:" + registeredAddress.port + "/api/agent/artifacts/xray/" + invalidArtifactId,
        { headers: {
          Authorization: "Bearer unregistered-artifact-route-token",
          "X-ForwardX-Xray-OS": "linux",
          "X-ForwardX-Xray-Arch": "amd64",
        } },
      );
      assert.equal(registeredResponse.status, 401);
      assert.equal(registeredResponse.headers.get(auth.AGENT_AUTH_RESULT_HEADER), auth.AGENT_AUTH_RESULT_REJECTED);
    } finally {
      if (registeredServer) await new Promise((resolve) => registeredServer.close(resolve));
      if (server) await new Promise((resolve) => server.close(resolve));
      await runtime.closeDatabase();
    }
  `;
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        DATABASE_TYPE: "sqlite",
        FORWARDX_TEST_DB: databasePath,
        FORWARDX_TEST_DATA: dataDirectory,
        JWT_SECRET: "xray-artifact-route-test-secret",
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
