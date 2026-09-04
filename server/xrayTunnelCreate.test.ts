import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("Tunnel create, persistence, desired config, DTO, and loopback boundary stay atomic", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-tunnel-create-"));
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const runtime = await load("server/dbRuntime.ts");
    const schema = await load("server/dbSchema.ts");
    const artifacts = await load("server/xrayArtifacts.ts");
    const ports = await load("server/xrayPortOperations.ts");
    const inboundService = await load("server/xrayInboundService.ts");
    const accessService = await load("server/xrayAccessService.ts");
    const queryService = await load("server/xrayQueryService.ts");
    const generator = await load("server/xrayConfigGenerator.ts");
    const heartbeat = await load("server/xrayHeartbeatState.ts");
    const profiles = await load("shared/xrayProfiles.ts");
    const versions = await load("shared/versions.ts");
    const { xrayRouter } = await load("server/routers/xray.ts");
    const nowIso = () => new Date().toISOString();
    const expectCode = async (promise, code) => assert.rejects(promise, (error) =>
      error?.cause?.code === code || error?.code === code || error?.message === code);

    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      const now = Math.floor(Date.now() / 1000);
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw(
        "INSERT INTO hosts (id, name, ip, ipv4, isOnline, lastHeartbeat, agentVersion, agentDistribution, userId) VALUES (10, 'edge', '8.8.8.8', '8.8.8.8', 1, ?, ?, 'forwardplus', 1)",
        [now, versions.AGENT_VERSION],
      );
      await runtime.executeRaw(
        "INSERT INTO xray_runtime_reports (hostId, capabilitySchemaVersion, supportedOS, supportedArch, supportsArtifactInstall, supportsPortProbe, supportsRealityScan) VALUES (10, 1, 'linux', 'amd64', 1, 1, 1)",
      );
      const artifact = artifacts.XRAY_ARTIFACT_MANIFEST.find((entry) => entry.arch === "amd64");
      await runtime.executeRaw(
        "INSERT INTO xray_artifacts (version, os, arch, packageFormat, storageKey, sha256, fileSize, status, source, verifiedAt) VALUES (?, ?, ?, ?, ?, ?, ?, 'VERIFIED', ?, ?)",
        [artifact.version, artifact.os, artifact.arch, artifact.packageFormat, artifact.storageKey, artifact.sha256, artifact.fileSize, artifact.source, now],
      );

      const operation = await ports.createXrayPortProbeOperation({
        hostId: 10, userId: 1, mode: "MANUAL", manualPort: 29611, network: "TCP",
      });
      const [task] = await ports.takeXrayPortProbeTasks(10, 1);
      await ports.completeXrayPortProbeTask(10, {
        schemaVersion: 1,
        taskId: task.taskId,
        type: "PORT_PROBE",
        status: "SUCCESS",
        startedAt: nowIso(),
        finishedAt: nowIso(),
        error: null,
        result: { ports: [{ port: 29611, available: true, errorCode: null }], observedAt: nowIso() },
      });
      const reservation = await ports.getXrayPortProbeOperationResult(operation.operationId, 1);
      const base = {
        hostId: 10,
        userId: 1,
        name: "Local database tunnel",
        portReservationId: reservation.reservationId,
        listenPort: 29611,
        profileId: "TUNNEL_TCP_LOCAL_NONE",
        initialAccessEntries: [],
      };

      assert.equal(profiles.findKnownXrayProfileById("TUNNEL_TCP_LOCAL_NONE").status, "AVAILABLE");
      assert.equal((await queryService.getXrayProfileCatalog()).find((profile) => profile.id === "TUNNEL_TCP_LOCAL_NONE").isAvailable, true);
      await expectCode(Promise.resolve().then(() => inboundService.createXrayInboundV2({
        ...base,
        publicAddress: "8.8.8.8",
        spec: { targetAddress: "DB.EXAMPLE.COM", targetPort: 5432 },
      })), "INVALID_CONFIG_INPUT");
      await expectCode(Promise.resolve().then(() => inboundService.createXrayInboundV2({
        ...base,
        spec: { targetAddress: "db.example.com", targetPort: 5432, followRedirect: true },
      })), "INVALID_CONFIG_INPUT");
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_inbounds"))[0].count, 0);

      const caller = xrayRouter.createCaller({
        req: { headers: {} },
        res: { clearCookie() {}, setHeader() {} },
        user: { id: 1, username: "admin", role: "admin", accountEnabled: true },
        authSession: null,
        authFailureReason: null,
      });
      await assert.rejects(caller.inbounds.createV2({
        ...base,
        spec: { targetAddress: "db.example.com", targetPort: 5432 },
        portMap: { 29611: 5432 },
      }), (error) => error?.code === "BAD_REQUEST");
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_inbounds"))[0].count, 0);

      const created = await inboundService.createXrayInboundV2({
        ...base,
        spec: { targetAddress: "DB.EXAMPLE.COM", targetPort: 5432 },
      });
      assert.equal(created.desiredGeneration, 1);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT profileId, specJson, publicAddress, listenAddress, protocol, transport, security, tlsCertificateId FROM xray_inbounds WHERE id = ?",
        [created.inboundId],
      ), [{
        profileId: "TUNNEL_TCP_LOCAL_NONE",
        specJson: '{"targetAddress":"db.example.com","targetPort":5432}',
        publicAddress: "127.0.0.1",
        listenAddress: "127.0.0.1",
        protocol: "tunnel",
        transport: "none",
        security: "none",
        tlsCertificateId: null,
      }]);
      for (const table of ["xray_clients", "xray_access_entries", "xray_inbound_secrets"]) {
        assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM " + table + " WHERE inboundId = ?", [created.inboundId]))[0].count, 0, table);
      }

      const generated = await generator.generateXrayHostConfig(10);
      const parsed = JSON.parse(generated.configJson);
      assert.deepEqual(parsed.inbounds, [{
        tag: parsed.inbounds[0].tag,
        listen: "127.0.0.1",
        port: 29611,
        protocol: "tunnel",
        settings: {
          address: "db.example.com",
          port: 5432,
          network: "tcp",
          followRedirect: false,
          userLevel: 0,
        },
      }]);
      assert.deepEqual(parsed.outbounds, [{ tag: "direct", protocol: "freedom" }]);
      assert.deepEqual(generated.expectedListeners, [{
        inboundId: created.inboundId,
        runtimeTag: parsed.inbounds[0].tag,
        network: "tcp",
        listenAddress: "127.0.0.1",
        port: 29611,
      }]);
      for (const forbidden of ["portMap", "rewriteAddress", "rewritePort", "allowedNetwork", "streamSettings", "routing", "sniffing"]) {
        assert.equal(generated.configJson.includes(forbidden), false, forbidden);
      }

      const detail = await queryService.getXrayInboundDetail(created.inboundId);
      assert.equal(detail.inbound.profileId, "TUNNEL_TCP_LOCAL_NONE");
      assert.equal(detail.inbound.publicAddress, "127.0.0.1");
      assert.equal(detail.inbound.listenAddress, "127.0.0.1");
      assert.equal(detail.inbound.tunnelTargetAddress, "db.example.com");
      assert.equal(detail.inbound.tunnelTargetPort, 5432);
      assert.deepEqual(detail.clients, []);
      assert.deepEqual(detail.accessEntries, []);
      await expectCode(accessService.createXrayAccessEntryForInbound({
        inboundId: created.inboundId, userId: 1, name: "forbidden", expectedGeneration: 1,
      }), "INVALID_CONFIG_INPUT");

      const desired = await heartbeat.buildXrayHeartbeatDesiredState(10);
      assert.equal(desired.generation, 1);
      assert.equal(desired.configHash, generated.configHash);
      assert.deepEqual(desired.expectedListeners, generated.expectedListeners);

      await runtime.executeRaw("UPDATE xray_inbounds SET publicAddress = '0.0.0.0' WHERE id = ?", [created.inboundId]);
      await expectCode(generator.generateXrayHostConfig(10), "INVALID_CONFIG_INPUT");
      await runtime.executeRaw("UPDATE xray_inbounds SET publicAddress = '127.0.0.1', listenAddress = '0.0.0.0' WHERE id = ?", [created.inboundId]);
      await expectCode(generator.generateXrayHostConfig(10), "INVALID_CONFIG_INPUT");
      assert.equal((await runtime.queryRaw("SELECT desiredGeneration FROM xray_host_deployments WHERE hostId = 10"))[0].desiredGeneration, 1);
    } finally {
      ports.clearXrayPortOperationStateForTest();
      await runtime.closeDatabase();
    }
  `;

  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        DATABASE_TYPE: "sqlite",
        FORWARDX_TEST_DB: path.join(directory, "panel.db"),
        JWT_SECRET: "xray-tunnel-create-test-secret",
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
