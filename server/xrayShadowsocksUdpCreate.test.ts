import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("Shadowsocks TCP+UDP creation atomically consumes two reservations", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-shadowsocks-udp-create-"));
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
    const secrets = await load("server/xraySecretCrypto.ts");
    const versions = await load("shared/versions.ts");
    const { xrayRouter } = await load("server/routers/xray.ts");
    const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
    const nowIso = () => new Date().toISOString();
    const expectCode = async (promise, code) => assert.rejects(promise, (error) => error?.code === code);
    const reserve = async (port, network) => {
      const operation = await ports.createXrayPortProbeOperation({
        hostId: 10, userId: 1, mode: "MANUAL", manualPort: port, network,
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
        result: {
          ports: [{ port, available: true, errorCode: null }],
          observedAt: nowIso(),
        },
      });
      return ports.getXrayPortProbeOperationResult(operation.operationId, 1);
    };

    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      const now = Math.floor(Date.now() / 1000);
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw(
        "INSERT INTO hosts (id, name, ip, ipv4, isOnline, lastHeartbeat, agentVersion, userId) VALUES (10, 'edge', '8.8.8.8', '8.8.8.8', 1, ?, ?, 1)",
        [now, versions.AGENT_VERSION],
      );
      await runtime.executeRaw(
        "INSERT INTO xray_runtime_reports (hostId, capabilitySchemaVersion, supportedOS, supportedArch, supportsArtifactInstall, supportsPortProbe, supportsUdpPortProbe, supportsUdpListenerReadiness, supportsRealityScan) VALUES (10, 1, 'linux', 'amd64', 1, 1, 1, 1, 1)",
      );
      const artifact = artifacts.XRAY_ARTIFACT_MANIFEST.find((entry) => entry.arch === "amd64");
      await runtime.executeRaw(
        "INSERT INTO xray_artifacts (version, os, arch, packageFormat, storageKey, sha256, fileSize, status, source, verifiedAt) VALUES (?, ?, ?, ?, ?, ?, ?, 'VERIFIED', ?, ?)",
        [artifact.version, artifact.os, artifact.arch, artifact.packageFormat, artifact.storageKey, artifact.sha256, artifact.fileSize, artifact.source, now],
      );

      const tcp = await reserve(29301, "TCP");
      const udp = await reserve(29301, "UDP");
      const input = {
        hostId: 10,
        userId: 1,
        name: "Shadowsocks TCP UDP",
        publicAddress: "8.8.8.8",
        portReservations: { tcp: tcp.reservationId, udp: udp.reservationId },
        listenPort: 29301,
        profileId: "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE",
        spec: {},
        initialAccessEntries: [{ name: "phone" }, { name: "laptop" }],
      };
      const { userId: _userId, ...routedInput } = input;
      const caller = xrayRouter.createCaller({
        req: { headers: {} },
        res: { clearCookie() {}, setHeader() {} },
        user: { id: 1, username: "admin", role: "admin", accountEnabled: true },
        authSession: null,
        authFailureReason: null,
      });
      await assert.rejects(() => caller.inbounds.createV2({
        ...routedInput,
        portReservationId: tcp.reservationId,
      }), (error) => error?.code === "BAD_REQUEST" && error?.message !== "INVALID_CONFIG_INPUT");

      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsUdpListenerReadiness = 0 WHERE hostId = 10");
      await expectCode(inboundService.createXrayInboundV2(input), "UDP_CAPABILITY_REQUIRED");
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_inbounds"))[0].count, 0);
      assert.equal(ports.validateXrayPortReservation({ reservationId: tcp.reservationId, hostId: 10, userId: 1, port: 29301, network: "TCP" }).network, "tcp");
      assert.equal(ports.validateXrayPortReservation({ reservationId: udp.reservationId, hostId: 10, userId: 1, port: 29301, network: "UDP" }).network, "udp");

      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsUdpListenerReadiness = 1 WHERE hostId = 10");
      await expectCode(inboundService.createXrayInboundV2({
        ...input,
        portReservationId: tcp.reservationId,
      }), "INVALID_CONFIG_INPUT");
      assert.equal(ports.validateXrayPortReservation({ reservationId: tcp.reservationId, hostId: 10, userId: 1, port: 29301, network: "TCP" }).network, "tcp");
      assert.equal(ports.validateXrayPortReservation({ reservationId: udp.reservationId, hostId: 10, userId: 1, port: 29301, network: "UDP" }).network, "udp");

      const created = await inboundService.createXrayInboundV2(input);
      assert.equal(created.desiredGeneration, 1);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT profileId, specJson, protocol, transport, security FROM xray_inbounds WHERE id = ?",
        [created.inboundId],
      ), [{
        profileId: "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE",
        specJson: "{}",
        protocol: "shadowsocks",
        transport: "tcp",
        security: "none",
      }]);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT credentialType, settingsJson FROM xray_access_entries WHERE inboundId = ? ORDER BY id",
        [created.inboundId],
      ), [
        { credentialType: "SHADOWSOCKS_KEY", settingsJson: '{"schemaVersion":1}' },
        { credentialType: "SHADOWSOCKS_KEY", settingsJson: '{"schemaVersion":1}' },
      ]);
      assert.equal((await runtime.queryRaw(
        "SELECT COUNT(*) count FROM xray_inbound_secrets WHERE inboundId = ? AND kind = 'SHADOWSOCKS_SERVER_KEY'",
        [created.inboundId],
      ))[0].count, 1);
      assert.equal((await runtime.queryRaw(
        "SELECT COUNT(*) count FROM xray_access_secrets s JOIN xray_access_entries a ON a.id = s.accessEntryId WHERE a.inboundId = ? AND s.kind = 'SHADOWSOCKS_KEY'",
        [created.inboundId],
      ))[0].count, 2);

      const generated = await generator.generateXrayHostConfig(10, keyring);
      assert.deepEqual(generated.expectedListeners.map(({ network, port }) => ({ network, port })), [
        { network: "tcp", port: 29301 },
        { network: "udp", port: 29301 },
      ]);
      assert.equal(JSON.parse(generated.configJson).inbounds[0].settings.network, "tcp,udp");
      await expectCode(Promise.resolve().then(() => ports.validateXrayPortReservation({ reservationId: tcp.reservationId, hostId: 10, userId: 1, port: 29301, network: "TCP" })), "PORT_RESERVATION_EXPIRED");
      await expectCode(Promise.resolve().then(() => ports.validateXrayPortReservation({ reservationId: udp.reservationId, hostId: 10, userId: 1, port: 29301, network: "UDP" })), "PORT_RESERVATION_EXPIRED");

      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsUdpPortProbe = 0 WHERE hostId = 10");
      await expectCode(accessService.createXrayAccessEntryForInbound({
        inboundId: created.inboundId, userId: 1, name: "blocked", expectedGeneration: 1,
      }), "UDP_CAPABILITY_REQUIRED");
      await expectCode(inboundService.updateXrayInbound({
        id: created.inboundId, userId: 1, name: "blocked", expectedGeneration: 1,
      }), "UDP_CAPABILITY_REQUIRED");
      assert.equal((await runtime.queryRaw("SELECT desiredGeneration FROM xray_host_deployments WHERE hostId = 10"))[0].desiredGeneration, 1);

      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsUdpPortProbe = 1 WHERE hostId = 10");
      const added = await accessService.createXrayAccessEntryForInbound({
        inboundId: created.inboundId, userId: 1, name: "desktop", expectedGeneration: 1,
      });
      assert.equal(added.desiredGeneration, 2);
      const share = await accessService.getXrayAccessEntryShare(added.accessEntryId, "SHADOWSOCKS_URI");
      assert.match(share.uri, /^ss:\/\/2022-blake3-aes-256-gcm:/);
      await runtime.executeRaw(
        "UPDATE xray_access_entries SET isEnabled = 0 WHERE inboundId = ? AND id <> ?",
        [created.inboundId, added.accessEntryId],
      );
      await expectCode(accessService.updateXrayAccessEntryForInbound({
        id: added.accessEntryId, userId: 1, isEnabled: false, expectedGeneration: 2,
      }), "LAST_ACTIVE_ACCESS_REQUIRED");
      assert.equal((await runtime.queryRaw("SELECT desiredGeneration FROM xray_host_deployments WHERE hostId = 10"))[0].desiredGeneration, 2);
      await expectCode(inboundService.updateXrayInbound({
        id: created.inboundId, userId: 1, listenPort: 29302, portReservationId: "missing", expectedGeneration: 2,
      }), "INVALID_CONFIG_INPUT");
      const renamed = await inboundService.updateXrayInbound({
        id: created.inboundId, userId: 1, name: "Shadowsocks dual renamed", expectedGeneration: 2,
      });
      assert.equal(renamed.desiredGeneration, 3);
      const renamedConfig = await generator.generateXrayHostConfig(10, keyring);
      await runtime.executeRaw("UPDATE xray_operations SET status = 'SUCCESS' WHERE operationId = ?", [renamed.operationId]);
      const listener = (network) => ({
        runtimeTag: JSON.parse(renamedConfig.configJson).inbounds[0].tag,
        network,
        port: 29301,
        status: "READY",
        errorCode: null,
      });
      const updateRuntime = (listeners) => runtime.executeRaw(
        "UPDATE xray_runtime_reports SET isInstalled = 1, installedVersion = ?, runningVersion = ?, serviceStatus = 'RUNNING', processId = 4242, binarySha256 = ?, appliedGeneration = 3, appliedConfigHash = ?, listenersJson = ? WHERE hostId = 10",
        [artifacts.XRAY_DEFAULT_VERSION, artifacts.XRAY_DEFAULT_VERSION, "a".repeat(64), renamedConfig.configHash, JSON.stringify(listeners)],
      );
      await updateRuntime([listener("tcp")]);
      assert.equal((await queryService.listXrayInboundSummaries({ hostId: 10 })).items[0].deploymentStatus, "UNKNOWN");
      await updateRuntime([listener("tcp"), listener("udp")]);
      assert.equal((await queryService.listXrayInboundSummaries({ hostId: 10 })).items[0].deploymentStatus, "RUNNING");
      assert.deepEqual((await queryService.getXrayInboundDetail(created.inboundId)).inbound.listenerNetworks, ["TCP", "UDP"]);
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
        XRAY_MASTER_KEY_PATH: path.join(directory, "xray-master.key"),
        JWT_SECRET: "xray-shadowsocks-udp-create-test-secret",
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
