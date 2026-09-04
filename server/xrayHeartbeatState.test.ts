import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("Xray heartbeat persists UDP capabilities and listener networks compatibly", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-heartbeat-udp-"));
  const databasePath = path.join(directory, "heartbeat.db");
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const heartbeat = await import(moduleUrl("server/xrayHeartbeatState.ts"));
    const capability = {
      schemaVersion: 1,
      supported: true,
      supervisor: "AGENT_CHILD",
      supportsPortProbe: true,
      supportsUdpPortProbe: true,
      supportsUdpListenerReadiness: true,
      supportsRealityScan: true,
      supportsArtifactInstall: true,
      supportedOS: "linux",
      supportedArch: "amd64",
    };
    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();

      await heartbeat.persistXrayCapabilityReport(21, {
        ...capability,
        supportsUdpPortProbe: undefined,
        supportsUdpListenerReadiness: undefined,
      });
      assert.deepEqual(
        await runtime.queryRaw("SELECT supportsUdpPortProbe, supportsUdpListenerReadiness FROM xray_runtime_reports WHERE hostId = 21"),
        [{ supportsUdpPortProbe: 0, supportsUdpListenerReadiness: 0 }],
      );

      await heartbeat.persistXrayCapabilityReport(22, {
        ...capability,
        supported: false,
        errorCode: "HOST_PLATFORM_UNSUPPORTED",
      });
      assert.deepEqual(
        await runtime.queryRaw("SELECT supportsUdpPortProbe, supportsUdpListenerReadiness FROM xray_runtime_reports WHERE hostId = 22"),
        [{ supportsUdpPortProbe: 0, supportsUdpListenerReadiness: 0 }],
      );

      await heartbeat.persistXrayCapabilityReport(23, capability);
      const state = {
        schemaVersion: 1,
        isInstalled: true,
        installedVersion: "v26.3.27",
        runningVersion: "v26.3.27",
        serviceStatus: "RUNNING",
        processId: 4321,
        binarySha256: "c".repeat(64),
        appliedGeneration: 0,
        appliedConfigHash: null,
        listeners: [
          { runtimeTag: "dual", network: "udp", port: 23456, status: "READY" },
          { runtimeTag: "dual", network: "tcp", port: 23456, status: "READY" },
        ],
        lastError: null,
        observedAt: "2026-09-01T08:00:06.000Z",
      };
      const signature = heartbeat.xrayObservedStateSignature(state);
      const result = await heartbeat.processXrayHeartbeatReport({ hostId: 23, xrayStateSignature: signature, xrayState: state });
      assert.equal(result.requestXrayState, false);
      assert.deepEqual(
        await runtime.queryRaw("SELECT supportsUdpPortProbe, supportsUdpListenerReadiness FROM xray_runtime_reports WHERE hostId = 23"),
        [{ supportsUdpPortProbe: 1, supportsUdpListenerReadiness: 1 }],
      );
      const [stored] = await runtime.queryRaw("SELECT listenersJson FROM xray_runtime_reports WHERE hostId = 23");
      assert.deepEqual(JSON.parse(stored.listenersJson).map(({ network }) => network), ["tcp", "udp"]);

      const runtimeTag = "forwardx-mkcp-heartbeat";
      await runtime.executeRaw("INSERT INTO xray_inbounds (id, hostId, name, runtimeTag, publicAddress, listenPort, protocol, transport, security, profileId, specVersion, specJson, realityTargetHost, realityServerName, realityPublicKey, realityPrivateKeyEncrypted, desiredGeneration, createdByUserId) VALUES (300, 23, 'mKCP node', ?, '203.0.113.23', 24567, 'vless', 'kcp', 'tls', 'VLESS_MKCP_TLS', 1, '{}', '', 'tls.example.com', '', '', 4, 1)", [runtimeTag]);
      await runtime.executeRaw("INSERT INTO xray_host_deployments (hostId, targetVersion, desiredGeneration, desiredConfigHash, lastOperationId) VALUES (23, 'v26.3.27', 4, ?, 'sync-udp-4')", ["d".repeat(64)]);
      await runtime.executeRaw("INSERT INTO xray_operations (operationId, hostId, inboundId, type, requestedGeneration, status, createdByUserId) VALUES ('sync-udp-4', 23, 300, 'SYNC', 4, 'QUEUED', 1)");
      const udpApplied = {
        ...state,
        appliedGeneration: 4,
        appliedConfigHash: "d".repeat(64),
        listeners: [{ runtimeTag, network: "udp", port: 24567, status: "READY" }],
        observedAt: "2026-09-01T08:00:07.000Z",
      };
      await heartbeat.processXrayHeartbeatReport({
        hostId: 23,
        xrayStateSignature: heartbeat.xrayObservedStateSignature(udpApplied),
        xrayState: udpApplied,
      });
      assert.equal((await runtime.queryRaw("SELECT status FROM xray_operations WHERE operationId = 'sync-udp-4'"))[0].status, "SUCCESS");

      await runtime.executeRaw("UPDATE xray_host_deployments SET desiredGeneration = 5, desiredConfigHash = ?, lastOperationId = 'sync-udp-5' WHERE hostId = 23", ["e".repeat(64)]);
      await runtime.executeRaw("INSERT INTO xray_operations (operationId, hostId, inboundId, type, requestedGeneration, status, createdByUserId) VALUES ('sync-udp-5', 23, 300, 'SYNC', 5, 'QUEUED', 1)");
      const wrongNetwork = {
        ...udpApplied,
        appliedGeneration: 5,
        appliedConfigHash: "e".repeat(64),
        listeners: [{ runtimeTag, network: "tcp", port: 24567, status: "READY" }],
        observedAt: "2026-09-01T08:00:08.000Z",
      };
      await heartbeat.processXrayHeartbeatReport({
        hostId: 23,
        xrayStateSignature: heartbeat.xrayObservedStateSignature(wrongNetwork),
        xrayState: wrongNetwork,
      });
      assert.equal((await runtime.queryRaw("SELECT status FROM xray_operations WHERE operationId = 'sync-udp-5'"))[0].status, "QUEUED");

      const dualRuntimeTag = "forwardx-shadowsocks-dual-heartbeat";
      await runtime.executeRaw("UPDATE xray_inbounds SET runtimeTag = ?, listenPort = 24568, protocol = 'shadowsocks', transport = 'tcp', security = 'none', profileId = 'SHADOWSOCKS_2022_RAW_TCP_UDP_NONE', specVersion = 1, specJson = '{}' WHERE id = 300", [dualRuntimeTag]);
      await runtime.executeRaw("UPDATE xray_host_deployments SET desiredGeneration = 6, desiredConfigHash = ?, lastOperationId = 'sync-dual-6' WHERE hostId = 23", ["f".repeat(64)]);
      await runtime.executeRaw("INSERT INTO xray_operations (operationId, hostId, inboundId, type, requestedGeneration, status, createdByUserId) VALUES ('sync-dual-6', 23, 300, 'SYNC', 6, 'QUEUED', 1)");
      const dualApplied = {
        ...state,
        appliedGeneration: 6,
        appliedConfigHash: "f".repeat(64),
        listeners: [
          { runtimeTag: dualRuntimeTag, network: "tcp", port: 24568, status: "READY" },
          { runtimeTag: dualRuntimeTag, network: "udp", port: 24568, status: "READY" },
        ],
        observedAt: "2026-09-01T08:00:09.000Z",
      };
      await heartbeat.processXrayHeartbeatReport({
        hostId: 23,
        xrayStateSignature: heartbeat.xrayObservedStateSignature(dualApplied),
        xrayState: dualApplied,
      });
      assert.equal((await runtime.queryRaw("SELECT status FROM xray_operations WHERE operationId = 'sync-dual-6'"))[0].status, "SUCCESS");
    } finally {
      heartbeat.clearXrayHeartbeatStateForTest();
      await runtime.closeDatabase();
    }
  `;
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: { ...process.env, DATABASE_TYPE: "sqlite", FORWARDX_TEST_DB: databasePath, JWT_SECRET: "xray-heartbeat-udp-test-secret" },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("Xray heartbeat state builds desired and safely converges observed reports", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-heartbeat-state-"));
  const databasePath = path.join(directory, "heartbeat.db");
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const secrets = await import(moduleUrl("server/xraySecretCrypto.ts"));
    const heartbeat = await import(moduleUrl("server/xrayHeartbeatState.ts"));
    const shared = await import(moduleUrl("shared/xrayTypes.ts"));
    const keyring = secrets.createXraySecretKeyring({ currentKeyId: "1", keys: { "1": Buffer.alloc(32, 9) } });
    const capability = {
      schemaVersion: 1,
      supported: true,
      supervisor: "AGENT_CHILD",
      supportsPortProbe: true,
      supportsRealityScan: true,
      supportsArtifactInstall: true,
      supportedOS: "linux",
      supportedArch: "amd64",
    };
    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, userId) VALUES (10, 'edge', '192.0.2.10', 1), (11, 'legacy', '192.0.2.11', 1), (12, 'empty', '192.0.2.12', 1)");

      const legacy = await heartbeat.processXrayHeartbeatReport({ hostId: 11 });
      assert.equal(legacy.compatible, false);
      assert.equal(legacy.requestXrayState, false);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_runtime_reports WHERE hostId = 11"))[0].count, 0);

      const unsupported = await heartbeat.persistXrayCapabilityReport(10, { ...capability, supported: false, supportedOS: "freebsd", supportedArch: "amd64", errorCode: "HOST_PLATFORM_UNSUPPORTED" });
      assert.equal(unsupported.compatible, false);
      assert.deepEqual(
        await runtime.queryRaw("SELECT capabilitySchemaVersion, supportedOS, supportedArch, supportsArtifactInstall, supportsPortProbe, supportsRealityScan, capabilityErrorCode FROM xray_runtime_reports WHERE hostId = 10"),
        [{ capabilitySchemaVersion: 0, supportedOS: "freebsd", supportedArch: "amd64", supportsArtifactInstall: 0, supportsPortProbe: 0, supportsRealityScan: 0, capabilityErrorCode: "HOST_PLATFORM_UNSUPPORTED" }],
      );
      const supported = await heartbeat.persistXrayCapabilityReport(10, capability);
      assert.equal(supported.compatible, true);
      assert.deepEqual(
        await runtime.queryRaw("SELECT capabilitySchemaVersion, supportedOS, supportedArch, supportsArtifactInstall, supportsPortProbe, supportsRealityScan, capabilityErrorCode FROM xray_runtime_reports WHERE hostId = 10"),
        [{ capabilitySchemaVersion: 1, supportedOS: "linux", supportedArch: "amd64", supportsArtifactInstall: 1, supportsPortProbe: 1, supportsRealityScan: 1, capabilityErrorCode: null }],
      );
      await runtime.executeRaw("INSERT INTO xray_host_deployments (hostId, targetVersion, desiredGeneration) VALUES (12, 'v26.3.27', 3)");
      const emptyDesired = await heartbeat.buildXrayHeartbeatDesiredState(12);
      assert.equal(emptyDesired.generation, 3);
      assert.deepEqual(emptyDesired.expectedListeners, []);

      const runtimeTag = "forwardx-inbound-heartbeat";
      const statsKey = "fwdx-client-heartbeat";
      const privateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
      const uuid = "00000000-0000-4000-8000-000000000001";
      const shortId = "0123456789abcdef";
      const privateEnvelope = secrets.encryptXraySecret(privateKey, secrets.xrayInboundPrivateKeyContext(runtimeTag), keyring);
      const uuidEnvelope = secrets.encryptXraySecret(uuid, secrets.xrayClientUuidContext(statsKey), keyring);
      const shortEnvelope = secrets.encryptXraySecret(shortId, secrets.xrayClientShortIdContext(statsKey), keyring);
      await runtime.executeRaw("INSERT INTO xray_inbounds (id, hostId, name, runtimeTag, publicAddress, listenPort, realityTargetHost, realityServerName, realityPublicKey, realityPrivateKeyEncrypted, desiredGeneration, createdByUserId) VALUES (100, 10, 'node', ?, '203.0.113.10', 23456, 'www.microsoft.com', 'www.microsoft.com', 'public', ?, 1, 1)", [runtimeTag, privateEnvelope]);
      await runtime.executeRaw("INSERT INTO xray_clients (id, inboundId, name, uuidEncrypted, uuidFingerprint, shortIdEncrypted, shortIdFingerprint, statsKey, desiredGeneration) VALUES (200, 100, 'client', ?, ?, ?, ?, ?, 1)", [uuidEnvelope, "a".repeat(64), shortEnvelope, "b".repeat(64), statsKey]);
      await runtime.executeRaw("INSERT INTO xray_host_deployments (hostId, desiredGeneration, lastOperationId) VALUES (10, 1, 'sync-1')");
      await runtime.executeRaw("INSERT INTO xray_operations (operationId, hostId, inboundId, type, requestedGeneration, status, createdByUserId) VALUES ('sync-1', 10, 100, 'SYNC', 1, 'QUEUED', 1)");

      const firstDesired = await heartbeat.buildXrayHeartbeatDesiredState(10, { keyring, issuedAt: new Date("2026-09-01T08:00:00.000Z") });
      const fallbackDesired = await heartbeat.buildXrayHeartbeatDesiredState(10, { keyring, issuedAt: new Date("2026-09-01T08:00:05.000Z") });
      assert.ok(firstDesired);
      assert.equal(firstDesired.generation, 1);
      assert.equal(firstDesired.targetVersion, "v26.3.27");
      assert.equal(firstDesired.configHash, fallbackDesired.configHash);
      assert.equal(firstDesired.configJson, fallbackDesired.configJson);
      assert.deepEqual(firstDesired.expectedListeners, fallbackDesired.expectedListeners);
      assert.equal(shared.XrayDesiredStateSchema.safeParse(firstDesired).success, true);
      assert.equal((await runtime.queryRaw("SELECT desiredConfigHash FROM xray_host_deployments WHERE hostId = 10"))[0].desiredConfigHash, firstDesired.configHash);

      const state = {
        schemaVersion: 1,
        isInstalled: true,
        installedVersion: "v26.3.27",
        runningVersion: "v26.3.27",
        serviceStatus: "RUNNING",
        processId: 4321,
        binarySha256: "c".repeat(64),
        appliedGeneration: firstDesired.generation,
        appliedConfigHash: firstDesired.configHash,
        listeners: [{ runtimeTag, network: "tcp", port: 23456, status: "READY" }],
        lastError: null,
        observedAt: "2026-09-01T08:00:06.000Z",
      };
      const signature = heartbeat.xrayObservedStateSignature(state);
      assert.match(signature, /^[0-9a-f]{64}$/);
      const applied = await heartbeat.processXrayHeartbeatReport({
        hostId: 10,
        xrayStateSignature: signature,
        xrayState: state,
      });
      assert.equal(applied.compatible, true);
      assert.equal(applied.requestXrayState, false);
      assert.equal(heartbeat.isXrayDesiredApplied(firstDesired, applied.observedState), true);
      const [stored] = await runtime.queryRaw("SELECT * FROM xray_runtime_reports WHERE hostId = 10");
      assert.equal(stored.reportSignature, signature);
      assert.equal(stored.appliedGeneration, 1);
      assert.equal(stored.appliedConfigHash, firstDesired.configHash);
      assert.equal(JSON.parse(stored.listenersJson)[0].runtimeTag, runtimeTag);
      assert.equal((await runtime.queryRaw("SELECT status FROM xray_operations WHERE operationId = 'sync-1'"))[0].status, "SUCCESS");

      const compact = await heartbeat.processXrayHeartbeatReport({ hostId: 10, xrayStateSignature: signature });
      assert.equal(compact.requestXrayState, false);
      assert.equal(heartbeat.isXrayDesiredApplied(firstDesired, compact.observedState), true);
      await runtime.executeRaw("UPDATE xray_runtime_reports SET binarySha256 = 'tampered' WHERE hostId = 10");
      const tamperedCache = await heartbeat.processXrayHeartbeatReport({ hostId: 10, xrayStateSignature: signature });
      assert.equal(tamperedCache.requestXrayState, true);
      assert.equal(tamperedCache.observedState, null);
      await runtime.executeRaw("UPDATE xray_runtime_reports SET binarySha256 = ? WHERE hostId = 10", ["c".repeat(64)]);
      await runtime.executeRaw("UPDATE xray_runtime_reports SET serviceStatus = 'TAMPERED' WHERE hostId = 10");
      const invalidStatusCache = await heartbeat.processXrayHeartbeatReport({ hostId: 10, xrayStateSignature: signature });
      assert.equal(invalidStatusCache.requestXrayState, true);
      assert.equal(invalidStatusCache.observedState, null);
      await runtime.executeRaw("UPDATE xray_runtime_reports SET serviceStatus = 'RUNNING' WHERE hostId = 10");
      const uppercaseSignature = await heartbeat.processXrayHeartbeatReport({ hostId: 10, xrayStateSignature: signature.toUpperCase() });
      assert.equal(uppercaseSignature.requestXrayState, true);
      assert.equal(uppercaseSignature.observedState, null);
      const unknown = await heartbeat.processXrayHeartbeatReport({ hostId: 10, xrayStateSignature: "d".repeat(64) });
      assert.equal(unknown.requestXrayState, true);
      assert.equal(unknown.observedState, null);

      const secretMarker = "uuid-private-secret-marker";
      const rejected = await heartbeat.processXrayHeartbeatReport({
        hostId: 10,
        xrayStateSignature: "e".repeat(64),
        xrayState: { ...state, privateKey: secretMarker },
      });
      assert.equal(rejected.requestXrayState, true);
      assert.equal(JSON.stringify(await runtime.queryRaw("SELECT * FROM xray_runtime_reports WHERE hostId = 10")).includes(secretMarker), false);
      const wrongSignature = await heartbeat.processXrayHeartbeatReport({
        hostId: 10,
        xrayStateSignature: "f".repeat(64),
        xrayState: state,
      });
      assert.equal(wrongSignature.requestXrayState, true);
      assert.equal((await runtime.queryRaw("SELECT reportSignature FROM xray_runtime_reports WHERE hostId = 10"))[0].reportSignature, signature);

      await runtime.executeRaw("UPDATE xray_host_deployments SET desiredGeneration = 2, desiredConfigHash = NULL, lastOperationId = 'sync-2' WHERE hostId = 10");
      await runtime.executeRaw("INSERT INTO xray_operations (operationId, hostId, inboundId, type, requestedGeneration, status, createdByUserId) VALUES ('sync-2', 10, 100, 'SYNC', 2, 'QUEUED', 1)");
      const secondDesired = await heartbeat.buildXrayHeartbeatDesiredState(10, { keyring });
      const failedState = {
        ...state,
        lastError: {
          code: "PRIVATE_KEY_LEAK",
          message: secretMarker,
          generation: 2,
          occurredAt: "2026-09-01T08:00:07.000Z",
        },
        observedAt: "2026-09-01T08:00:07.000Z",
      };
      const failedSignature = heartbeat.xrayObservedStateSignature(failedState);
      const failed = await heartbeat.processXrayHeartbeatReport({ hostId: 10, xrayStateSignature: failedSignature, xrayState: failedState });
      assert.equal(failed.requestXrayState, false);
      assert.equal(heartbeat.isXrayDesiredApplied(secondDesired, failed.observedState), false);
      const [failedOperation] = await runtime.queryRaw("SELECT status, errorCode, errorMessage FROM xray_operations WHERE operationId = 'sync-2'");
      assert.equal(failedOperation.status, "FAILED");
      assert.equal(failedOperation.errorCode, "INTERNAL_ERROR");
      assert.equal(String(failedOperation.errorMessage).includes(secretMarker), false);
      const [failedReport] = await runtime.queryRaw("SELECT lastErrorCode, lastErrorMessage FROM xray_runtime_reports WHERE hostId = 10");
      assert.equal(failedReport.lastErrorCode, "INTERNAL_ERROR");
      assert.equal(String(failedReport.lastErrorMessage).includes(secretMarker), false);
    } finally {
      heartbeat.clearXrayHeartbeatStateForTest();
      await runtime.closeDatabase();
    }
  `;
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: { ...process.env, DATABASE_TYPE: "sqlite", FORWARDX_TEST_DB: databasePath, JWT_SECRET: "xray-heartbeat-test-secret" },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
