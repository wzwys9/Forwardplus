import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("Xray inbound create is atomic, secret-safe, and coordinates install before desired apply", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-inbound-create-"));
  const databasePath = path.join(directory, "create.db");
  const keyPath = path.join(directory, "xray-master.key");
  const desiredPath = path.join(directory, "desired-state.json");
  const script = String.raw`
    import assert from "node:assert/strict";
    import { spawnSync } from "node:child_process";
    import fs from "node:fs";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const artifacts = await import(moduleUrl("server/xrayArtifacts.ts"));
    const secrets = await import(moduleUrl("server/xraySecretCrypto.ts"));
    const ports = await import(moduleUrl("server/xrayPortOperations.ts"));
    const reality = await import(moduleUrl("server/xrayRealityOperations.ts"));
    const runtimeOps = await import(moduleUrl("server/xrayRuntimeOperations.ts"));
    const heartbeat = await import(moduleUrl("server/xrayHeartbeatState.ts"));
    const { xrayRouter } = await import(moduleUrl("server/routers/xray.ts"));

    const admin = { id: 1, username: "admin", role: "admin", accountEnabled: true };
    const context = { req: { headers: {} }, res: { clearCookie() {}, setHeader() {} }, user: admin, authSession: null, authFailureReason: null };
    const caller = xrayRouter.createCaller(context);
    const memberCaller = xrayRouter.createCaller({
      ...context,
      user: { id: 2, username: "member", role: "user", accountEnabled: true },
    });
    const nowIso = () => new Date().toISOString();
    const taskSuccess = (task) => ({
      schemaVersion: 1, taskId: task.taskId, type: "PORT_PROBE", status: "SUCCESS",
      startedAt: nowIso(), finishedAt: nowIso(), error: null,
      result: { ports: task.payload.ports.map((port) => ({ port, available: true, errorCode: null })), observedAt: nowIso() },
    });
    const expectXrayCode = async (promise, code) => assert.rejects(promise, (error) =>
      error?.cause?.code === code || error?.message === code || error?.message === String(code));
    const reserve = async (hostId, port) => {
      const operation = await ports.createXrayPortProbeOperation({ hostId, userId: 1, mode: "MANUAL", manualPort: port });
      const [task] = await ports.takeXrayPortProbeTasks(hostId, 1);
      await ports.completeXrayPortProbeTask(hostId, taskSuccess(task));
      return await ports.getXrayPortProbeOperationResult(operation.operationId, 1);
    };
    const approveReality = async (hostId) => {
      const operation = await reality.createXrayRealityScanOperation({
        hostId, userId: 1, source: "ADMIN_DOMAINS", targets: ["www.microsoft.com:443"],
      }, { resolveHost: async () => ["8.8.8.8"] });
      const [task] = await reality.takeXrayRealityScanTasks(hostId, 1);
      await reality.completeXrayRealityScanTask(hostId, {
        schemaVersion: 1, taskId: task.taskId, type: "REALITY_SCAN", status: "SUCCESS",
        startedAt: nowIso(), finishedAt: nowIso(), error: null,
        result: { observedAt: nowIso(), results: [{
          target: "www.microsoft.com:443", host: "www.microsoft.com", resolvedIp: "8.8.8.8", port: 443,
          feasible: true, tls13: true, h2: true, x25519: true, certificateValid: true,
          serverNames: ["www.microsoft.com"], latencyMs: 12, reasonCode: null,
        }] },
      });
      return operation.operationId;
    };
    const input = (hostId, reservation) => ({
      hostId, name: "  Hong Kong Reality  ", publicAddress: "8.8.8.8",
      portReservationId: reservation.reservationId, listenPort: reservation.selectedPort,
      reality: { targetHost: "WWW.MICROSOFT.COM", targetPort: 443, serverName: "www.microsoft.com", fingerprint: "chrome", spiderX: "/" },
      initialClients: [
        { name: "phone", flow: "xtls-rprx-vision" },
        { name: "laptop", flow: "xtls-rprx-vision" },
        { name: "router", flow: "xtls-rprx-vision" },
      ],
    });
    const syncCounts = async () => ({
      inbounds: Number((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_inbounds"))[0].count),
      clients: Number((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_clients"))[0].count),
      deployments: Number((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_host_deployments"))[0].count),
      sync: Number((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_operations WHERE type = 'SYNC'"))[0].count),
    });

    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
      const now = Math.floor(Date.now() / 1000);
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (2, 'member', 'hash', 'user')");
      for (const hostId of [1, 2, 3]) {
        await runtime.executeRaw("INSERT INTO hosts (id, name, ip, ipv4, isOnline, lastHeartbeat, agentVersion, agentDistribution, userId) VALUES (?, ?, '8.8.8.8', '8.8.8.8', 1, ?, '2.3.1', 'forwardplus', 1)", [hostId, 'edge-' + hostId, now]);
        await runtime.executeRaw("INSERT INTO xray_runtime_reports (hostId, capabilitySchemaVersion, supportedOS, supportedArch, supportsArtifactInstall, supportsPortProbe, supportsRealityScan) VALUES (?, 1, 'linux', 'amd64', 1, 1, 1)", [hostId]);
        await approveReality(hostId);
      }
      const artifact = artifacts.XRAY_ARTIFACT_MANIFEST.find((entry) => entry.arch === "amd64");
      await runtime.executeRaw("INSERT INTO xray_artifacts (version, os, arch, packageFormat, storageKey, sha256, fileSize, status, source, verifiedAt) VALUES (?, ?, ?, ?, ?, ?, ?, 'VERIFIED', ?, ?)", [artifact.version, artifact.os, artifact.arch, artifact.packageFormat, artifact.storageKey, artifact.sha256, artifact.fileSize, artifact.source, now]);

      const offlineReservation = await reserve(3, 23003);
      await runtime.executeRaw("UPDATE hosts SET isOnline = 0 WHERE id = 3");
      const beforeOffline = await syncCounts();
      await expectXrayCode(caller.inbounds.create(input(3, offlineReservation)), "HOST_OFFLINE");
      assert.deepEqual(await syncCounts(), beforeOffline);

      const beforeInvalid = await syncCounts();
      await expectXrayCode(caller.inbounds.create(input(1, { reservationId: "missing", selectedPort: 23001 })), "PORT_RESERVATION_EXPIRED");
      assert.deepEqual(await syncCounts(), beforeInvalid);

      const reservation = await reserve(1, 23001);
      await assert.rejects(memberCaller.inbounds.create(input(1, reservation)), (error) => error?.code === "FORBIDDEN");
      assert.deepEqual(await syncCounts(), beforeInvalid);
      const created = await caller.inbounds.create(input(1, reservation));
      assert.equal(created.desiredGeneration, 1);
      assert.ok(created.inboundId > 0);
      assert.match(created.operationId, /^[A-Za-z0-9._:-]{1,64}$/);

      const inboundRows = await runtime.queryRaw("SELECT * FROM xray_inbounds WHERE id = ?", [created.inboundId]);
      const clientRows = await runtime.queryRaw("SELECT * FROM xray_clients WHERE inboundId = ? ORDER BY sortOrder, id", [created.inboundId]);
      const deployment = (await runtime.queryRaw("SELECT * FROM xray_host_deployments WHERE hostId = 1"))[0];
      assert.equal(inboundRows[0].name, "Hong Kong Reality");
      assert.equal(clientRows.length, 3);
      assert.equal(new Set(clientRows.map((row) => row.statsKey)).size, 3);
      assert.equal(new Set(clientRows.map((row) => row.uuidFingerprint)).size, 3);
      assert.match(inboundRows[0].realityPrivateKeyEncrypted, /^fwdx-secret:v1:/);
      assert.ok(deployment.desiredConfigHash);
      assert.equal(deployment.targetVersion, artifacts.XRAY_DEFAULT_VERSION);
      const keyring = secrets.loadXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
      const privateKey = secrets.decryptXraySecret(
        inboundRows[0].realityPrivateKeyEncrypted,
        secrets.xrayInboundPrivateKeyContext(inboundRows[0].runtimeTag),
        keyring,
      );
      assert.match(privateKey, /^[A-Za-z0-9_-]{43}$/);
      const plaintextCredentials = clientRows.map((row) => ({
        uuid: secrets.decryptXraySecret(row.uuidEncrypted, secrets.xrayClientUuidContext(row.statsKey), keyring),
        shortId: secrets.decryptXraySecret(row.shortIdEncrypted, secrets.xrayClientShortIdContext(row.statsKey), keyring),
      }));
      assert.equal(new Set(plaintextCredentials.map((item) => item.uuid)).size, 3);
      assert.equal(new Set(plaintextCredentials.map((item) => item.shortId)).size, 3);
      for (const credential of plaintextCredentials) {
        assert.match(credential.uuid, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
        assert.match(credential.shortId, /^[0-9a-f]{16}$/);
      }
      const serializedRows = JSON.stringify({ inboundRows, clientRows });
      assert.equal(serializedRows.includes("www-private-secret-marker"), false);
      assert.equal(serializedRows.includes('"uuidEncrypted":"00000000-'), false);

      const beforeObserved = await caller.inbounds.detail({ id: created.inboundId });
      assert.equal(beforeObserved.deployment.status, "WAITING_SYNC");
      assert.equal(await runtimeOps.shouldDeferXrayDesiredForInstall(1), true);
      const [installTask] = await runtimeOps.takeXrayRuntimeTasks(1, 1);
      assert.equal(installTask.type, "INSTALL");
      assert.equal(installTask.taskId, created.operationId);
      assert.equal(installTask.payload.artifactId > 0, true);
      assert.equal(await runtimeOps.shouldDeferXrayDesiredForInstall(1), true);
      assert.equal((await caller.inbounds.detail({ id: created.inboundId })).deployment.status, "INSTALLING");
      const installingOperation = await caller.operations.get({ operationId: created.operationId });
      assert.equal(installingOperation.stage, "DOWNLOADING_ARTIFACT");
      assert.equal(Object.hasOwn(installingOperation, "requestMetaJson"), false);

      await runtimeOps.completeXrayRuntimeTask(1, {
        schemaVersion: 1, taskId: installTask.taskId, type: "INSTALL", status: "SUCCESS",
        startedAt: nowIso(), finishedAt: nowIso(), error: null,
        result: { installedVersion: artifacts.XRAY_DEFAULT_VERSION, binarySha256: "b".repeat(64), reused: false },
      });
      assert.equal(await runtimeOps.shouldDeferXrayDesiredForInstall(1), false);
      const desired = await heartbeat.buildXrayHeartbeatDesiredState(1);
      assert.equal(desired.generation, 1);
      assert.equal(desired.configHash, deployment.desiredConfigHash);
      assert.deepEqual(desired.expectedListeners.map((listener) => listener.port), [23001]);
      if (process.env.XRAY_TEST_BINARY) {
        fs.writeFileSync(process.env.FORWARDX_XRAY_E2E_DESIRED_FILE, JSON.stringify(desired), { mode: 0o600 });
        const e2e = spawnSync("/tmp/forwardx-go1.23.1/go/bin/go", ["test", "./...", "-run", "^TestXrayAPIToAgentListenerE2E$", "-count=1"], {
          cwd: path.join(process.cwd(), "agent"),
          env: {
            ...process.env,
            GOTOOLCHAIN: "local",
            FORWARDX_XRAY_TEST_BINARY: process.env.XRAY_TEST_BINARY,
          },
          encoding: "utf8",
          timeout: 30_000,
        });
        assert.equal(e2e.status, 0, e2e.stderr || e2e.stdout);
      }

      const observed = {
        schemaVersion: 1, isInstalled: true, installedVersion: artifacts.XRAY_DEFAULT_VERSION,
        runningVersion: artifacts.XRAY_DEFAULT_VERSION, serviceStatus: "RUNNING", processId: 4242,
        binarySha256: "b".repeat(64), appliedGeneration: desired.generation, appliedConfigHash: desired.configHash,
        listeners: desired.expectedListeners.map((listener) => ({ runtimeTag: listener.runtimeTag, network: "tcp", port: listener.port, status: "READY", errorCode: null })),
        lastError: null, observedAt: nowIso(),
      };
      await heartbeat.processXrayHeartbeatReport({ hostId: 1, xrayStateSignature: heartbeat.xrayObservedStateSignature(observed), xrayState: observed });
      assert.equal((await caller.inbounds.detail({ id: created.inboundId })).deployment.status, "RUNNING");
      assert.equal((await caller.operations.get({ operationId: created.operationId })).status, "SUCCESS");

      await assert.rejects(
        memberCaller.inbounds.update({ id: created.inboundId, name: "forbidden", expectedGeneration: 1 }),
        (error) => error?.code === "FORBIDDEN",
      );
      await runtime.executeRaw("UPDATE hosts SET isOnline = 1, lastHeartbeat = ? WHERE id = 1", [Math.floor(Date.now() / 1000) - 3600]);
      await expectXrayCode(
        caller.inbounds.update({ id: created.inboundId, name: "offline-write", expectedGeneration: 1 }),
        "HOST_OFFLINE",
      );
      await runtime.executeRaw("UPDATE hosts SET isOnline = 1, lastHeartbeat = ? WHERE id = 1", [Math.floor(Date.now() / 1000)]);

      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsArtifactInstall = 0 WHERE hostId = 1");
      await expectXrayCode(
        caller.inbounds.update({ id: created.inboundId, name: "unsupported-write", expectedGeneration: 1 }),
        "AGENT_CAPABILITY_MISSING",
      );
      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsArtifactInstall = 1 WHERE hostId = 1");

      const updated = await caller.inbounds.update({
        id: created.inboundId,
        name: "Hong Kong Primary",
        publicAddress: "1.1.1.1",
        expectedGeneration: 1,
      });
      assert.equal(updated.desiredGeneration, 2);
      const updatedDetail = await caller.inbounds.detail({ id: created.inboundId });
      assert.equal(updatedDetail.inbound.name, "Hong Kong Primary");
      assert.equal(updatedDetail.inbound.publicAddress, "1.1.1.1");
      await expectXrayCode(
        caller.inbounds.update({ id: created.inboundId, name: "stale-write", expectedGeneration: 1 }),
        "CONFIG_GENERATION_CONFLICT",
      );

      const replacementPort = await reserve(1, 23004);
      const portUpdated = await caller.inbounds.update({
        id: created.inboundId,
        listenPort: replacementPort.selectedPort,
        portReservationId: replacementPort.reservationId,
        expectedGeneration: 2,
      });
      assert.equal(portUpdated.desiredGeneration, 3);
      assert.equal((await caller.inbounds.detail({ id: created.inboundId })).inbound.listenPort, 23004);

      const disabled = await caller.inbounds.setEnabled({ id: created.inboundId, isEnabled: false, expectedGeneration: 3 });
      assert.equal(disabled.desiredGeneration, 4);
      assert.deepEqual((await heartbeat.buildXrayHeartbeatDesiredState(1)).expectedListeners, []);
      const enabled = await caller.inbounds.setEnabled({ id: created.inboundId, isEnabled: true, expectedGeneration: 4 });
      assert.equal(enabled.desiredGeneration, 5);
      assert.deepEqual((await heartbeat.buildXrayHeartbeatDesiredState(1)).expectedListeners.map((listener) => listener.port), [23004]);

      const grpcReservation = await reserve(1, 23005);
      const grpcInput = {
        hostId: 1,
        name: "Hong Kong gRPC Reality",
        publicAddress: "8.8.8.8",
        portReservationId: grpcReservation.reservationId,
        listenPort: grpcReservation.selectedPort,
        profileId: "VLESS_GRPC_REALITY",
        spec: { serviceName: "forwardx-grpc" },
        reality: { targetHost: "www.microsoft.com", targetPort: 443, serverName: "www.microsoft.com", fingerprint: "chrome", spiderX: "/" },
        initialAccessEntries: [{ name: "grpc-phone" }],
      };
      await assert.rejects(memberCaller.inbounds.createV2(grpcInput), (error) => error?.code === "FORBIDDEN");
      const grpcCreated = await caller.inbounds.createV2(grpcInput);
      assert.equal(grpcCreated.desiredGeneration, 6);
      assert.deepEqual(await runtime.queryRaw("SELECT transport, profileId, specVersion, specJson FROM xray_inbounds WHERE id = ?", [grpcCreated.inboundId]), [{
        transport: "grpc", profileId: "VLESS_GRPC_REALITY", specVersion: 1, specJson: '{"serviceName":"forwardx-grpc"}',
      }]);
      const grpcClient = (await runtime.queryRaw("SELECT id, flow FROM xray_clients WHERE inboundId = ?", [grpcCreated.inboundId]))[0];
      assert.equal(grpcClient.flow, "");
      const grpcShare = await caller.clients.share({ clientId: grpcClient.id, format: "VLESS_URI" });
      assert.equal(new URL(grpcShare.uri).searchParams.get("serviceName"), "forwardx-grpc");
      assert.equal(new URL(grpcShare.uri).searchParams.has("flow"), false);
      const mixedDesired = await heartbeat.buildXrayHeartbeatDesiredState(1);
      assert.deepEqual(mixedDesired.expectedListeners.map((listener) => listener.port).sort((left, right) => left - right), [23004, 23005]);
      assert.deepEqual(JSON.parse(mixedDesired.configJson).inbounds.map((inbound) => inbound.streamSettings.network).sort(), ["grpc", "tcp"]);

      const xhttpReservation = await reserve(1, 23006);
      const xhttpInput = {
        hostId: 1,
        name: "Hong Kong XHTTP Reality",
        publicAddress: "8.8.8.8",
        portReservationId: xhttpReservation.reservationId,
        listenPort: xhttpReservation.selectedPort,
        profileId: "VLESS_XHTTP_REALITY",
        spec: { path: "/forwardx/xhttp-v1" },
        reality: { targetHost: "www.microsoft.com", targetPort: 443, serverName: "www.microsoft.com", fingerprint: "chrome", spiderX: "/" },
        initialAccessEntries: [{ name: "xhttp-phone" }],
      };
      const xhttpCreated = await caller.inbounds.createV2(xhttpInput);
      assert.equal(xhttpCreated.desiredGeneration, 7);
      assert.deepEqual(await runtime.queryRaw("SELECT transport, profileId, specVersion, specJson FROM xray_inbounds WHERE id = ?", [xhttpCreated.inboundId]), [{
        transport: "xhttp", profileId: "VLESS_XHTTP_REALITY", specVersion: 1, specJson: '{"path":"/forwardx/xhttp-v1"}',
      }]);
      const xhttpClient = (await runtime.queryRaw("SELECT id, flow FROM xray_clients WHERE inboundId = ?", [xhttpCreated.inboundId]))[0];
      assert.equal(xhttpClient.flow, "");
      const xhttpShare = new URL((await caller.clients.share({ clientId: xhttpClient.id, format: "VLESS_URI" })).uri);
      assert.equal(xhttpShare.searchParams.get("type"), "xhttp");
      assert.equal(xhttpShare.searchParams.get("path"), "/forwardx/xhttp-v1");
      assert.equal(xhttpShare.searchParams.get("mode"), "auto");
      assert.equal(xhttpShare.searchParams.has("flow"), false);
      const allProfilesDesired = await heartbeat.buildXrayHeartbeatDesiredState(1);
      assert.deepEqual(allProfilesDesired.expectedListeners.map((listener) => listener.port).sort((left, right) => left - right), [23004, 23005, 23006]);
      assert.deepEqual(JSON.parse(allProfilesDesired.configJson).inbounds.map((inbound) => inbound.streamSettings.network).sort(), ["grpc", "tcp", "xhttp"]);

      const trojanReservation = await reserve(1, 23007);
      const trojanInput = {
        hostId: 1,
        name: "Hong Kong Trojan Reality",
        publicAddress: "8.8.8.8",
        portReservationId: trojanReservation.reservationId,
        listenPort: trojanReservation.selectedPort,
        profileId: "TROJAN_RAW_REALITY",
        spec: {},
        reality: { targetHost: "www.microsoft.com", targetPort: 443, serverName: "www.microsoft.com", fingerprint: "chrome", spiderX: "/" },
        initialAccessEntries: [{ name: "trojan-phone" }],
      };
      await assert.rejects(memberCaller.inbounds.createV2(trojanInput), (error) => error?.code === "FORBIDDEN");
      const trojanCreated = await caller.inbounds.createV2(trojanInput);
      assert.equal(trojanCreated.desiredGeneration, 8);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_clients WHERE inboundId = ?", [trojanCreated.inboundId]))[0].count, 0);
      const trojanAccess = (await runtime.queryRaw("SELECT id, legacyClientId, credentialType, statsKey FROM xray_access_entries WHERE inboundId = ?", [trojanCreated.inboundId]))[0];
      assert.equal(trojanAccess.legacyClientId, null);
      assert.equal(trojanAccess.credentialType, "PASSWORD");
      const trojanSecretRows = await runtime.queryRaw("SELECT kind, encryptedValue FROM xray_access_secrets WHERE accessEntryId = ? ORDER BY kind", [trojanAccess.id]);
      assert.deepEqual(trojanSecretRows.map((row) => row.kind), ["PASSWORD", "SHORT_ID"]);
      const passwordRow = trojanSecretRows.find((row) => row.kind === "PASSWORD");
      const trojanPassword = secrets.decryptXraySecret(passwordRow.encryptedValue, secrets.xrayAccessSecretContext(trojanAccess.statsKey, "PASSWORD"), keyring);
      assert.match(trojanPassword, /^[A-Za-z0-9_-]{43}$/);
      const trojanShare = new URL((await caller.accessEntries.share({ accessEntryId: trojanAccess.id, format: "TROJAN_URI" })).uri);
      assert.equal(trojanShare.protocol, "trojan:");
      assert.equal(trojanShare.searchParams.get("type"), "tcp");
      assert.equal(trojanShare.searchParams.has("flow"), false);
      const trojanDetail = await caller.inbounds.detail({ id: trojanCreated.inboundId });
      assert.equal(trojanDetail.clients.length, 0);
      assert.equal(trojanDetail.accessEntries.length, 1);
      assert.equal(JSON.stringify(trojanDetail).includes(trojanPassword), false);
      const realityProfilesDesired = await heartbeat.buildXrayHeartbeatDesiredState(1);
      assert.deepEqual(realityProfilesDesired.expectedListeners.map((listener) => listener.port).sort((left, right) => left - right), [23004, 23005, 23006, 23007]);
      assert.deepEqual(JSON.parse(realityProfilesDesired.configJson).inbounds.map((inbound) => inbound.protocol).sort(), ["trojan", "vless", "vless", "vless"]);

      const failedReservation = await reserve(2, 23002);
      const failed = await caller.inbounds.create(input(2, failedReservation));
      const [failedInstall] = await runtimeOps.takeXrayRuntimeTasks(2, 1);
      await runtimeOps.completeXrayRuntimeTask(2, {
        schemaVersion: 1, taskId: failedInstall.taskId, type: "INSTALL", status: "FAILED",
        startedAt: nowIso(), finishedAt: nowIso(), result: null,
        error: { code: "PRIVATE_SECRET_FAILURE", message: "www-private-secret-marker", retryable: false },
      });
      const failedOperation = await caller.operations.get({ operationId: failed.operationId });
      assert.equal(failedOperation.status, "FAILED");
      assert.equal(failedOperation.errorCode, "INTERNAL_ERROR");
      assert.equal(JSON.stringify(failedOperation).includes("www-private-secret-marker"), false);
      assert.equal(JSON.stringify(await runtime.queryRaw("SELECT errorCode, errorMessage FROM xray_operations WHERE operationId = ?", [failed.operationId])).includes("www-private-secret-marker"), false);
    } finally {
      ports.clearXrayPortOperationStateForTest();
      await runtime.closeDatabase().catch(() => undefined);
    }
  `;
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        DATABASE_TYPE: "sqlite",
        FORWARDX_TEST_DB: databasePath,
        JWT_SECRET: "xray-inbound-create-test-secret",
        XRAY_MASTER_KEY_PATH: keyPath,
        FORWARDX_XRAY_E2E_DESIRED_FILE: desiredPath,
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
