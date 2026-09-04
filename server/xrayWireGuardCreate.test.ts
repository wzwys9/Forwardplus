import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("WireGuard create and peer CRUD keep UDP, addresses, secrets, desired config, and share atomic", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-wireguard-create-"));
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
    const accessRepository = await load("server/repositories/xrayAccessRepository.ts");
    const queryService = await load("server/xrayQueryService.ts");
    const generator = await load("server/xrayConfigGenerator.ts");
    const secrets = await load("server/xraySecretCrypto.ts");
    const versions = await load("shared/versions.ts");
    const { xrayRouter } = await load("server/routers/xray.ts");
    const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
    const nowIso = () => new Date().toISOString();
    const expectCode = async (promise, code) => assert.rejects(promise, (error) => error?.code === code);
    const reserveUdp = async (port) => {
      const operation = await ports.createXrayPortProbeOperation({
        hostId: 10, userId: 1, mode: "MANUAL", manualPort: port, network: "UDP",
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
        result: { ports: [{ port, available: true, errorCode: null }], observedAt: nowIso() },
      });
      return ports.getXrayPortProbeOperationResult(operation.operationId, 1);
    };

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
        "INSERT INTO xray_runtime_reports (hostId, capabilitySchemaVersion, supportedOS, supportedArch, supportsArtifactInstall, supportsPortProbe, supportsUdpPortProbe, supportsUdpListenerReadiness, supportsRealityScan) VALUES (10, 1, 'linux', 'amd64', 1, 1, 1, 1, 1)",
      );
      const artifact = artifacts.XRAY_ARTIFACT_MANIFEST.find((entry) => entry.arch === "amd64");
      await runtime.executeRaw(
        "INSERT INTO xray_artifacts (version, os, arch, packageFormat, storageKey, sha256, fileSize, status, source, verifiedAt) VALUES (?, ?, ?, ?, ?, ?, ?, 'VERIFIED', ?, ?)",
        [artifact.version, artifact.os, artifact.arch, artifact.packageFormat, artifact.storageKey, artifact.sha256, artifact.fileSize, artifact.source, now],
      );

      const reservation = await reserveUdp(29401);
      const input = {
        hostId: 10,
        userId: 1,
        name: "WireGuard",
        publicAddress: "8.8.8.8",
        portReservationId: reservation.reservationId,
        listenPort: 29401,
        profileId: "WIREGUARD_UDP_NONE",
        spec: {},
        initialAccessEntries: [{ name: "phone" }, { name: "laptop" }],
      };
      const internal = { isProfileEnabledForInternalTest: (profile) => profile.id === "WIREGUARD_UDP_NONE" };

      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsUdpListenerReadiness = 0 WHERE hostId = 10");
      await expectCode(inboundService.createXrayInboundV2(input, internal), "UDP_CAPABILITY_REQUIRED");
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_inbounds"))[0].count, 0);
      assert.equal(ports.validateXrayPortReservation({
        reservationId: reservation.reservationId, hostId: 10, userId: 1, port: 29401, network: "UDP",
      }).network, "udp");

      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsUdpListenerReadiness = 1 WHERE hostId = 10");
      const created = await inboundService.createXrayInboundV2(input, internal);
      assert.equal(created.desiredGeneration, 1);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT profileId, specJson, protocol, transport, security, tlsCertificateId FROM xray_inbounds WHERE id = ?",
        [created.inboundId],
      ), [{
        profileId: "WIREGUARD_UDP_NONE",
        specJson: "{}",
        protocol: "wireguard",
        transport: "none",
        security: "none",
        tlsCertificateId: null,
      }]);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT credentialType, settingsJson FROM xray_access_entries WHERE inboundId = ? ORDER BY sortOrder, id",
        [created.inboundId],
      ), [
        { credentialType: "WIREGUARD_PEER", settingsJson: '{"schemaVersion":2,"address":"10.0.0.2/32"}' },
        { credentialType: "WIREGUARD_PEER", settingsJson: '{"schemaVersion":2,"address":"10.0.0.3/32"}' },
      ]);
      assert.equal((await runtime.queryRaw(
        "SELECT COUNT(*) count FROM xray_inbound_secrets WHERE inboundId = ? AND kind = 'PRIVATE_KEY'",
        [created.inboundId],
      ))[0].count, 1);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT s.kind, COUNT(*) count FROM xray_access_secrets s JOIN xray_access_entries a ON a.id = s.accessEntryId WHERE a.inboundId = ? GROUP BY s.kind ORDER BY s.kind",
        [created.inboundId],
      ), [{ kind: "PRE_SHARED_KEY", count: 2 }, { kind: "PRIVATE_KEY", count: 2 }]);

      const initialConfig = await generator.generateXrayHostConfig(10, keyring);
      const inbound = JSON.parse(initialConfig.configJson).inbounds[0];
      assert.equal(inbound.protocol, "wireguard");
      assert.equal(inbound.settings.noKernelTun, true);
      assert.deepEqual(inbound.settings.address, ["10.0.0.1/32"]);
      assert.deepEqual(inbound.settings.peers.map((peer) => peer.allowedIPs), [["10.0.0.2/32"], ["10.0.0.3/32"]]);
      assert.deepEqual(initialConfig.expectedListeners.map(({ network, port }) => ({ network, port })), [
        { network: "udp", port: 29401 },
      ]);
      await expectCode(Promise.resolve().then(() => ports.validateXrayPortReservation({
        reservationId: reservation.reservationId, hostId: 10, userId: 1, port: 29401, network: "UDP",
      })), "PORT_RESERVATION_EXPIRED");

      const detail = await queryService.getXrayInboundDetail(created.inboundId);
      assert.deepEqual(detail.accessEntries.map((entry) => entry.settings.address), ["10.0.0.2/32", "10.0.0.3/32"]);
      const detailJson = JSON.stringify(detail);
      const forbiddenDetailKeys = new Set(["encryptedValue", "keyVersion", "privateKey", "preSharedKey", "publicKey"]);
      const visitDetail = (value) => {
        if (!value || typeof value !== "object") return;
        for (const [key, child] of Object.entries(value)) {
          assert.equal(forbiddenDetailKeys.has(key), false, key);
          visitDetail(child);
        }
      };
      visitDetail(detail);
      const persistedSecretMarkers = await runtime.queryRaw(
        "SELECT encryptedValue, fingerprint FROM xray_inbound_secrets WHERE inboundId = ? UNION ALL SELECT s.encryptedValue, s.fingerprint FROM xray_access_secrets s JOIN xray_access_entries a ON a.id = s.accessEntryId WHERE a.inboundId = ?",
        [created.inboundId, created.inboundId],
      );
      for (const marker of persistedSecretMarkers.flatMap((row) => [row.encryptedValue, row.fingerprint])) {
        assert.equal(detailJson.includes(marker), false);
      }

      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsUdpPortProbe = 0 WHERE hostId = 10");
      await expectCode(accessService.createXrayAccessEntryForInbound({
        inboundId: created.inboundId, userId: 1, name: "blocked", expectedGeneration: 1,
      }), "UDP_CAPABILITY_REQUIRED");
      assert.equal((await runtime.queryRaw("SELECT desiredGeneration FROM xray_host_deployments WHERE hostId = 10"))[0].desiredGeneration, 1);

      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsUdpPortProbe = 1 WHERE hostId = 10");
      const added = await accessService.createXrayAccessEntryForInbound({
        inboundId: created.inboundId, userId: 1, name: "desktop", expectedGeneration: 1,
      });
      assert.equal(added.desiredGeneration, 2);
      assert.equal((await accessRepository.getXrayAccessEntry(added.accessEntryId)).settings.address, "10.0.0.4/32");

      const initialPeers = await accessRepository.listXrayAccessEntries(created.inboundId);
      const removed = await accessService.removeXrayAccessEntryForInbound({
        id: initialPeers[1].id, userId: 1, expectedGeneration: 2,
      });
      assert.equal(removed.desiredGeneration, 3);
      const afterTombstone = await accessService.createXrayAccessEntryForInbound({
        inboundId: created.inboundId, userId: 1, name: "tablet", expectedGeneration: 3,
      });
      assert.equal(afterTombstone.desiredGeneration, 4);
      assert.equal((await accessRepository.getXrayAccessEntry(afterTombstone.accessEntryId)).settings.address, "10.0.0.5/32");

      const headers = new Map();
      const caller = xrayRouter.createCaller({
        req: { headers: {} },
        res: { clearCookie() {}, setHeader(name, value) { headers.set(name, value); } },
        user: { id: 1, username: "admin", role: "admin", accountEnabled: true },
        authSession: null,
        authFailureReason: null,
      });
      const share = await caller.accessEntries.share({
        accessEntryId: added.accessEntryId,
        format: "WIREGUARD_CONFIG",
      });
      assert.equal(share.format, "WIREGUARD_CONFIG");
      assert.equal("uri" in share, false);
      assert.match(share.fileName, /^forwardx-[a-z0-9-]+\.conf$/);
      assert.match(share.content, /^\[Interface\]\nPrivateKey = [A-Za-z0-9+/]{43}=\nAddress = 10\.0\.0\.4\/32/m);
      assert.match(share.content, /\n\[Peer\]\nPublicKey = [A-Za-z0-9+/]{43}=\nPresharedKey = [A-Za-z0-9+/]{43}=/);
      assert.equal(headers.get("Cache-Control"), "private, no-store, max-age=0");
      assert.equal(headers.get("Pragma"), "no-cache");

      const finalConfig = await generator.generateXrayHostConfig(10, keyring);
      await runtime.executeRaw("UPDATE xray_operations SET status = 'SUCCESS' WHERE operationId = ?", [afterTombstone.operationId]);
      await runtime.executeRaw(
        "UPDATE xray_runtime_reports SET isInstalled = 1, installedVersion = ?, runningVersion = ?, serviceStatus = 'RUNNING', processId = 4242, binarySha256 = ?, appliedGeneration = 4, appliedConfigHash = ?, listenersJson = ? WHERE hostId = 10",
        [artifacts.XRAY_DEFAULT_VERSION, artifacts.XRAY_DEFAULT_VERSION, "a".repeat(64), finalConfig.configHash, JSON.stringify([{
          runtimeTag: inbound.tag, network: "udp", port: 29401, status: "READY", errorCode: null,
        }])],
      );
      assert.equal((await queryService.listXrayInboundSummaries({ hostId: 10 })).items[0].deploymentStatus, "RUNNING");
      assert.deepEqual((await queryService.getXrayInboundDetail(created.inboundId)).inbound.listenerNetworks, ["UDP"]);

      await runtime.executeRaw(
        "UPDATE xray_access_entries SET isEnabled = CASE WHEN id = ? THEN 1 ELSE 0 END WHERE inboundId = ? AND pendingDelete = 0",
        [afterTombstone.accessEntryId, created.inboundId],
      );
      await expectCode(accessService.updateXrayAccessEntryForInbound({
        id: afterTombstone.accessEntryId, userId: 1, isEnabled: false, expectedGeneration: 4,
      }), "LAST_ACTIVE_ACCESS_REQUIRED");
      assert.equal((await runtime.queryRaw("SELECT desiredGeneration FROM xray_host_deployments WHERE hostId = 10"))[0].desiredGeneration, 4);
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
        JWT_SECRET: "xray-wireguard-create-test-secret",
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("HTTP proxy create and account CRUD keep Basic credentials encrypted, required, and share-only", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-http-create-"));
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const runtime = await load("server/dbRuntime.ts");
    const schema = await load("server/dbSchema.ts");
    const artifacts = await load("server/xrayArtifacts.ts");
    const ports = await load("server/xrayPortOperations.ts");
    const accessService = await load("server/xrayAccessService.ts");
    const accessRepository = await load("server/repositories/xrayAccessRepository.ts");
    const queryService = await load("server/xrayQueryService.ts");
    const generator = await load("server/xrayConfigGenerator.ts");
    const heartbeat = await load("server/xrayHeartbeatState.ts");
    const secrets = await load("server/xraySecretCrypto.ts");
    const versions = await load("shared/versions.ts");
    const { xrayRouter } = await load("server/routers/xray.ts");
    const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
    const nowIso = () => new Date().toISOString();
    const expectCode = async (promise, code) => assert.rejects(promise, (error) =>
      error?.cause?.code === code || error?.code === code || error?.message === code);
    const reserveTcp = async (port) => {
      const operation = await ports.createXrayPortProbeOperation({
        hostId: 10, userId: 1, mode: "MANUAL", manualPort: port, network: "TCP",
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
        result: { ports: [{ port, available: true, errorCode: null }], observedAt: nowIso() },
      });
      return ports.getXrayPortProbeOperationResult(operation.operationId, 1);
    };

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

      const headers = new Map();
      const caller = xrayRouter.createCaller({
        req: { headers: {} },
        res: { clearCookie() {}, setHeader(name, value) { headers.set(name, value); } },
        user: { id: 1, username: "admin", role: "admin", accountEnabled: true },
        authSession: null,
        authFailureReason: null,
      });
      const reservation = await reserveTcp(29501);
      const created = await caller.inbounds.createV2({
        hostId: 10,
        name: "Admin HTTP proxy",
        publicAddress: "8.8.8.8",
        portReservationId: reservation.reservationId,
        listenPort: 29501,
        profileId: "HTTP_RAW_NONE",
        spec: {},
        initialAccessEntries: [{ name: "operator" }, { name: "automation" }],
      });
      assert.equal(created.desiredGeneration, 1);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT profileId, specJson, protocol, transport, security, tlsCertificateId FROM xray_inbounds WHERE id = ?",
        [created.inboundId],
      ), [{
        profileId: "HTTP_RAW_NONE",
        specJson: "{}",
        protocol: "http",
        transport: "tcp",
        security: "none",
        tlsCertificateId: null,
      }]);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT credentialType, settingsJson FROM xray_access_entries WHERE inboundId = ? ORDER BY sortOrder, id",
        [created.inboundId],
      ), [
        { credentialType: "HTTP_BASIC", settingsJson: '{"schemaVersion":1}' },
        { credentialType: "HTTP_BASIC", settingsJson: '{"schemaVersion":1}' },
      ]);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT s.kind, COUNT(*) count FROM xray_access_secrets s JOIN xray_access_entries a ON a.id = s.accessEntryId WHERE a.inboundId = ? GROUP BY s.kind ORDER BY s.kind",
        [created.inboundId],
      ), [{ kind: "PASSWORD", count: 2 }, { kind: "USERNAME", count: 2 }]);
      assert.equal((await runtime.queryRaw(
        "SELECT COUNT(*) count FROM xray_inbound_secrets WHERE inboundId = ?",
        [created.inboundId],
      ))[0].count, 0);

      const generated = await generator.generateXrayHostConfig(10, keyring);
      const compiledInbound = JSON.parse(generated.configJson).inbounds[0];
      assert.equal(compiledInbound.protocol, "http");
      assert.deepEqual(compiledInbound.settings, {
        accounts: compiledInbound.settings.accounts,
        allowTransparent: false,
        userLevel: 0,
      });
      assert.equal(compiledInbound.settings.accounts.length, 2);
      for (const account of compiledInbound.settings.accounts) {
        assert.match(account.user, /^[A-Za-z0-9_-]{22}$/);
        assert.match(account.pass, /^[A-Za-z0-9_-]{43}$/);
      }
      assert.equal(new Set(compiledInbound.settings.accounts.map((account) => account.user)).size, 2);
      assert.equal(new Set(compiledInbound.settings.accounts.map((account) => account.pass)).size, 2);
      assert.deepEqual(generated.expectedListeners.map(({ network, port }) => ({ network, port })), [
        { network: "tcp", port: 29501 },
      ]);

      const detail = await queryService.getXrayInboundDetail(created.inboundId);
      const detailJson = JSON.stringify(detail);
      for (const account of compiledInbound.settings.accounts) {
        assert.equal(detailJson.includes(account.user), false);
        assert.equal(detailJson.includes(account.pass), false);
      }
      for (const forbiddenKey of ["encryptedValue", "keyVersion", "usernameEncrypted", "passwordEncrypted"]) {
        assert.equal(detailJson.includes(forbiddenKey), false, forbiddenKey);
      }
      const desired = await heartbeat.buildXrayHeartbeatDesiredState(10, { keyring });
      assert.equal(desired.generation, 1);
      assert.equal(desired.configHash, generated.configHash);
      assert.deepEqual(desired.expectedListeners, generated.expectedListeners);

      const entries = await accessRepository.listXrayAccessEntries(created.inboundId);
      const firstShare = await caller.accessEntries.share({ accessEntryId: entries[0].id, format: "HTTP_PROXY_URI" });
      assert.equal(firstShare.format, "HTTP_PROXY_URI");
      assert.equal(firstShare.uri, "http://" + compiledInbound.settings.accounts[0].user + ":" + compiledInbound.settings.accounts[0].pass + "@8.8.8.8:29501");
      assert.equal(new URL(firstShare.uri).hash, "");
      assert.equal(headers.get("Cache-Control"), "private, no-store, max-age=0");
      assert.equal(headers.get("Pragma"), "no-cache");
      await expectCode(accessService.getXrayAccessEntryShare(entries[0].id, "TROJAN_URI"), "INVALID_CONFIG_INPUT");

      const added = await accessService.createXrayAccessEntryForInbound({
        inboundId: created.inboundId, userId: 1, name: "breakglass", expectedGeneration: 1,
      });
      assert.equal(added.desiredGeneration, 2);
      const beforeRename = await accessService.getXrayAccessEntryShare(added.accessEntryId, "HTTP_PROXY_URI");
      const renamed = await accessService.updateXrayAccessEntryForInbound({
        id: added.accessEntryId, userId: 1, name: "breakglass renamed", expectedGeneration: 2,
      });
      assert.equal(renamed.desiredGeneration, 3);
      const afterRename = await accessService.getXrayAccessEntryShare(added.accessEntryId, "HTTP_PROXY_URI");
      assert.equal(afterRename.uri, beforeRename.uri);

      assert.equal((await accessService.updateXrayAccessEntryForInbound({
        id: entries[0].id, userId: 1, isEnabled: false, expectedGeneration: 3,
      })).desiredGeneration, 4);
      assert.equal((await accessService.removeXrayAccessEntryForInbound({
        id: entries[0].id, userId: 1, expectedGeneration: 4,
      })).desiredGeneration, 5);
      const second = (await accessRepository.listXrayAccessEntries(created.inboundId)).find((entry) => entry.id === entries[1].id);
      assert.equal((await accessService.updateXrayAccessEntryForInbound({
        id: second.id, userId: 1, isEnabled: false, expectedGeneration: 5,
      })).desiredGeneration, 6);
      await expectCode(accessService.updateXrayAccessEntryForInbound({
        id: added.accessEntryId, userId: 1, isEnabled: false, expectedGeneration: 6,
      }), "LAST_ACTIVE_ACCESS_REQUIRED");
      const finalConfig = JSON.parse((await generator.generateXrayHostConfig(10, keyring)).configJson).inbounds[0];
      assert.equal(finalConfig.settings.accounts.length, 1);
      assert.equal(finalConfig.settings.accounts[0].user, new URL(afterRename.uri).username);
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
        JWT_SECRET: "xray-http-create-test-secret",
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
