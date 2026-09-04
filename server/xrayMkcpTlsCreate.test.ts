import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("UDP TLS profiles require capabilities/reservations and keep credentials generic-only", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-mkcp-tls-create-"));
  const certificatePath = path.join(directory, "certificate.pem");
  const privateKeyPath = path.join(directory, "private-key.pem");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
    "-subj", "/CN=tls.example.com", "-keyout", privateKeyPath, "-out", certificatePath,
    "-addext", "basicConstraints=critical,CA:FALSE",
    "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
    "-addext", "extendedKeyUsage=serverAuth",
    "-addext", "subjectAltName=DNS:tls.example.com",
  ], { stdio: "ignore" });

  const script = String.raw`
    import assert from "node:assert/strict";
    import fs from "node:fs";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const runtime = await load("server/dbRuntime.ts");
    const schema = await load("server/dbSchema.ts");
    const artifacts = await load("server/xrayArtifacts.ts");
    const ports = await load("server/xrayPortOperations.ts");
    const heartbeat = await load("server/xrayHeartbeatState.ts");
    const inboundService = await load("server/xrayInboundService.ts");
    const certificateRepository = await load("server/repositories/xrayTlsCertificateRepository.ts");
    const secrets = await load("server/xraySecretCrypto.ts");
    const versions = await load("shared/versions.ts");
    const { xrayRouter } = await load("server/routers/xray.ts");
    const certificatePem = fs.readFileSync(process.env.FORWARDX_TEST_CERT_PATH, "utf8");
    const privateKeyPem = fs.readFileSync(process.env.FORWARDX_TEST_KEY_PATH, "utf8");
    const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
    const caller = xrayRouter.createCaller({
      req: { headers: {} }, res: { clearCookie() {}, setHeader() {} },
      user: { id: 1, username: "admin", role: "admin", accountEnabled: true },
      authSession: null, authFailureReason: null,
    });
    const nowIso = () => new Date().toISOString();
    let certificate;
    const reserve = async (port, network = "udp") => {
      const operation = await ports.createXrayPortProbeOperation({
        hostId: 10, userId: 1, mode: "MANUAL", manualPort: port, network,
      });
      const [task] = await ports.takeXrayPortProbeTasks(10, 1);
      await ports.completeXrayPortProbeTask(10, {
        schemaVersion: 1, taskId: task.taskId, type: "PORT_PROBE", status: "SUCCESS",
        startedAt: nowIso(), finishedAt: nowIso(), error: null,
        result: { ports: [{ port, available: true, errorCode: null }], observedAt: nowIso() },
      });
      return ports.getXrayPortProbeOperationResult(operation.operationId, 1);
    };
    const input = (profileId, reservation) => ({
      hostId: 10, userId: 1, name: profileId, publicAddress: "8.8.8.8",
      portReservationId: reservation.reservationId, listenPort: reservation.selectedPort,
      profileId, spec: {}, tlsCertificateId: certificate.id, serverName: "tls.example.com",
      initialAccessEntries: [{ name: "phone" }],
    });
    const enableUdpProfiles = {
      isProfileEnabledForInternalTest: (profile) => profile.id === "VLESS_MKCP_TLS"
        || profile.id === "TROJAN_MKCP_TLS" || profile.id === "HYSTERIA2_TLS",
    };
    const expectCode = (promise, code) => assert.rejects(promise, (error) =>
      error?.cause?.code === code || error?.code === code || error?.message === code);

    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      const now = Math.floor(Date.now() / 1000);
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw(
        "INSERT INTO hosts (id, name, ip, ipv4, isOnline, lastHeartbeat, agentVersion, agentDistribution, userId) VALUES (10, 'edge-a', '8.8.8.8', '8.8.8.8', 1, ?, ?, 'forwardplus', 1)",
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
      certificate = await certificateRepository.createXrayTlsCertificate({
        hostId: 10, name: "Edge TLS", certificatePem, privateKeyPem, createdByUserId: 1,
      }, { keyring });

      await assert.rejects(caller.inbounds.createV2({
        ...input("VLESS_MKCP_TLS", { reservationId: "missing", selectedPort: 29200 }),
        spec: { seed: "legacy-seed" },
      }));

      const vlessReservation = await reserve(29201);
      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsUdpPortProbe = 0 WHERE hostId = 10");
      assert.deepEqual((await caller.profiles.catalog({ hostId: 10 }))
        .filter((profile) => profile.listenerNetworks.includes("UDP"))
        .map((profile) => [profile.id, profile.isAvailable, profile.unavailableReasonCode]), [
        ["VLESS_MKCP_TLS", false, "UDP_CAPABILITY_REQUIRED"],
        ["TROJAN_MKCP_TLS", false, "UDP_CAPABILITY_REQUIRED"],
        ["HYSTERIA2_TLS", false, "UDP_CAPABILITY_REQUIRED"],
      ]);
      await expectCode(
        inboundService.createXrayInboundV2(input("VLESS_MKCP_TLS", vlessReservation), enableUdpProfiles),
        "UDP_CAPABILITY_REQUIRED",
      );
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_inbounds"))[0].count, 0);
      assert.equal(ports.validateXrayPortReservation({
        reservationId: vlessReservation.reservationId, hostId: 10, userId: 1, port: 29201, network: "udp",
      }).network, "udp");
      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsUdpPortProbe = 1 WHERE hostId = 10");
      assert.deepEqual((await caller.profiles.catalog({ hostId: 10 }))
        .filter((profile) => profile.listenerNetworks.includes("UDP"))
        .map((profile) => [profile.isAvailable, profile.unavailableReasonCode]), [
        [true, null], [true, null], [true, null],
      ]);
      assert.equal((await inboundService.createXrayInboundV2(
        input("VLESS_MKCP_TLS", vlessReservation), enableUdpProfiles,
      )).desiredGeneration, 1);

      const trojanReservation = await reserve(29202);
      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsUdpListenerReadiness = 0 WHERE hostId = 10");
      await expectCode(
        inboundService.createXrayInboundV2(input("TROJAN_MKCP_TLS", trojanReservation), enableUdpProfiles),
        "UDP_CAPABILITY_REQUIRED",
      );
      assert.equal((await runtime.queryRaw("SELECT desiredGeneration FROM xray_host_deployments WHERE hostId = 10"))[0].desiredGeneration, 1);
      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsUdpListenerReadiness = 1 WHERE hostId = 10");
      assert.equal((await inboundService.createXrayInboundV2(
        input("TROJAN_MKCP_TLS", trojanReservation), enableUdpProfiles,
      )).desiredGeneration, 2);

      const hysteriaReservation = await reserve(29204);
      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsUdpPortProbe = 0 WHERE hostId = 10");
      await expectCode(
        inboundService.createXrayInboundV2(input("HYSTERIA2_TLS", hysteriaReservation), enableUdpProfiles),
        "UDP_CAPABILITY_REQUIRED",
      );
      assert.equal((await runtime.queryRaw("SELECT desiredGeneration FROM xray_host_deployments WHERE hostId = 10"))[0].desiredGeneration, 2);
      assert.equal(ports.validateXrayPortReservation({
        reservationId: hysteriaReservation.reservationId, hostId: 10, userId: 1, port: 29204, network: "udp",
      }).network, "udp");
      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsUdpPortProbe = 1 WHERE hostId = 10");
      const hysteria = await inboundService.createXrayInboundV2(
        input("HYSTERIA2_TLS", hysteriaReservation), enableUdpProfiles,
      );
      assert.equal(hysteria.desiredGeneration, 3);

      const tcpReservation = await reserve(29203, "tcp");
      await expectCode(
        inboundService.createXrayInboundV2(input("VLESS_MKCP_TLS", tcpReservation), enableUdpProfiles),
        "PORT_RESERVATION_MISMATCH",
      );
      assert.equal(ports.validateXrayPortReservation({
        reservationId: tcpReservation.reservationId, hostId: 10, userId: 1, port: 29203,
      }).network, "tcp");
      ports.consumeXrayPortReservation({
        reservationId: tcpReservation.reservationId, hostId: 10, userId: 1, port: 29203,
      });

      assert.deepEqual(await runtime.queryRaw(
        "SELECT profileId, protocol, transport, security, specJson FROM xray_inbounds ORDER BY id",
      ), [{
        profileId: "VLESS_MKCP_TLS", protocol: "vless", transport: "kcp", security: "tls", specJson: "{}",
      }, {
        profileId: "TROJAN_MKCP_TLS", protocol: "trojan", transport: "kcp", security: "tls", specJson: "{}",
      }, {
        profileId: "HYSTERIA2_TLS", protocol: "hysteria", transport: "hysteria", security: "tls", specJson: "{}",
      }]);

      const [vlessInbound, trojanInbound, hysteriaInbound] = await runtime.queryRaw("SELECT id FROM xray_inbounds ORDER BY id");
      const vlessAccess = await caller.accessEntries.create({
        inboundId: vlessInbound.id, name: "laptop", expectedGeneration: 3,
      });
      assert.equal(vlessAccess.desiredGeneration, 4);
      const trojanAccess = await caller.accessEntries.create({
        inboundId: trojanInbound.id, name: "laptop", expectedGeneration: 4,
      });
      assert.equal(trojanAccess.desiredGeneration, 5);
      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsUdpListenerReadiness = 0 WHERE hostId = 10");
      await expectCode(caller.accessEntries.create({
        inboundId: hysteriaInbound.id, name: "laptop", expectedGeneration: 5,
      }), "UDP_CAPABILITY_REQUIRED");
      assert.equal((await runtime.queryRaw("SELECT desiredGeneration FROM xray_host_deployments WHERE hostId = 10"))[0].desiredGeneration, 5);
      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsUdpListenerReadiness = 1 WHERE hostId = 10");
      const hysteriaAccess = await caller.accessEntries.create({
        inboundId: hysteriaInbound.id, name: "laptop", expectedGeneration: 5,
      });
      assert.equal(hysteriaAccess.desiredGeneration, 6);
      const vlessUri = new URL((await caller.accessEntries.share({
        accessEntryId: vlessAccess.accessEntryId, format: "VLESS_URI",
      })).uri);
      const trojanUri = new URL((await caller.accessEntries.share({
        accessEntryId: trojanAccess.accessEntryId, format: "TROJAN_URI",
      })).uri);
      for (const uri of [vlessUri, trojanUri]) {
        assert.equal(uri.searchParams.get("type"), "kcp");
        assert.equal(uri.searchParams.get("security"), "tls");
        assert.equal(uri.searchParams.get("sni"), "tls.example.com");
        assert.equal(uri.searchParams.get("fp"), "chrome");
        assert.match(uri.searchParams.get("pcs") ?? "", /^[0-9a-f]{64}$/);
        for (const forbidden of ["flow", "seed", "headerType", "allowInsecure"]) {
          assert.equal(uri.searchParams.has(forbidden), false, forbidden);
        }
      }
      assert.equal(vlessUri.searchParams.get("encryption"), "none");
      const hysteriaShare = new URL((await caller.accessEntries.share({
        accessEntryId: hysteriaAccess.accessEntryId, format: "HYSTERIA2_URI",
      })).uri);
      assert.equal(hysteriaShare.protocol, "hysteria2:");
      assert.equal(hysteriaShare.searchParams.get("sni"), "tls.example.com");
      assert.equal(hysteriaShare.searchParams.get("pinSHA256"), certificate.leafFingerprintSha256);
      assert.deepEqual([...hysteriaShare.searchParams.keys()], ["sni", "pinSHA256"]);
      const [hysteriaRow] = await runtime.queryRaw(
        "SELECT a.credentialType, a.settingsJson, a.statsKey, s.kind, s.encryptedValue FROM xray_access_entries a JOIN xray_access_secrets s ON s.accessEntryId = a.id WHERE a.id = ?",
        [hysteriaAccess.accessEntryId],
      );
      assert.equal(hysteriaRow.credentialType, "HYSTERIA_AUTH");
      assert.equal(hysteriaRow.settingsJson, '{"schemaVersion":1}');
      assert.equal(hysteriaRow.kind, "HYSTERIA_AUTH");
      const hysteriaAuth = secrets.decryptXraySecret(
        hysteriaRow.encryptedValue,
        secrets.xrayAccessSecretContext(hysteriaRow.statsKey, "HYSTERIA_AUTH"),
        keyring,
      );
      assert.equal(Buffer.from(hysteriaAuth, "base64url").length, 32);
      assert.equal(Buffer.from(hysteriaAuth, "base64url").toString("base64url"), hysteriaAuth);
      assert.equal(hysteriaShare.username, hysteriaAuth);
      assert.equal((await caller.accessEntries.remove({
        id: hysteriaAccess.accessEntryId, expectedGeneration: 6,
      })).desiredGeneration, 7);
      const [initialHysteriaAccess] = await runtime.queryRaw(
        "SELECT id FROM xray_access_entries WHERE inboundId = ? AND pendingDelete = 0 ORDER BY id",
        [hysteriaInbound.id],
      );
      await expectCode(caller.accessEntries.remove({
        id: initialHysteriaAccess.id, expectedGeneration: 7,
      }), "LAST_ACTIVE_ACCESS_REQUIRED");
      assert.equal((await caller.accessEntries.update({
        id: vlessAccess.accessEntryId, name: "travel", expectedGeneration: 7,
      })).desiredGeneration, 8);
      assert.equal((await caller.accessEntries.remove({
        id: trojanAccess.accessEntryId, expectedGeneration: 8,
      })).desiredGeneration, 9);

      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsUdpListenerReadiness = 0 WHERE hostId = 10");
      await expectCode(caller.inbounds.update({
        id: hysteriaInbound.id, name: "blocked rename", expectedGeneration: 9,
      }), "UDP_CAPABILITY_REQUIRED");
      assert.equal((await runtime.queryRaw("SELECT desiredGeneration FROM xray_host_deployments WHERE hostId = 10"))[0].desiredGeneration, 9);
      assert.equal(await heartbeat.buildXrayHeartbeatDesiredState(10, { keyring }), null);
      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsUdpListenerReadiness = 1 WHERE hostId = 10");
      const desired = await heartbeat.buildXrayHeartbeatDesiredState(10, { keyring });
      assert.deepEqual(desired.expectedListeners.map(({ network, port }) => ({ network, port }))
        .sort((left, right) => left.port - right.port), [
        { network: "udp", port: 29201 }, { network: "udp", port: 29202 }, { network: "udp", port: 29204 },
      ]);
      await runtime.executeRaw(
        "UPDATE xray_runtime_reports SET appliedGeneration = ?, appliedConfigHash = ?, installedVersion = ?, runningVersion = ?, serviceStatus = 'RUNNING', listenersJson = ? WHERE hostId = 10",
        [desired.generation, desired.configHash, desired.targetVersion, desired.targetVersion, JSON.stringify(
          desired.expectedListeners.map((listener) => ({ ...listener, status: "READY", errorCode: null })),
        )],
      );
      await runtime.executeRaw("UPDATE xray_operations SET status = 'SUCCESS' WHERE hostId = 10");
      const detail = await caller.inbounds.detail({ id: vlessInbound.id });
      assert.equal(detail.deployment.status, "RUNNING");
      assert.deepEqual(detail.inbound.listenerNetworks, ["UDP"]);
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
        FORWARDX_TEST_CERT_PATH: certificatePath,
        FORWARDX_TEST_KEY_PATH: privateKeyPath,
        XRAY_MASTER_KEY_PATH: path.join(directory, "xray-master.key"),
        JWT_SECRET: "xray-mkcp-tls-create-test-secret",
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
