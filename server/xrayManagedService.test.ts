import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("managed MTProto and AmneziaWG create, secrets, share, generation, and cleanup stay atomic and isolated", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-managed-mtproto-"));
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const runtime = await load("server/dbRuntime.ts");
    const schema = await load("server/dbSchema.ts");
    const ports = await load("server/xrayPortOperations.ts");
    const artifacts = await load("server/xrayManagedServiceArtifacts.ts");
    const services = await load("server/xrayManagedServiceService.ts");
    const wireguard = await load("server/xrayWireGuard.ts");
    const secrets = await load("server/xraySecretCrypto.ts");
    const observability = await load("server/xrayObservability.ts");
    const installer = await load("server/agentInstallScripts.ts");
    const { xrayRouter } = await load("server/routers/xray.ts");
    const nowIso = () => new Date().toISOString();
    const expectCode = async (promise, code) => assert.rejects(promise, (error) =>
      error?.cause?.code === code || error?.code === code || error?.message === code);
    const reservePort = async (port, network) => {
      const operation = await ports.createXrayPortProbeOperation({ hostId: 10, userId: 1, mode: "MANUAL", manualPort: port, network });
      const [task] = await ports.takeXrayPortProbeTasks(10, 1);
      await ports.completeXrayPortProbeTask(10, {
        schemaVersion: 1,
        taskId: task.taskId,
        type: "PORT_PROBE",
        status: "SUCCESS",
        startedAt: nowIso(),
        finishedAt: nowIso(),
        result: { ports: [{ port, available: true, errorCode: null }], observedAt: nowIso() },
        error: null,
      });
      return ports.getXrayPortProbeOperationResult(operation.operationId, 1);
    };

    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      const managedTableNames = [
        "xray_managed_services", "xray_managed_service_instance_secrets", "xray_managed_service_accounts",
        "xray_managed_service_secrets", "xray_managed_service_deployments", "xray_managed_service_runtime_reports",
        "xray_managed_service_artifacts",
      ];
      const managedTableDefs = schema.getDatabaseTableDefs().filter((table) => managedTableNames.includes(table.name));
      assert.deepEqual(managedTableDefs.map((table) => table.name), managedTableNames);
      assert.deepEqual(managedTableDefs.find((table) => table.name === "xray_managed_service_accounts").columns
        .filter((column) => ["settingsVersion", "settingsJson"].includes(column.name))
        .map((column) => [column.name, column.notNull, column.default]), [
        ["settingsVersion", true, 1], ["settingsJson", true, "{}"],
      ]);
      const mysqlQueries = [];
      await schema.ensureDatabaseSchema({
        getConnection() { throw new Error("not used"); },
        async query(sql) { mysqlQueries.push(sql); return [[], []]; },
        async execute() { return [[], []]; },
      });
      const postgresQueries = [];
      await schema.ensureDatabaseSchema({ async query(sql) { postgresQueries.push(sql); return { rows: [] }; } });
      const mysqlQuote = String.fromCharCode(96);
      for (const table of managedTableNames) {
        assert.equal(mysqlQueries.some((sql) => sql.startsWith("CREATE TABLE IF NOT EXISTS " + mysqlQuote + table + mysqlQuote)), true, "mysql:" + table);
        assert.equal(postgresQueries.some((sql) => sql.startsWith('CREATE TABLE IF NOT EXISTS "' + table + '"')), true, "postgresql:" + table);
      }
      assert.equal(mysqlQueries.some((sql) => sql.includes("UNIQUE KEY " + mysqlQuote + "uniq_xray_managed_service_instance_secrets_serviceId_kind" + mysqlQuote)), true);
      assert.equal(postgresQueries.some((sql) => sql.includes('CREATE UNIQUE INDEX IF NOT EXISTS "uniq_xray_managed_service_instance_secrets_serviceId_kind"')), true);
      const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
      const now = Math.floor(Date.now() / 1000);
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw(
        "INSERT INTO hosts (id, name, ip, ipv4, isOnline, lastHeartbeat, agentVersion, userId) VALUES (10, 'edge', '8.8.8.8', '8.8.8.8', 1, ?, '2.10.0', 1)",
        [now],
      );
      await runtime.executeRaw(
        "INSERT INTO xray_runtime_reports (hostId, capabilitySchemaVersion, supportedOS, supportedArch, supportsArtifactInstall, supportsPortProbe, supportsUdpPortProbe, supportsUdpListenerReadiness, supportsRealityScan) VALUES (10, 1, 'linux', 'amd64', 1, 1, 1, 1, 1)",
      );
      const capability = {
        schemaVersion: 1,
        supportedKinds: ["MTPROTO_FAKE_TLS"],
        kindCapabilities: [
          { kind: "MTPROTO_FAKE_TLS", supervisor: "AGENT_CHILD", supportsArtifactInstall: true, runsAsDedicatedUser: true, network: "tcp" },
          { kind: "AMNEZIAWG", supervisor: "AGENT_CHILD", supportsArtifactInstall: false, runsAsDedicatedUser: true, network: "udp" },
        ],
        supervisor: "AGENT_CHILD",
        supportsArtifactInstall: true,
        runsAsDedicatedUser: true,
        supportedOS: "linux",
        supportedArch: "amd64",
      };
      await runtime.executeRaw(
        "INSERT INTO xray_managed_service_runtime_reports (hostId, capabilityJson, updatedAt) VALUES (10, ?, ?)",
        [JSON.stringify(capability), now],
      );
      const artifact = artifacts.MANAGED_SERVICE_ARTIFACT_MANIFEST.find((entry) => entry.arch === "amd64");
      await runtime.executeRaw(
        "INSERT INTO xray_managed_service_artifacts (kind, version, os, arch, packageFormat, storageKey, sha256, fileSize, status, source, verifiedAt, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'VERIFIED', ?, ?, ?, ?)",
        [artifact.kind, artifact.version, artifact.os, artifact.arch, artifact.packageFormat, artifact.storageKey, artifact.sha256, artifact.fileSize, artifact.source, now, now, now],
      );

      const headers = new Map();
      const caller = xrayRouter.createCaller({
        req: { headers: {} },
        res: { clearCookie() {}, setHeader(name, value) { headers.set(name, value); } },
        user: { id: 1, username: "admin", role: "admin", accountEnabled: true },
        authSession: null,
        authFailureReason: null,
      });
      const reservation = await reservePort(24443, "TCP");
      const createInput = {
        hostId: 10,
        name: "Telegram edge",
        publicAddress: "MT.EXAMPLE.COM",
        listenPort: 24443,
        portReservationId: reservation.reservationId,
        fakeTlsDomain: "EXAMPLE.COM",
        initialAccounts: [{ name: "primary" }],
      };
      await expectCode(caller.managedServices.createMtproto({ ...createInput, shellCommand: "id" }), "BAD_REQUEST");
      const created = await caller.managedServices.createMtproto(createInput);
      assert.equal(created.desiredGeneration, 1);
      await expectCode(Promise.resolve().then(() => ports.validateXrayPortReservation({
        reservationId: reservation.reservationId, hostId: 10, userId: 1, port: 24443, network: "tcp",
      })), "PORT_RESERVATION_EXPIRED");

      const [serviceRow] = await runtime.queryRaw("SELECT * FROM xray_managed_services WHERE id = ?", [created.serviceId]);
      const [accountRow] = await runtime.queryRaw("SELECT * FROM xray_managed_service_accounts WHERE id = ?", [created.accountIds[0]]);
      const [secretRow] = await runtime.queryRaw("SELECT * FROM xray_managed_service_secrets WHERE accountId = ?", [created.accountIds[0]]);
      assert.equal(serviceRow.publicAddress, "mt.example.com");
      assert.equal(serviceRow.specJson, '{"fakeTlsDomain":"example.com"}');
      assert.notEqual(secretRow.encryptedValue, "");
      assert.match(secretRow.fingerprint, /^[0-9a-f]{64}$/);

      const desired = await services.buildXrayManagedServicesDesiredState(10, { keyring, issuedAt: new Date("2026-09-02T08:00:00.000Z") });
      const plaintextSecret = desired.services[0].accounts[0].secret;
      assert.match(plaintextSecret, /^ee[0-9a-f]{32}6578616d706c652e636f6d$/);
      assert.equal(String(secretRow.encryptedValue).includes(plaintextSecret), false);
      assert.throws(() => secrets.decryptXraySecret(
        secretRow.encryptedValue,
        secrets.xrayManagedServiceAccountSecretContext(accountRow.accountTag + "-other"),
        keyring,
      ));

      const detail = await caller.managedServices.detail({ id: created.serviceId });
      const list = await caller.managedServices.list({ page: 1, pageSize: 20, search: "telegram" });
      assert.equal(list.total, 1);
      assert.equal(detail.accounts[0].secretConfigured, true);
      const ordinaryDto = JSON.stringify({ detail, list });
      for (const forbidden of [plaintextSecret, "encryptedValue", "fingerprint", "keyVersion"]) {
        assert.equal(ordinaryDto.includes(forbidden), false, forbidden);
      }

      const share = await caller.managedServices.share({ accountId: created.accountIds[0] });
      assert.equal(share.kind, "MTPROTO_PROXY");
      assert.equal(share.server, "mt.example.com");
      assert.equal(share.port, 24443);
      assert.equal(share.secret, plaintextSecret);
      const shareUrl = new URL(share.uri);
      assert.equal(shareUrl.protocol, "tg:");
      assert.equal(shareUrl.searchParams.get("server"), "mt.example.com");
      assert.equal(shareUrl.searchParams.get("secret"), plaintextSecret);
      assert.equal(headers.get("Cache-Control"), "private, no-store, max-age=0");
      assert.equal(headers.get("Pragma"), "no-cache");
      assert.equal(observability.scrubXraySensitiveText(share.uri), "tg://[REDACTED]");

      await expectCode(caller.managedServices.accounts.update({
        id: created.accountIds[0], isEnabled: false, expectedGeneration: 1,
      }), "CONFLICT");
      const secondary = await caller.managedServices.accounts.create({ serviceId: created.serviceId, name: "secondary", expectedGeneration: 1 });
      assert.equal(secondary.desiredGeneration, 2);
      assert.equal((await caller.managedServices.accounts.update({
        id: created.accountIds[0], isEnabled: false, expectedGeneration: 2,
      })).desiredGeneration, 3);
      assert.equal((await caller.managedServices.accounts.remove({
        id: created.accountIds[0], expectedGeneration: 3,
      })).desiredGeneration, 4);
      assert.equal((await caller.managedServices.remove({
        id: created.serviceId, expectedGeneration: 4, confirmName: "Telegram edge",
      })).desiredGeneration, 5);

      const awgReservation = await reservePort(25120, "UDP");
      const awgInput = {
        hostId: 10,
        name: "Private edge",
        publicAddress: "VPN.EXAMPLE.COM",
        listenPort: 25120,
        portReservationId: awgReservation.reservationId,
        initialPeers: [{ name: "phone" }],
      };
      await expectCode(caller.managedServices.createAmneziawg({ ...awgInput, mtu: 1280 }), "BAD_REQUEST");
      const awgCreated = await caller.managedServices.createAmneziawg(awgInput);
      assert.equal(awgCreated.desiredGeneration, 6);
      await expectCode(Promise.resolve().then(() => ports.validateXrayPortReservation({
        reservationId: awgReservation.reservationId, hostId: 10, userId: 1, port: 25120, network: "udp",
      })), "PORT_RESERVATION_EXPIRED");

      const [awgServiceRow] = await runtime.queryRaw("SELECT * FROM xray_managed_services WHERE id = ?", [awgCreated.serviceId]);
      const [awgPeerRow] = await runtime.queryRaw("SELECT * FROM xray_managed_service_accounts WHERE id = ?", [awgCreated.accountIds[0]]);
      const awgInstanceSecrets = await runtime.queryRaw("SELECT * FROM xray_managed_service_instance_secrets WHERE serviceId = ? ORDER BY kind", [awgCreated.serviceId]);
      const awgPeerSecrets = await runtime.queryRaw("SELECT * FROM xray_managed_service_secrets WHERE accountId = ? ORDER BY kind", [awgCreated.accountIds[0]]);
      assert.equal(awgServiceRow.publicAddress, "vpn.example.com");
      assert.equal(awgServiceRow.kind, "AMNEZIAWG");
      assert.equal("headerProtectionKey" in JSON.parse(awgServiceRow.specJson), false);
      assert.equal(awgPeerRow.settingsVersion, 1);
      assert.deepEqual(Object.keys(JSON.parse(awgPeerRow.settingsJson)).sort(), ["address", "publicKey"]);
      assert.deepEqual(awgInstanceSecrets.map((row) => row.kind), ["AMNEZIAWG_HEADER_PROTECTION_KEY", "AMNEZIAWG_SERVER_PRIVATE_KEY"]);
      assert.deepEqual(awgPeerSecrets.map((row) => row.kind), ["AMNEZIAWG_PRE_SHARED_KEY", "AMNEZIAWG_PRIVATE_KEY"]);
      for (const row of [...awgInstanceSecrets, ...awgPeerSecrets]) {
        assert.match(row.encryptedValue, /^fwdx-secret:v1:/);
        assert.match(row.fingerprint, /^[0-9a-f]{64}$/);
        assert.equal(row.keyVersion, 1);
      }

      const awgDesired = await services.buildXrayManagedServicesDesiredState(10, {
        keyring, issuedAt: new Date("2026-09-03T08:00:00.000Z"),
      });
      assert.equal(awgDesired.generation, 6);
      assert.equal(awgDesired.services.length, 1);
      const awgService = awgDesired.services[0];
      assert.equal(awgService.kind, "AMNEZIAWG");
      assert.equal(awgService.publicAddress, "vpn.example.com");
      assert.equal(awgService.listenPort, 25120);
      assert.equal(awgService.peers[0].address, "10.8.1.2/32");
      const peerPrivateRow = awgPeerSecrets.find((row) => row.kind === "AMNEZIAWG_PRIVATE_KEY");
      const peerPskRow = awgPeerSecrets.find((row) => row.kind === "AMNEZIAWG_PRE_SHARED_KEY");
      const headerKeyRow = awgInstanceSecrets.find((row) => row.kind === "AMNEZIAWG_HEADER_PROTECTION_KEY");
      const peerPrivateKey = secrets.decryptXraySecret(peerPrivateRow.encryptedValue,
        secrets.xrayManagedServiceAccountSecretContext(awgPeerRow.accountTag, "AMNEZIAWG_PRIVATE_KEY"), keyring);
      const peerPreSharedKey = secrets.decryptXraySecret(peerPskRow.encryptedValue,
        secrets.xrayManagedServiceAccountSecretContext(awgPeerRow.accountTag, "AMNEZIAWG_PRE_SHARED_KEY"), keyring);
      const headerProtectionKey = secrets.decryptXraySecret(headerKeyRow.encryptedValue,
        secrets.xrayManagedServiceInstanceSecretContext(awgServiceRow.serviceTag, "AMNEZIAWG_HEADER_PROTECTION_KEY"), keyring);
      assert.equal(wireguard.deriveXrayWireGuardPublicKey(peerPrivateKey), awgService.peers[0].publicKey);
      assert.equal(peerPreSharedKey, awgService.peers[0].preSharedKey);
      assert.equal(headerProtectionKey, awgService.obfuscation.headerProtectionKey);
      assert.equal(JSON.stringify(awgDesired).includes(peerPrivateKey), false);
      for (const row of [...awgInstanceSecrets, ...awgPeerSecrets]) {
        for (const plaintext of [awgService.serverPrivateKey, peerPrivateKey, peerPreSharedKey, headerProtectionKey]) {
          assert.equal(String(row.encryptedValue).includes(plaintext), false);
        }
      }

      const awgDetail = await caller.managedServices.detail({ id: awgCreated.serviceId });
      const awgList = await caller.managedServices.list({ page: 1, pageSize: 20, search: "private" });
      assert.equal(awgList.total, 1);
      assert.equal(awgDetail.accounts[0].address, "10.8.1.2/32");
      assert.equal(awgDetail.accounts[0].secretConfigured, true);
      const awgOrdinaryDto = JSON.stringify({ detail: awgDetail, list: awgList });
      for (const forbidden of [
        awgService.serverPrivateKey, peerPrivateKey, peerPreSharedKey, headerProtectionKey,
        "encryptedValue", "fingerprint", "keyVersion", "publicKey", "privateKey", "preSharedKey",
        "headerProtectionKey", "obfuscation", "randomTrailers", "disableCookies",
      ]) assert.equal(awgOrdinaryDto.includes(forbidden), false, forbidden);

      const awgShare = await caller.managedServices.share({ accountId: awgCreated.accountIds[0] });
      assert.equal(awgShare.kind, "AMNEZIAWG_CONFIG");
      assert.match(awgShare.fileName, /^forwardx-[a-z0-9-]+\.conf$/);
      assert.match(awgShare.content, /^\[Interface\]\n/);
      assert.equal(awgShare.content.includes("PrivateKey = " + peerPrivateKey), true);
      assert.equal(awgShare.content.includes("PresharedKey = " + peerPreSharedKey), true);
      assert.equal(awgShare.content.includes("HeaderProtectionKey = " + headerProtectionKey), true);
      assert.equal(awgShare.content.includes("Endpoint = vpn.example.com:25120"), true);
      assert.equal(awgShare.vpnUri.includes("="), false);
      assert.equal(Buffer.from(awgShare.vpnUri.slice("vpn://".length), "base64url").toString("utf8"), awgShare.content);
      assert.equal(headers.get("Cache-Control"), "private, no-store, max-age=0");
      assert.equal(headers.get("Pragma"), "no-cache");
      assert.equal(observability.scrubXraySensitiveText(awgShare.vpnUri), "vpn://[REDACTED]");

      await expectCode(services.createXrayMtprotoService({
        hostId: 10, userId: 1, name: "port conflict", publicAddress: "mt2.example.com", listenPort: 25120,
        fakeTlsDomain: "example.com", initialAccounts: [{ name: "collision" }],
      }), "INVALID_MANAGED_SERVICE_INPUT");
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_managed_services WHERE pendingDelete = 0"))[0].count, 1);

      const awgSecondary = await caller.managedServices.accounts.create({
        serviceId: awgCreated.serviceId, name: "tablet", expectedGeneration: 6,
      });
      assert.equal(awgSecondary.desiredGeneration, 7);
      assert.equal((await caller.managedServices.accounts.update({
        id: awgCreated.accountIds[0], name: "phone old", isEnabled: false, expectedGeneration: 7,
      })).desiredGeneration, 8);
      assert.equal((await caller.managedServices.accounts.remove({
        id: awgCreated.accountIds[0], expectedGeneration: 8,
      })).desiredGeneration, 9);
      const peerRows = await runtime.queryRaw("SELECT name, settingsJson FROM xray_managed_service_accounts WHERE serviceId = ? AND pendingDelete = 0 ORDER BY id", [awgCreated.serviceId]);
      assert.equal(peerRows.length, 1);
      assert.equal(JSON.parse(peerRows[0].settingsJson).address, "10.8.1.3/32");
      assert.equal((await caller.managedServices.remove({
        id: awgCreated.serviceId, expectedGeneration: 9, confirmName: "Private edge",
      })).desiredGeneration, 10);

      const emptyDesired = await services.buildXrayManagedServicesDesiredState(10, { keyring });
      assert.deepEqual(emptyDesired.services, []);
      const emptyObserved = {
        schemaVersion: 1,
        appliedGeneration: 10,
        appliedConfigHash: emptyDesired.configHash,
        services: [],
        observedAt: nowIso(),
      };
      const signature = services.xrayManagedServicesStateSignature(emptyObserved);
      const heartbeat = await services.processXrayManagedServicesHeartbeatReport({
        hostId: 10,
        managedServicesStateSignature: signature,
        managedServicesState: emptyObserved,
      });
      assert.equal(heartbeat.requestManagedServicesState, false);
      for (const table of ["xray_managed_services", "xray_managed_service_accounts", "xray_managed_service_secrets", "xray_managed_service_instance_secrets"]) {
        assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM " + table))[0].count, 0, table);
      }

      const installScript = installer.generateInstallScript("https://panel.example.com");
      for (const required of [
        'MTPROTO_USER="forwardx-mtproto"',
        'MTPROTO_GROUP="forwardx-mtproto"',
        'runtime-user-owned',
        '"$MTPROTO_ARTIFACT_DIR"/mtproto/v1.15.0/amd64/mtg-multi',
        '"$MTPROTO_ARTIFACT_DIR"/mtproto/v1.15.0/arm64/mtg-multi',
      ]) assert.equal(installScript.includes(required), true, required);
      assert.equal(installScript.includes('"$MTPROTO_ARTIFACT_DIR"/mtproto/v1.15.0/*/mtg-multi'), false);
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
        JWT_SECRET: "managed-mtproto-test-secret",
        XRAY_MASTER_KEY_PATH: path.join(directory, "xray-master.key"),
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
