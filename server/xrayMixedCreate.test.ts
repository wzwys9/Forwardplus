import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("Mixed create, account lifecycle, desired config, DTO, and dual share stay atomic and secret-safe", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-mixed-create-"));
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
        "INSERT INTO hosts (id, name, ip, ipv4, isOnline, lastHeartbeat, agentVersion, userId) VALUES (10, 'edge', '8.8.8.8', '8.8.8.8', 1, ?, ?, 1)",
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

      const reservation = await reserveTcp(29601);
      const base = {
        hostId: 10,
        userId: 1,
        name: "Mixed admin proxy",
        publicAddress: "8.8.8.8",
        portReservationId: reservation.reservationId,
        listenPort: 29601,
        profileId: "MIXED_RAW_NONE",
        initialAccessEntries: [{ name: "operator" }, { name: "automation" }],
      };
      await expectCode(Promise.resolve().then(() => inboundService.createXrayInboundV2({ ...base, spec: { udp: true } })), "INVALID_CONFIG_INPUT");
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_inbounds"))[0].count, 0);

      const created = await inboundService.createXrayInboundV2({ ...base, spec: {} });
      assert.equal(created.desiredGeneration, 1);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT profileId, specJson, protocol, transport, security, tlsCertificateId FROM xray_inbounds WHERE id = ?",
        [created.inboundId],
      ), [{
        profileId: "MIXED_RAW_NONE",
        specJson: "{}",
        protocol: "mixed",
        transport: "tcp",
        security: "none",
        tlsCertificateId: null,
      }]);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT credentialType, settingsJson FROM xray_access_entries WHERE inboundId = ? ORDER BY sortOrder, id",
        [created.inboundId],
      ), [
        { credentialType: "MIXED_USER_PASSWORD", settingsJson: '{"schemaVersion":1}' },
        { credentialType: "MIXED_USER_PASSWORD", settingsJson: '{"schemaVersion":1}' },
      ]);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT s.kind, COUNT(*) count FROM xray_access_secrets s JOIN xray_access_entries a ON a.id = s.accessEntryId WHERE a.inboundId = ? GROUP BY s.kind ORDER BY s.kind",
        [created.inboundId],
      ), [{ kind: "PASSWORD", count: 2 }, { kind: "USERNAME", count: 2 }]);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) count FROM xray_inbound_secrets WHERE inboundId = ?", [created.inboundId]))[0].count, 0);

      const generated = await generator.generateXrayHostConfig(10, keyring);
      const compiledInbound = JSON.parse(generated.configJson).inbounds[0];
      assert.equal(compiledInbound.protocol, "mixed");
      assert.deepEqual(compiledInbound.settings, {
        auth: "password",
        accounts: compiledInbound.settings.accounts,
        udp: false,
        userLevel: 0,
      });
      assert.deepEqual(compiledInbound.streamSettings, { network: "tcp" });
      assert.equal(compiledInbound.settings.accounts.length, 2);
      for (const account of compiledInbound.settings.accounts) {
        assert.match(account.user, /^[A-Za-z0-9_-]{22}$/);
        assert.match(account.pass, /^[A-Za-z0-9_-]{43}$/);
      }
      assert.equal(new Set(compiledInbound.settings.accounts.map((account) => account.user)).size, 2);
      assert.equal(new Set(compiledInbound.settings.accounts.map((account) => account.pass)).size, 2);
      assert.deepEqual(generated.expectedListeners.map(({ network, port }) => ({ network, port })), [{ network: "tcp", port: 29601 }]);

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

      const headers = new Map();
      const caller = xrayRouter.createCaller({
        req: { headers: {} },
        res: { clearCookie() {}, setHeader(name, value) { headers.set(name, value); } },
        user: { id: 1, username: "admin", role: "admin", accountEnabled: true },
        authSession: null,
        authFailureReason: null,
      });
      const entries = await accessRepository.listXrayAccessEntries(created.inboundId);
      const firstShare = await caller.accessEntries.share({ accessEntryId: entries[0].id, format: "MIXED_PROXY_ENDPOINTS" });
      assert.equal(firstShare.format, "MIXED_PROXY_ENDPOINTS");
      assert.equal(firstShare.socks5Uri, "socks5://" + compiledInbound.settings.accounts[0].user + ":" + compiledInbound.settings.accounts[0].pass + "@8.8.8.8:29601");
      assert.equal(firstShare.httpUri, "http://" + compiledInbound.settings.accounts[0].user + ":" + compiledInbound.settings.accounts[0].pass + "@8.8.8.8:29601");
      assert.equal("uri" in firstShare, false);
      assert.equal(headers.get("Cache-Control"), "private, no-store, max-age=0");
      assert.equal(headers.get("Pragma"), "no-cache");
      await expectCode(accessService.getXrayAccessEntryShare(entries[0].id, "HTTP_PROXY_URI"), "INVALID_CONFIG_INPUT");

      const added = await accessService.createXrayAccessEntryForInbound({
        inboundId: created.inboundId, userId: 1, name: "breakglass", expectedGeneration: 1,
      });
      assert.equal(added.desiredGeneration, 2);
      const beforeRename = await accessService.getXrayAccessEntryShare(added.accessEntryId, "MIXED_PROXY_ENDPOINTS");
      const renamed = await accessService.updateXrayAccessEntryForInbound({
        id: added.accessEntryId, userId: 1, name: "breakglass renamed", expectedGeneration: 2,
      });
      assert.equal(renamed.desiredGeneration, 3);
      const afterRename = await accessService.getXrayAccessEntryShare(added.accessEntryId, "MIXED_PROXY_ENDPOINTS");
      assert.deepEqual({ socks5Uri: afterRename.socks5Uri, httpUri: afterRename.httpUri }, {
        socks5Uri: beforeRename.socks5Uri,
        httpUri: beforeRename.httpUri,
      });

      assert.equal((await accessService.updateXrayAccessEntryForInbound({
        id: entries[0].id, userId: 1, isEnabled: false, expectedGeneration: 3,
      })).desiredGeneration, 4);
      assert.equal((await accessService.removeXrayAccessEntryForInbound({
        id: entries[0].id, userId: 1, expectedGeneration: 4,
      })).desiredGeneration, 5);
      assert.equal((await accessService.updateXrayAccessEntryForInbound({
        id: entries[1].id, userId: 1, isEnabled: false, expectedGeneration: 5,
      })).desiredGeneration, 6);
      await expectCode(accessService.updateXrayAccessEntryForInbound({
        id: added.accessEntryId, userId: 1, isEnabled: false, expectedGeneration: 6,
      }), "LAST_ACTIVE_ACCESS_REQUIRED");
      const finalConfig = JSON.parse((await generator.generateXrayHostConfig(10, keyring)).configJson).inbounds[0];
      assert.equal(finalConfig.settings.accounts.length, 1);
      assert.equal(finalConfig.settings.accounts[0].user, new URL(afterRename.socks5Uri).username);
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
        JWT_SECRET: "xray-mixed-create-test-secret",
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
