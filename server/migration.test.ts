import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  buildMigrationRuntimeExpectations,
  decryptPanelBackup,
  encryptMigrationSnapshot,
  pruneMigrationSnapshotForPanelBackup,
  type MigrationImportedIds,
  type MigrationSnapshot,
} from "./migration";
import type { XrayMasterKeyBackupBundle } from "./xrayBackup";
import {
  approveMigrationRequest,
  consumeApprovedMigrationRequest,
  consumeTakeoverToken,
  createMigrationCode,
  createMigrationRequest,
  prepareTakeoverToken,
} from "./migrationCodes";

function snapshot(tables: MigrationSnapshot["tables"]): MigrationSnapshot {
  return {
    version: 1,
    exportedAt: 2_000_000,
    tables,
  };
}

test("encrypted panel backup v2 authenticates KDF metadata and wraps the Xray master key", () => {
  const rawKey = Buffer.alloc(32, 0x31);
  const bundle: XrayMasterKeyBackupBundle = {
    format: "forwardx-xray-master-key",
    version: 1,
    currentKeyId: "1",
    keys: { "1": rawKey.toString("base64url") },
  };
  const source = snapshot({
    xray_inbounds: [{ id: 1, realityPrivateKeyEncrypted: "fwdx-secret:v1:1:envelope" }],
  });
  const encrypted = encryptMigrationSnapshot(source, "backup-password-031", { xrayMasterKey: bundle });
  const serialized = JSON.stringify(encrypted);
  assert.equal(encrypted.version, 2);
  assert.equal(serialized.includes(rawKey.toString("hex")), false);
  assert.equal(serialized.includes(rawKey.toString("base64url")), false);
  assert.deepEqual(decryptPanelBackup(serialized, "backup-password-031"), {
    snapshot: source,
    xrayMasterKey: bundle,
  });
  assert.throws(
    () => decryptPanelBackup(JSON.stringify({ ...encrypted, kdf: { ...encrypted.kdf, cost: 2 } }), "backup-password-031"),
    /加密参数|损坏/,
  );
  assert.throws(() => decryptPanelBackup(serialized, "wrong-password"), /密码错误|损坏/);
  const changedData = `${encrypted.data.slice(0, -1)}${encrypted.data.endsWith("A") ? "B" : "A"}`;
  assert.throws(() => decryptPanelBackup(JSON.stringify({ ...encrypted, data: changedData }), "backup-password-031"), /损坏/);
});

const importedIds: MigrationImportedIds = {
  hosts: { 1: 101, 2: 102 },
  tunnels: { 10: 110 },
  forwardRules: { 20: 120, 21: 121 },
};

test("essential snapshot pruning keeps business data and removes rebuildable history", () => {
  const result = pruneMigrationSnapshotForPanelBackup({
    ...snapshot({
      users: [{ id: 1, username: "admin" }],
      forward_rules: [{ id: 2, userId: 1 }],
      traffic_stats: [{ id: 3, ruleId: 2 }],
      traffic_stat_buckets: [{ id: 4, ruleId: 2 }],
      host_metrics: [{ id: 5, hostId: 1 }],
    }),
    dataScope: "essential",
    takeoverToken: "takeover-token",
  });
  assert.equal(result.tables.users.length, 1);
  assert.equal(result.tables.forward_rules.length, 1);
  assert.equal(result.tables.traffic_stats, undefined);
  assert.equal(result.tables.traffic_stat_buckets, undefined);
  assert.equal(result.tables.host_metrics, undefined);
  assert.equal(result.takeoverToken, "takeover-token");
});

test("backup import reports partial success after row-level failures instead of throwing", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-partial-import-"));
  const databasePath = path.join(directory, "panel.db");
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const migration = await import(moduleUrl("server/migration.ts"));
    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      const result = await migration.importMigrationSnapshot({
        version: 1,
        exportedAt: Date.now(),
        tables: {
          forward_rules: [{
            id: 1,
            hostId: 999,
            userId: 999,
            name: "orphan",
            forwardType: "gost",
            protocol: "tcp",
            sourcePort: 12000,
            targetIp: "example.com",
            targetPort: 443,
          }],
        },
      });
      assert.equal(result.success, true);
      assert.equal(result.partial, true);
      assert.equal(result.skippedRows, 1);
      assert.match(result.warnings[0], /其余数据已经导入/);
    } finally {
      await runtime.closeDatabase();
    }
  `;
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: { ...process.env, DATABASE_TYPE: "sqlite", FORWARDX_TEST_DB: databasePath },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("structured migration preserves Xray envelopes and remaps logical owners", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-migration-"));
  const databasePath = path.join(directory, "target.db");
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const migration = await import(moduleUrl("server/migration.ts"));
    const secrets = await import(moduleUrl("server/xraySecretCrypto.ts"));
    const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
    const privateEnvelope = secrets.encryptXraySecret(
      "PRIVATEKEYUNIQUE032-migration",
      secrets.xrayInboundPrivateKeyContext("inbound-200"),
      keyring,
    );
    const uuidEnvelope = secrets.encryptXraySecret(
      "03203203-2032-4032-8032-032032032032",
      secrets.xrayClientUuidContext("stats-300"),
      keyring,
    );
    const shortEnvelope = secrets.encryptXraySecret(
      "0320320320320320",
      secrets.xrayClientShortIdContext("stats-300"),
      keyring,
    );
    const privateFingerprint = secrets.fingerprintXraySecret(
      "PRIVATEKEYUNIQUE032-migration",
      secrets.xrayInboundPrivateKeyContext("inbound-200"),
      keyring,
    );
    const uuidFingerprint = secrets.fingerprintXraySecret(
      "03203203-2032-4032-8032-032032032032",
      secrets.xrayClientUuidContext("stats-300"),
      keyring,
    );
    const shortFingerprint = secrets.fingerprintXraySecret(
      "0320320320320320",
      secrets.xrayClientShortIdContext("stats-300"),
      keyring,
    );
    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      const result = await migration.importMigrationSnapshot({
        version: 1,
        exportedAt: Date.now(),
        dataScope: "full",
        tables: {
          users: [{ id: 10, username: "admin", password: "hash", role: "admin" }],
          hosts: [{ id: 100, name: "edge", ip: "192.0.2.1", userId: 10 }],
          xray_inbounds: [{
            id: 200, hostId: 100, name: "reality", runtimeTag: "inbound-200", publicAddress: "203.0.113.1",
            listenPort: 24443, realityTargetHost: "example.com", realityServerName: "example.com",
            realityPublicKey: "public", realityPrivateKeyEncrypted: privateEnvelope, createdByUserId: 10,
          }],
          xray_clients: [{
            id: 300, inboundId: 200, name: "client", uuidEncrypted: uuidEnvelope,
            uuidFingerprint, shortIdEncrypted: shortEnvelope,
            shortIdFingerprint: shortFingerprint, statsKey: "stats-300", ownerUserId: 10,
          }],
          xray_access_entries: [{
            id: 350, inboundId: 200, legacyClientId: 300, name: "client",
            credentialType: "UUID_AND_SHORT_ID", settingsJson: '{"schemaVersion":1,"flow":"XTLS_RPRX_VISION"}',
            statsKey: "stats-300", ownerUserId: 10, desiredGeneration: 0, sortOrder: 0,
          }],
          xray_access_secrets: [
            { id: 351, accessEntryId: 350, kind: "UUID", encryptedValue: uuidEnvelope, fingerprint: uuidFingerprint, keyVersion: 1 },
            { id: 352, accessEntryId: 350, kind: "SHORT_ID", encryptedValue: shortEnvelope, fingerprint: shortFingerprint, keyVersion: 1 },
          ],
          xray_inbound_secrets: [{
            id: 250, inboundId: 200, kind: "REALITY_PRIVATE_KEY", encryptedValue: privateEnvelope,
            fingerprint: privateFingerprint, keyVersion: 1,
          }],
          xray_artifacts: [{
            id: 400, version: "v26.7.28", os: "linux", arch: "amd64", packageFormat: "zip",
            storageKey: "xray/v26.7.28/linux-amd64.zip", sha256: "c".repeat(64), fileSize: 123,
          }],
          xray_operations: [{
            id: 500, operationId: "operation-500", hostId: 100, inboundId: 200,
            type: "SYNC", createdByUserId: 10,
          }],
          xray_host_deployments: [{ id: 600, hostId: 100, desiredGeneration: 3, lastOperationId: "operation-500" }],
          xray_runtime_reports: [{ id: 700, hostId: 100, appliedGeneration: 2, serviceStatus: "RUNNING" }],
        },
      });
      assert.equal(result.success, true);
      assert.equal(result.partial, false);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT hostId, createdByUserId, realityPrivateKeyEncrypted FROM xray_inbounds WHERE id = 200",
      ), [{ hostId: 100, createdByUserId: 1, realityPrivateKeyEncrypted: privateEnvelope }]);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT inboundId, ownerUserId, uuidEncrypted, shortIdEncrypted FROM xray_clients WHERE id = 300",
      ), [{ inboundId: 200, ownerUserId: 1, uuidEncrypted: uuidEnvelope, shortIdEncrypted: shortEnvelope }]);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT inboundId, legacyClientId, ownerUserId, statsKey FROM xray_access_entries WHERE id = 350",
      ), [{ inboundId: 200, legacyClientId: 300, ownerUserId: 1, statsKey: "stats-300" }]);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT accessEntryId, kind, encryptedValue FROM xray_access_secrets ORDER BY id",
      ), [
        { accessEntryId: 350, kind: "UUID", encryptedValue: uuidEnvelope },
        { accessEntryId: 350, kind: "SHORT_ID", encryptedValue: shortEnvelope },
      ]);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT inboundId, kind, encryptedValue FROM xray_inbound_secrets",
      ), [{ inboundId: 200, kind: "REALITY_PRIVATE_KEY", encryptedValue: privateEnvelope }]);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT hostId, inboundId, createdByUserId FROM xray_operations WHERE id = 500",
      ), [{ hostId: 100, inboundId: 200, createdByUserId: 1 }]);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_artifacts"))[0].count, 1);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_host_deployments"))[0].count, 1);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_runtime_reports"))[0].count, 1);
    } finally {
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

test("structured DNS provider migration remaps catalog IDs and preserves fixed binding seed semantics", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-dns-migration-"));
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const migration = await import(moduleUrl("server/migration.ts"));
    const crypto = await import(moduleUrl("server/xraySecretCrypto.ts"));
    const catalog = await import(moduleUrl("server/dnsProviderCatalog.ts"));
    const dnsTuple = await import(moduleUrl("server/xrayQuickConfigDnsTuple.ts"));
    const keyring = crypto.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
    const now = Math.floor(Date.now() / 1000);
    const catalogRevision = catalog.computeDnsProviderCatalogRevision([{
      providerZoneId: "zone-104", name: "example.com",
      lines: [{ providerLineId: "line-105", name: "默认" }],
    }]);
    const sourceAccountTag = "forwardx-dns-account-66666666-6666-4666-8666-666666666666";
    const dnsSecret = (id, kind, plaintext, accountId = 100, accountTag = sourceAccountTag) => {
      const context = crypto.xrayDnsProviderAccountSecretContext(accountTag, kind);
      return {
        id, accountId, kind,
        encryptedValue: crypto.encryptXraySecret(plaintext, context, keyring),
        fingerprint: crypto.fingerprintXraySecret(plaintext, context, keyring),
        keyVersion: 1, createdAt: now, updatedAt: now,
      };
    };
    const providerTables = (accountTag = sourceAccountTag) => ({
      dns_provider_accounts: [{
        id: 100, accountTag, provider: "DNSPOD", name: "Global DNSPod", revision: 4,
        isDisabled: false, verificationStatus: "VALID", lastValidationAttemptAt: now,
        verifiedAt: now, verificationExpiresAt: now + 86400, createdByUserId: 10,
        createdAt: now, updatedAt: now,
      }],
      dns_provider_account_secrets: [
        dnsSecret(101, "DNSPOD_SECRET_ID", "AKID-migration", 100, accountTag),
        dnsSecret(102, "DNSPOD_SECRET_KEY", "secret-key-migration", 100, accountTag),
      ],
      dns_provider_global_bindings: [{
        id: 103, scopeKey: "XRAY_QUICK_CONFIG", accountId: 100, revision: 7,
        createdAt: now, updatedAt: now,
      }],
      dns_provider_zones: [{
        id: 104, accountId: 100, providerZoneId: "zone-104", name: "example.com",
        status: "AVAILABLE", catalogRevision, refreshedAt: now, expiresAt: now + 21600,
        lastSeenAt: now, createdAt: now, updatedAt: now,
      }],
      dns_provider_record_lines: [{
        id: 105, zoneId: 104, providerLineId: "line-105", name: "默认", category: "DEFAULT",
        status: "AVAILABLE", catalogRevision, refreshedAt: now, expiresAt: now + 21600,
        lastSeenAt: now, createdAt: now, updatedAt: now,
      }],
    });
    const inboundRuntimeTag = "forwardx-inbound-20202020-2020-4020-8020-202020202020";
    const inboundPrivateKey = crypto.encryptXraySecret(
      "migration-private-key",
      crypto.xrayInboundPrivateKeyContext(inboundRuntimeTag),
      keyring,
    );
    const quickConfigTag = "forwardx-quick-config-21212121-2121-4121-8121-212121212121";
    const quickConfigTables = {
      global_port_allocations: [{
        id: 300, allocationTag: "global-port:v1:33333", port: 33333, status: "ACTIVE",
        primaryOwnerType: "XRAY_INBOUND", primaryOwnerTag: inboundRuntimeTag,
        reservationTokenHash: null, version: 3, createdAt: now, updatedAt: now,
      }],
      xray_quick_configs: [{
        id: 210, configTag: quickConfigTag, targetType: "XRAY_INBOUND",
        xrayInboundId: 200, externalProxyNodeId: null, targetVersion: "1".repeat(64),
        dnsAccountId: 100, zoneId: 104, relativeName: "edge", fqdn: "edge.example.com",
        state: "APPLYING", revision: 2, activeTopologyRevisionId: null,
        desiredTopologyRevisionId: 400, currentOperationId: 420, createdByUserId: 10,
        createdAt: now, updatedAt: now,
      }],
      xray_quick_config_domain_claims: [{
        id: 220, claimKey: "2".repeat(64), dnsAccountId: 100, zoneId: 104,
        normalizedRelativeName: "edge", quickConfigId: 210, revision: 1,
        createdAt: now, updatedAt: now,
      }],
      xray_quick_config_topology_revisions: [{
        id: 400, quickConfigId: 210, revisionNumber: 1, engine: "realm",
        targetAddress: "203.0.113.10", targetPort: 33333, publicPort: 33333,
        portAllocationId: 300, state: "APPLYING", activeSlot: null, createdByUserId: 10,
        createdAt: now, updatedAt: now,
      }],
      xray_quick_config_routes: [{
        id: 410, routeTag: "forwardx-quick-route-41414141-4141-4141-8141-414141414141",
        quickConfigId: 210, topologyRevisionId: 400, lineCategory: "DEFAULT",
        providerLineId: "line-105", sourceType: "MANAGED_HOST", hostId: 20,
        addressFamily: "IPV4", address: "203.0.113.20", routeMode: "FORWARD",
        sortOrder: 0, state: "PLANNED", createdAt: now, updatedAt: now,
      }],
      xray_quick_config_operations: [{
        id: 420, operationTag: "forwardx-quick-operation-42424242-4242-4242-8242-424242424242",
        quickConfigId: 210, type: "APPLY", status: "RUNNING", phase: "CREATING_RULES",
        activeSlot: 1, revision: 2, expectedRevision: 2, fromTopologyRevisionId: null,
        toTopologyRevisionId: 400, requestSummaryJson: "{}", retryOfOperationId: null,
        executionOwnerId: "source-panel", executionLeaseUntil: now + 60, executionFence: 1,
        errorCode: null, errorMessage: null, createdByUserId: 10, startedAt: now,
        finishedAt: null, createdAt: now, updatedAt: now,
      }],
      xray_quick_config_operation_steps: [{
        id: 430, operationId: 420, stepKey: "rule:500:create", kind: "RULE_CREATE",
        subjectType: "RULE", subjectId: "500", status: "PENDING", attemptCount: 0,
        idempotencyKey: "quick-operation-420-rule-500-create", requestSummaryJson: "{}",
        resultSummaryJson: null, errorCode: null, startedAt: null, finishedAt: null, updatedAt: now,
      }],
      xray_quick_config_dns_records: [{
        id: 440, quickConfigId: 210, routeId: 410, dnsAccountId: 100, zoneId: 104,
        recordTag: "forwardx-quick-record-44444444-4444-4444-8444-444444444444",
        providerRecordId: null, providerLineId: "line-105", fqdn: "edge.example.com",
        recordType: "A", value: "203.0.113.20", ttl: 600, status: "DESIRED",
        appliedRevision: 1, remoteTupleHash: dnsTuple.computeXrayQuickConfigDnsTupleHash({
          fqdn: "edge.example.com", recordType: "A", providerLineId: "line-105",
          value: "203.0.113.20", ttl: 600,
        }), lastVerifiedAt: null,
        createdAt: now, updatedAt: now,
      }],
      xray_quick_config_dns_record_backups: [{
        id: 450, operationId: 420, dnsAccountId: 100, zoneId: 104,
        providerRecordId: "old-record-1", fqdn: "edge.example.com", recordType: "CNAME",
        providerLineId: "line-105", value: "old.example.net", ttl: 600,
        remoteTupleHash: dnsTuple.computeXrayQuickConfigDnsTupleHash({
          fqdn: "edge.example.com", recordType: "CNAME", providerLineId: "line-105",
          value: "old.example.net", ttl: 600,
        }), snapshotOrder: 0, state: "CAPTURED",
        createdAt: now, updatedAt: now,
      }],
      forward_rules: [{
        id: 500, hostId: 20, name: "quick realm", forwardType: "realm", protocol: "tcp",
        sourcePort: 33333, targetIp: "203.0.113.10", targetPort: 33333,
        xrayQuickConfigId: 210, userId: 10, isEnabled: true, isRunning: true,
        pendingDelete: false, createdAt: now, updatedAt: now,
      }],
      xray_quick_config_rule_bindings: [{
        id: 510, bindingTag: "forwardx-quick-rule-binding-51515151-5151-4151-8151-515151515151",
        quickConfigId: 210, topologyRevisionId: 400, forwardRuleId: 500,
        state: "PLANNED", createdAt: now, updatedAt: now,
      }],
      global_port_allocation_references: [{
        id: 310, referenceKey: "global-port-ref:v1:XRAY_INBOUND:200:host-20:TCP:PUBLIC_LISTENER",
        allocationId: 300, resourceType: "XRAY_INBOUND", resourceId: 200,
        ownerGroupTag: inboundRuntimeTag, hostId: 20, network: "TCP",
        role: "PUBLIC_LISTENER", isOwning: true, createdAt: now, updatedAt: now,
      }, {
        id: 311, referenceKey: "global-port-ref:v1:QUICK_CONFIG:210:host-20:BOTH:PUBLIC_LISTENER",
        allocationId: 300, resourceType: "QUICK_CONFIG", resourceId: 210,
        ownerGroupTag: quickConfigTag, hostId: 20, network: "BOTH",
        role: "PUBLIC_LISTENER", isOwning: false, createdAt: now, updatedAt: now,
      }],
      global_port_probe_runs: [{
        id: 460, probeTag: "forwardx-port-probe-46464646-4646-4646-8646-464646464646",
        allocationId: 300, allocationVersion: 3, candidatePort: 33333,
        purpose: "CANDIDATE", status: "RUNNING", hostSetHash: "4".repeat(64),
        expectedHostCount: 1, createdByUserId: 10, startedAt: now, finishedAt: null,
        expiresAt: now + 300, errorCode: null,
      }],
      global_port_probe_results: [{
        id: 470, probeRunId: 460, hostId: 20, network: "tcp",
        xrayOperationId: "forwardx-port-probe-operation-47", status: "FREE",
        probedAt: now, expiresAt: now + 300,
      }],
      xray_operations: [{
        id: 600, operationId: "forwardx-port-probe-operation-47", hostId: 20,
        inboundId: null, type: "PORT_PROBE", status: "SUCCESS",
        requestMetaJson: JSON.stringify({ schemaVersion: 1, mode: "MANUAL", network: "tcp", candidates: [33333] }),
        resultJson: null, errorCode: null, errorMessage: null, attemptCount: 1,
        createdByUserId: 10, createdAt: now, startedAt: now, finishedAt: now,
        expiresAt: now + 300, updatedAt: now,
      }],
      global_port_scan_leases: [{
        id: 480, scopeKey: "GLOBAL_PORT_RECLAIM", leaseOwnerHash: "5".repeat(64),
        leaseUntil: now + 60, lastStartedAt: now, lastFinishedAt: null, updatedAt: now,
      }],
    };
    const sourceSnapshot = (accountTag = sourceAccountTag) => ({
      version: 1,
      exportedAt: Date.now(),
      dataScope: "full",
      tables: {
        users: [{ id: 10, username: "admin", password: "hash", role: "admin" }],
        hosts: [{ id: 20, name: "edge", ip: "203.0.113.20", agentToken: "quick-host-token", userId: 10 }],
        ...providerTables(accountTag),
        xray_inbounds: [{
          id: 200, hostId: 20, name: "landing", runtimeTag: inboundRuntimeTag,
          publicAddress: "203.0.113.10", listenPort: 33333, protocol: "vless",
          transport: "tcp", security: "reality", profileId: "VLESS_RAW_REALITY_VISION",
          specVersion: 1, specJson: "{}", realityTargetHost: "www.example.com",
          realityTargetPort: 443, realityServerName: "www.example.com", realityPublicKey: "public",
          realityPrivateKeyEncrypted: inboundPrivateKey, secretKeyVersion: 1,
          createdByUserId: 10, createdAt: now, updatedAt: now,
        }],
        ...quickConfigTables,
      },
    });

    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_FRESH_DB } });
      await schema.ensureDatabaseSchema();
      const [freshSeed] = await runtime.queryRaw("SELECT id, accountId, revision FROM dns_provider_global_bindings WHERE scopeKey = 'XRAY_QUICK_CONFIG'");
      assert.deepEqual({ accountId: freshSeed.accountId, revision: Number(freshSeed.revision) }, { accountId: null, revision: 1 });
      const fresh = await migration.importMigrationSnapshot(sourceSnapshot());
      assert.equal(fresh.mode, "restore");
      assert.equal(fresh.partial, false);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT id, scopeKey, accountId, revision FROM dns_provider_global_bindings",
      ), [{ id: freshSeed.id, scopeKey: "XRAY_QUICK_CONFIG", accountId: 100, revision: 7 }]);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT accountId, kind FROM dns_provider_account_secrets ORDER BY kind",
      ), [{ accountId: 100, kind: "DNSPOD_SECRET_ID" }, { accountId: 100, kind: "DNSPOD_SECRET_KEY" }]);
      assert.deepEqual(await runtime.queryRaw("SELECT accountId FROM dns_provider_zones WHERE id = 104"), [{ accountId: 100 }]);
      assert.deepEqual(await runtime.queryRaw("SELECT zoneId FROM dns_provider_record_lines WHERE id = 105"), [{ zoneId: 104 }]);
      await runtime.closeDatabase();

      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_INCREMENTAL_DB } });
      await schema.ensureDatabaseSchema();
      await runtime.executeRaw(
        "UPDATE global_port_scan_leases SET leaseOwnerHash = ?, leaseUntil = ? WHERE scopeKey = 'GLOBAL_PORT_RECLAIM'",
        ["7".repeat(64), now + 120],
      );
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, userId) VALUES (1, 'existing', '192.0.2.1', 1)");
      const incremental = await migration.importMigrationSnapshot(sourceSnapshot());
      assert.equal(incremental.mode, "incremental");
      assert.equal(incremental.partial, false);
      const [importedAccount] = await runtime.queryRaw("SELECT id, accountTag FROM dns_provider_accounts");
      assert.notEqual(importedAccount.id, 100);
      const [incrementalBinding] = await runtime.queryRaw(
        "SELECT id, accountId, revision FROM dns_provider_global_bindings WHERE scopeKey = 'XRAY_QUICK_CONFIG'",
      );
      assert.equal(incrementalBinding.accountId, importedAccount.id);
      assert.equal(Number(incrementalBinding.revision), 2);
      assert.deepEqual(await runtime.queryRaw("SELECT DISTINCT accountId FROM dns_provider_account_secrets"), [{ accountId: importedAccount.id }]);
      const [importedZone] = await runtime.queryRaw("SELECT id, accountId FROM dns_provider_zones");
      assert.equal(importedZone.accountId, importedAccount.id);
      assert.deepEqual(await runtime.queryRaw("SELECT DISTINCT zoneId FROM dns_provider_record_lines"), [{ zoneId: importedZone.id }]);

      const [importedHost] = await runtime.queryRaw("SELECT id FROM hosts WHERE name = 'edge'");
      const [importedUser] = await runtime.queryRaw("SELECT id FROM users WHERE username = 'admin'");
      const [importedInbound] = await runtime.queryRaw("SELECT id, runtimeTag FROM xray_inbounds");
      const [importedAllocation] = await runtime.queryRaw(
        "SELECT id, primaryOwnerType, primaryOwnerTag FROM global_port_allocations WHERE port = 33333",
      );
      const [importedQuickConfig] = await runtime.queryRaw(
        "SELECT id, xrayInboundId, dnsAccountId, zoneId, desiredTopologyRevisionId, currentOperationId FROM xray_quick_configs",
      );
      const [importedTopology] = await runtime.queryRaw(
        "SELECT id, quickConfigId, portAllocationId FROM xray_quick_config_topology_revisions",
      );
      const [importedOperation] = await runtime.queryRaw(
        "SELECT id, quickConfigId, toTopologyRevisionId, executionOwnerId, executionLeaseUntil FROM xray_quick_config_operations",
      );
      const [importedRoute] = await runtime.queryRaw(
        "SELECT id, quickConfigId, topologyRevisionId, hostId FROM xray_quick_config_routes",
      );
      const [importedRule] = await runtime.queryRaw(
        "SELECT id, hostId, xrayQuickConfigId, isRunning FROM forward_rules",
      );
      assert.notEqual(importedHost.id, 20);
      assert.notEqual(importedInbound.id, 200);
      assert.notEqual(importedQuickConfig.id, 210);
      assert.deepEqual(importedQuickConfig, {
        id: importedQuickConfig.id,
        xrayInboundId: importedInbound.id,
        dnsAccountId: importedAccount.id,
        zoneId: importedZone.id,
        desiredTopologyRevisionId: importedTopology.id,
        currentOperationId: importedOperation.id,
      });
      assert.deepEqual(importedTopology, {
        id: importedTopology.id,
        quickConfigId: importedQuickConfig.id,
        portAllocationId: importedAllocation.id,
      });
      assert.deepEqual(importedOperation, {
        id: importedOperation.id,
        quickConfigId: importedQuickConfig.id,
        toTopologyRevisionId: importedTopology.id,
        executionOwnerId: null,
        executionLeaseUntil: null,
      });
      assert.deepEqual(importedRoute, {
        id: importedRoute.id,
        quickConfigId: importedQuickConfig.id,
        topologyRevisionId: importedTopology.id,
        hostId: importedHost.id,
      });
      assert.deepEqual(importedRule, {
        id: importedRule.id,
        hostId: importedHost.id,
        xrayQuickConfigId: importedQuickConfig.id,
        isRunning: 0,
      });
      assert.deepEqual(await runtime.queryRaw(
        "SELECT quickConfigId, topologyRevisionId, forwardRuleId FROM xray_quick_config_rule_bindings",
      ), [{
        quickConfigId: importedQuickConfig.id,
        topologyRevisionId: importedTopology.id,
        forwardRuleId: importedRule.id,
      }]);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT quickConfigId, routeId, dnsAccountId, zoneId FROM xray_quick_config_dns_records",
      ), [{
        quickConfigId: importedQuickConfig.id,
        routeId: importedRoute.id,
        dnsAccountId: importedAccount.id,
        zoneId: importedZone.id,
      }]);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT operationId, dnsAccountId, zoneId FROM xray_quick_config_dns_record_backups",
      ), [{ operationId: importedOperation.id, dnsAccountId: importedAccount.id, zoneId: importedZone.id }]);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT operationId, subjectType, subjectId, status, startedAt FROM xray_quick_config_operation_steps",
      ), [{ operationId: importedOperation.id, subjectType: "RULE", subjectId: String(importedRule.id), status: "PENDING", startedAt: null }]);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT resourceType, resourceId, hostId, ownerGroupTag, referenceKey FROM global_port_allocation_references ORDER BY resourceType",
      ), [{
        resourceType: "QUICK_CONFIG", resourceId: importedQuickConfig.id, hostId: importedHost.id,
        ownerGroupTag: quickConfigTag,
        referenceKey: "global-port-ref:v1:QUICK_CONFIG:" + importedQuickConfig.id + ":host-" + importedHost.id + ":BOTH:PUBLIC_LISTENER",
      }, {
        resourceType: "XRAY_INBOUND", resourceId: importedInbound.id, hostId: importedHost.id,
        ownerGroupTag: inboundRuntimeTag,
        referenceKey: "global-port-ref:v1:XRAY_INBOUND:" + importedInbound.id + ":host-" + importedHost.id + ":TCP:PUBLIC_LISTENER",
      }]);
      assert.deepEqual(importedAllocation, {
        id: importedAllocation.id,
        primaryOwnerType: "XRAY_INBOUND",
        primaryOwnerTag: inboundRuntimeTag,
      });
      const [importedProbe] = await runtime.queryRaw("SELECT id, allocationId, createdByUserId FROM global_port_probe_runs");
      assert.deepEqual(importedProbe, {
        id: importedProbe.id,
        allocationId: importedAllocation.id,
        createdByUserId: importedUser.id,
      });
      assert.deepEqual(await runtime.queryRaw(
        "SELECT probeRunId, hostId FROM global_port_probe_results",
      ), [{ probeRunId: importedProbe.id, hostId: importedHost.id }]);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT scopeKey, leaseOwnerHash, leaseUntil FROM global_port_scan_leases",
      ), [{ scopeKey: "GLOBAL_PORT_RECLAIM", leaseOwnerHash: "7".repeat(64), leaseUntil: now + 120 }]);

      const graphCountsBeforeRepeat = Object.fromEntries(await Promise.all([
        "xray_quick_configs", "xray_quick_config_domain_claims", "xray_quick_config_topology_revisions",
        "xray_quick_config_routes", "xray_quick_config_rule_bindings", "xray_quick_config_dns_records",
        "xray_quick_config_dns_record_backups", "xray_quick_config_operations",
        "xray_quick_config_operation_steps", "global_port_allocations",
        "global_port_allocation_references", "global_port_probe_runs", "global_port_probe_results", "forward_rules",
      ].map(async (table) => [table, Number((await runtime.queryRaw("SELECT COUNT(*) AS count FROM " + table))[0].count)])));

      const preservedBinding = { ...incrementalBinding };
      const repeated = await migration.importMigrationSnapshot(sourceSnapshot());
      assert.equal(repeated.mode, "incremental");
      assert.deepEqual(await runtime.queryRaw(
        "SELECT id, accountId, revision FROM dns_provider_global_bindings WHERE scopeKey = 'XRAY_QUICK_CONFIG'",
      ), [preservedBinding]);
      const graphCountsAfterRepeat = Object.fromEntries(await Promise.all(
        Object.keys(graphCountsBeforeRepeat).map(async (table) => [
          table, Number((await runtime.queryRaw("SELECT COUNT(*) AS count FROM " + table))[0].count),
        ]),
      ));
      assert.deepEqual(graphCountsAfterRepeat, graphCountsBeforeRepeat);

      const emptyBindingSource = sourceSnapshot();
      emptyBindingSource.tables.dns_provider_accounts = [];
      emptyBindingSource.tables.dns_provider_account_secrets = [];
      emptyBindingSource.tables.dns_provider_zones = [];
      emptyBindingSource.tables.dns_provider_record_lines = [];
      emptyBindingSource.tables.dns_provider_global_bindings[0].accountId = null;
      await assert.rejects(
        () => migration.importMigrationSnapshot(emptyBindingSource),
        (error) => error?.code === "SENSITIVE_DATA_UNAVAILABLE",
      );

      const conflictingTag = "forwardx-dns-account-77777777-7777-4777-8777-777777777777";
      await assert.rejects(
        () => migration.importMigrationSnapshot(sourceSnapshot(conflictingTag)),
        (error) => error?.code === "SENSITIVE_DATA_UNAVAILABLE",
      );
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM dns_provider_accounts"))[0].count, 1);
      await runtime.closeDatabase();

      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_HISTORY_DB } });
      await schema.ensureDatabaseSchema();
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, userId) VALUES (1, 'existing', '192.0.2.2', 1)");
      await runtime.executeRaw(
        "UPDATE dns_provider_global_bindings SET revision = 9, updatedAt = ? WHERE scopeKey = 'XRAY_QUICK_CONFIG' AND accountId IS NULL AND revision = 1",
        [now],
      );
      const historical = await migration.importMigrationSnapshot(sourceSnapshot());
      assert.equal(historical.mode, "incremental");
      assert.equal(historical.partial, false);
      const [historicalAccount] = await runtime.queryRaw("SELECT id FROM dns_provider_accounts");
      assert.deepEqual(await runtime.queryRaw(
        "SELECT accountId, revision FROM dns_provider_global_bindings WHERE scopeKey = 'XRAY_QUICK_CONFIG'",
      ), [{ accountId: historicalAccount.id, revision: 10 }]);
      await runtime.closeDatabase();

      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_ROLLBACK_DB } });
      await schema.ensureDatabaseSchema();
      const bindingBeforeFailure = await runtime.queryRaw(
        "SELECT id, scopeKey, accountId, revision, createdAt, updatedAt FROM dns_provider_global_bindings",
      );
      await runtime.executeRaw(
        "CREATE TRIGGER fail_dns_provider_line_insert BEFORE INSERT ON dns_provider_record_lines BEGIN SELECT RAISE(ABORT, 'injected line insert failure'); END",
      );
      await assert.rejects(
        () => migration.importMigrationSnapshot(sourceSnapshot()),
        (error) => error?.code === "SENSITIVE_DATA_UNAVAILABLE",
      );
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM dns_provider_accounts"))[0].count, 0);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM dns_provider_account_secrets"))[0].count, 0);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM dns_provider_zones"))[0].count, 0);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM dns_provider_record_lines"))[0].count, 0);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT id, scopeKey, accountId, revision, createdAt, updatedAt FROM dns_provider_global_bindings",
      ), bindingBeforeFailure);
    } finally {
      await runtime.closeDatabase();
    }
  `;
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        DATABASE_TYPE: "sqlite",
        FORWARDX_FRESH_DB: path.join(directory, "fresh.db"),
        FORWARDX_INCREMENTAL_DB: path.join(directory, "incremental.db"),
        FORWARDX_HISTORY_DB: path.join(directory, "history.db"),
        FORWARDX_ROLLBACK_DB: path.join(directory, "rollback.db"),
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

test("essential migration skips rebuildable history while SQLite direct migration copies the full database", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-scope-migration-"));
  const sourcePath = path.join(directory, "source.db");
  const targetPath = path.join(directory, "target.db");
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    import BetterSqlite3 from "better-sqlite3";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const migration = await import(moduleUrl("server/migration.ts"));
    const sourcePath = process.env.FORWARDX_SOURCE_DB;
    const targetPath = process.env.SQLITE_PATH;
    const now = Math.floor(Date.now() / 1000);

    const source = new BetterSqlite3(sourcePath);
    await schema.ensureDatabaseSchema(source);
    source.prepare("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')").run();
    source.prepare("INSERT INTO auth_sessions (id, sid, userId, kind, expiresAt) VALUES (1, 'session-1', 1, 'browser', ?)").run(now + 3600);
    source.prepare("INSERT INTO hosts (id, name, ip, userId, isOnline, lastHeartbeat) VALUES (1, 'edge', '192.0.2.1', 1, 1, ?)").run(now);
    source.prepare("INSERT INTO tunnels (id, name, entryHostId, exitHostId, listenPort, userId, isEnabled, isRunning) VALUES (1, 'tunnel', 1, 1, 22000, 1, 1, 1)").run();
    source.prepare("INSERT INTO tunnel_hops (id, tunnelId, seq, hostId, listenPort, mimicPort) VALUES (1, 1, 1, 1, 22000, 0)").run();
    source.prepare("INSERT INTO forward_rules (id, hostId, name, forwardType, protocol, tunnelId, sourcePort, targetIp, targetPort, userId, isEnabled, isRunning, pendingDelete) VALUES (1, 1, 'rule', 'gost', 'tcp', 1, 12000, 'example.com', 443, 1, 1, 1, 0), (2, 1, 'deleted-rule', 'gost', 'tcp', 1, 12001, 'deleted.example.com', 443, 1, 0, 1, 1)").run();
    source.prepare("INSERT INTO global_port_allocations (id, allocationTag, port, status, primaryOwnerType, primaryOwnerTag, version) VALUES (1, 'global-port:v1:22000', 22000, 'ACTIVE', 'TUNNEL', 'tunnel:1', 1)").run();
    source.prepare("INSERT INTO global_port_allocation_references (id, referenceKey, allocationId, resourceType, resourceId, ownerGroupTag, hostId, network, role, isOwning) VALUES (1, 'global-port-ref:v1:TUNNEL:1:host-1:TCP:PUBLIC_LISTENER', 1, 'TUNNEL', 1, 'tunnel:1', 1, 'TCP', 'PUBLIC_LISTENER', 1), (2, 'global-port-ref:v1:TUNNEL_HOP:1:host-1:TCP:PUBLIC_LISTENER', 1, 'TUNNEL_HOP', 1, 'tunnel:1', 1, 'TCP', 'PUBLIC_LISTENER', 1)").run();
    source.prepare("INSERT INTO host_metrics (id, hostId, cpuUsage, recordedAt) VALUES (1, 1, 77, ?)").run(now);
    source.prepare("INSERT INTO tcping_stats (id, ruleId, hostId, latencyMs, isTimeout, recordedAt) VALUES (1, 1, 1, 33, 0, ?)").run(now);
    source.prepare("INSERT INTO host_traffic_counters (id, hostId, bytesIn, bytesOut) VALUES (1, 1, 1000, 2000)").run();
    source.prepare("INSERT INTO traffic_stat_buckets (id, bucketStart, bucketMinutes, userId, ruleId, hostId, bytesIn, bytesOut, connections) VALUES (1, ?, 30, 1, 1, 1, 500, 600, 2)").run(now);
    source.prepare("INSERT INTO agent_traffic_reports (id, hostId, producerId, reportId, receivedAt) VALUES (1, 1, 'agent-producer', 'pending-report', ?)").run(now);
    source.prepare("UPDATE system_settings SET value = 'https://old.example.com' WHERE key = 'panelPublicUrl'").run();
    source.close();

    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: sourcePath } });
      const exportProgress = [];
      const essential = await migration.exportMigrationSnapshot("https://old.example.com", {
        dataScope: "essential",
        onProgress: (progress) => exportProgress.push(progress),
      });
      assert.equal(essential.dataScope, "essential");
      assert.equal(essential.tables.users.length, 1);
      assert.equal(essential.tables.host_traffic_counters.length, 1);
      assert.equal(essential.tables.agent_traffic_reports.length, 1);
      assert.equal(essential.tables.host_metrics, undefined);
      assert.equal(essential.tables.tcping_stats, undefined);
      assert.equal(essential.tables.traffic_stat_buckets, undefined);
      assert.equal(essential.tables.config_audit_events, undefined);
      assert.equal(exportProgress[0].status, "reading");
      assert.equal(exportProgress.at(-1).status, "complete");
      assert.equal(exportProgress.at(-1).tableIndex, exportProgress.at(-1).tableTotal);
      const full = await migration.exportMigrationSnapshot("https://old.example.com", { dataScope: "full" });
      assert.equal(full.tables.traffic_stat_buckets.length, 1);
      await runtime.closeDatabase();

      const legacySource = new BetterSqlite3(sourcePath);
      legacySource.exec("UPDATE global_port_scan_leases SET leaseOwnerHash = '5555555555555555555555555555555555555555555555555555555555555555', leaseUntil = 1234567890 WHERE scopeKey = 'GLOBAL_PORT_RECLAIM'; DROP INDEX IF EXISTS idx_forward_rules_xrayQuickConfigId; ALTER TABLE forward_rules DROP COLUMN xrayQuickConfigId; DROP TABLE agent_traffic_reports; DROP TABLE xray_clients; DROP TABLE xray_inbounds; DROP TABLE xray_host_deployments; DROP TABLE xray_runtime_reports; DROP TABLE xray_artifacts; DROP TABLE xray_operations; DROP TABLE IF EXISTS xray_quick_config_operation_steps; DROP TABLE IF EXISTS xray_quick_config_dns_record_backups; DROP TABLE IF EXISTS xray_quick_config_dns_records; DROP TABLE IF EXISTS xray_quick_config_rule_bindings; DROP TABLE IF EXISTS xray_quick_config_routes; DROP TABLE IF EXISTS xray_quick_config_operations; DROP TABLE IF EXISTS xray_quick_config_topology_revisions; DROP TABLE IF EXISTS xray_quick_config_domain_claims; DROP TABLE IF EXISTS xray_quick_configs; DROP TABLE IF EXISTS global_port_probe_results; DROP TABLE IF EXISTS global_port_probe_runs; DROP TABLE IF EXISTS dns_provider_record_lines; DROP TABLE IF EXISTS dns_provider_zones; DROP TABLE IF EXISTS dns_provider_global_bindings; DROP TABLE IF EXISTS dns_provider_account_secrets; DROP TABLE IF EXISTS dns_provider_accounts;");
      legacySource.close();

      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: targetPath } });
      await schema.ensureDatabaseSchema();
      const direct = await migration.importDirectSqliteBackup({
        kind: "sqlite-direct",
        filePath: sourcePath,
        meta: {
          version: 1,
          format: "forwardx-sqlite-backup-v1",
          exportedAt: Date.now(),
          appVersion: "test",
          sourcePanelUrl: "https://old.example.com",
          takeoverToken: "TOKEN",
          dataScope: "full",
          byteLength: 1,
          sha256: "0".repeat(64),
        },
      }, "https://new.example.com");

      assert.equal(direct.result.transferMode, "sqlite-direct");
      assert.equal(direct.result.dataScope, "full");
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM users"))[0].count, 1);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM host_metrics"))[0].count, 1);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM tcping_stats"))[0].count, 1);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM traffic_stat_buckets"))[0].count, 1);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM agent_traffic_reports"))[0].count, 0);
      assert.deepEqual(
        await runtime.queryRaw("SELECT port, status FROM global_port_allocations ORDER BY port"),
        [{ port: 12000, status: "ACTIVE" }, { port: 12001, status: "ACTIVE" }, { port: 22000, status: "ACTIVE" }],
      );
      assert.deepEqual(
        await runtime.queryRaw("SELECT scopeKey, leaseOwnerHash, leaseUntil FROM global_port_scan_leases"),
        [{ scopeKey: "GLOBAL_PORT_RECLAIM", leaseOwnerHash: null, leaseUntil: null }],
      );
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_inbounds"))[0].count, 0);
      assert.deepEqual(await runtime.queryRaw(
        "SELECT scopeKey, accountId, revision FROM dns_provider_global_bindings",
      ), [{ scopeKey: "XRAY_QUICK_CONFIG", accountId: null, revision: 1 }]);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM auth_sessions"))[0].count, 1);
      assert.equal(Number((await runtime.queryRaw("SELECT isOnline FROM hosts WHERE id = 1"))[0].isOnline), 0);
      assert.equal(Number((await runtime.queryRaw("SELECT isRunning FROM tunnels WHERE id = 1"))[0].isRunning), 0);
      assert.deepEqual(
        await runtime.queryRaw("SELECT id, isRunning, pendingDelete FROM forward_rules ORDER BY id"),
        [
          { id: 1, isRunning: 0, pendingDelete: 0 },
          { id: 2, isRunning: 0, pendingDelete: 1 },
        ],
      );
      assert.equal((await runtime.queryRaw("SELECT value FROM system_settings WHERE key = 'panelPublicUrl'"))[0].value, "https://new.example.com");
    } finally {
      await runtime.closeDatabase();
    }

    const unchangedSource = new BetterSqlite3(sourcePath, { readonly: true });
    assert.equal(Number(unchangedSource.prepare("SELECT isOnline FROM hosts WHERE id = 1").get().isOnline), 1);
    unchangedSource.close();
  `;
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        DATABASE_TYPE: "sqlite",
        SQLITE_PATH: targetPath,
        FORWARDX_SOURCE_DB: sourcePath,
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("structured restore batches 3,000 rules, isolates invalid rows, and preserves cumulative traffic", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-structured-migration-"));
  const databasePath = path.join(directory, "target.db");
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const migration = await import(moduleUrl("server/migration.ts"));
    const now = Math.floor(Date.now() / 1000);
    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'temporary', 'admin')");

      const metrics = Array.from({ length: 10_000 }, (_, index) => ({
        id: 1_000 + index,
        hostId: 100,
        cpuUsage: index % 100,
        recordedAt: now + index,
      }));
      const rules = Array.from({ length: 3_000 }, (_, index) => ({
        id: 300 + index,
        hostId: 100,
        name: "rule-" + index,
        forwardType: "gost",
        protocol: index % 2 === 0 ? "tcp" : "udp",
        tunnelId: 200,
        sourcePort: 12_000 + index,
        targetIp: "target-" + index + ".example.com",
        targetPort: 20_000 + index,
        userId: 10,
        isEnabled: 1,
        isRunning: 1,
        pendingDelete: index === 0 ? 1 : 0,
      }));
      const buckets = Array.from({ length: 240 }, (_, index) => ({
        id: 3_000 + index,
        bucketStart: now + index * 1_800,
        bucketMinutes: 30,
        userId: 10,
        ruleId: 300,
        hostId: 100,
        bytesIn: 1_000 + index,
        bytesOut: 2_000 + index,
        connections: index,
        updatedAt: now,
      }));
      const progress = [];
      const startedAt = Date.now();
      const result = await migration.importMigrationSnapshot({
        version: 1,
        exportedAt: Date.now(),
        dataScope: "full",
        tables: {
          users: [{ id: 10, username: "admin", password: "source", role: "admin" }],
          hosts: [{ id: 100, name: "edge", ip: "192.0.2.1", userId: 10, isOnline: 1 }],
          tunnels: [{ id: 200, name: "tunnel", entryHostId: 100, exitHostId: 100, listenPort: 22000, userId: 10, isEnabled: 1, isRunning: 1 }],
          forward_rules: rules,
          host_metrics: [...metrics, { id: 99_999, hostId: 100, cpuUsage: 50, recordedAt: null }],
          forward_rule_traffic_counters: [{ id: 400, ruleId: 300, hostId: 100, userId: 10, bytesIn: 123456, bytesOut: 654321, connections: 7 }],
          user_traffic_counters: [{ id: 500, userId: 10, bytesIn: 123456, bytesOut: 654321, connections: 7 }],
          traffic_stat_buckets: buckets,
        },
      }, {
        onProgress: (value, step) => progress.push({ value, step }),
      });

      assert.equal(result.mode, "restore");
      assert.equal(result.partial, false);
      assert.equal(result.inserted.forward_rules, rules.length);
      assert.equal(result.inserted.host_metrics, metrics.length);
      assert.equal(result.skipped.host_metrics, 1);
      assert.equal(result.inserted.traffic_stat_buckets, buckets.length);
      assert.equal(result.reused.users, 1);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM host_metrics"))[0].count, metrics.length);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM forward_rules"))[0].count, rules.length);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM forward_rules WHERE isRunning <> 0"))[0].count, 0);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM traffic_stat_buckets"))[0].count, buckets.length);
      assert.deepEqual(
        await runtime.queryRaw("SELECT id, userId, isOnline FROM hosts WHERE id = 100"),
        [{ id: 100, userId: 1, isOnline: 0 }],
      );
      assert.deepEqual(
        await runtime.queryRaw("SELECT id, hostId, userId, isRunning, pendingDelete FROM forward_rules WHERE id = 300"),
        [{ id: 300, hostId: 100, userId: 1, isRunning: 0, pendingDelete: 1 }],
      );
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM forward_rules WHERE pendingDelete <> 0"))[0].count, 1);
      assert.deepEqual(
        await runtime.queryRaw("SELECT bytesIn, bytesOut, connections FROM forward_rule_traffic_counters WHERE id = 400"),
        [{ bytesIn: 123456, bytesOut: 654321, connections: 7 }],
      );
      assert.ok(progress.some((item) => item.step.includes("host_metrics") && item.step.includes("/")));
      assert.ok(new Set(progress.map((item) => item.value)).size > 5);
      assert.ok(Date.now() - startedAt < 15_000, "3,000-rule structured migration exceeded 15 seconds");
    } finally {
      await runtime.closeDatabase();
    }
  `;
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: { ...process.env, DATABASE_TYPE: "sqlite", FORWARDX_TEST_DB: databasePath },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("incremental structured migration batches generated IDs and keeps valid rules when one row fails", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-incremental-migration-"));
  const databasePath = path.join(directory, "target.db");
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const migration = await import(moduleUrl("server/migration.ts"));
    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'temporary', 'admin')");
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, userId, agentToken) VALUES (1, 'existing', '192.0.2.1', 1, 'existing-token')");
      await runtime.executeRaw("INSERT INTO forward_rules (id, hostId, name, forwardType, protocol, sourcePort, targetIp, targetPort, userId) VALUES (1, 1, 'existing-rule', 'gost', 'tcp', 15000, 'existing.example.com', 443, 1)");
      await runtime.executeRaw("INSERT INTO forward_rule_traffic_counters (id, ruleId, hostId, userId, bytesIn, bytesOut, connections) VALUES (1, 1, 1, 1, 777, 888, 9)");
      await runtime.executeRaw("INSERT INTO user_traffic_counters (id, userId, bytesIn, bytesOut, connections) VALUES (1, 1, 777, 888, 9)");

      const rules = Array.from({ length: 3_000 }, (_, index) => ({
        id: 300 + index,
        hostId: 100,
        name: "incremental-rule-" + index,
        forwardType: "gost",
        protocol: index % 2 === 0 ? "tcp" : "udp",
        sourcePort: 16_000 + index,
        targetIp: "incremental-" + index + ".example.com",
        targetPort: 24_000 + index,
        userId: 10,
        isEnabled: true,
        isRunning: true,
      }));
      let importedIds = null;
      const startedAt = Date.now();
      const result = await migration.importMigrationSnapshot({
        version: 1,
        exportedAt: Date.now(),
        dataScope: "essential",
        tables: {
          users: [{ id: 10, username: "admin", password: "source", role: "admin" }],
          hosts: [{ id: 100, name: "new-edge", ip: "198.51.100.10", userId: 10, agentToken: "new-token", isOnline: true }],
          forward_rules: [
            ...rules,
            { id: 99_999, hostId: 100, name: null, forwardType: "gost", protocol: "tcp", sourcePort: 30_000, targetIp: "invalid.example.com", targetPort: 443, userId: 10 },
          ],
        },
      }, {
        onImportedIds: (value) => { importedIds = value; },
      });

      assert.equal(result.mode, "incremental");
      assert.equal(result.partial, true);
      assert.equal(result.inserted.forward_rules, rules.length);
      assert.equal(result.skipped.forward_rules, 1);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM forward_rules"))[0].count, rules.length + 1);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM forward_rules WHERE isRunning <> 0"))[0].count, 0);
      assert.deepEqual(
        await runtime.queryRaw("SELECT bytesIn, bytesOut, connections FROM forward_rule_traffic_counters WHERE id = 1"),
        [{ bytesIn: 777, bytesOut: 888, connections: 9 }],
      );
      assert.ok(importedIds);
      assert.notEqual(importedIds.hosts[100], 100);
      const [importedHost] = await runtime.queryRaw("SELECT id, agentToken, isOnline FROM hosts WHERE id = ?", [importedIds.hosts[100]]);
      assert.equal(importedHost.agentToken, "new-token");
      assert.equal(importedHost.isOnline, 0);
      const [firstRule] = await runtime.queryRaw("SELECT id, hostId, userId FROM forward_rules WHERE name = ?", ["incremental-rule-0"]);
      assert.equal(firstRule.hostId, importedIds.hosts[100]);
      assert.equal(firstRule.userId, 1);
      assert.equal(importedIds.forwardRules[300], firstRule.id);
      assert.ok(Date.now() - startedAt < 15_000, "3,000-rule incremental migration exceeded 15 seconds");
    } finally {
      await runtime.closeDatabase();
    }
  `;
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: { ...process.env, DATABASE_TYPE: "sqlite", FORWARDX_TEST_DB: databasePath },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("migration runtime expectations include fresh hosts and previously running resources", () => {
  const result = buildMigrationRuntimeExpectations(snapshot({
    hosts: [
      { id: 1, isOnline: true, lastHeartbeat: 1_990 },
      { id: 2, isOnline: true, lastHeartbeat: 1_000 },
    ],
    tunnels: [{ id: 10, isEnabled: true, isRunning: true }],
    forward_rules: [
      { id: 20, isEnabled: true, isRunning: true, pendingDelete: false },
      { id: 21, isEnabled: true, isRunning: false, pendingDelete: false },
    ],
  }), importedIds);

  assert.deepEqual(result.hostIds, [101]);
  assert.deepEqual(result.ruleIds, [120]);
  assert.deepEqual(result.tunnelIds, [110]);
  assert.deepEqual(result.allImportedHostIds, [101, 102]);
});

test("migration refuses active forwarding when no online Agent can be verified", () => {
  assert.throws(() => buildMigrationRuntimeExpectations(snapshot({
    hosts: [{ id: 1, isOnline: false, lastHeartbeat: 1_990 }],
    forward_rules: [{ id: 20, isEnabled: true, isRunning: true, pendingDelete: false }],
  }), importedIds), /没有可验证的在线 Agent/);
});

test("takeover token is target-bound and can only commit after prepare", () => {
  const code = createMigrationCode();
  const target = "https://new.example.com";
  const request = createMigrationRequest(code.code, target);
  assert.ok(request);
  assert.ok(approveMigrationRequest(request.id));
  const takeover = consumeApprovedMigrationRequest(request.id, code.code, target);
  assert.ok(takeover);

  assert.equal(consumeTakeoverToken(takeover.takeoverToken, target), false);
  assert.equal(prepareTakeoverToken(takeover.takeoverToken, "https://other.example.com"), null);
  assert.ok(prepareTakeoverToken(takeover.takeoverToken, target));
  assert.equal(consumeTakeoverToken(takeover.takeoverToken, "https://other.example.com"), false);
  assert.equal(consumeTakeoverToken(takeover.takeoverToken, target), true);
  assert.equal(consumeTakeoverToken(takeover.takeoverToken, target), false);
});

test("migration approval binds the selected data scope and SQLite transfer request", () => {
  const code = createMigrationCode();
  const request = createMigrationRequest(code.code, "https://new.example.com", {
    dataScope: "full",
    targetDatabaseType: "sqlite",
    directSqliteRequested: true,
  });
  assert.equal(request?.dataScope, "full");
  assert.equal(request?.targetDatabaseType, "sqlite");
  assert.equal(request?.directSqliteRequested, true);
  assert.ok(request && approveMigrationRequest(request.id));
  const takeover = request
    ? consumeApprovedMigrationRequest(request.id, code.code, "https://new.example.com")
    : null;
  assert.equal(takeover?.dataScope, "full");
  assert.equal(takeover?.directSqliteRequested, true);
});
