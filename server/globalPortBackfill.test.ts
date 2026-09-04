import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("legacy logical listeners backfill atomically, merge same owners, and preserve conflicts", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-global-port-backfill-"));
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const runtime = await load("server/dbRuntime.ts");
    const backfill = await load("server/globalPortBackfill.ts");

    const createTables = async () => {
      await runtime.executeRaw('CREATE TABLE xray_inbounds (id INTEGER PRIMARY KEY, hostId INTEGER NOT NULL, runtimeTag TEXT NOT NULL, listenPort INTEGER NOT NULL, protocol TEXT NOT NULL, transport TEXT NOT NULL, security TEXT NOT NULL, profileId TEXT, specVersion INTEGER, specJson TEXT, isEnabled INTEGER NOT NULL, pendingDelete INTEGER NOT NULL)');
      await runtime.executeRaw('CREATE TABLE forward_rules (id INTEGER PRIMARY KEY, hostId INTEGER NOT NULL, protocol TEXT NOT NULL, tunnelId INTEGER, tunnelExitPort INTEGER, forwardGroupRuleId INTEGER, isForwardGroupTemplate INTEGER NOT NULL, sourcePort INTEGER NOT NULL, isEnabled INTEGER NOT NULL, pendingDelete INTEGER NOT NULL, xrayQuickConfigId INTEGER)');
      await runtime.executeRaw('CREATE TABLE xray_managed_services (id INTEGER PRIMARY KEY, hostId INTEGER NOT NULL, serviceTag TEXT NOT NULL, kind TEXT NOT NULL, listenPort INTEGER NOT NULL, isEnabled INTEGER NOT NULL, pendingDelete INTEGER NOT NULL)');
      await runtime.executeRaw('CREATE TABLE tunnels (id INTEGER PRIMARY KEY, exitHostId INTEGER NOT NULL, mode TEXT NOT NULL, forwardxVersion TEXT NOT NULL, listenPort INTEGER NOT NULL, mimicPort INTEGER NOT NULL, isEnabled INTEGER NOT NULL)');
      await runtime.executeRaw('CREATE TABLE tunnel_exit_nodes (id INTEGER PRIMARY KEY, tunnelId INTEGER NOT NULL, hostId INTEGER NOT NULL, listenPort INTEGER NOT NULL, mimicPort INTEGER NOT NULL, isEnabled INTEGER NOT NULL)');
      await runtime.executeRaw('CREATE TABLE tunnel_hops (id INTEGER PRIMARY KEY, tunnelId INTEGER NOT NULL, hostId INTEGER NOT NULL, listenPort INTEGER NOT NULL, mimicPort INTEGER NOT NULL)');
      await runtime.executeRaw('CREATE TABLE forward_rule_tunnel_exits (id INTEGER PRIMARY KEY, ruleId INTEGER NOT NULL, tunnelId INTEGER NOT NULL, exitNodeId INTEGER NOT NULL, exitHostId INTEGER NOT NULL, tunnelExitPort INTEGER NOT NULL)');
      await runtime.executeRaw('CREATE TABLE global_port_allocations (id INTEGER PRIMARY KEY AUTOINCREMENT, allocationTag TEXT NOT NULL UNIQUE, port INTEGER NOT NULL UNIQUE, status TEXT NOT NULL, primaryOwnerType TEXT, primaryOwnerTag TEXT, reservationTokenHash TEXT, reservedUntil INTEGER, scanNotBefore INTEGER, lastScanStartedAt INTEGER, lastScanFinishedAt INTEGER, lastErrorCode TEXT, version INTEGER NOT NULL DEFAULT 1, createdAt INTEGER NOT NULL, updatedAt INTEGER NOT NULL)');
      await runtime.executeRaw('CREATE TABLE global_port_allocation_references (id INTEGER PRIMARY KEY AUTOINCREMENT, referenceKey TEXT NOT NULL UNIQUE, allocationId INTEGER NOT NULL, resourceType TEXT NOT NULL, resourceId INTEGER NOT NULL, ownerGroupTag TEXT NOT NULL, hostId INTEGER NOT NULL, network TEXT NOT NULL, role TEXT NOT NULL, isOwning INTEGER NOT NULL, createdAt INTEGER NOT NULL, updatedAt INTEGER NOT NULL)');
      await runtime.executeRaw('CREATE TABLE global_port_scan_leases (id INTEGER PRIMARY KEY AUTOINCREMENT, scopeKey TEXT NOT NULL UNIQUE, leaseOwnerHash TEXT, leaseUntil INTEGER, lastStartedAt INTEGER, lastFinishedAt INTEGER, updatedAt INTEGER NOT NULL)');
      await runtime.executeRaw("INSERT INTO global_port_scan_leases (scopeKey, updatedAt) VALUES ('GLOBAL_PORT_RECLAIM', 1)");
    };

    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await createTables();

      assert.equal(backfill.buildGlobalPortOwnerGroupTag('FORWARD_RULE', 900), 'forward-rule:900');
      assert.equal(backfill.buildGlobalPortOwnerGroupTag('XRAY_INBOUND', 'inbound-stable'), 'inbound-stable');
      assert.equal(backfill.globalPortPrimaryOwnerTypeForResource('TUNNEL_EXIT_NODE'), 'TUNNEL');
      assert.equal(backfill.globalPortPrimaryOwnerTypeForResource('FORWARD_RULE_TUNNEL_EXIT'), 'FORWARD_RULE');
      assert.equal(backfill.buildGlobalPortReferenceKey({
        resourceType: 'FORWARD_RULE', resourceId: 10, hostId: 1,
        network: 'TCP', role: 'PUBLIC_LISTENER',
      }), 'global-port-ref:v1:FORWARD_RULE:10:host-1:TCP:PUBLIC_LISTENER');
      assert.equal(backfill.buildGlobalPortReferenceKey({
        resourceType: 'QUICK_CONFIG', resourceId: 77, hostId: null,
        network: 'NONE', role: 'OWNERSHIP',
      }), 'global-port-ref:v1:QUICK_CONFIG:77:host-none:NONE:OWNERSHIP');

      await runtime.executeRaw("INSERT INTO xray_inbounds VALUES (1, 1, 'inbound-low', 80, 'vless', 'tcp', 'reality', NULL, NULL, NULL, 1, 0)");
      await runtime.executeRaw("INSERT INTO xray_inbounds VALUES (2, 2, 'inbound-conflict', 20000, 'vless', 'tcp', 'reality', NULL, NULL, NULL, 1, 0)");
      await runtime.executeRaw("INSERT INTO xray_inbounds VALUES (3, 1, 'inbound-dual', 21000, 'shadowsocks', 'tcp', 'none', 'SHADOWSOCKS_2022_RAW_TCP_UDP_NONE', 1, '{}', 1, 0)");
      await runtime.executeRaw("INSERT INTO xray_inbounds VALUES (4, 1, 'disabled', 21001, 'vless', 'tcp', 'reality', NULL, NULL, NULL, 0, 0)");

      await runtime.executeRaw("INSERT INTO forward_rules VALUES (10, 1, 'tcp', NULL, NULL, 900, 0, 22000, 1, 0, NULL)");
      await runtime.executeRaw("INSERT INTO forward_rules VALUES (11, 2, 'udp', NULL, NULL, 900, 0, 22000, 1, 0, NULL)");
      await runtime.executeRaw("INSERT INTO forward_rules VALUES (12, 3, 'both', NULL, NULL, NULL, 0, 20000, 1, 0, NULL)");
      await runtime.executeRaw("INSERT INTO forward_rules VALUES (20, 1, 'both', 60, 24000, NULL, 0, 23000, 1, 0, NULL)");
      await runtime.executeRaw("INSERT INTO forward_rules VALUES (21, 1, 'tcp', NULL, NULL, NULL, 1, 22001, 1, 0, NULL)");
      await runtime.executeRaw("INSERT INTO forward_rules VALUES (22, 1, 'tcp', NULL, NULL, NULL, 0, 22002, 1, 1, NULL)");

      await runtime.executeRaw("INSERT INTO xray_managed_services VALUES (30, 3, 'managed-mtproto', 'MTPROTO_FAKE_TLS', 25000, 1, 0)");
      await runtime.executeRaw("INSERT INTO xray_managed_services VALUES (31, 4, 'managed-awg', 'AMNEZIAWG', 25001, 1, 0)");
      await runtime.executeRaw("INSERT INTO xray_managed_services VALUES (32, 4, 'managed-disabled', 'MTPROTO_FAKE_TLS', 25002, 0, 0)");

      await runtime.executeRaw("INSERT INTO tunnels VALUES (40, 2, 'forwardx', 'v1', 26000, 27000, 1)");
      await runtime.executeRaw("INSERT INTO tunnel_exit_nodes VALUES (41, 40, 3, 26000, 27000, 1)");
      await runtime.executeRaw("INSERT INTO tunnel_hops VALUES (42, 40, 4, 26000, 27000)");
      await runtime.executeRaw("INSERT INTO tunnel_hops VALUES (43, 40, 5, 0, 0)");
      await runtime.executeRaw("INSERT INTO tunnels VALUES (50, 5, 'forwardx', 'v2', 28000, 0, 1)");
      await runtime.executeRaw("INSERT INTO tunnels VALUES (60, 2, 'tls', 'v1', 29000, 0, 1)");
      await runtime.executeRaw("INSERT INTO tunnel_exit_nodes VALUES (61, 60, 3, 29000, 0, 1)");
      await runtime.executeRaw("INSERT INTO forward_rule_tunnel_exits VALUES (100, 20, 60, 61, 3, 24000)");

      await runtime.executeRaw("CREATE TRIGGER fail_managed_reference BEFORE INSERT ON global_port_allocation_references WHEN NEW.resourceType = 'MANAGED_SERVICE' BEGIN SELECT RAISE(ABORT, 'test rollback'); END");
      await assert.rejects(backfill.backfillGlobalPortAllocations(), /test rollback/);
      assert.equal((await runtime.queryRaw('SELECT COUNT(*) count FROM global_port_allocations'))[0].count, 0);
      assert.equal((await runtime.queryRaw('SELECT COUNT(*) count FROM global_port_allocation_references'))[0].count, 0);
      await runtime.executeRaw("DROP TRIGGER fail_managed_reference");

      const first = await backfill.backfillGlobalPortAllocations();
      assert.deepEqual(first, { allocationsCreated: 15, referencesCreated: 24, allocationsUpdated: 0 });
      const allocations = await runtime.queryRaw('SELECT * FROM global_port_allocations ORDER BY port');
      const byPort = new Map(allocations.map((row) => [Number(row.port), row]));
      assert.equal(byPort.get(80).status, 'ACTIVE');
      assert.equal(byPort.get(80).primaryOwnerType, 'XRAY_INBOUND');
      assert.equal(byPort.get(80).primaryOwnerTag, 'inbound-low');
      assert.equal(byPort.get(20000).status, 'LEGACY_CONFLICT');
      assert.equal(byPort.get(20000).primaryOwnerType, null);
      assert.equal(byPort.get(20000).primaryOwnerTag, null);
      assert.equal(byPort.get(22000).status, 'ACTIVE');
      assert.equal(byPort.get(22000).primaryOwnerTag, 'forward-rule:900');
      assert.equal(byPort.get(24000).status, 'ACTIVE');
      assert.equal(byPort.get(24000).primaryOwnerType, 'FORWARD_RULE');
      assert.equal(byPort.get(24000).primaryOwnerTag, 'forward-rule:20');
      assert.equal(byPort.get(26000).primaryOwnerTag, 'tunnel:40');
      assert.equal(byPort.get(27000).primaryOwnerTag, 'tunnel:40');

      const refs = await runtime.queryRaw('SELECT * FROM global_port_allocation_references ORDER BY referenceKey');
      const refsFor = (port) => refs.filter((row) => Number(row.allocationId) === Number(byPort.get(port).id));
      assert.deepEqual(refsFor(21000).map((row) => row.network).sort(), ['TCP', 'UDP']);
      assert.deepEqual(refsFor(22000).map((row) => [row.resourceId, row.hostId, row.network]), [[10, 1, 'TCP'], [11, 2, 'UDP']]);
      assert.equal(new Set(refsFor(22000).map((row) => row.ownerGroupTag)).size, 1);
      assert.deepEqual(refsFor(24000)
        .map((row) => [row.resourceType, row.resourceId, row.hostId, row.network])
        .sort((left, right) => Number(left[1]) - Number(right[1])), [
        ['FORWARD_RULE', 20, 2, 'BOTH'],
        ['FORWARD_RULE_TUNNEL_EXIT', 100, 3, 'BOTH'],
      ]);
      assert.deepEqual(refsFor(25000).map((row) => row.network), ['TCP']);
      assert.deepEqual(refsFor(25001).map((row) => row.network), ['UDP']);
      assert.deepEqual(refsFor(26000).map((row) => [row.resourceType, row.resourceId, row.hostId]), [
        ['TUNNEL', 40, 2], ['TUNNEL_EXIT_NODE', 41, 3], ['TUNNEL_HOP', 42, 4],
      ]);
      assert.equal(refsFor(26000).every((row) => row.network === 'TCP' && row.role === 'PUBLIC_LISTENER'), true);
      assert.equal(refsFor(27000).every((row) => row.network === 'UDP' && row.role === 'MIMIC'), true);
      assert.deepEqual(refsFor(28000).map((row) => row.network), ['UDP']);
      assert.equal(byPort.get(21001).primaryOwnerTag, 'disabled');
      assert.equal(byPort.has(22001), false);
      assert.equal(byPort.get(22002).primaryOwnerTag, 'forward-rule:22');
      assert.equal(byPort.get(25002).primaryOwnerTag, 'managed-disabled');

      const beforeSecond = JSON.stringify({ allocations, refs });
      assert.deepEqual(await backfill.backfillGlobalPortAllocations(), {
        allocationsCreated: 0, referencesCreated: 0, allocationsUpdated: 0,
      });
      const afterSecond = JSON.stringify({
        allocations: await runtime.queryRaw('SELECT * FROM global_port_allocations ORDER BY port'),
        refs: await runtime.queryRaw('SELECT * FROM global_port_allocation_references ORDER BY referenceKey'),
      });
      assert.equal(afterSecond, beforeSecond);

      await runtime.executeRaw("INSERT INTO global_port_allocations (id, allocationTag, port, status, primaryOwnerType, primaryOwnerTag, version, createdAt, updatedAt) VALUES (1000, 'global-port:v1:31000', 31000, 'ACTIVE', 'QUICK_CONFIG', 'quick-config:fixture', 4, 1, 1)");
      await runtime.executeRaw("INSERT INTO global_port_allocation_references (referenceKey, allocationId, resourceType, resourceId, ownerGroupTag, hostId, network, role, isOwning, createdAt, updatedAt) VALUES ('quick-config-existing', 1000, 'QUICK_CONFIG', 77, 'quick-config:fixture', 1, 'BOTH', 'PUBLIC_LISTENER', 1, 1, 1)");
      await runtime.executeRaw("INSERT INTO xray_managed_services VALUES (33, 4, 'managed-collision', 'MTPROTO_FAKE_TLS', 31000, 1, 0)");
      assert.deepEqual(await backfill.backfillGlobalPortAllocations(), {
        allocationsCreated: 0, referencesCreated: 1, allocationsUpdated: 1,
      });
      const occupied = (await runtime.queryRaw('SELECT status, primaryOwnerType, primaryOwnerTag, version FROM global_port_allocations WHERE port = 31000'))[0];
      assert.deepEqual(occupied, { status: 'LEGACY_CONFLICT', primaryOwnerType: null, primaryOwnerTag: null, version: 5 });

      for (const row of refs) {
        assert.match(row.referenceKey, /^global-port-ref:v1:/);
        assert.equal(row.referenceKey.includes('secret'), false);
      }
    } finally {
      await runtime.closeDatabase();
    }
  `;

  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: { ...process.env, DATABASE_TYPE: "sqlite", FORWARDX_TEST_DB: path.join(directory, "panel.db") },
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("database startup fails closed when the global port ledger cannot be backfilled", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-global-port-startup-"));
  const databasePath = path.join(directory, "panel.db");
  const configPath = path.join(directory, "database.json");
  fs.writeFileSync(configPath, JSON.stringify({ type: "sqlite", sqlite: { path: databasePath } }));
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const runtime = await load("server/dbRuntime.ts");
    const schema = await load("server/dbSchema.ts");
    const database = await load("server/db.ts");
    try {
      await runtime.connectDatabase();
      await schema.ensureDatabaseSchema();
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, userId) VALUES (1, 'edge', '192.0.2.1', 1)");
      await runtime.executeRaw("INSERT INTO xray_managed_services (id, hostId, name, serviceTag, kind, publicAddress, listenPort, specJson, targetVersion, createdByUserId) VALUES (1, 1, 'invalid', 'managed-invalid', 'UNKNOWN_KIND', '192.0.2.1', 25000, '{}', 'v1', 1)");
      const result = await database.initDatabase();
      assert.equal(result.configured, true);
      assert.equal(result.ready, false);
      assert.match(String(result.error), /GLOBAL_PORT_BACKFILL_INVALID_MANAGED_SERVICE_KIND/);
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM global_port_allocations"))[0].count, 0);
    } finally {
      await runtime.closeDatabase();
    }
  `;
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        DATABASE_CONFIG_PATH: configPath,
        SQLITE_PATH: databasePath,
        NODE_ENV: "test",
      },
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
