import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("quick config rules reuse or create real port resources and lock them", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-quick-port-resource-"));
  const databasePath = path.join(directory, "quick-port.db");
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";

    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));

    await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
    await schema.ensureDatabaseSchema();

    const resourceService = await import(moduleUrl("server/quickConfigPortResourceService.ts"));
    const groupsRepository = await import(moduleUrl("server/repositories/forwardGroupRepository.ts"));
    const q = (name) => '"' + name + '"';
    const insert = async (table, columns, values) => {
      await runtime.executeRaw(
        "INSERT INTO " + q(table) + " (" + columns.map(q).join(", ") + ") VALUES (" + values.map(() => "?").join(", ") + ")",
        values,
      );
    };

    try {
      const ruleColumns = [
        "id", "hostId", "name", "forwardType", "protocol", "forwardGroupId",
        "isForwardGroupTemplate", "sourcePort", "targetIp", "targetPort", "userId",
        "isEnabled", "pendingDelete", "xrayQuickConfigId",
      ];
      await insert("hosts", ["id", "name", "ip", "userId"], [1, "服务器 A", "192.0.2.1", 1]);
      await insert("hosts", ["id", "name", "ip", "userId"], [2, "服务器 B", "192.0.2.2", 1]);
      await insert("hosts", ["id", "name", "ip", "userId"], [3, "服务器 C", "192.0.2.3", 1]);

      await insert(
        "forward_groups",
        ["id", "name", "groupType", "groupMode", "forwardType", "protocol", "targetIp", "userId", "isEnabled"],
        [10, "dfaf", "host", "port", "realm", "both", "0.0.0.0", 1, 1],
      );
      await insert("forward_group_members", ["id", "groupId", "memberType", "hostId", "priority", "isEnabled"], [1001, 10, "host", 1, 0, 1]);

      await insert(
        "forward_groups",
        ["id", "name", "groupType", "groupMode", "forwardType", "protocol", "targetIp", "userId", "isEnabled"],
        [30, "C one", "host", "port", "gost", "both", "0.0.0.0", 1, 1],
      );
      await insert(
        "forward_groups",
        ["id", "name", "groupType", "groupMode", "forwardType", "protocol", "targetIp", "userId", "isEnabled"],
        [31, "C two", "host", "port", "gost", "both", "0.0.0.0", 1, 1],
      );
      await insert("forward_group_members", ["id", "groupId", "memberType", "hostId", "priority", "isEnabled"], [3001, 30, "host", 3, 0, 1]);
      await insert("forward_group_members", ["id", "groupId", "memberType", "hostId", "priority", "isEnabled"], [3101, 31, "host", 3, 0, 1]);

      await insert("forward_rules", ruleColumns, [90, 1, "manual", "realm", "tcp", 10, 1, 18000, "203.0.113.10", 443, 1, 1, 0, null]);
      await insert("forward_rules", ruleColumns, [100, 1, "quick A", "realm", "tcp", null, 0, 18001, "203.0.113.20", 443, 1, 1, 0, 1]);
      await insert("forward_rules", ruleColumns, [101, 2, "quick B one", "realm", "tcp", null, 0, 18002, "203.0.113.20", 443, 1, 1, 0, 1]);
      await insert("forward_rules", ruleColumns, [102, 2, "quick B two", "realm", "tcp", null, 0, 18003, "203.0.113.20", 443, 1, 1, 0, 2]);
      await insert("forward_rules", ruleColumns, [103, 3, "quick C", "gost", "tcp", null, 0, 18004, "203.0.113.20", 443, 1, 1, 0, 3]);

      const columns = await runtime.queryRaw('PRAGMA table_info("forward_rules")');
      assert.ok(columns.some((column) => column.name === "portResourceGroupId"));
      const groupColumns = await runtime.queryRaw('PRAGMA table_info("forward_groups")');
      assert.ok(groupColumns.some((column) => column.name === "systemManagedKind"));
      assert.ok(groupColumns.some((column) => column.name === "systemManagedKey"));

      const first = await resourceService.reconcileQuickConfigPortResources();
      assert.equal(first.rulesAssigned, 4);
      assert.equal(first.groupsCreated, 2);

      const assigned = await runtime.queryRaw(
        'SELECT "id", "portResourceGroupId" FROM "forward_rules" WHERE "id" IN (100, 101, 102, 103) ORDER BY "id"',
      );
      assert.equal(Number(assigned[0].portResourceGroupId), 10);
      assert.ok(Number(assigned[1].portResourceGroupId) > 31);
      assert.equal(Number(assigned[1].portResourceGroupId), Number(assigned[2].portResourceGroupId));
      assert.ok(Number(assigned[3].portResourceGroupId) > 31);
      assert.notEqual(Number(assigned[3].portResourceGroupId), 30);
      assert.notEqual(Number(assigned[3].portResourceGroupId), 31);

      const generated = await runtime.queryRaw(
        'SELECT "id", "name", "forwardType", "systemManagedKind", "systemManagedKey" FROM "forward_groups" WHERE "systemManagedKind" = ? ORDER BY "id"',
        ["XRAY_QUICK_CONFIG_PORT"],
      );
      assert.equal(generated.length, 2);
      assert.equal(generated[0].name, "快速配置默认生成");
      assert.match(String(generated[0].systemManagedKey), /^quick-config-port:v1:/);

      await insert(
        "forward_groups",
        ["id", "name", "groupType", "groupMode", "forwardType", "protocol", "targetIp", "userId", "isEnabled"],
        [12, "A later", "host", "port", "realm", "both", "0.0.0.0", 1, 1],
      );
      await insert("forward_group_members", ["id", "groupId", "memberType", "hostId", "priority", "isEnabled"], [1201, 12, "host", 1, 0, 1]);
      const second = await resourceService.reconcileQuickConfigPortResources();
      assert.deepEqual(second, { rulesAssigned: 0, groupsCreated: 0 });
      const generatedAgain = await runtime.queryRaw(
        'SELECT COUNT(*) AS "count" FROM "forward_groups" WHERE "systemManagedKind" = ?',
        ["XRAY_QUICK_CONFIG_PORT"],
      );
      assert.equal(Number(generatedAgain[0].count), 2);

      const groups = await groupsRepository.getForwardGroups(undefined, { includeRuntime: true });
      const dfaf = groups.find((group) => Number(group.id) === 10);
      assert.equal(dfaf.templateRuleCount, 1);
      assert.equal(dfaf.quickConfigRuleCount, 1);
      assert.equal(dfaf.referenceRuleCount, 2);
      assert.equal(dfaf.quickConfigLocked, true);
      const generatedB = groups.find((group) => Number(group.id) === Number(assigned[1].portResourceGroupId));
      assert.equal(generatedB.templateRuleCount, 0);
      assert.equal(generatedB.quickConfigRuleCount, 2);
      assert.equal(generatedB.referenceRuleCount, 2);

      await assert.rejects(
        () => groupsRepository.setForwardGroupEnabled(10, false),
        /QUICK_CONFIG_PORT_RESOURCE_IN_USE/,
      );
      await assert.rejects(
        () => groupsRepository.updateForwardGroup(10, { forwardType: "gost" }),
        /QUICK_CONFIG_PORT_RESOURCE_IN_USE/,
      );
      await groupsRepository.updateForwardGroup(10, { name: "dfaf renamed" }, { skipSync: true });
      assert.equal((await groupsRepository.getForwardGroupById(10)).name, "dfaf renamed");
      await assert.rejects(
        () => groupsRepository.deleteForwardGroup(10),
        /QUICK_CONFIG_PORT_RESOURCE_IN_USE/,
      );
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
        FORWARDX_LOG_DIR: path.join(directory, "logs"),
      },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
