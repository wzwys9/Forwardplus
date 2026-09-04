import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("forward-group port checks cover every entry and exclude the edited template children", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-rule-port-check-"));
  const databasePath = path.join(directory, "port-check.db");
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";

    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const operations = await import(moduleUrl("server/xrayPortOperations.ts"));
    const { rulesRouter } = await import(moduleUrl("server/routers/rules.ts"));
    const q = (name) => '"' + name + '"';
    const insert = async (table, columns, values) => {
      await runtime.executeRaw(
        "INSERT INTO " + q(table) + " (" + columns.map(q).join(", ") + ") VALUES (" + values.map(() => "?").join(", ") + ")",
        values,
      );
    };

    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      const now = Math.floor(Date.now() / 1000);
      await insert("hosts", ["id", "name", "ip", "ipv4", "userId", "isOnline", "lastHeartbeat", "portRangeStart", "portRangeEnd"], [1, "entry", "198.51.100.10", "198.51.100.10", 1, 1, now, 17000, 18000]);
      await insert("hosts", ["id", "name", "ip", "ipv4", "userId", "isOnline", "lastHeartbeat", "portRangeStart", "portRangeEnd"], [2, "tunnel-exit", "198.51.100.11", "198.51.100.11", 1, 1, now, 17650, 17650]);
      await insert("hosts", ["id", "name", "ip", "ipv4", "userId", "isOnline", "lastHeartbeat", "portRangeStart", "portRangeEnd"], [3, "overlapping-entry-exit", "198.51.100.12", "198.51.100.12", 1, 1, now, 17700, 17700]);
      await insert("forward_groups", [
        "id", "name", "groupType", "groupMode", "domain", "recordType", "targetIp",
        "userId", "isEnabled", "activeMemberId", "failoverSeconds", "recoverSeconds", "autoFailback",
      ], [10, "saved-forward", "host", "port", "", "A", "0.0.0.0", 1, 1, null, 60, 120, 1]);
      await insert("forward_groups", [
        "id", "name", "groupType", "groupMode", "domain", "recordType", "targetIp",
        "userId", "isEnabled", "activeMemberId", "failoverSeconds", "recoverSeconds", "autoFailback",
      ], [11, "private-forward", "host", "port", "", "A", "0.0.0.0", 1, 1, null, 60, 120, 1]);
      await insert("forward_groups", [
        "id", "name", "groupType", "groupMode", "domain", "recordType", "targetIp",
        "userId", "isEnabled", "activeMemberId", "failoverSeconds", "recoverSeconds", "autoFailback",
      ], [12, "tunnel-port-conflict", "host", "port", "", "A", "0.0.0.0", 1, 1, null, 60, 120, 1]);
      await insert("forward_groups", [
        "id", "name", "groupType", "groupMode", "domain", "recordType", "targetIp",
        "userId", "isEnabled", "activeMemberId", "failoverSeconds", "recoverSeconds", "autoFailback",
      ], [13, "rule-exit-port-conflict", "host", "port", "", "A", "0.0.0.0", 1, 1, null, 60, 120, 1]);
      await insert("forward_group_members", ["id", "groupId", "memberType", "hostId", "priority", "isEnabled"], [101, 10, "host", 1, 0, 1]);
      await insert("forward_group_members", ["id", "groupId", "memberType", "hostId", "priority", "isEnabled"], [121, 12, "host", 2, 0, 1]);
      await insert("forward_group_members", ["id", "groupId", "memberType", "hostId", "priority", "isEnabled"], [1310, 13, "host", 3, 0, 1]);
      await insert("tunnels", ["id", "name", "entryHostId", "exitHostId", "listenPort", "userId"], [200, "occupied-listener", 1, 2, 17650, 1]);
      await insert("tunnels", ["id", "name", "entryHostId", "exitHostId", "listenPort", "userId"], [201, "child-exit", 1, 3, 17800, 1]);
      await insert("forward_rules", [
        "id", "hostId", "name", "forwardType", "protocol", "forwardGroupId", "isForwardGroupTemplate",
        "sourcePort", "targetIp", "targetPort", "userId", "isEnabled", "isRunning",
      ], [100, 1, "template", "iptables", "tcp", 10, 1, 17500, "203.0.113.10", 80, 1, 1, 0]);
      await insert("forward_rules", [
        "id", "hostId", "name", "forwardType", "protocol", "forwardGroupId", "forwardGroupRuleId",
        "forwardGroupMemberId", "isForwardGroupTemplate", "sourcePort", "targetIp", "targetPort", "userId", "isEnabled", "isRunning",
      ], [101, 1, "child", "iptables", "tcp", 10, 100, 101, 0, 17500, "203.0.113.10", 80, 1, 1, 0]);
      await insert("forward_rules", [
        "id", "hostId", "name", "forwardType", "protocol", "forwardGroupId", "isForwardGroupTemplate",
        "sourcePort", "targetIp", "targetPort", "userId", "isEnabled", "isRunning",
      ], [130, 1, "tunnel-template", "gost", "tcp", 10, 1, 17400, "203.0.113.20", 443, 1, 1, 0]);
      await insert("forward_rules", [
        "id", "hostId", "name", "forwardType", "protocol", "tunnelId", "tunnelExitPort", "forwardGroupId", "forwardGroupRuleId",
        "forwardGroupMemberId", "isForwardGroupTemplate", "sourcePort", "targetIp", "targetPort", "userId", "isEnabled", "isRunning",
      ], [131, 1, "tunnel-child", "gost", "tcp", 201, 17700, 10, 130, 101, 0, 17400, "203.0.113.20", 443, 1, 1, 0]);
      await insert("global_port_allocations", [
        "allocationTag", "port", "status", "primaryOwnerType", "primaryOwnerTag", "version",
      ], ["test-global-port:17502", 17502, "ACTIVE", "XRAY_INBOUND", "xray-test-owner", 1]);
      await insert("xray_runtime_reports", [
        "hostId", "capabilitySchemaVersion", "supportsPortProbe", "supportsUdpPortProbe", "supportsUdpListenerReadiness",
      ], [1, 1, 1, 1, 1]);

      const caller = rulesRouter.createCaller({
        req: { headers: {} },
        res: { clearCookie() {} },
        user: { id: 1, username: "admin", role: "admin", accountEnabled: true },
        authSession: null,
        authFailureReason: null,
      });
      assert.deepEqual(
        await caller.checkPort({ forwardGroupId: 10, sourcePort: 17500, protocol: "tcp" }),
        { used: true },
      );
      assert.deepEqual(
        await caller.checkPort({ forwardGroupId: 10, sourcePort: 17500, protocol: "udp" }),
        { used: true },
      );
      assert.deepEqual(
        await caller.checkPort({ forwardGroupId: 10, sourcePort: 17501, protocol: "tcp" }),
        { used: false },
      );
      assert.deepEqual(
        await caller.checkPort({ forwardGroupId: 10, sourcePort: 17502, protocol: "tcp" }),
        { used: true, reason: "端口已被全局占用" },
      );
      assert.deepEqual(
        await caller.checkPort({ hostId: 1, sourcePort: 17502, protocol: "tcp" }),
        { used: true, reason: "端口已被全局占用" },
      );
      assert.deepEqual(
        await caller.portProbeStart({ hostId: 1, sourcePort: 17502, protocol: "tcp" }),
        { status: "USED", reasonCode: "GLOBAL_PORT_CONFLICT", reason: "端口已被全局占用" },
      );
      await runtime.executeRaw('UPDATE "hosts" SET "portRangeStart" = ?, "portRangeEnd" = ? WHERE "id" = ?', [17502, 17502, 1]);
      await assert.rejects(
        () => caller.randomPort({ forwardGroupId: 10, protocol: "tcp" }),
        /入口端口区间内已无可用端口/,
      );
      await runtime.executeRaw('UPDATE "hosts" SET "portRangeStart" = ?, "portRangeEnd" = ? WHERE "id" = ?', [17000, 18000, 1]);

      const occupiedProbe = await caller.portProbeStart({
        hostId: 1,
        sourcePort: 17503,
        protocol: "tcp",
      });
      assert.equal(occupiedProbe.status, "RUNNING");
      const [occupiedTask] = await operations.takeXrayPortProbeTasks(1, 1);
      assert.deepEqual(occupiedTask.payload, { network: "tcp", listenAddress: "0.0.0.0", ports: [17503] });
      await operations.completeXrayPortProbeTask(1, {
        schemaVersion: 1,
        taskId: occupiedTask.taskId,
        type: "PORT_PROBE",
        status: "SUCCESS",
        startedAt: new Date().toISOString(),
        finishedAt: new Date().toISOString(),
        result: {
          ports: [{ port: 17503, available: false, errorCode: "PORT_IN_USE" }],
          observedAt: new Date().toISOString(),
        },
        error: null,
      });
      assert.deepEqual(
        await caller.portProbeResult({ portCheckId: occupiedProbe.portCheckId }),
        { status: "USED", reasonCode: "PORT_IN_USE", reason: "端口已被入口服务器占用" },
      );

      const availableProbe = await caller.portProbeStart({
        forwardGroupId: 10,
        sourcePort: 17504,
        protocol: "both",
      });
      assert.equal(availableProbe.status, "RUNNING", JSON.stringify(availableProbe));
      const availableTasks = await operations.takeXrayPortProbeTasks(1, 2);
      assert.deepEqual(availableTasks.map((task) => task.payload.network).sort(), ["tcp", "udp"]);
      for (const task of availableTasks) await operations.completeXrayPortProbeTask(1, {
          schemaVersion: 1,
          taskId: task.taskId,
          type: "PORT_PROBE",
          status: "SUCCESS",
          startedAt: new Date().toISOString(),
          finishedAt: new Date().toISOString(),
          result: {
            ports: [{ port: 17504, available: true, errorCode: null }],
            observedAt: new Date().toISOString(),
          },
          error: null,
        });
      const availableResult = await caller.portProbeResult({ portCheckId: availableProbe.portCheckId });
      assert.equal(availableResult.status, "AVAILABLE");
      const foreignCaller = rulesRouter.createCaller({
        req: { headers: {} },
        res: { clearCookie() {} },
        user: { id: 2, username: "other-admin", role: "admin", accountEnabled: true },
        authSession: null,
        authFailureReason: null,
      });
      await assert.rejects(
        () => foreignCaller.portProbeResult({ portCheckId: availableProbe.portCheckId }),
        /端口检查凭证无效/,
      );
      const tamperedSuffix = availableProbe.portCheckId.endsWith("A") ? "B" : "A";
      await assert.rejects(
        () => caller.portProbeResult({ portCheckId: availableProbe.portCheckId.slice(0, -1) + tamperedSuffix }),
        /端口检查凭证无效/,
      );

      const replacedProbe = await caller.portProbeStart({ forwardGroupId: 10, sourcePort: 17505, protocol: "tcp" });
      assert.equal(replacedProbe.status, "RUNNING");
      const replacementProbe = await caller.portProbeStart({
        forwardGroupId: 10,
        sourcePort: 17506,
        protocol: "tcp",
        replacePortCheckId: replacedProbe.portCheckId,
      });
      assert.equal(replacementProbe.status, "RUNNING");
      const replacementTasks = await operations.takeXrayPortProbeTasks(1, 2);
      assert.equal(replacementTasks.length, 1);
      assert.deepEqual(replacementTasks[0].payload.ports, [17506]);
      await operations.completeXrayPortProbeTask(1, {
        schemaVersion: 1,
        taskId: replacementTasks[0].taskId,
        type: "PORT_PROBE",
        status: "SUCCESS",
        startedAt: new Date().toISOString(),
        finishedAt: new Date().toISOString(),
        result: { ports: [{ port: 17506, available: true, errorCode: null }], observedAt: new Date().toISOString() },
        error: null,
      });
      assert.equal((await caller.portProbeResult({ portCheckId: replacementProbe.portCheckId })).status, "AVAILABLE");
      assert.deepEqual(
        await caller.checkPort({ forwardGroupId: 10, sourcePort: 17500, excludeRuleId: 100, protocol: "tcp" }),
        { used: false },
      );
      assert.deepEqual(
        await caller.checkPort({ forwardGroupId: 10, sourcePort: 16000, protocol: "tcp" }),
        { used: true, reason: "入口端口必须在允许范围内：17000-18000" },
      );
      assert.deepEqual(
        await caller.checkPort({ forwardGroupId: 12, sourcePort: 17650, protocol: "tcp" }),
        { used: true },
      );
      await assert.rejects(
        () => caller.randomPort({ forwardGroupId: 12, protocol: "tcp" }),
        /入口端口区间内已无可用端口/,
      );
      assert.deepEqual(
        await caller.checkPort({ forwardGroupId: 13, sourcePort: 17700, excludeRuleId: 130, protocol: "tcp" }),
        { used: true },
      );
      await assert.rejects(
        () => caller.randomPort({ forwardGroupId: 13, excludeRuleId: 130, protocol: "tcp" }),
        /入口端口区间内已无可用端口/,
      );

      await insert("subscription_plans", ["id", "name"], [50, "limited-ports"]);
      await insert("subscription_plan_forward_groups", ["planId", "forwardGroupId"], [50, 10]);
      await insert("user_subscriptions", ["id", "userId", "planId", "status", "portRangeStart", "portRangeEnd"], [60, 2, 50, "active", 17400, 17600]);
      const userCaller = rulesRouter.createCaller({
        req: { headers: {} },
        res: { clearCookie() {} },
        user: { id: 2, username: "viewer", role: "user", accountEnabled: true },
        authSession: null,
        authFailureReason: null,
      });
      assert.deepEqual(
        await userCaller.checkPort({ forwardGroupId: 10, sourcePort: 17501, protocol: "tcp" }),
        { used: false },
      );
      assert.deepEqual(
        await userCaller.checkPort({ forwardGroupId: 10, sourcePort: 17700, protocol: "tcp" }),
        { used: true, reason: "套餐端口必须在 17400-17600 范围内" },
      );
      await assert.rejects(
        () => userCaller.checkPort({ forwardGroupId: 11, sourcePort: 17501, protocol: "tcp" }),
        /无权使用该转发组/,
      );
      await runtime.executeRaw('UPDATE "hosts" SET "portRangeStart" = ?, "portRangeEnd" = ? WHERE "id" = ?', [17500, 17500, 1]);
      assert.deepEqual(
        await caller.randomPort({ hostId: 1, excludeRuleId: 100, protocol: "tcp" }),
        { port: 17500 },
      );
      assert.deepEqual(
        await caller.randomPort({ forwardGroupId: 10, excludeRuleId: 100, protocol: "tcp" }),
        { port: 17500 },
      );
      await assert.rejects(
        () => caller.randomPort({ forwardGroupId: 10, protocol: "udp" }),
        /入口端口区间内已无可用端口/,
      );
    } finally {
      await runtime.closeDatabase();
    }
  `;
  const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script], {
    cwd: process.cwd(),
    env: { ...process.env, DATABASE_TYPE: "sqlite", FORWARDX_TEST_DB: databasePath, JWT_SECRET: "rule-port-check-test-secret-1234567890" },
    encoding: "utf8",
    timeout: 60_000,
  });
  fs.rmSync(directory, { recursive: true, force: true });
  assert.equal(result.status, 0, result.stderr || result.stdout);
});

test("direct-host create, port lookup, enable, and update paths enforce subscription port ranges", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-rule-port-enable-"));
  const databasePath = path.join(directory, "port-enable.db");
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";

    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const { rulesRouter } = await import(moduleUrl("server/routers/rules.ts"));
    const q = (name) => '"' + name + '"';
    const insert = async (table, columns, values) => {
      await runtime.executeRaw(
        "INSERT INTO " + q(table) + " (" + columns.map(q).join(", ") + ") VALUES (" + values.map(() => "?").join(", ") + ")",
        values,
      );
    };
    const callerContext = (user) => ({
      req: { headers: {} },
      res: { clearCookie() {} },
      user,
      authSession: null,
      authFailureReason: null,
    });

    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      await runtime.executeRaw('UPDATE "system_settings" SET "value" = ? WHERE "key" = ?', ["true", "trafficBillingEnabled"]);
      await insert("users", ["id", "username", "password", "role", "canAddRules", "balanceCents"], [1, "admin", "x", "admin", 1, 1000]);
      await insert("users", ["id", "username", "password", "role", "canAddRules", "balanceCents"], [2, "limited", "x", "user", 1, 1000]);
      await insert("hosts", ["id", "name", "ip", "ipv4", "userId", "isOnline", "lastHeartbeat", "portRangeStart", "portRangeEnd"], [1, "entry", "198.51.100.10", "198.51.100.10", 1, 1, Math.floor(Date.now() / 1000), 10000, 20000]);
      await insert("hosts", ["id", "name", "ip", "ipv4", "userId", "isOnline", "lastHeartbeat", "portRangeStart", "portRangeEnd"], [2, "limited-entry", "198.51.100.11", "198.51.100.11", 2, 1, Math.floor(Date.now() / 1000), 10000, 20000]);
      await insert("traffic_billing_configs", ["id", "resourceType", "resourceId", "enabled", "requiresPermission", "pricePerGbCents", "multiplier"], [70, "host", 2, 1, 0, 1, 100]);
      await insert("forward_groups", ["id", "name", "groupType", "groupMode", "domain", "targetIp", "userId", "isEnabled"], [10, "limited-group", "host", "port", "", "0.0.0.0", 2, 1]);
      await insert("forward_groups", ["id", "name", "groupType", "groupMode", "domain", "targetIp", "userId", "isEnabled"], [11, "second-limited-group", "host", "port", "", "0.0.0.0", 2, 1]);
      await insert("forward_group_members", ["id", "groupId", "memberType", "hostId", "priority", "isEnabled"], [101, 10, "host", 1, 0, 1]);
      await insert("forward_group_members", ["id", "groupId", "memberType", "hostId", "priority", "isEnabled"], [111, 11, "host", 1, 0, 1]);
      await insert("subscription_plans", ["id", "name"], [50, "limited-ports"]);
      await insert("subscription_plan_hosts", ["planId", "hostId"], [50, 2]);
      await insert("subscription_plan_forward_groups", ["planId", "forwardGroupId"], [50, 10]);
      await insert("subscription_plan_forward_groups", ["planId", "forwardGroupId"], [50, 11]);
      await insert("user_subscriptions", ["id", "userId", "planId", "status", "portRangeStart", "portRangeEnd"], [60, 2, 50, "active", 17000, 18000]);
      await insert("forward_rules", ["id", "hostId", "name", "forwardType", "protocol", "sourcePort", "targetIp", "targetPort", "userId", "isEnabled", "isRunning"], [102, 2, "toggle-rule", "iptables", "tcp", 16000, "203.0.113.10", 80, 2, 0, 0]);
      await insert("forward_rules", ["id", "hostId", "name", "forwardType", "protocol", "sourcePort", "targetIp", "targetPort", "userId", "isEnabled", "isRunning"], [104, 2, "update-rule", "iptables", "tcp", 16001, "203.0.113.10", 80, 2, 0, 0]);
      await insert("forward_rules", ["id", "hostId", "name", "forwardType", "protocol", "forwardGroupId", "isForwardGroupTemplate", "sourcePort", "targetIp", "targetPort", "userId", "isEnabled", "isRunning"], [103, 1, "group-template", "iptables", "tcp", 10, 1, 16000, "203.0.113.10", 80, 2, 0, 0]);

      const limitedUser = { id: 2, username: "limited", role: "user", accountEnabled: true };
      const admin = { id: 1, username: "admin", role: "admin", accountEnabled: true };
      const limitedCaller = rulesRouter.createCaller(callerContext(limitedUser));
      const adminCaller = rulesRouter.createCaller(callerContext(admin));

      assert.deepEqual(
        await limitedCaller.checkPort({ hostId: 2, sourcePort: 16999, protocol: "tcp" }),
        { used: true, reason: "套餐端口必须在允许范围内：17000-18000" },
      );
      assert.deepEqual(
        await limitedCaller.checkPort({ hostId: 2, sourcePort: 17500, protocol: "tcp" }),
        { used: false },
      );
      const randomPort = await limitedCaller.randomPort({ hostId: 2, protocol: "tcp" });
      assert.ok(randomPort.port >= 17000 && randomPort.port <= 18000, "random port escaped plan range: " + randomPort.port);

      const directRule = {
        hostId: 2,
        name: "limited-direct-rule",
        forwardType: "iptables",
        protocol: "tcp",
        sourcePort: 16999,
        targetIp: "203.0.113.20",
        targetPort: 8080,
        isEnabled: true,
      };
      await assert.rejects(
        () => limitedCaller.create(directRule),
        /源端口必须在允许范围内：17000-18000/,
      );
      const created = await limitedCaller.create({ ...directRule, name: "limited-direct-rule-in-range", sourcePort: 17500 });
      assert.equal(created.sourcePort, 17500);
      assert.ok(Number(created.id) > 0);
      assert.deepEqual(
        await runtime.queryRaw('SELECT "hostId", "sourcePort", "userId" FROM "forward_rules" WHERE "id" = ?', [created.id]),
        [{ hostId: 2, sourcePort: 17500, userId: 2 }],
      );

      const groupImportBase = {
        forwardGroupId: 10,
        name: "random-group-import",
        forwardType: "iptables",
        protocol: "tcp",
        sourcePort: 0,
        targetIp: "example.test",
        targetPort: 50010,
        isEnabled: true,
      };
      const originalRandom = Math.random;
      Math.random = () => 0;
      let importedOne;
      let importedTwo;
      try {
        [importedOne, importedTwo] = await Promise.all([
          limitedCaller.create(groupImportBase),
          limitedCaller.create({ ...groupImportBase, forwardGroupId: 11, name: "random-group-import-2", targetIp: "example-two.test" }),
        ]);
      } finally {
        Math.random = originalRandom;
      }
      assert.ok(importedOne.sourcePort >= 17000 && importedOne.sourcePort <= 18000, "first random group port escaped plan range");
      assert.ok(importedTwo.sourcePort >= 17000 && importedTwo.sourcePort <= 18000, "second random group port escaped plan range");
      assert.notEqual(importedOne.sourcePort, importedTwo.sourcePort, "rules sharing a target port must receive distinct listener ports");
      assert.deepEqual(
        await runtime.queryRaw('SELECT "targetPort" FROM "forward_rules" WHERE "id" IN (?, ?) ORDER BY "id"', [importedOne.id, importedTwo.id]),
        [{ targetPort: 50010 }, { targetPort: 50010 }],
      );

      await limitedCaller.update({
        id: importedOne.id,
        forwardGroupId: 11,
        forwardType: "iptables",
        sourcePort: importedOne.sourcePort,
      });
      assert.deepEqual(
        await runtime.queryRaw('SELECT "forwardGroupId", "sourcePort" FROM "forward_rules" WHERE "id" = ?', [importedOne.id]),
        [{ forwardGroupId: 11, sourcePort: importedOne.sourcePort }],
      );

      Math.random = () => 0;
      try {
        await Promise.all([
          limitedCaller.update({ id: importedOne.id, sourcePort: 0 }),
          limitedCaller.update({ id: importedTwo.id, sourcePort: 0 }),
        ]);
      } finally {
        Math.random = originalRandom;
      }
      const reassigned = await runtime.queryRaw(
        'SELECT "sourcePort" FROM "forward_rules" WHERE "id" IN (?, ?) ORDER BY "id"',
        [importedOne.id, importedTwo.id],
      );
      assert.equal(reassigned.length, 2);
      assert.notEqual(reassigned[0].sourcePort, reassigned[1].sourcePort, "concurrent updates must reserve distinct listener ports");
      assert.ok(reassigned.every((row) => Number(row.sourcePort) >= 17000 && Number(row.sourcePort) <= 18000));

      await assert.rejects(() => limitedCaller.toggle({ id: 102, isEnabled: true }), /套餐端口/);
      await adminCaller.toggle({ id: 102, isEnabled: true });
      assert.equal(Number((await runtime.queryRaw('SELECT "isEnabled" FROM "forward_rules" WHERE "id" = ?', [102]))[0].isEnabled), 1);

      await assert.rejects(() => limitedCaller.update({ id: 104, isEnabled: true }), /套餐端口/);
      await adminCaller.update({ id: 104, isEnabled: true });
      assert.equal(Number((await runtime.queryRaw('SELECT "isEnabled" FROM "forward_rules" WHERE "id" = ?', [104]))[0].isEnabled), 1);

      await assert.rejects(() => limitedCaller.toggle({ id: 103, isEnabled: true }), /套餐端口/);
      await adminCaller.toggle({ id: 103, isEnabled: true });
      assert.equal(Number((await runtime.queryRaw('SELECT "isEnabled" FROM "forward_rules" WHERE "id" = ?', [103]))[0].isEnabled), 1);
    } finally {
      await runtime.closeDatabase();
    }
  `;
  const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script], {
    cwd: process.cwd(),
    env: { ...process.env, DATABASE_TYPE: "sqlite", FORWARDX_TEST_DB: databasePath },
    encoding: "utf8",
    timeout: 60_000,
  });
  fs.rmSync(directory, { recursive: true, force: true });
  assert.equal(result.status, 0, result.stderr || result.stdout);
});
