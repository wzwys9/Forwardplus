import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import Database from "better-sqlite3";
import { ensureDatabaseSchema, getDatabaseTableDefs } from "./dbSchema";

const identityColumns = [
  "agentDistribution",
  "agentBuildId",
  "agentUpgradeTargetDistribution",
];

test("hosts runtime schema defines the additive Agent identity columns", () => {
  const hosts = getDatabaseTableDefs().find((table) => table.name === "hosts");
  assert.ok(hosts);
  const columns = new Map(hosts.columns.map((column) => [column.name, column]));
  for (const name of identityColumns) assert.equal(columns.has(name), true, `${name} is missing`);
  assert.deepEqual(columns.get("agentDistribution"), { name: "agentDistribution", type: "varchar", length: 32 });
  assert.deepEqual(columns.get("agentBuildId"), { name: "agentBuildId", type: "varchar", length: 64 });
  assert.deepEqual(columns.get("agentUpgradeTargetDistribution"), {
    name: "agentUpgradeTargetDistribution",
    type: "varchar",
    length: 32,
  });
});

test("SQLite adds Agent identity columns to an existing hosts table idempotently", async () => {
  const sqlite = new Database(":memory:");
  try {
    sqlite.exec("CREATE TABLE hosts (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, ip TEXT NOT NULL)");
    await ensureDatabaseSchema(sqlite);
    await ensureDatabaseSchema(sqlite);
    const columns = sqlite.prepare("PRAGMA table_info(hosts)").all() as Array<{ name: string }>;
    const names = new Set(columns.map((column) => column.name));
    for (const name of identityColumns) assert.equal(names.has(name), true, `${name} is missing`);
  } finally {
    sqlite.close();
  }
});

test("host repository preserves reported identity and the target distribution", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardplus-agent-identity-"));
  const databasePath = path.join(directory, "identity.db");
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const url = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(url("server/dbRuntime.ts"));
    const schema = await import(url("server/dbSchema.ts"));
    const hosts = await import(url("server/repositories/hostRepository.ts"));
    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, isOnline, lastHeartbeat, agentVersion, userId) VALUES (1, 'original', '127.0.0.1', 1, ?, '9.0.0', 1)", [Math.floor(Date.now() / 1000)]);
      const [candidate] = await hosts.getHostUpgradeCandidates({});
      assert.equal(candidate.agentVersion, "9.0.0");
      assert.equal(candidate.agentDistribution, null);
      await hosts.requestHostAgentUpgrade(1, "2.3.0");
      let [row] = await runtime.queryRaw("SELECT agentUpgradeTargetDistribution FROM hosts WHERE id = 1");
      assert.equal(row.agentUpgradeTargetDistribution, "forwardplus");
      await hosts.updateHostHeartbeat(1, { agentDistribution: "forwardplus", agentBuildId: "0123456789ab" });
      [row] = await runtime.queryRaw("SELECT agentVersion, agentDistribution, agentBuildId FROM hosts WHERE id = 1");
      assert.deepEqual(row, { agentVersion: "9.0.0", agentDistribution: "forwardplus", agentBuildId: "0123456789ab" });
      await hosts.clearHostAgentUpgradeRequest(1);
      [row] = await runtime.queryRaw("SELECT agentUpgradeRequested, agentUpgradeTargetDistribution FROM hosts WHERE id = 1");
      assert.equal(Number(row.agentUpgradeRequested), 0);
      assert.equal(row.agentUpgradeTargetDistribution, null);
    } finally {
      await runtime.closeDatabase();
    }
  `;
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: { ...process.env, DATABASE_TYPE: "sqlite", FORWARDX_TEST_DB: databasePath, JWT_SECRET: "agent-identity-test" },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
