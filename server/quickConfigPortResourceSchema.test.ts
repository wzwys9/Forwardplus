import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("quick config port resource columns stay aligned across database dialects", () => {
  const script = String.raw`
    import assert from "node:assert/strict";
    const schema = await import("./drizzle/schema.ts");
    const runtimeSchema = await import("./server/dbSchema.ts");
    const dialect = process.env.DATABASE_TYPE;
    const core = dialect === "sqlite"
      ? await import("drizzle-orm/sqlite-core")
      : dialect === "postgresql"
        ? await import("drizzle-orm/pg-core")
        : await import("drizzle-orm/mysql-core");
    const rules = core.getTableConfig(schema.forwardRules);
    const groups = core.getTableConfig(schema.forwardGroups);
    assert.ok(rules.columns.some((column) => column.name === "portResourceGroupId"));
    assert.ok(groups.columns.some((column) => column.name === "systemManagedKind"));
    assert.ok(groups.columns.some((column) => column.name === "systemManagedKey"));
    assert.ok(groups.indexes.some((index) => index.config.unique && index.config.columns.some((column) => column.name === "systemManagedKey")));

    const rulesDef = runtimeSchema.getDatabaseTableDefs().find((table) => table.name === "forward_rules");
    const groupsDef = runtimeSchema.getDatabaseTableDefs().find((table) => table.name === "forward_groups");
    assert.ok(rulesDef.columns.some((column) => column.name === "portResourceGroupId"));
    assert.ok(rulesDef.indexes.some((columns) => columns.join("|") === "portResourceGroupId"));
    assert.ok(groupsDef.columns.some((column) => column.name === "systemManagedKind"));
    assert.ok(groupsDef.columns.some((column) => column.name === "systemManagedKey"));
    assert.ok(groupsDef.unique.some((columns) => columns.join("|") === "systemManagedKey"));
  `;
  for (const dialect of ["sqlite", "mysql", "postgresql"]) {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: { ...process.env, DATABASE_TYPE: dialect },
      encoding: "utf8",
    });
    assert.equal(result.status, 0, `${dialect}: ${result.stderr || result.stdout}`);
  }
});
