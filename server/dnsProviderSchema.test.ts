import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";
import test from "node:test";
import Database from "better-sqlite3";
import { getTableConfig as getMysqlTableConfig } from "drizzle-orm/mysql-core";
import { getTableConfig as getPgTableConfig } from "drizzle-orm/pg-core";
import { getTableConfig as getSqliteTableConfig } from "drizzle-orm/sqlite-core";
import {
  MIGRATION_TABLES,
  ensureDatabaseSchema,
  getDatabaseTableDefs,
  type ColumnDef,
  type TableDef,
} from "./dbSchema";

const GLOBAL_SCOPE = "XRAY_QUICK_CONFIG";

const c = (name: string, type: ColumnDef["type"], options: Omit<ColumnDef, "name" | "type"> = {}): ColumnDef => ({
  name,
  type,
  ...options,
});

const expectedTables: TableDef[] = [
  {
    name: "dns_provider_accounts",
    columns: [
      c("id", "id"), c("accountTag", "varchar", { length: 128, notNull: true }),
      c("provider", "varchar", { length: 32, notNull: true }), c("name", "text", { notNull: true }),
      c("revision", "bigint", { notNull: true, default: 1 }), c("isDisabled", "bool", { notNull: true, default: false }),
      c("verificationStatus", "varchar", { length: 32, notNull: true, default: "UNVERIFIED" }),
      c("lastErrorCode", "varchar", { length: 64 }), c("lastValidationAttemptAt", "epoch"),
      c("verifiedAt", "epoch"), c("verificationExpiresAt", "epoch"), c("createdByUserId", "int", { notNull: true }),
      c("createdAt", "epoch", { notNull: true, default: "now" }), c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["accountTag"]],
    indexes: [["provider"], ["verificationExpiresAt"]],
  },
  {
    name: "dns_provider_account_secrets",
    columns: [
      c("id", "id"), c("accountId", "int", { notNull: true }), c("kind", "varchar", { length: 32, notNull: true }),
      c("encryptedValue", "text", { notNull: true }), c("fingerprint", "varchar", { length: 64, notNull: true }),
      c("keyVersion", "int", { notNull: true }), c("createdAt", "epoch", { notNull: true, default: "now" }),
      c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["accountId", "kind"]],
    indexes: [["kind", "fingerprint"]],
  },
  {
    name: "dns_provider_global_bindings",
    columns: [
      c("id", "id"), c("scopeKey", "varchar", { length: 64, notNull: true }), c("accountId", "int"),
      c("revision", "bigint", { notNull: true, default: 1 }),
      c("createdAt", "epoch", { notNull: true, default: "now" }), c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["scopeKey"]],
    indexes: [["accountId"]],
  },
  {
    name: "dns_provider_zones",
    columns: [
      c("id", "id"), c("accountId", "int", { notNull: true }),
      c("providerZoneId", "varchar", { length: 128, notNull: true }), c("name", "varchar", { length: 255, notNull: true }),
      c("status", "varchar", { length: 32, notNull: true }), c("catalogRevision", "varchar", { length: 64, notNull: true }),
      c("refreshedAt", "epoch", { notNull: true }), c("expiresAt", "epoch", { notNull: true }),
      c("lastSeenAt", "epoch", { notNull: true }), c("createdAt", "epoch", { notNull: true, default: "now" }),
      c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["accountId", "providerZoneId"], ["accountId", "name"]],
    indexes: [["accountId", "status", "expiresAt"]],
  },
  {
    name: "dns_provider_record_lines",
    columns: [
      c("id", "id"), c("zoneId", "int", { notNull: true }),
      c("providerLineId", "varchar", { length: 128, notNull: true }), c("name", "varchar", { length: 255, notNull: true }),
      c("category", "varchar", { length: 32, notNull: true }), c("status", "varchar", { length: 32, notNull: true }),
      c("catalogRevision", "varchar", { length: 64, notNull: true }), c("refreshedAt", "epoch", { notNull: true }),
      c("expiresAt", "epoch", { notNull: true }), c("lastSeenAt", "epoch", { notNull: true }),
      c("createdAt", "epoch", { notNull: true, default: "now" }), c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["zoneId", "providerLineId"]],
    indexes: [["zoneId", "category", "status"]],
  },
];

test("runtime descriptors define the five approved DNS provider tables", () => {
  const names = expectedTables.map((table) => table.name);
  assert.deepEqual(MIGRATION_TABLES.filter((name) => names.includes(name)), names);
  assert.deepEqual(getDatabaseTableDefs().filter((table) => names.includes(table.name)), expectedTables);
});

test("Drizzle exposes matching DNS provider tables for all three dialects", async () => {
  const previousDatabaseType = process.env.DATABASE_TYPE;
  const exportNames = [
    "dnsProviderAccounts",
    "dnsProviderAccountSecrets",
    "dnsProviderGlobalBindings",
    "dnsProviderZones",
    "dnsProviderRecordLines",
  ];
  const dialects = [
    { name: "sqlite", config: getSqliteTableConfig as (table: any) => any },
    { name: "mysql", config: getMysqlTableConfig as (table: any) => any },
    { name: "postgresql", config: getPgTableConfig as (table: any) => any },
  ] as const;

  try {
    for (const dialect of dialects) {
      process.env.DATABASE_TYPE = dialect.name;
      const schemaUrl = `${pathToFileURL(`${process.cwd()}/drizzle/schema.ts`).href}?dns-provider-schema=${dialect.name}-${Date.now()}`;
      const schema = await import(schemaUrl) as Record<string, any>;
      for (const [index, expected] of expectedTables.entries()) {
        const config = dialect.config(schema[exportNames[index]]);
        assert.equal(config.name, expected.name);
        assert.deepEqual(config.columns.map((column: any) => column.name), expected.columns.map((column) => column.name));
        for (const expectedColumn of expected.columns.filter((column) => column.type !== "id")) {
          const actualColumn = config.columns.find((column: any) => column.name === expectedColumn.name)!;
          assert.equal(actualColumn.notNull, expectedColumn.notNull === true, `${dialect.name}.${expected.name}.${expectedColumn.name} nullability`);
          assert.equal(actualColumn.hasDefault, expectedColumn.default !== undefined, `${dialect.name}.${expected.name}.${expectedColumn.name} default`);
        }
        const actualIndexes = config.indexes.map((item: any) => ({
          unique: item.config.unique,
          columns: item.config.columns.map((column: any) => column.name),
        }));
        const expectedIndexes = [
          ...(expected.indexes || []).map((columns) => ({ unique: false, columns })),
          ...(expected.unique || []).map((columns) => ({ unique: true, columns })),
        ];
        const byIdentity = (left: { unique: boolean; columns: string[] }, right: { unique: boolean; columns: string[] }) =>
          `${left.unique}:${left.columns.join("|")}`.localeCompare(`${right.unique}:${right.columns.join("|")}`);
        assert.deepEqual(actualIndexes.sort(byIdentity), expectedIndexes.sort(byIdentity));
      }
    }
  } finally {
    if (previousDatabaseType === undefined) delete process.env.DATABASE_TYPE;
    else process.env.DATABASE_TYPE = previousDatabaseType;
  }
});

test("SQLite creates DNS provider tables, uniqueness, and the fixed empty binding idempotently", async () => {
  const sqlite = new Database(":memory:");
  try {
    await ensureDatabaseSchema(sqlite);
    await ensureDatabaseSchema(sqlite);

    const seedRows = sqlite.prepare("SELECT scopeKey, accountId, revision FROM dns_provider_global_bindings").all();
    assert.deepEqual(seedRows, [{ scopeKey: GLOBAL_SCOPE, accountId: null, revision: 1 }]);

    const account = sqlite.prepare(`INSERT INTO dns_provider_accounts
      (accountTag, provider, name, createdByUserId) VALUES (?, ?, ?, ?)`);
    account.run("account-a", "DNSPOD", "primary", 1);
    account.run("account-b", "DNSPOD", "secondary", 1);
    assert.throws(() => account.run("account-a", "DNSPOD", "duplicate", 1), /UNIQUE/);

    const secret = sqlite.prepare(`INSERT INTO dns_provider_account_secrets
      (accountId, kind, encryptedValue, fingerprint, keyVersion) VALUES (?, ?, ?, ?, ?)`);
    secret.run(1, "DNSPOD_SECRET_ID", "encrypted-a", "same-fingerprint", 1);
    secret.run(2, "DNSPOD_SECRET_ID", "encrypted-b", "same-fingerprint", 1);
    assert.throws(() => secret.run(1, "DNSPOD_SECRET_ID", "encrypted-c", "other-fingerprint", 1), /UNIQUE/);

    const zone = sqlite.prepare(`INSERT INTO dns_provider_zones
      (accountId, providerZoneId, name, status, catalogRevision, refreshedAt, expiresAt, lastSeenAt)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
    zone.run(1, "zone-1", "example.com", "AVAILABLE", "catalog-1", 1, 2, 1);
    zone.run(2, "zone-1", "example.com", "AVAILABLE", "catalog-1", 1, 2, 1);
    assert.throws(() => zone.run(1, "zone-1", "example.net", "AVAILABLE", "catalog-1", 1, 2, 1), /UNIQUE/);
    assert.throws(() => zone.run(1, "zone-2", "example.com", "AVAILABLE", "catalog-1", 1, 2, 1), /UNIQUE/);

    const line = sqlite.prepare(`INSERT INTO dns_provider_record_lines
      (zoneId, providerLineId, name, category, status, catalogRevision, refreshedAt, expiresAt, lastSeenAt)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    line.run(1, "line-1", "电信", "TELECOM", "AVAILABLE", "catalog-1", 1, 2, 1);
    line.run(2, "line-1", "电信", "TELECOM", "AVAILABLE", "catalog-1", 1, 2, 1);
    assert.throws(() => line.run(1, "line-1", "重复", "TELECOM", "AVAILABLE", "catalog-1", 1, 2, 1), /UNIQUE/);
  } finally {
    sqlite.close();
  }
});

test("MySQL and PostgreSQL schema initialization emit the fixed binding seed", async () => {
  const mysqlQueries: Array<{ sql: string; params?: unknown[] }> = [];
  const mysqlPool = {
    getConnection() {
      throw new Error("not used");
    },
    async query(sql: string, params?: unknown[]) {
      mysqlQueries.push({ sql, params });
      return [[], []];
    },
    async execute(sql: string, params?: unknown[]) {
      mysqlQueries.push({ sql, params });
      return [[], []];
    },
  };
  await ensureDatabaseSchema(mysqlPool as any);
  assert.equal(mysqlQueries.some(({ sql, params }) =>
    sql.includes("INSERT INTO dns_provider_global_bindings") && params?.[0] === GLOBAL_SCOPE), true);

  const postgresQueries: Array<{ sql: string; params?: unknown[] }> = [];
  const postgresPool = {
    async query(sql: string, params?: unknown[]) {
      postgresQueries.push({ sql, params });
      return { rows: [] };
    },
  };
  await ensureDatabaseSchema(postgresPool as any);
  assert.equal(postgresQueries.some(({ sql, params }) =>
    sql.includes('INSERT INTO "dns_provider_global_bindings"') && params?.[0] === GLOBAL_SCOPE), true);
});
