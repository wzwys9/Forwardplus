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

const PORT_RECLAIM_SCOPE = "GLOBAL_PORT_RECLAIM";

const c = (name: string, type: ColumnDef["type"], options: Omit<ColumnDef, "name" | "type"> = {}): ColumnDef => ({
  name,
  type,
  ...options,
});
const timestamps = [
  c("createdAt", "epoch", { notNull: true, default: "now" }),
  c("updatedAt", "epoch", { notNull: true, default: "now" }),
];

const expectedTables: TableDef[] = [
  {
    name: "xray_quick_configs",
    columns: [
      c("id", "id"), c("configTag", "varchar", { length: 128, notNull: true }),
      c("targetType", "varchar", { length: 32, notNull: true }), c("xrayInboundId", "int"),
      c("externalProxyNodeId", "int"), c("targetVersion", "varchar", { length: 64, notNull: true }),
      c("dnsAccountId", "int", { notNull: true }), c("zoneId", "int", { notNull: true }),
      c("relativeName", "text", { notNull: true }), c("fqdn", "text", { notNull: true }),
      c("state", "varchar", { length: 32, notNull: true }),
      c("revision", "bigint", { notNull: true, default: 1 }), c("activeTopologyRevisionId", "int"),
      c("desiredTopologyRevisionId", "int"), c("currentOperationId", "int"),
      c("createdByUserId", "int", { notNull: true }), ...timestamps,
    ],
    unique: [["configTag"]],
    indexes: [["xrayInboundId"], ["externalProxyNodeId"], ["dnsAccountId"], ["zoneId"], ["activeTopologyRevisionId"], ["desiredTopologyRevisionId"], ["currentOperationId"]],
  },
  {
    name: "xray_quick_config_domain_claims",
    columns: [
      c("id", "id"), c("claimKey", "varchar", { length: 64, notNull: true }),
      c("dnsAccountId", "int", { notNull: true }), c("zoneId", "int", { notNull: true }),
      c("normalizedRelativeName", "text", { notNull: true }), c("quickConfigId", "int", { notNull: true }),
      c("revision", "bigint", { notNull: true, default: 1 }), ...timestamps,
    ],
    unique: [["claimKey"], ["quickConfigId"]],
    indexes: [["dnsAccountId", "zoneId"]],
  },
  {
    name: "xray_quick_config_topology_revisions",
    columns: [
      c("id", "id"), c("quickConfigId", "int", { notNull: true }),
      c("revisionNumber", "bigint", { notNull: true }), c("engine", "varchar", { length: 32, notNull: true }),
      c("targetAddress", "text", { notNull: true }), c("targetPort", "int", { notNull: true }),
      c("publicPort", "int", { notNull: true }), c("portAllocationId", "int", { notNull: true }),
      c("state", "varchar", { length: 32, notNull: true }), c("activeSlot", "int"),
      c("createdByUserId", "int", { notNull: true }), ...timestamps,
    ],
    unique: [["quickConfigId", "revisionNumber"], ["quickConfigId", "activeSlot"]],
    indexes: [["portAllocationId"], ["state"]],
  },
  {
    name: "xray_quick_config_routes",
    columns: [
      c("id", "id"), c("routeTag", "varchar", { length: 128, notNull: true }),
      c("quickConfigId", "int", { notNull: true }), c("topologyRevisionId", "int", { notNull: true }),
      c("lineCategory", "varchar", { length: 32, notNull: true }),
      c("providerLineId", "varchar", { length: 128, notNull: true }),
      c("sourceType", "varchar", { length: 32, notNull: true }), c("hostId", "int"),
      c("addressFamily", "varchar", { length: 16, notNull: true }), c("address", "text", { notNull: true }),
      c("relayHopsJson", "text"),
      c("routeMode", "varchar", { length: 16, notNull: true }), c("sortOrder", "int", { notNull: true, default: 0 }),
      c("state", "varchar", { length: 32, notNull: true }), ...timestamps,
    ],
    unique: [["routeTag"]],
    indexes: [["quickConfigId", "state"], ["topologyRevisionId", "sortOrder"], ["hostId"]],
  },
  {
    name: "xray_quick_config_rule_bindings",
    columns: [
      c("id", "id"), c("bindingTag", "varchar", { length: 128, notNull: true }),
      c("quickConfigId", "int", { notNull: true }), c("topologyRevisionId", "int", { notNull: true }),
      c("forwardRuleId", "int", { notNull: true }), c("state", "varchar", { length: 32, notNull: true }),
      ...timestamps,
    ],
    unique: [["bindingTag"], ["topologyRevisionId", "forwardRuleId"]],
    indexes: [["quickConfigId", "state"], ["forwardRuleId"]],
  },
  {
    name: "xray_quick_config_dns_records",
    columns: [
      c("id", "id"), c("quickConfigId", "int", { notNull: true }), c("routeId", "int", { notNull: true }),
      c("dnsAccountId", "int", { notNull: true }), c("zoneId", "int", { notNull: true }),
      c("recordTag", "varchar", { length: 128, notNull: true }), c("providerRecordId", "varchar", { length: 128 }),
      c("providerLineId", "varchar", { length: 128, notNull: true }), c("fqdn", "text", { notNull: true }),
      c("recordType", "varchar", { length: 16, notNull: true }), c("value", "text", { notNull: true }),
      c("ttl", "int", { notNull: true }), c("status", "varchar", { length: 32, notNull: true }),
      c("appliedRevision", "bigint", { notNull: true }), c("remoteTupleHash", "varchar", { length: 64, notNull: true }),
      c("lastVerifiedAt", "epoch"), ...timestamps,
    ],
    unique: [["recordTag"], ["dnsAccountId", "providerRecordId"]],
    indexes: [["quickConfigId", "status"], ["routeId"], ["zoneId"]],
  },
  {
    name: "xray_quick_config_dns_record_backups",
    columns: [
      c("id", "id"), c("operationId", "int", { notNull: true }), c("dnsAccountId", "int", { notNull: true }),
      c("zoneId", "int", { notNull: true }), c("providerRecordId", "varchar", { length: 128, notNull: true }),
      c("fqdn", "text", { notNull: true }), c("recordType", "varchar", { length: 16, notNull: true }),
      c("providerLineId", "varchar", { length: 128, notNull: true }), c("value", "text", { notNull: true }),
      c("ttl", "int", { notNull: true }), c("remoteTupleHash", "varchar", { length: 64, notNull: true }),
      c("snapshotOrder", "int", { notNull: true }), c("state", "varchar", { length: 32, notNull: true }),
      ...timestamps,
    ],
    unique: [["operationId", "dnsAccountId", "providerRecordId"], ["operationId", "snapshotOrder"]],
    indexes: [["operationId", "state"]],
  },
  {
    name: "xray_quick_config_operations",
    columns: [
      c("id", "id"), c("operationTag", "varchar", { length: 128, notNull: true }),
      c("quickConfigId", "int", { notNull: true }), c("type", "varchar", { length: 32, notNull: true }),
      c("status", "varchar", { length: 32, notNull: true }), c("phase", "varchar", { length: 32, notNull: true }),
      c("activeSlot", "int"), c("revision", "bigint", { notNull: true, default: 1 }),
      c("expectedRevision", "bigint", { notNull: true }), c("fromTopologyRevisionId", "int"),
      c("toTopologyRevisionId", "int"), c("requestSummaryJson", "text", { notNull: true }),
      c("retryOfOperationId", "int"), c("executionOwnerId", "varchar", { length: 128 }),
      c("executionLeaseUntil", "epoch"), c("executionFence", "bigint", { notNull: true, default: 1 }),
      c("errorCode", "varchar", { length: 64 }), c("errorMessage", "text"),
      c("createdByUserId", "int", { notNull: true }), c("startedAt", "epoch"), c("finishedAt", "epoch"),
      ...timestamps,
    ],
    unique: [["operationTag"], ["quickConfigId", "activeSlot"]],
    indexes: [["quickConfigId", "status", "createdAt"], ["retryOfOperationId"], ["executionLeaseUntil"], ["fromTopologyRevisionId"], ["toTopologyRevisionId"]],
  },
  {
    name: "xray_quick_config_operation_steps",
    columns: [
      c("id", "id"), c("operationId", "int", { notNull: true }),
      c("stepKey", "varchar", { length: 128, notNull: true }), c("kind", "varchar", { length: 32, notNull: true }),
      c("subjectType", "varchar", { length: 32, notNull: true }), c("subjectId", "varchar", { length: 128 }),
      c("status", "varchar", { length: 32, notNull: true }), c("attemptCount", "int", { notNull: true, default: 0 }),
      c("idempotencyKey", "varchar", { length: 128, notNull: true }), c("requestSummaryJson", "text", { notNull: true }),
      c("resultSummaryJson", "text"), c("errorCode", "varchar", { length: 64 }), c("startedAt", "epoch"),
      c("finishedAt", "epoch"), c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["operationId", "stepKey"], ["idempotencyKey"]],
    indexes: [["operationId", "status"], ["subjectType", "subjectId"]],
  },
  {
    name: "global_port_allocations",
    columns: [
      c("id", "id"), c("allocationTag", "varchar", { length: 128, notNull: true }), c("port", "int", { notNull: true }),
      c("status", "varchar", { length: 32, notNull: true }), c("primaryOwnerType", "varchar", { length: 64 }),
      c("primaryOwnerTag", "varchar", { length: 128 }), c("reservationTokenHash", "varchar", { length: 64 }),
      c("reservedUntil", "epoch"), c("scanNotBefore", "epoch"), c("lastScanStartedAt", "epoch"),
      c("lastScanFinishedAt", "epoch"), c("lastErrorCode", "varchar", { length: 64 }),
      c("version", "bigint", { notNull: true, default: 1 }), ...timestamps,
    ],
    unique: [["allocationTag"], ["port"]],
    indexes: [["status", "scanNotBefore"], ["primaryOwnerType", "primaryOwnerTag"]],
  },
  {
    name: "global_port_allocation_references",
    columns: [
      c("id", "id"), c("referenceKey", "varchar", { length: 255, notNull: true }),
      c("allocationId", "int", { notNull: true }), c("resourceType", "varchar", { length: 64, notNull: true }),
      c("resourceId", "int", { notNull: true }), c("ownerGroupTag", "varchar", { length: 128, notNull: true }),
      c("hostId", "int"), c("network", "varchar", { length: 16, notNull: true }),
      c("role", "varchar", { length: 32, notNull: true }), c("isOwning", "bool", { notNull: true, default: false }),
      ...timestamps,
    ],
    unique: [["referenceKey"]],
    indexes: [["allocationId", "ownerGroupTag"], ["resourceType", "resourceId"], ["hostId"]],
  },
  {
    name: "global_port_probe_runs",
    columns: [
      c("id", "id"), c("probeTag", "varchar", { length: 128, notNull: true }), c("allocationId", "int"),
      c("allocationVersion", "bigint"), c("candidatePort", "int", { notNull: true }),
      c("purpose", "varchar", { length: 32, notNull: true }), c("status", "varchar", { length: 32, notNull: true }),
      c("hostSetHash", "varchar", { length: 64, notNull: true }), c("expectedHostCount", "int", { notNull: true }),
      c("createdByUserId", "int"), c("startedAt", "epoch"), c("finishedAt", "epoch"),
      c("expiresAt", "epoch", { notNull: true }), c("errorCode", "varchar", { length: 64 }),
    ],
    unique: [["probeTag"]],
    indexes: [["allocationId"], ["purpose", "status", "expiresAt"]],
  },
  {
    name: "global_port_probe_results",
    columns: [
      c("id", "id"), c("probeRunId", "int", { notNull: true }), c("hostId", "int", { notNull: true }),
      c("network", "varchar", { length: 8, notNull: true }), c("xrayOperationId", "varchar", { length: 64, notNull: true }),
      c("status", "varchar", { length: 32, notNull: true }), c("probedAt", "epoch", { notNull: true }),
      c("expiresAt", "epoch", { notNull: true }),
    ],
    unique: [["probeRunId", "hostId", "network"]],
    indexes: [["xrayOperationId"], ["hostId", "expiresAt"]],
  },
  {
    name: "global_port_scan_leases",
    columns: [
      c("id", "id"), c("scopeKey", "varchar", { length: 64, notNull: true }),
      c("leaseOwnerHash", "varchar", { length: 64 }), c("leaseUntil", "epoch"), c("lastStartedAt", "epoch"),
      c("lastFinishedAt", "epoch"), c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["scopeKey"]],
  },
];

test("runtime descriptors define the approved quick-config and global-port schema", () => {
  const names = expectedTables.map((table) => table.name);
  assert.deepEqual(MIGRATION_TABLES.filter((name) => names.includes(name)), names);
  assert.deepEqual(getDatabaseTableDefs().filter((table) => names.includes(table.name)), expectedTables);

  const forwardRules = getDatabaseTableDefs().find((table) => table.name === "forward_rules")!;
  assert.deepEqual(forwardRules.columns.find((column) => column.name === "xrayQuickConfigId"), c("xrayQuickConfigId", "int"));
  assert.equal(forwardRules.indexes?.some((columns) => columns.length === 1 && columns[0] === "xrayQuickConfigId"), true);
});

test("Drizzle exposes matching quick-config and global-port tables for all three dialects", async () => {
  const previousDatabaseType = process.env.DATABASE_TYPE;
  const exportNames = [
    "xrayQuickConfigs", "xrayQuickConfigDomainClaims", "xrayQuickConfigTopologyRevisions",
    "xrayQuickConfigRoutes", "xrayQuickConfigRuleBindings", "xrayQuickConfigDnsRecords",
    "xrayQuickConfigDnsRecordBackups", "xrayQuickConfigOperations", "xrayQuickConfigOperationSteps",
    "globalPortAllocations", "globalPortAllocationReferences", "globalPortProbeRuns",
    "globalPortProbeResults", "globalPortScanLeases",
  ];
  const dialects = [
    {
      name: "sqlite",
      config: getSqliteTableConfig as (table: any) => any,
      sqlType: (column: ColumnDef) => column.type === "text" || column.type === "longtext" || column.type === "varchar"
        ? "text" : "integer",
    },
    {
      name: "mysql",
      config: getMysqlTableConfig as (table: any) => any,
      sqlType: (column: ColumnDef) => column.type === "id" ? "serial"
        : column.type === "varchar" ? `varchar(${column.length || 191})`
          : column.type === "int" || column.type === "epoch" ? "int"
            : column.type === "bool" ? "boolean"
            : column.type,
    },
    {
      name: "postgresql",
      config: getPgTableConfig as (table: any) => any,
      sqlType: (column: ColumnDef) => column.type === "id" ? "bigserial"
        : column.type === "varchar" ? `varchar(${column.length || 191})`
          : column.type === "int" ? "integer"
            : column.type === "epoch" ? "int"
              : column.type === "longtext" ? "text"
                : column.type === "bool" ? "boolean" : column.type,
    },
  ] as const;

  try {
    for (const dialect of dialects) {
      process.env.DATABASE_TYPE = dialect.name;
      const schemaUrl = `${pathToFileURL(`${process.cwd()}/drizzle/schema.ts`).href}?quick-config-schema=${dialect.name}-${Date.now()}`;
      const schema = await import(schemaUrl) as Record<string, any>;
      for (const [index, expected] of expectedTables.entries()) {
        const config = dialect.config(schema[exportNames[index]]);
        assert.equal(config.name, expected.name);
        assert.deepEqual(config.columns.map((column: any) => column.name), expected.columns.map((column) => column.name));
        for (const expectedColumn of expected.columns.filter((column) => column.type !== "id")) {
          const actualColumn = config.columns.find((column: any) => column.name === expectedColumn.name)!;
          assert.equal(actualColumn.notNull, expectedColumn.notNull === true, `${dialect.name}.${expected.name}.${expectedColumn.name} nullability`);
          assert.equal(actualColumn.hasDefault, expectedColumn.default !== undefined, `${dialect.name}.${expected.name}.${expectedColumn.name} default`);
          assert.equal(actualColumn.getSQLType(), dialect.sqlType(expectedColumn), `${dialect.name}.${expected.name}.${expectedColumn.name} SQL type`);
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

      const forwardRules = dialect.config(schema.forwardRules);
      assert.equal(forwardRules.columns.some((column: any) => column.name === "xrayQuickConfigId"), true);
      assert.equal(forwardRules.indexes.some((item: any) => item.config.columns.map((column: any) => column.name).join("|") === "xrayQuickConfigId"), true);
    }
  } finally {
    if (previousDatabaseType === undefined) delete process.env.DATABASE_TYPE;
    else process.env.DATABASE_TYPE = previousDatabaseType;
  }
});

test("SQLite creates the schema, nullable active slots, provider record ids, and fixed scan lease idempotently", async () => {
  const sqlite = new Database(":memory:");
  try {
    await ensureDatabaseSchema(sqlite);
    await ensureDatabaseSchema(sqlite);

    const leaseRows = sqlite.prepare("SELECT scopeKey, leaseOwnerHash, leaseUntil FROM global_port_scan_leases").all();
    assert.deepEqual(leaseRows, [{ scopeKey: PORT_RECLAIM_SCOPE, leaseOwnerHash: null, leaseUntil: null }]);
    sqlite.prepare("UPDATE global_port_scan_leases SET leaseOwnerHash = ?, leaseUntil = ? WHERE scopeKey = ?")
      .run("a".repeat(64), 1234, PORT_RECLAIM_SCOPE);
    await ensureDatabaseSchema(sqlite);
    assert.deepEqual(
      sqlite.prepare("SELECT scopeKey, leaseOwnerHash, leaseUntil FROM global_port_scan_leases").all(),
      [{ scopeKey: PORT_RECLAIM_SCOPE, leaseOwnerHash: "a".repeat(64), leaseUntil: 1234 }],
    );
    for (const table of expectedTables) {
      const row = sqlite.prepare("SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = ?")
        .get(table.name) as { present?: number } | undefined;
      assert.equal(row?.present, 1);
    }
    assert.equal(sqlite.prepare("PRAGMA table_info(forward_rules)").all().some((row: any) => row.name === "xrayQuickConfigId" && row.notnull === 0), true);

    sqlite.prepare(`INSERT INTO xray_quick_configs
      (configTag, targetType, targetVersion, dnsAccountId, zoneId, relativeName, fqdn, state, createdByUserId)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run("qc-a", "XRAY_INBOUND", "a".repeat(64), 1, 1, "edge", "edge.example.com", "APPLYING", 1);
    assert.throws(() => sqlite.prepare(`INSERT INTO xray_quick_configs
      (configTag, targetType, targetVersion, dnsAccountId, zoneId, relativeName, fqdn, state, createdByUserId)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run("qc-a", "XRAY_INBOUND", "b".repeat(64), 1, 1, "other", "other.example.com", "APPLYING", 1), /UNIQUE/);

    const topology = sqlite.prepare(`INSERT INTO xray_quick_config_topology_revisions
      (quickConfigId, revisionNumber, engine, targetAddress, targetPort, publicPort, portAllocationId, state, activeSlot, createdByUserId)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    topology.run(1, 1, "realm", "192.0.2.1", 443, 443, 1, "STAGED", null, 1);
    topology.run(1, 2, "realm", "192.0.2.1", 443, 443, 1, "STAGED", null, 1);
    topology.run(1, 3, "realm", "192.0.2.1", 443, 443, 1, "APPLIED", 1, 1);
    assert.throws(() => topology.run(1, 4, "realm", "192.0.2.1", 443, 443, 1, "APPLIED", 1, 1), /UNIQUE/);

    const dnsRecord = sqlite.prepare(`INSERT INTO xray_quick_config_dns_records
      (quickConfigId, routeId, dnsAccountId, zoneId, recordTag, providerRecordId, providerLineId, fqdn, recordType, value, ttl, status, appliedRevision, remoteTupleHash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    dnsRecord.run(1, 1, 1, 1, "record-a", null, "line-a", "edge.example.com", "A", "192.0.2.1", 600, "DESIRED", 1, "a".repeat(64));
    dnsRecord.run(1, 2, 1, 1, "record-b", null, "line-b", "edge.example.com", "AAAA", "2001:db8::1", 600, "DESIRED", 1, "b".repeat(64));

    sqlite.prepare(`INSERT INTO global_port_allocations (allocationTag, port, status) VALUES (?, ?, ?)`)
      .run("allocation-a", 33333, "ACTIVE");
    assert.throws(() => sqlite.prepare(`INSERT INTO global_port_allocations (allocationTag, port, status) VALUES (?, ?, ?)`)
      .run("allocation-b", 33333, "ACTIVE"), /UNIQUE/);
  } finally {
    sqlite.close();
  }
});

test("MySQL and PostgreSQL initialization emit the fixed scan lease seed", async () => {
  const mysqlQueries: Array<{ sql: string; params?: unknown[] }> = [];
  const mysqlPool = {
    getConnection() { throw new Error("not used"); },
    async query(sql: string, params?: unknown[]) { mysqlQueries.push({ sql, params }); return [[], []]; },
    async execute(sql: string, params?: unknown[]) { mysqlQueries.push({ sql, params }); return [[], []]; },
  };
  await ensureDatabaseSchema(mysqlPool as any);
  assert.equal(mysqlQueries.some(({ sql, params }) => sql.includes("INSERT INTO global_port_scan_leases") && params?.[0] === PORT_RECLAIM_SCOPE), true);

  const postgresQueries: Array<{ sql: string; params?: unknown[] }> = [];
  const postgresPool = {
    async query(sql: string, params?: unknown[]) { postgresQueries.push({ sql, params }); return { rows: [] }; },
  };
  await ensureDatabaseSchema(postgresPool as any);
  assert.equal(postgresQueries.some(({ sql, params }) => sql.includes('INSERT INTO "global_port_scan_leases"') && params?.[0] === PORT_RECLAIM_SCOPE), true);
});
