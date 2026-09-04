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

const xrayTableNames = [
  "xray_inbounds",
  "xray_external_proxy_nodes",
  "xray_external_proxy_secrets",
  "xray_clients",
  "xray_access_entries",
  "xray_access_secrets",
  "xray_inbound_secrets",
  "xray_tls_certificates",
  "xray_host_deployments",
  "xray_runtime_reports",
  "xray_artifacts",
  "xray_operations",
  "xray_managed_services",
  "xray_managed_service_instance_secrets",
  "xray_managed_service_accounts",
  "xray_managed_service_secrets",
  "xray_managed_service_deployments",
  "xray_managed_service_runtime_reports",
  "xray_managed_service_artifacts",
] as const;

const c = (name: string, type: ColumnDef["type"], options: Omit<ColumnDef, "name" | "type"> = {}): ColumnDef => ({
  name,
  type,
  ...options,
});

const expectedTables: TableDef[] = [
  {
    name: "xray_inbounds",
    columns: [
      c("id", "id"), c("hostId", "int", { notNull: true }), c("name", "text", { notNull: true }),
      c("runtimeTag", "varchar", { length: 128, notNull: true }), c("publicAddress", "text", { notNull: true }),
      c("listenAddress", "varchar", { length: 64, notNull: true, default: "0.0.0.0" }), c("listenPort", "int", { notNull: true }),
      c("protocol", "varchar", { length: 32, notNull: true, default: "vless" }), c("transport", "varchar", { length: 32, notNull: true, default: "tcp" }),
      c("security", "varchar", { length: 32, notNull: true, default: "reality" }), c("profileId", "varchar", { length: 128 }),
      c("specVersion", "int"), c("specJson", "text"), c("tlsCertificateId", "int"), c("externalProxyNodeId", "int"),
      c("realityTargetHost", "text", { notNull: true }),
      c("realityTargetPort", "int", { notNull: true, default: 443 }), c("realityServerName", "text", { notNull: true }),
      c("realityPublicKey", "text", { notNull: true }), c("realityPrivateKeyEncrypted", "text", { notNull: true }),
      c("secretKeyVersion", "int", { notNull: true, default: 1 }), c("fingerprint", "varchar", { length: 32, notNull: true, default: "chrome" }),
      c("spiderX", "varchar", { length: 256, notNull: true, default: "/" }), c("isEnabled", "bool", { notNull: true, default: true }),
      c("pendingDelete", "bool", { notNull: true, default: false }), c("desiredGeneration", "bigint", { notNull: true, default: 0 }),
      c("createdByUserId", "int", { notNull: true }), c("createdAt", "epoch", { notNull: true, default: "now" }),
      c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["runtimeTag"], ["hostId", "transport", "listenPort"]],
    indexes: [["hostId", "pendingDelete", "isEnabled"], ["hostId", "desiredGeneration"], ["createdByUserId", "createdAt"], ["externalProxyNodeId"]],
  },
  {
    name: "xray_external_proxy_nodes",
    columns: [
      c("id", "id"), c("name", "text", { notNull: true }), c("nodeTag", "varchar", { length: 128, notNull: true }),
      c("protocol", "varchar", { length: 32, notNull: true }), c("address", "text", { notNull: true }),
      c("port", "int", { notNull: true }), c("specVersion", "int", { notNull: true, default: 1 }),
      c("specJson", "text", { notNull: true }), c("createdByUserId", "int", { notNull: true }),
      c("createdAt", "epoch", { notNull: true, default: "now" }), c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["nodeTag"]],
    indexes: [["protocol", "updatedAt"], ["createdByUserId", "createdAt"]],
  },
  {
    name: "xray_external_proxy_secrets",
    columns: [
      c("id", "id"), c("externalProxyNodeId", "int", { notNull: true }), c("kind", "varchar", { length: 32, notNull: true }),
      c("encryptedValue", "text", { notNull: true }), c("fingerprint", "varchar", { length: 64, notNull: true }),
      c("keyVersion", "int", { notNull: true }), c("createdAt", "epoch", { notNull: true, default: "now" }),
      c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["externalProxyNodeId", "kind"]],
    indexes: [["kind", "fingerprint"]],
  },
  {
    name: "xray_clients",
    columns: [
      c("id", "id"), c("inboundId", "int", { notNull: true }), c("name", "text", { notNull: true }),
      c("uuidEncrypted", "text", { notNull: true }), c("uuidFingerprint", "varchar", { length: 64, notNull: true }),
      c("shortIdEncrypted", "text", { notNull: true }), c("shortIdFingerprint", "varchar", { length: 64, notNull: true }),
      c("statsKey", "varchar", { length: 128, notNull: true }), c("flow", "varchar", { length: 64, notNull: true, default: "xtls-rprx-vision" }),
      c("ownerUserId", "int"), c("isEnabled", "bool", { notNull: true, default: true }),
      c("pendingDelete", "bool", { notNull: true, default: false }), c("desiredGeneration", "bigint", { notNull: true, default: 0 }),
      c("sortOrder", "int", { notNull: true, default: 0 }), c("createdAt", "epoch", { notNull: true, default: "now" }),
      c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["uuidFingerprint"], ["statsKey"], ["inboundId", "shortIdFingerprint"]],
    indexes: [["inboundId", "pendingDelete", "isEnabled", "sortOrder"], ["ownerUserId", "createdAt"]],
  },
  {
    name: "xray_access_entries",
    columns: [
      c("id", "id"), c("inboundId", "int", { notNull: true }), c("legacyClientId", "int"),
      c("name", "text", { notNull: true }), c("credentialType", "varchar", { length: 32, notNull: true }),
      c("settingsJson", "text", { notNull: true }), c("statsKey", "varchar", { length: 128, notNull: true }),
      c("ownerUserId", "int"), c("isEnabled", "bool", { notNull: true, default: true }),
      c("pendingDelete", "bool", { notNull: true, default: false }), c("desiredGeneration", "bigint", { notNull: true, default: 0 }),
      c("sortOrder", "int", { notNull: true, default: 0 }), c("createdAt", "epoch", { notNull: true, default: "now" }),
      c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["legacyClientId"], ["statsKey"]],
    indexes: [["inboundId", "pendingDelete", "isEnabled", "sortOrder"], ["ownerUserId", "createdAt"]],
  },
  {
    name: "xray_access_secrets",
    columns: [
      c("id", "id"), c("accessEntryId", "int", { notNull: true }), c("kind", "varchar", { length: 32, notNull: true }),
      c("encryptedValue", "text", { notNull: true }), c("fingerprint", "varchar", { length: 64, notNull: true }),
      c("keyVersion", "int", { notNull: true }), c("createdAt", "epoch", { notNull: true, default: "now" }),
      c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["accessEntryId", "kind"]],
    indexes: [["kind", "fingerprint"]],
  },
  {
    name: "xray_inbound_secrets",
    columns: [
      c("id", "id"), c("inboundId", "int", { notNull: true }), c("kind", "varchar", { length: 32, notNull: true }),
      c("encryptedValue", "text", { notNull: true }), c("fingerprint", "varchar", { length: 64, notNull: true }),
      c("keyVersion", "int", { notNull: true }), c("createdAt", "epoch", { notNull: true, default: "now" }),
      c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["inboundId", "kind"]],
    indexes: [["kind", "fingerprint"]],
  },
  {
    name: "xray_tls_certificates",
    columns: [
      c("id", "id"), c("hostId", "int", { notNull: true }), c("name", "text", { notNull: true }),
      c("certificateTag", "varchar", { length: 128, notNull: true }), c("certificateChainPem", "text", { notNull: true }),
      c("privateKeyEncrypted", "text", { notNull: true }), c("privateKeyFingerprint", "varchar", { length: 64, notNull: true }),
      c("keyVersion", "int", { notNull: true }), c("leafFingerprintSha256", "varchar", { length: 64, notNull: true }),
      c("dnsNamesJson", "text", { notNull: true }), c("subject", "text", { notNull: true }), c("issuer", "text", { notNull: true }),
      c("serialNumber", "varchar", { length: 128, notNull: true }), c("notBefore", "epoch", { notNull: true }),
      c("notAfter", "epoch", { notNull: true }), c("keyAlgorithm", "varchar", { length: 32, notNull: true }),
      c("createdByUserId", "int", { notNull: true }), c("createdAt", "epoch", { notNull: true, default: "now" }),
      c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["certificateTag"]],
    indexes: [["hostId", "name"], ["hostId", "notAfter"], ["privateKeyFingerprint"], ["leafFingerprintSha256"]],
  },
  {
    name: "xray_host_deployments",
    columns: [
      c("id", "id"), c("hostId", "int", { notNull: true }), c("targetVersion", "varchar", { length: 64 }),
      c("desiredGeneration", "bigint", { notNull: true, default: 0 }), c("desiredConfigHash", "varchar", { length: 64 }),
      c("lastOperationId", "varchar", { length: 64 }), c("createdAt", "epoch", { notNull: true, default: "now" }),
      c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["hostId"]],
    indexes: [["lastOperationId"]],
  },
  {
    name: "xray_runtime_reports",
    columns: [
      c("id", "id"), c("hostId", "int", { notNull: true }), c("capabilitySchemaVersion", "int", { notNull: true, default: 0 }),
      c("supportedOS", "varchar", { length: 32 }), c("supportedArch", "varchar", { length: 32 }),
      c("supportsArtifactInstall", "bool", { notNull: true, default: false }), c("supportsPortProbe", "bool", { notNull: true, default: false }),
      c("supportsUdpPortProbe", "bool", { notNull: true, default: false }), c("supportsUdpListenerReadiness", "bool", { notNull: true, default: false }),
      c("supportsRealityScan", "bool", { notNull: true, default: false }), c("capabilityErrorCode", "varchar", { length: 64 }),
      c("isInstalled", "bool", { notNull: true, default: false }), c("installedVersion", "varchar", { length: 64 }),
      c("runningVersion", "varchar", { length: 64 }), c("serviceStatus", "varchar", { length: 32, notNull: true, default: "UNKNOWN" }),
      c("processId", "int"), c("appliedGeneration", "bigint", { notNull: true, default: 0 }), c("appliedConfigHash", "varchar", { length: 64 }),
      c("binarySha256", "varchar", { length: 64 }), c("listenersJson", "text"), c("reportSignature", "varchar", { length: 64 }),
      c("lastErrorCode", "varchar", { length: 64 }), c("lastErrorMessage", "text"), c("reportedAt", "epoch"),
      c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["hostId"]],
    indexes: [["reportedAt"]],
  },
  {
    name: "xray_artifacts",
    columns: [
      c("id", "id"), c("version", "varchar", { length: 64, notNull: true }), c("os", "varchar", { length: 32, notNull: true }),
      c("arch", "varchar", { length: 32, notNull: true }), c("packageFormat", "varchar", { length: 16, notNull: true }),
      c("storageKey", "text", { notNull: true }), c("sha256", "varchar", { length: 64, notNull: true }), c("fileSize", "bigint", { notNull: true }),
      c("status", "varchar", { length: 32, notNull: true, default: "CACHED" }), c("source", "text"), c("verifiedAt", "epoch"),
      c("createdAt", "epoch", { notNull: true, default: "now" }), c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["version", "os", "arch"]],
    indexes: [["version", "status"], ["updatedAt"]],
  },
  {
    name: "xray_operations",
    columns: [
      c("id", "id"), c("operationId", "varchar", { length: 64, notNull: true }), c("hostId", "int", { notNull: true }),
      c("inboundId", "int"), c("type", "varchar", { length: 32, notNull: true }), c("requestedGeneration", "bigint"),
      c("status", "varchar", { length: 32, notNull: true, default: "QUEUED" }), c("requestMetaJson", "text"), c("resultJson", "text"),
      c("errorCode", "varchar", { length: 64 }), c("errorMessage", "text"), c("attemptCount", "int", { notNull: true, default: 0 }),
      c("createdByUserId", "int", { notNull: true }), c("createdAt", "epoch", { notNull: true, default: "now" }), c("startedAt", "epoch"),
      c("finishedAt", "epoch"), c("expiresAt", "epoch"), c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["operationId"]],
    indexes: [["hostId", "status", "createdAt"], ["type", "status", "createdAt"], ["inboundId", "createdAt"], ["expiresAt"], ["updatedAt"]],
  },
  {
    name: "xray_managed_services",
    columns: [
      c("id", "id"), c("hostId", "int", { notNull: true }), c("name", "text", { notNull: true }),
      c("serviceTag", "varchar", { length: 128, notNull: true }), c("kind", "varchar", { length: 64, notNull: true }),
      c("publicAddress", "text", { notNull: true }), c("listenAddress", "varchar", { length: 64, notNull: true, default: "0.0.0.0" }),
      c("listenPort", "int", { notNull: true }), c("specVersion", "int", { notNull: true, default: 1 }),
      c("specJson", "text", { notNull: true }), c("targetVersion", "varchar", { length: 64, notNull: true }),
      c("isEnabled", "bool", { notNull: true, default: true }), c("pendingDelete", "bool", { notNull: true, default: false }),
      c("desiredGeneration", "bigint", { notNull: true, default: 0 }), c("createdByUserId", "int", { notNull: true }),
      c("createdAt", "epoch", { notNull: true, default: "now" }), c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["serviceTag"], ["hostId", "kind", "listenPort"]],
    indexes: [["hostId", "pendingDelete", "isEnabled"], ["createdByUserId", "createdAt"]],
  },
  {
    name: "xray_managed_service_instance_secrets",
    columns: [
      c("id", "id"), c("serviceId", "int", { notNull: true }), c("kind", "varchar", { length: 32, notNull: true }),
      c("encryptedValue", "text", { notNull: true }), c("fingerprint", "varchar", { length: 64, notNull: true }),
      c("keyVersion", "int", { notNull: true }), c("createdAt", "epoch", { notNull: true, default: "now" }),
      c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["serviceId", "kind"]],
    indexes: [["kind", "fingerprint"]],
  },
  {
    name: "xray_managed_service_accounts",
    columns: [
      c("id", "id"), c("serviceId", "int", { notNull: true }), c("name", "text", { notNull: true }),
      c("accountTag", "varchar", { length: 128, notNull: true }), c("settingsVersion", "int", { notNull: true, default: 1 }),
      c("settingsJson", "text", { notNull: true, default: "{}" }), c("isEnabled", "bool", { notNull: true, default: true }),
      c("pendingDelete", "bool", { notNull: true, default: false }), c("desiredGeneration", "bigint", { notNull: true, default: 0 }),
      c("sortOrder", "int", { notNull: true, default: 0 }), c("createdAt", "epoch", { notNull: true, default: "now" }),
      c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["accountTag"]],
    indexes: [["serviceId", "pendingDelete", "isEnabled", "sortOrder"]],
  },
  {
    name: "xray_managed_service_secrets",
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
    name: "xray_managed_service_deployments",
    columns: [
      c("id", "id"), c("hostId", "int", { notNull: true }), c("targetVersion", "varchar", { length: 64 }),
      c("desiredGeneration", "bigint", { notNull: true, default: 0 }), c("desiredConfigHash", "varchar", { length: 64 }),
      c("createdAt", "epoch", { notNull: true, default: "now" }), c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["hostId"]],
  },
  {
    name: "xray_managed_service_runtime_reports",
    columns: [
      c("id", "id"), c("hostId", "int", { notNull: true }), c("capabilityJson", "text"), c("stateJson", "text"),
      c("stateSignature", "varchar", { length: 64 }), c("reportedAt", "epoch"),
      c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["hostId"]],
    indexes: [["reportedAt"]],
  },
  {
    name: "xray_managed_service_artifacts",
    columns: [
      c("id", "id"), c("kind", "varchar", { length: 64, notNull: true }), c("version", "varchar", { length: 64, notNull: true }),
      c("os", "varchar", { length: 32, notNull: true }), c("arch", "varchar", { length: 32, notNull: true }),
      c("packageFormat", "varchar", { length: 16, notNull: true }), c("storageKey", "text", { notNull: true }),
      c("sha256", "varchar", { length: 64, notNull: true }), c("fileSize", "bigint", { notNull: true }),
      c("status", "varchar", { length: 32, notNull: true, default: "CACHED" }), c("source", "text"), c("verifiedAt", "epoch"),
      c("createdAt", "epoch", { notNull: true, default: "now" }), c("updatedAt", "epoch", { notNull: true, default: "now" }),
    ],
    unique: [["kind", "version", "os", "arch"]],
    indexes: [["kind", "version", "status"], ["updatedAt"]],
  },
];

function expectedIndexName(table: TableDef, columns: string[], unique: boolean) {
  return `${unique ? "uniq" : "idx"}_${table.name}_${columns.join("_")}`.slice(0, 60);
}

function sqliteIndexes(database: Database.Database, tableName: string) {
  const indexes = database.prepare(`PRAGMA index_list("${tableName}")`).all() as Array<{ name: string; unique: number }>;
  return indexes.map((entry) => ({
    name: entry.name,
    unique: entry.unique === 1,
    columns: (database.prepare(`PRAGMA index_info("${entry.name}")`).all() as Array<{ name: string }>).map((column) => column.name),
  }));
}

test("runtime schema descriptors exactly match the approved Xray tables", () => {
  assert.deepEqual(MIGRATION_TABLES.filter((name) => name.startsWith("xray_")), xrayTableNames);
  const actual = getDatabaseTableDefs().filter((table) => table.name.startsWith("xray_"));
  assert.deepEqual(actual, expectedTables);
});

test("panel migration module accepts every runtime schema table at startup", async () => {
  await import("./migration");
});

test("SQLite Xray schema is idempotent and creates every approved unique constraint and index", async () => {
  const sqlite = new Database(":memory:");
  try {
    await ensureDatabaseSchema(sqlite);
    await ensureDatabaseSchema(sqlite);

    for (const table of expectedTables) {
      const columns = sqlite.prepare(`PRAGMA table_info("${table.name}")`).all() as Array<{ name: string; notnull: number; pk: number }>;
      assert.deepEqual(columns.map((column) => column.name), table.columns.map((column) => column.name));
      assert.equal(columns[0].pk, 1);
      assert.deepEqual(columns.map((column) => column.notnull === 1), table.columns.map((column) => column.notNull === true));

      const indexes = sqliteIndexes(sqlite, table.name);
      for (const [unique, groups] of [[false, table.indexes || []], [true, table.unique || []]] as const) {
        for (const group of groups) {
          const name = expectedIndexName(table, group, unique);
          assert.deepEqual(indexes.find((index) => index.name === name), { name, unique, columns: group });
        }
      }
    }

    const indexedSecretColumns = expectedTables.flatMap((table) => sqliteIndexes(sqlite, table.name))
      .flatMap((index) => index.columns)
      .filter((name) => name.toLowerCase().includes("encrypted"));
    assert.deepEqual(indexedSecretColumns, []);

    const inbound = sqlite.prepare(`INSERT INTO xray_inbounds
      (hostId, name, runtimeTag, publicAddress, listenPort, realityTargetHost, realityServerName, realityPublicKey, realityPrivateKeyEncrypted, createdByUserId)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    inbound.run(1, "primary", "inbound-a", "203.0.113.1", 24443, "example.com", "example.com", "public", "encrypted", 1);
    assert.throws(() => inbound.run(2, "duplicate-tag", "inbound-a", "203.0.113.2", 24444, "example.com", "example.com", "public", "encrypted", 1), /UNIQUE/);
    assert.throws(() => inbound.run(1, "duplicate-port", "inbound-b", "203.0.113.1", 24443, "example.com", "example.com", "public", "encrypted", 1), /UNIQUE/);

    const client = sqlite.prepare(`INSERT INTO xray_clients
      (inboundId, name, uuidEncrypted, uuidFingerprint, shortIdEncrypted, shortIdFingerprint, statsKey)
      VALUES (?, ?, ?, ?, ?, ?, ?)`);
    client.run(1, "client-a", "uuid-enc-a", "uuid-fp-a", "short-enc-a", "short-fp-a", "stats-a");
    assert.throws(() => client.run(1, "uuid-duplicate", "uuid-enc-b", "uuid-fp-a", "short-enc-b", "short-fp-b", "stats-b"), /UNIQUE/);
    assert.throws(() => client.run(1, "stats-duplicate", "uuid-enc-c", "uuid-fp-c", "short-enc-c", "short-fp-c", "stats-a"), /UNIQUE/);
    assert.throws(() => client.run(1, "short-duplicate", "uuid-enc-d", "uuid-fp-d", "short-enc-d", "short-fp-a", "stats-d"), /UNIQUE/);

    const access = sqlite.prepare(`INSERT INTO xray_access_entries
      (inboundId, legacyClientId, name, credentialType, settingsJson, statsKey)
      VALUES (?, ?, ?, ?, ?, ?)`);
    access.run(1, 1, "access-a", "UUID", "{}", "access-stats-a");
    access.run(1, null, "access-b", "PASSWORD", "{}", "access-stats-b");
    access.run(1, null, "access-c", "PASSWORD", "{}", "access-stats-c");
    assert.throws(() => access.run(1, 1, "legacy-duplicate", "UUID", "{}", "access-stats-d"), /UNIQUE/);
    assert.throws(() => access.run(1, null, "stats-duplicate", "UUID", "{}", "access-stats-a"), /UNIQUE/);

    const accessSecret = sqlite.prepare(`INSERT INTO xray_access_secrets
      (accessEntryId, kind, encryptedValue, fingerprint, keyVersion) VALUES (?, ?, ?, ?, ?)`);
    accessSecret.run(1, "UUID", "encrypted-a", "fingerprint-a", 1);
    accessSecret.run(2, "UUID", "encrypted-b", "fingerprint-a", 1);
    assert.throws(() => accessSecret.run(1, "UUID", "encrypted-c", "fingerprint-c", 1), /UNIQUE/);

    const inboundSecret = sqlite.prepare(`INSERT INTO xray_inbound_secrets
      (inboundId, kind, encryptedValue, fingerprint, keyVersion) VALUES (?, ?, ?, ?, ?)`);
    inboundSecret.run(1, "PRIVATE_KEY", "encrypted-a", "fingerprint-a", 1);
    inboundSecret.run(2, "PRIVATE_KEY", "encrypted-b", "fingerprint-a", 1);
    assert.throws(() => inboundSecret.run(1, "PRIVATE_KEY", "encrypted-c", "fingerprint-c", 1), /UNIQUE/);

    const certificate = sqlite.prepare(`INSERT INTO xray_tls_certificates
      (hostId, name, certificateTag, certificateChainPem, privateKeyEncrypted, privateKeyFingerprint,
       keyVersion, leafFingerprintSha256, dnsNamesJson, subject, issuer, serialNumber, notBefore, notAfter,
       keyAlgorithm, createdByUserId)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    certificate.run(1, "example.com", "forwardx-cert-a", "certificate", "encrypted", "a".repeat(64), 1,
      "b".repeat(64), '["example.com"]', "CN=example.com", "CN=issuer", "01", 1, 2, "RSA_2048_4096", 1);
    assert.throws(() => certificate.run(1, "duplicate", "forwardx-cert-a", "certificate", "encrypted", "c".repeat(64), 1,
      "d".repeat(64), '["example.org"]', "CN=example.org", "CN=issuer", "02", 1, 2, "RSA_2048_4096", 1), /UNIQUE/);

    sqlite.prepare("INSERT INTO xray_host_deployments (hostId) VALUES (?)").run(1);
    assert.throws(() => sqlite.prepare("INSERT INTO xray_host_deployments (hostId) VALUES (?)").run(1), /UNIQUE/);
    sqlite.prepare("INSERT INTO xray_runtime_reports (hostId) VALUES (?)").run(1);
    assert.throws(() => sqlite.prepare("INSERT INTO xray_runtime_reports (hostId) VALUES (?)").run(1), /UNIQUE/);

    const artifact = sqlite.prepare(`INSERT INTO xray_artifacts
      (version, os, arch, packageFormat, storageKey, sha256, fileSize) VALUES (?, ?, ?, ?, ?, ?, ?)`);
    artifact.run("v26.7.28", "linux", "amd64", "zip", "xray/v26.7.28/linux-amd64.zip", "a".repeat(64), 1);
    assert.throws(() => artifact.run("v26.7.28", "linux", "amd64", "zip", "other", "b".repeat(64), 2), /UNIQUE/);

    const operation = sqlite.prepare("INSERT INTO xray_operations (operationId, hostId, type, createdByUserId) VALUES (?, ?, ?, ?)");
    operation.run("operation-a", 1, "SYNC", 1);
    assert.throws(() => operation.run("operation-a", 2, "SYNC", 1), /UNIQUE/);
  } finally {
    sqlite.close();
  }
});

test("existing Xray runtime report tables gain capability projection columns safely", async () => {
  const sqlite = new Database(":memory:");
  try {
    sqlite.exec('CREATE TABLE xray_runtime_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, hostId INTEGER NOT NULL, capabilitySchemaVersion INTEGER NOT NULL DEFAULT 0)');
    sqlite.prepare("INSERT INTO xray_runtime_reports (hostId) VALUES (?)").run(7);
    await ensureDatabaseSchema(sqlite);
    await ensureDatabaseSchema(sqlite);
    const [row] = sqlite.prepare("SELECT supportedOS, supportedArch, supportsArtifactInstall, supportsPortProbe, supportsRealityScan, capabilityErrorCode FROM xray_runtime_reports WHERE hostId = 7").all() as any[];
    assert.deepEqual(row, {
      supportedOS: null,
      supportedArch: null,
      supportsArtifactInstall: 0,
      supportsPortProbe: 0,
      supportsRealityScan: 0,
      capabilityErrorCode: null,
    });
  } finally {
    sqlite.close();
  }
});

test("existing Xray inbound rows gain nullable profile storage without rewriting legacy data", async () => {
  const sqlite = new Database(":memory:");
  try {
    sqlite.exec(`CREATE TABLE xray_inbounds (
      id INTEGER PRIMARY KEY AUTOINCREMENT, hostId INTEGER NOT NULL, name TEXT NOT NULL,
      runtimeTag TEXT NOT NULL, publicAddress TEXT NOT NULL, listenAddress TEXT NOT NULL DEFAULT '0.0.0.0',
      listenPort INTEGER NOT NULL, protocol TEXT NOT NULL DEFAULT 'vless', transport TEXT NOT NULL DEFAULT 'tcp',
      security TEXT NOT NULL DEFAULT 'reality', realityTargetHost TEXT NOT NULL, realityTargetPort INTEGER NOT NULL DEFAULT 443,
      realityServerName TEXT NOT NULL, realityPublicKey TEXT NOT NULL, realityPrivateKeyEncrypted TEXT NOT NULL,
      secretKeyVersion INTEGER NOT NULL DEFAULT 1, fingerprint TEXT NOT NULL DEFAULT 'chrome', spiderX TEXT NOT NULL DEFAULT '/',
      isEnabled INTEGER NOT NULL DEFAULT 1, pendingDelete INTEGER NOT NULL DEFAULT 0, desiredGeneration INTEGER NOT NULL DEFAULT 0,
      createdByUserId INTEGER NOT NULL, createdAt INTEGER NOT NULL DEFAULT (unixepoch()), updatedAt INTEGER NOT NULL DEFAULT (unixepoch())
    )`);
    sqlite.prepare(`INSERT INTO xray_inbounds
      (hostId, name, runtimeTag, publicAddress, listenPort, realityTargetHost, realityServerName, realityPublicKey, realityPrivateKeyEncrypted, createdByUserId)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(7, "legacy", "legacy-runtime", "203.0.113.7", 24443, "example.com", "example.com", "public", "encrypted", 1);

    await ensureDatabaseSchema(sqlite);
    await ensureDatabaseSchema(sqlite);

    const columns = sqlite.prepare('PRAGMA table_info("xray_inbounds")').all() as Array<{ name: string; notnull: number }>;
    assert.deepEqual(columns
      .filter((column) => ["profileId", "specVersion", "specJson", "tlsCertificateId", "externalProxyNodeId"].includes(column.name))
      .map(({ name, notnull }) => ({ name, notnull })), [
      { name: "profileId", notnull: 0 },
      { name: "specVersion", notnull: 0 },
      { name: "specJson", notnull: 0 },
      { name: "tlsCertificateId", notnull: 0 },
      { name: "externalProxyNodeId", notnull: 0 },
    ]);
    assert.deepEqual(sqlite.prepare("SELECT name, realityPrivateKeyEncrypted, profileId, specVersion, specJson, tlsCertificateId, externalProxyNodeId FROM xray_inbounds WHERE hostId = 7").get(), {
      name: "legacy",
      realityPrivateKeyEncrypted: "encrypted",
      profileId: null,
      specVersion: null,
      specJson: null,
      tlsCertificateId: null,
      externalProxyNodeId: null,
    });
  } finally {
    sqlite.close();
  }
});

test("Drizzle tables match runtime semantics for SQLite, MySQL, and PostgreSQL", async () => {
  const previousDatabaseType = process.env.DATABASE_TYPE;
  try {
    const exportNames = [
      "xrayInbounds", "xrayExternalProxyNodes", "xrayExternalProxySecrets", "xrayClients", "xrayAccessEntries", "xrayAccessSecrets", "xrayInboundSecrets", "xrayTlsCertificates",
      "xrayHostDeployments", "xrayRuntimeReports", "xrayArtifacts", "xrayOperations",
      "xrayManagedServices", "xrayManagedServiceInstanceSecrets", "xrayManagedServiceAccounts", "xrayManagedServiceSecrets",
      "xrayManagedServiceDeployments", "xrayManagedServiceRuntimeReports", "xrayManagedServiceArtifacts",
    ];
    const dialects = [
      { name: "sqlite", config: getSqliteTableConfig as (table: any) => any },
      { name: "mysql", config: getMysqlTableConfig as (table: any) => any },
      { name: "postgresql", config: getPgTableConfig as (table: any) => any },
    ] as const;

    for (const dialect of dialects) {
      process.env.DATABASE_TYPE = dialect.name;
      const schemaUrl = `${pathToFileURL(`${process.cwd()}/drizzle/schema.ts`).href}?xray-schema=${dialect.name}-${Date.now()}`;
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

test("MySQL and PostgreSQL generators emit the Xray tables and their critical indexes", async () => {
  const mysqlQueries: string[] = [];
  const mysql = {
    getConnection() { throw new Error("not used"); },
    async query(sql: string) { mysqlQueries.push(sql); return [[], []]; },
    async execute() { return [[], []]; },
  };
  await ensureDatabaseSchema(mysql as any);
  assert.equal(xrayTableNames.every((name) => mysqlQueries.some((sql) => sql.startsWith(`CREATE TABLE IF NOT EXISTS \`${name}\``))), true);
  assert.equal(mysqlQueries.some((sql) => sql.includes("UNIQUE KEY `uniq_xray_inbounds_hostId_transport_listenPort`")), true);
  assert.equal(mysqlQueries.some((sql) => sql === "ALTER TABLE `xray_inbounds` MODIFY COLUMN `spiderX` VARCHAR(256) NOT NULL DEFAULT '/'"), true);
  assert.equal(mysqlQueries.some((sql) => sql === "ALTER TABLE `xray_inbounds` ADD COLUMN `profileId` VARCHAR(128)"), true);
  assert.equal(mysqlQueries.some((sql) => sql === "ALTER TABLE `xray_inbounds` ADD COLUMN `specVersion` INT"), true);
  assert.equal(mysqlQueries.some((sql) => sql === "ALTER TABLE `xray_inbounds` ADD COLUMN `specJson` TEXT"), true);
  assert.equal(mysqlQueries.some((sql) => sql === "ALTER TABLE `xray_inbounds` ADD COLUMN `tlsCertificateId` INT"), true);
  assert.equal(mysqlQueries.some((sql) => sql === "ALTER TABLE `xray_inbounds` ADD COLUMN `externalProxyNodeId` INT"), true);
  assert.equal(mysqlQueries.some((sql) => sql === "ALTER TABLE `forward_rules` ADD COLUMN `targetExternalProxyNodeId` INT"), true);
  assert.equal(mysqlQueries.some((sql) => sql === "ALTER TABLE `xray_runtime_reports` ADD COLUMN `supportsUdpPortProbe` BOOLEAN NOT NULL DEFAULT 0"), true);
  assert.equal(mysqlQueries.some((sql) => sql === "ALTER TABLE `xray_runtime_reports` ADD COLUMN `supportsUdpListenerReadiness` BOOLEAN NOT NULL DEFAULT 0"), true);
  assert.equal(mysqlQueries.some((sql) => sql.includes("UNIQUE KEY `uniq_xray_access_entries_legacyClientId`")), true);
  assert.equal(mysqlQueries.some((sql) => sql.includes("UNIQUE KEY `uniq_xray_tls_certificates_certificateTag`")), true);
  assert.equal(mysqlQueries.some((sql) => sql.includes("KEY `idx_xray_access_secrets_kind_fingerprint`")), true);
  assert.equal(mysqlQueries.some((sql) => sql.includes("UNIQUE KEY `uniq_xray_external_proxy_nodes_nodeTag`")), true);

  const postgresQueries: string[] = [];
  const postgres = { async query(sql: string) { postgresQueries.push(sql); return { rows: [] }; } };
  await ensureDatabaseSchema(postgres as any);
  assert.equal(xrayTableNames.every((name) => postgresQueries.some((sql) => sql.startsWith(`CREATE TABLE IF NOT EXISTS "${name}"`))), true);
  assert.equal(postgresQueries.some((sql) => sql.includes('CREATE UNIQUE INDEX IF NOT EXISTS "uniq_xray_clients_inboundId_shortIdFingerprint"')), true);
  assert.equal(postgresQueries.some((sql) => sql === 'ALTER TABLE "xray_runtime_reports" ADD COLUMN "supportsUdpPortProbe" BOOLEAN NOT NULL DEFAULT FALSE'), true);
  assert.equal(postgresQueries.some((sql) => sql === 'ALTER TABLE "xray_runtime_reports" ADD COLUMN "supportsUdpListenerReadiness" BOOLEAN NOT NULL DEFAULT FALSE'), true);
  assert.equal(postgresQueries.some((sql) => sql.includes('CREATE INDEX IF NOT EXISTS "idx_xray_operations_hostId_status_createdAt"')), true);
  assert.equal(mysqlQueries.some((sql) => sql.includes("KEY `idx_xray_artifacts_updatedAt`")), true);
  assert.equal(postgresQueries.some((sql) => sql.includes('CREATE INDEX IF NOT EXISTS "idx_xray_operations_updatedAt"')), true);
  assert.equal(postgresQueries.some((sql) => sql === 'ALTER TABLE "xray_inbounds" ADD COLUMN "profileId" VARCHAR(128)'), true);
  assert.equal(postgresQueries.some((sql) => sql === 'ALTER TABLE "xray_inbounds" ADD COLUMN "specVersion" INTEGER'), true);
  assert.equal(postgresQueries.some((sql) => sql === 'ALTER TABLE "xray_inbounds" ADD COLUMN "specJson" TEXT'), true);
  assert.equal(postgresQueries.some((sql) => sql === 'ALTER TABLE "xray_inbounds" ADD COLUMN "tlsCertificateId" INTEGER'), true);
  assert.equal(postgresQueries.some((sql) => sql === 'ALTER TABLE "xray_inbounds" ADD COLUMN "externalProxyNodeId" INTEGER'), true);
  assert.equal(postgresQueries.some((sql) => sql === 'ALTER TABLE "forward_rules" ADD COLUMN "targetExternalProxyNodeId" INTEGER'), true);
  assert.equal(postgresQueries.some((sql) => sql.includes('CREATE UNIQUE INDEX IF NOT EXISTS "uniq_xray_access_entries_legacyClientId"')), true);
  assert.equal(postgresQueries.some((sql) => sql.includes('CREATE UNIQUE INDEX IF NOT EXISTS "uniq_xray_tls_certificates_certificateTag"')), true);
  assert.equal(postgresQueries.some((sql) => sql.includes('CREATE INDEX IF NOT EXISTS "idx_xray_inbound_secrets_kind_fingerprint"')), true);
});
