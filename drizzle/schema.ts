import fs from "fs";
import path from "path";
import { sql } from "drizzle-orm";
import {
  bigint as mysqlBigint,
  boolean as mysqlBoolean,
  customType,
  index as mysqlIndex,
  int as mysqlInt,
  longtext as mysqlLongText,
  mysqlTable,
  serial as mysqlSerial,
  text as mysqlText,
  uniqueIndex as mysqlUniqueIndex,
  varchar as mysqlVarchar,
} from "drizzle-orm/mysql-core";
import {
  index as sqliteIndex,
  integer as sqliteInteger,
  sqliteTable,
  text as sqliteText,
  uniqueIndex as sqliteUniqueIndex,
} from "drizzle-orm/sqlite-core";
import {
  bigint as pgBigint,
  bigserial as pgBigSerial,
  boolean as pgBoolean,
  customType as pgCustomType,
  index as pgIndex,
  integer as pgInteger,
  pgTable,
  text as pgText,
  uniqueIndex as pgUniqueIndex,
  varchar as pgVarchar,
} from "drizzle-orm/pg-core";

/**
 * MySQL schema for ForwardX.
 *
 * Notes:
 * - Time fields are stored as Unix epoch seconds to keep compatibility with the
 *   existing API shape. Drizzle maps them to JS Date values for application code.
 * - Booleans are mapped by mysql-core boolean() so app code stays clean.
 * - All `id` fields are auto-incrementing primary keys.
 */

export type DatabaseDialect = "mysql" | "sqlite" | "postgresql";

function readConfiguredDialect(): DatabaseDialect {
  const explicit = (process.env.DATABASE_TYPE || process.env.DB_TYPE || "").toLowerCase();
  if (explicit === "sqlite" || explicit === "mysql" || explicit === "postgresql" || explicit === "postgres" || explicit === "pg") {
    return explicit === "postgres" || explicit === "pg" ? "postgresql" : explicit;
  }
  const candidates = [
    process.env.DATABASE_CONFIG_PATH || "",
    process.env.DB_CONFIG_PATH || "",
    "/data/database.json",
    path.resolve(process.cwd(), "data", "database.json"),
  ].filter(Boolean);
  for (const file of candidates) {
    try {
      if (!fs.existsSync(file)) continue;
      const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
      const type = String(parsed?.type || "").toLowerCase();
      if (type === "sqlite" || type === "mysql" || type === "postgresql" || type === "postgres" || type === "pg") {
        return type === "postgres" || type === "pg" ? "postgresql" : type;
      }
    } catch {
      // dbRuntime reports malformed config with a useful setup error.
    }
  }
  if (process.env.SQLITE_PATH && fs.existsSync(process.env.SQLITE_PATH)) return "sqlite";
  return "mysql";
}

export const SCHEMA_DIALECT: DatabaseDialect = readConfiguredDialect();
const isSqliteDialect = SCHEMA_DIALECT === "sqlite";
const isPostgresqlDialect = SCHEMA_DIALECT === "postgresql";

type SchemaIndexDef = Readonly<{ columns: readonly string[]; unique?: boolean }>;

function schemaIndexName(tableName: string, definition: SchemaIndexDef): string {
  return `${definition.unique ? "uniq" : "idx"}_${tableName}_${definition.columns.join("_")}`.slice(0, 60);
}

const table = (name: string, columns: any, indexDefinitions: readonly SchemaIndexDef[] = []): any => {
  if (indexDefinitions.length === 0) {
    return isSqliteDialect
      ? sqliteTable(name, columns)
      : isPostgresqlDialect
        ? pgTable(name, columns)
        : mysqlTable(name, columns);
  }
  const extraConfig = (builtColumns: Record<string, any>) => Object.fromEntries(indexDefinitions.map((definition) => {
    const selectedColumns = definition.columns.map((column) => builtColumns[column]);
    const indexBuilder = isSqliteDialect
      ? (definition.unique ? sqliteUniqueIndex : sqliteIndex)
      : isPostgresqlDialect
        ? (definition.unique ? pgUniqueIndex : pgIndex)
        : (definition.unique ? mysqlUniqueIndex : mysqlIndex);
    const indexName = schemaIndexName(name, definition);
    return [indexName, (indexBuilder as any)(indexName).on(...selectedColumns)];
  }));
  return isSqliteDialect
    ? sqliteTable(name, columns, extraConfig)
    : isPostgresqlDialect
      ? pgTable(name, columns, extraConfig)
      : mysqlTable(name, columns, extraConfig);
};
const serial = (name: string): any =>
  isSqliteDialect
    ? sqliteInteger(name).primaryKey({ autoIncrement: true })
    : isPostgresqlDialect
      ? pgBigSerial(name, { mode: "number" }).primaryKey()
      : mysqlSerial(name);
const text = (name: string): any => (isSqliteDialect ? sqliteText(name) : isPostgresqlDialect ? pgText(name) : mysqlText(name));
const longtext = (name: string): any => (isSqliteDialect ? sqliteText(name) : isPostgresqlDialect ? pgText(name) : mysqlLongText(name));
const varchar = (name: string, config: { length: number }): any =>
  isSqliteDialect ? sqliteText(name) : isPostgresqlDialect ? pgVarchar(name, config) : mysqlVarchar(name, config);
const int = (name: string): any => (isSqliteDialect ? sqliteInteger(name) : isPostgresqlDialect ? pgInteger(name) : mysqlInt(name));
const boolean = (name: string): any =>
  isSqliteDialect ? sqliteInteger(name, { mode: "boolean" }) : isPostgresqlDialect ? pgBoolean(name) : mysqlBoolean(name);
const bigint = (name: string, config?: { mode?: "number" }): any =>
  isSqliteDialect ? sqliteInteger(name) : isPostgresqlDialect ? pgBigint(name, config as any) : mysqlBigint(name, config as any);
const nowDefault = () => (isSqliteDialect ? sql`(unixepoch())` : isPostgresqlDialect ? sql`(EXTRACT(EPOCH FROM NOW())::INT)` : sql`(UNIX_TIMESTAMP())`);

const mysqlEpoch = customType<{ data: Date; driverData: number | string | null }>({
  dataType() {
    return "int";
  },
  fromDriver(value) {
    if (value === null || value === undefined || value === "") return null as any;
    const n = Number(value);
    if (!Number.isFinite(n) || n <= 0) return null as any;
    return new Date(n * 1000);
  },
  toDriver(value) {
    if (!value) return null;
    return Math.floor(value.getTime() / 1000);
  },
});

const postgresEpoch = pgCustomType<{ data: Date; driverData: number | string | null }>({
  dataType() {
    return "int";
  },
  fromDriver(value) {
    if (value === null || value === undefined || value === "") return null as any;
    const n = Number(value);
    if (!Number.isFinite(n) || n <= 0) return null as any;
    return new Date(n * 1000);
  },
  toDriver(value) {
    if (!value) return null;
    return Math.floor(value.getTime() / 1000);
  },
});

const epoch = (name: string): any =>
  isSqliteDialect
    ? sqliteInteger(name, { mode: "timestamp" })
    : isPostgresqlDialect
      ? postgresEpoch(name)
    : mysqlEpoch(name);

export const users = table("users", {
  id: serial("id"),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  name: text("name"),
  email: text("email"),
  emailVerified: boolean("emailVerified").notNull().default(false),
  emailVerifiedAt: epoch("emailVerifiedAt"),
  displayRemark: text("displayRemark"),
  avatar: text("avatar"),
  avatarChangeDay: varchar("avatarChangeDay", { length: 16 }),
  avatarChangeCount: int("avatarChangeCount").notNull().default(0),
  role: varchar("role", { length: 32 }).notNull().default("user"), // 'user' | 'admin'
  accountEnabled: boolean("accountEnabled").notNull().default(true),
  // ===== 权限控制 =====
  canAddRules: boolean("canAddRules").notNull().default(false), // 是否允许添加转发规则
  forwardAccessPauseReason: varchar("forwardAccessPauseReason", { length: 64 }),
  maxRules: int("maxRules").notNull().default(0),       // 最大规则条数，0 = 不限制
  maxPorts: int("maxPorts").notNull().default(0),       // 最大端口数，0 = 不限制（与 maxRules 相同概念，但可独立控制）
  // 允许使用的转发方式，逗号分隔，如 "iptables,realm,socat"；null 或空串 = 全部允许
  allowedForwardTypes: text("allowedForwardTypes"),
  allowForwardXTunnel: boolean("allowForwardXTunnel").notNull().default(false),
  gostRateLimitIn: int("gostRateLimitIn").notNull().default(0),
  gostRateLimitOut: int("gostRateLimitOut").notNull().default(0),
  maxConnections: int("maxConnections").notNull().default(0),
  maxIPs: int("maxIPs").notNull().default(0),
  manualCanAddRules: boolean("manualCanAddRules").notNull().default(false),
  manualMaxRules: int("manualMaxRules").notNull().default(0),
  manualMaxPorts: int("manualMaxPorts").notNull().default(0),
  manualMaxConnections: int("manualMaxConnections").notNull().default(0),
  manualMaxIPs: int("manualMaxIPs").notNull().default(0),
  manualAllowForwardXTunnel: boolean("manualAllowForwardXTunnel").notNull().default(false),
  manualGostRateLimitIn: int("manualGostRateLimitIn").notNull().default(0),
  manualGostRateLimitOut: int("manualGostRateLimitOut").notNull().default(0),
  manualTrafficLimit: bigint("manualTrafficLimit", { mode: "number" }).notNull().default(0),
  manualExpiresAt: epoch("manualExpiresAt"),
  balanceCents: bigint("balanceCents", { mode: "number" }).notNull().default(0),
  // ===== 流量管理字段 =====
  trafficLimit: bigint("trafficLimit", { mode: "number" }).notNull().default(0),           // 流量额度（字节），0 = 不限制
  trafficUsed: bigint("trafficUsed", { mode: "number" }).notNull().default(0),             // 已用流量（字节）
  // 按量计费统计的显示基线；不修改按量计费累计/结算表。
  trafficBillingResetBytes: bigint("trafficBillingResetBytes", { mode: "number" }).notNull().default(0),
  expiresAt: epoch("expiresAt"),               // 到期时间，null = 永不过期
  trafficAutoReset: boolean("trafficAutoReset").notNull().default(false), // 月度自动重置开关
  trafficResetDay: int("trafficResetDay").notNull().default(1),     // 每月重置日（1-28）
  lastTrafficReset: epoch("lastTrafficReset"), // 上次重置时间
  // Automatic billing cycles use an independent marker so a manual reset
  // cannot suppress the scheduled reset for the same month.
  lastAutoTrafficReset: epoch("lastAutoTrafficReset"),
  telegramId: text("telegramId").unique(),
  telegramUsername: text("telegramUsername"),
  telegramFirstName: text("telegramFirstName"),
  telegramLastName: text("telegramLastName"),
  telegramLinkedAt: epoch("telegramLinkedAt"),
  telegramLastSeenAt: epoch("telegramLastSeenAt"),
  telegramAnnouncementSubscribed: boolean("telegramAnnouncementSubscribed").notNull().default(false),
  telegramBindCode: text("telegramBindCode").unique(),
  telegramBindCodeExpiresAt: epoch("telegramBindCodeExpiresAt"),
  telegramLoginCode: text("telegramLoginCode").unique(),
  telegramLoginCodeExpiresAt: epoch("telegramLoginCodeExpiresAt"),
  twoFactorEnabled: boolean("twoFactorEnabled").notNull().default(false),
  twoFactorSecret: text("twoFactorSecret"),
  twoFactorEnabledAt: epoch("twoFactorEnabledAt"),
  browserSessionToken: text("browserSessionToken"),
  mobileSessionToken: text("mobileSessionToken"),
  telegramSessionToken: text("telegramSessionToken"),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
  lastSignedIn: epoch("lastSignedIn").notNull().default(nowDefault()),
});
export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

export const authSessions = table("auth_sessions", {
  id: serial("id"),
  sid: varchar("sid", { length: 80 }).notNull().unique(),
  userId: int("userId").notNull(),
  kind: varchar("kind", { length: 32 }).notNull().default("browser"),
  expiresAt: epoch("expiresAt").notNull(),
  revokedAt: epoch("revokedAt"),
  revokeReason: varchar("revokeReason", { length: 64 }),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  lastSeenAt: epoch("lastSeenAt").notNull().default(nowDefault()),
});
export type AuthSession = typeof authSessions.$inferSelect;
export type InsertAuthSession = typeof authSessions.$inferInsert;

export const hosts = table("hosts", {
  id: serial("id"),
  name: text("name").notNull(),
  ip: text("ip").notNull(),
  ipv4: text("ipv4"),
  ipv6: text("ipv6"),
  hostType: varchar("hostType", { length: 32 }).notNull().default("slave"), // 'master' | 'slave'
  agentToken: text("agentToken"),
  // 用户自定义的入口 IP/域名，为空时回退使用 ip
  entryIp: text("entryIp"),
  // 隧道链路使用的内网/专用入口地址（可选）
  tunnelEntryIp: text("tunnelEntryIp"),
  osInfo: text("osInfo"),
  cpuInfo: text("cpuInfo"),
  memoryTotal: bigint("memoryTotal", { mode: "number" }),
  agentVersion: text("agentVersion"),
  agentDistribution: varchar("agentDistribution", { length: 32 }),
  agentBuildId: varchar("agentBuildId", { length: 64 }),
  mimicAvailable: boolean("mimicAvailable"),
  mimicVersion: text("mimicVersion"),
  mimicStatus: varchar("mimicStatus", { length: 64 }),
  mimicMessage: text("mimicMessage"),
  mimicCheckedAt: epoch("mimicCheckedAt"),
  mimicRuntimeStatus: varchar("mimicRuntimeStatus", { length: 32 }),
  mimicRuntimeMessage: text("mimicRuntimeMessage"),
  mimicRuntimeCheckedAt: epoch("mimicRuntimeCheckedAt"),
  agentBootId: varchar("agentBootId", { length: 128 }),
  agentBootedAt: epoch("agentBootedAt"),
  agentProcessId: int("agentProcessId"),
  agentProcessStartedAt: epoch("agentProcessStartedAt"),
  agentLastReceivedRevision: bigint("agentLastReceivedRevision", { mode: "number" }).notNull().default(0),
  agentLastAppliedRevision: bigint("agentLastAppliedRevision", { mode: "number" }).notNull().default(0),
  agentLastReceivedHash: varchar("agentLastReceivedHash", { length: 64 }),
  agentLastAppliedHash: varchar("agentLastAppliedHash", { length: 64 }),
  agentRecoveryStartedAt: epoch("agentRecoveryStartedAt"),
  agentRecoveryCompletedAt: epoch("agentRecoveryCompletedAt"),
  agentRecoveryExpected: int("agentRecoveryExpected").notNull().default(0),
  agentRecoveryReady: int("agentRecoveryReady").notNull().default(0),
  agentUpgradeRequested: boolean("agentUpgradeRequested").notNull().default(false),
  agentUpgradeTargetVersion: text("agentUpgradeTargetVersion"),
  agentUpgradeTargetDistribution: varchar("agentUpgradeTargetDistribution", { length: 32 }),
  agentUpgradeReleaseVersion: text("agentUpgradeReleaseVersion"),
  agentUpgradeRequestedAt: epoch("agentUpgradeRequestedAt"),
  purchasedAt: epoch("purchasedAt"),
  stoppedAt: epoch("stoppedAt"),
  // Host billing calendar. The legacy stoppedAt value remains the source of
  // truth; these fields only control optional automatic cycle extension.
  billingCycleMonths: int("billingCycleMonths").notNull().default(1),
  billingMonth: int("billingMonth").notNull().default(1),
  billingDay: int("billingDay").notNull().default(1),
  expiryHandling: varchar("expiryHandling", { length: 24 }).notNull().default("none"),
  trafficLimit: bigint("trafficLimit", { mode: "number" }).notNull().default(0),
  trafficMeasureMode: varchar("trafficMeasureMode", { length: 16 }).notNull().default("both"),
  telegramTrafficAlertEnabled: boolean("telegramTrafficAlertEnabled").notNull().default(false),
  trafficAlertThresholdPercent: int("trafficAlertThresholdPercent").notNull().default(20),
  telegramRenewalReminderEnabled: boolean("telegramRenewalReminderEnabled").notNull().default(false),
  renewalReminderDays: int("renewalReminderDays").notNull().default(3),
  trafficAutoReset: boolean("trafficAutoReset").notNull().default(false),
  trafficResetDay: int("trafficResetDay").notNull().default(1),
  lastTrafficReset: epoch("lastTrafficReset"),
  ddnsEnabled: boolean("ddnsEnabled").notNull().default(false),
  ddnsDomain: text("ddnsDomain"),
  ddnsRecordType: varchar("ddnsRecordType", { length: 8 }).notNull().default("A"),
  ddnsIpVersion: varchar("ddnsIpVersion", { length: 8 }).notNull().default("ipv4"),
  lastDdnsValue: text("lastDdnsValue"),
  lastDdnsAt: epoch("lastDdnsAt"),
  lastDdnsError: text("lastDdnsError"),
  networkInterface: text("networkInterface"),
  sortOrder: int("sortOrder").notNull().default(0),
  geoCountryCode: varchar("geoCountryCode", { length: 8 }),
  geoCountryName: text("geoCountryName"),
  geoRegion: text("geoRegion"),
  geoEmoji: varchar("geoEmoji", { length: 16 }),
  geoLatitudeMicro: int("geoLatitudeMicro"),
  geoLongitudeMicro: int("geoLongitudeMicro"),
  geoUpdatedAt: epoch("geoUpdatedAt"),
  // ===== 端口区间限制 =====
  portRangeStart: int("portRangeStart"),  // 允许转发的起始端口，null = 不限制
  portRangeEnd: int("portRangeEnd"),      // 允许转发的结束端口，null = 不限制
  portAllowlist: text("portAllowlist"),    // 逗号分隔的额外允许端口
  blockHttp: boolean("blockHttp").notNull().default(false),
  blockSocks: boolean("blockSocks").notNull().default(false),
  blockTls: boolean("blockTls").notNull().default(false),
  isOnline: boolean("isOnline").notNull().default(false),
  lastHeartbeat: epoch("lastHeartbeat"),
  userId: int("userId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type Host = typeof hosts.$inferSelect;
export type InsertHost = typeof hosts.$inferInsert;

export const xrayInbounds = table("xray_inbounds", {
  id: serial("id"),
  hostId: int("hostId").notNull(),
  name: text("name").notNull(),
  runtimeTag: varchar("runtimeTag", { length: 128 }).notNull(),
  publicAddress: text("publicAddress").notNull(),
  listenAddress: varchar("listenAddress", { length: 64 }).notNull().default("0.0.0.0"),
  listenPort: int("listenPort").notNull(),
  protocol: varchar("protocol", { length: 32 }).notNull().default("vless"),
  transport: varchar("transport", { length: 32 }).notNull().default("tcp"),
  security: varchar("security", { length: 32 }).notNull().default("reality"),
  profileId: varchar("profileId", { length: 128 }),
  specVersion: int("specVersion"),
  specJson: text("specJson"),
  tlsCertificateId: int("tlsCertificateId"),
  externalProxyNodeId: int("externalProxyNodeId"),
  realityTargetHost: text("realityTargetHost").notNull(),
  realityTargetPort: int("realityTargetPort").notNull().default(443),
  realityServerName: text("realityServerName").notNull(),
  realityPublicKey: text("realityPublicKey").notNull(),
  realityPrivateKeyEncrypted: text("realityPrivateKeyEncrypted").notNull(),
  secretKeyVersion: int("secretKeyVersion").notNull().default(1),
  fingerprint: varchar("fingerprint", { length: 32 }).notNull().default("chrome"),
  spiderX: varchar("spiderX", { length: 256 }).notNull().default("/"),
  isEnabled: boolean("isEnabled").notNull().default(true),
  pendingDelete: boolean("pendingDelete").notNull().default(false),
  desiredGeneration: bigint("desiredGeneration", { mode: "number" }).notNull().default(0),
  createdByUserId: int("createdByUserId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["hostId", "pendingDelete", "isEnabled"] },
  { columns: ["hostId", "desiredGeneration"] },
  { columns: ["createdByUserId", "createdAt"] },
  { columns: ["externalProxyNodeId"] },
  { columns: ["runtimeTag"], unique: true },
  { columns: ["hostId", "transport", "listenPort"], unique: true },
]);
export type XrayInbound = typeof xrayInbounds.$inferSelect;
export type InsertXrayInbound = typeof xrayInbounds.$inferInsert;

export const xrayExternalProxyNodes = table("xray_external_proxy_nodes", {
  id: serial("id"),
  name: text("name").notNull(),
  nodeTag: varchar("nodeTag", { length: 128 }).notNull(),
  protocol: varchar("protocol", { length: 32 }).notNull(),
  address: text("address").notNull(),
  port: int("port").notNull(),
  specVersion: int("specVersion").notNull().default(1),
  specJson: text("specJson").notNull(),
  createdByUserId: int("createdByUserId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["protocol", "updatedAt"] },
  { columns: ["createdByUserId", "createdAt"] },
  { columns: ["nodeTag"], unique: true },
]);
export type XrayExternalProxyNode = typeof xrayExternalProxyNodes.$inferSelect;

export const xrayExternalProxySecrets = table("xray_external_proxy_secrets", {
  id: serial("id"),
  externalProxyNodeId: int("externalProxyNodeId").notNull(),
  kind: varchar("kind", { length: 32 }).notNull(),
  encryptedValue: text("encryptedValue").notNull(),
  fingerprint: varchar("fingerprint", { length: 64 }).notNull(),
  keyVersion: int("keyVersion").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["kind", "fingerprint"] },
  { columns: ["externalProxyNodeId", "kind"], unique: true },
]);
export type XrayExternalProxySecret = typeof xrayExternalProxySecrets.$inferSelect;

export const dnsProviderAccounts = table("dns_provider_accounts", {
  id: serial("id"),
  accountTag: varchar("accountTag", { length: 128 }).notNull(),
  provider: varchar("provider", { length: 32 }).notNull(),
  name: text("name").notNull(),
  revision: bigint("revision", { mode: "number" }).notNull().default(1),
  isDisabled: boolean("isDisabled").notNull().default(false),
  verificationStatus: varchar("verificationStatus", { length: 32 }).notNull().default("UNVERIFIED"),
  lastErrorCode: varchar("lastErrorCode", { length: 64 }),
  lastValidationAttemptAt: epoch("lastValidationAttemptAt"),
  verifiedAt: epoch("verifiedAt"),
  verificationExpiresAt: epoch("verificationExpiresAt"),
  createdByUserId: int("createdByUserId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["provider"] },
  { columns: ["verificationExpiresAt"] },
  { columns: ["accountTag"], unique: true },
]);
export type DnsProviderAccount = typeof dnsProviderAccounts.$inferSelect;
export type InsertDnsProviderAccount = typeof dnsProviderAccounts.$inferInsert;

export const dnsProviderAccountSecrets = table("dns_provider_account_secrets", {
  id: serial("id"),
  accountId: int("accountId").notNull(),
  kind: varchar("kind", { length: 32 }).notNull(),
  encryptedValue: text("encryptedValue").notNull(),
  fingerprint: varchar("fingerprint", { length: 64 }).notNull(),
  keyVersion: int("keyVersion").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["kind", "fingerprint"] },
  { columns: ["accountId", "kind"], unique: true },
]);
export type DnsProviderAccountSecret = typeof dnsProviderAccountSecrets.$inferSelect;
export type InsertDnsProviderAccountSecret = typeof dnsProviderAccountSecrets.$inferInsert;

export const dnsProviderGlobalBindings = table("dns_provider_global_bindings", {
  id: serial("id"),
  scopeKey: varchar("scopeKey", { length: 64 }).notNull(),
  accountId: int("accountId"),
  revision: bigint("revision", { mode: "number" }).notNull().default(1),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["accountId"] },
  { columns: ["scopeKey"], unique: true },
]);
export type DnsProviderGlobalBinding = typeof dnsProviderGlobalBindings.$inferSelect;
export type InsertDnsProviderGlobalBinding = typeof dnsProviderGlobalBindings.$inferInsert;

export const dnsProviderZones = table("dns_provider_zones", {
  id: serial("id"),
  accountId: int("accountId").notNull(),
  providerZoneId: varchar("providerZoneId", { length: 128 }).notNull(),
  name: varchar("name", { length: 255 }).notNull(),
  status: varchar("status", { length: 32 }).notNull(),
  catalogRevision: varchar("catalogRevision", { length: 64 }).notNull(),
  refreshedAt: epoch("refreshedAt").notNull(),
  expiresAt: epoch("expiresAt").notNull(),
  lastSeenAt: epoch("lastSeenAt").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["accountId", "status", "expiresAt"] },
  { columns: ["accountId", "providerZoneId"], unique: true },
  { columns: ["accountId", "name"], unique: true },
]);
export type DnsProviderZone = typeof dnsProviderZones.$inferSelect;
export type InsertDnsProviderZone = typeof dnsProviderZones.$inferInsert;

export const dnsProviderRecordLines = table("dns_provider_record_lines", {
  id: serial("id"),
  zoneId: int("zoneId").notNull(),
  providerLineId: varchar("providerLineId", { length: 128 }).notNull(),
  name: varchar("name", { length: 255 }).notNull(),
  category: varchar("category", { length: 32 }).notNull(),
  status: varchar("status", { length: 32 }).notNull(),
  catalogRevision: varchar("catalogRevision", { length: 64 }).notNull(),
  refreshedAt: epoch("refreshedAt").notNull(),
  expiresAt: epoch("expiresAt").notNull(),
  lastSeenAt: epoch("lastSeenAt").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["zoneId", "category", "status"] },
  { columns: ["zoneId", "providerLineId"], unique: true },
]);
export type DnsProviderRecordLine = typeof dnsProviderRecordLines.$inferSelect;
export type InsertDnsProviderRecordLine = typeof dnsProviderRecordLines.$inferInsert;

export const xrayQuickConfigs = table("xray_quick_configs", {
  id: serial("id"),
  configTag: varchar("configTag", { length: 128 }).notNull(),
  targetType: varchar("targetType", { length: 32 }).notNull(),
  xrayInboundId: int("xrayInboundId"),
  externalProxyNodeId: int("externalProxyNodeId"),
  targetVersion: varchar("targetVersion", { length: 64 }).notNull(),
  dnsAccountId: int("dnsAccountId").notNull(),
  zoneId: int("zoneId").notNull(),
  relativeName: text("relativeName").notNull(),
  fqdn: text("fqdn").notNull(),
  state: varchar("state", { length: 32 }).notNull(),
  revision: bigint("revision", { mode: "number" }).notNull().default(1),
  activeTopologyRevisionId: int("activeTopologyRevisionId"),
  desiredTopologyRevisionId: int("desiredTopologyRevisionId"),
  currentOperationId: int("currentOperationId"),
  createdByUserId: int("createdByUserId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["xrayInboundId"] },
  { columns: ["externalProxyNodeId"] },
  { columns: ["dnsAccountId"] },
  { columns: ["zoneId"] },
  { columns: ["activeTopologyRevisionId"] },
  { columns: ["desiredTopologyRevisionId"] },
  { columns: ["currentOperationId"] },
  { columns: ["configTag"], unique: true },
]);
export type XrayQuickConfig = typeof xrayQuickConfigs.$inferSelect;
export type InsertXrayQuickConfig = typeof xrayQuickConfigs.$inferInsert;

export const xrayQuickConfigDomainClaims = table("xray_quick_config_domain_claims", {
  id: serial("id"),
  claimKey: varchar("claimKey", { length: 64 }).notNull(),
  dnsAccountId: int("dnsAccountId").notNull(),
  zoneId: int("zoneId").notNull(),
  normalizedRelativeName: text("normalizedRelativeName").notNull(),
  quickConfigId: int("quickConfigId").notNull(),
  revision: bigint("revision", { mode: "number" }).notNull().default(1),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["dnsAccountId", "zoneId"] },
  { columns: ["claimKey"], unique: true },
  { columns: ["quickConfigId"], unique: true },
]);
export type XrayQuickConfigDomainClaim = typeof xrayQuickConfigDomainClaims.$inferSelect;
export type InsertXrayQuickConfigDomainClaim = typeof xrayQuickConfigDomainClaims.$inferInsert;

export const xrayQuickConfigTopologyRevisions = table("xray_quick_config_topology_revisions", {
  id: serial("id"),
  quickConfigId: int("quickConfigId").notNull(),
  revisionNumber: bigint("revisionNumber", { mode: "number" }).notNull(),
  engine: varchar("engine", { length: 32 }).notNull(),
  targetAddress: text("targetAddress").notNull(),
  targetPort: int("targetPort").notNull(),
  publicPort: int("publicPort").notNull(),
  portAllocationId: int("portAllocationId").notNull(),
  state: varchar("state", { length: 32 }).notNull(),
  activeSlot: int("activeSlot"),
  createdByUserId: int("createdByUserId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["portAllocationId"] },
  { columns: ["state"] },
  { columns: ["quickConfigId", "revisionNumber"], unique: true },
  { columns: ["quickConfigId", "activeSlot"], unique: true },
]);
export type XrayQuickConfigTopologyRevision = typeof xrayQuickConfigTopologyRevisions.$inferSelect;
export type InsertXrayQuickConfigTopologyRevision = typeof xrayQuickConfigTopologyRevisions.$inferInsert;

export const xrayQuickConfigRoutes = table("xray_quick_config_routes", {
  id: serial("id"),
  routeTag: varchar("routeTag", { length: 128 }).notNull(),
  quickConfigId: int("quickConfigId").notNull(),
  topologyRevisionId: int("topologyRevisionId").notNull(),
  lineCategory: varchar("lineCategory", { length: 32 }).notNull(),
  providerLineId: varchar("providerLineId", { length: 128 }).notNull(),
  sourceType: varchar("sourceType", { length: 32 }).notNull(),
  hostId: int("hostId"),
  addressFamily: varchar("addressFamily", { length: 16 }).notNull(),
  address: text("address").notNull(),
  routeMode: varchar("routeMode", { length: 16 }).notNull(),
  sortOrder: int("sortOrder").notNull().default(0),
  state: varchar("state", { length: 32 }).notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["quickConfigId", "state"] },
  { columns: ["topologyRevisionId", "sortOrder"] },
  { columns: ["hostId"] },
  { columns: ["routeTag"], unique: true },
]);
export type XrayQuickConfigRoute = typeof xrayQuickConfigRoutes.$inferSelect;
export type InsertXrayQuickConfigRoute = typeof xrayQuickConfigRoutes.$inferInsert;

export const xrayQuickConfigRuleBindings = table("xray_quick_config_rule_bindings", {
  id: serial("id"),
  bindingTag: varchar("bindingTag", { length: 128 }).notNull(),
  quickConfigId: int("quickConfigId").notNull(),
  topologyRevisionId: int("topologyRevisionId").notNull(),
  forwardRuleId: int("forwardRuleId").notNull(),
  state: varchar("state", { length: 32 }).notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["quickConfigId", "state"] },
  { columns: ["forwardRuleId"] },
  { columns: ["bindingTag"], unique: true },
  { columns: ["topologyRevisionId", "forwardRuleId"], unique: true },
]);
export type XrayQuickConfigRuleBinding = typeof xrayQuickConfigRuleBindings.$inferSelect;
export type InsertXrayQuickConfigRuleBinding = typeof xrayQuickConfigRuleBindings.$inferInsert;

export const xrayQuickConfigDnsRecords = table("xray_quick_config_dns_records", {
  id: serial("id"),
  quickConfigId: int("quickConfigId").notNull(),
  routeId: int("routeId").notNull(),
  dnsAccountId: int("dnsAccountId").notNull(),
  zoneId: int("zoneId").notNull(),
  recordTag: varchar("recordTag", { length: 128 }).notNull(),
  providerRecordId: varchar("providerRecordId", { length: 128 }),
  providerLineId: varchar("providerLineId", { length: 128 }).notNull(),
  fqdn: text("fqdn").notNull(),
  recordType: varchar("recordType", { length: 16 }).notNull(),
  value: text("value").notNull(),
  ttl: int("ttl").notNull(),
  status: varchar("status", { length: 32 }).notNull(),
  appliedRevision: bigint("appliedRevision", { mode: "number" }).notNull(),
  remoteTupleHash: varchar("remoteTupleHash", { length: 64 }).notNull(),
  lastVerifiedAt: epoch("lastVerifiedAt"),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["quickConfigId", "status"] },
  { columns: ["routeId"] },
  { columns: ["zoneId"] },
  { columns: ["recordTag"], unique: true },
  { columns: ["dnsAccountId", "providerRecordId"], unique: true },
]);
export type XrayQuickConfigDnsRecord = typeof xrayQuickConfigDnsRecords.$inferSelect;
export type InsertXrayQuickConfigDnsRecord = typeof xrayQuickConfigDnsRecords.$inferInsert;

export const xrayQuickConfigDnsRecordBackups = table("xray_quick_config_dns_record_backups", {
  id: serial("id"),
  operationId: int("operationId").notNull(),
  dnsAccountId: int("dnsAccountId").notNull(),
  zoneId: int("zoneId").notNull(),
  providerRecordId: varchar("providerRecordId", { length: 128 }).notNull(),
  fqdn: text("fqdn").notNull(),
  recordType: varchar("recordType", { length: 16 }).notNull(),
  providerLineId: varchar("providerLineId", { length: 128 }).notNull(),
  value: text("value").notNull(),
  ttl: int("ttl").notNull(),
  remoteTupleHash: varchar("remoteTupleHash", { length: 64 }).notNull(),
  snapshotOrder: int("snapshotOrder").notNull(),
  state: varchar("state", { length: 32 }).notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["operationId", "state"] },
  { columns: ["operationId", "dnsAccountId", "providerRecordId"], unique: true },
  { columns: ["operationId", "snapshotOrder"], unique: true },
]);
export type XrayQuickConfigDnsRecordBackup = typeof xrayQuickConfigDnsRecordBackups.$inferSelect;
export type InsertXrayQuickConfigDnsRecordBackup = typeof xrayQuickConfigDnsRecordBackups.$inferInsert;

export const xrayQuickConfigOperations = table("xray_quick_config_operations", {
  id: serial("id"),
  operationTag: varchar("operationTag", { length: 128 }).notNull(),
  quickConfigId: int("quickConfigId").notNull(),
  type: varchar("type", { length: 32 }).notNull(),
  status: varchar("status", { length: 32 }).notNull(),
  phase: varchar("phase", { length: 32 }).notNull(),
  activeSlot: int("activeSlot"),
  revision: bigint("revision", { mode: "number" }).notNull().default(1),
  expectedRevision: bigint("expectedRevision", { mode: "number" }).notNull(),
  fromTopologyRevisionId: int("fromTopologyRevisionId"),
  toTopologyRevisionId: int("toTopologyRevisionId"),
  requestSummaryJson: text("requestSummaryJson").notNull(),
  retryOfOperationId: int("retryOfOperationId"),
  executionOwnerId: varchar("executionOwnerId", { length: 128 }),
  executionLeaseUntil: epoch("executionLeaseUntil"),
  executionFence: bigint("executionFence", { mode: "number" }).notNull().default(1),
  errorCode: varchar("errorCode", { length: 64 }),
  errorMessage: text("errorMessage"),
  createdByUserId: int("createdByUserId").notNull(),
  startedAt: epoch("startedAt"),
  finishedAt: epoch("finishedAt"),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["quickConfigId", "status", "createdAt"] },
  { columns: ["retryOfOperationId"] },
  { columns: ["executionLeaseUntil"] },
  { columns: ["fromTopologyRevisionId"] },
  { columns: ["toTopologyRevisionId"] },
  { columns: ["operationTag"], unique: true },
  { columns: ["quickConfigId", "activeSlot"], unique: true },
]);
export type XrayQuickConfigOperation = typeof xrayQuickConfigOperations.$inferSelect;
export type InsertXrayQuickConfigOperation = typeof xrayQuickConfigOperations.$inferInsert;

export const xrayQuickConfigOperationSteps = table("xray_quick_config_operation_steps", {
  id: serial("id"),
  operationId: int("operationId").notNull(),
  stepKey: varchar("stepKey", { length: 128 }).notNull(),
  kind: varchar("kind", { length: 32 }).notNull(),
  subjectType: varchar("subjectType", { length: 32 }).notNull(),
  subjectId: varchar("subjectId", { length: 128 }),
  status: varchar("status", { length: 32 }).notNull(),
  attemptCount: int("attemptCount").notNull().default(0),
  idempotencyKey: varchar("idempotencyKey", { length: 128 }).notNull(),
  requestSummaryJson: text("requestSummaryJson").notNull(),
  resultSummaryJson: text("resultSummaryJson"),
  errorCode: varchar("errorCode", { length: 64 }),
  startedAt: epoch("startedAt"),
  finishedAt: epoch("finishedAt"),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["operationId", "status"] },
  { columns: ["subjectType", "subjectId"] },
  { columns: ["operationId", "stepKey"], unique: true },
  { columns: ["idempotencyKey"], unique: true },
]);
export type XrayQuickConfigOperationStep = typeof xrayQuickConfigOperationSteps.$inferSelect;
export type InsertXrayQuickConfigOperationStep = typeof xrayQuickConfigOperationSteps.$inferInsert;

export const globalPortAllocations = table("global_port_allocations", {
  id: serial("id"),
  allocationTag: varchar("allocationTag", { length: 128 }).notNull(),
  port: int("port").notNull(),
  status: varchar("status", { length: 32 }).notNull(),
  primaryOwnerType: varchar("primaryOwnerType", { length: 64 }),
  primaryOwnerTag: varchar("primaryOwnerTag", { length: 128 }),
  reservationTokenHash: varchar("reservationTokenHash", { length: 64 }),
  reservedUntil: epoch("reservedUntil"),
  scanNotBefore: epoch("scanNotBefore"),
  lastScanStartedAt: epoch("lastScanStartedAt"),
  lastScanFinishedAt: epoch("lastScanFinishedAt"),
  lastErrorCode: varchar("lastErrorCode", { length: 64 }),
  version: bigint("version", { mode: "number" }).notNull().default(1),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["status", "scanNotBefore"] },
  { columns: ["primaryOwnerType", "primaryOwnerTag"] },
  { columns: ["allocationTag"], unique: true },
  { columns: ["port"], unique: true },
]);
export type GlobalPortAllocation = typeof globalPortAllocations.$inferSelect;
export type InsertGlobalPortAllocation = typeof globalPortAllocations.$inferInsert;

export const globalPortAllocationReferences = table("global_port_allocation_references", {
  id: serial("id"),
  referenceKey: varchar("referenceKey", { length: 255 }).notNull(),
  allocationId: int("allocationId").notNull(),
  resourceType: varchar("resourceType", { length: 64 }).notNull(),
  resourceId: int("resourceId").notNull(),
  ownerGroupTag: varchar("ownerGroupTag", { length: 128 }).notNull(),
  hostId: int("hostId"),
  network: varchar("network", { length: 16 }).notNull(),
  role: varchar("role", { length: 32 }).notNull(),
  isOwning: boolean("isOwning").notNull().default(false),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["allocationId", "ownerGroupTag"] },
  { columns: ["resourceType", "resourceId"] },
  { columns: ["hostId"] },
  { columns: ["referenceKey"], unique: true },
]);
export type GlobalPortAllocationReference = typeof globalPortAllocationReferences.$inferSelect;
export type InsertGlobalPortAllocationReference = typeof globalPortAllocationReferences.$inferInsert;

export const globalPortProbeRuns = table("global_port_probe_runs", {
  id: serial("id"),
  probeTag: varchar("probeTag", { length: 128 }).notNull(),
  allocationId: int("allocationId"),
  allocationVersion: bigint("allocationVersion", { mode: "number" }),
  candidatePort: int("candidatePort").notNull(),
  purpose: varchar("purpose", { length: 32 }).notNull(),
  status: varchar("status", { length: 32 }).notNull(),
  hostSetHash: varchar("hostSetHash", { length: 64 }).notNull(),
  expectedHostCount: int("expectedHostCount").notNull(),
  createdByUserId: int("createdByUserId"),
  startedAt: epoch("startedAt"),
  finishedAt: epoch("finishedAt"),
  expiresAt: epoch("expiresAt").notNull(),
  errorCode: varchar("errorCode", { length: 64 }),
}, [
  { columns: ["allocationId"] },
  { columns: ["purpose", "status", "expiresAt"] },
  { columns: ["probeTag"], unique: true },
]);
export type GlobalPortProbeRun = typeof globalPortProbeRuns.$inferSelect;
export type InsertGlobalPortProbeRun = typeof globalPortProbeRuns.$inferInsert;

export const globalPortProbeResults = table("global_port_probe_results", {
  id: serial("id"),
  probeRunId: int("probeRunId").notNull(),
  hostId: int("hostId").notNull(),
  network: varchar("network", { length: 8 }).notNull(),
  xrayOperationId: varchar("xrayOperationId", { length: 64 }).notNull(),
  status: varchar("status", { length: 32 }).notNull(),
  probedAt: epoch("probedAt").notNull(),
  expiresAt: epoch("expiresAt").notNull(),
}, [
  { columns: ["xrayOperationId"] },
  { columns: ["hostId", "expiresAt"] },
  { columns: ["probeRunId", "hostId", "network"], unique: true },
]);
export type GlobalPortProbeResult = typeof globalPortProbeResults.$inferSelect;
export type InsertGlobalPortProbeResult = typeof globalPortProbeResults.$inferInsert;

export const globalPortScanLeases = table("global_port_scan_leases", {
  id: serial("id"),
  scopeKey: varchar("scopeKey", { length: 64 }).notNull(),
  leaseOwnerHash: varchar("leaseOwnerHash", { length: 64 }),
  leaseUntil: epoch("leaseUntil"),
  lastStartedAt: epoch("lastStartedAt"),
  lastFinishedAt: epoch("lastFinishedAt"),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["scopeKey"], unique: true },
]);
export type GlobalPortScanLease = typeof globalPortScanLeases.$inferSelect;
export type InsertGlobalPortScanLease = typeof globalPortScanLeases.$inferInsert;

export const xrayClients = table("xray_clients", {
  id: serial("id"),
  inboundId: int("inboundId").notNull(),
  name: text("name").notNull(),
  uuidEncrypted: text("uuidEncrypted").notNull(),
  uuidFingerprint: varchar("uuidFingerprint", { length: 64 }).notNull(),
  shortIdEncrypted: text("shortIdEncrypted").notNull(),
  shortIdFingerprint: varchar("shortIdFingerprint", { length: 64 }).notNull(),
  statsKey: varchar("statsKey", { length: 128 }).notNull(),
  flow: varchar("flow", { length: 64 }).notNull().default("xtls-rprx-vision"),
  ownerUserId: int("ownerUserId"),
  isEnabled: boolean("isEnabled").notNull().default(true),
  pendingDelete: boolean("pendingDelete").notNull().default(false),
  desiredGeneration: bigint("desiredGeneration", { mode: "number" }).notNull().default(0),
  sortOrder: int("sortOrder").notNull().default(0),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["inboundId", "pendingDelete", "isEnabled", "sortOrder"] },
  { columns: ["ownerUserId", "createdAt"] },
  { columns: ["uuidFingerprint"], unique: true },
  { columns: ["statsKey"], unique: true },
  { columns: ["inboundId", "shortIdFingerprint"], unique: true },
]);
export type XrayClient = typeof xrayClients.$inferSelect;
export type InsertXrayClient = typeof xrayClients.$inferInsert;

export const xrayAccessEntries = table("xray_access_entries", {
  id: serial("id"),
  inboundId: int("inboundId").notNull(),
  legacyClientId: int("legacyClientId"),
  name: text("name").notNull(),
  credentialType: varchar("credentialType", { length: 32 }).notNull(),
  settingsJson: text("settingsJson").notNull(),
  statsKey: varchar("statsKey", { length: 128 }).notNull(),
  ownerUserId: int("ownerUserId"),
  isEnabled: boolean("isEnabled").notNull().default(true),
  pendingDelete: boolean("pendingDelete").notNull().default(false),
  desiredGeneration: bigint("desiredGeneration", { mode: "number" }).notNull().default(0),
  sortOrder: int("sortOrder").notNull().default(0),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["inboundId", "pendingDelete", "isEnabled", "sortOrder"] },
  { columns: ["ownerUserId", "createdAt"] },
  { columns: ["legacyClientId"], unique: true },
  { columns: ["statsKey"], unique: true },
]);
export type XrayAccessEntry = typeof xrayAccessEntries.$inferSelect;
export type InsertXrayAccessEntry = typeof xrayAccessEntries.$inferInsert;

export const xrayAccessSecrets = table("xray_access_secrets", {
  id: serial("id"),
  accessEntryId: int("accessEntryId").notNull(),
  kind: varchar("kind", { length: 32 }).notNull(),
  encryptedValue: text("encryptedValue").notNull(),
  fingerprint: varchar("fingerprint", { length: 64 }).notNull(),
  keyVersion: int("keyVersion").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["kind", "fingerprint"] },
  { columns: ["accessEntryId", "kind"], unique: true },
]);
export type XrayAccessSecret = typeof xrayAccessSecrets.$inferSelect;
export type InsertXrayAccessSecret = typeof xrayAccessSecrets.$inferInsert;

export const xrayInboundSecrets = table("xray_inbound_secrets", {
  id: serial("id"),
  inboundId: int("inboundId").notNull(),
  kind: varchar("kind", { length: 32 }).notNull(),
  encryptedValue: text("encryptedValue").notNull(),
  fingerprint: varchar("fingerprint", { length: 64 }).notNull(),
  keyVersion: int("keyVersion").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["kind", "fingerprint"] },
  { columns: ["inboundId", "kind"], unique: true },
]);
export type XrayInboundSecret = typeof xrayInboundSecrets.$inferSelect;
export type InsertXrayInboundSecret = typeof xrayInboundSecrets.$inferInsert;

export const xrayTlsCertificates = table("xray_tls_certificates", {
  id: serial("id"),
  hostId: int("hostId").notNull(),
  name: text("name").notNull(),
  certificateTag: varchar("certificateTag", { length: 128 }).notNull(),
  certificateChainPem: text("certificateChainPem").notNull(),
  privateKeyEncrypted: text("privateKeyEncrypted").notNull(),
  privateKeyFingerprint: varchar("privateKeyFingerprint", { length: 64 }).notNull(),
  keyVersion: int("keyVersion").notNull(),
  leafFingerprintSha256: varchar("leafFingerprintSha256", { length: 64 }).notNull(),
  dnsNamesJson: text("dnsNamesJson").notNull(),
  subject: text("subject").notNull(),
  issuer: text("issuer").notNull(),
  serialNumber: varchar("serialNumber", { length: 128 }).notNull(),
  notBefore: epoch("notBefore").notNull(),
  notAfter: epoch("notAfter").notNull(),
  keyAlgorithm: varchar("keyAlgorithm", { length: 32 }).notNull(),
  createdByUserId: int("createdByUserId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["hostId", "name"] },
  { columns: ["hostId", "notAfter"] },
  { columns: ["privateKeyFingerprint"] },
  { columns: ["leafFingerprintSha256"] },
  { columns: ["certificateTag"], unique: true },
]);
export type XrayTlsCertificate = typeof xrayTlsCertificates.$inferSelect;
export type InsertXrayTlsCertificate = typeof xrayTlsCertificates.$inferInsert;

export const xrayHostDeployments = table("xray_host_deployments", {
  id: serial("id"),
  hostId: int("hostId").notNull(),
  targetVersion: varchar("targetVersion", { length: 64 }),
  desiredGeneration: bigint("desiredGeneration", { mode: "number" }).notNull().default(0),
  desiredConfigHash: varchar("desiredConfigHash", { length: 64 }),
  lastOperationId: varchar("lastOperationId", { length: 64 }),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["lastOperationId"] },
  { columns: ["hostId"], unique: true },
]);
export type XrayHostDeployment = typeof xrayHostDeployments.$inferSelect;
export type InsertXrayHostDeployment = typeof xrayHostDeployments.$inferInsert;

export const xrayRuntimeReports = table("xray_runtime_reports", {
  id: serial("id"),
  hostId: int("hostId").notNull(),
  capabilitySchemaVersion: int("capabilitySchemaVersion").notNull().default(0),
  supportedOS: varchar("supportedOS", { length: 32 }),
  supportedArch: varchar("supportedArch", { length: 32 }),
  supportsArtifactInstall: boolean("supportsArtifactInstall").notNull().default(false),
  supportsPortProbe: boolean("supportsPortProbe").notNull().default(false),
  supportsUdpPortProbe: boolean("supportsUdpPortProbe").notNull().default(false),
  supportsUdpListenerReadiness: boolean("supportsUdpListenerReadiness").notNull().default(false),
  supportsRealityScan: boolean("supportsRealityScan").notNull().default(false),
  capabilityErrorCode: varchar("capabilityErrorCode", { length: 64 }),
  isInstalled: boolean("isInstalled").notNull().default(false),
  installedVersion: varchar("installedVersion", { length: 64 }),
  runningVersion: varchar("runningVersion", { length: 64 }),
  serviceStatus: varchar("serviceStatus", { length: 32 }).notNull().default("UNKNOWN"),
  processId: int("processId"),
  appliedGeneration: bigint("appliedGeneration", { mode: "number" }).notNull().default(0),
  appliedConfigHash: varchar("appliedConfigHash", { length: 64 }),
  binarySha256: varchar("binarySha256", { length: 64 }),
  listenersJson: text("listenersJson"),
  reportSignature: varchar("reportSignature", { length: 64 }),
  lastErrorCode: varchar("lastErrorCode", { length: 64 }),
  lastErrorMessage: text("lastErrorMessage"),
  reportedAt: epoch("reportedAt"),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["reportedAt"] },
  { columns: ["hostId"], unique: true },
]);
export type XrayRuntimeReport = typeof xrayRuntimeReports.$inferSelect;
export type InsertXrayRuntimeReport = typeof xrayRuntimeReports.$inferInsert;

export const xrayArtifacts = table("xray_artifacts", {
  id: serial("id"),
  version: varchar("version", { length: 64 }).notNull(),
  os: varchar("os", { length: 32 }).notNull(),
  arch: varchar("arch", { length: 32 }).notNull(),
  packageFormat: varchar("packageFormat", { length: 16 }).notNull(),
  storageKey: text("storageKey").notNull(),
  sha256: varchar("sha256", { length: 64 }).notNull(),
  fileSize: bigint("fileSize", { mode: "number" }).notNull(),
  status: varchar("status", { length: 32 }).notNull().default("CACHED"),
  source: text("source"),
  verifiedAt: epoch("verifiedAt"),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["version", "status"] },
  { columns: ["updatedAt"] },
  { columns: ["version", "os", "arch"], unique: true },
]);
export type XrayArtifact = typeof xrayArtifacts.$inferSelect;
export type InsertXrayArtifact = typeof xrayArtifacts.$inferInsert;

export const xrayOperations = table("xray_operations", {
  id: serial("id"),
  operationId: varchar("operationId", { length: 64 }).notNull(),
  hostId: int("hostId").notNull(),
  inboundId: int("inboundId"),
  type: varchar("type", { length: 32 }).notNull(),
  requestedGeneration: bigint("requestedGeneration", { mode: "number" }),
  status: varchar("status", { length: 32 }).notNull().default("QUEUED"),
  requestMetaJson: text("requestMetaJson"),
  resultJson: text("resultJson"),
  errorCode: varchar("errorCode", { length: 64 }),
  errorMessage: text("errorMessage"),
  attemptCount: int("attemptCount").notNull().default(0),
  createdByUserId: int("createdByUserId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  startedAt: epoch("startedAt"),
  finishedAt: epoch("finishedAt"),
  expiresAt: epoch("expiresAt"),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["hostId", "status", "createdAt"] },
  { columns: ["type", "status", "createdAt"] },
  { columns: ["inboundId", "createdAt"] },
  { columns: ["expiresAt"] },
  { columns: ["updatedAt"] },
  { columns: ["operationId"], unique: true },
]);
export type XrayOperation = typeof xrayOperations.$inferSelect;
export type InsertXrayOperation = typeof xrayOperations.$inferInsert;

export const xrayManagedServices = table("xray_managed_services", {
  id: serial("id"),
  hostId: int("hostId").notNull(),
  name: text("name").notNull(),
  serviceTag: varchar("serviceTag", { length: 128 }).notNull(),
  kind: varchar("kind", { length: 64 }).notNull(),
  publicAddress: text("publicAddress").notNull(),
  listenAddress: varchar("listenAddress", { length: 64 }).notNull().default("0.0.0.0"),
  listenPort: int("listenPort").notNull(),
  specVersion: int("specVersion").notNull().default(1),
  specJson: text("specJson").notNull(),
  targetVersion: varchar("targetVersion", { length: 64 }).notNull(),
  isEnabled: boolean("isEnabled").notNull().default(true),
  pendingDelete: boolean("pendingDelete").notNull().default(false),
  desiredGeneration: bigint("desiredGeneration", { mode: "number" }).notNull().default(0),
  createdByUserId: int("createdByUserId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["serviceTag"], unique: true },
  { columns: ["hostId", "kind", "listenPort"], unique: true },
  { columns: ["hostId", "pendingDelete", "isEnabled"] },
  { columns: ["createdByUserId", "createdAt"] },
]);
export type XrayManagedService = typeof xrayManagedServices.$inferSelect;
export type InsertXrayManagedService = typeof xrayManagedServices.$inferInsert;

export const xrayManagedServiceInstanceSecrets = table("xray_managed_service_instance_secrets", {
  id: serial("id"),
  serviceId: int("serviceId").notNull(),
  kind: varchar("kind", { length: 32 }).notNull(),
  encryptedValue: text("encryptedValue").notNull(),
  fingerprint: varchar("fingerprint", { length: 64 }).notNull(),
  keyVersion: int("keyVersion").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["serviceId", "kind"], unique: true },
  { columns: ["kind", "fingerprint"] },
]);
export type XrayManagedServiceInstanceSecret = typeof xrayManagedServiceInstanceSecrets.$inferSelect;
export type InsertXrayManagedServiceInstanceSecret = typeof xrayManagedServiceInstanceSecrets.$inferInsert;

export const xrayManagedServiceAccounts = table("xray_managed_service_accounts", {
  id: serial("id"),
  serviceId: int("serviceId").notNull(),
  name: text("name").notNull(),
  accountTag: varchar("accountTag", { length: 128 }).notNull(),
  settingsVersion: int("settingsVersion").notNull().default(1),
  settingsJson: text("settingsJson").notNull().default("{}"),
  isEnabled: boolean("isEnabled").notNull().default(true),
  pendingDelete: boolean("pendingDelete").notNull().default(false),
  desiredGeneration: bigint("desiredGeneration", { mode: "number" }).notNull().default(0),
  sortOrder: int("sortOrder").notNull().default(0),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["accountTag"], unique: true },
  { columns: ["serviceId", "pendingDelete", "isEnabled", "sortOrder"] },
]);
export type XrayManagedServiceAccount = typeof xrayManagedServiceAccounts.$inferSelect;
export type InsertXrayManagedServiceAccount = typeof xrayManagedServiceAccounts.$inferInsert;

export const xrayManagedServiceSecrets = table("xray_managed_service_secrets", {
  id: serial("id"),
  accountId: int("accountId").notNull(),
  kind: varchar("kind", { length: 32 }).notNull(),
  encryptedValue: text("encryptedValue").notNull(),
  fingerprint: varchar("fingerprint", { length: 64 }).notNull(),
  keyVersion: int("keyVersion").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["accountId", "kind"], unique: true },
  { columns: ["kind", "fingerprint"] },
]);
export type XrayManagedServiceSecret = typeof xrayManagedServiceSecrets.$inferSelect;
export type InsertXrayManagedServiceSecret = typeof xrayManagedServiceSecrets.$inferInsert;

export const xrayManagedServiceDeployments = table("xray_managed_service_deployments", {
  id: serial("id"),
  hostId: int("hostId").notNull(),
  targetVersion: varchar("targetVersion", { length: 64 }),
  desiredGeneration: bigint("desiredGeneration", { mode: "number" }).notNull().default(0),
  desiredConfigHash: varchar("desiredConfigHash", { length: 64 }),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["hostId"], unique: true },
]);
export type XrayManagedServiceDeployment = typeof xrayManagedServiceDeployments.$inferSelect;

export const xrayManagedServiceRuntimeReports = table("xray_managed_service_runtime_reports", {
  id: serial("id"),
  hostId: int("hostId").notNull(),
  capabilityJson: text("capabilityJson"),
  stateJson: text("stateJson"),
  stateSignature: varchar("stateSignature", { length: 64 }),
  reportedAt: epoch("reportedAt"),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["hostId"], unique: true },
  { columns: ["reportedAt"] },
]);
export type XrayManagedServiceRuntimeReport = typeof xrayManagedServiceRuntimeReports.$inferSelect;

export const xrayManagedServiceArtifacts = table("xray_managed_service_artifacts", {
  id: serial("id"),
  kind: varchar("kind", { length: 64 }).notNull(),
  version: varchar("version", { length: 64 }).notNull(),
  os: varchar("os", { length: 32 }).notNull(),
  arch: varchar("arch", { length: 32 }).notNull(),
  packageFormat: varchar("packageFormat", { length: 16 }).notNull(),
  storageKey: text("storageKey").notNull(),
  sha256: varchar("sha256", { length: 64 }).notNull(),
  fileSize: bigint("fileSize", { mode: "number" }).notNull(),
  status: varchar("status", { length: 32 }).notNull().default("CACHED"),
  source: text("source"),
  verifiedAt: epoch("verifiedAt"),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["kind", "version", "os", "arch"], unique: true },
  { columns: ["kind", "version", "status"] },
  { columns: ["updatedAt"] },
]);
export type XrayManagedServiceArtifact = typeof xrayManagedServiceArtifacts.$inferSelect;

export const hostGroups = table("host_groups", {
  id: serial("id"),
  name: text("name").notNull(),
  isEnabled: boolean("isEnabled").notNull().default(true),
  sortOrder: int("sortOrder").notNull().default(0),
  userId: int("userId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type HostGroup = typeof hostGroups.$inferSelect;
export type InsertHostGroup = typeof hostGroups.$inferInsert;

export const hostGroupMembers = table("host_group_members", {
  id: serial("id"),
  groupId: int("groupId").notNull(),
  hostId: int("hostId").notNull(),
  sortOrder: int("sortOrder").notNull().default(0),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
});
export type HostGroupMember = typeof hostGroupMembers.$inferSelect;
export type InsertHostGroupMember = typeof hostGroupMembers.$inferInsert;

export const forwardRules = table("forward_rules", {
  id: serial("id"),
  hostId: int("hostId").notNull(),
  name: text("name").notNull(),
  forwardType: varchar("forwardType", { length: 32 }).notNull().default("iptables"), // 'iptables' | 'realm' | 'socat'
  protocol: varchar("protocol", { length: 16 }).notNull().default("both"), // 'tcp' | 'udp' | 'both'
  gostMode: varchar("gostMode", { length: 32 }).notNull().default("direct"), // 'direct' | 'reverse'
  gostRelayHost: text("gostRelayHost"),
  gostRelayPort: int("gostRelayPort"),
  tunnelId: int("tunnelId"),
  tunnelExitPort: int("tunnelExitPort"),
  forwardGroupId: int("forwardGroupId"),
  forwardGroupRuleId: int("forwardGroupRuleId"),
  forwardGroupMemberId: int("forwardGroupMemberId"),
  isForwardGroupTemplate: boolean("isForwardGroupTemplate").notNull().default(false),
  sourcePort: int("sourcePort").notNull(),
  targetIp: text("targetIp").notNull(),
  targetPort: int("targetPort").notNull(),
  targetExternalProxyNodeId: int("targetExternalProxyNodeId"),
  xrayQuickConfigId: int("xrayQuickConfigId"),
  portResourceGroupId: int("portResourceGroupId"),
  telegramErrorNotifyEnabled: boolean("telegramErrorNotifyEnabled").notNull().default(false),
  blockHttp: boolean("blockHttp").notNull().default(false),
  blockSocks: boolean("blockSocks").notNull().default(false),
  blockTls: boolean("blockTls").notNull().default(false),
  proxyProtocolReceive: boolean("proxyProtocolReceive").notNull().default(false),
  proxyProtocolSend: boolean("proxyProtocolSend").notNull().default(false),
  proxyProtocolExitReceive: boolean("proxyProtocolExitReceive").notNull().default(false),
  proxyProtocolExitSend: boolean("proxyProtocolExitSend").notNull().default(false),
  proxyProtocolVersion: int("proxyProtocolVersion").notNull().default(1),
  tcpFastOpen: boolean("tcpFastOpen").notNull().default(false),
  zeroCopy: boolean("zeroCopy").notNull().default(false),
  udpOverTcp: boolean("udpOverTcp").notNull().default(false),
  udpOverTcpPort: int("udpOverTcpPort"),
  protocolBlockReason: text("protocolBlockReason"),
  isEnabled: boolean("isEnabled").notNull().default(true),
  failoverEnabled: boolean("failoverEnabled").notNull().default(false),
  failoverStrategy: varchar("failoverStrategy", { length: 32 }).notNull().default("fallback"),
  failoverTargets: text("failoverTargets"),
  failoverSeconds: int("failoverSeconds").notNull().default(60),
  recoverSeconds: int("recoverSeconds").notNull().default(120),
  autoFailback: boolean("autoFailback").notNull().default(true),
  disabledByTunnel: boolean("disabledByTunnel").notNull().default(false),
  disabledByGroup: boolean("disabledByGroup").notNull().default(false),
  disabledByUser: boolean("disabledByUser").notNull().default(false),
  isRunning: boolean("isRunning").notNull().default(false),
  pendingDelete: boolean("pendingDelete").notNull().default(false),
  sortOrder: int("sortOrder").notNull().default(0),
  userId: int("userId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["targetExternalProxyNodeId"] },
  { columns: ["xrayQuickConfigId"] },
  { columns: ["portResourceGroupId"] },
]);
export type ForwardRule = typeof forwardRules.$inferSelect;
export type InsertForwardRule = typeof forwardRules.$inferInsert;

export const forwardGroups = table("forward_groups", {
  id: serial("id"),
  name: text("name").notNull(),
  remark: text("remark"),
  groupType: varchar("groupType", { length: 32 }).notNull().default("host"),
  groupMode: varchar("groupMode", { length: 32 }).notNull().default("failover"),
  exitStrategy: varchar("exitStrategy", { length: 32 }).notNull().default("round_robin"),
  entryGroupId: int("entryGroupId"),
  forwardType: varchar("forwardType", { length: 32 }).notNull().default("iptables"),
  domain: text("domain"),
  recordType: varchar("recordType", { length: 16 }).notNull().default("A"),
  sourcePort: int("sourcePort").notNull().default(1),
  protocol: varchar("protocol", { length: 16 }).notNull().default("both"),
  targetIp: text("targetIp").notNull(),
  targetPort: int("targetPort").notNull().default(1),
  rateLimitMbps: int("rateLimitMbps").notNull().default(0),
  trafficMultiplier: int("trafficMultiplier").notNull().default(100), // 0.01x = 1, 1x = 100, 50x = 5000
  proxyProtocolReceive: boolean("proxyProtocolReceive").notNull().default(false),
  proxyProtocolSend: boolean("proxyProtocolSend").notNull().default(false),
  proxyProtocolExitReceive: boolean("proxyProtocolExitReceive").notNull().default(false),
  proxyProtocolExitSend: boolean("proxyProtocolExitSend").notNull().default(false),
  proxyProtocolVersion: int("proxyProtocolVersion").notNull().default(1),
  tcpFastOpen: boolean("tcpFastOpen").notNull().default(false),
  zeroCopy: boolean("zeroCopy").notNull().default(false),
  udpOverTcp: boolean("udpOverTcp").notNull().default(false),
  udpOverTcpPort: int("udpOverTcpPort"),
  failoverEnabled: boolean("failoverEnabled").notNull().default(false),
  failoverStrategy: varchar("failoverStrategy", { length: 32 }).notNull().default("fallback"),
  failoverTargets: text("failoverTargets"),
  failoverSeconds: int("failoverSeconds").notNull().default(60),
  recoverSeconds: int("recoverSeconds").notNull().default(120),
  chinaHealthCheckEnabled: boolean("chinaHealthCheckEnabled").notNull().default(false),
  chinaHealthCheckTarget: text("chinaHealthCheckTarget"),
  telegramSwitchNotifyEnabled: boolean("telegramSwitchNotifyEnabled").notNull().default(false),
  ddnsAutoResolveEnabled: boolean("ddnsAutoResolveEnabled").notNull().default(true),
  autoFailback: boolean("autoFailback").notNull().default(true),
  isEnabled: boolean("isEnabled").notNull().default(true),
  activeMemberId: int("activeMemberId"),
  lastDdnsValue: text("lastDdnsValue"),
  lastDdnsAt: epoch("lastDdnsAt"),
  lastFailoverAt: epoch("lastFailoverAt"),
  lastStatus: varchar("lastStatus", { length: 32 }).notNull().default("unknown"),
  lastMessage: text("lastMessage"),
  systemManagedKind: varchar("systemManagedKind", { length: 32 }),
  systemManagedKey: varchar("systemManagedKey", { length: 128 }),
  sortOrder: int("sortOrder").notNull().default(0),
  userId: int("userId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
}, [
  { columns: ["systemManagedKey"], unique: true },
]);
export type ForwardGroup = typeof forwardGroups.$inferSelect;
export type InsertForwardGroup = typeof forwardGroups.$inferInsert;

export const forwardGroupMembers = table("forward_group_members", {
  id: serial("id"),
  groupId: int("groupId").notNull(),
  memberType: varchar("memberType", { length: 32 }).notNull(),
  hostId: int("hostId"),
  tunnelId: int("tunnelId"),
  connectHost: text("connectHost"),
  priority: int("priority").notNull().default(0),
  ruleId: int("ruleId"),
  isEnabled: boolean("isEnabled").notNull().default(true),
  healthStatus: varchar("healthStatus", { length: 32 }).notNull().default("unknown"),
  lastLatencyMs: int("lastLatencyMs"),
  chinaHealthStatus: varchar("chinaHealthStatus", { length: 32 }).notNull().default("unknown"),
  chinaHealthLatencyMs: int("chinaHealthLatencyMs"),
  chinaHealthCheckedAt: epoch("chinaHealthCheckedAt"),
  failureSince: epoch("failureSince"),
  healthySince: epoch("healthySince"),
  lastCheckedAt: epoch("lastCheckedAt"),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type ForwardGroupMember = typeof forwardGroupMembers.$inferSelect;
export type InsertForwardGroupMember = typeof forwardGroupMembers.$inferInsert;

export const forwardGroupEvents = table("forward_group_events", {
  id: serial("id"),
  groupId: int("groupId").notNull(),
  memberId: int("memberId"),
  type: varchar("type", { length: 32 }).notNull(),
  message: text("message"),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
});
export type ForwardGroupEvent = typeof forwardGroupEvents.$inferSelect;
export type InsertForwardGroupEvent = typeof forwardGroupEvents.$inferInsert;

// ===== gost 隧道配置（两台公网 Agent 组建链路） =====
export const tunnels = table("tunnels", {
  id: serial("id"),
  name: text("name").notNull(),
  entryGroupId: int("entryGroupId"),
  exitGroupId: int("exitGroupId"),
  entryHostId: int("entryHostId").notNull(),
  exitHostId: int("exitHostId").notNull(),
  mode: varchar("mode", { length: 32 }).notNull().default("tls"), // forwardx | tls | wss | tcp | mtls | mwss | mtcp | nginx_stream
  relayMode: varchar("relayMode", { length: 16 }).notNull().default("chain"), // chain | failover
  forwardxVersion: varchar("forwardxVersion", { length: 8 }).notNull().default("v1"),
  certDomain: text("certDomain"),
  certPem: text("certPem"),
  certKeyPem: text("certKeyPem"),
  secret: text("secret"),
  listenPort: int("listenPort").notNull(),
  mimicPort: int("mimicPort").notNull().default(0),
  rateLimitMbps: int("rateLimitMbps").notNull().default(0),
  trafficMultiplier: int("trafficMultiplier").notNull().default(100), // 0.01x = 1, 1x = 100, 50x = 5000
  // Legacy columns retained for migration compatibility; runtime ignores them.
  trafficPaddingEnabled: boolean("trafficPaddingEnabled").notNull().default(false),
  trafficPaddingRatio: int("trafficPaddingRatio").notNull().default(0),
  trafficPaddingMaxMbps: int("trafficPaddingMaxMbps").notNull().default(0),
  portRangeStart: int("portRangeStart"),
  portRangeEnd: int("portRangeEnd"),
  networkType: varchar("networkType", { length: 32 }).notNull().default("public"),
  connectHost: text("connectHost"),
  proxyProtocolReceive: boolean("proxyProtocolReceive").notNull().default(false),
  proxyProtocolSend: boolean("proxyProtocolSend").notNull().default(false),
  proxyProtocolExitReceive: boolean("proxyProtocolExitReceive").notNull().default(false),
  proxyProtocolExitSend: boolean("proxyProtocolExitSend").notNull().default(false),
  proxyProtocolVersion: int("proxyProtocolVersion").notNull().default(1),
  tcpFastOpen: boolean("tcpFastOpen").notNull().default(false),
  udpOverTcp: boolean("udpOverTcp").notNull().default(false),
  blockHttp: boolean("blockHttp").notNull().default(false),
  blockSocks: boolean("blockSocks").notNull().default(false),
  blockTls: boolean("blockTls").notNull().default(false),
  loadBalanceEnabled: boolean("loadBalanceEnabled").notNull().default(false),
  loadBalanceStrategy: varchar("loadBalanceStrategy", { length: 32 }).notNull().default("round_robin"),
  isEnabled: boolean("isEnabled").notNull().default(true),
  disabledByGroup: boolean("disabledByGroup").notNull().default(false),
  isRunning: boolean("isRunning").notNull().default(false),
  lastLatencyMs: int("lastLatencyMs"),
  lastTestStatus: text("lastTestStatus"),
  lastTestMessage: text("lastTestMessage"),
  lastTestAt: epoch("lastTestAt"),
  sortOrder: int("sortOrder").notNull().default(0),
  userId: int("userId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type Tunnel = typeof tunnels.$inferSelect;
export type InsertTunnel = typeof tunnels.$inferInsert;

export const tunnelExitNodes = table("tunnel_exit_nodes", {
  id: serial("id"),
  tunnelId: int("tunnelId").notNull(),
  seq: int("seq").notNull(),
  hostId: int("hostId").notNull(),
  listenPort: int("listenPort").notNull(),
  mimicPort: int("mimicPort").notNull().default(0),
  connectHost: text("connectHost"),
  isEnabled: boolean("isEnabled").notNull().default(true),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type TunnelExitNode = typeof tunnelExitNodes.$inferSelect;
export type InsertTunnelExitNode = typeof tunnelExitNodes.$inferInsert;

export const tunnelHops = table("tunnel_hops", {
  id: serial("id"),
  tunnelId: int("tunnelId").notNull(),
  seq: int("seq").notNull(),
  hostId: int("hostId").notNull(),
  listenPort: int("listenPort").notNull().default(0),
  mimicPort: int("mimicPort").notNull().default(0),
  connectHost: text("connectHost"),
});
export type TunnelHop = typeof tunnelHops.$inferSelect;
export type InsertTunnelHop = typeof tunnelHops.$inferInsert;

export const forwardRuleTunnelExits = table("forward_rule_tunnel_exits", {
  id: serial("id"),
  ruleId: int("ruleId").notNull(),
  tunnelId: int("tunnelId").notNull(),
  exitNodeId: int("exitNodeId").notNull(),
  exitSeq: int("exitSeq").notNull(),
  exitHostId: int("exitHostId").notNull(),
  tunnelExitPort: int("tunnelExitPort").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type ForwardRuleTunnelExit = typeof forwardRuleTunnelExits.$inferSelect;
export type InsertForwardRuleTunnelExit = typeof forwardRuleTunnelExits.$inferInsert;

export const hostMetrics = table("host_metrics", {
  id: serial("id"),
  hostId: int("hostId").notNull(),
  cpuUsage: int("cpuUsage"),
  memoryUsage: int("memoryUsage"),
  memoryUsed: bigint("memoryUsed", { mode: "number" }),
  swapUsage: int("swapUsage"),
  swapUsed: bigint("swapUsed", { mode: "number" }),
  swapTotal: bigint("swapTotal", { mode: "number" }),
  networkIn: bigint("networkIn", { mode: "number" }),
  networkOut: bigint("networkOut", { mode: "number" }),
  diskUsage: int("diskUsage"),
  diskUsed: bigint("diskUsed", { mode: "number" }),
  diskTotal: bigint("diskTotal", { mode: "number" }),
  uptime: bigint("uptime", { mode: "number" }),
  recordedAt: epoch("recordedAt").notNull().default(nowDefault()),
});
export type HostMetric = typeof hostMetrics.$inferSelect;
export type InsertHostMetric = typeof hostMetrics.$inferInsert;

export const hostTrafficCounters = table("host_traffic_counters", {
  id: serial("id"),
  hostId: int("hostId").notNull().unique(),
  bytesIn: bigint("bytesIn", { mode: "number" }).notNull().default(0),
  bytesOut: bigint("bytesOut", { mode: "number" }).notNull().default(0),
  lastSystemIn: bigint("lastSystemIn", { mode: "number" }),
  lastSystemOut: bigint("lastSystemOut", { mode: "number" }),
  lastDeltaIn: bigint("lastDeltaIn", { mode: "number" }).notNull().default(0),
  lastDeltaOut: bigint("lastDeltaOut", { mode: "number" }).notNull().default(0),
  lastReportedAt: epoch("lastReportedAt"),
  resetAt: epoch("resetAt"),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type HostTrafficCounter = typeof hostTrafficCounters.$inferSelect;
export type InsertHostTrafficCounter = typeof hostTrafficCounters.$inferInsert;

export const userTrafficCounters = table("user_traffic_counters", {
  id: serial("id"),
  userId: int("userId").notNull().unique(),
  bytesIn: bigint("bytesIn", { mode: "number" }).notNull().default(0),
  bytesOut: bigint("bytesOut", { mode: "number" }).notNull().default(0),
  connections: int("connections").notNull().default(0),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type UserTrafficCounter = typeof userTrafficCounters.$inferSelect;
export type InsertUserTrafficCounter = typeof userTrafficCounters.$inferInsert;

export const forwardRuleTrafficCounters = table("forward_rule_traffic_counters", {
  id: serial("id"),
  ruleId: int("ruleId").notNull(),
  hostId: int("hostId").notNull(),
  userId: int("userId").notNull(),
  bytesIn: bigint("bytesIn", { mode: "number" }).notNull().default(0),
  bytesOut: bigint("bytesOut", { mode: "number" }).notNull().default(0),
  connections: int("connections").notNull().default(0),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type ForwardRuleTrafficCounter = typeof forwardRuleTrafficCounters.$inferSelect;
export type InsertForwardRuleTrafficCounter = typeof forwardRuleTrafficCounters.$inferInsert;

export const trafficStats = table("traffic_stats", {
  id: serial("id"),
  ruleId: int("ruleId").notNull(),
  hostId: int("hostId").notNull(),
  bytesIn: bigint("bytesIn", { mode: "number" }).notNull().default(0),
  bytesOut: bigint("bytesOut", { mode: "number" }).notNull().default(0),
  connections: int("connections").notNull().default(0),
  recordedAt: epoch("recordedAt").notNull().default(nowDefault()),
});
export type TrafficStat = typeof trafficStats.$inferSelect;
export type InsertTrafficStat = typeof trafficStats.$inferInsert;

export const trafficStatBuckets = table("traffic_stat_buckets", {
  id: serial("id"),
  bucketStart: epoch("bucketStart").notNull(),
  bucketMinutes: int("bucketMinutes").notNull().default(30),
  userId: int("userId").notNull(),
  ruleId: int("ruleId").notNull(),
  hostId: int("hostId").notNull(),
  bytesIn: bigint("bytesIn", { mode: "number" }).notNull().default(0),
  bytesOut: bigint("bytesOut", { mode: "number" }).notNull().default(0),
  connections: int("connections").notNull().default(0),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type TrafficStatBucket = typeof trafficStatBuckets.$inferSelect;
export type InsertTrafficStatBucket = typeof trafficStatBuckets.$inferInsert;

export const agentTrafficReports = table("agent_traffic_reports", {
  id: serial("id"),
  hostId: int("hostId").notNull(),
  producerId: varchar("producerId", { length: 128 }),
  reportId: varchar("reportId", { length: 128 }).notNull(),
  receivedAt: epoch("receivedAt").notNull().default(nowDefault()),
});
export type AgentTrafficReport = typeof agentTrafficReports.$inferSelect;
export type InsertAgentTrafficReport = typeof agentTrafficReports.$inferInsert;

export const tunnelLatencyStats = table("tunnel_latency_stats", {
  id: serial("id"),
  tunnelId: int("tunnelId").notNull(),
  seriesKey: varchar("seriesKey", { length: 64 }),
  seriesLabel: text("seriesLabel"),
  latencyMs: int("latencyMs"),
  isTimeout: boolean("isTimeout").notNull().default(false),
  recordedAt: epoch("recordedAt").notNull().default(nowDefault()),
});
export type TunnelLatencyStat = typeof tunnelLatencyStats.$inferSelect;
export type InsertTunnelLatencyStat = typeof tunnelLatencyStats.$inferInsert;

export const forwardGroupLatencyStats = table("forward_group_latency_stats", {
  id: serial("id"),
  groupId: int("groupId").notNull(),
  latencyMs: int("latencyMs"),
  isTimeout: boolean("isTimeout").notNull().default(false),
  recordedAt: epoch("recordedAt").notNull().default(nowDefault()),
});
export type ForwardGroupLatencyStat = typeof forwardGroupLatencyStats.$inferSelect;
export type InsertForwardGroupLatencyStat = typeof forwardGroupLatencyStats.$inferInsert;

export const hostProbeServices = table("host_probe_services", {
  id: serial("id"),
  name: text("name").notNull(),
  method: varchar("method", { length: 16 }).notNull().default("tcping"),
  targetIp: text("targetIp").notNull(),
  targetPort: int("targetPort"),
  hostScope: varchar("hostScope", { length: 16 }).notNull().default("all"),
  hostIds: text("hostIds"),
  excludeHostIds: text("excludeHostIds"),
  intervalSeconds: int("intervalSeconds").notNull().default(30),
  isEnabled: boolean("isEnabled").notNull().default(true),
  sortOrder: int("sortOrder").notNull().default(0),
  userId: int("userId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type HostProbeService = typeof hostProbeServices.$inferSelect;
export type InsertHostProbeService = typeof hostProbeServices.$inferInsert;

export const hostProbeServiceStats = table("host_probe_service_stats", {
  id: serial("id"),
  serviceId: int("serviceId").notNull(),
  hostId: int("hostId").notNull(),
  latencyMs: int("latencyMs"),
  isTimeout: boolean("isTimeout").notNull().default(false),
  recordedAt: epoch("recordedAt").notNull().default(nowDefault()),
});
export type HostProbeServiceStat = typeof hostProbeServiceStats.$inferSelect;
export type InsertHostProbeServiceStat = typeof hostProbeServiceStats.$inferInsert;

export const ipGeoCache = table("ip_geo_cache", {
  id: serial("id"),
  address: varchar("address", { length: 253 }).notNull().unique(),
  resolvedAddress: varchar("resolvedAddress", { length: 64 }).notNull(),
  geoCountryCode: varchar("geoCountryCode", { length: 8 }).notNull(),
  geoCountryName: text("geoCountryName"),
  geoRegion: text("geoRegion"),
  geoEmoji: varchar("geoEmoji", { length: 16 }),
  geoLatitudeMicro: int("geoLatitudeMicro"),
  geoLongitudeMicro: int("geoLongitudeMicro"),
  provider: varchar("provider", { length: 32 }).notNull().default("ipapi.co"),
  fetchedAt: epoch("fetchedAt").notNull().default(nowDefault()),
  expiresAt: epoch("expiresAt").notNull(),
});
export type IpGeoCache = typeof ipGeoCache.$inferSelect;
export type InsertIpGeoCache = typeof ipGeoCache.$inferInsert;

export const agentTokens = table("agent_tokens", {
  id: serial("id"),
  token: text("token").notNull().unique(),
  hostId: int("hostId"),
  description: text("description"),
  isUsed: boolean("isUsed").notNull().default(false),
  sortOrder: int("sortOrder").notNull().default(0),
  userId: int("userId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
});
export type AgentToken = typeof agentTokens.$inferSelect;
export type InsertAgentToken = typeof agentTokens.$inferInsert;

export const forwardTests = table("forward_tests", {
  id: serial("id"),
  ruleId: int("ruleId").notNull(),
  hostId: int("hostId").notNull(),
  userId: int("userId").notNull(),
  status: varchar("status", { length: 32 }).notNull().default("pending"), // pending | running | success | failed | timeout
  listenOk: boolean("listenOk").notNull().default(false),
  targetReachable: boolean("targetReachable").notNull().default(false),
  forwardOk: boolean("forwardOk").notNull().default(false),
  latencyMs: int("latencyMs"),
  message: text("message"),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type ForwardTest = typeof forwardTests.$inferSelect;
export type InsertForwardTest = typeof forwardTests.$inferInsert;

// ===== TCPing 延迟统计表 =====
export const tcpingStats = table("tcping_stats", {
  id: serial("id"),
  ruleId: int("ruleId").notNull(),
  hostId: int("hostId").notNull(),
  latencyMs: int("latencyMs"),           // 延迟毫秒数，null 表示超时/不可达
  isTimeout: boolean("isTimeout").notNull().default(false),
  healthStatus: varchar("healthStatus", { length: 16 }),
  healthPending: boolean("healthPending").notNull().default(false),
  recordedAt: epoch("recordedAt").notNull().default(nowDefault()),
});
export type TcpingStat = typeof tcpingStats.$inferSelect;
export type InsertTcpingStat = typeof tcpingStats.$inferInsert;

// ===== 系统设置表（键值存储） =====
export const systemSettings = table("system_settings", {
  key: varchar("key", { length: 191 }).primaryKey(),
  value: longtext("value"),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type SystemSetting = typeof systemSettings.$inferSelect;
export type InsertSystemSetting = typeof systemSettings.$inferInsert;

// ===== Payment orders =====
export const paymentOrders = table("payment_orders", {
  id: serial("id"),
  outTradeNo: text("outTradeNo").notNull().unique(),
  userId: int("userId").notNull(),
  provider: varchar("provider", { length: 32 }).notNull(), // easypay | alipay | wxpay | stripe | gmpay
  paymentType: varchar("paymentType", { length: 32 }).notNull(), // alipay | wxpay | stripe | usdt
  status: varchar("status", { length: 32 }).notNull().default("pending"), // pending | paid | completed | expired | cancelled | failed
  subject: text("subject").notNull(),
  amountCents: bigint("amountCents", { mode: "number" }).notNull(),
  currency: varchar("currency", { length: 16 }).notNull().default("CNY"),
  tradeNo: text("tradeNo"),
  payUrl: text("payUrl"),
  qrCode: text("qrCode"),
  orderType: varchar("orderType", { length: 32 }).notNull().default("balance"), // balance | plan | test
  planId: int("planId"),
  subscriptionId: int("subscriptionId"),
  discountCodeId: int("discountCodeId"),
  discountConsumed: boolean("discountConsumed").notNull().default(false),
  discountAmountCents: bigint("discountAmountCents", { mode: "number" }).notNull().default(0),
  clientIp: text("clientIp"),
  rawNotify: text("rawNotify"),
  expiresAt: epoch("expiresAt"),
  paidAt: epoch("paidAt"),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type PaymentOrder = typeof paymentOrders.$inferSelect;
export type InsertPaymentOrder = typeof paymentOrders.$inferInsert;

// ===== Subscription plans =====
export const subscriptionPlans = table("subscription_plans", {
  id: serial("id"),
  name: text("name").notNull(),
  description: text("description"),
  priceCents: bigint("priceCents", { mode: "number" }).notNull().default(0),
  currency: varchar("currency", { length: 16 }).notNull().default("CNY"),
  durationDays: int("durationDays").notNull().default(30),
  portCount: int("portCount").notNull().default(20),
  trafficLimit: bigint("trafficLimit", { mode: "number" }).notNull().default(0),
  rateLimitMbps: int("rateLimitMbps").notNull().default(0),
  maxRules: int("maxRules").notNull().default(20),
  maxConnections: int("maxConnections").notNull().default(2000),
  maxIPs: int("maxIPs").notNull().default(10),
  isActive: boolean("isActive").notNull().default(true),
  isStoreVisible: boolean("isStoreVisible").notNull().default(true),
  sortOrder: int("sortOrder").notNull().default(0),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type SubscriptionPlan = typeof subscriptionPlans.$inferSelect;
export type InsertSubscriptionPlan = typeof subscriptionPlans.$inferInsert;

export const subscriptionPlanHosts = table("subscription_plan_hosts", {
  id: serial("id"),
  planId: int("planId").notNull(),
  hostId: int("hostId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
});
export type SubscriptionPlanHost = typeof subscriptionPlanHosts.$inferSelect;
export type InsertSubscriptionPlanHost = typeof subscriptionPlanHosts.$inferInsert;

export const subscriptionPlanTunnels = table("subscription_plan_tunnels", {
  id: serial("id"),
  planId: int("planId").notNull(),
  tunnelId: int("tunnelId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
});
export type SubscriptionPlanTunnel = typeof subscriptionPlanTunnels.$inferSelect;
export type InsertSubscriptionPlanTunnel = typeof subscriptionPlanTunnels.$inferInsert;

export const subscriptionPlanForwardGroups = table("subscription_plan_forward_groups", {
  id: serial("id"),
  planId: int("planId").notNull(),
  forwardGroupId: int("forwardGroupId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
});
export type SubscriptionPlanForwardGroup = typeof subscriptionPlanForwardGroups.$inferSelect;
export type InsertSubscriptionPlanForwardGroup = typeof subscriptionPlanForwardGroups.$inferInsert;

export const subscriptionPlanTrafficAddons = table("subscription_plan_traffic_addons", {
  id: serial("id"),
  planId: int("planId").notNull(),
  trafficBytes: bigint("trafficBytes", { mode: "number" }).notNull().default(0),
  priceCents: bigint("priceCents", { mode: "number" }).notNull().default(0),
  isActive: boolean("isActive").notNull().default(true),
  sortOrder: int("sortOrder").notNull().default(0),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type SubscriptionPlanTrafficAddon = typeof subscriptionPlanTrafficAddons.$inferSelect;
export type InsertSubscriptionPlanTrafficAddon = typeof subscriptionPlanTrafficAddons.$inferInsert;

export const userSubscriptions = table("user_subscriptions", {
  id: serial("id"),
  userId: int("userId").notNull(),
  planId: int("planId").notNull(),
  status: varchar("status", { length: 32 }).notNull().default("active"), // active | expired | cancelled
  source: varchar("source", { length: 32 }).notNull().default("admin"), // admin | payment | balance | redeem
  paymentOrderNo: text("paymentOrderNo"),
  planSnapshot: text("planSnapshot"),
  portRangeStart: int("portRangeStart"),
  portRangeEnd: int("portRangeEnd"),
  nextTrafficResetAt: epoch("nextTrafficResetAt"),
  lastTrafficResetAt: epoch("lastTrafficResetAt"),
  userDismissedAt: epoch("userDismissedAt"),
  adminDismissedAt: epoch("adminDismissedAt"),
  startedAt: epoch("startedAt").notNull().default(nowDefault()),
  expiresAt: epoch("expiresAt"),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type UserSubscription = typeof userSubscriptions.$inferSelect;
export type InsertUserSubscription = typeof userSubscriptions.$inferInsert;

export const userTrafficAddons = table("user_traffic_addons", {
  id: serial("id"),
  userId: int("userId").notNull(),
  subscriptionId: int("subscriptionId").notNull(),
  planId: int("planId").notNull(),
  addonId: int("addonId"),
  trafficBytes: bigint("trafficBytes", { mode: "number" }).notNull().default(0),
  priceCents: bigint("priceCents", { mode: "number" }).notNull().default(0),
  source: varchar("source", { length: 32 }).notNull().default("user"), // user | admin
  status: varchar("status", { length: 32 }).notNull().default("active"), // active | expired
  operatorUserId: int("operatorUserId"),
  description: text("description"),
  cycleResetAt: epoch("cycleResetAt"),
  expiresAt: epoch("expiresAt"),
  expiredAt: epoch("expiredAt"),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type UserTrafficAddon = typeof userTrafficAddons.$inferSelect;
export type InsertUserTrafficAddon = typeof userTrafficAddons.$inferInsert;

export const balanceTransactions = table("balance_transactions", {
  id: serial("id"),
  userId: int("userId").notNull(),
  type: varchar("type", { length: 32 }).notNull(), // admin_recharge | admin_adjust | payment | purchase | redeem | traffic_addon_purchase
  amountCents: bigint("amountCents", { mode: "number" }).notNull(),
  balanceAfterCents: bigint("balanceAfterCents", { mode: "number" }).notNull(),
  description: text("description"),
  operatorUserId: int("operatorUserId"),
  paymentOrderNo: text("paymentOrderNo"),
  redemptionCodeId: int("redemptionCodeId"),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
});
export type BalanceTransaction = typeof balanceTransactions.$inferSelect;
export type InsertBalanceTransaction = typeof balanceTransactions.$inferInsert;

export const trafficBillingConfigs = table("traffic_billing_configs", {
  id: serial("id"),
  resourceType: varchar("resourceType", { length: 16 }).notNull(), // host | tunnel | forward_group
  resourceId: int("resourceId").notNull(),
  enabled: boolean("enabled").notNull().default(true),
  requiresPermission: boolean("requiresPermission").notNull().default(false),
  description: text("description"),
  pricePerGbCents: bigint("pricePerGbCents", { mode: "number" }).notNull().default(0),
  pricePerGbMilliCents: bigint("pricePerGbMilliCents", { mode: "number" }).notNull().default(0),
  multiplier: int("multiplier").notNull().default(100), // snapshot from linked resource, 0.01x = 1, 1x = 100, 50x = 5000
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type TrafficBillingConfig = typeof trafficBillingConfigs.$inferSelect;
export type InsertTrafficBillingConfig = typeof trafficBillingConfigs.$inferInsert;

export const trafficBillingRecords = table("traffic_billing_records", {
  id: serial("id"),
  userId: int("userId").notNull(),
  ruleId: int("ruleId").notNull(),
  resourceType: varchar("resourceType", { length: 16 }).notNull(),
  resourceId: int("resourceId").notNull(),
  bytes: bigint("bytes", { mode: "number" }).notNull().default(0),
  billedGb: int("billedGb").notNull().default(0),
  pricePerGbCents: bigint("pricePerGbCents", { mode: "number" }).notNull().default(0),
  pricePerGbMilliCents: bigint("pricePerGbMilliCents", { mode: "number" }).notNull().default(0),
  multiplier: int("multiplier").notNull().default(100),
  amountCents: bigint("amountCents", { mode: "number" }).notNull().default(0),
  balanceAfterCents: bigint("balanceAfterCents", { mode: "number" }).notNull().default(0),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
});
export type TrafficBillingRecord = typeof trafficBillingRecords.$inferSelect;
export type InsertTrafficBillingRecord = typeof trafficBillingRecords.$inferInsert;

export const trafficBillingUsage = table("traffic_billing_usage", {
  id: serial("id"),
  userId: int("userId").notNull(),
  resourceType: varchar("resourceType", { length: 16 }).notNull(),
  resourceId: int("resourceId").notNull(),
  totalBytes: bigint("totalBytes", { mode: "number" }).notNull().default(0),
  billedGb: int("billedGb").notNull().default(0),
  pendingMilliCents: bigint("pendingMilliCents", { mode: "number" }).notNull().default(0),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type TrafficBillingUsage = typeof trafficBillingUsage.$inferSelect;
export type InsertTrafficBillingUsage = typeof trafficBillingUsage.$inferInsert;

export const trafficBillingRuleUsage = table("traffic_billing_rule_usage", {
  id: serial("id"),
  userId: int("userId").notNull(),
  ruleId: int("ruleId").notNull(),
  resourceType: varchar("resourceType", { length: 16 }).notNull(),
  resourceId: int("resourceId").notNull(),
  totalBytes: bigint("totalBytes", { mode: "number" }).notNull().default(0),
  billedGb: int("billedGb").notNull().default(0),
  pendingMilliCents: bigint("pendingMilliCents", { mode: "number" }).notNull().default(0),
  settled: boolean("settled").notNull().default(false),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type TrafficBillingRuleUsage = typeof trafficBillingRuleUsage.$inferSelect;
export type InsertTrafficBillingRuleUsage = typeof trafficBillingRuleUsage.$inferInsert;

export const userTrafficBillingPermissions = table("user_traffic_billing_permissions", {
  id: serial("id"),
  userId: int("userId").notNull(),
  resourceType: varchar("resourceType", { length: 16 }).notNull(),
  resourceId: int("resourceId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
});
export type UserTrafficBillingPermission = typeof userTrafficBillingPermissions.$inferSelect;
export type InsertUserTrafficBillingPermission = typeof userTrafficBillingPermissions.$inferInsert;

export const redemptionCodes = table("redemption_codes", {
  id: serial("id"),
  code: text("code").notNull().unique(),
  type: varchar("type", { length: 32 }).notNull(), // plan | balance
  planId: int("planId"),
  durationDays: int("durationDays"),
  amountCents: bigint("amountCents", { mode: "number" }).notNull().default(0),
  startsAt: epoch("startsAt"),
  expiresAt: epoch("expiresAt"),
  isActive: boolean("isActive").notNull().default(true),
  usedByUserId: int("usedByUserId"),
  usedAt: epoch("usedAt"),
  createdByUserId: int("createdByUserId"),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type RedemptionCode = typeof redemptionCodes.$inferSelect;
export type InsertRedemptionCode = typeof redemptionCodes.$inferInsert;

export const discountCodes = table("discount_codes", {
  id: serial("id"),
  code: text("code").notNull().unique(),
  discountType: varchar("discountType", { length: 32 }).notNull(), // percent | amount
  discountValue: int("discountValue").notNull(),
  maxUses: int("maxUses").notNull().default(0),
  usedCount: int("usedCount").notNull().default(0),
  startsAt: epoch("startsAt"),
  expiresAt: epoch("expiresAt"),
  isActive: boolean("isActive").notNull().default(true),
  createdByUserId: int("createdByUserId"),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type DiscountCode = typeof discountCodes.$inferSelect;
export type InsertDiscountCode = typeof discountCodes.$inferInsert;

export const discountCodePlans = table("discount_code_plans", {
  id: serial("id"),
  discountCodeId: int("discountCodeId").notNull(),
  planId: int("planId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
});
export type DiscountCodePlan = typeof discountCodePlans.$inferSelect;
export type InsertDiscountCodePlan = typeof discountCodePlans.$inferInsert;

export const announcements = table("announcements", {
  id: serial("id"),
  title: text("title").notNull(),
  content: text("content").notNull(),
  type: varchar("type", { length: 32 }).notNull().default("normal"), // normal | popup | upgrade_popup
  targetVersion: text("targetVersion"),
  isActive: boolean("isActive").notNull().default(true),
  startsAt: epoch("startsAt"),
  expiresAt: epoch("expiresAt"),
  createdByUserId: int("createdByUserId"),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type Announcement = typeof announcements.$inferSelect;
export type InsertAnnouncement = typeof announcements.$inferInsert;

export const announcementReads = table("announcement_reads", {
  id: serial("id"),
  announcementId: int("announcementId").notNull(),
  userId: int("userId").notNull(),
  dismissedAt: epoch("dismissedAt").notNull().default(nowDefault()),
});
export type AnnouncementRead = typeof announcementReads.$inferSelect;
export type InsertAnnouncementRead = typeof announcementReads.$inferInsert;

export const plugins = table("plugins", {
  id: serial("id"),
  pluginId: varchar("pluginId", { length: 128 }).notNull().unique(),
  name: text("name").notNull(),
  version: varchar("version", { length: 64 }).notNull().default("0.0.0"),
  description: text("description"),
  author: text("author"),
  homepage: text("homepage"),
  repository: text("repository"),
  sourceType: varchar("sourceType", { length: 32 }).notNull().default("github"), // github | upload | local
  sourceUrl: text("sourceUrl"),
  branch: varchar("branch", { length: 128 }),
  manifestPath: text("manifestPath"),
  manifestJson: text("manifestJson").notNull(),
  permissionsJson: text("permissionsJson"),
  extensionPointsJson: text("extensionPointsJson"),
  status: varchar("status", { length: 32 }).notNull().default("disabled"), // enabled | disabled | error
  trusted: boolean("trusted").notNull().default(false),
  installedAt: epoch("installedAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
  lastCheckedAt: epoch("lastCheckedAt"),
  latestVersion: varchar("latestVersion", { length: 64 }),
  lastError: text("lastError"),
});
export type Plugin = typeof plugins.$inferSelect;
export type InsertPlugin = typeof plugins.$inferInsert;

export const pluginStoreSources = table("plugin_store_sources", {
  id: serial("id"),
  name: text("name").notNull(),
  repository: text("repository").notNull(),
  branch: varchar("branch", { length: 128 }).notNull().default("main"),
  catalogPath: text("catalogPath").notNull().default("forwardx-store.json"),
  itemsJson: text("itemsJson"),
  lastSyncedAt: epoch("lastSyncedAt"),
  lastError: text("lastError"),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type PluginStoreSource = typeof pluginStoreSources.$inferSelect;
export type InsertPluginStoreSource = typeof pluginStoreSources.$inferInsert;

export const pluginAssets = table("plugin_assets", {
  id: serial("id"),
  pluginId: varchar("pluginId", { length: 128 }).notNull(),
  path: text("path").notNull(),
  contentType: varchar("contentType", { length: 128 }),
  size: int("size").notNull().default(0),
  sha256: varchar("sha256", { length: 64 }),
  content: text("content"),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type PluginAsset = typeof pluginAssets.$inferSelect;
export type InsertPluginAsset = typeof pluginAssets.$inferInsert;

export const pluginAgentStates = table("plugin_agent_states", {
  id: serial("id"),
  pluginId: varchar("pluginId", { length: 128 }).notNull(),
  resourceViewId: varchar("resourceViewId", { length: 128 }).notNull(),
  hostId: int("hostId").notNull(),
  pluginVersion: varchar("pluginVersion", { length: 64 }),
  actionId: varchar("actionId", { length: 128 }),
  groupId: varchar("groupId", { length: 64 }),
  taskId: varchar("taskId", { length: 64 }),
  status: varchar("status", { length: 32 }).notNull().default("idle"),
  dataJson: text("dataJson"),
  output: text("output"),
  error: text("error"),
  startedAt: epoch("startedAt"),
  finishedAt: epoch("finishedAt"),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
  updatedAt: epoch("updatedAt").notNull().default(nowDefault()),
});
export type PluginAgentState = typeof pluginAgentStates.$inferSelect;
export type InsertPluginAgentState = typeof pluginAgentStates.$inferInsert;

export const configAuditEvents = table("config_audit_events", {
  id: serial("id"),
  resourceType: varchar("resourceType", { length: 32 }).notNull(),
  resourceId: int("resourceId").notNull(),
  hostId: int("hostId"),
  action: varchar("action", { length: 32 }).notNull(),
  source: varchar("source", { length: 64 }).notNull().default("system"),
  actorUserId: int("actorUserId"),
  actorName: text("actorName"),
  requestId: varchar("requestId", { length: 64 }),
  requestPath: text("requestPath"),
  beforeJson: text("beforeJson"),
  afterJson: text("afterJson"),
  diffJson: text("diffJson"),
  configHash: varchar("configHash", { length: 64 }).notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
});
export type ConfigAuditEvent = typeof configAuditEvents.$inferSelect;
export type InsertConfigAuditEvent = typeof configAuditEvents.$inferInsert;

// ===== 用户-主机权限表（管理员指定用户可使用哪些 Agent/主机） =====
export const userHostPermissions = table("user_host_permissions", {
  id: serial("id"),
  userId: int("userId").notNull(),
  hostId: int("hostId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
});
export type UserHostPermission = typeof userHostPermissions.$inferSelect;
export type InsertUserHostPermission = typeof userHostPermissions.$inferInsert;

export const userTunnelPermissions = table("user_tunnel_permissions", {
  id: serial("id"),
  userId: int("userId").notNull(),
  tunnelId: int("tunnelId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
});
export type UserTunnelPermission = typeof userTunnelPermissions.$inferSelect;
export type InsertUserTunnelPermission = typeof userTunnelPermissions.$inferInsert;
export const userForwardGroupPermissions = table("user_forward_group_permissions", {
  id: serial("id"),
  userId: int("userId").notNull(),
  forwardGroupId: int("forwardGroupId").notNull(),
  createdAt: epoch("createdAt").notNull().default(nowDefault()),
});
export type UserForwardGroupPermission = typeof userForwardGroupPermissions.$inferSelect;
export type InsertUserForwardGroupPermission = typeof userForwardGroupPermissions.$inferInsert;
