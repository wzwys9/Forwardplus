import crypto from "node:crypto";

import { quoteIdentifier } from "../dbCompat";
import {
  DNS_PROVIDER_REQUIRED_CATEGORIES,
  DnsProviderCatalogValidationError,
  classifyDnsProviderLineName,
  computeDnsProviderCatalogRevision,
  computeStoredDnsProviderCatalogRevision,
  normalizeDnsProviderCatalog,
  normalizeDnsProviderZoneName,
  type DnsProviderCatalogInput,
  type DnsProviderLineCategory,
} from "../dnsProviderCatalog";
import {
  decryptXraySecret,
  encryptXraySecret,
  fingerprintXraySecret,
  inspectXraySecretEnvelope,
  loadXrayMasterKeyFile,
  xrayDnsProviderAccountSecretContext,
  XraySecretUnavailableError,
  type XrayDnsProviderAccountSecretKind,
  type XraySecretKeyring,
} from "../xraySecretCrypto";
import {
  executeRaw,
  insertAndGetId,
  nowDate,
  queryRaw,
  rawAffectedRows,
  withDatabaseTransaction,
} from "../dbRuntime";
import { withKeyedTaskLock } from "../keyedTaskLock";

export const DNS_PROVIDER_GLOBAL_SCOPE = "XRAY_QUICK_CONFIG" as const;
export const DNS_PROVIDER_CATALOG_TTL_MS = 6 * 60 * 60 * 1_000;
export const DNS_PROVIDER_VERIFICATION_TTL_MS = 24 * 60 * 60 * 1_000;

const FIXED_SECRET_MASK = "••••••••";
const MAX_SAFE_REVISION = Number.MAX_SAFE_INTEGER;
const SECRET_KINDS = ["DNSPOD_SECRET_ID", "DNSPOD_SECRET_KEY"] as const;
const SAFE_LAST_ERROR_CODES = new Set([
  "DNS_PROVIDER_INVALID",
  "DNS_PROVIDER_VALIDATION_STALE",
  "DNS_PROVIDER_CATALOG_STALE",
  "DNS_PROVIDER_LINE_MISSING",
  "DNS_PROVIDER_LINE_AMBIGUOUS",
  "DNS_PROVIDER_NO_ZONES",
]);

type Row = Record<string, unknown>;
export type { DnsProviderCatalogInput, DnsProviderLineCategory } from "../dnsProviderCatalog";
export { computeDnsProviderCatalogRevision } from "../dnsProviderCatalog";
export type DnsProviderVerificationStatus = "UNVERIFIED" | "VALID" | "INVALID" | "ERROR" | "EXPIRED";
export type DnsProviderCatalogStatus = "AVAILABLE" | "STALE" | "REMOVED" | "ERROR";

export const DNS_PROVIDER_REPOSITORY_ERROR_CODES = [
  "DNS_PROVIDER_NOT_CONFIGURED",
  "DNS_PROVIDER_CONFLICT",
  "DNS_PROVIDER_IN_USE",
  "DNS_PROVIDER_INVALID",
  "SENSITIVE_DATA_UNAVAILABLE",
] as const;

export type DnsProviderRepositoryErrorCode = typeof DNS_PROVIDER_REPOSITORY_ERROR_CODES[number];

export class DnsProviderRepositoryError extends Error {
  constructor(readonly code: DnsProviderRepositoryErrorCode) {
    super(code);
    this.name = "DnsProviderRepositoryError";
  }
}

export type DnsProviderGlobalSafeDto =
  | Readonly<{ configured: false; provider: "DNSPOD"; bindingRevision: number }>
  | Readonly<{
      configured: true;
      accountId: number;
      provider: "DNSPOD";
      name: string;
      accountRevision: number;
      bindingRevision: number;
      credentialsConfigured: true;
      secretIdMask: string;
      secretKeyMask: string;
      validationStatus: DnsProviderVerificationStatus;
      verifiedAt: string | null;
      verificationExpiresAt: string | null;
      zonesSyncedAt: string | null;
      zoneCount: number;
      quickConfigReferenceCount: number;
      managedRecordCount: number;
      canRotateCredentials: boolean;
      canRebind: boolean;
      canRemove: boolean;
      lastErrorCode: string | null;
    }>;

export type DnsProviderCarrierLineSafeDto =
  | Readonly<{
      category: typeof DNS_PROVIDER_REQUIRED_CATEGORIES[number];
      status: "AVAILABLE";
      lineId: number;
      providerLineId: string;
      name: string;
    }>
  | Readonly<{
      category: typeof DNS_PROVIDER_REQUIRED_CATEGORIES[number];
      status: "MISSING" | "AMBIGUOUS" | "STALE";
      reasonCode: "DNS_PROVIDER_LINE_MISSING" | "DNS_PROVIDER_LINE_AMBIGUOUS" | "DNS_PROVIDER_CATALOG_STALE";
    }>;

export type DnsProviderZoneSafeDto = Readonly<{
  zoneId: number;
  providerZoneId: string;
  name: string;
  status: DnsProviderCatalogStatus;
  catalogRevision: string;
  expiresAt: string;
  catalogUsable: boolean;
  catalogReasonCode: null | "DNS_PROVIDER_CATALOG_STALE" | "DNS_PROVIDER_LINE_MISSING" | "DNS_PROVIDER_LINE_AMBIGUOUS";
  lines: readonly Readonly<{
    lineId: number;
    providerLineId: string;
    name: string;
    category: DnsProviderLineCategory;
    status: DnsProviderCatalogStatus;
  }>[];
  carrierLines: readonly DnsProviderCarrierLineSafeDto[];
}>;

function repositoryError(error: unknown): never {
  if (error instanceof DnsProviderRepositoryError) throw error;
  if (error instanceof DnsProviderCatalogValidationError) {
    throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
  }
  if (error instanceof XraySecretUnavailableError) {
    throw new DnsProviderRepositoryError("SENSITIVE_DATA_UNAVAILABLE");
  }
  throw error;
}

function positiveSafeInteger(value: unknown, code: DnsProviderRepositoryErrorCode = "DNS_PROVIDER_INVALID"): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new DnsProviderRepositoryError(code);
  return parsed;
}

function nonnegativeSafeInteger(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
  return parsed;
}

function revision(value: unknown): number {
  const parsed = positiveSafeInteger(value, "DNS_PROVIDER_CONFLICT");
  if (parsed >= MAX_SAFE_REVISION) throw new DnsProviderRepositoryError("DNS_PROVIDER_CONFLICT");
  return parsed;
}

function boundedString(value: unknown, maxBytes: number, code: DnsProviderRepositoryErrorCode = "DNS_PROVIDER_INVALID"): string {
  const normalized = String(value ?? "").trim().normalize("NFC");
  if (!normalized || Buffer.byteLength(normalized, "utf8") > maxBytes || /[\u0000-\u001f\u007f]/.test(normalized)) {
    throw new DnsProviderRepositoryError(code);
  }
  return normalized;
}

function secretValue(value: unknown): string {
  if (typeof value !== "string" || value.length < 1 || Buffer.byteLength(value, "utf8") > 4096
    || /[\u0000\r\n]/.test(value)) {
    throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
  }
  return value;
}

function dateFromDatabase(value: unknown): Date | null {
  if (value == null || value === "") return null;
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value : null;
  const numeric = typeof value === "number" ? value : Number(value);
  const parsed = Number.isFinite(numeric)
    ? new Date(numeric < 10_000_000_000 ? numeric * 1_000 : numeric)
    : new Date(String(value));
  return Number.isFinite(parsed.getTime()) ? parsed : null;
}

function isoDate(value: unknown): string | null {
  return dateFromDatabase(value)?.toISOString() ?? null;
}

function databaseBoolean(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || String(value ?? "").toLowerCase() === "true";
}

function verificationStatus(value: unknown): DnsProviderVerificationStatus {
  if (value === "UNVERIFIED" || value === "VALID" || value === "INVALID" || value === "ERROR" || value === "EXPIRED") {
    return value;
  }
  throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
}

function catalogStatus(value: unknown): DnsProviderCatalogStatus {
  if (value === "AVAILABLE" || value === "STALE" || value === "REMOVED" || value === "ERROR") return value;
  throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
}

function lineCategory(value: unknown): DnsProviderLineCategory {
  if (value === "DEFAULT" || value === "TELECOM" || value === "UNICOM" || value === "MOBILE"
    || value === "EDUCATION" || value === "OTHER") return value;
  throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
}

async function globalBindingRow(): Promise<Row> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Row>(
    `SELECT * FROM ${q("dns_provider_global_bindings")} WHERE ${q("scopeKey")} = ? LIMIT 1`,
    [DNS_PROVIDER_GLOBAL_SCOPE],
  );
  if (!rows[0]) throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
  return rows[0];
}

async function globalAccountRow(): Promise<Row | null> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Row>(
    `SELECT a.*, b.${q("revision")} AS ${q("bindingRevision")},
      (SELECT COUNT(*) FROM ${q("dns_provider_account_secrets")} s WHERE s.${q("accountId")} = a.${q("id")}) AS ${q("secretCount")},
      (SELECT COUNT(*) FROM ${q("dns_provider_account_secrets")} s WHERE s.${q("accountId")} = a.${q("id")} AND s.${q("kind")} = 'DNSPOD_SECRET_ID') AS ${q("secretIdCount")},
      (SELECT COUNT(*) FROM ${q("dns_provider_account_secrets")} s WHERE s.${q("accountId")} = a.${q("id")} AND s.${q("kind")} = 'DNSPOD_SECRET_KEY') AS ${q("secretKeyCount")},
      (SELECT COUNT(*) FROM ${q("dns_provider_zones")} z WHERE z.${q("accountId")} = a.${q("id")} AND z.${q("status")} = 'AVAILABLE') AS ${q("zoneCount")},
      (SELECT MAX(z.${q("refreshedAt")}) FROM ${q("dns_provider_zones")} z WHERE z.${q("accountId")} = a.${q("id")}) AS ${q("zonesSyncedAt")},
      (SELECT COUNT(*) FROM ${q("xray_quick_configs")} qc WHERE qc.${q("dnsAccountId")} = a.${q("id")} AND qc.${q("state")} <> 'REMOVED') AS ${q("quickConfigReferenceCount")},
      (SELECT COUNT(*) FROM ${q("xray_quick_config_dns_records")} r WHERE r.${q("dnsAccountId")} = a.${q("id")} AND r.${q("status")} <> 'REMOVED') AS ${q("managedRecordCount")},
      (SELECT COUNT(*) FROM ${q("xray_quick_config_operations")} o
        JOIN ${q("xray_quick_configs")} qc ON qc.${q("id")} = o.${q("quickConfigId")}
        WHERE qc.${q("dnsAccountId")} = a.${q("id")} AND o.${q("status")} IN ('QUEUED', 'RUNNING', 'COMPENSATING')) AS ${q("activeOperationCount")},
      (SELECT COUNT(*) FROM ${q("xray_quick_configs")} qc WHERE qc.${q("dnsAccountId")} = a.${q("id")})
        + (SELECT COUNT(*) FROM ${q("xray_quick_config_dns_records")} r WHERE r.${q("dnsAccountId")} = a.${q("id")})
        + (SELECT COUNT(*) FROM ${q("xray_quick_config_operations")} o
          JOIN ${q("xray_quick_configs")} qc ON qc.${q("id")} = o.${q("quickConfigId")}
          WHERE qc.${q("dnsAccountId")} = a.${q("id")}) AS ${q("historicalReferenceCount")}
    FROM ${q("dns_provider_global_bindings")} b
    JOIN ${q("dns_provider_accounts")} a ON a.${q("id")} = b.${q("accountId")}
    WHERE b.${q("scopeKey")} = ? LIMIT 1`,
    [DNS_PROVIDER_GLOBAL_SCOPE],
  );
  return rows[0] ?? null;
}

function safeAccountDto(row: Row): DnsProviderGlobalSafeDto {
  const accountId = positiveSafeInteger(row.id);
  const accountRevision = positiveSafeInteger(row.revision);
  const bindingRevision = positiveSafeInteger(row.bindingRevision);
  if (row.provider !== "DNSPOD" || databaseBoolean(row.isDisabled) || Number(row.secretCount) !== 2
    || Number(row.secretIdCount) !== 1 || Number(row.secretKeyCount) !== 1) {
    throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
  }
  const storedValidationStatus = verificationStatus(row.verificationStatus);
  const verificationExpiresAt = dateFromDatabase(row.verificationExpiresAt);
  if (storedValidationStatus === "VALID" && !verificationExpiresAt) {
    throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
  }
  const validationStatus = storedValidationStatus === "VALID"
    && verificationExpiresAt!.getTime() <= Date.now()
    ? "EXPIRED"
    : storedValidationStatus;
  const quickConfigReferenceCount = nonnegativeSafeInteger(row.quickConfigReferenceCount ?? 0);
  const managedRecordCount = nonnegativeSafeInteger(row.managedRecordCount ?? 0);
  const activeOperationCount = nonnegativeSafeInteger(row.activeOperationCount ?? 0);
  const inUse = quickConfigReferenceCount > 0 || managedRecordCount > 0 || activeOperationCount > 0;
  const historicalReferenceCount = nonnegativeSafeInteger(row.historicalReferenceCount ?? 0);
  const lastErrorCode = row.lastErrorCode == null ? null : String(row.lastErrorCode);
  if (lastErrorCode !== null && !SAFE_LAST_ERROR_CODES.has(lastErrorCode)) {
    throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
  }
  return {
    configured: true,
    accountId,
    provider: "DNSPOD",
    name: boundedString(row.name, 128),
    accountRevision,
    bindingRevision,
    credentialsConfigured: true,
    secretIdMask: FIXED_SECRET_MASK,
    secretKeyMask: FIXED_SECRET_MASK,
    validationStatus,
    verifiedAt: isoDate(row.verifiedAt),
    verificationExpiresAt: verificationExpiresAt?.toISOString() ?? null,
    zonesSyncedAt: isoDate(row.zonesSyncedAt),
    zoneCount: nonnegativeSafeInteger(row.zoneCount ?? 0),
    quickConfigReferenceCount,
    managedRecordCount,
    canRotateCredentials: !inUse,
    canRebind: !inUse && historicalReferenceCount === 0,
    canRemove: !inUse && historicalReferenceCount === 0,
    lastErrorCode,
  };
}

function validationDate(value: unknown): Date {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
  }
  return new Date(value);
}

async function assertCurrentGlobalAccount(input: {
  expectedBindingRevision: number;
  expectedAccountRevision: number;
}): Promise<{ accountId: number; bindingId: number }> {
  const binding = await globalBindingRow();
  if (revision(binding.revision) !== input.expectedBindingRevision || binding.accountId == null) {
    throw new DnsProviderRepositoryError("DNS_PROVIDER_CONFLICT");
  }
  const accountId = positiveSafeInteger(binding.accountId);
  const q = quoteIdentifier;
  const accounts = await queryRaw<Row>(
    `SELECT * FROM ${q("dns_provider_accounts")} WHERE ${q("id")} = ? LIMIT 1`,
    [accountId],
  );
  const account = accounts[0];
  if (!account || account.provider !== "DNSPOD"
    || positiveSafeInteger(account.revision) !== input.expectedAccountRevision) {
    throw new DnsProviderRepositoryError("DNS_PROVIDER_CONFLICT");
  }
  return { accountId, bindingId: positiveSafeInteger(binding.id) };
}

export async function getGlobalDnsProviderAccount(): Promise<DnsProviderGlobalSafeDto> {
  try {
    const row = await globalAccountRow();
    if (row) return safeAccountDto(row);
    const binding = await globalBindingRow();
    if (binding.accountId != null) throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
    return { configured: false, provider: "DNSPOD", bindingRevision: positiveSafeInteger(binding.revision) };
  } catch (error) {
    repositoryError(error);
  }
}

async function insertSecretRows(input: {
  accountId: number;
  accountTag: string;
  secretId: string;
  secretKey: string;
  keyring: XraySecretKeyring;
  now: Date;
}): Promise<void> {
  const values = new Map<XrayDnsProviderAccountSecretKind, string>([
    ["DNSPOD_SECRET_ID", input.secretId],
    ["DNSPOD_SECRET_KEY", input.secretKey],
  ]);
  for (const kind of SECRET_KINDS) {
    const value = values.get(kind);
    if (!value) throw new DnsProviderRepositoryError("SENSITIVE_DATA_UNAVAILABLE");
    const context = xrayDnsProviderAccountSecretContext(input.accountTag, kind);
    const encryptedValue = encryptXraySecret(value, context, input.keyring);
    await insertAndGetId("dns_provider_account_secrets", {
      accountId: input.accountId,
      kind,
      encryptedValue,
      fingerprint: fingerprintXraySecret(value, context, input.keyring),
      keyVersion: inspectXraySecretEnvelope(encryptedValue).version,
      createdAt: input.now,
      updatedAt: input.now,
    });
  }
}

async function replaceCatalog(input: {
  accountId: number;
  zones: ReturnType<typeof normalizeDnsProviderCatalog>;
  catalogRevision: string;
  refreshedAt: Date;
}): Promise<void> {
  const q = quoteIdentifier;
  const expiresAt = new Date(input.refreshedAt.getTime() + DNS_PROVIDER_CATALOG_TTL_MS);
  const existingZones = await queryRaw<Row>(
    `SELECT * FROM ${q("dns_provider_zones")} WHERE ${q("accountId")} = ?`,
    [input.accountId],
  );
  const existingLines = await queryRaw<Row>(
    `SELECT l.* FROM ${q("dns_provider_record_lines")} l
      JOIN ${q("dns_provider_zones")} z ON z.${q("id")} = l.${q("zoneId")}
      WHERE z.${q("accountId")} = ?`,
    [input.accountId],
  );
  const zonesByProviderId = new Map(existingZones.map((zone) => [String(zone.providerZoneId), zone]));
  const zonesByName = new Map(existingZones.map((zone) => [String(zone.name), zone]));
  const linesByZone = new Map<number, Row[]>();
  for (const line of existingLines) {
    const zoneId = positiveSafeInteger(line.zoneId);
    const mappedCategory = classifyDnsProviderLineName(line.name);
    if (lineCategory(line.category) !== mappedCategory) {
      await executeRaw(
        `UPDATE ${q("dns_provider_record_lines")} SET ${q("category")} = ?, ${q("updatedAt")} = ? WHERE ${q("id")} = ?`,
        [mappedCategory, input.refreshedAt, positiveSafeInteger(line.id)],
      );
      line.category = mappedCategory;
    }
    const rows = linesByZone.get(zoneId) ?? [];
    rows.push(line);
    linesByZone.set(zoneId, rows);
  }
  const seenZoneIds = new Set<number>();

  for (const zone of input.zones) {
    const byProviderId = zonesByProviderId.get(zone.providerZoneId);
    const byName = zonesByName.get(zone.name);
    if (byProviderId && byName && positiveSafeInteger(byProviderId.id) !== positiveSafeInteger(byName.id)) {
      throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
    }
    const existingZone = byProviderId ?? byName;
    const zoneId = existingZone
      ? positiveSafeInteger(existingZone.id)
      : await insertAndGetId("dns_provider_zones", {
        accountId: input.accountId,
        providerZoneId: zone.providerZoneId,
        name: zone.name,
        status: zone.status,
        catalogRevision: input.catalogRevision,
        refreshedAt: input.refreshedAt,
        expiresAt,
        lastSeenAt: input.refreshedAt,
        createdAt: input.refreshedAt,
        updatedAt: input.refreshedAt,
      });
    if (existingZone) {
      await executeRaw(
        `UPDATE ${q("dns_provider_zones")} SET ${q("providerZoneId")} = ?, ${q("name")} = ?, ${q("status")} = 'AVAILABLE', ${q("catalogRevision")} = ?, ${q("refreshedAt")} = ?, ${q("expiresAt")} = ?, ${q("lastSeenAt")} = ?, ${q("updatedAt")} = ? WHERE ${q("id")} = ?`,
        [zone.providerZoneId, zone.name, input.catalogRevision, input.refreshedAt, expiresAt,
          input.refreshedAt, input.refreshedAt, zoneId],
      );
    }
    seenZoneIds.add(zoneId);

    const priorLines = linesByZone.get(zoneId) ?? [];
    const linesByProviderId = new Map(priorLines.map((line) => [String(line.providerLineId), line]));
    const seenLineIds = new Set<number>();
    for (const line of zone.lines) {
      const existingLine = linesByProviderId.get(line.providerLineId);
      if (existingLine) {
        const lineId = positiveSafeInteger(existingLine.id);
        await executeRaw(
          `UPDATE ${q("dns_provider_record_lines")} SET ${q("name")} = ?, ${q("category")} = ?, ${q("status")} = 'AVAILABLE', ${q("catalogRevision")} = ?, ${q("refreshedAt")} = ?, ${q("expiresAt")} = ?, ${q("lastSeenAt")} = ?, ${q("updatedAt")} = ? WHERE ${q("id")} = ?`,
          [line.name, line.category, input.catalogRevision, input.refreshedAt, expiresAt,
            input.refreshedAt, input.refreshedAt, lineId],
        );
        seenLineIds.add(lineId);
      } else {
        const lineId = await insertAndGetId("dns_provider_record_lines", {
          zoneId,
          providerLineId: line.providerLineId,
          name: line.name,
          category: line.category,
          status: line.status,
          catalogRevision: input.catalogRevision,
          refreshedAt: input.refreshedAt,
          expiresAt,
          lastSeenAt: input.refreshedAt,
          createdAt: input.refreshedAt,
          updatedAt: input.refreshedAt,
        });
        seenLineIds.add(lineId);
      }
    }
    for (const line of priorLines) {
      const lineId = positiveSafeInteger(line.id);
      if (seenLineIds.has(lineId)) continue;
      await executeRaw(
        `UPDATE ${q("dns_provider_record_lines")} SET ${q("status")} = 'REMOVED', ${q("catalogRevision")} = ?, ${q("refreshedAt")} = ?, ${q("expiresAt")} = ?, ${q("updatedAt")} = ? WHERE ${q("id")} = ?`,
        [input.catalogRevision, input.refreshedAt, expiresAt, input.refreshedAt, lineId],
      );
    }
  }

  for (const zone of existingZones) {
    const zoneId = positiveSafeInteger(zone.id);
    if (seenZoneIds.has(zoneId)) continue;
    await executeRaw(
      `UPDATE ${q("dns_provider_zones")} SET ${q("status")} = 'REMOVED', ${q("catalogRevision")} = ?, ${q("refreshedAt")} = ?, ${q("expiresAt")} = ?, ${q("updatedAt")} = ? WHERE ${q("id")} = ?`,
      [input.catalogRevision, input.refreshedAt, expiresAt, input.refreshedAt, zoneId],
    );
    await executeRaw(
      `UPDATE ${q("dns_provider_record_lines")} SET ${q("status")} = 'REMOVED', ${q("catalogRevision")} = ?, ${q("refreshedAt")} = ?, ${q("expiresAt")} = ?, ${q("updatedAt")} = ? WHERE ${q("zoneId")} = ?`,
      [input.catalogRevision, input.refreshedAt, expiresAt, input.refreshedAt, zoneId],
    );
  }

  const storedZones = await queryRaw<Row>(
    `SELECT * FROM ${q("dns_provider_zones")} WHERE ${q("accountId")} = ?`,
    [input.accountId],
  );
  const storedLines = await queryRaw<Row>(
    `SELECT l.* FROM ${q("dns_provider_record_lines")} l
      JOIN ${q("dns_provider_zones")} z ON z.${q("id")} = l.${q("zoneId")}
      WHERE z.${q("accountId")} = ?`,
    [input.accountId],
  );
  const storedLinesByZone = new Map<number, Row[]>();
  for (const line of storedLines) {
    const zoneId = positiveSafeInteger(line.zoneId);
    const rows = storedLinesByZone.get(zoneId) ?? [];
    rows.push(line);
    storedLinesByZone.set(zoneId, rows);
  }
  const catalogRevision = computeStoredDnsProviderCatalogRevision(storedZones.map((zone) => ({
    providerZoneId: boundedString(zone.providerZoneId, 128),
    name: normalizeDnsProviderZoneName(zone.name),
    status: catalogStatus(zone.status),
    lines: (storedLinesByZone.get(positiveSafeInteger(zone.id)) ?? []).map((line) => ({
      providerLineId: boundedString(line.providerLineId, 128),
      name: boundedString(line.name, 128),
      status: catalogStatus(line.status),
      category: lineCategory(line.category),
    })),
  })));
  await executeRaw(
    `UPDATE ${q("dns_provider_zones")} SET ${q("catalogRevision")} = ? WHERE ${q("accountId")} = ?`,
    [catalogRevision, input.accountId],
  );
  for (const zone of storedZones) {
    await executeRaw(
      `UPDATE ${q("dns_provider_record_lines")} SET ${q("catalogRevision")} = ? WHERE ${q("zoneId")} = ?`,
      [catalogRevision, positiveSafeInteger(zone.id)],
    );
  }
}

export async function saveVerifiedGlobalDnsProviderAccount(input: {
  expectedBindingRevision: unknown;
  expectedAccountRevision: unknown | null;
  name: unknown;
  secretId: unknown;
  secretKey: unknown;
  createdByUserId: unknown;
  verifiedAt: Date;
  zones: readonly DnsProviderCatalogInput[];
}, options: { keyring?: XraySecretKeyring } = {}): Promise<DnsProviderGlobalSafeDto> {
  try {
    const expectedBindingRevision = revision(input.expectedBindingRevision);
    const expectedAccountRevision = input.expectedAccountRevision == null ? null : revision(input.expectedAccountRevision);
    const name = boundedString(input.name, 128);
    const secretId = secretValue(input.secretId);
    const secretKey = secretValue(input.secretKey);
    const createdByUserId = positiveSafeInteger(input.createdByUserId);
    const verifiedAt = input.verifiedAt instanceof Date && Number.isFinite(input.verifiedAt.getTime())
      ? new Date(input.verifiedAt)
      : (() => { throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID"); })();
    const zones = normalizeDnsProviderCatalog(input.zones);
    const catalogRevision = computeDnsProviderCatalogRevision(input.zones);
    const keyring = options.keyring ?? loadXrayMasterKeyFile();

    return await withKeyedTaskLock("dns-provider-global", async () => {
      await withDatabaseTransaction(async () => {
        const binding = await globalBindingRow();
        const bindingRevision = revision(binding.revision);
        if (bindingRevision !== expectedBindingRevision) throw new DnsProviderRepositoryError("DNS_PROVIDER_CONFLICT");
        const existingAccountId = binding.accountId == null ? null : positiveSafeInteger(binding.accountId);
        if ((existingAccountId === null) !== (expectedAccountRevision === null)) {
          throw new DnsProviderRepositoryError("DNS_PROVIDER_CONFLICT");
        }

        const q = quoteIdentifier;
        const now = nowDate();
        const verificationExpiresAt = new Date(verifiedAt.getTime() + DNS_PROVIDER_VERIFICATION_TTL_MS);
        let accountId: number;
        let accountTag: string;
        if (existingAccountId === null) {
          accountTag = `forwardx-dns-account-${crypto.randomUUID()}`;
          accountId = await insertAndGetId("dns_provider_accounts", {
            accountTag,
            provider: "DNSPOD",
            name,
            revision: 1,
            isDisabled: false,
            verificationStatus: "VALID",
            lastErrorCode: null,
            lastValidationAttemptAt: verifiedAt,
            verifiedAt,
            verificationExpiresAt,
            createdByUserId,
            createdAt: now,
            updatedAt: now,
          });
        } else {
          const rows = await queryRaw<Row>(
            `SELECT * FROM ${q("dns_provider_accounts")} WHERE ${q("id")} = ? LIMIT 1`,
            [existingAccountId],
          );
          const account = rows[0];
          if (!account || positiveSafeInteger(account.revision) !== expectedAccountRevision || account.provider !== "DNSPOD") {
            throw new DnsProviderRepositoryError("DNS_PROVIDER_CONFLICT");
          }
          accountId = existingAccountId;
          accountTag = boundedString(account.accountTag, 128);
          const updated = await executeRaw(
            `UPDATE ${q("dns_provider_accounts")} SET ${q("name")} = ?, ${q("revision")} = ${q("revision")} + 1, ${q("isDisabled")} = ?, ${q("verificationStatus")} = 'VALID', ${q("lastErrorCode")} = NULL, ${q("lastValidationAttemptAt")} = ?, ${q("verifiedAt")} = ?, ${q("verificationExpiresAt")} = ?, ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("revision")} = ?`,
            [name, false, verifiedAt, verifiedAt, verificationExpiresAt, now, accountId, expectedAccountRevision],
          );
          if (rawAffectedRows(updated) !== 1) throw new DnsProviderRepositoryError("DNS_PROVIDER_CONFLICT");
          await executeRaw(`DELETE FROM ${q("dns_provider_account_secrets")} WHERE ${q("accountId")} = ?`, [accountId]);
        }

        await insertSecretRows({ accountId, accountTag, secretId, secretKey, keyring, now });
        await replaceCatalog({ accountId, zones, catalogRevision, refreshedAt: verifiedAt });
        const bindingUpdated = await executeRaw(
          `UPDATE ${q("dns_provider_global_bindings")} SET ${q("accountId")} = ?, ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("revision")} = ?`,
          [accountId, now, positiveSafeInteger(binding.id), expectedBindingRevision],
        );
        if (rawAffectedRows(bindingUpdated) !== 1) throw new DnsProviderRepositoryError("DNS_PROVIDER_CONFLICT");
      });
      return getGlobalDnsProviderAccount();
    });
  } catch (error) {
    repositoryError(error);
  }
}

export async function refreshVerifiedGlobalDnsProviderAccount(input: {
  expectedBindingRevision: unknown;
  expectedAccountRevision: unknown;
  verifiedAt: Date;
  zones: readonly DnsProviderCatalogInput[];
}): Promise<DnsProviderGlobalSafeDto> {
  try {
    const expectedBindingRevision = revision(input.expectedBindingRevision);
    const expectedAccountRevision = revision(input.expectedAccountRevision);
    const verifiedAt = validationDate(input.verifiedAt);
    const zones = normalizeDnsProviderCatalog(input.zones);
    const catalogRevision = computeDnsProviderCatalogRevision(input.zones);

    return await withKeyedTaskLock("dns-provider-global", async () => {
      await withDatabaseTransaction(async () => {
        const { accountId } = await assertCurrentGlobalAccount({
          expectedBindingRevision,
          expectedAccountRevision,
        });
        await replaceCatalog({ accountId, zones, catalogRevision, refreshedAt: verifiedAt });
        const q = quoteIdentifier;
        const now = nowDate();
        const verificationExpiresAt = new Date(verifiedAt.getTime() + DNS_PROVIDER_VERIFICATION_TTL_MS);
        const updated = await executeRaw(
          `UPDATE ${q("dns_provider_accounts")} SET ${q("revision")} = ${q("revision")} + 1, ${q("verificationStatus")} = 'VALID', ${q("lastErrorCode")} = NULL, ${q("lastValidationAttemptAt")} = ?, ${q("verifiedAt")} = ?, ${q("verificationExpiresAt")} = ?, ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("revision")} = ?`,
          [verifiedAt, verifiedAt, verificationExpiresAt, now, accountId, expectedAccountRevision],
        );
        if (rawAffectedRows(updated) !== 1) throw new DnsProviderRepositoryError("DNS_PROVIDER_CONFLICT");
      });
      return getGlobalDnsProviderAccount();
    });
  } catch (error) {
    repositoryError(error);
  }
}

export async function refreshGlobalDnsProviderCatalog(input: {
  expectedBindingRevision: unknown;
  expectedAccountRevision: unknown;
  refreshedAt: Date;
  zones: readonly DnsProviderCatalogInput[];
}): Promise<void> {
  try {
    const expectedBindingRevision = revision(input.expectedBindingRevision);
    const expectedAccountRevision = revision(input.expectedAccountRevision);
    const refreshedAt = validationDate(input.refreshedAt);
    const zones = normalizeDnsProviderCatalog(input.zones);
    const catalogRevision = computeDnsProviderCatalogRevision(input.zones);
    await withKeyedTaskLock("dns-provider-global", async () => {
      await withDatabaseTransaction(async () => {
        const { accountId } = await assertCurrentGlobalAccount({
          expectedBindingRevision,
          expectedAccountRevision,
        });
        await replaceCatalog({ accountId, zones, catalogRevision, refreshedAt });
      });
    });
  } catch (error) {
    repositoryError(error);
  }
}

export async function markGlobalDnsProviderValidationFailed(input: {
  expectedBindingRevision: unknown;
  expectedAccountRevision: unknown;
  status: "INVALID" | "ERROR";
  errorCode: unknown;
  attemptedAt: Date;
}): Promise<DnsProviderGlobalSafeDto> {
  try {
    const expectedBindingRevision = revision(input.expectedBindingRevision);
    const expectedAccountRevision = revision(input.expectedAccountRevision);
    const attemptedAt = validationDate(input.attemptedAt);
    const errorCode = boundedString(input.errorCode, 64);
    if (input.status !== "INVALID" && input.status !== "ERROR") {
      throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
    }

    return await withKeyedTaskLock("dns-provider-global", async () => {
      await withDatabaseTransaction(async () => {
        const { accountId } = await assertCurrentGlobalAccount({
          expectedBindingRevision,
          expectedAccountRevision,
        });
        const q = quoteIdentifier;
        const updated = await executeRaw(
          `UPDATE ${q("dns_provider_accounts")} SET ${q("revision")} = ${q("revision")} + 1, ${q("verificationStatus")} = ?, ${q("lastErrorCode")} = ?, ${q("lastValidationAttemptAt")} = ?, ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("revision")} = ?`,
          [input.status, errorCode, attemptedAt, nowDate(), accountId, expectedAccountRevision],
        );
        if (rawAffectedRows(updated) !== 1) throw new DnsProviderRepositoryError("DNS_PROVIDER_CONFLICT");
      });
      return getGlobalDnsProviderAccount();
    });
  } catch (error) {
    repositoryError(error);
  }
}

export async function removeGlobalDnsProviderAccountRecord(input: {
  expectedBindingRevision: unknown;
  expectedAccountRevision: unknown;
  confirmName: unknown;
}): Promise<DnsProviderGlobalSafeDto> {
  try {
    const expectedBindingRevision = revision(input.expectedBindingRevision);
    const expectedAccountRevision = revision(input.expectedAccountRevision);
    if (typeof input.confirmName !== "string" || input.confirmName.length < 1
      || Buffer.byteLength(input.confirmName, "utf8") > 128 || /[\u0000-\u001f\u007f]/.test(input.confirmName)) {
      throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
    }

    return await withKeyedTaskLock("dns-provider-global", async () => {
      await withDatabaseTransaction(async () => {
        const { accountId, bindingId } = await assertCurrentGlobalAccount({
          expectedBindingRevision,
          expectedAccountRevision,
        });
        const q = quoteIdentifier;
        const accounts = await queryRaw<Row>(
          `SELECT ${q("name")} FROM ${q("dns_provider_accounts")} WHERE ${q("id")} = ? LIMIT 1`,
          [accountId],
        );
        if (!accounts[0] || String(accounts[0].name) !== input.confirmName) {
          throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
        }
        const counts = await queryRaw<Row>(
          `SELECT
            (SELECT COUNT(*) FROM ${q("xray_quick_configs")} qc WHERE qc.${q("dnsAccountId")} = ?) AS ${q("quickConfigCount")},
            (SELECT COUNT(*) FROM ${q("xray_quick_config_dns_records")} r WHERE r.${q("dnsAccountId")} = ?) AS ${q("managedRecordCount")},
            (SELECT COUNT(*) FROM ${q("xray_quick_config_operations")} o
              JOIN ${q("xray_quick_configs")} qc ON qc.${q("id")} = o.${q("quickConfigId")}
              WHERE qc.${q("dnsAccountId")} = ?) AS ${q("operationCount")}`,
          [accountId, accountId, accountId],
        );
        const usage = counts[0];
        if (!usage || nonnegativeSafeInteger(usage.quickConfigCount) > 0
          || nonnegativeSafeInteger(usage.managedRecordCount) > 0
          || nonnegativeSafeInteger(usage.operationCount) > 0) {
          throw new DnsProviderRepositoryError("DNS_PROVIDER_IN_USE");
        }

        const now = nowDate();
        const bindingUpdated = await executeRaw(
          `UPDATE ${q("dns_provider_global_bindings")} SET ${q("accountId")} = NULL, ${q("revision")} = ${q("revision")} + 1, ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("accountId")} = ? AND ${q("revision")} = ?`,
          [now, bindingId, accountId, expectedBindingRevision],
        );
        if (rawAffectedRows(bindingUpdated) !== 1) throw new DnsProviderRepositoryError("DNS_PROVIDER_CONFLICT");

        const zoneRows = await queryRaw<Row>(
          `SELECT ${q("id")} FROM ${q("dns_provider_zones")} WHERE ${q("accountId")} = ?`,
          [accountId],
        );
        for (const zone of zoneRows) {
          await executeRaw(
            `DELETE FROM ${q("dns_provider_record_lines")} WHERE ${q("zoneId")} = ?`,
            [positiveSafeInteger(zone.id)],
          );
        }
        await executeRaw(`DELETE FROM ${q("dns_provider_zones")} WHERE ${q("accountId")} = ?`, [accountId]);
        await executeRaw(`DELETE FROM ${q("dns_provider_account_secrets")} WHERE ${q("accountId")} = ?`, [accountId]);
        await executeRaw(`DELETE FROM ${q("dns_provider_accounts")} WHERE ${q("id")} = ?`, [accountId]);
      });
      return getGlobalDnsProviderAccount();
    });
  } catch (error) {
    repositoryError(error);
  }
}

function secureFingerprintEqual(actual: unknown, expected: string): boolean {
  if (typeof actual !== "string" || !/^[a-f0-9]{64}$/.test(actual) || !/^[a-f0-9]{64}$/.test(expected)) return false;
  return crypto.timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
}

export async function loadGlobalDnsProviderCredentials(options: { keyring?: XraySecretKeyring } = {}): Promise<{
  accountId: number;
  accountRevision: number;
  bindingRevision: number;
  secretId: string;
  secretKey: string;
}> {
  try {
    const row = await globalAccountRow();
    if (!row) {
      const binding = await globalBindingRow();
      if (binding.accountId != null) throw new DnsProviderRepositoryError("SENSITIVE_DATA_UNAVAILABLE");
      throw new DnsProviderRepositoryError("DNS_PROVIDER_NOT_CONFIGURED");
    }
    const accountId = positiveSafeInteger(row.id);
    const accountRevision = positiveSafeInteger(row.revision);
    const bindingRevision = positiveSafeInteger(row.bindingRevision);
    const accountTag = boundedString(row.accountTag, 128);
    const keyring = options.keyring ?? loadXrayMasterKeyFile();
    const q = quoteIdentifier;
    const secretRows = await queryRaw<Row>(
      `SELECT * FROM ${q("dns_provider_account_secrets")} WHERE ${q("accountId")} = ? ORDER BY ${q("kind")} ASC`,
      [accountId],
    );
    if (secretRows.length !== SECRET_KINDS.length) throw new DnsProviderRepositoryError("SENSITIVE_DATA_UNAVAILABLE");
    const values = new Map<XrayDnsProviderAccountSecretKind, string>();
    for (const secret of secretRows) {
      const kind = String(secret.kind) as XrayDnsProviderAccountSecretKind;
      if (!SECRET_KINDS.includes(kind) || values.has(kind) || Number(secret.keyVersion) !== 1) {
        throw new DnsProviderRepositoryError("SENSITIVE_DATA_UNAVAILABLE");
      }
      const context = xrayDnsProviderAccountSecretContext(accountTag, kind);
      const envelope = String(secret.encryptedValue ?? "");
      if (inspectXraySecretEnvelope(envelope).version !== 1) {
        throw new DnsProviderRepositoryError("SENSITIVE_DATA_UNAVAILABLE");
      }
      const value = decryptXraySecret(envelope, context, keyring);
      const fingerprint = fingerprintXraySecret(value, context, keyring);
      if (!secureFingerprintEqual(secret.fingerprint, fingerprint)) {
        throw new DnsProviderRepositoryError("SENSITIVE_DATA_UNAVAILABLE");
      }
      values.set(kind, value);
    }
    const secretId = values.get("DNSPOD_SECRET_ID");
    const secretKey = values.get("DNSPOD_SECRET_KEY");
    if (!secretId || !secretKey) throw new DnsProviderRepositoryError("SENSITIVE_DATA_UNAVAILABLE");
    return { accountId, accountRevision, bindingRevision, secretId, secretKey };
  } catch (error) {
    repositoryError(error);
  }
}

export async function listGlobalDnsProviderZones(now = new Date()): Promise<DnsProviderZoneSafeDto[]> {
  try {
    if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
    const account = await globalAccountRow();
    if (!account) throw new DnsProviderRepositoryError("DNS_PROVIDER_NOT_CONFIGURED");
    const accountId = positiveSafeInteger(account.id);
    const q = quoteIdentifier;
    const zones = await queryRaw<Row>(
      `SELECT * FROM ${q("dns_provider_zones")} WHERE ${q("accountId")} = ? ORDER BY ${q("name")} ASC, ${q("id")} ASC`,
      [accountId],
    );
    const allLines = await queryRaw<Row>(
      `SELECT l.* FROM ${q("dns_provider_record_lines")} l
        JOIN ${q("dns_provider_zones")} z ON z.${q("id")} = l.${q("zoneId")}
        WHERE z.${q("accountId")} = ? ORDER BY l.${q("providerLineId")} ASC, l.${q("id")} ASC`,
      [accountId],
    );
    const linesByZone = new Map<number, Row[]>();
    for (const row of allLines) {
      const zoneId = positiveSafeInteger(row.zoneId);
      if (catalogStatus(row.status) === "AVAILABLE"
        && lineCategory(row.category) !== classifyDnsProviderLineName(row.name)) {
        throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
      }
      const entries = linesByZone.get(zoneId) ?? [];
      entries.push(row);
      linesByZone.set(zoneId, entries);
    }
    if (zones.length > 0) {
      const expectedRevision = computeStoredDnsProviderCatalogRevision(zones.map((zone) => {
        const zoneId = positiveSafeInteger(zone.id);
        return {
          providerZoneId: boundedString(zone.providerZoneId, 128),
          name: normalizeDnsProviderZoneName(zone.name),
          status: catalogStatus(zone.status),
          lines: (linesByZone.get(zoneId) ?? []).map((line) => ({
            providerLineId: boundedString(line.providerLineId, 128),
            name: boundedString(line.name, 128),
            status: catalogStatus(line.status),
            category: lineCategory(line.category),
          })),
        };
      }));
      if ([...zones, ...allLines].some((row) => String(row.catalogRevision ?? "") !== expectedRevision)) {
        throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
      }
    }
    const output: DnsProviderZoneSafeDto[] = [];
    for (const zone of zones) {
      const zoneId = positiveSafeInteger(zone.id);
      const rows = linesByZone.get(zoneId) ?? [];
      const expiresAt = dateFromDatabase(zone.expiresAt);
      if (!expiresAt) throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
      const stale = expiresAt.getTime() <= now.getTime()
        || catalogStatus(zone.status) !== "AVAILABLE"
        || rows.some((row) => {
          const lineExpiresAt = dateFromDatabase(row.expiresAt);
          if (!lineExpiresAt) throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
          return lineExpiresAt.getTime() <= now.getTime();
        });
      const lines = rows.map((row) => ({
        lineId: positiveSafeInteger(row.id),
        providerLineId: boundedString(row.providerLineId, 128),
        name: boundedString(row.name, 128),
        category: lineCategory(row.category),
        status: catalogStatus(row.status),
      }));
      const carrierLines: DnsProviderCarrierLineSafeDto[] = DNS_PROVIDER_REQUIRED_CATEGORIES.map((category) => {
        if (stale) return { category, status: "STALE", reasonCode: "DNS_PROVIDER_CATALOG_STALE" } as const;
        const matching = lines.filter((line) => line.category === category && line.status === "AVAILABLE");
        if (matching.length === 0) return { category, status: "MISSING", reasonCode: "DNS_PROVIDER_LINE_MISSING" } as const;
        if (matching.length > 1) return { category, status: "AMBIGUOUS", reasonCode: "DNS_PROVIDER_LINE_AMBIGUOUS" } as const;
        const line = matching[0];
        return { category, status: "AVAILABLE", lineId: line.lineId, providerLineId: line.providerLineId, name: line.name } as const;
      });
      const firstUnavailable = carrierLines.find((line) => line.status !== "AVAILABLE");
      output.push({
        zoneId,
        providerZoneId: boundedString(zone.providerZoneId, 128),
        name: normalizeDnsProviderZoneName(zone.name),
        status: catalogStatus(zone.status),
        catalogRevision: (() => {
          const value = String(zone.catalogRevision ?? "");
          if (!/^[a-f0-9]{64}$/.test(value)) throw new DnsProviderRepositoryError("DNS_PROVIDER_INVALID");
          return value;
        })(),
        expiresAt: expiresAt.toISOString(),
        catalogUsable: !firstUnavailable,
        catalogReasonCode: firstUnavailable?.reasonCode ?? null,
        lines,
        carrierLines,
      });
    }
    return output;
  } catch (error) {
    repositoryError(error);
  }
}
