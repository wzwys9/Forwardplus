import { createHash } from "node:crypto";
import { isIP } from "node:net";

import { normalizeDnsProviderZoneName } from "./dnsProviderCatalog";
import { listDnsProviderUsedNames } from "./dnsProviderSubdomainUsage";
import {
  DnsPodProviderClient,
  DnsPodProviderError,
  type DnsPodCredentials,
  type DnsPodRecord,
  type DnsPodRecordLine,
  type DnsPodRecordWriteInput,
  type DnsPodZone,
} from "./dnsPodProviderClient";
import { withKeyedTaskLock } from "./keyedTaskLock";
import {
  DnsProviderRepositoryError,
  getGlobalDnsProviderAccount,
  listGlobalDnsProviderZones,
  loadGlobalDnsProviderCredentials,
  type DnsProviderZoneSafeDto,
} from "./repositories/dnsProviderRepository";
import type { XraySecretKeyring } from "./xraySecretCrypto";

const WRITABLE_RECORD_TYPES = ["A", "AAAA", "CNAME"] as const;
type WritableRecordType = typeof WRITABLE_RECORD_TYPES[number];

export type DnsProviderRecordServiceErrorCode =
  | "DNS_PROVIDER_NOT_CONFIGURED"
  | "DNS_PROVIDER_VALIDATION_STALE"
  | "DNS_PROVIDER_CATALOG_STALE"
  | "DNS_PROVIDER_INVALID"
  | "DNS_PROVIDER_UNAVAILABLE"
  | "DNS_PROVIDER_REQUEST_REJECTED"
  | "DNS_PROVIDER_INVALID_RESPONSE"
  | "DNS_ZONE_NOT_FOUND"
  | "DNS_ZONE_IN_USE"
  | "DNS_SUBDOMAIN_IN_USE"
  | "DNS_RECORD_NOT_FOUND"
  | "DNS_RECORD_CHANGED"
  | "DNS_WRITE_UNCERTAIN"
  | "SENSITIVE_DATA_UNAVAILABLE";

export class DnsProviderRecordServiceError extends Error {
  constructor(readonly code: DnsProviderRecordServiceErrorCode) {
    super(code);
    this.name = "DnsProviderRecordServiceError";
  }
}

type DnsRecordClient = Pick<
  DnsPodProviderClient,
  "listRecords" | "getRecord" | "createRecord" | "updateRecord" | "deleteRecord"
>;

export type DnsProviderRecordServiceOptions = Readonly<{
  clientFactory?: (credentials: DnsPodCredentials) => DnsRecordClient;
  keyring?: XraySecretKeyring;
}>;

export type DnsProviderRecordSafeDto = Readonly<{
  providerRecordId: string;
  subdomain: string;
  fqdn: string;
  recordType: string;
  providerLineId: string;
  lineName: string;
  value: string;
  ttl: number;
  status: string | null;
  recordRevision: string;
  inUse: boolean;
}>;

type ZoneContext = Readonly<{
  accountId: number;
  zone: DnsProviderZoneSafeDto;
  providerZone: DnsPodZone;
  credentials: DnsPodCredentials;
}>;

function fail(code: DnsProviderRecordServiceErrorCode): never {
  throw new DnsProviderRecordServiceError(code);
}

function positiveInteger(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) fail("DNS_PROVIDER_INVALID");
  return parsed;
}

function pageNumber(value: unknown, maximum: number): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) fail("DNS_PROVIDER_INVALID");
  return parsed;
}

function boundedText(value: unknown, maximum: number, allowEmpty = false): string {
  if (typeof value !== "string") fail("DNS_PROVIDER_INVALID");
  const normalized = value.trim().normalize("NFC");
  if ((!allowEmpty && !normalized) || Buffer.byteLength(normalized, "utf8") > maximum
    || /[\u0000-\u001f\u007f]/.test(normalized)) fail("DNS_PROVIDER_INVALID");
  return normalized;
}

function providerRecordId(value: unknown): string {
  const id = boundedText(value, 128);
  if (!/^\d+$/.test(id) || !Number.isSafeInteger(Number(id)) || Number(id) <= 0) fail("DNS_PROVIDER_INVALID");
  return id;
}

function recordRevision(value: unknown): string {
  const revision = boundedText(value, 64);
  if (!/^[a-f0-9]{64}$/.test(revision)) fail("DNS_PROVIDER_INVALID");
  return revision;
}

function writableRecordType(value: unknown): WritableRecordType {
  const type = boundedText(value, 16).toUpperCase();
  if (!(WRITABLE_RECORD_TYPES as readonly string[]).includes(type)) fail("DNS_PROVIDER_INVALID");
  return type as WritableRecordType;
}

function normalizedSubdomain(value: unknown): string {
  const name = boundedText(value, 253).toLowerCase();
  if (name !== "@" && name.split(".").some((label) => (
    !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)
  ))) fail("DNS_PROVIDER_INVALID");
  return name;
}

function normalizedValue(type: WritableRecordType, value: unknown): string {
  const text = boundedText(value, 2_048);
  if (type === "A" && isIP(text) !== 4) fail("DNS_PROVIDER_INVALID");
  if (type === "AAAA" && isIP(text) !== 6) fail("DNS_PROVIDER_INVALID");
  if (type === "CNAME") {
    try {
      return normalizeDnsProviderZoneName(text);
    } catch {
      fail("DNS_PROVIDER_INVALID");
    }
  }
  return text;
}

function normalizedTtl(value: unknown): number {
  const ttl = Number(value);
  if (!Number.isSafeInteger(ttl) || ttl < 1 || ttl > 604_800) fail("DNS_PROVIDER_INVALID");
  return ttl;
}

function revisionForRecord(record: DnsPodRecord): string {
  return createHash("sha256").update(JSON.stringify([
    "dns-record:v1",
    record.providerRecordId,
    record.subdomain,
    record.recordType,
    record.providerLineId,
    record.lineName,
    record.value,
    record.ttl,
    record.status,
  ]), "utf8").digest("hex");
}

function recordFqdn(subdomain: string, zoneName: string): string {
  return subdomain === "@" ? zoneName : `${subdomain}.${zoneName}`;
}

function safeRecord(record: DnsPodRecord, zoneName: string, usedNames: ReadonlySet<string>): DnsProviderRecordSafeDto {
  const subdomain = record.subdomain.toLowerCase();
  return {
    providerRecordId: record.providerRecordId,
    subdomain,
    fqdn: recordFqdn(subdomain, zoneName),
    recordType: record.recordType,
    providerLineId: record.providerLineId,
    lineName: record.lineName,
    value: record.value,
    ttl: record.ttl,
    status: record.status,
    recordRevision: revisionForRecord(record),
    inUse: usedNames.has(recordFqdn(subdomain, zoneName)),
  };
}

function mapError(error: unknown): never {
  if (error instanceof DnsProviderRecordServiceError) throw error;
  if (error instanceof DnsProviderRepositoryError) {
    if (error.code === "DNS_PROVIDER_NOT_CONFIGURED" || error.code === "SENSITIVE_DATA_UNAVAILABLE") fail(error.code);
    fail("DNS_PROVIDER_INVALID");
  }
  if (error instanceof DnsPodProviderError) {
    if (error.ambiguousWrite) fail("DNS_WRITE_UNCERTAIN");
    if (error.code === "DNS_PROVIDER_RECORD_NOT_FOUND") fail("DNS_RECORD_NOT_FOUND");
    fail(error.code);
  }
  if (error instanceof Error && error.message === "DNS_PROVIDER_RECORD_NOT_FOUND") fail("DNS_RECORD_NOT_FOUND");
  throw error;
}

async function zoneContext(zoneIdValue: unknown, options: DnsProviderRecordServiceOptions): Promise<ZoneContext> {
  const zoneId = positiveInteger(zoneIdValue);
  try {
    const account = await getGlobalDnsProviderAccount();
    if (!account.configured) fail("DNS_PROVIDER_NOT_CONFIGURED");
    if (account.validationStatus !== "VALID") fail("DNS_PROVIDER_VALIDATION_STALE");
    const zones = await listGlobalDnsProviderZones();
    const zone = zones.find((item) => item.zoneId === zoneId);
    if (!zone) fail("DNS_ZONE_NOT_FOUND");
    if (zone.status !== "AVAILABLE" || Date.parse(zone.expiresAt) <= Date.now()) fail("DNS_PROVIDER_CATALOG_STALE");
    const credentials = await loadGlobalDnsProviderCredentials({ keyring: options.keyring });
    if (credentials.accountId !== account.accountId
      || credentials.accountRevision !== account.accountRevision
      || credentials.bindingRevision !== account.bindingRevision) fail("DNS_PROVIDER_INVALID");
    return {
      accountId: account.accountId,
      zone,
      providerZone: {
        providerZoneId: zone.providerZoneId,
        name: zone.name,
        grade: "UNKNOWN",
        status: zone.status,
      },
      credentials: { secretId: credentials.secretId, secretKey: credentials.secretKey },
    };
  } catch (error) {
    mapError(error);
  }
}

function clientFor(context: ZoneContext, options: DnsProviderRecordServiceOptions): DnsRecordClient {
  return options.clientFactory?.(context.credentials)
    ?? new DnsPodProviderClient({ credentials: context.credentials });
}

async function usedNamesFor(context: ZoneContext) {
  return listDnsProviderUsedNames(context.accountId, context.zone.zoneId, context.zone.name);
}

async function assertNamesWritable(context: ZoneContext, names: readonly string[]) {
  const used = await usedNamesFor(context);
  if (names.some((name) => used.has(recordFqdn(name.trim().toLowerCase(), context.zone.name)))) {
    fail("DNS_SUBDOMAIN_IN_USE");
  }
}

function writeInput(input: {
  subdomain: unknown;
  recordType: unknown;
  lineId: unknown;
  value: unknown;
  ttl: unknown;
}, context: ZoneContext): DnsPodRecordWriteInput {
  const recordType = writableRecordType(input.recordType);
  const lineId = positiveInteger(input.lineId);
  const storedLine = context.zone.lines.find((line) => line.lineId === lineId && line.status === "AVAILABLE");
  if (!storedLine) fail("DNS_PROVIDER_CATALOG_STALE");
  const line: DnsPodRecordLine = {
    providerLineId: storedLine.providerLineId,
    name: storedLine.name,
  };
  return {
    zone: context.providerZone,
    subdomain: normalizedSubdomain(input.subdomain),
    recordType,
    line,
    value: normalizedValue(recordType, input.value),
    ttl: normalizedTtl(input.ttl),
  };
}

export async function listDnsProviderRecords(input: {
  zoneId: number;
  subdomain?: string;
  search?: string;
  recordType?: string;
  page?: number;
  pageSize?: number;
}, options: DnsProviderRecordServiceOptions = {}): Promise<{
  items: DnsProviderRecordSafeDto[];
  total: number;
  page: number;
  pageSize: number;
  subdomain: { name: string; fqdn: string; inUse: boolean } | null;
  zone: Pick<DnsProviderZoneSafeDto, "zoneId" | "name" | "inUse" | "quickConfigReferenceCount" | "managedRecordCount" | "activeOperationCount">;
}> {
  const page = pageNumber(input.page ?? 1, Number.MAX_SAFE_INTEGER);
  const pageSize = pageNumber(input.pageSize ?? 20, 100);
  const search = boundedText(input.search ?? "", 128, true).toLowerCase();
  const typeFilter = input.recordType === undefined
    ? ""
    : boundedText(input.recordType, 16).toUpperCase();
  if (typeFilter && !/^[A-Z][A-Z0-9]{0,15}$/.test(typeFilter)) fail("DNS_PROVIDER_INVALID");
  const context = await zoneContext(input.zoneId, options);
  const subdomain = input.subdomain === undefined ? null : boundedText(input.subdomain, 253).toLowerCase();
  try {
    const records = await clientFor(context, options).listRecords({ zone: context.providerZone });
    const usedNames = await usedNamesFor(context);
    const filtered = records.map((record) => safeRecord(record, context.zone.name, usedNames)).filter((record) => (
      (subdomain === null || record.subdomain === subdomain)
      && (!typeFilter || record.recordType === typeFilter)
      && (!search || [record.subdomain, record.fqdn, record.recordType, record.lineName, record.value]
        .some((value) => value.toLowerCase().includes(search)))
    )).sort((left, right) => (
      left.subdomain.localeCompare(right.subdomain, "en")
      || left.recordType.localeCompare(right.recordType, "en")
      || left.providerLineId.localeCompare(right.providerLineId, "en")
      || Number(left.providerRecordId) - Number(right.providerRecordId)
    ));
    const offset = (page - 1) * pageSize;
    return {
      items: filtered.slice(offset, offset + pageSize),
      total: filtered.length,
      page,
      pageSize,
      subdomain: subdomain === null ? null : {
        name: subdomain, fqdn: recordFqdn(subdomain, context.zone.name),
        inUse: usedNames.has(recordFqdn(subdomain, context.zone.name)),
      },
      zone: {
        zoneId: context.zone.zoneId,
        name: context.zone.name,
        inUse: context.zone.inUse,
        quickConfigReferenceCount: context.zone.quickConfigReferenceCount,
        managedRecordCount: context.zone.managedRecordCount,
        activeOperationCount: context.zone.activeOperationCount,
      },
    };
  } catch (error) {
    mapError(error);
  }
}

export async function listDnsProviderRecordGroups(input: {
  zoneId: number; search?: string; page?: number; pageSize?: number;
}, options: DnsProviderRecordServiceOptions = {}) {
  const page = pageNumber(input.page ?? 1, Number.MAX_SAFE_INTEGER);
  const pageSize = pageNumber(input.pageSize ?? 20, 100);
  const search = boundedText(input.search ?? "", 128, true).toLowerCase();
  const context = await zoneContext(input.zoneId, options);
  try {
    const records = await clientFor(context, options).listRecords({ zone: context.providerZone });
    const used = await usedNamesFor(context);
    const groups = new Map<string, {
      subdomain: string; fqdn: string; recordCount: number; recordTypes: string[]; inUse: boolean;
    }>();
    const matches = new Set<string>();
    const ensureGroup = (subdomain: string) => {
      let group = groups.get(subdomain);
      if (!group) {
        const fqdn = recordFqdn(subdomain, context.zone.name);
        group = { subdomain, fqdn, recordCount: 0, recordTypes: [], inUse: used.has(fqdn) };
        groups.set(subdomain, group);
        if (!search || fqdn.includes(search) || subdomain.includes(search)) matches.add(subdomain);
      }
      return group;
    };
    for (const record of records) {
      const group = ensureGroup(record.subdomain.trim().toLowerCase());
      group.recordCount += 1;
      if (!group.recordTypes.includes(record.recordType)) group.recordTypes.push(record.recordType);
      if ([record.recordType, record.lineName, record.value].some((value) => value.toLowerCase().includes(search))) {
        matches.add(group.subdomain);
      }
    }
    for (const fqdn of used) {
      if (fqdn === context.zone.name) ensureGroup("@");
      else if (fqdn.endsWith(`.${context.zone.name}`)) ensureGroup(fqdn.slice(0, -(context.zone.name.length + 1)));
    }
    const items = [...groups.values()].filter((group) => matches.has(group.subdomain))
      .sort((left, right) => left.subdomain.localeCompare(right.subdomain, "en"));
    for (const group of items) group.recordTypes.sort();
    return { items: items.slice((page - 1) * pageSize, page * pageSize), total: items.length, page, pageSize };
  } catch (error) {
    mapError(error);
  }
}

export async function createDnsProviderRecord(input: {
  zoneId: number;
  subdomain: string;
  recordType: WritableRecordType;
  lineId: number;
  value: string;
  ttl: number;
}, options: DnsProviderRecordServiceOptions = {}): Promise<{ providerRecordId: string }> {
  return withKeyedTaskLock(`dns-provider-record-zone:${positiveInteger(input.zoneId)}`, async () => {
    const context = await zoneContext(input.zoneId, options);
    try {
      const payload = writeInput(input, context);
      await assertNamesWritable(context, [payload.subdomain]);
      return await clientFor(context, options).createRecord(payload);
    } catch (error) {
      mapError(error);
    }
  });
}

export async function updateDnsProviderRecord(input: {
  zoneId: number;
  providerRecordId: string;
  expectedRecordRevision: string;
  subdomain: string;
  recordType: WritableRecordType;
  lineId: number;
  value: string;
  ttl: number;
}, options: DnsProviderRecordServiceOptions = {}): Promise<{ providerRecordId: string }> {
  return withKeyedTaskLock(`dns-provider-record-zone:${positiveInteger(input.zoneId)}`, async () => {
    const context = await zoneContext(input.zoneId, options);
    const id = providerRecordId(input.providerRecordId);
    const expected = recordRevision(input.expectedRecordRevision);
    const client = clientFor(context, options);
    try {
      const current = await client.getRecord({ zone: context.providerZone, providerRecordId: id });
      if (revisionForRecord(current) !== expected) fail("DNS_RECORD_CHANGED");
      writableRecordType(current.recordType);
      const payload = writeInput(input, context);
      await assertNamesWritable(context, [current.subdomain, payload.subdomain]);
      return await client.updateRecord({ ...payload, providerRecordId: id });
    } catch (error) {
      mapError(error);
    }
  });
}

export async function removeDnsProviderRecord(input: {
  zoneId: number;
  providerRecordId: string;
  expectedRecordRevision: string;
}, options: DnsProviderRecordServiceOptions = {}): Promise<{ providerRecordId: string }> {
  return withKeyedTaskLock(`dns-provider-record-zone:${positiveInteger(input.zoneId)}`, async () => {
    const context = await zoneContext(input.zoneId, options);
    const id = providerRecordId(input.providerRecordId);
    const expected = recordRevision(input.expectedRecordRevision);
    const client = clientFor(context, options);
    try {
      const current = await client.getRecord({ zone: context.providerZone, providerRecordId: id });
      if (revisionForRecord(current) !== expected) fail("DNS_RECORD_CHANGED");
      writableRecordType(current.recordType);
      await assertNamesWritable(context, [current.subdomain]);
      await client.deleteRecord({ zone: context.providerZone, providerRecordId: id });
      return { providerRecordId: id };
    } catch (error) {
      mapError(error);
    }
  });
}
