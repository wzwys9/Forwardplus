import crypto from "node:crypto";
import { domainToASCII } from "node:url";

const CATALOG_HASH_PREFIX = "dnspod-catalog:v1";
const CARRIER_MAPPING_VERSION = "dnspod-carrier-map:v1";

export const DNS_PROVIDER_REQUIRED_CATEGORIES = [
  "DEFAULT",
  "TELECOM",
  "UNICOM",
  "MOBILE",
  "EDUCATION",
] as const;

export type DnsProviderRequiredLineCategory = typeof DNS_PROVIDER_REQUIRED_CATEGORIES[number];
export type DnsProviderLineCategory = DnsProviderRequiredLineCategory | "OTHER";
export type DnsProviderCatalogStatus = "AVAILABLE" | "STALE" | "REMOVED" | "ERROR";
export type DnsProviderCatalogLineInput = Readonly<{ providerLineId: string; name: string }>;
export type DnsProviderCatalogInput = Readonly<{
  providerZoneId: string;
  name: string;
  lines: readonly DnsProviderCatalogLineInput[];
}>;
export type StoredDnsProviderCatalogLineInput = Readonly<{
  providerLineId: string;
  name: string;
  status: DnsProviderCatalogStatus;
  category: DnsProviderLineCategory;
}>;
export type StoredDnsProviderCatalogInput = Readonly<{
  providerZoneId: string;
  name: string;
  status: DnsProviderCatalogStatus;
  lines: readonly StoredDnsProviderCatalogLineInput[];
}>;

export class DnsProviderCatalogValidationError extends Error {
  constructor() {
    super("DNS_PROVIDER_CATALOG_INVALID");
    this.name = "DnsProviderCatalogValidationError";
  }
}

const categoryByName = new Map<string, DnsProviderLineCategory>([
  ["默认", "DEFAULT"],
  ["电信", "TELECOM"],
  ["联通", "UNICOM"],
  ["移动", "MOBILE"],
  ["教育网", "EDUCATION"],
]);

function invalid(): never {
  throw new DnsProviderCatalogValidationError();
}

function compareCanonical(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function boundedString(value: unknown, maxBytes: number): string {
  const normalized = String(value ?? "").trim().normalize("NFC");
  if (!normalized || Buffer.byteLength(normalized, "utf8") > maxBytes || /[\u0000-\u001f\u007f]/.test(normalized)) invalid();
  return normalized;
}

export function normalizeDnsProviderZoneName(value: unknown): string {
  const input = boundedString(value, 253).replace(/\.$/, "");
  const ascii = domainToASCII(input).toLowerCase();
  if (!ascii || ascii.length > 253 || ascii.split(".").some((label) => (
    label.length < 1 || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)
  ))) invalid();
  return ascii;
}

export function classifyDnsProviderLineName(value: unknown): DnsProviderLineCategory {
  return categoryByName.get(boundedString(value, 128)) ?? "OTHER";
}

function catalogStatus(value: unknown): DnsProviderCatalogStatus {
  if (value === "AVAILABLE" || value === "STALE" || value === "REMOVED" || value === "ERROR") return value;
  return invalid();
}

function lineCategory(value: unknown): DnsProviderLineCategory {
  if (value === "DEFAULT" || value === "TELECOM" || value === "UNICOM" || value === "MOBILE"
    || value === "EDUCATION" || value === "OTHER") return value;
  return invalid();
}

export function normalizeDnsProviderCatalog(zones: readonly DnsProviderCatalogInput[]) {
  if (!Array.isArray(zones) || zones.length < 1 || zones.length > 100) invalid();
  const zoneIds = new Set<string>();
  const zoneNames = new Set<string>();
  return zones.map((zone) => {
    const providerZoneId = boundedString(zone.providerZoneId, 128);
    const name = normalizeDnsProviderZoneName(zone.name);
    if (zoneIds.has(providerZoneId) || zoneNames.has(name) || !Array.isArray(zone.lines) || zone.lines.length > 1_000) invalid();
    zoneIds.add(providerZoneId);
    zoneNames.add(name);
    const lineIds = new Set<string>();
    const lines = zone.lines.map((line: DnsProviderCatalogLineInput) => {
      const providerLineId = boundedString(line.providerLineId, 128);
      const lineName = boundedString(line.name, 128);
      if (lineIds.has(providerLineId)) invalid();
      lineIds.add(providerLineId);
      return {
        providerLineId,
        name: lineName,
        status: "AVAILABLE" as const,
        category: classifyDnsProviderLineName(lineName),
      };
    }).sort((left: { providerLineId: string }, right: { providerLineId: string }) => (
      compareCanonical(left.providerLineId, right.providerLineId)
    ));
    return { providerZoneId, name, status: "AVAILABLE" as const, lines };
  }).sort((left, right) => compareCanonical(left.providerZoneId, right.providerZoneId));
}

export function computeDnsProviderCatalogRevision(zones: readonly DnsProviderCatalogInput[]): string {
  return computeStoredDnsProviderCatalogRevision(normalizeDnsProviderCatalog(zones));
}

export function computeStoredDnsProviderCatalogRevision(zones: readonly StoredDnsProviderCatalogInput[]): string {
  if (!Array.isArray(zones) || zones.length < 1 || zones.length > 1_000) invalid();
  const zoneIds = new Set<string>();
  const zoneNames = new Set<string>();
  const normalized = zones.map((zone) => {
    const providerZoneId = boundedString(zone.providerZoneId, 128);
    const name = normalizeDnsProviderZoneName(zone.name);
    if (zoneIds.has(providerZoneId) || zoneNames.has(name) || !Array.isArray(zone.lines) || zone.lines.length > 1_000) invalid();
    zoneIds.add(providerZoneId);
    zoneNames.add(name);
    const lineIds = new Set<string>();
    const lines = zone.lines.map((line: StoredDnsProviderCatalogLineInput) => {
      const providerLineId = boundedString(line.providerLineId, 128);
      const lineName = boundedString(line.name, 128);
      const category = lineCategory(line.category);
      if (lineIds.has(providerLineId) || category !== classifyDnsProviderLineName(lineName)) invalid();
      lineIds.add(providerLineId);
      return { providerLineId, name: lineName, status: catalogStatus(line.status), category };
    }).sort((left: { providerLineId: string }, right: { providerLineId: string }) => (
      compareCanonical(left.providerLineId, right.providerLineId)
    ));
    return { providerZoneId, name, status: catalogStatus(zone.status), lines };
  }).sort((left, right) => compareCanonical(left.providerZoneId, right.providerZoneId));
  return crypto.createHash("sha256")
    .update(CATALOG_HASH_PREFIX, "utf8")
    .update("\n", "utf8")
    .update(JSON.stringify({ mappingVersion: CARRIER_MAPPING_VERSION, zones: normalized }), "utf8")
    .digest("hex");
}
