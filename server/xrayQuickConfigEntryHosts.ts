import net from "node:net";

import { isPresenceCapableHostConfirmedOffline } from "./agentFastLiveness";
import { quoteIdentifier } from "./dbCompat";
import { queryRaw } from "./dbRuntime";
import { HOST_ONLINE_TTL_MS } from "./hostHeartbeatPolicy";

export const QUICK_CONFIG_ENTRY_HOST_DISABLED_REASON_CODES = [
  "HOST_OFFLINE",
  "AGENT_CAPABILITY_MISSING",
  "UDP_CAPABILITY_REQUIRED",
  "QUICK_CONFIG_HOST_UNAVAILABLE",
] as const;

export type QuickConfigEntryHostDisabledReasonCode =
  (typeof QUICK_CONFIG_ENTRY_HOST_DISABLED_REASON_CODES)[number];

export type QuickConfigEntryHostEndpoint = {
  addressFamily: "IPV4" | "IPV6";
  address: string;
};

export type QuickConfigEntryHost = {
  hostId: number;
  name: string;
  eligible: boolean;
  disabledReasonCode: QuickConfigEntryHostDisabledReasonCode | null;
  endpoints: QuickConfigEntryHostEndpoint[];
};

type EntryHostRow = Record<string, unknown>;

function databaseBoolean(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || value === "true";
}

function dateFromDatabase(value: unknown): Date | null {
  if (value === null || value === undefined || value === "") return null;
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value : null;
  const numeric = Number(value);
  if (Number.isFinite(numeric) && numeric > 0) {
    const date = new Date(numeric < 10_000_000_000 ? numeric * 1000 : numeric);
    return Number.isFinite(date.getTime()) ? date : null;
  }
  const date = new Date(String(value));
  return Number.isFinite(date.getTime()) ? date : null;
}

function ipv4Number(address: string): number {
  return address.split(".").reduce((value, part) => value * 256 + Number(part), 0) >>> 0;
}

function ipv4InCidr(address: number, base: string, bits: number): boolean {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (address & mask) === (ipv4Number(base) & mask);
}

function publicIpv4(value: unknown): string | null {
  const address = String(value ?? "").trim();
  if (net.isIP(address) !== 4) return null;
  const numeric = ipv4Number(address);
  const restricted: Array<readonly [string, number]> = [
    ["0.0.0.0", 8],
    ["10.0.0.0", 8],
    ["100.64.0.0", 10],
    ["127.0.0.0", 8],
    ["169.254.0.0", 16],
    ["172.16.0.0", 12],
    ["192.0.0.0", 24],
    ["192.0.2.0", 24],
    ["192.88.99.0", 24],
    ["192.168.0.0", 16],
    ["198.18.0.0", 15],
    ["198.51.100.0", 24],
    ["203.0.113.0", 24],
    ["224.0.0.0", 4],
    ["240.0.0.0", 4],
  ];
  return restricted.some(([base, bits]) => ipv4InCidr(numeric, base, bits)) ? null : address;
}

function ipv6Number(address: string): bigint | null {
  if (net.isIP(address) !== 6) return null;
  let normalized = address.toLowerCase();
  if (normalized.includes(".")) {
    const separator = normalized.lastIndexOf(":");
    const tail = normalized.slice(separator + 1);
    if (net.isIP(tail) !== 4) return null;
    const value = ipv4Number(tail);
    normalized = `${normalized.slice(0, separator)}:${(value >>> 16).toString(16)}:${(value & 0xffff).toString(16)}`;
  }
  const halves = normalized.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const omitted = 8 - left.length - right.length;
  if (omitted < 0 || (halves.length === 1 && omitted !== 0)) return null;
  const groups = [...left, ...Array.from({ length: omitted }, () => "0"), ...right];
  if (groups.length !== 8) return null;
  let result = 0n;
  for (const group of groups) result = (result << 16n) | BigInt(Number.parseInt(group || "0", 16));
  return result;
}

function ipv6InCidr(address: bigint, base: bigint, bits: number): boolean {
  const shift = BigInt(128 - bits);
  return address >> shift === base >> shift;
}

function publicIpv6(value: unknown): string | null {
  const address = String(value ?? "").trim().toLowerCase();
  const numeric = ipv6Number(address);
  if (numeric === null) return null;
  const globalUnicastBase = 0x20000000000000000000000000000000n;
  if (!ipv6InCidr(numeric, globalUnicastBase, 3)) return null;
  const documentationBase = 0x20010db8000000000000000000000000n;
  const benchmarkingBase = 0x20010002000000000000000000000000n;
  if (ipv6InCidr(numeric, documentationBase, 32) || ipv6InCidr(numeric, benchmarkingBase, 48)) return null;
  return address;
}

export function normalizeQuickConfigPublicIp(value: unknown, family: "IPV4" | "IPV6"): string | null {
  return family === "IPV4" ? publicIpv4(value) : publicIpv6(value);
}

function hostEndpoints(row: EntryHostRow): QuickConfigEntryHostEndpoint[] {
  const ipv4 = publicIpv4(row.ipv4) ?? publicIpv4(row.primaryAddress);
  const ipv6 = publicIpv6(row.ipv6) ?? publicIpv6(row.primaryAddress);
  return [
    ...(ipv4 ? [{ addressFamily: "IPV4" as const, address: ipv4 }] : []),
    ...(ipv6 ? [{ addressFamily: "IPV6" as const, address: ipv6 }] : []),
  ];
}

function hostDisabledReason(
  row: EntryHostRow,
  endpoints: QuickConfigEntryHostEndpoint[],
): QuickConfigEntryHostDisabledReasonCode | null {
  const hostId = Number(row.hostId);
  const heartbeat = dateFromDatabase(row.lastHeartbeat);
  const heartbeatFresh = !!heartbeat && Date.now() - heartbeat.getTime() <= HOST_ONLINE_TTL_MS;
  if (!databaseBoolean(row.isOnline) || !heartbeatFresh || isPresenceCapableHostConfirmedOffline(hostId)) {
    return "HOST_OFFLINE";
  }
  const platformSupported = row.supportedOS === "linux"
    && (row.supportedArch === "amd64" || row.supportedArch === "arm64");
  if (Number(row.capabilitySchemaVersion) !== 1 || !platformSupported || !databaseBoolean(row.supportsPortProbe)) {
    return "AGENT_CAPABILITY_MISSING";
  }
  if (!databaseBoolean(row.supportsUdpPortProbe) || !databaseBoolean(row.supportsUdpListenerReadiness)) {
    return "UDP_CAPABILITY_REQUIRED";
  }
  if (endpoints.length === 0) return "QUICK_CONFIG_HOST_UNAVAILABLE";
  return null;
}

export async function listXrayQuickConfigEntryHosts(): Promise<{ items: QuickConfigEntryHost[] }> {
  const q = quoteIdentifier;
  const rows = await queryRaw<EntryHostRow>(
      `SELECT h.${q("id")} AS ${q("hostId")}, h.${q("name")} AS ${q("hostName")},
          h.${q("ip")} AS ${q("primaryAddress")}, h.${q("ipv4")} AS ${q("ipv4")},
          h.${q("ipv6")} AS ${q("ipv6")}, h.${q("isOnline")} AS ${q("isOnline")},
          h.${q("lastHeartbeat")} AS ${q("lastHeartbeat")},
          r.${q("capabilitySchemaVersion")} AS ${q("capabilitySchemaVersion")},
          r.${q("supportedOS")} AS ${q("supportedOS")}, r.${q("supportedArch")} AS ${q("supportedArch")},
          r.${q("supportsPortProbe")} AS ${q("supportsPortProbe")},
          r.${q("supportsUdpPortProbe")} AS ${q("supportsUdpPortProbe")},
          r.${q("supportsUdpListenerReadiness")} AS ${q("supportsUdpListenerReadiness")}
        FROM ${q("hosts")} h
        LEFT JOIN ${q("xray_runtime_reports")} r ON r.${q("hostId")} = h.${q("id")}
        ORDER BY h.${q("name")} ASC, h.${q("id")} ASC`,
    );
  return {
    items: rows.map((row) => {
      const endpoints = hostEndpoints(row);
      const disabledReasonCode = hostDisabledReason(row, endpoints);
      return {
        hostId: Number(row.hostId),
        name: String(row.hostName ?? ""),
        eligible: disabledReasonCode === null,
        disabledReasonCode,
        endpoints,
      };
    }),
  };
}
