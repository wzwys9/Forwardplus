import { normalizeQuickConfigPublicIp } from "./xrayQuickConfigEntryHosts";
import { normalizeXrayExternalProxyAddress } from "../shared/xrayExternalProxy";

export type QuickConfigHopInput = Readonly<{ hostId: number; addressFamily: "IPV4" | "IPV6" }>;
export type QuickConfigRelay = QuickConfigHopInput & Readonly<{ address: string }>;
export type QuickConfigPathEndpoint = QuickConfigHopInput & Readonly<{ relays?: readonly QuickConfigHopInput[] }>;
export type QuickConfigTopologyRoute = Readonly<{
  hostId: unknown; routeMode: unknown; relayHopsJson?: unknown;
}>;
export type QuickConfigSegment = Readonly<{ hostId: number; targetAddress: string; targetPort: number }>;

export class QuickConfigPathError extends Error {
  constructor() { super("QUICK_CONFIG_PATH_INVALID"); }
}
function invalid(): never { throw new QuickConfigPathError(); }
function id(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) invalid();
  return value;
}

/** Only endpoint identities cross the browser boundary. Missing relays is the legacy path. */
export function normalizeQuickConfigPath(endpoint: QuickConfigPathEndpoint): QuickConfigPathEndpoint {
  function identity(value: QuickConfigHopInput): QuickConfigHopInput {
    if (!value || (value.addressFamily !== "IPV4" && value.addressFamily !== "IPV6")) invalid();
    return { hostId: id(value.hostId), addressFamily: value.addressFamily };
  }
  const entry = identity(endpoint);
  if (endpoint.relays === undefined) return entry;
  if (!Array.isArray(endpoint.relays) || endpoint.relays.length > 8) invalid();
  const relays = endpoint.relays.map(identity);
  const hosts = [entry, ...relays].map(hop => hop.hostId);
  if (new Set(hosts).size !== hosts.length) invalid();
  return relays.length ? { ...entry, relays } : entry;
}

export function parseQuickConfigRelays(raw: unknown): QuickConfigRelay[] {
  if (raw === undefined || raw === null) return [];
  if (typeof raw !== "string" || raw.length > 4096) invalid();
  let value: unknown;
  try { value = JSON.parse(raw); } catch { invalid(); }
  if (!Array.isArray(value) || value.length > 8) invalid();
  const result = value.map((hop): QuickConfigRelay => {
    if (!hop || typeof hop !== "object" || Array.isArray(hop)
      || Object.keys(hop).sort().join(",") !== "address,addressFamily,hostId"
      || (hop.addressFamily !== "IPV4" && hop.addressFamily !== "IPV6")
      || typeof hop.address !== "string") invalid();
    const address = normalizeQuickConfigPublicIp(hop.address, hop.addressFamily);
    if (!address || address !== hop.address) invalid();
    return { hostId: id(hop.hostId), addressFamily: hop.addressFamily, address };
  });
  if (new Set(result.map(hop => hop.hostId)).size !== result.length) invalid();
  return result;
}

export function serializeQuickConfigRelays(hops: readonly QuickConfigRelay[]): string | null {
  if (!hops.length) return null;
  const json = JSON.stringify(hops.map(({ hostId, addressFamily, address }) => ({ hostId, addressFamily, address })));
  return JSON.stringify(parseQuickConfigRelays(json));
}

/** Immutable routes, never live rules, are the authority for each shared listener. */
export function compileQuickConfigTopology(
  routes: readonly QuickConfigTopologyRoute[],
  target: Readonly<{ publicPort: number; targetAddress: string; targetPort: number }>,
): QuickConfigSegment[] {
  if (!Array.isArray(routes) || routes.length < 1 || routes.length > 128
    || !target || typeof target.targetAddress !== "string" || !target.targetAddress
    || target.targetAddress.length > 253 || /[\s\u0000-\u001f\u007f]/.test(target.targetAddress)) invalid();
  try { if (normalizeXrayExternalProxyAddress(target.targetAddress) !== target.targetAddress) invalid(); }
  catch { invalid(); }
  for (const port of [target.publicPort, target.targetPort]) {
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535) invalid();
  }
  const segments = new Map<number, QuickConfigSegment>();
  const nextHosts = new Map<number, number | null>();
  for (const route of routes) {
    if (!route || typeof route !== "object") invalid();
    const relays = parseQuickConfigRelays(route.relayHopsJson);
    if (route.routeMode === "DIRECT") {
      if (relays.length) invalid();
      if (route.hostId !== null) id(Number(route.hostId));
      continue;
    }
    if (route.routeMode !== "FORWARD") invalid();
    const hostIds = [id(Number(route.hostId)), ...relays.map(hop => hop.hostId)];
    if (new Set(hostIds).size !== hostIds.length) invalid();
    for (const [index, hostId] of hostIds.entries()) {
      const next = relays[index];
      const segment = { hostId, targetAddress: next?.address ?? target.targetAddress, targetPort: next ? target.publicPort : target.targetPort };
      const existing = segments.get(hostId);
      if (existing && (existing.targetAddress !== segment.targetAddress || existing.targetPort !== segment.targetPort
        || nextHosts.get(hostId) !== (next?.hostId ?? null))) invalid();
      segments.set(hostId, segment);
      nextHosts.set(hostId, next?.hostId ?? null);
    }
  }
  if (segments.size > 64) invalid();
  for (const hostId of nextHosts.keys()) {
    const seen = new Set<number>();
    let current: number | null = hostId;
    while (current !== null) {
      if (seen.has(current)) invalid();
      seen.add(current);
      current = nextHosts.get(current) ?? null;
    }
  }
  return [...segments.values()].sort((a, b) => a.hostId - b.hostId);
}
