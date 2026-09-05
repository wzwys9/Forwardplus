import {
  FORWARD_TYPES,
  FORWARD_TYPE_LABELS,
  type ForwardType,
} from "./forwardTypes";

export const XRAY_QUICK_CONFIG_FORWARD_ENGINES = FORWARD_TYPES;
export type XrayQuickConfigForwardEngine = ForwardType;

export const XRAY_QUICK_CONFIG_DEFAULT_FORWARD_ENGINE = "realm" as const satisfies XrayQuickConfigForwardEngine;
export const XRAY_QUICK_CONFIG_FORWARD_ENGINE_MIN_AGENT_VERSION = "2.2.192";

export const XRAY_QUICK_CONFIG_FORWARD_ENGINE_ADDRESS_FAMILIES = {
  iptables: ["IPV4", "IPV6"],
  nftables: ["IPV4", "IPV6"],
  realm: ["IPV4", "IPV6"],
  socat: ["IPV4", "IPV6"],
  gost: ["IPV4", "IPV6"],
  nginx: ["IPV4", "IPV6"],
} as const satisfies Record<XrayQuickConfigForwardEngine, readonly ("IPV4" | "IPV6")[]>;

export const XRAY_QUICK_CONFIG_FORWARD_ENGINE_DISABLED_REASON_CODES = [
  "FORWARD_PROTOCOL_DISABLED",
  "HOST_OFFLINE",
  "AGENT_CAPABILITY_MISSING",
  "UDP_CAPABILITY_REQUIRED",
  "QUICK_CONFIG_HOST_UNAVAILABLE",
  "QUICK_CONFIG_ADDRESS_UNAVAILABLE",
  "QUICK_CONFIG_PATH_ADDRESS_FAMILY_UNSUPPORTED",
] as const;

export type XrayQuickConfigForwardEngineDisabledReasonCode =
  (typeof XRAY_QUICK_CONFIG_FORWARD_ENGINE_DISABLED_REASON_CODES)[number];

export type XrayQuickConfigForwardEngineCatalogItem = Readonly<{
  engine: XrayQuickConfigForwardEngine;
  label: string;
  isDefault: boolean;
  eligible: boolean;
  disabledReasonCode: XrayQuickConfigForwardEngineDisabledReasonCode | null;
}>;

export function xrayQuickConfigForwardEngineLabel(engine: XrayQuickConfigForwardEngine): string {
  return FORWARD_TYPE_LABELS[engine];
}

export function quickConfigPathEngineCompatible(engine: XrayQuickConfigForwardEngine,
  paths: readonly (readonly { hostId: number; addressFamily: "IPV4" | "IPV6" }[])[],
  targetAddress: string, directLandingHostId?: number,
  registeredHosts?: readonly { hostId: number; endpoints: readonly { addressFamily: "IPV4" | "IPV6" }[] }[]): boolean {
  const targetFamily = targetAddress.includes(":") ? "IPV6" : /^\d+\.\d+\.\d+\.\d+$/.test(targetAddress) ? "IPV4" : null;
  if (registeredHosts) {
    const hosts = new Map(registeredHosts.map(host => [host.hostId, new Set(host.endpoints.map(endpoint => endpoint.addressFamily))]));
    if (!paths.every(hops => hops.every((hop, index) => {
      const families = hosts.get(hop.hostId);
      if (!families?.has(hop.addressFamily)) return false;
      if (hops.length === 1 && hop.hostId === directLandingHostId) return true;
      const nextFamily = hops[index + 1]?.addressFamily ?? targetFamily;
      return !nextFamily || families.has(nextFamily);
    }))) return false;
  }
  if (engine !== "iptables" && engine !== "nftables") return true;
  return paths.every(hops => hops.length === 1 && hops[0].hostId === directLandingHostId
    || !!targetFamily && hops.every((hop, index) => hop.addressFamily === (hops[index + 1]?.addressFamily ?? targetFamily)));
}

export function filterQuickConfigPathEngines(catalog: { defaultEngine: "realm"; items: XrayQuickConfigForwardEngineCatalogItem[] } | undefined,
  paths: Parameters<typeof quickConfigPathEngineCompatible>[1], targetAddress: string, directLandingHostId?: number) {
  if (!catalog) return undefined;
  return { ...catalog, items: catalog.items.map(item => quickConfigPathEngineCompatible(item.engine, paths, targetAddress, directLandingHostId)
    ? item : { ...item, eligible: false, disabledReasonCode: "QUICK_CONFIG_PATH_ADDRESS_FAMILY_UNSUPPORTED" as const }) };
}
