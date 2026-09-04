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
