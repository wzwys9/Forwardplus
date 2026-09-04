import { z } from "zod";
import type { XrayAccessCredentialType } from "./xrayAccess";

export type XrayProfileProtocol = "VLESS" | "TROJAN" | "VMESS" | "SHADOWSOCKS" | "HYSTERIA2" | "WIREGUARD" | "HTTP" | "MIXED" | "TUNNEL";
export type XrayProfileTransport = "RAW" | "GRPC" | "WEBSOCKET" | "HTTP_UPGRADE" | "XHTTP" | "MKCP" | "HYSTERIA" | "NONE";
export type XrayProfileSecurity = "NONE" | "TLS" | "REALITY";
export type XrayProfileClientFlow = "XTLS_RPRX_VISION" | "NONE";
export type XrayProfileListenerNetwork = "TCP" | "UDP";
export type XrayProfileCredentialType = XrayAccessCredentialType | "NONE";
export type XrayProfileShareFormat = "VLESS_URI" | "TROJAN_URI" | "VMESS_URI" | "SHADOWSOCKS_URI" | "HYSTERIA2_URI" | "WIREGUARD_CONFIG" | "HTTP_PROXY_URI" | "MIXED_PROXY_ENDPOINTS" | "NONE";
export type XrayProfileAdvisoryCode = "CORE_DEPRECATED" | "WIREGUARD_BLOCKING_RISK" | "PLAINTEXT_PROXY_AUTH_RISK" | "PLAINTEXT_MIXED_AUTH_RISK";

export type XrayProfileSummary = {
  id: string;
  status: "AVAILABLE" | "IMPLEMENTING";
  protocol: XrayProfileProtocol;
  transport: XrayProfileTransport;
  security: XrayProfileSecurity;
  clientFlow: XrayProfileClientFlow;
  listenerNetworks: readonly XrayProfileListenerNetwork[];
  clientCredentialType: XrayProfileCredentialType;
  shareFormat: XrayProfileShareFormat;
  testedCoreVersion: "v26.3.27";
  advisoryCode?: XrayProfileAdvisoryCode;
};

export type XrayProfileMatchInput = {
  [key: string]: unknown;
  protocol?: unknown;
  transport?: unknown;
  security?: unknown;
  clientFlow?: unknown;
};

type XrayProfileDefinition = XrayProfileSummary & {
  storage: {
    protocol: string;
    transport: string;
    security: string;
    clientFlow: string;
  };
};

export const XRAY_INBOUND_SPEC_MAX_BYTES = 4 * 1024;
const hostnamePattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const xrayInboundSpecV1Schema = z.object({}).strict();
const xrayGrpcSpecV1Schema = z.object({
  serviceName: z.string().min(1).max(128).regex(/^[A-Za-z0-9._~-]+$/),
}).strict();
const xrayPathSpecV1Schema = z.object({
  path: z.string().min(1).max(128).regex(/^\/[A-Za-z0-9._~/-]*$/),
}).strict();
const xrayTunnelTargetAddressSchema = z.string().refine(
  (value) => normalizeXrayTunnelTargetAddress(value) === value,
  "Tunnel target address must be canonical",
);
const xrayTunnelSpecV1Schema = z.object({
  targetAddress: xrayTunnelTargetAddressSchema,
  targetPort: z.number().int().min(1).max(65535),
}).strict();
const xrayInboundSpecSchemas = new Map<string, ReadonlyMap<number, z.ZodTypeAny>>([
  ["VLESS_RAW_REALITY_VISION", new Map([[1, xrayInboundSpecV1Schema]])],
  ["VLESS_GRPC_REALITY", new Map([[1, xrayGrpcSpecV1Schema]])],
  ["VLESS_XHTTP_REALITY", new Map([[1, xrayPathSpecV1Schema]])],
  ["TROJAN_RAW_REALITY", new Map([[1, xrayInboundSpecV1Schema]])],
  ["VLESS_RAW_TLS", new Map([[1, xrayInboundSpecV1Schema]])],
  ["VLESS_RAW_TLS_VISION", new Map([[1, xrayInboundSpecV1Schema]])],
  ["TROJAN_RAW_TLS", new Map([[1, xrayInboundSpecV1Schema]])],
  ["VLESS_WEBSOCKET_TLS", new Map([[1, xrayPathSpecV1Schema]])],
  ["TROJAN_WEBSOCKET_TLS", new Map([[1, xrayPathSpecV1Schema]])],
  ["VLESS_GRPC_TLS", new Map([[1, xrayGrpcSpecV1Schema]])],
  ["TROJAN_GRPC_TLS", new Map([[1, xrayGrpcSpecV1Schema]])],
  ["VLESS_HTTP_UPGRADE_TLS", new Map([[1, xrayPathSpecV1Schema]])],
  ["TROJAN_HTTP_UPGRADE_TLS", new Map([[1, xrayPathSpecV1Schema]])],
  ["VLESS_XHTTP_TLS", new Map([[1, xrayPathSpecV1Schema]])],
  ["TROJAN_XHTTP_TLS", new Map([[1, xrayPathSpecV1Schema]])],
  ["VLESS_MKCP_TLS", new Map([[1, xrayInboundSpecV1Schema]])],
  ["TROJAN_MKCP_TLS", new Map([[1, xrayInboundSpecV1Schema]])],
  ["VMESS_RAW_TLS", new Map([[1, xrayInboundSpecV1Schema]])],
  ["SHADOWSOCKS_2022_RAW_NONE", new Map([[1, xrayInboundSpecV1Schema]])],
  ["SHADOWSOCKS_2022_RAW_TCP_UDP_NONE", new Map([[1, xrayInboundSpecV1Schema]])],
  ["HYSTERIA2_TLS", new Map([[1, xrayInboundSpecV1Schema]])],
  ["WIREGUARD_UDP_NONE", new Map([[1, xrayInboundSpecV1Schema]])],
  ["HTTP_RAW_NONE", new Map([[1, xrayInboundSpecV1Schema]])],
  ["MIXED_RAW_NONE", new Map([[1, xrayInboundSpecV1Schema]])],
  ["TUNNEL_TCP_LOCAL_NONE", new Map([[1, xrayTunnelSpecV1Schema]])],
]);
const textEncoder = new TextEncoder();

export function normalizeXrayTunnelTargetAddress(value: unknown): string | null {
  const input = String(value ?? "").trim().toLowerCase();
  if (!input || input.length > 253 || /[^\x00-\x7f]/.test(input) || /[\u0000-\u001f\u007f]/.test(input)) return null;

  const ipv4Parts = input.split(".");
  if (ipv4Parts.length === 4 && ipv4Parts.every((part) => /^\d{1,3}$/.test(part))) {
    const octets = ipv4Parts.map(Number);
    if (octets.every((octet) => octet >= 0 && octet <= 255)) return octets.join(".");
    return null;
  }
  if (input.includes(":")) {
    try {
      const hostname = new URL(`http://[${input}]/`).hostname;
      return hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : null;
    } catch {
      return null;
    }
  }
  return hostnamePattern.test(input) ? input : null;
}

function tlsProfile(input: {
  id: string;
  protocol: "VLESS" | "TROJAN";
  transport: "RAW" | "GRPC" | "WEBSOCKET" | "HTTP_UPGRADE" | "XHTTP" | "MKCP";
  storageTransport: string;
  clientFlow?: XrayProfileClientFlow;
  listenerNetwork?: XrayProfileListenerNetwork;
  status?: XrayProfileSummary["status"];
}): XrayProfileDefinition {
  const clientFlow = input.clientFlow ?? "NONE";
  return {
    id: input.id,
    status: input.status ?? "IMPLEMENTING",
    protocol: input.protocol,
    transport: input.transport,
    security: "TLS",
    clientFlow,
    listenerNetworks: [input.listenerNetwork ?? "TCP"],
    clientCredentialType: input.protocol === "VLESS" ? "UUID" : "PASSWORD",
    shareFormat: input.protocol === "VLESS" ? "VLESS_URI" : "TROJAN_URI",
    testedCoreVersion: "v26.3.27",
    storage: {
      protocol: input.protocol.toLowerCase(),
      transport: input.storageTransport,
      security: "tls",
      clientFlow: clientFlow === "XTLS_RPRX_VISION" ? "xtls-rprx-vision" : "",
    },
  };
}

const profileDefinitions: readonly XrayProfileDefinition[] = [
  {
    id: "VLESS_RAW_REALITY_VISION",
    status: "AVAILABLE",
    protocol: "VLESS",
    transport: "RAW",
    security: "REALITY",
    clientFlow: "XTLS_RPRX_VISION",
    listenerNetworks: ["TCP"],
    clientCredentialType: "UUID_AND_SHORT_ID",
    shareFormat: "VLESS_URI",
    testedCoreVersion: "v26.3.27",
    storage: {
      protocol: "vless",
      transport: "tcp",
      security: "reality",
      clientFlow: "xtls-rprx-vision",
    },
  },
  {
    id: "VLESS_GRPC_REALITY",
    status: "AVAILABLE",
    protocol: "VLESS",
    transport: "GRPC",
    security: "REALITY",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "UUID_AND_SHORT_ID",
    shareFormat: "VLESS_URI",
    testedCoreVersion: "v26.3.27",
    storage: {
      protocol: "vless",
      transport: "grpc",
      security: "reality",
      clientFlow: "",
    },
  },
  {
    id: "VLESS_XHTTP_REALITY",
    status: "AVAILABLE",
    protocol: "VLESS",
    transport: "XHTTP",
    security: "REALITY",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "UUID_AND_SHORT_ID",
    shareFormat: "VLESS_URI",
    testedCoreVersion: "v26.3.27",
    storage: {
      protocol: "vless",
      transport: "xhttp",
      security: "reality",
      clientFlow: "",
    },
  },
  {
    id: "TROJAN_RAW_REALITY",
    status: "AVAILABLE",
    protocol: "TROJAN",
    transport: "RAW",
    security: "REALITY",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "PASSWORD",
    shareFormat: "TROJAN_URI",
    testedCoreVersion: "v26.3.27",
    storage: {
      protocol: "trojan",
      transport: "tcp",
      security: "reality",
      clientFlow: "",
    },
  },
  tlsProfile({ id: "VLESS_RAW_TLS", protocol: "VLESS", transport: "RAW", storageTransport: "tcp", status: "AVAILABLE" }),
  tlsProfile({ id: "VLESS_RAW_TLS_VISION", protocol: "VLESS", transport: "RAW", storageTransport: "tcp", clientFlow: "XTLS_RPRX_VISION", status: "AVAILABLE" }),
  tlsProfile({ id: "TROJAN_RAW_TLS", protocol: "TROJAN", transport: "RAW", storageTransport: "tcp", status: "AVAILABLE" }),
  tlsProfile({ id: "VLESS_WEBSOCKET_TLS", protocol: "VLESS", transport: "WEBSOCKET", storageTransport: "ws", status: "AVAILABLE" }),
  tlsProfile({ id: "TROJAN_WEBSOCKET_TLS", protocol: "TROJAN", transport: "WEBSOCKET", storageTransport: "ws", status: "AVAILABLE" }),
  tlsProfile({ id: "VLESS_GRPC_TLS", protocol: "VLESS", transport: "GRPC", storageTransport: "grpc", status: "AVAILABLE" }),
  tlsProfile({ id: "TROJAN_GRPC_TLS", protocol: "TROJAN", transport: "GRPC", storageTransport: "grpc", status: "AVAILABLE" }),
  tlsProfile({ id: "VLESS_HTTP_UPGRADE_TLS", protocol: "VLESS", transport: "HTTP_UPGRADE", storageTransport: "httpupgrade", status: "AVAILABLE" }),
  tlsProfile({ id: "TROJAN_HTTP_UPGRADE_TLS", protocol: "TROJAN", transport: "HTTP_UPGRADE", storageTransport: "httpupgrade", status: "AVAILABLE" }),
  tlsProfile({ id: "VLESS_XHTTP_TLS", protocol: "VLESS", transport: "XHTTP", storageTransport: "xhttp", status: "AVAILABLE" }),
  tlsProfile({ id: "TROJAN_XHTTP_TLS", protocol: "TROJAN", transport: "XHTTP", storageTransport: "xhttp", status: "AVAILABLE" }),
  tlsProfile({ id: "VLESS_MKCP_TLS", protocol: "VLESS", transport: "MKCP", storageTransport: "kcp", listenerNetwork: "UDP", status: "AVAILABLE" }),
  tlsProfile({ id: "TROJAN_MKCP_TLS", protocol: "TROJAN", transport: "MKCP", storageTransport: "kcp", listenerNetwork: "UDP", status: "AVAILABLE" }),
  {
    id: "VMESS_RAW_TLS",
    status: "AVAILABLE",
    protocol: "VMESS",
    transport: "RAW",
    security: "TLS",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "UUID",
    shareFormat: "VMESS_URI",
    testedCoreVersion: "v26.3.27",
    advisoryCode: "CORE_DEPRECATED",
    storage: {
      protocol: "vmess",
      transport: "tcp",
      security: "tls",
      clientFlow: "",
    },
  },
  {
    id: "SHADOWSOCKS_2022_RAW_NONE",
    status: "AVAILABLE",
    protocol: "SHADOWSOCKS",
    transport: "RAW",
    security: "NONE",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "SHADOWSOCKS_KEY",
    shareFormat: "SHADOWSOCKS_URI",
    testedCoreVersion: "v26.3.27",
    advisoryCode: "CORE_DEPRECATED",
    storage: {
      protocol: "shadowsocks",
      transport: "tcp",
      security: "none",
      clientFlow: "",
    },
  },
  {
    id: "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE",
    status: "AVAILABLE",
    protocol: "SHADOWSOCKS",
    transport: "RAW",
    security: "NONE",
    clientFlow: "NONE",
    listenerNetworks: ["TCP", "UDP"],
    clientCredentialType: "SHADOWSOCKS_KEY",
    shareFormat: "SHADOWSOCKS_URI",
    testedCoreVersion: "v26.3.27",
    advisoryCode: "CORE_DEPRECATED",
    storage: {
      protocol: "shadowsocks",
      transport: "tcp",
      security: "none",
      clientFlow: "",
    },
  },
  {
    id: "HYSTERIA2_TLS",
    status: "AVAILABLE",
    protocol: "HYSTERIA2",
    transport: "HYSTERIA",
    security: "TLS",
    clientFlow: "NONE",
    listenerNetworks: ["UDP"],
    clientCredentialType: "HYSTERIA_AUTH",
    shareFormat: "HYSTERIA2_URI",
    testedCoreVersion: "v26.3.27",
    storage: {
      protocol: "hysteria",
      transport: "hysteria",
      security: "tls",
      clientFlow: "",
    },
  },
  {
    id: "WIREGUARD_UDP_NONE",
    status: "AVAILABLE",
    protocol: "WIREGUARD",
    transport: "NONE",
    security: "NONE",
    clientFlow: "NONE",
    listenerNetworks: ["UDP"],
    clientCredentialType: "WIREGUARD_PEER",
    shareFormat: "WIREGUARD_CONFIG",
    testedCoreVersion: "v26.3.27",
    advisoryCode: "WIREGUARD_BLOCKING_RISK",
    storage: {
      protocol: "wireguard",
      transport: "none",
      security: "none",
      clientFlow: "",
    },
  },
  {
    id: "HTTP_RAW_NONE",
    status: "AVAILABLE",
    protocol: "HTTP",
    transport: "RAW",
    security: "NONE",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "HTTP_BASIC",
    shareFormat: "HTTP_PROXY_URI",
    testedCoreVersion: "v26.3.27",
    advisoryCode: "PLAINTEXT_PROXY_AUTH_RISK",
    storage: {
      protocol: "http",
      transport: "tcp",
      security: "none",
      clientFlow: "",
    },
  },
  {
    id: "MIXED_RAW_NONE",
    status: "AVAILABLE",
    protocol: "MIXED",
    transport: "RAW",
    security: "NONE",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "MIXED_USER_PASSWORD",
    shareFormat: "MIXED_PROXY_ENDPOINTS",
    testedCoreVersion: "v26.3.27",
    advisoryCode: "PLAINTEXT_MIXED_AUTH_RISK",
    storage: {
      protocol: "mixed",
      transport: "tcp",
      security: "none",
      clientFlow: "",
    },
  },
  {
    id: "TUNNEL_TCP_LOCAL_NONE",
    status: "AVAILABLE",
    protocol: "TUNNEL",
    transport: "NONE",
    security: "NONE",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "NONE",
    shareFormat: "NONE",
    testedCoreVersion: "v26.3.27",
    storage: {
      protocol: "tunnel",
      transport: "none",
      security: "none",
      clientFlow: "",
    },
  },
];

function publicSummary(definition: XrayProfileDefinition): XrayProfileSummary {
  return {
    id: definition.id,
    status: definition.status,
    protocol: definition.protocol,
    transport: definition.transport,
    security: definition.security,
    clientFlow: definition.clientFlow,
    listenerNetworks: [...definition.listenerNetworks],
    clientCredentialType: definition.clientCredentialType,
    shareFormat: definition.shareFormat,
    testedCoreVersion: definition.testedCoreVersion,
    ...(definition.advisoryCode ? { advisoryCode: definition.advisoryCode } : {}),
  };
}

export function listAvailableXrayProfiles(): XrayProfileSummary[] {
  return profileDefinitions.filter((profile) => profile.status === "AVAILABLE").map(publicSummary);
}

export function listKnownXrayProfiles(): XrayProfileSummary[] {
  return profileDefinitions.map(publicSummary);
}

export function findAvailableXrayProfileById(profileId: unknown): XrayProfileSummary | null {
  if (typeof profileId !== "string") return null;
  const definition = profileDefinitions.find((profile) => profile.id === profileId && profile.status === "AVAILABLE");
  return definition ? publicSummary(definition) : null;
}

export function findKnownXrayProfileById(profileId: unknown): XrayProfileSummary | null {
  if (typeof profileId !== "string") return null;
  const definition = profileDefinitions.find((profile) => profile.id === profileId);
  return definition ? publicSummary(definition) : null;
}

function matchingProfileDefinition(input: XrayProfileMatchInput): XrayProfileDefinition | null {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  const keys = Object.keys(input);
  if (keys.some((key) => !["protocol", "transport", "security", "clientFlow"].includes(key))) return null;
  if (!["protocol", "transport", "security"].every((key) => keys.includes(key))) return null;
  const matches = profileDefinitions.filter((profile) => (
    input.protocol === profile.storage.protocol
    && input.transport === profile.storage.transport
    && input.security === profile.storage.security
    && (input.clientFlow === undefined || input.clientFlow === profile.storage.clientFlow)
  ));
  return matches.length === 1 ? matches[0] : null;
}

export function findAvailableXrayProfile(input: XrayProfileMatchInput): XrayProfileSummary | null {
  const definition = matchingProfileDefinition(input);
  if (definition?.status !== "AVAILABLE") return null;
  return definition ? publicSummary(definition) : null;
}

export function findKnownXrayProfile(input: XrayProfileMatchInput): XrayProfileSummary | null {
  const definition = matchingProfileDefinition(input);
  return definition ? publicSummary(definition) : null;
}

export type ResolvedStoredXrayInboundDefinition = {
  profile: XrayProfileSummary;
  specVersion: number;
  spec: Readonly<Record<string, unknown>>;
};

export function resolveStoredXrayInboundDefinition(input: XrayProfileMatchInput & {
  profileId?: unknown;
  specVersion?: unknown;
  specJson?: unknown;
}): ResolvedStoredXrayInboundDefinition | null {
  const matchedProfile = findKnownXrayProfile({
    protocol: input.protocol,
    transport: input.transport,
    security: input.security,
    clientFlow: input.clientFlow,
  });
  const storedValues = [input.profileId, input.specVersion, input.specJson];
  const missingCount = storedValues.filter((value) => value === null || value === undefined).length;
  if (missingCount === storedValues.length) {
    return matchedProfile?.id === "VLESS_RAW_REALITY_VISION"
      ? { profile: matchedProfile, specVersion: 1, spec: {} }
      : null;
  }
  if (missingCount !== 0) return null;
  if (typeof input.profileId !== "string" || typeof input.specVersion !== "number"
    || !Number.isSafeInteger(input.specVersion) || input.specVersion < 1 || typeof input.specJson !== "string") return null;
  if (textEncoder.encode(input.specJson).byteLength > XRAY_INBOUND_SPEC_MAX_BYTES) return null;

  const storedDefinition = profileDefinitions.find((profile) => profile.id === input.profileId);
  if (!storedDefinition
    || input.protocol !== storedDefinition.storage.protocol
    || input.transport !== storedDefinition.storage.transport
    || input.security !== storedDefinition.storage.security
    || (input.clientFlow !== undefined && input.clientFlow !== storedDefinition.storage.clientFlow)) return null;
  const storedProfile = publicSummary(storedDefinition);
  const specSchema = xrayInboundSpecSchemas.get(storedProfile.id)?.get(input.specVersion);
  if (!specSchema) return null;
  try {
    const parsed = specSchema.safeParse(JSON.parse(input.specJson));
    return parsed.success
      ? { profile: storedProfile, specVersion: input.specVersion, spec: parsed.data as Readonly<Record<string, unknown>> }
      : null;
  } catch {
    return null;
  }
}

export function resolveStoredXrayInboundProfile(input: Parameters<typeof resolveStoredXrayInboundDefinition>[0]): XrayProfileSummary | null {
  return resolveStoredXrayInboundDefinition(input)?.profile ?? null;
}
