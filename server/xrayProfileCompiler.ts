import {
  findKnownXrayProfile,
  resolveStoredXrayInboundDefinition,
  type XrayProfileSummary,
} from "../shared/xrayProfiles";
import { XRAY_DEFAULT_VERSION } from "./xrayArtifacts";
import {
  canonicalXrayWireGuardKey,
  canonicalXrayWireGuardPeerAddress,
  canonicalXrayWireGuardPrivateKey,
} from "./xrayWireGuard";

const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const hostnamePattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const shortIdPattern = /^(?:[0-9a-f]{2}){1,8}$/;
const x25519KeyPattern = /^[A-Za-z0-9_-]{43}$/;

type XrayConfigClientBase = {
  id: number;
  statsKey: string;
  isEnabled: boolean;
  pendingDelete: boolean;
  sortOrder: number;
};

export type XrayConfigClientInput = XrayConfigClientBase & (
  | { credentialType?: "UUID_AND_SHORT_ID"; uuid: string; shortId: string; flow: string; username?: never; password?: never; shadowsocksKey?: never; auth?: never }
  | { credentialType: "UUID"; uuid: string; flow: string; shortId?: never; username?: never; password?: never; shadowsocksKey?: never; auth?: never }
  | { credentialType: "PASSWORD"; password: string; shortId?: string; uuid?: never; flow?: never; username?: never; shadowsocksKey?: never; auth?: never }
  | { credentialType: "SHADOWSOCKS_KEY"; shadowsocksKey: string; uuid?: never; shortId?: never; flow?: never; username?: never; password?: never; auth?: never }
  | { credentialType: "HYSTERIA_AUTH"; auth: string; uuid?: never; shortId?: never; flow?: never; username?: never; password?: never; shadowsocksKey?: never }
  | { credentialType: "HTTP_BASIC"; username: string; password: string; uuid?: never; shortId?: never; flow?: never; shadowsocksKey?: never; auth?: never }
  | { credentialType: "MIXED_USER_PASSWORD"; username: string; password: string; uuid?: never; shortId?: never; flow?: never; shadowsocksKey?: never; auth?: never }
  | {
    credentialType: "WIREGUARD_PEER";
    privateKey: string;
    preSharedKey: string;
    address: string;
    uuid?: never;
    shortId?: never;
    flow?: never;
    password?: never;
    shadowsocksKey?: never;
    auth?: never;
    username?: never;
  }
);

type XrayConfigInboundBase = {
  id: number;
  runtimeTag: string;
  listenAddress: string;
  listenPort: number;
  protocol: string;
  transport: string;
  profileId?: unknown;
  specVersion?: unknown;
  specJson?: unknown;
  isEnabled: boolean;
  pendingDelete: boolean;
  clients: XrayConfigClientInput[];
};

export type XrayConfigInboundInput = XrayConfigInboundBase & (
  | {
    security: "reality";
    realityTargetHost: string;
    realityTargetPort: number;
    realityServerName: string;
    realityPrivateKey: string;
    shadowsocksServerKey?: never;
    wireguardServerPrivateKey?: never;
    tlsCertificateChainPem?: never;
    tlsPrivateKeyPem?: never;
  }
  | {
    security: "tls";
    realityServerName: string;
    tlsCertificateChainPem: string;
    tlsPrivateKeyPem: string;
    realityTargetHost?: never;
    realityTargetPort?: never;
    realityPrivateKey?: never;
    shadowsocksServerKey?: never;
    wireguardServerPrivateKey?: never;
  }
  | {
    security: "none";
    shadowsocksServerKey: string;
    wireguardServerPrivateKey?: never;
    realityTargetHost?: never;
    realityTargetPort?: never;
    realityServerName?: never;
    realityPrivateKey?: never;
    tlsCertificateChainPem?: never;
    tlsPrivateKeyPem?: never;
  }
  | {
    security: "none";
    shadowsocksServerKey?: never;
    wireguardServerPrivateKey?: never;
    realityTargetHost?: never;
    realityTargetPort?: never;
    realityServerName?: never;
    realityPrivateKey?: never;
    tlsCertificateChainPem?: never;
    tlsPrivateKeyPem?: never;
  }
  | {
    security: "none";
    wireguardServerPrivateKey: string;
    shadowsocksServerKey?: never;
    realityTargetHost?: never;
    realityTargetPort?: never;
    realityServerName?: never;
    realityPrivateKey?: never;
    tlsCertificateChainPem?: never;
    tlsPrivateKeyPem?: never;
  }
);

type NormalizedXrayClientBase = {
  id: number;
  statsKey: string;
  sortOrder: number;
};

export type NormalizedXrayClient = NormalizedXrayClientBase & (
  | { credentialType: "UUID_AND_SHORT_ID"; uuid: string; shortId: string; flow: string }
  | { credentialType: "UUID"; uuid: string; flow: string }
  | { credentialType: "PASSWORD"; password: string; shortId?: string }
  | { credentialType: "SHADOWSOCKS_KEY"; shadowsocksKey: string }
  | { credentialType: "HYSTERIA_AUTH"; auth: string }
  | { credentialType: "WIREGUARD_PEER"; privateKey: string; preSharedKey: string; address: string }
  | { credentialType: "HTTP_BASIC"; username: string; password: string }
  | { credentialType: "MIXED_USER_PASSWORD"; username: string; password: string }
);

type NormalizedXrayInboundBase = {
  id: number;
  profile: XrayProfileSummary;
  specVersion: number;
  spec: Readonly<Record<string, unknown>>;
  runtimeTag: string;
  listenAddress: string;
  listenPort: number;
  clients: NormalizedXrayClient[];
};

export type NormalizedXrayInbound = NormalizedXrayInboundBase & (
  | {
    security: "REALITY";
    realityTargetPort: number;
    realityTargetHost: string;
    realityServerName: string;
    realityPrivateKey: string;
  }
  | {
    security: "TLS";
    realityServerName: string;
    tlsCertificateChainPem: string;
    tlsPrivateKeyPem: string;
  }
  | {
    security: "NONE";
    shadowsocksServerKey: string;
  }
  | {
    security: "NONE";
    wireguardServerPrivateKey: string;
  }
  | {
    security: "NONE";
    httpBasic: true;
  }
  | {
    security: "NONE";
    mixedUserPassword: true;
  }
  | {
    security: "NONE";
    tunnel: true;
  }
);

export class XrayConfigGenerationError extends Error {
  readonly code = "INVALID_CONFIG_INPUT" as const;

  constructor() {
    super("Xray configuration input is invalid");
    this.name = "XrayConfigGenerationError";
  }
}

export function invalidXrayConfig(): never {
  throw new XrayConfigGenerationError();
}

export function positiveXrayId(value: unknown): number {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) invalidXrayConfig();
  return id;
}

function portValue(value: unknown): number {
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) invalidXrayConfig();
  return port;
}

function listenPortValue(value: unknown): number {
  const port = portValue(value);
  if (port < 1000) invalidXrayConfig();
  return port;
}

export function xrayOrderValue(value: unknown): number {
  const order = Number(value);
  if (!Number.isSafeInteger(order)) invalidXrayConfig();
  return order;
}

function normalizedHostname(value: unknown): string {
  const hostname = String(value ?? "").toLowerCase();
  if (!hostnamePattern.test(hostname)) invalidXrayConfig();
  return hostname;
}

function isCanonicalX25519Key(value: string): boolean {
  if (!x25519KeyPattern.test(value)) return false;
  const decoded = Buffer.from(value, "base64url");
  return decoded.length === 32 && decoded.toString("base64url") === value;
}

function canonicalShadowsocks2022Key(value: unknown): string {
  const key = String(value ?? "");
  if (!/^[A-Za-z0-9+/]{43}=$/.test(key)) invalidXrayConfig();
  const decoded = Buffer.from(key, "base64");
  if (decoded.length !== 32 || decoded.toString("base64") !== key) invalidXrayConfig();
  return key;
}

function canonicalHysteriaAuth(value: unknown): string {
  const auth = String(value ?? "");
  if (!/^[A-Za-z0-9_-]{43}$/.test(auth)) invalidXrayConfig();
  const decoded = Buffer.from(auth, "base64url");
  if (decoded.length !== 32 || decoded.toString("base64url") !== auth) invalidXrayConfig();
  return auth;
}

function canonicalBase64UrlToken(value: unknown, bytes: number): string {
  const token = String(value ?? "");
  if (!/^[A-Za-z0-9_-]+$/.test(token)) invalidXrayConfig();
  const decoded = Buffer.from(token, "base64url");
  if (decoded.length !== bytes || decoded.toString("base64url") !== token) invalidXrayConfig();
  return token;
}

function normalizeClient(
  client: XrayConfigClientInput,
  profile: XrayProfileSummary,
  inboundProfile: Pick<XrayConfigInboundInput, "protocol" | "transport" | "security">,
): NormalizedXrayClient {
  const id = positiveXrayId(client.id);
  const statsKey = String(client.statsKey ?? "");
  if (!identifierPattern.test(statsKey)) invalidXrayConfig();
  const matchedProfile = findKnownXrayProfile({
      protocol: inboundProfile.protocol,
      transport: inboundProfile.transport,
      security: inboundProfile.security,
      clientFlow: client.credentialType === "PASSWORD" || client.credentialType === "SHADOWSOCKS_KEY"
        || client.credentialType === "HYSTERIA_AUTH" || client.credentialType === "WIREGUARD_PEER"
        || client.credentialType === "HTTP_BASIC" || client.credentialType === "MIXED_USER_PASSWORD" ? "" : client.flow,
  });
  const matchesExactProfile = matchedProfile?.id === profile.id
    && matchedProfile.clientCredentialType === profile.clientCredentialType;
  const matchesShadowsocksStorage = (profile.id === "SHADOWSOCKS_2022_RAW_NONE"
      || profile.id === "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE")
    && profile.clientCredentialType === "SHADOWSOCKS_KEY"
    && inboundProfile.protocol === "shadowsocks"
    && inboundProfile.transport === "tcp"
    && inboundProfile.security === "none";
  if (!matchesExactProfile && !matchesShadowsocksStorage) invalidXrayConfig();
  const base = { id, statsKey, sortOrder: xrayOrderValue(client.sortOrder) };
  if (profile.clientCredentialType === "HTTP_BASIC" || profile.clientCredentialType === "MIXED_USER_PASSWORD") {
    if (client.credentialType !== profile.clientCredentialType || client.uuid !== undefined || client.shortId !== undefined
      || client.flow !== undefined || client.shadowsocksKey !== undefined || client.auth !== undefined) invalidXrayConfig();
    const normalized = {
      ...base,
      username: canonicalBase64UrlToken(client.username, 16),
      password: canonicalBase64UrlToken(client.password, 32),
    };
    return profile.clientCredentialType === "HTTP_BASIC"
      ? { ...normalized, credentialType: "HTTP_BASIC" }
      : { ...normalized, credentialType: "MIXED_USER_PASSWORD" };
  }
  if (profile.clientCredentialType === "SHADOWSOCKS_KEY") {
    if (client.credentialType !== "SHADOWSOCKS_KEY" || client.uuid !== undefined || client.shortId !== undefined
      || client.flow !== undefined || client.password !== undefined) invalidXrayConfig();
    return { ...base, credentialType: "SHADOWSOCKS_KEY", shadowsocksKey: canonicalShadowsocks2022Key(client.shadowsocksKey) };
  }
  if (profile.clientCredentialType === "HYSTERIA_AUTH") {
    if (client.credentialType !== "HYSTERIA_AUTH" || client.uuid !== undefined || client.shortId !== undefined
      || client.flow !== undefined || client.password !== undefined || client.shadowsocksKey !== undefined) invalidXrayConfig();
    return { ...base, credentialType: "HYSTERIA_AUTH", auth: canonicalHysteriaAuth(client.auth) };
  }
  if (profile.clientCredentialType === "WIREGUARD_PEER") {
    if (client.credentialType !== "WIREGUARD_PEER" || client.uuid !== undefined || client.shortId !== undefined
      || client.flow !== undefined || client.password !== undefined || client.shadowsocksKey !== undefined
      || client.auth !== undefined) invalidXrayConfig();
    try {
      return {
        ...base,
        credentialType: "WIREGUARD_PEER",
        privateKey: canonicalXrayWireGuardPrivateKey(client.privateKey),
        preSharedKey: canonicalXrayWireGuardKey(client.preSharedKey),
        address: canonicalXrayWireGuardPeerAddress(client.address),
      };
    } catch {
      invalidXrayConfig();
    }
  }
  if (profile.clientCredentialType === "PASSWORD") {
    const password = String(client.password ?? "");
    const requiresShortId = profile.security === "REALITY";
    const shortId = client.shortId === undefined ? undefined : String(client.shortId).toLowerCase();
    if (client.credentialType !== "PASSWORD" || client.uuid !== undefined || client.flow !== undefined
      || !/^[A-Za-z0-9_-]{43}$/.test(password)
      || (requiresShortId ? !shortIdPattern.test(shortId ?? "") : shortId !== undefined)) {
      invalidXrayConfig();
    }
    return requiresShortId
      ? { ...base, credentialType: "PASSWORD", password, shortId: shortId as string }
      : { ...base, credentialType: "PASSWORD", password };
  }
  const uuid = String(client.uuid ?? "").toLowerCase();
  if (!uuidPattern.test(uuid)) invalidXrayConfig();
  if (profile.clientCredentialType === "UUID") {
    if (client.credentialType !== "UUID" || client.shortId !== undefined) invalidXrayConfig();
    return { ...base, credentialType: "UUID", uuid, flow: String(client.flow) };
  }
  const shortId = String(client.shortId ?? "").toLowerCase();
  if ((client.credentialType !== undefined && client.credentialType !== "UUID_AND_SHORT_ID") || !shortIdPattern.test(shortId)) {
    invalidXrayConfig();
  }
  return { ...base, credentialType: "UUID_AND_SHORT_ID", uuid, shortId, flow: String(client.flow) };
}

export function normalizeXrayInbound(inbound: XrayConfigInboundInput): NormalizedXrayInbound {
  const id = positiveXrayId(inbound.id);
  const runtimeTag = String(inbound.runtimeTag ?? "");
  const definition = resolveStoredXrayInboundDefinition({
    protocol: inbound.protocol,
    transport: inbound.transport,
    security: inbound.security,
    profileId: inbound.profileId,
    specVersion: inbound.specVersion,
    specJson: inbound.specJson,
  });
  const expectedListenAddress = definition?.profile.id === "TUNNEL_TCP_LOCAL_NONE" ? "127.0.0.1" : "0.0.0.0";
  if (!identifierPattern.test(runtimeTag) || inbound.listenAddress !== expectedListenAddress
    || !definition || definition.profile.testedCoreVersion !== XRAY_DEFAULT_VERSION) {
    invalidXrayConfig();
  }
  const clients = inbound.clients
    .filter((client) => client.isEnabled && !client.pendingDelete)
    .map((client) => normalizeClient(client, definition.profile, inbound))
    .sort((left, right) => left.sortOrder - right.sortOrder || left.id - right.id);
  const clientIds = new Set<number>();
  const uuids = new Set<string>();
  const passwords = new Set<string>();
  const shadowsocksKeys = new Set<string>();
  const hysteriaAuths = new Set<string>();
  const wireguardPrivateKeys = new Set<string>();
  const wireguardPreSharedKeys = new Set<string>();
  const wireguardAddresses = new Set<string>();
  const httpUsernames = new Set<string>();
  const shortIds = new Set<string>();
  const statsKeys = new Set<string>();
  for (const client of clients) {
    const credentialDuplicate = client.credentialType === "PASSWORD"
      ? passwords.has(client.password)
      : client.credentialType === "SHADOWSOCKS_KEY"
        ? shadowsocksKeys.has(client.shadowsocksKey)
        : client.credentialType === "HYSTERIA_AUTH"
          ? hysteriaAuths.has(client.auth)
          : client.credentialType === "WIREGUARD_PEER"
            ? wireguardPrivateKeys.has(client.privateKey)
              || wireguardPreSharedKeys.has(client.preSharedKey)
              || wireguardAddresses.has(client.address)
            : client.credentialType === "HTTP_BASIC" || client.credentialType === "MIXED_USER_PASSWORD"
              ? httpUsernames.has(client.username) || passwords.has(client.password)
            : uuids.has(client.uuid);
    const shortId = "shortId" in client ? client.shortId ?? null : null;
    if (clientIds.has(client.id) || credentialDuplicate || (shortId !== null && shortIds.has(shortId)) || statsKeys.has(client.statsKey)) {
      invalidXrayConfig();
    }
    clientIds.add(client.id);
    if (client.credentialType === "PASSWORD") passwords.add(client.password);
    else if (client.credentialType === "SHADOWSOCKS_KEY") shadowsocksKeys.add(client.shadowsocksKey);
    else if (client.credentialType === "HYSTERIA_AUTH") hysteriaAuths.add(client.auth);
    else if (client.credentialType === "WIREGUARD_PEER") {
      wireguardPrivateKeys.add(client.privateKey);
      wireguardPreSharedKeys.add(client.preSharedKey);
      wireguardAddresses.add(client.address);
    }
    else if (client.credentialType === "HTTP_BASIC" || client.credentialType === "MIXED_USER_PASSWORD") {
      httpUsernames.add(client.username);
      passwords.add(client.password);
    }
    else uuids.add(client.uuid);
    if (shortId !== null) shortIds.add(shortId);
    statsKeys.add(client.statsKey);
  }
  const base = {
    id,
    profile: definition.profile,
    specVersion: definition.specVersion,
    spec: definition.spec,
    runtimeTag,
    listenAddress: expectedListenAddress,
    listenPort: listenPortValue(inbound.listenPort),
    clients,
  };
  if (definition.profile.security === "TLS") {
    const realityServerName = normalizedHostname(inbound.realityServerName);
    if (inbound.security !== "tls" || typeof inbound.tlsCertificateChainPem !== "string"
      || typeof inbound.tlsPrivateKeyPem !== "string"
      || inbound.realityTargetHost !== undefined || inbound.realityTargetPort !== undefined
      || inbound.realityPrivateKey !== undefined || inbound.shadowsocksServerKey !== undefined
      || inbound.wireguardServerPrivateKey !== undefined) invalidXrayConfig();
    return {
      ...base,
      security: "TLS",
      realityServerName,
      tlsCertificateChainPem: inbound.tlsCertificateChainPem,
      tlsPrivateKeyPem: inbound.tlsPrivateKeyPem,
    };
  }
  if (definition.profile.security === "NONE") {
    if (definition.profile.id === "TUNNEL_TCP_LOCAL_NONE") {
      if (inbound.security !== "none" || inbound.shadowsocksServerKey !== undefined
        || inbound.wireguardServerPrivateKey !== undefined
        || inbound.realityTargetHost !== undefined || inbound.realityTargetPort !== undefined
        || inbound.realityServerName !== undefined || inbound.realityPrivateKey !== undefined
        || inbound.tlsCertificateChainPem !== undefined || inbound.tlsPrivateKeyPem !== undefined
        || clients.length !== 0
        || typeof definition.spec.targetAddress !== "string"
        || typeof definition.spec.targetPort !== "number") {
        invalidXrayConfig();
      }
      return { ...base, security: "NONE", tunnel: true };
    }
    if (definition.profile.id === "HTTP_RAW_NONE") {
      if (inbound.security !== "none" || inbound.shadowsocksServerKey !== undefined
        || inbound.wireguardServerPrivateKey !== undefined
        || inbound.realityTargetHost !== undefined || inbound.realityTargetPort !== undefined
        || inbound.realityServerName !== undefined || inbound.realityPrivateKey !== undefined
        || inbound.tlsCertificateChainPem !== undefined || inbound.tlsPrivateKeyPem !== undefined
        || clients.length < 1 || clients.some((client) => client.credentialType !== "HTTP_BASIC")) {
        invalidXrayConfig();
      }
      return { ...base, security: "NONE", httpBasic: true };
    }
    if (definition.profile.id === "MIXED_RAW_NONE") {
      if (inbound.security !== "none" || inbound.shadowsocksServerKey !== undefined
        || inbound.wireguardServerPrivateKey !== undefined
        || inbound.realityTargetHost !== undefined || inbound.realityTargetPort !== undefined
        || inbound.realityServerName !== undefined || inbound.realityPrivateKey !== undefined
        || inbound.tlsCertificateChainPem !== undefined || inbound.tlsPrivateKeyPem !== undefined
        || clients.length < 1 || clients.some((client) => client.credentialType !== "MIXED_USER_PASSWORD")) {
        invalidXrayConfig();
      }
      return { ...base, security: "NONE", mixedUserPassword: true };
    }
    if (definition.profile.id === "WIREGUARD_UDP_NONE") {
      let wireguardServerPrivateKey: string;
      try {
        wireguardServerPrivateKey = canonicalXrayWireGuardPrivateKey(inbound.wireguardServerPrivateKey);
      } catch {
        invalidXrayConfig();
      }
      if (inbound.security !== "none" || inbound.shadowsocksServerKey !== undefined
        || inbound.realityTargetHost !== undefined || inbound.realityTargetPort !== undefined
        || inbound.realityServerName !== undefined || inbound.realityPrivateKey !== undefined
        || inbound.tlsCertificateChainPem !== undefined || inbound.tlsPrivateKeyPem !== undefined
        || clients.length < 1 || clients.length > 32
        || clients.some((client) => client.credentialType !== "WIREGUARD_PEER"
          || client.privateKey === wireguardServerPrivateKey)) invalidXrayConfig();
      return { ...base, security: "NONE", wireguardServerPrivateKey };
    }
    const shadowsocksServerKey = canonicalShadowsocks2022Key(inbound.shadowsocksServerKey);
    if ((definition.profile.id !== "SHADOWSOCKS_2022_RAW_NONE"
        && definition.profile.id !== "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE")
      || inbound.security !== "none"
      || inbound.realityTargetHost !== undefined || inbound.realityTargetPort !== undefined
      || inbound.realityServerName !== undefined || inbound.realityPrivateKey !== undefined
      || inbound.tlsCertificateChainPem !== undefined || inbound.tlsPrivateKeyPem !== undefined
      || inbound.wireguardServerPrivateKey !== undefined
      || clients.length < 1 || clients.some((client) => client.credentialType !== "SHADOWSOCKS_KEY"
        || client.shadowsocksKey === shadowsocksServerKey)) invalidXrayConfig();
    return { ...base, security: "NONE", shadowsocksServerKey };
  }
  const realityServerName = normalizedHostname(inbound.realityServerName);
  const realityPrivateKey = String(inbound.realityPrivateKey ?? "");
  if (definition.profile.security !== "REALITY" || inbound.security !== "reality"
    || inbound.tlsCertificateChainPem !== undefined || inbound.tlsPrivateKeyPem !== undefined
    || inbound.shadowsocksServerKey !== undefined || inbound.wireguardServerPrivateKey !== undefined
    || !isCanonicalX25519Key(realityPrivateKey)) {
    invalidXrayConfig();
  }
  return {
    ...base,
    security: "REALITY",
    realityTargetPort: portValue(inbound.realityTargetPort),
    realityTargetHost: normalizedHostname(inbound.realityTargetHost),
    realityServerName,
    realityPrivateKey,
  };
}
