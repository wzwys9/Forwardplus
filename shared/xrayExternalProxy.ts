export const XRAY_EXTERNAL_PROXY_PROTOCOLS = [
  "VLESS_REALITY_VISION",
  "SHADOWSOCKS",
  "SOCKS5",
] as const;

export type XrayExternalProxyProtocol = (typeof XRAY_EXTERNAL_PROXY_PROTOCOLS)[number];

export const XRAY_EXTERNAL_PROXY_SECRET_KINDS = [
  "VLESS_UUID",
  "VLESS_SHORT_ID",
  "SHADOWSOCKS_PASSWORD",
  "SOCKS_USERNAME",
  "SOCKS_PASSWORD",
] as const;

export type XrayExternalProxySecretKind = (typeof XRAY_EXTERNAL_PROXY_SECRET_KINDS)[number];

export const XRAY_EXTERNAL_VLESS_FINGERPRINTS = ["chrome", "random"] as const;
export type XrayExternalVlessFingerprint = (typeof XRAY_EXTERNAL_VLESS_FINGERPRINTS)[number];

type ExternalProxyBase = {
  address: string;
  port: number;
  displayName: string;
  specVersion: 1;
};

export type XrayExternalVlessRealityVisionDefinition = ExternalProxyBase & {
  protocol: "VLESS_REALITY_VISION";
  spec: {
    serverName: string;
    fingerprint: XrayExternalVlessFingerprint;
    publicKey: string;
    spiderX: string;
  };
  credentials: {
    uuid: string;
    shortId: string;
  };
};

export type XrayExternalShadowsocksDefinition = ExternalProxyBase & {
  protocol: "SHADOWSOCKS";
  spec: { method: XrayExternalShadowsocksMethod };
  credentials: { password: string };
};

export type XrayExternalSocks5Definition = ExternalProxyBase & {
  protocol: "SOCKS5";
  spec: Record<string, never>;
  credentials: { username?: string; password?: string };
};

export type XrayExternalProxyDefinition =
  | XrayExternalVlessRealityVisionDefinition
  | XrayExternalShadowsocksDefinition
  | XrayExternalSocks5Definition;

export const XRAY_EXTERNAL_SHADOWSOCKS_METHODS = [
  "2022-blake3-aes-128-gcm",
  "2022-blake3-aes-256-gcm",
  "2022-blake3-chacha20-poly1305",
  "aes-128-gcm",
  "aes-256-gcm",
  "chacha20-ietf-poly1305",
  "chacha20-poly1305",
] as const;

export type XrayExternalShadowsocksMethod = (typeof XRAY_EXTERNAL_SHADOWSOCKS_METHODS)[number];

const MAX_URI_BYTES = 4096;
const MAX_PASSWORD_BYTES = 512;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const HOSTNAME_PATTERN = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const CONTROL_PATTERN = /[\u0000-\u001f\u007f]/;
const BASE64URL_32_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const SHORT_ID_PATTERN = /^(?:[0-9a-f]{2}){1,8}$/;

function invalid(): never {
  throw new Error("INVALID_EXTERNAL_PROXY_LINK");
}

function utf8Length(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

function boundedText(value: unknown, maxBytes: number, allowEmpty = false): string {
  if (typeof value !== "string" || (!allowEmpty && value.length === 0)
    || CONTROL_PATTERN.test(value) || utf8Length(value) > maxBytes) invalid();
  return value;
}

function decodePart(value: string, maxBytes: number, allowEmpty = false): string {
  let decoded: string;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    invalid();
  }
  return boundedText(decoded!, maxBytes, allowEmpty);
}

function decodeBase64(value: string): string {
  if (!value || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(value)) invalid();
  const standard = value.replace(/-/g, "+").replace(/_/g, "/");
  if (standard.length % 4 === 1) invalid();
  const padded = standard + "=".repeat((4 - standard.length % 4) % 4);
  const decoded = Buffer.from(padded, "base64");
  if (!decoded.length || decoded.toString("base64").replace(/=+$/, "") !== padded.replace(/=+$/, "")) invalid();
  return boundedText(decoded.toString("utf8"), MAX_PASSWORD_BYTES + 300);
}

function isIpv4(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => /^(?:0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
}

function isIpv6(value: string): boolean {
  if (!value.includes(":") || value.includes("%") || value.includes("[") || value.includes("]")) return false;
  try {
    const parsed = new URL(`http://[${value}]/`);
    return parsed.hostname.slice(1, -1).toLowerCase() === value.toLowerCase();
  } catch {
    return false;
  }
}

export function normalizeXrayExternalProxyAddress(value: unknown): string {
  const address = boundedText(typeof value === "string" ? value.trim().toLowerCase() : value, 253);
  if (!isIpv4(address) && !isIpv6(address) && !HOSTNAME_PATTERN.test(address)) invalid();
  return address;
}

function normalizePort(value: unknown): number {
  const port = typeof value === "number" ? value : Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) invalid();
  return port;
}

function endpointFromUrl(url: URL): { address: string; port: number } {
  const hostname = url.hostname.startsWith("[") && url.hostname.endsWith("]")
    ? url.hostname.slice(1, -1)
    : url.hostname;
  if (!url.port) invalid();
  return { address: normalizeXrayExternalProxyAddress(hostname), port: normalizePort(url.port) };
}

function displayNameFromHash(hash: string): string {
  return hash ? decodePart(hash.slice(1), 128, true) : "";
}

function assertNoDuplicateParams(params: URLSearchParams, allowed: ReadonlySet<string>): void {
  const seen = new Set<string>();
  for (const [key] of params) {
    if (!allowed.has(key) || seen.has(key)) invalid();
    seen.add(key);
  }
}

function requiredQuery(params: URLSearchParams, key: string, maxBytes: number): string {
  const value = params.get(key);
  if (value === null) invalid();
  return boundedText(value, maxBytes);
}

function canonicalPublicKey(value: unknown): string {
  const key = boundedText(value, 43);
  if (!BASE64URL_32_PATTERN.test(key)) invalid();
  const decoded = Buffer.from(key, "base64url");
  if (decoded.length !== 32 || decoded.toString("base64url") !== key) invalid();
  return key;
}

function canonicalUuid(value: unknown): string {
  const uuid = boundedText(value, 36).toLowerCase();
  if (!UUID_PATTERN.test(uuid)) invalid();
  return uuid;
}

function canonicalShortId(value: unknown): string {
  const shortId = boundedText(value, 16).toLowerCase();
  if (!SHORT_ID_PATTERN.test(shortId)) invalid();
  return shortId;
}

function canonicalServerName(value: unknown): string {
  const serverName = boundedText(typeof value === "string" ? value.trim().toLowerCase() : value, 253);
  if (!HOSTNAME_PATTERN.test(serverName)) invalid();
  return serverName;
}

function canonicalVlessFingerprint(value: unknown): XrayExternalVlessFingerprint {
  const fingerprint = boundedText(value, 16);
  if (!(XRAY_EXTERNAL_VLESS_FINGERPRINTS as readonly string[]).includes(fingerprint)) invalid();
  return fingerprint as XrayExternalVlessFingerprint;
}

function hasApprovedVlessRawPath(uri: string): boolean {
  const authorityStart = uri.indexOf("://") + 3;
  const queryStart = uri.indexOf("?");
  if (authorityStart < 3 || queryStart < authorityStart) return false;
  const authorityAndPath = uri.slice(authorityStart, queryStart);
  const pathStart = authorityAndPath.indexOf("/");
  return pathStart === -1 || authorityAndPath.slice(pathStart) === "/";
}

function parseVless(uri: string): XrayExternalVlessRealityVisionDefinition {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    invalid();
  }
  if (url!.protocol !== "vless:" || url!.password
    || !hasApprovedVlessRawPath(uri)
    || (url!.pathname !== "" && url!.pathname !== "/") || url!.search === "") invalid();
  const allowed = new Set(["type", "security", "encryption", "flow", "sni", "fp", "pbk", "sid", "spx"]);
  assertNoDuplicateParams(url!.searchParams, allowed);
  if (requiredQuery(url!.searchParams, "type", 16) !== "tcp"
    || requiredQuery(url!.searchParams, "security", 16) !== "reality"
    || (url!.searchParams.get("encryption") !== null && url!.searchParams.get("encryption") !== "none")
    || requiredQuery(url!.searchParams, "flow", 32) !== "xtls-rprx-vision") invalid();

  const { address, port } = endpointFromUrl(url!);
  const fingerprint = canonicalVlessFingerprint(requiredQuery(url!.searchParams, "fp", 16));
  const spiderX = url!.searchParams.get("spx") ?? "/";
  boundedText(spiderX, 256);
  if (!spiderX.startsWith("/")) invalid();
  return {
    protocol: "VLESS_REALITY_VISION",
    address,
    port,
    displayName: displayNameFromHash(url!.hash),
    specVersion: 1,
    spec: {
      serverName: canonicalServerName(requiredQuery(url!.searchParams, "sni", 253)),
      fingerprint,
      publicKey: canonicalPublicKey(requiredQuery(url!.searchParams, "pbk", 43)),
      spiderX,
    },
    credentials: {
      uuid: canonicalUuid(decodePart(url!.username, 36)),
      shortId: canonicalShortId(requiredQuery(url!.searchParams, "sid", 16)),
    },
  };
}

function canonicalShadowsocksMethod(value: unknown): XrayExternalShadowsocksMethod {
  const method = boundedText(value, 64).toLowerCase();
  if (!(XRAY_EXTERNAL_SHADOWSOCKS_METHODS as readonly string[]).includes(method)) invalid();
  return method as XrayExternalShadowsocksMethod;
}

function canonicalStandardBase64Key(value: string, bytes: number): boolean {
  if (!/^[A-Za-z0-9+/]+={1,2}$/.test(value)) return false;
  const decoded = Buffer.from(value, "base64");
  return decoded.length === bytes && decoded.toString("base64") === value;
}

function canonicalShadowsocksPassword(method: XrayExternalShadowsocksMethod, value: unknown): string {
  const password = boundedText(value, MAX_PASSWORD_BYTES);
  if (method.startsWith("2022-")) {
    const keyBytes = method === "2022-blake3-aes-128-gcm" ? 16 : 32;
    const parts = password.split(":");
    if ((parts.length !== 1 && parts.length !== 2)
      || !parts.every((part) => canonicalStandardBase64Key(part, keyBytes))) invalid();
  }
  return password;
}

function splitShadowsocksUserInfo(value: string): { method: XrayExternalShadowsocksMethod; password: string } {
  const separator = value.indexOf(":");
  if (separator <= 0 || separator === value.length - 1) invalid();
  const method = canonicalShadowsocksMethod(value.slice(0, separator));
  return { method, password: canonicalShadowsocksPassword(method, value.slice(separator + 1)) };
}

function parseShadowsocks(uri: string): XrayExternalShadowsocksDefinition {
  const hashIndex = uri.indexOf("#");
  const withoutHash = hashIndex < 0 ? uri : uri.slice(0, hashIndex);
  const hash = hashIndex < 0 ? "" : uri.slice(hashIndex + 1);
  const body = withoutHash.slice("ss://".length);
  let endpointUrl: URL;
  let userInfo: { method: XrayExternalShadowsocksMethod; password: string };

  if (body.includes("@")) {
    try {
      endpointUrl = new URL(withoutHash);
    } catch {
      invalid();
    }
    if (endpointUrl!.protocol !== "ss:" || endpointUrl!.search || endpointUrl!.pathname) invalid();
    if (endpointUrl!.password) {
      userInfo = splitShadowsocksUserInfo(
        `${decodePart(endpointUrl!.username, 64)}:${decodePart(endpointUrl!.password, MAX_PASSWORD_BYTES)}`,
      );
    } else {
      userInfo = splitShadowsocksUserInfo(decodeBase64(endpointUrl!.username));
    }
  } else {
    const decoded = decodeBase64(body);
    const at = decoded.lastIndexOf("@");
    if (at <= 0 || at === decoded.length - 1) invalid();
    userInfo = splitShadowsocksUserInfo(decoded.slice(0, at));
    try {
      endpointUrl = new URL(`ss://placeholder@${decoded.slice(at + 1)}`);
    } catch {
      invalid();
    }
    if (endpointUrl!.search || endpointUrl!.pathname) invalid();
  }

  const { address, port } = endpointFromUrl(endpointUrl!);
  return {
    protocol: "SHADOWSOCKS",
    address,
    port,
    displayName: hash ? decodePart(hash, 128, true) : "",
    specVersion: 1,
    spec: { method: userInfo!.method },
    credentials: { password: userInfo!.password },
  };
}

function parseSocks5(uri: string): XrayExternalSocks5Definition {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    invalid();
  }
  if (url!.protocol !== "socks5:" || url!.pathname || url!.search) invalid();
  const hasUsername = url!.username.length > 0;
  const hasPassword = url!.password.length > 0;
  if (hasUsername !== hasPassword) invalid();
  const { address, port } = endpointFromUrl(url!);
  const credentials = hasUsername ? {
    username: decodePart(url!.username, 256),
    password: decodePart(url!.password, MAX_PASSWORD_BYTES),
  } : {};
  return {
    protocol: "SOCKS5",
    address,
    port,
    displayName: displayNameFromHash(url!.hash),
    specVersion: 1,
    spec: {},
    credentials,
  };
}

export function parseXrayExternalProxyUri(value: unknown): XrayExternalProxyDefinition {
  if (typeof value !== "string" || utf8Length(value) > MAX_URI_BYTES
    || value.trim() !== value || CONTROL_PATTERN.test(value)) invalid();
  try {
    decodeURI(value);
  } catch {
    invalid();
  }
  const scheme = value.slice(0, value.indexOf(":" )).toLowerCase();
  if (scheme === "vless") return parseVless(value);
  if (scheme === "ss") return parseShadowsocks(value);
  if (scheme === "socks5") return parseSocks5(value);
  return invalid();
}

function normalizedDefinition(input: XrayExternalProxyDefinition): XrayExternalProxyDefinition {
  const address = normalizeXrayExternalProxyAddress(input.address);
  const port = normalizePort(input.port);
  const displayName = boundedText(input.displayName, 128, true);
  if (input.specVersion !== 1) invalid();
  if (input.protocol === "VLESS_REALITY_VISION") {
    if (Object.keys(input.spec).some((key) => !["serverName", "fingerprint", "publicKey", "spiderX"].includes(key))
      || !input.spec.spiderX.startsWith("/")) invalid();
    const fingerprint = canonicalVlessFingerprint(input.spec.fingerprint);
    return {
      protocol: input.protocol,
      address,
      port,
      displayName,
      specVersion: 1,
      spec: {
        serverName: canonicalServerName(input.spec.serverName),
        fingerprint,
        publicKey: canonicalPublicKey(input.spec.publicKey),
        spiderX: boundedText(input.spec.spiderX, 256),
      },
      credentials: {
        uuid: canonicalUuid(input.credentials.uuid),
        shortId: canonicalShortId(input.credentials.shortId),
      },
    };
  }
  if (input.protocol === "SHADOWSOCKS") {
    if (Object.keys(input.spec).some((key) => key !== "method")) invalid();
    const method = canonicalShadowsocksMethod(input.spec.method);
    return {
      protocol: input.protocol,
      address,
      port,
      displayName,
      specVersion: 1,
      spec: { method },
      credentials: { password: canonicalShadowsocksPassword(method, input.credentials.password) },
    };
  }
  if (input.protocol !== "SOCKS5" || Object.keys(input.spec).length !== 0) invalid();
  const username = input.credentials.username;
  const password = input.credentials.password;
  if ((username === undefined) !== (password === undefined)) invalid();
  return {
    protocol: input.protocol,
    address,
    port,
    displayName,
    specVersion: 1,
    spec: {},
    credentials: username === undefined ? {} : {
      username: boundedText(username, 256),
      password: boundedText(password, MAX_PASSWORD_BYTES),
    },
  };
}

function endpointAuthority(address: string, port: number): string {
  return `${isIpv6(address) ? `[${address}]` : address}:${port}`;
}

export function buildXrayExternalProxyUri(
  input: XrayExternalProxyDefinition,
  endpointOverride?: { address: string; port: number },
): string {
  const definition = normalizedDefinition(input);
  const address = endpointOverride
    ? normalizeXrayExternalProxyAddress(endpointOverride.address)
    : definition.address;
  const port = endpointOverride ? normalizePort(endpointOverride.port) : definition.port;
  const endpoint = endpointAuthority(address, port);
  const fragment = definition.displayName ? `#${encodeURIComponent(definition.displayName)}` : "";

  if (definition.protocol === "VLESS_REALITY_VISION") {
    const query = new URLSearchParams([
      ["type", "tcp"],
      ["security", "reality"],
      ["encryption", "none"],
      ["flow", "xtls-rprx-vision"],
      ["sni", definition.spec.serverName],
      ["fp", definition.spec.fingerprint],
      ["pbk", definition.spec.publicKey],
      ["sid", definition.credentials.shortId],
      ["spx", definition.spec.spiderX],
    ]);
    return `vless://${definition.credentials.uuid}@${endpoint}?${query.toString()}${fragment}`;
  }
  if (definition.protocol === "SHADOWSOCKS") {
    const encoded = Buffer.from(`${definition.spec.method}:${definition.credentials.password}`, "utf8").toString("base64url");
    return `ss://${encoded}@${endpoint}${fragment}`;
  }
  const auth = definition.credentials.username === undefined ? "" :
    `${encodeURIComponent(definition.credentials.username)}:${encodeURIComponent(definition.credentials.password!)}@`;
  return `socks5://${auth}${endpoint}${fragment}`;
}
