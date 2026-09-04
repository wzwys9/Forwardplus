type XrayRealityShareBase = {
  publicAddress: string;
  listenPort: number;
  serverName: string;
  realityPublicKey: string;
  shortId: string;
  fingerprint: "chrome";
  spiderX: string;
  displayName: string;
};

type XrayVlessRealityShareBase = XrayRealityShareBase & { uuid: string };

export type XrayVlessRealityShareInput = XrayVlessRealityShareBase & (
  | { transport?: "tcp"; flow: "xtls-rprx-vision"; serviceName?: never; path?: never }
  | { transport: "grpc"; flow: ""; serviceName: string; path?: never }
  | { transport: "xhttp"; flow: ""; path: string; serviceName?: never }
);

export type XrayTrojanRealityShareInput = XrayRealityShareBase & { password: string };

type XrayVlessTlsShareBase = {
  uuid: string;
  publicAddress: string;
  listenPort: number;
  serverName: string;
  fingerprint: "chrome";
  leafFingerprintSha256: string;
  displayName: string;
};

export type XrayVmessTlsShareInput = XrayVlessTlsShareBase;

export type XrayShadowsocks2022ShareInput = {
  serverKey: string;
  userKey: string;
  publicAddress: string;
  listenPort: number;
  displayName: string;
};

export type XrayHysteria2ShareInput = {
  auth: string;
  publicAddress: string;
  listenPort: number;
  serverName: string;
  leafFingerprintSha256: string;
  displayName: string;
};

export type XrayHttpProxyShareInput = {
  username: string;
  password: string;
  publicAddress: string;
  listenPort: number;
};

export type XrayMixedProxyShareInput = XrayHttpProxyShareInput;

export type XrayMixedProxyEndpoints = Readonly<{
  socks5Uri: string;
  httpUri: string;
}>;

export type XrayVlessTlsShareInput = XrayVlessTlsShareBase & (
  | { profileId: "VLESS_RAW_TLS" | "VLESS_RAW_TLS_VISION"; path?: never; serviceName?: never }
  | { profileId: "VLESS_WEBSOCKET_TLS"; path: string; serviceName?: never }
  | { profileId: "VLESS_HTTP_UPGRADE_TLS"; path: string; serviceName?: never }
  | { profileId: "VLESS_XHTTP_TLS"; path: string; serviceName?: never }
  | { profileId: "VLESS_GRPC_TLS"; serviceName: string; path?: never }
  | { profileId: "VLESS_MKCP_TLS"; path?: never; serviceName?: never }
);

type XrayTrojanTlsShareBase = {
  password: string;
  publicAddress: string;
  listenPort: number;
  serverName: string;
  fingerprint: "chrome";
  leafFingerprintSha256: string;
  displayName: string;
};

export type XrayTrojanTlsShareInput = XrayTrojanTlsShareBase & (
  | { profileId: "TROJAN_RAW_TLS"; path?: never; serviceName?: never }
  | { profileId: "TROJAN_WEBSOCKET_TLS"; path: string; serviceName?: never }
  | { profileId: "TROJAN_HTTP_UPGRADE_TLS"; path: string; serviceName?: never }
  | { profileId: "TROJAN_XHTTP_TLS"; path: string; serviceName?: never }
  | { profileId: "TROJAN_GRPC_TLS"; serviceName: string; path?: never }
  | { profileId: "TROJAN_MKCP_TLS"; path?: never; serviceName?: never }
);

const hostnamePattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const ipv4Pattern = /^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/;
const controlPattern = /[\u0000-\u001f\u007f]/;

function isIpv4(value: string): boolean {
  return ipv4Pattern.test(value) && value.split(".").every((octet) => Number(octet) <= 255);
}

function isIpv6(value: string): boolean {
  if (!value.includes(":") || value.includes("[") || value.includes("]") || value.includes("%")) return false;
  try {
    return new URL(`http://[${value}]/`).hostname.startsWith("[");
  } catch {
    return false;
  }
}

function requiredString(value: unknown, maxLength: number): string {
  const normalized = String(value ?? "").trim();
  if (!normalized || normalized.length > maxLength || controlPattern.test(normalized)) {
    throw new Error("Invalid Xray share input");
  }
  return normalized;
}

function canonicalShadowsocks2022Key(value: unknown): string {
  const key = requiredString(value, 44);
  if (!/^[A-Za-z0-9+/]{43}=$/.test(key)) throw new Error("Invalid Xray share input");
  const decoded = Buffer.from(key, "base64");
  if (decoded.length !== 32 || decoded.toString("base64") !== key) throw new Error("Invalid Xray share input");
  return key;
}

function canonicalHysteria2Auth(value: unknown): string {
  const auth = String(value ?? "");
  if (!/^[A-Za-z0-9_-]{43}$/.test(auth)) throw new Error("Invalid Xray share input");
  const decoded = Buffer.from(auth, "base64url");
  if (decoded.length !== 32 || decoded.toString("base64url") !== auth) throw new Error("Invalid Xray share input");
  return auth;
}

export function buildXrayVlessRealityUri(input: XrayVlessRealityShareInput): string {
  const uuid = requiredString(input.uuid, 36).toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(uuid)) {
    throw new Error("Invalid Xray share input");
  }
  const publicAddress = requiredString(input.publicAddress, 253).toLowerCase();
  const endpoint = isIpv6(publicAddress) ? `[${publicAddress}]`
    : isIpv4(publicAddress) || hostnamePattern.test(publicAddress) ? publicAddress : null;
  if (!endpoint || !Number.isInteger(input.listenPort) || input.listenPort < 1000 || input.listenPort > 65535) {
    throw new Error("Invalid Xray share input");
  }
  const serverName = requiredString(input.serverName, 253).toLowerCase();
  const publicKey = requiredString(input.realityPublicKey, 43);
  const shortId = requiredString(input.shortId, 16).toLowerCase();
  const spiderX = requiredString(input.spiderX, 256);
  const displayName = requiredString(input.displayName, 128);
  const transport = input.transport ?? "tcp";
  if (!hostnamePattern.test(serverName)
    || !/^[A-Za-z0-9_-]{43}$/.test(publicKey)
    || !/^[0-9a-f]{16}$/.test(shortId)
    || !spiderX.startsWith("/")
    || input.fingerprint !== "chrome") {
    throw new Error("Invalid Xray share input");
  }
  let serviceName: string | null = null;
  let xhttpPath: string | null = null;
  if (transport === "grpc") {
    serviceName = requiredString(input.serviceName, 128);
    if (!/^[A-Za-z0-9._~-]+$/.test(serviceName) || input.flow !== "") {
      throw new Error("Invalid Xray share input");
    }
  } else if (transport === "xhttp") {
    xhttpPath = requiredString(input.path, 128);
    if (!/^\/[A-Za-z0-9._~/-]*$/.test(xhttpPath) || input.flow !== "") {
      throw new Error("Invalid Xray share input");
    }
  } else if (transport !== "tcp" || input.flow !== "xtls-rprx-vision"
    || ("serviceName" in input && input.serviceName !== undefined)
    || ("path" in input && input.path !== undefined)) {
    throw new Error("Invalid Xray share input");
  }

  const query = [
    ["type", transport],
    ["security", "reality"],
    ["sni", serverName],
    ["fp", "chrome"],
    ["pbk", publicKey],
    ["sid", shortId],
    ["spx", spiderX],
    ...(transport === "grpc"
      ? [["serviceName", serviceName as string]]
      : transport === "xhttp"
        ? [["path", xhttpPath as string], ["mode", "auto"]]
        : [["flow", "xtls-rprx-vision"]]),
  ].map(([key, value]) => `${key}=${encodeURIComponent(value)}`).join("&");
  return `vless://${uuid}@${endpoint}:${input.listenPort}?${query}#${encodeURIComponent(displayName)}`;
}

export function buildXrayVlessTlsUri(input: XrayVlessTlsShareInput): string {
  const uuid = requiredString(input.uuid, 36).toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(uuid)) {
    throw new Error("Invalid Xray share input");
  }
  const publicAddress = requiredString(input.publicAddress, 253).toLowerCase();
  const endpoint = isIpv6(publicAddress) ? `[${publicAddress}]`
    : isIpv4(publicAddress) || hostnamePattern.test(publicAddress) ? publicAddress : null;
  if (!endpoint || !Number.isInteger(input.listenPort) || input.listenPort < 1000 || input.listenPort > 65535) {
    throw new Error("Invalid Xray share input");
  }
  const serverName = requiredString(input.serverName, 253).toLowerCase();
  const pin = requiredString(input.leafFingerprintSha256, 64);
  const displayName = requiredString(input.displayName, 128);
  const webSocket = input.profileId === "VLESS_WEBSOCKET_TLS";
  const httpUpgrade = input.profileId === "VLESS_HTTP_UPGRADE_TLS";
  const xhttp = input.profileId === "VLESS_XHTTP_TLS";
  const grpc = input.profileId === "VLESS_GRPC_TLS";
  const mkcp = input.profileId === "VLESS_MKCP_TLS";
  if ((input.profileId !== "VLESS_RAW_TLS" && input.profileId !== "VLESS_RAW_TLS_VISION"
      && !webSocket && !httpUpgrade && !xhttp && !grpc && !mkcp)
    || !hostnamePattern.test(serverName) || input.fingerprint !== "chrome" || !/^[0-9a-f]{64}$/.test(pin)) {
    throw new Error("Invalid Xray share input");
  }
  const path = webSocket || httpUpgrade || xhttp ? requiredString(input.path, 128) : null;
  const serviceName = grpc ? requiredString(input.serviceName, 128) : null;
  if ((path !== null && !/^\/[A-Za-z0-9._~/-]*$/.test(path))
    || (serviceName !== null && !/^[A-Za-z0-9._~-]+$/.test(serviceName))
    || (!webSocket && !httpUpgrade && !xhttp && "path" in input && input.path !== undefined)
    || (!grpc && "serviceName" in input && input.serviceName !== undefined)) {
    throw new Error("Invalid Xray share input");
  }
  const query = [
    ["type", grpc ? "grpc" : webSocket ? "ws" : httpUpgrade ? "httpupgrade" : xhttp ? "xhttp" : mkcp ? "kcp" : "tcp"],
    ["security", "tls"],
    ["sni", serverName],
    ["fp", "chrome"],
    ["pcs", pin],
    ["encryption", "none"],
    ...(input.profileId === "VLESS_RAW_TLS_VISION" ? [["flow", "xtls-rprx-vision"]] : []),
    ...(path === null ? [] : [["path", path]]),
    ...(xhttp ? [["mode", "auto"]] : []),
    ...(serviceName === null ? [] : [["serviceName", serviceName], ["alpn", "h2"]]),
  ].map(([key, value]) => `${key}=${encodeURIComponent(value)}`).join("&");
  return `vless://${uuid}@${endpoint}:${input.listenPort}?${query}#${encodeURIComponent(displayName)}`;
}

export function buildXrayVmessTlsUri(input: XrayVmessTlsShareInput): string {
  const uuid = requiredString(input.uuid, 36).toLowerCase();
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(uuid)) {
    throw new Error("Invalid Xray share input");
  }
  const publicAddress = requiredString(input.publicAddress, 253).toLowerCase();
  if ((!isIpv6(publicAddress) && !isIpv4(publicAddress) && !hostnamePattern.test(publicAddress))
    || !Number.isInteger(input.listenPort) || input.listenPort < 1000 || input.listenPort > 65535) {
    throw new Error("Invalid Xray share input");
  }
  const serverName = requiredString(input.serverName, 253).toLowerCase();
  const pin = requiredString(input.leafFingerprintSha256, 64);
  const displayName = requiredString(input.displayName, 128);
  if (!hostnamePattern.test(serverName) || input.fingerprint !== "chrome" || !/^[0-9a-f]{64}$/.test(pin)) {
    throw new Error("Invalid Xray share input");
  }
  const payload = JSON.stringify({
    v: "2",
    ps: displayName,
    add: publicAddress,
    port: input.listenPort,
    id: uuid,
    scy: "auto",
    net: "tcp",
    type: "none",
    tls: "tls",
    sni: serverName,
    fp: "chrome",
    pcs: pin,
  });
  return `vmess://${Buffer.from(payload, "utf8").toString("base64")}`;
}

export function buildXrayShadowsocks2022Uri(input: XrayShadowsocks2022ShareInput): string {
  const serverKey = canonicalShadowsocks2022Key(input.serverKey);
  const userKey = canonicalShadowsocks2022Key(input.userKey);
  const publicAddress = requiredString(input.publicAddress, 253).toLowerCase();
  const endpoint = isIpv6(publicAddress) ? `[${publicAddress}]`
    : isIpv4(publicAddress) || hostnamePattern.test(publicAddress) ? publicAddress : null;
  const displayName = requiredString(input.displayName, 128);
  if (!endpoint || serverKey === userKey
    || !Number.isInteger(input.listenPort) || input.listenPort < 1000 || input.listenPort > 65535) {
    throw new Error("Invalid Xray share input");
  }
  return `ss://2022-blake3-aes-256-gcm:${encodeURIComponent(serverKey)}:${encodeURIComponent(userKey)}`
    + `@${endpoint}:${input.listenPort}#${encodeURIComponent(displayName)}`;
}

export function buildXrayHysteria2Uri(input: XrayHysteria2ShareInput): string {
  const auth = canonicalHysteria2Auth(input.auth);
  const publicAddress = requiredString(input.publicAddress, 253).toLowerCase();
  const endpoint = isIpv6(publicAddress) ? `[${publicAddress}]`
    : isIpv4(publicAddress) || hostnamePattern.test(publicAddress) ? publicAddress : null;
  const serverName = requiredString(input.serverName, 253).toLowerCase();
  const pin = requiredString(input.leafFingerprintSha256, 64);
  const displayName = requiredString(input.displayName, 128);
  if (!endpoint || !Number.isInteger(input.listenPort) || input.listenPort < 1000 || input.listenPort > 65535
    || !hostnamePattern.test(serverName) || !/^[0-9a-f]{64}$/.test(pin)) {
    throw new Error("Invalid Xray share input");
  }
  return `hysteria2://${encodeURIComponent(auth)}@${endpoint}:${input.listenPort}`
    + `?sni=${encodeURIComponent(serverName)}&pinSHA256=${pin}#${encodeURIComponent(displayName)}`;
}

function xrayUserPasswordProxyAuthority(input: XrayHttpProxyShareInput): string {
  const username = requiredString(input.username, 22);
  const password = requiredString(input.password, 43);
  const publicAddress = requiredString(input.publicAddress, 253).toLowerCase();
  const endpoint = isIpv6(publicAddress) ? `[${publicAddress}]`
    : isIpv4(publicAddress) || hostnamePattern.test(publicAddress) ? publicAddress : null;
  const usernameBytes = Buffer.from(username, "base64url");
  const passwordBytes = Buffer.from(password, "base64url");
  if (!/^[A-Za-z0-9_-]{22}$/.test(username) || !/^[A-Za-z0-9_-]{43}$/.test(password)
    || usernameBytes.length !== 16 || usernameBytes.toString("base64url") !== username
    || passwordBytes.length !== 32 || passwordBytes.toString("base64url") !== password
    || !endpoint || !Number.isInteger(input.listenPort)
    || input.listenPort < 1000 || input.listenPort > 65535) {
    throw new Error("Invalid Xray share input");
  }
  return `${encodeURIComponent(username)}:${encodeURIComponent(password)}@${endpoint}:${input.listenPort}`;
}

export function buildXrayHttpProxyUri(input: XrayHttpProxyShareInput): string {
  return `http://${xrayUserPasswordProxyAuthority(input)}`;
}

export function buildXrayMixedProxyEndpoints(input: XrayMixedProxyShareInput): XrayMixedProxyEndpoints {
  const authority = xrayUserPasswordProxyAuthority(input);
  return {
    socks5Uri: `socks5://${authority}`,
    httpUri: `http://${authority}`,
  };
}

export function buildXrayTrojanTlsUri(input: XrayTrojanTlsShareInput): string {
  const password = requiredString(input.password, 43);
  const publicAddress = requiredString(input.publicAddress, 253).toLowerCase();
  const endpoint = isIpv6(publicAddress) ? `[${publicAddress}]`
    : isIpv4(publicAddress) || hostnamePattern.test(publicAddress) ? publicAddress : null;
  if (!endpoint || !Number.isInteger(input.listenPort) || input.listenPort < 1000 || input.listenPort > 65535) {
    throw new Error("Invalid Xray share input");
  }
  const serverName = requiredString(input.serverName, 253).toLowerCase();
  const pin = requiredString(input.leafFingerprintSha256, 64);
  const displayName = requiredString(input.displayName, 128);
  const webSocket = input.profileId === "TROJAN_WEBSOCKET_TLS";
  const httpUpgrade = input.profileId === "TROJAN_HTTP_UPGRADE_TLS";
  const xhttp = input.profileId === "TROJAN_XHTTP_TLS";
  const grpc = input.profileId === "TROJAN_GRPC_TLS";
  const mkcp = input.profileId === "TROJAN_MKCP_TLS";
  if ((input.profileId !== "TROJAN_RAW_TLS" && !webSocket && !httpUpgrade && !xhttp && !grpc && !mkcp)
    || !/^[A-Za-z0-9_-]{43}$/.test(password)
    || !hostnamePattern.test(serverName)
    || input.fingerprint !== "chrome"
    || !/^[0-9a-f]{64}$/.test(pin)) {
    throw new Error("Invalid Xray share input");
  }
  const path = webSocket || httpUpgrade || xhttp ? requiredString(input.path, 128) : null;
  const serviceName = grpc ? requiredString(input.serviceName, 128) : null;
  if ((path !== null && !/^\/[A-Za-z0-9._~/-]*$/.test(path))
    || (serviceName !== null && !/^[A-Za-z0-9._~-]+$/.test(serviceName))
    || (!webSocket && !httpUpgrade && !xhttp && "path" in input && input.path !== undefined)
    || (!grpc && "serviceName" in input && input.serviceName !== undefined)) {
    throw new Error("Invalid Xray share input");
  }
  const query = [
    ["type", grpc ? "grpc" : webSocket ? "ws" : httpUpgrade ? "httpupgrade" : xhttp ? "xhttp" : mkcp ? "kcp" : "tcp"],
    ["security", "tls"],
    ["sni", serverName],
    ["fp", "chrome"],
    ["pcs", pin],
    ...(path === null ? [] : [["path", path]]),
    ...(xhttp ? [["mode", "auto"]] : []),
    ...(serviceName === null ? [] : [["serviceName", serviceName], ["alpn", "h2"]]),
  ].map(([key, value]) => `${key}=${encodeURIComponent(value)}`).join("&");
  return `trojan://${encodeURIComponent(password)}@${endpoint}:${input.listenPort}?${query}#${encodeURIComponent(displayName)}`;
}

export function buildXrayTrojanRealityUri(input: XrayTrojanRealityShareInput): string {
  const password = requiredString(input.password, 43);
  if (!/^[A-Za-z0-9_-]{43}$/.test(password)) throw new Error("Invalid Xray share input");
  const publicAddress = requiredString(input.publicAddress, 253).toLowerCase();
  const endpoint = isIpv6(publicAddress) ? `[${publicAddress}]`
    : isIpv4(publicAddress) || hostnamePattern.test(publicAddress) ? publicAddress : null;
  if (!endpoint || !Number.isInteger(input.listenPort) || input.listenPort < 1000 || input.listenPort > 65535) {
    throw new Error("Invalid Xray share input");
  }
  const serverName = requiredString(input.serverName, 253).toLowerCase();
  const publicKey = requiredString(input.realityPublicKey, 43);
  const shortId = requiredString(input.shortId, 16).toLowerCase();
  const spiderX = requiredString(input.spiderX, 256);
  const displayName = requiredString(input.displayName, 128);
  if (!hostnamePattern.test(serverName)
    || !/^[A-Za-z0-9_-]{43}$/.test(publicKey)
    || !/^[0-9a-f]{16}$/.test(shortId)
    || !spiderX.startsWith("/")
    || input.fingerprint !== "chrome") {
    throw new Error("Invalid Xray share input");
  }
  const query = [
    ["type", "tcp"],
    ["security", "reality"],
    ["sni", serverName],
    ["fp", "chrome"],
    ["pbk", publicKey],
    ["sid", shortId],
    ["spx", spiderX],
  ].map(([key, value]) => `${key}=${encodeURIComponent(value)}`).join("&");
  return `trojan://${encodeURIComponent(password)}@${endpoint}:${input.listenPort}?${query}#${encodeURIComponent(displayName)}`;
}
