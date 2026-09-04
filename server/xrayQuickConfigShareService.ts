import { resolveStoredXrayInboundDefinition } from "../shared/xrayProfiles";
import { boolLiteral, quoteIdentifier } from "./dbCompat";
import { queryRaw } from "./dbRuntime";
import {
  getXrayAccessEntryShare,
  XrayAccessServiceError,
} from "./xrayAccessService";
import {
  getXrayClientShare,
  XrayClientServiceError,
} from "./xrayClientService";
import {
  buildXrayExternalProxyShare,
  XrayExternalProxyServiceError,
} from "./xrayExternalProxyService";

export const XRAY_QUICK_CONFIG_SHARE_ERROR_CODES = [
  "QUICK_CONFIG_NOT_FOUND",
  "QUICK_CONFIG_TARGET_UNSUPPORTED",
  "SENSITIVE_DATA_UNAVAILABLE",
] as const;

export type XrayQuickConfigShareErrorCode =
  (typeof XRAY_QUICK_CONFIG_SHARE_ERROR_CODES)[number];

export class XrayQuickConfigShareError extends Error {
  constructor(readonly code: XrayQuickConfigShareErrorCode) {
    super(code);
    this.name = "XrayQuickConfigShareError";
  }
}

export type XrayQuickConfigShareAccessRef =
  | Readonly<{ type: "LEGACY_CLIENT"; legacyClientId: unknown }>
  | Readonly<{ type: "ACCESS_ENTRY"; accessEntryId: unknown }>;

export type XrayQuickConfigDerivedShare =
  | Readonly<{ format: "VLESS_URI" | "SHADOWSOCKS_URI"; uri: string }>
  | Readonly<{
    format: "SOCKS5_ENDPOINT";
    endpoint: Readonly<{
      host: string;
      port: number;
      username?: string;
      password?: string;
    }>;
  }>;

type Row = Record<string, unknown>;
type ResolvedAccessRef =
  | Readonly<{ type: "LEGACY_CLIENT"; id: number }>
  | Readonly<{ type: "ACCESS_ENTRY"; id: number }>;

const CONTROL_PATTERN = /[\u0000-\u001f\u007f]/;
const FQDN_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function fail(code: XrayQuickConfigShareErrorCode): never {
  throw new XrayQuickConfigShareError(code);
}

function positiveId(value: unknown, code: XrayQuickConfigShareErrorCode): number {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) fail(code);
  return id;
}

function publicPort(value: unknown): number {
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    fail("QUICK_CONFIG_TARGET_UNSUPPORTED");
  }
  return port;
}

function canonicalFqdn(value: unknown): string {
  if (typeof value !== "string" || value !== value.trim().toLowerCase()
    || CONTROL_PATTERN.test(value) || !FQDN_PATTERN.test(value)) {
    fail("QUICK_CONFIG_TARGET_UNSUPPORTED");
  }
  return value;
}

function parseAccessRef(value: XrayQuickConfigShareAccessRef | undefined): ResolvedAccessRef | undefined {
  if (value === undefined) return undefined;
  if (!value || typeof value !== "object") fail("QUICK_CONFIG_TARGET_UNSUPPORTED");
  const keys = Object.keys(value).sort();
  if (value.type === "LEGACY_CLIENT"
    && keys.length === 2 && keys[0] === "legacyClientId" && keys[1] === "type") {
    return {
      type: value.type,
      id: positiveId(value.legacyClientId, "QUICK_CONFIG_TARGET_UNSUPPORTED"),
    };
  }
  if (value.type === "ACCESS_ENTRY"
    && keys.length === 2 && keys[0] === "accessEntryId" && keys[1] === "type") {
    return {
      type: value.type,
      id: positiveId(value.accessEntryId, "QUICK_CONFIG_TARGET_UNSUPPORTED"),
    };
  }
  return fail("QUICK_CONFIG_TARGET_UNSUPPORTED");
}

function replaceUriAuthority(
  uri: string,
  expectedScheme: "vless" | "ss" | "socks5",
  fqdn: string,
  port: number,
): string {
  if (!uri.startsWith(`${expectedScheme}://`) || Buffer.byteLength(uri, "utf8") > 8192
    || CONTROL_PATTERN.test(uri)) {
    fail("SENSITIVE_DATA_UNAVAILABLE");
  }
  const authorityStart = expectedScheme.length + 3;
  const suffixStartCandidate = [uri.indexOf("/", authorityStart), uri.indexOf("?", authorityStart), uri.indexOf("#", authorityStart)]
    .filter((index) => index >= authorityStart)
    .sort((left, right) => left - right)[0];
  const authorityEnd = suffixStartCandidate ?? uri.length;
  const authority = uri.slice(authorityStart, authorityEnd);
  const at = authority.lastIndexOf("@");
  const userInfo = at < 0 ? "" : authority.slice(0, at + 1);
  if ((expectedScheme === "vless" || expectedScheme === "ss") && userInfo.length === 0) {
    fail("SENSITIVE_DATA_UNAVAILABLE");
  }
  return `${uri.slice(0, authorityStart)}${userInfo}${fqdn}:${port}${uri.slice(authorityEnd)}`;
}

function decodedCredential(value: string, maxBytes: number): string {
  let decoded: string;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    return fail("SENSITIVE_DATA_UNAVAILABLE");
  }
  if (!decoded || CONTROL_PATTERN.test(decoded) || Buffer.byteLength(decoded, "utf8") > maxBytes) {
    fail("SENSITIVE_DATA_UNAVAILABLE");
  }
  return decoded;
}

function socks5Endpoint(uri: string, fqdn: string, port: number): XrayQuickConfigDerivedShare {
  const prefix = "socks5://";
  const authorityEndCandidate = [uri.indexOf("/", prefix.length), uri.indexOf("?", prefix.length), uri.indexOf("#", prefix.length)]
    .filter((index) => index >= prefix.length)
    .sort((left, right) => left - right)[0];
  const authorityEnd = authorityEndCandidate ?? uri.length;
  const authority = uri.slice(prefix.length, authorityEnd);
  const at = authority.lastIndexOf("@");
  const hostPort = at < 0 ? authority : authority.slice(at + 1);
  if (!uri.startsWith(prefix) || hostPort !== `${fqdn}:${port}`) {
    fail("SENSITIVE_DATA_UNAVAILABLE");
  }
  if (at < 0) return { format: "SOCKS5_ENDPOINT", endpoint: { host: fqdn, port } };
  const userInfo = authority.slice(0, at);
  const separator = userInfo.indexOf(":");
  if (separator <= 0 || separator === userInfo.length - 1) fail("SENSITIVE_DATA_UNAVAILABLE");
  return {
    format: "SOCKS5_ENDPOINT",
    endpoint: {
      host: fqdn,
      port,
      username: decodedCredential(userInfo.slice(0, separator), 256),
      password: decodedCredential(userInfo.slice(separator + 1), 512),
    },
  };
}

async function activeQuickConfig(quickConfigId: number): Promise<Row> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Row>(
    `SELECT qc.${q("targetType")}, qc.${q("xrayInboundId")}, qc.${q("externalProxyNodeId")},
            qc.${q("fqdn")}, t.${q("publicPort")},
            i.${q("protocol")} AS ${q("inboundProtocol")}, i.${q("transport")} AS ${q("inboundTransport")},
            i.${q("security")} AS ${q("inboundSecurity")}, i.${q("profileId")} AS ${q("inboundProfileId")},
            i.${q("specVersion")} AS ${q("inboundSpecVersion")}, i.${q("specJson")} AS ${q("inboundSpecJson")}
       FROM ${q("xray_quick_configs")} qc
       JOIN ${q("xray_quick_config_topology_revisions")} t
         ON t.${q("id")} = qc.${q("activeTopologyRevisionId")} AND t.${q("quickConfigId")} = qc.${q("id")}
       LEFT JOIN ${q("xray_inbounds")} i ON i.${q("id")} = qc.${q("xrayInboundId")}
      WHERE qc.${q("id")} = ? AND qc.${q("state")} = 'ACTIVE'
        AND t.${q("state")} = 'APPLIED' AND t.${q("activeSlot")} = 1
      LIMIT 1`,
    [quickConfigId],
  );
  if (!rows[0]) fail("QUICK_CONFIG_NOT_FOUND");
  return rows[0];
}

async function resolveInboundAccessRef(
  inboundId: number,
  requested: ResolvedAccessRef | undefined,
): Promise<ResolvedAccessRef> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Row>(
    `SELECT ${q("id")}, ${q("legacyClientId")}
       FROM ${q("xray_access_entries")}
      WHERE ${q("inboundId")} = ? AND ${q("isEnabled")} = ${boolLiteral(true)}
        AND ${q("pendingDelete")} = ${boolLiteral(false)}
      ORDER BY ${q("sortOrder")} ASC, ${q("id")} ASC`,
    [inboundId],
  );
  const available = rows.map((row): ResolvedAccessRef => row.legacyClientId === null || row.legacyClientId === undefined
    ? { type: "ACCESS_ENTRY", id: positiveId(row.id, "SENSITIVE_DATA_UNAVAILABLE") }
    : { type: "LEGACY_CLIENT", id: positiveId(row.legacyClientId, "SENSITIVE_DATA_UNAVAILABLE") });
  if (!requested) {
    if (available.length !== 1) fail("QUICK_CONFIG_TARGET_UNSUPPORTED");
    return available[0];
  }
  const matched = available.find((candidate) => candidate.type === requested.type && candidate.id === requested.id);
  if (!matched) fail("QUICK_CONFIG_TARGET_UNSUPPORTED");
  return matched;
}

async function managedInboundShare(
  row: Row,
  requested: ResolvedAccessRef | undefined,
  fqdn: string,
  port: number,
): Promise<XrayQuickConfigDerivedShare> {
  const inboundId = positiveId(row.xrayInboundId, "QUICK_CONFIG_TARGET_UNSUPPORTED");
  const definition = resolveStoredXrayInboundDefinition({
    protocol: row.inboundProtocol,
    transport: row.inboundTransport,
    security: row.inboundSecurity,
    profileId: row.inboundProfileId,
    specVersion: row.inboundSpecVersion,
    specJson: row.inboundSpecJson,
  });
  const format = definition?.profile.shareFormat;
  if (format !== "VLESS_URI" && format !== "SHADOWSOCKS_URI" && format !== "MIXED_PROXY_ENDPOINTS") {
    fail("QUICK_CONFIG_TARGET_UNSUPPORTED");
  }
  const access = await resolveInboundAccessRef(inboundId, requested);
  if (access.type === "LEGACY_CLIENT") {
    if (format !== "VLESS_URI") fail("QUICK_CONFIG_TARGET_UNSUPPORTED");
    const share = await getXrayClientShare(access.id);
    return { format, uri: replaceUriAuthority(share.uri, "vless", fqdn, port) };
  }
  const share = await getXrayAccessEntryShare(access.id, format);
  if (format === "MIXED_PROXY_ENDPOINTS") {
    if (!("socks5Uri" in share) || typeof share.socks5Uri !== "string") fail("SENSITIVE_DATA_UNAVAILABLE");
    const uri = replaceUriAuthority(share.socks5Uri, "socks5", fqdn, port);
    return socks5Endpoint(uri, fqdn, port);
  }
  if (!("uri" in share) || typeof share.uri !== "string") fail("SENSITIVE_DATA_UNAVAILABLE");
  return {
    format,
    uri: replaceUriAuthority(share.uri, format === "VLESS_URI" ? "vless" : "ss", fqdn, port),
  };
}

function mapServiceError(error: unknown): never {
  if (error instanceof XrayQuickConfigShareError) throw error;
  if (error instanceof XrayClientServiceError || error instanceof XrayAccessServiceError
    || error instanceof XrayExternalProxyServiceError) {
    if (error.code === "SENSITIVE_DATA_UNAVAILABLE") fail("SENSITIVE_DATA_UNAVAILABLE");
    fail("QUICK_CONFIG_TARGET_UNSUPPORTED");
  }
  throw error;
}

export async function getXrayQuickConfigDerivedShare(input: {
  quickConfigId: unknown;
  userId: unknown;
  accessRef?: XrayQuickConfigShareAccessRef;
}): Promise<XrayQuickConfigDerivedShare> {
  try {
    const quickConfigId = positiveId(input?.quickConfigId, "QUICK_CONFIG_NOT_FOUND");
    positiveId(input?.userId, "QUICK_CONFIG_TARGET_UNSUPPORTED");
    const accessRef = parseAccessRef(input?.accessRef);
    const row = await activeQuickConfig(quickConfigId);
    const fqdn = canonicalFqdn(row.fqdn);
    const port = publicPort(row.publicPort);
    if (row.targetType === "XRAY_INBOUND") {
      return await managedInboundShare(row, accessRef, fqdn, port);
    }
    if (row.targetType !== "EXTERNAL_PROXY_NODE" || accessRef) {
      fail("QUICK_CONFIG_TARGET_UNSUPPORTED");
    }
    const externalProxyNodeId = positiveId(row.externalProxyNodeId, "QUICK_CONFIG_TARGET_UNSUPPORTED");
    const originalUri = await buildXrayExternalProxyShare(externalProxyNodeId);
    if (originalUri.startsWith("vless://")) {
      return { format: "VLESS_URI", uri: replaceUriAuthority(originalUri, "vless", fqdn, port) };
    }
    if (originalUri.startsWith("ss://")) {
      return { format: "SHADOWSOCKS_URI", uri: replaceUriAuthority(originalUri, "ss", fqdn, port) };
    }
    if (originalUri.startsWith("socks5://")) {
      return socks5Endpoint(replaceUriAuthority(originalUri, "socks5", fqdn, port), fqdn, port);
    }
    return fail("QUICK_CONFIG_TARGET_UNSUPPORTED");
  } catch (error) {
    mapServiceError(error);
  }
}
