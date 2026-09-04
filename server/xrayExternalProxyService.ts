import crypto from "node:crypto";
import { isIP } from "node:net";

import {
  buildXrayExternalProxyUri,
  normalizeXrayExternalProxyAddress,
  parseXrayExternalProxyUri,
  type XrayExternalProxyDefinition,
  type XrayExternalProxyProtocol,
  type XrayExternalProxySecretKind,
} from "../shared/xrayExternalProxy";
import { isExternalProxyForwardType } from "../shared/forwardTypes";
import { quoteIdentifier } from "./dbCompat";
import {
  executeRaw,
  insertAndGetId,
  nowDate,
  queryRaw,
  rawAffectedRows,
  withDatabaseTransaction,
} from "./dbRuntime";
import { withKeyedTaskLock } from "./keyedTaskLock";
import {
  decryptXraySecret,
  encryptXraySecret,
  fingerprintXraySecret,
  inspectXraySecretEnvelope,
  loadXrayMasterKeyFile,
  xrayExternalProxySecretContext,
  XraySecretUnavailableError,
  type XraySecretKeyring,
} from "./xraySecretCrypto";

export const XRAY_EXTERNAL_PROXY_ERROR_CODES = [
  "EXTERNAL_PROXY_NOT_FOUND",
  "EXTERNAL_PROXY_IN_USE",
  "EXTERNAL_PROXY_INVALID_LINK",
  "EXTERNAL_PROXY_UNSUPPORTED",
  "EXTERNAL_PROXY_REFERENCE_INVALID",
  "CONFIRMATION_MISMATCH",
  "SENSITIVE_DATA_UNAVAILABLE",
] as const;

export type XrayExternalProxyErrorCode = (typeof XRAY_EXTERNAL_PROXY_ERROR_CODES)[number];

export class XrayExternalProxyServiceError extends Error {
  constructor(readonly code: XrayExternalProxyErrorCode) {
    super(code);
    this.name = "XrayExternalProxyServiceError";
  }
}

type Row = Record<string, unknown>;

export type XrayExternalProxySafeDto = Readonly<{
  id: number;
  name: string;
  protocol: XrayExternalProxyProtocol;
  address: string;
  port: number;
  specVersion: 1;
  publicSettings: Record<string, unknown>;
  credentialsConfigured: boolean;
  inboundCount: number;
  ruleCount: number;
  createdAt: Date | null;
  updatedAt: Date | null;
}>;

function serviceError(error: unknown): never {
  if (error instanceof XrayExternalProxyServiceError) throw error;
  if (error instanceof XraySecretUnavailableError) {
    throw new XrayExternalProxyServiceError("SENSITIVE_DATA_UNAVAILABLE");
  }
  if (error instanceof Error && error.message === "INVALID_EXTERNAL_PROXY_LINK") {
    throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_INVALID_LINK");
  }
  throw error;
}

function positiveId(value: unknown, code: XrayExternalProxyErrorCode = "EXTERNAL_PROXY_NOT_FOUND"): number {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) throw new XrayExternalProxyServiceError(code);
  return id;
}

function displayName(value: unknown): string {
  const name = String(value ?? "").trim();
  if (!name || Buffer.byteLength(name, "utf8") > 128 || /[\u0000-\u001f\u007f]/.test(name)) {
    throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_INVALID_LINK");
  }
  return name;
}

function dateValue(value: unknown): Date | null {
  if (value == null || value === "") return null;
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value : null;
  const text = String(value);
  const numeric = /^\d+(?:\.\d+)?$/.test(text) ? Number(text) : NaN;
  const date = Number.isFinite(numeric) ? new Date(numeric < 10_000_000_000 ? numeric * 1000 : numeric) : new Date(text);
  return Number.isFinite(date.getTime()) ? date : null;
}

function databaseBoolean(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || String(value ?? "").toLowerCase() === "true";
}

function protocolValue(value: unknown): XrayExternalProxyProtocol {
  if (value === "VLESS_REALITY_VISION" || value === "SHADOWSOCKS" || value === "SOCKS5") return value;
  throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_REFERENCE_INVALID");
}

function parsePublicSettings(row: Row): Record<string, unknown> {
  if (Number(row.specVersion) !== 1 || typeof row.specJson !== "string"
    || Buffer.byteLength(row.specJson, "utf8") > 4096) {
    throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_REFERENCE_INVALID");
  }
  let spec: unknown;
  try {
    spec = JSON.parse(row.specJson);
  } catch {
    throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_REFERENCE_INVALID");
  }
  if (!spec || typeof spec !== "object" || Array.isArray(spec)) {
    throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_REFERENCE_INVALID");
  }
  return spec as Record<string, unknown>;
}

function credentialCountIsValid(protocol: XrayExternalProxyProtocol, count: number): boolean {
  if (protocol === "VLESS_REALITY_VISION") return count === 2;
  if (protocol === "SHADOWSOCKS") return count === 1;
  return count === 0 || count === 2;
}

function safeDto(row: Row): XrayExternalProxySafeDto {
  const id = positiveId(row.id);
  const protocol = protocolValue(row.protocol);
  const secretCount = Number(row.secretCount ?? 0);
  if (!Number.isSafeInteger(secretCount) || !credentialCountIsValid(protocol, secretCount)) {
    throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_REFERENCE_INVALID");
  }
  const port = Number(row.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_REFERENCE_INVALID");
  }
  const name = String(row.name ?? "");
  const address = String(row.address ?? "");
  const publicSettings = parsePublicSettings(row);
  const candidate: XrayExternalProxyDefinition = protocol === "VLESS_REALITY_VISION" ? {
    protocol,
    address,
    port,
    displayName: name,
    specVersion: 1,
    spec: publicSettings as Extract<XrayExternalProxyDefinition, { protocol: "VLESS_REALITY_VISION" }>["spec"],
    credentials: { uuid: "00000000-0000-4000-8000-000000000001", shortId: "12" },
  } as XrayExternalProxyDefinition : protocol === "SHADOWSOCKS" ? {
    protocol,
    address,
    port,
    displayName: name,
    specVersion: 1,
    spec: publicSettings as Extract<XrayExternalProxyDefinition, { protocol: "SHADOWSOCKS" }>["spec"],
    credentials: {
      password: String(publicSettings.method).startsWith("2022-blake3-aes-128")
        ? Buffer.alloc(16).toString("base64")
        : String(publicSettings.method).startsWith("2022-")
          ? Buffer.alloc(32).toString("base64")
          : "configured",
    },
  } as XrayExternalProxyDefinition : {
    protocol,
    address,
    port,
    displayName: name,
    specVersion: 1,
    spec: publicSettings as Record<string, never>,
    credentials: {},
  };
  try {
    buildXrayExternalProxyUri(candidate);
  } catch {
    throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_REFERENCE_INVALID");
  }
  return {
    id,
    name,
    protocol,
    address: candidate.address,
    port,
    specVersion: 1,
    publicSettings,
    credentialsConfigured: true,
    inboundCount: Number(row.inboundCount ?? 0),
    ruleCount: Number(row.ruleCount ?? 0),
    createdAt: dateValue(row.createdAt),
    updatedAt: dateValue(row.updatedAt),
  };
}

function selectWithCounts(where = ""): string {
  const q = quoteIdentifier;
  return `SELECT n.*,
      (SELECT COUNT(*) FROM ${q("xray_external_proxy_secrets")} s WHERE s.${q("externalProxyNodeId")} = n.${q("id")}) AS ${q("secretCount")},
      (SELECT COUNT(*) FROM ${q("xray_inbounds")} i WHERE i.${q("externalProxyNodeId")} = n.${q("id")}) AS ${q("inboundCount")},
      (SELECT COUNT(*) FROM ${q("forward_rules")} r WHERE r.${q("targetExternalProxyNodeId")} = n.${q("id")}) AS ${q("ruleCount")},
      (SELECT COUNT(*) FROM ${q("xray_quick_configs")} qc WHERE qc.${q("externalProxyNodeId")} = n.${q("id")} AND qc.${q("state")} <> 'REMOVED') AS ${q("quickConfigCount")}
    FROM ${q("xray_external_proxy_nodes")} n${where}`;
}

async function requireNodeRow(id: number): Promise<Row> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Row>(`${selectWithCounts(` WHERE n.${q("id")} = ?`)} LIMIT 1`, [id]);
  if (!rows[0]) throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_NOT_FOUND");
  return rows[0];
}

function publicSpec(definition: XrayExternalProxyDefinition): Record<string, unknown> {
  return definition.spec;
}

function credentialEntries(definition: XrayExternalProxyDefinition): Array<[XrayExternalProxySecretKind, string]> {
  if (definition.protocol === "VLESS_REALITY_VISION") {
    return [["VLESS_UUID", definition.credentials.uuid], ["VLESS_SHORT_ID", definition.credentials.shortId]];
  }
  if (definition.protocol === "SHADOWSOCKS") return [["SHADOWSOCKS_PASSWORD", definition.credentials.password]];
  if (definition.credentials.username === undefined) return [];
  return [["SOCKS_USERNAME", definition.credentials.username], ["SOCKS_PASSWORD", definition.credentials.password!]];
}

async function insertCredentialRows(
  nodeId: number,
  nodeTag: string,
  definition: XrayExternalProxyDefinition,
  keyring: XraySecretKeyring,
): Promise<void> {
  for (const [kind, plaintext] of credentialEntries(definition)) {
    const context = xrayExternalProxySecretContext(nodeTag, kind);
    const encryptedValue = encryptXraySecret(plaintext, context, keyring);
    const envelope = inspectXraySecretEnvelope(encryptedValue);
    await insertAndGetId("xray_external_proxy_secrets", {
      externalProxyNodeId: nodeId,
      kind,
      encryptedValue,
      fingerprint: fingerprintXraySecret(plaintext, context, keyring),
      keyVersion: envelope.version,
      createdAt: nowDate(),
      updatedAt: nowDate(),
    });
  }
}

function parseImport(uri: unknown): XrayExternalProxyDefinition {
  try {
    return parseXrayExternalProxyUri(uri);
  } catch {
    throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_INVALID_LINK");
  }
}

export function previewXrayExternalProxyImport(uri: unknown) {
  const definition = parseImport(uri);
  return {
    protocol: definition.protocol,
    suggestedName: definition.displayName,
    address: definition.address,
    port: definition.port,
    specVersion: definition.specVersion,
    publicSettings: definition.spec,
    credentialsConfigured: true,
  } as const;
}

export async function listXrayExternalProxyNodes(input: {
  search?: unknown;
  protocol?: unknown;
  page?: unknown;
  pageSize?: unknown;
} = {}): Promise<{ items: XrayExternalProxySafeDto[]; page: number; pageSize: number; total: number }> {
  try {
    const page = input.page === undefined ? 1 : positiveId(input.page, "EXTERNAL_PROXY_INVALID_LINK");
    const pageSize = input.pageSize === undefined ? 20 : positiveId(input.pageSize, "EXTERNAL_PROXY_INVALID_LINK");
    if (pageSize > 100) throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_INVALID_LINK");
    const search = String(input.search ?? "").trim().toLocaleLowerCase();
    if (Buffer.byteLength(search, "utf8") > 128) throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_INVALID_LINK");
    const protocol = input.protocol === undefined ? undefined : protocolValue(input.protocol);
    const q = quoteIdentifier;
    const clauses: string[] = [];
    const params: unknown[] = [];
    if (search) {
      clauses.push(`(LOWER(n.${q("name")}) LIKE ? OR LOWER(n.${q("address")}) LIKE ?)`);
      params.push(`%${search}%`, `%${search}%`);
    }
    if (protocol) {
      clauses.push(`n.${q("protocol")} = ?`);
      params.push(protocol);
    }
    const where = clauses.length ? ` WHERE ${clauses.join(" AND ")}` : "";
    const count = await queryRaw<{ count: unknown }>(
      `SELECT COUNT(*) AS ${q("count")} FROM ${q("xray_external_proxy_nodes")} n${where}`,
      params,
    );
    const rows = await queryRaw<Row>(
      `${selectWithCounts(where)} ORDER BY n.${q("updatedAt")} DESC, n.${q("id")} DESC LIMIT ? OFFSET ?`,
      [...params, pageSize, (page - 1) * pageSize],
    );
    return { items: rows.map(safeDto), page, pageSize, total: Number(count[0]?.count ?? 0) };
  } catch (error) {
    serviceError(error);
  }
}

export async function getXrayExternalProxyNodeDetail(idValue: unknown): Promise<XrayExternalProxySafeDto> {
  try {
    return safeDto(await requireNodeRow(positiveId(idValue)));
  } catch (error) {
    serviceError(error);
  }
}

export async function getXrayExternalProxyNodeSummaries(
  idValues: readonly unknown[],
): Promise<XrayExternalProxySafeDto[]> {
  try {
    const ids = [...new Set(idValues.map((value) => positiveId(value)))];
    const rows: Row[] = [];
    const q = quoteIdentifier;
    for (let offset = 0; offset < ids.length; offset += 200) {
      const chunk = ids.slice(offset, offset + 200);
      if (chunk.length === 0) continue;
      rows.push(...await queryRaw<Row>(
        `${selectWithCounts(` WHERE n.${q("id")} IN (${chunk.map(() => "?").join(", ")})`)}`,
        chunk,
      ));
    }
    const byId = new Map(rows.map((row) => [positiveId(row.id), safeDto(row)]));
    return ids.map((id) => byId.get(id)).filter((item): item is XrayExternalProxySafeDto => !!item);
  } catch (error) {
    serviceError(error);
  }
}

export async function createXrayExternalProxyNode(
  input: { name: unknown; uri: unknown; createdByUserId: unknown },
  options: { keyring?: XraySecretKeyring } = {},
): Promise<XrayExternalProxySafeDto> {
  try {
    const name = displayName(input.name);
    const createdByUserId = positiveId(input.createdByUserId, "EXTERNAL_PROXY_INVALID_LINK");
    const definition = parseImport(input.uri);
    const keyring = options.keyring ?? loadXrayMasterKeyFile();
    return await withKeyedTaskLock("xray-external-proxies", async () => {
      const id = await withDatabaseTransaction(async () => {
        const nodeTag = `forwardx-external-${crypto.randomUUID()}`;
        const now = nowDate();
        const nodeId = await insertAndGetId("xray_external_proxy_nodes", {
          name,
          nodeTag,
          protocol: definition.protocol,
          address: definition.address,
          port: definition.port,
          specVersion: 1,
          specJson: JSON.stringify(publicSpec(definition)),
          createdByUserId,
          createdAt: now,
          updatedAt: now,
        });
        await insertCredentialRows(nodeId, nodeTag, definition, keyring);
        return nodeId;
      });
      return getXrayExternalProxyNodeDetail(id);
    });
  } catch (error) {
    serviceError(error);
  }
}

export async function renameXrayExternalProxyNode(input: { id: unknown; name: unknown }): Promise<XrayExternalProxySafeDto> {
  try {
    const id = positiveId(input.id);
    const name = displayName(input.name);
    return await withKeyedTaskLock("xray-external-proxies", async () => {
      await requireNodeRow(id);
      const q = quoteIdentifier;
      await executeRaw(
        `UPDATE ${q("xray_external_proxy_nodes")} SET ${q("name")} = ?, ${q("updatedAt")} = ? WHERE ${q("id")} = ?`,
        [name, nowDate(), id],
      );
      return getXrayExternalProxyNodeDetail(id);
    });
  } catch (error) {
    serviceError(error);
  }
}

export async function replaceXrayExternalProxyNode(
  input: { id: unknown; uri: unknown },
  options: { keyring?: XraySecretKeyring } = {},
): Promise<XrayExternalProxySafeDto> {
  try {
    const id = positiveId(input.id);
    const definition = parseImport(input.uri);
    const keyring = options.keyring ?? loadXrayMasterKeyFile();
    return await withKeyedTaskLock("xray-external-proxies", async () => {
      await withDatabaseTransaction(async () => {
        const row = await requireNodeRow(id);
        if (Number(row.inboundCount) > 0 || Number(row.ruleCount) > 0 || Number(row.quickConfigCount) > 0) {
          throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_IN_USE");
        }
        const nodeTag = String(row.nodeTag ?? "");
        const q = quoteIdentifier;
        await executeRaw(`DELETE FROM ${q("xray_external_proxy_secrets")} WHERE ${q("externalProxyNodeId")} = ?`, [id]);
        await executeRaw(
          `UPDATE ${q("xray_external_proxy_nodes")} SET ${q("protocol")} = ?, ${q("address")} = ?, ${q("port")} = ?, ${q("specVersion")} = 1, ${q("specJson")} = ?, ${q("updatedAt")} = ? WHERE ${q("id")} = ?`,
          [definition.protocol, definition.address, definition.port, JSON.stringify(publicSpec(definition)), nowDate(), id],
        );
        await insertCredentialRows(id, nodeTag, definition, keyring);
      });
      return getXrayExternalProxyNodeDetail(id);
    });
  } catch (error) {
    serviceError(error);
  }
}

export async function removeXrayExternalProxyNode(input: {
  id: unknown;
  confirmName: unknown;
}): Promise<{ id: number; removed: true }> {
  try {
    const id = positiveId(input.id);
    return await withKeyedTaskLock("xray-external-proxies", async () => withDatabaseTransaction(async () => {
      const row = await requireNodeRow(id);
      if (String(input.confirmName ?? "") !== String(row.name ?? "")) {
        throw new XrayExternalProxyServiceError("CONFIRMATION_MISMATCH");
      }
      if (Number(row.inboundCount) > 0 || Number(row.ruleCount) > 0 || Number(row.quickConfigCount) > 0) {
        throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_IN_USE");
      }
      const q = quoteIdentifier;
      await executeRaw(`DELETE FROM ${q("xray_external_proxy_secrets")} WHERE ${q("externalProxyNodeId")} = ?`, [id]);
      const removed = await executeRaw(`DELETE FROM ${q("xray_external_proxy_nodes")} WHERE ${q("id")} = ?`, [id]);
      if (rawAffectedRows(removed) !== 1) throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_NOT_FOUND");
      return { id, removed: true as const };
    }));
  } catch (error) {
    serviceError(error);
  }
}

function expectedKinds(protocol: XrayExternalProxyProtocol, actual: XrayExternalProxySecretKind[]): XrayExternalProxySecretKind[] {
  if (protocol === "VLESS_REALITY_VISION") return ["VLESS_UUID", "VLESS_SHORT_ID"];
  if (protocol === "SHADOWSOCKS") return ["SHADOWSOCKS_PASSWORD"];
  if (actual.length === 0) return [];
  return ["SOCKS_USERNAME", "SOCKS_PASSWORD"];
}

export async function loadXrayExternalProxyMaterial(
  idValue: unknown,
  options: { keyring?: XraySecretKeyring } = {},
): Promise<{ id: number; nodeTag: string; definition: XrayExternalProxyDefinition }> {
  try {
    const id = positiveId(idValue);
    const row = await requireNodeRow(id);
    const dto = safeDto(row);
    const nodeTag = String(row.nodeTag ?? "");
    const q = quoteIdentifier;
    const secretRows = await queryRaw<Row>(
      `SELECT * FROM ${q("xray_external_proxy_secrets")} WHERE ${q("externalProxyNodeId")} = ? ORDER BY ${q("kind")} ASC`,
      [id],
    );
    const kinds = secretRows.map((secret) => String(secret.kind) as XrayExternalProxySecretKind);
    const expected = expectedKinds(dto.protocol, kinds);
    if (kinds.length !== expected.length || !expected.every((kind) => kinds.includes(kind))
      || kinds.some((kind) => !expected.includes(kind))) {
      throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_REFERENCE_INVALID");
    }
    const keyring = options.keyring ?? loadXrayMasterKeyFile();
    const plaintext = new Map<XrayExternalProxySecretKind, string>();
    for (const secret of secretRows) {
      const kind = String(secret.kind) as XrayExternalProxySecretKind;
      const context = xrayExternalProxySecretContext(nodeTag, kind);
      const value = decryptXraySecret(String(secret.encryptedValue ?? ""), context, keyring);
      if (fingerprintXraySecret(value, context, keyring) !== String(secret.fingerprint ?? "")) {
        throw new XrayExternalProxyServiceError("SENSITIVE_DATA_UNAVAILABLE");
      }
      plaintext.set(kind, value);
    }
    const base = {
      address: dto.address,
      port: dto.port,
      displayName: dto.name,
      specVersion: 1 as const,
    };
    const definition: XrayExternalProxyDefinition = dto.protocol === "VLESS_REALITY_VISION" ? {
      ...base,
      protocol: dto.protocol,
      spec: dto.publicSettings as XrayExternalProxyDefinition & never,
      credentials: {
        uuid: plaintext.get("VLESS_UUID")!,
        shortId: plaintext.get("VLESS_SHORT_ID")!,
      },
    } as XrayExternalProxyDefinition : dto.protocol === "SHADOWSOCKS" ? {
      ...base,
      protocol: dto.protocol,
      spec: dto.publicSettings as XrayExternalProxyDefinition & never,
      credentials: { password: plaintext.get("SHADOWSOCKS_PASSWORD")! },
    } as XrayExternalProxyDefinition : {
      ...base,
      protocol: dto.protocol,
      spec: {},
      credentials: plaintext.size === 0 ? {} : {
        username: plaintext.get("SOCKS_USERNAME")!,
        password: plaintext.get("SOCKS_PASSWORD")!,
      },
    };
    return {
      id,
      nodeTag,
      definition: parseXrayExternalProxyUri(buildXrayExternalProxyUri(definition)),
    };
  } catch (error) {
    serviceError(error);
  }
}

export async function loadXrayExternalProxyDefinition(
  idValue: unknown,
  options: { keyring?: XraySecretKeyring } = {},
): Promise<XrayExternalProxyDefinition> {
  return (await loadXrayExternalProxyMaterial(idValue, options)).definition;
}

export async function buildXrayExternalProxyShare(
  idValue: unknown,
  endpointOverride?: { address: string; port: number },
  options: { keyring?: XraySecretKeyring } = {},
): Promise<string> {
  try {
    return buildXrayExternalProxyUri(
      await loadXrayExternalProxyDefinition(idValue, options),
      endpointOverride,
    );
  } catch (error) {
    serviceError(error);
  }
}

function publicRelayAddress(value: unknown): string {
  let address: string;
  try {
    address = normalizeXrayExternalProxyAddress(value);
  } catch {
    throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_REFERENCE_INVALID");
  }
  if (isIP(address) === 4) {
    const [a, b, c] = address.split(".").map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 0) || (a === 192 && b === 168)
      || (a === 198 && (b === 18 || b === 19))
      || (a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100)
      || (a === 203 && b === 0 && c === 113)) {
      throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_REFERENCE_INVALID");
    }
  } else if (isIP(address) === 6) {
    const lower = address.toLowerCase();
    if (lower === "::" || lower === "::1" || lower.startsWith("fc") || lower.startsWith("fd")
      || /^fe[89ab]/.test(lower) || lower.startsWith("ff")) {
      throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_REFERENCE_INVALID");
    }
  }
  return address;
}

export async function buildXrayExternalProxyRelayShare(
  input: { id: unknown; relayRuleId: unknown },
  options: { keyring?: XraySecretKeyring } = {},
): Promise<string> {
  try {
    const id = positiveId(input.id);
    const relayRuleId = positiveId(input.relayRuleId, "EXTERNAL_PROXY_REFERENCE_INVALID");
    const node = await getXrayExternalProxyNodeDetail(id);
    const q = quoteIdentifier;
    const rows = await queryRaw<Row>(
      `SELECT r.*, h.${q("entryIp")} AS ${q("relayEntryIp")}, h.${q("ipv4")} AS ${q("relayIpv4")},
          h.${q("ipv6")} AS ${q("relayIpv6")}, h.${q("ip")} AS ${q("relayIp")}
         FROM ${q("forward_rules")} r JOIN ${q("hosts")} h ON h.${q("id")} = r.${q("hostId")}
        WHERE r.${q("id")} = ? LIMIT 1`,
      [relayRuleId],
    );
    const rule = rows[0];
    if (!rule || Number(rule.targetExternalProxyNodeId) !== id || rule.protocol !== "tcp"
      || !isExternalProxyForwardType(rule.forwardType)
      || databaseBoolean(rule.proxyProtocolSend) || databaseBoolean(rule.proxyProtocolExitSend)
      || databaseBoolean(rule.pendingDelete) || !databaseBoolean(rule.isEnabled)
      || databaseBoolean(rule.isForwardGroupTemplate) || rule.forwardGroupRuleId !== null && rule.forwardGroupRuleId !== undefined
      || String(rule.targetIp ?? "") !== node.address || Number(rule.targetPort) !== node.port) {
      throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_REFERENCE_INVALID");
    }
    const address = publicRelayAddress(rule.relayEntryIp || rule.relayIpv4 || rule.relayIpv6 || rule.relayIp);
    const port = Number(rule.sourcePort);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new XrayExternalProxyServiceError("EXTERNAL_PROXY_REFERENCE_INVALID");
    }
    return buildXrayExternalProxyShare(id, { address, port }, options);
  } catch (error) {
    serviceError(error);
  }
}
