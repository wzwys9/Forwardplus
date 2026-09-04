import { parseStoredXrayAccessSettings } from "../shared/xrayAccess";
import { resolveStoredXrayInboundDefinition } from "../shared/xrayProfiles";
import { quoteIdentifier } from "./dbCompat";
import { queryRaw } from "./dbRuntime";
import { inspectXraySecretEnvelope, XraySecretUnavailableError } from "./xraySecretCrypto";

export type GenericUuidAccessProjection = {
  accessEntryId: number;
  inboundId: number;
  name: string;
  statsKey: string;
  uuidEncrypted: string;
  uuidFingerprint: string;
  flow: "" | "xtls-rprx-vision";
  isEnabled: boolean;
  pendingDelete: boolean;
  sortOrder: number;
};

function unavailable(): never {
  throw new XraySecretUnavailableError();
}

function positiveId(value: unknown): number {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) unavailable();
  return id;
}

function nonNegativeInteger(value: unknown): number {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) unavailable();
  return number;
}

function requiredString(value: unknown): string {
  if (typeof value !== "string" || value.length < 1) unavailable();
  return value;
}

function databaseBoolean(value: unknown): boolean {
  if (value === true || value === 1 || value === "1") return true;
  if (value === false || value === 0 || value === "0") return false;
  unavailable();
}

function project(row: Record<string, unknown>): GenericUuidAccessProjection {
  const definition = resolveStoredXrayInboundDefinition({
    protocol: row.protocol,
    transport: row.transport,
    security: row.security,
    profileId: row.profileId,
    specVersion: row.specVersion,
    specJson: row.specJson,
  });
  const settings = parseStoredXrayAccessSettings({
    credentialType: row.credentialType,
    settingsJson: row.settingsJson,
  });
  const profileId = definition?.profile.id;
  if (profileId !== "VLESS_RAW_TLS"
    && profileId !== "VLESS_RAW_TLS_VISION"
    && profileId !== "VLESS_WEBSOCKET_TLS"
    && profileId !== "VLESS_GRPC_TLS"
    && profileId !== "VLESS_HTTP_UPGRADE_TLS"
    && profileId !== "VLESS_XHTTP_TLS"
    && profileId !== "VLESS_MKCP_TLS"
    && profileId !== "VMESS_RAW_TLS") unavailable();
  const expectedFlow = profileId === "VLESS_RAW_TLS_VISION" ? "XTLS_RPRX_VISION" : "NONE";
  const validSettings = profileId === "VMESS_RAW_TLS"
    ? settings?.credentialType === "UUID" && settings.schemaVersion === 1
      && settings.flow === "NONE" && settings.security === "AUTO"
    : settings?.credentialType === "UUID" && settings.schemaVersion === 2
      && settings.protocol === "VLESS" && settings.encryption === "NONE" && settings.flow === expectedFlow;
  if (!validSettings || Number(row.secretCount) !== 1) {
    unavailable();
  }
  const uuidEncrypted = requiredString(row.uuidEncrypted);
  const uuidFingerprint = requiredString(row.uuidFingerprint);
  if (!/^[0-9a-f]{64}$/.test(uuidFingerprint)) unavailable();
  const envelope = inspectXraySecretEnvelope(uuidEncrypted);
  if (Number(row.uuidKeyVersion) !== envelope.version) unavailable();
  return {
    accessEntryId: positiveId(row.accessEntryId),
    inboundId: positiveId(row.inboundId),
    name: requiredString(row.name),
    statsKey: requiredString(row.statsKey),
    uuidEncrypted,
    uuidFingerprint,
    flow: profileId === "VLESS_RAW_TLS_VISION" ? "xtls-rprx-vision" : "",
    isEnabled: databaseBoolean(row.isEnabled),
    pendingDelete: databaseBoolean(row.pendingDelete),
    sortOrder: nonNegativeInteger(row.sortOrder),
  };
}

async function load(whereSql: string, params: unknown[]): Promise<GenericUuidAccessProjection[]> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Record<string, unknown>>(
    `SELECT a.${q("id")} AS ${q("accessEntryId")}, a.${q("inboundId")} AS ${q("inboundId")},
            a.${q("name")} AS ${q("name")}, a.${q("credentialType")} AS ${q("credentialType")},
            a.${q("settingsJson")} AS ${q("settingsJson")}, a.${q("statsKey")} AS ${q("statsKey")},
            a.${q("isEnabled")} AS ${q("isEnabled")}, a.${q("pendingDelete")} AS ${q("pendingDelete")},
            a.${q("sortOrder")} AS ${q("sortOrder")}, i.${q("protocol")} AS ${q("protocol")},
            i.${q("transport")} AS ${q("transport")}, i.${q("security")} AS ${q("security")},
            i.${q("profileId")} AS ${q("profileId")}, i.${q("specVersion")} AS ${q("specVersion")},
            i.${q("specJson")} AS ${q("specJson")}, u.${q("encryptedValue")} AS ${q("uuidEncrypted")},
            u.${q("fingerprint")} AS ${q("uuidFingerprint")}, u.${q("keyVersion")} AS ${q("uuidKeyVersion")},
            (SELECT COUNT(*) FROM ${q("xray_access_secrets")} all_secrets
              WHERE all_secrets.${q("accessEntryId")} = a.${q("id")}) AS ${q("secretCount")}
       FROM ${q("xray_access_entries")} a
       JOIN ${q("xray_inbounds")} i ON i.${q("id")} = a.${q("inboundId")}
       LEFT JOIN ${q("xray_access_secrets")} u
         ON u.${q("accessEntryId")} = a.${q("id")} AND u.${q("kind")} = 'UUID'
      WHERE a.${q("legacyClientId")} IS NULL AND i.${q("profileId")} IN (?, ?, ?, ?, ?, ?, ?, ?)
        AND ${whereSql}
      ORDER BY a.${q("inboundId")} ASC, a.${q("sortOrder")} ASC, a.${q("id")} ASC`,
    ["VLESS_RAW_TLS", "VLESS_RAW_TLS_VISION", "VLESS_WEBSOCKET_TLS", "VLESS_GRPC_TLS",
      "VLESS_HTTP_UPGRADE_TLS", "VLESS_XHTTP_TLS", "VLESS_MKCP_TLS", "VMESS_RAW_TLS", ...params],
  );
  return rows.map(project);
}

export function loadGenericUuidAccessEntriesByHost(hostIdValue: number): Promise<GenericUuidAccessProjection[]> {
  const q = quoteIdentifier;
  return load(`i.${q("hostId")} = ?`, [positiveId(hostIdValue)]);
}

export async function loadGenericUuidAccessEntryById(accessEntryIdValue: number): Promise<GenericUuidAccessProjection> {
  const q = quoteIdentifier;
  const rows = await load(`a.${q("id")} = ?`, [positiveId(accessEntryIdValue)]);
  if (rows.length !== 1) unavailable();
  return rows[0];
}
