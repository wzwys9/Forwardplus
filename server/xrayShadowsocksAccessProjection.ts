import { parseStoredXrayAccessSettings } from "../shared/xrayAccess";
import { resolveStoredXrayInboundDefinition } from "../shared/xrayProfiles";
import { quoteIdentifier } from "./dbCompat";
import { queryRaw } from "./dbRuntime";
import { inspectXraySecretEnvelope, XraySecretUnavailableError } from "./xraySecretCrypto";

export type ShadowsocksAccessProjection = {
  accessEntryId: number;
  inboundId: number;
  name: string;
  statsKey: string;
  userKeyEncrypted: string;
  userKeyFingerprint: string;
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

function requiredString(value: unknown): string {
  if (typeof value !== "string" || value.length < 1) unavailable();
  return value;
}

function databaseBoolean(value: unknown): boolean {
  if (value === true || value === 1 || value === "1") return true;
  if (value === false || value === 0 || value === "0") return false;
  unavailable();
}

function verifiedSecret(row: Record<string, unknown>, encryptedField: string, fingerprintField: string, keyVersionField: string) {
  const encryptedValue = requiredString(row[encryptedField]);
  const fingerprint = requiredString(row[fingerprintField]);
  if (!/^[0-9a-f]{64}$/.test(fingerprint)) unavailable();
  const envelope = inspectXraySecretEnvelope(encryptedValue);
  if (Number(row[keyVersionField]) !== envelope.version) unavailable();
  return { encryptedValue, fingerprint };
}

function project(row: Record<string, unknown>): ShadowsocksAccessProjection {
  const definition = resolveStoredXrayInboundDefinition(row);
  const settings = parseStoredXrayAccessSettings({
    credentialType: row.credentialType,
    settingsJson: row.settingsJson,
  });
  if ((definition?.profile.id !== "SHADOWSOCKS_2022_RAW_NONE"
      && definition?.profile.id !== "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE")
    || settings?.credentialType !== "SHADOWSOCKS_KEY" || settings.schemaVersion !== 1
    || Number(row.secretCount) !== 1) unavailable();
  const userKey = verifiedSecret(row, "userKeyEncrypted", "userKeyFingerprint", "userKeyVersion");
  const sortOrder = Number(row.sortOrder);
  if (!Number.isSafeInteger(sortOrder) || sortOrder < 0) unavailable();
  return {
    accessEntryId: positiveId(row.accessEntryId),
    inboundId: positiveId(row.inboundId),
    name: requiredString(row.name),
    statsKey: requiredString(row.statsKey),
    userKeyEncrypted: userKey.encryptedValue,
    userKeyFingerprint: userKey.fingerprint,
    isEnabled: databaseBoolean(row.isEnabled),
    pendingDelete: databaseBoolean(row.pendingDelete),
    sortOrder,
  };
}

async function load(whereSql: string, params: unknown[]) {
  const q = quoteIdentifier;
  const rows = await queryRaw<Record<string, unknown>>(
    `SELECT a.${q("id")} AS ${q("accessEntryId")}, a.${q("inboundId")} AS ${q("inboundId")},
            a.${q("name")} AS ${q("name")}, a.${q("credentialType")} AS ${q("credentialType")},
            a.${q("settingsJson")} AS ${q("settingsJson")}, a.${q("statsKey")} AS ${q("statsKey")},
            a.${q("isEnabled")} AS ${q("isEnabled")}, a.${q("pendingDelete")} AS ${q("pendingDelete")},
            a.${q("sortOrder")} AS ${q("sortOrder")}, i.${q("protocol")} AS ${q("protocol")},
            i.${q("transport")} AS ${q("transport")}, i.${q("security")} AS ${q("security")},
            i.${q("profileId")} AS ${q("profileId")}, i.${q("specVersion")} AS ${q("specVersion")},
            i.${q("specJson")} AS ${q("specJson")}, s.${q("encryptedValue")} AS ${q("userKeyEncrypted")},
            s.${q("fingerprint")} AS ${q("userKeyFingerprint")}, s.${q("keyVersion")} AS ${q("userKeyVersion")},
            (SELECT COUNT(*) FROM ${q("xray_access_secrets")} all_secrets
              WHERE all_secrets.${q("accessEntryId")} = a.${q("id")}) AS ${q("secretCount")}
       FROM ${q("xray_access_entries")} a
       JOIN ${q("xray_inbounds")} i ON i.${q("id")} = a.${q("inboundId")}
       LEFT JOIN ${q("xray_access_secrets")} s
         ON s.${q("accessEntryId")} = a.${q("id")} AND s.${q("kind")} = 'SHADOWSOCKS_KEY'
      WHERE a.${q("legacyClientId")} IS NULL
        AND i.${q("profileId")} IN ('SHADOWSOCKS_2022_RAW_NONE', 'SHADOWSOCKS_2022_RAW_TCP_UDP_NONE')
        AND ${whereSql}
      ORDER BY a.${q("inboundId")} ASC, a.${q("sortOrder")} ASC, a.${q("id")} ASC`,
    params,
  );
  return rows.map(project);
}

export function loadShadowsocksAccessEntriesByHost(hostId: number) {
  const q = quoteIdentifier;
  return load(`i.${q("hostId")} = ?`, [positiveId(hostId)]);
}

export async function loadShadowsocksAccessEntryById(accessEntryId: number) {
  const q = quoteIdentifier;
  const rows = await load(`a.${q("id")} = ?`, [positiveId(accessEntryId)]);
  if (rows.length !== 1) unavailable();
  return rows[0];
}

export async function loadShadowsocksServerKeyByInboundId(inboundId: number) {
  const q = quoteIdentifier;
  const rows = await queryRaw<Record<string, unknown>>(
    `SELECT s.${q("encryptedValue")} AS ${q("encryptedValue")}, s.${q("fingerprint")} AS ${q("fingerprint")},
            s.${q("keyVersion")} AS ${q("keyVersion")},
            (SELECT COUNT(*) FROM ${q("xray_inbound_secrets")} all_secrets
              WHERE all_secrets.${q("inboundId")} = i.${q("id")}) AS ${q("secretCount")}
       FROM ${q("xray_inbounds")} i
       LEFT JOIN ${q("xray_inbound_secrets")} s
         ON s.${q("inboundId")} = i.${q("id")} AND s.${q("kind")} = 'SHADOWSOCKS_SERVER_KEY'
      WHERE i.${q("id")} = ?
        AND i.${q("profileId")} IN ('SHADOWSOCKS_2022_RAW_NONE', 'SHADOWSOCKS_2022_RAW_TCP_UDP_NONE') LIMIT 1`,
    [positiveId(inboundId)],
  );
  if (rows.length !== 1 || Number(rows[0].secretCount) !== 1) unavailable();
  return verifiedSecret(rows[0], "encryptedValue", "fingerprint", "keyVersion");
}
