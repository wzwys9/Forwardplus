import { parseStoredXrayAccessSettings } from "../shared/xrayAccess";
import { resolveStoredXrayInboundDefinition } from "../shared/xrayProfiles";
import { quoteIdentifier } from "./dbCompat";
import { queryRaw } from "./dbRuntime";
import { inspectXraySecretEnvelope, XraySecretUnavailableError } from "./xraySecretCrypto";

export type HysteriaAccessProjection = {
  accessEntryId: number;
  inboundId: number;
  name: string;
  statsKey: string;
  authEncrypted: string;
  authFingerprint: string;
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

function project(row: Record<string, unknown>): HysteriaAccessProjection {
  const definition = resolveStoredXrayInboundDefinition(row);
  const settings = parseStoredXrayAccessSettings({
    credentialType: row.credentialType,
    settingsJson: row.settingsJson,
  });
  if (definition?.profile.id !== "HYSTERIA2_TLS"
    || settings?.credentialType !== "HYSTERIA_AUTH" || settings.schemaVersion !== 1
    || Number(row.secretCount) !== 1) unavailable();
  const authEncrypted = requiredString(row.authEncrypted);
  const authFingerprint = requiredString(row.authFingerprint);
  if (!/^[0-9a-f]{64}$/.test(authFingerprint)) unavailable();
  const envelope = inspectXraySecretEnvelope(authEncrypted);
  if (Number(row.authKeyVersion) !== envelope.version) unavailable();
  return {
    accessEntryId: positiveId(row.accessEntryId),
    inboundId: positiveId(row.inboundId),
    name: requiredString(row.name),
    statsKey: requiredString(row.statsKey),
    authEncrypted,
    authFingerprint,
    isEnabled: databaseBoolean(row.isEnabled),
    pendingDelete: databaseBoolean(row.pendingDelete),
    sortOrder: nonNegativeInteger(row.sortOrder),
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
            i.${q("specJson")} AS ${q("specJson")}, s.${q("encryptedValue")} AS ${q("authEncrypted")},
            s.${q("fingerprint")} AS ${q("authFingerprint")}, s.${q("keyVersion")} AS ${q("authKeyVersion")},
            (SELECT COUNT(*) FROM ${q("xray_access_secrets")} all_secrets
              WHERE all_secrets.${q("accessEntryId")} = a.${q("id")}) AS ${q("secretCount")}
       FROM ${q("xray_access_entries")} a
       JOIN ${q("xray_inbounds")} i ON i.${q("id")} = a.${q("inboundId")}
       LEFT JOIN ${q("xray_access_secrets")} s
         ON s.${q("accessEntryId")} = a.${q("id")} AND s.${q("kind")} = 'HYSTERIA_AUTH'
      WHERE a.${q("legacyClientId")} IS NULL AND i.${q("profileId")} = 'HYSTERIA2_TLS'
        AND ${whereSql}
      ORDER BY a.${q("inboundId")} ASC, a.${q("sortOrder")} ASC, a.${q("id")} ASC`,
    params,
  );
  return rows.map(project);
}

export function loadHysteriaAccessEntriesByHost(hostId: number) {
  const q = quoteIdentifier;
  return load(`i.${q("hostId")} = ?`, [positiveId(hostId)]);
}

export async function loadHysteriaAccessEntryById(accessEntryId: number) {
  const q = quoteIdentifier;
  const rows = await load(`a.${q("id")} = ?`, [positiveId(accessEntryId)]);
  if (rows.length !== 1) unavailable();
  return rows[0];
}
