import { parseStoredXrayAccessSettings } from "../shared/xrayAccess";
import { resolveStoredXrayInboundDefinition } from "../shared/xrayProfiles";
import { quoteIdentifier } from "./dbCompat";
import { queryRaw } from "./dbRuntime";
import { inspectXraySecretEnvelope, XraySecretUnavailableError } from "./xraySecretCrypto";

export type UserPasswordAccessProjection = {
  accessEntryId: number;
  inboundId: number;
  profileId: "HTTP_RAW_NONE" | "MIXED_RAW_NONE";
  credentialType: "HTTP_BASIC" | "MIXED_USER_PASSWORD";
  name: string;
  statsKey: string;
  usernameEncrypted: string;
  usernameFingerprint: string;
  passwordEncrypted: string;
  passwordFingerprint: string;
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

function verifiedEnvelope(row: Record<string, unknown>, prefix: "username" | "password") {
  const encrypted = requiredString(row[`${prefix}Encrypted`]);
  const fingerprint = requiredString(row[`${prefix}Fingerprint`]);
  if (!/^[0-9a-f]{64}$/.test(fingerprint)) unavailable();
  const envelope = inspectXraySecretEnvelope(encrypted);
  if (Number(row[`${prefix}KeyVersion`]) !== envelope.version) unavailable();
  return { encrypted, fingerprint };
}

function project(row: Record<string, unknown>): UserPasswordAccessProjection {
  const definition = resolveStoredXrayInboundDefinition(row);
  const settings = parseStoredXrayAccessSettings({
    credentialType: row.credentialType,
    settingsJson: row.settingsJson,
  });
  const validHttp = definition?.profile.id === "HTTP_RAW_NONE" && settings?.credentialType === "HTTP_BASIC";
  const validMixed = definition?.profile.id === "MIXED_RAW_NONE" && settings?.credentialType === "MIXED_USER_PASSWORD";
  if ((!validHttp && !validMixed) || settings?.schemaVersion !== 1
    || Number(row.secretCount) !== 2) unavailable();
  const username = verifiedEnvelope(row, "username");
  const password = verifiedEnvelope(row, "password");
  return {
    accessEntryId: positiveId(row.accessEntryId),
    inboundId: positiveId(row.inboundId),
    profileId: definition.profile.id as UserPasswordAccessProjection["profileId"],
    credentialType: settings.credentialType as UserPasswordAccessProjection["credentialType"],
    name: requiredString(row.name),
    statsKey: requiredString(row.statsKey),
    usernameEncrypted: username.encrypted,
    usernameFingerprint: username.fingerprint,
    passwordEncrypted: password.encrypted,
    passwordFingerprint: password.fingerprint,
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
            i.${q("specJson")} AS ${q("specJson")}, u.${q("encryptedValue")} AS ${q("usernameEncrypted")},
            u.${q("fingerprint")} AS ${q("usernameFingerprint")}, u.${q("keyVersion")} AS ${q("usernameKeyVersion")},
            p.${q("encryptedValue")} AS ${q("passwordEncrypted")}, p.${q("fingerprint")} AS ${q("passwordFingerprint")},
            p.${q("keyVersion")} AS ${q("passwordKeyVersion")},
            (SELECT COUNT(*) FROM ${q("xray_access_secrets")} all_secrets
              WHERE all_secrets.${q("accessEntryId")} = a.${q("id")}) AS ${q("secretCount")}
       FROM ${q("xray_access_entries")} a
       JOIN ${q("xray_inbounds")} i ON i.${q("id")} = a.${q("inboundId")}
       LEFT JOIN ${q("xray_access_secrets")} u
         ON u.${q("accessEntryId")} = a.${q("id")} AND u.${q("kind")} = 'USERNAME'
       LEFT JOIN ${q("xray_access_secrets")} p
         ON p.${q("accessEntryId")} = a.${q("id")} AND p.${q("kind")} = 'PASSWORD'
      WHERE a.${q("legacyClientId")} IS NULL
        AND i.${q("profileId")} IN ('HTTP_RAW_NONE', 'MIXED_RAW_NONE')
        AND ${whereSql}
      ORDER BY a.${q("inboundId")} ASC, a.${q("sortOrder")} ASC, a.${q("id")} ASC`,
    params,
  );
  return rows.map(project);
}

export function loadHttpBasicAccessEntriesByHost(hostId: number) {
  const q = quoteIdentifier;
  return load(`i.${q("hostId")} = ? AND i.${q("profileId")} = 'HTTP_RAW_NONE'`, [positiveId(hostId)]);
}

export async function loadHttpBasicAccessEntryById(accessEntryId: number) {
  const q = quoteIdentifier;
  const rows = await load(`a.${q("id")} = ? AND i.${q("profileId")} = 'HTTP_RAW_NONE'`, [positiveId(accessEntryId)]);
  if (rows.length !== 1) unavailable();
  return rows[0];
}

export function loadMixedUserPasswordAccessEntriesByHost(hostId: number) {
  const q = quoteIdentifier;
  return load(`i.${q("hostId")} = ? AND i.${q("profileId")} = 'MIXED_RAW_NONE'`, [positiveId(hostId)]);
}

export async function loadMixedUserPasswordAccessEntryById(accessEntryId: number) {
  const q = quoteIdentifier;
  const rows = await load(`a.${q("id")} = ? AND i.${q("profileId")} = 'MIXED_RAW_NONE'`, [positiveId(accessEntryId)]);
  if (rows.length !== 1) unavailable();
  return rows[0];
}
