import { parseStoredXrayAccessSettings } from "../shared/xrayAccess";
import { findKnownXrayProfile } from "../shared/xrayProfiles";
import { quoteIdentifier } from "./dbCompat";
import { queryRaw } from "./dbRuntime";
import { inspectXraySecretEnvelope, XraySecretUnavailableError } from "./xraySecretCrypto";

export type LegacyVlessAccessProjection = {
  clientId: number;
  inboundId: number;
  name: string;
  uuidEncrypted: string;
  shortIdEncrypted: string;
  statsKey: string;
  flow: "xtls-rprx-vision" | "";
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

function databaseBoolean(value: unknown): boolean {
  if (value === true || value === 1 || value === "1") return true;
  if (value === false || value === 0 || value === "0") return false;
  unavailable();
}

function requiredString(value: unknown): string {
  if (typeof value !== "string" || value.length < 1) unavailable();
  return value;
}

function nullableId(value: unknown): number | null {
  return value === null || value === undefined ? null : positiveId(value);
}

function assertSame(left: unknown, right: unknown) {
  if (left === null || left === undefined) {
    if (right !== null && right !== undefined) unavailable();
    return;
  }
  if (typeof left === "boolean") {
    if (databaseBoolean(right) !== left) unavailable();
    return;
  }
  if (typeof left === "number") {
    if (Number(right) !== left) unavailable();
    return;
  }
  if (String(right) !== String(left)) unavailable();
}

function verifiedSecret(row: Record<string, unknown>, prefix: "uuid" | "shortId") {
  const encryptedValue = requiredString(row[`${prefix}Encrypted`]);
  const fingerprint = requiredString(row[`${prefix}Fingerprint`]);
  const genericEncryptedValue = requiredString(row[`${prefix}GenericEncrypted`]);
  const genericFingerprint = requiredString(row[`${prefix}GenericFingerprint`]);
  if (genericEncryptedValue !== encryptedValue || genericFingerprint !== fingerprint || !/^[0-9a-f]{64}$/.test(genericFingerprint)) {
    unavailable();
  }
  const envelope = inspectXraySecretEnvelope(genericEncryptedValue);
  if (Number(row[`${prefix}GenericKeyVersion`]) !== envelope.version) unavailable();
  return genericEncryptedValue;
}

function projectAccessRow(row: Record<string, unknown>): LegacyVlessAccessProjection {
  const clientId = positiveId(row.clientId);
  const inboundId = positiveId(row.inboundId);
  const name = requiredString(row.clientName);
  const statsKey = requiredString(row.statsKey);
  const ownerUserId = nullableId(row.ownerUserId);
  const isEnabled = databaseBoolean(row.isEnabled);
  const pendingDelete = databaseBoolean(row.pendingDelete);
  const desiredGeneration = nonNegativeInteger(row.desiredGeneration);
  const sortOrder = nonNegativeInteger(row.sortOrder);
  const settings = parseStoredXrayAccessSettings({
    credentialType: row.credentialType,
    settingsJson: row.settingsJson,
  });
  const inboundProfile = findKnownXrayProfile({
    protocol: row.inboundProtocol,
    transport: row.inboundTransport,
    security: row.inboundSecurity,
  });
  const expectedSettingsFlow = inboundProfile?.clientFlow;
  const expectedStorageFlow = expectedSettingsFlow === "XTLS_RPRX_VISION" ? "xtls-rprx-vision"
    : expectedSettingsFlow === "NONE" ? "" : null;
  if (expectedStorageFlow === null || settings?.credentialType !== "UUID_AND_SHORT_ID"
    || settings.flow !== expectedSettingsFlow || row.flow !== expectedStorageFlow) unavailable();
  for (const [legacy, generic] of [
    [inboundId, row.genericInboundId],
    [clientId, row.legacyClientId],
    [name, row.genericName],
    [statsKey, row.genericStatsKey],
    [ownerUserId, row.genericOwnerUserId],
    [isEnabled, row.genericIsEnabled],
    [pendingDelete, row.genericPendingDelete],
    [desiredGeneration, row.genericDesiredGeneration],
    [sortOrder, row.genericSortOrder],
  ] as const) assertSame(legacy, generic);
  return {
    clientId,
    inboundId,
    name: requiredString(row.genericName),
    uuidEncrypted: verifiedSecret(row, "uuid"),
    shortIdEncrypted: verifiedSecret(row, "shortId"),
    statsKey: requiredString(row.genericStatsKey),
    flow: expectedStorageFlow,
    isEnabled: databaseBoolean(row.genericIsEnabled),
    pendingDelete: databaseBoolean(row.genericPendingDelete),
    sortOrder: nonNegativeInteger(row.genericSortOrder),
  };
}

async function loadAccessRows(whereSql: string, params: unknown[]) {
  const q = quoteIdentifier;
  const rows = await queryRaw<Record<string, unknown>>(
    `SELECT c.${q("id")} AS ${q("clientId")}, c.${q("inboundId")} AS ${q("inboundId")},
            c.${q("name")} AS ${q("clientName")}, c.${q("uuidEncrypted")} AS ${q("uuidEncrypted")},
            c.${q("uuidFingerprint")} AS ${q("uuidFingerprint")}, c.${q("shortIdEncrypted")} AS ${q("shortIdEncrypted")},
            c.${q("shortIdFingerprint")} AS ${q("shortIdFingerprint")}, c.${q("statsKey")} AS ${q("statsKey")},
            c.${q("flow")} AS ${q("flow")}, c.${q("ownerUserId")} AS ${q("ownerUserId")},
            c.${q("isEnabled")} AS ${q("isEnabled")}, c.${q("pendingDelete")} AS ${q("pendingDelete")},
            c.${q("desiredGeneration")} AS ${q("desiredGeneration")}, c.${q("sortOrder")} AS ${q("sortOrder")},
            i.${q("protocol")} AS ${q("inboundProtocol")}, i.${q("transport")} AS ${q("inboundTransport")},
            i.${q("security")} AS ${q("inboundSecurity")},
            a.${q("inboundId")} AS ${q("genericInboundId")}, a.${q("legacyClientId")} AS ${q("legacyClientId")},
            a.${q("name")} AS ${q("genericName")}, a.${q("credentialType")} AS ${q("credentialType")},
            a.${q("settingsJson")} AS ${q("settingsJson")}, a.${q("statsKey")} AS ${q("genericStatsKey")},
            a.${q("ownerUserId")} AS ${q("genericOwnerUserId")}, a.${q("isEnabled")} AS ${q("genericIsEnabled")},
            a.${q("pendingDelete")} AS ${q("genericPendingDelete")}, a.${q("desiredGeneration")} AS ${q("genericDesiredGeneration")},
            a.${q("sortOrder")} AS ${q("genericSortOrder")},
            u.${q("encryptedValue")} AS ${q("uuidGenericEncrypted")}, u.${q("fingerprint")} AS ${q("uuidGenericFingerprint")},
            u.${q("keyVersion")} AS ${q("uuidGenericKeyVersion")},
            s.${q("encryptedValue")} AS ${q("shortIdGenericEncrypted")}, s.${q("fingerprint")} AS ${q("shortIdGenericFingerprint")},
            s.${q("keyVersion")} AS ${q("shortIdGenericKeyVersion")}
       FROM ${q("xray_clients")} c
       JOIN ${q("xray_inbounds")} i ON i.${q("id")} = c.${q("inboundId")}
       LEFT JOIN ${q("xray_access_entries")} a ON a.${q("legacyClientId")} = c.${q("id")}
       LEFT JOIN ${q("xray_access_secrets")} u ON u.${q("accessEntryId")} = a.${q("id")} AND u.${q("kind")} = 'UUID'
       LEFT JOIN ${q("xray_access_secrets")} s ON s.${q("accessEntryId")} = a.${q("id")} AND s.${q("kind")} = 'SHORT_ID'
      WHERE ${whereSql}
      ORDER BY c.${q("inboundId")} ASC, c.${q("sortOrder")} ASC, c.${q("id")} ASC`,
    params,
  );
  return rows.map(projectAccessRow);
}

export function loadLegacyVlessAccessEntriesByHost(hostId: number) {
  const q = quoteIdentifier;
  return loadAccessRows(`i.${q("hostId")} = ?`, [positiveId(hostId)]);
}

export async function loadLegacyVlessAccessEntryByClientId(clientId: number) {
  const q = quoteIdentifier;
  const rows = await loadAccessRows(`c.${q("id")} = ?`, [positiveId(clientId)]);
  if (rows.length !== 1) unavailable();
  return rows[0];
}

export async function verifiedLegacyRealityPrivateKeyEnvelope(input: {
  inboundId: number;
  legacyEncryptedValue: unknown;
}) {
  const q = quoteIdentifier;
  const rows = await queryRaw<Record<string, unknown>>(
    `SELECT ${q("encryptedValue")}, ${q("fingerprint")}, ${q("keyVersion")}
       FROM ${q("xray_inbound_secrets")}
      WHERE ${q("inboundId")} = ? AND ${q("kind")} = 'REALITY_PRIVATE_KEY' LIMIT 1`,
    [positiveId(input.inboundId)],
  );
  if (rows.length !== 1) unavailable();
  const encryptedValue = requiredString(rows[0].encryptedValue);
  if (encryptedValue !== requiredString(input.legacyEncryptedValue)
    || !/^[0-9a-f]{64}$/.test(requiredString(rows[0].fingerprint))) unavailable();
  const envelope = inspectXraySecretEnvelope(encryptedValue);
  if (Number(rows[0].keyVersion) !== envelope.version) unavailable();
  return encryptedValue;
}
