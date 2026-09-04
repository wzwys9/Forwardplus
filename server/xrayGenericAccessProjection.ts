import { parseStoredXrayAccessSettings } from "../shared/xrayAccess";
import { resolveStoredXrayInboundDefinition } from "../shared/xrayProfiles";
import { quoteIdentifier } from "./dbCompat";
import { queryRaw } from "./dbRuntime";
import { inspectXraySecretEnvelope, XraySecretUnavailableError } from "./xraySecretCrypto";

type GenericPasswordAccessProjectionBase = {
  accessEntryId: number;
  inboundId: number;
  name: string;
  statsKey: string;
  passwordEncrypted: string;
  passwordFingerprint: string;
  isEnabled: boolean;
  pendingDelete: boolean;
  sortOrder: number;
};

export type GenericPasswordAccessProjection = GenericPasswordAccessProjectionBase & (
  | {
    profileId: "TROJAN_RAW_REALITY";
    shortIdEncrypted: string;
    shortIdFingerprint: string;
  }
  | {
    profileId: "TROJAN_RAW_TLS" | "TROJAN_WEBSOCKET_TLS" | "TROJAN_GRPC_TLS" | "TROJAN_HTTP_UPGRADE_TLS" | "TROJAN_XHTTP_TLS" | "TROJAN_MKCP_TLS";
    shortIdEncrypted?: never;
    shortIdFingerprint?: never;
  }
);

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

function verifiedEnvelope(row: Record<string, unknown>, prefix: "password" | "shortId") {
  const encrypted = requiredString(row[`${prefix}Encrypted`]);
  const fingerprint = requiredString(row[`${prefix}Fingerprint`]);
  if (!/^[0-9a-f]{64}$/.test(fingerprint)) unavailable();
  const envelope = inspectXraySecretEnvelope(encrypted);
  if (Number(row[`${prefix}KeyVersion`]) !== envelope.version) unavailable();
  return { encrypted, fingerprint };
}

function project(row: Record<string, unknown>): GenericPasswordAccessProjection {
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
  if ((definition?.profile.id !== "TROJAN_RAW_REALITY"
      && definition?.profile.id !== "TROJAN_RAW_TLS"
      && definition?.profile.id !== "TROJAN_WEBSOCKET_TLS"
      && definition?.profile.id !== "TROJAN_GRPC_TLS"
      && definition?.profile.id !== "TROJAN_HTTP_UPGRADE_TLS"
      && definition?.profile.id !== "TROJAN_XHTTP_TLS"
      && definition?.profile.id !== "TROJAN_MKCP_TLS")
    || settings?.credentialType !== "PASSWORD") unavailable();
  const password = verifiedEnvelope(row, "password");
  const base = {
    accessEntryId: positiveId(row.accessEntryId),
    inboundId: positiveId(row.inboundId),
    name: requiredString(row.name),
    statsKey: requiredString(row.statsKey),
    passwordEncrypted: password.encrypted,
    passwordFingerprint: password.fingerprint,
    isEnabled: databaseBoolean(row.isEnabled),
    pendingDelete: databaseBoolean(row.pendingDelete),
    sortOrder: nonNegativeInteger(row.sortOrder),
  };
  if (definition.profile.id === "TROJAN_RAW_REALITY") {
    const shortId = verifiedEnvelope(row, "shortId");
    return {
      ...base,
      profileId: "TROJAN_RAW_REALITY" as const,
      shortIdEncrypted: shortId.encrypted,
      shortIdFingerprint: shortId.fingerprint,
    };
  }
  if (row.shortIdEncrypted != null || row.shortIdFingerprint != null || row.shortIdKeyVersion != null) unavailable();
  return { ...base, profileId: definition.profile.id };
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
            i.${q("specJson")} AS ${q("specJson")}, p.${q("encryptedValue")} AS ${q("passwordEncrypted")},
            p.${q("fingerprint")} AS ${q("passwordFingerprint")}, p.${q("keyVersion")} AS ${q("passwordKeyVersion")},
            s.${q("encryptedValue")} AS ${q("shortIdEncrypted")}, s.${q("fingerprint")} AS ${q("shortIdFingerprint")},
            s.${q("keyVersion")} AS ${q("shortIdKeyVersion")}
       FROM ${q("xray_access_entries")} a
       JOIN ${q("xray_inbounds")} i ON i.${q("id")} = a.${q("inboundId")}
       LEFT JOIN ${q("xray_access_secrets")} p ON p.${q("accessEntryId")} = a.${q("id")} AND p.${q("kind")} = 'PASSWORD'
       LEFT JOIN ${q("xray_access_secrets")} s ON s.${q("accessEntryId")} = a.${q("id")} AND s.${q("kind")} = 'SHORT_ID'
      WHERE a.${q("legacyClientId")} IS NULL AND ${whereSql}
      ORDER BY a.${q("inboundId")} ASC, a.${q("sortOrder")} ASC, a.${q("id")} ASC`,
    params,
  );
  return rows.map(project);
}

export function loadGenericPasswordAccessEntriesByHost(hostId: number) {
  const q = quoteIdentifier;
  return load(`i.${q("hostId")} = ? AND i.${q("profileId")} IN (?, ?, ?, ?, ?, ?, ?)`, [
    positiveId(hostId), "TROJAN_RAW_REALITY", "TROJAN_RAW_TLS", "TROJAN_WEBSOCKET_TLS", "TROJAN_GRPC_TLS",
    "TROJAN_HTTP_UPGRADE_TLS", "TROJAN_XHTTP_TLS", "TROJAN_MKCP_TLS",
  ]);
}

export async function loadGenericPasswordAccessEntryById(accessEntryId: number) {
  const q = quoteIdentifier;
  const rows = await load(`a.${q("id")} = ? AND i.${q("profileId")} IN (?, ?, ?, ?, ?, ?, ?)`, [
    positiveId(accessEntryId), "TROJAN_RAW_REALITY", "TROJAN_RAW_TLS", "TROJAN_WEBSOCKET_TLS", "TROJAN_GRPC_TLS",
    "TROJAN_HTTP_UPGRADE_TLS", "TROJAN_XHTTP_TLS", "TROJAN_MKCP_TLS",
  ]);
  if (rows.length !== 1) unavailable();
  return rows[0];
}
