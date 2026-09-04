import { parseStoredXrayAccessSettings } from "../shared/xrayAccess";
import { resolveStoredXrayInboundProfile } from "../shared/xrayProfiles";
import { quoteIdentifier } from "./dbCompat";
import { insertAndGetId, nowDate, queryRaw, withDatabaseTransaction } from "./dbRuntime";
import { withKeyedTaskLock } from "./keyedTaskLock";
import {
  decryptXraySecret,
  fingerprintXraySecret,
  inspectXraySecretEnvelope,
  loadXrayMasterKeyFile,
  xrayClientShortIdContext,
  xrayClientUuidContext,
  xrayInboundPrivateKeyContext,
  XraySecretUnavailableError,
  type XraySecretKeyring,
} from "./xraySecretCrypto";

const MIGRATION_LOCK = "xray-access-entry-backfill";
const VISION_SETTINGS_JSON = '{"schemaVersion":1,"flow":"XTLS_RPRX_VISION"}';
const NONE_SETTINGS_JSON = '{"schemaVersion":1,"flow":"NONE"}';

type LegacyInbound = Record<string, unknown> & {
  id: unknown;
  runtimeTag: unknown;
  protocol: unknown;
  transport: unknown;
  security: unknown;
  profileId: unknown;
  specVersion: unknown;
  specJson: unknown;
  realityPrivateKeyEncrypted: unknown;
  createdAt: unknown;
  updatedAt: unknown;
};

type LegacyClient = Record<string, unknown> & {
  id: unknown;
  inboundId: unknown;
  name: unknown;
  uuidEncrypted: unknown;
  uuidFingerprint: unknown;
  shortIdEncrypted: unknown;
  shortIdFingerprint: unknown;
  statsKey: unknown;
  flow: unknown;
  ownerUserId: unknown;
  isEnabled: unknown;
  pendingDelete: unknown;
  desiredGeneration: unknown;
  sortOrder: unknown;
  createdAt: unknown;
  updatedAt: unknown;
};

type PreparedSecret = {
  kind: "UUID" | "SHORT_ID" | "REALITY_PRIVATE_KEY";
  encryptedValue: string;
  fingerprint: string;
  keyVersion: number;
};

function unavailable(): never {
  throw new XraySecretUnavailableError();
}

function positiveId(value: unknown): number {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) unavailable();
  return id;
}

function optionalId(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null;
  return positiveId(value);
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

function timestamp(value: unknown) {
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : nowDate();
}

function preparedSecret(input: {
  kind: PreparedSecret["kind"];
  envelope: unknown;
  fingerprint: string;
}): PreparedSecret {
  const encryptedValue = requiredString(input.envelope);
  const envelope = inspectXraySecretEnvelope(encryptedValue);
  if (!/^[0-9a-f]{64}$/.test(input.fingerprint)) unavailable();
  return {
    kind: input.kind,
    encryptedValue,
    fingerprint: input.fingerprint,
    keyVersion: envelope.version,
  };
}

function sameValue(left: unknown, right: unknown) {
  if (left === null || left === undefined) return right === null || right === undefined;
  if (typeof left === "boolean") return databaseBoolean(right) === left;
  if (typeof left === "number") return Number(right) === left;
  return String(right) === String(left);
}

function assertFields(row: Record<string, unknown>, expected: Record<string, unknown>) {
  for (const [field, value] of Object.entries(expected)) {
    if (!sameValue(value, row[field])) unavailable();
  }
}

async function insertOrVerifySecret(input: {
  table: "xray_access_secrets" | "xray_inbound_secrets";
  ownerColumn: "accessEntryId" | "inboundId";
  ownerId: number;
  secret: PreparedSecret;
  createdAt: unknown;
  updatedAt: unknown;
}): Promise<boolean> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Record<string, unknown>>(
    `SELECT * FROM ${q(input.table)} WHERE ${q(input.ownerColumn)} = ? AND ${q("kind")} = ? LIMIT 1`,
    [input.ownerId, input.secret.kind],
  );
  if (rows[0]) {
    assertFields(rows[0], input.secret);
    return false;
  }
  await insertAndGetId(input.table, {
    [input.ownerColumn]: input.ownerId,
    ...input.secret,
    createdAt: timestamp(input.createdAt),
    updatedAt: timestamp(input.updatedAt),
  });
  return true;
}

export async function backfillLegacyXrayAccessEntries(options: {
  keyring?: XraySecretKeyring;
} = {}): Promise<{ accessEntries: number; accessSecrets: number; inboundSecrets: number }> {
  return withKeyedTaskLock(MIGRATION_LOCK, async () => {
    const q = quoteIdentifier;
    const inbounds = await queryRaw<LegacyInbound>(
      `SELECT * FROM ${q("xray_inbounds")} ORDER BY ${q("id")} ASC`,
    );
    const clients = await queryRaw<LegacyClient>(
      `SELECT * FROM ${q("xray_clients")} ORDER BY ${q("id")} ASC`,
    );
    if (inbounds.length === 0 && clients.length === 0) {
      return { accessEntries: 0, accessSecrets: 0, inboundSecrets: 0 };
    }
    const keyring = options.keyring ?? loadXrayMasterKeyFile();
    const inboundFlows = new Map<number, { storage: "xtls-rprx-vision" | ""; settingsJson: string }>();
    const preparedInbounds = inbounds.map((row) => {
      const id = positiveId(row.id);
      const runtimeTag = requiredString(row.runtimeTag);
      const profile = resolveStoredXrayInboundProfile({
        protocol: row.protocol,
        transport: row.transport,
        security: row.security,
        profileId: row.profileId,
        specVersion: row.specVersion,
        specJson: row.specJson,
      });
      const flow = profile?.clientFlow === "XTLS_RPRX_VISION"
        ? { storage: "xtls-rprx-vision" as const, settingsJson: VISION_SETTINGS_JSON }
        : profile?.clientFlow === "NONE"
          ? { storage: "" as const, settingsJson: NONE_SETTINGS_JSON }
          : null;
      if (!flow || inboundFlows.has(id)) unavailable();
      inboundFlows.set(id, flow);
      const context = xrayInboundPrivateKeyContext(runtimeTag);
      const plaintext = decryptXraySecret(requiredString(row.realityPrivateKeyEncrypted), context, keyring);
      return {
        row,
        id,
        secret: preparedSecret({
          kind: "REALITY_PRIVATE_KEY",
          envelope: row.realityPrivateKeyEncrypted,
          fingerprint: fingerprintXraySecret(plaintext, context, keyring),
        }),
      };
    });

    const preparedClients = clients.map((row) => {
      const id = positiveId(row.id);
      const inboundId = positiveId(row.inboundId);
      const flow = inboundFlows.get(inboundId);
      if (!flow || row.flow !== flow.storage) unavailable();
      const statsKey = requiredString(row.statsKey);
      const uuidContext = xrayClientUuidContext(statsKey);
      const shortIdContext = xrayClientShortIdContext(statsKey);
      const uuidFingerprint = fingerprintXraySecret(
        decryptXraySecret(requiredString(row.uuidEncrypted), uuidContext, keyring),
        uuidContext,
        keyring,
      );
      const shortIdFingerprint = fingerprintXraySecret(
        decryptXraySecret(requiredString(row.shortIdEncrypted), shortIdContext, keyring),
        shortIdContext,
        keyring,
      );
      if (uuidFingerprint !== row.uuidFingerprint || shortIdFingerprint !== row.shortIdFingerprint) unavailable();
      return {
        row,
        id,
        inboundId,
        statsKey,
        settingsJson: flow.settingsJson,
        secrets: [
          preparedSecret({ kind: "UUID", envelope: row.uuidEncrypted, fingerprint: uuidFingerprint }),
          preparedSecret({ kind: "SHORT_ID", envelope: row.shortIdEncrypted, fingerprint: shortIdFingerprint }),
        ],
      };
    });

    return withDatabaseTransaction(async () => {
      let accessEntries = 0;
      let accessSecrets = 0;
      let inboundSecrets = 0;
      for (const inbound of preparedInbounds) {
        if (await insertOrVerifySecret({
          table: "xray_inbound_secrets",
          ownerColumn: "inboundId",
          ownerId: inbound.id,
          secret: inbound.secret,
          createdAt: inbound.row.createdAt,
          updatedAt: inbound.row.updatedAt,
        })) inboundSecrets += 1;
      }
      for (const client of preparedClients) {
        const existing = await queryRaw<Record<string, unknown>>(
          `SELECT * FROM ${q("xray_access_entries")} WHERE ${q("legacyClientId")} = ? LIMIT 1`,
          [client.id],
        );
        const expected = {
          inboundId: client.inboundId,
          legacyClientId: client.id,
          name: requiredString(client.row.name),
          credentialType: "UUID_AND_SHORT_ID",
          settingsJson: client.settingsJson,
          statsKey: client.statsKey,
          ownerUserId: optionalId(client.row.ownerUserId),
          isEnabled: databaseBoolean(client.row.isEnabled),
          pendingDelete: databaseBoolean(client.row.pendingDelete),
          desiredGeneration: nonNegativeInteger(client.row.desiredGeneration),
          sortOrder: nonNegativeInteger(client.row.sortOrder),
        };
        let accessEntryId: number;
        if (existing[0]) {
          assertFields(existing[0], expected);
          if (!parseStoredXrayAccessSettings({
            credentialType: existing[0].credentialType,
            settingsJson: existing[0].settingsJson,
          })) unavailable();
          accessEntryId = positiveId(existing[0].id);
        } else {
          accessEntryId = await insertAndGetId("xray_access_entries", {
            ...expected,
            createdAt: timestamp(client.row.createdAt),
            updatedAt: timestamp(client.row.updatedAt),
          });
          accessEntries += 1;
        }
        for (const secret of client.secrets) {
          if (await insertOrVerifySecret({
            table: "xray_access_secrets",
            ownerColumn: "accessEntryId",
            ownerId: accessEntryId,
            secret,
            createdAt: client.row.createdAt,
            updatedAt: client.row.updatedAt,
          })) accessSecrets += 1;
        }
      }
      return { accessEntries, accessSecrets, inboundSecrets };
    });
  });
}
