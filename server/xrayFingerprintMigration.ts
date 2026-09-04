import crypto from "node:crypto";

import { isXrayAccessSecretKind, isXrayInboundSecretKind } from "../shared/xrayAccess";
import { quoteIdentifier } from "./dbCompat";
import { executeRaw, queryRaw, withDatabaseTransaction } from "./dbRuntime";
import { withKeyedTaskLock } from "./keyedTaskLock";
import { getSetting, setSetting } from "./repositories/settingsRepository";
import {
  decryptXraySecret,
  fingerprintXraySecret,
  loadXrayMasterKeyFile,
  xrayAccessSecretContext,
  xrayClientShortIdContext,
  xrayClientUuidContext,
  xrayInboundSecretContext,
  XraySecretUnavailableError,
  type XraySecretKeyring,
} from "./xraySecretCrypto";

const FINGERPRINT_VERSION_SETTING = "xraySecretFingerprintVersion";
const FINGERPRINT_VERSION = "3";
const FINGERPRINT_MIGRATION_LOCK = "xray-client-fingerprint-migration";

type StoredClientSecret = {
  id: unknown;
  inboundId: unknown;
  statsKey: unknown;
  uuidEncrypted: unknown;
  shortIdEncrypted: unknown;
};

type StoredAccessSecret = {
  id: unknown;
  inboundId: unknown;
  statsKey: unknown;
  kind: unknown;
  encryptedValue: unknown;
};

type StoredInboundSecret = {
  id: unknown;
  runtimeTag: unknown;
  kind: unknown;
  encryptedValue: unknown;
};

export async function repairXrayClientFingerprints(options: {
  force?: boolean;
  keyring?: XraySecretKeyring;
} = {}): Promise<number> {
  return withKeyedTaskLock(FINGERPRINT_MIGRATION_LOCK, () => repairXrayClientFingerprintsUnlocked(options));
}

async function repairXrayClientFingerprintsUnlocked(options: {
  force?: boolean;
  keyring?: XraySecretKeyring;
}): Promise<number> {
  if (!options.force && await getSetting(FINGERPRINT_VERSION_SETTING) === FINGERPRINT_VERSION) return 0;
  const q = quoteIdentifier;
  const rows = await queryRaw<StoredClientSecret>(
    `SELECT ${["id", "inboundId", "statsKey", "uuidEncrypted", "shortIdEncrypted"].map(q).join(", ")} FROM ${q("xray_clients")} ORDER BY ${q("id")} ASC`,
  );
  const accessRows = await queryRaw<StoredAccessSecret>(
    `SELECT s.${q("id")} AS ${q("id")}, a.${q("inboundId")} AS ${q("inboundId")},
            a.${q("statsKey")} AS ${q("statsKey")}, s.${q("kind")} AS ${q("kind")},
            s.${q("encryptedValue")} AS ${q("encryptedValue")}
       FROM ${q("xray_access_secrets")} s
       LEFT JOIN ${q("xray_access_entries")} a ON a.${q("id")} = s.${q("accessEntryId")}
      ORDER BY s.${q("id")} ASC`,
  );
  const inboundRows = await queryRaw<StoredInboundSecret>(
    `SELECT s.${q("id")} AS ${q("id")}, i.${q("runtimeTag")} AS ${q("runtimeTag")},
            s.${q("kind")} AS ${q("kind")}, s.${q("encryptedValue")} AS ${q("encryptedValue")}
       FROM ${q("xray_inbound_secrets")} s
       LEFT JOIN ${q("xray_inbounds")} i ON i.${q("id")} = s.${q("inboundId")}
      ORDER BY s.${q("id")} ASC`,
  );
  if (rows.length === 0 && accessRows.length === 0 && inboundRows.length === 0) {
    await setSetting(FINGERPRINT_VERSION_SETTING, FINGERPRINT_VERSION);
    return 0;
  }

  const keyring = options.keyring ?? loadXrayMasterKeyFile();
  const prepared = rows.map((row) => {
    const id = Number(row.id);
    const inboundId = Number(row.inboundId);
    const statsKey = String(row.statsKey ?? "");
    if (!Number.isSafeInteger(id) || id <= 0 || !Number.isSafeInteger(inboundId) || inboundId <= 0 || !statsKey) {
      throw new XraySecretUnavailableError();
    }
    const uuidContext = xrayClientUuidContext(statsKey);
    const shortIdContext = xrayClientShortIdContext(statsKey);
    return {
      id,
      inboundId,
      uuidFingerprint: fingerprintXraySecret(decryptXraySecret(String(row.uuidEncrypted ?? ""), uuidContext, keyring), uuidContext, keyring),
      shortIdFingerprint: fingerprintXraySecret(decryptXraySecret(String(row.shortIdEncrypted ?? ""), shortIdContext, keyring), shortIdContext, keyring),
    };
  });
  const preparedAccess = accessRows.map((row) => {
    const id = Number(row.id);
    const inboundId = Number(row.inboundId);
    const statsKey = String(row.statsKey ?? "");
    if (!Number.isSafeInteger(id) || id <= 0 || !Number.isSafeInteger(inboundId) || inboundId <= 0
      || !statsKey || !isXrayAccessSecretKind(row.kind)) throw new XraySecretUnavailableError();
    const context = xrayAccessSecretContext(statsKey, row.kind);
    return {
      id,
      inboundId,
      kind: row.kind,
      fingerprint: fingerprintXraySecret(
        decryptXraySecret(String(row.encryptedValue ?? ""), context, keyring),
        context,
        keyring,
      ),
    };
  });
  const preparedInbound = inboundRows.map((row) => {
    const id = Number(row.id);
    const runtimeTag = String(row.runtimeTag ?? "");
    if (!Number.isSafeInteger(id) || id <= 0 || !runtimeTag || !isXrayInboundSecretKind(row.kind)) {
      throw new XraySecretUnavailableError();
    }
    const context = xrayInboundSecretContext(runtimeTag, row.kind);
    return {
      id,
      fingerprint: fingerprintXraySecret(
        decryptXraySecret(String(row.encryptedValue ?? ""), context, keyring),
        context,
        keyring,
      ),
    };
  });

  const uuidFingerprints = new Set<string>();
  const inboundShortIds = new Set<string>();
  for (const row of prepared) {
    const shortIdIdentity = `${row.inboundId}:${row.shortIdFingerprint}`;
    if (uuidFingerprints.has(row.uuidFingerprint) || inboundShortIds.has(shortIdIdentity)) {
      throw new XraySecretUnavailableError();
    }
    uuidFingerprints.add(row.uuidFingerprint);
    inboundShortIds.add(shortIdIdentity);
  }
  const genericUuids = new Set<string>();
  const genericInboundShortIds = new Set<string>();
  for (const row of preparedAccess) {
    if (row.kind === "UUID") {
      if (genericUuids.has(row.fingerprint)) throw new XraySecretUnavailableError();
      genericUuids.add(row.fingerprint);
    } else if (row.kind === "SHORT_ID") {
      const identity = `${row.inboundId}:${row.fingerprint}`;
      if (genericInboundShortIds.has(identity)) throw new XraySecretUnavailableError();
      genericInboundShortIds.add(identity);
    }
  }

  const migrationNonce = crypto.randomBytes(16).toString("hex");
  await withDatabaseTransaction(async () => {
    for (const row of prepared) {
      const placeholder = (field: string) => crypto.createHash("sha256")
        .update(`forwardx-xray-fingerprint-migration:${migrationNonce}:${field}:${row.id}`)
        .digest("hex");
      await executeRaw(
        `UPDATE ${q("xray_clients")} SET ${q("uuidFingerprint")} = ?, ${q("shortIdFingerprint")} = ? WHERE ${q("id")} = ?`,
        [placeholder("uuid"), placeholder("short-id"), row.id],
      );
    }
    for (const row of prepared) {
      await executeRaw(
        `UPDATE ${q("xray_clients")} SET ${q("uuidFingerprint")} = ?, ${q("shortIdFingerprint")} = ? WHERE ${q("id")} = ?`,
        [row.uuidFingerprint, row.shortIdFingerprint, row.id],
      );
    }
    for (const row of preparedAccess) {
      await executeRaw(
        `UPDATE ${q("xray_access_secrets")} SET ${q("fingerprint")} = ? WHERE ${q("id")} = ?`,
        [row.fingerprint, row.id],
      );
    }
    for (const row of preparedInbound) {
      await executeRaw(
        `UPDATE ${q("xray_inbound_secrets")} SET ${q("fingerprint")} = ? WHERE ${q("id")} = ?`,
        [row.fingerprint, row.id],
      );
    }
    await setSetting(FINGERPRINT_VERSION_SETTING, FINGERPRINT_VERSION);
  });
  return prepared.length;
}
