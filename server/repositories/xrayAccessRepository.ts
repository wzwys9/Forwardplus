import {
  XRAY_ACCESS_SECRET_MAX_BYTES,
  accessSecretPolicyForCredentialType,
  isXrayAccessSecretKind,
  parseStoredXrayAccessSettings,
  type XrayAccessCredentialType,
  type XrayAccessSecretKind,
  type XrayAccessSettings,
} from "../../shared/xrayAccess";
import {
  executeRaw,
  insertAndGetId,
  nowDate,
  queryRaw,
  rawAffectedRows,
  withDatabaseTransaction,
} from "../dbRuntime";
import { quoteIdentifier } from "../dbCompat";
import {
  encryptXraySecret,
  fingerprintXraySecret,
  inspectXraySecretEnvelope,
  xrayAccessSecretContext,
  type XraySecretKeyring,
} from "../xraySecretCrypto";

export type XrayAccessRepositoryErrorCode =
  | "INBOUND_NOT_FOUND"
  | "ACCESS_NOT_FOUND"
  | "INVALID_ACCESS_DATA"
  | "ACCESS_CONFLICT";

export class XrayAccessRepositoryError extends Error {
  constructor(readonly code: XrayAccessRepositoryErrorCode) {
    super({
      INBOUND_NOT_FOUND: "Xray inbound was not found",
      ACCESS_NOT_FOUND: "Xray access entry was not found",
      INVALID_ACCESS_DATA: "Xray access data is invalid",
      ACCESS_CONFLICT: "Xray access entry conflicts with existing data",
    }[code]);
    this.name = "XrayAccessRepositoryError";
  }
}

export type XrayAccessSecretInput = Readonly<{
  kind: XrayAccessSecretKind;
  plaintext: string;
}>;

export type XrayAccessEntryDto = Readonly<{
  id: number;
  inboundId: number;
  legacyClientId: number | null;
  name: string;
  credentialType: XrayAccessCredentialType;
  settings: XrayAccessSettings;
  statsKey: string;
  ownerUserId: number | null;
  isEnabled: boolean;
  pendingDelete: boolean;
  desiredGeneration: number;
  sortOrder: number;
  createdAt: number;
  updatedAt: number;
  secretStatus: {
    requiredConfigured: boolean;
    configuredKinds: XrayAccessSecretKind[];
  };
}>;

export type NewXrayAccessEntry = {
  inboundId: number;
  legacyClientId?: number | null;
  name: string;
  credentialType: XrayAccessCredentialType;
  settingsJson: string;
  statsKey: string;
  ownerUserId?: number | null;
  isEnabled?: boolean;
  pendingDelete?: boolean;
  desiredGeneration: number;
  sortOrder?: number;
  secrets: XrayAccessSecretInput[];
};

export type XrayAccessEntryPatch = Partial<Pick<NewXrayAccessEntry,
  "name" | "settingsJson" | "ownerUserId" | "isEnabled" | "pendingDelete" | "desiredGeneration" | "sortOrder"
>>;

type AccessRow = Record<string, unknown> & {
  id: unknown;
  inboundId: unknown;
  legacyClientId: unknown;
  name: unknown;
  credentialType: unknown;
  settingsJson: unknown;
  statsKey: unknown;
  ownerUserId: unknown;
  isEnabled: unknown;
  pendingDelete: unknown;
  desiredGeneration: unknown;
  sortOrder: unknown;
  createdAt: unknown;
  updatedAt: unknown;
};

type SecretRow = Record<string, unknown> & {
  accessEntryId: unknown;
  kind: unknown;
  encryptedValue: unknown;
  fingerprint: unknown;
  keyVersion: unknown;
};

const textEncoder = new TextEncoder();
const stableIdentityPattern = /^[A-Za-z0-9._:-]{1,128}$/;

function invalid(): never {
  throw new XrayAccessRepositoryError("INVALID_ACCESS_DATA");
}

function positiveId(value: unknown, code: "INBOUND_NOT_FOUND" | "ACCESS_NOT_FOUND"): number {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) throw new XrayAccessRepositoryError(code);
  return id;
}

function optionalPositiveId(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) invalid();
  return id;
}

function nonNegativeInteger(value: unknown): number {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) invalid();
  return number;
}

function displayName(value: unknown): string {
  if (typeof value !== "string") invalid();
  const name = value.trim();
  if (name.length < 1 || textEncoder.encode(name).byteLength > 256) invalid();
  return name;
}

function stableIdentity(value: unknown): string {
  if (typeof value !== "string" || !stableIdentityPattern.test(value)) invalid();
  return value;
}

function booleanValue(value: unknown): boolean {
  if (value === true || value === 1 || value === "1") return true;
  if (value === false || value === 0 || value === "0") return false;
  invalid();
}

function canonicalSettings(credentialType: unknown, settingsJson: unknown) {
  const parsed = parseStoredXrayAccessSettings({ credentialType, settingsJson });
  if (!parsed) invalid();
  const { credentialType: validatedCredentialType, ...settings } = parsed;
  return {
    credentialType: validatedCredentialType,
    settings,
    settingsJson: JSON.stringify(settings),
  };
}

function normalizedSecrets(
  credentialType: XrayAccessCredentialType,
  inputs: readonly XrayAccessSecretInput[],
): XrayAccessSecretInput[] {
  if (!Array.isArray(inputs)) invalid();
  const policy = accessSecretPolicyForCredentialType(credentialType);
  if (!policy) invalid();
  const allowed = new Set([...policy.required, ...policy.optional]);
  const seen = new Set<XrayAccessSecretKind>();
  const normalized: XrayAccessSecretInput[] = [];
  for (const input of inputs) {
    if (!input || !isXrayAccessSecretKind(input.kind) || !allowed.has(input.kind) || seen.has(input.kind)) invalid();
    if (typeof input.plaintext !== "string") invalid();
    const byteLength = textEncoder.encode(input.plaintext).byteLength;
    if (byteLength < 1 || byteLength > XRAY_ACCESS_SECRET_MAX_BYTES) invalid();
    seen.add(input.kind);
    normalized.push({ kind: input.kind, plaintext: input.plaintext });
  }
  if (policy.required.some((kind) => !seen.has(kind))) invalid();
  return normalized.sort((left, right) => left.kind.localeCompare(right.kind));
}

function isUniqueConstraintError(error: unknown): boolean {
  const code = String((error as { code?: unknown })?.code ?? "").toUpperCase();
  const errno = Number((error as { errno?: unknown })?.errno ?? 0);
  return code === "23505" || code === "ER_DUP_ENTRY" || code.startsWith("SQLITE_CONSTRAINT") || errno === 1062;
}

async function assertInboundExists(inboundId: number) {
  const q = quoteIdentifier;
  const rows = await queryRaw(`SELECT ${q("id")} FROM ${q("xray_inbounds")} WHERE ${q("id")} = ? LIMIT 1`, [inboundId]);
  if (rows.length !== 1) throw new XrayAccessRepositoryError("INBOUND_NOT_FOUND");
}

async function insertSecrets(
  accessEntryId: number,
  statsKey: string,
  inputs: readonly XrayAccessSecretInput[],
  keyring: XraySecretKeyring,
) {
  const now = nowDate();
  for (const input of inputs) {
    const context = xrayAccessSecretContext(statsKey, input.kind);
    const encryptedValue = encryptXraySecret(input.plaintext, context, keyring);
    const envelope = inspectXraySecretEnvelope(encryptedValue);
    await insertAndGetId("xray_access_secrets", {
      accessEntryId,
      kind: input.kind,
      encryptedValue,
      fingerprint: fingerprintXraySecret(input.plaintext, context, keyring),
      keyVersion: envelope.version,
      createdAt: now,
      updatedAt: now,
    });
  }
}

async function accessRows(whereSql: string, params: unknown[]): Promise<AccessRow[]> {
  const q = quoteIdentifier;
  return queryRaw<AccessRow>(
    `SELECT * FROM ${q("xray_access_entries")} WHERE ${whereSql}
      ORDER BY ${q("sortOrder")} ASC, ${q("id")} ASC`,
    params,
  );
}

async function secretRowsForAccessIds(ids: number[]): Promise<Map<number, SecretRow[]>> {
  const result = new Map<number, SecretRow[]>();
  const q = quoteIdentifier;
  for (let offset = 0; offset < ids.length; offset += 200) {
    const chunk = ids.slice(offset, offset + 200);
    const rows = await queryRaw<SecretRow>(
      `SELECT * FROM ${q("xray_access_secrets")} WHERE ${q("accessEntryId")} IN (${chunk.map(() => "?").join(", ")})
        ORDER BY ${q("accessEntryId")} ASC, ${q("kind")} ASC`,
      chunk,
    );
    for (const row of rows) {
      const accessEntryId = positiveId(row.accessEntryId, "ACCESS_NOT_FOUND");
      const entries = result.get(accessEntryId) ?? [];
      entries.push(row);
      result.set(accessEntryId, entries);
    }
  }
  return result;
}

function safeDto(row: AccessRow, secretRows: readonly SecretRow[]): XrayAccessEntryDto {
  const id = positiveId(row.id, "ACCESS_NOT_FOUND");
  const inboundId = positiveId(row.inboundId, "INBOUND_NOT_FOUND");
  const parsed = canonicalSettings(row.credentialType, row.settingsJson);
  const statsKey = stableIdentity(row.statsKey);
  const policy = accessSecretPolicyForCredentialType(parsed.credentialType);
  if (!policy) invalid();
  const allowed = new Set([...policy.required, ...policy.optional]);
  const configuredKinds: XrayAccessSecretKind[] = [];
  for (const secret of secretRows) {
    if (!isXrayAccessSecretKind(secret.kind) || !allowed.has(secret.kind) || configuredKinds.includes(secret.kind)) invalid();
    if (typeof secret.encryptedValue !== "string" || typeof secret.fingerprint !== "string"
      || !/^[0-9a-f]{64}$/.test(secret.fingerprint)) invalid();
    const envelope = inspectXraySecretEnvelope(secret.encryptedValue);
    if (nonNegativeInteger(secret.keyVersion) !== envelope.version) invalid();
    configuredKinds.push(secret.kind);
  }
  configuredKinds.sort((left, right) => left.localeCompare(right));

  return {
    id,
    inboundId,
    legacyClientId: optionalPositiveId(row.legacyClientId),
    name: displayName(row.name),
    credentialType: parsed.credentialType,
    settings: { credentialType: parsed.credentialType, ...parsed.settings } as XrayAccessSettings,
    statsKey,
    ownerUserId: optionalPositiveId(row.ownerUserId),
    isEnabled: booleanValue(row.isEnabled),
    pendingDelete: booleanValue(row.pendingDelete),
    desiredGeneration: nonNegativeInteger(row.desiredGeneration),
    sortOrder: nonNegativeInteger(row.sortOrder),
    createdAt: nonNegativeInteger(row.createdAt),
    updatedAt: nonNegativeInteger(row.updatedAt),
    secretStatus: {
      requiredConfigured: policy.required.every((kind) => configuredKinds.includes(kind)),
      configuredKinds,
    },
  };
}

async function projectRows(rows: AccessRow[]) {
  const secrets = await secretRowsForAccessIds(rows.map((row) => positiveId(row.id, "ACCESS_NOT_FOUND")));
  return rows.map((row) => {
    const id = positiveId(row.id, "ACCESS_NOT_FOUND");
    return safeDto(row, secrets.get(id) ?? []);
  });
}

export async function getXrayAccessEntry(idValue: unknown): Promise<XrayAccessEntryDto> {
  const id = positiveId(idValue, "ACCESS_NOT_FOUND");
  const q = quoteIdentifier;
  const rows = await accessRows(`${q("id")} = ?`, [id]);
  if (rows.length !== 1) throw new XrayAccessRepositoryError("ACCESS_NOT_FOUND");
  return (await projectRows(rows))[0];
}

export async function listXrayAccessEntries(inboundIdValue: unknown): Promise<XrayAccessEntryDto[]> {
  const inboundId = positiveId(inboundIdValue, "INBOUND_NOT_FOUND");
  const q = quoteIdentifier;
  return projectRows(await accessRows(`${q("inboundId")} = ?`, [inboundId]));
}

export async function createXrayAccessEntry(
  input: NewXrayAccessEntry,
  options: { keyring: XraySecretKeyring },
): Promise<XrayAccessEntryDto> {
  const inboundId = positiveId(input?.inboundId, "INBOUND_NOT_FOUND");
  const settings = canonicalSettings(input?.credentialType, input?.settingsJson);
  const statsKey = stableIdentity(input?.statsKey);
  const secrets = normalizedSecrets(settings.credentialType, input?.secrets);
  const now = nowDate();
  try {
    return await withDatabaseTransaction(async () => {
      await assertInboundExists(inboundId);
      const id = await insertAndGetId("xray_access_entries", {
        inboundId,
        legacyClientId: optionalPositiveId(input.legacyClientId),
        name: displayName(input.name),
        credentialType: settings.credentialType,
        settingsJson: settings.settingsJson,
        statsKey,
        ownerUserId: optionalPositiveId(input.ownerUserId),
        isEnabled: input.isEnabled === undefined ? true : booleanValue(input.isEnabled),
        pendingDelete: input.pendingDelete === undefined ? false : booleanValue(input.pendingDelete),
        desiredGeneration: nonNegativeInteger(input.desiredGeneration),
        sortOrder: input.sortOrder === undefined ? 0 : nonNegativeInteger(input.sortOrder),
        createdAt: now,
        updatedAt: now,
      });
      await insertSecrets(id, statsKey, secrets, options.keyring);
      return getXrayAccessEntry(id);
    });
  } catch (error) {
    if (isUniqueConstraintError(error)) throw new XrayAccessRepositoryError("ACCESS_CONFLICT");
    throw error;
  }
}

export async function updateXrayAccessEntry(
  input: { id: unknown; patch: XrayAccessEntryPatch; secrets?: XrayAccessSecretInput[] },
  options: { keyring: XraySecretKeyring },
): Promise<XrayAccessEntryDto> {
  const id = positiveId(input?.id, "ACCESS_NOT_FOUND");
  try {
    return await withDatabaseTransaction(async () => {
      const current = await getXrayAccessEntry(id);
      const values: Record<string, unknown> = {};
      if (input.patch?.name !== undefined) values.name = displayName(input.patch.name);
      if (input.patch?.settingsJson !== undefined) {
        values.settingsJson = canonicalSettings(current.credentialType, input.patch.settingsJson).settingsJson;
      }
      if (input.patch?.ownerUserId !== undefined) values.ownerUserId = optionalPositiveId(input.patch.ownerUserId);
      if (input.patch?.isEnabled !== undefined) values.isEnabled = booleanValue(input.patch.isEnabled);
      if (input.patch?.pendingDelete !== undefined) values.pendingDelete = booleanValue(input.patch.pendingDelete);
      if (input.patch?.desiredGeneration !== undefined) values.desiredGeneration = nonNegativeInteger(input.patch.desiredGeneration);
      if (input.patch?.sortOrder !== undefined) values.sortOrder = nonNegativeInteger(input.patch.sortOrder);
      if (Object.keys(values).length === 0 && input.secrets === undefined) invalid();
      if (Object.keys(values).length > 0) {
        values.updatedAt = nowDate();
        const q = quoteIdentifier;
        const result = await executeRaw(
          `UPDATE ${q("xray_access_entries")} SET ${Object.keys(values).map((key) => `${q(key)} = ?`).join(", ")} WHERE ${q("id")} = ?`,
          [...Object.values(values), id],
        );
        if (rawAffectedRows(result) !== 1) throw new XrayAccessRepositoryError("ACCESS_NOT_FOUND");
      }
      if (input.secrets !== undefined) {
        const secrets = normalizedSecrets(current.credentialType, input.secrets);
        const q = quoteIdentifier;
        await executeRaw(`DELETE FROM ${q("xray_access_secrets")} WHERE ${q("accessEntryId")} = ?`, [id]);
        await insertSecrets(id, current.statsKey, secrets, options.keyring);
      }
      return getXrayAccessEntry(id);
    });
  } catch (error) {
    if (isUniqueConstraintError(error)) throw new XrayAccessRepositoryError("ACCESS_CONFLICT");
    throw error;
  }
}
