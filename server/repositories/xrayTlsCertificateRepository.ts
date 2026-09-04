import crypto from "node:crypto";

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
  decryptXraySecret,
  encryptXraySecret,
  fingerprintXraySecret,
  inspectXraySecretEnvelope,
  XraySecretUnavailableError,
  xrayTlsCertificatePrivateKeyContext,
  type XraySecretKeyring,
} from "../xraySecretCrypto";
import {
  validateXrayTlsCertificateInput,
  type ValidatedXrayTlsCertificate,
} from "../xrayTlsCertificate";

export type XrayTlsCertificateRepositoryErrorCode =
  | "HOST_NOT_FOUND"
  | "CERTIFICATE_NOT_FOUND"
  | "INVALID_CERTIFICATE_DATA"
  | "CERTIFICATE_CONFLICT"
  | "CERTIFICATE_IN_USE"
  | "CONFIRMATION_MISMATCH";

export class XrayTlsCertificateRepositoryError extends Error {
  constructor(readonly code: XrayTlsCertificateRepositoryErrorCode) {
    super({
      HOST_NOT_FOUND: "Xray TLS certificate host was not found",
      CERTIFICATE_NOT_FOUND: "Xray TLS certificate was not found",
      INVALID_CERTIFICATE_DATA: "Xray TLS certificate data is invalid",
      CERTIFICATE_CONFLICT: "Xray TLS certificate conflicts with existing data",
      CERTIFICATE_IN_USE: "Xray TLS certificate is in use",
      CONFIRMATION_MISMATCH: "Xray TLS certificate confirmation does not match",
    }[code]);
    this.name = "XrayTlsCertificateRepositoryError";
  }
}

export type XrayTlsCertificateStatus = "VALID" | "EXPIRING_30" | "EXPIRING_14" | "EXPIRING_7" | "EXPIRED";

export type XrayTlsCertificateDto = Readonly<{
  id: number;
  hostId: number;
  name: string;
  dnsNames: string[];
  subject: string;
  issuer: string;
  serialNumber: string;
  notBefore: number;
  notAfter: number;
  keyAlgorithm: "RSA_2048_4096" | "ECDSA_P256_P384";
  leafFingerprintSha256: string;
  privateKeyConfigured: true;
  referenceCount: number;
  status: XrayTlsCertificateStatus;
  createdAt: number;
  updatedAt: number;
}>;

export type XrayTlsCertificateMaterial = ValidatedXrayTlsCertificate & Readonly<{
  id: number;
  hostId: number;
  name: string;
  certificateTag: string;
}>;

type CertificateRow = Record<string, unknown> & {
  id: unknown;
  hostId: unknown;
  name: unknown;
  certificateTag: unknown;
  certificateChainPem: unknown;
  privateKeyEncrypted: unknown;
  privateKeyFingerprint: unknown;
  keyVersion: unknown;
  leafFingerprintSha256: unknown;
  dnsNamesJson: unknown;
  subject: unknown;
  issuer: unknown;
  serialNumber: unknown;
  notBefore: unknown;
  notAfter: unknown;
  keyAlgorithm: unknown;
  referenceCount?: unknown;
  createdAt: unknown;
  updatedAt: unknown;
};

const textEncoder = new TextEncoder();
const certificateTagPattern = /^forwardx-cert-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function invalid(): never {
  throw new XrayTlsCertificateRepositoryError("INVALID_CERTIFICATE_DATA");
}

function positiveInteger(value: unknown, code: "HOST_NOT_FOUND" | "CERTIFICATE_NOT_FOUND" = "CERTIFICATE_NOT_FOUND"): number {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number <= 0) throw new XrayTlsCertificateRepositoryError(code);
  return number;
}

function nonNegativeInteger(value: unknown): number {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) invalid();
  return number;
}

function epoch(value: unknown): number {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number <= 0) invalid();
  return number;
}

function text(value: unknown, maxBytes = 2048): string {
  if (typeof value !== "string") invalid();
  const normalized = value.trim();
  if (!normalized || textEncoder.encode(normalized).byteLength > maxBytes) invalid();
  return normalized;
}

function displayName(value: unknown): string {
  const normalized = text(value, 256);
  if ([...normalized].length > 128) invalid();
  return normalized;
}

function fingerprint(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) invalid();
  return value;
}

function certificateTag(value: unknown): string {
  if (typeof value !== "string" || !certificateTagPattern.test(value)) invalid();
  return value;
}

function dnsNames(value: unknown): string[] {
  if (typeof value !== "string" || textEncoder.encode(value).byteLength > 4096) invalid();
  try {
    const parsed = JSON.parse(value);
    if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 64
      || parsed.some((item) => typeof item !== "string" || item.length < 1 || item.length > 253)) invalid();
    const normalized = [...new Set(parsed)].sort((left, right) => left.localeCompare(right));
    if (JSON.stringify(normalized) !== JSON.stringify(parsed)) invalid();
    return normalized;
  } catch (error) {
    if (error instanceof XrayTlsCertificateRepositoryError) throw error;
    invalid();
  }
}

function algorithm(value: unknown): XrayTlsCertificateDto["keyAlgorithm"] {
  if (value === "RSA_2048_4096" || value === "ECDSA_P256_P384") return value;
  invalid();
}

function status(notAfter: number, nowSeconds = Math.floor(Date.now() / 1000)): XrayTlsCertificateStatus {
  const days = (notAfter - nowSeconds) / 86_400;
  if (days < 0) return "EXPIRED";
  if (days <= 7) return "EXPIRING_7";
  if (days <= 14) return "EXPIRING_14";
  if (days <= 30) return "EXPIRING_30";
  return "VALID";
}

function dto(row: CertificateRow): XrayTlsCertificateDto {
  const notBefore = epoch(row.notBefore);
  const notAfter = epoch(row.notAfter);
  if (notBefore >= notAfter) invalid();
  return {
    id: positiveInteger(row.id),
    hostId: positiveInteger(row.hostId, "HOST_NOT_FOUND"),
    name: displayName(row.name),
    dnsNames: dnsNames(row.dnsNamesJson),
    subject: text(row.subject),
    issuer: text(row.issuer),
    serialNumber: typeof row.serialNumber === "string" && /^[0-9a-f]{1,128}$/.test(row.serialNumber) ? row.serialNumber : invalid(),
    notBefore,
    notAfter,
    keyAlgorithm: algorithm(row.keyAlgorithm),
    leafFingerprintSha256: fingerprint(row.leafFingerprintSha256),
    privateKeyConfigured: true,
    referenceCount: nonNegativeInteger(row.referenceCount ?? 0),
    status: status(notAfter),
    createdAt: epoch(row.createdAt),
    updatedAt: epoch(row.updatedAt),
  };
}

function certificateSelect(whereSql: string): string {
  const q = quoteIdentifier;
  return `SELECT c.*,
      (SELECT COUNT(*) FROM ${q("xray_inbounds")} i
        WHERE i.${q("tlsCertificateId")} = c.${q("id")} AND i.${q("pendingDelete")} = ?) AS ${q("referenceCount")}
    FROM ${q("xray_tls_certificates")} c WHERE ${whereSql}`;
}

async function assertHostExists(hostId: number): Promise<void> {
  const q = quoteIdentifier;
  const rows = await queryRaw(`SELECT ${q("id")} FROM ${q("hosts")} WHERE ${q("id")} = ? LIMIT 1`, [hostId]);
  if (rows.length !== 1) throw new XrayTlsCertificateRepositoryError("HOST_NOT_FOUND");
}

async function assertNameAvailable(hostId: number, name: string): Promise<void> {
  const q = quoteIdentifier;
  const rows = await queryRaw(
    `SELECT ${q("id")} FROM ${q("xray_tls_certificates")} WHERE ${q("hostId")} = ? AND LOWER(${q("name")}) = LOWER(?) LIMIT 1`,
    [hostId, name],
  );
  if (rows.length > 0) throw new XrayTlsCertificateRepositoryError("CERTIFICATE_CONFLICT");
}

function uniqueConstraint(error: unknown): boolean {
  const code = String((error as { code?: unknown })?.code ?? "").toUpperCase();
  const errno = Number((error as { errno?: unknown })?.errno ?? 0);
  return code === "23505" || code === "ER_DUP_ENTRY" || code.startsWith("SQLITE_CONSTRAINT") || errno === 1062;
}

export async function createXrayTlsCertificate(input: {
  hostId: number;
  name: string;
  certificatePem: string;
  privateKeyPem: string;
  createdByUserId: number;
}, dependencies: { keyring: XraySecretKeyring }): Promise<XrayTlsCertificateDto> {
  const hostId = positiveInteger(input.hostId, "HOST_NOT_FOUND");
  const createdByUserId = positiveInteger(input.createdByUserId, "HOST_NOT_FOUND");
  const name = displayName(input.name);
  const validated = validateXrayTlsCertificateInput(input);
  const tag = `forwardx-cert-${crypto.randomUUID()}`;
  const context = xrayTlsCertificatePrivateKeyContext(tag);
  const privateKeyEncrypted = encryptXraySecret(validated.privateKeyPem, context, dependencies.keyring);
  const envelope = inspectXraySecretEnvelope(privateKeyEncrypted);

  try {
    const id = await withDatabaseTransaction(async () => {
      await assertHostExists(hostId);
      await assertNameAvailable(hostId, name);
      const now = nowDate();
      return insertAndGetId("xray_tls_certificates", {
        hostId,
        name,
        certificateTag: tag,
        certificateChainPem: validated.certificateChainPem,
        privateKeyEncrypted,
        privateKeyFingerprint: fingerprintXraySecret(validated.privateKeyPem, context, dependencies.keyring),
        keyVersion: envelope.version,
        leafFingerprintSha256: validated.leafFingerprintSha256,
        dnsNamesJson: JSON.stringify(validated.dnsNames),
        subject: validated.subject,
        issuer: validated.issuer,
        serialNumber: validated.serialNumber,
        notBefore: new Date(validated.notBefore * 1000),
        notAfter: new Date(validated.notAfter * 1000),
        keyAlgorithm: validated.keyAlgorithm,
        createdByUserId,
        createdAt: now,
        updatedAt: now,
      });
    });
    return getXrayTlsCertificate(id);
  } catch (error) {
    if (uniqueConstraint(error)) throw new XrayTlsCertificateRepositoryError("CERTIFICATE_CONFLICT");
    throw error;
  }
}

export async function getXrayTlsCertificate(idValue: number): Promise<XrayTlsCertificateDto> {
  const id = positiveInteger(idValue);
  const q = quoteIdentifier;
  const rows = await queryRaw<CertificateRow>(`${certificateSelect(`c.${q("id")} = ?`)} LIMIT 1`, [false, id]);
  if (rows.length !== 1) throw new XrayTlsCertificateRepositoryError("CERTIFICATE_NOT_FOUND");
  return dto(rows[0]);
}

export async function listXrayTlsCertificates(input: { hostId?: number } = {}): Promise<XrayTlsCertificateDto[]> {
  const q = quoteIdentifier;
  const hostId = input.hostId === undefined ? null : positiveInteger(input.hostId, "HOST_NOT_FOUND");
  const rows = await queryRaw<CertificateRow>(
    `${certificateSelect(hostId === null ? "1 = 1" : `c.${q("hostId")} = ?`)} ORDER BY c.${q("hostId")} ASC, LOWER(c.${q("name")}) ASC, c.${q("id")} ASC`,
    hostId === null ? [false] : [false, hostId],
  );
  return rows.map(dto);
}

export async function getXrayTlsCertificateMaterial(
  idValue: number,
  dependencies: { keyring: XraySecretKeyring },
): Promise<XrayTlsCertificateMaterial> {
  const id = positiveInteger(idValue);
  const q = quoteIdentifier;
  const rows = await queryRaw<CertificateRow>(
    `SELECT * FROM ${q("xray_tls_certificates")} WHERE ${q("id")} = ? LIMIT 1`,
    [id],
  );
  if (rows.length !== 1) throw new XrayTlsCertificateRepositoryError("CERTIFICATE_NOT_FOUND");
  const row = rows[0];
  dto({ ...row, referenceCount: 0 });
  const tag = certificateTag(row.certificateTag);
  if (typeof row.privateKeyEncrypted !== "string") invalid();
  const envelope = inspectXraySecretEnvelope(row.privateKeyEncrypted);
  if (envelope.version !== nonNegativeInteger(row.keyVersion)) invalid();
  const context = xrayTlsCertificatePrivateKeyContext(tag);
  const privateKeyPem = decryptXraySecret(row.privateKeyEncrypted, context, dependencies.keyring);
  if (typeof row.privateKeyFingerprint !== "string"
    || fingerprintXraySecret(privateKeyPem, context, dependencies.keyring) !== row.privateKeyFingerprint) {
    throw new XraySecretUnavailableError();
  }
  const validated = validateXrayTlsCertificateInput({
    certificatePem: row.certificateChainPem,
    privateKeyPem,
    enforceValidity: false,
  });
  const expected = dto({ ...row, referenceCount: 0 });
  if (validated.leafFingerprintSha256 !== expected.leafFingerprintSha256
    || JSON.stringify(validated.dnsNames) !== JSON.stringify(expected.dnsNames)
    || validated.subject !== expected.subject
    || validated.issuer !== expected.issuer
    || validated.serialNumber !== expected.serialNumber
    || validated.notBefore !== expected.notBefore
    || validated.notAfter !== expected.notAfter
    || validated.keyAlgorithm !== expected.keyAlgorithm) invalid();
  return {
    id,
    hostId: expected.hostId,
    name: expected.name,
    certificateTag: tag,
    ...validated,
  };
}

export async function getXrayTlsCertificateLocation(idValue: number): Promise<{
  id: number;
  hostId: number;
  name: string;
  referenceCount: number;
}> {
  const certificate = await getXrayTlsCertificate(idValue);
  return {
    id: certificate.id,
    hostId: certificate.hostId,
    name: certificate.name,
    referenceCount: certificate.referenceCount,
  };
}

export async function rotateXrayTlsCertificate(input: {
  id: number;
  certificatePem: string;
  privateKeyPem: string;
}, dependencies: { keyring: XraySecretKeyring }): Promise<XrayTlsCertificateDto> {
  const id = positiveInteger(input.id);
  const q = quoteIdentifier;
  const validated = validateXrayTlsCertificateInput(input);
  return withDatabaseTransaction(async () => {
    const rows = await queryRaw<CertificateRow>(
      `SELECT * FROM ${q("xray_tls_certificates")} WHERE ${q("id")} = ? LIMIT 1`,
      [id],
    );
    if (rows.length !== 1) throw new XrayTlsCertificateRepositoryError("CERTIFICATE_NOT_FOUND");
    const tag = certificateTag(rows[0].certificateTag);
    const context = xrayTlsCertificatePrivateKeyContext(tag);
    const privateKeyEncrypted = encryptXraySecret(validated.privateKeyPem, context, dependencies.keyring);
    const envelope = inspectXraySecretEnvelope(privateKeyEncrypted);
    const result = await executeRaw(
      `UPDATE ${q("xray_tls_certificates")}
          SET ${q("certificateChainPem")} = ?, ${q("privateKeyEncrypted")} = ?, ${q("privateKeyFingerprint")} = ?,
              ${q("keyVersion")} = ?, ${q("leafFingerprintSha256")} = ?, ${q("dnsNamesJson")} = ?,
              ${q("subject")} = ?, ${q("issuer")} = ?, ${q("serialNumber")} = ?, ${q("notBefore")} = ?,
              ${q("notAfter")} = ?, ${q("keyAlgorithm")} = ?, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ?`,
      [
        validated.certificateChainPem,
        privateKeyEncrypted,
        fingerprintXraySecret(validated.privateKeyPem, context, dependencies.keyring),
        envelope.version,
        validated.leafFingerprintSha256,
        JSON.stringify(validated.dnsNames),
        validated.subject,
        validated.issuer,
        validated.serialNumber,
        new Date(validated.notBefore * 1000),
        new Date(validated.notAfter * 1000),
        validated.keyAlgorithm,
        nowDate(),
        id,
      ],
    );
    if (rawAffectedRows(result) !== 1) throw new XrayTlsCertificateRepositoryError("CERTIFICATE_NOT_FOUND");
    return getXrayTlsCertificate(id);
  });
}

export async function removeXrayTlsCertificate(input: {
  id: number;
  confirmName: string;
}): Promise<{ id: number; removed: true }> {
  const id = positiveInteger(input.id);
  return withDatabaseTransaction(async () => {
    const current = await getXrayTlsCertificate(id);
    if (input.confirmName !== current.name) throw new XrayTlsCertificateRepositoryError("CONFIRMATION_MISMATCH");
    if (current.referenceCount > 0) throw new XrayTlsCertificateRepositoryError("CERTIFICATE_IN_USE");
    const q = quoteIdentifier;
    const result = await executeRaw(`DELETE FROM ${q("xray_tls_certificates")} WHERE ${q("id")} = ?`, [id]);
    if (rawAffectedRows(result) !== 1) throw new XrayTlsCertificateRepositoryError("CERTIFICATE_NOT_FOUND");
    return { id, removed: true };
  });
}
