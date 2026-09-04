import {
  X509Certificate,
  createPrivateKey,
  createPublicKey,
  type KeyObject,
} from "node:crypto";

export const MAX_XRAY_TLS_CERTIFICATE_BYTES = 16 * 1024;
export const MAX_XRAY_TLS_PRIVATE_KEY_BYTES = 8 * 1024;
export const MAX_XRAY_TLS_CERTIFICATE_COUNT = 4;

export type XrayTlsCertificateValidationErrorCode =
  | "CERTIFICATE_INVALID"
  | "PRIVATE_KEY_INVALID"
  | "CERTIFICATE_KEY_MISMATCH"
  | "CERTIFICATE_EXPIRED"
  | "CERTIFICATE_NOT_YET_VALID";

export class XrayTlsCertificateValidationError extends Error {
  constructor(readonly code: XrayTlsCertificateValidationErrorCode) {
    super({
      CERTIFICATE_INVALID: "TLS certificate is invalid",
      PRIVATE_KEY_INVALID: "TLS private key is invalid",
      CERTIFICATE_KEY_MISMATCH: "TLS certificate and private key do not match",
      CERTIFICATE_EXPIRED: "TLS certificate is expired",
      CERTIFICATE_NOT_YET_VALID: "TLS certificate is not yet valid",
    }[code]);
    this.name = "XrayTlsCertificateValidationError";
  }
}

export type ValidatedXrayTlsCertificate = Readonly<{
  certificateChainPem: string;
  privateKeyPem: string;
  certificateCount: number;
  leafFingerprintSha256: string;
  dnsNames: string[];
  subject: string;
  issuer: string;
  serialNumber: string;
  notBefore: number;
  notAfter: number;
  keyAlgorithm: "RSA_2048_4096" | "ECDSA_P256_P384";
}>;

const textEncoder = new TextEncoder();
const certificatePattern = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
const privateKeyPattern = /-----BEGIN (PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----[\s\S]*?-----END \1-----/g;

function fail(code: XrayTlsCertificateValidationErrorCode): never {
  throw new XrayTlsCertificateValidationError(code);
}

function normalizedInput(value: unknown, maxBytes: number, code: XrayTlsCertificateValidationErrorCode): string {
  if (typeof value !== "string" || value.includes("\0") || textEncoder.encode(value).byteLength > maxBytes) fail(code);
  const normalized = value.replace(/^\uFEFF/, "").replace(/\r\n?/g, "\n").trim();
  if (!normalized || textEncoder.encode(normalized).byteLength > maxBytes) fail(code);
  return normalized;
}

function parseCertificates(value: unknown): X509Certificate[] {
  const normalized = normalizedInput(value, MAX_XRAY_TLS_CERTIFICATE_BYTES, "CERTIFICATE_INVALID");
  const blocks = Array.from(normalized.matchAll(certificatePattern), (match) => match[0].trim());
  if (blocks.length < 1 || blocks.length > MAX_XRAY_TLS_CERTIFICATE_COUNT) fail("CERTIFICATE_INVALID");
  if (normalized.replace(certificatePattern, "").trim()) fail("CERTIFICATE_INVALID");
  try {
    const certificates = blocks.map((block) => new X509Certificate(block));
    if (new Set(certificates.map((certificate) => certificate.raw.toString("base64"))).size !== certificates.length) {
      fail("CERTIFICATE_INVALID");
    }
    return certificates;
  } catch (error) {
    if (error instanceof XrayTlsCertificateValidationError) throw error;
    fail("CERTIFICATE_INVALID");
  }
}

function parsePrivateKey(value: unknown): KeyObject {
  const normalized = normalizedInput(value, MAX_XRAY_TLS_PRIVATE_KEY_BYTES, "PRIVATE_KEY_INVALID");
  if (/-----BEGIN ENCRYPTED PRIVATE KEY-----|Proc-Type:\s*4,ENCRYPTED/i.test(normalized)) fail("PRIVATE_KEY_INVALID");
  const blocks = Array.from(normalized.matchAll(privateKeyPattern), (match) => match[0].trim());
  if (blocks.length !== 1 || normalized.replace(privateKeyPattern, "").trim()) fail("PRIVATE_KEY_INVALID");
  try {
    return createPrivateKey({ key: blocks[0], format: "pem" });
  } catch {
    fail("PRIVATE_KEY_INVALID");
  }
}

function keyAlgorithm(key: KeyObject): ValidatedXrayTlsCertificate["keyAlgorithm"] {
  if (key.asymmetricKeyType === "rsa") {
    const bits = key.asymmetricKeyDetails?.modulusLength;
    if (typeof bits === "number" && bits >= 2048 && bits <= 4096) return "RSA_2048_4096";
  }
  if (key.asymmetricKeyType === "ec") {
    const curve = key.asymmetricKeyDetails?.namedCurve;
    if (curve === "prime256v1" || curve === "secp384r1") return "ECDSA_P256_P384";
  }
  fail("PRIVATE_KEY_INVALID");
}

function normalizedDnsNames(certificate: X509Certificate): string[] {
  const values = Array.from((certificate.subjectAltName ?? "").matchAll(/(?:^|,\s*)DNS:([^,]+)/g), (match) => match[1]
    .trim().toLowerCase().replace(/\.$/, ""));
  const hostnamePattern = /^(?:\*\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  if (values.length < 1 || values.length > 64 || values.some((value) => !hostnamePattern.test(value))) fail("CERTIFICATE_INVALID");
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function boundedMetadata(value: string): string {
  const normalized = value.trim();
  if (!normalized || textEncoder.encode(normalized).byteLength > 2048) fail("CERTIFICATE_INVALID");
  return normalized;
}

function validateChain(certificates: X509Certificate[]): void {
  if (certificates[0].ca) fail("CERTIFICATE_INVALID");
  for (let index = 0; index < certificates.length - 1; index += 1) {
    const certificate = certificates[index];
    const issuer = certificates[index + 1];
    if (!issuer.ca || certificate.issuer !== issuer.subject || !certificate.verify(issuer.publicKey)) {
      fail("CERTIFICATE_INVALID");
    }
  }
}

export function validateXrayTlsCertificateInput(input: {
  certificatePem: unknown;
  privateKeyPem: unknown;
  now?: Date;
  enforceValidity?: boolean;
}): ValidatedXrayTlsCertificate {
  const certificates = parseCertificates(input.certificatePem);
  const privateKey = parsePrivateKey(input.privateKeyPem);
  const algorithm = keyAlgorithm(privateKey);
  const leaf = certificates[0];
  validateChain(certificates);

  const certificatePublicKey = leaf.publicKey.export({ type: "spki", format: "der" });
  const privatePublicKey = createPublicKey(privateKey).export({ type: "spki", format: "der" });
  if (!certificatePublicKey.equals(privatePublicKey)) fail("CERTIFICATE_KEY_MISMATCH");

  const notBeforeMs = Date.parse(leaf.validFrom);
  const notAfterMs = Date.parse(leaf.validTo);
  if (!Number.isFinite(notBeforeMs) || !Number.isFinite(notAfterMs) || notBeforeMs >= notAfterMs) fail("CERTIFICATE_INVALID");
  const nowMs = (input.now ?? new Date()).getTime();
  if (!Number.isFinite(nowMs)) fail("CERTIFICATE_INVALID");
  if (input.enforceValidity !== false) {
    if (nowMs < notBeforeMs) fail("CERTIFICATE_NOT_YET_VALID");
    if (nowMs > notAfterMs) fail("CERTIFICATE_EXPIRED");
  }

  const fingerprint = leaf.fingerprint256.replaceAll(":", "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(fingerprint)) fail("CERTIFICATE_INVALID");
  const serialNumber = leaf.serialNumber.replaceAll(":", "").toLowerCase();
  if (!/^[0-9a-f]{1,128}$/.test(serialNumber)) fail("CERTIFICATE_INVALID");

  return {
    certificateChainPem: `${certificates.map((certificate) => certificate.toString().trim()).join("\n")}\n`,
    privateKeyPem: String(privateKey.export({ type: "pkcs8", format: "pem" })),
    certificateCount: certificates.length,
    leafFingerprintSha256: fingerprint,
    dnsNames: normalizedDnsNames(leaf),
    subject: boundedMetadata(leaf.subject),
    issuer: boundedMetadata(leaf.issuer),
    serialNumber,
    notBefore: Math.floor(notBeforeMs / 1000),
    notAfter: Math.floor(notAfterMs / 1000),
    keyAlgorithm: algorithm,
  };
}

export function xrayTlsCertificateCoversServerName(certificatePem: string, serverName: string): boolean {
  try {
    if (typeof serverName !== "string" || serverName.length < 1 || serverName.length > 253) return false;
    const normalized = serverName.trim().toLowerCase().replace(/\.$/, "");
    if (!normalized || normalized !== serverName.trim().toLowerCase().replace(/\.$/, "")) return false;
    const [leaf] = parseCertificates(certificatePem);
    return leaf.checkHost(normalized, {
      subject: "never",
      wildcards: true,
      partialWildcards: false,
      multiLabelWildcards: false,
      singleLabelSubdomains: false,
    }) !== undefined;
  } catch {
    return false;
  }
}

export function xrayTlsCertificateLeafFingerprintSha256(certificatePem: string): string | null {
  try {
    const [leaf] = parseCertificates(certificatePem);
    const fingerprint = leaf.fingerprint256.replaceAll(":", "").toLowerCase();
    return /^[0-9a-f]{64}$/.test(fingerprint) ? fingerprint : null;
  } catch {
    return null;
  }
}
