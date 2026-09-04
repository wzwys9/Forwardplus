import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  isXrayAccessSecretKind,
  isXrayInboundSecretKind,
  type XrayAccessSecretKind,
  type XrayInboundSecretKind,
} from "../shared/xrayAccess";
import type { XrayExternalProxySecretKind } from "../shared/xrayExternalProxy";

const XRAY_SECRET_PREFIX = "fwdx-secret";
const XRAY_SECRET_VERSION = "v1";
const XRAY_MASTER_KEY_BYTES = 32;
const XRAY_GCM_NONCE_BYTES = 12;
const XRAY_GCM_TAG_BYTES = 16;
const XRAY_MAX_SECRET_BYTES = 64 * 1024;
const XRAY_DEFAULT_KEY_ID = "1";
const XRAY_SECRET_ERROR_MESSAGE = "Xray sensitive data is unavailable";
const keyIdPattern = /^[A-Za-z0-9._-]{1,64}$/;
const contextPartPattern = /^[A-Za-z0-9._:-]{1,128}$/;

export type XraySecretContext = Readonly<{
  resourceType: string;
  resourceId: string;
  field: string;
}>;

export type XraySecretKeyring = Readonly<{
  currentKeyId: string;
  keys: ReadonlyMap<string, Buffer>;
}>;

export function xrayInboundPrivateKeyContext(runtimeTag: string): XraySecretContext {
  return { resourceType: "xray-inbound", resourceId: runtimeTag, field: "reality-private-key" };
}

export function xrayClientUuidContext(statsKey: string): XraySecretContext {
  return { resourceType: "xray-client", resourceId: statsKey, field: "uuid" };
}

export function xrayClientShortIdContext(statsKey: string): XraySecretContext {
  return { resourceType: "xray-client", resourceId: statsKey, field: "short-id" };
}

export function xrayAccessSecretContext(statsKey: string, kind: XrayAccessSecretKind): XraySecretContext {
  if (!isXrayAccessSecretKind(kind)) throw unavailable();
  if (kind === "UUID") return xrayClientUuidContext(statsKey);
  if (kind === "SHORT_ID") return xrayClientShortIdContext(statsKey);
  const field = {
    USERNAME: "username",
    PASSWORD: "password",
    SHADOWSOCKS_KEY: "shadowsocks-key",
    HYSTERIA_AUTH: "hysteria-auth",
    PRIVATE_KEY: "private-key",
    PRE_SHARED_KEY: "pre-shared-key",
  }[kind];
  return { resourceType: "xray-access", resourceId: statsKey, field };
}

export function xrayInboundSecretContext(runtimeTag: string, kind: XrayInboundSecretKind): XraySecretContext {
  if (!isXrayInboundSecretKind(kind)) throw unavailable();
  const field = {
    REALITY_PRIVATE_KEY: "reality-private-key",
    TLS_PRIVATE_KEY: "tls-private-key",
    SHADOWSOCKS_SERVER_KEY: "shadowsocks-server-key",
    PRIVATE_KEY: "private-key",
    PRE_SHARED_KEY: "pre-shared-key",
  }[kind];
  return { resourceType: "xray-inbound", resourceId: runtimeTag, field };
}

export function xrayTlsCertificatePrivateKeyContext(certificateTag: string): XraySecretContext {
  return { resourceType: "xray-tls-certificate", resourceId: certificateTag, field: "tls-private-key" };
}

export function xrayExternalProxySecretContext(
  nodeTag: string,
  kind: XrayExternalProxySecretKind,
): XraySecretContext {
  const field = {
    VLESS_UUID: "vless-uuid",
    VLESS_SHORT_ID: "vless-short-id",
    SHADOWSOCKS_PASSWORD: "shadowsocks-password",
    SOCKS_USERNAME: "socks-username",
    SOCKS_PASSWORD: "socks-password",
  }[kind];
  if (!field) throw unavailable();
  return { resourceType: "xray-external-proxy", resourceId: nodeTag, field };
}

export type XrayDnsProviderAccountSecretKind = "DNSPOD_SECRET_ID" | "DNSPOD_SECRET_KEY";

export function xrayDnsProviderAccountSecretContext(
  accountTag: string,
  kind: XrayDnsProviderAccountSecretKind,
): XraySecretContext {
  const field = {
    DNSPOD_SECRET_ID: "dnspod-secret-id",
    DNSPOD_SECRET_KEY: "dnspod-secret-key",
  }[kind];
  if (!field) throw unavailable();
  return { resourceType: "dns-provider-account", resourceId: accountTag, field };
}

export type XrayManagedServiceAccountSecretKind = "MTPROTO_SECRET" | "AMNEZIAWG_PRIVATE_KEY" | "AMNEZIAWG_PRE_SHARED_KEY";
export type XrayManagedServiceInstanceSecretKind = "AMNEZIAWG_SERVER_PRIVATE_KEY" | "AMNEZIAWG_HEADER_PROTECTION_KEY";

export function xrayManagedServiceAccountSecretContext(
  accountTag: string,
  kind: XrayManagedServiceAccountSecretKind = "MTPROTO_SECRET",
): XraySecretContext {
  const field = {
    MTPROTO_SECRET: "mtproto-secret",
    AMNEZIAWG_PRIVATE_KEY: "amneziawg-private-key",
    AMNEZIAWG_PRE_SHARED_KEY: "amneziawg-pre-shared-key",
  }[kind];
  return { resourceType: "xray-managed-service-account", resourceId: accountTag, field };
}

export function xrayManagedServiceInstanceSecretContext(
  serviceTag: string,
  kind: XrayManagedServiceInstanceSecretKind,
): XraySecretContext {
  const field = {
    AMNEZIAWG_SERVER_PRIVATE_KEY: "amneziawg-server-private-key",
    AMNEZIAWG_HEADER_PROTECTION_KEY: "amneziawg-header-protection-key",
  }[kind];
  return { resourceType: "xray-managed-service", resourceId: serviceTag, field };
}

export class XraySecretUnavailableError extends Error {
  readonly code = "SENSITIVE_DATA_UNAVAILABLE" as const;

  constructor() {
    super(XRAY_SECRET_ERROR_MESSAGE);
    this.name = "XraySecretUnavailableError";
  }
}

type MasterKeyPathOptions = {
  env?: NodeJS.ProcessEnv;
  cwd?: string;
};

type MasterKeyFileOptions = MasterKeyPathOptions & {
  path?: string;
  keyId?: string;
};

function unavailable(): XraySecretUnavailableError {
  return new XraySecretUnavailableError();
}

function resolvedFilePath(options: MasterKeyFileOptions): string {
  if (options.path) return path.resolve(options.path);
  return resolveXrayMasterKeyPath(options);
}

function validateKeyId(keyId: string): void {
  if (!keyIdPattern.test(keyId)) throw unavailable();
}

function validateContext(context: XraySecretContext): void {
  for (const value of [context.resourceType, context.resourceId, context.field]) {
    if (!contextPartPattern.test(value)) throw unavailable();
  }
}

function contextAAD(context: XraySecretContext): Buffer {
  validateContext(context);
  return Buffer.from(JSON.stringify({
    version: XRAY_SECRET_VERSION,
    resourceType: context.resourceType,
    resourceId: context.resourceId,
    field: context.field,
  }), "utf8");
}

function keyFor(keyring: XraySecretKeyring, keyId: string): Buffer {
  validateKeyId(keyId);
  const key = keyring.keys.get(keyId);
  if (!key || key.length !== XRAY_MASTER_KEY_BYTES) throw unavailable();
  return key;
}

function plaintextBytes(plaintext: string): Buffer {
  if (typeof plaintext !== "string") throw unavailable();
  const encoded = Buffer.from(plaintext, "utf8");
  if (encoded.length < 1 || encoded.length > XRAY_MAX_SECRET_BYTES) throw unavailable();
  return encoded;
}

function parseEnvelope(envelope: string): { keyId: string; payload: Buffer } {
  if (typeof envelope !== "string") throw unavailable();
  const match = /^fwdx-secret:v1:([A-Za-z0-9._-]{1,64}):([A-Za-z0-9_-]+)$/.exec(envelope);
  if (!match) throw unavailable();
  const payload = Buffer.from(match[2], "base64url");
  if (payload.toString("base64url") !== match[2]) throw unavailable();
  if (payload.length < XRAY_GCM_NONCE_BYTES + XRAY_GCM_TAG_BYTES
    || payload.length > XRAY_MAX_SECRET_BYTES + XRAY_GCM_NONCE_BYTES + XRAY_GCM_TAG_BYTES) {
    throw unavailable();
  }
  return { keyId: match[1], payload };
}

export function inspectXraySecretEnvelope(envelope: string): { version: 1; keyId: string } {
  try {
    const parsed = parseEnvelope(envelope);
    return { version: 1, keyId: parsed.keyId };
  } catch {
    throw unavailable();
  }
}

export function createXraySecretKeyring(input: {
  currentKeyId: string;
  keys: Record<string, Uint8Array>;
}): XraySecretKeyring {
  validateKeyId(input.currentKeyId);
  const keys = new Map<string, Buffer>();
  for (const [keyId, keyValue] of Object.entries(input.keys)) {
    validateKeyId(keyId);
    const key = Buffer.from(keyValue);
    if (key.length !== XRAY_MASTER_KEY_BYTES) throw unavailable();
    keys.set(keyId, key);
  }
  if (!keys.has(input.currentKeyId)) throw unavailable();
  return Object.freeze({ currentKeyId: input.currentKeyId, keys });
}

export function encryptXraySecret(
  plaintext: string,
  context: XraySecretContext,
  keyring: XraySecretKeyring,
): string {
  try {
    validateContext(context);
    const keyId = keyring.currentKeyId;
    const key = keyFor(keyring, keyId);
    const nonce = crypto.randomBytes(XRAY_GCM_NONCE_BYTES);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce, { authTagLength: XRAY_GCM_TAG_BYTES });
    cipher.setAAD(contextAAD(context));
    const ciphertext = Buffer.concat([cipher.update(plaintextBytes(plaintext)), cipher.final()]);
    const payload = Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]);
    return `${XRAY_SECRET_PREFIX}:${XRAY_SECRET_VERSION}:${keyId}:${payload.toString("base64url")}`;
  } catch {
    throw unavailable();
  }
}

export function decryptXraySecret(
  envelope: string,
  context: XraySecretContext,
  keyring: XraySecretKeyring,
): string {
  try {
    const parsed = parseEnvelope(envelope);
    const key = keyFor(keyring, parsed.keyId);
    const nonce = parsed.payload.subarray(0, XRAY_GCM_NONCE_BYTES);
    const tag = parsed.payload.subarray(parsed.payload.length - XRAY_GCM_TAG_BYTES);
    const ciphertext = parsed.payload.subarray(XRAY_GCM_NONCE_BYTES, parsed.payload.length - XRAY_GCM_TAG_BYTES);
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, nonce, { authTagLength: XRAY_GCM_TAG_BYTES });
    decipher.setAAD(contextAAD(context));
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    if (plaintext.length < 1 || plaintext.length > XRAY_MAX_SECRET_BYTES) throw unavailable();
    return plaintext.toString("utf8");
  } catch {
    throw unavailable();
  }
}

export function fingerprintXraySecret(
  plaintext: string,
  context: XraySecretContext,
  keyring: XraySecretKeyring,
): string {
  try {
    const keyId = keyring.currentKeyId;
    const masterKey = keyFor(keyring, keyId);
    const hmacKey = Buffer.from(crypto.hkdfSync(
      "sha256",
      masterKey,
      Buffer.from("forwardx-xray-secret-fingerprint-salt-v1", "utf8"),
      Buffer.from(`forwardx-xray-secret-fingerprint:${keyId}`, "utf8"),
      32,
    ));
    return crypto.createHmac("sha256", hmacKey)
      .update(Buffer.from(JSON.stringify({
        version: XRAY_SECRET_VERSION,
        resourceType: context.resourceType,
        field: context.field,
      }), "utf8"))
      .update(Buffer.from([0]))
      .update(plaintextBytes(plaintext))
      .digest("hex");
  } catch {
    throw unavailable();
  }
}

export function resolveXrayMasterKeyPath(options: MasterKeyPathOptions = {}): string {
  const env = options.env ?? process.env;
  const cwd = options.cwd ?? process.cwd();
  const configured = String(env.XRAY_MASTER_KEY_PATH ?? "").trim();
  if (configured) return path.resolve(cwd, configured);
  if (String(env.NODE_ENV ?? "").trim().toLowerCase() !== "production") {
    return path.resolve(cwd, "data", "xray-master.key");
  }
  if (String(env.FORWARDX_PORT_MANAGEMENT ?? "").trim().toLowerCase() === "docker") {
    return "/data/xray-master.key";
  }
  return "/opt/forwardx-panel/data/xray-master.key";
}

function validateOpenKeyFile(filePath: string): { descriptor: number; stat: fs.Stats } {
  let descriptor = -1;
  try {
    const before = fs.lstatSync(filePath);
    if (!before.isFile() || before.isSymbolicLink() || (before.mode & 0o777) !== 0o600) throw unavailable();
    if (typeof process.getuid === "function" && before.uid !== process.getuid()) throw unavailable();
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const after = fs.fstatSync(descriptor);
    if (!after.isFile() || after.dev !== before.dev || after.ino !== before.ino || (after.mode & 0o777) !== 0o600) {
      throw unavailable();
    }
    return { descriptor, stat: after };
  } catch {
    if (descriptor >= 0) fs.closeSync(descriptor);
    throw unavailable();
  }
}

export function loadXrayMasterKeyFile(options: MasterKeyFileOptions = {}): XraySecretKeyring {
  const filePath = resolvedFilePath(options);
  const keyId = options.keyId ?? XRAY_DEFAULT_KEY_ID;
  validateKeyId(keyId);
  const opened = validateOpenKeyFile(filePath);
  try {
    const encoded = fs.readFileSync(opened.descriptor, "utf8");
    if (!/^[0-9a-fA-F]{64}\n?$/.test(encoded)) throw unavailable();
    return createXraySecretKeyring({
      currentKeyId: keyId,
      keys: { [keyId]: Buffer.from(encoded.trim(), "hex") },
    });
  } catch {
    throw unavailable();
  } finally {
    fs.closeSync(opened.descriptor);
  }
}

function assertSafeParentDirectory(directory: string): void {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || fs.realpathSync(directory) !== path.resolve(directory)) {
    throw unavailable();
  }
}

function fsyncDirectory(directory: string): void {
  let descriptor = -1;
  try {
    descriptor = fs.openSync(directory, fs.constants.O_RDONLY);
    fs.fsyncSync(descriptor);
  } catch {
    // The file itself is already fsynced; some platforms do not allow fsync on directories.
  } finally {
    if (descriptor >= 0) fs.closeSync(descriptor);
  }
}

export function createXrayMasterKeyFile(options: MasterKeyFileOptions = {}): XraySecretKeyring {
  const filePath = resolvedFilePath(options);
  const keyId = options.keyId ?? XRAY_DEFAULT_KEY_ID;
  validateKeyId(keyId);
  try {
    if (fs.existsSync(filePath) || fs.lstatSync(filePath, { throwIfNoEntry: false })) {
      return loadXrayMasterKeyFile({ path: filePath, keyId });
    }
    const directory = path.dirname(filePath);
    assertSafeParentDirectory(directory);
    const temporary = path.join(directory, `.${path.basename(filePath)}.tmp-${crypto.randomBytes(8).toString("hex")}`);
    let descriptor = -1;
    try {
      descriptor = fs.openSync(
        temporary,
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0),
        0o600,
      );
      fs.writeFileSync(descriptor, `${crypto.randomBytes(XRAY_MASTER_KEY_BYTES).toString("hex")}\n`, "utf8");
      fs.fsyncSync(descriptor);
      fs.closeSync(descriptor);
      descriptor = -1;
      try {
        fs.linkSync(temporary, filePath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      }
    } finally {
      if (descriptor >= 0) fs.closeSync(descriptor);
      fs.rmSync(temporary, { force: true });
    }
    fsyncDirectory(directory);
    return loadXrayMasterKeyFile({ path: filePath, keyId });
  } catch {
    throw unavailable();
  }
}

export function restoreXrayMasterKeyFile(options: MasterKeyFileOptions & {
  key: Uint8Array;
  allowReplace?: boolean;
}): XraySecretKeyring {
  const filePath = resolvedFilePath(options);
  const keyId = options.keyId ?? XRAY_DEFAULT_KEY_ID;
  validateKeyId(keyId);
  const key = Buffer.from(options.key);
  if (key.length !== XRAY_MASTER_KEY_BYTES) throw unavailable();
  try {
    const existingStat = fs.lstatSync(filePath, { throwIfNoEntry: false });
    if (existingStat) {
      const existing = loadXrayMasterKeyFile({ path: filePath, keyId });
      if (existing.keys.get(keyId)?.equals(key)) return existing;
      if (!options.allowReplace) throw unavailable();
    }

    const directory = path.dirname(filePath);
    assertSafeParentDirectory(directory);
    const temporary = path.join(directory, `.${path.basename(filePath)}.restore-${crypto.randomBytes(8).toString("hex")}`);
    let descriptor = -1;
    try {
      descriptor = fs.openSync(
        temporary,
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW ?? 0),
        0o600,
      );
      fs.writeFileSync(descriptor, `${key.toString("hex")}\n`, "utf8");
      fs.fsyncSync(descriptor);
      fs.closeSync(descriptor);
      descriptor = -1;
      if (existingStat && options.allowReplace) {
        fs.renameSync(temporary, filePath);
      } else {
        try {
          fs.linkSync(temporary, filePath);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        }
      }
    } finally {
      if (descriptor >= 0) fs.closeSync(descriptor);
      fs.rmSync(temporary, { force: true });
    }
    fsyncDirectory(directory);
    const restored = loadXrayMasterKeyFile({ path: filePath, keyId });
    if (!restored.keys.get(keyId)?.equals(key)) throw unavailable();
    return restored;
  } catch {
    throw unavailable();
  }
}
