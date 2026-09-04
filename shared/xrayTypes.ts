import { z } from "zod";

export const XRAY_SCHEMA_VERSION = 1 as const;

export const XRAY_LIMITS = Object.freeze({
  maxConfigJsonBytes: 1024 * 1024,
  maxExpectedListeners: 256,
  maxPortProbeCandidates: 32,
  maxRealityTargets: 64,
  maxRealityConcurrency: 16,
  maxRealityTimeoutMs: 10_000,
  maxControlPayloadBytes: 256 * 1024,
  maxTaskResultBytes: 256 * 1024,
  maxErrorMessageBytes: 2 * 1024,
  maxIdentifierLength: 128,
});

export const XRAY_AGENT_ERROR_CODES = [
  "CAPABILITY_UNSUPPORTED",
  "TASK_EXPIRED",
  "TASK_ALREADY_COMPLETED",
  "INVALID_PAYLOAD",
  "HOST_PLATFORM_UNSUPPORTED",
  "PORT_IN_USE",
  "PORT_BIND_DENIED",
  "REALITY_TARGET_BLOCKED",
  "REALITY_TLS_UNSUPPORTED",
  "ARTIFACT_NOT_FOUND",
  "ARTIFACT_SIZE_MISMATCH",
  "ARTIFACT_HASH_MISMATCH",
  "ARTIFACT_ARCH_MISMATCH",
  "XRAY_VERSION_MISMATCH",
  "CONFIG_INVALID",
  "GENERATION_HASH_CONFLICT",
  "RUNTIME_START_FAILED",
  "RUNTIME_NOT_READY",
  "ROLLBACK_FAILED",
  "INTERNAL_ERROR",
] as const;

export const XRAY_TASK_TYPES = [
  "PORT_PROBE",
  "REALITY_SCAN",
  "INSTALL",
  "UPGRADE",
  "RESTART",
] as const;

export const XRAY_TASK_RESULT_STATUSES = [
  "SUCCESS",
  "FAILED",
  "TIMEOUT",
  "REJECTED",
] as const;

export const XRAY_SERVICE_STATUSES = [
  "RUNNING",
  "STOPPED",
  "ERROR",
  "UNKNOWN",
] as const;

export const XRAY_LISTENER_STATUSES = [
  "READY",
  "MISSING",
  "WRONG_PROCESS",
  "UNKNOWN",
] as const;

export const XRAY_MANAGED_SERVICE_KINDS = ["MTPROTO_FAKE_TLS", "AMNEZIAWG"] as const;
export const XRAY_MANAGED_SERVICE_IMPLEMENTATION_STATUSES = ["AVAILABLE", "IMPLEMENTING", "NOT_IMPLEMENTED"] as const;

export const XRAY_MANAGED_SERVICE_LIMITS = Object.freeze({
  maxServices: 32,
  maxAccountsPerService: 64,
  maxArtifactBytes: 16 * 1024 * 1024,
});

const encoder = new TextEncoder();
const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]*$/;
const errorCodePattern = /^[A-Z][A-Z0-9_]*$/;
const sha256Pattern = /^[0-9a-f]{64}$/;
const versionPattern = /^v[0-9]+\.[0-9]+\.[0-9]+$/;
const canonicalUuidV4Pattern = "[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}";
const mtprotoServiceTagPattern = new RegExp(`^forwardx-mtproto-${canonicalUuidV4Pattern}$`);
const mtprotoAccountTagPattern = new RegExp(`^forwardx-mtproto-account-${canonicalUuidV4Pattern}$`);
const mtprotoDomainPattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const mtprotoSecretPattern = /^ee[0-9a-f]{32}[0-9a-f]{2,506}$/;
const amneziawgServiceTagPattern = new RegExp(`^forwardx-amneziawg-${canonicalUuidV4Pattern}$`);
const amneziawgAccountTagPattern = new RegExp(`^forwardx-amneziawg-peer-${canonicalUuidV4Pattern}$`);
const amneziawgKeyPattern = /^[A-Za-z0-9+/]{43}=$/;
const amneziawgPeerAddressPattern = /^10\.8\.1\.(?:[2-9]|[1-9]\d|1\d{2}|2[0-4]\d|25[0-4])\/32$/;
const unsignedRangePattern = /^(?:0|[1-9]\d{0,9})(?:-(?:0|[1-9]\d{0,9}))?$/;
const amneziawgI1Pattern = /^<r (?:3[2-9]|[4-9]\d|1\d{2}|2[0-4]\d|25[0-6])>$/;
const managedServicePublicAddressSchema = z.union([
  z.string().ip(),
  z.string().regex(mtprotoDomainPattern),
]);

function decodeCanonicalAmneziaWGKey(value: string): Uint8Array | null {
  if (!amneziawgKeyPattern.test(value)) return null;
  try {
    const decoded = Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
    return decoded.length === 32 && btoa(String.fromCharCode(...decoded)) === value ? decoded : null;
  } catch {
    return null;
  }
}

const amneziawgNonZeroKeySchema = z.string().regex(amneziawgKeyPattern).superRefine((value, ctx) => {
  const decoded = decodeCanonicalAmneziaWGKey(value);
  if (!decoded || decoded.every((byte) => byte === 0)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "key must be canonical base64 and nonzero" });
  }
});

const amneziawgPrivateKeySchema = amneziawgNonZeroKeySchema.superRefine((value, ctx) => {
  const decoded = decodeCanonicalAmneziaWGKey(value);
  if (decoded && ((decoded[0] & 7) !== 0 || (decoded[31] & 128) !== 0 || (decoded[31] & 64) === 0)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "private key must be Curve25519-clamped" });
  }
});
const realityTargetPattern = /^(?=.{1,260}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?:([1-9][0-9]{0,4})$/;

const observedForbiddenKeys = new Set([
  "agenttoken",
  "authorization",
  "client",
  "clients",
  "configjson",
  "privatekey",
  "realityprivatekey",
  "shortid",
  "shareuri",
  "token",
  "uuid",
  "vlessuri",
]);

const taskForbiddenKeys = new Set(["command", "script", "shell"]);

function utf8Size(value: string): number {
  return encoder.encode(value).byteLength;
}

function utf8Hex(value: string): string {
  return Array.from(encoder.encode(value), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function jsonUtf8Size(value: unknown): number | null {
  try {
    const serialized = JSON.stringify(value);
    return serialized === undefined ? null : utf8Size(serialized);
  } catch {
    return null;
  }
}

function normalizedKey(key: string): string {
  return key.replace(/[_-]/g, "").toLowerCase();
}

function findForbiddenKey(
  value: unknown,
  forbidden: ReadonlySet<string>,
  seen = new WeakSet<object>(),
  path: Array<string | number> = [],
): Array<string | number> | null {
  if (value === null || typeof value !== "object") return null;
  if (seen.has(value)) return null;
  seen.add(value);

  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const found = findForbiddenKey(value[index], forbidden, seen, [...path, index]);
      if (found) return found;
    }
    return null;
  }

  for (const [key, child] of Object.entries(value)) {
    if (forbidden.has(normalizedKey(key))) return [...path, key];
    const found = findForbiddenKey(child, forbidden, seen, [...path, key]);
    if (found) return found;
  }
  return null;
}

function withRawChecks<T extends z.ZodTypeAny>(
  schema: T,
  options: {
    forbiddenKeys?: ReadonlySet<string>;
    maxJsonBytes?: number;
  },
) {
  return z.unknown().superRefine((value, ctx) => {
    if (options.maxJsonBytes !== undefined) {
      const size = jsonUtf8Size(value);
      if (size === null || size > options.maxJsonBytes) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `JSON payload exceeds ${options.maxJsonBytes} bytes`,
        });
      }
    }

    if (options.forbiddenKeys) {
      const path = findForbiddenKey(value, options.forbiddenKeys);
      if (path) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "payload contains a forbidden field",
          path,
        });
      }
    }
  }).pipe(schema);
}

const schemaVersionSchema = z.literal(XRAY_SCHEMA_VERSION);
const nonNegativeIntegerSchema = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const positiveIntegerSchema = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const portSchema = z.number().int().min(1000).max(65535);
const sha256Schema = z.string().regex(sha256Pattern);
const versionSchema = z.string().min(1).max(64).regex(versionPattern);
const timestampSchema = z.string().datetime({ offset: true });
const identifierSchema = z.string()
  .min(1)
  .max(XRAY_LIMITS.maxIdentifierLength)
  .regex(identifierPattern);
const errorCodeSchema = z.string().min(1).max(64).regex(errorCodePattern);
const errorMessageSchema = z.string().refine(
  (value) => utf8Size(value) <= XRAY_LIMITS.maxErrorMessageBytes,
  `error message exceeds ${XRAY_LIMITS.maxErrorMessageBytes} bytes`,
);
const listenerNetworkSchema = z.enum(["tcp", "udp"]);

const supportedCapabilitySchema = z.object({
  schemaVersion: schemaVersionSchema,
  supported: z.literal(true),
  supervisor: z.literal("AGENT_CHILD"),
  supportsPortProbe: z.boolean(),
  supportsUdpPortProbe: z.boolean().optional().default(false),
  supportsUdpListenerReadiness: z.boolean().optional().default(false),
  supportsRealityScan: z.boolean(),
  supportsArtifactInstall: z.boolean(),
  supportedOS: z.literal("linux"),
  supportedArch: z.enum(["amd64", "arm64"]),
});

const unsupportedCapabilitySchema = z.object({
  schemaVersion: schemaVersionSchema,
  supported: z.literal(false),
  supervisor: z.literal("AGENT_CHILD"),
  supportsPortProbe: z.boolean(),
  supportsUdpPortProbe: z.boolean().optional().default(false),
  supportsUdpListenerReadiness: z.boolean().optional().default(false),
  supportsRealityScan: z.boolean(),
  supportsArtifactInstall: z.boolean(),
  supportedOS: z.string().min(1).max(32),
  supportedArch: z.string().min(1).max(32),
  errorCode: errorCodeSchema.optional(),
});

const capabilityUnionSchema = z.discriminatedUnion("supported", [
  supportedCapabilitySchema,
  unsupportedCapabilitySchema,
]);

export const XrayCapabilitySchema = withRawChecks(capabilityUnionSchema, {
  maxJsonBytes: XRAY_LIMITS.maxControlPayloadBytes,
});

export const XrayExpectedListenerSchema = z.object({
  inboundId: positiveIntegerSchema,
  runtimeTag: identifierSchema,
  network: listenerNetworkSchema,
  listenAddress: z.string().min(1).max(64),
  port: portSchema,
});

const configJsonSchema = z.string().min(2).superRefine((value, ctx) => {
  if (utf8Size(value) > XRAY_LIMITS.maxConfigJsonBytes) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: `configJson exceeds ${XRAY_LIMITS.maxConfigJsonBytes} bytes`,
    });
    return;
  }
  try {
    const parsed = JSON.parse(value);
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "configJson must encode a JSON object" });
    }
  } catch {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "configJson must be valid JSON" });
  }
});

export const XrayDesiredStateSchema = z.object({
  schemaVersion: schemaVersionSchema,
  generation: nonNegativeIntegerSchema,
  issuedAt: timestampSchema,
  targetVersion: versionSchema,
  configHash: sha256Schema,
  configEncoding: z.literal("JSON_UTF8"),
  configJson: configJsonSchema,
  expectedListeners: z.array(XrayExpectedListenerSchema).max(XRAY_LIMITS.maxExpectedListeners),
});

export const XrayManagedServiceKindCapabilitySchema = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("MTPROTO_FAKE_TLS"),
    supervisor: z.literal("AGENT_CHILD"),
    supportsArtifactInstall: z.literal(true),
    runsAsDedicatedUser: z.literal(true),
    network: z.literal("tcp"),
  }).strict(),
  z.object({
    kind: z.literal("AMNEZIAWG"),
    supervisor: z.literal("AGENT_CHILD"),
    supportsArtifactInstall: z.literal(false),
    runsAsDedicatedUser: z.literal(true),
    network: z.literal("udp"),
  }).strict(),
]);

export const XrayManagedServicesCapabilitySchema = withRawChecks(z.object({
  schemaVersion: schemaVersionSchema,
  supportedKinds: z.array(z.literal("MTPROTO_FAKE_TLS")).max(8)
    .refine((kinds) => new Set(kinds).size === kinds.length, "supportedKinds must be unique"),
  kindCapabilities: z.array(XrayManagedServiceKindCapabilitySchema).max(8)
    .refine((items) => new Set(items.map((item) => item.kind)).size === items.length, "kindCapabilities must be unique")
    .optional(),
  supervisor: z.literal("AGENT_CHILD"),
  supportsArtifactInstall: z.boolean(),
  runsAsDedicatedUser: z.boolean(),
  supportedOS: z.string().min(1).max(32),
  supportedArch: z.string().min(1).max(32),
  errorCode: errorCodeSchema.optional(),
}).superRefine((capability, ctx) => {
  if (capability.supportedKinds.length > 0) {
    if (capability.supportedOS !== "linux" || !["amd64", "arm64"].includes(capability.supportedArch)
      || !capability.supportsArtifactInstall || !capability.runsAsDedicatedUser) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "supported managed services require the approved platform and isolation" });
    }
  }
}), { maxJsonBytes: XRAY_LIMITS.maxControlPayloadBytes });

export const XrayManagedServiceArtifactSchema = z.object({
  artifactId: positiveIntegerSchema,
  packageFormat: z.literal("tar.gz"),
  sha256: sha256Schema,
  fileSize: positiveIntegerSchema.max(XRAY_MANAGED_SERVICE_LIMITS.maxArtifactBytes),
}).strict();

export const XrayMtprotoAccountDesiredSchema = z.object({
  accountTag: z.string().regex(mtprotoAccountTagPattern),
  secret: z.string().regex(mtprotoSecretPattern).max(540),
}).strict();

export const XrayMtprotoServiceDesiredSchema = z.object({
  kind: z.literal("MTPROTO_FAKE_TLS"),
  serviceId: positiveIntegerSchema,
  serviceTag: z.string().regex(mtprotoServiceTagPattern),
  targetVersion: z.literal("v1.15.0"),
  artifact: XrayManagedServiceArtifactSchema,
  listenAddress: z.literal("0.0.0.0"),
  listenPort: portSchema,
  fakeTlsDomain: z.string().regex(mtprotoDomainPattern),
  accounts: z.array(XrayMtprotoAccountDesiredSchema).min(1).max(XRAY_MANAGED_SERVICE_LIMITS.maxAccountsPerService),
}).strict().superRefine((service, ctx) => {
  const tags = service.accounts.map((account) => account.accountTag);
  if (new Set(tags).size !== tags.length) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["accounts"], message: "accountTag must be unique" });
  }
  const expectedDomainHex = utf8Hex(service.fakeTlsDomain);
  service.accounts.forEach((account, index) => {
    if (account.secret.length !== 2 + 32 + expectedDomainHex.length || !account.secret.endsWith(expectedDomainHex)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["accounts", index, "secret"], message: "secret host must match fakeTlsDomain" });
    }
  });
});

function parsedUnsignedRange(value: string): readonly [number, number] | null {
  if (!unsignedRangePattern.test(value)) return null;
  const [lowerText, upperText = lowerText] = value.split("-", 2);
  const lower = Number(lowerText);
  const upper = Number(upperText);
  return Number.isSafeInteger(lower) && Number.isSafeInteger(upper) && lower <= upper
    ? [lower, upper] as const
    : null;
}

const amneziawgRangeSchema = (maximum: number, minimum = 0) => z.string().max(32).superRefine((value, ctx) => {
  const parsed = parsedUnsignedRange(value);
  if (!parsed || parsed[0] < minimum || parsed[1] > maximum) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: `range must be within ${minimum}..${maximum}` });
  }
});

export const XrayAmneziawgObfuscationSchema = z.object({
  jc: z.number().int().min(1).max(128),
  jmin: z.number().int().min(0).max(1280),
  jmax: z.number().int().min(0).max(1280),
  s1: z.number().int().min(12).max(1024),
  s2: z.number().int().min(12).max(1024),
  s3: z.number().int().min(12).max(64),
  s4: z.number().int().min(12).max(32),
  h1: amneziawgRangeSchema(4_294_967_295, 5),
  h2: amneziawgRangeSchema(4_294_967_295, 5),
  h3: amneziawgRangeSchema(4_294_967_295, 5),
  h4: amneziawgRangeSchema(4_294_967_295, 5),
  i1: z.string().regex(amneziawgI1Pattern),
  headerProtectionKey: amneziawgNonZeroKeySchema,
  contentPaddingAddition: amneziawgRangeSchema(64),
  rekeyAfterTime: amneziawgRangeSchema(86_400, 1),
  rekeyTimeout: amneziawgRangeSchema(300, 1),
  rejectAfterTime: amneziawgRangeSchema(86_400, 1),
  keepaliveTimeout: amneziawgRangeSchema(300, 1),
  maxHandshakeAttempts: amneziawgRangeSchema(1_000, 1),
  randomTrailers: z.literal(true),
  disableCookies: z.literal(true),
}).strict().superRefine((obfuscation, ctx) => {
  if (obfuscation.jmin > obfuscation.jmax) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["jmax"], message: "jmax must not be less than jmin" });
  }
  if (obfuscation.s1 + 56 === obfuscation.s2) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["s2"], message: "s1 + 56 must not equal s2" });
  }
  const ranges = [obfuscation.h1, obfuscation.h2, obfuscation.h3, obfuscation.h4]
    .map(parsedUnsignedRange)
    .filter((range): range is readonly [number, number] => range !== null)
    .sort((left, right) => left[0] - right[0]);
  if (ranges.length === 4 && ranges.some((range, index) => index > 0 && range[0] <= ranges[index - 1][1])) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["h1"], message: "h1-h4 ranges must not overlap" });
  }
});

export const XrayAmneziawgPeerDesiredSchema = z.object({
  accountTag: z.string().regex(amneziawgAccountTagPattern),
  address: z.string().regex(amneziawgPeerAddressPattern),
  publicKey: amneziawgNonZeroKeySchema,
  preSharedKey: amneziawgNonZeroKeySchema,
}).strict();

export const XrayAmneziawgServiceDesiredSchema = z.object({
  kind: z.literal("AMNEZIAWG"),
  serviceId: positiveIntegerSchema,
  serviceTag: z.string().regex(amneziawgServiceTagPattern),
  targetVersion: z.literal("v3.1.20260814"),
  listenAddress: z.literal("0.0.0.0"),
  listenPort: portSchema,
  publicAddress: managedServicePublicAddressSchema,
  subnet: z.literal("10.8.1.0/24"),
  mtu: z.literal(1420),
  dns: z.tuple([z.literal("1.1.1.1"), z.literal("1.0.0.1")]),
  serverPrivateKey: amneziawgPrivateKeySchema,
  obfuscation: XrayAmneziawgObfuscationSchema,
  peers: z.array(XrayAmneziawgPeerDesiredSchema).min(1).max(32),
}).strict().superRefine((service, ctx) => {
  const tags = service.peers.map((peer) => peer.accountTag);
  const addresses = service.peers.map((peer) => peer.address);
  const publicKeys = service.peers.map((peer) => peer.publicKey);
  const preSharedKeys = service.peers.map((peer) => peer.preSharedKey);
  if (new Set(tags).size !== tags.length) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["peers"], message: "accountTag must be unique" });
  if (new Set(addresses).size !== addresses.length) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["peers"], message: "peer address must be unique" });
  if (new Set(publicKeys).size !== publicKeys.length) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["peers"], message: "peer public key must be unique" });
  if (new Set(preSharedKeys).size !== preSharedKeys.length) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["peers"], message: "peer pre-shared key must be unique" });
});

export const XrayManagedServiceDesiredSchema = z.union([
  XrayMtprotoServiceDesiredSchema,
  XrayAmneziawgServiceDesiredSchema,
]);

export const XrayManagedServiceDesiredServicesSchema = z.array(XrayManagedServiceDesiredSchema)
  .max(XRAY_MANAGED_SERVICE_LIMITS.maxServices);

export const XrayManagedServicesDesiredStateSchema = z.object({
  schemaVersion: schemaVersionSchema,
  generation: nonNegativeIntegerSchema,
  issuedAt: timestampSchema,
  configHash: sha256Schema,
  services: XrayManagedServiceDesiredServicesSchema,
}).strict().superRefine((desired, ctx) => {
  const size = jsonUtf8Size(desired);
  if (size === null || size > XRAY_LIMITS.maxControlPayloadBytes) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: `JSON payload exceeds ${XRAY_LIMITS.maxControlPayloadBytes} bytes` });
  }
  const ids = desired.services.map((service) => service.serviceId);
  const tags = desired.services.map((service) => service.serviceTag);
  const accountTags = desired.services.flatMap((service) => service.kind === "MTPROTO_FAKE_TLS"
    ? service.accounts.map((account) => account.accountTag)
    : service.peers.map((peer) => peer.accountTag));
  const ports = desired.services.map((service) => service.listenPort);
  if (new Set(ids).size !== ids.length) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["services"], message: "serviceId must be unique" });
  if (new Set(tags).size !== tags.length) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["services"], message: "serviceTag must be unique" });
  if (new Set(accountTags).size !== accountTags.length) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["services"], message: "accountTag must be globally unique" });
  if (new Set(ports).size !== ports.length) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["services"], message: "listenPort must be unique" });
});

const xrayManagedServiceObservedRuntime = {
  installedVersion: versionSchema.nullable(),
  runningVersion: versionSchema.nullable(),
  serviceStatus: z.enum(XRAY_SERVICE_STATUSES),
  processId: positiveIntegerSchema.nullable(),
  binarySha256: sha256Schema.nullable(),
};

export const XrayMtprotoServiceObservedSchema = z.object({
  kind: z.literal("MTPROTO_FAKE_TLS"),
  serviceId: positiveIntegerSchema,
  serviceTag: z.string().regex(mtprotoServiceTagPattern),
  ...xrayManagedServiceObservedRuntime,
  listener: z.object({
    network: z.literal("tcp"),
    listenAddress: z.literal("0.0.0.0"),
    port: portSchema,
    status: z.enum(XRAY_LISTENER_STATUSES),
    errorCode: errorCodeSchema.nullable(),
  }).strict(),
  errorCode: errorCodeSchema.nullable(),
}).strict();

export const XrayAmneziawgServiceObservedSchema = z.object({
  kind: z.literal("AMNEZIAWG"),
  serviceId: positiveIntegerSchema,
  serviceTag: z.string().regex(amneziawgServiceTagPattern),
  ...xrayManagedServiceObservedRuntime,
  listener: z.object({
    network: z.literal("udp"),
    listenAddress: z.literal("0.0.0.0"),
    port: portSchema,
    status: z.enum(XRAY_LISTENER_STATUSES),
    errorCode: errorCodeSchema.nullable(),
  }).strict(),
  errorCode: errorCodeSchema.nullable(),
}).strict();

export const XrayManagedServiceObservedSchema = z.union([
  XrayMtprotoServiceObservedSchema,
  XrayAmneziawgServiceObservedSchema,
]);

export const XrayManagedServicesObservedStateSchema = withRawChecks(z.object({
  schemaVersion: schemaVersionSchema,
  appliedGeneration: nonNegativeIntegerSchema,
  appliedConfigHash: sha256Schema.nullable(),
  services: z.array(XrayManagedServiceObservedSchema).max(XRAY_MANAGED_SERVICE_LIMITS.maxServices),
  observedAt: timestampSchema,
}).strict(), {
  forbiddenKeys: new Set([
    ...observedForbiddenKeys,
    "secret",
    "presharedkey",
    "headerprotectionkey",
    "obfuscation",
    "faketlsdomain",
    "configtoml",
    "config",
    "vpnuri",
    "path",
    "argv",
    "environment",
  ]),
  maxJsonBytes: XRAY_LIMITS.maxControlPayloadBytes,
});

export const XrayManagedServicesObservedReportSchema = z.object({
  managedServicesStateSignature: sha256Schema,
  managedServicesState: XrayManagedServicesObservedStateSchema.optional(),
}).strict();

export const XrayObservedListenerSchema = z.object({
  runtimeTag: identifierSchema,
  network: listenerNetworkSchema,
  port: portSchema,
  status: z.enum(XRAY_LISTENER_STATUSES),
  errorCode: errorCodeSchema.nullish(),
});

export const XrayObservedErrorSchema = z.object({
  code: errorCodeSchema,
  message: errorMessageSchema,
  generation: nonNegativeIntegerSchema,
  occurredAt: timestampSchema,
});

const observedStateObjectSchema = z.object({
  schemaVersion: schemaVersionSchema,
  isInstalled: z.boolean(),
  installedVersion: versionSchema.nullable(),
  runningVersion: versionSchema.nullable(),
  serviceStatus: z.enum(XRAY_SERVICE_STATUSES),
  processId: positiveIntegerSchema.nullable(),
  binarySha256: sha256Schema.nullable(),
  appliedGeneration: nonNegativeIntegerSchema,
  appliedConfigHash: sha256Schema.nullable(),
  listeners: z.array(XrayObservedListenerSchema).max(XRAY_LIMITS.maxExpectedListeners),
  lastError: XrayObservedErrorSchema.nullable(),
  observedAt: timestampSchema,
});

export const XrayObservedStateSchema = withRawChecks(observedStateObjectSchema, {
  forbiddenKeys: observedForbiddenKeys,
  maxJsonBytes: XRAY_LIMITS.maxControlPayloadBytes,
});

const observedReportObjectSchema = z.object({
  xrayStateSignature: sha256Schema,
  xrayState: XrayObservedStateSchema.optional(),
});

export const XrayObservedReportSchema = withRawChecks(observedReportObjectSchema, {
  forbiddenKeys: observedForbiddenKeys,
  maxJsonBytes: XRAY_LIMITS.maxControlPayloadBytes,
});

export const XrayPortProbePayloadSchema = z.object({
  network: listenerNetworkSchema,
  listenAddress: z.literal("0.0.0.0"),
  ports: z.array(portSchema)
    .min(1)
    .max(XRAY_LIMITS.maxPortProbeCandidates)
    .refine((ports) => new Set(ports).size === ports.length, "ports must be unique"),
}).superRefine((payload, ctx) => {
  if (payload.network === "udp" && payload.ports.length !== 1) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "UDP port probes must contain exactly one port",
      path: ["ports"],
    });
  }
});

const realityTargetSchema = z.string().min(1).max(260)
  .regex(realityTargetPattern)
  .refine((target) => {
    const port = Number(target.slice(target.lastIndexOf(":") + 1));
    return port >= 1 && port <= 65535;
  }, "target port must be between 1 and 65535");

export const XrayRealityScanPayloadSchema = z.object({
  targets: z.array(realityTargetSchema).min(1).max(XRAY_LIMITS.maxRealityTargets),
  timeoutMs: z.number().int().positive().max(XRAY_LIMITS.maxRealityTimeoutMs),
  maxConcurrency: z.number().int().positive().max(XRAY_LIMITS.maxRealityConcurrency),
});

export const XrayArtifactTaskPayloadSchema = z.object({
  artifactId: positiveIntegerSchema,
  version: versionSchema,
  os: z.literal("linux"),
  arch: z.enum(["amd64", "arm64"]),
  size: positiveIntegerSchema,
  sha256: sha256Schema,
  downloadPath: z.string().regex(/^\/api\/agent\/artifacts\/xray\/[1-9][0-9]*$/),
}).superRefine((payload, ctx) => {
  if (payload.downloadPath !== `/api/agent/artifacts/xray/${payload.artifactId}`) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "downloadPath must match artifactId",
      path: ["downloadPath"],
    });
  }
});

export const XrayRestartPayloadSchema = z.object({
  reason: z.literal("ADMIN_REQUEST"),
});

const portProbeTaskSchema = z.object({
  schemaVersion: schemaVersionSchema,
  taskId: identifierSchema,
  type: z.literal("PORT_PROBE"),
  createdAt: timestampSchema,
  expiresAt: timestampSchema,
  payload: XrayPortProbePayloadSchema,
});

const realityScanTaskSchema = z.object({
  schemaVersion: schemaVersionSchema,
  taskId: identifierSchema,
  type: z.literal("REALITY_SCAN"),
  createdAt: timestampSchema,
  expiresAt: timestampSchema,
  payload: XrayRealityScanPayloadSchema,
});

const installTaskSchema = z.object({
  schemaVersion: schemaVersionSchema,
  taskId: identifierSchema,
  type: z.literal("INSTALL"),
  createdAt: timestampSchema,
  expiresAt: timestampSchema,
  payload: XrayArtifactTaskPayloadSchema,
});

const upgradeTaskSchema = z.object({
  schemaVersion: schemaVersionSchema,
  taskId: identifierSchema,
  type: z.literal("UPGRADE"),
  createdAt: timestampSchema,
  expiresAt: timestampSchema,
  payload: XrayArtifactTaskPayloadSchema,
});

const restartTaskSchema = z.object({
  schemaVersion: schemaVersionSchema,
  taskId: identifierSchema,
  type: z.literal("RESTART"),
  createdAt: timestampSchema,
  expiresAt: timestampSchema,
  payload: XrayRestartPayloadSchema,
});

const taskUnionSchema = z.discriminatedUnion("type", [
  portProbeTaskSchema,
  realityScanTaskSchema,
  installTaskSchema,
  upgradeTaskSchema,
  restartTaskSchema,
]).superRefine((task, ctx) => {
  if (Date.parse(task.expiresAt) <= Date.parse(task.createdAt)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "expiresAt must be later than createdAt",
      path: ["expiresAt"],
    });
  }
});

export const XrayTaskSchema = withRawChecks(taskUnionSchema, {
  forbiddenKeys: taskForbiddenKeys,
  maxJsonBytes: XRAY_LIMITS.maxControlPayloadBytes,
});

export const XrayTaskErrorSchema = z.object({
  code: errorCodeSchema,
  message: errorMessageSchema,
  retryable: z.boolean(),
});

const portProbeResultItemSchema = z.object({
    port: portSchema,
    available: z.boolean(),
    errorCode: errorCodeSchema.nullable(),
}).superRefine((result, ctx) => {
  if (result.available === (result.errorCode !== null)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: result.available
        ? "available port must not include an error code"
        : "unavailable port must include an error code",
      path: ["errorCode"],
    });
  }
});

export const XrayPortProbeResultSchema = z.object({
  ports: z.array(portProbeResultItemSchema).min(1).max(XRAY_LIMITS.maxPortProbeCandidates),
  observedAt: timestampSchema,
});

export const XrayRealityScanItemSchema = z.object({
  target: realityTargetSchema,
  host: z.string().min(1).max(253),
  resolvedIp: z.string().min(1).max(64),
  port: z.number().int().min(1).max(65535),
  feasible: z.boolean(),
  tls13: z.boolean(),
  h2: z.boolean(),
  x25519: z.boolean(),
  certificateValid: z.boolean(),
  serverNames: z.array(z.string().min(1).max(253)).max(16),
  latencyMs: z.number().int().min(0).max(60_000),
  reasonCode: errorCodeSchema.nullable(),
  reasonMessage: errorMessageSchema.optional(),
});

export const XrayRealityScanResultSchema = z.object({
  results: z.array(XrayRealityScanItemSchema).max(XRAY_LIMITS.maxRealityTargets),
  observedAt: timestampSchema,
});

export const XrayInstallResultSchema = z.object({
  installedVersion: versionSchema,
  binarySha256: sha256Schema,
  reused: z.boolean(),
});

export const XrayUpgradeResultSchema = z.object({
  previousVersion: versionSchema.nullable(),
  installedVersion: versionSchema,
  binarySha256: sha256Schema,
  rolledBack: z.boolean(),
});

export const XrayRestartResultSchema = z.object({
  previousVersion: versionSchema.nullable(),
  runningVersion: versionSchema.nullable(),
  serviceStatus: z.enum(XRAY_SERVICE_STATUSES),
  readyListenerCount: nonNegativeIntegerSchema,
});

const taskResultBaseShape = {
  schemaVersion: schemaVersionSchema,
  taskId: identifierSchema,
  status: z.enum(XRAY_TASK_RESULT_STATUSES),
  startedAt: timestampSchema,
  finishedAt: timestampSchema,
  error: XrayTaskErrorSchema.nullable().optional(),
};

const taskResultUnionSchema = z.discriminatedUnion("type", [
  z.object({ ...taskResultBaseShape, type: z.literal("PORT_PROBE"), result: XrayPortProbeResultSchema.nullable().optional() }),
  z.object({ ...taskResultBaseShape, type: z.literal("REALITY_SCAN"), result: XrayRealityScanResultSchema.nullable().optional() }),
  z.object({ ...taskResultBaseShape, type: z.literal("INSTALL"), result: XrayInstallResultSchema.nullable().optional() }),
  z.object({ ...taskResultBaseShape, type: z.literal("UPGRADE"), result: XrayUpgradeResultSchema.nullable().optional() }),
  z.object({ ...taskResultBaseShape, type: z.literal("RESTART"), result: XrayRestartResultSchema.nullable().optional() }),
]).superRefine((taskResult, ctx) => {
  if (Date.parse(taskResult.finishedAt) < Date.parse(taskResult.startedAt)) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "finishedAt must not be earlier than startedAt",
      path: ["finishedAt"],
    });
  }
  if (taskResult.status === "SUCCESS") {
    if (taskResult.result == null) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "successful task result is required", path: ["result"] });
    }
    if (taskResult.error != null) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "successful task must not include an error", path: ["error"] });
    }
  } else if (taskResult.error == null) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "failed task error is required", path: ["error"] });
  }
});

export const XrayTaskResultSchema = withRawChecks(taskResultUnionSchema, {
  forbiddenKeys: observedForbiddenKeys,
  maxJsonBytes: XRAY_LIMITS.maxTaskResultBytes,
});

export type XrayCapability = z.infer<typeof XrayCapabilitySchema>;
export type XrayExpectedListener = z.infer<typeof XrayExpectedListenerSchema>;
export type XrayDesiredState = z.infer<typeof XrayDesiredStateSchema>;
export type XrayManagedServiceKindCapability = z.infer<typeof XrayManagedServiceKindCapabilitySchema>;
export type XrayManagedServicesCapability = z.infer<typeof XrayManagedServicesCapabilitySchema>;
export type XrayManagedServicesDesiredState = z.infer<typeof XrayManagedServicesDesiredStateSchema>;
export type XrayManagedServicesObservedState = z.infer<typeof XrayManagedServicesObservedStateSchema>;
export type XrayManagedServiceDesired = z.infer<typeof XrayManagedServiceDesiredSchema>;
export type XrayManagedServiceObserved = z.infer<typeof XrayManagedServiceObservedSchema>;
export type XrayObservedListener = z.infer<typeof XrayObservedListenerSchema>;
export type XrayObservedError = z.infer<typeof XrayObservedErrorSchema>;
export type XrayObservedState = z.infer<typeof XrayObservedStateSchema>;
export type XrayObservedReport = z.infer<typeof XrayObservedReportSchema>;
export type XrayTask = z.infer<typeof XrayTaskSchema>;
export type XrayTaskError = z.infer<typeof XrayTaskErrorSchema>;
export type XrayTaskResult = z.infer<typeof XrayTaskResultSchema>;
export type XrayAgentErrorCode = (typeof XRAY_AGENT_ERROR_CODES)[number];
export type XrayTaskType = (typeof XRAY_TASK_TYPES)[number];
export type XrayTaskResultStatus = (typeof XRAY_TASK_RESULT_STATUSES)[number];
export type XrayServiceStatus = (typeof XRAY_SERVICE_STATUSES)[number];
export type XrayListenerStatus = (typeof XRAY_LISTENER_STATUSES)[number];
