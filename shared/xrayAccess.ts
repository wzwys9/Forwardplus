import { z } from "zod";

export const XRAY_ACCESS_SETTINGS_MAX_BYTES = 4 * 1024;
export const XRAY_ACCESS_SECRET_MAX_BYTES = 4 * 1024;

export const XRAY_ACCESS_CREDENTIAL_TYPES = [
  "UUID_AND_SHORT_ID",
  "UUID",
  "PASSWORD",
  "SHADOWSOCKS_KEY",
  "HYSTERIA_AUTH",
  "WIREGUARD_PEER",
  "HTTP_BASIC",
  "MIXED_USER_PASSWORD",
] as const;
export type XrayAccessCredentialType = (typeof XRAY_ACCESS_CREDENTIAL_TYPES)[number];

export const XRAY_ACCESS_SECRET_KINDS = [
  "UUID",
  "SHORT_ID",
  "USERNAME",
  "PASSWORD",
  "SHADOWSOCKS_KEY",
  "HYSTERIA_AUTH",
  "PRIVATE_KEY",
  "PRE_SHARED_KEY",
] as const;
export type XrayAccessSecretKind = (typeof XRAY_ACCESS_SECRET_KINDS)[number];

export const XRAY_INBOUND_SECRET_KINDS = [
  "REALITY_PRIVATE_KEY",
  "TLS_PRIVATE_KEY",
  "SHADOWSOCKS_SERVER_KEY",
  "PRIVATE_KEY",
  "PRE_SHARED_KEY",
] as const;
export type XrayInboundSecretKind = (typeof XRAY_INBOUND_SECRET_KINDS)[number];

export type XrayAccessSettings =
  | { credentialType: "UUID_AND_SHORT_ID"; schemaVersion: 1; flow: "XTLS_RPRX_VISION" | "NONE" }
  | { credentialType: "UUID"; schemaVersion: 1; flow: "NONE"; security: "AUTO" }
  | { credentialType: "UUID"; schemaVersion: 2; protocol: "VLESS"; encryption: "NONE"; flow: "XTLS_RPRX_VISION" | "NONE" }
  | { credentialType: "PASSWORD"; schemaVersion: 1 }
  | { credentialType: "SHADOWSOCKS_KEY"; schemaVersion: 1 }
  | { credentialType: "HYSTERIA_AUTH"; schemaVersion: 1 }
  | { credentialType: "WIREGUARD_PEER"; schemaVersion: 1 }
  | { credentialType: "WIREGUARD_PEER"; schemaVersion: 2; address: string }
  | { credentialType: "HTTP_BASIC"; schemaVersion: 1 }
  | { credentialType: "MIXED_USER_PASSWORD"; schemaVersion: 1 };

export type XrayAccessSecretPolicy = Readonly<{
  required: readonly XrayAccessSecretKind[];
  optional: readonly XrayAccessSecretKind[];
}>;

const credentialTypeSchema = z.enum(XRAY_ACCESS_CREDENTIAL_TYPES);
const accessSecretKindSchema = z.enum(XRAY_ACCESS_SECRET_KINDS);
const inboundSecretKindSchema = z.enum(XRAY_INBOUND_SECRET_KINDS);
const textEncoder = new TextEncoder();

const accessSettingsSchemas: Record<XrayAccessCredentialType, z.ZodTypeAny> = {
  UUID_AND_SHORT_ID: z.object({
    schemaVersion: z.literal(1),
    flow: z.enum(["XTLS_RPRX_VISION", "NONE"]),
  }).strict(),
  UUID: z.discriminatedUnion("schemaVersion", [
    z.object({
      schemaVersion: z.literal(1),
      flow: z.literal("NONE"),
      security: z.literal("AUTO"),
    }).strict(),
    z.object({
      schemaVersion: z.literal(2),
      protocol: z.literal("VLESS"),
      encryption: z.literal("NONE"),
      flow: z.enum(["XTLS_RPRX_VISION", "NONE"]),
    }).strict(),
  ]),
  PASSWORD: z.object({ schemaVersion: z.literal(1) }).strict(),
  SHADOWSOCKS_KEY: z.object({ schemaVersion: z.literal(1) }).strict(),
  HYSTERIA_AUTH: z.object({ schemaVersion: z.literal(1) }).strict(),
  HTTP_BASIC: z.object({ schemaVersion: z.literal(1) }).strict(),
  MIXED_USER_PASSWORD: z.object({ schemaVersion: z.literal(1) }).strict(),
  WIREGUARD_PEER: z.discriminatedUnion("schemaVersion", [
    z.object({ schemaVersion: z.literal(1) }).strict(),
    z.object({
      schemaVersion: z.literal(2),
      address: z.string().regex(/^10\.0\.0\.(?:[2-9]|[1-9]\d|1\d{2}|2[0-4]\d|25[0-4])\/32$/),
    }).strict(),
  ]),
};

const accessSecretPolicies: Record<XrayAccessCredentialType, XrayAccessSecretPolicy> = {
  UUID_AND_SHORT_ID: { required: ["UUID", "SHORT_ID"], optional: [] },
  UUID: { required: ["UUID"], optional: [] },
  PASSWORD: { required: ["PASSWORD"], optional: ["SHORT_ID"] },
  SHADOWSOCKS_KEY: { required: ["SHADOWSOCKS_KEY"], optional: [] },
  HYSTERIA_AUTH: { required: ["HYSTERIA_AUTH"], optional: [] },
  WIREGUARD_PEER: { required: ["PRIVATE_KEY", "PRE_SHARED_KEY"], optional: [] },
  HTTP_BASIC: { required: ["USERNAME", "PASSWORD"], optional: [] },
  MIXED_USER_PASSWORD: { required: ["USERNAME", "PASSWORD"], optional: [] },
};

export function isXrayAccessSecretKind(value: unknown): value is XrayAccessSecretKind {
  return accessSecretKindSchema.safeParse(value).success;
}

export function isXrayInboundSecretKind(value: unknown): value is XrayInboundSecretKind {
  return inboundSecretKindSchema.safeParse(value).success;
}

export function parseStoredXrayAccessSettings(input: {
  credentialType?: unknown;
  settingsJson?: unknown;
}): XrayAccessSettings | null {
  const credentialType = credentialTypeSchema.safeParse(input?.credentialType);
  if (!credentialType.success || typeof input?.settingsJson !== "string") return null;
  if (textEncoder.encode(input.settingsJson).byteLength > XRAY_ACCESS_SETTINGS_MAX_BYTES) return null;

  try {
    const parsed = accessSettingsSchemas[credentialType.data].safeParse(JSON.parse(input.settingsJson));
    if (!parsed.success) return null;
    return { credentialType: credentialType.data, ...parsed.data } as XrayAccessSettings;
  } catch {
    return null;
  }
}

export function accessSecretPolicyForCredentialType(value: unknown): XrayAccessSecretPolicy | null {
  const credentialType = credentialTypeSchema.safeParse(value);
  if (!credentialType.success) return null;
  const policy = accessSecretPolicies[credentialType.data];
  return { required: [...policy.required], optional: [...policy.optional] };
}
