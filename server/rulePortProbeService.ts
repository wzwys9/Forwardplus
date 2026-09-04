import crypto from "node:crypto";
import { z } from "zod";

import { ENV } from "./env";
import {
  cancelXrayPortProbeOperation,
  createXrayPortProbeOperation,
  getXrayPortProbeOperationResult,
  releaseXrayPortProbeReservations,
  validateXrayPortReservation,
  XrayPortOperationError,
} from "./xrayPortOperations";

const TOKEN_CONTEXT = "forwardx-rule-port-check-token:v1";
const TOKEN_TTL_MS = 90_000;
const MAX_TOKEN_BYTES = 16_384;
const TOKEN_PART = /^[A-Za-z0-9_-]+$/;

const probeSchema = z.object({
  hostId: z.number().int().positive(),
  network: z.enum(["tcp", "udp"]),
  operationId: z.string().uuid(),
}).strict();

const tokenPayloadSchema = z.object({
  v: z.literal(1),
  kind: z.literal("RULE_PORT_CHECK"),
  nonce: z.string().regex(/^[A-Za-z0-9_-]{22}$/),
  userId: z.number().int().positive(),
  sourcePort: z.number().int().min(1_000).max(65_535),
  protocol: z.enum(["tcp", "udp", "both"]),
  probes: z.array(probeSchema).min(1).max(128),
  issuedAt: z.number().int().nonnegative(),
  expiresAt: z.number().int().positive(),
}).strict().superRefine((value, ctx) => {
  if (value.expiresAt - value.issuedAt !== TOKEN_TTL_MS) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "invalid token lifetime" });
  }
  const expectedNetworks = value.protocol === "both" ? ["tcp", "udp"] : [value.protocol];
  const scopes = new Set<string>();
  for (const probe of value.probes) {
    if (!expectedNetworks.includes(probe.network)) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "unexpected probe network" });
    }
    const scope = `${probe.hostId}:${probe.network}`;
    if (scopes.has(scope)) ctx.addIssue({ code: z.ZodIssueCode.custom, message: "duplicate probe scope" });
    scopes.add(scope);
  }
  const hostIds = new Set(value.probes.map((probe) => probe.hostId));
  for (const hostId of hostIds) {
    for (const network of expectedNetworks) {
      if (!scopes.has(`${hostId}:${network}`)) {
        ctx.addIssue({ code: z.ZodIssueCode.custom, message: "incomplete probe scope" });
      }
    }
  }
});

type RulePortCheckPayload = z.infer<typeof tokenPayloadSchema>;
type ProbeNetwork = "tcp" | "udp";

export type RulePortProbeResult =
  | Readonly<{ status: "RUNNING"; completed: number; total: number }>
  | Readonly<{ status: "AVAILABLE"; checkedAt: string }>
  | Readonly<{ status: "USED"; reasonCode: "PORT_IN_USE"; reason: string }>
  | Readonly<{ status: "FAILED"; reasonCode: string; reason: string }>
  | Readonly<{ status: "EXPIRED"; reasonCode: "PORT_CHECK_EXPIRED"; reason: string }>;

export class RulePortCheckError extends Error {
  constructor(readonly code: "PORT_CHECK_INVALID" | "PORT_CHECK_EXPIRED") {
    super(code === "PORT_CHECK_EXPIRED" ? "端口检查已过期，请重新检测" : "端口检查凭证无效");
    this.name = "RulePortCheckError";
  }
}

function tokenKey() {
  if (typeof ENV.cookieSecret !== "string" || Buffer.byteLength(ENV.cookieSecret, "utf8") < 16) {
    throw new RulePortCheckError("PORT_CHECK_INVALID");
  }
  return crypto.createHmac("sha256", ENV.cookieSecret).update(TOKEN_CONTEXT, "utf8").digest();
}

function signToken(payload: RulePortCheckPayload) {
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const unsigned = `rpc1.${body}`;
  const signature = crypto.createHmac("sha256", tokenKey()).update(unsigned, "utf8").digest("base64url");
  const token = `${unsigned}.${signature}`;
  if (Buffer.byteLength(token, "utf8") > MAX_TOKEN_BYTES) throw new RulePortCheckError("PORT_CHECK_INVALID");
  return token;
}

function parseToken(raw: unknown, userId: number, options: { allowExpired?: boolean } = {}) {
  if (typeof raw !== "string" || Buffer.byteLength(raw, "utf8") > MAX_TOKEN_BYTES) {
    throw new RulePortCheckError("PORT_CHECK_INVALID");
  }
  const parts = raw.split(".");
  if (parts.length !== 3 || parts[0] !== "rpc1" || !TOKEN_PART.test(parts[1]) || !TOKEN_PART.test(parts[2])) {
    throw new RulePortCheckError("PORT_CHECK_INVALID");
  }
  const unsigned = `${parts[0]}.${parts[1]}`;
  const expected = crypto.createHmac("sha256", tokenKey()).update(unsigned, "utf8").digest();
  const actual = Buffer.from(parts[2], "base64url");
  if (actual.toString("base64url") !== parts[2]
    || actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
    throw new RulePortCheckError("PORT_CHECK_INVALID");
  }
  let decoded: unknown;
  try {
    const body = Buffer.from(parts[1], "base64url");
    if (body.toString("base64url") !== parts[1]) throw new Error("non-canonical token");
    decoded = JSON.parse(body.toString("utf8"));
  } catch {
    throw new RulePortCheckError("PORT_CHECK_INVALID");
  }
  const parsed = tokenPayloadSchema.safeParse(decoded);
  if (!parsed.success || parsed.data.userId !== userId || parsed.data.issuedAt > Date.now() + 30_000) {
    throw new RulePortCheckError("PORT_CHECK_INVALID");
  }
  if (!options.allowExpired && parsed.data.expiresAt <= Date.now()) {
    throw new RulePortCheckError("PORT_CHECK_EXPIRED");
  }
  return parsed.data;
}

function normalizedIds(values: readonly number[]) {
  const ids = Array.from(new Set(values.map(Number))).sort((left, right) => left - right);
  if (ids.length < 1 || ids.length > 64 || ids.some((id) => !Number.isSafeInteger(id) || id <= 0)) {
    throw new RulePortCheckError("PORT_CHECK_INVALID");
  }
  return ids;
}

function networksForProtocol(protocol: "tcp" | "udp" | "both"): ProbeNetwork[] {
  return protocol === "both" ? ["tcp", "udp"] : [protocol];
}

export async function discardRulePortCheck(portCheckId: unknown, userId: number) {
  const payload = parseToken(portCheckId, userId, { allowExpired: true });
  await Promise.all(payload.probes.map((probe) => cancelXrayPortProbeOperation(probe.operationId, userId)));
}

export async function createRulePortCheck(input: {
  userId: number;
  hostIds: readonly number[];
  sourcePort: number;
  protocol: "tcp" | "udp" | "both";
  replacePortCheckId?: string;
}) {
  const hostIds = normalizedIds(input.hostIds);
  if (!Number.isSafeInteger(input.sourcePort) || input.sourcePort < 1_000 || input.sourcePort > 65_535) {
    throw new RulePortCheckError("PORT_CHECK_INVALID");
  }
  if (input.replacePortCheckId) await discardRulePortCheck(input.replacePortCheckId, input.userId);

  const requested = hostIds.flatMap((hostId) => networksForProtocol(input.protocol).map((network) => ({ hostId, network })));
  const settled = await Promise.allSettled(requested.map(async (probe) => ({
    ...probe,
    ...(await createXrayPortProbeOperation({
      hostId: probe.hostId,
      userId: input.userId,
      mode: "MANUAL",
      manualPort: input.sourcePort,
      network: probe.network,
    })),
  })));
  const probes = settled.flatMap((result) => result.status === "fulfilled" ? [result.value] : []);
  const failed = settled.find((result): result is PromiseRejectedResult => result.status === "rejected");
  if (failed) {
    await Promise.all(probes.map((probe) => cancelXrayPortProbeOperation(probe.operationId, input.userId)));
    throw failed.reason;
  }

  const issuedAt = Date.now();
  const payload = tokenPayloadSchema.parse({
    v: 1,
    kind: "RULE_PORT_CHECK",
    nonce: crypto.randomBytes(16).toString("base64url"),
    userId: input.userId,
    sourcePort: input.sourcePort,
    protocol: input.protocol,
    probes,
    issuedAt,
    expiresAt: issuedAt + TOKEN_TTL_MS,
  });
  return { status: "RUNNING" as const, portCheckId: signToken(payload) };
}

function failedReason(errorCode: string | undefined) {
  if (errorCode === "HOST_OFFLINE") return "入口服务器已离线";
  if (errorCode === "AGENT_CAPABILITY_MISSING" || errorCode === "UDP_CAPABILITY_REQUIRED") {
    return "入口服务器 Agent 不支持所需端口检测";
  }
  if (errorCode === "TASK_EXPIRED") return "入口服务器端口检测超时，请重试";
  return "入口服务器端口检测失败，请重试";
}

export async function getRulePortCheckResult(input: {
  userId: number;
  portCheckId: string;
}): Promise<RulePortProbeResult> {
  let payload: RulePortCheckPayload;
  try {
    payload = parseToken(input.portCheckId, input.userId);
  } catch (error) {
    if (error instanceof RulePortCheckError && error.code === "PORT_CHECK_EXPIRED") {
      await discardRulePortCheck(input.portCheckId, input.userId);
      return { status: "EXPIRED", reasonCode: "PORT_CHECK_EXPIRED", reason: error.message };
    }
    throw error;
  }

  const results = await Promise.all(payload.probes.map((probe) => getXrayPortProbeOperationResult(probe.operationId, input.userId)));
  const terminalCount = results.filter((result) => result.status !== "QUEUED" && result.status !== "RUNNING").length;
  if (terminalCount < results.length) return { status: "RUNNING", completed: terminalCount, total: results.length };

  const failed = results.find((result) => result.status !== "SUCCESS");
  if (failed) {
    await discardRulePortCheck(input.portCheckId, input.userId);
    if (failed.errorCode === "PORT_IN_USE") {
      return { status: "USED", reasonCode: "PORT_IN_USE", reason: "端口已被入口服务器占用" };
    }
    return {
      status: "FAILED",
      reasonCode: failed.errorCode || "PORT_CHECK_FAILED",
      reason: failedReason(failed.errorCode),
    };
  }

  try {
    const reservations = payload.probes.map((probe, index) => {
      const result = results[index];
      if (result.network !== probe.network || result.selectedPort !== payload.sourcePort || !result.reservationId) {
        throw new RulePortCheckError("PORT_CHECK_INVALID");
      }
      return validateXrayPortReservation({
        reservationId: result.reservationId,
        hostId: probe.hostId,
        userId: input.userId,
        port: payload.sourcePort,
        network: probe.network,
      });
    });
    releaseXrayPortProbeReservations({ userId: input.userId, reservations });
  } catch (error) {
    await Promise.all(payload.probes.map((probe) => cancelXrayPortProbeOperation(probe.operationId, input.userId)));
    if (error instanceof XrayPortOperationError && error.code === "PORT_RESERVATION_EXPIRED") {
      return { status: "EXPIRED", reasonCode: "PORT_CHECK_EXPIRED", reason: "端口检查已过期，请重新检测" };
    }
    if (error instanceof RulePortCheckError) throw error;
    return { status: "FAILED", reasonCode: "PORT_CHECK_FAILED", reason: "入口服务器端口检测失败，请重试" };
  }

  return { status: "AVAILABLE", checkedAt: new Date().toISOString() };
}
