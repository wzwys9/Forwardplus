import crypto from "node:crypto";
import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";
import {
  XRAY_AGENT_ERROR_CODES,
  XRAY_LIMITS,
  XrayRealityScanResultSchema,
  XrayTaskResultSchema,
  XrayTaskSchema,
  type XrayTask,
} from "../shared/xrayTypes";
import { pushAgentRefresh } from "./agentEvents";
import { quoteIdentifier } from "./dbCompat";
import { executeRaw, insertAndGetId, nowDate, queryRaw } from "./dbRuntime";
import { withKeyedTaskLock } from "./keyedTaskLock";
import { getHostById } from "./repositories/hostRepository";
import { getXrayRuntimeReport } from "./repositories/xrayRepository";
import {
  XRAY_REALITY_CANDIDATE_LIST_VERSION,
  XRAY_REALITY_DEFAULT_CANDIDATES,
  type XrayRealityCandidateListVersion,
} from "./xrayRealityCandidates";

const XRAY_REALITY_OPERATION_TTL_MS = 150_000;
const XRAY_REALITY_RESOLVE_TIMEOUT_MS = 3_000;
const XRAY_REALITY_RESOLVE_CONCURRENCY = 8;
const XRAY_REALITY_MAX_RESOLVED_ADDRESSES = 16;
const XRAY_REALITY_MAX_ACTIVE_PER_HOST = 2;
const XRAY_REALITY_TARGET_PATTERN = /^(?=.{1,260}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?:([1-9][0-9]{0,4})$/;
const TERMINAL_OPERATION_STATUSES = new Set(["SUCCESS", "FAILED", "TIMEOUT", "CANCELLED"]);
const SAFE_REALITY_REASON_CODES = new Set(["REALITY_TARGET_BLOCKED", "REALITY_TLS_UNSUPPORTED"]);
const SAFE_RESOLVED_SENTINELS = new Set(["redacted", "unresolved"]);
const STABLE_XRAY_AGENT_ERROR_CODES = new Set<string>(XRAY_AGENT_ERROR_CODES);
const BLOCKED_CLOUD_PLATFORM_ENDPOINTS = new Set(["168.63.129.16"]);

function safeXrayOperationErrorCode(code: unknown) {
  const value = String(code ?? "");
  return STABLE_XRAY_AGENT_ERROR_CODES.has(value) ? value : "INTERNAL_ERROR";
}

const blockedIPv4 = new BlockList();
const blockedIPv6 = new BlockList();
const allowedIPv6 = new BlockList();
allowedIPv6.addSubnet("2000::", 3, "ipv6");
for (const cidr of [
  "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
  "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
  "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
]) {
  const [network, prefix] = cidr.split("/");
  blockedIPv4.addSubnet(network, Number(prefix), "ipv4");
}
for (const cidr of [
  "::/96", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
  "2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10",
  "fec0::/10", "ff00::/8",
]) {
  const separator = cidr.lastIndexOf("/");
  blockedIPv6.addSubnet(cidr.slice(0, separator), Number(cidr.slice(separator + 1)), "ipv6");
}

export type XrayRealityOperationErrorCode =
  | "HOST_NOT_FOUND"
  | "HOST_OFFLINE"
  | "AGENT_CAPABILITY_MISSING"
  | "REALITY_TARGET_INVALID"
  | "REALITY_TARGET_BLOCKED"
  | "OPERATION_CONFLICT";

export type XrayRealityCandidateResult = {
  target: string;
  host: string;
  resolvedIp: string;
  port: number;
  feasible: boolean;
  tls13: boolean;
  h2: boolean;
  x25519: boolean;
  certificateValid: boolean;
  serverNames: string[];
  latencyMs: number;
  reasonCode: string | null;
};

export type XrayRealityScanOperationResult = {
  operationId: string;
  status: string;
  createdAt: string;
  errorCode?: string;
  candidateListVersion?: XrayRealityCandidateListVersion | null;
  results?: XrayRealityCandidateResult[];
  observedAt?: string;
};

const errorMessages: Record<XrayRealityOperationErrorCode, string> = {
  HOST_NOT_FOUND: "Xray host was not found",
  HOST_OFFLINE: "Xray host is offline",
  AGENT_CAPABILITY_MISSING: "Xray Reality scan capability is unavailable",
  REALITY_TARGET_INVALID: "Reality scan target is invalid",
  REALITY_TARGET_BLOCKED: "Reality scan target is blocked by network policy",
  OPERATION_CONFLICT: "Xray Reality scan operation conflict",
};

export class XrayRealityOperationError extends Error {
  constructor(readonly code: XrayRealityOperationErrorCode) {
    super(errorMessages[code]);
    this.name = "XrayRealityOperationError";
  }
}

type RealityScanSource = "DEFAULT_CANDIDATES" | "ADMIN_DOMAINS";
type RealityScanRequestMeta = {
  schemaVersion: 1;
  source: RealityScanSource;
  candidateListVersion: XrayRealityCandidateListVersion | null;
  targets: string[];
};
type RealityOperationRow = {
  operationId: string;
  hostId: number;
  type: string;
  status: string;
  requestMetaJson: string | null;
  resultJson: string | null;
  errorCode: string | null;
  createdByUserId: number;
  createdAt: unknown;
  expiresAt: unknown;
};
type ResolveHost = (host: string) => Promise<string[]>;

function positiveId(value: unknown, code: XrayRealityOperationErrorCode): number {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) throw new XrayRealityOperationError(code);
  return id;
}

function dateFromDatabase(value: unknown): Date {
  if (value instanceof Date) return new Date(value.getTime());
  if (typeof value === "number" || (typeof value === "string" && /^\d+(?:\.\d+)?$/.test(value.trim()))) {
    return new Date(Number(value) * 1000);
  }
  const parsed = new Date(String(value ?? ""));
  return Number.isFinite(parsed.getTime()) ? parsed : new Date(0);
}

function targetParts(target: string): { host: string; port: number } {
  const separator = target.lastIndexOf(":");
  return { host: target.slice(0, separator), port: Number(target.slice(separator + 1)) };
}

export function normalizeXrayRealityTargets(rawTargets: unknown): string[] {
  if (!Array.isArray(rawTargets) || rawTargets.length < 1 || rawTargets.length > XRAY_LIMITS.maxRealityTargets) {
    throw new XrayRealityOperationError("REALITY_TARGET_INVALID");
  }
  const normalized: string[] = [];
  const seen = new Set<string>();
  for (const value of rawTargets) {
    if (typeof value !== "string") throw new XrayRealityOperationError("REALITY_TARGET_INVALID");
    const target = value.trim().toLowerCase();
    const match = XRAY_REALITY_TARGET_PATTERN.exec(target);
    const port = Number(match?.[1]);
    if (!match || !Number.isInteger(port) || port < 1 || port > 65535) {
      throw new XrayRealityOperationError("REALITY_TARGET_INVALID");
    }
    if (!seen.has(target)) {
      seen.add(target);
      normalized.push(target);
    }
  }
  return normalized;
}

export function isAllowedXrayRealityAddressText(address: string): boolean {
  if (BLOCKED_CLOUD_PLATFORM_ENDPOINTS.has(address.trim().toLowerCase())) return false;
  const family = isIP(address);
  if (family === 4) return !blockedIPv4.check(address, "ipv4");
  if (family === 6) return allowedIPv6.check(address, "ipv6") && !blockedIPv6.check(address, "ipv6");
  return false;
}

async function defaultResolveHost(host: string): Promise<string[]> {
  const rows = await lookup(host, { all: true, verbatim: true });
  return rows.map((row) => row.address);
}

function withResolveTimeout(host: string, resolveHost: ResolveHost): Promise<string[]> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new XrayRealityOperationError("REALITY_TARGET_INVALID")), XRAY_REALITY_RESOLVE_TIMEOUT_MS);
    timer.unref?.();
    Promise.resolve().then(() => resolveHost(host)).then(
      (addresses) => {
        clearTimeout(timer);
        resolve(addresses);
      },
      () => {
        clearTimeout(timer);
        reject(new XrayRealityOperationError("REALITY_TARGET_INVALID"));
      },
    );
  });
}

async function validateResolvedTargets(targets: string[], resolveHost: ResolveHost) {
  const hosts = [...new Set(targets.map((target) => targetParts(target).host))];
  let nextIndex = 0;
  const workers = Array.from({ length: Math.min(XRAY_REALITY_RESOLVE_CONCURRENCY, hosts.length) }, async () => {
    while (nextIndex < hosts.length) {
      const index = nextIndex;
      nextIndex += 1;
      const addresses = await withResolveTimeout(hosts[index], resolveHost);
      if (!Array.isArray(addresses) || addresses.length < 1) throw new XrayRealityOperationError("REALITY_TARGET_INVALID");
      if (addresses.length > XRAY_REALITY_MAX_RESOLVED_ADDRESSES) {
        throw new XrayRealityOperationError("REALITY_TARGET_BLOCKED");
      }
      const unique = new Set(addresses.map((address) => String(address).trim().toLowerCase()));
      if (unique.size < 1 || [...unique].some((address) => !isAllowedXrayRealityAddressText(address))) {
        throw new XrayRealityOperationError("REALITY_TARGET_BLOCKED");
      }
    }
  });
  await Promise.all(workers);
}

async function requireRealityHost(hostId: number) {
  const host = await getHostById(hostId);
  if (!host) throw new XrayRealityOperationError("HOST_NOT_FOUND");
  if (!host.isOnline) throw new XrayRealityOperationError("HOST_OFFLINE");
  const capability = await getXrayRuntimeReport(hostId);
  if (!capability || capability.capabilitySchemaVersion !== 1 || !capability.supportsRealityScan) {
    throw new XrayRealityOperationError("AGENT_CAPABILITY_MISSING");
  }
  return host;
}

async function activeRealityOperationCount(hostId: number): Promise<number> {
  const q = quoteIdentifier;
  const rows = await queryRaw<{ count: number }>(
    `SELECT COUNT(*) AS ${q("count")} FROM ${q("xray_operations")}
      WHERE ${q("hostId")} = ? AND ${q("type")} = ? AND ${q("status")} IN (?, ?) AND ${q("expiresAt")} > ?`,
    [hostId, "REALITY_SCAN", "QUEUED", "RUNNING", nowDate()],
  );
  return Number(rows[0]?.count || 0);
}

export async function createXrayRealityScanOperation(input: {
  hostId: unknown;
  userId: unknown;
  source: unknown;
  targets?: unknown;
}, options: { resolveHost?: ResolveHost } = {}): Promise<{ operationId: string }> {
  const hostId = positiveId(input.hostId, "HOST_NOT_FOUND");
  const userId = positiveId(input.userId, "OPERATION_CONFLICT");
  const source = String(input.source ?? "").toUpperCase();
  if (source !== "DEFAULT_CANDIDATES" && source !== "ADMIN_DOMAINS") {
    throw new XrayRealityOperationError("REALITY_TARGET_INVALID");
  }
  const targets = source === "DEFAULT_CANDIDATES"
    ? (input.targets === undefined
        ? [...XRAY_REALITY_DEFAULT_CANDIDATES]
        : (() => { throw new XrayRealityOperationError("REALITY_TARGET_INVALID"); })())
    : normalizeXrayRealityTargets(input.targets);
  await requireRealityHost(hostId);
  if (await activeRealityOperationCount(hostId) >= XRAY_REALITY_MAX_ACTIVE_PER_HOST) {
    throw new XrayRealityOperationError("OPERATION_CONFLICT");
  }
  await validateResolvedTargets(targets, options.resolveHost ?? defaultResolveHost);

  return withKeyedTaskLock(`xray-reality-create:${hostId}`, async () => {
    await requireRealityHost(hostId);
    if (await activeRealityOperationCount(hostId) >= XRAY_REALITY_MAX_ACTIVE_PER_HOST) {
      throw new XrayRealityOperationError("OPERATION_CONFLICT");
    }
    const operationId = crypto.randomUUID();
    const createdAt = nowDate();
    const expiresAt = new Date(createdAt.getTime() + XRAY_REALITY_OPERATION_TTL_MS);
    const requestMeta: RealityScanRequestMeta = {
      schemaVersion: 1,
      source,
      candidateListVersion: source === "DEFAULT_CANDIDATES" ? XRAY_REALITY_CANDIDATE_LIST_VERSION : null,
      targets,
    };
    await insertAndGetId("xray_operations", {
      operationId,
      hostId,
      inboundId: null,
      type: "REALITY_SCAN",
      status: "QUEUED",
      requestMetaJson: JSON.stringify(requestMeta),
      resultJson: null,
      errorCode: null,
      errorMessage: null,
      attemptCount: 0,
      createdByUserId: userId,
      createdAt,
      startedAt: null,
      finishedAt: null,
      expiresAt,
      updatedAt: createdAt,
    });
    pushAgentRefresh(hostId, "xray-reality-scan", { urgent: true });
    return { operationId };
  });
}

function parseRequestMeta(value: unknown): RealityScanRequestMeta | null {
  try {
    const parsed = typeof value === "string" ? JSON.parse(value) : value;
    if (!parsed || parsed.schemaVersion !== 1 || (parsed.source !== "DEFAULT_CANDIDATES" && parsed.source !== "ADMIN_DOMAINS")) return null;
    const targets = normalizeXrayRealityTargets(parsed.targets);
    const candidateListVersion = parsed.source === "DEFAULT_CANDIDATES" ? parsed.candidateListVersion : null;
    if (parsed.source === "DEFAULT_CANDIDATES" && candidateListVersion !== XRAY_REALITY_CANDIDATE_LIST_VERSION) return null;
    return { schemaVersion: 1, source: parsed.source, candidateListVersion, targets };
  } catch {
    return null;
  }
}

async function operationRows(hostId: number, limit: number): Promise<RealityOperationRow[]> {
  const q = quoteIdentifier;
  return queryRaw<RealityOperationRow>(
    `SELECT ${["operationId", "hostId", "type", "status", "requestMetaJson", "resultJson", "errorCode", "createdByUserId", "createdAt", "expiresAt"].map(q).join(", ")}
       FROM ${q("xray_operations")}
      WHERE ${q("hostId")} = ? AND ${q("type")} = ? AND ${q("status")} IN (?, ?)
      ORDER BY ${q("createdAt")} ASC, ${q("id")} ASC LIMIT ?`,
    [hostId, "REALITY_SCAN", "QUEUED", "RUNNING", limit],
  );
}

async function markOperationFailed(operationId: string, status: "FAILED" | "TIMEOUT", errorCode: string, now: Date) {
  const q = quoteIdentifier;
  await executeRaw(
    `UPDATE ${q("xray_operations")}
        SET ${q("status")} = ?, ${q("errorCode")} = ?, ${q("errorMessage")} = ?,
            ${q("finishedAt")} = ?, ${q("updatedAt")} = ?
      WHERE ${q("operationId")} = ? AND ${q("status")} IN (?, ?)`,
    [status, errorCode, "Xray Reality scan did not complete", now, now, operationId, "QUEUED", "RUNNING"],
  );
}

export async function takeXrayRealityScanTasks(hostIdValue: unknown, requestedLimit = 1): Promise<XrayTask[]> {
  const hostId = positiveId(hostIdValue, "HOST_NOT_FOUND");
  const limit = Math.max(1, Math.min(XRAY_REALITY_MAX_ACTIVE_PER_HOST, Math.floor(Number(requestedLimit) || 0)));
  const now = nowDate();
  const q = quoteIdentifier;
  const tasks: XrayTask[] = [];
  for (const row of await operationRows(hostId, limit)) {
    const expiresAt = dateFromDatabase(row.expiresAt);
    if (expiresAt.getTime() <= now.getTime()) {
      await markOperationFailed(row.operationId, "TIMEOUT", "TASK_EXPIRED", now);
      continue;
    }
    const meta = parseRequestMeta(row.requestMetaJson);
    if (!meta) {
      await markOperationFailed(row.operationId, "FAILED", "INVALID_PAYLOAD", now);
      continue;
    }
    const task = XrayTaskSchema.parse({
      schemaVersion: 1,
      taskId: row.operationId,
      type: "REALITY_SCAN",
      createdAt: dateFromDatabase(row.createdAt).toISOString(),
      expiresAt: expiresAt.toISOString(),
      payload: { targets: meta.targets, timeoutMs: 10_000, maxConcurrency: XRAY_LIMITS.maxRealityConcurrency },
    });
    await executeRaw(
      `UPDATE ${q("xray_operations")}
          SET ${q("status")} = ?, ${q("startedAt")} = COALESCE(${q("startedAt")}, ?),
              ${q("attemptCount")} = ${q("attemptCount")} + 1, ${q("updatedAt")} = ?
        WHERE ${q("operationId")} = ? AND ${q("status")} IN (?, ?)`,
      ["RUNNING", now, now, row.operationId, "QUEUED", "RUNNING"],
    );
    tasks.push(task);
  }
  return tasks;
}

export async function hasQueuedXrayRealityScanTasks(hostIdValue: unknown): Promise<boolean> {
  return await activeRealityOperationCount(positiveId(hostIdValue, "HOST_NOT_FOUND")) > 0;
}

async function getOperation(operationId: string): Promise<RealityOperationRow | null> {
  if (!/^[A-Za-z0-9._:-]{1,64}$/.test(operationId)) throw new XrayRealityOperationError("OPERATION_CONFLICT");
  const q = quoteIdentifier;
  const rows = await queryRaw<RealityOperationRow>(
    `SELECT ${["operationId", "hostId", "type", "status", "requestMetaJson", "resultJson", "errorCode", "createdByUserId", "createdAt", "expiresAt"].map(q).join(", ")}
       FROM ${q("xray_operations")} WHERE ${q("operationId")} = ? LIMIT 1`,
    [operationId],
  );
  return rows[0] ?? null;
}

function projectSafeResults(meta: RealityScanRequestMeta, rawResult: unknown) {
  const result = XrayRealityScanResultSchema.parse(rawResult);
  if (result.results.length !== meta.targets.length) return null;
  const expected = new Map(meta.targets.map((target) => [target, targetParts(target)]));
  const seen = new Set<string>();
  const projected = [];
  for (const item of result.results) {
    const identity = expected.get(item.target);
    if (!identity || seen.has(item.target) || item.host !== identity.host || item.port !== identity.port) return null;
    seen.add(item.target);
    const sentinel = SAFE_RESOLVED_SENTINELS.has(item.resolvedIp);
    if (!sentinel && !isAllowedXrayRealityAddressText(item.resolvedIp)) return null;
    if (sentinel && item.feasible) return null;
    if (item.resolvedIp === "redacted" && item.reasonCode !== "REALITY_TARGET_BLOCKED") return null;
    if (item.resolvedIp === "unresolved" && item.reasonCode !== "REALITY_TLS_UNSUPPORTED") return null;
    if (item.reasonCode === "REALITY_TARGET_BLOCKED" && item.resolvedIp !== "redacted") return null;
    if (item.serverNames.some((serverName) => serverName !== identity.host)) return null;
    if (item.feasible) {
      if (!item.tls13 || !item.h2 || !item.x25519 || !item.certificateValid || item.reasonCode !== null ||
          item.serverNames.length !== 1 || item.serverNames[0] !== identity.host) return null;
    } else if (!item.reasonCode || !SAFE_REALITY_REASON_CODES.has(item.reasonCode)) {
      return null;
    }
    projected.push({
      target: item.target,
      host: item.host,
      resolvedIp: item.resolvedIp,
      port: item.port,
      feasible: item.feasible,
      tls13: item.tls13,
      h2: item.h2,
      x25519: item.x25519,
      certificateValid: item.certificateValid,
      serverNames: [...item.serverNames],
      latencyMs: item.latencyMs,
      reasonCode: item.reasonCode,
    });
  }
  projected.sort((left, right) => Number(right.feasible) - Number(left.feasible) || left.latencyMs - right.latencyMs || left.target.localeCompare(right.target));
  return { results: projected, observedAt: result.observedAt };
}

export async function completeXrayRealityScanTask(hostIdValue: unknown, rawResult: unknown): Promise<{ accepted: true }> {
  const hostId = positiveId(hostIdValue, "HOST_NOT_FOUND");
  const result = XrayTaskResultSchema.parse(rawResult);
  if (result.type !== "REALITY_SCAN") throw new XrayRealityOperationError("OPERATION_CONFLICT");
  return withKeyedTaskLock(`xray-reality-operation:${result.taskId}`, async () => {
    const operation = await getOperation(result.taskId);
    if (!operation || operation.type !== "REALITY_SCAN" || Number(operation.hostId) !== hostId) {
      throw new XrayRealityOperationError("OPERATION_CONFLICT");
    }
    if (TERMINAL_OPERATION_STATUSES.has(operation.status)) return { accepted: true };
    const now = nowDate();
    if (dateFromDatabase(operation.expiresAt).getTime() <= now.getTime()) {
      await markOperationFailed(operation.operationId, "TIMEOUT", "TASK_EXPIRED", now);
      return { accepted: true };
    }
    const meta = parseRequestMeta(operation.requestMetaJson);
    if (!meta) {
      await markOperationFailed(operation.operationId, "FAILED", "INVALID_PAYLOAD", now);
      return { accepted: true };
    }
    if (result.status !== "SUCCESS" || !result.result) {
      const errorCode = STABLE_XRAY_AGENT_ERROR_CODES.has(result.error?.code || "") ? result.error!.code : "INTERNAL_ERROR";
      await markOperationFailed(operation.operationId, result.status === "TIMEOUT" ? "TIMEOUT" : "FAILED", errorCode, now);
      return { accepted: true };
    }
    const safeResult = projectSafeResults(meta, result.result);
    if (!safeResult) {
      await markOperationFailed(operation.operationId, "FAILED", "INVALID_PAYLOAD", now);
      return { accepted: true };
    }
    const q = quoteIdentifier;
    await executeRaw(
      `UPDATE ${q("xray_operations")}
          SET ${q("status")} = ?, ${q("resultJson")} = ?, ${q("errorCode")} = NULL,
              ${q("errorMessage")} = NULL, ${q("finishedAt")} = ?, ${q("updatedAt")} = ?
        WHERE ${q("operationId")} = ? AND ${q("status")} IN (?, ?)`,
      ["SUCCESS", JSON.stringify({ candidateListVersion: meta.candidateListVersion, ...safeResult }), now, now, operation.operationId, "QUEUED", "RUNNING"],
    );
    return { accepted: true };
  });
}

export async function acceptXrayRealityTaskResults(hostIdValue: unknown, rawResults: unknown): Promise<string[]> {
  const hostId = positiveId(hostIdValue, "HOST_NOT_FOUND");
  if (!Array.isArray(rawResults)) return [];
  const accepted: string[] = [];
  for (const rawResult of rawResults.slice(0, 8)) {
    try {
      const result = XrayTaskResultSchema.parse(rawResult);
      if (result.type !== "REALITY_SCAN") continue;
      await completeXrayRealityScanTask(hostId, result);
      accepted.push(result.taskId);
    } catch {
      // Leave malformed, foreign, or transiently unpersistable results in the
      // Agent spool. Only explicit accepted IDs are removed by the Agent.
    }
  }
  return accepted;
}

export async function getXrayRealityScanOperationResult(operationIdValue: unknown, userIdValue: unknown): Promise<XrayRealityScanOperationResult> {
  const operationId = String(operationIdValue ?? "");
  const userId = positiveId(userIdValue, "OPERATION_CONFLICT");
  const operation = await getOperation(operationId);
  if (!operation || operation.type !== "REALITY_SCAN" || Number(operation.createdByUserId) !== userId) {
    throw new XrayRealityOperationError("OPERATION_CONFLICT");
  }
  const response: XrayRealityScanOperationResult = {
    operationId, status: operation.status, createdAt: dateFromDatabase(operation.createdAt).toISOString(),
  };
  if (operation.errorCode) response.errorCode = safeXrayOperationErrorCode(operation.errorCode);
  if (operation.status === "SUCCESS") {
    try {
      const parsed = JSON.parse(String(operation.resultJson ?? ""));
      const meta = parseRequestMeta(operation.requestMetaJson);
      const safeResult = meta && projectSafeResults(meta, { results: parsed.results, observedAt: parsed.observedAt });
      if (!meta || !safeResult || parsed.candidateListVersion !== meta.candidateListVersion) {
        throw new XrayRealityOperationError("OPERATION_CONFLICT");
      }
      response.candidateListVersion = meta.candidateListVersion;
      response.results = safeResult.results;
      response.observedAt = safeResult.observedAt;
    } catch {
      throw new XrayRealityOperationError("OPERATION_CONFLICT");
    }
  }
  return response;
}

export async function validateXrayRealityDestinationForCreate(input: {
  hostId: unknown;
  userId: unknown;
  targetHost: unknown;
  targetPort: unknown;
  serverName: unknown;
}): Promise<{ targetHost: string; targetPort: number; serverName: string }> {
  const hostId = positiveId(input.hostId, "HOST_NOT_FOUND");
  const userId = positiveId(input.userId, "OPERATION_CONFLICT");
  const [target] = normalizeXrayRealityTargets([`${String(input.targetHost ?? "").trim()}:${String(input.targetPort ?? "").trim()}`]);
  const identity = targetParts(target);
  const serverName = String(input.serverName ?? "").trim().toLowerCase();
  if (serverName !== identity.host) throw new XrayRealityOperationError("REALITY_TARGET_INVALID");

  const q = quoteIdentifier;
  const rows = await queryRaw<RealityOperationRow>(
    `SELECT ${["operationId", "hostId", "type", "status", "requestMetaJson", "resultJson", "errorCode", "createdByUserId", "createdAt", "expiresAt"].map(q).join(", ")}
       FROM ${q("xray_operations")}
      WHERE ${q("hostId")} = ? AND ${q("createdByUserId")} = ? AND ${q("type")} = ?
        AND ${q("status")} = ? AND ${q("expiresAt")} > ?
      ORDER BY ${q("finishedAt")} DESC, ${q("id")} DESC LIMIT 16`,
    [hostId, userId, "REALITY_SCAN", "SUCCESS", nowDate()],
  );
  for (const row of rows) {
    try {
      const meta = parseRequestMeta(row.requestMetaJson);
      const stored = JSON.parse(String(row.resultJson ?? ""));
      const safe = meta && projectSafeResults(meta, { results: stored.results, observedAt: stored.observedAt });
      if (safe?.results.some((item) => item.target === target && item.feasible && item.serverNames.includes(serverName))) {
        return { targetHost: identity.host, targetPort: identity.port, serverName };
      }
    } catch {
      // Ignore malformed or tampered historical results.
    }
  }
  throw new XrayRealityOperationError("REALITY_TARGET_INVALID");
}
