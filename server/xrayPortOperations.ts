import crypto from "node:crypto";
import {
  XRAY_AGENT_ERROR_CODES,
  XRAY_LIMITS,
  XrayTaskResultSchema,
  XrayTaskSchema,
  type XrayTask,
} from "../shared/xrayTypes";
import { resolveStoredXrayInboundDefinition } from "../shared/xrayProfiles";
import { executeRaw, insertAndGetId, nowDate, queryRaw } from "./dbRuntime";
import { quoteIdentifier } from "./dbCompat";
import { withKeyedTaskLock } from "./keyedTaskLock";
import {
  reservedHostPorts,
  reserveSpecificHostPort,
  type HostPortReservation,
} from "./portReservations";
import { isPortAllowedByPolicy, portPolicyFrom } from "./portPolicy";
import { getHostById } from "./repositories/hostRepository";
import { getUsedPortsOnHost } from "./repositories/tunnelRepository";
import { getXrayRuntimeReport } from "./repositories/xrayRepository";
import { pushAgentRefresh } from "./agentEvents";
import {
  assertActiveXrayInboundPortTargetAlias,
  collectUnavailableGlobalPorts,
  GlobalPortAllocationError,
  type XrayInboundPortTargetAlias,
} from "./globalPortAllocationService";

const MIN_XRAY_PORT = 1000;
const MAX_XRAY_PORT = 65535;
const XRAY_PORT_PROBE_TTL_MS = 90_000;
const XRAY_PORT_RESERVATION_TTL_MS = 60_000;
const XRAY_PORT_MAX_ACTIVE_PER_HOST = 4;
const TERMINAL_OPERATION_STATUSES = new Set(["SUCCESS", "FAILED", "TIMEOUT", "CANCELLED"]);
const STABLE_XRAY_AGENT_ERROR_CODES = new Set<string>(XRAY_AGENT_ERROR_CODES);

function safeXrayOperationErrorCode(code: unknown) {
  const value = String(code ?? "");
  if (value === "UDP_CAPABILITY_REQUIRED") return value;
  return STABLE_XRAY_AGENT_ERROR_CODES.has(value) ? value : "INTERNAL_ERROR";
}

export type XrayPortOperationErrorCode =
  | "HOST_NOT_FOUND"
  | "HOST_OFFLINE"
  | "AGENT_CAPABILITY_MISSING"
  | "UDP_CAPABILITY_REQUIRED"
  | "PORT_OUT_OF_RANGE"
  | "PORT_IN_USE"
  | "PORT_RESERVATION_EXPIRED"
  | "PORT_RESERVATION_MISMATCH"
  | "OPERATION_CONFLICT";

const errorMessages: Record<XrayPortOperationErrorCode, string> = {
  HOST_NOT_FOUND: "Xray host was not found",
  HOST_OFFLINE: "Xray host is offline",
  AGENT_CAPABILITY_MISSING: "Xray port probe capability is unavailable",
  UDP_CAPABILITY_REQUIRED: "Xray UDP capability is unavailable",
  PORT_OUT_OF_RANGE: "Xray port is outside the allowed range",
  PORT_IN_USE: "Xray port is already in use",
  PORT_RESERVATION_EXPIRED: "Xray port reservation has expired",
  PORT_RESERVATION_MISMATCH: "Xray port reservation does not match this request",
  OPERATION_CONFLICT: "Xray port operation conflict",
};

export class XrayPortOperationError extends Error {
  constructor(readonly code: XrayPortOperationErrorCode) {
    super(errorMessages[code]);
    this.name = "XrayPortOperationError";
  }
}

type PortProbeMode = "AUTO" | "MANUAL";
type XrayListenerNetwork = "tcp" | "udp";

type PortProbeRequestMeta = {
  schemaVersion: 1;
  mode: PortProbeMode;
  network: XrayListenerNetwork;
  candidates: number[];
  targetAlias?: XrayInboundPortTargetAlias;
};

type PortOperationRow = {
  operationId: string;
  hostId: number;
  type: string;
  status: string;
  requestMetaJson: string | null;
  resultJson: string | null;
  errorCode: string | null;
  createdByUserId: number;
  attemptCount: number;
  createdAt: unknown;
  startedAt: unknown;
  finishedAt: unknown;
  expiresAt: unknown;
};

type XrayReservationEntry = {
  reservationId: string;
  hostId: number;
  userId: number;
  port: number;
  network: XrayListenerNetwork;
  protocol: XrayListenerNetwork;
  expiresAt: number;
  hostReservation: HostPortReservation;
  timer: ReturnType<typeof setTimeout>;
};

const xrayReservations = new Map<string, XrayReservationEntry>();

function positiveId(value: unknown, code: XrayPortOperationErrorCode): number {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) throw new XrayPortOperationError(code);
  return id;
}

function normalizedPort(value: unknown): number {
  const port = Number(value);
  if (!Number.isInteger(port) || port < MIN_XRAY_PORT || port > MAX_XRAY_PORT) {
    throw new XrayPortOperationError("PORT_OUT_OF_RANGE");
  }
  return port;
}

function normalizedNetwork(
  value: unknown,
  errorCode: "OPERATION_CONFLICT" | "PORT_RESERVATION_MISMATCH" = "OPERATION_CONFLICT",
): XrayListenerNetwork {
  if (value === undefined) return "tcp";
  const network = String(value).trim().toLowerCase();
  if (network === "tcp" || network === "udp") return network;
  throw new XrayPortOperationError(errorCode);
}

function dateFromDatabase(value: unknown): Date {
  if (value instanceof Date) return new Date(value.getTime());
  if (typeof value === "number" || (typeof value === "string" && /^\d+(?:\.\d+)?$/.test(value.trim()))) {
    return new Date(Number(value) * 1000);
  }
  const parsed = new Date(String(value ?? ""));
  return Number.isFinite(parsed.getTime()) ? parsed : new Date(0);
}

function parseRequestMeta(value: unknown): PortProbeRequestMeta | null {
  try {
    const parsed = typeof value === "string" ? JSON.parse(value) : value;
    if (!parsed || parsed.schemaVersion !== 1 || (parsed.mode !== "AUTO" && parsed.mode !== "MANUAL")) return null;
    const network = parsed.network === undefined ? "tcp" : parsed.network;
    if (network !== "tcp" && network !== "udp") return null;
    if (!Array.isArray(parsed.candidates) || parsed.candidates.length < 1 || parsed.candidates.length > XRAY_LIMITS.maxPortProbeCandidates) return null;
    const candidates = parsed.candidates.map((candidate: unknown) => Number(candidate));
    if (candidates.some((port: number) => !Number.isInteger(port) || port < MIN_XRAY_PORT || port > MAX_XRAY_PORT)) return null;
    if (new Set(candidates).size !== candidates.length) return null;
    if ((parsed.mode === "MANUAL" || network === "udp") && candidates.length !== 1) return null;
    const targetAlias = normalizedTargetAlias(parsed.targetAlias, parsed.mode, candidates[0]);
    return { schemaVersion: 1, mode: parsed.mode, network, candidates, ...(targetAlias ? { targetAlias } : {}) };
  } catch {
    return null;
  }
}

function normalizedTargetAlias(
  value: unknown,
  mode: unknown,
  manualPort: number | undefined,
): XrayInboundPortTargetAlias | null {
  if (value === undefined) return null;
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).some((key) => key !== "inboundId" && key !== "port")) {
    throw new XrayPortOperationError("OPERATION_CONFLICT");
  }
  const alias = value as Record<string, unknown>;
  const inboundId = Number(alias.inboundId);
  const port = Number(alias.port);
  if (mode !== "MANUAL" || !Number.isSafeInteger(inboundId) || inboundId <= 0
    || !Number.isSafeInteger(port) || port !== manualPort) {
    throw new XrayPortOperationError("OPERATION_CONFLICT");
  }
  return { inboundId, port };
}

async function assertTargetAliasAvailable(alias: XrayInboundPortTargetAlias): Promise<void> {
  try {
    await assertActiveXrayInboundPortTargetAlias(alias);
  } catch (error) {
    if (error instanceof GlobalPortAllocationError) throw new XrayPortOperationError("PORT_IN_USE");
    throw error;
  }
}

function randomStart(min: number, maxExclusive: number): number {
  return crypto.randomInt(min, maxExclusive);
}

export function generateXrayPortCandidates(
  usedPorts: ReadonlySet<number>,
  requestedCount: number = XRAY_LIMITS.maxPortProbeCandidates,
  randomInt: (min: number, maxExclusive: number) => number | undefined = randomStart,
  allowed: (port: number) => boolean = () => true,
): number[] {
  const count = Math.max(1, Math.min(XRAY_LIMITS.maxPortProbeCandidates, Math.floor(Number(requestedCount) || 0)));
  const span = MAX_XRAY_PORT - MIN_XRAY_PORT + 1;
  const rawStart = Number(randomInt(MIN_XRAY_PORT, MAX_XRAY_PORT + 1));
  const start = Number.isInteger(rawStart) && rawStart >= MIN_XRAY_PORT && rawStart <= MAX_XRAY_PORT
    ? rawStart
    : MIN_XRAY_PORT;
  const candidates: number[] = [];
  for (let offset = 0; offset < span && candidates.length < count; offset += 1) {
    const port = MIN_XRAY_PORT + ((start - MIN_XRAY_PORT + offset) % span);
    if (!usedPorts.has(port) && allowed(port)) candidates.push(port);
  }
  return candidates;
}

async function collectXrayDatabasePorts(hostId: number, network: XrayListenerNetwork): Promise<Set<number>> {
  const used = await getUsedPortsOnHost(hostId, undefined, network);
  const q = quoteIdentifier;
  const columns = ["listenPort", "protocol", "transport", "security", "profileId", "specVersion", "specJson"];
  const rows = await queryRaw<Record<string, unknown>>(
    `SELECT ${columns.map(q).join(", ")} FROM ${q("xray_inbounds")} WHERE ${q("hostId")} = ?`,
    [hostId],
  );
  for (const row of rows) {
    const port = Number(row.listenPort);
    if (!Number.isInteger(port) || port < 1 || port > MAX_XRAY_PORT) continue;
    const definition = resolveStoredXrayInboundDefinition(row);
    if (!definition || definition.profile.listenerNetworks.includes(network.toUpperCase() as "TCP" | "UDP")) used.add(port);
  }
  return used;
}

export async function collectXrayUsedPorts(hostIdValue: unknown, networkValue?: unknown): Promise<Set<number>> {
  const hostId = positiveId(hostIdValue, "HOST_NOT_FOUND");
  const network = normalizedNetwork(networkValue);
  const [used, globallyUnavailable] = await Promise.all([
    collectXrayDatabasePorts(hostId, network),
    collectUnavailableGlobalPorts(),
  ]);
  for (const port of globallyUnavailable) used.add(port);
  for (const port of reservedHostPorts(hostId, network)) used.add(port);
  return used;
}

export async function createXrayPortProbeOperation(input: {
  hostId: unknown;
  userId: unknown;
  mode: unknown;
  manualPort?: unknown;
  network?: unknown;
  replaceReservationIds?: unknown;
  targetAlias?: XrayInboundPortTargetAlias;
}): Promise<{ operationId: string }> {
  const hostId = positiveId(input.hostId, "HOST_NOT_FOUND");
  const userId = positiveId(input.userId, "OPERATION_CONFLICT");
  const mode = String(input.mode ?? "").toUpperCase();
  if (mode !== "AUTO" && mode !== "MANUAL") throw new XrayPortOperationError("OPERATION_CONFLICT");
  const network = normalizedNetwork(input.network);

  const host = await getHostById(hostId);
  if (!host) throw new XrayPortOperationError("HOST_NOT_FOUND");
  if (!host.isOnline) throw new XrayPortOperationError("HOST_OFFLINE");
  const capability = await getXrayRuntimeReport(hostId);
  if (!capability || capability.capabilitySchemaVersion !== 1 || !capability.supportsPortProbe) {
    throw new XrayPortOperationError("AGENT_CAPABILITY_MISSING");
  }
  if (network === "udp" && (!capability.supportsUdpPortProbe || !capability.supportsUdpListenerReadiness)) {
    throw new XrayPortOperationError("UDP_CAPABILITY_REQUIRED");
  }

  return withKeyedTaskLock(`xray-port-create:${hostId}`, async () => {
    const createdAt = nowDate();
    const q = quoteIdentifier;
    await executeRaw(
      `UPDATE ${q("xray_operations")} SET ${q("status")} = ?, ${q("errorCode")} = ?, ${q("errorMessage")} = ?,
          ${q("finishedAt")} = ?, ${q("updatedAt")} = ?
        WHERE ${q("hostId")} = ? AND ${q("type")} = ? AND ${q("status")} IN (?, ?) AND ${q("expiresAt")} <= ?`,
      ["TIMEOUT", "TASK_EXPIRED", "Xray port probe did not complete", createdAt, createdAt,
        hostId, "PORT_PROBE", "QUEUED", "RUNNING", createdAt],
    );
    const activeRows = await queryRaw<{ count: unknown }>(
      `SELECT COUNT(*) AS ${q("count")} FROM ${q("xray_operations")}
        WHERE ${q("hostId")} = ? AND ${q("type")} = ? AND ${q("status")} IN (?, ?)`,
      [hostId, "PORT_PROBE", "QUEUED", "RUNNING"],
    );
    if (Number(activeRows[0]?.count ?? 0) >= XRAY_PORT_MAX_ACTIVE_PER_HOST) {
      throw new XrayPortOperationError("OPERATION_CONFLICT");
    }

    const policy = portPolicyFrom(host);
    const allowed = (port: number) => isPortAllowedByPolicy(port, policy);
    const manualPort = mode === "MANUAL" ? normalizedPort(input.manualPort) : undefined;
    if (manualPort !== undefined && !allowed(manualPort)) throw new XrayPortOperationError("PORT_OUT_OF_RANGE");
    if (mode === "AUTO" && input.manualPort !== undefined) throw new XrayPortOperationError("OPERATION_CONFLICT");
    const targetAlias = normalizedTargetAlias(input.targetAlias, mode, manualPort);
    if (targetAlias) await assertTargetAliasAvailable(targetAlias);
    releaseReplacementXrayReservations({
      reservationIds: input.replaceReservationIds,
      hostId,
      userId,
      manualPort,
    });
    const used = await collectXrayUsedPorts(hostId, network);
    if (targetAlias) {
      const locallyUsed = await collectXrayDatabasePorts(hostId, network);
      if (!locallyUsed.has(targetAlias.port) && !reservedHostPorts(hostId, network).includes(targetAlias.port)) {
        used.delete(targetAlias.port);
      }
    }
    let candidates: number[];
    if (mode === "MANUAL") {
      if (used.has(manualPort!)) throw new XrayPortOperationError("PORT_IN_USE");
      candidates = [manualPort!];
    } else {
      const candidateCount = network === "udp" ? 1 : XRAY_LIMITS.maxPortProbeCandidates;
      candidates = generateXrayPortCandidates(used, candidateCount, randomStart, allowed);
      if (candidates.length === 0) throw new XrayPortOperationError("PORT_OUT_OF_RANGE");
    }

    const operationId = crypto.randomUUID();
    const expiresAt = new Date(createdAt.getTime() + XRAY_PORT_PROBE_TTL_MS);
    const requestMeta: PortProbeRequestMeta = {
      schemaVersion: 1,
      mode,
      network,
      candidates,
      ...(targetAlias ? { targetAlias } : {}),
    };
    await insertAndGetId("xray_operations", {
      operationId,
      hostId,
      inboundId: null,
      type: "PORT_PROBE",
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
    pushAgentRefresh(hostId, "xray-port-probe", { urgent: true });
    return { operationId };
  });
}

async function portOperationRows(hostId: number, limit: number): Promise<PortOperationRow[]> {
  const q = quoteIdentifier;
  return queryRaw<PortOperationRow>(
    `SELECT ${[
      "operationId", "hostId", "type", "status", "requestMetaJson", "resultJson", "errorCode",
      "createdByUserId", "attemptCount", "createdAt", "startedAt", "finishedAt", "expiresAt",
    ].map(q).join(", ")}
       FROM ${q("xray_operations")}
      WHERE ${q("hostId")} = ? AND ${q("type")} = ? AND ${q("status")} IN (?, ?)
      ORDER BY ${q("createdAt")} ASC, ${q("id")} ASC
      LIMIT ?`,
    [hostId, "PORT_PROBE", "QUEUED", "RUNNING", limit],
  );
}

async function markPortOperationFailed(operationId: string, status: "FAILED" | "TIMEOUT", errorCode: string, now: Date) {
  const q = quoteIdentifier;
  await executeRaw(
    `UPDATE ${q("xray_operations")}
        SET ${q("status")} = ?, ${q("errorCode")} = ?, ${q("errorMessage")} = ?,
            ${q("finishedAt")} = ?, ${q("updatedAt")} = ?
      WHERE ${q("operationId")} = ? AND ${q("status")} IN (?, ?)`,
    [status, errorCode, "Xray port probe did not complete", now, now, operationId, "QUEUED", "RUNNING"],
  );
}

export async function takeXrayPortProbeTasks(hostIdValue: unknown, requestedLimit = 4): Promise<XrayTask[]> {
  const hostId = positiveId(hostIdValue, "HOST_NOT_FOUND");
  const limit = Math.max(1, Math.min(16, Math.floor(Number(requestedLimit) || 0)));
  const now = nowDate();
  const rows = await portOperationRows(hostId, limit);
  const capability = await getXrayRuntimeReport(hostId);
  const supportsUdp = capability?.capabilitySchemaVersion === 1
    && capability.supportsPortProbe
    && capability.supportsUdpPortProbe
    && capability.supportsUdpListenerReadiness;
  const tasks: XrayTask[] = [];
  const q = quoteIdentifier;
  for (const row of rows) {
    const expiresAt = dateFromDatabase(row.expiresAt);
    if (expiresAt.getTime() <= now.getTime()) {
      await markPortOperationFailed(row.operationId, "TIMEOUT", "TASK_EXPIRED", now);
      continue;
    }
    const meta = parseRequestMeta(row.requestMetaJson);
    if (!meta) {
      await markPortOperationFailed(row.operationId, "FAILED", "INVALID_PAYLOAD", now);
      continue;
    }
    if (meta.network === "udp" && !supportsUdp) {
      await markPortOperationFailed(row.operationId, "FAILED", "UDP_CAPABILITY_REQUIRED", now);
      continue;
    }
    if (meta.targetAlias) {
      try {
        await assertActiveXrayInboundPortTargetAlias(meta.targetAlias);
      } catch (error) {
        if (!(error instanceof GlobalPortAllocationError)) throw error;
        await markPortOperationFailed(row.operationId, "FAILED", "PORT_IN_USE", now);
        continue;
      }
    }
    const task = XrayTaskSchema.parse({
      schemaVersion: 1,
      taskId: row.operationId,
      type: "PORT_PROBE",
      createdAt: dateFromDatabase(row.createdAt).toISOString(),
      expiresAt: expiresAt.toISOString(),
      payload: { network: meta.network, listenAddress: "0.0.0.0", ports: meta.candidates },
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

export async function hasQueuedXrayPortProbeTasks(hostIdValue: unknown): Promise<boolean> {
  const hostId = positiveId(hostIdValue, "HOST_NOT_FOUND");
  const q = quoteIdentifier;
  const rows = await queryRaw<{ count: number }>(
    `SELECT COUNT(*) AS ${q("count")} FROM ${q("xray_operations")}
      WHERE ${q("hostId")} = ? AND ${q("type")} = ? AND ${q("status")} IN (?, ?) AND ${q("expiresAt")} > ?`,
    [hostId, "PORT_PROBE", "QUEUED", "RUNNING", nowDate()],
  );
  return Number(rows[0]?.count || 0) > 0;
}

async function getPortOperation(operationId: string): Promise<PortOperationRow | null> {
  if (!/^[A-Za-z0-9._:-]{1,64}$/.test(operationId)) throw new XrayPortOperationError("OPERATION_CONFLICT");
  const q = quoteIdentifier;
  const rows = await queryRaw<PortOperationRow>(
    `SELECT ${[
      "operationId", "hostId", "type", "status", "requestMetaJson", "resultJson", "errorCode",
      "createdByUserId", "attemptCount", "createdAt", "startedAt", "finishedAt", "expiresAt",
    ].map(q).join(", ")} FROM ${q("xray_operations")} WHERE ${q("operationId")} = ? LIMIT 1`,
    [operationId],
  );
  return rows[0] ?? null;
}

function removeXrayReservation(entry: XrayReservationEntry) {
  if (xrayReservations.get(entry.reservationId) !== entry) return;
  xrayReservations.delete(entry.reservationId);
  clearTimeout(entry.timer);
  entry.hostReservation.release();
}

function replacementReservationIds(value: unknown): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length < 1 || value.length > 2) {
    throw new XrayPortOperationError("OPERATION_CONFLICT");
  }
  const ids = value.map((item) => String(item ?? ""));
  if (new Set(ids).size !== ids.length || ids.some((id) => !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id))) {
    throw new XrayPortOperationError("OPERATION_CONFLICT");
  }
  return ids;
}

function releaseReplacementXrayReservations(input: {
  reservationIds: unknown;
  hostId: number;
  userId: number;
  manualPort?: number;
}) {
  const entries: XrayReservationEntry[] = [];
  const expired: XrayReservationEntry[] = [];
  const networks = new Set<XrayListenerNetwork>();
  let commonPort: number | null = null;
  const now = Date.now();
  for (const reservationId of replacementReservationIds(input.reservationIds)) {
    const entry = xrayReservations.get(reservationId);
    if (!entry) continue;
    if (entry.expiresAt <= now) {
      expired.push(entry);
      continue;
    }
    if (entry.hostId !== input.hostId || entry.userId !== input.userId
      || (input.manualPort !== undefined && entry.port !== input.manualPort)
      || (commonPort !== null && entry.port !== commonPort) || networks.has(entry.network)) {
      throw new XrayPortOperationError("PORT_RESERVATION_MISMATCH");
    }
    commonPort = entry.port;
    networks.add(entry.network);
    entries.push(entry);
  }
  for (const entry of [...expired, ...entries]) removeXrayReservation(entry);
}

export function releaseXrayPortProbeReservation(input: {
  reservationId: unknown;
  hostId: unknown;
  userId: unknown;
  port: unknown;
  network?: unknown;
}): boolean {
  const reservationId = String(input.reservationId ?? "");
  const entry = xrayReservations.get(reservationId);
  if (!entry) return false;
  validateXrayPortReservation(input);
  removeXrayReservation(entry);
  return true;
}

export function releaseXrayPortProbeReservations(input: {
  userId: unknown;
  reservations: ReadonlyArray<Readonly<{
    reservationId: unknown;
    hostId: unknown;
    port: unknown;
    network: unknown;
  }>>;
}) {
  const userId = positiveId(input.userId, "PORT_RESERVATION_MISMATCH");
  if (!Array.isArray(input.reservations) || input.reservations.length < 1 || input.reservations.length > 128) {
    throw new XrayPortOperationError("OPERATION_CONFLICT");
  }
  const reservationIds = input.reservations.map((reservation) => String(reservation.reservationId ?? ""));
  const scopes = input.reservations.map((reservation) => `${Number(reservation.hostId)}:${String(reservation.network).toLowerCase()}`);
  if (new Set(reservationIds).size !== reservationIds.length || new Set(scopes).size !== scopes.length) {
    throw new XrayPortOperationError("OPERATION_CONFLICT");
  }
  const validated = input.reservations.map((reservation) => validateXrayPortReservation({
    reservationId: reservation.reservationId,
    hostId: reservation.hostId,
    userId,
    port: reservation.port,
    network: reservation.network,
  }));
  for (const reservation of validated) {
    const entry = xrayReservations.get(reservation.reservationId);
    if (!entry) throw new XrayPortOperationError("PORT_RESERVATION_EXPIRED");
    removeXrayReservation(entry);
  }
  return validated;
}

function registerXrayReservation(input: {
  hostId: number;
  userId: number;
  port: number;
  network: XrayListenerNetwork;
  hostReservation: HostPortReservation;
  now: Date;
}) {
  const reservationId = crypto.randomUUID();
  const expiresAt = input.now.getTime() + XRAY_PORT_RESERVATION_TTL_MS;
  const entry = {
    reservationId,
    hostId: input.hostId,
    userId: input.userId,
    port: input.port,
    network: input.network,
    protocol: input.network,
    expiresAt,
    hostReservation: input.hostReservation,
    timer: undefined as unknown as ReturnType<typeof setTimeout>,
  };
  entry.timer = setTimeout(() => removeXrayReservation(entry), XRAY_PORT_RESERVATION_TTL_MS);
  entry.timer.unref?.();
  xrayReservations.set(reservationId, entry);
  return entry;
}

function samePortSet(left: number[], right: number[]) {
  if (left.length !== right.length) return false;
  const sortedLeft = [...left].sort((a, b) => a - b);
  const sortedRight = [...right].sort((a, b) => a - b);
  return sortedLeft.every((value, index) => value === sortedRight[index]);
}

export async function completeXrayPortProbeTask(hostIdValue: unknown, rawResult: unknown): Promise<{ accepted: true }> {
  const hostId = positiveId(hostIdValue, "HOST_NOT_FOUND");
  const result = XrayTaskResultSchema.parse(rawResult);
  if (result.type !== "PORT_PROBE") throw new XrayPortOperationError("OPERATION_CONFLICT");
  return withKeyedTaskLock(`xray-port-operation:${result.taskId}`, async () => {
    const operation = await getPortOperation(result.taskId);
    if (!operation || operation.type !== "PORT_PROBE" || Number(operation.hostId) !== hostId) {
      throw new XrayPortOperationError("OPERATION_CONFLICT");
    }
    if (TERMINAL_OPERATION_STATUSES.has(operation.status)) return { accepted: true };
    const now = nowDate();
    if (dateFromDatabase(operation.expiresAt).getTime() <= now.getTime()) {
      await markPortOperationFailed(operation.operationId, "TIMEOUT", "TASK_EXPIRED", now);
      return { accepted: true };
    }
    const meta = parseRequestMeta(operation.requestMetaJson);
    if (!meta) {
      await markPortOperationFailed(operation.operationId, "FAILED", "INVALID_PAYLOAD", now);
      return { accepted: true };
    }
    if (result.status !== "SUCCESS" || !result.result) {
      const status = result.status === "TIMEOUT" ? "TIMEOUT" : "FAILED";
      const errorCode = STABLE_XRAY_AGENT_ERROR_CODES.has(result.error?.code || "") ? result.error!.code : "INTERNAL_ERROR";
      await markPortOperationFailed(operation.operationId, status, errorCode, now);
      return { accepted: true };
    }
    if (!samePortSet(meta.candidates, result.result.ports.map((item) => item.port))) {
      await markPortOperationFailed(operation.operationId, "FAILED", "INVALID_PAYLOAD", now);
      return { accepted: true };
    }

    let selected: { port: number; reservation: HostPortReservation } | null = null;
    const available = new Set(result.result.ports.filter((item) => item.available).map((item) => item.port));
    const globallyUnavailable = await collectUnavailableGlobalPorts();
    if (meta.targetAlias) {
      try {
        await assertActiveXrayInboundPortTargetAlias(meta.targetAlias);
        globallyUnavailable.delete(meta.targetAlias.port);
      } catch (error) {
        if (!(error instanceof GlobalPortAllocationError)) throw error;
        await markPortOperationFailed(operation.operationId, "FAILED", "PORT_IN_USE", now);
        return { accepted: true };
      }
    }
    for (const port of meta.candidates) {
      if (!available.has(port) || globallyUnavailable.has(port)) continue;
      const reservation = await reserveSpecificHostPort({
        hostId,
        port,
        protocol: meta.network,
        isUsed: async (candidate) => (await collectXrayDatabasePorts(hostId, meta.network)).has(candidate),
      });
      if (reservation) {
        selected = { port, reservation };
        break;
      }
    }
    if (!selected) {
      await markPortOperationFailed(operation.operationId, "FAILED", "PORT_IN_USE", now);
      return { accepted: true };
    }

    const reservation = registerXrayReservation({
      hostId,
      userId: Number(operation.createdByUserId),
      port: selected.port,
      network: meta.network,
      hostReservation: selected.reservation,
      now,
    });
    const resultJson = JSON.stringify({
      network: meta.network,
      selectedPort: selected.port,
      reservationId: reservation.reservationId,
      expiresAt: new Date(reservation.expiresAt).toISOString(),
    });
    const q = quoteIdentifier;
    try {
      await executeRaw(
        `UPDATE ${q("xray_operations")}
            SET ${q("status")} = ?, ${q("resultJson")} = ?, ${q("errorCode")} = NULL,
                ${q("errorMessage")} = NULL, ${q("finishedAt")} = ?, ${q("updatedAt")} = ?
          WHERE ${q("operationId")} = ? AND ${q("status")} IN (?, ?)`,
        ["SUCCESS", resultJson, now, now, operation.operationId, "QUEUED", "RUNNING"],
      );
    } catch (error) {
      removeXrayReservation(reservation);
      throw error;
    }
    return { accepted: true };
  });
}

export async function acceptXrayTaskResults(hostIdValue: unknown, rawResults: unknown): Promise<string[]> {
  const hostId = positiveId(hostIdValue, "HOST_NOT_FOUND");
  if (!Array.isArray(rawResults)) return [];
  const accepted: string[] = [];
  for (const rawResult of rawResults.slice(0, 8)) {
    try {
      const result = XrayTaskResultSchema.parse(rawResult);
      if (result.type !== "PORT_PROBE") continue;
      await completeXrayPortProbeTask(hostId, result);
      accepted.push(result.taskId);
    } catch {
      // A malformed, foreign, or currently unpersistable result is not
      // acknowledged, so the Agent retains its local terminal result for retry.
    }
  }
  return accepted;
}

export type XrayPortProbeOperationResult = {
  operationId: string;
  status: string;
  createdAt: string;
  network: XrayListenerNetwork;
  selectedPort?: number;
  reservationId?: string;
  expiresAt?: string;
  errorCode?: string;
};

export async function getXrayPortProbeOperationResult(operationIdValue: unknown, userIdValue: unknown): Promise<XrayPortProbeOperationResult> {
  const operationId = String(operationIdValue ?? "");
  const userId = positiveId(userIdValue, "PORT_RESERVATION_MISMATCH");
  const operation = await getPortOperation(operationId);
  if (!operation || operation.type !== "PORT_PROBE") throw new XrayPortOperationError("OPERATION_CONFLICT");
  if (Number(operation.createdByUserId) !== userId) throw new XrayPortOperationError("PORT_RESERVATION_MISMATCH");
  const meta = parseRequestMeta(operation.requestMetaJson);
  if (!meta) throw new XrayPortOperationError("OPERATION_CONFLICT");
  const response: XrayPortProbeOperationResult = {
    operationId, status: operation.status, createdAt: dateFromDatabase(operation.createdAt).toISOString(), network: meta.network,
  };
  if (operation.errorCode) response.errorCode = safeXrayOperationErrorCode(operation.errorCode);
  if (operation.status === "SUCCESS") {
    try {
      const parsed = JSON.parse(String(operation.resultJson ?? ""));
      if (parsed.network !== undefined && parsed.network !== meta.network) throw new Error("network mismatch");
      response.selectedPort = normalizedPort(parsed.selectedPort);
      response.reservationId = String(parsed.reservationId ?? "");
      response.expiresAt = new Date(String(parsed.expiresAt ?? "")).toISOString();
    } catch {
      throw new XrayPortOperationError("OPERATION_CONFLICT");
    }
  }
  return response;
}

export function validateXrayPortReservation(input: {
  reservationId: unknown;
  hostId: unknown;
  userId: unknown;
  port: unknown;
  network?: unknown;
}, now = Date.now()) {
  const reservationId = String(input.reservationId ?? "");
  const entry = xrayReservations.get(reservationId);
  if (!entry) throw new XrayPortOperationError("PORT_RESERVATION_EXPIRED");
  if (entry.expiresAt <= now) {
    removeXrayReservation(entry);
    throw new XrayPortOperationError("PORT_RESERVATION_EXPIRED");
  }
  const network = normalizedNetwork(input.network, "PORT_RESERVATION_MISMATCH");
  if (Number(input.hostId) !== entry.hostId || Number(input.userId) !== entry.userId
    || Number(input.port) !== entry.port || network !== entry.network) {
    throw new XrayPortOperationError("PORT_RESERVATION_MISMATCH");
  }
  return {
    reservationId: entry.reservationId,
    hostId: entry.hostId,
    userId: entry.userId,
    port: entry.port,
    network: entry.network,
    protocol: entry.protocol,
    expiresAt: new Date(entry.expiresAt).toISOString(),
  };
}

export function consumeXrayPortReservation(input: {
  reservationId: unknown;
  hostId: unknown;
  userId: unknown;
  port: unknown;
  network?: unknown;
}) {
  const validated = validateXrayPortReservation(input);
  const entry = xrayReservations.get(validated.reservationId)!;
  removeXrayReservation(entry);
  return validated;
}

export async function withConsumedXrayPortReservation<T>(input: {
  reservationId: unknown;
  hostId: unknown;
  userId: unknown;
  port: unknown;
  network?: unknown;
}, task: (reservation: ReturnType<typeof validateXrayPortReservation>) => Promise<T>): Promise<T> {
  const validated = validateXrayPortReservation(input);
  const entry = xrayReservations.get(validated.reservationId)!;
  xrayReservations.delete(entry.reservationId);
  clearTimeout(entry.timer);
  try {
    return await task(validated);
  } finally {
    entry.hostReservation.release();
  }
}

export async function withConsumedXrayPortReservations<T>(input: {
  tcpReservationId: unknown;
  udpReservationId: unknown;
  hostId: unknown;
  userId: unknown;
  port: unknown;
}, task: (reservations: {
  tcp: ReturnType<typeof validateXrayPortReservation>;
  udp: ReturnType<typeof validateXrayPortReservation>;
}) => Promise<T>): Promise<T> {
  const tcpReservationId = String(input.tcpReservationId ?? "");
  const udpReservationId = String(input.udpReservationId ?? "");
  if (!tcpReservationId || !udpReservationId || tcpReservationId === udpReservationId) {
    throw new XrayPortOperationError("PORT_RESERVATION_MISMATCH");
  }
  const tcp = validateXrayPortReservation({
    reservationId: tcpReservationId,
    hostId: input.hostId,
    userId: input.userId,
    port: input.port,
    network: "tcp",
  });
  const udp = validateXrayPortReservation({
    reservationId: udpReservationId,
    hostId: input.hostId,
    userId: input.userId,
    port: input.port,
    network: "udp",
  });
  const tcpEntry = xrayReservations.get(tcp.reservationId)!;
  const udpEntry = xrayReservations.get(udp.reservationId)!;
  for (const entry of [tcpEntry, udpEntry]) {
    xrayReservations.delete(entry.reservationId);
    clearTimeout(entry.timer);
  }
  try {
    return await task({ tcp, udp });
  } finally {
    tcpEntry.hostReservation.release();
    udpEntry.hostReservation.release();
  }
}

export function clearXrayPortOperationStateForTest() {
  for (const entry of [...xrayReservations.values()]) removeXrayReservation(entry);
}
