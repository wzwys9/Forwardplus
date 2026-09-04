import crypto from "node:crypto";

import { quoteIdentifier } from "./dbCompat";
import {
  executeRaw,
  insertAndGetId,
  nowDate,
  queryRaw,
  rawAffectedRows,
  withDatabaseTransaction,
} from "./dbRuntime";
import {
  createXrayPortProbeOperation,
  getXrayPortProbeOperationResult,
  releaseXrayPortProbeReservation,
  XrayPortOperationError,
} from "./xrayPortOperations";

type Row = Record<string, unknown>;
type ProbeNetwork = "tcp" | "udp";
type ProbeStatus = "FREE" | "OCCUPIED" | "OFFLINE" | "UNSUPPORTED" | "ERROR" | "EXPIRED";

type ManagedHost = Readonly<{ id: number; userId: number }>;
type AllocationCandidate = Readonly<{ id: number; port: number }>;
type ProbeOutcome = Readonly<{
  hostId: number;
  network: ProbeNetwork;
  operationId: string;
  status: ProbeStatus;
}>;

export type GlobalPortReclaimScanSummary = Readonly<{
  acquired: boolean;
  scanned: number;
  freed: number;
  occupied: number;
  deferred: number;
}>;

const LEASE_SCOPE = "GLOBAL_PORT_RECLAIM";
const SCAN_INTERVAL_MS = 12 * 60 * 60 * 1_000;
const LEASE_TTL_MS = 30 * 60 * 1_000;
const RUN_TTL_MS = 2 * 60 * 1_000;
const POLL_INTERVAL_MS = 500;
const DEFAULT_BATCH_SIZE = 8;
const HOST_CONCURRENCY = 4;

function positiveInteger(value: unknown): number | null {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function databaseDate(value: unknown): Date | null {
  if (value == null || value === "") return null;
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? new Date(value) : null;
  if (typeof value === "number" || (typeof value === "string" && /^\d+(?:\.\d+)?$/.test(value.trim()))) {
    const numeric = Number(value);
    const parsed = new Date(numeric < 10_000_000_000 ? numeric * 1_000 : numeric);
    return Number.isFinite(parsed.getTime()) ? parsed : null;
  }
  const parsed = new Date(String(value));
  return Number.isFinite(parsed.getTime()) ? parsed : null;
}

function hostSetHash(hosts: readonly ManagedHost[]): string {
  const hostIds = hosts.map((host) => host.id).sort((left, right) => left - right);
  return crypto.createHash("sha256")
    .update("forwardx-global-port-host-set:v1\n")
    .update(JSON.stringify(hostIds))
    .digest("hex");
}

function leaseOwnerHash(): string {
  return crypto.createHash("sha256")
    .update("forwardx-global-port-reclaim-lease:v1\n")
    .update(crypto.randomUUID())
    .digest("hex");
}

async function managedHosts(): Promise<ManagedHost[]> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Row>(
    `SELECT ${q("id")}, ${q("userId")} FROM ${q("hosts")} ORDER BY ${q("id")} ASC`,
  );
  return rows.flatMap((row) => {
    const id = positiveInteger(row.id);
    const userId = positiveInteger(row.userId);
    return id && userId ? [{ id, userId }] : [];
  });
}

async function acquireLease(ownerHash: string, now: Date): Promise<boolean> {
  const q = quoteIdentifier;
  const result = await executeRaw(
    `UPDATE ${q("global_port_scan_leases")}
        SET ${q("leaseOwnerHash")} = ?, ${q("leaseUntil")} = ?, ${q("lastStartedAt")} = ?, ${q("updatedAt")} = ?
      WHERE ${q("scopeKey")} = ?
        AND (${q("leaseUntil")} IS NULL OR ${q("leaseUntil")} <= ?)
        AND (${q("lastStartedAt")} IS NULL OR ${q("lastStartedAt")} <= ?)`,
    [ownerHash, new Date(now.getTime() + LEASE_TTL_MS), now, now, LEASE_SCOPE, now,
      new Date(now.getTime() - SCAN_INTERVAL_MS)],
  );
  return rawAffectedRows(result) === 1;
}

async function releaseLease(ownerHash: string, now: Date): Promise<void> {
  const q = quoteIdentifier;
  await executeRaw(
    `UPDATE ${q("global_port_scan_leases")}
        SET ${q("leaseOwnerHash")} = NULL, ${q("leaseUntil")} = NULL,
            ${q("lastFinishedAt")} = ?, ${q("updatedAt")} = ?
      WHERE ${q("scopeKey")} = ? AND ${q("leaseOwnerHash")} = ?`,
    [now, now, LEASE_SCOPE, ownerHash],
  );
}

async function eligibleAllocations(now: Date, batchSize: number): Promise<AllocationCandidate[]> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Row>(
    `SELECT a.${q("id")}, a.${q("port")}
       FROM ${q("global_port_allocations")} a
      WHERE a.${q("status")} IN ('PENDING_SCAN', 'EXTERNAL_OCCUPIED')
        AND (a.${q("scanNotBefore")} IS NULL OR a.${q("scanNotBefore")} <= ?)
        AND NOT EXISTS (
          SELECT 1 FROM ${q("global_port_allocation_references")} r
           WHERE r.${q("allocationId")} = a.${q("id")}
        )
      ORDER BY a.${q("scanNotBefore")} ASC, a.${q("id")} ASC
      LIMIT ?`,
    [now, batchSize],
  );
  return rows.flatMap((row) => {
    const id = positiveInteger(row.id);
    const port = positiveInteger(row.port);
    return id && port && port <= 65_535 ? [{ id, port }] : [];
  });
}

async function hasListenerDrift(port: number): Promise<boolean> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Row>(
    `SELECT (
       (SELECT COUNT(*) FROM ${q("xray_inbounds")} WHERE ${q("listenPort")} = ?)
       + (SELECT COUNT(*) FROM ${q("forward_rules")} WHERE ${q("sourcePort")} = ? OR ${q("tunnelExitPort")} = ?)
     ) AS ${q("count")}`,
    [port, port, port],
  );
  return Number(rows[0]?.count ?? 0) > 0;
}

function safePreflightError(error: unknown): { status: ProbeStatus; errorCode: string } {
  const code = error instanceof XrayPortOperationError ? error.code : "INTERNAL_ERROR";
  if (code === "HOST_OFFLINE" || code === "HOST_NOT_FOUND") return { status: "OFFLINE", errorCode: "HOST_OFFLINE" };
  if (code === "AGENT_CAPABILITY_MISSING" || code === "UDP_CAPABILITY_REQUIRED") {
    return { status: "UNSUPPORTED", errorCode: code };
  }
  if (code === "PORT_IN_USE") return { status: "OCCUPIED", errorCode: "PORT_IN_USE" };
  return { status: "ERROR", errorCode: "INTERNAL_ERROR" };
}

function terminalProbeStatus(result: Awaited<ReturnType<typeof getXrayPortProbeOperationResult>>): ProbeStatus | null {
  if (result.status === "SUCCESS") return result.selectedPort ? "FREE" : "ERROR";
  if (result.status === "TIMEOUT") return "EXPIRED";
  if (result.status !== "FAILED" && result.status !== "CANCELLED") return null;
  if (result.errorCode === "PORT_IN_USE") return "OCCUPIED";
  if (result.errorCode === "HOST_OFFLINE") return "OFFLINE";
  if (result.errorCode === "AGENT_CAPABILITY_MISSING" || result.errorCode === "UDP_CAPABILITY_REQUIRED") {
    return "UNSUPPORTED";
  }
  if (result.errorCode === "TASK_EXPIRED") return "EXPIRED";
  return "ERROR";
}

async function insertPreflightFailureOperation(input: {
  host: ManagedHost;
  network: ProbeNetwork;
  port: number;
  errorCode: string;
  now: Date;
}): Promise<string> {
  const operationId = crypto.randomUUID();
  await insertAndGetId("xray_operations", {
    operationId,
    hostId: input.host.id,
    inboundId: null,
    type: "PORT_PROBE",
    status: "FAILED",
    requestMetaJson: JSON.stringify({
      schemaVersion: 1,
      mode: "MANUAL",
      network: input.network,
      candidates: [input.port],
    }),
    resultJson: null,
    errorCode: input.errorCode,
    errorMessage: null,
    attemptCount: 0,
    createdByUserId: input.host.userId,
    createdAt: input.now,
    startedAt: input.now,
    finishedAt: input.now,
    expiresAt: input.now,
    updatedAt: input.now,
  });
  return operationId;
}

async function probeOne(input: {
  host: ManagedHost;
  network: ProbeNetwork;
  port: number;
  deadline: Date;
}): Promise<ProbeOutcome> {
  let operationId: string;
  try {
    ({ operationId } = await createXrayPortProbeOperation({
      hostId: input.host.id,
      userId: input.host.userId,
      mode: "MANUAL",
      manualPort: input.port,
      network: input.network,
    }));
  } catch (error) {
    const safe = safePreflightError(error);
    operationId = await insertPreflightFailureOperation({
      host: input.host,
      network: input.network,
      port: input.port,
      errorCode: safe.errorCode,
      now: nowDate(),
    });
    return { hostId: input.host.id, network: input.network, operationId, status: safe.status };
  }

  try {
    while (Date.now() < input.deadline.getTime()) {
      const result = await getXrayPortProbeOperationResult(operationId, input.host.userId);
      const status = terminalProbeStatus(result);
      if (status) {
        if (status === "FREE" && result.reservationId && result.selectedPort === input.port) {
          try {
            const released = releaseXrayPortProbeReservation({
              reservationId: result.reservationId,
              hostId: input.host.id,
              userId: input.host.userId,
              port: input.port,
              network: input.network,
            });
            if (!released) throw new Error("reservation unavailable");
          } catch {
            return { hostId: input.host.id, network: input.network, operationId, status: "ERROR" };
          }
        }
        return {
          hostId: input.host.id,
          network: input.network,
          operationId,
          status: status === "FREE" && result.selectedPort !== input.port ? "ERROR" : status,
        };
      }
      await new Promise<void>((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
    }
  } catch {
    return { hostId: input.host.id, network: input.network, operationId, status: "ERROR" };
  }
  return { hostId: input.host.id, network: input.network, operationId, status: "EXPIRED" };
}

async function probeHost(input: {
  host: ManagedHost;
  port: number;
  deadline: Date;
}): Promise<ProbeOutcome[]> {
  return Promise.all((["tcp", "udp"] as const).map((network) => probeOne({ ...input, network })));
}

async function probeHostsBounded(input: {
  hosts: readonly ManagedHost[];
  port: number;
  deadline: Date;
}): Promise<ProbeOutcome[]> {
  const outcomes: ProbeOutcome[] = [];
  let cursor = 0;
  const worker = async () => {
    while (cursor < input.hosts.length) {
      const host = input.hosts[cursor];
      cursor += 1;
      outcomes.push(...await probeHost({ host, port: input.port, deadline: input.deadline }));
    }
  };
  await Promise.all(Array.from({ length: Math.min(HOST_CONCURRENCY, input.hosts.length) }, worker));
  return outcomes;
}

async function startProbeRun(input: {
  allocationId: number;
  port: number;
  hosts: readonly ManagedHost[];
  now: Date;
}): Promise<{ runId: number; allocationVersion: number; expiresAt: Date } | null> {
  return withDatabaseTransaction(async () => {
    const q = quoteIdentifier;
    const rows = await queryRaw<Row>(
      `SELECT * FROM ${q("global_port_allocations")} WHERE ${q("id")} = ? LIMIT 1`,
      [input.allocationId],
    );
    const row = rows[0];
    const version = positiveInteger(row?.version);
    if (!row || Number(row.port) !== input.port || !version
      || (row.status !== "PENDING_SCAN" && row.status !== "EXTERNAL_OCCUPIED")) return null;
    const references = await queryRaw<Row>(
      `SELECT COUNT(*) AS ${q("count")} FROM ${q("global_port_allocation_references")} WHERE ${q("allocationId")} = ?`,
      [input.allocationId],
    );
    if (Number(references[0]?.count ?? 0) !== 0) return null;

    const changed = await executeRaw(
      `UPDATE ${q("global_port_allocations")}
          SET ${q("lastScanStartedAt")} = ?, ${q("lastErrorCode")} = NULL,
              ${q("version")} = ${q("version")} + 1, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("version")} = ?
          AND ${q("status")} IN ('PENDING_SCAN', 'EXTERNAL_OCCUPIED')`,
      [input.now, input.now, input.allocationId, version],
    );
    if (rawAffectedRows(changed) !== 1) return null;
    const allocationVersion = version + 1;
    const expiresAt = new Date(input.now.getTime() + RUN_TTL_MS);
    const runId = await insertAndGetId("global_port_probe_runs", {
      probeTag: `global-port-reclaim:v1:${input.allocationId}:${allocationVersion}:${crypto.randomUUID()}`,
      allocationId: input.allocationId,
      allocationVersion,
      candidatePort: input.port,
      purpose: "RECLAIM",
      status: "RUNNING",
      hostSetHash: hostSetHash(input.hosts),
      expectedHostCount: input.hosts.length,
      createdByUserId: null,
      startedAt: input.now,
      finishedAt: null,
      expiresAt,
      errorCode: null,
    });
    return { runId, allocationVersion, expiresAt };
  });
}

async function persistOutcomes(runId: number, outcomes: readonly ProbeOutcome[], expiresAt: Date): Promise<void> {
  for (const outcome of outcomes) {
    await insertAndGetId("global_port_probe_results", {
      probeRunId: runId,
      hostId: outcome.hostId,
      network: outcome.network,
      xrayOperationId: outcome.operationId,
      status: outcome.status,
      probedAt: nowDate(),
      expiresAt,
    });
  }
}

async function failRun(runId: number, errorCode: string, now: Date): Promise<void> {
  const q = quoteIdentifier;
  await executeRaw(
    `UPDATE ${q("global_port_probe_runs")}
        SET ${q("status")} = 'FAILED', ${q("finishedAt")} = ?, ${q("errorCode")} = ?
      WHERE ${q("id")} = ? AND ${q("status")} = 'RUNNING'`,
    [now, errorCode, runId],
  );
}

async function finalizeProbeRun(input: {
  runId: number;
  allocationId: number;
  allocationVersion: number;
  expectedHosts: readonly ManagedHost[];
  leaseOwnerHash: string;
  now: Date;
}): Promise<"FREE" | "OCCUPIED" | "DEFERRED"> {
  return withDatabaseTransaction(async () => {
    const q = quoteIdentifier;
    const runRows = await queryRaw<Row>(
      `SELECT * FROM ${q("global_port_probe_runs")} WHERE ${q("id")} = ? LIMIT 1`,
      [input.runId],
    );
    const run = runRows[0];
    const allocationRows = await queryRaw<Row>(
      `SELECT * FROM ${q("global_port_allocations")} WHERE ${q("id")} = ? LIMIT 1`,
      [input.allocationId],
    );
    const allocation = allocationRows[0];
    const leaseRows = await queryRaw<Row>(
      `SELECT ${q("leaseOwnerHash")}, ${q("leaseUntil")} FROM ${q("global_port_scan_leases")} WHERE ${q("scopeKey")} = ? LIMIT 1`,
      [LEASE_SCOPE],
    );
    const references = await queryRaw<Row>(
      `SELECT COUNT(*) AS ${q("count")} FROM ${q("global_port_allocation_references")} WHERE ${q("allocationId")} = ?`,
      [input.allocationId],
    );
    const listenerDrift = allocation ? await hasListenerDrift(Number(allocation.port)) : true;
    const currentHosts = await managedHosts();
    const results = await queryRaw<Row>(
      `SELECT ${q("hostId")}, ${q("network")}, ${q("status")}, ${q("expiresAt")}
         FROM ${q("global_port_probe_results")} WHERE ${q("probeRunId")} = ?`,
      [input.runId],
    );
    const leaseUntil = databaseDate(leaseRows[0]?.leaseUntil);
    const validLease = leaseRows[0]?.leaseOwnerHash === input.leaseOwnerHash
      && !!leaseUntil && leaseUntil.getTime() > input.now.getTime();
    const expectedHash = hostSetHash(input.expectedHosts);
    const currentHash = hostSetHash(currentHosts);
    const expectedKeys = new Set(input.expectedHosts.flatMap((host) => [`${host.id}:tcp`, `${host.id}:udp`]));
    const resultKeys = new Set(results.map((result) => `${Number(result.hostId)}:${String(result.network)}`));
    const resultsComplete = results.length === expectedKeys.size && resultKeys.size === expectedKeys.size
      && [...expectedKeys].every((key) => resultKeys.has(key))
      && results.every((result) => {
        const expiresAt = databaseDate(result.expiresAt);
        return expiresAt !== null && expiresAt.getTime() > input.now.getTime();
      });
    const validSnapshot = run?.status === "RUNNING"
      && Number(run.allocationVersion) === input.allocationVersion
      && Number(run.expectedHostCount) === input.expectedHosts.length
      && run.hostSetHash === expectedHash
      && allocation && Number(allocation.version) === input.allocationVersion
      && (allocation.status === "PENDING_SCAN" || allocation.status === "EXTERNAL_OCCUPIED")
      && Number(references[0]?.count ?? 0) === 0
      && !listenerDrift
      && currentHosts.length === input.expectedHosts.length
      && currentHash === expectedHash
      && resultsComplete
      && validLease;
    if (!validSnapshot) {
      await failRun(input.runId, "GLOBAL_PORT_SCAN_STALE", input.now);
      return "DEFERRED";
    }

    const hasOccupied = results.some((result) => result.status === "OCCUPIED");
    const allFree = results.length > 0 && results.every((result) => result.status === "FREE");
    const nextScan = new Date(input.now.getTime() + SCAN_INTERVAL_MS);
    if (allFree) {
      const changed = await executeRaw(
        `UPDATE ${q("global_port_allocations")}
            SET ${q("status")} = 'FREE', ${q("primaryOwnerType")} = NULL, ${q("primaryOwnerTag")} = NULL,
                ${q("reservationTokenHash")} = NULL, ${q("reservedUntil")} = NULL, ${q("scanNotBefore")} = NULL,
                ${q("lastScanFinishedAt")} = ?, ${q("lastErrorCode")} = NULL,
                ${q("version")} = ${q("version")} + 1, ${q("updatedAt")} = ?
          WHERE ${q("id")} = ? AND ${q("version")} = ?
            AND ${q("status")} IN ('PENDING_SCAN', 'EXTERNAL_OCCUPIED')`,
        [input.now, input.now, input.allocationId, input.allocationVersion],
      );
      if (rawAffectedRows(changed) !== 1) {
        await failRun(input.runId, "GLOBAL_PORT_SCAN_STALE", input.now);
        return "DEFERRED";
      }
      await executeRaw(
        `UPDATE ${q("global_port_probe_runs")} SET ${q("status")} = 'SUCCESS', ${q("finishedAt")} = ?, ${q("errorCode")} = NULL WHERE ${q("id")} = ? AND ${q("status")} = 'RUNNING'`,
        [input.now, input.runId],
      );
      return "FREE";
    }

    const errorCode = hasOccupied ? "GLOBAL_PORT_EXTERNAL_OCCUPIED" : "GLOBAL_PORT_PROBE_FAILED";
    const nextStatus = hasOccupied ? "EXTERNAL_OCCUPIED" : String(allocation.status);
    const changed = await executeRaw(
      `UPDATE ${q("global_port_allocations")}
          SET ${q("status")} = ?, ${q("scanNotBefore")} = ?, ${q("lastScanFinishedAt")} = ?,
              ${q("lastErrorCode")} = ?, ${q("version")} = ${q("version")} + 1, ${q("updatedAt")} = ?
        WHERE ${q("id")} = ? AND ${q("version")} = ?
          AND ${q("status")} IN ('PENDING_SCAN', 'EXTERNAL_OCCUPIED')`,
      [nextStatus, nextScan, input.now, errorCode, input.now, input.allocationId, input.allocationVersion],
    );
    if (rawAffectedRows(changed) !== 1) {
      await failRun(input.runId, "GLOBAL_PORT_SCAN_STALE", input.now);
      return "DEFERRED";
    }
    await executeRaw(
      `UPDATE ${q("global_port_probe_runs")} SET ${q("status")} = ?, ${q("finishedAt")} = ?, ${q("errorCode")} = ? WHERE ${q("id")} = ? AND ${q("status")} = 'RUNNING'`,
      [hasOccupied ? "SUCCESS" : "FAILED", input.now, hasOccupied ? null : errorCode, input.runId],
    );
    return hasOccupied ? "OCCUPIED" : "DEFERRED";
  });
}

async function markDriftDeferred(allocationId: number, now: Date): Promise<void> {
  const q = quoteIdentifier;
  await executeRaw(
    `UPDATE ${q("global_port_allocations")}
        SET ${q("lastScanStartedAt")} = ?, ${q("lastScanFinishedAt")} = ?,
            ${q("lastErrorCode")} = 'GLOBAL_PORT_REFERENCE_DRIFT', ${q("scanNotBefore")} = ?,
            ${q("version")} = ${q("version")} + 1, ${q("updatedAt")} = ?
      WHERE ${q("id")} = ? AND ${q("status")} IN ('PENDING_SCAN', 'EXTERNAL_OCCUPIED')
        AND NOT EXISTS (
          SELECT 1 FROM ${q("global_port_allocation_references")} r
           WHERE r.${q("allocationId")} = ${q("global_port_allocations")}.${q("id")}
        )`,
    [now, now, new Date(now.getTime() + SCAN_INTERVAL_MS), now, allocationId],
  );
}

async function scanAllocation(input: {
  candidate: AllocationCandidate;
  leaseOwnerHash: string;
}): Promise<"FREE" | "OCCUPIED" | "DEFERRED"> {
  const startedAt = nowDate();
  if (await hasListenerDrift(input.candidate.port)) {
    await markDriftDeferred(input.candidate.id, startedAt);
    return "DEFERRED";
  }
  const hosts = await managedHosts();
  const run = await startProbeRun({
    allocationId: input.candidate.id,
    port: input.candidate.port,
    hosts,
    now: startedAt,
  });
  if (!run) return "DEFERRED";
  try {
    const outcomes = await probeHostsBounded({ hosts, port: input.candidate.port, deadline: run.expiresAt });
    await persistOutcomes(run.runId, outcomes, run.expiresAt);
    return finalizeProbeRun({
      runId: run.runId,
      allocationId: input.candidate.id,
      allocationVersion: run.allocationVersion,
      expectedHosts: hosts,
      leaseOwnerHash: input.leaseOwnerHash,
      now: nowDate(),
    });
  } catch {
    await failRun(run.runId, "GLOBAL_PORT_PROBE_FAILED", nowDate());
    return "DEFERRED";
  }
}

export async function runGlobalPortReclaimScan(input: {
  batchSize?: number;
  now?: Date;
} = {}): Promise<GlobalPortReclaimScanSummary> {
  const batchSize = Math.max(1, Math.min(32, Math.floor(Number(input.batchSize ?? DEFAULT_BATCH_SIZE))));
  const startedAt = input.now ?? nowDate();
  const ownerHash = leaseOwnerHash();
  if (!await acquireLease(ownerHash, startedAt)) {
    return { acquired: false, scanned: 0, freed: 0, occupied: 0, deferred: 0 };
  }
  const summary = { acquired: true, scanned: 0, freed: 0, occupied: 0, deferred: 0 };
  try {
    const candidates = await eligibleAllocations(startedAt, batchSize);
    for (const candidate of candidates) {
      const result = await scanAllocation({ candidate, leaseOwnerHash: ownerHash });
      summary.scanned += 1;
      if (result === "FREE") summary.freed += 1;
      else if (result === "OCCUPIED") summary.occupied += 1;
      else summary.deferred += 1;
    }
    return summary;
  } finally {
    await releaseLease(ownerHash, nowDate());
  }
}
