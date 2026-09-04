import crypto from "node:crypto";

import {
  XRAY_AGENT_ERROR_CODES,
  XRAY_LIMITS,
  XrayCapabilitySchema,
  XrayDesiredStateSchema,
  XrayObservedListenerSchema,
  XrayObservedStateSchema,
  type XrayDesiredState,
  type XrayObservedListener,
  type XrayObservedState,
} from "../shared/xrayTypes";
import { resolveStoredXrayInboundDefinition } from "../shared/xrayProfiles";
import { quoteIdentifier } from "./dbCompat";
import { executeRaw, insertAndGetId, nowDate, queryRaw, withDatabaseTransaction } from "./dbRuntime";
import { withKeyedTaskLock } from "./keyedTaskLock";
import { generateXrayHostConfig } from "./xrayConfigGenerator";
import {
  deleteAppliedPendingXrayRecordsWithinHostLock,
  reconcileAppliedXrayInboundGlobalPortsWithinHostLock,
} from "./repositories/xrayRepository";
import type { XraySecretKeyring } from "./xraySecretCrypto";

const STABLE_XRAY_AGENT_ERROR_CODES = new Set<string>(XRAY_AGENT_ERROR_CODES);
const GENERIC_XRAY_RUNTIME_ERROR = "Managed Xray runtime reported an error";

type XrayRuntimeReportRow = Record<string, unknown> & {
  id?: unknown;
  hostId?: unknown;
  capabilitySchemaVersion?: unknown;
  supportedOS?: unknown;
  supportedArch?: unknown;
  supportsArtifactInstall?: unknown;
  supportsPortProbe?: unknown;
  supportsUdpPortProbe?: unknown;
  supportsUdpListenerReadiness?: unknown;
  supportsRealityScan?: unknown;
  capabilityErrorCode?: unknown;
  isInstalled?: unknown;
  installedVersion?: unknown;
  runningVersion?: unknown;
  serviceStatus?: unknown;
  processId?: unknown;
  appliedGeneration?: unknown;
  appliedConfigHash?: unknown;
  binarySha256?: unknown;
  listenersJson?: unknown;
  reportSignature?: unknown;
  lastErrorCode?: unknown;
  lastErrorMessage?: unknown;
  reportedAt?: unknown;
  updatedAt?: unknown;
};

export type XrayHeartbeatObservedState = Pick<XrayObservedState,
  | "isInstalled"
  | "installedVersion"
  | "runningVersion"
  | "serviceStatus"
  | "processId"
  | "binarySha256"
  | "appliedGeneration"
  | "appliedConfigHash"
  | "listeners"
> & { reportSignature: string };

export type XrayHeartbeatReportResult = {
  compatible: boolean;
  capabilityChanged: boolean;
  requestXrayState: boolean;
  xrayStateSignature: string;
  observedState: XrayHeartbeatObservedState | null;
};

function positiveId(value: unknown): number {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) throw new Error("Invalid Xray host identity");
  return id;
}

function safeErrorCode(value: unknown): string {
  const code = String(value ?? "");
  return STABLE_XRAY_AGENT_ERROR_CODES.has(code) ? code : "INTERNAL_ERROR";
}

function databaseBoolean(value: unknown): boolean | null {
  if (value === true || value === 1 || value === "1" || value === "true") return true;
  if (value === false || value === 0 || value === "0" || value === "false") return false;
  return null;
}

function nullableString(value: unknown): string | null {
  if (value === null || value === undefined || value === "") return null;
  return String(value);
}

function nullablePositiveInteger(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function reportColumns() {
  return [
    "id", "hostId", "capabilitySchemaVersion", "supportedOS", "supportedArch", "supportsArtifactInstall",
    "supportsPortProbe", "supportsUdpPortProbe", "supportsUdpListenerReadiness", "supportsRealityScan", "capabilityErrorCode",
    "isInstalled", "installedVersion", "runningVersion", "serviceStatus",
    "processId", "appliedGeneration", "appliedConfigHash", "binarySha256", "listenersJson", "reportSignature",
    "lastErrorCode", "lastErrorMessage", "reportedAt", "updatedAt",
  ];
}

async function getRuntimeReport(hostId: number): Promise<XrayRuntimeReportRow | null> {
  const q = quoteIdentifier;
  const rows = await queryRaw<XrayRuntimeReportRow>(
    `SELECT ${reportColumns().map(q).join(", ")} FROM ${q("xray_runtime_reports")} WHERE ${q("hostId")} = ? LIMIT 1`,
    [hostId],
  );
  return rows[0] ?? null;
}

async function writeRuntimeReport(
  hostId: number,
  current: XrayRuntimeReportRow | null,
  values: Record<string, unknown>,
): Promise<XrayRuntimeReportRow> {
  const updatedAt = nowDate();
  if (current?.id) {
    const q = quoteIdentifier;
    const columns = Object.keys(values);
    await executeRaw(
      `UPDATE ${q("xray_runtime_reports")} SET ${columns.map((column) => `${q(column)} = ?`).join(", ")}, ${q("updatedAt")} = ? WHERE ${q("id")} = ?`,
      [...columns.map((column) => values[column]), updatedAt, Number(current.id)],
    );
  } else {
    await insertAndGetId("xray_runtime_reports", { hostId, ...values, updatedAt });
  }
  return (await getRuntimeReport(hostId))!;
}

function safeListeners(listeners: XrayObservedListener[]): XrayObservedListener[] {
  return listeners.map((listener) => ({
    runtimeTag: listener.runtimeTag,
    network: listener.network,
    port: listener.port,
    status: listener.status,
    errorCode: listener.errorCode ? safeErrorCode(listener.errorCode) : null,
  })).sort((left, right) => (
    left.runtimeTag < right.runtimeTag ? -1 : left.runtimeTag > right.runtimeTag ? 1
      : left.network < right.network ? -1 : left.network > right.network ? 1 : left.port - right.port
  ));
}

function projectedObservedState(state: XrayObservedState, reportSignature: string): XrayHeartbeatObservedState {
  return {
    reportSignature,
    isInstalled: state.isInstalled,
    installedVersion: state.installedVersion,
    runningVersion: state.runningVersion,
    serviceStatus: state.serviceStatus,
    processId: state.processId,
    binarySha256: state.binarySha256,
    appliedGeneration: state.appliedGeneration,
    appliedConfigHash: state.appliedConfigHash,
    listeners: safeListeners(state.listeners),
  };
}

function observedStateFromRow(row: XrayRuntimeReportRow | null): XrayHeartbeatObservedState | null {
  const reportSignature = String(row?.reportSignature ?? "");
  if (!/^[0-9a-f]{64}$/.test(reportSignature)) return null;
  try {
    const isInstalled = databaseBoolean(row?.isInstalled);
    const serviceStatus = String(row?.serviceStatus ?? "");
    const appliedGeneration = Number(row?.appliedGeneration);
    if (isInstalled === null || !["RUNNING", "STOPPED", "ERROR", "UNKNOWN"].includes(serviceStatus)) return null;
    if (!Number.isSafeInteger(appliedGeneration) || appliedGeneration < 0) return null;
    const rawListeners = JSON.parse(String(row?.listenersJson ?? "[]"));
    if (!Array.isArray(rawListeners) || rawListeners.length > XRAY_LIMITS.maxExpectedListeners) return null;
    const parsedListeners = rawListeners.map((listener) => XrayObservedListenerSchema.safeParse(listener));
    if (parsedListeners.some((listener) => !listener.success)) return null;
    const listeners = safeListeners(parsedListeners.map((listener) => listener.data!));
    const parsedState = XrayObservedStateSchema.safeParse({
      schemaVersion: 1,
      isInstalled,
      installedVersion: nullableString(row?.installedVersion),
      runningVersion: nullableString(row?.runningVersion),
      serviceStatus: serviceStatus as XrayObservedState["serviceStatus"],
      processId: nullablePositiveInteger(row?.processId),
      binarySha256: nullableString(row?.binarySha256),
      appliedGeneration,
      appliedConfigHash: nullableString(row?.appliedConfigHash),
      listeners,
      lastError: null,
      observedAt: "1970-01-01T00:00:00.000Z",
    });
    return parsedState.success ? projectedObservedState(parsedState.data, reportSignature) : null;
  } catch {
    return null;
  }
}

type StoredExpectedListener = {
  runtimeTag: string;
  network: "tcp" | "udp";
  port: number;
};

async function loadStoredExpectedListeners(hostId: number): Promise<StoredExpectedListener[] | null> {
  const q = quoteIdentifier;
  const columns = [
    "runtimeTag", "listenPort", "protocol", "transport", "security", "profileId", "specVersion", "specJson",
    "isEnabled", "pendingDelete",
  ];
  const rows = await queryRaw<Record<string, unknown>>(
    `SELECT ${columns.map(q).join(", ")} FROM ${q("xray_inbounds")} WHERE ${q("hostId")} = ?`,
    [hostId],
  );
  const listeners: StoredExpectedListener[] = [];
  for (const row of rows) {
    if (!databaseBoolean(row.isEnabled) || databaseBoolean(row.pendingDelete)) continue;
    const definition = resolveStoredXrayInboundDefinition({
      protocol: row.protocol,
      transport: row.transport,
      security: row.security,
      profileId: row.profileId,
      specVersion: row.specVersion,
      specJson: row.specJson,
    });
    if (!definition) return null;
    for (const declaredNetwork of definition.profile.listenerNetworks) {
      const network = declaredNetwork === "TCP" ? "tcp" : declaredNetwork === "UDP" ? "udp" : null;
      if (!network) return null;
      listeners.push({ runtimeTag: String(row.runtimeTag), network, port: Number(row.listenPort) });
    }
  }
  return listeners.sort((left, right) => (
    left.runtimeTag < right.runtimeTag ? -1 : left.runtimeTag > right.runtimeTag ? 1
      : left.network < right.network ? -1 : left.network > right.network ? 1 : left.port - right.port
  ));
}

export function xrayObservedStateSignature(value: unknown): string {
  const parsed = XrayObservedStateSchema.parse(value);
  const signatureState = {
    schemaVersion: parsed.schemaVersion,
    isInstalled: parsed.isInstalled,
    installedVersion: parsed.installedVersion,
    runningVersion: parsed.runningVersion,
    serviceStatus: parsed.serviceStatus,
    processId: parsed.processId,
    binarySha256: parsed.binarySha256,
    appliedGeneration: parsed.appliedGeneration,
    appliedConfigHash: parsed.appliedConfigHash,
    listeners: parsed.listeners,
    lastError: parsed.lastError ? { ...parsed.lastError, occurredAt: "" } : null,
    observedAt: "",
  };
  return crypto.createHash("sha256").update(JSON.stringify(signatureState), "utf8").digest("hex");
}

async function reconcileDesiredOperation(hostId: number, state: XrayObservedState) {
  const q = quoteIdentifier;
  const deployments = await queryRaw<Record<string, unknown>>(
    `SELECT ${["desiredGeneration", "desiredConfigHash", "lastOperationId", "targetVersion"].map(q).join(", ")}
       FROM ${q("xray_host_deployments")} WHERE ${q("hostId")} = ? LIMIT 1`,
    [hostId],
  );
  const deployment = deployments[0];
  if (!deployment?.lastOperationId) return;
  const desiredGeneration = Number(deployment.desiredGeneration ?? 0);
  const desiredConfigHash = String(deployment.desiredConfigHash ?? "");
  const operationId = String(deployment.lastOperationId);
  const finishedAt = nowDate();
  const storedExpectedListeners = await loadStoredExpectedListeners(hostId);
  if (!storedExpectedListeners) return;
  const expectedListeners = storedExpectedListeners
    .map((listener) => `${listener.runtimeTag}:${listener.network}:${listener.port}`)
    .sort();
  const actualReadyListeners = state.listeners
    .filter((listener) => listener.status === "READY")
    .map((listener) => `${listener.runtimeTag}:${listener.network}:${listener.port}`)
    .sort();
  const targetVersion = String(deployment.targetVersion ?? "");
  const runtimeReady = expectedListeners.length === 0
    ? state.isInstalled && state.installedVersion === targetVersion && state.serviceStatus === "STOPPED"
      && state.processId === null && state.listeners.length === 0
    : state.isInstalled && state.installedVersion === targetVersion && state.runningVersion === targetVersion
      && state.serviceStatus === "RUNNING" && !!state.processId && !!state.binarySha256
      && JSON.stringify(actualReadyListeners) === JSON.stringify(expectedListeners)
      && state.listeners.length === expectedListeners.length;
  if (state.appliedGeneration === desiredGeneration && state.appliedConfigHash === desiredConfigHash && desiredConfigHash && runtimeReady) {
    await executeRaw(
      `UPDATE ${q("xray_operations")}
          SET ${q("status")} = ?, ${q("errorCode")} = NULL, ${q("errorMessage")} = NULL,
              ${q("finishedAt")} = ?, ${q("updatedAt")} = ?
        WHERE ${q("operationId")} = ? AND ${q("hostId")} = ? AND ${q("type")} IN (?, ?)
          AND ${q("requestedGeneration")} = ? AND ${q("status")} IN (?, ?)`,
      ["SUCCESS", finishedAt, finishedAt, operationId, hostId, "SYNC", "UPGRADE", desiredGeneration, "QUEUED", "RUNNING"],
    );
    await reconcileAppliedXrayInboundGlobalPortsWithinHostLock(hostId, desiredGeneration);
    await deleteAppliedPendingXrayRecordsWithinHostLock(hostId, desiredGeneration);
    return;
  }
  if (state.lastError && state.lastError.generation === desiredGeneration) {
    await executeRaw(
      `UPDATE ${q("xray_operations")}
          SET ${q("status")} = ?, ${q("errorCode")} = ?, ${q("errorMessage")} = ?,
              ${q("finishedAt")} = ?, ${q("updatedAt")} = ?
        WHERE ${q("operationId")} = ? AND ${q("hostId")} = ? AND ${q("type")} IN (?, ?)
          AND ${q("requestedGeneration")} = ? AND ${q("status")} IN (?, ?)`,
      ["FAILED", safeErrorCode(state.lastError.code), GENERIC_XRAY_RUNTIME_ERROR, finishedAt, finishedAt,
        operationId, hostId, "SYNC", "UPGRADE", desiredGeneration, "QUEUED", "RUNNING"],
    );
  }
}

async function persistCapabilityWithinLock(
  hostId: number,
  current: XrayRuntimeReportRow | null,
  rawCapability: unknown,
) {
  if (rawCapability === undefined) {
    return { current, compatible: Number(current?.capabilitySchemaVersion ?? 0) === 1, changed: false };
  }
  const parsed = XrayCapabilitySchema.safeParse(rawCapability);
  const capabilitySchemaVersion = parsed.success && parsed.data.supported ? 1 : 0;
  const supportedOS = parsed.success ? parsed.data.supportedOS : null;
  const supportedArch = parsed.success ? parsed.data.supportedArch : null;
  const supportsArtifactInstall = parsed.success && parsed.data.supported ? parsed.data.supportsArtifactInstall : false;
  const supportsPortProbe = parsed.success && parsed.data.supported ? parsed.data.supportsPortProbe : false;
  const supportsUdpPortProbe = parsed.success && parsed.data.supported ? parsed.data.supportsUdpPortProbe : false;
  const supportsUdpListenerReadiness = parsed.success && parsed.data.supported ? parsed.data.supportsUdpListenerReadiness : false;
  const supportsRealityScan = parsed.success && parsed.data.supported ? parsed.data.supportsRealityScan : false;
  const capabilityErrorCode = parsed.success && !parsed.data.supported && parsed.data.errorCode
    ? safeErrorCode(parsed.data.errorCode)
    : null;
  const changed = Number(current?.capabilitySchemaVersion ?? 0) !== capabilitySchemaVersion
    || nullableString(current?.supportedOS) !== supportedOS
    || nullableString(current?.supportedArch) !== supportedArch
    || databaseBoolean(current?.supportsArtifactInstall) !== supportsArtifactInstall
    || databaseBoolean(current?.supportsPortProbe) !== supportsPortProbe
    || databaseBoolean(current?.supportsUdpPortProbe) !== supportsUdpPortProbe
    || databaseBoolean(current?.supportsUdpListenerReadiness) !== supportsUdpListenerReadiness
    || databaseBoolean(current?.supportsRealityScan) !== supportsRealityScan
    || nullableString(current?.capabilityErrorCode) !== capabilityErrorCode;
  const next = await writeRuntimeReport(hostId, current, {
    capabilitySchemaVersion,
    supportedOS,
    supportedArch,
    supportsArtifactInstall,
    supportsPortProbe,
    supportsUdpPortProbe,
    supportsUdpListenerReadiness,
    supportsRealityScan,
    capabilityErrorCode,
  });
  return { current: next, compatible: capabilitySchemaVersion === 1, changed };
}

export async function persistXrayCapabilityReport(hostIdValue: unknown, rawCapability: unknown) {
  const hostId = positiveId(hostIdValue);
  return withKeyedTaskLock(`xray-host:${hostId}`, async () => {
    const current = await getRuntimeReport(hostId);
    const result = await persistCapabilityWithinLock(hostId, current, rawCapability);
    return { compatible: result.compatible, changed: result.changed };
  });
}

export async function processXrayHeartbeatReport(input: {
  hostId: unknown;
  xrayCapability?: unknown;
  xrayStateSignature?: unknown;
  xrayState?: unknown;
}): Promise<XrayHeartbeatReportResult> {
  const hostId = positiveId(input.hostId);
  return withKeyedTaskLock(`xray-host:${hostId}`, async () => {
    let current = await getRuntimeReport(hostId);
    const capability = await persistCapabilityWithinLock(hostId, current, input.xrayCapability);
    current = capability.current;
    if (!capability.compatible) {
      return {
        compatible: false,
        capabilityChanged: capability.changed,
        requestXrayState: false,
        xrayStateSignature: "",
        observedState: null,
      };
    }

    const rawSignature = String(input.xrayStateSignature ?? "");
    if (!/^[0-9a-f]{64}$/.test(rawSignature)) {
      return {
        compatible: true,
        capabilityChanged: capability.changed,
        requestXrayState: true,
        xrayStateSignature: "",
        observedState: null,
      };
    }
    if (input.xrayState === undefined) {
      const cached = current?.reportSignature === rawSignature ? observedStateFromRow(current) : null;
      return {
        compatible: true,
        capabilityChanged: capability.changed,
        requestXrayState: !cached,
        xrayStateSignature: rawSignature,
        observedState: cached,
      };
    }

    const parsed = XrayObservedStateSchema.safeParse(input.xrayState);
    if (!parsed.success || xrayObservedStateSignature(parsed.data) !== rawSignature) {
      return {
        compatible: true,
        capabilityChanged: capability.changed,
        requestXrayState: true,
        xrayStateSignature: rawSignature,
        observedState: null,
      };
    }
    const state = parsed.data;
    const listeners = safeListeners(state.listeners);
    current = await withDatabaseTransaction(async () => {
      const updated = await writeRuntimeReport(hostId, current, {
        capabilitySchemaVersion: 1,
        isInstalled: state.isInstalled,
        installedVersion: state.installedVersion,
        runningVersion: state.runningVersion,
        serviceStatus: state.serviceStatus,
        processId: state.processId,
        appliedGeneration: state.appliedGeneration,
        appliedConfigHash: state.appliedConfigHash,
        binarySha256: state.binarySha256,
        listenersJson: JSON.stringify(listeners),
        reportSignature: rawSignature,
        lastErrorCode: state.lastError ? safeErrorCode(state.lastError.code) : null,
        lastErrorMessage: state.lastError ? GENERIC_XRAY_RUNTIME_ERROR : null,
        reportedAt: new Date(state.observedAt),
      });
      await reconcileDesiredOperation(hostId, state);
      return updated;
    });
    return {
      compatible: true,
      capabilityChanged: capability.changed,
      requestXrayState: false,
      xrayStateSignature: rawSignature,
      observedState: projectedObservedState(state, rawSignature),
    };
  });
}

export async function buildXrayHeartbeatDesiredState(
  hostIdValue: unknown,
  options: { keyring?: XraySecretKeyring; issuedAt?: Date } = {},
): Promise<XrayDesiredState | null> {
  const hostId = positiveId(hostIdValue);
  return withKeyedTaskLock(`xray-host:${hostId}`, async () => {
    const q = quoteIdentifier;
    const rows = await queryRaw<Record<string, unknown>>(
      `SELECT ${["desiredGeneration", "desiredConfigHash", "targetVersion"].map(q).join(", ")}
         FROM ${q("xray_host_deployments")} WHERE ${q("hostId")} = ? LIMIT 1`,
      [hostId],
    );
    const deployment = rows[0];
    if (!deployment) return null;
    const generation = Number(deployment.desiredGeneration ?? 0);
    if (!Number.isSafeInteger(generation) || generation < 0) throw new Error("Invalid Xray desired generation");
    const storedExpectedListeners = await loadStoredExpectedListeners(hostId);
    if (storedExpectedListeners?.some((listener) => listener.network === "udp")) {
      const runtime = await getRuntimeReport(hostId);
      if (Number(runtime?.capabilitySchemaVersion ?? 0) !== 1
        || databaseBoolean(runtime?.supportsUdpPortProbe) !== true
        || databaseBoolean(runtime?.supportsUdpListenerReadiness) !== true) {
        return null;
      }
    }
    const generated = await generateXrayHostConfig(hostId, options.keyring);
    const storedHash = String(deployment.desiredConfigHash ?? "");
    if (storedHash && storedHash !== generated.configHash) throw new Error("Xray desired config hash conflicts with structured state");
    if (!storedHash || deployment.targetVersion !== generated.targetVersion) {
      await executeRaw(
        `UPDATE ${q("xray_host_deployments")}
            SET ${q("targetVersion")} = ?, ${q("desiredConfigHash")} = ?, ${q("updatedAt")} = ?
          WHERE ${q("hostId")} = ? AND ${q("desiredGeneration")} = ?`,
        [generated.targetVersion, generated.configHash, nowDate(), hostId, generation],
      );
    }
    return XrayDesiredStateSchema.parse({
      schemaVersion: 1,
      generation,
      issuedAt: (options.issuedAt ?? new Date()).toISOString(),
      targetVersion: generated.targetVersion,
      configHash: generated.configHash,
      configEncoding: "JSON_UTF8",
      configJson: generated.configJson,
      expectedListeners: generated.expectedListeners,
    });
  });
}

export function isXrayDesiredApplied(
  desired: XrayDesiredState | null | undefined,
  observed: XrayHeartbeatObservedState | null | undefined,
): boolean {
  if (!desired) return true;
  if (!observed || observed.appliedGeneration !== desired.generation || observed.appliedConfigHash !== desired.configHash) return false;
  if (!observed.isInstalled || observed.installedVersion !== desired.targetVersion) return false;
  if (desired.expectedListeners.length === 0) {
    return observed.serviceStatus === "STOPPED" && observed.processId === null && observed.listeners.length === 0;
  }
  if (observed.serviceStatus !== "RUNNING" || observed.runningVersion !== desired.targetVersion || !observed.processId || !observed.binarySha256) {
    return false;
  }
  if (observed.listeners.length !== desired.expectedListeners.length) return false;
  const actual = new Map(observed.listeners.map((listener) => [
    `${listener.runtimeTag}:${listener.network}:${listener.port}`,
    listener.status,
  ]));
  return desired.expectedListeners.every((listener) => (
    actual.get(`${listener.runtimeTag}:${listener.network}:${listener.port}`) === "READY"
  ));
}

export async function markXrayDesiredDispatched(hostIdValue: unknown, generationValue: unknown) {
  const hostId = positiveId(hostIdValue);
  const generation = Number(generationValue);
  if (!Number.isSafeInteger(generation) || generation < 0) return;
  const q = quoteIdentifier;
  const now = nowDate();
  await executeRaw(
    `UPDATE ${q("xray_operations")}
        SET ${q("status")} = ?, ${q("startedAt")} = ?, ${q("updatedAt")} = ?, ${q("attemptCount")} = ${q("attemptCount")} + 1
      WHERE ${q("hostId")} = ? AND ${q("type")} IN (?, ?) AND ${q("requestedGeneration")} = ? AND ${q("status")} = ?`,
    ["RUNNING", now, now, hostId, "SYNC", "UPGRADE", generation, "QUEUED"],
  );
}

export function clearXrayHeartbeatStateForTest() {
  // State is intentionally database-backed so panel restarts do not force a
  // full Agent upload. This hook keeps the test API symmetric with other caches.
}
