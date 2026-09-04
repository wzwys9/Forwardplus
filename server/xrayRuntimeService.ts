import crypto from "node:crypto";

import { compareVersions } from "./agentRouteUtils";
import { pushAgentRefresh } from "./agentEvents";
import { quoteIdentifier } from "./dbCompat";
import { executeRaw, insertAndGetId, nowDate, queryRaw, rawAffectedRows, withDatabaseTransaction } from "./dbRuntime";
import { generateXrayHostConfig } from "./xrayConfigGenerator";
import { listXrayRuntimeSummaries } from "./xrayQueryService";
import { recordXrayMutationObservability } from "./xrayMutationObservability";
import { withKeyedTaskLock } from "./keyedTaskLock";
import { XRAY_DEFAULT_VERSION } from "./xrayArtifacts";

export type XrayRuntimeServiceErrorCode =
  | "HOST_NOT_FOUND"
  | "HOST_OFFLINE"
  | "AGENT_CAPABILITY_MISSING"
  | "PLATFORM_UNSUPPORTED"
  | "ARTIFACT_UNAVAILABLE"
  | "RUNTIME_NOT_READY"
  | "XRAY_VERSION_MISMATCH"
  | "DOWNGRADE_NOT_ALLOWED"
  | "CONFIRMATION_MISMATCH"
  | "OPERATION_CONFLICT"
  | "INVALID_CONFIG_INPUT";

export class XrayRuntimeServiceError extends Error {
  constructor(readonly code: XrayRuntimeServiceErrorCode) {
    super(code);
    this.name = "XrayRuntimeServiceError";
  }
}

type RuntimeAction = "INSTALL" | "UPGRADE" | "RESTART";
type DeploymentRow = { id: number; desiredGeneration: number; desiredConfigHash: string | null; targetVersion: string | null };

function positiveId(value: unknown): number {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) throw new XrayRuntimeServiceError("HOST_NOT_FOUND");
  return id;
}

function userId(value: unknown): number {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) throw new XrayRuntimeServiceError("OPERATION_CONFLICT");
  return id;
}

function targetVersion(value: unknown): typeof XRAY_DEFAULT_VERSION {
  const version = String(value ?? XRAY_DEFAULT_VERSION).trim();
  if (version !== XRAY_DEFAULT_VERSION) throw new XrayRuntimeServiceError("INVALID_CONFIG_INPUT");
  return XRAY_DEFAULT_VERSION;
}

async function runtimeForHost(hostId: number) {
  const result = await listXrayRuntimeSummaries({ page: 1, pageSize: 1, hostId });
  const runtime = result.items[0];
  if (!runtime) throw new XrayRuntimeServiceError("HOST_NOT_FOUND");
  if (!runtime.isAgentOnline) throw new XrayRuntimeServiceError("HOST_OFFLINE");
  if (runtime.capabilityVersion !== 1 || runtime.unavailableReasonCode === "AGENT_UPGRADE_REQUIRED") {
    throw new XrayRuntimeServiceError("AGENT_CAPABILITY_MISSING");
  }
  if (runtime.unavailableReasonCode === "PLATFORM_UNSUPPORTED") throw new XrayRuntimeServiceError("PLATFORM_UNSUPPORTED");
  return runtime;
}

async function deploymentForHost(hostId: number): Promise<DeploymentRow | null> {
  const q = quoteIdentifier;
  const rows = await queryRaw<DeploymentRow>(
    `SELECT ${q("id")}, ${q("desiredGeneration")}, ${q("desiredConfigHash")}, ${q("targetVersion")}
       FROM ${q("xray_host_deployments")} WHERE ${q("hostId")} = ? LIMIT 1`,
    [hostId],
  );
  return rows[0] ?? null;
}

async function assertNoRuntimeOperation(hostId: number) {
  const q = quoteIdentifier;
  const rows = await queryRaw(
    `SELECT ${q("operationId")} FROM ${q("xray_operations")}
      WHERE ${q("hostId")} = ? AND ${q("type")} IN (?, ?, ?, ?) AND ${q("status")} IN (?, ?) LIMIT 1`,
    [hostId, "INSTALL", "UPGRADE", "SYNC", "RESTART", "QUEUED", "RUNNING"],
  );
  if (rows.length) throw new XrayRuntimeServiceError("OPERATION_CONFLICT");
}

async function hostName(hostId: number): Promise<string> {
  const q = quoteIdentifier;
  const rows = await queryRaw<{ name: string }>(`SELECT ${q("name")} FROM ${q("hosts")} WHERE ${q("id")} = ? LIMIT 1`, [hostId]);
  if (!rows[0]) throw new XrayRuntimeServiceError("HOST_NOT_FOUND");
  return String(rows[0].name ?? "");
}

async function createTaskOperation(input: {
  hostId: number;
  createdByUserId: number;
  type: RuntimeAction;
  version: typeof XRAY_DEFAULT_VERSION;
  validateRuntime: (runtime: Awaited<ReturnType<typeof runtimeForHost>>) => void | Promise<void>;
}) {
  return withKeyedTaskLock(`xray-host:${input.hostId}`, async () => {
    const runtime = await runtimeForHost(input.hostId);
    await input.validateRuntime(runtime);
    await assertNoRuntimeOperation(input.hostId);
    if ((input.type === "INSTALL" || input.type === "UPGRADE") && runtime.unavailableReasonCode === "ARTIFACT_UNAVAILABLE") {
      throw new XrayRuntimeServiceError("ARTIFACT_UNAVAILABLE");
    }
    const deployment = await deploymentForHost(input.hostId);
    const operationId = crypto.randomUUID();
    const now = nowDate();
    await withDatabaseTransaction(async () => {
      await insertAndGetId("xray_operations", {
        operationId,
        hostId: input.hostId,
        inboundId: null,
        type: input.type,
        requestedGeneration: deployment?.desiredGeneration ?? null,
        status: "QUEUED",
        attemptCount: 0,
        createdByUserId: input.createdByUserId,
        createdAt: now,
        updatedAt: now,
      });
      const q = quoteIdentifier;
      if (deployment) {
        const targetAssignment = input.type === "RESTART"
          ? ""
          : `${q("targetVersion")} = ?, `;
        const parameters = input.type === "RESTART"
          ? [operationId, now, deployment.id, deployment.desiredGeneration]
          : [input.version, operationId, now, deployment.id, deployment.desiredGeneration];
        const changed = await executeRaw(
          `UPDATE ${q("xray_host_deployments")} SET ${targetAssignment}${q("lastOperationId")} = ?, ${q("updatedAt")} = ?
            WHERE ${q("id")} = ? AND ${q("desiredGeneration")} = ?`,
          parameters,
        );
        if (rawAffectedRows(changed) !== 1) throw new XrayRuntimeServiceError("OPERATION_CONFLICT");
      } else if (input.type === "RESTART") {
        throw new XrayRuntimeServiceError("RUNTIME_NOT_READY");
      } else {
        await insertAndGetId("xray_host_deployments", {
          hostId: input.hostId,
          targetVersion: input.version,
          desiredGeneration: 0,
          desiredConfigHash: null,
          lastOperationId: operationId,
          createdAt: now,
          updatedAt: now,
        });
      }
    });
    pushAgentRefresh(input.hostId, `xray-runtime-${input.type.toLowerCase()}`, { urgent: true });
    const desiredGeneration = deployment?.desiredGeneration ?? 0;
    await recordXrayMutationObservability({
      event: `RUNTIME_${input.type}_DISPATCHED`,
      resourceType: "xray_runtime",
      resourceId: input.hostId,
      hostId: input.hostId,
      action: "dispatch",
      fields: {
        userId: input.createdByUserId, hostId: input.hostId, operationId,
        taskType: input.type, version: input.version, generation: desiredGeneration, status: "QUEUED",
      },
    });
    return { operationId, desiredGeneration };
  });
}

export async function createXrayRuntimeInstall(input: { hostId: unknown; userId: unknown; targetVersion?: unknown }) {
  const hostId = positiveId(input.hostId);
  const version = targetVersion(input.targetVersion);
  return createTaskOperation({
    hostId, createdByUserId: userId(input.userId), type: "INSTALL", version,
    validateRuntime(runtime) {
      if (!runtime.installedVersion) return;
      if (compareVersions(runtime.installedVersion, version) > 0) throw new XrayRuntimeServiceError("DOWNGRADE_NOT_ALLOWED");
      throw new XrayRuntimeServiceError("INVALID_CONFIG_INPUT");
    },
  });
}

export async function createXrayRuntimeUpgrade(input: {
  hostId: unknown;
  userId: unknown;
  targetVersion: unknown;
  expectedInstalledVersion: unknown;
}) {
  const hostId = positiveId(input.hostId);
  const version = targetVersion(input.targetVersion);
  const expectedInstalledVersion = String(input.expectedInstalledVersion ?? "").trim();
  return createTaskOperation({
    hostId, createdByUserId: userId(input.userId), type: "UPGRADE", version,
    validateRuntime(runtime) {
      const installedVersion = String(runtime.installedVersion ?? "");
      if (!installedVersion) throw new XrayRuntimeServiceError("RUNTIME_NOT_READY");
      if (installedVersion !== expectedInstalledVersion) throw new XrayRuntimeServiceError("XRAY_VERSION_MISMATCH");
      const compared = compareVersions(installedVersion, version);
      if (compared > 0) throw new XrayRuntimeServiceError("DOWNGRADE_NOT_ALLOWED");
      if (compared === 0) throw new XrayRuntimeServiceError("INVALID_CONFIG_INPUT");
    },
  });
}

export async function createXrayRuntimeRestart(input: { hostId: unknown; userId: unknown; confirmHostName: unknown }) {
  const hostId = positiveId(input.hostId);
  const confirmation = String(input.confirmHostName ?? "");
  return createTaskOperation({
    hostId, createdByUserId: userId(input.userId), type: "RESTART", version: XRAY_DEFAULT_VERSION,
    async validateRuntime(runtime) {
      if (confirmation !== await hostName(hostId)) throw new XrayRuntimeServiceError("CONFIRMATION_MISMATCH");
      if (!runtime.installedVersion || runtime.serviceStatus !== "RUNNING") throw new XrayRuntimeServiceError("RUNTIME_NOT_READY");
    },
  });
}

export async function createXrayRuntimeSync(input: { hostId: unknown; userId: unknown }) {
  const hostId = positiveId(input.hostId);
  const createdByUserId = userId(input.userId);
  return withKeyedTaskLock(`xray-host:${hostId}`, async () => {
    const runtime = await runtimeForHost(hostId);
    await assertNoRuntimeOperation(hostId);
    if (!runtime.installedVersion) throw new XrayRuntimeServiceError("RUNTIME_NOT_READY");
    if (compareVersions(runtime.installedVersion, XRAY_DEFAULT_VERSION) > 0) throw new XrayRuntimeServiceError("DOWNGRADE_NOT_ALLOWED");
    if (runtime.installedVersion !== XRAY_DEFAULT_VERSION) throw new XrayRuntimeServiceError("XRAY_VERSION_MISMATCH");
    const deployment = await deploymentForHost(hostId);
    if (!deployment) throw new XrayRuntimeServiceError("RUNTIME_NOT_READY");
    const generated = await generateXrayHostConfig(hostId);
    const desiredGeneration = deployment.desiredGeneration + 1;
    if (!Number.isSafeInteger(desiredGeneration)) throw new XrayRuntimeServiceError("OPERATION_CONFLICT");
    const operationId = crypto.randomUUID();
    const now = nowDate();
    await withDatabaseTransaction(async () => {
      await insertAndGetId("xray_operations", {
        operationId,
        hostId,
        inboundId: null,
        type: "SYNC",
        requestedGeneration: desiredGeneration,
        status: "QUEUED",
        requestMetaJson: JSON.stringify({ schemaVersion: 1, stage: "SYNC_ONLY" }),
        attemptCount: 0,
        createdByUserId,
        createdAt: now,
        updatedAt: now,
      });
      const q = quoteIdentifier;
      const changed = await executeRaw(
        `UPDATE ${q("xray_host_deployments")}
            SET ${q("targetVersion")} = ?, ${q("desiredGeneration")} = ?, ${q("desiredConfigHash")} = ?,
                ${q("lastOperationId")} = ?, ${q("updatedAt")} = ?
          WHERE ${q("id")} = ? AND ${q("desiredGeneration")} = ?`,
        [generated.targetVersion, desiredGeneration, generated.configHash, operationId, now, deployment.id, deployment.desiredGeneration],
      );
      if (rawAffectedRows(changed) !== 1) throw new XrayRuntimeServiceError("OPERATION_CONFLICT");
    });
    pushAgentRefresh(hostId, "xray-runtime-sync", { urgent: true });
    await recordXrayMutationObservability({
      event: "RUNTIME_SYNC_DISPATCHED",
      resourceType: "xray_runtime",
      resourceId: hostId,
      hostId,
      action: "dispatch",
      fields: {
        userId: createdByUserId, hostId, operationId, taskType: "SYNC",
        version: generated.targetVersion, generation: desiredGeneration, status: "QUEUED",
      },
    });
    return { operationId, desiredGeneration };
  });
}
