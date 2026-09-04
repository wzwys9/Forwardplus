import {
  XRAY_AGENT_ERROR_CODES,
  XrayTaskResultSchema,
  XrayTaskSchema,
  type XrayTask,
} from "../shared/xrayTypes";
import { pushAgentRefresh } from "./agentEvents";
import { quoteIdentifier } from "./dbCompat";
import { executeRaw, nowDate, queryRaw } from "./dbRuntime";
import { withKeyedTaskLock } from "./keyedTaskLock";
import { getXrayArtifactManifestEntry, XRAY_DEFAULT_VERSION } from "./xrayArtifacts";

const XRAY_INSTALL_TASK_TTL_MS = 5 * 60_000;
const SAFE_AGENT_ERROR_CODES = new Set<string>(XRAY_AGENT_ERROR_CODES);
const TERMINAL_STATUSES = new Set(["SUCCESS", "FAILED", "TIMEOUT", "CANCELLED"]);

type RuntimeOperationRow = Record<string, unknown>;
type ArtifactMeta = {
  schemaVersion: 1;
  stage: "INSTALL" | "INSTALL_COMPLETE";
  createdAt: string;
  expiresAt: string;
  artifactId: number;
  version: string;
  os: "linux";
  arch: "amd64" | "arm64";
  size: number;
  sha256: string;
  downloadPath: string;
};

type RestartMeta = {
  schemaVersion: 1;
  stage: "RESTART";
  createdAt: string;
  expiresAt: string;
  reason: "ADMIN_REQUEST";
};

function positiveId(value: unknown): number {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) throw new Error("Invalid Xray host identity");
  return id;
}

function parseArtifactMeta(value: unknown, taskType: "INSTALL" | "UPGRADE"): ArtifactMeta | null {
  try {
    const parsed = typeof value === "string" ? JSON.parse(value) : value;
    if (!parsed || parsed.schemaVersion !== 1 || (parsed.stage !== "INSTALL" && parsed.stage !== "INSTALL_COMPLETE")) return null;
    const allowedKeys = new Set([
      "schemaVersion", "stage", "createdAt", "expiresAt", "artifactId", "version", "os", "arch", "size", "sha256", "downloadPath",
    ]);
    if (Object.keys(parsed).some((key) => !allowedKeys.has(key)) || Object.keys(parsed).length !== allowedKeys.size) return null;
    const task = XrayTaskSchema.safeParse({
      schemaVersion: 1,
      taskId: "install-meta-validation",
      type: taskType,
      createdAt: parsed.createdAt,
      expiresAt: parsed.expiresAt,
      payload: {
        artifactId: parsed.artifactId,
        version: parsed.version,
        os: parsed.os,
        arch: parsed.arch,
        size: parsed.size,
        sha256: parsed.sha256,
        downloadPath: parsed.downloadPath,
      },
    });
    if (!task.success || task.data.type !== taskType) return null;
    return { schemaVersion: 1, stage: parsed.stage, createdAt: task.data.createdAt, expiresAt: task.data.expiresAt, ...task.data.payload };
  } catch {
    return null;
  }
}

function parseRestartMeta(value: unknown): RestartMeta | null {
  try {
    const parsed = typeof value === "string" ? JSON.parse(value) : value;
    if (!parsed || parsed.schemaVersion !== 1 || parsed.stage !== "RESTART" || parsed.reason !== "ADMIN_REQUEST") return null;
    const allowedKeys = new Set(["schemaVersion", "stage", "createdAt", "expiresAt", "reason"]);
    if (Object.keys(parsed).some((key) => !allowedKeys.has(key)) || Object.keys(parsed).length !== allowedKeys.size) return null;
    const task = XrayTaskSchema.safeParse({
      schemaVersion: 1,
      taskId: "restart-meta-validation",
      type: "RESTART",
      createdAt: parsed.createdAt,
      expiresAt: parsed.expiresAt,
      payload: { reason: parsed.reason },
    });
    if (!task.success || task.data.type !== "RESTART") return null;
    return { schemaVersion: 1, stage: "RESTART", createdAt: task.data.createdAt, expiresAt: task.data.expiresAt, reason: "ADMIN_REQUEST" };
  } catch {
    return null;
  }
}

function artifactMatches(row: RuntimeOperationRow) {
  try {
    const manifest = getXrayArtifactManifestEntry({
      version: String(row.artifactVersion ?? ""),
      os: String(row.artifactOS ?? ""),
      arch: String(row.artifactArch ?? ""),
    });
    return Number(row.artifactId) > 0
      && row.artifactPackageFormat === manifest.packageFormat
      && row.artifactStorageKey === manifest.storageKey
      && row.artifactSha256 === manifest.sha256
      && Number(row.artifactFileSize) === manifest.fileSize
      && row.artifactStatus === "VERIFIED"
      && row.artifactSource === manifest.source
      && row.artifactVerifiedAt !== null
      && row.artifactVerifiedAt !== undefined;
  } catch {
    return false;
  }
}

async function runtimeOperation(hostId: number): Promise<RuntimeOperationRow | null> {
  const q = quoteIdentifier;
  const rows = await queryRaw<RuntimeOperationRow>(
    `SELECT o.${q("operationId")}, o.${q("hostId")}, o.${q("type")}, o.${q("status")},
            o.${q("requestMetaJson")}, o.${q("requestedGeneration")}, o.${q("createdAt")},
            d.${q("targetVersion")}, d.${q("desiredGeneration")},
            r.${q("isInstalled")}, r.${q("installedVersion")}, r.${q("supportedOS")}, r.${q("supportedArch")},
            a.${q("id")} AS ${q("artifactId")}, a.${q("version")} AS ${q("artifactVersion")},
            a.${q("os")} AS ${q("artifactOS")}, a.${q("arch")} AS ${q("artifactArch")},
            a.${q("packageFormat")} AS ${q("artifactPackageFormat")}, a.${q("storageKey")} AS ${q("artifactStorageKey")},
            a.${q("sha256")} AS ${q("artifactSha256")}, a.${q("fileSize")} AS ${q("artifactFileSize")},
            a.${q("status")} AS ${q("artifactStatus")}, a.${q("source")} AS ${q("artifactSource")},
            a.${q("verifiedAt")} AS ${q("artifactVerifiedAt")}
       FROM ${q("xray_host_deployments")} d
       JOIN ${q("xray_operations")} o ON o.${q("operationId")} = d.${q("lastOperationId")}
       LEFT JOIN ${q("xray_runtime_reports")} r ON r.${q("hostId")} = d.${q("hostId")}
       LEFT JOIN ${q("xray_artifacts")} a ON a.${q("version")} = d.${q("targetVersion")}
        AND a.${q("os")} = r.${q("supportedOS")} AND a.${q("arch")} = r.${q("supportedArch")}
      WHERE d.${q("hostId")} = ? LIMIT 1`,
    [hostId],
  );
  return rows[0] ?? null;
}

function needsArtifactTask(row: RuntimeOperationRow) {
  if (!["SYNC", "INSTALL", "UPGRADE"].includes(String(row.type))) return false;
  return String(row.targetVersion ?? "") === XRAY_DEFAULT_VERSION
    && !((row.isInstalled === true || row.isInstalled === 1 || row.isInstalled === "1")
      && String(row.installedVersion ?? "") === XRAY_DEFAULT_VERSION);
}

function newArtifactMeta(row: RuntimeOperationRow, now: Date): ArtifactMeta | null {
  if (!artifactMatches(row)) return null;
  const artifactId = Number(row.artifactId);
  return {
    schemaVersion: 1,
    stage: "INSTALL",
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + XRAY_INSTALL_TASK_TTL_MS).toISOString(),
    artifactId,
    version: String(row.artifactVersion),
    os: row.artifactOS as "linux",
    arch: row.artifactArch as "amd64" | "arm64",
    size: Number(row.artifactFileSize),
    sha256: String(row.artifactSha256),
    downloadPath: `/api/agent/artifacts/xray/${artifactId}`,
  };
}

function newRestartMeta(now: Date): RestartMeta {
  return {
    schemaVersion: 1,
    stage: "RESTART",
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + XRAY_INSTALL_TASK_TTL_MS).toISOString(),
    reason: "ADMIN_REQUEST",
  };
}

async function failOperation(operationId: string, errorCode: string, status: "FAILED" | "TIMEOUT" = "FAILED") {
  const q = quoteIdentifier;
  const now = nowDate();
  await executeRaw(
    `UPDATE ${q("xray_operations")}
        SET ${q("status")} = ?, ${q("errorCode")} = ?, ${q("errorMessage")} = ?,
            ${q("finishedAt")} = ?, ${q("updatedAt")} = ?
      WHERE ${q("operationId")} = ? AND ${q("status")} IN (?, ?)`,
    [status, errorCode, "Managed Xray installation did not complete", now, now, operationId, "QUEUED", "RUNNING"],
  );
}

export async function shouldDeferXrayDesiredForInstall(hostIdValue: unknown): Promise<boolean> {
  const row = await runtimeOperation(positiveId(hostIdValue));
  if (!row || !needsArtifactTask(row) || !["QUEUED", "RUNNING"].includes(String(row.status))) return false;
  const taskType = String(row.type) === "UPGRADE" ? "UPGRADE" : "INSTALL";
  const meta = parseArtifactMeta(row.requestMetaJson, taskType);
  return meta?.stage !== "INSTALL_COMPLETE";
}

export async function takeXrayRuntimeTasks(hostIdValue: unknown, requestedLimit = 1): Promise<XrayTask[]> {
  const hostId = positiveId(hostIdValue);
  if (Math.max(0, Math.floor(Number(requestedLimit) || 0)) < 1) return [];
  return withKeyedTaskLock(`xray-runtime-operation:${hostId}`, async () => {
    const row = await runtimeOperation(hostId);
    if (!row || !["QUEUED", "RUNNING"].includes(String(row.status))) return [];
    const operationType = String(row.type);
    const isRestart = operationType === "RESTART";
    const taskType = operationType === "UPGRADE" ? "UPGRADE" : "INSTALL";
    if (!isRestart && !needsArtifactTask(row)) return [];
    const now = nowDate();
    let task: XrayTask;
    let metaJson: string;
    if (isRestart) {
      const existingMeta = row.requestMetaJson == null ? null : parseRestartMeta(row.requestMetaJson);
      if (row.requestMetaJson != null && !existingMeta) {
        await failOperation(String(row.operationId), "INVALID_PAYLOAD");
        return [];
      }
      const meta = existingMeta ?? newRestartMeta(now);
      if (Date.parse(meta.expiresAt) <= now.getTime()) {
        await failOperation(String(row.operationId), "TASK_EXPIRED", "TIMEOUT");
        return [];
      }
      task = XrayTaskSchema.parse({
        schemaVersion: 1,
        taskId: String(row.operationId),
        type: "RESTART",
        createdAt: meta.createdAt,
        expiresAt: meta.expiresAt,
        payload: { reason: "ADMIN_REQUEST" },
      });
      metaJson = JSON.stringify(meta);
    } else {
      const existingMeta = row.requestMetaJson == null ? null : parseArtifactMeta(row.requestMetaJson, taskType);
      if (row.requestMetaJson != null && !existingMeta) {
        await failOperation(String(row.operationId), "INVALID_PAYLOAD");
        return [];
      }
      if (existingMeta?.stage === "INSTALL_COMPLETE") return [];
      const meta = existingMeta ?? newArtifactMeta(row, now);
      if (!meta) {
        await failOperation(String(row.operationId), "ARTIFACT_NOT_FOUND");
        return [];
      }
      if (Date.parse(meta.expiresAt) <= now.getTime()) {
        await failOperation(String(row.operationId), "TASK_EXPIRED", "TIMEOUT");
        return [];
      }
      task = XrayTaskSchema.parse({
        schemaVersion: 1,
        taskId: String(row.operationId),
        type: taskType,
        createdAt: meta.createdAt,
        expiresAt: meta.expiresAt,
        payload: {
          artifactId: meta.artifactId,
          version: meta.version,
          os: meta.os,
          arch: meta.arch,
          size: meta.size,
          sha256: meta.sha256,
          downloadPath: meta.downloadPath,
        },
      });
      metaJson = JSON.stringify(meta);
    }
    const q = quoteIdentifier;
    await executeRaw(
      `UPDATE ${q("xray_operations")}
          SET ${q("status")} = ?, ${q("requestMetaJson")} = ?,
              ${q("startedAt")} = COALESCE(${q("startedAt")}, ?),
              ${q("attemptCount")} = ${q("attemptCount")} + 1, ${q("updatedAt")} = ?
        WHERE ${q("operationId")} = ? AND ${q("status")} IN (?, ?)`,
      ["RUNNING", metaJson, now, now, row.operationId, "QUEUED", "RUNNING"],
    );
    return [task];
  });
}

export async function hasQueuedXrayRuntimeTasks(hostIdValue: unknown): Promise<boolean> {
  const row = await runtimeOperation(positiveId(hostIdValue));
  if (!row || !["QUEUED", "RUNNING"].includes(String(row.status))) return false;
  if (String(row.type) === "RESTART") return true;
  if (!needsArtifactTask(row)) return false;
  const taskType = String(row.type) === "UPGRADE" ? "UPGRADE" : "INSTALL";
  return parseArtifactMeta(row.requestMetaJson, taskType)?.stage !== "INSTALL_COMPLETE";
}

export async function completeXrayRuntimeTask(hostIdValue: unknown, rawResult: unknown): Promise<{ accepted: true }> {
  const hostId = positiveId(hostIdValue);
  const result = XrayTaskResultSchema.parse(rawResult);
  return withKeyedTaskLock(`xray-runtime-operation:${hostId}`, async () => {
    const row = await runtimeOperation(hostId);
    if (!row || String(row.operationId) !== result.taskId || Number(row.hostId) !== hostId) {
      throw new Error("Xray runtime operation conflict");
    }
    if (TERMINAL_STATUSES.has(String(row.status))) return { accepted: true };
    const operationType = String(row.type);
    const expectedTaskType = operationType === "UPGRADE" ? "UPGRADE" : operationType === "RESTART" ? "RESTART" : "INSTALL";
    if (result.type !== expectedTaskType) throw new Error("Xray runtime operation conflict");
    if (result.type === "RESTART") {
      const meta = parseRestartMeta(row.requestMetaJson);
      if (!meta) {
        await failOperation(result.taskId, "INVALID_PAYLOAD");
        return { accepted: true };
      }
      if (result.status !== "SUCCESS" || !result.result) {
        const errorCode = SAFE_AGENT_ERROR_CODES.has(result.error?.code ?? "") ? result.error!.code : "INTERNAL_ERROR";
        await failOperation(result.taskId, errorCode, result.status === "TIMEOUT" ? "TIMEOUT" : "FAILED");
        return { accepted: true };
      }
      const q = quoteIdentifier;
      const now = nowDate();
      await executeRaw(
        `UPDATE ${q("xray_operations")}
            SET ${q("status")} = ?, ${q("errorCode")} = NULL, ${q("errorMessage")} = NULL,
                ${q("finishedAt")} = ?, ${q("updatedAt")} = ?
          WHERE ${q("operationId")} = ? AND ${q("status")} IN (?, ?)`,
        ["SUCCESS", now, now, result.taskId, "QUEUED", "RUNNING"],
      );
      return { accepted: true };
    }
    const meta = parseArtifactMeta(row.requestMetaJson, result.type);
    if (!meta || meta.stage === "INSTALL_COMPLETE") {
      await failOperation(result.taskId, "INVALID_PAYLOAD");
      return { accepted: true };
    }
    if (result.status !== "SUCCESS" || !result.result) {
      const errorCode = SAFE_AGENT_ERROR_CODES.has(result.error?.code ?? "") ? result.error!.code : "INTERNAL_ERROR";
      await failOperation(result.taskId, errorCode, result.status === "TIMEOUT" ? "TIMEOUT" : "FAILED");
      return { accepted: true };
    }
    if (result.result.installedVersion !== meta.version || (result.type === "UPGRADE" && result.result.rolledBack)) {
      await failOperation(result.taskId, "XRAY_VERSION_MISMATCH");
      return { accepted: true };
    }
    const q = quoteIdentifier;
    const now = nowDate();
    if (operationType === "INSTALL") {
      await executeRaw(
        `UPDATE ${q("xray_operations")}
            SET ${q("status")} = ?, ${q("errorCode")} = NULL, ${q("errorMessage")} = NULL,
                ${q("finishedAt")} = ?, ${q("updatedAt")} = ?
          WHERE ${q("operationId")} = ? AND ${q("status")} IN (?, ?)`,
        ["SUCCESS", now, now, result.taskId, "QUEUED", "RUNNING"],
      );
      return { accepted: true };
    }
    const completeMeta: ArtifactMeta = { ...meta, stage: "INSTALL_COMPLETE" };
    await executeRaw(
      `UPDATE ${q("xray_operations")}
          SET ${q("status")} = ?, ${q("requestMetaJson")} = ?, ${q("errorCode")} = NULL,
              ${q("errorMessage")} = NULL, ${q("finishedAt")} = NULL, ${q("updatedAt")} = ?
        WHERE ${q("operationId")} = ? AND ${q("status")} IN (?, ?)`,
      ["QUEUED", JSON.stringify(completeMeta), now, result.taskId, "QUEUED", "RUNNING"],
    );
    pushAgentRefresh(hostId, operationType === "UPGRADE" ? "xray-upgrade-complete" : "xray-install-complete", { urgent: true });
    return { accepted: true };
  });
}

export async function acceptXrayRuntimeTaskResults(hostIdValue: unknown, rawResults: unknown): Promise<string[]> {
  const hostId = positiveId(hostIdValue);
  if (!Array.isArray(rawResults)) return [];
  const accepted: string[] = [];
  for (const rawResult of rawResults.slice(0, 8)) {
    try {
      const result = XrayTaskResultSchema.parse(rawResult);
      if (result.type !== "INSTALL" && result.type !== "UPGRADE" && result.type !== "RESTART") continue;
      await completeXrayRuntimeTask(hostId, result);
      accepted.push(result.taskId);
    } catch {
      // The Agent retains malformed, foreign, or transiently unpersistable
      // terminal results until the panel explicitly acknowledges them.
    }
  }
  return accepted;
}
