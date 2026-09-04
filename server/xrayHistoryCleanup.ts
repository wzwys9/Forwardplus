import fs from "node:fs/promises";
import path from "node:path";

import { compareVersions } from "./agentRouteUtils";
import { quoteIdentifier } from "./dbCompat";
import {
  executeRaw,
  queryRaw,
  rawAffectedRows,
  withDatabaseTransaction,
} from "./dbRuntime";
import { ENV } from "./env";
import { resolveXrayArtifactStoragePath, XRAY_DEFAULT_VERSION } from "./xrayArtifacts";

const TERMINAL_OPERATION_STATUSES = ["SUCCESS", "FAILED", "TIMEOUT", "CANCELLED"] as const;
const ACTIVE_OPERATION_STATUSES = ["QUEUED", "RUNNING"] as const;
const DEFAULT_XRAY_HISTORY_RETENTION_DAYS = 30;
const MIN_ARTIFACT_VERSIONS_PER_PLATFORM = 2;

type ArtifactRow = {
  id: unknown;
  version: unknown;
  os: unknown;
  arch: unknown;
  storageKey: unknown;
  updatedAt: unknown;
};

function defaultArtifactDataDirectory() {
  return path.dirname(ENV.databaseConfigPath || ENV.sqlitePath || "/data/database.json");
}

function safeVersion(value: unknown) {
  const version = String(value ?? "");
  return /^v?\d+\.\d+\.\d+$/.test(version) ? version : null;
}

function dateMilliseconds(value: unknown) {
  if (value instanceof Date) return value.getTime();
  const numeric = Number(value);
  if (Number.isFinite(numeric)) return numeric < 10_000_000_000 ? numeric * 1000 : numeric;
  const parsed = Date.parse(String(value ?? ""));
  return Number.isFinite(parsed) ? parsed : 0;
}

function operationMetaVersion(value: unknown) {
  try {
    const parsed = typeof value === "string" ? JSON.parse(value) : value;
    return safeVersion(parsed?.version);
  } catch {
    return null;
  }
}

async function protectedArtifactVersions() {
  const q = quoteIdentifier;
  const [deployments, reports, operations] = await Promise.all([
    queryRaw<Record<string, unknown>>(`SELECT ${q("targetVersion")} FROM ${q("xray_host_deployments")}`),
    queryRaw<Record<string, unknown>>(`SELECT ${q("installedVersion")}, ${q("runningVersion")} FROM ${q("xray_runtime_reports")}`),
    queryRaw<Record<string, unknown>>(
      `SELECT ${q("requestMetaJson")} FROM ${q("xray_operations")} WHERE ${q("status")} IN (?, ?)`,
      [...ACTIVE_OPERATION_STATUSES],
    ),
  ]);
  const protectedVersions = new Set<string>([XRAY_DEFAULT_VERSION]);
  for (const row of deployments) {
    const version = safeVersion(row.targetVersion);
    if (version) protectedVersions.add(version);
  }
  for (const row of reports) {
    for (const value of [row.installedVersion, row.runningVersion]) {
      const version = safeVersion(value);
      if (version) protectedVersions.add(version);
    }
  }
  for (const row of operations) {
    const version = operationMetaVersion(row.requestMetaJson);
    if (version) protectedVersions.add(version);
  }
  return protectedVersions;
}

function artifactRetentionIds(rows: ArtifactRow[]) {
  const keep = new Set<number>();
  const groups = new Map<string, ArtifactRow[]>();
  for (const row of rows) {
    const key = `${String(row.os)}:${String(row.arch)}`;
    const group = groups.get(key) || [];
    group.push(row);
    groups.set(key, group);
  }
  for (const group of groups.values()) {
    group.sort((left, right) => {
      const leftVersion = safeVersion(left.version);
      const rightVersion = safeVersion(right.version);
      if (leftVersion && rightVersion) return compareVersions(rightVersion, leftVersion);
      return dateMilliseconds(right.updatedAt) - dateMilliseconds(left.updatedAt);
    });
    for (const row of group.slice(0, MIN_ARTIFACT_VERSIONS_PER_PLATFORM)) {
      const id = Number(row.id);
      if (Number.isSafeInteger(id) && id > 0) keep.add(id);
    }
  }
  return keep;
}

async function removeArtifactFiles(rows: ArtifactRow[], dataDirectory: string) {
  let removed = 0;
  let skipped = 0;
  const deletableIds: number[] = [];
  for (const row of rows) {
    const id = Number(row.id);
    try {
      const filePath = resolveXrayArtifactStoragePath(dataDirectory, String(row.storageKey ?? ""));
      const stat = await fs.lstat(filePath).catch((error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") return null;
        throw error;
      });
      if (!stat) {
        deletableIds.push(id);
        continue;
      }
      if (!stat.isFile() || stat.isSymbolicLink()) {
        skipped += 1;
        continue;
      }
      await fs.rm(filePath, { force: true });
      removed += 1;
      deletableIds.push(id);
    } catch {
      skipped += 1;
    }
  }
  return { removed, skipped, deletableIds };
}

export async function cleanOldXrayHistory(options: {
  now?: Date;
  retainDays?: number;
  artifactDataDirectory?: string;
} = {}) {
  const now = options.now instanceof Date && Number.isFinite(options.now.getTime()) ? options.now : new Date();
  const retainDays = Number.isFinite(options.retainDays)
    ? Math.max(1, Math.min(3650, Math.floor(options.retainDays!)))
    : DEFAULT_XRAY_HISTORY_RETENTION_DAYS;
  const cutoff = new Date(now.getTime() - retainDays * 24 * 60 * 60 * 1000);
  const q = quoteIdentifier;
  const artifacts = await queryRaw<ArtifactRow>(
    `SELECT ${q("id")}, ${q("version")}, ${q("os")}, ${q("arch")}, ${q("storageKey")}, ${q("updatedAt")}
       FROM ${q("xray_artifacts")}`,
  );
  const protectedVersions = await protectedArtifactVersions();
  const retainedIds = artifactRetentionIds(artifacts);
  const staleArtifacts = artifacts.filter((row) => {
    const id = Number(row.id);
    return Number.isSafeInteger(id) && id > 0 && !retainedIds.has(id)
      && !protectedVersions.has(String(row.version ?? ""))
      && dateMilliseconds(row.updatedAt) < cutoff.getTime();
  });

  const fileResult = await removeArtifactFiles(
    staleArtifacts,
    path.resolve(options.artifactDataDirectory || defaultArtifactDataDirectory()),
  );
  const deleted = await withDatabaseTransaction(async () => {
    const operationResult = await executeRaw(
      `DELETE FROM ${q("xray_operations")}
        WHERE ${q("status")} IN (${TERMINAL_OPERATION_STATUSES.map(() => "?").join(", ")})
          AND ${q("updatedAt")} < ?
          AND NOT EXISTS (
            SELECT 1 FROM ${q("xray_host_deployments")} d
             WHERE d.${q("lastOperationId")} = ${q("xray_operations")}.${q("operationId")}
          )`,
      [...TERMINAL_OPERATION_STATUSES, cutoff],
    );
    let artifactCount = 0;
    if (fileResult.deletableIds.length > 0) {
      const artifactResult = await executeRaw(
        `DELETE FROM ${q("xray_artifacts")} WHERE ${q("id")} IN (${fileResult.deletableIds.map(() => "?").join(", ")})`,
        fileResult.deletableIds,
      );
      artifactCount = rawAffectedRows(artifactResult);
    }
    return { operations: rawAffectedRows(operationResult), artifacts: artifactCount };
  });
  return {
    deletedOperations: deleted.operations,
    deletedArtifacts: deleted.artifacts,
    deletedArtifactFiles: fileResult.removed,
    skippedArtifactFiles: fileResult.skipped,
  };
}
