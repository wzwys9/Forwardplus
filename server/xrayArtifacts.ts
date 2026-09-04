import crypto from "node:crypto";
import fsConstants from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";

import {
  executeRaw,
  insertAndGetId,
  nowDate,
  queryRaw,
  rawAffectedRows,
  withDatabaseTransaction,
} from "./dbRuntime";
import { quoteIdentifier } from "./dbCompat";
import { withKeyedTaskLock } from "./keyedTaskLock";
import { getSetting, setSetting } from "./repositories/settingsRepository";

export const XRAY_DEFAULT_VERSION = "v26.3.27" as const;
export const XRAY_DEFAULT_VERSION_SETTING_KEY = "xrayDefaultVersion" as const;

export type XrayArtifactIdentity = {
  version: string;
  os: string;
  arch: string;
};

export type XrayArtifactManifestEntry = XrayArtifactIdentity & {
  packageFormat: "zip";
  archiveName: string;
  storageKey: string;
  source: string;
  digestSource: string;
  sha256: string;
  fileSize: number;
  digestSha256: string;
  digestFileSize: number;
};

const RELEASE_BASE_URL = `https://github.com/XTLS/Xray-core/releases/download/${XRAY_DEFAULT_VERSION}`;

function manifestEntry(
  arch: "amd64" | "arm64",
  archiveName: string,
  sha256: string,
  fileSize: number,
  digestSha256: string,
): Readonly<XrayArtifactManifestEntry> {
  const source = `${RELEASE_BASE_URL}/${archiveName}`;
  return Object.freeze({
    version: XRAY_DEFAULT_VERSION,
    os: "linux",
    arch,
    packageFormat: "zip",
    archiveName,
    storageKey: `xray/artifacts/${XRAY_DEFAULT_VERSION}/linux/${arch}/${archiveName}`,
    source,
    digestSource: `${source}.dgst`,
    sha256,
    fileSize,
    digestSha256,
    digestFileSize: 299,
  });
}

export const XRAY_ARTIFACT_MANIFEST: readonly Readonly<XrayArtifactManifestEntry>[] = Object.freeze([
  manifestEntry(
    "amd64",
    "Xray-linux-64.zip",
    "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
    21_136_402,
    "052fc1c5c4bd5b44d799f785792a9631bce8da4aa0d385a783e9a711ad352a58",
  ),
  manifestEntry(
    "arm64",
    "Xray-linux-arm64-v8a.zip",
    "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c",
    19_716_427,
    "1cafbf4fa746688990a12a6d344b638f706e531f1b81b8b583f9b2164561ad2f",
  ),
]);

export type XrayArtifactErrorCode =
  | "ARTIFACT_UNSUPPORTED"
  | "ARTIFACT_PATH_INVALID"
  | "ARTIFACT_SOURCE_FAILED"
  | "ARTIFACT_INTEGRITY_FAILED"
  | "ARTIFACT_MANIFEST_INCOMPLETE"
  | "ARTIFACT_NOT_FOUND"
  | "ARTIFACT_PLATFORM_MISMATCH";

const ERROR_MESSAGES: Record<XrayArtifactErrorCode, string> = {
  ARTIFACT_UNSUPPORTED: "The requested Xray artifact is not approved",
  ARTIFACT_PATH_INVALID: "The Xray artifact storage path is invalid",
  ARTIFACT_SOURCE_FAILED: "The approved Xray artifact source is unavailable",
  ARTIFACT_INTEGRITY_FAILED: "The Xray artifact failed integrity verification",
  ARTIFACT_MANIFEST_INCOMPLETE: "The Xray artifact manifest is incomplete",
  ARTIFACT_NOT_FOUND: "The verified Xray artifact is not available",
  ARTIFACT_PLATFORM_MISMATCH: "The Xray artifact does not match the Agent platform",
};

export class XrayArtifactError extends Error {
  constructor(readonly code: XrayArtifactErrorCode, options?: ErrorOptions) {
    super(ERROR_MESSAGES[code], options);
    this.name = "XrayArtifactError";
  }
}

function artifactIdentityKey(identity: XrayArtifactIdentity) {
  return `${identity.version}:${identity.os}:${identity.arch}`;
}

export function getXrayArtifactManifestEntry(identity: XrayArtifactIdentity): Readonly<XrayArtifactManifestEntry> {
  const entry = XRAY_ARTIFACT_MANIFEST.find((candidate) => (
    candidate.version === identity.version
    && candidate.os === identity.os
    && candidate.arch === identity.arch
  ));
  if (!entry) throw new XrayArtifactError("ARTIFACT_UNSUPPORTED");
  return entry;
}

function assertRelativeStorageKey(storageKey: string) {
  if (!storageKey
    || storageKey.includes("\\")
    || path.posix.isAbsolute(storageKey)
    || path.posix.normalize(storageKey) !== storageKey
    || storageKey.startsWith("./")
    || storageKey.split("/").some((segment) => !segment || segment === "." || segment === "..")) {
    throw new XrayArtifactError("ARTIFACT_PATH_INVALID");
  }
}

export function resolveXrayArtifactStoragePath(dataDirectory: string, storageKey: string): string {
  assertRelativeStorageKey(storageKey);
  if (!String(dataDirectory || "").trim()) throw new XrayArtifactError("ARTIFACT_PATH_INVALID");
  const root = path.resolve(dataDirectory);
  const target = path.resolve(root, ...storageKey.split("/"));
  if (target === root || !target.startsWith(`${root}${path.sep}`)) {
    throw new XrayArtifactError("ARTIFACT_PATH_INVALID");
  }
  return target;
}

type ExpectedIntegrity = {
  fileSize: number;
  sha256: string;
};

function validExpectedIntegrity(expected: ExpectedIntegrity) {
  return Number.isSafeInteger(expected.fileSize)
    && expected.fileSize > 0
    && /^[a-f0-9]{64}$/.test(expected.sha256);
}

export async function verifyXrayArtifactFile(
  filePath: string,
  expected: ExpectedIntegrity,
): Promise<ExpectedIntegrity> {
  if (!validExpectedIntegrity(expected)) throw new XrayArtifactError("ARTIFACT_INTEGRITY_FAILED");
  let handle: Awaited<ReturnType<typeof fs.open>> | null = null;
  try {
    const beforeOpen = await fs.lstat(filePath);
    if (!beforeOpen.isFile() || beforeOpen.isSymbolicLink() || beforeOpen.size !== expected.fileSize) {
      throw new XrayArtifactError("ARTIFACT_INTEGRITY_FAILED");
    }
    const noFollow = "O_NOFOLLOW" in fsConstants.constants ? fsConstants.constants.O_NOFOLLOW : 0;
    handle = await fs.open(filePath, fsConstants.constants.O_RDONLY | noFollow);
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size !== expected.fileSize) {
      throw new XrayArtifactError("ARTIFACT_INTEGRITY_FAILED");
    }

    let bytesRead = 0;
    const hash = crypto.createHash("sha256");
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      bytesRead += data.byteLength;
      if (bytesRead > expected.fileSize) throw new XrayArtifactError("ARTIFACT_INTEGRITY_FAILED");
      hash.update(data);
    }
    const afterRead = await handle.stat();
    const actualHash = hash.digest("hex");
    if (bytesRead !== expected.fileSize
      || afterRead.size !== opened.size
      || afterRead.mtimeMs !== opened.mtimeMs
      || actualHash !== expected.sha256) {
      throw new XrayArtifactError("ARTIFACT_INTEGRITY_FAILED");
    }
    return { fileSize: bytesRead, sha256: actualHash };
  } catch (error) {
    if (error instanceof XrayArtifactError) throw error;
    throw new XrayArtifactError("ARTIFACT_INTEGRITY_FAILED", { cause: error });
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

async function ensureManagedDirectory(dataDirectory: string, destination: string) {
  const root = path.resolve(dataDirectory);
  const destinationDirectory = path.dirname(destination);
  const relative = path.relative(root, destinationDirectory);
  if (relative.startsWith("..") || path.isAbsolute(relative)) throw new XrayArtifactError("ARTIFACT_PATH_INVALID");

  await fs.mkdir(root, { recursive: true, mode: 0o755 });
  let current = root;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    const rootStat = await fs.lstat(current);
    if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) throw new XrayArtifactError("ARTIFACT_PATH_INVALID");
    current = path.join(current, segment);
    await fs.mkdir(current, { mode: 0o755 }).catch((error: NodeJS.ErrnoException) => {
      if (error.code !== "EEXIST") throw error;
    });
  }
  const finalStat = await fs.lstat(current);
  if (!finalStat.isDirectory() || finalStat.isSymbolicLink()) throw new XrayArtifactError("ARTIFACT_PATH_INVALID");
}

function isUniqueConstraintError(error: unknown): boolean {
  const code = String((error as { code?: unknown })?.code ?? "").toUpperCase();
  const errno = Number((error as { errno?: unknown })?.errno ?? 0);
  return code === "23505"
    || code === "ER_DUP_ENTRY"
    || code.startsWith("SQLITE_CONSTRAINT")
    || errno === 1062;
}

type ArtifactRecordStatus = "CACHED" | "VERIFIED" | "INVALID";

async function updateArtifactRecord(
  entry: Readonly<XrayArtifactManifestEntry>,
  status: ArtifactRecordStatus,
  verifiedAt: Date | null,
): Promise<number> {
  const q = quoteIdentifier;
  const now = nowDate();
  const updateResult = await executeRaw(
    `UPDATE ${q("xray_artifacts")} SET ${q("packageFormat")} = ?, ${q("storageKey")} = ?, ${q("sha256")} = ?, ${q("fileSize")} = ?, ${q("status")} = ?, ${q("source")} = ?, ${q("verifiedAt")} = ?, ${q("updatedAt")} = ? WHERE ${q("version")} = ? AND ${q("os")} = ? AND ${q("arch")} = ?`,
    [entry.packageFormat, entry.storageKey, entry.sha256, entry.fileSize, status, entry.source, verifiedAt, now,
      entry.version, entry.os, entry.arch],
  );
  if (rawAffectedRows(updateResult) === 0) {
    try {
      await insertAndGetId("xray_artifacts", {
        version: entry.version,
        os: entry.os,
        arch: entry.arch,
        packageFormat: entry.packageFormat,
        storageKey: entry.storageKey,
        sha256: entry.sha256,
        fileSize: entry.fileSize,
        status,
        source: entry.source,
        verifiedAt,
        createdAt: now,
        updatedAt: now,
      });
    } catch (error) {
      if (!isUniqueConstraintError(error)) throw error;
      await executeRaw(
        `UPDATE ${q("xray_artifacts")} SET ${q("packageFormat")} = ?, ${q("storageKey")} = ?, ${q("sha256")} = ?, ${q("fileSize")} = ?, ${q("status")} = ?, ${q("source")} = ?, ${q("verifiedAt")} = ?, ${q("updatedAt")} = ? WHERE ${q("version")} = ? AND ${q("os")} = ? AND ${q("arch")} = ?`,
        [entry.packageFormat, entry.storageKey, entry.sha256, entry.fileSize, status, entry.source, verifiedAt, now,
          entry.version, entry.os, entry.arch],
      );
    }
  }
  const rows = await queryRaw<{ id: unknown }>(
    `SELECT ${q("id")} AS ${q("id")} FROM ${q("xray_artifacts")} WHERE ${q("version")} = ? AND ${q("os")} = ? AND ${q("arch")} = ? LIMIT 1`,
    [entry.version, entry.os, entry.arch],
  );
  const id = Number(rows[0]?.id ?? 0);
  if (!Number.isSafeInteger(id) || id <= 0) throw new Error("Xray artifact record was not persisted");
  return id;
}

async function persistArtifactStatus(
  entry: Readonly<XrayArtifactManifestEntry>,
  status: ArtifactRecordStatus,
): Promise<number> {
  return withDatabaseTransaction(() => updateArtifactRecord(
    entry,
    status,
    status === "VERIFIED" ? nowDate() : null,
  ));
}

type FetchLike = (input: string) => Promise<Response>;

async function fetchApprovedSource(fetchImpl: FetchLike, source: string): Promise<Response> {
  try {
    const response = await fetchImpl(source);
    if (!response.ok || !response.body) throw new XrayArtifactError("ARTIFACT_SOURCE_FAILED");
    return response;
  } catch (error) {
    if (error instanceof XrayArtifactError) throw error;
    throw new XrayArtifactError("ARTIFACT_SOURCE_FAILED", { cause: error });
  }
}

function assertContentLength(response: Response, expectedSize: number) {
  const header = response.headers.get("content-length");
  if (header === null) return;
  const parsed = Number(header);
  if (!Number.isSafeInteger(parsed) || parsed !== expectedSize) {
    throw new XrayArtifactError("ARTIFACT_INTEGRITY_FAILED");
  }
}

async function readVerifiedDigest(response: Response, entry: Readonly<XrayArtifactManifestEntry>) {
  assertContentLength(response, entry.digestFileSize);
  const reader = response.body?.getReader();
  if (!reader) throw new XrayArtifactError("ARTIFACT_SOURCE_FAILED");
  const chunks: Uint8Array[] = [];
  let size = 0;
  const hash = crypto.createHash("sha256");
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > entry.digestFileSize) {
      await reader.cancel().catch(() => undefined);
      throw new XrayArtifactError("ARTIFACT_INTEGRITY_FAILED");
    }
    chunks.push(value);
    hash.update(value);
  }
  if (size !== entry.digestFileSize || hash.digest("hex") !== entry.digestSha256) {
    throw new XrayArtifactError("ARTIFACT_INTEGRITY_FAILED");
  }
  const text = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk))).toString("utf8");
  const digest = /^SHA2-256=\s*([a-f0-9]{64})\s*$/mi.exec(text)?.[1];
  if (digest !== entry.sha256) throw new XrayArtifactError("ARTIFACT_INTEGRITY_FAILED");
}

async function downloadArchive(
  response: Response,
  temporaryPath: string,
  entry: Readonly<XrayArtifactManifestEntry>,
) {
  assertContentLength(response, entry.fileSize);
  const reader = response.body?.getReader();
  if (!reader) throw new XrayArtifactError("ARTIFACT_SOURCE_FAILED");
  const handle = await fs.open(temporaryPath, "wx", 0o600);
  let size = 0;
  const hash = crypto.createHash("sha256");
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > entry.fileSize) {
        await reader.cancel().catch(() => undefined);
        throw new XrayArtifactError("ARTIFACT_INTEGRITY_FAILED");
      }
      hash.update(value);
      let offset = 0;
      while (offset < value.byteLength) {
        const { bytesWritten } = await handle.write(value, offset, value.byteLength - offset);
        if (bytesWritten <= 0) throw new XrayArtifactError("ARTIFACT_INTEGRITY_FAILED");
        offset += bytesWritten;
      }
    }
    if (size !== entry.fileSize || hash.digest("hex") !== entry.sha256) {
      throw new XrayArtifactError("ARTIFACT_INTEGRITY_FAILED");
    }
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export type CacheOfficialXrayArtifactOptions = {
  dataDirectory: string;
  fetchImpl?: FetchLike;
};

export async function cacheOfficialXrayArtifact(
  identity: XrayArtifactIdentity,
  options: CacheOfficialXrayArtifactOptions,
): Promise<{ artifactId: number; storageKey: string; sha256: string; fileSize: number }> {
  const entry = getXrayArtifactManifestEntry(identity);
  return withKeyedTaskLock(`xray-artifact:${artifactIdentityKey(entry)}`, async () => {
    const destination = resolveXrayArtifactStoragePath(options.dataDirectory, entry.storageKey);
    await ensureManagedDirectory(options.dataDirectory, destination);

    try {
      await verifyXrayArtifactFile(destination, entry);
      const artifactId = await persistArtifactStatus(entry, "VERIFIED");
      return { artifactId, storageKey: entry.storageKey, sha256: entry.sha256, fileSize: entry.fileSize };
    } catch (error) {
      if (!(error instanceof XrayArtifactError) || error.code !== "ARTIFACT_INTEGRITY_FAILED") throw error;
    }

    const fetchImpl: FetchLike = options.fetchImpl ?? ((input) => fetch(input, {
      method: "GET",
      redirect: "follow",
      headers: { accept: "application/octet-stream" },
    }));
    const temporaryPath = path.join(path.dirname(destination), `.${entry.archiveName}.${crypto.randomUUID()}.tmp`);
    try {
      const digestResponse = await fetchApprovedSource(fetchImpl, entry.digestSource);
      await readVerifiedDigest(digestResponse, entry);
      const archiveResponse = await fetchApprovedSource(fetchImpl, entry.source);
      await downloadArchive(archiveResponse, temporaryPath, entry);
      await verifyXrayArtifactFile(temporaryPath, entry);
      await fs.rename(temporaryPath, destination);
      await fs.chmod(destination, 0o644);
      await verifyXrayArtifactFile(destination, entry);
      const artifactId = await persistArtifactStatus(entry, "VERIFIED");
      return { artifactId, storageKey: entry.storageKey, sha256: entry.sha256, fileSize: entry.fileSize };
    } catch (error) {
      await fs.rm(temporaryPath, { force: true }).catch(() => undefined);
      await persistArtifactStatus(entry, "INVALID").catch(() => undefined);
      if (error instanceof XrayArtifactError) throw error;
      throw new XrayArtifactError("ARTIFACT_SOURCE_FAILED", { cause: error });
    }
  });
}

function rowMatchesManifest(row: Record<string, unknown>, entry: Readonly<XrayArtifactManifestEntry>) {
  return row.version === entry.version
    && row.os === entry.os
    && row.arch === entry.arch
    && row.packageFormat === entry.packageFormat
    && row.storageKey === entry.storageKey
    && row.sha256 === entry.sha256
    && Number(row.fileSize) === entry.fileSize
    && row.status === "VERIFIED"
    && row.source === entry.source
    && row.verifiedAt !== null
    && row.verifiedAt !== undefined;
}

export async function setDefaultXrayVersion(version: string): Promise<void> {
  if (version !== XRAY_DEFAULT_VERSION) throw new XrayArtifactError("ARTIFACT_UNSUPPORTED");
  const entries = XRAY_ARTIFACT_MANIFEST.filter((entry) => entry.version === version);
  await withDatabaseTransaction(async () => {
    const q = quoteIdentifier;
    const rows = await queryRaw<Record<string, unknown>>(
      `SELECT ${q("version")}, ${q("os")}, ${q("arch")}, ${q("packageFormat")}, ${q("storageKey")}, ${q("sha256")}, ${q("fileSize")}, ${q("status")}, ${q("source")}, ${q("verifiedAt")} FROM ${q("xray_artifacts")} WHERE ${q("version")} = ?`,
      [version],
    );
    const complete = entries.length > 0 && entries.every((entry) => rows.some((row) => rowMatchesManifest(row, entry)));
    if (!complete) throw new XrayArtifactError("ARTIFACT_MANIFEST_INCOMPLETE");
    await setSetting(XRAY_DEFAULT_VERSION_SETTING_KEY, version);
  });
}

export async function getDefaultXrayVersion(): Promise<typeof XRAY_DEFAULT_VERSION | null> {
  const version = await getSetting(XRAY_DEFAULT_VERSION_SETTING_KEY);
  return version === XRAY_DEFAULT_VERSION ? version : null;
}

type CacheXrayArtifact = typeof cacheOfficialXrayArtifact;
type SetDefaultXrayVersion = typeof setDefaultXrayVersion;

export type PrepareDefaultXrayArtifactsOptions = {
  dataDirectory: string;
  cacheArtifact?: CacheXrayArtifact;
  setDefaultVersion?: SetDefaultXrayVersion;
};

export async function prepareDefaultXrayArtifacts(
  options: PrepareDefaultXrayArtifactsOptions,
): Promise<void> {
  const cacheArtifact = options.cacheArtifact ?? cacheOfficialXrayArtifact;
  const setDefaultVersion = options.setDefaultVersion ?? setDefaultXrayVersion;
  for (const entry of XRAY_ARTIFACT_MANIFEST) {
    await cacheArtifact(
      { version: entry.version, os: entry.os, arch: entry.arch },
      { dataDirectory: options.dataDirectory },
    );
  }
  await setDefaultVersion(XRAY_DEFAULT_VERSION);
}

export type VerifiedXrayArtifactDownload = {
  artifactId: number;
  version: string;
  os: string;
  arch: string;
  archiveName: string;
  filePath: string;
  fileSize: number;
  sha256: string;
};

export type ResolveVerifiedXrayArtifactDownloadInput = {
  artifactId: number;
  os: string;
  arch: string;
  dataDirectory: string;
};

function artifactIdValue(value: unknown) {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) throw new XrayArtifactError("ARTIFACT_NOT_FOUND");
  return id;
}

async function artifactRecordById(artifactId: number) {
  const q = quoteIdentifier;
  const rows = await queryRaw<Record<string, unknown>>(
    `SELECT ${q("id")}, ${q("version")}, ${q("os")}, ${q("arch")}, ${q("packageFormat")}, ${q("storageKey")}, ${q("sha256")}, ${q("fileSize")}, ${q("status")}, ${q("source")}, ${q("verifiedAt")} FROM ${q("xray_artifacts")} WHERE ${q("id")} = ? LIMIT 1`,
    [artifactId],
  );
  return rows[0] ?? null;
}

export async function resolveVerifiedXrayArtifactDownload(
  input: ResolveVerifiedXrayArtifactDownloadInput,
): Promise<VerifiedXrayArtifactDownload> {
  const artifactId = artifactIdValue(input.artifactId);
  const initial = await artifactRecordById(artifactId);
  if (!initial) throw new XrayArtifactError("ARTIFACT_NOT_FOUND");
  if (initial.os !== input.os || initial.arch !== input.arch) {
    throw new XrayArtifactError("ARTIFACT_PLATFORM_MISMATCH");
  }

  let entry: Readonly<XrayArtifactManifestEntry>;
  try {
    entry = getXrayArtifactManifestEntry({
      version: String(initial.version ?? ""),
      os: String(initial.os ?? ""),
      arch: String(initial.arch ?? ""),
    });
  } catch {
    throw new XrayArtifactError("ARTIFACT_NOT_FOUND");
  }

  return withKeyedTaskLock(`xray-artifact:${artifactIdentityKey(entry)}`, async () => {
    const row = await artifactRecordById(artifactId);
    if (!row) throw new XrayArtifactError("ARTIFACT_NOT_FOUND");
    if (row.os !== input.os || row.arch !== input.arch) {
      throw new XrayArtifactError("ARTIFACT_PLATFORM_MISMATCH");
    }
    if (!rowMatchesManifest(row, entry)) {
      await persistArtifactStatus(entry, "INVALID").catch(() => undefined);
      throw new XrayArtifactError("ARTIFACT_NOT_FOUND");
    }

    const filePath = resolveXrayArtifactStoragePath(input.dataDirectory, entry.storageKey);
    try {
      await verifyXrayArtifactFile(filePath, entry);
    } catch {
      await persistArtifactStatus(entry, "INVALID").catch(() => undefined);
      throw new XrayArtifactError("ARTIFACT_NOT_FOUND");
    }
    return {
      artifactId,
      version: entry.version,
      os: entry.os,
      arch: entry.arch,
      archiveName: entry.archiveName,
      filePath,
      fileSize: entry.fileSize,
      sha256: entry.sha256,
    };
  });
}
