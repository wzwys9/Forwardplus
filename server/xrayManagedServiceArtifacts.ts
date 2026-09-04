import crypto from "node:crypto";
import fsConstants from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";

import { quoteIdentifier } from "./dbCompat";
import { executeRaw, insertAndGetId, nowDate, queryRaw, rawAffectedRows } from "./dbRuntime";
import { withKeyedTaskLock } from "./keyedTaskLock";

export const MTPROTO_MANAGED_SERVICE_KIND = "MTPROTO_FAKE_TLS" as const;
export const MTPROTO_DEFAULT_VERSION = "v1.15.0" as const;

export type ManagedServiceArtifactManifestEntry = Readonly<{
  kind: typeof MTPROTO_MANAGED_SERVICE_KIND;
  version: typeof MTPROTO_DEFAULT_VERSION;
  os: "linux";
  arch: "amd64" | "arm64";
  packageFormat: "tar.gz";
  archiveName: string;
  storageKey: string;
  source: string;
  sha256: string;
  fileSize: number;
  checksumSource: string;
  checksumSha256: string;
  checksumFileSize: number;
}>;

const releaseBase = `https://github.com/MHSanaei/mtg-multi/releases/download/${MTPROTO_DEFAULT_VERSION}`;
const checksumName = "mtg-multi-1.15.0-checksums.txt";
const checksumSha256 = "90ba733fefcadb0de8c3fe82d3ac5165deacfe96d4feaad7891256b5e32d3740";

function entry(arch: "amd64" | "arm64", fileSize: number, sha256: string): ManagedServiceArtifactManifestEntry {
  const archiveName = `mtg-multi-1.15.0-linux-${arch}.tar.gz`;
  return Object.freeze({
    kind: MTPROTO_MANAGED_SERVICE_KIND,
    version: MTPROTO_DEFAULT_VERSION,
    os: "linux",
    arch,
    packageFormat: "tar.gz",
    archiveName,
    storageKey: `managed-services/mtproto/${MTPROTO_DEFAULT_VERSION}/linux/${arch}/${archiveName}`,
    source: `${releaseBase}/${archiveName}`,
    sha256,
    fileSize,
    checksumSource: `${releaseBase}/${checksumName}`,
    checksumSha256,
    checksumFileSize: 1013,
  });
}

export const MANAGED_SERVICE_ARTIFACT_MANIFEST = Object.freeze([
  entry("amd64", 5_307_638, "f1f8763504753fb863a0ddff83eab19c856747289c376275c44b717f1747908e"),
  entry("arm64", 4_767_178, "9ed776b2052b95e8344896d43fbe01250014f36d7cfdd7f29f7903179bce4bed"),
]);

export class ManagedServiceArtifactError extends Error {
  constructor(readonly code: "ARTIFACT_UNSUPPORTED" | "ARTIFACT_SOURCE_FAILED" | "ARTIFACT_INTEGRITY_FAILED" | "ARTIFACT_NOT_FOUND" | "ARTIFACT_PLATFORM_MISMATCH", options?: ErrorOptions) {
    super(code, options);
    this.name = "ManagedServiceArtifactError";
  }
}

function safeStoragePath(dataDirectory: string, storageKey: string) {
  if (!storageKey || storageKey.includes("\\") || path.posix.isAbsolute(storageKey)
    || path.posix.normalize(storageKey) !== storageKey
    || storageKey.split("/").some((part) => !part || part === "." || part === "..")) {
    throw new ManagedServiceArtifactError("ARTIFACT_INTEGRITY_FAILED");
  }
  const root = path.resolve(dataDirectory);
  const destination = path.resolve(root, ...storageKey.split("/"));
  if (!destination.startsWith(`${root}${path.sep}`)) throw new ManagedServiceArtifactError("ARTIFACT_INTEGRITY_FAILED");
  return destination;
}

async function sha256File(filePath: string, expectedSize: number) {
  let handle: Awaited<ReturnType<typeof fs.open>> | undefined;
  try {
    const before = await fs.lstat(filePath);
    if (!before.isFile() || before.isSymbolicLink() || before.size !== expectedSize) throw new Error("invalid artifact file");
    handle = await fs.open(filePath, fsConstants.constants.O_RDONLY | (fsConstants.constants.O_NOFOLLOW ?? 0));
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size !== expectedSize) throw new Error("artifact changed");
    const hash = crypto.createHash("sha256");
    let size = 0;
    for await (const chunk of handle.createReadStream({ autoClose: false })) {
      const data = Buffer.from(chunk);
      size += data.byteLength;
      if (size > expectedSize) throw new Error("artifact too large");
      hash.update(data);
    }
    if (size !== expectedSize) throw new Error("artifact size mismatch");
    return hash.digest("hex");
  } catch (error) {
    throw new ManagedServiceArtifactError("ARTIFACT_INTEGRITY_FAILED", { cause: error });
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

function manifestFor(input: { kind: string; version: string; os: string; arch: string }) {
  const found = MANAGED_SERVICE_ARTIFACT_MANIFEST.find((candidate) => (
    candidate.kind === input.kind && candidate.version === input.version
    && candidate.os === input.os && candidate.arch === input.arch
  ));
  if (!found) throw new ManagedServiceArtifactError("ARTIFACT_UNSUPPORTED");
  return found;
}

async function readBoundedResponse(response: Response, expectedSize: number) {
  if (!response.ok || !response.body) throw new ManagedServiceArtifactError("ARTIFACT_SOURCE_FAILED");
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > expectedSize) {
      await reader.cancel().catch(() => undefined);
      throw new ManagedServiceArtifactError("ARTIFACT_INTEGRITY_FAILED");
    }
    chunks.push(Buffer.from(value));
  }
  if (size !== expectedSize) throw new ManagedServiceArtifactError("ARTIFACT_INTEGRITY_FAILED");
  return Buffer.concat(chunks);
}

async function verifyOfficialChecksum(fetchImpl: typeof fetch, item: ManagedServiceArtifactManifestEntry) {
  let response: Response;
  try {
    response = await fetchImpl(item.checksumSource, { redirect: "follow", cache: "no-store" });
  } catch (error) {
    throw new ManagedServiceArtifactError("ARTIFACT_SOURCE_FAILED", { cause: error });
  }
  const bytes = await readBoundedResponse(response, item.checksumFileSize);
  if (crypto.createHash("sha256").update(bytes).digest("hex") !== item.checksumSha256) {
    throw new ManagedServiceArtifactError("ARTIFACT_INTEGRITY_FAILED");
  }
  const escaped = item.archiveName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const declared = new RegExp(`^([0-9a-f]{64})\\s+${escaped}$`, "m").exec(bytes.toString("utf8"))?.[1];
  if (declared !== item.sha256) throw new ManagedServiceArtifactError("ARTIFACT_INTEGRITY_FAILED");
}

async function upsertArtifact(item: ManagedServiceArtifactManifestEntry, status: "VERIFIED" | "INVALID") {
  const q = quoteIdentifier;
  const now = nowDate();
  const values = [item.packageFormat, item.storageKey, item.sha256, item.fileSize, status, item.source,
    status === "VERIFIED" ? now : null, now, item.kind, item.version, item.os, item.arch];
  const result = await executeRaw(
    `UPDATE ${q("xray_managed_service_artifacts")} SET ${q("packageFormat")}=?, ${q("storageKey")}=?, ${q("sha256")}=?, ${q("fileSize")}=?, ${q("status")}=?, ${q("source")}=?, ${q("verifiedAt")}=?, ${q("updatedAt")}=? WHERE ${q("kind")}=? AND ${q("version")}=? AND ${q("os")}=? AND ${q("arch")}=?`,
    values,
  );
  if (rawAffectedRows(result) === 0) {
    try {
      await insertAndGetId("xray_managed_service_artifacts", {
        kind: item.kind, version: item.version, os: item.os, arch: item.arch,
        packageFormat: item.packageFormat, storageKey: item.storageKey, sha256: item.sha256,
        fileSize: item.fileSize, status, source: item.source, verifiedAt: status === "VERIFIED" ? now : null,
        createdAt: now, updatedAt: now,
      });
    } catch {
      await executeRaw(
        `UPDATE ${q("xray_managed_service_artifacts")} SET ${q("packageFormat")}=?, ${q("storageKey")}=?, ${q("sha256")}=?, ${q("fileSize")}=?, ${q("status")}=?, ${q("source")}=?, ${q("verifiedAt")}=?, ${q("updatedAt")}=? WHERE ${q("kind")}=? AND ${q("version")}=? AND ${q("os")}=? AND ${q("arch")}=?`,
        values,
      );
    }
  }
  const rows = await queryRaw<{ id: unknown }>(
    `SELECT ${q("id")} FROM ${q("xray_managed_service_artifacts")} WHERE ${q("kind")}=? AND ${q("version")}=? AND ${q("os")}=? AND ${q("arch")}=? LIMIT 1`,
    [item.kind, item.version, item.os, item.arch],
  );
  return Number(rows[0]?.id ?? 0);
}

export async function cacheManagedServiceArtifact(
  identity: { kind: string; version: string; os: string; arch: string },
  options: { dataDirectory: string; fetchImpl?: typeof fetch },
) {
  const item = manifestFor(identity);
  return withKeyedTaskLock(`managed-service-artifact:${item.kind}:${item.version}:${item.os}:${item.arch}`, async () => {
    const destination = safeStoragePath(options.dataDirectory, item.storageKey);
    const existingHash = await sha256File(destination, item.fileSize).catch(() => "");
    if (existingHash === item.sha256) {
      const artifactId = await upsertArtifact(item, "VERIFIED");
      return { artifactId, ...item, filePath: destination };
    }
    const fetchImpl = options.fetchImpl ?? fetch;
    await verifyOfficialChecksum(fetchImpl, item);
    await fs.mkdir(path.dirname(destination), { recursive: true, mode: 0o755 });
    const temporary = `${destination}.partial-${process.pid}-${crypto.randomBytes(8).toString("hex")}`;
    try {
      let response: Response;
      try {
        response = await fetchImpl(item.source, { redirect: "follow", cache: "no-store" });
      } catch (error) {
        throw new ManagedServiceArtifactError("ARTIFACT_SOURCE_FAILED", { cause: error });
      }
      const bytes = await readBoundedResponse(response, item.fileSize);
      if (crypto.createHash("sha256").update(bytes).digest("hex") !== item.sha256) {
        throw new ManagedServiceArtifactError("ARTIFACT_INTEGRITY_FAILED");
      }
      await fs.writeFile(temporary, bytes, { mode: 0o600, flag: "wx" });
      await fs.rename(temporary, destination);
      await fs.chmod(destination, 0o644);
      if (await sha256File(destination, item.fileSize) !== item.sha256) throw new ManagedServiceArtifactError("ARTIFACT_INTEGRITY_FAILED");
      const artifactId = await upsertArtifact(item, "VERIFIED");
      return { artifactId, ...item, filePath: destination };
    } catch (error) {
      await fs.rm(temporary, { force: true }).catch(() => undefined);
      await upsertArtifact(item, "INVALID").catch(() => undefined);
      if (error instanceof ManagedServiceArtifactError) throw error;
      throw new ManagedServiceArtifactError("ARTIFACT_SOURCE_FAILED", { cause: error });
    }
  });
}

export async function prepareDefaultManagedServiceArtifacts(options: { dataDirectory: string }) {
  for (const item of MANAGED_SERVICE_ARTIFACT_MANIFEST) {
    await cacheManagedServiceArtifact(item, options);
  }
}

function rowMatches(row: Record<string, unknown>, item: ManagedServiceArtifactManifestEntry) {
  return row.kind === item.kind && row.version === item.version && row.os === item.os && row.arch === item.arch
    && row.packageFormat === item.packageFormat && row.storageKey === item.storageKey && row.sha256 === item.sha256
    && Number(row.fileSize) === item.fileSize && row.status === "VERIFIED" && row.source === item.source && row.verifiedAt != null;
}

export async function resolveManagedServiceArtifactDownload(input: {
  artifactId: number; os: string; arch: string; dataDirectory: string;
}) {
  const q = quoteIdentifier;
  if (!Number.isSafeInteger(input.artifactId) || input.artifactId <= 0) throw new ManagedServiceArtifactError("ARTIFACT_NOT_FOUND");
  const rows = await queryRaw<Record<string, unknown>>(
    `SELECT * FROM ${q("xray_managed_service_artifacts")} WHERE ${q("id")}=? LIMIT 1`, [input.artifactId],
  );
  const row = rows[0];
  if (!row) throw new ManagedServiceArtifactError("ARTIFACT_NOT_FOUND");
  if (row.os !== input.os || row.arch !== input.arch) throw new ManagedServiceArtifactError("ARTIFACT_PLATFORM_MISMATCH");
  let item: ManagedServiceArtifactManifestEntry;
  try {
    item = manifestFor({ kind: String(row.kind), version: String(row.version), os: String(row.os), arch: String(row.arch) });
  } catch {
    throw new ManagedServiceArtifactError("ARTIFACT_NOT_FOUND");
  }
  if (!rowMatches(row, item)) throw new ManagedServiceArtifactError("ARTIFACT_NOT_FOUND");
  const filePath = safeStoragePath(input.dataDirectory, item.storageKey);
  if (await sha256File(filePath, item.fileSize) !== item.sha256) throw new ManagedServiceArtifactError("ARTIFACT_NOT_FOUND");
  return { artifactId: input.artifactId, ...item, filePath };
}

export async function findVerifiedMtprotoArtifact(os: string, arch: string) {
  const item = manifestFor({ kind: MTPROTO_MANAGED_SERVICE_KIND, version: MTPROTO_DEFAULT_VERSION, os, arch });
  const q = quoteIdentifier;
  const rows = await queryRaw<Record<string, unknown>>(
    `SELECT * FROM ${q("xray_managed_service_artifacts")} WHERE ${q("kind")}=? AND ${q("version")}=? AND ${q("os")}=? AND ${q("arch")}=? LIMIT 1`,
    [item.kind, item.version, item.os, item.arch],
  );
  const row = rows[0];
  if (!row || !rowMatches(row, item)) return null;
  return { artifactId: Number(row.id), packageFormat: item.packageFormat, sha256: item.sha256, fileSize: item.fileSize };
}
