import path from "node:path";
import { constants as fsConstants } from "node:fs";
import fs from "node:fs/promises";
import { pipeline } from "node:stream/promises";
import type { Request, Response, Router } from "express";

import {
  AGENT_AUTH_RESULT_ACCEPTED,
  AGENT_AUTH_RESULT_HEADER,
  AGENT_AUTH_RESULT_REJECTED,
  getAgentHostFromRequest,
  resolveAgentTokenFromAuthorization,
} from "./agentAuth";
import { quoteIdentifier } from "./dbCompat";
import { queryRaw } from "./dbRuntime";
import { ENV } from "./env";
import { panelCryptoNowMs } from "./panelClock";
import {
  ManagedServiceArtifactError,
  resolveManagedServiceArtifactDownload,
} from "./xrayManagedServiceArtifacts";

export const MANAGED_SERVICE_AGENT_OS_HEADER = "X-ForwardX-Managed-Service-OS";
export const MANAGED_SERVICE_AGENT_ARCH_HEADER = "X-ForwardX-Managed-Service-Arch";

function dataDirectory() {
  return path.resolve(path.dirname(ENV.databaseConfigPath || ENV.sqlitePath || "/data/database.json"));
}

async function authenticatedHost(req: Request) {
  const token = await resolveAgentTokenFromAuthorization(req, "", panelCryptoNowMs());
  if (!token) return null;
  (req as Request & { agentToken?: string }).agentToken = token;
  return getAgentHostFromRequest(req);
}

async function storedCapabilityMatches(hostId: number, os: string, arch: string) {
  const q = quoteIdentifier;
  const rows = await queryRaw<{ capabilityJson: unknown }>(
    `SELECT ${q("capabilityJson")} FROM ${q("xray_managed_service_runtime_reports")} WHERE ${q("hostId")}=? LIMIT 1`, [hostId],
  );
  try {
    const capability = JSON.parse(String(rows[0]?.capabilityJson ?? ""));
    return capability.schemaVersion === 1 && capability.supportsArtifactInstall === true
      && capability.runsAsDedicatedUser === true && capability.supportedOS === os && capability.supportedArch === arch
      && Array.isArray(capability.supportedKinds) && capability.supportedKinds.includes("MTPROTO_FAKE_TLS");
  } catch {
    return false;
  }
}

export function registerAgentManagedServiceArtifactRoute(router: Router) {
  router.get("/api/agent/artifacts/managed-service/:artifactId", async (req: Request, res: Response) => {
    res.setHeader("Cache-Control", "private, no-store, max-age=0");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Accept-Ranges", "none");
    const host = await authenticatedHost(req).catch(() => null);
    if (!host) {
      res.setHeader(AGENT_AUTH_RESULT_HEADER, AGENT_AUTH_RESULT_REJECTED);
      res.status(401).json({ error: "Unauthorized" });
      return;
    }
    res.setHeader(AGENT_AUTH_RESULT_HEADER, AGENT_AUTH_RESULT_ACCEPTED);
    const rawId = String(req.params.artifactId ?? "");
    const artifactId = /^[1-9][0-9]*$/.test(rawId) ? Number(rawId) : 0;
    const os = String(req.header(MANAGED_SERVICE_AGENT_OS_HEADER) ?? "").trim();
    const arch = String(req.header(MANAGED_SERVICE_AGENT_ARCH_HEADER) ?? "").trim();
    if (!Number.isSafeInteger(artifactId) || artifactId <= 0 || Object.keys(req.query ?? {}).length > 0
      || os !== "linux" || (arch !== "amd64" && arch !== "arm64") || req.headers.range) {
      res.status(req.headers.range ? 416 : 400).json({ error: "Invalid artifact request" });
      return;
    }
    const hostId = Number((host as { id?: unknown }).id ?? 0);
    if (!await storedCapabilityMatches(hostId, os, arch)) {
      res.status(403).json({ error: "ARTIFACT_PLATFORM_MISMATCH" });
      return;
    }
    let handle: Awaited<ReturnType<typeof fs.open>> | null = null;
    try {
      const root = dataDirectory();
      const download = await resolveManagedServiceArtifactDownload({ artifactId, os, arch, dataDirectory: root });
      const resolved = path.resolve(download.filePath);
      if (!resolved.startsWith(`${root}${path.sep}`)) throw new ManagedServiceArtifactError("ARTIFACT_NOT_FOUND");
      const noFollow = "O_NOFOLLOW" in fsConstants ? fsConstants.O_NOFOLLOW : 0;
      handle = await fs.open(resolved, fsConstants.O_RDONLY | noFollow);
      const opened = await handle.stat();
      if (!opened.isFile() || opened.size !== download.fileSize) throw new ManagedServiceArtifactError("ARTIFACT_NOT_FOUND");
      res.status(200);
      res.setHeader("Content-Type", "application/octet-stream");
      res.setHeader("Content-Length", String(download.fileSize));
      res.setHeader("Content-Disposition", `attachment; filename="${download.archiveName}"`);
      res.setHeader("ETag", `"sha256:${download.sha256}"`);
      res.setHeader("X-ForwardX-Artifact-SHA256", download.sha256);
      res.setHeader("X-ForwardX-Artifact-Version", download.version);
      res.setHeader("X-ForwardX-Artifact-OS", download.os);
      res.setHeader("X-ForwardX-Artifact-Arch", download.arch);
      await pipeline(handle.createReadStream({ autoClose: false }), res);
    } catch (error) {
      const code = error instanceof ManagedServiceArtifactError ? error.code : "ARTIFACT_NOT_FOUND";
      if (res.headersSent) res.destroy();
      else res.status(code === "ARTIFACT_PLATFORM_MISMATCH" ? 403 : 404).json({ error: code });
    } finally {
      await handle?.close().catch(() => undefined);
    }
  });
}
