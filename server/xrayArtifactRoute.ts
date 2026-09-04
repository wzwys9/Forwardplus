import { constants as fsConstants } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { pipeline } from "node:stream/promises";

import type { Request, Response, Router } from "express";

import {
  AGENT_AUTH_RESULT_ACCEPTED,
  AGENT_AUTH_RESULT_HEADER,
  AGENT_AUTH_RESULT_REJECTED,
  getAgentHostFromRequest,
  resolveAgentTokenFromAuthorization,
} from "./agentAuth";
import { appendPanelLog, type PanelLogLevel } from "./_core/panelLogger";
import { ENV } from "./env";
import { panelCryptoNowMs } from "./panelClock";
import {
  XRAY_DEFAULT_VERSION,
  XrayArtifactError,
  resolveVerifiedXrayArtifactDownload,
  type ResolveVerifiedXrayArtifactDownloadInput,
  type VerifiedXrayArtifactDownload,
} from "./xrayArtifacts";
import { getXrayRuntimeReport } from "./repositories/xrayRepository";

export const XRAY_AGENT_OS_HEADER = "X-ForwardX-Xray-OS";
export const XRAY_AGENT_ARCH_HEADER = "X-ForwardX-Xray-Arch";

type ArtifactResolver = (
  input: ResolveVerifiedXrayArtifactDownloadInput,
) => Promise<VerifiedXrayArtifactDownload>;

type ArtifactRouteLogger = (level: PanelLogLevel, message: string) => void;

export type AgentXrayArtifactRouteOptions = {
  dataDirectory?: string;
  resolveArtifact?: ArtifactResolver;
  log?: ArtifactRouteLogger;
};

function defaultArtifactDataDirectory() {
  return path.dirname(ENV.databaseConfigPath || ENV.sqlitePath || "/data/database.json");
}

function artifactIdFromRequest(req: Request) {
  const raw = String(req.params.artifactId || "");
  if (!/^[1-9][0-9]*$/.test(raw)) return null;
  const artifactId = Number(raw);
  return Number.isSafeInteger(artifactId) ? artifactId : null;
}

function platformFromRequest(req: Request) {
  const os = String(req.header(XRAY_AGENT_OS_HEADER) || "").trim();
  const arch = String(req.header(XRAY_AGENT_ARCH_HEADER) || "").trim();
  if (os !== "linux" || (arch !== "amd64" && arch !== "arm64")) return null;
  return { os, arch };
}

function routeLogMessage(hostId: number, artifactId: number, result: string, bytes: number) {
  return `[XrayArtifact] host=${hostId} artifact=${artifactId} result=${result} bytes=${bytes}`;
}

function isSafeDownload(download: VerifiedXrayArtifactDownload, dataDirectory: string) {
  const root = path.resolve(dataDirectory);
  const filePath = path.resolve(download.filePath);
  return download.artifactId > 0
    && download.version === XRAY_DEFAULT_VERSION
    && download.fileSize > 0
    && Number.isSafeInteger(download.fileSize)
    && /^[a-f0-9]{64}$/.test(download.sha256)
    && /^[A-Za-z0-9][A-Za-z0-9._-]*\.zip$/.test(download.archiveName)
    && path.basename(download.archiveName) === download.archiveName
    && filePath.startsWith(`${root}${path.sep}`);
}

export function registerAgentXrayArtifactRoute(router: Router, options: AgentXrayArtifactRouteOptions = {}) {
  const dataDirectory = path.resolve(options.dataDirectory || defaultArtifactDataDirectory());
  const resolveArtifact = options.resolveArtifact || resolveVerifiedXrayArtifactDownload;
  const log: ArtifactRouteLogger = options.log || ((level, message) => appendPanelLog(level, message));
  const record = (level: PanelLogLevel, message: string) => {
    try { log(level, message); } catch { /* artifact delivery must not depend on audit I/O */ }
  };

  router.get("/api/agent/artifacts/xray/:artifactId", async (req: Request, res: Response) => {
    res.setHeader("Cache-Control", "private, no-store, max-age=0");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Accept-Ranges", "none");

    let token: string | null = null;
    let host: Awaited<ReturnType<typeof getAgentHostFromRequest>> = null;
    try {
      token = await resolveAgentTokenFromAuthorization(req, "", panelCryptoNowMs());
      if (token) {
        (req as Request & { agentToken?: string }).agentToken = token;
        host = await getAgentHostFromRequest(req);
      }
    } catch {
      token = null;
      host = null;
    }
    if (!token || !host) {
      res.setHeader(AGENT_AUTH_RESULT_HEADER, AGENT_AUTH_RESULT_REJECTED);
      res.status(401).json({ error: "Unauthorized" });
      return;
    }
    res.setHeader(AGENT_AUTH_RESULT_HEADER, AGENT_AUTH_RESULT_ACCEPTED);

    const hostId = Number((host as { id?: unknown }).id || 0);
    const artifactId = artifactIdFromRequest(req);
    if (!artifactId || Object.keys(req.query || {}).length > 0) {
      record("warn", routeLogMessage(hostId, artifactId || 0, "INVALID_REQUEST", 0));
      res.status(400).json({ error: "Invalid artifact request" });
      return;
    }
    const platform = platformFromRequest(req);
    if (!platform) {
      record("warn", routeLogMessage(hostId, artifactId, "PLATFORM_UNSUPPORTED", 0));
      res.status(400).json({ error: "Unsupported Agent platform" });
      return;
    }
    const runtimeReport = await getXrayRuntimeReport(hostId).catch(() => null);
    if (!runtimeReport || runtimeReport.capabilitySchemaVersion !== 1
      || runtimeReport.supportedOS !== platform.os || runtimeReport.supportedArch !== platform.arch) {
      record("warn", routeLogMessage(hostId, artifactId, "ARTIFACT_PLATFORM_MISMATCH", 0));
      res.status(403).json({ error: "ARTIFACT_PLATFORM_MISMATCH" });
      return;
    }
    if (req.headers.range) {
      record("warn", routeLogMessage(hostId, artifactId, "RANGE_UNSUPPORTED", 0));
      res.status(416).json({ error: "Range requests are not supported" });
      return;
    }

    let download: VerifiedXrayArtifactDownload;
    try {
      download = await resolveArtifact({ artifactId, ...platform, dataDirectory });
      if (download.artifactId !== artifactId
        || download.os !== platform.os
        || download.arch !== platform.arch) {
        throw new XrayArtifactError("ARTIFACT_PLATFORM_MISMATCH");
      }
      if (!isSafeDownload(download, dataDirectory)) throw new XrayArtifactError("ARTIFACT_NOT_FOUND");
    } catch (error) {
      const code = error instanceof XrayArtifactError ? error.code : "ARTIFACT_NOT_FOUND";
      const status = code === "ARTIFACT_PLATFORM_MISMATCH" ? 403 : 404;
      record("warn", routeLogMessage(hostId, artifactId, code, 0));
      res.status(status).json({ error: code });
      return;
    }

    res.status(200);
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Length", String(download.fileSize));
    res.setHeader("Content-Disposition", `attachment; filename="${download.archiveName}"`);
    res.setHeader("ETag", `"sha256:${download.sha256}"`);
    res.setHeader("X-ForwardX-Artifact-SHA256", download.sha256);
    res.setHeader("X-ForwardX-Artifact-Version", download.version);
    res.setHeader("X-ForwardX-Artifact-OS", download.os);
    res.setHeader("X-ForwardX-Artifact-Arch", download.arch);

    const noFollow = "O_NOFOLLOW" in fsConstants ? fsConstants.O_NOFOLLOW : 0;
    let fileHandle: Awaited<ReturnType<typeof fs.open>> | null = null;
    try {
      fileHandle = await fs.open(download.filePath, fsConstants.O_RDONLY | noFollow);
      const opened = await fileHandle.stat();
      if (!opened.isFile() || opened.size !== download.fileSize) {
        throw new XrayArtifactError("ARTIFACT_NOT_FOUND");
      }
      await pipeline(
        fileHandle.createReadStream({ autoClose: false }),
        res,
      );
      record("info", routeLogMessage(hostId, artifactId, "SERVED", download.fileSize));
    } catch {
      record("warn", routeLogMessage(hostId, artifactId, "STREAM_FAILED", 0));
      if (!res.headersSent) {
        for (const header of ["Content-Length", "Content-Disposition", "ETag", "X-ForwardX-Artifact-SHA256",
          "X-ForwardX-Artifact-Version", "X-ForwardX-Artifact-OS", "X-ForwardX-Artifact-Arch"]) {
          res.removeHeader(header);
        }
        res.status(503).json({ error: "Artifact stream failed" });
      } else res.destroy();
    } finally {
      await fileHandle?.close().catch(() => undefined);
    }
  });
}
