import crypto from "crypto";
import { Readable } from "stream";
import { Router, type Request, type Response } from "express";
import { ENV } from "./env";
import { withGithubAuth } from "./githubAuth";

const DOWNLOAD_TTL_SECONDS = 5 * 60;
const REPOSITORY = "wzwys9/Forwardplus";

function sign(unsigned: string) {
  return crypto.createHmac("sha256", ENV.cookieSecret).update(unsigned, "utf8").digest("base64url");
}

export function createMobileReleaseDownloadToken(assetId: number, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (!Number.isSafeInteger(assetId) || assetId <= 0) throw new Error("Invalid release asset id");
  const unsigned = `${assetId}.${nowSeconds + DOWNLOAD_TTL_SECONDS}`;
  return `${unsigned}.${sign(unsigned)}`;
}

export function verifyMobileReleaseDownloadToken(token: unknown, assetId: number, nowSeconds = Math.floor(Date.now() / 1000)) {
  const match = String(token || "").match(/^(\d+)\.(\d+)\.([A-Za-z0-9_-]{43})$/);
  if (!match || Number(match[1]) !== assetId) return false;
  const expiresAt = Number(match[2]);
  if (!Number.isSafeInteger(expiresAt) || expiresAt < nowSeconds || expiresAt > nowSeconds + DOWNLOAD_TTL_SECONDS + 30) return false;
  const expected = Buffer.from(sign(`${match[1]}.${match[2]}`), "base64url");
  const actual = Buffer.from(match[3], "base64url");
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

export function mobileReleaseDownloadPath(assetId: number) {
  const token = createMobileReleaseDownloadToken(assetId);
  return `/api/mobile/releases/android/${assetId}.apk?token=${encodeURIComponent(token)}`;
}

export const mobileReleaseRouter = Router();

mobileReleaseRouter.get("/api/mobile/releases/android/:assetId.apk", async (req: Request, res: Response) => {
  const assetId = Number(req.params.assetId);
  if (!Number.isSafeInteger(assetId) || assetId <= 0 || !verifyMobileReleaseDownloadToken(req.query.token, assetId)) {
    res.status(404).send("Not found");
    return;
  }

  const apiUrl = `https://api.github.com/repos/${REPOSITORY}/releases/assets/${assetId}`;
  try {
    const upstream = await fetch(apiUrl, withGithubAuth(apiUrl, {
      cache: "no-store",
      headers: {
        Accept: "application/octet-stream",
        "User-Agent": "Forwardplus-mobile-update",
      },
    }));
    if (!upstream.ok || !upstream.body) {
      res.status(upstream.status === 404 ? 404 : 502).send("Release asset unavailable");
      return;
    }
    res.setHeader("Content-Type", upstream.headers.get("content-type") || "application/vnd.android.package-archive");
    res.setHeader("Content-Disposition", "attachment; filename=\"forwardplus-android.apk\"");
    res.setHeader("Cache-Control", "private, no-store");
    res.setHeader("Referrer-Policy", "no-referrer");
    Readable.fromWeb(upstream.body as any).pipe(res);
  } catch {
    if (!res.headersSent) res.status(502).send("Release asset unavailable");
    else res.destroy();
  }
});
