import { ENV } from "./env";

const TRUSTED_GITHUB_HOSTS = new Set([
  "api.github.com",
  "codeload.github.com",
  "github.com",
  "raw.githubusercontent.com",
  "uploads.github.com",
]);

function isTrustedGithubUrl(value: string) {
  try {
    const url = new URL(value);
    return url.protocol === "https:"
      && (!url.port || url.port === "443")
      && TRUSTED_GITHUB_HOSTS.has(url.hostname.toLowerCase());
  } catch {
    return false;
  }
}

/**
 * Adds the optional server-side token only to official GitHub hosts. In
 * particular, the token must never be forwarded to a configured accelerator.
 */
export function withGithubAuth(url: string, init: RequestInit = {}): RequestInit {
  const headers = new Headers(init.headers);
  const token = ENV.githubToken.trim();
  if (token && isTrustedGithubUrl(url)) {
    headers.set("Authorization", `Bearer ${token}`);
    headers.set("X-GitHub-Api-Version", "2022-11-28");
  }
  return { ...init, headers };
}
