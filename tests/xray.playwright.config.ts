import path from "node:path";

import { defineConfig } from "@playwright/test";

const root = path.resolve(import.meta.dirname, "..");
const devDirectory = path.join(root, ".tmp-xray-browser");
const baseURL = "http://127.0.0.1:43174";

process.env.FORWARDX_DEV_DIR = devDirectory;
process.env.FORWARDX_BROWSER_BASE_URL = baseURL;

export default defineConfig({
  testDir: root,
  testMatch: "tests/xray-browser-smoke.spec.ts",
  fullyParallel: false,
  workers: 1,
  reporter: "line",
  use: {
    baseURL,
    browserName: "chromium",
  },
  webServer: {
    command: "corepack pnpm dev:panel",
    cwd: root,
    url: `${baseURL}/xray`,
    reuseExistingServer: false,
    timeout: 30_000,
    env: {
      ...process.env,
      FORWARDX_DEV_DIR: devDirectory,
      FORWARDX_DEV_SERVER_PORT: "43173",
      FORWARDX_DEV_CLIENT_PORT: "43174",
      FORWARDX_XRAY_ENABLED: "1",
      XRAY_MASTER_KEY_PATH: path.join(devDirectory, "xray-master.key"),
    },
  },
});
