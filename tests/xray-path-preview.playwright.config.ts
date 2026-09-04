import { defineConfig } from "@playwright/test";
import path from "node:path";

// UI-only fixture: no panel database, DNSPod credentials, Agent or API writes.
export default defineConfig({
  testDir: ".", testMatch: "xray-path-preview.spec.ts", workers: 1, reporter: "line",
  use: { baseURL: "http://127.0.0.1:43179", browserName: "chromium" },
  webServer: {
    cwd: path.resolve(import.meta.dirname, ".."),
    command: "corepack pnpm exec vite --host 127.0.0.1 --port 43179 --strictPort",
    url: "http://127.0.0.1:43179/tests/fixtures/xray-path-preview.html",
    reuseExistingServer: process.env.FORWARDPLUS_PATH_PREVIEW_SERVER === "existing", timeout: 30_000,
  },
});
