import assert from "node:assert/strict";
import test from "node:test";
import { AGENT_TUNNEL_PATHS } from "./agentEncryptionMiddleware";
import {
  completeSupportBundleHost,
  createSupportBundleTask,
  getSupportBundleTask,
  redactSupportValue,
} from "./supportBundle";

test("Agent support and migration reports are accepted through the encrypted sync tunnel", () => {
  assert.equal(AGENT_TUNNEL_PATHS.has("/api/agent/support-bundle-result"), true);
  assert.equal(AGENT_TUNNEL_PATHS.has("/api/agent/migration-rollback"), true);
});

test("support bundle redaction removes nested credentials", () => {
  const value = redactSupportValue({ token: "abc", nested: { password: "def", message: "token=ghi" } });
  assert.deepEqual(value, { token: "[REDACTED]", nested: { password: "[REDACTED]", message: "token=[REDACTED]" } });
});

test("support bundle completes immediately for offline Agents", async () => {
  const task = createSupportBundleTask([{ id: 9, name: "offline", isOnline: false, agentToken: "hidden" }]);
  const status = await getSupportBundleTask(task.taskId);
  assert.equal(status?.complete, true);
  assert.equal(status?.hosts[0]?.status, "offline");
  assert.ok(status?.download?.content.includes("forwardx-support-bundle-v1"));
  assert.ok(!status?.download?.content.includes("hidden"));
});

test("generated support bundle contains only approved Xray runtime fields and no unique secrets", async () => {
  const secrets = {
    token: "xray-token-UNIQUE-031-bundle",
    uuid: "03103103-1031-4031-8031-031031031031",
    privateKey: "PRIVATEKEYUNIQUE031-bundle",
    shortId: "0310310310310310",
    config: "CONFIGJSONUNIQUE031-bundle",
  };
  const task = createSupportBundleTask([{ id: 31, name: "edge", isOnline: true, agentToken: secrets.token }]);
  assert.equal(completeSupportBundleHost(task.taskId, 31, {
    diagnostics: {
      xrayRuntime: {
        installedVersion: "26.7.28",
        serviceStatus: "RUNNING",
        configHashPrefix: "aaaaaaaaaaaa",
        listeners: [{ runtimeTag: "forwardx-inbound-safe", port: 443, status: "READY", network: "tcp" }],
        processId: 3131,
        generation: 31,
        uuid: secrets.uuid,
        shortId: secrets.shortId,
        privateKey: secrets.privateKey,
        configJson: secrets.config,
      },
      commands: [{ output: `Authorization: Bearer ${secrets.token} runtime={"uuid":"${secrets.uuid}"}` }],
    },
  }), true);
  const status = await getSupportBundleTask(task.taskId);
  assert.equal(status?.complete, true);
  const content = status?.download?.content ?? "";
  for (const secret of Object.values(secrets)) assert.doesNotMatch(content, new RegExp(secret));
  assert.match(content, /forwardx-inbound-safe/);
  assert.match(content, /aaaaaaaaaaaa/);
  assert.match(content, /"port": 443/);
  assert.doesNotMatch(content, /"processId"/);
  assert.doesNotMatch(content, /"generation"/);
  assert.doesNotMatch(content, /"network"/);
});
