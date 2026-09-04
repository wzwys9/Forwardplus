import fs from "node:fs";
import path from "node:path";

import { expect, test } from "@playwright/test";
import Database from "better-sqlite3";

import { AGENT_VERSION } from "../shared/versions";
import { XRAY_ARTIFACT_MANIFEST, XRAY_DEFAULT_VERSION } from "../server/xrayArtifacts";
import {
  createXrayMasterKeyFile,
  encryptXraySecret,
  fingerprintXraySecret,
  xrayAccessSecretContext,
  xrayClientShortIdContext,
  xrayClientUuidContext,
  xrayInboundSecretContext,
  xrayInboundPrivateKeyContext,
} from "../server/xraySecretCrypto";
import { generateXrayWireGuardKeyPair, generateXrayWireGuardPreSharedKey } from "../server/xrayWireGuard";

const devDirectory = path.resolve(process.env.FORWARDX_DEV_DIR || ".dev-xray-browser");
const databasePath = path.join(devDirectory, "forwardx-dev.db");
const keyPath = path.join(devDirectory, "xray-master.key");
const baseURL = process.env.FORWARDX_BROWSER_BASE_URL || "http://127.0.0.1:5173";
let seededHostId = 0;
let seededWireGuardPrivateKey = "";
let seededWireGuardPsk = "";
let seededHttpUsername = "";
let seededHttpPassword = "";
let seededMixedUsername = "";
let seededMixedPassword = "";

async function waitForDatabase() {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (fs.existsSync(databasePath)) {
      const database = new Database(databasePath);
      try {
        database.prepare("SELECT 1 FROM users LIMIT 1").get();
        return database;
      } catch {
        database.close();
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error("isolated dev-panel database did not become ready");
}

async function seedXrayBrowserFixture() {
  const database = await waitForDatabase();
  const keyring = createXrayMasterKeyFile({ path: keyPath });
  const now = Math.floor(Date.now() / 1000);
  try {
    const admin = database.prepare("SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1").get() as { id: number };
    const host = database.prepare("SELECT id FROM hosts ORDER BY id LIMIT 1").get() as { id: number };
    seededHostId = host.id;
    database.exec("BEGIN IMMEDIATE");
    database.prepare("UPDATE xray_inbounds SET externalProxyNodeId = NULL").run();
    database.prepare("UPDATE forward_rules SET targetExternalProxyNodeId = NULL").run();
    database.prepare("DELETE FROM xray_external_proxy_secrets").run();
    database.prepare("DELETE FROM xray_external_proxy_nodes").run();
    for (const table of [
      "xray_managed_service_secrets",
      "xray_managed_service_accounts",
      "xray_managed_service_deployments",
      "xray_managed_service_runtime_reports",
      "xray_managed_services",
      "xray_managed_service_artifacts",
      "xray_access_secrets",
      "xray_access_entries",
      "xray_inbound_secrets",
      "xray_clients",
      "xray_inbounds",
      "xray_tls_certificates",
      "xray_operations",
      "xray_host_deployments",
      "xray_runtime_reports",
      "xray_artifacts",
    ]) {
      database.prepare(`DELETE FROM ${table}`).run();
    }
    database.prepare("UPDATE hosts SET name = ?, ip = ?, ipv4 = ?, isOnline = 1, lastHeartbeat = ?, agentVersion = ? WHERE id = ?")
      .run("xray-browser-edge", "8.8.8.8", "8.8.8.8", now, AGENT_VERSION, host.id);
    const artifact = XRAY_ARTIFACT_MANIFEST.find((entry) => entry.arch === "amd64")!;
    database.prepare(`INSERT INTO xray_artifacts
      (version, os, arch, packageFormat, storageKey, sha256, fileSize, status, source, verifiedAt, createdAt, updatedAt)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'VERIFIED', ?, ?, ?, ?)`)
      .run(artifact.version, artifact.os, artifact.arch, artifact.packageFormat, artifact.storageKey, artifact.sha256,
        artifact.fileSize, artifact.source, now, now, now);
    const runtimeTag = "forwardx-inbound-browser-smoke";
    const configHash = "a".repeat(64);
    const binaryHash = "b".repeat(64);
    const privateKey = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq";
    const realityPrivateKeyEncrypted = encryptXraySecret(privateKey, xrayInboundPrivateKeyContext(runtimeTag), keyring);
    database.prepare(`INSERT INTO xray_inbounds
      (id, hostId, name, runtimeTag, publicAddress, listenAddress, listenPort, protocol, transport, security,
       realityTargetHost, realityTargetPort, realityServerName, realityPublicKey, realityPrivateKeyEncrypted,
       secretKeyVersion, fingerprint, spiderX, isEnabled, pendingDelete, desiredGeneration, createdByUserId, createdAt, updatedAt)
      VALUES (1, ?, 'Browser Reality', ?, '8.8.8.8', '0.0.0.0', 24443, 'vless', 'tcp', 'reality',
       'www.cloudflare.com', 443, 'www.cloudflare.com', ?, ?, 1, 'chrome', '/', 1, 0, 1, ?, ?, ?)`)
      .run(host.id, runtimeTag, privateKey, realityPrivateKeyEncrypted, admin.id, now, now);
    const wireGuardRuntimeTag = "forwardx-inbound-browser-wireguard";
    const wireGuardServerPrivateKey = generateXrayWireGuardKeyPair().privateKey;
    const wireGuardPeer = generateXrayWireGuardKeyPair();
    seededWireGuardPrivateKey = wireGuardPeer.privateKey;
    seededWireGuardPsk = generateXrayWireGuardPreSharedKey();
    const wireGuardServerContext = xrayInboundSecretContext(wireGuardRuntimeTag, "PRIVATE_KEY");
    const wireGuardServerEncrypted = encryptXraySecret(wireGuardServerPrivateKey, wireGuardServerContext, keyring);
    database.prepare(`INSERT INTO xray_inbounds
      (id, hostId, name, runtimeTag, publicAddress, listenAddress, listenPort, protocol, transport, security,
       profileId, specVersion, specJson, realityTargetHost, realityTargetPort, realityServerName, realityPublicKey,
       realityPrivateKeyEncrypted, secretKeyVersion, fingerprint, spiderX, isEnabled, pendingDelete,
       desiredGeneration, createdByUserId, createdAt, updatedAt)
      VALUES (2, ?, 'Browser WireGuard', ?, '8.8.8.8', '0.0.0.0', 24444, 'wireguard', 'none', 'none',
       'WIREGUARD_UDP_NONE', 1, '{}', '', 443, '', '', '', 1, 'chrome', '/', 1, 0, 1, ?, ?, ?)`)
      .run(host.id, wireGuardRuntimeTag, admin.id, now, now);
    const httpRuntimeTag = "forwardx-inbound-browser-http";
    database.prepare(`INSERT INTO xray_inbounds
      (id, hostId, name, runtimeTag, publicAddress, listenAddress, listenPort, protocol, transport, security,
       profileId, specVersion, specJson, realityTargetHost, realityTargetPort, realityServerName, realityPublicKey,
       realityPrivateKeyEncrypted, secretKeyVersion, fingerprint, spiderX, isEnabled, pendingDelete,
       desiredGeneration, createdByUserId, createdAt, updatedAt)
      VALUES (3, ?, 'Browser HTTP Proxy', ?, '8.8.8.8', '0.0.0.0', 24445, 'http', 'tcp', 'none',
       'HTTP_RAW_NONE', 1, '{}', '', 443, '', '', '', 1, 'chrome', '/', 1, 0, 1, ?, ?, ?)`)
      .run(host.id, httpRuntimeTag, admin.id, now, now);
    const mixedRuntimeTag = "forwardx-inbound-browser-mixed";
    database.prepare(`INSERT INTO xray_inbounds
      (id, hostId, name, runtimeTag, publicAddress, listenAddress, listenPort, protocol, transport, security,
       profileId, specVersion, specJson, realityTargetHost, realityTargetPort, realityServerName, realityPublicKey,
       realityPrivateKeyEncrypted, secretKeyVersion, fingerprint, spiderX, isEnabled, pendingDelete,
       desiredGeneration, createdByUserId, createdAt, updatedAt)
      VALUES (4, ?, 'Browser Mixed Proxy', ?, '8.8.8.8', '0.0.0.0', 24446, 'mixed', 'tcp', 'none',
       'MIXED_RAW_NONE', 1, '{}', '', 443, '', '', '', 1, 'chrome', '/', 1, 0, 1, ?, ?, ?)`)
      .run(host.id, mixedRuntimeTag, admin.id, now, now);
    const tunnelRuntimeTag = "forwardx-inbound-browser-tunnel";
    database.prepare(`INSERT INTO xray_inbounds
      (id, hostId, name, runtimeTag, publicAddress, listenAddress, listenPort, protocol, transport, security,
       profileId, specVersion, specJson, realityTargetHost, realityTargetPort, realityServerName, realityPublicKey,
       realityPrivateKeyEncrypted, secretKeyVersion, fingerprint, spiderX, isEnabled, pendingDelete,
       desiredGeneration, createdByUserId, createdAt, updatedAt)
      VALUES (5, ?, 'Browser Local Tunnel', ?, '127.0.0.1', '127.0.0.1', 24447, 'tunnel', 'none', 'none',
       'TUNNEL_TCP_LOCAL_NONE', 1, '{"targetAddress":"db.example.com","targetPort":5432}', '', 443, '', '', '', 1, 'chrome', '/', 1, 0, 1, ?, ?, ?)`)
      .run(host.id, tunnelRuntimeTag, admin.id, now, now);
    const statsKey = "forwardx-client-browser-smoke";
    const uuid = "00000000-0000-4000-8000-000000000123";
    const shortId = "0123456789abcdef";
    const uuidEncrypted = encryptXraySecret(uuid, xrayClientUuidContext(statsKey), keyring);
    const uuidFingerprint = fingerprintXraySecret(uuid, xrayClientUuidContext(statsKey), keyring);
    const shortIdEncrypted = encryptXraySecret(shortId, xrayClientShortIdContext(statsKey), keyring);
    const shortIdFingerprint = fingerprintXraySecret(shortId, xrayClientShortIdContext(statsKey), keyring);
    database.prepare(`INSERT INTO xray_clients
      (id, inboundId, name, uuidEncrypted, uuidFingerprint, shortIdEncrypted, shortIdFingerprint, statsKey, flow,
       isEnabled, pendingDelete, desiredGeneration, sortOrder, createdAt, updatedAt)
      VALUES (1, 1, 'Browser Client', ?, ?, ?, ?, ?, 'xtls-rprx-vision', 1, 0, 1, 0, ?, ?)`)
      .run(
        uuidEncrypted,
        uuidFingerprint,
        shortIdEncrypted,
        shortIdFingerprint,
        statsKey, now, now,
      );
    database.prepare(`INSERT INTO xray_access_entries
      (id, inboundId, legacyClientId, name, credentialType, settingsJson, statsKey, isEnabled, pendingDelete,
       desiredGeneration, sortOrder, createdAt, updatedAt)
      VALUES (1, 1, 1, 'Browser Client', 'UUID_AND_SHORT_ID', '{"schemaVersion":1,"flow":"XTLS_RPRX_VISION"}', ?, 1, 0, 1, 0, ?, ?)`).run(statsKey, now, now);
    database.prepare(`INSERT INTO xray_access_secrets (accessEntryId, kind, encryptedValue, fingerprint, keyVersion, createdAt, updatedAt)
      VALUES (1, 'UUID', ?, ?, 1, ?, ?), (1, 'SHORT_ID', ?, ?, 1, ?, ?)`)
      .run(uuidEncrypted, uuidFingerprint, now, now, shortIdEncrypted, shortIdFingerprint, now, now);
    const wireGuardStatsKey = "forwardx-wireguard-browser-peer";
    const wireGuardPrivateContext = xrayAccessSecretContext(wireGuardStatsKey, "PRIVATE_KEY");
    const wireGuardPskContext = xrayAccessSecretContext(wireGuardStatsKey, "PRE_SHARED_KEY");
    const wireGuardPrivateEncrypted = encryptXraySecret(seededWireGuardPrivateKey, wireGuardPrivateContext, keyring);
    const wireGuardPskEncrypted = encryptXraySecret(seededWireGuardPsk, wireGuardPskContext, keyring);
    database.prepare(`INSERT INTO xray_access_entries
      (id, inboundId, legacyClientId, name, credentialType, settingsJson, statsKey, isEnabled, pendingDelete,
       desiredGeneration, sortOrder, createdAt, updatedAt)
      VALUES (2, 2, NULL, 'Browser Phone', 'WIREGUARD_PEER', '{"schemaVersion":2,"address":"10.0.0.2/32"}', ?, 1, 0, 1, 0, ?, ?)`)
      .run(wireGuardStatsKey, now, now);
    database.prepare(`INSERT INTO xray_access_secrets
      (accessEntryId, kind, encryptedValue, fingerprint, keyVersion, createdAt, updatedAt)
      VALUES (2, 'PRIVATE_KEY', ?, ?, 1, ?, ?), (2, 'PRE_SHARED_KEY', ?, ?, 1, ?, ?)`)
      .run(
        wireGuardPrivateEncrypted,
        fingerprintXraySecret(seededWireGuardPrivateKey, wireGuardPrivateContext, keyring),
        now,
        now,
        wireGuardPskEncrypted,
        fingerprintXraySecret(seededWireGuardPsk, wireGuardPskContext, keyring),
        now,
        now,
      );
    const mixedStatsKey = "forwardx-mixed-browser-account";
    seededMixedUsername = Buffer.alloc(16, 0xfc).toString("base64url");
    seededMixedPassword = Buffer.alloc(32, 0xfd).toString("base64url");
    const mixedUsernameContext = xrayAccessSecretContext(mixedStatsKey, "USERNAME");
    const mixedPasswordContext = xrayAccessSecretContext(mixedStatsKey, "PASSWORD");
    const mixedUsernameEncrypted = encryptXraySecret(seededMixedUsername, mixedUsernameContext, keyring);
    const mixedPasswordEncrypted = encryptXraySecret(seededMixedPassword, mixedPasswordContext, keyring);
    database.prepare(`INSERT INTO xray_access_entries
      (id, inboundId, legacyClientId, name, credentialType, settingsJson, statsKey, isEnabled, pendingDelete,
       desiredGeneration, sortOrder, createdAt, updatedAt)
      VALUES (4, 4, NULL, 'Browser Mixed Operator', 'MIXED_USER_PASSWORD', '{"schemaVersion":1}', ?, 1, 0, 1, 0, ?, ?)`)
      .run(mixedStatsKey, now, now);
    database.prepare(`INSERT INTO xray_access_secrets
      (accessEntryId, kind, encryptedValue, fingerprint, keyVersion, createdAt, updatedAt)
      VALUES (4, 'USERNAME', ?, ?, 1, ?, ?), (4, 'PASSWORD', ?, ?, 1, ?, ?)`)
      .run(
        mixedUsernameEncrypted,
        fingerprintXraySecret(seededMixedUsername, mixedUsernameContext, keyring),
        now,
        now,
        mixedPasswordEncrypted,
        fingerprintXraySecret(seededMixedPassword, mixedPasswordContext, keyring),
        now,
        now,
      );
    const httpStatsKey = "forwardx-http-browser-account";
    seededHttpUsername = Buffer.alloc(16, 0xfa).toString("base64url");
    seededHttpPassword = Buffer.alloc(32, 0xfb).toString("base64url");
    const httpUsernameContext = xrayAccessSecretContext(httpStatsKey, "USERNAME");
    const httpPasswordContext = xrayAccessSecretContext(httpStatsKey, "PASSWORD");
    const httpUsernameEncrypted = encryptXraySecret(seededHttpUsername, httpUsernameContext, keyring);
    const httpPasswordEncrypted = encryptXraySecret(seededHttpPassword, httpPasswordContext, keyring);
    database.prepare(`INSERT INTO xray_access_entries
      (id, inboundId, legacyClientId, name, credentialType, settingsJson, statsKey, isEnabled, pendingDelete,
       desiredGeneration, sortOrder, createdAt, updatedAt)
      VALUES (3, 3, NULL, 'Browser Operator', 'HTTP_BASIC', '{"schemaVersion":1}', ?, 1, 0, 1, 0, ?, ?)`)
      .run(httpStatsKey, now, now);
    database.prepare(`INSERT INTO xray_access_secrets
      (accessEntryId, kind, encryptedValue, fingerprint, keyVersion, createdAt, updatedAt)
      VALUES (3, 'USERNAME', ?, ?, 1, ?, ?), (3, 'PASSWORD', ?, ?, 1, ?, ?)`)
      .run(
        httpUsernameEncrypted,
        fingerprintXraySecret(seededHttpUsername, httpUsernameContext, keyring),
        now,
        now,
        httpPasswordEncrypted,
        fingerprintXraySecret(seededHttpPassword, httpPasswordContext, keyring),
        now,
        now,
      );
    database.prepare(`INSERT INTO xray_inbound_secrets (inboundId, kind, encryptedValue, fingerprint, keyVersion, createdAt, updatedAt)
      VALUES (1, 'REALITY_PRIVATE_KEY', ?, ?, 1, ?, ?)`)
      .run(realityPrivateKeyEncrypted, fingerprintXraySecret(privateKey, xrayInboundPrivateKeyContext(runtimeTag), keyring), now, now);
    database.prepare(`INSERT INTO xray_inbound_secrets (inboundId, kind, encryptedValue, fingerprint, keyVersion, createdAt, updatedAt)
      VALUES (2, 'PRIVATE_KEY', ?, ?, 1, ?, ?)`)
      .run(
        wireGuardServerEncrypted,
        fingerprintXraySecret(wireGuardServerPrivateKey, wireGuardServerContext, keyring),
        now,
        now,
      );
    database.prepare(`INSERT INTO xray_operations
      (operationId, hostId, inboundId, type, requestedGeneration, status, attemptCount, createdByUserId, createdAt, startedAt, finishedAt, updatedAt)
      VALUES ('browser-sync-1', ?, 1, 'SYNC', 1, 'SUCCESS', 1, ?, ?, ?, ?, ?)`)
      .run(host.id, admin.id, now, now, now, now);
    database.prepare(`INSERT INTO xray_host_deployments
      (hostId, targetVersion, desiredGeneration, desiredConfigHash, lastOperationId, createdAt, updatedAt)
      VALUES (?, ?, 1, ?, 'browser-sync-1', ?, ?)`)
      .run(host.id, XRAY_DEFAULT_VERSION, configHash, now, now);
    database.prepare(`INSERT INTO xray_runtime_reports
      (hostId, capabilitySchemaVersion, supportedOS, supportedArch, supportsArtifactInstall, supportsPortProbe,
       supportsUdpPortProbe, supportsUdpListenerReadiness, supportsRealityScan, isInstalled, installedVersion, runningVersion, serviceStatus, processId,
       appliedGeneration, appliedConfigHash, binarySha256, listenersJson, reportedAt, updatedAt)
      VALUES (?, 1, 'linux', 'amd64', 1, 1, 1, 1, 1, 1, ?, ?, 'RUNNING', 4242, 1, ?, ?, ?, ?, ?)`)
      .run(host.id, XRAY_DEFAULT_VERSION, XRAY_DEFAULT_VERSION, configHash, binaryHash,
        JSON.stringify([
          { runtimeTag, network: "tcp", port: 24443, status: "READY" },
          { runtimeTag: wireGuardRuntimeTag, network: "udp", port: 24444, status: "READY" },
          { runtimeTag: httpRuntimeTag, network: "tcp", port: 24445, status: "READY" },
          { runtimeTag: mixedRuntimeTag, network: "tcp", port: 24446, status: "READY" },
          { runtimeTag: tunnelRuntimeTag, network: "tcp", port: 24447, status: "READY" },
        ]), now, now);
    database.exec("COMMIT");
  } catch (error) {
    if (database.inTransaction) database.exec("ROLLBACK");
    throw error;
  } finally {
    database.close();
  }
}

test.beforeAll(seedXrayBrowserFixture);

test("real Xray admin page is responsive and keeps secrets out of browser persistence", async ({ page }) => {
  await page.clock.install();
  const errors: string[] = [];
  let shareCacheControl = "";
  let wireGuardShareRequests = 0;
  let createPayload: Record<string, unknown> | null = null;
  const probedNetworks: string[] = [];
  const issuedReservations: string[] = [];
  const reservationByOperation = new Map<string, string>();
  const networkByOperation = new Map<string, "TCP" | "UDP">();
  const findCreatePayload = (value: unknown): Record<string, unknown> | null => {
    if (!value || typeof value !== "object") return null;
    if (!Array.isArray(value) && typeof (value as Record<string, unknown>).profileId === "string") {
      return value as Record<string, unknown>;
    }
    for (const child of Object.values(value)) {
      const found = findCreatePayload(child);
      if (found) return found;
    }
    return null;
  };
  await page.route("**/api/trpc/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const encodedPaths = url.pathname.split("/api/trpc/")[1] ?? "";
    const procedurePaths = decodeURIComponent(encodedPaths).split(",");
    if (procedurePaths.includes("xray.accessEntries.share")) wireGuardShareRequests += 1;
    if (procedurePaths.includes("xray.portProbes.create") && request.method() === "POST") {
      const postData = request.postData() ?? "";
      const network = postData.match(/\"network\"\s*:\s*\"(TCP|UDP)\"/)?.[1];
      if (network === "TCP" || network === "UDP") {
        probedNetworks.push(network);
        const operationId = `browser-port-probe-${probedNetworks.length}`;
        networkByOperation.set(operationId, network);
        const success = { result: { data: { json: { operationId } } } };
        await route.fulfill({
          status: 200,
          contentType: "application/json",
          json: url.searchParams.get("batch") === "1" ? [success] : success,
        });
        return;
      }
    }
    if (procedurePaths.includes("xray.inbounds.createV2") && request.method() === "POST") {
      try {
        createPayload = findCreatePayload(JSON.parse(request.postData() ?? "null"));
      } catch {
        createPayload = null;
      }
      const response = await route.fetch();
      let responseBody = await response.json();
      const index = procedurePaths.indexOf("xray.inbounds.createV2");
      const success = { result: { data: { json: {
        inboundId: 99,
        operationId: "browser-create-v2",
        desiredGeneration: 2,
      } } } };
      if (Array.isArray(responseBody)) responseBody[index] = success;
      else responseBody = success;
      await route.fulfill({ response, status: 200, json: responseBody });
      return;
    }
    const targetPaths = new Set([
      "xray.certificates.list", "xray.portProbes.result", "xray.operations.get",
    ]);
    if (!procedurePaths.some((procedurePath) => targetPaths.has(procedurePath))) {
      await route.continue();
      return;
    }
    const response = await route.fetch();
    let responseBody = await response.json();
    procedurePaths.forEach((procedurePath, index) => {
      if (!targetPaths.has(procedurePath)) return;
      const entryIndex = Array.isArray(responseBody) ? index : 0;
      let entry = entries[entryIndex];
      if (procedurePath === "xray.operations.get") {
        entry = { result: { data: { json: {
          operationId: "browser-create-v2",
          hostId: seededHostId,
          inboundId: 99,
          type: "SYNC",
          status: "SUCCESS",
          stage: "COMPLETE",
          requestedGeneration: 2,
          errorCode: null,
          errorMessage: null,
          attemptCount: 1,
          createdAt: new Date().toISOString(),
          startedAt: new Date().toISOString(),
          finishedAt: new Date().toISOString(),
          expiresAt: null,
          updatedAt: new Date().toISOString(),
        } } } };
        if (Array.isArray(responseBody)) responseBody[index] = entry;
        else responseBody = entry;
      }
      if (procedurePath === "xray.portProbes.result") {
        const operationId = [...networkByOperation.keys()].find((candidate) => request.url().includes(candidate)) ?? "";
        let reservationId = reservationByOperation.get(operationId);
        if (!reservationId) {
          reservationId = `browser-port-reservation-${issuedReservations.length + 1}`;
          reservationByOperation.set(operationId, reservationId);
          issuedReservations.push(reservationId);
        }
        entry = { result: { data: { json: {
          operationId,
          status: "SUCCESS",
          createdAt: new Date().toISOString(),
          network: (networkByOperation.get(operationId) ?? "TCP").toLowerCase(),
          selectedPort: 29443,
          reservationId,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
        } } } };
        if (Array.isArray(responseBody)) responseBody[index] = entry;
        else responseBody = entry;
        return;
      }
      const resultData = entry?.result?.data;
      if (!resultData || !("json" in resultData)) return;
      if (procedurePath === "xray.certificates.list") {
        resultData.json = {
          items: [{
            id: 91,
            hostId: seededHostId,
            name: "Browser TLS",
            dnsNames: ["tls.example.com", "*.edge.example.com"],
            subject: "CN=tls.example.com",
            issuer: "CN=Browser Test CA",
            serialNumber: "01",
            notBefore: Math.floor(Date.now() / 1000) - 60,
            notAfter: Math.floor(Date.now() / 1000) + 86_400,
            keyAlgorithm: "RSA_2048_4096",
            leafFingerprintSha256: "c".repeat(64),
            privateKeyConfigured: true,
            referenceCount: 0,
            status: "VALID",
            createdAt: Math.floor(Date.now() / 1000) - 60,
            updatedAt: Math.floor(Date.now() / 1000) - 60,
          }],
          page: 1,
          pageSize: 100,
          total: 1,
        };
      }
    });
    await route.fulfill({ response, status: 200, json: responseBody });
  });
  page.on("console", (message) => { if (message.type() === "error") errors.push(`console:${message.text()}`); });
  page.on("pageerror", (error) => errors.push(`page:${error.message}`));
  page.on("requestfailed", (request) => errors.push(`network:${request.url()}:${request.failure()?.errorText}`));
  page.on("response", (response) => {
    if (response.status() >= 500) errors.push(`http:${response.status()}:${response.url()}`);
    if (response.url().includes("accessEntries.share")) shareCacheControl = response.headers()["cache-control"] || "";
  });

  await page.goto(`${baseURL}/xray`, { waitUntil: "networkidle" });
  const devAnnouncement = page.getByRole("dialog", { name: "Dev popup announcement" });
  if (await devAnnouncement.isVisible()) {
    await devAnnouncement.getByRole("button", { name: "我知道了" }).click();
  }
  await expect(page.getByRole("region", { name: "Xray 节点结果" })).toBeVisible();
  await expect(page.getByRole("row", { name: /Browser Reality/ })).toBeVisible();

  for (const viewport of [{ width: 320, height: 760 }, { width: 768, height: 900 }, { width: 1440, height: 1000 }]) {
    await page.setViewportSize(viewport);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
  }

  await page.locator("button:visible", { hasText: "创建节点" }).click();
  const createDialog = page.getByRole("dialog");
  await expect(createDialog.getByText("创建 Xray 节点", { exact: true })).toBeVisible();
  const createSections = createDialog.getByRole("navigation", { name: "创建节点配置分区" });
  for (const label of ["基础配置", "协议", "传输", "端口", "安全", "账户", "确认"]) {
    await expect(createSections.getByText(label, { exact: true })).toBeVisible();
  }
  await expect.poll(() => createDialog.evaluate((dialog) => dialog.contains(document.activeElement))).toBe(true);
  await page.keyboard.press("Escape");

  await page.locator("button:visible", { hasText: "创建节点" }).click();
  const wireGuardCreateDialog = page.getByRole("dialog");
  await wireGuardCreateDialog.getByRole("button", { name: /xray-browser-edge/ }).click();
  await wireGuardCreateDialog.getByLabel("节点名称").fill("Browser WireGuard Created");
  await wireGuardCreateDialog.getByRole("button", { name: "下一步：选择协议" }).click();
  const wireGuardProtocol = wireGuardCreateDialog.getByRole("button", { name: /WIREGUARD/ });
  await wireGuardProtocol.click();
  await expect(wireGuardCreateDialog.getByRole("button", { name: /WIREGUARD/ })).toHaveAttribute("aria-pressed", "true");
  await expect(wireGuardCreateDialog.getByText("WireGuard 外层特征明显，可能被识别或封锁", { exact: true })).toBeVisible();
  await wireGuardCreateDialog.getByRole("button", { name: "下一步：选择传输" }).click();
  await expect(wireGuardCreateDialog.getByRole("button", { name: "无独立传输" })).toHaveAttribute("aria-pressed", "true");
  await expect(wireGuardCreateDialog.getByText("Xray 内置 / UDP / 无 TLS", { exact: true })).toBeVisible();
  await expect(wireGuardCreateDialog.getByText("gVisor · IPv4 · MTU 1420 · 10.0.0.0/24", { exact: true })).toBeVisible();
  await expect(wireGuardCreateDialog.getByText(/kernel TUN|workers|reserved|domain strategy|IPv6|allowedIPs|高级 JSON/i)).toHaveCount(0);
  for (const viewport of [{ width: 320, height: 760 }, { width: 768, height: 900 }, { width: 1440, height: 1000 }]) {
    await page.setViewportSize(viewport);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth + 1)).toBe(true);
    await expect(wireGuardCreateDialog.getByText("Xray 内置 / UDP / 无 TLS", { exact: true })).toBeVisible();
  }
  await wireGuardCreateDialog.getByRole("button", { name: "下一步：检测端口" }).click();
  await expect(wireGuardCreateDialog.getByText("UDP 端口检测与短期预留", { exact: true })).toBeVisible();
  await wireGuardCreateDialog.getByRole("button", { name: "自动检测可用端口" }).click();
  await expect(wireGuardCreateDialog.getByText("端口可用", { exact: true })).toBeVisible();
  await wireGuardCreateDialog.getByRole("button", { name: "下一步：配置安全" }).click();
  const wireGuardSections = wireGuardCreateDialog.getByRole("navigation", { name: "创建节点配置分区" });
  await page.clock.fastForward(61_000);
  const completedTransportStep = wireGuardSections.getByRole("button", { name: /传输/ });
  await expect(completedTransportStep).toBeEnabled();
  await expect(wireGuardSections.getByRole("button", { name: /账户/ })).toBeDisabled();
  await expect(wireGuardSections.getByRole("button", { name: /确认/ })).toBeDisabled();
  await completedTransportStep.click();
  await expect(wireGuardCreateDialog.getByRole("button", { name: "无独立传输" })).toHaveAttribute("aria-pressed", "true");
  await wireGuardSections.getByRole("button", { name: /基础配置/ }).click();
  await expect(wireGuardCreateDialog.getByLabel("节点名称")).toHaveValue("Browser WireGuard Created");
  await expect(wireGuardCreateDialog.getByLabel("公网地址")).toHaveValue("8.8.8.8");
  await page.clock.setSystemTime(Date.now());
  await wireGuardCreateDialog.getByRole("button", { name: "下一步：选择协议" }).click();
  await expect(wireGuardCreateDialog.getByRole("button", { name: /WIREGUARD/ })).toHaveAttribute("aria-pressed", "true");
  await wireGuardCreateDialog.getByRole("button", { name: "下一步：选择传输" }).click();
  await wireGuardCreateDialog.getByRole("button", { name: "下一步：检测端口" }).click();
  await wireGuardCreateDialog.getByRole("button", { name: "自动检测可用端口" }).click();
  await expect(wireGuardCreateDialog.getByText("端口可用", { exact: true })).toBeVisible();
  const replacementReservationId = issuedReservations.at(-1);
  await wireGuardCreateDialog.getByRole("button", { name: "下一步：配置安全" }).click();
  await expect(wireGuardCreateDialog.getByText("WireGuard 固定安全边界", { exact: true })).toBeVisible();
  await expect(wireGuardCreateDialog.getByText(/不接受密钥、PSK 或网络参数输入/)).toBeVisible();
  await expect(wireGuardCreateDialog.getByLabel("受管 TLS 证书")).toHaveCount(0);
  await expect(wireGuardCreateDialog.getByText(/私钥 PEM|allowedIPs|keepAlive/)).toHaveCount(0);
  await wireGuardCreateDialog.getByRole("button", { name: "下一步：peer" }).click();
  await wireGuardCreateDialog.getByLabel("peer 1 名称").fill("Browser Phone");
  await wireGuardCreateDialog.getByRole("button", { name: /添加 peer/ }).click();
  await wireGuardCreateDialog.getByLabel("peer 2 名称").fill("Browser Laptop");
  await page.setViewportSize({ width: 320, height: 500 });
  const createFormScroller = wireGuardCreateDialog.locator("div.overflow-y-auto").last();
  await expect.poll(() => createFormScroller.evaluate((element) => {
    element.scrollTop = element.scrollHeight;
    return element.scrollHeight > element.clientHeight
      && Math.ceil(element.scrollTop + element.clientHeight) >= element.scrollHeight;
  })).toBe(true);
  await page.setViewportSize({ width: 1440, height: 1000 });
  await wireGuardCreateDialog.getByRole("button", { name: "下一步：确认部署" }).click();
  await expect(wireGuardCreateDialog.getByText(/WireGuard · Xray 内置 \/ UDP \/ 无 TLS/)).toBeVisible();
  await expect(wireGuardCreateDialog.getByText(/gVisor · IPv4 · MTU 1420 · 10.0.0.0\/24/)).toBeVisible();
  await expect(wireGuardCreateDialog.getByText(/2 个/)).toBeVisible();
  await wireGuardCreateDialog.getByRole("button", { name: "创建并部署" }).click();
  await expect(wireGuardCreateDialog.getByRole("heading", { name: "操作成功" })).toBeVisible();
  expect(createPayload).toMatchObject({
    hostId: seededHostId,
    name: "Browser WireGuard Created",
    publicAddress: "8.8.8.8",
    portReservationId: replacementReservationId,
    listenPort: 29443,
    profileId: "WIREGUARD_UDP_NONE",
    spec: {},
    initialAccessEntries: [{ name: "Browser Phone" }, { name: "Browser Laptop" }],
  });
  expect(probedNetworks).toEqual(["UDP", "UDP"]);
  const serializedWireGuardPayload = JSON.stringify(createPayload);
  for (const forbidden of ["reality", "tlsCertificateId", "serverName", "uuid", "shortId", "flow", "privateKey", "publicKey", "preSharedKey", "psk", "allowedIPs", "keepAlive", "mtu", "dns", "route", "noKernelTun", "reserved"]) {
    expect(serializedWireGuardPayload.toLowerCase()).not.toContain(forbidden.toLowerCase());
  }
  await page.keyboard.press("Escape");

  await page.getByRole("tab", { name: "TLS 证书" }).click();
  await expect(page.getByRole("region", { name: "TLS 证书结果" })).toBeVisible();
  await expect(page.getByRole("row", { name: /Browser TLS/ })).toBeVisible();
  await page.getByRole("button", { name: "导入证书" }).click();
  const certificateDialog = page.getByRole("dialog", { name: "导入 TLS 证书" });
  await expect(certificateDialog.getByLabel("完整证书链 PEM")).toBeVisible();
  await expect(certificateDialog.getByLabel("未加密私钥 PEM")).toBeVisible();
  await page.keyboard.press("Escape");
  await page.getByRole("tab", { name: "节点管理" }).click();

  await page.getByRole("row", { name: /Browser Reality/ }).getByRole("button", { name: "查看详情" }).click();
  await expect(page.getByRole("dialog").getByRole("heading", { name: "Browser Reality" })).toBeVisible();
  await page.getByRole("tab", { name: "运行时" }).click();
  await expect(page.getByText("4242", { exact: true })).toBeVisible();
  await page.getByRole("tab", { name: "Reality" }).click();
  await expect(page.getByText("www.cloudflare.com:443", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");

  await page.getByRole("row", { name: /Browser WireGuard/ }).getByRole("button", { name: "查看详情" }).click();
  const wireGuardDetail = page.getByRole("dialog").filter({ hasText: "Browser WireGuard" });
  await expect(wireGuardDetail.getByRole("heading", { name: "Browser WireGuard" })).toBeVisible();
  await expect(wireGuardDetail.getByText("WireGuard · Xray 内置 / UDP / 无 TLS", { exact: true })).toBeVisible();
  await expect(wireGuardDetail.getByText("WireGuard 外层特征明显，可能被识别或封锁", { exact: true })).toBeVisible();
  await wireGuardDetail.getByRole("tab", { name: "Peers" }).click();
  await expect(wireGuardDetail.getByText("Browser Phone", { exact: true })).toBeVisible();
  await expect(wireGuardDetail.getByText("地址：10.0.0.2/32 · 凭据已配置（隐藏）", { exact: true })).toBeVisible();
  const shareRequestStart = wireGuardShareRequests;
  await wireGuardDetail.getByRole("button", { name: "配置 / QR" }).click();
  const wireGuardShareDialog = page.getByRole("dialog").filter({ hasText: "WireGuard peer 配置" });
  const wireGuardConfigField = wireGuardShareDialog.getByLabel("WireGuard peer 配置");
  await expect(wireGuardConfigField).toHaveValue(/^\[Interface\]/);
  await expect(wireGuardShareDialog.getByRole("img", { name: /WireGuard 二维码/ })).toBeVisible();
  const wireGuardConfig = await wireGuardConfigField.inputValue();
  expect(wireGuardConfig).toContain(`PrivateKey = ${seededWireGuardPrivateKey}`);
  expect(wireGuardConfig).toContain(`PresharedKey = ${seededWireGuardPsk}`);
  await expect.poll(() => wireGuardShareRequests).toBeGreaterThan(shareRequestStart);
  const firstShareRequestCount = wireGuardShareRequests;
  await page.keyboard.press("Escape");
  await wireGuardDetail.getByRole("button", { name: "配置 / QR" }).click();
  await expect(page.getByRole("dialog").filter({ hasText: "WireGuard peer 配置" }).getByLabel("WireGuard peer 配置")).toHaveValue(wireGuardConfig);
  await expect.poll(() => wireGuardShareRequests).toBeGreaterThan(firstShareRequestCount);
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("dialog").filter({ hasText: "WireGuard peer 配置" }).getByRole("button", { name: "下载 .conf" }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe("forwardx-browser-phone.conf");
  const downloadPath = await download.path();
  expect(downloadPath).not.toBeNull();
  expect(fs.readFileSync(downloadPath!, "utf8")).toBe(wireGuardConfig);
  await expect(page.getByRole("dialog").filter({ hasText: "WireGuard peer 配置" })).toHaveCount(0);
  await page.keyboard.press("Escape");

  await page.getByRole("tab", { name: "运行环境" }).click();
  const runtimeRow = page.getByRole("row", { name: /xray-browser-edge/ });
  await expect(runtimeRow).toBeVisible();
  await runtimeRow.getByRole("button", { name: "同步配置" }).click();
  await expect(page.getByRole("dialog").getByText("重新同步配置", { exact: true })).toBeVisible();
  await expect(page.getByLabel(/输入主机名/)).toBeVisible();
  await page.keyboard.press("Escape");

  expect(shareCacheControl).toContain("private");
  expect(shareCacheControl).toContain("no-store");
  expect(page.url()).not.toContain("[Interface]");
  const persisted = await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }));
  for (const forbidden of [wireGuardConfig, seededWireGuardPrivateKey, seededWireGuardPsk]) {
    expect(persisted).not.toContain(forbidden);
  }
  expect(errors).toEqual([]);
});

test("HTTP management proxy create and share UI expose only the approved Basic-auth workflow", async ({ page }) => {
  const errors: string[] = [];
  let createPayload: Record<string, unknown> | null = null;
  let shareCacheControl = "";
  const findCreatePayload = (value: unknown): Record<string, unknown> | null => {
    if (!value || typeof value !== "object") return null;
    if (!Array.isArray(value) && (value as Record<string, unknown>).profileId === "HTTP_RAW_NONE") {
      return value as Record<string, unknown>;
    }
    for (const child of Object.values(value)) {
      const found = findCreatePayload(child);
      if (found) return found;
    }
    return null;
  };
  await page.route("**/api/trpc/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const procedurePaths = decodeURIComponent(url.pathname.split("/api/trpc/")[1] ?? "").split(",");
    const batched = url.searchParams.get("batch") === "1";
    const responseFor = (json: unknown) => ({ result: { data: { json } } });
    if (procedurePaths.includes("xray.portProbes.create") && request.method() === "POST") {
      const response = responseFor({ operationId: "browser-http-port-probe" });
      await route.fulfill({ status: 200, contentType: "application/json", json: batched ? [response] : response });
      return;
    }
    if (procedurePaths.includes("xray.portProbes.result")) {
      const response = responseFor({
        operationId: "browser-http-port-probe",
        status: "SUCCESS",
        createdAt: new Date().toISOString(),
        network: "tcp",
        selectedPort: 29543,
        reservationId: "browser-http-reservation",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      });
      await route.fulfill({ status: 200, contentType: "application/json", json: batched ? [response] : response });
      return;
    }
    if (procedurePaths.includes("xray.inbounds.createV2") && request.method() === "POST") {
      try {
        createPayload = findCreatePayload(JSON.parse(request.postData() ?? "null"));
      } catch {
        createPayload = null;
      }
      const response = responseFor({ inboundId: 99, operationId: "browser-http-create", desiredGeneration: 2 });
      await route.fulfill({ status: 200, contentType: "application/json", json: batched ? [response] : response });
      return;
    }
    if (procedurePaths.includes("xray.operations.get")) {
      const response = responseFor({
        operationId: "browser-http-create",
        hostId: seededHostId,
        inboundId: 99,
        type: "SYNC",
        status: "SUCCESS",
        stage: "COMPLETE",
        requestedGeneration: 2,
        errorCode: null,
        errorMessage: null,
        attemptCount: 1,
        createdAt: new Date().toISOString(),
        startedAt: new Date().toISOString(),
        finishedAt: new Date().toISOString(),
        expiresAt: null,
        updatedAt: new Date().toISOString(),
      });
      await route.fulfill({ status: 200, contentType: "application/json", json: batched ? [response] : response });
      return;
    }
    await route.continue();
  });
  page.on("console", (message) => { if (message.type() === "error") errors.push(`console:${message.text()}`); });
  page.on("pageerror", (error) => errors.push(`page:${error.message}`));
  page.on("requestfailed", (request) => errors.push(`network:${request.url()}:${request.failure()?.errorText}`));
  page.on("response", (response) => {
    if (response.status() >= 500) errors.push(`http:${response.status()}:${response.url()}`);
    if (response.url().includes("xray.accessEntries.share")) {
      shareCacheControl = response.headers()["cache-control"] || "";
    }
  });

  await page.goto(`${baseURL}/xray`, { waitUntil: "networkidle" });
  const devAnnouncement = page.getByRole("dialog", { name: "Dev popup announcement" });
  if (await devAnnouncement.isVisible()) await devAnnouncement.getByRole("button", { name: "我知道了" }).click();
  await page.locator("button:visible", { hasText: "创建节点" }).click();
  const createDialog = page.getByRole("dialog");
  await createDialog.getByRole("button", { name: /xray-browser-edge/ }).click();
  await createDialog.getByLabel("节点名称").fill("Browser HTTP Created");
  await createDialog.getByRole("button", { name: "下一步：选择协议" }).click();
  await createDialog.getByRole("button", { name: /HTTP 管理代理/ }).click();
  await expect(createDialog.getByText(/Basic 用户名和密码可能被链路观察者读取/)).toBeVisible();
  await createDialog.getByRole("button", { name: "下一步：选择传输" }).click();
  await expect(createDialog.getByRole("button", { name: /RAW \/ TCP/ })).toHaveAttribute("aria-pressed", "true");
  await expect(createDialog.getByText("RAW / TCP / 无 TLS · 强制 Basic 认证", { exact: true })).toBeVisible();
  await expect(createDialog.getByText(/allowTransparent、账户凭据或任意 JSON/)).toBeVisible();
  await expect(createDialog.getByLabel(/用户名|密码|allowTransparent/i)).toHaveCount(0);
  await createDialog.getByRole("button", { name: "下一步：检测端口" }).click();
  await createDialog.getByRole("button", { name: "自动检测可用端口" }).click();
  await expect(createDialog.getByText("端口可用", { exact: true })).toBeVisible();
  await createDialog.getByRole("button", { name: "下一步：配置安全" }).click();
  await expect(createDialog.getByText("HTTP 代理固定安全边界", { exact: true })).toBeVisible();
  await expect(createDialog.getByText(/强制 HTTP Basic；不允许匿名账户/)).toBeVisible();
  await expect(createDialog.getByLabel("受管 TLS 证书")).toHaveCount(0);
  await createDialog.getByRole("button", { name: "下一步：账户" }).click();
  await createDialog.getByLabel("账户 1 备注").fill("Browser Operator Created");
  await createDialog.getByRole("button", { name: /添加账户/ }).click();
  await createDialog.getByLabel("账户 2 备注").fill("Browser Automation Created");
  await createDialog.getByRole("button", { name: "下一步：确认部署" }).click();
  await expect(createDialog.getByText(/HTTP 管理代理 · RAW \/ TCP \/ 无 TLS · 强制 Basic 认证/)).toBeVisible();
  await expect(createDialog.getByText(/非透明代理 · 强制 Basic 认证；用户名和密码由服务端生成/)).toBeVisible();
  await createDialog.getByRole("button", { name: "创建并部署" }).click();
  await expect(createDialog.getByRole("heading", { name: "操作成功" })).toBeVisible();
  expect(createPayload).toMatchObject({
    hostId: seededHostId,
    name: "Browser HTTP Created",
    publicAddress: "8.8.8.8",
    portReservationId: "browser-http-reservation",
    listenPort: 29543,
    profileId: "HTTP_RAW_NONE",
    spec: {},
    initialAccessEntries: [{ name: "Browser Operator Created" }, { name: "Browser Automation Created" }],
  });
  const serializedPayload = JSON.stringify(createPayload);
  for (const forbidden of ["username", "password", "authorization", "allowTransparent", "reality", "tlsCertificateId", "serverName", "configJson"]) {
    expect(serializedPayload.toLowerCase()).not.toContain(forbidden.toLowerCase());
  }
  await page.keyboard.press("Escape");

  const httpRow = page.getByRole("row", { name: /Browser HTTP Proxy/ });
  await expect(httpRow).toBeVisible();
  await httpRow.getByRole("button", { name: "查看详情" }).click();
  const detail = page.getByRole("dialog").filter({ hasText: "Browser HTTP Proxy" });
  await expect(detail.getByText("HTTP 管理代理 · RAW / TCP / 无 TLS", { exact: true })).toBeVisible();
  await expect(detail.getByText(/Basic 用户名和密码可能被链路观察者读取/)).toBeVisible();
  await detail.getByRole("tab", { name: "账户" }).click();
  await expect(detail.getByText("Browser Operator", { exact: true })).toBeVisible();
  await expect(detail.getByText("代理用户名：已配置（隐藏） · 密码：已配置（隐藏）", { exact: true })).toBeVisible();
  await detail.getByRole("button", { name: "代理地址 / QR" }).click();
  const shareDialog = page.getByRole("dialog").filter({ hasText: "HTTP 代理地址" });
  const shareField = shareDialog.getByLabel("HTTP 代理地址");
  await expect(shareField).toHaveValue(`http://${seededHttpUsername}:${seededHttpPassword}@8.8.8.8:24445`);
  await expect(shareDialog.getByText(/该地址不会进入订阅/)).toBeVisible();
  await expect(shareDialog.getByRole("button", { name: "复制代理地址" })).toBeVisible();
  expect(shareCacheControl).toContain("private");
  expect(shareCacheControl).toContain("no-store");

  const persisted = await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }));
  expect(persisted).not.toContain(seededHttpUsername);
  expect(persisted).not.toContain(seededHttpPassword);
  expect(errors).toEqual([]);
});

test("Mixed management proxy create and share UI expose one TCP profile and two ephemeral endpoints", async ({ page }) => {
  const errors: string[] = [];
  const probeNetworks: string[] = [];
  let createPayload: Record<string, unknown> | null = null;
  let shareCacheControl = "";
  const findCreatePayload = (value: unknown): Record<string, unknown> | null => {
    if (!value || typeof value !== "object") return null;
    if (!Array.isArray(value) && (value as Record<string, unknown>).profileId === "MIXED_RAW_NONE") {
      return value as Record<string, unknown>;
    }
    for (const child of Object.values(value)) {
      const found = findCreatePayload(child);
      if (found) return found;
    }
    return null;
  };
  await page.route("**/api/trpc/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const procedurePaths = decodeURIComponent(url.pathname.split("/api/trpc/")[1] ?? "").split(",");
    const batched = url.searchParams.get("batch") === "1";
    const responseFor = (json: unknown) => ({ result: { data: { json } } });
    if (procedurePaths.includes("xray.portProbes.create") && request.method() === "POST") {
      const network = (request.postData() ?? "").match(/"network"\s*:\s*"(TCP|UDP)"/)?.[1] ?? "";
      probeNetworks.push(network);
      const response = responseFor({ operationId: "browser-mixed-port-probe" });
      await route.fulfill({ status: 200, contentType: "application/json", json: batched ? [response] : response });
      return;
    }
    if (procedurePaths.includes("xray.portProbes.result")) {
      const response = responseFor({
        operationId: "browser-mixed-port-probe",
        status: "SUCCESS",
        createdAt: new Date().toISOString(),
        network: "tcp",
        selectedPort: 29643,
        reservationId: "browser-mixed-reservation",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      });
      await route.fulfill({ status: 200, contentType: "application/json", json: batched ? [response] : response });
      return;
    }
    if (procedurePaths.includes("xray.inbounds.createV2") && request.method() === "POST") {
      try {
        createPayload = findCreatePayload(JSON.parse(request.postData() ?? "null"));
      } catch {
        createPayload = null;
      }
      const response = responseFor({ inboundId: 100, operationId: "browser-mixed-create", desiredGeneration: 2 });
      await route.fulfill({ status: 200, contentType: "application/json", json: batched ? [response] : response });
      return;
    }
    if (procedurePaths.includes("xray.operations.get")) {
      const response = responseFor({
        operationId: "browser-mixed-create",
        hostId: seededHostId,
        inboundId: 100,
        type: "SYNC",
        status: "SUCCESS",
        stage: "COMPLETE",
        requestedGeneration: 2,
        errorCode: null,
        errorMessage: null,
        attemptCount: 1,
        createdAt: new Date().toISOString(),
        startedAt: new Date().toISOString(),
        finishedAt: new Date().toISOString(),
        expiresAt: null,
        updatedAt: new Date().toISOString(),
      });
      await route.fulfill({ status: 200, contentType: "application/json", json: batched ? [response] : response });
      return;
    }
    await route.continue();
  });
  page.on("console", (message) => { if (message.type() === "error") errors.push(`console:${message.text()}`); });
  page.on("pageerror", (error) => errors.push(`page:${error.message}`));
  page.on("requestfailed", (request) => errors.push(`network:${request.url()}:${request.failure()?.errorText}`));
  page.on("response", (response) => {
    if (response.status() >= 500) errors.push(`http:${response.status()}:${response.url()}`);
    if (response.url().includes("xray.accessEntries.share")) shareCacheControl = response.headers()["cache-control"] || "";
  });

  await page.goto(`${baseURL}/xray`, { waitUntil: "networkidle" });
  const devAnnouncement = page.getByRole("dialog", { name: "Dev popup announcement" });
  if (await devAnnouncement.isVisible()) await devAnnouncement.getByRole("button", { name: "我知道了" }).click();
  await page.locator("button:visible", { hasText: "创建节点" }).click();
  const createDialog = page.getByRole("dialog");
  await createDialog.getByRole("button", { name: /xray-browser-edge/ }).click();
  await createDialog.getByLabel("节点名称").fill("Browser Mixed Created");
  await createDialog.getByRole("button", { name: "下一步：选择协议" }).click();
  await createDialog.getByRole("button", { name: /Mixed（SOCKS5 \+ HTTP）/ }).click();
  await expect(createDialog.getByText(/SOCKS5 用户名\/密码和 HTTP Basic 凭据可能被链路观察者读取/)).toBeVisible();
  await createDialog.getByRole("button", { name: "下一步：选择传输" }).click();
  await expect(createDialog.getByRole("button", { name: /RAW \/ TCP/ })).toHaveAttribute("aria-pressed", "true");
  await expect(createDialog.getByText("RAW / TCP / 无 TLS · SOCKS5 + HTTP 共用监听", { exact: true })).toBeVisible();
  await expect(createDialog.getByText(/不支持 SOCKS4\/4a 与 UDP/)).toBeVisible();
  await expect(createDialog.getByLabel(/用户名|密码|UDP|认证方式/i)).toHaveCount(0);
  await createDialog.getByRole("button", { name: "下一步：检测端口" }).click();
  await createDialog.getByRole("button", { name: "自动检测可用端口" }).click();
  await expect(createDialog.getByText("端口可用", { exact: true })).toBeVisible();
  await createDialog.getByRole("button", { name: "下一步：配置安全" }).click();
  await expect(createDialog.getByText("Mixed 代理固定安全边界", { exact: true })).toBeVisible();
  await expect(createDialog.getByText(/SOCKS5 \+ HTTP\/CONNECT · 共用端口/)).toBeVisible();
  await createDialog.getByRole("button", { name: "下一步：账户" }).click();
  await createDialog.getByLabel("账户 1 备注").fill("Browser Mixed Created Operator");
  await createDialog.getByRole("button", { name: "下一步：确认部署" }).click();
  await expect(createDialog.getByText(/Mixed（SOCKS5 \+ HTTP）· RAW \/ TCP \/ 无 TLS · 强制认证/)).toBeVisible();
  await expect(createDialog.getByText(/共用 TCP 端口 · 强制认证 · 无 UDP/)).toBeVisible();
  await createDialog.getByRole("button", { name: "创建并部署" }).click();
  await expect(createDialog.getByRole("heading", { name: "操作成功" })).toBeVisible();
  expect(probeNetworks).toEqual(["TCP"]);
  expect(createPayload).toMatchObject({
    hostId: seededHostId,
    name: "Browser Mixed Created",
    publicAddress: "8.8.8.8",
    portReservationId: "browser-mixed-reservation",
    listenPort: 29643,
    profileId: "MIXED_RAW_NONE",
    spec: {},
    initialAccessEntries: [{ name: "Browser Mixed Created Operator" }],
  });
  const serializedPayload = JSON.stringify(createPayload);
  for (const forbidden of ["username", "password", "udp", "authorization", "reality", "tlsCertificateId", "serverName", "configJson"]) {
    expect(serializedPayload.toLowerCase()).not.toContain(forbidden.toLowerCase());
  }
  await page.keyboard.press("Escape");

  const mixedRow = page.getByRole("row", { name: /Browser Mixed Proxy/ });
  await expect(mixedRow).toBeVisible();
  await expect(mixedRow.getByText(/Mixed（SOCKS5 \+ HTTP）/)).toBeVisible();
  await mixedRow.getByRole("button", { name: "查看详情" }).click();
  const detail = page.getByRole("dialog").filter({ hasText: "Browser Mixed Proxy" });
  await expect(detail.getByText("Mixed（SOCKS5 + HTTP）· RAW / TCP / 无 TLS", { exact: true })).toBeVisible();
  await expect(detail.getByText(/仅 TCP · 无 SOCKS4\/4a 与 UDP/)).toBeVisible();
  await detail.getByRole("tab", { name: "账户" }).click();
  await expect(detail.getByText("Browser Mixed Operator", { exact: true })).toBeVisible();
  await expect(detail.getByText("SOCKS5 / HTTP 共用用户名：已配置（隐藏） · 密码：已配置（隐藏）", { exact: true })).toBeVisible();
  await detail.getByRole("button", { name: "双代理地址 / QR" }).click();
  const shareDialog = page.getByRole("dialog").filter({ hasText: "Mixed 管理代理地址" });
  await expect(shareDialog.getByLabel("SOCKS5 代理地址", { exact: true })).toHaveValue(`socks5://${seededMixedUsername}:${seededMixedPassword}@8.8.8.8:24446`);
  await expect(shareDialog.getByLabel("HTTP 代理地址", { exact: true })).toHaveValue(`http://${seededMixedUsername}:${seededMixedPassword}@8.8.8.8:24446`);
  await expect(shareDialog.getByRole("button", { name: "复制 SOCKS5 地址" })).toBeVisible();
  await expect(shareDialog.getByRole("button", { name: "复制 HTTP 地址" })).toBeVisible();
  await expect(shareDialog.getByText(/这两个地址不会进入订阅/)).toBeVisible();
  expect(shareCacheControl).toContain("private");
  expect(shareCacheControl).toContain("no-store");
  expect(page.url()).not.toContain(seededMixedUsername);
  expect(page.url()).not.toContain(seededMixedPassword);
  const persisted = await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }));
  expect(persisted).not.toContain(seededMixedUsername);
  expect(persisted).not.toContain(seededMixedPassword);
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog").filter({ hasText: "Mixed 管理代理地址" })).toHaveCount(0);
  expect(errors).toEqual([]);
});

test("Tunnel create and detail UI keep the endpoint local and submit no credentials", async ({ page }) => {
  const errors: string[] = [];
  const probeNetworks: string[] = [];
  let createPayload: Record<string, unknown> | null = null;
  const findCreatePayload = (value: unknown): Record<string, unknown> | null => {
    if (!value || typeof value !== "object") return null;
    if (!Array.isArray(value) && (value as Record<string, unknown>).profileId === "TUNNEL_TCP_LOCAL_NONE") {
      return value as Record<string, unknown>;
    }
    for (const child of Object.values(value)) {
      const found = findCreatePayload(child);
      if (found) return found;
    }
    return null;
  };
  await page.route("**/api/trpc/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const procedurePaths = decodeURIComponent(url.pathname.split("/api/trpc/")[1] ?? "").split(",");
    const batched = url.searchParams.get("batch") === "1";
    const responseFor = (json: unknown) => ({ result: { data: { json } } });
    if (procedurePaths.includes("xray.portProbes.create") && request.method() === "POST") {
      const network = (request.postData() ?? "").match(/"network"\s*:\s*"(TCP|UDP)"/)?.[1] ?? "";
      probeNetworks.push(network);
      const response = responseFor({ operationId: "browser-tunnel-port-probe" });
      await route.fulfill({ status: 200, contentType: "application/json", json: batched ? [response] : response });
      return;
    }
    if (procedurePaths.includes("xray.portProbes.result")) {
      const response = responseFor({
        operationId: "browser-tunnel-port-probe",
        status: "SUCCESS",
        createdAt: new Date().toISOString(),
        network: "tcp",
        selectedPort: 29644,
        reservationId: "browser-tunnel-reservation",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      });
      await route.fulfill({ status: 200, contentType: "application/json", json: batched ? [response] : response });
      return;
    }
    if (procedurePaths.includes("xray.inbounds.createV2") && request.method() === "POST") {
      try {
        createPayload = findCreatePayload(JSON.parse(request.postData() ?? "null"));
      } catch {
        createPayload = null;
      }
      const response = responseFor({ inboundId: 101, operationId: "browser-tunnel-create", desiredGeneration: 2 });
      await route.fulfill({ status: 200, contentType: "application/json", json: batched ? [response] : response });
      return;
    }
    if (procedurePaths.includes("xray.operations.get")) {
      const response = responseFor({
        operationId: "browser-tunnel-create",
        hostId: seededHostId,
        inboundId: 101,
        type: "SYNC",
        status: "SUCCESS",
        stage: "COMPLETE",
        requestedGeneration: 2,
        errorCode: null,
        errorMessage: null,
        attemptCount: 1,
        createdAt: new Date().toISOString(),
        startedAt: new Date().toISOString(),
        finishedAt: new Date().toISOString(),
        expiresAt: null,
        updatedAt: new Date().toISOString(),
      });
      await route.fulfill({ status: 200, contentType: "application/json", json: batched ? [response] : response });
      return;
    }
    await route.continue();
  });
  page.on("console", (message) => { if (message.type() === "error") errors.push(`console:${message.text()}`); });
  page.on("pageerror", (error) => errors.push(`page:${error.message}`));
  page.on("requestfailed", (request) => errors.push(`network:${request.url()}:${request.failure()?.errorText}`));
  page.on("response", (response) => { if (response.status() >= 500) errors.push(`http:${response.status()}:${response.url()}`); });

  await page.goto(`${baseURL}/xray`, { waitUntil: "networkidle" });
  const devAnnouncement = page.getByRole("dialog", { name: "Dev popup announcement" });
  if (await devAnnouncement.isVisible()) await devAnnouncement.getByRole("button", { name: "我知道了" }).click();
  await page.locator("button:visible", { hasText: "创建节点" }).click();
  const createDialog = page.getByRole("dialog");
  await createDialog.getByRole("button", { name: /xray-browser-edge/ }).click();
  await createDialog.getByLabel("节点名称").fill("Browser Tunnel Created");
  await createDialog.getByRole("button", { name: "下一步：选择协议" }).click();
  await createDialog.getByRole("button", { name: /Tunnel（本机端口转发）/ }).click();
  await createDialog.getByRole("button", { name: "下一步：选择传输" }).click();
  await expect(createDialog.getByRole("button", { name: /无独立传输/ })).toHaveAttribute("aria-pressed", "true");
  await expect(createDialog.getByText("本机回环 / TCP / 固定目标", { exact: true })).toBeVisible();
  await createDialog.getByLabel("目标地址").fill("DB.EXAMPLE.COM");
  await createDialog.getByLabel("目标端口").fill("5432");
  await expect(createDialog.getByLabel(/portMap|followRedirect|TProxy|路由|出站/i)).toHaveCount(0);
  await createDialog.getByRole("button", { name: "下一步：检测端口" }).click();
  await createDialog.getByRole("button", { name: "自动检测可用端口" }).click();
  await expect(createDialog.getByText("端口可用", { exact: true })).toBeVisible();
  await createDialog.getByRole("button", { name: "下一步：配置安全" }).click();
  await expect(createDialog.getByText("Tunnel 固定访问边界", { exact: true })).toBeVisible();
  await createDialog.getByRole("button", { name: "下一步：访问边界" }).click();
  await expect(createDialog.getByText("0 个", { exact: true })).toBeVisible();
  await expect(createDialog.getByLabel(/账户|客户端|用户名|密码|UUID/i)).toHaveCount(0);
  await createDialog.getByRole("button", { name: "下一步：确认部署" }).click();
  await expect(createDialog.getByText("127.0.0.1:29644", { exact: true })).toBeVisible();
  await expect(createDialog.getByText(/默认 direct → db\.example\.com:5432/)).toBeVisible();
  await createDialog.getByRole("button", { name: "创建并部署" }).click();
  await expect(createDialog.getByRole("heading", { name: "操作成功" })).toBeVisible();
  expect(probeNetworks).toEqual(["TCP"]);
  expect(createPayload).toEqual({
    hostId: seededHostId,
    name: "Browser Tunnel Created",
    listenPort: 29644,
    portReservationId: "browser-tunnel-reservation",
    profileId: "TUNNEL_TCP_LOCAL_NONE",
    spec: { targetAddress: "db.example.com", targetPort: 5432 },
    initialAccessEntries: [],
  });
  const serializedPayload = JSON.stringify(createPayload);
  for (const forbidden of ["publicAddress", "listenAddress", "username", "password", "uuid", "portMap", "followRedirect", "route", "outbound", "configJson"]) {
    expect(serializedPayload.toLowerCase()).not.toContain(forbidden.toLowerCase());
  }
  await page.keyboard.press("Escape");

  const tunnelRow = page.getByRole("row", { name: /Browser Local Tunnel/ });
  await expect(tunnelRow).toBeVisible();
  await expect(tunnelRow.getByText("127.0.0.1:24447", { exact: true })).toBeVisible();
  await expect(tunnelRow.getByText("无", { exact: true })).toBeVisible();
  await tunnelRow.getByRole("button", { name: "查看详情" }).click();
  const detail = page.getByRole("dialog").filter({ hasText: "Browser Local Tunnel" });
  await expect(detail.getByText("Tunnel · 本机回环 / TCP / 无客户端认证", { exact: true })).toBeVisible();
  await expect(detail.getByText("db.example.com:5432", { exact: true })).toBeVisible();
  await expect(detail.getByRole("tab", { name: /账户|客户端|Peers/ })).toHaveCount(0);
  await expect(detail.getByRole("button", { name: /分享|QR/ })).toHaveCount(0);
  expect(errors).toEqual([]);
});

test("managed AmneziaWG supports typed UDP creation, peer detail, ephemeral share, and keeps TUN unavailable", async ({ page }) => {
  const errors: string[] = [];
  const probedNetworks: string[] = [];
  let createPayload: Record<string, unknown> | null = null;
  let shareRequests = 0;
  let shareCacheControl = "";
  const operationId = "browser-amneziawg-probe";
  const reservationId = "browser-amneziawg-reservation";
  const peerConfig = [
    "[Interface]",
    "PrivateKey = BROWSER_TEST_PRIVATE_KEY",
    "Address = 10.8.1.2/32",
    "DNS = 1.1.1.1, 1.0.0.1",
    "MTU = 1420",
    "",
    "[Peer]",
    "PublicKey = BROWSER_TEST_SERVER_KEY",
    "PresharedKey = BROWSER_TEST_PSK",
    "AllowedIPs = 0.0.0.0/0",
    "Endpoint = awg.example.com:29876",
    "PersistentKeepalive = 25",
    "",
  ].join("\n");
  const vpnUri = `vpn://${Buffer.from(peerConfig, "utf8").toString("base64url")}`;
  const hostOption = {
    id: seededHostId,
    name: "xray-browser-edge",
    isOnline: true,
    lastHeartbeat: new Date().toISOString(),
    publicAddress: "8.8.8.8",
    os: "linux",
    arch: "amd64",
    canCreateMtproto: true,
    canCreateAmneziawg: true,
    amneziawgUnavailableReasonCode: null,
    unavailableReasonCode: null,
  };
  const peer = {
    id: 701,
    name: "Browser Phone",
    accountTag: "forwardx-amneziawg-peer-browser",
    address: "10.8.1.2/32",
    isEnabled: true,
    secretConfigured: true,
    sortOrder: 0,
    updatedAt: new Date().toISOString(),
  };
  const service = {
    id: 700,
    hostId: seededHostId,
    hostName: "xray-browser-edge",
    name: "Browser AmneziaWG",
    kind: "AMNEZIAWG",
    publicAddress: "awg.example.com",
    listenAddress: "0.0.0.0",
    listenPort: 29876,
    targetVersion: "v3.1.20260814",
    isEnabled: true,
    pendingDelete: false,
    status: "RUNNING",
    desiredGeneration: 4,
    appliedGeneration: 4,
    desiredConfigHash: "a".repeat(64),
    appliedConfigHash: "a".repeat(64),
    observed: null,
    isHostOnline: true,
    capabilityAvailable: true,
    artifactAvailable: false,
    accounts: [peer],
    subnet: "10.8.1.0/24",
    mtu: 1420,
    dns: ["1.1.1.1", "1.0.0.1"],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  const mockedProcedures = new Set([
    "xray.managedServices.catalog",
    "xray.managedServices.hostOptions",
    "xray.managedServices.list",
    "xray.managedServices.detail",
    "xray.managedServices.createAmneziawg",
    "xray.managedServices.share",
    "xray.portProbes.create",
    "xray.portProbes.result",
  ]);
  const success = (json: unknown) => ({ result: { data: { json } } });
  const findCreatePayload = (value: unknown): Record<string, unknown> | null => {
    if (!value || typeof value !== "object") return null;
    if (!Array.isArray(value) && Array.isArray((value as Record<string, unknown>).initialPeers)) {
      return value as Record<string, unknown>;
    }
    for (const child of Object.values(value)) {
      const found = findCreatePayload(child);
      if (found) return found;
    }
    return null;
  };
  await page.route("**/api/trpc/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const encodedPaths = url.pathname.split("/api/trpc/")[1] ?? "";
    const procedurePaths = decodeURIComponent(encodedPaths).split(",");
    if (!procedurePaths.some((procedurePath) => mockedProcedures.has(procedurePath))) {
      await route.continue();
      return;
    }

    let responseBody: unknown;
    let sourceResponse: Awaited<ReturnType<typeof route.fetch>> | null = null;
    if (procedurePaths.some((procedurePath) => !mockedProcedures.has(procedurePath))) {
      sourceResponse = await route.fetch();
      responseBody = await sourceResponse.json();
    } else {
      responseBody = url.searchParams.get("batch") === "1"
        ? procedurePaths.map(() => success(null))
        : success(null);
    }
    const entries = Array.isArray(responseBody) ? responseBody : [responseBody];
    procedurePaths.forEach((procedurePath, index) => {
      if (!mockedProcedures.has(procedurePath)) return;
      let entry = success(null);
      if (procedurePath === "xray.managedServices.catalog") {
        entry = success([
          { kind: "MTPROTO_FAKE_TLS", name: "MTProto（Telegram FakeTLS）", status: "AVAILABLE", targetVersion: "v1.15.0", network: "TCP", privilege: "DEDICATED_UNPRIVILEGED_USER", unavailableReasonCode: null },
          { kind: "TUN", name: "TUN", status: "NOT_IMPLEMENTED", targetVersion: null, network: null, privilege: "REQUIRES_SEPARATE_CAP_NET_ADMIN_DESIGN", unavailableReasonCode: "NOT_IMPLEMENTED" },
          { kind: "AMNEZIAWG", name: "AmneziaWG", status: "AVAILABLE", targetVersion: "v3.1.20260814", network: "UDP", privilege: "DEDICATED_UNPRIVILEGED_USER", unavailableReasonCode: null },
        ]);
      } else if (procedurePath === "xray.managedServices.hostOptions") {
        entry = success([hostOption]);
      } else if (procedurePath === "xray.managedServices.list") {
        entry = success({ items: [service], page: 1, pageSize: 20, total: 1, totalPages: 1 });
      } else if (procedurePath === "xray.managedServices.detail") {
        entry = success(service);
      } else if (procedurePath === "xray.portProbes.create") {
        const network = (request.postData() ?? "").match(/\"network\"\s*:\s*\"(TCP|UDP)\"/)?.[1];
        if (network) probedNetworks.push(network);
        entry = success({ operationId });
      } else if (procedurePath === "xray.portProbes.result") {
        entry = success({
          operationId,
          status: "SUCCESS",
          createdAt: new Date().toISOString(),
          network: "udp",
          selectedPort: 29876,
          reservationId,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
        });
      } else if (procedurePath === "xray.managedServices.createAmneziawg") {
        try {
          createPayload = findCreatePayload(JSON.parse(request.postData() ?? "null"));
        } catch {
          createPayload = null;
        }
        entry = success({ serviceId: 702, accountIds: [703], generation: 5 });
      } else if (procedurePath === "xray.managedServices.share") {
        shareRequests += 1;
        entry = success({ kind: "AMNEZIAWG_CONFIG", content: peerConfig, fileName: "forwardx-browser-phone.conf", vpnUri });
      }
      if (Array.isArray(responseBody)) responseBody[index] = entry;
      else responseBody = entry;
    });
    const headers = sourceResponse?.headers() ?? {};
    if (procedurePaths.includes("xray.managedServices.share")) {
      headers["cache-control"] = "private, no-store, max-age=0";
      headers.pragma = "no-cache";
    }
    await route.fulfill({
      ...(sourceResponse ? { response: sourceResponse } : {}),
      status: 200,
      contentType: "application/json",
      headers,
      json: responseBody,
    });
  });
  page.on("console", (message) => { if (message.type() === "error") errors.push(`console:${message.text()}`); });
  page.on("pageerror", (error) => errors.push(`page:${error.message}`));
  page.on("requestfailed", (request) => errors.push(`network:${request.url()}:${request.failure()?.errorText}`));
  page.on("response", (response) => {
    if (response.status() >= 500) errors.push(`http:${response.status()}:${response.url()}`);
    if (response.url().includes("xray.managedServices.share")) shareCacheControl = response.headers()["cache-control"] ?? "";
  });

  await page.goto(`${baseURL}/xray`, { waitUntil: "networkidle" });
  const devAnnouncement = page.getByRole("dialog", { name: "Dev popup announcement" });
  if (await devAnnouncement.isVisible()) await devAnnouncement.getByRole("button", { name: "我知道了" }).click();

  await page.getByRole("tab", { name: "独立服务" }).click();
  await expect(page).toHaveURL(/(?:\?|&)tab=managed-services(?:&|$)/);
  const results = page.getByRole("region", { name: "独立服务结果" });
  await expect(results).toBeVisible();
  await expect(results.getByText("MTProto（Telegram FakeTLS）", { exact: true })).toBeVisible();
  await expect(results.getByText("AmneziaWG", { exact: true }).first()).toBeVisible();
  await expect(results.getByText("amneziawg-go v3.1.20260814 · userspace helper · UDP", { exact: true })).toBeVisible();
  await expect(results.getByText("需要单独的特权与运行时方案，当前不可创建。", { exact: true })).toBeVisible();
  await expect(results.getByRole("button", { name: /创建 TUN/i })).toHaveCount(0);

  await results.getByRole("button", { name: "创建 AmneziaWG" }).click();
  const dialog = page.getByRole("dialog", { name: "创建独立服务" });
  await expect(dialog).toBeVisible();
  for (const label of ["服务类型", "主机", "名称 / 备注", "公开地址", "UDP 端口", "初始 peer 名称"]) {
    await expect(dialog.getByLabel(label, { exact: true })).toBeVisible();
  }
  await expect(dialog.getByText("地址、密钥与 PSK 由服务端生成。", { exact: true })).toBeVisible();
  await expect(dialog.getByText(/IPv4 10\.8\.1\.0\/24 · MTU 1420/)).toBeVisible();
  await expect(dialog.getByLabel(/Secret|密码|私钥|PSK|混淆|路由|interface|JSON|额外参数/i)).toHaveCount(0);
  await dialog.getByLabel("主机", { exact: true }).click();
  await page.getByRole("option", { name: "xray-browser-edge" }).click();
  await dialog.getByLabel("名称 / 备注", { exact: true }).fill("Browser Created AWG");
  await dialog.getByLabel("公开地址", { exact: true }).fill("awg-created.example.com");
  await dialog.getByLabel("初始 peer 名称", { exact: true }).fill("Browser Created Peer");
  await dialog.getByRole("button", { name: "探测" }).click();
  await expect(dialog.getByText("UDP 端口 29876 已临时预留", { exact: true })).toBeVisible();
  await dialog.getByRole("button", { name: "创建", exact: true }).click();
  await expect(dialog).toBeHidden();
  expect(probedNetworks).toEqual(["UDP"]);
  expect(createPayload).toEqual({
    hostId: seededHostId,
    name: "Browser Created AWG",
    publicAddress: "awg-created.example.com",
    listenPort: 29876,
    portReservationId: reservationId,
    initialPeers: [{ name: "Browser Created Peer" }],
  });
  const serializedCreate = JSON.stringify(createPayload);
  for (const forbidden of ["privateKey", "publicKey", "preSharedKey", "psk", "obfuscation", "route", "interface", "configJson"]) {
    expect(serializedCreate.toLowerCase()).not.toContain(forbidden.toLowerCase());
  }

  await results.getByRole("button", { name: /Browser AmneziaWG/ }).click();
  const detail = page.getByRole("dialog", { name: "Browser AmneziaWG" });
  await expect(detail.getByText("awg.example.com:29876/udp", { exact: true })).toBeVisible();
  await expect(detail.getByText("10.8.1.2/32", { exact: true })).toBeVisible();
  await expect(detail.getByText("配置已就绪", { exact: true })).toBeVisible();

  await detail.getByRole("button", { name: "配置", exact: true }).click();
  let share = page.getByRole("dialog", { name: "AmneziaWG peer 配置" });
  await expect(share.getByLabel("标准 .conf", { exact: true })).toHaveValue(peerConfig);
  await expect(share.getByLabel("vpn:// 导入链接", { exact: true })).toHaveValue(vpnUri);
  await expect(share.getByRole("img", { name: "AmneziaWG 配置二维码" })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(share).toBeHidden();
  await expect(page.getByText("BROWSER_TEST_PRIVATE_KEY", { exact: false })).toHaveCount(0);

  await detail.getByRole("button", { name: "配置", exact: true }).click();
  share = page.getByRole("dialog", { name: "AmneziaWG peer 配置" });
  await expect(share.getByLabel("标准 .conf", { exact: true })).toHaveValue(peerConfig);
  await expect.poll(() => shareRequests).toBe(2);
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    share.getByRole("button", { name: "下载 .conf", exact: true }).click(),
  ]);
  expect(download.suggestedFilename()).toBe("forwardx-browser-phone.conf");
  await expect(share).toBeHidden();
  await expect(page.getByText("BROWSER_TEST_PRIVATE_KEY", { exact: false })).toHaveCount(0);

  await detail.getByRole("button", { name: "配置", exact: true }).click();
  share = page.getByRole("dialog", { name: "AmneziaWG peer 配置" });
  await expect(share.getByLabel("vpn:// 导入链接", { exact: true })).toHaveValue(vpnUri);
  await expect.poll(() => shareRequests).toBe(3);
  expect(shareCacheControl).toContain("private");
  expect(shareCacheControl).toContain("no-store");
  await page.keyboard.press("Escape");
  expect(errors).toEqual([]);
});

test("successful inbound deletion closes the removed detail instead of refetching it", async ({ page }) => {
  let removalAccepted = false;
  let detailRequestsAfterRemoval = 0;
  await page.route("**/api/trpc/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const encodedPaths = url.pathname.split("/api/trpc/")[1] ?? "";
    const procedurePaths = decodeURIComponent(encodedPaths).split(",");
    if (procedurePaths.includes("xray.inbounds.remove") && request.method() === "POST") {
      removalAccepted = true;
      const success = { result: { data: { json: {
        inboundId: 1,
        operationId: "browser-remove-2",
        desiredGeneration: 2,
        pendingDelete: true,
        mayRemainActive: true,
        lastInbound: false,
      } } } };
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        json: url.searchParams.get("batch") === "1" ? [success] : success,
      });
      return;
    }
    if (removalAccepted && procedurePaths.includes("xray.inbounds.detail")) {
      detailRequestsAfterRemoval += 1;
      await route.fulfill({ status: 404, contentType: "application/json", json: {} });
      return;
    }
    await route.continue();
  });

  await page.goto(`${baseURL}/xray`, { waitUntil: "networkidle" });
  const devAnnouncement = page.getByRole("dialog", { name: "Dev popup announcement" });
  if (await devAnnouncement.isVisible()) await devAnnouncement.getByRole("button", { name: "我知道了" }).click();

  await page.getByRole("row", { name: /Browser Reality/ }).getByRole("button", { name: "查看详情" }).click();
  const detail = page.getByRole("dialog", { name: "Browser Reality" });
  await detail.getByRole("button", { name: "删除节点" }).click();
  const confirmation = page.getByRole("dialog", { name: "删除 Xray 节点" });
  await confirmation.getByLabel(/输入节点名/).fill("Browser Reality");
  await confirmation.getByRole("button", { name: "确认删除节点" }).click();

  await expect(page.getByText("节点详情加载失败或节点已不存在。", { exact: true })).toHaveCount(0);
  await expect(page).not.toHaveURL(/(?:\?|&)inboundId=1(?:&|$)/);
  expect(detailRequestsAfterRemoval).toBe(0);
});

test("external proxy import and Xray inbound binding controls stay usable in a small viewport", async ({ page }) => {
  const errors: string[] = [];
  page.on("console", (message) => { if (message.type() === "error") errors.push(`console:${message.text()}`); });
  page.on("pageerror", (error) => errors.push(`page:${error.message}`));
  page.on("requestfailed", (request) => errors.push(`network:${request.url()}:${request.failure()?.errorText}`));

  await page.goto(`${baseURL}/xray`, { waitUntil: "networkidle" });
  const devAnnouncement = page.getByRole("dialog", { name: "Dev popup announcement" });
  if (await devAnnouncement.isVisible()) await devAnnouncement.getByRole("button", { name: "我知道了" }).click();

  await page.getByRole("tab", { name: "出口节点" }).click();
  await expect(page.getByRole("region", { name: "出口节点结果" })).toBeVisible();
  await page.getByRole("button", { name: "导入出口节点" }).click();
  const importDialog = page.getByRole("dialog", { name: "导入出口节点" });
  const credentials = Buffer.from("aes-256-gcm:p@ss:word", "utf8").toString("base64url");
  await importDialog.getByLabel("节点链接").fill(`ss://${credentials}@ss.example.com:8388#Browser%20US%20A`);
  await importDialog.getByRole("button", { name: "识别并预览" }).click();
  await expect(importDialog.getByText("Shadowsocks", { exact: true })).toBeVisible();
  await expect(importDialog.getByText("ss.example.com:8388", { exact: true })).toBeVisible();
  await expect(importDialog.getByLabel("显示名称")).toHaveValue("Browser US A");

  await page.setViewportSize({ width: 320, height: 360 });
  await expect.poll(() => importDialog.evaluate((element) => {
    element.scrollTop = element.scrollHeight;
    return element.scrollHeight > element.clientHeight
      && Math.ceil(element.scrollTop + element.clientHeight) >= element.scrollHeight;
  })).toBe(true);
  await importDialog.getByRole("button", { name: "确认导入" }).click();
  await expect(importDialog).toBeHidden();
  await page.setViewportSize({ width: 1440, height: 900 });
  await expect(page.getByRole("row", { name: /Browser US A/ })).toBeVisible();

  await page.getByRole("tab", { name: "节点管理" }).click();
  const inboundRow = page.getByRole("row", { name: /Browser Reality/ });
  await inboundRow.getByRole("button", { name: "查看详情" }).click();
  const inboundDetail = page.getByRole("dialog", { name: "Browser Reality" });
  await expect(inboundDetail.getByText("直连", { exact: true })).toBeVisible();
  await inboundDetail.getByRole("button", { name: "配置出口" }).click();
  const bindingDialog = page.getByRole("dialog", { name: "配置出口节点" });
  await bindingDialog.getByLabel("搜索出口节点").fill("Browser US A");
  await bindingDialog.getByRole("combobox").click();
  await page.getByRole("option", { name: /Browser US A/ }).click();
  await expect(bindingDialog.getByRole("button", { name: "保存并同步" })).toBeEnabled();
  await bindingDialog.getByRole("button", { name: "取消" }).click();
  await page.keyboard.press("Escape");

  await page.goto(`${baseURL}/rules`, { waitUntil: "networkidle" });
  await page.getByRole("button", { name: "添加规则" }).click();
  const ruleDialog = page.getByRole("dialog", { name: "添加转发规则" });
  const portForwardSelector = ruleDialog.locator("label", { hasText: "使用端口转发" }).locator("..").getByRole("combobox");
  await portForwardSelector.click();
  await page.getByRole("option", { name: /Port forward - JP game/ }).click();
  const externalTargetButton = ruleDialog.getByRole("button", { name: "出口节点" });
  await expect(externalTargetButton).toBeEnabled();
  await externalTargetButton.click();
  await expect(ruleDialog.getByLabel("搜索规则出口节点")).toBeVisible();
  await expect(ruleDialog.getByPlaceholder("例如: 10.0.0.1 或 example.com")).toHaveValue("ss.example.com");
  await expect(ruleDialog.getByPlaceholder("例如: 10.0.0.1 或 example.com")).toHaveAttribute("readonly", "");
  await expect(ruleDialog.getByPlaceholder("例如: 80")).toHaveValue("8388");
  await expect(ruleDialog.getByText(/六种本地转发工具只把 TCP 原始流量转发/)).toBeVisible();
  await ruleDialog.getByRole("button", { name: "手动目标" }).click();
  await expect(ruleDialog.getByPlaceholder("例如: 10.0.0.1 或 example.com")).toHaveValue("");
  await expect(ruleDialog.getByPlaceholder("例如: 10.0.0.1 或 example.com")).not.toHaveAttribute("readonly", "");
  await page.keyboard.press("Escape");

  expect(errors).toEqual([]);
});
