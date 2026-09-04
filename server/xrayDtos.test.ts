import assert from "node:assert/strict";
import test from "node:test";
import {
  toXrayArtifactDto,
  toXrayClientDto,
  toXrayHostDeploymentDto,
  toXrayInboundDto,
  toXrayOperationDto,
  toXrayRuntimeReportDto,
} from "./xrayDtos";

const secretMarker = "xray-dto-secret-marker";

function assertSafeDto(dto: unknown, forbiddenKeys: string[]) {
  const serialized = JSON.stringify(dto);
  assert.equal(serialized.includes(secretMarker), false);
  for (const key of forbiddenKeys) assert.equal(Object.hasOwn(dto as object, key), false, key);
}

test("ordinary Xray DTOs use explicit projections and exclude encrypted or credential-bearing fields", () => {
  const common = {
    id: 1,
    createdAt: new Date("2026-01-01T00:00:00.000Z"),
    updatedAt: new Date("2026-01-02T00:00:00.000Z"),
    configJson: secretMarker,
    privateKey: secretMarker,
    shareUri: secretMarker,
    agentToken: secretMarker,
  };

  const inbound = toXrayInboundDto({
    ...common,
    hostId: 2,
    name: "inbound",
    runtimeTag: "inbound-1",
    publicAddress: "203.0.113.1",
    listenAddress: "0.0.0.0",
    listenPort: 24443,
    protocol: "vless",
    transport: "tcp",
    security: "reality",
    realityTargetHost: "example.com",
    realityTargetPort: 443,
    realityServerName: "example.com",
    realityPublicKey: "public-key",
    realityPrivateKeyEncrypted: secretMarker,
    secretKeyVersion: 1,
    fingerprint: "chrome",
    spiderX: "/",
    isEnabled: 1,
    pendingDelete: 0,
    desiredGeneration: 3,
    createdByUserId: 4,
    hasRealityPrivateKey: 1,
  });
  assert.equal(inbound.hasRealityPrivateKey, true);
  assertSafeDto(inbound, ["realityPrivateKeyEncrypted", "secretKeyVersion", "configJson", "privateKey", "shareUri"]);

  const client = toXrayClientDto({
    ...common,
    inboundId: 1,
    name: "client",
    uuidEncrypted: secretMarker,
    uuidFingerprint: secretMarker,
    shortIdEncrypted: secretMarker,
    shortIdFingerprint: secretMarker,
    statsKey: "stats-1",
    flow: "xtls-rprx-vision",
    ownerUserId: null,
    isEnabled: true,
    pendingDelete: false,
    desiredGeneration: 3,
    sortOrder: 0,
    hasUuid: 1,
    hasShortId: 1,
  });
  assert.deepEqual(client.credentials, { uuidConfigured: true, shortIdConfigured: true });
  assertSafeDto(client, ["uuidEncrypted", "uuidFingerprint", "shortIdEncrypted", "shortIdFingerprint"]);

  const deployment = toXrayHostDeploymentDto({
    ...common,
    hostId: 2,
    targetVersion: "v26.7.28",
    desiredGeneration: 3,
    desiredConfigHash: "a".repeat(64),
    lastOperationId: "operation-1",
  });
  assertSafeDto(deployment, ["configJson"]);

  const runtime = toXrayRuntimeReportDto({
    ...common,
    hostId: 2,
    capabilitySchemaVersion: 1,
    supportsUdpPortProbe: 1,
    supportsUdpListenerReadiness: true,
    isInstalled: true,
    installedVersion: "v26.7.28",
    runningVersion: "v26.7.28",
    serviceStatus: "RUNNING",
    processId: 123,
    appliedGeneration: 3,
    appliedConfigHash: "a".repeat(64),
    binarySha256: "b".repeat(64),
    listenersJson: secretMarker,
    reportSignature: secretMarker,
    lastErrorCode: null,
    lastErrorMessage: null,
    reportedAt: new Date("2026-01-02T00:00:00.000Z"),
  });
  assert.equal(runtime.supportsUdpPortProbe, true);
  assert.equal(runtime.supportsUdpListenerReadiness, true);
  assertSafeDto(runtime, ["listenersJson", "reportSignature", "configJson"]);

  const artifact = toXrayArtifactDto({
    ...common,
    version: "v26.7.28",
    os: "linux",
    arch: "amd64",
    packageFormat: "zip",
    storageKey: secretMarker,
    sha256: "c".repeat(64),
    fileSize: 123,
    status: "VERIFIED",
    source: secretMarker,
    verifiedAt: new Date("2026-01-02T00:00:00.000Z"),
  });
  assertSafeDto(artifact, ["storageKey", "source"]);

  const operation = toXrayOperationDto({
    ...common,
    operationId: "operation-1",
    hostId: 2,
    inboundId: 1,
    type: "SYNC",
    requestedGeneration: 3,
    status: "QUEUED",
    requestMetaJson: secretMarker,
    resultJson: secretMarker,
    errorCode: null,
    errorMessage: null,
    attemptCount: 0,
    createdByUserId: 4,
    startedAt: null,
    finishedAt: null,
    expiresAt: null,
  });
  assertSafeDto(operation, ["requestMetaJson", "resultJson", "configJson"]);
});

test("Xray runtime and operation DTOs never expose persisted error text", () => {
  const secret = "xray-token-UNIQUE-031-dto-error";
  const runtime = toXrayRuntimeReportDto({
    id: 1, hostId: 2, capabilitySchemaVersion: 1, serviceStatus: "ERROR",
    lastErrorCode: "CONFIG_INVALID", lastErrorMessage: secret, updatedAt: new Date(0),
  });
  const operation = toXrayOperationDto({
    id: 3, operationId: "operation-safe", hostId: 2, type: "SYNC", status: "FAILED",
    errorCode: "CONFIG_INVALID", errorMessage: secret, attemptCount: 1,
    createdByUserId: 4, createdAt: new Date(0), updatedAt: new Date(0),
  });
  assert.equal(JSON.stringify({ runtime, operation }).includes(secret), false);
  assert.equal(runtime.lastErrorMessage, "Managed Xray runtime reported an error");
  assert.equal(runtime.supportsUdpPortProbe, false);
  assert.equal(runtime.supportsUdpListenerReadiness, false);
  assert.equal(operation.errorMessage, "Managed Xray operation did not complete");
});

test("DTO conversion normalizes database booleans and epoch values without copying unknown fields", () => {
  const dto = toXrayClientDto({
    id: "5",
    inboundId: "4",
    name: "client",
    statsKey: "stats-5",
    flow: "xtls-rprx-vision",
    ownerUserId: "3",
    isEnabled: "0",
    pendingDelete: "true",
    desiredGeneration: "7",
    sortOrder: "2",
    hasUuid: "1",
    hasShortId: 0,
    createdAt: 1_700_000_000,
    updatedAt: "1700000001",
    unexpected: secretMarker,
  });
  assert.equal(dto.id, 5);
  assert.equal(dto.isEnabled, false);
  assert.equal(dto.pendingDelete, true);
  assert.equal(dto.createdAt.toISOString(), "2023-11-14T22:13:20.000Z");
  assert.equal(dto.updatedAt.toISOString(), "2023-11-14T22:13:21.000Z");
  assert.equal(Object.hasOwn(dto, "unexpected"), false);
});
