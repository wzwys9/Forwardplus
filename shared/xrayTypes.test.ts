import assert from "node:assert/strict";
import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  XRAY_AGENT_ERROR_CODES,
  XRAY_LIMITS,
  XrayCapabilitySchema,
  XrayDesiredStateSchema,
  XrayManagedServicesCapabilitySchema,
  XrayManagedServicesDesiredStateSchema,
  XrayManagedServicesObservedReportSchema,
  XrayObservedReportSchema,
  XrayObservedStateSchema,
  XrayTaskResultSchema,
  XrayTaskSchema,
} from "./xrayTypes";

function readExample(name: string): unknown {
  return JSON.parse(readFileSync(new URL(`../docs/xray/examples/${name}`, import.meta.url), "utf8"));
}

function validPortProbeTask() {
  return readExample("agent-task.v1.json") as Record<string, unknown>;
}

function validPortProbeResult() {
  return {
    schemaVersion: 1,
    taskId: "01991b5b-38e7-7f22-a676-c42693bded21",
    type: "PORT_PROBE",
    status: "SUCCESS",
    startedAt: "2026-09-01T08:00:01Z",
    finishedAt: "2026-09-01T08:00:02Z",
    result: {
      ports: [
        { port: 23456, available: true, errorCode: null },
        { port: 23501, available: false, errorCode: "PORT_IN_USE" },
      ],
      observedAt: "2026-09-01T08:00:02Z",
    },
    error: null,
  };
}

function udpContractFixture() {
  return readExample("udp-contract.v1.json") as Record<string, any>;
}

test("keeps mixed MTProto and AmneziaWG on one strict leak-safe v1 contract", () => {
  const fixture = readExample("managed-services.v1.json") as Record<string, any>;
  const capability = XrayManagedServicesCapabilitySchema.parse(fixture.capability);
  const desired = XrayManagedServicesDesiredStateSchema.parse(fixture.desired);
  const observed = XrayManagedServicesObservedReportSchema.parse(fixture.observedReport);
  const state = observed.managedServicesState!;
  const mtproto = desired.services[0] as any;
  const amneziawg = desired.services[1] as any;
  const configHash = crypto.createHash("sha256").update(JSON.stringify(desired.services)).digest("hex");
  const signature = crypto.createHash("sha256").update(JSON.stringify({ ...state, observedAt: "" })).digest("hex");

  assert.deepEqual(capability.supportedKinds, ["MTPROTO_FAKE_TLS"]);
  assert.deepEqual(capability.kindCapabilities?.map((item) => [item.kind, item.network]), [
    ["MTPROTO_FAKE_TLS", "tcp"],
    ["AMNEZIAWG", "udp"],
  ]);
  assert.equal(configHash, desired.configHash);
  assert.equal(signature, observed.managedServicesStateSignature);
  assert.deepEqual(state.services.map((service) => [service.kind, service.listener.network, service.listener.status]), [
    ["MTPROTO_FAKE_TLS", "tcp", "READY"],
    ["AMNEZIAWG", "udp", "READY"],
  ]);
  assert.equal(amneziawg.publicAddress, "vpn.example.com");
  assert.equal(JSON.stringify(state).includes(mtproto.accounts[0].secret), false);
  assert.equal(JSON.stringify(state).includes(amneziawg.serverPrivateKey), false);
  assert.equal(JSON.stringify(state).includes(amneziawg.peers[0].preSharedKey), false);

  assert.equal(XrayManagedServicesDesiredStateSchema.safeParse({
    ...desired,
    services: [{ ...mtproto, apiBindTo: "127.0.0.1:3129" }, amneziawg],
  }).success, false);
  assert.equal(XrayManagedServicesDesiredStateSchema.safeParse({
    ...desired,
    services: [{
      ...mtproto,
      accounts: [{ ...mtproto.accounts[0], secret: mtproto.accounts[0].secret.replace("6578", "006578") }],
    }, amneziawg],
  }).success, false);
  assert.equal(XrayManagedServicesDesiredStateSchema.safeParse({
    ...desired,
    services: [mtproto, { ...amneziawg, artifact: null }],
  }).success, false, "an explicit null field from the other branch must be rejected");
  assert.equal(XrayManagedServicesDesiredStateSchema.safeParse({
    ...desired,
    services: [{ ...mtproto, publicAddress: null }, amneziawg],
  }).success, false, "MTProto must reject even an empty field from the AmneziaWG branch");
  assert.equal(XrayManagedServicesDesiredStateSchema.safeParse({
    ...desired,
    services: [mtproto, { ...amneziawg, publicAddress: null }],
  }).success, false);
  const zeroKey = Buffer.alloc(32).toString("base64");
  const unclampedPrivateKey = Buffer.alloc(32, 1).toString("base64");
  assert.equal(XrayManagedServicesDesiredStateSchema.safeParse({
    ...desired,
    services: [mtproto, { ...amneziawg, serverPrivateKey: zeroKey }],
  }).success, false, "the zero server private key must be rejected");
  assert.equal(XrayManagedServicesDesiredStateSchema.safeParse({
    ...desired,
    services: [mtproto, { ...amneziawg, serverPrivateKey: unclampedPrivateKey }],
  }).success, false, "the server private key must already be Curve25519-clamped");
  assert.equal(XrayManagedServicesDesiredStateSchema.safeParse({
    ...desired,
    services: [mtproto, {
      ...amneziawg,
      peers: [{ ...amneziawg.peers[0], preSharedKey: zeroKey }],
    }],
  }).success, false, "the zero peer PSK must be rejected");
  assert.equal(XrayManagedServicesDesiredStateSchema.safeParse({
    ...desired,
    services: [mtproto, {
      ...amneziawg,
      obfuscation: { ...amneziawg.obfuscation, headerProtectionKey: zeroKey },
    }],
  }).success, false, "the zero header protection key must be rejected");
  assert.equal("futureSafeCapability" in XrayManagedServicesCapabilitySchema.parse({ ...fixture.capability, futureSafeCapability: true }), false);
  assert.equal(XrayManagedServicesObservedReportSchema.safeParse({
    ...observed,
    managedServicesState: { ...state, secret: mtproto.accounts[0].secret },
  }).success, false);
});

test("parses the approved desired, observed, and task v1 examples", () => {
  const desired = XrayDesiredStateSchema.parse(readExample("desired-state.v1.json"));
  const observed = XrayObservedReportSchema.parse(readExample("observed-state.v1.json"));
  const task = XrayTaskSchema.parse(readExample("agent-task.v1.json"));

  assert.equal(desired.schemaVersion, 1);
  assert.equal(observed.xrayState?.serviceStatus, "RUNNING");
  assert.equal(task.type, "PORT_PROBE");
});

test("parses the shared additive UDP contract while preserving old capability defaults", () => {
  const fixture = udpContractFixture();
  const capability = XrayCapabilitySchema.parse(fixture.capability);
  const desired = XrayDesiredStateSchema.parse(fixture.desired);
  const observed = XrayObservedReportSchema.parse(fixture.observed);
  const task = XrayTaskSchema.parse(fixture.task);

  assert.equal(capability.supportsUdpPortProbe, true);
  assert.equal(capability.supportsUdpListenerReadiness, true);
  assert.deepEqual(desired.expectedListeners.map((listener) => listener.network), ["tcp", "udp"]);
  assert.deepEqual(observed.xrayState?.listeners.map((listener) => listener.network), ["tcp", "udp"]);
  assert.equal(task.type === "PORT_PROBE" ? task.payload.network : null, "udp");

  const oldCapability = XrayCapabilitySchema.parse({
    ...fixture.capability,
    supportsUdpPortProbe: undefined,
    supportsUdpListenerReadiness: undefined,
  });
  assert.equal(oldCapability.supportsUdpPortProbe, false);
  assert.equal(oldCapability.supportsUdpListenerReadiness, false);

  assert.equal(XrayTaskSchema.safeParse({
    ...fixture.task,
    payload: { ...fixture.task.payload, ports: [24456, 24457] },
  }).success, false);
  assert.equal(XrayTaskSchema.safeParse({
    ...fixture.task,
    payload: { ...fixture.task.payload, network: "both" },
  }).success, false);
});

test("accepts safe additive fields while stripping them from parsed protocol values", () => {
  const capability = XrayCapabilitySchema.parse({
    schemaVersion: 1,
    supported: true,
    supervisor: "AGENT_CHILD",
    supportsPortProbe: true,
    supportsRealityScan: true,
    supportsArtifactInstall: true,
    supportedOS: "linux",
    supportedArch: "amd64",
    futureCapability: "safe-addition",
  });
  const task = XrayTaskSchema.parse({
    ...validPortProbeTask(),
    futureEnvelopeField: true,
    payload: {
      network: "tcp",
      listenAddress: "0.0.0.0",
      ports: [23456],
      futurePayloadField: "safe-addition",
    },
  });

  assert.equal("futureCapability" in capability, false);
  assert.equal("futureEnvelopeField" in task, false);
  assert.equal("futurePayloadField" in task.payload, false);
});

test("defines every approved typed task variant", () => {
  const base = {
    schemaVersion: 1,
    taskId: "task-123",
    createdAt: "2026-09-01T08:00:00Z",
    expiresAt: "2026-09-01T08:01:00Z",
  };
  const fixtures = [
    {
      ...base,
      type: "PORT_PROBE",
      payload: { network: "tcp", listenAddress: "0.0.0.0", ports: [1000, 65535] },
    },
    {
      ...base,
      type: "REALITY_SCAN",
      payload: { targets: ["www.microsoft.com:443"], timeoutMs: 10_000, maxConcurrency: 16 },
    },
    {
      ...base,
      type: "INSTALL",
      payload: {
        artifactId: 7,
        version: "v26.3.27",
        os: "linux",
        arch: "amd64",
        size: 17_234_567,
        sha256: "a".repeat(64),
        downloadPath: "/api/agent/artifacts/xray/7",
      },
    },
    {
      ...base,
      type: "UPGRADE",
      payload: {
        artifactId: 8,
        version: "v26.3.27",
        os: "linux",
        arch: "arm64",
        size: 17_234_567,
        sha256: "b".repeat(64),
        downloadPath: "/api/agent/artifacts/xray/8",
      },
    },
    { ...base, type: "RESTART", payload: { reason: "ADMIN_REQUEST" } },
  ];

  assert.deepEqual(fixtures.map((fixture) => XrayTaskSchema.parse(fixture).type), [
    "PORT_PROBE",
    "REALITY_SCAN",
    "INSTALL",
    "UPGRADE",
    "RESTART",
  ]);
});

test("rejects invalid schema versions, enums, identifiers, and task chronology", () => {
  assert.equal(XrayCapabilitySchema.safeParse({
    schemaVersion: 2,
    supported: true,
    supervisor: "AGENT_CHILD",
    supportsPortProbe: true,
    supportsRealityScan: true,
    supportsArtifactInstall: true,
    supportedOS: "linux",
    supportedArch: "amd64",
  }).success, false);
  assert.equal(XrayCapabilitySchema.safeParse({
    schemaVersion: 1,
    supported: true,
    supervisor: "SYSTEMD",
    supportsPortProbe: true,
    supportsRealityScan: true,
    supportsArtifactInstall: true,
    supportedOS: "linux",
    supportedArch: "amd64",
  }).success, false);
  assert.equal(XrayObservedStateSchema.safeParse({
    ...(readExample("observed-state.v1.json") as any).xrayState,
    serviceStatus: "STARTING",
  }).success, false);
  assert.equal(XrayTaskSchema.safeParse({ ...validPortProbeTask(), type: "SHELL" }).success, false);
  assert.equal(XrayTaskSchema.safeParse({ ...validPortProbeTask(), taskId: "bad id with spaces" }).success, false);
  assert.equal(XrayTaskSchema.safeParse({
    ...validPortProbeTask(),
    createdAt: "2026-09-01T08:00:30Z",
    expiresAt: "2026-09-01T08:00:00Z",
  }).success, false);
  assert.equal(XrayTaskResultSchema.safeParse({ ...validPortProbeResult(), status: "QUEUED" }).success, false);
});

test("enforces desired config byte and expected listener limits", () => {
  const desired = readExample("desired-state.v1.json") as any;
  assert.equal(XrayDesiredStateSchema.safeParse({
    ...desired,
    configJson: "😀".repeat(Math.ceil(XRAY_LIMITS.maxConfigJsonBytes / 4) + 1),
  }).success, false);
  assert.equal(XrayDesiredStateSchema.safeParse({
    ...desired,
    expectedListeners: Array.from({ length: XRAY_LIMITS.maxExpectedListeners + 1 }, () => desired.expectedListeners[0]),
  }).success, false);
  assert.equal(XrayDesiredStateSchema.safeParse({ ...desired, configHash: "A".repeat(64) }).success, false);
  assert.equal(XrayDesiredStateSchema.safeParse({ ...desired, configJson: "not-json" }).success, false);
});

test("enforces port probe range, count, uniqueness, and fixed bind settings", () => {
  const task = validPortProbeTask() as any;
  for (const ports of [[999], [65_536], Array.from({ length: XRAY_LIMITS.maxPortProbeCandidates + 1 }, (_, index) => 20_000 + index), [20_000, 20_000]]) {
    assert.equal(XrayTaskSchema.safeParse({ ...task, payload: { ...task.payload, ports } }).success, false);
  }
  assert.equal(XrayTaskSchema.safeParse({ ...task, payload: { ...task.payload, network: "both" } }).success, false);
  assert.equal(XrayTaskSchema.safeParse({ ...task, payload: { ...task.payload, listenAddress: "127.0.0.1" } }).success, false);
});

test("enforces Reality scan target, concurrency, and timeout limits", () => {
  const base = {
    schemaVersion: 1,
    taskId: "reality-scan-1",
    type: "REALITY_SCAN",
    createdAt: "2026-09-01T08:00:00Z",
    expiresAt: "2026-09-01T08:01:00Z",
    payload: { targets: ["www.microsoft.com:443"], timeoutMs: 10_000, maxConcurrency: 16 },
  };
  assert.equal(XrayTaskSchema.safeParse({
    ...base,
    payload: { ...base.payload, targets: Array.from({ length: XRAY_LIMITS.maxRealityTargets + 1 }, (_, i) => `host-${i}.example.com:443`) },
  }).success, false);
  assert.equal(XrayTaskSchema.safeParse({ ...base, payload: { ...base.payload, maxConcurrency: 17 } }).success, false);
  assert.equal(XrayTaskSchema.safeParse({ ...base, payload: { ...base.payload, timeoutMs: 10_001 } }).success, false);
  for (const target of ["10.0.0.0/8", "https://example.com", "user@example.com:443", "example.com:0"]) {
    assert.equal(XrayTaskSchema.safeParse({ ...base, payload: { ...base.payload, targets: [target] } }).success, false);
  }
});

test("rejects command fields in typed tasks and secret fields in observed state or task results", () => {
  const observed = readExample("observed-state.v1.json") as any;
  for (const injected of [
    { configJson: "secret-config" },
    { privateKey: "secret-private-key" },
    { nested: { uuid: "00000000-0000-4000-8000-000000000001" } },
    { nested: [{ shortId: "0123456789abcdef" }] },
  ]) {
    assert.equal(XrayObservedReportSchema.safeParse({ ...observed, xrayState: { ...observed.xrayState, ...injected } }).success, false);
  }
  assert.equal(XrayTaskSchema.safeParse({
    ...validPortProbeTask(),
    payload: { ...(validPortProbeTask() as any).payload, command: "id" },
  }).success, false);
  assert.equal(XrayTaskSchema.safeParse({ ...validPortProbeTask(), script: "echo unsafe" }).success, false);
  assert.equal(XrayTaskResultSchema.safeParse({
    ...validPortProbeResult(),
    result: { ...(validPortProbeResult() as any).result, configJson: "secret-config" },
  }).success, false);
});

test("bounds raw forward-compatible control payloads before unknown fields are stripped", () => {
  const observed = readExample("observed-state.v1.json") as any;
  assert.equal(XrayTaskSchema.safeParse({
    ...validPortProbeTask(),
    futureField: "x".repeat(XRAY_LIMITS.maxControlPayloadBytes),
  }).success, false);
  assert.equal(XrayObservedReportSchema.safeParse({
    ...observed,
    futureField: "x".repeat(XRAY_LIMITS.maxControlPayloadBytes),
  }).success, false);
});

test("parses typed task results and enforces error and total payload limits", () => {
  assert.equal(XrayTaskResultSchema.safeParse(validPortProbeResult()).success, true);
  assert.equal(XrayTaskResultSchema.safeParse({
    ...validPortProbeResult(),
    status: "FAILED",
    result: null,
    error: { code: "PORT_IN_USE", message: "port became busy", retryable: true },
  }).success, true);
  assert.equal(XrayTaskResultSchema.safeParse({
    ...validPortProbeResult(),
    status: "FAILED",
    result: null,
    error: { code: "PORT_IN_USE", message: "x".repeat(XRAY_LIMITS.maxErrorMessageBytes + 1), retryable: true },
  }).success, false);
  assert.equal(XrayTaskResultSchema.safeParse({
    ...validPortProbeResult(),
    futureField: "x".repeat(XRAY_LIMITS.maxTaskResultBytes),
  }).success, false);
  assert.ok(XRAY_AGENT_ERROR_CODES.includes("GENERATION_HASH_CONFLICT"));
  assert.ok(XRAY_AGENT_ERROR_CODES.includes("ROLLBACK_FAILED"));
});

test("defines typed success results for scan, install, upgrade, and restart", () => {
  const base = {
    schemaVersion: 1,
    taskId: "task-result-1",
    status: "SUCCESS",
    startedAt: "2026-09-01T08:00:01Z",
    finishedAt: "2026-09-01T08:00:02Z",
    error: null,
  };
  const fixtures = [
    {
      ...base,
      type: "REALITY_SCAN",
      result: {
        results: [{
          target: "www.microsoft.com:443",
          host: "www.microsoft.com",
          resolvedIp: "203.0.113.10",
          port: 443,
          feasible: true,
          tls13: true,
          h2: true,
          x25519: true,
          certificateValid: true,
          serverNames: ["www.microsoft.com"],
          latencyMs: 83,
          reasonCode: null,
        }],
        observedAt: "2026-09-01T08:00:02Z",
      },
    },
    {
      ...base,
      type: "INSTALL",
      result: { installedVersion: "v26.3.27", binarySha256: "a".repeat(64), reused: false },
    },
    {
      ...base,
      type: "UPGRADE",
      result: {
        previousVersion: "v26.7.27",
        installedVersion: "v26.3.27",
        binarySha256: "b".repeat(64),
        rolledBack: false,
      },
    },
    {
      ...base,
      type: "RESTART",
      result: {
        previousVersion: "v26.3.27",
        runningVersion: "v26.3.27",
        serviceStatus: "RUNNING",
        readyListenerCount: 2,
      },
    },
  ];

  assert.deepEqual(fixtures.map((fixture) => XrayTaskResultSchema.parse(fixture).type), [
    "REALITY_SCAN",
    "INSTALL",
    "UPGRADE",
    "RESTART",
  ]);
  assert.equal(XrayTaskResultSchema.safeParse({
    ...fixtures[1],
    type: "RESTART",
  }).success, false);
});

test("requires port probe availability and error codes to agree", () => {
  const result = validPortProbeResult() as any;
  assert.equal(XrayTaskResultSchema.safeParse({
    ...result,
    result: { ...result.result, ports: [{ port: 23456, available: false, errorCode: null }] },
  }).success, false);
  assert.equal(XrayTaskResultSchema.safeParse({
    ...result,
    result: { ...result.result, ports: [{ port: 23456, available: true, errorCode: "PORT_IN_USE" }] },
  }).success, false);
});
