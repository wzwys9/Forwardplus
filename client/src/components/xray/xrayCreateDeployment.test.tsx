import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";

import { XrayRealityClientSteps } from "./XrayRealityClientSteps";
import { XrayProfileSteps } from "./XrayProfileSteps";
import {
  buildXrayInboundCreateRequest,
  buildXrayInboundCreateV2Request,
  initialXrayDeploymentState,
  operationFailureNextStep,
  reduceXrayDeploymentState,
  validInitialClients,
  type XrayRealityCandidate,
} from "./xrayCreateDeployment";
import { initialXrayCreateState, reduceXrayCreateState } from "./xrayCreateFlow";

const feasible: XrayRealityCandidate = {
  target: "www.microsoft.com:443", host: "www.microsoft.com", resolvedIp: "1.1.1.1", port: 443,
  feasible: true, tls13: true, h2: true, x25519: true, certificateValid: true,
  serverNames: ["www.microsoft.com"], latencyMs: 18, reasonCode: null,
};
const unsafe: XrayRealityCandidate = {
  ...feasible, target: "blocked.example.com:443", host: "blocked.example.com", resolvedIp: "redacted",
  feasible: false, serverNames: [], reasonCode: "REALITY_TARGET_BLOCKED",
};

test("only feasible Reality results are selectable and all diagnostics stay visible", () => {
  let state = reduceXrayDeploymentState(initialXrayDeploymentState(), { type: "ENTER_REALITY" });
  state = reduceXrayDeploymentState(state, { type: "SCAN_SUCCESS", results: [feasible, unsafe] });
  assert.equal(reduceXrayDeploymentState(state, { type: "SELECT_REALITY", candidate: unsafe }).selectedReality, null);
  state = reduceXrayDeploymentState(state, { type: "SELECT_REALITY", candidate: feasible });
  assert.equal(state.selectedReality?.target, feasible.target);
  const markup = renderToStaticMarkup(<XrayRealityClientSteps state={state} onAction={() => undefined} onScan={() => undefined} onSubmit={() => undefined} submitting={false} canSubmit={true} />);
  for (const text of ["TLS 1.3", "H2", "X25519", "证书有效", "18 ms", "REALITY_TARGET_BLOCKED"]) assert.match(markup, new RegExp(text));
  assert.doesNotMatch(markup, /私钥|privateKey/i);
});

test("initial clients are bounded, unique, and projected without browser credentials", () => {
  let deployment = reduceXrayDeploymentState(initialXrayDeploymentState(), { type: "ENTER_REALITY" });
  deployment = reduceXrayDeploymentState(deployment, { type: "SCAN_SUCCESS", results: [feasible] });
  deployment = reduceXrayDeploymentState(deployment, { type: "SELECT_REALITY", candidate: feasible });
  deployment = reduceXrayDeploymentState(deployment, { type: "GO_CLIENTS" });
  deployment = reduceXrayDeploymentState(deployment, { type: "SET_CLIENT_NAME", key: 1, value: "Alice" });
  deployment = reduceXrayDeploymentState(deployment, { type: "ADD_CLIENT" });
  deployment = reduceXrayDeploymentState(deployment, { type: "SET_CLIENT_NAME", key: 2, value: "Bob" });
  assert.equal(validInitialClients(deployment.clients), true);

  let setup = reduceXrayCreateState(initialXrayCreateState(), { type: "SELECT_HOST", host: { id: 7, name: "edge", publicIpv4: "8.8.8.8", isOnline: true, canCreateXrayInbound: true, unavailableReasonCode: null, os: "linux", arch: "amd64" } });
  setup = reduceXrayCreateState(setup, { type: "SET_NAME", value: "香港 Reality" });
  setup = reduceXrayCreateState(setup, { type: "PROBE_QUEUED", operationId: "probe-1" });
  setup = reduceXrayCreateState(setup, { type: "PROBE_RESERVED", selectedPort: 24443, reservationId: "reservation-1", expiresAt: "2026-09-01T00:10:00Z" });
  const request = buildXrayInboundCreateRequest(setup, deployment, Date.parse("2026-09-01T00:05:00Z"));
  assert.deepEqual(request.initialClients, [
    { name: "Alice", flow: "xtls-rprx-vision" }, { name: "Bob", flow: "xtls-rprx-vision" },
  ]);
  const serialized = JSON.stringify(request);
  for (const forbidden of ["uuid", "shortId", "privateKey", "statsKey"]) assert.equal(serialized.includes(forbidden), false);

  const grpcRequest = buildXrayInboundCreateV2Request(
    setup,
    deployment,
    { profileId: "VLESS_GRPC_REALITY", serviceName: "forwardx-grpc" },
    Date.parse("2026-09-01T00:05:00Z"),
  );
  assert.equal(grpcRequest.profileId, "VLESS_GRPC_REALITY");
  assert.deepEqual(grpcRequest.spec, { serviceName: "forwardx-grpc" });
  assert.deepEqual(grpcRequest.initialAccessEntries, [{ name: "Alice" }, { name: "Bob" }]);
  assert.equal(JSON.stringify(grpcRequest).includes("flow"), false);

  const xhttpRequest = buildXrayInboundCreateV2Request(
    setup,
    deployment,
    { profileId: "VLESS_XHTTP_REALITY", path: "/forwardx/xhttp-v1" },
    Date.parse("2026-09-01T00:05:00Z"),
  );
  assert.equal(xhttpRequest.profileId, "VLESS_XHTTP_REALITY");
  assert.deepEqual(xhttpRequest.spec, { path: "/forwardx/xhttp-v1" });
  assert.deepEqual(xhttpRequest.initialAccessEntries, [{ name: "Alice" }, { name: "Bob" }]);
  assert.equal(JSON.stringify(xhttpRequest).includes("flow"), false);
  const trojanRequest = buildXrayInboundCreateV2Request(
    setup,
    deployment,
    { profileId: "TROJAN_RAW_REALITY" },
    Date.parse("2026-09-01T00:05:00Z"),
  );
  assert.equal(trojanRequest.profileId, "TROJAN_RAW_REALITY");
  assert.deepEqual(trojanRequest.spec, {});
  assert.deepEqual(trojanRequest.initialAccessEntries, [{ name: "Alice" }, { name: "Bob" }]);
  for (const forbidden of ["password", "uuid", "shortId", "flow"]) {
    assert.equal(JSON.stringify(trojanRequest).includes(forbidden), false);
  }
  assert.throws(() => buildXrayInboundCreateV2Request(
    setup,
    deployment,
    { profileId: "VLESS_XHTTP_REALITY", path: "/bad?query" },
    Date.parse("2026-09-01T00:05:00Z"),
  ));
});

test("duplicate or empty client names block confirmation without discarding rows", () => {
  let state = initialXrayDeploymentState();
  state = reduceXrayDeploymentState(state, { type: "SET_CLIENT_NAME", key: 1, value: "Alice" });
  state = reduceXrayDeploymentState(state, { type: "ADD_CLIENT" });
  state = reduceXrayDeploymentState(state, { type: "SET_CLIENT_NAME", key: 2, value: "alice" });
  assert.equal(validInitialClients(state.clients), false);
  assert.equal(reduceXrayDeploymentState(state, { type: "GO_CONFIRM" }).stage, state.stage);
  assert.deepEqual(state.clients.map((client) => client.name), ["Alice", "alice"]);
});

test("operation failures provide a safe actionable next step", () => {
  assert.match(operationFailureNextStep("HOST_OFFLINE"), /不要据此判断 Xray 已停止/);
  assert.match(operationFailureNextStep("CONFIG_INVALID"), /generation\/hash/);
  assert.match(operationFailureNextStep("RUNTIME_NOT_READY"), /监听器/);
});

test("TLS and Shadowsocks requests use only strict profile-derived fields", () => {
  let setup = reduceXrayCreateState(initialXrayCreateState(), { type: "SELECT_HOST", host: {
    id: 7, name: "edge", publicIpv4: "8.8.8.8", isOnline: true, canCreateXrayInbound: true,
    unavailableReasonCode: null, os: "linux", arch: "amd64",
  } });
  setup = reduceXrayCreateState(setup, { type: "SET_NAME", value: "TLS edge" });
  setup = reduceXrayCreateState(setup, { type: "PROBE_QUEUED", operationId: "probe-tls" });
  setup = reduceXrayCreateState(setup, {
    type: "PROBE_RESERVED", selectedPort: 24444, reservationId: "reservation-tls", expiresAt: "2026-09-01T00:10:00Z",
  });
  let deployment = initialXrayDeploymentState();
  deployment = reduceXrayDeploymentState(deployment, { type: "SET_CLIENT_NAME", key: 1, value: "phone" });
  deployment = reduceXrayDeploymentState(deployment, { type: "SELECT_TLS_CERTIFICATE", certificateId: 12 });
  deployment = reduceXrayDeploymentState(deployment, { type: "SET_TLS_SERVER_NAME", value: "TLS.EXAMPLE.COM" });

  for (const profileId of ["VLESS_RAW_TLS", "VLESS_RAW_TLS_VISION", "TROJAN_RAW_TLS", "VMESS_RAW_TLS"] as const) {
    const request = buildXrayInboundCreateV2Request(
      setup,
      deployment,
      { profileId, tlsCertificateId: 12, serverName: "TLS.EXAMPLE.COM" },
      Date.parse("2026-09-01T00:05:00Z"),
    );
    assert.deepEqual(request, {
      hostId: 7,
      name: "TLS edge",
      publicAddress: "8.8.8.8",
      portReservationId: "reservation-tls",
      listenPort: 24444,
      profileId,
      spec: {},
      tlsCertificateId: 12,
      serverName: "tls.example.com",
      initialAccessEntries: [{ name: "phone" }],
    });
    for (const forbidden of ["reality", "uuid", "shortId", "privateKey", "flow", "certificatePem", "allowInsecure"]) {
      assert.equal(JSON.stringify(request).toLowerCase().includes(forbidden.toLowerCase()), false, forbidden);
    }
  }
  for (const profileId of ["VLESS_MKCP_TLS", "TROJAN_MKCP_TLS", "HYSTERIA2_TLS"] as const) {
    const request = buildXrayInboundCreateV2Request(
      setup,
      deployment,
      { profileId, tlsCertificateId: 12, serverName: "TLS.EXAMPLE.COM" },
      Date.parse("2026-09-01T00:05:00Z"),
    );
    assert.deepEqual(request.spec, {});
    assert.equal("serverName" in request ? request.serverName : null, "tls.example.com");
    assert.deepEqual(request.initialAccessEntries, [{ name: "phone" }]);
    for (const forbidden of ["reality", "seed", "header", "mtu", "tti", "uplinkCapacity", "downlinkCapacity", "congestion", "bandwidth", "obfs", "masquerade", "auth", "allowInsecure"]) {
      assert.equal(JSON.stringify(request).toLowerCase().includes(forbidden.toLowerCase()), false, forbidden);
    }
  }
  for (const profileId of ["VLESS_WEBSOCKET_TLS", "TROJAN_WEBSOCKET_TLS"] as const) {
    const request = buildXrayInboundCreateV2Request(
      setup,
      deployment,
      { profileId, path: "/forwardx/ws-v1", tlsCertificateId: 12, serverName: "TLS.EXAMPLE.COM" },
      Date.parse("2026-09-01T00:05:00Z"),
    );
    assert.deepEqual(request, {
      hostId: 7,
      name: "TLS edge",
      publicAddress: "8.8.8.8",
      portReservationId: "reservation-tls",
      listenPort: 24444,
      profileId,
      spec: { path: "/forwardx/ws-v1" },
      tlsCertificateId: 12,
      serverName: "tls.example.com",
      initialAccessEntries: [{ name: "phone" }],
    });
  }
  for (const profileId of ["VLESS_HTTP_UPGRADE_TLS", "TROJAN_HTTP_UPGRADE_TLS"] as const) {
    const request = buildXrayInboundCreateV2Request(
      setup,
      deployment,
      { profileId, path: "/forwardx/httpupgrade-v1", tlsCertificateId: 12, serverName: "TLS.EXAMPLE.COM" },
      Date.parse("2026-09-01T00:05:00Z"),
    );
    assert.deepEqual(request, {
      hostId: 7,
      name: "TLS edge",
      publicAddress: "8.8.8.8",
      portReservationId: "reservation-tls",
      listenPort: 24444,
      profileId,
      spec: { path: "/forwardx/httpupgrade-v1" },
      tlsCertificateId: 12,
      serverName: "tls.example.com",
      initialAccessEntries: [{ name: "phone" }],
    });
  }
  for (const profileId of ["VLESS_XHTTP_TLS", "TROJAN_XHTTP_TLS"] as const) {
    const request = buildXrayInboundCreateV2Request(
      setup,
      deployment,
      { profileId, path: "/forwardx/xhttp-v1", tlsCertificateId: 12, serverName: "TLS.EXAMPLE.COM" },
      Date.parse("2026-09-01T00:05:00Z"),
    );
    assert.deepEqual(request, {
      hostId: 7,
      name: "TLS edge",
      publicAddress: "8.8.8.8",
      portReservationId: "reservation-tls",
      listenPort: 24444,
      profileId,
      spec: { path: "/forwardx/xhttp-v1" },
      tlsCertificateId: 12,
      serverName: "tls.example.com",
      initialAccessEntries: [{ name: "phone" }],
    });
  }
  for (const profileId of ["VLESS_GRPC_TLS", "TROJAN_GRPC_TLS"] as const) {
    const request = buildXrayInboundCreateV2Request(
      setup,
      deployment,
      { profileId, serviceName: " forwardx.grpc-v1 ", tlsCertificateId: 12, serverName: "TLS.EXAMPLE.COM" },
      Date.parse("2026-09-01T00:05:00Z"),
    );
    assert.deepEqual(request, {
      hostId: 7,
      name: "TLS edge",
      publicAddress: "8.8.8.8",
      portReservationId: "reservation-tls",
      listenPort: 24444,
      profileId,
      spec: { serviceName: "forwardx.grpc-v1" },
      tlsCertificateId: 12,
      serverName: "tls.example.com",
      initialAccessEntries: [{ name: "phone" }],
    });
  }
  const shadowsocksRequest = buildXrayInboundCreateV2Request(
    setup,
    deployment,
    { profileId: "SHADOWSOCKS_2022_RAW_NONE" },
    Date.parse("2026-09-01T00:05:00Z"),
  );
  assert.deepEqual(shadowsocksRequest, {
    hostId: 7,
    name: "TLS edge",
    publicAddress: "8.8.8.8",
    portReservationId: "reservation-tls",
    listenPort: 24444,
    profileId: "SHADOWSOCKS_2022_RAW_NONE",
    spec: {},
    initialAccessEntries: [{ name: "phone" }],
  });
  for (const forbidden of ["reality", "tlsCertificateId", "serverName", "password", "key", "method"]) {
    assert.equal(JSON.stringify(shadowsocksRequest).includes(forbidden), false, forbidden);
  }
  assert.throws(() => buildXrayInboundCreateV2Request(
    setup,
    deployment,
    { profileId: "VLESS_RAW_TLS", tlsCertificateId: 12, serverName: "127.0.0.1" },
    Date.parse("2026-09-01T00:05:00Z"),
  ));
  assert.deepEqual(reduceXrayDeploymentState(deployment, { type: "RESET" }), initialXrayDeploymentState());
});

test("Shadowsocks TCP plus UDP create request requires two live same-port reservations", () => {
  let setup = reduceXrayCreateState(initialXrayCreateState(), { type: "SELECT_HOST", host: {
    id: 7, name: "edge", publicIpv4: "8.8.8.8", isOnline: true, canCreateXrayInbound: true,
    unavailableReasonCode: null, os: "linux", arch: "amd64",
  } });
  setup = reduceXrayCreateState(setup, { type: "SET_NAME", value: "SS dual" });
  setup = reduceXrayCreateState(setup, { type: "PROBE_QUEUED", operationId: "probe-tcp" });
  setup = reduceXrayCreateState(setup, {
    type: "PROBE_RESERVED", selectedPort: 24443, reservationId: "reservation-tcp", expiresAt: "2026-09-01T00:10:00Z",
  });
  setup = reduceXrayCreateState(setup, { type: "PROBE_QUEUED", slot: "SECONDARY", operationId: "probe-udp" });
  setup = reduceXrayCreateState(setup, {
    type: "PROBE_RESERVED", slot: "SECONDARY", selectedPort: 24443, reservationId: "reservation-udp", expiresAt: "2026-09-01T00:09:00Z",
  });
  let deployment = initialXrayDeploymentState();
  deployment = reduceXrayDeploymentState(deployment, { type: "SET_CLIENT_NAME", key: 1, value: "phone" });

  const request = buildXrayInboundCreateV2Request(
    setup,
    deployment,
    { profileId: "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE" },
    Date.parse("2026-09-01T00:05:00Z"),
  );
  assert.deepEqual(request, {
    hostId: 7,
    name: "SS dual",
    publicAddress: "8.8.8.8",
    listenPort: 24443,
    portReservations: { tcp: "reservation-tcp", udp: "reservation-udp" },
    profileId: "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE",
    spec: {},
    initialAccessEntries: [{ name: "phone" }],
  });
  for (const forbidden of ["portReservationId", "password", "key", "method", "network"]) {
    assert.equal(JSON.stringify(request).includes(forbidden), false, forbidden);
  }

  const mismatchedSetup = reduceXrayCreateState(setup, {
    type: "PROBE_RESERVED", slot: "SECONDARY", selectedPort: 24444, reservationId: "reservation-udp", expiresAt: "2026-09-01T00:09:00Z",
  });
  assert.throws(() => buildXrayInboundCreateV2Request(
    mismatchedSetup,
    deployment,
    { profileId: "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE" },
    Date.parse("2026-09-01T00:05:00Z"),
  ), /PORT_RESERVATIONS_MISMATCH/);
  const expiredSetup = reduceXrayCreateState(setup, {
    type: "PROBE_RESERVED", slot: "SECONDARY", selectedPort: 24443, reservationId: "reservation-udp", expiresAt: "2026-09-01T00:04:00Z",
  });
  assert.throws(() => buildXrayInboundCreateV2Request(
    expiredSetup,
    deployment,
    { profileId: "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE" },
    Date.parse("2026-09-01T00:05:00Z"),
  ), /PORT_RESERVATION_EXPIRED/);
});

test("transport options expose only profile-derived fields and catalog advisories", () => {
  const profile = (id: string, security: "REALITY" | "TLS", clientFlow: "NONE" | "XTLS_RPRX_VISION") => ({
    id, protocol: "VLESS" as const, transport: "RAW" as const, security, clientFlow,
    listenerNetworks: ["TCP"] as const, clientCredentialType: security === "TLS" ? "UUID" : "UUID_AND_SHORT_ID",
    shareFormat: "VLESS_URI", testedCoreVersion: "v26.3.27" as const, isAvailable: true, unavailableReasonCode: null,
  });
  const profiles = [
    profile("VLESS_RAW_REALITY_VISION", "REALITY", "XTLS_RPRX_VISION"),
    profile("VLESS_RAW_TLS", "TLS", "NONE"),
    profile("VLESS_RAW_TLS_VISION", "TLS", "XTLS_RPRX_VISION"),
    {
      id: "TROJAN_RAW_TLS", protocol: "TROJAN" as const, transport: "RAW" as const,
      security: "TLS" as const, clientFlow: "NONE" as const, listenerNetworks: ["TCP"] as const,
      clientCredentialType: "PASSWORD" as const, shareFormat: "TROJAN_URI",
      testedCoreVersion: "v26.3.27" as const, isAvailable: true, unavailableReasonCode: null,
    },
    {
      id: "VMESS_RAW_TLS", protocol: "VMESS" as const, transport: "RAW" as const,
      security: "TLS" as const, clientFlow: "NONE" as const, listenerNetworks: ["TCP"] as const,
      clientCredentialType: "UUID" as const, shareFormat: "VMESS_URI",
      testedCoreVersion: "v26.3.27" as const, advisoryCode: "CORE_DEPRECATED" as const,
      isAvailable: true, unavailableReasonCode: null,
    },
    {
      id: "SHADOWSOCKS_2022_RAW_NONE", protocol: "SHADOWSOCKS" as const, transport: "RAW" as const,
      security: "NONE" as const, clientFlow: "NONE" as const, listenerNetworks: ["TCP"] as const,
      clientCredentialType: "SHADOWSOCKS_KEY" as const, shareFormat: "SHADOWSOCKS_URI",
      testedCoreVersion: "v26.3.27" as const, advisoryCode: "CORE_DEPRECATED" as const,
      isAvailable: true, unavailableReasonCode: null,
    },
    {
      id: "VLESS_WEBSOCKET_TLS", protocol: "VLESS" as const, transport: "WEBSOCKET" as const,
      security: "TLS" as const, clientFlow: "NONE" as const, listenerNetworks: ["TCP"] as const,
      clientCredentialType: "UUID" as const, shareFormat: "VLESS_URI",
      testedCoreVersion: "v26.3.27" as const, isAvailable: true, unavailableReasonCode: null,
    },
    {
      id: "TROJAN_WEBSOCKET_TLS", protocol: "TROJAN" as const, transport: "WEBSOCKET" as const,
      security: "TLS" as const, clientFlow: "NONE" as const, listenerNetworks: ["TCP"] as const,
      clientCredentialType: "PASSWORD" as const, shareFormat: "TROJAN_URI",
      testedCoreVersion: "v26.3.27" as const, isAvailable: true, unavailableReasonCode: null,
    },
    {
      id: "VLESS_GRPC_TLS", protocol: "VLESS" as const, transport: "GRPC" as const,
      security: "TLS" as const, clientFlow: "NONE" as const, listenerNetworks: ["TCP"] as const,
      clientCredentialType: "UUID" as const, shareFormat: "VLESS_URI",
      testedCoreVersion: "v26.3.27" as const, isAvailable: true, unavailableReasonCode: null,
    },
    {
      id: "TROJAN_GRPC_TLS", protocol: "TROJAN" as const, transport: "GRPC" as const,
      security: "TLS" as const, clientFlow: "NONE" as const, listenerNetworks: ["TCP"] as const,
      clientCredentialType: "PASSWORD" as const, shareFormat: "TROJAN_URI",
      testedCoreVersion: "v26.3.27" as const, isAvailable: true, unavailableReasonCode: null,
    },
    {
      id: "VLESS_HTTP_UPGRADE_TLS", protocol: "VLESS" as const, transport: "HTTP_UPGRADE" as const,
      security: "TLS" as const, clientFlow: "NONE" as const, listenerNetworks: ["TCP"] as const,
      clientCredentialType: "UUID" as const, shareFormat: "VLESS_URI",
      testedCoreVersion: "v26.3.27" as const, isAvailable: true, unavailableReasonCode: null,
    },
    {
      id: "TROJAN_HTTP_UPGRADE_TLS", protocol: "TROJAN" as const, transport: "HTTP_UPGRADE" as const,
      security: "TLS" as const, clientFlow: "NONE" as const, listenerNetworks: ["TCP"] as const,
      clientCredentialType: "PASSWORD" as const, shareFormat: "TROJAN_URI",
      testedCoreVersion: "v26.3.27" as const, isAvailable: true, unavailableReasonCode: null,
    },
    {
      id: "VLESS_XHTTP_TLS", protocol: "VLESS" as const, transport: "XHTTP" as const,
      security: "TLS" as const, clientFlow: "NONE" as const, listenerNetworks: ["TCP"] as const,
      clientCredentialType: "UUID" as const, shareFormat: "VLESS_URI",
      testedCoreVersion: "v26.3.27" as const, isAvailable: true, unavailableReasonCode: null,
    },
    {
      id: "TROJAN_XHTTP_TLS", protocol: "TROJAN" as const, transport: "XHTTP" as const,
      security: "TLS" as const, clientFlow: "NONE" as const, listenerNetworks: ["TCP"] as const,
      clientCredentialType: "PASSWORD" as const, shareFormat: "TROJAN_URI",
      testedCoreVersion: "v26.3.27" as const, isAvailable: true, unavailableReasonCode: null,
    },
    {
      id: "HYSTERIA2_TLS", protocol: "HYSTERIA2" as const, transport: "HYSTERIA" as const,
      security: "TLS" as const, clientFlow: "NONE" as const, listenerNetworks: ["UDP"] as const,
      clientCredentialType: "HYSTERIA_AUTH" as const, shareFormat: "HYSTERIA2_URI",
      testedCoreVersion: "v26.3.27" as const, isAvailable: true, unavailableReasonCode: null,
    },
  ];
  const markup = renderToStaticMarkup(<XrayProfileSteps
    section="TRANSPORT"
    profiles={profiles}
    profilesLoading={false}
    profilesError={false}
    selectedProfileId="VLESS_RAW_TLS"
    grpcServiceName=""
    xhttpPath=""
    onSelectProfile={() => undefined}
    onGrpcServiceNameChange={() => undefined}
    onXhttpPathChange={() => undefined}
    onRetry={() => undefined}
    onBack={() => undefined}
    onNext={() => undefined}
  />);
  for (const label of ["安全与 Flow", "Reality · Vision", "TLS · 标准", "TLS · Vision"]) assert.match(markup, new RegExp(label));
  const trojanMarkup = renderToStaticMarkup(<XrayProfileSteps
    section="TRANSPORT"
    profiles={profiles}
    profilesLoading={false}
    profilesError={false}
    selectedProfileId="TROJAN_RAW_TLS"
    grpcServiceName=""
    xhttpPath=""
    onSelectProfile={() => undefined}
    onGrpcServiceNameChange={() => undefined}
    onXhttpPathChange={() => undefined}
    onRetry={() => undefined}
    onBack={() => undefined}
    onNext={() => undefined}
  />);
  assert.match(trojanMarkup, /TROJAN · RAW \/ TCP · TLS · 无 Flow/);
  assert.doesNotMatch(trojanMarkup, /Vision|shortId/);
  const vmessProtocolMarkup = renderToStaticMarkup(<XrayProfileSteps
    section="PROTOCOL"
    profiles={profiles}
    profilesLoading={false}
    profilesError={false}
    selectedProfileId="VMESS_RAW_TLS"
    grpcServiceName=""
    xhttpPath=""
    onSelectProfile={() => undefined}
    onGrpcServiceNameChange={() => undefined}
    onXhttpPathChange={() => undefined}
    onRetry={() => undefined}
    onBack={() => undefined}
    onNext={() => undefined}
  />);
  assert.match(vmessProtocolMarkup, /兼容协议，固定 Xray 核心已标记 deprecated；新节点优先使用 VLESS\/Trojan/);
  const vmessTransportMarkup = renderToStaticMarkup(<XrayProfileSteps
    section="TRANSPORT"
    profiles={profiles}
    profilesLoading={false}
    profilesError={false}
    selectedProfileId="VMESS_RAW_TLS"
    grpcServiceName=""
    xhttpPath=""
    onSelectProfile={() => undefined}
    onGrpcServiceNameChange={() => undefined}
    onXhttpPathChange={() => undefined}
    onRetry={() => undefined}
    onBack={() => undefined}
    onNext={() => undefined}
  />);
  assert.match(vmessTransportMarkup, /兼容协议，固定 Xray 核心已标记 deprecated/);
  assert.doesNotMatch(vmessTransportMarkup, /alterId|aid|Vision/);
  const vmessConfirmMarkup = renderToStaticMarkup(<XrayRealityClientSteps
    state={{ ...initialXrayDeploymentState(), stage: "CONFIRM" }}
    onAction={() => undefined}
    onScan={() => undefined}
    onSubmit={() => undefined}
    submitting={false}
    canSubmit={true}
    summary={{
      hostName: "edge",
      nodeName: "VMess TLS",
      endpoint: "203.0.113.10:24444",
      currentVersion: "v26.3.27",
      targetVersion: "v26.3.27",
      willInstall: false,
      protocolLabel: "VMess · RAW · TLS · AEAD AUTO",
      advisoryLabel: "兼容协议，固定 Xray 核心已标记 deprecated；新节点优先使用 VLESS/Trojan",
    }}
  />);
  assert.match(vmessConfirmMarkup, /VMess · RAW · TLS · AEAD AUTO/);
  assert.match(vmessConfirmMarkup, /兼容协议，固定 Xray 核心已标记 deprecated/);
  const shadowsocksSecurityMarkup = renderToStaticMarkup(<XrayRealityClientSteps
    state={{ ...initialXrayDeploymentState(), stage: "REALITY" }}
    security="NONE"
    onAction={() => undefined}
    onScan={() => undefined}
    onSubmit={() => undefined}
    submitting={false}
    canSubmit={true}
  />);
  for (const text of ["协议层加密（无 TLS/Reality）", "2022-blake3-aes-256-gcm", "服务端自动生成"] ) {
    assert.match(shadowsocksSecurityMarkup, new RegExp(text));
  }
  assert.doesNotMatch(shadowsocksSecurityMarkup, /密钥输入|密码输入|Reality 目标扫描|TLS 证书与 SNI/);
  const webSocketMarkup = renderToStaticMarkup(<XrayProfileSteps
    section="TRANSPORT"
    profiles={profiles}
    profilesLoading={false}
    profilesError={false}
    selectedProfileId="VLESS_WEBSOCKET_TLS"
    grpcServiceName=""
    xhttpPath="/forwardx/ws-v1"
    onSelectProfile={() => undefined}
    onGrpcServiceNameChange={() => undefined}
    onXhttpPathChange={() => undefined}
    onRetry={() => undefined}
    onBack={() => undefined}
    onNext={() => undefined}
  />);
  assert.match(webSocketMarkup, /WebSocket 路径/);
  assert.match(webSocketMarkup, /\/forwardx\/ws-v1/);
  assert.doesNotMatch(webSocketMarkup, /Vision|Host|headers|early data/);
  const grpcTlsMarkup = renderToStaticMarkup(<XrayProfileSteps
    section="TRANSPORT"
    profiles={profiles}
    profilesLoading={false}
    profilesError={false}
    selectedProfileId="VLESS_GRPC_TLS"
    grpcServiceName="forwardx.grpc-v1"
    xhttpPath=""
    onSelectProfile={() => undefined}
    onGrpcServiceNameChange={() => undefined}
    onXhttpPathChange={() => undefined}
    onRetry={() => undefined}
    onBack={() => undefined}
    onNext={() => undefined}
  />);
  assert.match(grpcTlsMarkup, /gRPC 服务名/);
  assert.match(grpcTlsMarkup, /forwardx\.grpc-v1/);
  assert.doesNotMatch(grpcTlsMarkup, />Vision<|authority|multiMode/);
  const httpUpgradeMarkup = renderToStaticMarkup(<XrayProfileSteps
    section="TRANSPORT"
    profiles={profiles}
    profilesLoading={false}
    profilesError={false}
    selectedProfileId="VLESS_HTTP_UPGRADE_TLS"
    grpcServiceName=""
    xhttpPath="/forwardx/httpupgrade-v1"
    onSelectProfile={() => undefined}
    onGrpcServiceNameChange={() => undefined}
    onXhttpPathChange={() => undefined}
    onRetry={() => undefined}
    onBack={() => undefined}
    onNext={() => undefined}
  />);
  assert.match(httpUpgradeMarkup, /HTTPUpgrade 路径/);
  assert.match(httpUpgradeMarkup, /\/forwardx\/httpupgrade-v1/);
  assert.doesNotMatch(httpUpgradeMarkup, /Host|headers|acceptProxyProtocol|early data/);
  const xhttpTlsMarkup = renderToStaticMarkup(<XrayProfileSteps
    section="TRANSPORT"
    profiles={profiles}
    profilesLoading={false}
    profilesError={false}
    selectedProfileId="TROJAN_XHTTP_TLS"
    grpcServiceName=""
    xhttpPath="/forwardx/xhttp-v1"
    onSelectProfile={() => undefined}
    onGrpcServiceNameChange={() => undefined}
    onXhttpPathChange={() => undefined}
    onRetry={() => undefined}
    onBack={() => undefined}
    onNext={() => undefined}
  />);
  assert.match(xhttpTlsMarkup, /XHTTP 路径/);
  assert.match(xhttpTlsMarkup, /\/forwardx\/xhttp-v1/);
  assert.match(xhttpTlsMarkup, /固定使用 auto 模式/);
  assert.doesNotMatch(xhttpTlsMarkup, /Host|headers|padding|xmux|downloadSettings/);
  const hysteriaMarkup = renderToStaticMarkup(<XrayProfileSteps
    section="TRANSPORT"
    profiles={profiles}
    profilesLoading={false}
    profilesError={false}
    selectedProfileId="HYSTERIA2_TLS"
    grpcServiceName=""
    xhttpPath=""
    onSelectProfile={() => undefined}
    onGrpcServiceNameChange={() => undefined}
    onXhttpPathChange={() => undefined}
    onRetry={() => undefined}
    onBack={() => undefined}
    onNext={() => undefined}
  />);
  for (const text of ["Hysteria 2 · Hysteria · TLS · 无 Flow", "UDP 监听", "版本 2", "ALPN h3", "UDP 空闲 60 秒"]) {
    assert.match(hysteriaMarkup, new RegExp(text));
  }
  assert.doesNotMatch(hysteriaMarkup, /<input|带宽|拥塞|跳端口|masquerade|obfs|FinalMask|ECH|高级 JSON/i);
});

test("TLS security step selects a same-host certificate and never renders secret inputs", () => {
  let state = reduceXrayDeploymentState(initialXrayDeploymentState(), { type: "ENTER_REALITY" });
  state = reduceXrayDeploymentState(state, { type: "SELECT_TLS_CERTIFICATE", certificateId: 12 });
  state = reduceXrayDeploymentState(state, { type: "SET_TLS_SERVER_NAME", value: "tls.example.com" });
  const markup = renderToStaticMarkup(<XrayRealityClientSteps
    state={state}
    security="TLS"
    certificates={[{
      id: 12, name: "Edge TLS", dnsNames: ["tls.example.com"], status: "VALID", privateKeyConfigured: true,
    }]}
    certificatesLoading={false}
    certificatesError={false}
    onRetryCertificates={() => undefined}
    onAction={() => undefined}
    onScan={() => undefined}
    onSubmit={() => undefined}
    submitting={false}
    canSubmit={true}
  />);
  for (const text of ["TLS 证书与 SNI", "Edge TLS", "tls.example.com", "证书 pin"] ) assert.match(markup, new RegExp(text));
  assert.doesNotMatch(markup, /Reality 目标扫描|完整证书链|私钥 PEM|UUID|shortId/i);
});

test("WireGuard create UI keeps UDP and peer credentials server-owned", () => {
  let setup = reduceXrayCreateState(initialXrayCreateState(), {
    type: "SELECT_HOST",
    host: { id: 9, name: "wg-edge", publicIpv4: "8.8.4.4", isOnline: true, canCreateXrayInbound: true, unavailableReasonCode: null, os: "linux", arch: "amd64" },
  });
  setup = reduceXrayCreateState(setup, { type: "SET_NAME", value: "WireGuard UDP" });
  setup = reduceXrayCreateState(setup, { type: "PROBE_QUEUED", operationId: "wg-probe" });
  setup = reduceXrayCreateState(setup, {
    type: "PROBE_RESERVED",
    selectedPort: 29876,
    reservationId: "wg-reservation",
    expiresAt: "2026-09-03T09:10:00Z",
  });
  let deployment = reduceXrayDeploymentState(initialXrayDeploymentState(), {
    type: "SET_CLIENT_NAME", key: 1, value: "phone",
  });
  deployment = reduceXrayDeploymentState(deployment, { type: "GO_CLIENTS_NONE" });
  const request = buildXrayInboundCreateV2Request(
    setup,
    deployment,
    { profileId: "WIREGUARD_UDP_NONE" },
    Date.parse("2026-09-03T09:05:00Z"),
  );
  assert.deepEqual(request, {
    hostId: 9,
    name: "WireGuard UDP",
    publicAddress: "8.8.4.4",
    portReservationId: "wg-reservation",
    listenPort: 29876,
    profileId: "WIREGUARD_UDP_NONE",
    spec: {},
    initialAccessEntries: [{ name: "phone" }],
  });
  for (const forbidden of ["key", "psk", "allowedIPs", "mtu", "dns", "route", "keepAlive"]) {
    assert.equal(JSON.stringify(request).toLowerCase().includes(forbidden.toLowerCase()), false);
  }

  const wireGuardProfile = {
    id: "WIREGUARD_UDP_NONE",
    protocol: "WIREGUARD" as const,
    transport: "NONE" as const,
    security: "NONE" as const,
    clientFlow: "NONE" as const,
    listenerNetworks: ["UDP"] as const,
    clientCredentialType: "WIREGUARD_PEER",
    shareFormat: "WIREGUARD_CONFIG",
    testedCoreVersion: "v26.3.27" as const,
    advisoryCode: "WIREGUARD_BLOCKING_RISK" as const,
    isAvailable: true,
    unavailableReasonCode: null,
  };
  const transportMarkup = renderToStaticMarkup(<XrayProfileSteps
    section="TRANSPORT"
    profiles={[wireGuardProfile]}
    profilesLoading={false}
    profilesError={false}
    selectedProfileId="WIREGUARD_UDP_NONE"
    grpcServiceName=""
    xhttpPath=""
    onSelectProfile={() => undefined}
    onGrpcServiceNameChange={() => undefined}
    onXhttpPathChange={() => undefined}
    onRetry={() => undefined}
    onBack={() => undefined}
    onNext={() => undefined}
  />);
  for (const text of ["Xray 内置 / UDP / 无 TLS", "gVisor · IPv4 · MTU 1420 · 10.0.0.0/24", "WireGuard 外层特征明显，可能被识别或封锁"]) {
    assert.match(transportMarkup, new RegExp(text));
  }
  assert.doesNotMatch(transportMarkup, /kernel TUN|workers|reserved|domain strategy|IPv6|allowedIPs|高级 JSON/);

  const securityMarkup = renderToStaticMarkup(<XrayRealityClientSteps
    state={{ ...deployment, stage: "REALITY" }}
    security="NONE"
    accessKind="WIREGUARD_PEER"
    onAction={() => undefined}
    onScan={() => undefined}
    onSubmit={() => undefined}
    submitting={false}
    canSubmit={true}
  />);
  for (const text of ["WireGuard 固定安全边界", "服务端生成", "不接受密钥、PSK"] ) {
    assert.match(securityMarkup, new RegExp(text));
  }
  const peerMarkup = renderToStaticMarkup(<XrayRealityClientSteps
    state={{ ...deployment, stage: "CLIENTS" }}
    security="NONE"
    accessKind="WIREGUARD_PEER"
    onAction={() => undefined}
    onScan={() => undefined}
    onSubmit={() => undefined}
    submitting={false}
    canSubmit={true}
  />);
  assert.match(peerMarkup, /初始 peer|peer 1 名称|添加 peer/);
  assert.doesNotMatch(peerMarkup, /私钥|公钥|PSK|allowedIPs/);
});

test("Mixed create UI exposes one authenticated TCP listener without browser-owned credentials", () => {
  let setup = reduceXrayCreateState(initialXrayCreateState(), {
    type: "SELECT_HOST",
    host: { id: 11, name: "mixed-edge", publicIpv4: "8.8.8.8", isOnline: true, canCreateXrayInbound: true, unavailableReasonCode: null, os: "linux", arch: "amd64" },
  });
  setup = reduceXrayCreateState(setup, { type: "SET_NAME", value: "Mixed admin" });
  setup = reduceXrayCreateState(setup, { type: "PROBE_QUEUED", operationId: "mixed-probe" });
  setup = reduceXrayCreateState(setup, {
    type: "PROBE_RESERVED",
    selectedPort: 29901,
    reservationId: "mixed-reservation",
    expiresAt: "2026-09-03T09:10:00Z",
  });
  let deployment = reduceXrayDeploymentState(initialXrayDeploymentState(), { type: "SET_CLIENT_NAME", key: 1, value: "operator" });
  deployment = reduceXrayDeploymentState(deployment, { type: "GO_CLIENTS_NONE" });
  const request = buildXrayInboundCreateV2Request(
    setup,
    deployment,
    { profileId: "MIXED_RAW_NONE" },
    Date.parse("2026-09-03T09:05:00Z"),
  );
  assert.deepEqual(request, {
    hostId: 11,
    name: "Mixed admin",
    publicAddress: "8.8.8.8",
    portReservationId: "mixed-reservation",
    listenPort: 29901,
    profileId: "MIXED_RAW_NONE",
    spec: {},
    initialAccessEntries: [{ name: "operator" }],
  });
  for (const forbidden of ["username", "password", "udp", "auth", "configJson"]) {
    assert.equal(JSON.stringify(request).toLowerCase().includes(forbidden.toLowerCase()), false, forbidden);
  }

  const mixedProfile = {
    id: "MIXED_RAW_NONE",
    protocol: "MIXED" as const,
    transport: "RAW" as const,
    security: "NONE" as const,
    clientFlow: "NONE" as const,
    listenerNetworks: ["TCP"] as const,
    clientCredentialType: "MIXED_USER_PASSWORD",
    shareFormat: "MIXED_PROXY_ENDPOINTS",
    testedCoreVersion: "v26.3.27" as const,
    advisoryCode: "PLAINTEXT_MIXED_AUTH_RISK" as const,
    isAvailable: true,
    unavailableReasonCode: null,
  };
  const transportMarkup = renderToStaticMarkup(<XrayProfileSteps
    section="TRANSPORT"
    profiles={[mixedProfile]}
    profilesLoading={false}
    profilesError={false}
    selectedProfileId="MIXED_RAW_NONE"
    grpcServiceName=""
    xhttpPath=""
    onSelectProfile={() => undefined}
    onGrpcServiceNameChange={() => undefined}
    onXhttpPathChange={() => undefined}
    onRetry={() => undefined}
    onBack={() => undefined}
    onNext={() => undefined}
  />);
  for (const text of ["SOCKS5 + HTTP 共用监听", "强制用户名与密码认证", "不支持 SOCKS4/4a 与 UDP", "SOCKS5 用户名/密码和 HTTP Basic 凭据可能被链路观察者读取"]) {
    assert.equal(transportMarkup.includes(text), true, text);
  }
  assert.doesNotMatch(transportMarkup, /<input|任意 JSON 输入框|UDP 开关|认证方式/);

  const securityMarkup = renderToStaticMarkup(<XrayRealityClientSteps
    state={{ ...deployment, stage: "REALITY" }}
    security="NONE"
    accessKind="MIXED_USER_PASSWORD"
    onAction={() => undefined}
    onScan={() => undefined}
    onSubmit={() => undefined}
    submitting={false}
    canSubmit={true}
  />);
  for (const text of ["Mixed 代理固定安全边界", "SOCKS5 + HTTP/CONNECT", "仅 TCP", "不支持 SOCKS4/4a 与 UDP", "两个代理地址"]) {
    assert.equal(securityMarkup.includes(text), true, text);
  }
  assert.doesNotMatch(securityMarkup, /type="password"|受管 TLS 证书|Reality 目标扫描/);

  const accountsMarkup = renderToStaticMarkup(<XrayRealityClientSteps
    state={{ ...deployment, stage: "CLIENTS" }}
    security="NONE"
    accessKind="MIXED_USER_PASSWORD"
    onAction={() => undefined}
    onScan={() => undefined}
    onSubmit={() => undefined}
    submitting={false}
    canSubmit={true}
  />);
  assert.match(accountsMarkup, /账户 1 备注/);
  assert.match(accountsMarkup, /SOCKS5 与 HTTP 共用的用户名和密码由服务端独立生成/);
  assert.doesNotMatch(accountsMarkup, /type="password"|username/i);

});
