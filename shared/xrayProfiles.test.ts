import assert from "node:assert/strict";
import test from "node:test";

import {
  findAvailableXrayProfile,
  findAvailableXrayProfileById,
  findKnownXrayProfile,
  findKnownXrayProfileById,
  listAvailableXrayProfiles,
  resolveStoredXrayInboundDefinition,
  resolveStoredXrayInboundProfile,
  XRAY_INBOUND_SPEC_MAX_BYTES,
} from "./xrayProfiles";

const tcpTlsProfiles = [{
  id: "VLESS_RAW_TLS",
  protocol: "VLESS",
  transport: "RAW",
  clientFlow: "NONE",
  clientCredentialType: "UUID",
  shareFormat: "VLESS_URI",
  storage: { protocol: "vless", transport: "tcp", clientFlow: "" },
}, {
  id: "VLESS_RAW_TLS_VISION",
  protocol: "VLESS",
  transport: "RAW",
  clientFlow: "XTLS_RPRX_VISION",
  clientCredentialType: "UUID",
  shareFormat: "VLESS_URI",
  storage: { protocol: "vless", transport: "tcp", clientFlow: "xtls-rprx-vision" },
}, {
  id: "TROJAN_RAW_TLS",
  protocol: "TROJAN",
  transport: "RAW",
  clientFlow: "NONE",
  clientCredentialType: "PASSWORD",
  shareFormat: "TROJAN_URI",
  storage: { protocol: "trojan", transport: "tcp", clientFlow: "" },
}, {
  id: "VLESS_WEBSOCKET_TLS",
  protocol: "VLESS",
  transport: "WEBSOCKET",
  clientFlow: "NONE",
  clientCredentialType: "UUID",
  shareFormat: "VLESS_URI",
  storage: { protocol: "vless", transport: "ws", clientFlow: "" },
}, {
  id: "TROJAN_WEBSOCKET_TLS",
  protocol: "TROJAN",
  transport: "WEBSOCKET",
  clientFlow: "NONE",
  clientCredentialType: "PASSWORD",
  shareFormat: "TROJAN_URI",
  storage: { protocol: "trojan", transport: "ws", clientFlow: "" },
}, {
  id: "VLESS_GRPC_TLS",
  protocol: "VLESS",
  transport: "GRPC",
  clientFlow: "NONE",
  clientCredentialType: "UUID",
  shareFormat: "VLESS_URI",
  storage: { protocol: "vless", transport: "grpc", clientFlow: "" },
}, {
  id: "TROJAN_GRPC_TLS",
  protocol: "TROJAN",
  transport: "GRPC",
  clientFlow: "NONE",
  clientCredentialType: "PASSWORD",
  shareFormat: "TROJAN_URI",
  storage: { protocol: "trojan", transport: "grpc", clientFlow: "" },
}, {
  id: "VLESS_HTTP_UPGRADE_TLS",
  protocol: "VLESS",
  transport: "HTTP_UPGRADE",
  clientFlow: "NONE",
  clientCredentialType: "UUID",
  shareFormat: "VLESS_URI",
  storage: { protocol: "vless", transport: "httpupgrade", clientFlow: "" },
}, {
  id: "TROJAN_HTTP_UPGRADE_TLS",
  protocol: "TROJAN",
  transport: "HTTP_UPGRADE",
  clientFlow: "NONE",
  clientCredentialType: "PASSWORD",
  shareFormat: "TROJAN_URI",
  storage: { protocol: "trojan", transport: "httpupgrade", clientFlow: "" },
}, {
  id: "VLESS_XHTTP_TLS",
  protocol: "VLESS",
  transport: "XHTTP",
  clientFlow: "NONE",
  clientCredentialType: "UUID",
  shareFormat: "VLESS_URI",
  storage: { protocol: "vless", transport: "xhttp", clientFlow: "" },
}, {
  id: "TROJAN_XHTTP_TLS",
  protocol: "TROJAN",
  transport: "XHTTP",
  clientFlow: "NONE",
  clientCredentialType: "PASSWORD",
  shareFormat: "TROJAN_URI",
  storage: { protocol: "trojan", transport: "xhttp", clientFlow: "" },
}] as const;

test("the fixed-version verified profiles are available", () => {
  const profiles = listAvailableXrayProfiles();

  assert.deepEqual(profiles, [{
    id: "VLESS_RAW_REALITY_VISION",
    status: "AVAILABLE",
    protocol: "VLESS",
    transport: "RAW",
    security: "REALITY",
    clientFlow: "XTLS_RPRX_VISION",
    listenerNetworks: ["TCP"],
    clientCredentialType: "UUID_AND_SHORT_ID",
    shareFormat: "VLESS_URI",
    testedCoreVersion: "v26.3.27",
  }, {
    id: "VLESS_GRPC_REALITY",
    status: "AVAILABLE",
    protocol: "VLESS",
    transport: "GRPC",
    security: "REALITY",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "UUID_AND_SHORT_ID",
    shareFormat: "VLESS_URI",
    testedCoreVersion: "v26.3.27",
  }, {
    id: "VLESS_XHTTP_REALITY",
    status: "AVAILABLE",
    protocol: "VLESS",
    transport: "XHTTP",
    security: "REALITY",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "UUID_AND_SHORT_ID",
    shareFormat: "VLESS_URI",
    testedCoreVersion: "v26.3.27",
  }, {
    id: "TROJAN_RAW_REALITY",
    status: "AVAILABLE",
    protocol: "TROJAN",
    transport: "RAW",
    security: "REALITY",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "PASSWORD",
    shareFormat: "TROJAN_URI",
    testedCoreVersion: "v26.3.27",
  }, {
    id: "VLESS_RAW_TLS",
    status: "AVAILABLE",
    protocol: "VLESS",
    transport: "RAW",
    security: "TLS",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "UUID",
    shareFormat: "VLESS_URI",
    testedCoreVersion: "v26.3.27",
  }, {
    id: "VLESS_RAW_TLS_VISION",
    status: "AVAILABLE",
    protocol: "VLESS",
    transport: "RAW",
    security: "TLS",
    clientFlow: "XTLS_RPRX_VISION",
    listenerNetworks: ["TCP"],
    clientCredentialType: "UUID",
    shareFormat: "VLESS_URI",
    testedCoreVersion: "v26.3.27",
  }, {
    id: "TROJAN_RAW_TLS",
    status: "AVAILABLE",
    protocol: "TROJAN",
    transport: "RAW",
    security: "TLS",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "PASSWORD",
    shareFormat: "TROJAN_URI",
    testedCoreVersion: "v26.3.27",
  }, {
    id: "VLESS_WEBSOCKET_TLS",
    status: "AVAILABLE",
    protocol: "VLESS",
    transport: "WEBSOCKET",
    security: "TLS",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "UUID",
    shareFormat: "VLESS_URI",
    testedCoreVersion: "v26.3.27",
  }, {
    id: "TROJAN_WEBSOCKET_TLS",
    status: "AVAILABLE",
    protocol: "TROJAN",
    transport: "WEBSOCKET",
    security: "TLS",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "PASSWORD",
    shareFormat: "TROJAN_URI",
    testedCoreVersion: "v26.3.27",
  }, {
    id: "VLESS_GRPC_TLS",
    status: "AVAILABLE",
    protocol: "VLESS",
    transport: "GRPC",
    security: "TLS",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "UUID",
    shareFormat: "VLESS_URI",
    testedCoreVersion: "v26.3.27",
  }, {
    id: "TROJAN_GRPC_TLS",
    status: "AVAILABLE",
    protocol: "TROJAN",
    transport: "GRPC",
    security: "TLS",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "PASSWORD",
    shareFormat: "TROJAN_URI",
    testedCoreVersion: "v26.3.27",
  }, {
    id: "VLESS_HTTP_UPGRADE_TLS",
    status: "AVAILABLE",
    protocol: "VLESS",
    transport: "HTTP_UPGRADE",
    security: "TLS",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "UUID",
    shareFormat: "VLESS_URI",
    testedCoreVersion: "v26.3.27",
  }, {
    id: "TROJAN_HTTP_UPGRADE_TLS",
    status: "AVAILABLE",
    protocol: "TROJAN",
    transport: "HTTP_UPGRADE",
    security: "TLS",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "PASSWORD",
    shareFormat: "TROJAN_URI",
    testedCoreVersion: "v26.3.27",
  }, {
    id: "VLESS_XHTTP_TLS",
    status: "AVAILABLE",
    protocol: "VLESS",
    transport: "XHTTP",
    security: "TLS",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "UUID",
    shareFormat: "VLESS_URI",
    testedCoreVersion: "v26.3.27",
  }, {
    id: "TROJAN_XHTTP_TLS",
    status: "AVAILABLE",
    protocol: "TROJAN",
    transport: "XHTTP",
    security: "TLS",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "PASSWORD",
    shareFormat: "TROJAN_URI",
    testedCoreVersion: "v26.3.27",
  }, {
    id: "VLESS_MKCP_TLS",
    status: "AVAILABLE",
    protocol: "VLESS",
    transport: "MKCP",
    security: "TLS",
    clientFlow: "NONE",
    listenerNetworks: ["UDP"],
    clientCredentialType: "UUID",
    shareFormat: "VLESS_URI",
    testedCoreVersion: "v26.3.27",
  }, {
    id: "TROJAN_MKCP_TLS",
    status: "AVAILABLE",
    protocol: "TROJAN",
    transport: "MKCP",
    security: "TLS",
    clientFlow: "NONE",
    listenerNetworks: ["UDP"],
    clientCredentialType: "PASSWORD",
    shareFormat: "TROJAN_URI",
    testedCoreVersion: "v26.3.27",
  }, {
    id: "VMESS_RAW_TLS",
    status: "AVAILABLE",
    protocol: "VMESS",
    transport: "RAW",
    security: "TLS",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "UUID",
    shareFormat: "VMESS_URI",
    testedCoreVersion: "v26.3.27",
    advisoryCode: "CORE_DEPRECATED",
  }, {
    id: "SHADOWSOCKS_2022_RAW_NONE",
    status: "AVAILABLE",
    protocol: "SHADOWSOCKS",
    transport: "RAW",
    security: "NONE",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "SHADOWSOCKS_KEY",
    shareFormat: "SHADOWSOCKS_URI",
    testedCoreVersion: "v26.3.27",
    advisoryCode: "CORE_DEPRECATED",
  }, {
    id: "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE",
    status: "AVAILABLE",
    protocol: "SHADOWSOCKS",
    transport: "RAW",
    security: "NONE",
    clientFlow: "NONE",
    listenerNetworks: ["TCP", "UDP"],
    clientCredentialType: "SHADOWSOCKS_KEY",
    shareFormat: "SHADOWSOCKS_URI",
    testedCoreVersion: "v26.3.27",
    advisoryCode: "CORE_DEPRECATED",
  }, {
    id: "HYSTERIA2_TLS",
    status: "AVAILABLE",
    protocol: "HYSTERIA2",
    transport: "HYSTERIA",
    security: "TLS",
    clientFlow: "NONE",
    listenerNetworks: ["UDP"],
    clientCredentialType: "HYSTERIA_AUTH",
    shareFormat: "HYSTERIA2_URI",
    testedCoreVersion: "v26.3.27",
  }, {
    id: "WIREGUARD_UDP_NONE",
    status: "AVAILABLE",
    protocol: "WIREGUARD",
    transport: "NONE",
    security: "NONE",
    clientFlow: "NONE",
    listenerNetworks: ["UDP"],
    clientCredentialType: "WIREGUARD_PEER",
    shareFormat: "WIREGUARD_CONFIG",
    testedCoreVersion: "v26.3.27",
    advisoryCode: "WIREGUARD_BLOCKING_RISK",
  }, {
    id: "HTTP_RAW_NONE",
    status: "AVAILABLE",
    protocol: "HTTP",
    transport: "RAW",
    security: "NONE",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "HTTP_BASIC",
    shareFormat: "HTTP_PROXY_URI",
    testedCoreVersion: "v26.3.27",
    advisoryCode: "PLAINTEXT_PROXY_AUTH_RISK",
  }, {
    id: "MIXED_RAW_NONE",
    status: "AVAILABLE",
    protocol: "MIXED",
    transport: "RAW",
    security: "NONE",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "MIXED_USER_PASSWORD",
    shareFormat: "MIXED_PROXY_ENDPOINTS",
    testedCoreVersion: "v26.3.27",
    advisoryCode: "PLAINTEXT_MIXED_AUTH_RISK",
  }, {
    id: "TUNNEL_TCP_LOCAL_NONE",
    status: "AVAILABLE",
    protocol: "TUNNEL",
    transport: "NONE",
    security: "NONE",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "NONE",
    shareFormat: "NONE",
    testedCoreVersion: "v26.3.27",
  }]);
});

test("all fixed-version transport profiles are available in stable order", () => {
  for (const expected of tcpTlsProfiles) {
    assert.deepEqual(findKnownXrayProfileById(expected.id), {
      id: expected.id,
      status: "AVAILABLE",
      protocol: expected.protocol,
      transport: expected.transport,
      security: "TLS",
      clientFlow: expected.clientFlow,
      listenerNetworks: ["TCP"],
      clientCredentialType: expected.clientCredentialType,
      shareFormat: expected.shareFormat,
      testedCoreVersion: "v26.3.27",
    });
    assert.equal(findAvailableXrayProfile({
      ...expected.storage,
      security: "tls",
    })?.id ?? null, expected.id);
    assert.equal(findAvailableXrayProfileById(expected.id)?.id ?? null, expected.id);
  }

  assert.deepEqual(listAvailableXrayProfiles().map((profile) => profile.id), [
    "VLESS_RAW_REALITY_VISION",
    "VLESS_GRPC_REALITY",
    "VLESS_XHTTP_REALITY",
    "TROJAN_RAW_REALITY",
    "VLESS_RAW_TLS",
    "VLESS_RAW_TLS_VISION",
    "TROJAN_RAW_TLS",
    "VLESS_WEBSOCKET_TLS",
    "TROJAN_WEBSOCKET_TLS",
    "VLESS_GRPC_TLS",
    "TROJAN_GRPC_TLS",
    "VLESS_HTTP_UPGRADE_TLS",
    "TROJAN_HTTP_UPGRADE_TLS",
    "VLESS_XHTTP_TLS",
    "TROJAN_XHTTP_TLS",
    "VLESS_MKCP_TLS",
    "TROJAN_MKCP_TLS",
    "VMESS_RAW_TLS",
    "SHADOWSOCKS_2022_RAW_NONE",
    "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE",
    "HYSTERIA2_TLS",
    "WIREGUARD_UDP_NONE",
    "HTTP_RAW_NONE",
    "MIXED_RAW_NONE",
    "TUNNEL_TCP_LOCAL_NONE",
  ]);
});

test("Tunnel is available only with the canonical fixed-target spec", () => {
  const stored = {
    protocol: "tunnel",
    transport: "none",
    security: "none",
    profileId: "TUNNEL_TCP_LOCAL_NONE",
    specVersion: 1,
  };
  assert.deepEqual(resolveStoredXrayInboundDefinition({
    ...stored,
    specJson: '{"targetAddress":"db.example.com","targetPort":5432}',
  }), {
    profile: {
      id: "TUNNEL_TCP_LOCAL_NONE",
      status: "AVAILABLE",
      protocol: "TUNNEL",
      transport: "NONE",
      security: "NONE",
      clientFlow: "NONE",
      listenerNetworks: ["TCP"],
      clientCredentialType: "NONE",
      shareFormat: "NONE",
      testedCoreVersion: "v26.3.27",
    },
    specVersion: 1,
    spec: { targetAddress: "db.example.com", targetPort: 5432 },
  });
  for (const specJson of [
    '{"targetAddress":"DB.EXAMPLE.COM","targetPort":5432}',
    '{"targetAddress":"db.example.com","targetPort":0}',
    '{"targetAddress":"db.example.com","targetPort":5432,"followRedirect":true}',
  ]) {
    assert.equal(resolveStoredXrayInboundDefinition({ ...stored, specJson }), null);
  }
});

test("HTTP management proxy is available only as strict authenticated RAW TCP", () => {
  assert.deepEqual(findKnownXrayProfileById("HTTP_RAW_NONE"), {
    id: "HTTP_RAW_NONE",
    status: "AVAILABLE",
    protocol: "HTTP",
    transport: "RAW",
    security: "NONE",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "HTTP_BASIC",
    shareFormat: "HTTP_PROXY_URI",
    testedCoreVersion: "v26.3.27",
    advisoryCode: "PLAINTEXT_PROXY_AUTH_RISK",
  });
  const stored = {
    protocol: "http",
    transport: "tcp",
    security: "none",
    clientFlow: "",
    profileId: "HTTP_RAW_NONE",
    specVersion: 1,
    specJson: "{}",
  };
  assert.deepEqual(resolveStoredXrayInboundDefinition(stored)?.spec, {});
  assert.equal(findAvailableXrayProfileById("HTTP_RAW_NONE")?.id, "HTTP_RAW_NONE");
  assert.equal(findAvailableXrayProfile({
    protocol: "http", transport: "tcp", security: "none", clientFlow: "",
  })?.id, "HTTP_RAW_NONE");
  for (const specJson of ['{"allowTransparent":true}', '{"accounts":[]}', '{"userLevel":1}']) {
    assert.equal(resolveStoredXrayInboundDefinition({ ...stored, specJson }), null);
  }
});

test("Mixed management proxy is available only as its strict authenticated RAW TCP profile", () => {
  assert.deepEqual(findKnownXrayProfileById("MIXED_RAW_NONE"), {
    id: "MIXED_RAW_NONE",
    status: "AVAILABLE",
    protocol: "MIXED",
    transport: "RAW",
    security: "NONE",
    clientFlow: "NONE",
    listenerNetworks: ["TCP"],
    clientCredentialType: "MIXED_USER_PASSWORD",
    shareFormat: "MIXED_PROXY_ENDPOINTS",
    testedCoreVersion: "v26.3.27",
    advisoryCode: "PLAINTEXT_MIXED_AUTH_RISK",
  });
  const stored = {
    protocol: "mixed",
    transport: "tcp",
    security: "none",
    clientFlow: "",
    profileId: "MIXED_RAW_NONE",
    specVersion: 1,
    specJson: "{}",
  };
  assert.deepEqual(resolveStoredXrayInboundDefinition(stored)?.spec, {});
  assert.equal(findAvailableXrayProfileById("MIXED_RAW_NONE")?.id, "MIXED_RAW_NONE");
  assert.equal(findAvailableXrayProfile({
    protocol: "mixed", transport: "tcp", security: "none", clientFlow: "",
  })?.id, "MIXED_RAW_NONE");
  for (const specJson of ['{"udp":true}', '{"auth":"noauth"}', '{"accounts":[]}']) {
    assert.equal(resolveStoredXrayInboundDefinition({ ...stored, specJson }), null);
  }
});

test("VLESS RAW TLS requires flow to disambiguate a storage combination", () => {
  const storage = { protocol: "vless", transport: "tcp", security: "tls" };

  assert.equal(findKnownXrayProfile(storage), null);
  assert.equal(findKnownXrayProfile({ ...storage, clientFlow: "" })?.id, "VLESS_RAW_TLS");
  assert.equal(findKnownXrayProfile({ ...storage, clientFlow: "xtls-rprx-vision" })?.id, "VLESS_RAW_TLS_VISION");

  for (const [profileId, expectedFlow] of [
    ["VLESS_RAW_TLS", "NONE"],
    ["VLESS_RAW_TLS_VISION", "XTLS_RPRX_VISION"],
  ] as const) {
    const resolved = resolveStoredXrayInboundDefinition({
      ...storage,
      profileId,
      specVersion: 1,
      specJson: "{}",
    });
    assert.equal(resolved?.profile.id, profileId);
    assert.equal(resolved?.profile.clientFlow, expectedFlow);
    assert.deepEqual(resolved?.spec, {});
  }
  assert.equal(resolveStoredXrayInboundDefinition({
    ...storage,
    clientFlow: "xtls-rprx-vision",
    profileId: "VLESS_RAW_TLS",
    specVersion: 1,
    specJson: "{}",
  }), null);
});

test("TCP TLS transport specs accept only their approved strict fields", () => {
  const transports = [
    { ids: ["VLESS_RAW_TLS", "VLESS_RAW_TLS_VISION", "TROJAN_RAW_TLS"], storage: "tcp", spec: {} },
    { ids: ["VLESS_WEBSOCKET_TLS", "TROJAN_WEBSOCKET_TLS"], storage: "ws", spec: { path: "/forwardx-ws" } },
    { ids: ["VLESS_GRPC_TLS", "TROJAN_GRPC_TLS"], storage: "grpc", spec: { serviceName: "forwardx.grpc" } },
    { ids: ["VLESS_HTTP_UPGRADE_TLS", "TROJAN_HTTP_UPGRADE_TLS"], storage: "httpupgrade", spec: { path: "/forwardx-upgrade" } },
    { ids: ["VLESS_XHTTP_TLS", "TROJAN_XHTTP_TLS"], storage: "xhttp", spec: { path: "/forwardx-xhttp" } },
  ] as const;

  for (const transport of transports) {
    for (const profileId of transport.ids) {
      const protocol = profileId.startsWith("VLESS_") ? "vless" : "trojan";
      const input = {
        protocol,
        transport: transport.storage,
        security: "tls",
        profileId,
        specVersion: 1,
        specJson: JSON.stringify(transport.spec),
      };
      assert.deepEqual(resolveStoredXrayInboundDefinition(input)?.spec, transport.spec);
      assert.equal(resolveStoredXrayInboundDefinition({ ...input, specJson: JSON.stringify({ ...transport.spec, extra: true }) }), null);
    }
  }

  for (const [profileId, protocol, transport, specJson] of [
    ["VLESS_WEBSOCKET_TLS", "vless", "ws", '{"path":"relative"}'],
    ["TROJAN_HTTP_UPGRADE_TLS", "trojan", "httpupgrade", '{"path":"/bad?query"}'],
    ["VLESS_XHTTP_TLS", "vless", "xhttp", `{"path":"/${"a".repeat(128)}"}`],
    ["TROJAN_GRPC_TLS", "trojan", "grpc", '{"serviceName":"bad/name"}'],
  ] as const) {
    assert.equal(resolveStoredXrayInboundDefinition({
      protocol,
      transport,
      security: "tls",
      profileId,
      specVersion: 1,
      specJson,
    }), null);
  }
});

test("mKCP TLS profiles are available with UDP listeners and strict empty specs", () => {
  const cases = [{
    id: "VLESS_MKCP_TLS",
    protocol: "VLESS",
    clientCredentialType: "UUID",
    shareFormat: "VLESS_URI",
    storageProtocol: "vless",
  }, {
    id: "TROJAN_MKCP_TLS",
    protocol: "TROJAN",
    clientCredentialType: "PASSWORD",
    shareFormat: "TROJAN_URI",
    storageProtocol: "trojan",
  }] as const;

  for (const expected of cases) {
    assert.deepEqual(findKnownXrayProfileById(expected.id), {
      id: expected.id,
      status: "AVAILABLE",
      protocol: expected.protocol,
      transport: "MKCP",
      security: "TLS",
      clientFlow: "NONE",
      listenerNetworks: ["UDP"],
      clientCredentialType: expected.clientCredentialType,
      shareFormat: expected.shareFormat,
      testedCoreVersion: "v26.3.27",
    });
    assert.equal(findAvailableXrayProfileById(expected.id)?.id, expected.id);
    assert.equal(findAvailableXrayProfile({
      protocol: expected.storageProtocol,
      transport: "kcp",
      security: "tls",
      clientFlow: "",
    })?.id, expected.id);

    const stored = {
      protocol: expected.storageProtocol,
      transport: "kcp",
      security: "tls",
      clientFlow: "",
      profileId: expected.id,
      specVersion: 1,
      specJson: "{}",
    };
    assert.deepEqual(resolveStoredXrayInboundDefinition(stored)?.spec, {});
    for (const specJson of [
      '{"mtu":1350}',
      '{"tti":50}',
      '{"seed":"legacy"}',
      '{"header":{"type":"none"}}',
      '{"finalmask":{}}',
    ]) {
      assert.equal(resolveStoredXrayInboundDefinition({ ...stored, specJson }), null);
    }
  }
});

test("Hysteria 2 TLS is an available UDP profile with a strict empty spec", () => {
  assert.deepEqual(findKnownXrayProfileById("HYSTERIA2_TLS"), {
    id: "HYSTERIA2_TLS",
    status: "AVAILABLE",
    protocol: "HYSTERIA2",
    transport: "HYSTERIA",
    security: "TLS",
    clientFlow: "NONE",
    listenerNetworks: ["UDP"],
    clientCredentialType: "HYSTERIA_AUTH",
    shareFormat: "HYSTERIA2_URI",
    testedCoreVersion: "v26.3.27",
  });
  assert.equal(findAvailableXrayProfileById("HYSTERIA2_TLS")?.id, "HYSTERIA2_TLS");
  assert.equal(findKnownXrayProfile({
    protocol: "hysteria",
    transport: "hysteria",
    security: "tls",
    clientFlow: "",
  })?.id, "HYSTERIA2_TLS");

  const stored = {
    protocol: "hysteria",
    transport: "hysteria",
    security: "tls",
    clientFlow: "",
    profileId: "HYSTERIA2_TLS",
    specVersion: 1,
    specJson: "{}",
  };
  assert.deepEqual(resolveStoredXrayInboundDefinition(stored)?.spec, {});
  for (const specJson of [
    '{"udpIdleTimeout":30}',
    '{"bandwidth":{"up":"100 mbps"}}',
    '{"masquerade":{"type":"proxy","url":"https://example.com"}}',
    '{"obfs":"salamander"}',
    '{"ports":"443,8443"}',
  ]) {
    assert.equal(resolveStoredXrayInboundDefinition({ ...stored, specJson }), null);
  }
  assert.equal(findKnownXrayProfile({ ...stored, security: "none" }), null);
  assert.equal(listAvailableXrayProfiles().some((profile) => profile.id === "HYSTERIA2_TLS"), true);
});

test("gRPC Reality uses a strict versioned spec", () => {
  assert.equal(findKnownXrayProfileById("VLESS_GRPC_REALITY")?.status, "AVAILABLE");
  const stored = {
    protocol: "vless",
    transport: "grpc",
    security: "reality",
    profileId: "VLESS_GRPC_REALITY",
    specVersion: 1,
    specJson: '{"serviceName":"forwardx-grpc"}',
  };
  assert.deepEqual(resolveStoredXrayInboundDefinition(stored), {
    profile: {
      id: "VLESS_GRPC_REALITY",
      status: "AVAILABLE",
      protocol: "VLESS",
      transport: "GRPC",
      security: "REALITY",
      clientFlow: "NONE",
      listenerNetworks: ["TCP"],
      clientCredentialType: "UUID_AND_SHORT_ID",
      shareFormat: "VLESS_URI",
      testedCoreVersion: "v26.3.27",
    },
    specVersion: 1,
    spec: { serviceName: "forwardx-grpc" },
  });
  for (const specJson of [
    '{}',
    '{"serviceName":""}',
    '{"serviceName":"bad/name"}',
    `{"serviceName":"${"a".repeat(129)}"}`,
    '{"serviceName":"grpc","authority":"hidden.example"}',
  ]) {
    assert.equal(resolveStoredXrayInboundDefinition({ ...stored, specJson }), null);
  }
  assert.equal(resolveStoredXrayInboundDefinition({
    ...stored,
    profileId: null,
    specVersion: null,
    specJson: null,
  }), null);
});

test("XHTTP Reality is available with only its strict path profile", () => {
  assert.equal(findKnownXrayProfileById("VLESS_XHTTP_REALITY")?.status, "AVAILABLE");
  assert.equal(findAvailableXrayProfile({
    protocol: "vless",
    transport: "xhttp",
    security: "reality",
    clientFlow: "",
  })?.id, "VLESS_XHTTP_REALITY");
  const stored = {
    protocol: "vless",
    transport: "xhttp",
    security: "reality",
    profileId: "VLESS_XHTTP_REALITY",
    specVersion: 1,
    specJson: '{"path":"/forwardx-xhttp"}',
  };
  assert.deepEqual(resolveStoredXrayInboundDefinition(stored)?.spec, { path: "/forwardx-xhttp" });
  for (const specJson of [
    '{}',
    '{"path":""}',
    '{"path":"relative"}',
    '{"path":"/bad?query"}',
    '{"path":"/bad%2Fescape"}',
    `{"path":"/${"a".repeat(128)}"}`,
    '{"path":"/ok","mode":"stream-up"}',
  ]) {
    assert.equal(resolveStoredXrayInboundDefinition({ ...stored, specJson }), null);
  }
});

test("Trojan RAW Reality is available with a strict empty spec", () => {
  assert.equal(findKnownXrayProfileById("TROJAN_RAW_REALITY")?.status, "AVAILABLE");
  const stored = {
    protocol: "trojan",
    transport: "tcp",
    security: "reality",
    profileId: "TROJAN_RAW_REALITY",
    specVersion: 1,
    specJson: '{}',
  };
  assert.deepEqual(resolveStoredXrayInboundDefinition(stored)?.spec, {});
  assert.equal(findAvailableXrayProfile({ protocol: "trojan", transport: "tcp", security: "reality", clientFlow: "" })?.id, "TROJAN_RAW_REALITY");
  assert.equal(resolveStoredXrayInboundDefinition({ ...stored, specJson: '{"flow":"vision"}' }), null);
});

test("VMess and Shadowsocks compatibility profiles have independent gates and strict empty specs", () => {
  const cases = [{
    id: "VMESS_RAW_TLS",
    status: "AVAILABLE",
    protocol: "VMESS",
    transport: "RAW",
    security: "TLS",
    clientCredentialType: "UUID",
    shareFormat: "VMESS_URI",
    listenerNetworks: ["TCP"],
    storage: { protocol: "vmess", transport: "tcp", security: "tls", clientFlow: "" },
  }, {
    id: "SHADOWSOCKS_2022_RAW_NONE",
    status: "AVAILABLE",
    protocol: "SHADOWSOCKS",
    transport: "RAW",
    security: "NONE",
    clientCredentialType: "SHADOWSOCKS_KEY",
    shareFormat: "SHADOWSOCKS_URI",
    listenerNetworks: ["TCP"],
    storage: { protocol: "shadowsocks", transport: "tcp", security: "none", clientFlow: "" },
  }, {
    id: "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE",
    status: "AVAILABLE",
    protocol: "SHADOWSOCKS",
    transport: "RAW",
    security: "NONE",
    clientCredentialType: "SHADOWSOCKS_KEY",
    shareFormat: "SHADOWSOCKS_URI",
    listenerNetworks: ["TCP", "UDP"],
    storage: { protocol: "shadowsocks", transport: "tcp", security: "none", clientFlow: "" },
  }] as const;

  for (const profile of cases) {
    assert.deepEqual(findKnownXrayProfileById(profile.id), {
      id: profile.id,
      status: profile.status,
      protocol: profile.protocol,
      transport: profile.transport,
      security: profile.security,
      clientFlow: "NONE",
      listenerNetworks: profile.listenerNetworks,
      clientCredentialType: profile.clientCredentialType,
      shareFormat: profile.shareFormat,
      testedCoreVersion: "v26.3.27",
      advisoryCode: "CORE_DEPRECATED",
    });
    assert.equal(findAvailableXrayProfileById(profile.id)?.id ?? null, profile.status === "AVAILABLE" ? profile.id : null);
    if (profile.protocol === "SHADOWSOCKS") assert.equal(findKnownXrayProfile(profile.storage), null);
    else assert.equal(findKnownXrayProfile(profile.storage)?.id, profile.id);

    const stored = {
      ...profile.storage,
      profileId: profile.id,
      specVersion: 1,
      specJson: "{}",
    };
    assert.deepEqual(resolveStoredXrayInboundDefinition(stored)?.spec, {});
    assert.equal(resolveStoredXrayInboundDefinition({ ...stored, specJson: '{"extra":true}' }), null);
  }

  const availableIds = listAvailableXrayProfiles().map((profile) => profile.id);
  assert.equal(availableIds.includes("VMESS_RAW_TLS"), true);
  assert.equal(availableIds.includes("SHADOWSOCKS_2022_RAW_NONE"), true);
  assert.equal(availableIds.includes("SHADOWSOCKS_2022_RAW_TCP_UDP_NONE"), true);
});

test("profile matching accepts only the exact storage combination and flow", () => {
  const current = {
    protocol: "vless",
    transport: "tcp",
    security: "reality",
    clientFlow: "xtls-rprx-vision",
  };

  assert.equal(findAvailableXrayProfile(current)?.id, "VLESS_RAW_REALITY_VISION");
  assert.equal(findAvailableXrayProfile({ ...current, protocol: "vmess" }), null);
  assert.equal(findAvailableXrayProfile({ ...current, transport: "grpc" }), null);
  assert.equal(findAvailableXrayProfile({ ...current, security: "tls" })?.id, "VLESS_RAW_TLS_VISION");
  assert.equal(findAvailableXrayProfile({ ...current, clientFlow: "" }), null);
  assert.equal(findAvailableXrayProfile({ ...current, extra: "config" }), null);
});

test("profile summaries expose metadata only", () => {
  const serialized = JSON.stringify(listAvailableXrayProfiles());

  for (const forbidden of ["configJson", "privateKey", "password", "command", "script"]) {
    assert.equal(serialized.includes(forbidden), false);
  }
});

test("stored inbound profiles map legacy rows and accept only the versioned empty current spec", () => {
  const legacyColumns = {
    protocol: "vless",
    transport: "tcp",
    security: "reality",
  };

  assert.equal(resolveStoredXrayInboundProfile({
    profileId: null,
    specVersion: null,
    specJson: null,
    ...legacyColumns,
  })?.id, "VLESS_RAW_REALITY_VISION");
  assert.equal(resolveStoredXrayInboundProfile({
    profileId: "VLESS_RAW_REALITY_VISION",
    specVersion: 1,
    specJson: "{}",
    ...legacyColumns,
  })?.id, "VLESS_RAW_REALITY_VISION");

  const invalid = [
    { profileId: "VLESS_RAW_REALITY_VISION", specVersion: null, specJson: null },
    { profileId: "VLESS_RAW_REALITY_VISION", specVersion: 2, specJson: "{}" },
    { profileId: "UNKNOWN", specVersion: 1, specJson: "{}" },
    { profileId: "VLESS_RAW_REALITY_VISION", specVersion: 1, specJson: "not-json" },
    { profileId: "VLESS_RAW_REALITY_VISION", specVersion: 1, specJson: '{"inbounds":[]}' },
    { profileId: "VLESS_RAW_REALITY_VISION", specVersion: 1, specJson: "{}".padEnd(XRAY_INBOUND_SPEC_MAX_BYTES + 1, " ") },
  ];
  for (const stored of invalid) {
    assert.equal(resolveStoredXrayInboundProfile({ ...stored, ...legacyColumns }), null);
  }
  assert.equal(resolveStoredXrayInboundProfile({
    profileId: "VLESS_RAW_REALITY_VISION",
    specVersion: 1,
    specJson: "{}",
    ...legacyColumns,
    transport: "grpc",
  }), null);
});
