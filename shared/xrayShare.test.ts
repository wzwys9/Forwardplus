import assert from "node:assert/strict";
import test from "node:test";

import {
  buildXrayHttpProxyUri,
  buildXrayMixedProxyEndpoints,
  buildXrayHysteria2Uri,
  buildXrayShadowsocks2022Uri,
  buildXrayTrojanTlsUri,
  buildXrayVmessTlsUri,
  buildXrayTrojanRealityUri,
  buildXrayVlessRealityUri,
  buildXrayVlessTlsUri,
} from "./xrayShare";
import type { XrayTrojanTlsShareInput, XrayVlessTlsShareInput } from "./xrayShare";

const baseInput = {
  uuid: "00000000-0000-4000-8000-000000000101",
  publicAddress: "edge.example.com",
  listenPort: 23456,
  serverName: "www.microsoft.com",
  realityPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  shortId: "0123456789abcdef",
  fingerprint: "chrome" as const,
  spiderX: "/",
  flow: "xtls-rprx-vision" as const,
  displayName: "Hong Kong / phone #1",
};

test("builds a stable VLESS TCP Reality Vision URI with encoded values", () => {
  const uri = buildXrayVlessRealityUri(baseInput);
  assert.equal(uri,
    "vless://00000000-0000-4000-8000-000000000101@edge.example.com:23456"
    + "?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome"
    + "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef"
    + "&spx=%2F&flow=xtls-rprx-vision#Hong%20Kong%20%2F%20phone%20%231");

  const parsed = new URL(uri);
  assert.equal(parsed.protocol, "vless:");
  assert.equal(parsed.username, baseInput.uuid);
  assert.equal(parsed.hostname, "edge.example.com");
  assert.equal(parsed.port, "23456");
  assert.deepEqual([...parsed.searchParams.entries()], [
    ["type", "tcp"], ["security", "reality"], ["sni", "www.microsoft.com"],
    ["fp", "chrome"], ["pbk", baseInput.realityPublicKey], ["sid", baseInput.shortId],
    ["spx", "/"], ["flow", "xtls-rprx-vision"],
  ]);
  assert.equal(uri.includes("private"), false);
});

test("builds stable VLESS RAW standard and Vision TLS URIs with certificate pinning", () => {
  const tlsBase = {
    uuid: baseInput.uuid,
    publicAddress: baseInput.publicAddress,
    listenPort: baseInput.listenPort,
    serverName: "tls.example.com",
    fingerprint: "chrome" as const,
    leafFingerprintSha256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    displayName: baseInput.displayName,
  };
  const standard = buildXrayVlessTlsUri({ ...tlsBase, profileId: "VLESS_RAW_TLS" });
  const vision = buildXrayVlessTlsUri({ ...tlsBase, profileId: "VLESS_RAW_TLS_VISION" });

  assert.equal(standard,
    "vless://00000000-0000-4000-8000-000000000101@edge.example.com:23456"
    + "?type=tcp&security=tls&sni=tls.example.com&fp=chrome"
    + "&pcs=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    + "&encryption=none#Hong%20Kong%20%2F%20phone%20%231");
  assert.equal(vision, `${standard.replace("#", "&flow=xtls-rprx-vision#")}`);

  const standardQuery = new URL(standard).searchParams;
  assert.deepEqual([...standardQuery.entries()], [
    ["type", "tcp"], ["security", "tls"], ["sni", "tls.example.com"], ["fp", "chrome"],
    ["pcs", tlsBase.leafFingerprintSha256], ["encryption", "none"],
  ]);
  assert.equal(standardQuery.has("flow"), false);
  assert.equal(new URL(vision).searchParams.get("flow"), "xtls-rprx-vision");
  for (const uri of [standard, vision]) {
    assert.equal(uri.includes("allowInsecure"), false);
    assert.equal(uri.includes("pbk="), false);
    assert.equal(uri.includes("sid="), false);
  }
});

test("VLESS RAW TLS URI validates the endpoint, SNI, pin, and fixed profile", () => {
  const valid = {
    profileId: "VLESS_RAW_TLS" as const,
    uuid: baseInput.uuid,
    publicAddress: "2001:db8::1234",
    listenPort: baseInput.listenPort,
    serverName: "TLS.EXAMPLE.COM",
    fingerprint: "chrome" as const,
    leafFingerprintSha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    displayName: "手机 & router",
  };
  const uri = buildXrayVlessTlsUri(valid);
  assert.match(uri, /^vless:\/\/[^@]+@\[2001:db8::1234\]:23456\?/);
  assert.equal(new URL(uri).searchParams.get("sni"), "tls.example.com");
  assert.ok(uri.endsWith("#%E6%89%8B%E6%9C%BA%20%26%20router"));

  for (const patch of [
    { profileId: "VLESS_GRPC_TLS" },
    { uuid: "not-a-uuid" },
    { publicAddress: "[2001:db8::1]" },
    { listenPort: 999 },
    { serverName: "*.example.com" },
    { serverName: "192.0.2.1" },
    { fingerprint: "firefox" },
    { leafFingerprintSha256: "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789" },
    { leafFingerprintSha256: "short" },
    { displayName: "" },
  ]) {
    assert.throws(() => buildXrayVlessTlsUri({ ...valid, ...patch } as typeof valid));
  }
});

test("all available VLESS and Trojan TLS profiles emit only their strict share fields", () => {
  const leafFingerprintSha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  const endpoint = {
    publicAddress: "edge.example.com",
    listenPort: 23456,
    serverName: "tls.example.com",
    fingerprint: "chrome" as const,
    leafFingerprintSha256,
    displayName: "TLS checkpoint",
  };
  const vlessCases: Array<{
    input: XrayVlessTlsShareInput;
    transport: string;
    fields?: Record<string, string>;
  }> = [
    { input: { ...endpoint, uuid: baseInput.uuid, profileId: "VLESS_RAW_TLS" }, transport: "tcp" },
    {
      input: { ...endpoint, uuid: baseInput.uuid, profileId: "VLESS_RAW_TLS_VISION" },
      transport: "tcp",
      fields: { flow: "xtls-rprx-vision" },
    },
    {
      input: { ...endpoint, uuid: baseInput.uuid, profileId: "VLESS_WEBSOCKET_TLS", path: "/forwardx/ws" },
      transport: "ws",
      fields: { path: "/forwardx/ws" },
    },
    {
      input: { ...endpoint, uuid: baseInput.uuid, profileId: "VLESS_GRPC_TLS", serviceName: "forwardx-grpc" },
      transport: "grpc",
      fields: { serviceName: "forwardx-grpc", alpn: "h2" },
    },
    {
      input: { ...endpoint, uuid: baseInput.uuid, profileId: "VLESS_HTTP_UPGRADE_TLS", path: "/forwardx/httpupgrade" },
      transport: "httpupgrade",
      fields: { path: "/forwardx/httpupgrade" },
    },
    {
      input: { ...endpoint, uuid: baseInput.uuid, profileId: "VLESS_XHTTP_TLS", path: "/forwardx/xhttp" },
      transport: "xhttp",
      fields: { path: "/forwardx/xhttp", mode: "auto" },
    },
    { input: { ...endpoint, uuid: baseInput.uuid, profileId: "VLESS_MKCP_TLS" }, transport: "kcp" },
  ];
  const trojanCases: Array<{
    input: XrayTrojanTlsShareInput;
    transport: string;
    fields?: Record<string, string>;
  }> = [
    { input: { ...endpoint, password: "B".repeat(43), profileId: "TROJAN_RAW_TLS" }, transport: "tcp" },
    {
      input: { ...endpoint, password: "B".repeat(43), profileId: "TROJAN_WEBSOCKET_TLS", path: "/forwardx/ws" },
      transport: "ws",
      fields: { path: "/forwardx/ws" },
    },
    {
      input: { ...endpoint, password: "B".repeat(43), profileId: "TROJAN_GRPC_TLS", serviceName: "forwardx-grpc" },
      transport: "grpc",
      fields: { serviceName: "forwardx-grpc", alpn: "h2" },
    },
    {
      input: { ...endpoint, password: "B".repeat(43), profileId: "TROJAN_HTTP_UPGRADE_TLS", path: "/forwardx/httpupgrade" },
      transport: "httpupgrade",
      fields: { path: "/forwardx/httpupgrade" },
    },
    {
      input: { ...endpoint, password: "B".repeat(43), profileId: "TROJAN_XHTTP_TLS", path: "/forwardx/xhttp" },
      transport: "xhttp",
      fields: { path: "/forwardx/xhttp", mode: "auto" },
    },
    { input: { ...endpoint, password: "B".repeat(43), profileId: "TROJAN_MKCP_TLS" }, transport: "kcp" },
  ];

  const shares = [
    ...vlessCases.map(({ input, transport, fields = {} }) => ({
      profileId: input.profileId,
      uri: buildXrayVlessTlsUri(input),
      protocol: "vless:",
      username: input.uuid,
      transport,
      fields: { encryption: "none", ...fields },
    })),
    ...trojanCases.map(({ input, transport, fields = {} }) => ({
      profileId: input.profileId,
      uri: buildXrayTrojanTlsUri(input),
      protocol: "trojan:",
      username: input.password,
      transport,
      fields,
    })),
  ];
  assert.equal(shares.length, 13);
  assert.equal(new Set(shares.map(({ profileId }) => profileId)).size, 13);

  for (const share of shares) {
    const parsed = new URL(share.uri);
    assert.equal(parsed.protocol, share.protocol, share.profileId);
    assert.equal(parsed.username, share.username, share.profileId);
    assert.deepEqual(Object.fromEntries(parsed.searchParams), {
      type: share.transport,
      security: "tls",
      sni: "tls.example.com",
      fp: "chrome",
      pcs: leafFingerprintSha256,
      ...share.fields,
    }, share.profileId);
    assert.equal(decodeURIComponent(parsed.hash), "#TLS checkpoint", share.profileId);
  }
});

test("builds a strict compact VMess RAW TLS v2 URI", () => {
  const valid = {
    uuid: baseInput.uuid,
    publicAddress: "2001:db8::1234",
    listenPort: baseInput.listenPort,
    serverName: "TLS.EXAMPLE.COM",
    fingerprint: "chrome" as const,
    leafFingerprintSha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    displayName: "手机 & router",
  };
  const uri = buildXrayVmessTlsUri(valid);
  const encoded = uri.slice("vmess://".length);
  assert.equal(encoded.includes("\n"), false);
  assert.deepEqual(JSON.parse(Buffer.from(encoded, "base64").toString("utf8")), {
    v: "2",
    ps: "手机 & router",
    add: "2001:db8::1234",
    port: 23456,
    id: baseInput.uuid,
    scy: "auto",
    net: "tcp",
    type: "none",
    tls: "tls",
    sni: "tls.example.com",
    fp: "chrome",
    pcs: valid.leafFingerprintSha256,
  });
  for (const forbidden of ["aid", "alterId", "host", "path", "allowInsecure"]) {
    assert.equal(Buffer.from(encoded, "base64").toString("utf8").includes(forbidden), false);
  }
  for (const patch of [
    { uuid: "not-a-uuid" },
    { publicAddress: "[2001:db8::1]" },
    { listenPort: 999 },
    { serverName: "192.0.2.1" },
    { fingerprint: "firefox" },
    { leafFingerprintSha256: "A".repeat(64) },
    { displayName: "" },
  ]) {
    assert.throws(() => buildXrayVmessTlsUri({ ...valid, ...patch } as typeof valid));
  }
});

test("builds a strict Shadowsocks 2022 SIP002 URI with two directly encoded PSKs", () => {
  const serverKey = Buffer.alloc(32, 0xfb).toString("base64");
  const userKey = Buffer.alloc(32, 0xff).toString("base64");
  const uri = buildXrayShadowsocks2022Uri({
    serverKey,
    userKey,
    publicAddress: "2001:db8::1234",
    listenPort: 23456,
    displayName: "手机 & router",
  });
  assert.equal(uri,
    `ss://2022-blake3-aes-256-gcm:${encodeURIComponent(serverKey)}:${encodeURIComponent(userKey)}`
    + "@[2001:db8::1234]:23456#%E6%89%8B%E6%9C%BA%20%26%20router");
  assert.equal(uri.includes("?"), false);
  assert.equal(uri.includes(Buffer.from(`2022-blake3-aes-256-gcm:${serverKey}:${userKey}`).toString("base64")), false);

  for (const patch of [
    { serverKey: serverKey.slice(0, -1) },
    { userKey: userKey.replace(/\+/g, "-").replace(/\//g, "_") },
    { userKey: serverKey },
    { publicAddress: "[2001:db8::1]" },
    { listenPort: 999 },
    { displayName: "" },
  ]) {
    assert.throws(() => buildXrayShadowsocks2022Uri({
      serverKey,
      userKey,
      publicAddress: "edge.example.com",
      listenPort: 23456,
      displayName: "router",
      ...patch,
    }));
  }
});

test("builds a standard Hysteria 2 URI with only SNI and the managed leaf pin", () => {
  const auth = Buffer.alloc(32, 0xfa).toString("base64url");
  const pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  const uri = buildXrayHysteria2Uri({
    auth,
    publicAddress: "2001:db8::1234",
    listenPort: 23456,
    serverName: "TLS.EXAMPLE.COM",
    leafFingerprintSha256: pin,
    displayName: "手机 & router",
  });

  assert.equal(uri, `hysteria2://${auth}@[2001:db8::1234]:23456`
    + `?sni=tls.example.com&pinSHA256=${pin}#%E6%89%8B%E6%9C%BA%20%26%20router`);
  const parsed = new URL(uri);
  assert.equal(parsed.protocol, "hysteria2:");
  assert.equal(parsed.username, auth);
  assert.deepEqual([...parsed.searchParams.entries()], [["sni", "tls.example.com"], ["pinSHA256", pin]]);
  for (const forbidden of ["insecure", "allowInsecure", "security", "fp", "alpn", "pcs", "obfs", "mport"]) {
    assert.equal(uri.includes(forbidden), false, forbidden);
  }

  for (const patch of [
    { auth: "not-canonical" },
    { auth: "B".repeat(43) },
    { publicAddress: "[2001:db8::1]" },
    { listenPort: 999 },
    { serverName: "*.example.com" },
    { serverName: "192.0.2.1" },
    { leafFingerprintSha256: "A".repeat(64) },
    { displayName: "" },
  ]) {
    assert.throws(() => buildXrayHysteria2Uri({
      auth,
      publicAddress: "edge.example.com",
      listenPort: 23456,
      serverName: "tls.example.com",
      leafFingerprintSha256: pin,
      displayName: "router",
      ...patch,
    }));
  }
});

test("builds a strict authenticated HTTP proxy URI without subscription metadata", () => {
  const username = Buffer.alloc(16, 0xfa).toString("base64url");
  const password = Buffer.alloc(32, 0xfb).toString("base64url");
  const uri = buildXrayHttpProxyUri({
    username,
    password,
    publicAddress: "2001:DB8::1234",
    listenPort: 23456,
  });
  assert.equal(uri, `http://${username}:${password}@[2001:db8::1234]:23456`);
  const parsed = new URL(uri);
  assert.equal(parsed.username, username);
  assert.equal(parsed.password, password);
  assert.equal(parsed.search, "");
  assert.equal(parsed.hash, "");

  for (const patch of [
    { username: username.slice(1) },
    { username: "B".repeat(22) },
    { password: password.slice(1) },
    { password: "B".repeat(43) },
    { publicAddress: "[2001:db8::1]" },
    { listenPort: 999 },
  ]) {
    assert.throws(() => buildXrayHttpProxyUri({
      username,
      password,
      publicAddress: "edge.example.com",
      listenPort: 23456,
      ...patch,
    }));
  }
});

test("builds strict Mixed SOCKS5 and HTTP endpoints from one credential pair", () => {
  const username = Buffer.alloc(16, 0xfc).toString("base64url");
  const password = Buffer.alloc(32, 0xfd).toString("base64url");
  const endpoints = buildXrayMixedProxyEndpoints({
    username,
    password,
    publicAddress: "2001:DB8::4321",
    listenPort: 24567,
  });
  assert.deepEqual(endpoints, {
    socks5Uri: `socks5://${username}:${password}@[2001:db8::4321]:24567`,
    httpUri: `http://${username}:${password}@[2001:db8::4321]:24567`,
  });
  for (const uri of Object.values(endpoints)) {
    const parsed = new URL(uri);
    assert.equal(parsed.username, username);
    assert.equal(parsed.password, password);
    assert.equal(parsed.search, "");
    assert.equal(parsed.hash, "");
  }
  assert.throws(() => buildXrayMixedProxyEndpoints({
    username,
    password: "not-canonical",
    publicAddress: "edge.example.com",
    listenPort: 24567,
  }));
});

test("brackets a bare IPv6 endpoint and percent-encodes every dynamic component", () => {
  const uri = buildXrayVlessRealityUri({
    ...baseInput,
    publicAddress: "2001:db8::1234",
    serverName: "xn--bcher-kva.example",
    spiderX: "/news?a=b c",
    displayName: "手机 & router",
  });
  assert.match(uri, /^vless:\/\/[^@]+@\[2001:db8::1234\]:23456\?/);
  assert.ok(uri.includes("sni=xn--bcher-kva.example"));
  assert.ok(uri.includes("spx=%2Fnews%3Fa%3Db%20c"));
  assert.ok(uri.endsWith("#%E6%89%8B%E6%9C%BA%20%26%20router"));
});

test("builds VLESS gRPC Reality URI with serviceName and no hidden Vision flow", () => {
  const uri = buildXrayVlessRealityUri({
    ...baseInput,
    transport: "grpc",
    serviceName: "forwardx-grpc",
    flow: "",
  });
  assert.equal(uri,
    "vless://00000000-0000-4000-8000-000000000101@edge.example.com:23456"
    + "?type=grpc&security=reality&sni=www.microsoft.com&fp=chrome"
    + "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef"
    + "&spx=%2F&serviceName=forwardx-grpc#Hong%20Kong%20%2F%20phone%20%231");
  const parsed = new URL(uri);
  assert.equal(parsed.searchParams.get("serviceName"), "forwardx-grpc");
  assert.equal(parsed.searchParams.has("flow"), false);
  assert.throws(() => buildXrayVlessRealityUri({
    ...baseInput,
    transport: "grpc",
    serviceName: "bad/name",
    flow: "",
  }));
});

test("builds VLESS XHTTP Reality URI with strict path, fixed auto mode, and no flow", () => {
  const uri = buildXrayVlessRealityUri({
    ...baseInput,
    transport: "xhttp",
    path: "/forwardx/xhttp-v1",
    flow: "",
  });
  assert.equal(uri,
    "vless://00000000-0000-4000-8000-000000000101@edge.example.com:23456"
    + "?type=xhttp&security=reality&sni=www.microsoft.com&fp=chrome"
    + "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef"
    + "&spx=%2F&path=%2Fforwardx%2Fxhttp-v1&mode=auto#Hong%20Kong%20%2F%20phone%20%231");
  const parsed = new URL(uri);
  assert.equal(parsed.searchParams.get("path"), "/forwardx/xhttp-v1");
  assert.equal(parsed.searchParams.get("mode"), "auto");
  assert.equal(parsed.searchParams.has("flow"), false);
  assert.throws(() => buildXrayVlessRealityUri({
    ...baseInput,
    transport: "xhttp",
    path: "/bad?query",
    flow: "",
  }));
});

test("builds Trojan RAW Reality URI from password and Reality shortId without flow", () => {
  const uri = buildXrayTrojanRealityUri({
    password: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    publicAddress: baseInput.publicAddress,
    listenPort: baseInput.listenPort,
    serverName: baseInput.serverName,
    realityPublicKey: baseInput.realityPublicKey,
    shortId: baseInput.shortId,
    fingerprint: "chrome",
    spiderX: baseInput.spiderX,
    displayName: baseInput.displayName,
  });
  assert.equal(uri,
    "trojan://BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB@edge.example.com:23456"
    + "?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome"
    + "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef"
    + "&spx=%2F#Hong%20Kong%20%2F%20phone%20%231");
  const parsed = new URL(uri);
  assert.equal(parsed.searchParams.has("flow"), false);
  assert.throws(() => buildXrayTrojanRealityUri({
    password: "short",
    publicAddress: baseInput.publicAddress,
    listenPort: baseInput.listenPort,
    serverName: baseInput.serverName,
    realityPublicKey: baseInput.realityPublicKey,
    shortId: baseInput.shortId,
    fingerprint: "chrome",
    spiderX: baseInput.spiderX,
    displayName: baseInput.displayName,
  }));
});

test("rejects malformed identities, endpoints, ports, and unsupported fields", () => {
  for (const patch of [
    { uuid: "not-a-uuid" },
    { publicAddress: "[2001:db8::1]" },
    { publicAddress: "bad host" },
    { listenPort: 999 },
    { serverName: "https://example.com" },
    { realityPublicKey: "short" },
    { shortId: "not-hex" },
    { fingerprint: "firefox" },
    { spiderX: "relative" },
    { flow: "" },
    { displayName: "" },
  ]) {
    assert.throws(() => buildXrayVlessRealityUri({ ...baseInput, ...patch } as typeof baseInput));
  }
});
