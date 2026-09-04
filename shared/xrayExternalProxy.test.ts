import assert from "node:assert/strict";
import test from "node:test";

import {
  buildXrayExternalProxyUri,
  parseXrayExternalProxyUri,
  type XrayExternalProxyDefinition,
} from "./xrayExternalProxy";

const publicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

test("parses and canonicalizes VLESS RAW Reality Vision without retaining the source URI", () => {
  const parsed = parseXrayExternalProxyUri(
    "vless://00000000-0000-4000-8000-000000000101@EDGE.Example.com:443"
      + `?security=reality&type=tcp&flow=xtls-rprx-vision&encryption=none&sni=CDN.Example.com&fp=chrome&pbk=${publicKey}`
      + "&sid=12ab34cd&spx=%2Fcdn#US%20A",
  );

  assert.deepEqual(parsed, {
    protocol: "VLESS_REALITY_VISION",
    address: "edge.example.com",
    port: 443,
    displayName: "US A",
    specVersion: 1,
    spec: {
      serverName: "cdn.example.com",
      fingerprint: "chrome",
      publicKey,
      spiderX: "/cdn",
    },
    credentials: {
      uuid: "00000000-0000-4000-8000-000000000101",
      shortId: "12ab34cd",
    },
  });
  assert.equal("sourceUri" in parsed, false);

  assert.equal(buildXrayExternalProxyUri(parsed),
    "vless://00000000-0000-4000-8000-000000000101@edge.example.com:443"
      + `?type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&sni=cdn.example.com&fp=chrome&pbk=${publicKey}`
      + "&sid=12ab34cd&spx=%2Fcdn#US%20A");
  assert.equal(buildXrayExternalProxyUri(parsed, { address: "2001:db8::10", port: 23001 }),
    "vless://00000000-0000-4000-8000-000000000101@[2001:db8::10]:23001"
      + `?type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&sni=cdn.example.com&fp=chrome&pbk=${publicKey}`
      + "&sid=12ab34cd&spx=%2Fcdn#US%20A");
});

test("accepts the approved VLESS fingerprint, root-path, and query-order compatibility matrix", () => {
  const uuid = "00000000-0000-4000-8000-000000000102";
  const endpoint = `${uuid}@edge.example.com:8443`;
  const queryOrders = [
    (fingerprint: string) => `type=tcp&security=reality&encryption=none&flow=xtls-rprx-vision&sni=cdn.example.com&fp=${fingerprint}&pbk=${publicKey}&sid=12ab34cd`,
    (fingerprint: string) => `sid=12ab34cd&pbk=${publicKey}&fp=${fingerprint}&sni=cdn.example.com&flow=xtls-rprx-vision&encryption=none&security=reality&type=tcp`,
  ];

  for (const fingerprint of ["chrome", "random"] as const) {
    for (const path of ["", "/"] as const) {
      for (const query of queryOrders) {
        const uri = `vless://${endpoint}${path}?${query(fingerprint)}#Compat%20Node`;
        const parsed = parseXrayExternalProxyUri(uri);
        assert.equal(parsed.protocol, "VLESS_REALITY_VISION", uri);
        if (parsed.protocol !== "VLESS_REALITY_VISION") assert.fail(uri);
        assert.equal(parsed.spec.fingerprint, fingerprint, uri);
        assert.equal(parsed.spec.spiderX, "/", uri);
        assert.equal(parsed.displayName, "Compat Node", uri);

        const rebuilt = buildXrayExternalProxyUri(parsed);
        assert.equal(rebuilt.includes(":8443/?"), false, uri);
        assert.equal(new URL(rebuilt).searchParams.get("fp"), fingerprint, uri);
        const reparsed = parseXrayExternalProxyUri(rebuilt);
        assert.equal(reparsed.protocol === "VLESS_REALITY_VISION" && reparsed.spec.fingerprint, fingerprint, uri);
      }
    }
  }
});

test("parses SIP002 and legacy Shadowsocks links into one canonical definition", () => {
  const encoded = Buffer.from("aes-256-gcm:p@ss:word", "utf8").toString("base64url");
  const expected = {
    protocol: "SHADOWSOCKS",
    address: "ss.example.com",
    port: 8388,
    displayName: "SS node",
    specVersion: 1,
    spec: { method: "aes-256-gcm" },
    credentials: { password: "p@ss:word" },
  } as const;

  assert.deepEqual(parseXrayExternalProxyUri(`ss://${encoded}@ss.example.com:8388#SS%20node`), expected);
  assert.deepEqual(parseXrayExternalProxyUri("ss://aes-256-gcm:p%40ss%3Aword@ss.example.com:8388#SS%20node"), expected);
  const legacy = Buffer.from("aes-256-gcm:p@ss:word@ss.example.com:8388", "utf8").toString("base64");
  assert.deepEqual(parseXrayExternalProxyUri(`ss://${legacy}#SS%20node`), expected);
  assert.equal(buildXrayExternalProxyUri(expected), `ss://${encoded}@ss.example.com:8388#SS%20node`);
});

test("supports approved Shadowsocks 2022 methods and preserves the combined password", () => {
  const password = `${Buffer.alloc(32, 1).toString("base64")}:${Buffer.alloc(32, 2).toString("base64")}`;
  const encoded = Buffer.from(`2022-blake3-aes-256-gcm:${password}`, "utf8").toString("base64url");
  const parsed = parseXrayExternalProxyUri(`ss://${encoded}@[2001:db8::20]:443#SS2022`);
  assert.equal(parsed.protocol, "SHADOWSOCKS");
  assert.equal(parsed.address, "2001:db8::20");
  assert.deepEqual(parsed.spec, { method: "2022-blake3-aes-256-gcm" });
  assert.deepEqual(parsed.credentials, { password });

  const aes128Password = Buffer.alloc(16, 3).toString("base64");
  const aes128 = Buffer.from(`2022-blake3-aes-128-gcm:${aes128Password}`, "utf8").toString("base64url");
  assert.deepEqual(
    parseXrayExternalProxyUri(`ss://${aes128}@ss128.example.com:8443`).credentials,
    { password: aes128Password },
  );
});

test("parses authenticated and no-auth SOCKS5 links and replaces only the endpoint", () => {
  const authenticated = parseXrayExternalProxyUri(
    "socks5://user%40example:p%3Aa%2Fss@Proxy.Example.com:1080#Office%20SOCKS",
  );
  assert.deepEqual(authenticated, {
    protocol: "SOCKS5",
    address: "proxy.example.com",
    port: 1080,
    displayName: "Office SOCKS",
    specVersion: 1,
    spec: {},
    credentials: { username: "user@example", password: "p:a/ss" },
  });
  assert.equal(buildXrayExternalProxyUri(authenticated, { address: "relay.example.com", port: 31080 }),
    "socks5://user%40example:p%3Aa%2Fss@relay.example.com:31080#Office%20SOCKS");

  const noAuth = parseXrayExternalProxyUri("socks5://192.0.2.10:1080");
  assert.deepEqual(noAuth.credentials, {});
  assert.equal(buildXrayExternalProxyUri(noAuth), "socks5://192.0.2.10:1080");
});

test("rejects unsupported, ambiguous, malformed, and oversized import links", () => {
  const invalid = [
    "http://user:pass@example.com:8080",
    "vless://not-a-uuid@example.com:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=cdn.example.com&fp=chrome&pbk=" + publicKey + "&sid=12",
    "vless://00000000-0000-4000-8000-000000000101@example.com:443?type=ws&security=reality&flow=xtls-rprx-vision&sni=cdn.example.com&fp=chrome&pbk=" + publicKey + "&sid=12",
    "vless://00000000-0000-4000-8000-000000000101@example.com:443?type=tcp&type=tcp&security=reality&flow=xtls-rprx-vision&sni=cdn.example.com&fp=chrome&pbk=" + publicKey + "&sid=12",
    "vless://00000000-0000-4000-8000-000000000101@example.com:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=cdn.example.com&fp=chrome&pbk=" + publicKey + "&sid=12&headerType=http",
    "vless://00000000-0000-4000-8000-000000000101@example.com:443/nested?type=tcp&security=reality&flow=xtls-rprx-vision&sni=cdn.example.com&fp=chrome&pbk=" + publicKey + "&sid=12",
    "vless://00000000-0000-4000-8000-000000000101@example.com:443/./?type=tcp&security=reality&flow=xtls-rprx-vision&sni=cdn.example.com&fp=chrome&pbk=" + publicKey + "&sid=12",
    "vless://00000000-0000-4000-8000-000000000101@example.com:443/%2e%2e?type=tcp&security=reality&flow=xtls-rprx-vision&sni=cdn.example.com&fp=chrome&pbk=" + publicKey + "&sid=12",
    "vless://00000000-0000-4000-8000-000000000101@example.com:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=cdn.example.com&fp=randomized&pbk=" + publicKey + "&sid=12",
    "vless://00000000-0000-4000-8000-000000000101@example.com:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=cdn.example.com&fp=firefox&pbk=" + publicKey + "&sid=12",
    "vless://00000000-0000-4000-8000-000000000101@example.com:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=cdn.example.com&fp=chrome&pbk=" + publicKey + "&sid=12&spx=/%ZZ",
    "vless://00000000-0000-4000-8000-000000000101@example.com:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=cdn.example.com&fp=chrome&pbk=" + publicKey + "&sid=12&spx=/%",
    "vless://00000000-0000-4000-8000-000000000101@example.com:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=cdn.example.com&fp=chrome&pbk=" + publicKey + "&sid=12&spx=/%FF",
    "ss://aes-256-gcm:password@example.com:8388?plugin=obfs-local",
    "ss://rc4-md5:password@example.com:8388",
    "socks5://user@example.com:1080",
    "socks5://user:pass@example.com:1080/path",
    "socks5://user:pass@example.com:1080?udp=1",
    "socks5://user%ZZ:pass@example.com:1080",
    `socks5://${"a".repeat(4097)}`,
  ];
  for (const uri of invalid) {
    assert.throws(() => parseXrayExternalProxyUri(uri), { message: "INVALID_EXTERNAL_PROXY_LINK" }, uri);
  }
});

test("builder revalidates persisted definitions before exposing a credential URI", () => {
  const valid = parseXrayExternalProxyUri(
    `vless://00000000-0000-4000-8000-000000000101@example.com:443?type=tcp&security=reality&flow=xtls-rprx-vision&sni=cdn.example.com&fp=chrome&pbk=${publicKey}&sid=12`,
  );
  assert.throws(() => buildXrayExternalProxyUri({
    ...valid,
    spec: { ...valid.spec, fingerprint: "firefox" },
  } as unknown as XrayExternalProxyDefinition), { message: "INVALID_EXTERNAL_PROXY_LINK" });
});
