import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";

import { XrayInboundDetailContent } from "./XrayInboundDetailContent";

const detail = {
  inbound: {
    id: 8,
    hostId: 2,
    name: "edge-reality",
    runtimeTag: "inbound-8",
    publicAddress: "203.0.113.8",
    listenAddress: "0.0.0.0",
    listenPort: 443,
    listenerNetworks: ["tcp"],
    protocol: "VLESS",
    transport: "TCP",
    security: "REALITY",
    realityTargetHost: "www.example.com",
    realityTargetPort: 443,
    realityServerName: "www.example.com",
    realityPublicKey: "PUBLIC_KEY_SAFE",
    hasRealityPrivateKey: true,
    fingerprint: "chrome",
    spiderX: "/",
    isEnabled: true,
    pendingDelete: false,
    desiredGeneration: 4,
    externalProxy: { id: 9, name: "美国 A", protocol: "VLESS_REALITY_VISION", address: "us.example.com", port: 443 },
    createdAt: new Date("2026-09-01T00:00:00Z"),
    updatedAt: new Date("2026-09-01T00:00:00Z"),
  },
  clients: [{
    id: 21,
    inboundId: 8,
    name: "Alice",
    statsKey: "hidden-stats-key",
    flow: "xtls-rprx-vision",
    isEnabled: true,
    pendingDelete: true,
    credentials: { uuidConfigured: true, shortIdConfigured: true },
    createdAt: new Date("2026-09-01T00:00:00Z"),
    updatedAt: new Date("2026-09-01T00:00:00Z"),
  }],
  accessEntries: [],
  host: { id: 2, name: "edge-02", isOnline: false, lastHeartbeat: new Date("2026-09-01T00:00:00Z") },
  deployment: {
    status: "HOST_OFFLINE",
    targetVersion: "26.3.27",
    desiredGeneration: 4,
    appliedGeneration: 3,
    desiredConfigHash: "desired-hash",
    appliedConfigHash: "applied-hash",
    configInSync: false,
    lastErrorCode: null,
  },
  operations: [{
    operationId: "sync-4",
    hostId: 2,
    inboundId: 8,
    type: "SYNC",
    status: "QUEUED",
    stage: "QUEUED",
    requestedGeneration: 4,
    errorCode: null,
    errorMessage: null,
    attemptCount: 0,
    createdAt: new Date("2026-09-01T00:00:00Z"),
    startedAt: null,
    finishedAt: null,
    expiresAt: null,
    updatedAt: new Date("2026-09-01T00:00:00Z"),
  }],
};

const callbacks = {
  onEditInbound: () => undefined,
  onConfigureExternalProxy: () => undefined,
  onSetInboundEnabled: () => undefined,
  onSyncInbound: () => undefined,
  onCreateClient: () => undefined,
  onUpdateClient: () => undefined,
  onRemoveClient: () => undefined,
  onShareClient: () => undefined,
  onCreateAccessEntry: () => undefined,
  onUpdateAccessEntry: () => undefined,
  onRemoveAccessEntry: () => undefined,
  onShareAccessEntry: () => undefined,
};

test("detail tabs expose safe Reality and pending client state without rendering secrets", () => {
  const overview = renderToStaticMarkup(
    <XrayInboundDetailContent detail={detail as never} runtime={null} busy={false} {...callbacks} />,
  );
  const reality = renderToStaticMarkup(
    <XrayInboundDetailContent detail={detail as never} runtime={null} busy={false} defaultTab="reality" {...callbacks} />,
  );
  const clients = renderToStaticMarkup(
    <XrayInboundDetailContent detail={detail as never} runtime={null} busy={false} defaultTab="clients" {...callbacks} />,
  );
  const runtime = renderToStaticMarkup(
    <XrayInboundDetailContent detail={detail as never} runtime={null} busy={false} defaultTab="runtime" {...callbacks} />,
  );
  const markup = overview + reality + clients + runtime;
  for (const label of ["概览", "客户端", "Reality", "运行时", "操作记录"]) assert.match(overview, new RegExp(label));
  assert.match(overview, /配置出口/);
  assert.match(overview, /美国 A（VLESS_REALITY_VISION）/);
  assert.match(reality, /PUBLIC_KEY_SAFE/);
  assert.match(reality, /私钥已安全生成/);
  assert.match(clients, /待删除/);
  assert.match(clients, /应用完成前旧链接可能继续有效/);
  assert.match(runtime, /Agent 离线，Xray 运行状态未知/);
  assert.doesNotMatch(markup, /hidden-stats-key/);
  assert.doesNotMatch(markup, /privateKey|realityPrivateKeyEncrypted/);
});

test("offline or pending clients keep share available while disabling all writes", () => {
  const markup = renderToStaticMarkup(
    <XrayInboundDetailContent detail={detail as never} runtime={null} busy={false} defaultTab="clients" {...callbacks} />,
  );
  assert.match(markup, />分享 \/ QR</);
  assert.match(markup, />添加客户端</);
  assert.match(markup, /添加客户端<\/button>/);
  assert.match(markup, /disabled=""[^>]*>[^<]*(?:<[^>]+>)*分享 \/ QR<\/button>|>分享 \/ QR<\/button>/);
  assert.doesNotMatch(markup, /disabled=""[^>]*>[^<]*(?:<[^>]+>)*分享 \/ QR<\/button>/);
  assert.match(markup, /disabled=""[^>]*>[^<]*(?:<[^>]+>)*改名<\/button>/);
  assert.match(markup, /disabled=""[^>]*>[^<]*(?:<[^>]+>)*启用|disabled=""[^>]*>[^<]*(?:<[^>]+>)*停用/);
  assert.match(markup, /disabled=""[^>]*>[^<]*(?:<[^>]+>)*删除<\/button>/);
});

test("node-level edit, enable, and resync actions remain visible but disabled while the Agent is offline", () => {
  const markup = renderToStaticMarkup(
    <XrayInboundDetailContent detail={detail as never} runtime={null} busy={false} {...callbacks} />,
  );
  for (const label of ["编辑节点", "停用节点", "重新同步"]) {
    assert.match(markup, new RegExp(`disabled=""[^>]*>[^<]*(?:<[^>]+>)*${label}<\\/button>`));
  }
});

test("Trojan detail renders generic password accounts without exposing credential material", () => {
  const trojan = {
    ...detail,
    inbound: { ...detail.inbound, protocol: "trojan", transport: "tcp" },
    clients: [],
    accessEntries: [{
      id: 31,
      inboundId: 8,
      legacyClientId: null,
      name: "Trojan Phone",
      credentialType: "PASSWORD",
      settings: { credentialType: "PASSWORD", schemaVersion: 1 },
      statsKey: "forwardx-access-safe",
      ownerUserId: null,
      isEnabled: true,
      pendingDelete: false,
      desiredGeneration: 4,
      sortOrder: 0,
      createdAt: 1,
      updatedAt: 1,
      secretStatus: { requiredConfigured: true, configuredKinds: ["PASSWORD", "SHORT_ID"] },
    }],
  };
  const markup = renderToStaticMarkup(
    <XrayInboundDetailContent detail={trojan as never} runtime={null} busy={false} defaultTab="clients" {...callbacks} />,
  );
  assert.match(markup, /Trojan Phone/);
  assert.match(markup, /Password：已配置（隐藏）/);
  assert.match(markup, /shortId：已配置（隐藏）/);
  assert.match(markup, /添加账户/);
  assert.doesNotMatch(markup, /forwardx-access-safe/);

  const vmess = {
    ...detail,
    inbound: {
      ...detail.inbound,
      protocol: "vmess",
      transport: "tcp",
      profileId: "VMESS_RAW_TLS",
      advisoryCode: "CORE_DEPRECATED",
    },
    clients: [],
    accessEntries: [{
      ...trojan.accessEntries[0],
      id: 32,
      name: "VMess Router",
      credentialType: "UUID",
      settings: { credentialType: "UUID", schemaVersion: 1, flow: "NONE", security: "AUTO" },
      secretStatus: { requiredConfigured: true, configuredKinds: ["UUID"] },
    }],
  };
  const vmessMarkup = renderToStaticMarkup(
    <XrayInboundDetailContent detail={vmess as never} runtime={null} busy={false} defaultTab="clients" {...callbacks} />,
  );
  assert.match(vmessMarkup, /VMess Router/);
  assert.match(vmessMarkup, /兼容协议，固定 Xray 核心已标记 deprecated；新节点优先使用 VLESS\/Trojan/);
  assert.match(vmessMarkup, /UUID：已配置（隐藏）/);
  assert.match(vmessMarkup, /添加账户/);
  assert.doesNotMatch(vmessMarkup, /Password：|shortId：|forwardx-access-safe/);

  const shadowsocks = {
    ...detail,
    inbound: {
      ...detail.inbound,
      protocol: "shadowsocks",
      transport: "tcp",
      security: "none",
      profileId: "SHADOWSOCKS_2022_RAW_NONE",
      advisoryCode: "CORE_DEPRECATED",
      realityTargetHost: "",
      realityServerName: "",
      realityPublicKey: "",
      hasRealityPrivateKey: false,
    },
    clients: [],
    accessEntries: [{
      ...trojan.accessEntries[0],
      id: 33,
      name: "Shadowsocks Phone",
      credentialType: "SHADOWSOCKS_KEY",
      settings: { credentialType: "SHADOWSOCKS_KEY", schemaVersion: 1 },
      secretStatus: { requiredConfigured: true, configuredKinds: ["SHADOWSOCKS_KEY"] },
    }],
  };
  const shadowsocksOverview = renderToStaticMarkup(
    <XrayInboundDetailContent detail={shadowsocks as never} runtime={null} busy={false} {...callbacks} />,
  );
  const shadowsocksAccounts = renderToStaticMarkup(
    <XrayInboundDetailContent detail={shadowsocks as never} runtime={null} busy={false} defaultTab="clients" {...callbacks} />,
  );
  assert.match(shadowsocksOverview, /2022-blake3-aes-256-gcm/);
  assert.match(shadowsocksOverview, /协议层加密（无 TLS\/Reality）/);
  assert.match(shadowsocksOverview, /兼容协议，固定 Xray 核心已标记 deprecated；新节点优先使用 VLESS\/Trojan/);
  assert.doesNotMatch(shadowsocksOverview, />Reality<|Reality 公钥|Reality 目标/);
  assert.match(shadowsocksAccounts, /Shadowsocks Phone/);
  assert.match(shadowsocksAccounts, /Shadowsocks 密钥：已配置（隐藏）/);
  assert.match(shadowsocksAccounts, /添加账户/);
  assert.doesNotMatch(shadowsocksAccounts, /Password：|UUID：|forwardx-access-safe/);
});

test("mKCP TLS detail labels its UDP listener and managed certificate without advanced fields", () => {
  const mkcp = {
    ...detail,
    inbound: {
      ...detail.inbound,
      profileId: "VLESS_MKCP_TLS",
      protocol: "vless",
      transport: "kcp",
      security: "tls",
      listenerNetworks: ["UDP"],
      tlsCertificate: { id: 12, name: "Edge TLS", configured: true },
      realityTargetHost: "",
      realityServerName: "tls.example.com",
      realityPublicKey: "",
      hasRealityPrivateKey: false,
    },
    host: { ...detail.host, isOnline: true },
    deployment: { ...detail.deployment, status: "RUNNING", configInSync: true },
    runtime: {
      serviceStatus: "RUNNING",
      installedVersion: "v26.3.27",
      runningVersion: "v26.3.27",
      processId: 123,
      reportedAt: new Date("2026-09-01T00:00:00Z"),
      listeners: [{ runtimeTag: "inbound-8", network: "udp", port: 443, status: "READY", errorCode: null }],
      lastErrorCode: null,
      lastErrorMessage: null,
    },
  };
  const overview = renderToStaticMarkup(
    <XrayInboundDetailContent detail={mkcp as never} runtime={null} busy={false} {...callbacks} />,
  );
  const runtime = renderToStaticMarkup(
    <XrayInboundDetailContent detail={mkcp as never} runtime={null} busy={false} defaultTab="runtime" {...callbacks} />,
  );
  assert.match(overview, /VLESS · mKCP · TLS/);
  assert.match(overview, /监听网络[\s\S]*UDP/);
  assert.match(overview, /TLS 证书[\s\S]*Edge TLS/);
  assert.match(overview, /TLS SNI[\s\S]*tls\.example\.com/);
  assert.match(runtime, /UDP 443\/READY/);
  assert.doesNotMatch(overview + runtime, /seed|headerType|FinalMask|privateKey|certificatePem|MTU|TTI/i);
});

test("WireGuard detail shows peer addresses and fixed safety boundaries without key material", () => {
  const wireGuard = {
    ...detail,
    inbound: {
      ...detail.inbound,
      name: "WireGuard edge",
      protocol: "wireguard",
      transport: "none",
      security: "none",
      profileId: "WIREGUARD_UDP_NONE",
      advisoryCode: "WIREGUARD_BLOCKING_RISK",
      listenerNetworks: ["UDP"],
      realityTargetHost: "",
      realityServerName: "",
      realityPublicKey: "",
      hasRealityPrivateKey: false,
    },
    clients: [],
    accessEntries: [{
      id: 61,
      inboundId: 8,
      legacyClientId: null,
      name: "phone",
      credentialType: "WIREGUARD_PEER",
      settings: { credentialType: "WIREGUARD_PEER", schemaVersion: 2, address: "10.0.0.2/32" },
      statsKey: "forwardx-wireguard-hidden",
      ownerUserId: null,
      isEnabled: true,
      pendingDelete: false,
      desiredGeneration: 4,
      sortOrder: 0,
      createdAt: 1,
      updatedAt: 1,
      secretStatus: { requiredConfigured: true, configuredKinds: ["PRE_SHARED_KEY", "PRIVATE_KEY"] },
    }],
  };
  const overview = renderToStaticMarkup(
    <XrayInboundDetailContent detail={wireGuard as never} runtime={null} busy={false} {...callbacks} />,
  );
  const peers = renderToStaticMarkup(
    <XrayInboundDetailContent detail={wireGuard as never} runtime={null} busy={false} defaultTab="clients" {...callbacks} />,
  );
  for (const text of ["Xray 内置 / UDP / 无 TLS", "gVisor · IPv4 · MTU 1420 · 10.0.0.0/24", "WireGuard 外层特征明显，可能被识别或封锁"]) {
    assert.match(overview, new RegExp(text));
  }
  for (const text of ["Peers", "phone", "10.0.0.2/32", "已启用", "待同步", "凭据已配置（隐藏）", "添加 peer", "配置 / QR"]) {
    assert.match(peers, new RegExp(text));
  }
  assert.doesNotMatch(overview + peers, /forwardx-wireguard-hidden|PresharedKey|PrivateKey|PublicKey|keyVersion|encryptedValue/);
});

test("Shadowsocks dual-network detail shows both same-port listeners without secrets", () => {
  const shadowsocks = {
    ...detail,
    inbound: {
      ...detail.inbound,
      profileId: "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE",
      protocol: "shadowsocks",
      transport: "tcp",
      security: "none",
      listenerNetworks: ["TCP", "UDP"],
      realityTargetHost: "",
      realityServerName: "",
      realityPublicKey: "",
      hasRealityPrivateKey: false,
    },
    host: { ...detail.host, isOnline: true },
    deployment: { ...detail.deployment, status: "RUNNING", configInSync: true },
    runtime: {
      serviceStatus: "RUNNING",
      installedVersion: "v26.3.27",
      runningVersion: "v26.3.27",
      processId: 123,
      reportedAt: new Date("2026-09-01T00:00:00Z"),
      listeners: [
        { runtimeTag: "inbound-8", network: "tcp", port: 443, status: "READY", errorCode: null },
        { runtimeTag: "inbound-8", network: "udp", port: 443, status: "READY", errorCode: null },
      ],
      lastErrorCode: null,
      lastErrorMessage: null,
    },
  };
  const overview = renderToStaticMarkup(
    <XrayInboundDetailContent detail={shadowsocks as never} runtime={null} busy={false} {...callbacks} />,
  );
  const runtime = renderToStaticMarkup(
    <XrayInboundDetailContent detail={shadowsocks as never} runtime={null} busy={false} defaultTab="runtime" {...callbacks} />,
  );
  assert.match(overview, /监听网络[\s\S]*TCP \/ UDP/);
  assert.match(overview, /2022-blake3-aes-256-gcm/);
  assert.match(runtime, /TCP 443\/READY · UDP 443\/READY/);
  assert.doesNotMatch(overview + runtime, /privateKey|SHADOWSOCKS_KEY|password/i);
});

test("Hysteria 2 detail exposes fixed UDP/TLS semantics and hides auth", () => {
  const hysteria = {
    ...detail,
    inbound: {
      ...detail.inbound,
      profileId: "HYSTERIA2_TLS",
      protocol: "hysteria",
      transport: "hysteria",
      security: "tls",
      listenerNetworks: ["UDP"],
      tlsCertificate: { id: 12, name: "Edge TLS", configured: true },
      realityTargetHost: "",
      realityServerName: "tls.example.com",
      realityPublicKey: "",
      hasRealityPrivateKey: false,
    },
    clients: [],
    accessEntries: [{
      id: 34,
      inboundId: 8,
      legacyClientId: null,
      name: "Hysteria Phone",
      credentialType: "HYSTERIA_AUTH",
      settings: { credentialType: "HYSTERIA_AUTH", schemaVersion: 1 },
      statsKey: "forwardx-hysteria-hidden",
      ownerUserId: null,
      isEnabled: true,
      pendingDelete: false,
      desiredGeneration: 4,
      sortOrder: 0,
      createdAt: 1,
      updatedAt: 1,
      secretStatus: { requiredConfigured: true, configuredKinds: ["HYSTERIA_AUTH"] },
    }],
    host: { ...detail.host, isOnline: true },
  };
  const overview = renderToStaticMarkup(
    <XrayInboundDetailContent detail={hysteria as never} runtime={null} busy={false} {...callbacks} />,
  );
  const accounts = renderToStaticMarkup(
    <XrayInboundDetailContent detail={hysteria as never} runtime={null} busy={false} defaultTab="clients" {...callbacks} />,
  );
  for (const text of ["Hysteria 2 · Hysteria · TLS", "UDP", "版本 2", "ALPN h3", "UDP 空闲 60 秒", "pinSHA256", "不关闭证书校验"]) {
    assert.match(overview, new RegExp(text));
  }
  assert.match(accounts, /Hysteria Phone/);
  assert.match(accounts, /Hysteria auth：已配置（隐藏）/);
  assert.doesNotMatch(overview + accounts, /forwardx-hysteria-hidden|privateKey|certificatePem|auth[^：]/i);
});

test("Mixed detail shows dual proxy semantics and only hidden credential status", () => {
  const mixed = {
    ...detail,
    inbound: {
      ...detail.inbound,
      name: "Mixed edge",
      profileId: "MIXED_RAW_NONE",
      protocol: "mixed",
      transport: "tcp",
      security: "none",
      advisoryCode: "PLAINTEXT_MIXED_AUTH_RISK",
      listenerNetworks: ["TCP"],
      realityTargetHost: "",
      realityServerName: "",
      realityPublicKey: "",
      hasRealityPrivateKey: false,
    },
    clients: [],
    accessEntries: [{
      id: 71,
      inboundId: 8,
      legacyClientId: null,
      name: "operator",
      credentialType: "MIXED_USER_PASSWORD",
      settings: { credentialType: "MIXED_USER_PASSWORD", schemaVersion: 1 },
      statsKey: "forwardx-mixed-hidden",
      ownerUserId: null,
      isEnabled: true,
      pendingDelete: false,
      desiredGeneration: 4,
      sortOrder: 0,
      createdAt: 1,
      updatedAt: 1,
      secretStatus: { requiredConfigured: true, configuredKinds: ["USERNAME", "PASSWORD"] },
    }],
    host: { ...detail.host, isOnline: true },
  };
  const overview = renderToStaticMarkup(
    <XrayInboundDetailContent detail={mixed as never} runtime={null} busy={false} {...callbacks} />,
  );
  const accounts = renderToStaticMarkup(
    <XrayInboundDetailContent detail={mixed as never} runtime={null} busy={false} defaultTab="clients" {...callbacks} />,
  );
  for (const text of ["Mixed（SOCKS5 + HTTP）· RAW / TCP / 无 TLS", "SOCKS5 + HTTP/CONNECT · 共用端口", "仅 TCP · 无 SOCKS4/4a 与 UDP", "SOCKS5 用户名/密码和 HTTP Basic 凭据可能被链路观察者读取"]) {
    assert.equal(overview.includes(text), true, text);
  }
  for (const text of ["operator", "SOCKS5 / HTTP 共用用户名：已配置（隐藏） · 密码：已配置（隐藏）", "双代理地址 / QR"]) {
    assert.equal(accounts.includes(text), true, text);
  }
  assert.doesNotMatch(overview + accounts, /forwardx-mixed-hidden|user:password|encryptedValue|keyVersion/);
});
