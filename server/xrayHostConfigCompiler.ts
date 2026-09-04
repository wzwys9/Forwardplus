import crypto from "node:crypto";

import {
  buildXrayExternalProxyUri,
  parseXrayExternalProxyUri,
  type XrayExternalProxyDefinition,
} from "../shared/xrayExternalProxy";
import { XRAY_LIMITS } from "../shared/xrayTypes";
import { XRAY_DEFAULT_VERSION } from "./xrayArtifacts";
import {
  invalidXrayConfig,
  normalizeXrayInbound,
  type NormalizedXrayInbound,
  type XrayConfigInboundInput,
} from "./xrayProfileCompiler";
import { compileXrayProtocol } from "./xrayProtocolCompiler";
import { compileXrayTransportSecurity } from "./xrayTransportSecurityCompiler";

export type XrayGeneratedConfig = {
  targetVersion: typeof XRAY_DEFAULT_VERSION;
  configJson: string;
  configHash: string;
  expectedListeners: Array<{
    inboundId: number;
    runtimeTag: string;
    network: "tcp" | "udp";
    listenAddress: string;
    port: number;
  }>;
};

export type XrayExternalProxyBindingInput = Readonly<{
  inboundId: number;
  nodeTag: string;
  definition: XrayExternalProxyDefinition;
}>;

function asciiCompare(left: string, right: string) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function listenerNetworks(inbound: NormalizedXrayInbound): Array<"tcp" | "udp"> {
  return inbound.profile.listenerNetworks.map((network) => {
    if (network === "TCP") return "tcp";
    if (network === "UDP") return "udp";
    invalidXrayConfig();
  });
}

function assertUniqueHostResources(inbounds: readonly NormalizedXrayInbound[]) {
  const inboundIds = new Set<number>();
  const runtimeTags = new Set<string>();
  const listeners = new Set<string>();
  const globalUuids = new Set<string>();
  const globalPasswords = new Set<string>();
  const globalShadowsocksKeys = new Set<string>();
  const globalHysteriaAuths = new Set<string>();
  const globalWireGuardKeys = new Set<string>();
  const globalWireGuardPreSharedKeys = new Set<string>();
  const globalHttpUsernames = new Set<string>();
  const globalStatsKeys = new Set<string>();
  for (const inbound of inbounds) {
    if (inboundIds.has(inbound.id) || runtimeTags.has(inbound.runtimeTag)) invalidXrayConfig();
    inboundIds.add(inbound.id);
    runtimeTags.add(inbound.runtimeTag);
    for (const network of listenerNetworks(inbound)) {
      const listener = `${network}:${inbound.listenPort}`;
      if (listeners.has(listener)) invalidXrayConfig();
      listeners.add(listener);
    }
    if (inbound.security === "NONE") {
      if ("shadowsocksServerKey" in inbound) {
        if (globalShadowsocksKeys.has(inbound.shadowsocksServerKey)) invalidXrayConfig();
        globalShadowsocksKeys.add(inbound.shadowsocksServerKey);
      } else if ("wireguardServerPrivateKey" in inbound) {
        if (globalWireGuardKeys.has(inbound.wireguardServerPrivateKey)) invalidXrayConfig();
        globalWireGuardKeys.add(inbound.wireguardServerPrivateKey);
      }
    }
    for (const client of inbound.clients) {
      const credentialDuplicate = client.credentialType === "PASSWORD"
        ? globalPasswords.has(client.password)
        : client.credentialType === "SHADOWSOCKS_KEY"
          ? globalShadowsocksKeys.has(client.shadowsocksKey)
          : client.credentialType === "HYSTERIA_AUTH"
            ? globalHysteriaAuths.has(client.auth)
            : client.credentialType === "WIREGUARD_PEER"
              ? globalWireGuardKeys.has(client.privateKey) || globalWireGuardPreSharedKeys.has(client.preSharedKey)
              : client.credentialType === "HTTP_BASIC" || client.credentialType === "MIXED_USER_PASSWORD"
                ? globalHttpUsernames.has(client.username) || globalPasswords.has(client.password)
              : globalUuids.has(client.uuid);
      if (credentialDuplicate || globalStatsKeys.has(client.statsKey)) invalidXrayConfig();
      if (client.credentialType === "PASSWORD") globalPasswords.add(client.password);
      else if (client.credentialType === "SHADOWSOCKS_KEY") globalShadowsocksKeys.add(client.shadowsocksKey);
      else if (client.credentialType === "HYSTERIA_AUTH") globalHysteriaAuths.add(client.auth);
      else if (client.credentialType === "WIREGUARD_PEER") {
        globalWireGuardKeys.add(client.privateKey);
        globalWireGuardPreSharedKeys.add(client.preSharedKey);
      }
      else if (client.credentialType === "HTTP_BASIC" || client.credentialType === "MIXED_USER_PASSWORD") {
        globalHttpUsernames.add(client.username);
        globalPasswords.add(client.password);
      }
      else globalUuids.add(client.uuid);
      globalStatsKeys.add(client.statsKey);
    }
  }
}

function compileExternalProxyOutbound(binding: XrayExternalProxyBindingInput) {
  if (!/^forwardx-external-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(binding.nodeTag)) {
    invalidXrayConfig();
  }
  let definition: XrayExternalProxyDefinition;
  try {
    definition = parseXrayExternalProxyUri(buildXrayExternalProxyUri(binding.definition));
  } catch {
    invalidXrayConfig();
  }
  if (definition!.protocol === "VLESS_REALITY_VISION") {
    return {
      tag: binding.nodeTag,
      protocol: "vless",
      settings: {
        vnext: [{
          address: definition!.address,
          port: definition!.port,
          users: [{ id: definition!.credentials.uuid, encryption: "none", flow: "xtls-rprx-vision" }],
        }],
      },
      streamSettings: {
        network: "tcp",
        security: "reality",
        realitySettings: {
          serverName: definition!.spec.serverName,
          fingerprint: definition!.spec.fingerprint,
          publicKey: definition!.spec.publicKey,
          shortId: definition!.credentials.shortId,
          spiderX: definition!.spec.spiderX,
        },
      },
    };
  }
  if (definition!.protocol === "SHADOWSOCKS") {
    return {
      tag: binding.nodeTag,
      protocol: "shadowsocks",
      settings: {
        servers: [{
          address: definition!.address,
          port: definition!.port,
          method: definition!.spec.method,
          password: definition!.credentials.password,
        }],
      },
    };
  }
  return {
    tag: binding.nodeTag,
    protocol: "socks",
    settings: {
      servers: [{
        address: definition!.address,
        port: definition!.port,
        ...(definition!.credentials.username === undefined ? {} : {
          users: [{ user: definition!.credentials.username, pass: definition!.credentials.password }],
        }),
      }],
    },
  };
}

export function generateDeterministicXrayConfig(
  input: readonly XrayConfigInboundInput[],
  externalProxyBindings: readonly XrayExternalProxyBindingInput[] = [],
): XrayGeneratedConfig {
  if (!Array.isArray(input) || !Array.isArray(externalProxyBindings)) invalidXrayConfig();
  const inbounds = input
    .filter((inbound) => inbound.isEnabled && !inbound.pendingDelete)
    .map(normalizeXrayInbound)
    .sort((left, right) => asciiCompare(left.runtimeTag, right.runtimeTag) || left.id - right.id);
  assertUniqueHostResources(inbounds);

  const activeById = new Map(inbounds.map((inbound) => [inbound.id, inbound]));
  const bindingByInboundId = new Map<number, XrayExternalProxyBindingInput>();
  const outboundByTag = new Map<string, ReturnType<typeof compileExternalProxyOutbound>>();
  for (const binding of externalProxyBindings) {
    if (!binding || !Number.isSafeInteger(binding.inboundId) || binding.inboundId <= 0
      || bindingByInboundId.has(binding.inboundId)) invalidXrayConfig();
    const inbound = activeById.get(binding.inboundId);
    if (!inbound || inbound.profile.id === "TUNNEL_TCP_LOCAL_NONE"
      || listenerNetworks(inbound).length !== 1 || listenerNetworks(inbound)[0] !== "tcp") invalidXrayConfig();
    const outbound = compileExternalProxyOutbound(binding);
    const existing = outboundByTag.get(binding.nodeTag);
    if (existing && JSON.stringify(existing) !== JSON.stringify(outbound)) invalidXrayConfig();
    outboundByTag.set(binding.nodeTag, outbound);
    bindingByInboundId.set(binding.inboundId, binding);
  }

  const externalOutbounds = [...outboundByTag.values()].sort((left, right) => asciiCompare(left.tag, right.tag));
  const routingRules = [...bindingByInboundId.entries()]
    .map(([inboundId, binding]) => ({ inbound: activeById.get(inboundId)!, binding }))
    .sort((left, right) => asciiCompare(left.inbound.runtimeTag, right.inbound.runtimeTag) || left.inbound.id - right.inbound.id)
    .map(({ inbound, binding }) => ({
      type: "field",
      inboundTag: [inbound.runtimeTag],
      outboundTag: binding.nodeTag,
    }));

  const config = {
    log: { loglevel: "warning" },
    inbounds: inbounds.map((inbound) => ({
      tag: inbound.runtimeTag,
      listen: inbound.listenAddress,
      port: inbound.listenPort,
      ...compileXrayProtocol(inbound),
      streamSettings: compileXrayTransportSecurity(inbound),
    })),
    outbounds: [{ tag: "direct", protocol: "freedom" }, ...externalOutbounds],
    ...(routingRules.length === 0 ? {} : { routing: { rules: routingRules } }),
  };
  const configJson = `${JSON.stringify(config, null, 2)}\n`;
  if (Buffer.byteLength(configJson, "utf8") > XRAY_LIMITS.maxConfigJsonBytes) invalidXrayConfig();
  return {
    targetVersion: XRAY_DEFAULT_VERSION,
    configJson,
    configHash: crypto.createHash("sha256").update(configJson, "utf8").digest("hex"),
    expectedListeners: inbounds.flatMap((inbound) => listenerNetworks(inbound).map((network) => ({
      inboundId: inbound.id,
      runtimeTag: inbound.runtimeTag,
      network,
      listenAddress: inbound.listenAddress,
      port: inbound.listenPort,
    }))),
  };
}
