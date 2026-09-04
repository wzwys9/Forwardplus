import { quoteIdentifier } from "./dbCompat";
import { queryRaw } from "./dbRuntime";
import { resolveStoredXrayInboundDefinition } from "../shared/xrayProfiles";
import {
  generateDeterministicXrayConfig,
  type XrayExternalProxyBindingInput,
  type XrayGeneratedConfig,
} from "./xrayHostConfigCompiler";
import { loadXrayExternalProxyMaterial } from "./xrayExternalProxyService";
import {
  loadLegacyVlessAccessEntriesByHost,
  verifiedLegacyRealityPrivateKeyEnvelope,
} from "./xrayLegacyAccessProjection";
import { loadGenericPasswordAccessEntriesByHost } from "./xrayGenericAccessProjection";
import { loadGenericUuidAccessEntriesByHost } from "./xrayGenericUuidAccessProjection";
import {
  loadShadowsocksAccessEntriesByHost,
  loadShadowsocksServerKeyByInboundId,
} from "./xrayShadowsocksAccessProjection";
import { loadHysteriaAccessEntriesByHost } from "./xrayHysteriaAccessProjection";
import {
  loadHttpBasicAccessEntriesByHost,
  loadMixedUserPasswordAccessEntriesByHost,
} from "./xrayHttpAccessProjection";
import {
  loadWireGuardAccessEntriesByHost,
  loadWireGuardServerPrivateKeyByInboundId,
} from "./xrayWireGuardAccessProjection";
import {
  getXrayTlsCertificateLocation,
  getXrayTlsCertificateMaterial,
} from "./repositories/xrayTlsCertificateRepository";
import {
  invalidXrayConfig,
  positiveXrayId,
  type XrayConfigClientInput,
  type XrayConfigInboundInput,
} from "./xrayProfileCompiler";
import {
  decryptXraySecret,
  fingerprintXraySecret,
  loadXrayMasterKeyFile,
  xrayAccessSecretContext,
  xrayClientShortIdContext,
  xrayClientUuidContext,
  xrayInboundPrivateKeyContext,
  xrayInboundSecretContext,
  XraySecretUnavailableError,
  type XraySecretKeyring,
} from "./xraySecretCrypto";

export {
  XrayConfigGenerationError,
  type XrayConfigClientInput,
  type XrayConfigInboundInput,
} from "./xrayProfileCompiler";
export {
  generateDeterministicXrayConfig,
  type XrayExternalProxyBindingInput,
  type XrayGeneratedConfig,
} from "./xrayHostConfigCompiler";
export { xrayClientShortIdContext, xrayClientUuidContext, xrayInboundPrivateKeyContext };

function databaseBoolean(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || String(value ?? "").toLowerCase() === "true";
}

async function assertCredentiallessTunnelRows(inboundIds: readonly number[]) {
  const q = quoteIdentifier;
  for (const inboundId of inboundIds) {
    const rows = await queryRaw<Record<string, unknown>>(
      `SELECT
        (SELECT COUNT(*) FROM ${q("xray_clients")} WHERE ${q("inboundId")} = ?) AS ${q("clientCount")},
        (SELECT COUNT(*) FROM ${q("xray_access_entries")} WHERE ${q("inboundId")} = ?) AS ${q("accessCount")},
        (SELECT COUNT(*) FROM ${q("xray_inbound_secrets")} WHERE ${q("inboundId")} = ?) AS ${q("secretCount")}`,
      [inboundId, inboundId, inboundId],
    );
    const row = rows[0];
    if (!row || Number(row.clientCount) !== 0 || Number(row.accessCount) !== 0 || Number(row.secretCount) !== 0) {
      invalidXrayConfig();
    }
  }
}

export async function generateXrayHostConfig(hostIdValue: unknown, keyring?: XraySecretKeyring): Promise<XrayGeneratedConfig> {
  const hostId = positiveXrayId(hostIdValue);
  let resolvedKeyring = keyring;
  const requireKeyring = () => {
    resolvedKeyring ??= loadXrayMasterKeyFile();
    return resolvedKeyring;
  };
  const q = quoteIdentifier;
  const inboundColumns = [
    "id", "runtimeTag", "publicAddress", "listenAddress", "listenPort", "protocol", "transport", "security", "profileId", "specVersion", "specJson", "realityTargetHost",
    "realityTargetPort", "realityServerName", "realityPrivateKeyEncrypted", "tlsCertificateId", "externalProxyNodeId", "isEnabled", "pendingDelete",
  ].map((column) => q(column)).join(", ");
  const inboundRows = await queryRaw<Record<string, unknown>>(
    `SELECT ${inboundColumns} FROM ${q("xray_inbounds")} WHERE ${q("hostId")} = ? ORDER BY ${q("runtimeTag")} ASC, ${q("id")} ASC`,
    [hostId],
  );
  const activeRows = inboundRows.filter((row) => databaseBoolean(row.isEnabled) && !databaseBoolean(row.pendingDelete));
  const activeIds = new Set(activeRows.map((row) => positiveXrayId(row.id)));
  const tunnelIds = activeRows.filter((row) => row.profileId === "TUNNEL_TCP_LOCAL_NONE").map((row) => positiveXrayId(row.id));
  await assertCredentiallessTunnelRows(tunnelIds);
  const clientRows = activeIds.size === 0 ? [] : await loadLegacyVlessAccessEntriesByHost(hostId);
  const genericPasswordAccessRows = activeIds.size === 0 ? [] : await loadGenericPasswordAccessEntriesByHost(hostId);
  const genericUuidAccessRows = activeIds.size === 0 ? [] : await loadGenericUuidAccessEntriesByHost(hostId);
  const shadowsocksAccessRows = activeIds.size === 0 ? [] : await loadShadowsocksAccessEntriesByHost(hostId);
  const hysteriaAccessRows = activeIds.size === 0 ? [] : await loadHysteriaAccessEntriesByHost(hostId);
  const wireguardAccessRows = activeIds.size === 0 ? [] : await loadWireGuardAccessEntriesByHost(hostId);
  const httpAccessRows = activeIds.size === 0 ? [] : await loadHttpBasicAccessEntriesByHost(hostId);
  const mixedAccessRows = activeIds.size === 0 ? [] : await loadMixedUserPasswordAccessEntriesByHost(hostId);
  const clientsByInbound = new Map<number, XrayConfigClientInput[]>();
  for (const row of clientRows) {
    const inboundId = row.inboundId;
    if (!activeIds.has(inboundId) || !row.isEnabled || row.pendingDelete) continue;
    const statsKey = row.statsKey;
    const client: XrayConfigClientInput = {
      id: row.clientId,
      uuid: decryptXraySecret(row.uuidEncrypted, xrayClientUuidContext(statsKey), requireKeyring()),
      shortId: decryptXraySecret(row.shortIdEncrypted, xrayClientShortIdContext(statsKey), requireKeyring()),
      statsKey,
      flow: row.flow,
      isEnabled: true,
      pendingDelete: false,
      sortOrder: row.sortOrder,
    };
    const clients = clientsByInbound.get(inboundId) ?? [];
    clients.push(client);
    clientsByInbound.set(inboundId, clients);
  }
  for (const row of genericPasswordAccessRows) {
    const inboundId = row.inboundId;
    if (!activeIds.has(inboundId) || !row.isEnabled || row.pendingDelete) continue;
    const passwordContext = xrayAccessSecretContext(row.statsKey, "PASSWORD");
    const password = decryptXraySecret(row.passwordEncrypted, passwordContext, requireKeyring());
    if (fingerprintXraySecret(password, passwordContext, requireKeyring()) !== row.passwordFingerprint) {
      throw new XraySecretUnavailableError();
    }
    const base = {
      id: row.accessEntryId,
      password,
      statsKey: row.statsKey,
      isEnabled: true,
      pendingDelete: false,
      sortOrder: row.sortOrder,
    };
    let client: XrayConfigClientInput;
    if (row.profileId === "TROJAN_RAW_REALITY") {
      const shortIdContext = xrayAccessSecretContext(row.statsKey, "SHORT_ID");
      const shortId = decryptXraySecret(row.shortIdEncrypted, shortIdContext, requireKeyring());
      if (fingerprintXraySecret(shortId, shortIdContext, requireKeyring()) !== row.shortIdFingerprint) {
        throw new XraySecretUnavailableError();
      }
      client = { ...base, credentialType: "PASSWORD", shortId };
    } else {
      client = { ...base, credentialType: "PASSWORD" };
    }
    const clients = clientsByInbound.get(inboundId) ?? [];
    clients.push(client);
    clientsByInbound.set(inboundId, clients);
  }
  for (const row of genericUuidAccessRows) {
    const inboundId = row.inboundId;
    if (!activeIds.has(inboundId) || !row.isEnabled || row.pendingDelete) continue;
    const uuidContext = xrayAccessSecretContext(row.statsKey, "UUID");
    const uuid = decryptXraySecret(row.uuidEncrypted, uuidContext, requireKeyring());
    if (fingerprintXraySecret(uuid, uuidContext, requireKeyring()) !== row.uuidFingerprint) {
      throw new XraySecretUnavailableError();
    }
    const client: XrayConfigClientInput = {
      id: row.accessEntryId,
      credentialType: "UUID",
      uuid,
      flow: row.flow,
      statsKey: row.statsKey,
      isEnabled: true,
      pendingDelete: false,
      sortOrder: row.sortOrder,
    };
    const clients = clientsByInbound.get(inboundId) ?? [];
    clients.push(client);
    clientsByInbound.set(inboundId, clients);
  }
  for (const row of shadowsocksAccessRows) {
    const inboundId = row.inboundId;
    if (!activeIds.has(inboundId) || !row.isEnabled || row.pendingDelete) continue;
    const userKeyContext = xrayAccessSecretContext(row.statsKey, "SHADOWSOCKS_KEY");
    const shadowsocksKey = decryptXraySecret(row.userKeyEncrypted, userKeyContext, requireKeyring());
    if (fingerprintXraySecret(shadowsocksKey, userKeyContext, requireKeyring()) !== row.userKeyFingerprint) {
      throw new XraySecretUnavailableError();
    }
    const client: XrayConfigClientInput = {
      id: row.accessEntryId,
      credentialType: "SHADOWSOCKS_KEY",
      shadowsocksKey,
      statsKey: row.statsKey,
      isEnabled: true,
      pendingDelete: false,
      sortOrder: row.sortOrder,
    };
    const clients = clientsByInbound.get(inboundId) ?? [];
    clients.push(client);
    clientsByInbound.set(inboundId, clients);
  }
  for (const row of hysteriaAccessRows) {
    const inboundId = row.inboundId;
    if (!activeIds.has(inboundId) || !row.isEnabled || row.pendingDelete) continue;
    const authContext = xrayAccessSecretContext(row.statsKey, "HYSTERIA_AUTH");
    const auth = decryptXraySecret(row.authEncrypted, authContext, requireKeyring());
    if (fingerprintXraySecret(auth, authContext, requireKeyring()) !== row.authFingerprint) {
      throw new XraySecretUnavailableError();
    }
    const client: XrayConfigClientInput = {
      id: row.accessEntryId,
      credentialType: "HYSTERIA_AUTH",
      auth,
      statsKey: row.statsKey,
      isEnabled: true,
      pendingDelete: false,
      sortOrder: row.sortOrder,
    };
    const clients = clientsByInbound.get(inboundId) ?? [];
    clients.push(client);
    clientsByInbound.set(inboundId, clients);
  }
  for (const row of wireguardAccessRows) {
    const inboundId = row.inboundId;
    if (!activeIds.has(inboundId) || !row.isEnabled || row.pendingDelete) continue;
    const privateKeyContext = xrayAccessSecretContext(row.statsKey, "PRIVATE_KEY");
    const preSharedKeyContext = xrayAccessSecretContext(row.statsKey, "PRE_SHARED_KEY");
    const privateKey = decryptXraySecret(row.privateKeyEncrypted, privateKeyContext, requireKeyring());
    const preSharedKey = decryptXraySecret(row.preSharedKeyEncrypted, preSharedKeyContext, requireKeyring());
    if (fingerprintXraySecret(privateKey, privateKeyContext, requireKeyring()) !== row.privateKeyFingerprint
      || fingerprintXraySecret(preSharedKey, preSharedKeyContext, requireKeyring()) !== row.preSharedKeyFingerprint) {
      throw new XraySecretUnavailableError();
    }
    const client: XrayConfigClientInput = {
      id: row.accessEntryId,
      credentialType: "WIREGUARD_PEER",
      privateKey,
      preSharedKey,
      address: row.address,
      statsKey: row.statsKey,
      isEnabled: true,
      pendingDelete: false,
      sortOrder: row.sortOrder,
    };
    const clients = clientsByInbound.get(inboundId) ?? [];
    clients.push(client);
    clientsByInbound.set(inboundId, clients);
  }
  for (const row of httpAccessRows) {
    const inboundId = row.inboundId;
    if (!activeIds.has(inboundId) || !row.isEnabled || row.pendingDelete) continue;
    const usernameContext = xrayAccessSecretContext(row.statsKey, "USERNAME");
    const passwordContext = xrayAccessSecretContext(row.statsKey, "PASSWORD");
    const username = decryptXraySecret(row.usernameEncrypted, usernameContext, requireKeyring());
    const password = decryptXraySecret(row.passwordEncrypted, passwordContext, requireKeyring());
    if (fingerprintXraySecret(username, usernameContext, requireKeyring()) !== row.usernameFingerprint
      || fingerprintXraySecret(password, passwordContext, requireKeyring()) !== row.passwordFingerprint) {
      throw new XraySecretUnavailableError();
    }
    const client: XrayConfigClientInput = {
      id: row.accessEntryId,
      credentialType: "HTTP_BASIC",
      username,
      password,
      statsKey: row.statsKey,
      isEnabled: true,
      pendingDelete: false,
      sortOrder: row.sortOrder,
    };
    const clients = clientsByInbound.get(inboundId) ?? [];
    clients.push(client);
    clientsByInbound.set(inboundId, clients);
  }
  for (const row of mixedAccessRows) {
    const inboundId = row.inboundId;
    if (!activeIds.has(inboundId) || !row.isEnabled || row.pendingDelete) continue;
    const usernameContext = xrayAccessSecretContext(row.statsKey, "USERNAME");
    const passwordContext = xrayAccessSecretContext(row.statsKey, "PASSWORD");
    const username = decryptXraySecret(row.usernameEncrypted, usernameContext, requireKeyring());
    const password = decryptXraySecret(row.passwordEncrypted, passwordContext, requireKeyring());
    if (fingerprintXraySecret(username, usernameContext, requireKeyring()) !== row.usernameFingerprint
      || fingerprintXraySecret(password, passwordContext, requireKeyring()) !== row.passwordFingerprint) {
      throw new XraySecretUnavailableError();
    }
    const client: XrayConfigClientInput = {
      id: row.accessEntryId,
      credentialType: "MIXED_USER_PASSWORD",
      username,
      password,
      statsKey: row.statsKey,
      isEnabled: true,
      pendingDelete: false,
      sortOrder: row.sortOrder,
    };
    const clients = clientsByInbound.get(inboundId) ?? [];
    clients.push(client);
    clientsByInbound.set(inboundId, clients);
  }

  const input = await Promise.all(activeRows.map(async (row): Promise<XrayConfigInboundInput> => {
    const id = positiveXrayId(row.id);
    const runtimeTag = String(row.runtimeTag ?? "");
    const security = String(row.security ?? "");
    const definition = resolveStoredXrayInboundDefinition({
      protocol: row.protocol,
      transport: row.transport,
      security: row.security,
      profileId: row.profileId,
      specVersion: row.specVersion,
      specJson: row.specJson,
    });
    if (!definition) invalidXrayConfig();
    const base = {
      id,
      runtimeTag,
      listenAddress: String(row.listenAddress ?? ""),
      listenPort: Number(row.listenPort),
      protocol: String(row.protocol ?? ""),
      transport: String(row.transport ?? ""),
      profileId: row.profileId,
      specVersion: row.specVersion,
      specJson: row.specJson,
      isEnabled: true as const,
      pendingDelete: false as const,
      clients: clientsByInbound.get(id) ?? [],
    };
    if (definition.profile.security === "TLS") {
      if (security !== "tls"
        || (definition.profile.id !== "VLESS_RAW_TLS"
          && definition.profile.id !== "VLESS_RAW_TLS_VISION"
          && definition.profile.id !== "VMESS_RAW_TLS"
          && definition.profile.id !== "TROJAN_RAW_TLS"
          && definition.profile.id !== "VLESS_WEBSOCKET_TLS"
          && definition.profile.id !== "TROJAN_WEBSOCKET_TLS"
          && definition.profile.id !== "VLESS_GRPC_TLS"
          && definition.profile.id !== "TROJAN_GRPC_TLS"
          && definition.profile.id !== "VLESS_HTTP_UPGRADE_TLS"
          && definition.profile.id !== "TROJAN_HTTP_UPGRADE_TLS"
          && definition.profile.id !== "VLESS_XHTTP_TLS"
          && definition.profile.id !== "TROJAN_XHTTP_TLS"
          && definition.profile.id !== "VLESS_MKCP_TLS"
          && definition.profile.id !== "TROJAN_MKCP_TLS"
          && definition.profile.id !== "HYSTERIA2_TLS")) {
        invalidXrayConfig();
      }
      const certificateId = positiveXrayId(row.tlsCertificateId);
      const location = await getXrayTlsCertificateLocation(certificateId);
      if (location.hostId !== hostId) invalidXrayConfig();
      const certificate = await getXrayTlsCertificateMaterial(certificateId, {
        keyring: requireKeyring(),
      });
      if (certificate.hostId !== hostId) invalidXrayConfig();
      return {
        ...base,
        security: "tls",
        realityServerName: String(row.realityServerName ?? ""),
        tlsCertificateChainPem: certificate.certificateChainPem,
        tlsPrivateKeyPem: certificate.privateKeyPem,
      };
    }
    if (definition.profile.security === "NONE") {
      if (definition.profile.id === "HTTP_RAW_NONE" || definition.profile.id === "MIXED_RAW_NONE"
        || definition.profile.id === "TUNNEL_TCP_LOCAL_NONE") {
        if (security !== "none") invalidXrayConfig();
        if (definition.profile.id === "TUNNEL_TCP_LOCAL_NONE"
          && (row.publicAddress !== "127.0.0.1" || row.listenAddress !== "127.0.0.1" || row.tlsCertificateId !== null
            || String(row.realityTargetHost ?? "") !== "" || Number(row.realityTargetPort) !== 443
            || String(row.realityServerName ?? "") !== "" || String(row.realityPrivateKeyEncrypted ?? "") !== "")) {
          invalidXrayConfig();
        }
        return { ...base, security: "none" };
      }
      if (definition.profile.id === "WIREGUARD_UDP_NONE") {
        if (security !== "none") invalidXrayConfig();
        const serverSecret = await loadWireGuardServerPrivateKeyByInboundId(id);
        const serverContext = xrayInboundSecretContext(runtimeTag, "PRIVATE_KEY");
        const wireguardServerPrivateKey = decryptXraySecret(
          serverSecret.encryptedValue,
          serverContext,
          requireKeyring(),
        );
        if (fingerprintXraySecret(wireguardServerPrivateKey, serverContext, requireKeyring()) !== serverSecret.fingerprint) {
          throw new XraySecretUnavailableError();
        }
        return { ...base, security: "none", wireguardServerPrivateKey };
      }
      if ((definition.profile.id !== "SHADOWSOCKS_2022_RAW_NONE"
          && definition.profile.id !== "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE")
        || security !== "none") invalidXrayConfig();
      const serverSecret = await loadShadowsocksServerKeyByInboundId(id);
      const serverKeyContext = xrayInboundSecretContext(runtimeTag, "SHADOWSOCKS_SERVER_KEY");
      const shadowsocksServerKey = decryptXraySecret(serverSecret.encryptedValue, serverKeyContext, requireKeyring());
      if (fingerprintXraySecret(shadowsocksServerKey, serverKeyContext, requireKeyring()) !== serverSecret.fingerprint) {
        throw new XraySecretUnavailableError();
      }
      return { ...base, security: "none", shadowsocksServerKey };
    }
    if (definition.profile.security !== "REALITY" || security !== "reality") invalidXrayConfig();
    return {
      ...base,
      security: "reality",
      realityServerName: String(row.realityServerName ?? ""),
      realityTargetHost: String(row.realityTargetHost ?? ""),
      realityTargetPort: Number(row.realityTargetPort),
      realityPrivateKey: decryptXraySecret(
        await verifiedLegacyRealityPrivateKeyEnvelope({
          inboundId: id,
          legacyEncryptedValue: row.realityPrivateKeyEncrypted,
        }),
        xrayInboundPrivateKeyContext(runtimeTag),
        requireKeyring(),
      ),
    };
  }));
  const externalProxyById = new Map<number, Awaited<ReturnType<typeof loadXrayExternalProxyMaterial>>>();
  const externalProxyBindings: XrayExternalProxyBindingInput[] = [];
  for (const row of activeRows) {
    if (row.externalProxyNodeId === null || row.externalProxyNodeId === undefined) continue;
    const externalProxyNodeId = positiveXrayId(row.externalProxyNodeId);
    let material = externalProxyById.get(externalProxyNodeId);
    if (!material) {
      material = await loadXrayExternalProxyMaterial(externalProxyNodeId, { keyring: requireKeyring() });
      externalProxyById.set(externalProxyNodeId, material);
    }
    externalProxyBindings.push({
      inboundId: positiveXrayId(row.id),
      nodeTag: material.nodeTag,
      definition: material.definition,
    });
  }
  return generateDeterministicXrayConfig(input, externalProxyBindings);
}
