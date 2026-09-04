import { invalidXrayConfig, type NormalizedXrayInbound } from "./xrayProfileCompiler";
import { deriveXrayWireGuardPublicKey } from "./xrayWireGuard";

export function compileXrayProtocol(inbound: NormalizedXrayInbound) {
  if (inbound.profile.id === "TUNNEL_TCP_LOCAL_NONE") {
    const targetAddress = inbound.spec.targetAddress;
    const targetPort = inbound.spec.targetPort;
    if (inbound.security !== "NONE" || !("tunnel" in inbound) || inbound.clients.length !== 0
      || typeof targetAddress !== "string" || typeof targetPort !== "number") {
      invalidXrayConfig();
    }
    return {
      protocol: "tunnel" as const,
      settings: {
        address: targetAddress,
        port: targetPort,
        network: "tcp" as const,
        followRedirect: false as const,
        userLevel: 0,
      },
    };
  }
  if (inbound.profile.id === "MIXED_RAW_NONE") {
    if (inbound.security !== "NONE" || inbound.clients.length < 1) invalidXrayConfig();
    return {
      protocol: "mixed" as const,
      settings: {
        auth: "password" as const,
        accounts: inbound.clients.map((client) => {
          if (client.credentialType !== "MIXED_USER_PASSWORD") invalidXrayConfig();
          return { user: client.username, pass: client.password };
        }),
        udp: false as const,
        userLevel: 0,
      },
    };
  }
  if (inbound.profile.id === "HTTP_RAW_NONE") {
    if (inbound.security !== "NONE" || inbound.clients.length < 1) invalidXrayConfig();
    return {
      protocol: "http" as const,
      settings: {
        accounts: inbound.clients.map((client) => {
          if (client.credentialType !== "HTTP_BASIC") invalidXrayConfig();
          return { user: client.username, pass: client.password };
        }),
        allowTransparent: false as const,
        userLevel: 0,
      },
    };
  }
  if (inbound.profile.id === "WIREGUARD_UDP_NONE") {
    if (inbound.security !== "NONE" || !("wireguardServerPrivateKey" in inbound) || inbound.clients.length < 1) {
      invalidXrayConfig();
    }
    return {
      protocol: "wireguard" as const,
      settings: {
        secretKey: inbound.wireguardServerPrivateKey,
        address: ["10.0.0.1/32"],
        peers: inbound.clients.map((client) => {
          if (client.credentialType !== "WIREGUARD_PEER") invalidXrayConfig();
          return {
            publicKey: deriveXrayWireGuardPublicKey(client.privateKey),
            preSharedKey: client.preSharedKey,
            allowedIPs: [client.address],
          };
        }),
        mtu: 1420,
        noKernelTun: true as const,
      },
    };
  }
  if (inbound.profile.id === "HYSTERIA2_TLS") {
    if (inbound.security !== "TLS" || inbound.clients.length < 1) invalidXrayConfig();
    return {
      protocol: "hysteria" as const,
      settings: {
        version: 2 as const,
        clients: inbound.clients.map((client) => {
          if (client.credentialType !== "HYSTERIA_AUTH") invalidXrayConfig();
          return { auth: client.auth, email: client.statsKey };
        }),
      },
    };
  }
  if (inbound.profile.id === "SHADOWSOCKS_2022_RAW_NONE"
    || inbound.profile.id === "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE") {
    if (inbound.security !== "NONE" || !("shadowsocksServerKey" in inbound) || inbound.clients.length < 1) {
      invalidXrayConfig();
    }
    return {
      protocol: "shadowsocks" as const,
      settings: {
        method: "2022-blake3-aes-256-gcm" as const,
        password: inbound.shadowsocksServerKey,
        network: inbound.profile.id === "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE" ? "tcp,udp" as const : "tcp" as const,
        clients: inbound.clients.map((client) => {
          if (client.credentialType !== "SHADOWSOCKS_KEY") invalidXrayConfig();
          return { password: client.shadowsocksKey, email: client.statsKey };
        }),
      },
    };
  }
  if (inbound.profile.id === "VMESS_RAW_TLS") {
    return {
      protocol: "vmess" as const,
      settings: {
        clients: inbound.clients.map((client) => {
          if (client.credentialType !== "UUID" || client.flow !== "") invalidXrayConfig();
          return { id: client.uuid, email: client.statsKey, security: "auto" as const };
        }),
      },
    };
  }
  if (inbound.profile.id === "TROJAN_RAW_REALITY"
    || inbound.profile.id === "TROJAN_RAW_TLS"
    || inbound.profile.id === "TROJAN_WEBSOCKET_TLS"
    || inbound.profile.id === "TROJAN_GRPC_TLS"
    || inbound.profile.id === "TROJAN_HTTP_UPGRADE_TLS"
    || inbound.profile.id === "TROJAN_XHTTP_TLS"
    || inbound.profile.id === "TROJAN_MKCP_TLS") {
    return {
      protocol: "trojan" as const,
      settings: {
        clients: inbound.clients.map((client) => {
          if (client.credentialType !== "PASSWORD") invalidXrayConfig();
          return { password: client.password, email: client.statsKey };
        }),
      },
    };
  }
  if (inbound.profile.id !== "VLESS_RAW_REALITY_VISION"
    && inbound.profile.id !== "VLESS_GRPC_REALITY"
    && inbound.profile.id !== "VLESS_XHTTP_REALITY"
    && inbound.profile.id !== "VLESS_RAW_TLS"
    && inbound.profile.id !== "VLESS_RAW_TLS_VISION"
    && inbound.profile.id !== "VLESS_WEBSOCKET_TLS"
    && inbound.profile.id !== "VLESS_GRPC_TLS"
    && inbound.profile.id !== "VLESS_HTTP_UPGRADE_TLS"
    && inbound.profile.id !== "VLESS_XHTTP_TLS"
    && inbound.profile.id !== "VLESS_MKCP_TLS") {
    invalidXrayConfig();
  }
  return {
    protocol: "vless" as const,
    settings: {
      clients: inbound.clients.map((client) => {
        if (client.credentialType !== "UUID_AND_SHORT_ID" && client.credentialType !== "UUID") invalidXrayConfig();
        return client.flow
          ? { id: client.uuid, email: client.statsKey, flow: client.flow }
          : { id: client.uuid, email: client.statsKey };
      }),
      decryption: "none" as const,
    },
  };
}
