import { invalidXrayConfig, type NormalizedXrayInbound } from "./xrayProfileCompiler";
import {
  validateXrayTlsCertificateInput,
  xrayTlsCertificateCoversServerName,
} from "./xrayTlsCertificate";

function pemLines(pem: string): string[] {
  return pem.trimEnd().split("\n");
}

export function compileXrayInlineTlsSecurity(input: {
  certificateChainPem: string;
  privateKeyPem: string;
}) {
  const material = validateXrayTlsCertificateInput({
    certificatePem: input.certificateChainPem,
    privateKeyPem: input.privateKeyPem,
  });
  return {
    security: "tls" as const,
    tlsSettings: {
      certificates: [{
        certificate: pemLines(material.certificateChainPem),
        key: pemLines(material.privateKeyPem),
      }],
    },
  };
}

export function compileXrayTransportSecurity(inbound: NormalizedXrayInbound) {
  if (inbound.profile.id === "TUNNEL_TCP_LOCAL_NONE") {
    if (inbound.security !== "NONE" || !("tunnel" in inbound)) invalidXrayConfig();
    return undefined;
  }
  if (inbound.profile.id === "HTTP_RAW_NONE" || inbound.profile.id === "MIXED_RAW_NONE") {
    if (inbound.security !== "NONE") invalidXrayConfig();
    return { network: "tcp" as const };
  }
  if (inbound.profile.id === "WIREGUARD_UDP_NONE") {
    if (inbound.security !== "NONE" || !("wireguardServerPrivateKey" in inbound)) invalidXrayConfig();
    return undefined;
  }
  if (inbound.profile.id === "SHADOWSOCKS_2022_RAW_NONE"
    || inbound.profile.id === "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE") {
    if (inbound.security !== "NONE") invalidXrayConfig();
    return { network: "tcp" as const };
  }
  if (inbound.profile.id === "VLESS_RAW_TLS"
    || inbound.profile.id === "VLESS_RAW_TLS_VISION"
    || inbound.profile.id === "VMESS_RAW_TLS"
    || inbound.profile.id === "TROJAN_RAW_TLS"
    || inbound.profile.id === "VLESS_WEBSOCKET_TLS"
    || inbound.profile.id === "TROJAN_WEBSOCKET_TLS"
    || inbound.profile.id === "VLESS_GRPC_TLS"
    || inbound.profile.id === "TROJAN_GRPC_TLS"
    || inbound.profile.id === "VLESS_HTTP_UPGRADE_TLS"
    || inbound.profile.id === "TROJAN_HTTP_UPGRADE_TLS"
    || inbound.profile.id === "VLESS_XHTTP_TLS"
    || inbound.profile.id === "TROJAN_XHTTP_TLS"
    || inbound.profile.id === "VLESS_MKCP_TLS"
    || inbound.profile.id === "TROJAN_MKCP_TLS"
    || inbound.profile.id === "HYSTERIA2_TLS") {
    if (inbound.security !== "TLS"
      || !xrayTlsCertificateCoversServerName(inbound.tlsCertificateChainPem, inbound.realityServerName)) {
      invalidXrayConfig();
    }
    let tlsSecurity: ReturnType<typeof compileXrayInlineTlsSecurity>;
    try {
      tlsSecurity = compileXrayInlineTlsSecurity({
        certificateChainPem: inbound.tlsCertificateChainPem,
        privateKeyPem: inbound.tlsPrivateKeyPem,
      });
    } catch {
      invalidXrayConfig();
    }
    if (inbound.profile.id === "VLESS_WEBSOCKET_TLS" || inbound.profile.id === "TROJAN_WEBSOCKET_TLS") {
      const path = inbound.spec.path;
      if (typeof path !== "string" || !/^\/[A-Za-z0-9._~/-]*$/.test(path)) invalidXrayConfig();
      return { network: "ws" as const, ...tlsSecurity, wsSettings: { path } };
    }
    if (inbound.profile.id === "VLESS_GRPC_TLS" || inbound.profile.id === "TROJAN_GRPC_TLS") {
      const serviceName = inbound.spec.serviceName;
      if (typeof serviceName !== "string" || !/^[A-Za-z0-9._~-]{1,128}$/.test(serviceName)) invalidXrayConfig();
      return {
        network: "grpc" as const,
        ...tlsSecurity,
        tlsSettings: { ...tlsSecurity.tlsSettings, alpn: ["h2"] },
        grpcSettings: { serviceName, multiMode: false as const },
      };
    }
    if (inbound.profile.id === "VLESS_HTTP_UPGRADE_TLS" || inbound.profile.id === "TROJAN_HTTP_UPGRADE_TLS") {
      const path = inbound.spec.path;
      if (typeof path !== "string" || !/^\/[A-Za-z0-9._~/-]*$/.test(path)) invalidXrayConfig();
      return { network: "httpupgrade" as const, ...tlsSecurity, httpupgradeSettings: { path } };
    }
    if (inbound.profile.id === "VLESS_XHTTP_TLS" || inbound.profile.id === "TROJAN_XHTTP_TLS") {
      const path = inbound.spec.path;
      if (typeof path !== "string" || !/^\/[A-Za-z0-9._~/-]*$/.test(path)) invalidXrayConfig();
      return { network: "xhttp" as const, ...tlsSecurity, xhttpSettings: { path, mode: "auto" as const } };
    }
    if (inbound.profile.id === "VLESS_MKCP_TLS" || inbound.profile.id === "TROJAN_MKCP_TLS") {
      return { network: "kcp" as const, ...tlsSecurity, kcpSettings: {} };
    }
    if (inbound.profile.id === "HYSTERIA2_TLS") {
      return {
        network: "hysteria" as const,
        ...tlsSecurity,
        tlsSettings: { ...tlsSecurity.tlsSettings, alpn: ["h3"] },
        hysteriaSettings: { version: 2 as const, udpIdleTimeout: 60 },
      };
    }
    return { network: "tcp" as const, ...tlsSecurity };
  }
  if (inbound.profile.id !== "VLESS_RAW_REALITY_VISION"
    && inbound.profile.id !== "VLESS_GRPC_REALITY"
    && inbound.profile.id !== "VLESS_XHTTP_REALITY"
    && inbound.profile.id !== "TROJAN_RAW_REALITY") {
    invalidXrayConfig();
  }
  if (inbound.security !== "REALITY") invalidXrayConfig();
  const shortIds = inbound.clients.map((client) => {
    if (!("shortId" in client) || typeof client.shortId !== "string") invalidXrayConfig();
    return client.shortId;
  });
  const reality = {
    security: "reality" as const,
    realitySettings: {
      show: false,
      dest: `${inbound.realityTargetHost}:${inbound.realityTargetPort}`,
      xver: 0,
      serverNames: [inbound.realityServerName],
      privateKey: inbound.realityPrivateKey,
      shortIds: shortIds.length > 0 ? shortIds : [""],
    },
  };
  if (inbound.profile.id === "VLESS_RAW_REALITY_VISION" || inbound.profile.id === "TROJAN_RAW_REALITY") {
    return { network: "tcp" as const, ...reality };
  }
  if (inbound.profile.id === "VLESS_GRPC_REALITY") {
    const serviceName = inbound.spec.serviceName;
    if (typeof serviceName !== "string") invalidXrayConfig();
    return {
      network: "grpc" as const,
      ...reality,
      grpcSettings: { serviceName, multiMode: false as const },
    };
  }
  const path = inbound.spec.path;
  if (typeof path !== "string") invalidXrayConfig();
  return {
    network: "xhttp" as const,
    ...reality,
    xhttpSettings: { path, mode: "auto" as const },
  };
}
