import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { XrayCreateOperationProgress } from "@/components/xray/XrayCreateOperationProgress";
import {
  XRAY_CREATE_SECTIONS,
  selectableXrayCreateSections,
  XrayCreateSectionNav,
  type XrayCreateSection,
} from "@/components/xray/XrayCreateSectionNav";
import { XrayHostPortSteps } from "@/components/xray/XrayHostPortSteps";
import { XrayProfileSteps } from "@/components/xray/XrayProfileSteps";
import {
  XrayRealityClientSteps,
  type XrayCreateTlsCertificateOption,
} from "@/components/xray/XrayRealityClientSteps";
import {
  buildXrayInboundCreateRequest,
  buildXrayInboundCreateV2Request,
  initialXrayDeploymentState,
  normalizedTunnelTarget,
  parseAdminRealityTargets,
  reduceXrayDeploymentState,
  tlsCertificateCoversServerName,
  validInitialClients,
  validTlsServerName,
  type XrayRealityCandidate,
} from "@/components/xray/xrayCreateDeployment";
import {
  availableXrayCreateProfiles,
  currentXrayPortReplacementIds,
  initialXrayCreateState,
  listenerNetworkForXrayProfile,
  listenerNetworksMatch,
  nextSecondaryPortProbeInput,
  portReservationsReady,
  reduceXrayCreateState,
  XRAY_CORE_DEPRECATED_WARNING,
  XRAY_HTTP_PLAINTEXT_AUTH_WARNING,
  XRAY_MIXED_PLAINTEXT_AUTH_WARNING,
  XRAY_WIREGUARD_BLOCKING_WARNING,
  type XrayCreateAction,
  type XrayCreateProfileOption,
  type XrayHostOption,
} from "@/components/xray/xrayCreateFlow";
import { formatXrayEndpoint } from "@/components/xray/xrayInboundPresentation";
import { trpc } from "@/lib/trpc";
import { useEffect, useReducer, useState } from "react";
import { operationQueryPolling } from "./xrayOperationPolling";

function errorCode(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error ?? "");
  return /^[A-Z][A-Z0-9_]{1,63}$/.test(message) ? message : "INTERNAL_ERROR";
}

type Props = {
  operationId: string | null;
  onClose: () => void;
  onOperationStarted: (operationId: string) => void;
  onShowRuntime: (hostId: number) => void;
};

export function XrayCreateDialog({ operationId, onClose, onOperationStarted, onShowRuntime }: Props) {
  const [setup, setupDispatch] = useReducer(reduceXrayCreateState, undefined, initialXrayCreateState);
  const [deployment, deploymentDispatch] = useReducer(reduceXrayDeploymentState, undefined, initialXrayDeploymentState);
  const [now, setNow] = useState(Date.now());
  const [selectedProfileId, setSelectedProfileId] = useState<string | null>(null);
  const [setupSection, setSetupSection] = useState<"BASIC" | "PROTOCOL" | "TRANSPORT">("BASIC");
  const [grpcServiceName, setGrpcServiceName] = useState("forwardx-grpc");
  const [xhttpPath, setXhttpPath] = useState("/forwardx/xhttp-v1");
  const [webSocketPath, setWebSocketPath] = useState("/forwardx/ws-v1");
  const [httpUpgradePath, setHttpUpgradePath] = useState("/forwardx/httpupgrade-v1");
  const hostsQuery = trpc.xray.hosts.options.useQuery(undefined, { enabled: !operationId, retry: false, refetchInterval: operationId ? false : 5_000 });
  const hosts = (hostsQuery.data ?? []) as XrayHostOption[];
  const currentHost = hosts.find((host) => host.id === setup.hostId);
  const profilesQuery = trpc.xray.profiles.catalog.useQuery(
    setup.hostId ? { hostId: setup.hostId } : {},
    { enabled: !operationId, retry: false },
  );
  const catalogProfiles = (profilesQuery.data ?? []) as XrayCreateProfileOption[];
  const profiles = availableXrayCreateProfiles(catalogProfiles);
  const profileIds = profiles.map((profile) => profile.id).join("\u0000");
  const selectedProfile = profiles.find((profile) => profile.id === selectedProfileId);
  const listenerNetwork = listenerNetworkForXrayProfile(selectedProfile);
  const listenerNetworks = selectedProfile?.listenerNetworks ?? [listenerNetwork];
  const listenerNetworkKey = listenerNetworks.join("\u0000");
  const udpCapabilityRequired = catalogProfiles.some((profile) => (
    profile.listenerNetworks.includes("UDP") && profile.unavailableReasonCode === "UDP_CAPABILITY_REQUIRED"
  ));
  const portOperationId = setup.probe.phase === "QUEUED" || setup.probe.phase === "RUNNING" ? setup.probe.operationId : null;
  const secondaryPortOperationId = setup.secondaryProbe.phase === "QUEUED" || setup.secondaryProbe.phase === "RUNNING"
    ? setup.secondaryProbe.operationId : null;
  const scanOperationId = deployment.scan.phase === "QUEUED" || deployment.scan.phase === "RUNNING" ? deployment.scan.operationId : null;
  const portResult = trpc.xray.portProbes.result.useQuery({ operationId: portOperationId ?? "pending" }, { enabled: !!portOperationId && !operationId, retry: false, refetchInterval: operationQueryPolling, refetchOnWindowFocus: false });
  const secondaryPortResult = trpc.xray.portProbes.result.useQuery(
    { operationId: secondaryPortOperationId ?? "pending" },
    { enabled: !!secondaryPortOperationId && !operationId, retry: false, refetchInterval: operationQueryPolling, refetchOnWindowFocus: false },
  );
  const scanResult = trpc.xray.realityScans.result.useQuery({ operationId: scanOperationId ?? "pending" }, { enabled: !!scanOperationId && !operationId, retry: false, refetchInterval: operationQueryPolling, refetchOnWindowFocus: false });
  const createProbe = trpc.xray.portProbes.create.useMutation({ onSuccess: ({ operationId: id }) => setupDispatch({ type: "PROBE_QUEUED", operationId: id }), onError: (error) => setupDispatch({ type: "PROBE_FAILED", errorCode: errorCode(error) }) });
  const createSecondaryProbe = trpc.xray.portProbes.create.useMutation({
    onSuccess: ({ operationId: id }) => setupDispatch({ type: "PROBE_QUEUED", slot: "SECONDARY", operationId: id }),
    onError: (error) => setupDispatch({ type: "PROBE_FAILED", slot: "SECONDARY", errorCode: errorCode(error) }),
  });
  const createScan = trpc.xray.realityScans.create.useMutation({ onSuccess: ({ operationId: id }) => deploymentDispatch({ type: "SCAN_QUEUED", operationId: id }), onError: (error) => deploymentDispatch({ type: "SCAN_FAILED", errorCode: errorCode(error) }) });
  const createInbound = trpc.xray.inbounds.create.useMutation({ onSuccess: ({ operationId: id }) => onOperationStarted(id), onError: (error) => deploymentDispatch({ type: "SUBMIT_FAILED", errorCode: errorCode(error) }) });
  const createInboundV2 = trpc.xray.inbounds.createV2.useMutation({ onSuccess: ({ operationId: id }) => onOperationStarted(id), onError: (error) => deploymentDispatch({ type: "SUBMIT_FAILED", errorCode: errorCode(error) }) });

  useEffect(() => {
    const result = portResult.data;
    if (!result || !portOperationId || result.status === "QUEUED") return;
    if (result.status === "RUNNING") {
      if (setup.probe.phase !== "RUNNING") setupDispatch({ type: "PROBE_RUNNING", operationId: portOperationId });
    } else if (result.status === "SUCCESS" && result.selectedPort && result.reservationId && result.expiresAt) {
      setupDispatch({ type: "PROBE_RESERVED", selectedPort: result.selectedPort, reservationId: result.reservationId, expiresAt: result.expiresAt });
    } else setupDispatch({ type: "PROBE_FAILED", errorCode: result.errorCode ?? "INTERNAL_ERROR" });
  }, [portOperationId, portResult.data, setup.probe.phase]);
  useEffect(() => { if (portResult.error && portOperationId) setupDispatch({ type: "PROBE_FAILED", errorCode: errorCode(portResult.error) }); }, [portOperationId, portResult.error]);

  useEffect(() => {
    const result = secondaryPortResult.data;
    if (!result || !secondaryPortOperationId || result.status === "QUEUED") return;
    if (result.status === "RUNNING") {
      if (setup.secondaryProbe.phase !== "RUNNING") setupDispatch({ type: "PROBE_RUNNING", slot: "SECONDARY", operationId: secondaryPortOperationId });
    } else if (result.status === "SUCCESS" && result.selectedPort && result.reservationId && result.expiresAt) {
      setupDispatch({ type: "PROBE_RESERVED", slot: "SECONDARY", selectedPort: result.selectedPort, reservationId: result.reservationId, expiresAt: result.expiresAt });
    } else setupDispatch({ type: "PROBE_FAILED", slot: "SECONDARY", errorCode: result.errorCode ?? "INTERNAL_ERROR" });
  }, [secondaryPortOperationId, secondaryPortResult.data, setup.secondaryProbe.phase]);
  useEffect(() => {
    if (secondaryPortResult.error && secondaryPortOperationId) {
      setupDispatch({ type: "PROBE_FAILED", slot: "SECONDARY", errorCode: errorCode(secondaryPortResult.error) });
    }
  }, [secondaryPortOperationId, secondaryPortResult.error]);

  useEffect(() => {
    const input = nextSecondaryPortProbeInput(setup, listenerNetworks, Date.now());
    if (!input || createSecondaryProbe.isPending || !currentHost?.canCreateXrayInbound) return;
    createSecondaryProbe.mutate(input);
  }, [createSecondaryProbe, currentHost?.canCreateXrayInbound, listenerNetworkKey, setup.hostId, setup.probe, setup.secondaryProbe.phase]);

  useEffect(() => {
    const result = scanResult.data;
    if (!result || !scanOperationId || result.status === "QUEUED") return;
    if (result.status === "RUNNING") {
      if (deployment.scan.phase !== "RUNNING") deploymentDispatch({ type: "SCAN_RUNNING", operationId: scanOperationId });
    } else if (result.status === "SUCCESS" && result.results) {
      deploymentDispatch({ type: "SCAN_SUCCESS", results: result.results as XrayRealityCandidate[] });
    } else deploymentDispatch({ type: "SCAN_FAILED", errorCode: result.errorCode ?? "INTERNAL_ERROR" });
  }, [deployment.scan.phase, scanOperationId, scanResult.data]);
  useEffect(() => { if (scanResult.error && scanOperationId) deploymentDispatch({ type: "SCAN_FAILED", errorCode: errorCode(scanResult.error) }); }, [scanOperationId, scanResult.error]);

  useEffect(() => {
    const expirations: number[] = [];
    if (setup.probe.phase === "RESERVED") expirations.push(Date.parse(setup.probe.expiresAt));
    if (setup.secondaryProbe.phase === "RESERVED") expirations.push(Date.parse(setup.secondaryProbe.expiresAt));
    if (expirations.length === 0) return;
    const timer = window.setTimeout(() => setNow(Date.now()), Math.max(0, Math.min(...expirations) - Date.now() + 50));
    return () => window.clearTimeout(timer);
  }, [setup.probe, setup.secondaryProbe]);

  useEffect(() => {
    if (selectedProfileId && profiles.some((profile) => profile.id === selectedProfileId)) return;
    setSelectedProfileId(profiles[0]?.id ?? null);
  }, [profileIds, profiles, selectedProfileId]);

  const dispatchSetup = (action: XrayCreateAction) => {
    if (action.type === "SELECT_HOST" && action.host.id !== setup.hostId) {
      deploymentDispatch({ type: "RESET" });
      setGrpcServiceName("forwardx-grpc");
      setXhttpPath("/forwardx/xhttp-v1");
      setWebSocketPath("/forwardx/ws-v1");
      setHttpUpgradePath("/forwardx/httpupgrade-v1");
      setSetupSection("BASIC");
    }
    setupDispatch(action);
  };
  const selectProfile = (profileId: string) => {
    if (profileId !== selectedProfileId) {
      const nextProfile = profiles.find((profile) => profile.id === profileId);
      deploymentDispatch({ type: "RESET" });
      setGrpcServiceName("forwardx-grpc");
      setXhttpPath("/forwardx/xhttp-v1");
      setWebSocketPath("/forwardx/ws-v1");
      setHttpUpgradePath("/forwardx/httpupgrade-v1");
      if (nextProfile?.id === "WIREGUARD_UDP_NONE"
        || selectedProfile?.id === "WIREGUARD_UDP_NONE"
        || !listenerNetworksMatch(nextProfile, selectedProfile)) {
        setupDispatch({ type: "RESET_PROBE" });
        setSetupSection("BASIC");
      }
    }
    setSelectedProfileId(profileId);
  };
  const tlsCertificatesQuery = trpc.xray.certificates.list.useQuery(
    { hostId: setup.hostId ?? 1, search: "", page: 1, pageSize: 100 },
    { enabled: !operationId && !!setup.hostId && selectedProfile?.security === "TLS", retry: false },
  );
  const tlsCertificates = (tlsCertificatesQuery.data?.items ?? []) as XrayCreateTlsCertificateOption[];
  const selectedTlsCertificate = tlsCertificates.find((certificate) => certificate.id === deployment.tlsCertificateId);
  const selectedRuntimeQuery = trpc.xray.runtimes.list.useQuery(
    { page: 1, pageSize: 1, ...(setup.hostId ? { hostId: setup.hostId } : {}) },
    { enabled: !operationId && !!setup.hostId, retry: false, refetchInterval: 10_000, refetchOnWindowFocus: true },
  );
  const runtimeCatalogQuery = trpc.xray.runtimes.catalog.useQuery(undefined, { enabled: !operationId, retry: false });
  const probe = () => {
    if (createProbe.isPending || !setup.hostId) return;
    if (!currentHost?.canCreateXrayInbound) return setupDispatch({ type: "PROBE_FAILED", errorCode: "HOST_OFFLINE" });
    setNow(Date.now());
    const replaceReservationIds = currentXrayPortReplacementIds(setup);
    setupDispatch({ type: "RESET_PROBE" });
    createProbe.mutate({
      hostId: setup.hostId,
      mode: setup.portMode,
      network: listenerNetwork,
      ...(setup.portMode === "MANUAL" ? { manualPort: Number(setup.manualPort) } : {}),
      ...(replaceReservationIds.length > 0 ? { replaceReservationIds } : {}),
    });
  };
  const scan = () => {
    if (createScan.isPending || !setup.hostId) return;
    if (!currentHost?.canCreateXrayInbound) return deploymentDispatch({ type: "SCAN_FAILED", errorCode: "HOST_OFFLINE" });
    createScan.mutate({ hostId: setup.hostId, source: deployment.scanSource, ...(deployment.scanSource === "ADMIN_DOMAINS" ? { targets: parseAdminRealityTargets(deployment.customTargets) } : {}) });
  };
  const submit = () => {
    if (!currentHost?.canCreateXrayInbound) return deploymentDispatch({ type: "SUBMIT_FAILED", errorCode: "HOST_OFFLINE" });
    try {
      if (selectedProfileId === "VLESS_RAW_REALITY_VISION") {
        createInbound.mutate(buildXrayInboundCreateRequest(setup, deployment, Date.now()));
      } else if (selectedProfileId === "VLESS_GRPC_REALITY") {
        createInboundV2.mutate(buildXrayInboundCreateV2Request(
          setup,
          deployment,
          { profileId: selectedProfileId, serviceName: grpcServiceName },
          Date.now(),
        ));
      } else if (selectedProfileId === "VLESS_XHTTP_REALITY") {
        createInboundV2.mutate(buildXrayInboundCreateV2Request(
          setup,
          deployment,
          { profileId: selectedProfileId, path: xhttpPath },
          Date.now(),
        ));
      } else if (selectedProfileId === "TROJAN_RAW_REALITY") {
        createInboundV2.mutate(buildXrayInboundCreateV2Request(
          setup,
          deployment,
          { profileId: selectedProfileId },
          Date.now(),
        ));
      } else if (selectedProfileId === "HTTP_RAW_NONE"
        || selectedProfileId === "MIXED_RAW_NONE"
        || selectedProfileId === "WIREGUARD_UDP_NONE"
        || selectedProfileId === "SHADOWSOCKS_2022_RAW_NONE"
        || selectedProfileId === "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE") {
        createInboundV2.mutate(buildXrayInboundCreateV2Request(
          setup,
          deployment,
          { profileId: selectedProfileId },
          Date.now(),
        ));
      } else if (selectedProfileId === "TUNNEL_TCP_LOCAL_NONE") {
        const target = normalizedTunnelTarget(deployment);
        if (!target) throw new Error("INVALID_CONFIG_INPUT");
        createInboundV2.mutate(buildXrayInboundCreateV2Request(
          setup,
          deployment,
          { profileId: selectedProfileId, ...target },
          Date.now(),
        ));
      } else if (selectedProfileId === "VLESS_RAW_TLS"
        || selectedProfileId === "VLESS_RAW_TLS_VISION"
        || selectedProfileId === "TROJAN_RAW_TLS"
        || selectedProfileId === "VMESS_RAW_TLS"
        || selectedProfileId === "VLESS_MKCP_TLS"
        || selectedProfileId === "TROJAN_MKCP_TLS"
        || selectedProfileId === "HYSTERIA2_TLS") {
        if (!deployment.tlsCertificateId) throw new Error("INVALID_CONFIG_INPUT");
        createInboundV2.mutate(buildXrayInboundCreateV2Request(
          setup,
          deployment,
          {
            profileId: selectedProfileId,
            tlsCertificateId: deployment.tlsCertificateId,
            serverName: deployment.tlsServerName,
          },
          Date.now(),
        ));
      } else if (selectedProfileId === "VLESS_WEBSOCKET_TLS"
        || selectedProfileId === "TROJAN_WEBSOCKET_TLS") {
        if (!deployment.tlsCertificateId) throw new Error("INVALID_CONFIG_INPUT");
        createInboundV2.mutate(buildXrayInboundCreateV2Request(
          setup,
          deployment,
          {
            profileId: selectedProfileId,
            path: webSocketPath,
            tlsCertificateId: deployment.tlsCertificateId,
            serverName: deployment.tlsServerName,
          },
          Date.now(),
        ));
      } else if (selectedProfileId === "VLESS_GRPC_TLS"
        || selectedProfileId === "TROJAN_GRPC_TLS") {
        if (!deployment.tlsCertificateId) throw new Error("INVALID_CONFIG_INPUT");
        createInboundV2.mutate(buildXrayInboundCreateV2Request(
          setup,
          deployment,
          {
            profileId: selectedProfileId,
            serviceName: grpcServiceName,
            tlsCertificateId: deployment.tlsCertificateId,
            serverName: deployment.tlsServerName,
          },
          Date.now(),
        ));
      } else if (selectedProfileId === "VLESS_HTTP_UPGRADE_TLS"
        || selectedProfileId === "TROJAN_HTTP_UPGRADE_TLS") {
        if (!deployment.tlsCertificateId) throw new Error("INVALID_CONFIG_INPUT");
        createInboundV2.mutate(buildXrayInboundCreateV2Request(
          setup,
          deployment,
          {
            profileId: selectedProfileId,
            path: httpUpgradePath,
            tlsCertificateId: deployment.tlsCertificateId,
            serverName: deployment.tlsServerName,
          },
          Date.now(),
        ));
      } else if (selectedProfileId === "VLESS_XHTTP_TLS"
        || selectedProfileId === "TROJAN_XHTTP_TLS") {
        if (!deployment.tlsCertificateId) throw new Error("INVALID_CONFIG_INPUT");
        createInboundV2.mutate(buildXrayInboundCreateV2Request(
          setup,
          deployment,
          {
            profileId: selectedProfileId,
            path: xhttpPath,
            tlsCertificateId: deployment.tlsCertificateId,
            serverName: deployment.tlsServerName,
          },
          Date.now(),
        ));
      } else {
        throw new Error("INVALID_CONFIG_INPUT");
      }
    }
    catch (error) { deploymentDispatch({ type: "SUBMIT_FAILED", errorCode: errorCode(error) }); }
  };
  const selectedRuntime = selectedRuntimeQuery.data?.items[0];
  const targetVersion = runtimeCatalogQuery.data?.defaultVersion ?? "v26.3.27";
  const tunnelTarget = normalizedTunnelTarget(deployment);
  const summary = {
    hostName: currentHost?.name ?? "-",
    nodeName: setup.name,
    endpoint: setup.probe.phase === "RESERVED"
      ? formatXrayEndpoint(selectedProfile?.id === "TUNNEL_TCP_LOCAL_NONE" ? "127.0.0.1" : setup.publicAddress, setup.probe.selectedPort)
      : "-",
    currentVersion: selectedRuntime?.installedVersion ?? null,
    targetVersion,
    willInstall: selectedRuntime?.installedVersion !== targetVersion,
    protocolLabel: selectedProfile?.id === "TUNNEL_TCP_LOCAL_NONE"
      ? "Tunnel · 本机回环 / TCP / 固定目标"
      : selectedProfile?.id === "HTTP_RAW_NONE"
      ? "HTTP 管理代理 · RAW / TCP / 无 TLS · 强制 Basic 认证"
      : selectedProfile?.id === "MIXED_RAW_NONE"
        ? "Mixed（SOCKS5 + HTTP）· RAW / TCP / 无 TLS · 强制认证"
      : selectedProfile?.id === "VMESS_RAW_TLS"
      ? "VMess · RAW · TLS · AEAD AUTO"
      : selectedProfile?.id === "WIREGUARD_UDP_NONE"
        ? "WireGuard · Xray 内置 / UDP / 无 TLS"
      : selectedProfile?.id === "SHADOWSOCKS_2022_RAW_NONE" || selectedProfile?.id === "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE"
        ? `Shadowsocks 2022 · RAW / ${selectedProfile.listenerNetworks.join(" + ")} · 2022-blake3-aes-256-gcm`
        : selectedProfile?.id === "HYSTERIA2_TLS"
          ? "Hysteria 2 · Hysteria · TLS · UDP"
      : selectedProfile ? `${selectedProfile.protocol} · ${selectedProfile.transport} · ${selectedProfile.security === "REALITY" ? "Reality" : selectedProfile.security}${selectedProfile.clientFlow === "XTLS_RPRX_VISION" ? " · Vision" : selectedProfile.security === "TLS" ? " · 标准" : ""}` : "-",
    clientFlowLabel: selectedProfile?.clientFlow === "NONE" ? "无" : "Vision",
    securityDetail: selectedProfile?.security === "TLS"
      ? `${selectedTlsCertificate?.name ?? "未选择证书"} · SNI ${deployment.tlsServerName || "-"}`
        + (selectedProfile.id === "HYSTERIA2_TLS" ? " · 分享使用叶证书 pinSHA256，不关闭证书校验" : "")
      : selectedProfile?.security === "NONE"
        ? selectedProfile.id === "TUNNEL_TCP_LOCAL_NONE"
          ? `仅 127.0.0.1 可连接 · 默认 direct → ${tunnelTarget ? formatXrayEndpoint(tunnelTarget.targetAddress, tunnelTarget.targetPort) : "-"}`
          : selectedProfile.id === "WIREGUARD_UDP_NONE"
          ? "gVisor · IPv4 · MTU 1420 · 10.0.0.0/24；peer 配置由服务端生成"
          : selectedProfile.id === "HTTP_RAW_NONE"
            ? "非透明代理 · 强制 Basic 认证；用户名和密码由服务端生成"
            : selectedProfile.id === "MIXED_RAW_NONE"
              ? "SOCKS5 + HTTP/CONNECT 共用 TCP 端口 · 强制认证 · 无 UDP；用户名和密码由服务端生成"
            : "协议层加密（无 TLS/Reality）；密钥由服务端自动生成"
        : deployment.selectedReality?.target ?? "-",
    advisoryLabel: selectedProfile?.advisoryCode === "CORE_DEPRECATED"
      ? XRAY_CORE_DEPRECATED_WARNING
      : selectedProfile?.advisoryCode === "WIREGUARD_BLOCKING_RISK"
        ? XRAY_WIREGUARD_BLOCKING_WARNING
        : selectedProfile?.advisoryCode === "PLAINTEXT_PROXY_AUTH_RISK"
          ? XRAY_HTTP_PLAINTEXT_AUTH_WARNING
          : selectedProfile?.advisoryCode === "PLAINTEXT_MIXED_AUTH_RISK"
            ? XRAY_MIXED_PLAINTEXT_AUTH_WARNING
          : undefined,
  };

  const selectedProfileValid = selectedProfile?.id === "VLESS_RAW_REALITY_VISION"
    || selectedProfile?.id === "TROJAN_RAW_REALITY"
    || selectedProfile?.id === "VLESS_RAW_TLS"
    || selectedProfile?.id === "VLESS_RAW_TLS_VISION"
    || selectedProfile?.id === "TROJAN_RAW_TLS"
    || selectedProfile?.id === "VMESS_RAW_TLS"
    || selectedProfile?.id === "SHADOWSOCKS_2022_RAW_NONE"
    || selectedProfile?.id === "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE"
    || selectedProfile?.id === "WIREGUARD_UDP_NONE"
    || selectedProfile?.id === "HTTP_RAW_NONE"
    || selectedProfile?.id === "MIXED_RAW_NONE"
    || (selectedProfile?.id === "TUNNEL_TCP_LOCAL_NONE" && tunnelTarget !== null)
    || selectedProfile?.id === "VLESS_MKCP_TLS"
    || selectedProfile?.id === "TROJAN_MKCP_TLS"
    || selectedProfile?.id === "HYSTERIA2_TLS"
    || ((selectedProfile?.id === "VLESS_WEBSOCKET_TLS" || selectedProfile?.id === "TROJAN_WEBSOCKET_TLS")
      && /^\/[A-Za-z0-9._~/-]{0,127}$/.test(webSocketPath))
    || ((selectedProfile?.id === "VLESS_GRPC_REALITY"
      || selectedProfile?.id === "VLESS_GRPC_TLS"
      || selectedProfile?.id === "TROJAN_GRPC_TLS")
      && /^[A-Za-z0-9._~-]{1,128}$/.test(grpcServiceName))
    || ((selectedProfile?.id === "VLESS_HTTP_UPGRADE_TLS" || selectedProfile?.id === "TROJAN_HTTP_UPGRADE_TLS")
      && /^\/[A-Za-z0-9._~/-]{0,127}$/.test(httpUpgradePath))
    || ((selectedProfile?.id === "VLESS_XHTTP_REALITY"
      || selectedProfile?.id === "VLESS_XHTTP_TLS"
      || selectedProfile?.id === "TROJAN_XHTTP_TLS")
      && /^\/[A-Za-z0-9._~/-]{0,127}$/.test(xhttpPath));
  const activeSection: XrayCreateSection = deployment.stage === "SETUP"
    ? setupSection
      : deployment.stage === "REALITY" ? "SECURITY"
      : deployment.stage === "CLIENTS" ? "ACCOUNT" : "CONFIRM";
  const reservationReady = portReservationsReady(setup, listenerNetworks, now);
  const securityReady = selectedProfile?.security === "TLS"
    ? !!selectedTlsCertificate && selectedTlsCertificate.status !== "EXPIRED"
      && validTlsServerName(deployment.tlsServerName)
      && tlsCertificateCoversServerName(selectedTlsCertificate, deployment.tlsServerName)
    : selectedProfile?.security === "NONE" || !!deployment.selectedReality;
  const enabledSections = new Set<XrayCreateSection>(["BASIC"]);
  if (reservationReady) enabledSections.add("PROTOCOL");
  if (reservationReady && selectedProfile) enabledSections.add("TRANSPORT");
  if (reservationReady && selectedProfileValid) enabledSections.add("SECURITY");
  if (reservationReady && selectedProfileValid && securityReady) enabledSections.add("ACCOUNT");
  if (reservationReady && selectedProfileValid && securityReady
    && (selectedProfile?.id === "TUNNEL_TCP_LOCAL_NONE" || validInitialClients(deployment.clients))) enabledSections.add("CONFIRM");
  const selectableSections = selectableXrayCreateSections(activeSection, enabledSections);
  const selectSection = (section: XrayCreateSection) => {
    if (!selectableSections.has(section)) return;
    if (section === "BASIC" || section === "PROTOCOL" || section === "TRANSPORT") {
      deploymentDispatch({ type: "BACK_SETUP" });
      setSetupSection(section);
      if (section === "BASIC") setupDispatch({ type: "GO_TO_HOST" });
      return;
    }
    if (section === "SECURITY") deploymentDispatch({ type: "ENTER_REALITY" });
    else if (section === "ACCOUNT") deploymentDispatch({ type: selectedProfile?.security === "NONE" ? "GO_CLIENTS_NONE" : "GO_CLIENTS" });
    else deploymentDispatch({ type: selectedProfile?.id === "TUNNEL_TCP_LOCAL_NONE"
      ? "GO_CONFIRM_CREDENTIALLESS"
      : selectedProfile?.security === "NONE" ? "GO_CONFIRM_NONE" : "GO_CONFIRM" });
  };
  const sectionNumber = XRAY_CREATE_SECTIONS.indexOf(activeSection) + 1;
  const form = activeSection === "BASIC"
    ? <XrayHostPortSteps state={setup} hosts={hosts} hostsLoading={hostsQuery.isLoading} now={now} listenerNetworks={listenerNetworks} onAction={dispatchSetup} onProbe={probe} onPortReady={() => setSetupSection("PROTOCOL")} />
    : activeSection === "PROTOCOL" || activeSection === "TRANSPORT"
      ? <XrayProfileSteps
          section={activeSection}
          profiles={profiles}
          profilesLoading={profilesQuery.isLoading}
          profilesError={profilesQuery.isError}
          selectedProfileId={selectedProfileId}
          grpcServiceName={grpcServiceName}
          xhttpPath={selectedProfile?.transport === "WEBSOCKET"
            ? webSocketPath
            : selectedProfile?.transport === "HTTP_UPGRADE" ? httpUpgradePath : xhttpPath}
          tunnelTargetAddress={deployment.tunnelTargetAddress}
          tunnelTargetPort={deployment.tunnelTargetPort}
          udpCapabilityRequired={udpCapabilityRequired}
          onSelectProfile={selectProfile}
          onGrpcServiceNameChange={setGrpcServiceName}
          onXhttpPathChange={selectedProfile?.transport === "WEBSOCKET"
            ? setWebSocketPath
            : selectedProfile?.transport === "HTTP_UPGRADE" ? setHttpUpgradePath : setXhttpPath}
          onTunnelTargetAddressChange={(value) => deploymentDispatch({ type: "SET_TUNNEL_TARGET_ADDRESS", value })}
          onTunnelTargetPortChange={(value) => deploymentDispatch({ type: "SET_TUNNEL_TARGET_PORT", value })}
          onRetry={() => { void profilesQuery.refetch(); }}
          onBack={() => selectSection(activeSection === "PROTOCOL" ? "BASIC" : "PROTOCOL")}
          onNext={() => activeSection === "PROTOCOL" ? setSetupSection("TRANSPORT") : deploymentDispatch({ type: "ENTER_REALITY" })}
        />
      : <XrayRealityClientSteps
          state={deployment}
          security={selectedProfile?.security === "TLS" ? "TLS" : selectedProfile?.security === "NONE" ? "NONE" : "REALITY"}
          accessKind={selectedProfile?.id === "WIREGUARD_UDP_NONE"
            ? "WIREGUARD_PEER"
            : selectedProfile?.id === "HTTP_RAW_NONE"
              ? "HTTP_BASIC"
              : selectedProfile?.id === "MIXED_RAW_NONE"
                ? "MIXED_USER_PASSWORD"
                : selectedProfile?.id === "TUNNEL_TCP_LOCAL_NONE" ? "NONE" : "STANDARD"}
          certificates={tlsCertificates}
          certificatesLoading={tlsCertificatesQuery.isLoading}
          certificatesError={tlsCertificatesQuery.isError}
          onRetryCertificates={() => { void tlsCertificatesQuery.refetch(); }}
          onAction={deploymentDispatch}
          onBackFromSecurity={() => { deploymentDispatch({ type: "BACK_SETUP" }); setSetupSection("TRANSPORT"); }}
          onScan={scan}
          onSubmit={submit}
          submitting={createInbound.isPending || createInboundV2.isPending}
          canSubmit={currentHost?.canCreateXrayInbound === true && selectedProfileValid && securityReady}
          summary={summary}
        />;
  return <Dialog open onOpenChange={(open) => { if (!open) onClose(); }}><DialogContent className="flex max-w-5xl flex-col"><DialogHeader className="shrink-0"><DialogTitle>{operationId ? "Xray 节点部署" : "创建 Xray 节点"}</DialogTitle><DialogDescription>{operationId ? "从持久 operation 恢复真实部署状态。" : `分区 ${sectionNumber} / 6 · 只显示已验证 profile 支持的字段，提交前不会写入节点配置。`}</DialogDescription></DialogHeader>{operationId ? <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain pr-1"><XrayCreateOperationProgress operationId={operationId} onClose={onClose} onShowRuntime={onShowRuntime} /></div> : <>{hostsQuery.isError && <div role="alert" className="flex shrink-0 items-center justify-between gap-3 rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm"><span>主机状态加载失败，请重试。</span><Button type="button" size="sm" variant="outline" onClick={() => { void hostsQuery.refetch(); }}>重新加载</Button></div>}<div className="shrink-0"><XrayCreateSectionNav active={activeSection} enabled={selectableSections} onSelect={selectSection} /></div><div className="min-h-0 flex-1 overflow-y-auto overscroll-contain pb-1 pr-1">{form}</div></>}</DialogContent></Dialog>;
}
