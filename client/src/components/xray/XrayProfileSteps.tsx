import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Boxes, Cable, Network, ShieldCheck } from "lucide-react";
import { normalizeXrayTunnelTargetAddress } from "@shared/xrayProfiles";

import {
  XRAY_CORE_DEPRECATED_WARNING,
  XRAY_HTTP_PLAINTEXT_AUTH_WARNING,
  XRAY_MIXED_PLAINTEXT_AUTH_WARNING,
  XRAY_WIREGUARD_BLOCKING_WARNING,
  type XrayCreateProfileOption,
} from "./xrayCreateFlow";
import { createProfileAxes, selectProfileForAxes } from "./xrayCreateSections";

type Props = {
  section: "PROTOCOL" | "TRANSPORT";
  profiles: XrayCreateProfileOption[];
  profilesLoading: boolean;
  profilesError: boolean;
  selectedProfileId: string | null;
  grpcServiceName: string;
  xhttpPath: string;
  tunnelTargetAddress?: string;
  tunnelTargetPort?: string;
  udpCapabilityRequired?: boolean;
  onSelectProfile: (profileId: string) => void;
  onGrpcServiceNameChange: (value: string) => void;
  onXhttpPathChange: (value: string) => void;
  onTunnelTargetAddressChange?: (value: string) => void;
  onTunnelTargetPortChange?: (value: string) => void;
  onRetry: () => void;
  onBack: () => void;
  onNext: () => void;
};

const protocolDescriptions: Record<string, string> = {
  VLESS: "轻量、现代，支持 Vision 与多种传输。",
  TROJAN: "使用服务端生成的随机密码凭据。",
  VMESS: "兼容 VMess 客户端生态。",
  SHADOWSOCKS: "按批准 method 管理密钥。",
  HYSTERIA2: "基于 QUIC，必须配合 TLS。",
  WIREGUARD: "面向网络层 peer 配置。",
  HTTP: "面向管理和临时接入的传统 HTTP 代理，强制 Basic 认证。",
  MIXED: "同一端口同时提供认证 SOCKS5 与 HTTP 代理。",
  TUNNEL: "只供目标主机本地进程使用的固定 TCP 端口转发。",
};

const protocolLabels: Record<string, string> = {
  HYSTERIA2: "Hysteria 2",
  HTTP: "HTTP 管理代理",
  MIXED: "Mixed（SOCKS5 + HTTP）",
  TUNNEL: "Tunnel（本机端口转发）",
};

const transportLabels: Record<string, string> = {
  RAW: "RAW / TCP",
  GRPC: "gRPC",
  WEBSOCKET: "WebSocket",
  HTTP_UPGRADE: "HTTPUpgrade",
  XHTTP: "XHTTP",
  MKCP: "mKCP",
  HYSTERIA: "Hysteria",
  NONE: "无独立传输",
};

function LoadingProfiles() {
  return <div className="grid gap-3 sm:grid-cols-2" aria-label="正在加载可用配置"><Skeleton className="h-24 w-full" /><Skeleton className="h-24 w-full" /></div>;
}

export function XrayProfileSteps(props: Props) {
  const selected = props.profiles.find((profile) => profile.id === props.selectedProfileId) ?? props.profiles[0];
  const axes = createProfileAxes(props.profiles, selected?.protocol, selected?.transport);
  const matchingProfiles = selected
    ? props.profiles.filter((profile) => profile.protocol === selected.protocol && profile.transport === selected.transport)
    : [];
  const selectsListenerNetwork = matchingProfiles.some((profile) => (
    profile.listenerNetworks.join("\u0000") !== matchingProfiles[0]?.listenerNetworks.join("\u0000")
  ));
  const usesServiceName = selected?.id === "VLESS_GRPC_REALITY"
    || selected?.id === "VLESS_GRPC_TLS"
    || selected?.id === "TROJAN_GRPC_TLS";
  const serviceNameValid = !usesServiceName || /^[A-Za-z0-9._~-]{1,128}$/.test(props.grpcServiceName);
  const usesPath = selected?.id === "VLESS_XHTTP_REALITY"
    || selected?.id === "VLESS_WEBSOCKET_TLS"
    || selected?.id === "TROJAN_WEBSOCKET_TLS"
    || selected?.id === "VLESS_HTTP_UPGRADE_TLS"
    || selected?.id === "TROJAN_HTTP_UPGRADE_TLS"
    || selected?.id === "VLESS_XHTTP_TLS"
    || selected?.id === "TROJAN_XHTTP_TLS";
  const pathValid = !usesPath || /^\/[A-Za-z0-9._~/-]{0,127}$/.test(props.xhttpPath);
  const tunnelTargetPort = Number(props.tunnelTargetPort);
  const tunnelTargetValid = selected?.id !== "TUNNEL_TCP_LOCAL_NONE"
    || (!!normalizeXrayTunnelTargetAddress(props.tunnelTargetAddress) && Number.isSafeInteger(tunnelTargetPort)
      && tunnelTargetPort >= 1 && tunnelTargetPort <= 65535);
  const chooseProtocol = (protocol: XrayCreateProfileOption["protocol"]) => {
    const profile = selectProfileForAxes(props.profiles, { protocol });
    if (profile) props.onSelectProfile(profile.id);
  };
  const chooseTransport = (transport: XrayCreateProfileOption["transport"]) => {
    if (!selected) return;
    const profile = selectProfileForAxes(props.profiles, { protocol: selected.protocol, transport });
    if (profile) props.onSelectProfile(profile.id);
  };

  if (props.profilesLoading) return <LoadingProfiles />;
  if (props.profilesError) return <div role="alert" className="flex items-center justify-between gap-3 rounded-lg border border-destructive/30 bg-destructive/5 p-4 text-sm"><span>可用 profile 加载失败，请重试。</span><Button type="button" variant="outline" size="sm" onClick={props.onRetry}>重新加载</Button></div>;
  if (!selected) return <div className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">当前没有可创建的协议配置。</div>;

  if (props.section === "PROTOCOL") {
    return (
      <div className="space-y-5">
        <div><h3 className="font-semibold">选择协议</h3><p className="mt-1 text-sm text-muted-foreground">这里只展示服务端目录中已经通过验证并标记可用的协议。</p></div>
        <div className="grid gap-3 sm:grid-cols-2">
          {axes.protocols.map((protocol) => <button key={protocol} type="button" aria-pressed={selected.protocol === protocol} onClick={() => chooseProtocol(protocol)} className="flex gap-3 rounded-lg border border-border/60 p-4 text-left transition-colors hover:bg-muted/60 aria-pressed:border-primary aria-pressed:bg-primary/5"><span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md bg-muted"><Network className="h-4 w-4" aria-hidden={true} /></span><span><span className="block font-medium">{protocolLabels[protocol] ?? protocol}</span><span className="mt-1 block text-xs leading-5 text-muted-foreground">{protocolDescriptions[protocol] ?? "由 ForwardX profile 严格约束。"}</span>{props.profiles.some((profile) => profile.protocol === protocol && profile.advisoryCode === "CORE_DEPRECATED") && <span className="mt-2 block text-xs leading-5 text-amber-700 dark:text-amber-300">{XRAY_CORE_DEPRECATED_WARNING}</span>}{props.profiles.some((profile) => profile.protocol === protocol && profile.advisoryCode === "WIREGUARD_BLOCKING_RISK") && <span className="mt-2 block text-xs leading-5 text-amber-700 dark:text-amber-300">{XRAY_WIREGUARD_BLOCKING_WARNING}</span>}{props.profiles.some((profile) => profile.protocol === protocol && profile.advisoryCode === "PLAINTEXT_PROXY_AUTH_RISK") && <span className="mt-2 block text-xs leading-5 text-amber-700 dark:text-amber-300">{XRAY_HTTP_PLAINTEXT_AUTH_WARNING}</span>}{props.profiles.some((profile) => profile.protocol === protocol && profile.advisoryCode === "PLAINTEXT_MIXED_AUTH_RISK") && <span className="mt-2 block text-xs leading-5 text-amber-700 dark:text-amber-300">{XRAY_MIXED_PLAINTEXT_AUTH_WARNING}</span>}</span></button>)}
        </div>
        <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between"><Button type="button" variant="outline" onClick={props.onBack}>返回基础配置</Button><Button type="button" onClick={props.onNext}>下一步：选择传输</Button></div>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <div><h3 className="font-semibold">选择传输</h3><p className="mt-1 text-sm text-muted-foreground">传输选项由 {protocolLabels[selected.protocol] ?? selected.protocol} 的可用 profile 派生，不会保留隐藏高级字段。</p></div>
      {props.udpCapabilityRequired && <p role="alert" className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">UDP profile 暂不可用：需要升级 Agent 以支持 UDP 端口探测和监听确认。</p>}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {(axes.transports ?? []).map((transport) => <button key={transport} type="button" aria-pressed={selected.transport === transport} onClick={() => chooseTransport(transport)} className="rounded-lg border border-border/60 p-4 text-left transition-colors hover:bg-muted/60 aria-pressed:border-primary aria-pressed:bg-primary/5"><Cable className="mb-3 h-5 w-5 text-muted-foreground" aria-hidden={true} /><span className="block font-medium">{selected.protocol === "SHADOWSOCKS" && transport === "RAW" ? "RAW" : transportLabels[transport] ?? transport}</span><span className="mt-1 block text-xs text-muted-foreground">{props.profiles.filter((profile) => profile.protocol === selected.protocol && profile.transport === transport).length} 个可用配置</span></button>)}
      </div>
      {matchingProfiles.length > 1 && <div className="space-y-3 rounded-lg border border-border/60 p-4"><div><h4 className="flex items-center gap-2 text-sm font-medium"><ShieldCheck className="h-4 w-4 text-muted-foreground" aria-hidden={true} />{selectsListenerNetwork ? "监听网络" : "安全与 Flow"}</h4><p className="mt-1 text-xs text-muted-foreground">{selectsListenerNetwork ? "TCP 与 UDP 使用同一个监听端口，但会分别探测和短期预留。" : "同一传输下的安全组合是独立 profile，不会自动继承隐藏字段。"}</p></div><div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3" role="group" aria-label={selectsListenerNetwork ? "监听网络" : "安全与 Flow"}>{matchingProfiles.map((profile) => {
        const label = selectsListenerNetwork
          ? profile.listenerNetworks.length === 2 ? "TCP + UDP" : `仅 ${profile.listenerNetworks[0]}`
          : `${profile.security === "REALITY" ? "Reality" : profile.security} · ${profile.clientFlow === "XTLS_RPRX_VISION" ? "Vision" : "标准"}`;
        const credentialLabel = profile.clientCredentialType === "UUID" ? "服务端生成 UUID"
          : profile.clientCredentialType === "PASSWORD" ? "服务端生成密码"
            : profile.clientCredentialType === "SHADOWSOCKS_KEY" ? "服务端生成 Shadowsocks 密钥" : "服务端生成 UUID 与 shortId";
        const resolvedCredentialLabel = profile.clientCredentialType === "HTTP_BASIC"
          ? "服务端生成代理用户名与密码"
          : profile.clientCredentialType === "MIXED_USER_PASSWORD"
            ? "服务端生成 SOCKS5 / HTTP 共用用户名与密码"
          : credentialLabel;
        return <button key={profile.id} type="button" aria-pressed={profile.id === selected.id} onClick={() => props.onSelectProfile(profile.id)} className="rounded-md border border-border/60 px-3 py-2 text-left text-sm transition-colors hover:bg-muted/60 aria-pressed:border-primary aria-pressed:bg-primary/5"><span className="block font-medium">{label}</span><span className="mt-1 block text-xs text-muted-foreground">{resolvedCredentialLabel}</span></button>;
      })}</div></div>}
      {usesServiceName && <div className="space-y-1.5 rounded-lg border border-border/60 p-4"><Label htmlFor="xray-grpc-service-name">gRPC 服务名</Label><Input id="xray-grpc-service-name" maxLength={128} value={props.grpcServiceName} onChange={(event) => props.onGrpcServiceNameChange(event.target.value)} /><p className="text-xs text-muted-foreground">1–128 位，仅允许字母、数字、点、下划线、波浪号和连字符；该 profile 不使用 Vision flow。</p></div>}
      {usesPath && <div className="space-y-1.5 rounded-lg border border-border/60 p-4"><Label htmlFor="xray-transport-path">{selected.transport === "WEBSOCKET" ? "WebSocket 路径" : selected.transport === "HTTP_UPGRADE" ? "HTTPUpgrade 路径" : "XHTTP 路径"}</Label><Input id="xray-transport-path" maxLength={128} value={props.xhttpPath} onChange={(event) => props.onXhttpPathChange(event.target.value)} /><p className="text-xs text-muted-foreground">{selected.transport === "XHTTP" ? "固定使用 auto 模式；不开放高级选项或任意 JSON。" : "只允许受控路径；不开放其他高级选项或任意 JSON。"}</p></div>}
      {selected.transport === "MKCP" && <div className="rounded-lg border border-border/60 p-4 text-sm"><p className="font-medium">UDP 监听 · 固定 Xray 核心默认值</p><p className="mt-1 text-xs leading-5 text-muted-foreground">不开放传输调优、seed/header、FinalMask 或任意 JSON；切换到 mKCP 后会重新执行 UDP 端口探测。</p></div>}
      {selected.id === "HYSTERIA2_TLS" && <div className="rounded-lg border border-border/60 p-4 text-sm"><p className="font-medium">UDP 监听 · 固定 Hysteria 2</p><p className="mt-1 text-xs leading-5 text-muted-foreground">版本 2 · ALPN h3 · UDP 空闲 60 秒</p></div>}
      {selected.id === "WIREGUARD_UDP_NONE" && <div className="rounded-lg border border-border/60 p-4 text-sm"><p className="font-medium">Xray 内置 / UDP / 无 TLS</p><p className="mt-1 text-xs leading-5 text-muted-foreground">gVisor · IPv4 · MTU 1420 · 10.0.0.0/24</p><p className="mt-1 text-xs leading-5 text-muted-foreground">网络参数固定，peer 配置由服务端生成。</p></div>}
      {selected.id === "HTTP_RAW_NONE" && <div className="rounded-lg border border-border/60 p-4 text-sm"><p className="font-medium">RAW / TCP / 无 TLS · 强制 Basic 认证</p><p className="mt-1 text-xs leading-5 text-muted-foreground">固定为非透明代理，不开放 allowTransparent、账户凭据或任意 JSON 输入。</p><p className="mt-1 text-xs leading-5 text-muted-foreground">每个账户的代理用户名和密码由服务端独立生成并加密保存。</p></div>}
      {selected.id === "MIXED_RAW_NONE" && <div className="rounded-lg border border-border/60 p-4 text-sm"><p className="font-medium">RAW / TCP / 无 TLS · SOCKS5 + HTTP 共用监听</p><p className="mt-1 text-xs leading-5 text-muted-foreground">同一端口自动识别 SOCKS5 或 HTTP/CONNECT；固定强制用户名与密码认证。</p><p className="mt-1 text-xs leading-5 text-muted-foreground">不支持 SOCKS4/4a 与 UDP，不开放账户凭据、UDP 或任意 JSON 输入。</p></div>}
      {selected.id === "TUNNEL_TCP_LOCAL_NONE" && <div className="space-y-4 rounded-lg border border-border/60 p-4"><div><p className="text-sm font-medium">本机回环 / TCP / 固定目标</p><p className="mt-1 text-xs leading-5 text-muted-foreground">入口恒为目标主机的 127.0.0.1，不使用公网地址；流量通过默认 direct outbound 发往唯一目标。</p></div><div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_10rem]"><div className="space-y-1.5"><Label htmlFor="xray-tunnel-target-address">目标地址</Label><Input id="xray-tunnel-target-address" maxLength={253} autoCapitalize="none" autoCorrect="off" spellCheck={false} value={props.tunnelTargetAddress ?? ""} onChange={(event) => props.onTunnelTargetAddressChange?.(event.target.value)} placeholder="127.0.0.1 或 service.example.com" /></div><div className="space-y-1.5"><Label htmlFor="xray-tunnel-target-port">目标端口</Label><Input id="xray-tunnel-target-port" inputMode="numeric" maxLength={5} value={props.tunnelTargetPort ?? ""} onChange={(event) => props.onTunnelTargetPortChange?.(event.target.value.replace(/\D/g, "").slice(0, 5))} placeholder="1–65535" /></div></div><p className="text-xs leading-5 text-muted-foreground">不开放 UDP、portMap、followRedirect/TProxy、路由、出站选择或任意 JSON。</p></div>}
      <div className="rounded-lg border border-border/60 bg-muted/30 p-4 text-sm"><div className="flex items-center gap-2 font-medium"><Boxes className="h-4 w-4" aria-hidden={true} />当前 profile</div><p className="mt-2 text-muted-foreground">{selected.id === "WIREGUARD_UDP_NONE" ? "WireGuard · Xray 内置 / UDP / 无 TLS" : selected.id === "HTTP_RAW_NONE" ? "HTTP 管理代理 · RAW / TCP / 无 TLS · 强制 Basic 认证" : selected.id === "MIXED_RAW_NONE" ? "Mixed（SOCKS5 + HTTP）· RAW / TCP / 无 TLS · 强制认证" : selected.id === "TUNNEL_TCP_LOCAL_NONE" ? "Tunnel · 本机回环 / TCP / 无客户端认证" : `${protocolLabels[selected.protocol] ?? selected.protocol} · ${transportLabels[selected.transport] ?? selected.transport} · ${selected.security === "REALITY" ? "Reality" : selected.security} · ${selected.clientFlow === "XTLS_RPRX_VISION" ? "Vision" : "无 Flow"}${selected.listenerNetworks.length > 1 ? ` · 监听 ${selected.listenerNetworks.join(" + ")}` : ""}`} · Xray {selected.testedCoreVersion}</p></div>
      {selected.advisoryCode === "CORE_DEPRECATED" && <p role="alert" className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">{XRAY_CORE_DEPRECATED_WARNING}</p>}
      {selected.advisoryCode === "WIREGUARD_BLOCKING_RISK" && <p role="alert" className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">{XRAY_WIREGUARD_BLOCKING_WARNING}</p>}
      {selected.advisoryCode === "PLAINTEXT_PROXY_AUTH_RISK" && <p role="alert" className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">{XRAY_HTTP_PLAINTEXT_AUTH_WARNING}</p>}
      {selected.advisoryCode === "PLAINTEXT_MIXED_AUTH_RISK" && <p role="alert" className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">{XRAY_MIXED_PLAINTEXT_AUTH_WARNING}</p>}
      <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between"><Button type="button" variant="outline" onClick={props.onBack}>返回协议</Button><Button type="button" disabled={!serviceNameValid || !pathValid || !tunnelTargetValid} onClick={props.onNext}>下一步：检测端口</Button></div>
    </div>
  );
}
