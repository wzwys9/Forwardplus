import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { AppRouterOutputs } from "@/lib/trpc";
import { CircleAlert, CircleCheck, CircleHelp, Clock3, KeyRound, Pencil, Power, RefreshCw, Route, WifiOff } from "lucide-react";
import type { ReactNode } from "react";

import { XrayAccessManager } from "./XrayAccessManager";
import { XrayClientManager } from "./XrayClientManager";
import { XRAY_CORE_DEPRECATED_WARNING, XRAY_HTTP_PLAINTEXT_AUTH_WARNING, XRAY_MIXED_PLAINTEXT_AUTH_WARNING, XRAY_WIREGUARD_BLOCKING_WARNING } from "./xrayCreateFlow";
import { formatXrayEndpoint, formatXrayTime } from "./xrayInboundPresentation";

type Detail = AppRouterOutputs["xray"]["inbounds"]["detail"];
type Client = Detail["clients"][number];
type AccessEntry = Detail["accessEntries"][number];
type Runtime = AppRouterOutputs["xray"]["runtimes"]["list"]["items"][number];
type OperationsPage = AppRouterOutputs["xray"]["operations"]["list"];
type RealityScan = AppRouterOutputs["xray"]["realityScans"]["result"];
type DetailTab = "overview" | "clients" | "reality" | "runtime" | "operations";

type Props = {
  detail: Detail;
  runtime: Runtime | null;
  busy: boolean;
  defaultTab?: DetailTab;
  onEditInbound: () => void;
  onConfigureExternalProxy: () => void;
  onSetInboundEnabled: () => void;
  onSyncInbound: () => void;
  operations?: OperationsPage;
  realityScan?: RealityScan | null;
  onOperationPageChange?: (page: number) => void;
  onRescanReality?: () => void;
  onCreateClient: (name: string) => void;
  onUpdateClient: (client: Client, changes: { name?: string; isEnabled?: boolean }) => void;
  onRemoveClient: (client: Client) => void;
  onShareClient: (client: Client, trigger: HTMLButtonElement) => void;
  onCreateAccessEntry: (name: string) => void;
  onUpdateAccessEntry: (entry: AccessEntry, changes: { name?: string; isEnabled?: boolean }) => void;
  onRemoveAccessEntry: (entry: AccessEntry) => void;
  onShareAccessEntry: (entry: AccessEntry, trigger: HTMLButtonElement) => void;
};

const statusLabels: Record<string, string> = {
  WAITING_SYNC: "待同步",
  INSTALLING: "正在安装",
  APPLYING: "正在应用",
  RUNNING: "运行中",
  DISABLED: "已停用",
  PENDING_DELETE: "待删除",
  ERROR: "错误",
  HOST_OFFLINE: "主机离线",
  UNKNOWN: "未知",
  STOPPED: "已停止",
};

const operationLabels: Record<string, string> = {
  PORT_PROBE: "端口探测",
  REALITY_SCAN: "Reality 探测",
  INSTALL: "安装",
  UPGRADE: "升级",
  SYNC: "同步配置",
  RESTART: "重启运行时",
  QUEUED: "排队中",
  SUCCESS: "成功",
  FAILED: "失败",
  TIMEOUT: "超时",
  CANCELLED: "已取消",
  APPLYING: "正在应用",
  VALIDATING_CONFIG: "验证配置",
  DOWNLOADING_ARTIFACT: "下载制品",
  RESTARTING_RUNTIME: "重启运行时",
  CHECKING_LISTENERS: "检查监听器",
  ROLLING_BACK: "回滚",
  COMPLETE: "完成",
};

function Field({ label, children, mono = false }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0 rounded-lg border border-border/60 p-3">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className={`mt-1 break-all text-sm ${mono ? "font-mono" : ""}`}>{children}</dd>
    </div>
  );
}

function OverviewTab({
  detail,
  busy,
  onEditInbound,
  onConfigureExternalProxy,
  onSetInboundEnabled,
  onSyncInbound,
}: Pick<Props, "detail" | "busy" | "onEditInbound" | "onConfigureExternalProxy" | "onSetInboundEnabled" | "onSyncInbound">) {
  const { inbound, deployment, host } = detail;
  const writeDisabled = busy || !host.isOnline || inbound.pendingDelete;
  const hasReality = inbound.security.toLowerCase() === "reality";
  const hasTls = inbound.security.toLowerCase() === "tls";
  const isShadowsocks2022 = inbound.profileId === "SHADOWSOCKS_2022_RAW_NONE"
    || inbound.profileId === "SHADOWSOCKS_2022_RAW_TCP_UDP_NONE";
  const isHysteria2 = inbound.profileId === "HYSTERIA2_TLS";
  const isWireGuard = inbound.profileId === "WIREGUARD_UDP_NONE";
  const isHttp = inbound.profileId === "HTTP_RAW_NONE";
  const isMixed = inbound.profileId === "MIXED_RAW_NONE";
  const isTunnel = inbound.profileId === "TUNNEL_TCP_LOCAL_NONE";
  const protocolLabel = isHysteria2 ? "Hysteria 2" : isWireGuard ? "WireGuard" : isHttp ? "HTTP 管理代理" : isMixed ? "Mixed（SOCKS5 + HTTP）" : isTunnel ? "Tunnel（本机端口转发）" : inbound.protocol.toUpperCase();
  const transportLabel = inbound.transport.toLowerCase() === "kcp" ? "mKCP"
    : isHysteria2 ? "Hysteria" : inbound.transport.toUpperCase();
  const securityLabel = hasReality ? "Reality" : inbound.security.toUpperCase();
  const listenerNetworks = inbound.listenerNetworks ?? [];
  const externalProxySupported = !isTunnel && listenerNetworks.length === 1 && listenerNetworks[0]?.toLowerCase() === "tcp";
  return (
    <div className="space-y-4">
      {!host.isOnline && (
        <p role="alert" className="flex gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">
          <WifiOff className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          Agent 离线，Xray 运行状态未知。这里展示的是最后一次已知报告，不代表 Xray 已停止。
        </p>
      )}
      {inbound.pendingDelete && (
        <p role="alert" className="flex gap-2 rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm">
          <CircleAlert className="mt-0.5 h-4 w-4 shrink-0 text-destructive" aria-hidden="true" />
          节点正在等待新 generation 应用；完成前旧节点和已分享凭据可能继续有效。
        </p>
      )}
      <div className="flex flex-wrap gap-2">
        <Button type="button" size="sm" variant="outline" disabled={writeDisabled} onClick={onEditInbound}>
          <Pencil className="mr-1.5 h-4 w-4" />编辑节点
        </Button>
        <Button type="button" size="sm" variant="outline" disabled={writeDisabled || !externalProxySupported} title={externalProxySupported ? "配置该入站的出口节点" : "首版只支持单 TCP、非 Tunnel 入站"} onClick={onConfigureExternalProxy}>
          <Route className="mr-1.5 h-4 w-4" />配置出口
        </Button>
        <Button type="button" size="sm" variant="outline" disabled={writeDisabled} onClick={onSetInboundEnabled}>
          <Power className="mr-1.5 h-4 w-4" />{inbound.isEnabled ? "停用节点" : "启用节点"}
        </Button>
        <Button type="button" size="sm" variant="outline" disabled={writeDisabled} onClick={onSyncInbound}>
          <RefreshCw className="mr-1.5 h-4 w-4" />重新同步
        </Button>
      </div>
      <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <Field label="节点名称">{inbound.name}</Field>
        <Field label="所属主机">{host.name}</Field>
        <Field label={isTunnel ? "本机入口" : "公网入口"} mono>{formatXrayEndpoint(isTunnel ? inbound.listenAddress : inbound.publicAddress, inbound.listenPort)}</Field>
        <Field label="协议 / 传输 / 安全">{isWireGuard ? "WireGuard · Xray 内置 / UDP / 无 TLS" : isHttp ? "HTTP 管理代理 · RAW / TCP / 无 TLS" : isMixed ? "Mixed（SOCKS5 + HTTP）· RAW / TCP / 无 TLS" : isTunnel ? "Tunnel · 本机回环 / TCP / 无客户端认证" : `${protocolLabel} · ${transportLabel} · ${securityLabel}`}</Field>
        <Field label="监听网络">{listenerNetworks.length > 0 ? listenerNetworks.join(" / ") : "未知"}</Field>
        <Field label="出口">{inbound.externalProxy ? `${inbound.externalProxy.name}（${inbound.externalProxy.protocol}）` : "直连"}</Field>
        {isShadowsocks2022 && <Field label="固定 method" mono>2022-blake3-aes-256-gcm</Field>}
        {isShadowsocks2022 && <Field label="安全层">协议层加密（无 TLS/Reality）</Field>}
        {isHysteria2 && <Field label="固定 Hysteria 2">版本 2 · ALPN h3 · UDP 空闲 60 秒</Field>}
        {isHysteria2 && <Field label="分享校验">叶证书 pinSHA256 · 不关闭证书校验</Field>}
        {isWireGuard && <Field label="固定 WireGuard">gVisor · IPv4 · MTU 1420 · 10.0.0.0/24</Field>}
        {isHttp && <Field label="HTTP 认证">强制 Basic 认证 · 非透明代理</Field>}
        {isHttp && <Field label="账户凭据">服务端生成并加密保存</Field>}
        {isMixed && <Field label="代理入口">SOCKS5 + HTTP/CONNECT · 共用端口</Field>}
        {isMixed && <Field label="认证 / 网络">强制用户名密码 · 仅 TCP · 无 SOCKS4/4a 与 UDP</Field>}
        {isMixed && <Field label="账户凭据">服务端生成并加密保存</Field>}
        {isTunnel && <Field label="固定目标" mono>{formatXrayEndpoint(inbound.tunnelTargetAddress ?? "", inbound.tunnelTargetPort ?? 0)}</Field>}
        {isTunnel && <Field label="访问 / 出站">仅 127.0.0.1 · 零凭据 · 默认 direct</Field>}
        {hasTls && <Field label="TLS 证书">{inbound.tlsCertificate?.configured ? inbound.tlsCertificate.name ?? "已配置" : "未配置"}</Field>}
        {hasTls && <Field label="TLS SNI" mono>{inbound.realityServerName || "未配置"}</Field>}
        {hasReality && <Field label="Reality 目标" mono>{inbound.realityTargetHost}:{inbound.realityTargetPort}</Field>}
        {hasReality && <Field label="Reality serverName" mono>{inbound.realityServerName}</Field>}
        <Field label="部署状态">{statusLabels[deployment.status] ?? deployment.status}</Field>
        <Field label="配置同步">{deployment.configInSync ? "已同步" : "未同步"}</Field>
        <Field label="Generation">期望 {deployment.desiredGeneration} / 已应用 {deployment.appliedGeneration}</Field>
        <Field label="目标版本">{deployment.targetVersion ?? "未知"}</Field>
        <Field label="最后 Agent 报告">{formatXrayTime(host.lastHeartbeat)}</Field>
        {hasReality && <Field label="Reality 公钥" mono>{inbound.realityPublicKey || "未生成"}</Field>}
      </dl>
      {deployment.lastErrorCode && (
        <p role="alert" className="flex gap-2 rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm">
          <CircleAlert className="mt-0.5 h-4 w-4 shrink-0 text-destructive" aria-hidden="true" />
          最近错误码：<span className="font-mono">{deployment.lastErrorCode}</span>
        </p>
      )}
    </div>
  );
}

function RealityTab({ detail, scan, busy, onRescan }: { detail: Detail; scan?: RealityScan | null; busy: boolean; onRescan?: () => void }) {
  const { inbound } = detail;
  const result = scan?.status === "SUCCESS"
    ? scan.results?.find((item) => item.target === `${inbound.realityTargetHost}:${inbound.realityTargetPort}`)
    : undefined;
  return (
    <div className="space-y-4">
      <dl className="grid gap-3 sm:grid-cols-2">
        <Field label="Reality 目标" mono>{inbound.realityTargetHost}:{inbound.realityTargetPort}</Field>
        <Field label="serverName" mono>{inbound.realityServerName}</Field>
        <Field label="Reality 公钥" mono>{inbound.realityPublicKey || "未生成"}</Field>
        <Field label="Reality 私钥状态"><span className="inline-flex items-center gap-2"><KeyRound className="h-4 w-4" aria-hidden="true" />{inbound.hasRealityPrivateKey ? "私钥已安全生成" : "密钥不可用"}</span></Field>
        <Field label="最近 TLS 探测">{result ? `TLS 1.3 ${result.tls13 ? "通过" : "未通过"} · H2 ${result.h2 ? "通过" : "未通过"} · X25519 ${result.x25519 ? "通过" : "未通过"} · ${result.latencyMs} ms` : scan?.status === "RUNNING" || scan?.status === "QUEUED" ? "正在等待 Agent 探测" : scan?.errorCode ? `失败：${scan.errorCode}` : "本次会话尚未重新探测"}</Field>
        <Field label="证书 / 可行性">{result ? `${result.certificateValid ? "证书有效" : "证书无效"} · ${result.feasible ? "可用于 Reality" : "不可用"}` : "未报告"}</Field>
      </dl>
      {onRescan && <Button type="button" size="sm" variant="outline" disabled={busy || !detail.host.isOnline || scan?.status === "RUNNING" || scan?.status === "QUEUED"} onClick={onRescan}><RefreshCw className="mr-1.5 h-4 w-4" />重新探测当前目标</Button>}
    </div>
  );
}

function RuntimeTab({ detail, runtime }: { detail: Detail; runtime: Runtime | null }) {
  if (!detail.host.isOnline) {
    return (
      <p role="alert" className="flex gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-4 text-sm">
        <WifiOff className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
        Agent 离线，Xray 运行状态未知。不会把离线误判为已停止。
      </p>
    );
  }
  const serviceStatus = runtime?.serviceStatus ?? detail.runtime.serviceStatus;
  const installedVersion = runtime?.installedVersion ?? detail.runtime.installedVersion;
  const runningVersion = runtime?.runningVersion ?? detail.runtime.runningVersion;
  return (
    <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
      <Field label="所属主机">{detail.host.name}</Field>
      <Field label="服务状态">{statusLabels[serviceStatus] ?? serviceStatus}</Field>
      <Field label="已安装版本">{installedVersion ?? "未安装"}</Field>
      <Field label="运行版本">{runningVersion ?? "未知"}</Field>
      <Field label="目标版本">{runtime?.targetVersion ?? detail.deployment.targetVersion ?? "未知"}</Field>
      <Field label="Generation">期望 {runtime?.desiredGeneration ?? detail.deployment.desiredGeneration} / 已应用 {runtime?.appliedGeneration ?? detail.deployment.appliedGeneration}</Field>
      <Field label="进程 PID">{detail.runtime.processId ?? "未运行"}</Field>
      <Field label="期望配置哈希" mono>{detail.deployment.desiredConfigHash?.slice(0, 12) ?? "未知"}</Field>
      <Field label="已应用配置哈希" mono>{detail.deployment.appliedConfigHash?.slice(0, 12) ?? "未知"}</Field>
      <Field label="监听器">{detail.runtime.listeners.length > 0 ? detail.runtime.listeners.map((listener) => `${listener.network.toUpperCase()} ${listener.port}/${listener.status}`).join(" · ") : "未报告"}</Field>
      <Field label="最近稳定错误">{detail.runtime.lastErrorCode ? `${detail.runtime.lastErrorCode} · ${detail.runtime.lastErrorMessage ?? "运行时报告错误"}` : "无"}</Field>
      <Field label="最后报告">{formatXrayTime(runtime?.lastReportedAt ?? detail.runtime.reportedAt)}</Field>
    </dl>
  );
}

function operationDuration(operation: OperationsPage["items"][number]) {
  if (!operation.startedAt) return "未开始";
  const end = operation.finishedAt ? new Date(operation.finishedAt).getTime() : Date.now();
  const start = new Date(operation.startedAt).getTime();
  return Number.isFinite(end - start) ? `${Math.max(0, Math.round((end - start) / 1000))} 秒` : "未知";
}

function OperationsTab({ detail, operations, onPageChange }: { detail: Detail; operations?: OperationsPage; onPageChange?: (page: number) => void }) {
  const page = operations ?? { items: detail.operations, page: 1, pageSize: detail.operations.length || 20, totalItems: detail.operations.length, totalPages: 1 };
  if (page.items.length === 0) {
    return <p className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">暂无操作记录。</p>;
  }
  return (
    <ol className="space-y-2">
      {page.items.map((operation) => {
        const Icon = operation.status === "SUCCESS" ? CircleCheck
          : operation.status === "FAILED" || operation.status === "TIMEOUT" ? CircleAlert
            : operation.status === "QUEUED" || operation.status === "RUNNING" ? Clock3 : CircleHelp;
        return (
          <li key={operation.operationId} className="flex flex-col gap-2 rounded-lg border border-border/60 p-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="flex min-w-0 gap-2">
              <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              <div className="min-w-0">
                <p className="text-sm font-medium">{operationLabels[operation.type] ?? operation.type}</p>
                <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{operation.operationId}</p>
                <p className="mt-1 text-xs text-muted-foreground">阶段：{operationLabels[operation.stage] ?? operation.stage} · 耗时：{operationDuration(operation)}</p>
                {operation.errorCode && <p className="mt-1 text-xs text-destructive">错误码：{operation.errorCode}</p>}
              </div>
            </div>
            <div className="shrink-0 text-left sm:text-right">
              <Badge variant={operation.status === "SUCCESS" ? "default" : operation.status === "FAILED" ? "destructive" : "secondary"}>
                {operationLabels[operation.status] ?? operation.status}
              </Badge>
              <p className="mt-1 text-xs text-muted-foreground">{formatXrayTime(operation.updatedAt)}</p>
            </div>
          </li>
        );
      })}
      {page.totalPages > 1 && <li className="flex items-center justify-between gap-3 pt-2"><p className="text-xs text-muted-foreground">第 {page.page} / {page.totalPages} 页 · 共 {page.totalItems} 条</p><div className="flex gap-2"><Button type="button" size="sm" variant="outline" disabled={page.page <= 1} onClick={() => onPageChange?.(page.page - 1)}>上一页</Button><Button type="button" size="sm" variant="outline" disabled={page.page >= page.totalPages} onClick={() => onPageChange?.(page.page + 1)}>下一页</Button></div></li>}
    </ol>
  );
}

export function XrayInboundDetailContent({
  detail,
  runtime,
  busy,
  defaultTab = "overview",
  onEditInbound,
  onConfigureExternalProxy,
  onSetInboundEnabled,
  onSyncInbound,
  onCreateClient,
  onUpdateClient,
  onRemoveClient,
  onShareClient,
  onCreateAccessEntry,
  onUpdateAccessEntry,
  onRemoveAccessEntry,
  onShareAccessEntry,
  operations,
  realityScan,
  onOperationPageChange,
  onRescanReality,
}: Props) {
  const genericAccessEntries = detail.accessEntries.filter((entry) => entry.legacyClientId === null);
  const protocol = detail.inbound.protocol.toLowerCase();
  const usesGenericAccess = genericAccessEntries.length > 0 || protocol === "trojan" || protocol === "vmess" || protocol === "http" || protocol === "mixed"
    || protocol === "shadowsocks" || protocol === "hysteria" || protocol === "wireguard";
  const isWireGuard = detail.inbound.profileId === "WIREGUARD_UDP_NONE";
  const isHttp = detail.inbound.profileId === "HTTP_RAW_NONE";
  const isMixed = detail.inbound.profileId === "MIXED_RAW_NONE";
  const isTunnel = detail.inbound.profileId === "TUNNEL_TCP_LOCAL_NONE";
  const hasReality = detail.inbound.security.toLowerCase() === "reality";
  return (
    <Tabs defaultValue={defaultTab} className="min-h-0">
      <TabsList aria-label="节点详情" className="h-auto w-full justify-start overflow-x-auto">
        <TabsTrigger value="overview">概览</TabsTrigger>
        {!isTunnel && <TabsTrigger value="clients">{isWireGuard ? "Peers" : usesGenericAccess ? "账户" : "客户端"}</TabsTrigger>}
        {hasReality && <TabsTrigger value="reality">Reality</TabsTrigger>}
        <TabsTrigger value="runtime">运行时</TabsTrigger>
        <TabsTrigger value="operations">操作记录</TabsTrigger>
      </TabsList>
      {detail.inbound.advisoryCode === "CORE_DEPRECATED" && (
        <p role="alert" className="mt-3 flex gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">
          <CircleAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          {XRAY_CORE_DEPRECATED_WARNING}
        </p>
      )}
      {detail.inbound.advisoryCode === "WIREGUARD_BLOCKING_RISK" && (
        <p role="alert" className="mt-3 flex gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">
          <CircleAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          {XRAY_WIREGUARD_BLOCKING_WARNING}
        </p>
      )}
      {detail.inbound.advisoryCode === "PLAINTEXT_PROXY_AUTH_RISK" && (
        <p role="alert" className="mt-3 flex gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">
          <CircleAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          {XRAY_HTTP_PLAINTEXT_AUTH_WARNING}
        </p>
      )}
      {detail.inbound.advisoryCode === "PLAINTEXT_MIXED_AUTH_RISK" && (
        <p role="alert" className="mt-3 flex gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">
          <CircleAlert className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          {XRAY_MIXED_PLAINTEXT_AUTH_WARNING}
        </p>
      )}
      <div className="mt-3 max-h-[62svh] overflow-y-auto pr-1">
        <TabsContent value="overview">
          <OverviewTab
            detail={detail}
            busy={busy}
            onEditInbound={onEditInbound}
            onConfigureExternalProxy={onConfigureExternalProxy}
            onSetInboundEnabled={onSetInboundEnabled}
            onSyncInbound={onSyncInbound}
          />
        </TabsContent>
        {!isTunnel && <TabsContent value="clients">
          {usesGenericAccess ? (
            <XrayAccessManager
              accessEntries={genericAccessEntries}
              accessKind={isWireGuard ? "WIREGUARD_PEER" : isHttp ? "HTTP_BASIC" : isMixed ? "MIXED_USER_PASSWORD" : "STANDARD"}
              appliedGeneration={detail.deployment.appliedGeneration}
              hostOnline={detail.host.isOnline}
              busy={busy}
              onCreate={onCreateAccessEntry}
              onUpdate={onUpdateAccessEntry}
              onRemove={onRemoveAccessEntry}
              onShare={onShareAccessEntry}
            />
          ) : (
            <XrayClientManager
              clients={detail.clients}
              hostOnline={detail.host.isOnline}
              busy={busy}
              onCreate={onCreateClient}
              onUpdate={onUpdateClient}
              onRemove={onRemoveClient}
              onShare={onShareClient}
            />
          )}
        </TabsContent>}
        {hasReality && <TabsContent value="reality"><RealityTab detail={detail} scan={realityScan} busy={busy} onRescan={onRescanReality} /></TabsContent>}
        <TabsContent value="runtime"><RuntimeTab detail={detail} runtime={runtime} /></TabsContent>
        <TabsContent value="operations"><OperationsTab detail={detail} operations={operations} onPageChange={onOperationPageChange} /></TabsContent>
      </div>
    </Tabs>
  );
}
