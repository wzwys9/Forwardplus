import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { AlertTriangle, Check, CircleX, Plus, Radar, Trash2 } from "lucide-react";

import {
  parseAdminRealityTargets,
  validInitialClients,
  type XrayDeploymentAction,
  type XrayDeploymentState,
  type XrayRealityCandidate,
  tlsCertificateCoversServerName,
  validTlsServerName,
} from "./xrayCreateDeployment";
import { XRAY_HTTP_PLAINTEXT_AUTH_WARNING, XRAY_MIXED_PLAINTEXT_AUTH_WARNING } from "./xrayCreateFlow";

export type XrayCreateTlsCertificateOption = {
  id: number;
  name: string;
  dnsNames: string[];
  status: "VALID" | "EXPIRING_30" | "EXPIRING_14" | "EXPIRING_7" | "EXPIRED";
  privateKeyConfigured: true;
};

type Props = {
  state: XrayDeploymentState;
  security?: "REALITY" | "TLS" | "NONE";
  accessKind?: "STANDARD" | "WIREGUARD_PEER" | "HTTP_BASIC" | "MIXED_USER_PASSWORD" | "NONE";
  certificates?: XrayCreateTlsCertificateOption[];
  certificatesLoading?: boolean;
  certificatesError?: boolean;
  onRetryCertificates?: () => void;
  onAction: (action: XrayDeploymentAction) => void;
  onBackFromSecurity?: () => void;
  onScan: () => void;
  onSubmit: () => void;
  submitting: boolean;
  canSubmit: boolean;
  summary?: {
    hostName: string;
    nodeName: string;
    endpoint: string;
    currentVersion: string | null;
    targetVersion: string;
    willInstall: boolean;
    protocolLabel?: string;
    clientFlowLabel?: string;
    securityDetail?: string;
    advisoryLabel?: string;
  };
};

function Feature({ label, value }: { label: string; value: boolean }) {
  const Icon = value ? Check : CircleX;
  return <span className="inline-flex items-center gap-1 text-xs"><Icon className="h-3.5 w-3.5" aria-hidden={true} />{label}：{value ? "是" : "否"}</span>;
}

function Candidate({ item, selected, onSelect }: { item: XrayRealityCandidate; selected: boolean; onSelect: () => void }) {
  return (
    <article className="rounded-lg border border-border/60 p-3">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0"><p className="break-all text-sm font-medium">{item.target}</p><p className="mt-1 break-all text-xs text-muted-foreground">serverName：{item.serverNames[0] ?? "无"} · {item.resolvedIp}</p></div>
        <Badge variant={item.feasible ? "default" : "destructive"}>{item.feasible ? "可用" : "不可用"}</Badge>
      </div>
      <div className="mt-3 flex flex-wrap gap-x-3 gap-y-2 text-muted-foreground"><Feature label="TLS 1.3" value={item.tls13} /><Feature label="H2" value={item.h2} /><Feature label="X25519" value={item.x25519} /><Feature label="证书有效" value={item.certificateValid} /><span className="text-xs">延迟：{item.latencyMs} ms</span></div>
      {!item.feasible && <p className="mt-2 break-all font-mono text-xs text-destructive">{item.reasonCode ?? "REALITY_TLS_UNSUPPORTED"}</p>}
      <Button type="button" size="sm" variant={selected ? "default" : "outline"} className="mt-3" disabled={!item.feasible} onClick={onSelect}>{selected ? "已选择" : "选择此目标"}</Button>
    </article>
  );
}

function RealityStep({ state, onAction, onScan, onBackFromSecurity }: Pick<Props, "state" | "onAction" | "onScan" | "onBackFromSecurity">) {
  const pending = state.scan.phase === "QUEUED" || state.scan.phase === "RUNNING";
  const targets = parseAdminRealityTargets(state.customTargets);
  const canScan = !pending && (state.scanSource === "DEFAULT_CANDIDATES" || targets.length > 0);
  return (
    <div className="space-y-5">
      <div><h3 className="font-semibold">Reality 目标扫描</h3><p className="mt-1 text-sm text-muted-foreground">扫描由目标 Agent 执行，只有全部安全与 TLS 条件通过的候选可以选择。</p></div>
      <div className="grid grid-cols-2 gap-2" role="group" aria-label="Reality 扫描来源"><Button type="button" variant={state.scanSource === "DEFAULT_CANDIDATES" ? "default" : "outline"} aria-pressed={state.scanSource === "DEFAULT_CANDIDATES"} onClick={() => onAction({ type: "SET_SCAN_SOURCE", source: "DEFAULT_CANDIDATES" })}>默认候选</Button><Button type="button" variant={state.scanSource === "ADMIN_DOMAINS" ? "default" : "outline"} aria-pressed={state.scanSource === "ADMIN_DOMAINS"} onClick={() => onAction({ type: "SET_SCAN_SOURCE", source: "ADMIN_DOMAINS" })}>自定义域名</Button></div>
      {state.scanSource === "ADMIN_DOMAINS" && <div className="space-y-1.5"><Label htmlFor="xray-reality-targets">目标列表</Label><Textarea id="xray-reality-targets" value={state.customTargets} onChange={(event) => onAction({ type: "SET_CUSTOM_TARGETS", value: event.target.value })} aria-describedby="xray-reality-targets-help" placeholder={"example.com:443\nwww.example.org:443"} /><p id="xray-reality-targets-help" className="text-xs text-muted-foreground">每行或逗号分隔，最多 64 个 hostname:port；URL、IP 和 CIDR 会被后端拒绝。</p></div>}
      <Button type="button" disabled={!canScan} onClick={onScan}><Radar className="mr-2 h-4 w-4" aria-hidden={true} />{pending ? "等待 Agent 扫描" : state.scan.phase === "SUCCESS" || state.scan.phase === "FAILED" ? "重新扫描" : "扫描目标站点"}</Button>
      <div aria-live="polite">
        {pending && <p className="rounded-lg border border-border/60 p-3 text-sm text-muted-foreground">扫描 operation 已创建，等待 Agent 返回结构化结果。</p>}
        {state.scan.phase === "FAILED" && <p role="alert" className="flex gap-2 rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm"><AlertTriangle className="h-4 w-4 shrink-0 text-destructive" aria-hidden={true} />扫描失败：{state.scan.errorCode}。请检查主机状态或目标后重试。</p>}
      </div>
      {state.scan.phase === "SUCCESS" && <div className="space-y-2">{state.scan.results.map((item) => <Candidate key={item.target} item={item} selected={state.selectedReality?.target === item.target} onSelect={() => onAction({ type: "SELECT_REALITY", candidate: item })} />)}{state.scan.results.length === 0 && <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">扫描没有返回候选，请重新扫描。</p>}</div>}
      <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between"><Button type="button" variant="outline" onClick={() => onBackFromSecurity ? onBackFromSecurity() : onAction({ type: "BACK_SETUP" })}>返回传输</Button><Button type="button" disabled={!state.selectedReality} onClick={() => onAction({ type: "GO_CLIENTS" })}>下一步：账户</Button></div>
    </div>
  );
}

function TlsStep(props: Pick<Props,
  "state" | "onAction" | "onBackFromSecurity" | "certificates" | "certificatesLoading" | "certificatesError" | "onRetryCertificates"
>) {
  const certificates = props.certificates ?? [];
  const selected = certificates.find((certificate) => certificate.id === props.state.tlsCertificateId);
  const serverNameValid = validTlsServerName(props.state.tlsServerName);
  const covered = tlsCertificateCoversServerName(selected, props.state.tlsServerName);
  const canContinue = !!selected && selected.status !== "EXPIRED" && selected.privateKeyConfigured && serverNameValid && covered;
  return (
    <div className="space-y-5">
      <div><h3 className="font-semibold">TLS 证书与 SNI</h3><p className="mt-1 text-sm text-muted-foreground">只能选择当前主机托管的有效证书；服务端会在创建前后再次验证归属、私钥和 DNS SAN。</p></div>
      {props.certificatesLoading ? <div aria-label="正在加载 TLS 证书" className="space-y-2"><Skeleton className="h-10 w-full" /><Skeleton className="h-20 w-full" /></div> : props.certificatesError ? <div role="alert" className="flex items-center justify-between gap-3 rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm"><span>TLS 证书加载失败，请重试。</span><Button type="button" size="sm" variant="outline" onClick={props.onRetryCertificates}>重新加载</Button></div> : certificates.length === 0 ? <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">当前主机尚未导入 TLS 证书。请关闭创建窗口，先到“TLS 证书”页签导入。</p> : <div className="space-y-1.5"><Label htmlFor="xray-tls-certificate">受管 TLS 证书</Label><Select value={selected ? String(selected.id) : undefined} onValueChange={(value) => props.onAction({ type: "SELECT_TLS_CERTIFICATE", certificateId: Number(value) || null })}><SelectTrigger id="xray-tls-certificate"><SelectValue placeholder="请选择当前主机证书" /></SelectTrigger><SelectContent>{certificates.map((certificate) => <SelectItem key={certificate.id} value={String(certificate.id)} disabled={certificate.status === "EXPIRED"}>{certificate.name}{certificate.status === "EXPIRED" ? "（已过期）" : ""}</SelectItem>)}</SelectContent></Select>{selected && <p className="break-all text-xs text-muted-foreground">已选择：{selected.name} · DNS SAN：{selected.dnsNames.join("、")}</p>}</div>}
      <div className="space-y-1.5"><Label htmlFor="xray-tls-server-name">服务器名称（SNI）</Label><Input id="xray-tls-server-name" maxLength={253} autoCapitalize="none" autoCorrect="off" spellCheck={false} value={props.state.tlsServerName} onChange={(event) => props.onAction({ type: "SET_TLS_SERVER_NAME", value: event.target.value })} placeholder="tls.example.com" /><p className="text-xs text-muted-foreground">只接受规范化 DNS 名称，不接受 IP 或通配符；必须被所选证书的 DNS SAN 覆盖。</p></div>
      {props.state.tlsServerName && !serverNameValid && <p role="alert" className="text-sm text-destructive">SNI 必须是 1–253 位 ASCII DNS 名称，不能是 IP 或通配符。</p>}
      {selected && serverNameValid && !covered && <p role="alert" className="text-sm text-destructive">所选证书的 DNS SAN 不覆盖该 SNI。</p>}
      <p className="rounded-lg border border-border/60 bg-muted/30 p-3 text-sm text-muted-foreground">分享链接会固定携带叶证书 pin，不使用 <code>allowInsecure</code>；证书轮换后需要重新分享。</p>
      <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between"><Button type="button" variant="outline" onClick={() => props.onBackFromSecurity ? props.onBackFromSecurity() : props.onAction({ type: "BACK_SETUP" })}>返回传输</Button><Button type="button" disabled={!canContinue} onClick={() => props.onAction({ type: "GO_CLIENTS" })}>下一步：账户</Button></div>
    </div>
  );
}

function NoTransportSecurityStep({ onAction, onBackFromSecurity, accessKind }: Pick<Props, "onAction" | "onBackFromSecurity" | "accessKind">) {
  if (accessKind === "NONE") {
    return (
      <div className="space-y-5">
        <div><h3 className="font-semibold">Tunnel 固定访问边界</h3><p className="mt-1 text-sm text-muted-foreground">Xray Tunnel 没有客户端认证协议，因此服务端强制只监听目标主机回环地址。</p></div>
        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-3 rounded-lg border border-border/60 p-4 text-sm">
          <dt className="text-muted-foreground">入口</dt><dd className="font-mono text-xs">127.0.0.1 · 单 TCP 端口</dd>
          <dt className="text-muted-foreground">凭据</dt><dd>无；只有目标主机本地进程可以连接</dd>
          <dt className="text-muted-foreground">出站</dt><dd>唯一固定目标 · 默认 direct</dd>
        </dl>
        <p className="rounded-lg border border-border/60 bg-muted/30 p-3 text-sm text-muted-foreground">该入口不会暴露到公网，也不生成客户端、账户、分享或订阅；回环边界不提供传输加密。</p>
        <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between"><Button type="button" variant="outline" onClick={() => onBackFromSecurity ? onBackFromSecurity() : onAction({ type: "BACK_SETUP" })}>返回传输</Button><Button type="button" onClick={() => onAction({ type: "GO_CLIENTS_NONE" })}>下一步：访问边界</Button></div>
      </div>
    );
  }
  if (accessKind === "WIREGUARD_PEER") {
    return (
      <div className="space-y-5">
        <div><h3 className="font-semibold">WireGuard 固定安全边界</h3><p className="mt-1 text-sm text-muted-foreground">节点和每个 peer 的安全材料均由服务端生成、加密保存，并只在按需导出配置时短暂返回。</p></div>
        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-3 rounded-lg border border-border/60 p-4 text-sm">
          <dt className="text-muted-foreground">实现</dt><dd>Xray 内置 WireGuard · gVisor</dd>
          <dt className="text-muted-foreground">网络</dt><dd>UDP · IPv4 · MTU 1420 · 10.0.0.0/24</dd>
          <dt className="text-muted-foreground">配置</dt><dd>服务端生成并分配 peer 地址</dd>
        </dl>
        <p className="rounded-lg border border-border/60 bg-muted/30 p-3 text-sm text-muted-foreground">界面不接受密钥、PSK 或网络参数输入；创建后按 peer 导出独立配置。</p>
        <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between"><Button type="button" variant="outline" onClick={() => onBackFromSecurity ? onBackFromSecurity() : onAction({ type: "BACK_SETUP" })}>返回传输</Button><Button type="button" onClick={() => onAction({ type: "GO_CLIENTS_NONE" })}>下一步：peer</Button></div>
      </div>
    );
  }
  if (accessKind === "HTTP_BASIC") {
    return (
      <div className="space-y-5">
        <div><h3 className="font-semibold">HTTP 代理固定安全边界</h3><p className="mt-1 text-sm text-muted-foreground">固定为非透明 RAW / TCP 代理，并强制每个账户使用独立的 Basic 认证。</p></div>
        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-3 rounded-lg border border-border/60 p-4 text-sm">
          <dt className="text-muted-foreground">认证</dt><dd>强制 HTTP Basic；不允许匿名账户</dd>
          <dt className="text-muted-foreground">凭据</dt><dd>用户名和密码均由服务端生成并加密保存</dd>
          <dt className="text-muted-foreground">传输</dt><dd>RAW / TCP · 非透明代理 · 无 TLS</dd>
        </dl>
        <p role="alert" className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">{XRAY_HTTP_PLAINTEXT_AUTH_WARNING}</p>
        <p className="rounded-lg border border-border/60 bg-muted/30 p-3 text-sm text-muted-foreground">界面不接受用户名、密码、allowTransparent 或任意 JSON；创建后按账户生成独立代理地址。</p>
        <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between"><Button type="button" variant="outline" onClick={() => onBackFromSecurity ? onBackFromSecurity() : onAction({ type: "BACK_SETUP" })}>返回传输</Button><Button type="button" onClick={() => onAction({ type: "GO_CLIENTS_NONE" })}>下一步：账户</Button></div>
      </div>
    );
  }
  if (accessKind === "MIXED_USER_PASSWORD") {
    return (
      <div className="space-y-5">
        <div><h3 className="font-semibold">Mixed 代理固定安全边界</h3><p className="mt-1 text-sm text-muted-foreground">同一 RAW / TCP 端口提供 SOCKS5 与 HTTP/CONNECT，并强制每个账户使用独立认证。</p></div>
        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-3 rounded-lg border border-border/60 p-4 text-sm">
          <dt className="text-muted-foreground">入口</dt><dd>SOCKS5 + HTTP/CONNECT · 共用端口</dd>
          <dt className="text-muted-foreground">认证</dt><dd>用户名与密码；不允许匿名账户</dd>
          <dt className="text-muted-foreground">边界</dt><dd>仅 TCP · 不支持 SOCKS4/4a 与 UDP · 无 TLS</dd>
        </dl>
        <p role="alert" className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">{XRAY_MIXED_PLAINTEXT_AUTH_WARNING}</p>
        <p className="rounded-lg border border-border/60 bg-muted/30 p-3 text-sm text-muted-foreground">界面不接受用户名、密码、UDP 或任意 JSON；创建后按账户生成 SOCKS5 和 HTTP 两个代理地址。</p>
        <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between"><Button type="button" variant="outline" onClick={() => onBackFromSecurity ? onBackFromSecurity() : onAction({ type: "BACK_SETUP" })}>返回传输</Button><Button type="button" onClick={() => onAction({ type: "GO_CLIENTS_NONE" })}>下一步：账户</Button></div>
      </div>
    );
  }
  return (
    <div className="space-y-5">
      <div><h3 className="font-semibold">协议层加密（无 TLS/Reality）</h3><p className="mt-1 text-sm text-muted-foreground">Shadowsocks 2022 由协议自身提供加密，不叠加 TLS 或 Reality。</p></div>
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-3 rounded-lg border border-border/60 p-4 text-sm">
        <dt className="text-muted-foreground">固定 method</dt><dd className="font-mono text-xs">2022-blake3-aes-256-gcm</dd>
        <dt className="text-muted-foreground">密钥</dt><dd>服务器密钥和每个账户密钥均由服务端自动生成并加密保存</dd>
        <dt className="text-muted-foreground">传输</dt><dd>RAW / TCP</dd>
      </dl>
      <p className="rounded-lg border border-border/60 bg-muted/30 p-3 text-sm text-muted-foreground">界面不接受密钥、method 或任意 JSON 输入；创建后按账户生成独立分享链接。</p>
      <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between"><Button type="button" variant="outline" onClick={() => onBackFromSecurity ? onBackFromSecurity() : onAction({ type: "BACK_SETUP" })}>返回传输</Button><Button type="button" onClick={() => onAction({ type: "GO_CLIENTS_NONE" })}>下一步：账户</Button></div>
    </div>
  );
}

function ClientStep({ state, onAction, summary, security, canSubmit, accessKind }: Pick<Props, "state" | "onAction" | "summary" | "security" | "canSubmit" | "accessKind">) {
  if (accessKind === "NONE") {
    return (
      <div className="space-y-5">
        <div><h3 className="font-semibold">访问边界</h3><p className="mt-1 text-sm text-muted-foreground">此 profile 不创建账户或客户端，访问控制由目标主机的 127.0.0.1 回环监听提供。</p></div>
        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-3 rounded-lg border border-border/60 p-4 text-sm"><dt className="text-muted-foreground">账户</dt><dd>0 个</dd><dt className="text-muted-foreground">分享</dt><dd>无</dd><dt className="text-muted-foreground">本机入口</dt><dd className="font-mono text-xs">{summary?.endpoint ?? "-"}</dd></dl>
        <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between"><Button type="button" variant="outline" onClick={() => onAction({ type: "BACK_REALITY" })}>返回安全配置</Button><Button type="button" disabled={!canSubmit} onClick={() => onAction({ type: "GO_CONFIRM_CREDENTIALLESS" })}>下一步：确认部署</Button></div>
      </div>
    );
  }
  const valid = validInitialClients(state.clients);
  const isWireGuard = accessKind === "WIREGUARD_PEER";
  const isHttp = accessKind === "HTTP_BASIC";
  const isMixed = accessKind === "MIXED_USER_PASSWORD";
  const isProxyAccount = isHttp || isMixed;
  return (
    <div className="space-y-5">
      <div><h3 className="font-semibold">{isWireGuard ? "初始 peer" : "初始账户"}</h3><p className="mt-1 text-sm text-muted-foreground">{isWireGuard ? "浏览器只提交 peer 名称；地址和认证材料由服务端独立生成。" : isProxyAccount ? `浏览器只提交账户备注；${isMixed ? "SOCKS5 与 HTTP 共用的" : "代理"}用户名和密码由服务端独立生成。` : `浏览器只提交名称；认证凭据由服务端独立生成。当前 Flow：${summary?.clientFlowLabel ?? "Vision"}。`}</p></div>
      <div className="space-y-3">{state.clients.map((client, index) => <div key={client.key} className="flex items-end gap-2 rounded-lg border border-border/60 p-3"><div className="min-w-0 flex-1 space-y-1.5"><Label htmlFor={`xray-client-${client.key}`}>{isWireGuard ? `peer ${index + 1} 名称` : isProxyAccount ? `账户 ${index + 1} 备注` : `客户端 ${index + 1} 名称`}</Label><Input id={`xray-client-${client.key}`} maxLength={128} value={client.name} onChange={(event) => onAction({ type: "SET_CLIENT_NAME", key: client.key, value: event.target.value })} /></div><Button type="button" size="icon" variant="outline" aria-label={`删除${isWireGuard ? " peer" : isProxyAccount ? "账户" : "客户端"} ${index + 1}`} disabled={state.clients.length <= 1} onClick={() => onAction({ type: "REMOVE_CLIENT", key: client.key })}><Trash2 className="h-4 w-4" aria-hidden={true} /></Button></div>)}</div>
      {!valid && <p role="alert" className="text-sm text-destructive">名称不能为空、最长 128 个字符，且不能大小写重复。</p>}
      <Button type="button" variant="outline" disabled={state.clients.length >= 32} onClick={() => onAction({ type: "ADD_CLIENT" })}><Plus className="mr-2 h-4 w-4" aria-hidden={true} />添加{isWireGuard ? " peer" : isProxyAccount ? "账户" : "客户端"}（{state.clients.length}/32）</Button>
      <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between"><Button type="button" variant="outline" onClick={() => onAction({ type: "BACK_REALITY" })}>返回{security === "TLS" ? " TLS 配置" : security === "NONE" ? "安全配置" : " Reality"}</Button><Button type="button" disabled={!valid || !canSubmit} onClick={() => onAction({ type: security === "NONE" ? "GO_CONFIRM_NONE" : "GO_CONFIRM" })}>下一步：确认部署</Button></div>
    </div>
  );
}

function ConfirmStep({ state, onAction, onSubmit, submitting, canSubmit, summary, accessKind }: Props) {
  const accessLabel = accessKind === "WIREGUARD_PEER" ? "peer"
    : accessKind === "HTTP_BASIC" || accessKind === "MIXED_USER_PASSWORD" ? "账户" : accessKind === "NONE" ? "凭据" : "客户端";
  const accessCount = accessKind === "NONE" ? 0 : state.clients.length;
  return <div className="space-y-5"><div><h3 className="font-semibold">确认并部署</h3><p className="mt-1 text-sm text-muted-foreground">{accessKind === "NONE" ? "提交后以持久 operation 部署固定回环 Tunnel；不会创建、生成或保存任何客户端凭据。" : "提交后由服务端生成认证凭据和所需安全材料，并以持久 operation 跟踪部署；浏览器不会生成或保存凭据。"}</p></div><dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-3 rounded-lg border border-border/60 p-4 text-sm"><dt className="text-muted-foreground">节点</dt><dd>{summary?.nodeName ?? "-"}</dd><dt className="text-muted-foreground">主机</dt><dd>{summary?.hostName ?? "-"}</dd><dt className="text-muted-foreground">{accessKind === "NONE" ? "本机 endpoint" : "公网 endpoint"}</dt><dd className="break-all font-mono text-xs">{summary?.endpoint ?? "-"}</dd><dt className="text-muted-foreground">协议</dt><dd>{summary?.protocolLabel ?? "VLESS · RAW · Reality · Vision"}</dd><dt className="text-muted-foreground">安全配置</dt><dd className="break-all">{summary?.securityDetail ?? state.selectedReality?.target ?? "-"}</dd><dt className="text-muted-foreground">{accessLabel}</dt><dd>{accessCount} 个</dd><dt className="text-muted-foreground">Xray 版本</dt><dd className="font-mono text-xs">{summary?.currentVersion ?? "未安装"} → {summary?.targetVersion ?? "-"}</dd></dl>{summary?.advisoryLabel && <p role="alert" className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">{summary.advisoryLabel}</p>}{summary?.willInstall && <p className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">目标主机尚未运行面板固定版本；部署会先安装并验证 ForwardX 专属 Xray，再应用节点配置。</p>}{!canSubmit && <p role="alert" className="rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm">主机已离线或能力状态发生变化，请恢复后再提交。</p>}{state.submitError && <p role="alert" className="flex gap-2 rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm"><AlertTriangle className="h-4 w-4 shrink-0 text-destructive" aria-hidden={true} />创建未提交：{state.submitError}。表单已保留，请按提示处理后重试。</p>}<div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between"><Button type="button" variant="outline" disabled={submitting} onClick={() => onAction({ type: "BACK_CLIENTS" })}>返回{accessKind === "NONE" ? "访问边界" : accessLabel}</Button><Button type="button" disabled={submitting || !canSubmit} onClick={onSubmit}>{submitting ? "正在创建 operation" : "创建并部署"}</Button></div></div>;
}

export function XrayRealityClientSteps(props: Props) {
  if (props.state.stage === "REALITY") {
    if (props.security === "TLS") return <TlsStep {...props} />;
    if (props.security === "NONE") return <NoTransportSecurityStep {...props} />;
    return <RealityStep {...props} />;
  }
  if (props.state.stage === "CLIENTS") return <ClientStep {...props} />;
  return <ConfirmStep {...props} />;
}
