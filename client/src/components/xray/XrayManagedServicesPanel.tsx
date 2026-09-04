import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "./XrayDialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { copyTextToClipboard } from "@/lib/clipboard";
import { trpc } from "@/lib/trpc";
import { getQueryKey } from "@trpc/react-query";
import { useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Copy, Download, KeyRound, Network, Plus, QrCode, RefreshCw, Server, ShieldCheck, Trash2, Users } from "lucide-react";
import QRCode from "qrcode";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

const statusLabels: Record<string, string> = {
  WAITING_SYNC: "待同步", RUNNING: "运行中", DISABLED: "已停用", PENDING_DELETE: "待删除", ERROR: "错误",
};

type CreateForm = {
  kind: "MTPROTO_FAKE_TLS" | "AMNEZIAWG";
  hostId: number | null;
  name: string;
  publicAddress: string;
  port: string;
  fakeTlsDomain: string;
  memberName: string;
};

function emptyCreate(kind: CreateForm["kind"]): CreateForm {
  return kind === "AMNEZIAWG"
    ? { kind, hostId: null, name: "AmneziaWG", publicAddress: "", port: "", fakeTlsDomain: "", memberName: "default" }
    : { kind, hostId: null, name: "Telegram MTProto", publicAddress: "", port: "", fakeTlsDomain: "www.cloudflare.com", memberName: "default" };
}

function errorCode(error: unknown) {
  const message = String((error as { message?: unknown })?.message ?? "");
  const match = /[A-Z][A-Z0-9_]{2,}/.exec(message);
  return match?.[0] ?? "INTERNAL_ERROR";
}

async function copySensitiveText(value: string, message: string) {
  const copied = await copyTextToClipboard(value);
  if (copied) toast.success(message);
  else toast.error("复制失败");
}

function CreateManagedServiceDialog({ open, preferredKind, mtprotoAvailable, amneziawgAvailable, onOpenChange, onCreated }: {
  open: boolean; preferredKind: CreateForm["kind"]; mtprotoAvailable: boolean; amneziawgAvailable: boolean;
  onOpenChange: (open: boolean) => void; onCreated: () => void;
}) {
  const [form, setForm] = useState<CreateForm>(() => emptyCreate(preferredKind));
  const [probeOperationId, setProbeOperationId] = useState<string | null>(null);
  const [reservation, setReservation] = useState<{ id: string; port: number; expiresAt: string; network: "TCP" | "UDP" } | null>(null);
  const hosts = trpc.xray.managedServices.hostOptions.useQuery(undefined, { enabled: open, retry: false, refetchInterval: 5_000 });
  const probe = trpc.xray.portProbes.create.useMutation({ onSuccess: (data) => setProbeOperationId(data.operationId), onError: (error) => toast.error(`端口探测失败：${errorCode(error)}`) });
  const result = trpc.xray.portProbes.result.useQuery(
    { operationId: probeOperationId ?? "pending" },
    { enabled: open && !!probeOperationId, retry: false, refetchInterval: (query) => ["SUCCESS", "FAILED", "TIMEOUT", "CANCELLED"].includes(String(query.state.data?.status)) ? false : 500 },
  );
  const created = (name: string) => { toast.success(`${name} 独立服务已创建，正在同步到 Agent`); onCreated(); onOpenChange(false); };
  const createMtproto = trpc.xray.managedServices.createMtproto.useMutation({ onSuccess: () => created("MTProto"), onError: (error) => toast.error(`创建失败：${errorCode(error)}`) });
  const createAmneziawg = trpc.xray.managedServices.createAmneziawg.useMutation({ onSuccess: () => created("AmneziaWG"), onError: (error) => toast.error(`创建失败：${errorCode(error)}`) });

  useEffect(() => { setForm(emptyCreate(preferredKind)); setProbeOperationId(null); setReservation(null); }, [open, preferredKind]);
  const network = form.kind === "AMNEZIAWG" ? "UDP" as const : "TCP" as const;
  useEffect(() => {
    const data = result.data;
    if (!data || !probeOperationId) return;
    if (data.status === "SUCCESS" && data.selectedPort && data.reservationId && data.expiresAt) {
      setReservation({ id: data.reservationId, port: data.selectedPort, expiresAt: data.expiresAt, network });
      setForm((current) => ({ ...current, port: String(data.selectedPort) }));
      setProbeOperationId(null);
    } else if (["FAILED", "TIMEOUT", "CANCELLED"].includes(data.status)) {
      toast.error(`端口不可用：${data.errorCode ?? "PORT_IN_USE"}`); setProbeOperationId(null);
    }
  }, [network, probeOperationId, result.data]);

  const available = form.kind === "AMNEZIAWG" ? amneziawgAvailable : mtprotoAvailable;
  const compatibleHosts = (hosts.data ?? []).filter((host) => form.kind === "AMNEZIAWG" ? host.canCreateAmneziawg : host.canCreateMtproto);
  const selectedHost = compatibleHosts.find((host) => host.id === form.hostId);
  const probing = probe.isPending || !!probeOperationId;
  const creating = createMtproto.isPending || createAmneziawg.isPending;
  const reservationValid = !!reservation && reservation.network === network && reservation.port === Number(form.port) && Date.parse(reservation.expiresAt) > Date.now();
  const setField = <K extends keyof CreateForm>(key: K, value: CreateForm[K]) => {
    setForm((current) => ({ ...current, [key]: value }));
    if (key === "hostId" || key === "port") setReservation(null);
  };
  const selectKind = (kind: CreateForm["kind"]) => { setForm(emptyCreate(kind)); setProbeOperationId(null); setReservation(null); };
  const runProbe = () => {
    if (!form.hostId) return;
    setReservation(null);
    const manual = !!form.port.trim();
    probe.mutate({ hostId: form.hostId, mode: manual ? "MANUAL" : "AUTO", ...(manual ? { manualPort: Number(form.port) } : {}), network });
  };
  const submit = () => {
    if (!form.hostId || !reservationValid || !reservation) return;
    const common = { hostId: form.hostId, name: form.name, publicAddress: form.publicAddress, listenPort: reservation.port, portReservationId: reservation.id };
    if (form.kind === "AMNEZIAWG") createAmneziawg.mutate({ ...common, initialPeers: [{ name: form.memberName }] });
    else createMtproto.mutate({ ...common, fakeTlsDomain: form.fakeTlsDomain, initialAccounts: [{ name: form.memberName }] });
  };
  const valid = available && !!selectedHost && reservationValid && !!form.name.trim() && !!form.publicAddress.trim() && !!form.memberName.trim() && (form.kind === "AMNEZIAWG" || !!form.fakeTlsDomain.trim());

  return <Dialog open={open} onOpenChange={onOpenChange}><DialogContent className="max-h-[90vh] max-w-3xl overflow-y-auto">
    <DialogHeader><DialogTitle>创建独立服务</DialogTitle><DialogDescription>选择由 Agent 管理的独立 sidecar 类型；它们不会写入 Xray 配置。</DialogDescription></DialogHeader>
    <div className="space-y-2"><Label htmlFor="managed-kind">服务类型</Label><Select value={form.kind} onValueChange={(value) => selectKind(value as CreateForm["kind"])}><SelectTrigger id="managed-kind"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="MTPROTO_FAKE_TLS" disabled={!mtprotoAvailable}>MTProto（Telegram FakeTLS）</SelectItem><SelectItem value="AMNEZIAWG" disabled={!amneziawgAvailable}>AmneziaWG</SelectItem></SelectContent></Select></div>
    {!available && <div role="status" className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-amber-700">当前类型正在完成上线验证，暂不可创建。</div>}
    <div className="grid gap-5 py-2 md:grid-cols-2">
      <div className="space-y-2"><Label htmlFor="managed-host">主机</Label><Select value={form.hostId ? String(form.hostId) : ""} onValueChange={(value) => { const host = compatibleHosts.find((item) => item.id === Number(value)); setField("hostId", Number(value)); if (!form.publicAddress && host?.publicAddress) setForm((current) => ({ ...current, publicAddress: host.publicAddress })); }}><SelectTrigger id="managed-host"><SelectValue placeholder="选择在线兼容主机" /></SelectTrigger><SelectContent>{compatibleHosts.map((host) => <SelectItem key={host.id} value={String(host.id)}>{host.name}</SelectItem>)}</SelectContent></Select>{!hosts.isLoading && available && compatibleHosts.length === 0 && <p className="text-xs text-destructive">当前没有在线兼容主机。</p>}</div>
      <div className="space-y-2"><Label htmlFor="managed-name">名称 / 备注</Label><Input id="managed-name" value={form.name} onChange={(event) => setField("name", event.target.value)} /></div>
      <div className="space-y-2"><Label htmlFor="managed-public">公开地址</Label><Input id="managed-public" value={form.publicAddress} placeholder="域名或服务器公网 IP" onChange={(event) => setField("publicAddress", event.target.value)} /></div>
      {form.kind === "MTPROTO_FAKE_TLS" && <div className="space-y-2"><Label htmlFor="managed-domain">FakeTLS 域名</Label><Input id="managed-domain" value={form.fakeTlsDomain} placeholder="www.cloudflare.com" onChange={(event) => setField("fakeTlsDomain", event.target.value)} /><p className="text-xs text-muted-foreground">应填写可正常访问 HTTPS 的域名。</p></div>}
      <div className="space-y-2"><Label htmlFor="managed-port">{network} 端口</Label><div className="flex gap-2"><Input id="managed-port" inputMode="numeric" value={form.port} placeholder="留空自动分配" onChange={(event) => setField("port", event.target.value.replace(/\D/g, "").slice(0, 5))} /><Button type="button" variant="outline" disabled={!selectedHost || probing} onClick={runProbe}>{probing ? <RefreshCw className="h-4 w-4 animate-spin" aria-label="探测中" /> : "探测"}</Button></div>{reservationValid && <p className="text-xs text-emerald-600">{network} 端口 {reservation.port} 已临时预留</p>}</div>
      <div className="space-y-2"><Label htmlFor="managed-member">{form.kind === "AMNEZIAWG" ? "初始 peer 名称" : "初始账户名称"}</Label><Input id="managed-member" value={form.memberName} onChange={(event) => setField("memberName", event.target.value)} /><p className="text-xs text-muted-foreground">{form.kind === "AMNEZIAWG" ? "地址、密钥与 PSK 由服务端生成。" : "Secret 由服务端生成，不在表单中输入。"}</p></div>
    </div>
    {form.kind === "AMNEZIAWG" ? <div className="space-y-2 rounded-lg border border-border/60 bg-muted/30 p-4 text-sm"><div className="flex items-center gap-2 font-medium"><ShieldCheck className="h-4 w-4 text-emerald-600" />固定安全与网络边界</div><p className="text-muted-foreground">amneziawg-go v3.1.20260814 userspace helper · 专用 no-login 用户 · UDP · 无 OS TUN、系统路由或 CAP_NET_ADMIN。</p><p className="text-muted-foreground">IPv4 10.8.1.0/24 · MTU 1420 · DNS 1.1.1.1 / 1.0.0.1 · AllowedIPs 0.0.0.0/0 · keepalive 25 秒。</p><p className="text-muted-foreground">密钥、PSK 和 AWG 3.1 混淆参数均由服务端生成并加密保存；私网、本机与 metadata 目的固定拒绝。</p></div> : <div className="rounded-lg border border-border/60 bg-muted/30 p-4 text-sm"><div className="flex items-center gap-2 font-medium"><ShieldCheck className="h-4 w-4 text-emerald-600" />安全边界</div><p className="mt-2 text-muted-foreground">独立 mtg-multi v1.15.0 sidecar · 专用 no-login 用户 · TCP · 无额外 Linux capability · 无任意参数或 TOML 入口。</p></div>}
    <DialogFooter><Button type="button" variant="outline" onClick={() => onOpenChange(false)}>取消</Button><Button type="button" disabled={!valid || creating} onClick={submit}>{creating ? "创建中…" : "创建"}</Button></DialogFooter>
  </DialogContent></Dialog>;
}

function ManagedServiceShareDialog({ accountId, onClose }: { accountId: number; onClose: () => void }) {
  const client = useQueryClient();
  const input = useMemo(() => ({ accountId }), [accountId]);
  const queryKey = useMemo(() => getQueryKey(trpc.xray.managedServices.share, input, "query"), [input]);
  const [failed, setFailed] = useState(false);
  const [qr, setQr] = useState<string | null>(null);
  const query = trpc.xray.managedServices.share.useQuery(input, { enabled: !failed, retry: false, staleTime: 0, gcTime: 0, refetchOnMount: "always" });
  const qrContent = query.data ? query.data.kind === "AMNEZIAWG_CONFIG" ? query.data.content : query.data.uri : null;
  const mtprotoUri = query.data?.kind === "MTPROTO_PROXY" ? query.data.uri : "";
  useEffect(() => {
    let active = true;
    setQr(null);
    if (!failed && qrContent) void QRCode.toDataURL(qrContent, { width: 240, margin: 1 }).then((value) => { if (active) setQr(value); }).catch(() => { if (active) setQr(null); });
    return () => { active = false; setQr(null); };
  }, [failed, qrContent]);
  useEffect(() => {
    if (!query.isError || failed) return;
    setFailed(true);
    setQr(null);
    void client.cancelQueries({ queryKey, exact: true });
    client.removeQueries({ queryKey, exact: true });
  }, [client, failed, query.isError, queryKey]);
  const clear = () => {
    setQr(null);
    void client.cancelQueries({ queryKey, exact: true });
    client.removeQueries({ queryKey, exact: true });
    onClose();
  };
  useEffect(() => () => {
    void client.cancelQueries({ queryKey, exact: true });
    client.removeQueries({ queryKey, exact: true });
  }, [client, queryKey]);
  const download = (content: string, fileName: string) => {
    const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = fileName || "amneziawg.conf";
    anchor.style.display = "none";
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
    clear();
  };
  const awg = query.data?.kind === "AMNEZIAWG_CONFIG" ? query.data : null;
  return <Dialog open onOpenChange={(open) => { if (!open) clear(); }}><DialogContent className="max-h-[90vh] max-w-xl overflow-y-auto"><DialogHeader><DialogTitle>{awg ? "AmneziaWG peer 配置" : "Telegram 代理链接"}</DialogTitle><DialogDescription>敏感分享材料仅保存在当前窗口内存中；关闭、失败或下载后立即清理。</DialogDescription></DialogHeader>{query.isLoading && !failed ? <div className="space-y-3"><Skeleton className="mx-auto h-52 w-52" /><Skeleton className="h-24" /></div> : failed || query.isError || !query.data ? <div role="alert" className="rounded-lg border border-destructive/30 p-4 text-sm text-destructive">分享材料加载失败，缓存已清理。</div> : awg ? <div className="space-y-4">{qr ? <img src={qr} alt="AmneziaWG 配置二维码" width={220} height={220} className="mx-auto rounded-lg border bg-white p-2" /> : <div className="mx-auto flex h-52 w-52 items-center justify-center rounded-lg border"><QrCode className="h-8 w-8" /></div>}<div className="space-y-2"><Label htmlFor="managed-awg-config">标准 .conf</Label><Textarea id="managed-awg-config" readOnly value={awg.content} className="min-h-48 break-all font-mono text-xs" /></div><div className="grid gap-2 sm:grid-cols-2"><Button variant="outline" onClick={() => void copySensitiveText(awg.content, "配置已复制")}><Copy className="mr-2 h-4 w-4" />复制 .conf</Button><Button onClick={() => download(awg.content, awg.fileName)}><Download className="mr-2 h-4 w-4" />下载 .conf</Button></div><div className="space-y-2"><Label htmlFor="managed-awg-vpn-uri">vpn:// 导入链接</Label><Textarea id="managed-awg-vpn-uri" readOnly value={awg.vpnUri} className="min-h-20 break-all font-mono text-xs" /><Button className="w-full" variant="outline" onClick={() => void copySensitiveText(awg.vpnUri, "vpn:// 链接已复制")}><Copy className="mr-2 h-4 w-4" />复制 vpn://</Button></div></div> : <div className="space-y-4">{qr ? <img src={qr} alt="Telegram MTProto 代理二维码" width={220} height={220} className="mx-auto rounded-lg border bg-white p-2" /> : <div className="mx-auto flex h-52 w-52 items-center justify-center rounded-lg border"><QrCode className="h-8 w-8" /></div>}<Textarea aria-label="Telegram MTProto 代理链接" readOnly value={mtprotoUri} className="min-h-24 break-all font-mono text-xs" /><Button className="w-full" onClick={() => void copySensitiveText(mtprotoUri, "链接已复制")}><Copy className="mr-2 h-4 w-4" />复制链接</Button></div>}</DialogContent></Dialog>;
}

function ManagedServiceDetailDialog({ serviceId, onClose, onChanged }: { serviceId: number; onClose: () => void; onChanged: () => void }) {
  const [newAccount, setNewAccount] = useState("");
  const [shareAccountId, setShareAccountId] = useState<number | null>(null);
  const [confirmName, setConfirmName] = useState("");
  const detail = trpc.xray.managedServices.detail.useQuery({ id: serviceId }, { retry: false, refetchInterval: 5_000 });
  const mutationOptions = { onSuccess: () => { void detail.refetch(); onChanged(); }, onError: (error: unknown) => toast.error(errorCode(error)) };
  const toggleService = trpc.xray.managedServices.setEnabled.useMutation(mutationOptions);
  const removeService = trpc.xray.managedServices.remove.useMutation({ ...mutationOptions, onSuccess: () => { toast.success("删除请求已提交"); onChanged(); onClose(); } });
  const createAccount = trpc.xray.managedServices.accounts.create.useMutation({ ...mutationOptions, onSuccess: () => { setNewAccount(""); void detail.refetch(); onChanged(); } });
  const updateAccount = trpc.xray.managedServices.accounts.update.useMutation(mutationOptions);
  const removeAccount = trpc.xray.managedServices.accounts.remove.useMutation(mutationOptions);
  const service = detail.data;
  const isAmneziawg = service?.kind === "AMNEZIAWG";
  const writable = !!service?.isHostOnline && !!service.capabilityAvailable && !service.pendingDelete;
  const enabledAccounts = service?.accounts.filter((account) => account.isEnabled).length ?? 0;
  return <><Dialog open onOpenChange={(open) => { if (!open) onClose(); }}><DialogContent className="max-h-[90vh] max-w-3xl overflow-y-auto"><DialogHeader><DialogTitle>{service?.name ?? "独立服务详情"}</DialogTitle><DialogDescription>{isAmneziawg ? "AmneziaWG userspace helper" : "MTProto sidecar"} 的期望状态与 Agent 实际状态。</DialogDescription></DialogHeader>{detail.isLoading ? <div className="space-y-3"><Skeleton className="h-28" /><Skeleton className="h-44" /></div> : detail.isError || !service ? <div role="alert" className="rounded-lg border border-destructive/30 p-4 text-sm text-destructive">服务详情加载失败。</div> : <div className="space-y-5"><div className="grid gap-3 rounded-lg border p-4 sm:grid-cols-2"><div><p className="text-xs text-muted-foreground">公开入口</p><p className="mt-1 font-mono text-sm">{service.publicAddress}:{service.listenPort}/{isAmneziawg ? "udp" : "tcp"}</p></div>{isAmneziawg ? <div><p className="text-xs text-muted-foreground">固定网络</p><p className="mt-1 text-sm">10.8.1.0/24 · MTU 1420</p></div> : <div><p className="text-xs text-muted-foreground">FakeTLS</p><p className="mt-1 font-mono text-sm">{"fakeTlsDomain" in service ? service.fakeTlsDomain : ""}</p></div>}<div><p className="text-xs text-muted-foreground">同步</p><p className="mt-1 text-sm">generation {service.appliedGeneration} / {service.desiredGeneration}</p></div><div className="flex items-center justify-between"><div><p className="text-xs text-muted-foreground">启用</p><p className="mt-1 text-sm">{statusLabels[service.status] ?? service.status}</p></div><Switch checked={service.isEnabled} disabled={!writable || toggleService.isPending} aria-label="启用独立服务" onCheckedChange={(isEnabled) => toggleService.mutate({ id: service.id, isEnabled, expectedGeneration: service.desiredGeneration })} /></div></div>{isAmneziawg && <div className="space-y-1 rounded-lg border border-border/60 bg-muted/30 p-4 text-sm text-muted-foreground"><p>userspace helper · 无 OS TUN / CAP_NET_ADMIN · peer 地址从 10.8.1.2/32 起自动分配。</p><p>DNS 1.1.1.1 / 1.0.0.1 · AllowedIPs 0.0.0.0/0 · keepalive 25 秒 · 非公网目的固定拒绝。</p></div>}{!writable && <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3 text-sm text-amber-700">Agent 离线或能力不可用，当前只展示最后状态，写操作与新分享已禁用。</div>}<section className="space-y-3"><div className="flex items-center justify-between"><div><h3 className="font-medium">{isAmneziawg ? "Peers" : "账户"}</h3><p className="text-xs text-muted-foreground">{isAmneziawg ? "私钥、PSK 与完整配置仅在打开分享窗口时读取。" : "Secret 只在打开分享窗口时读取。"}</p></div><Badge variant="secondary">{service.accounts.length} 个</Badge></div><div className="space-y-2">{service.accounts.map((account) => <div key={account.id} className="flex flex-col gap-3 rounded-lg border p-3 sm:flex-row sm:items-center"><div className="min-w-0 flex-1"><p className="truncate font-medium">{account.name}</p>{isAmneziawg ? <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground"><span className="font-mono">{"address" in account ? account.address : "地址待分配"}</span><Badge variant={account.secretConfigured ? "secondary" : "destructive"}>{account.secretConfigured ? "配置已就绪" : "配置未就绪"}</Badge></div> : <p className="truncate font-mono text-xs text-muted-foreground">{account.accountTag}</p>}</div><div className="flex items-center gap-2"><Switch checked={account.isEnabled} disabled={!writable || updateAccount.isPending} aria-label={`${account.isEnabled ? "停用" : "启用"}${isAmneziawg ? " peer " : "账户 "}${account.name}`} onCheckedChange={(isEnabled) => updateAccount.mutate({ id: account.id, isEnabled, expectedGeneration: service.desiredGeneration })} /><Button size="sm" variant="outline" disabled={!writable || !service.isEnabled || !account.isEnabled || !account.secretConfigured} onClick={() => setShareAccountId(account.id)}><KeyRound className="mr-2 h-4 w-4" />{isAmneziawg ? "配置" : "链接"}</Button><Button size="icon" variant="ghost" disabled={!writable || (account.isEnabled && enabledAccounts <= 1) || removeAccount.isPending} aria-label={`删除${isAmneziawg ? " peer " : "账户 "}${account.name}`} onClick={() => removeAccount.mutate({ id: account.id, expectedGeneration: service.desiredGeneration })}><Trash2 className="h-4 w-4" /></Button></div></div>)}</div><div className="flex gap-2"><Input aria-label={isAmneziawg ? "新 peer 名称" : "新账户名称"} value={newAccount} placeholder={isAmneziawg ? "新 peer 名称" : "新账户名称"} disabled={!writable} onChange={(event) => setNewAccount(event.target.value)} /><Button variant="outline" disabled={!writable || !newAccount.trim() || createAccount.isPending} onClick={() => createAccount.mutate({ serviceId: service.id, name: newAccount, expectedGeneration: service.desiredGeneration })}><Plus className="mr-2 h-4 w-4" />添加</Button></div></section><section className="space-y-2 rounded-lg border border-destructive/20 p-4"><Label htmlFor="managed-confirm">删除服务：输入完整名称确认</Label><div className="flex gap-2"><Input id="managed-confirm" value={confirmName} onChange={(event) => setConfirmName(event.target.value)} /><Button variant="destructive" disabled={!writable || confirmName !== service.name || removeService.isPending} onClick={() => removeService.mutate({ id: service.id, expectedGeneration: service.desiredGeneration, confirmName })}>删除</Button></div></section></div>}</DialogContent></Dialog>{shareAccountId && <ManagedServiceShareDialog accountId={shareAccountId} onClose={() => setShareAccountId(null)} />}</>;
}

export function XrayManagedServicesPanel({ createOpen, onCreateOpenChange, search, hostId, status, page, onPageChange }: {
  createOpen: boolean; onCreateOpenChange: (open: boolean) => void; search: string; hostId: number | null; status: string | null; page: number; onPageChange: (page: number) => void;
}) {
  const [detailId, setDetailId] = useState<number | null>(null);
  const [createKind, setCreateKind] = useState<CreateForm["kind"]>("MTPROTO_FAKE_TLS");
  const catalog = trpc.xray.managedServices.catalog.useQuery(undefined, { retry: false });
  const list = trpc.xray.managedServices.list.useQuery({ page, pageSize: 20, search, ...(hostId ? { hostId } : {}), ...(status ? { status: status as "WAITING_SYNC" | "RUNNING" | "DISABLED" | "PENDING_DELETE" | "ERROR" } : {}) }, { retry: false, refetchInterval: 10_000 });
  const mtproto = catalog.data?.find((item) => item.kind === "MTPROTO_FAKE_TLS");
  const amneziawg = catalog.data?.find((item) => item.kind === "AMNEZIAWG");
  const tun = catalog.data?.find((item) => item.kind === "TUN");
  const mtprotoAvailable = mtproto?.status === "AVAILABLE";
  const amneziawgAvailable = String(amneziawg?.status ?? "") === "AVAILABLE";
  const openCreate = (kind: CreateForm["kind"]) => { setCreateKind(kind); onCreateOpenChange(true); };
  if (list.isLoading || catalog.isLoading) return <div className="space-y-3">{[0, 1, 2].map((item) => <Skeleton key={item} className="h-24 w-full" />)}</div>;
  if (list.isError || catalog.isError) return <Card className="border-destructive/30"><CardContent className="flex min-h-48 flex-col items-center justify-center gap-3"><AlertTriangle className="h-8 w-8 text-destructive" /><p>独立服务数据加载失败。</p><Button variant="outline" onClick={() => { void list.refetch(); void catalog.refetch(); }}><RefreshCw className="mr-2 h-4 w-4" />重试</Button></CardContent></Card>;
  return <div className="space-y-4"><div className="grid gap-3 md:grid-cols-3">
    <Card className={mtprotoAvailable ? "border-primary/30" : "opacity-70"}><CardHeader className="pb-2"><CardTitle className="flex items-center gap-2 text-base"><Server className="h-4 w-4" /><span>{mtproto?.name ?? "MTProto"}</span><Badge variant={mtprotoAvailable ? "default" : "secondary"} className="ml-auto">{mtprotoAvailable ? "可用" : "验证中"}</Badge></CardTitle></CardHeader><CardContent className="space-y-3 text-xs text-muted-foreground"><p>mtg-multi {mtproto?.targetVersion} · 专用低权限用户 · TCP</p><Button size="sm" variant="outline" disabled={!mtprotoAvailable} onClick={() => openCreate("MTPROTO_FAKE_TLS")}>创建 MTProto</Button></CardContent></Card>
    <Card className={amneziawgAvailable ? "border-primary/30" : "opacity-70"}><CardHeader className="pb-2"><CardTitle className="flex items-center gap-2 text-base"><Network className="h-4 w-4" /><span>{amneziawg?.name ?? "AmneziaWG"}</span><Badge variant={amneziawgAvailable ? "default" : "secondary"} className="ml-auto">{amneziawgAvailable ? "可用" : "验证中"}</Badge></CardTitle></CardHeader><CardContent className="space-y-3 text-xs text-muted-foreground"><p>amneziawg-go {amneziawg?.targetVersion} · userspace helper · UDP</p><Button size="sm" variant="outline" disabled={!amneziawgAvailable} onClick={() => openCreate("AMNEZIAWG")}>创建 AmneziaWG</Button></CardContent></Card>
    <Card className="opacity-70"><CardHeader className="pb-2"><CardTitle className="flex items-center gap-2 text-base"><ShieldCheck className="h-4 w-4" />{tun?.name ?? "TUN"}<Badge variant="outline" className="ml-auto">待设计</Badge></CardTitle></CardHeader><CardContent className="text-xs text-muted-foreground">需要单独的特权与运行时方案，当前不可创建。</CardContent></Card>
  </div>{list.data?.items.length ? <div className="space-y-2">{list.data.items.map((service) => { const awg = service.kind === "AMNEZIAWG"; return <button key={service.id} type="button" className="flex w-full flex-col gap-3 rounded-lg border border-border/60 bg-card p-4 text-left transition-colors hover:bg-muted/40 sm:flex-row sm:items-center" onClick={() => setDetailId(service.id)}><span className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/10">{awg ? <Network className="h-5 w-5 text-primary" /> : <Server className="h-5 w-5 text-primary" />}</span><span className="min-w-0 flex-1"><span className="flex items-center gap-2"><span className="block truncate font-medium">{service.name}</span><Badge variant="outline">{awg ? "AmneziaWG" : "MTProto"}</Badge></span><span className="mt-1 block truncate font-mono text-xs text-muted-foreground">{service.publicAddress}:{service.listenPort}/{awg ? "udp" : "tcp"} · {service.hostName}</span></span><span className="flex items-center gap-3"><span className="text-xs text-muted-foreground">{service.accounts.length} 个{awg ? " peer" : "账户"}</span><Badge variant={service.status === "ERROR" ? "destructive" : service.status === "RUNNING" ? "default" : "secondary"}>{statusLabels[service.status] ?? service.status}</Badge></span></button>; })}{list.data.totalPages > 1 && <div className="flex items-center justify-end gap-2 pt-2"><Button size="sm" variant="outline" disabled={page <= 1} onClick={() => onPageChange(page - 1)}>上一页</Button><span className="text-xs text-muted-foreground">{page} / {list.data.totalPages}</span><Button size="sm" variant="outline" disabled={page >= list.data.totalPages} onClick={() => onPageChange(page + 1)}>下一页</Button></div>}</div> : <Card><CardContent className="flex min-h-52 flex-col items-center justify-center text-center"><Users className="h-9 w-9 text-muted-foreground" /><h2 className="mt-3 font-medium">尚未创建独立服务</h2><p className="mt-1 text-sm text-muted-foreground">创建 MTProto 或 AmneziaWG 后，会在这里显示独立的 Agent sidecar 状态。</p></CardContent></Card>}<CreateManagedServiceDialog open={createOpen} preferredKind={createKind} mtprotoAvailable={mtprotoAvailable} amneziawgAvailable={amneziawgAvailable} onOpenChange={onCreateOpenChange} onCreated={() => void list.refetch()} />{detailId && <ManagedServiceDetailDialog serviceId={detailId} onClose={() => setDetailId(null)} onChanged={() => void list.refetch()} />}</div>;
}
