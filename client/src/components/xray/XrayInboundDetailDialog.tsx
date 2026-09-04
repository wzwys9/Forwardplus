import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "./XrayDialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import type { AppRouterOutputs } from "@/lib/trpc";
import { trpc } from "@/lib/trpc";
import { AlertTriangle, RefreshCw, Trash2 } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";

import { XrayInboundDetailContent } from "./XrayInboundDetailContent";
import { XrayInboundRemoveDialog } from "./XrayInboundRemoveDialog";
import { XrayShareDialog } from "./XrayShareDialog";
import { operationQueryPolling } from "./xrayOperationPolling";

type Detail = AppRouterOutputs["xray"]["inbounds"]["detail"];
type Client = Detail["clients"][number];
type AccessEntry = Detail["accessEntries"][number];
type ShareTarget = { kind: "VLESS" | "VLESS_ACCESS" | "TROJAN" | "VMESS" | "SHADOWSOCKS" | "HYSTERIA2" | "WIREGUARD" | "HTTP" | "MIXED"; id: number };

function safeMutationMessage(message: string, profileId?: string | null): string {
  if (message === "LAST_ACTIVE_ACCESS_REQUIRED" && profileId === "WIREGUARD_UDP_NONE") {
    return "启用中的 WireGuard 节点至少需要一个 peer；请先停用节点";
  }
  const labels: Record<string, string> = {
    HOST_OFFLINE: "Agent 离线，写操作已拒绝",
    CONFIG_GENERATION_CONFLICT: "配置 generation 已变化，请刷新后重试",
    OPERATION_CONFLICT: "已有操作正在执行，请稍后重试",
    CONFIRMATION_MISMATCH: "节点名称确认不匹配",
    CLIENT_NAME_DUPLICATE: "客户端名称已存在",
    CLIENT_LIMIT_EXCEEDED: "客户端数量已达到上限",
    RUNTIME_NOT_READY: "Xray 运行环境尚未就绪",
    UDP_CAPABILITY_REQUIRED: "需要升级 Agent 以支持 UDP 端口探测和监听确认",
    LAST_ACTIVE_ACCESS_REQUIRED: "启用中的此类节点至少需要一个账户；请先停用节点",
    EXTERNAL_PROXY_NOT_FOUND: "出口节点已不存在，请刷新后重试",
    EXTERNAL_PROXY_UNSUPPORTED: "该节点不是单 TCP 入站，不能配置外部出口",
    EXTERNAL_PROXY_REFERENCE_INVALID: "出口节点定义不完整，配置未更改",
    SENSITIVE_DATA_UNAVAILABLE: "出口节点凭据无法解密，配置未更改",
  };
  return labels[message] ?? "节点操作失败，请刷新后重试";
}

export function XrayInboundDetailDialog({ inboundId, onClose, onOperationStarted }: {
  inboundId: number;
  onClose: () => void;
  onOperationStarted: (operationId: string) => void;
}) {
  const [shareTarget, setShareTarget] = useState<ShareTarget | null>(null);
  const [removeOpen, setRemoveOpen] = useState(false);
  const [editOpen, setEditOpen] = useState(false);
  const [editName, setEditName] = useState("");
  const [editAddress, setEditAddress] = useState("");
  const [syncOpen, setSyncOpen] = useState(false);
  const [syncConfirm, setSyncConfirm] = useState("");
  const [externalProxyOpen, setExternalProxyOpen] = useState(false);
  const [externalProxyId, setExternalProxyId] = useState("DIRECT");
  const [externalProxySearch, setExternalProxySearch] = useState("");
  const [operationPage, setOperationPage] = useState(1);
  const [realityScanOperationId, setRealityScanOperationId] = useState<string | null>(null);
  const shareTriggerRef = useRef<HTMLButtonElement | null>(null);
  const detailQuery = trpc.xray.inbounds.detail.useQuery(
    { id: inboundId },
    { retry: false, refetchInterval: 10_000, refetchOnWindowFocus: true },
  );
  const hostId = detailQuery.data?.host.id;
  const runtimeQuery = trpc.xray.runtimes.list.useQuery(
    { page: 1, pageSize: 1, hostId },
    { enabled: hostId !== undefined, retry: false, refetchInterval: 10_000, refetchOnWindowFocus: true },
  );
  const operationsQuery = trpc.xray.operations.list.useQuery(
    { page: operationPage, pageSize: 10, inboundId, sortOrder: "desc" },
    { retry: false, refetchInterval: 10_000, refetchOnWindowFocus: true },
  );
  const realityScanQuery = trpc.xray.realityScans.result.useQuery(
    { operationId: realityScanOperationId ?? "pending" },
    { enabled: !!realityScanOperationId, retry: false, refetchInterval: operationQueryPolling, refetchOnWindowFocus: false },
  );
  const externalProxyQuery = trpc.xray.externalProxyNodes.list.useQuery(
    { page: 1, pageSize: 100, search: externalProxySearch },
    { enabled: externalProxyOpen, retry: false, refetchOnWindowFocus: false },
  );
  const mutationOptions = {
    onSuccess: async () => {
      toast.success("已创建新 generation，正在等待 Agent 应用");
      await detailQuery.refetch();
    },
    onError: (error: { message: string }) => toast.error(safeMutationMessage(error.message, detailQuery.data?.inbound.profileId)),
  };
  const createClient = trpc.xray.clients.create.useMutation(mutationOptions);
  const updateClient = trpc.xray.clients.update.useMutation(mutationOptions);
  const removeClient = trpc.xray.clients.remove.useMutation(mutationOptions);
  const createAccessEntry = trpc.xray.accessEntries.create.useMutation(mutationOptions);
  const updateAccessEntry = trpc.xray.accessEntries.update.useMutation(mutationOptions);
  const removeAccessEntry = trpc.xray.accessEntries.remove.useMutation(mutationOptions);
  const updateInbound = trpc.xray.inbounds.update.useMutation({
    onSuccess: async () => {
      toast.success("节点已更新，正在等待 Agent 应用");
      setEditOpen(false);
      await detailQuery.refetch();
    },
    onError: (error) => toast.error(safeMutationMessage(error.message)),
  });
  const setInboundEnabled = trpc.xray.inbounds.setEnabled.useMutation({
    onSuccess: async () => {
      toast.success("节点状态已更新，正在等待 Agent 应用");
      await detailQuery.refetch();
    },
    onError: (error) => toast.error(safeMutationMessage(error.message)),
  });
  const setExternalProxy = trpc.xray.inbounds.setExternalProxy.useMutation({
    onSuccess: async () => {
      toast.success(externalProxyId === "DIRECT" ? "已恢复直连，正在等待 Agent 应用完整配置" : "出口已更新，正在等待 Agent 应用完整配置");
      setExternalProxyOpen(false);
      await detailQuery.refetch();
    },
    onError: (error) => toast.error(safeMutationMessage(error.message)),
  });
  const syncInbound = trpc.xray.runtimes.sync.useMutation({
    onSuccess: async (result) => {
      toast.success("已创建重新同步 operation");
      setSyncOpen(false);
      setSyncConfirm("");
      onOperationStarted(result.operationId);
      await detailQuery.refetch();
    },
    onError: (error) => toast.error(safeMutationMessage(error.message)),
  });
  const rescanReality = trpc.xray.realityScans.create.useMutation({
    onSuccess: ({ operationId }) => setRealityScanOperationId(operationId),
    onError: (error) => toast.error(safeMutationMessage(error.message)),
  });
  const removeInbound = trpc.xray.inbounds.remove.useMutation({
    onSuccess: (result) => {
      toast.success(result.lastInbound
        ? "节点已进入待删除；应用完成后将停止受管 Xray 并保留二进制"
        : "节点已进入待删除；应用完成前旧配置可能继续有效");
      setRemoveOpen(false);
      onClose();
    },
    onError: (error) => toast.error(safeMutationMessage(error.message)),
  });
  const busy = createClient.isPending || updateClient.isPending || removeClient.isPending
    || createAccessEntry.isPending || updateAccessEntry.isPending || removeAccessEntry.isPending || updateInbound.isPending
    || setInboundEnabled.isPending || setExternalProxy.isPending || syncInbound.isPending || rescanReality.isPending || removeInbound.isPending || detailQuery.isFetching;
  const generation = detailQuery.data?.deployment.desiredGeneration ?? 0;
  const externalProxyOptions: Array<{ id: number; name: string; protocol: string; address: string; port: number }> = [...(externalProxyQuery.data?.items ?? [])];
  const currentExternalProxy = detailQuery.data?.inbound.externalProxy;
  if (currentExternalProxy && !externalProxyOptions.some((node) => node.id === currentExternalProxy.id)) {
    externalProxyOptions.unshift(currentExternalProxy);
  }

  useEffect(() => {
    if (realityScanQuery.data?.status === "FAILED" || realityScanQuery.data?.status === "TIMEOUT") {
      toast.error("Reality 重新探测未完成，请检查错误码");
    }
  }, [realityScanQuery.data?.status]);

  const update = (client: Client, changes: { name?: string; isEnabled?: boolean }) => {
    updateClient.mutate({ id: client.id, expectedGeneration: generation, ...changes });
  };
  const updateAccess = (entry: AccessEntry, changes: { name?: string; isEnabled?: boolean }) => {
    updateAccessEntry.mutate({ id: entry.id, expectedGeneration: generation, ...changes });
  };
  const close = () => {
    setShareTarget(null);
    shareTriggerRef.current = null;
    onClose();
  };
  const closeShare = () => {
    const trigger = shareTriggerRef.current;
    setShareTarget(null);
    shareTriggerRef.current = null;
    window.requestAnimationFrame(() => trigger?.focus());
  };

  return (
    <>
      <Dialog open onOpenChange={(open) => { if (!open) close(); }}>
        <DialogContent className="max-w-5xl">
          <DialogHeader>
            <div className="flex items-start justify-between gap-4 pr-8">
              <div className="min-w-0 space-y-1.5">
                <DialogTitle>{detailQuery.data?.inbound.name ?? "Xray 节点详情"}</DialogTitle>
                <DialogDescription>查看期望配置、Agent 实际状态和操作记录；敏感材料仅在按需分享时加载。</DialogDescription>
              </div>
              {detailQuery.data && (
                <Button
                  type="button"
                  size="sm"
                  variant="destructive"
                  disabled={busy || !detailQuery.data.host.isOnline || detailQuery.data.inbound.pendingDelete}
                  title={!detailQuery.data.host.isOnline ? "Agent 离线，无法删除节点" : detailQuery.data.inbound.pendingDelete ? "节点已在等待删除" : "删除节点"}
                  onClick={() => setRemoveOpen(true)}
                >
                  <Trash2 className="mr-1.5 h-4 w-4" />删除节点
                </Button>
              )}
            </div>
          </DialogHeader>
          {detailQuery.isLoading ? (
            <div className="space-y-3" aria-busy="true" aria-label="正在加载节点详情">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-64 w-full" />
            </div>
          ) : detailQuery.isError || !detailQuery.data ? (
            <div role="alert" className="flex min-h-48 flex-col items-center justify-center gap-3 rounded-lg border border-destructive/30 bg-destructive/5 p-6 text-center">
              <AlertTriangle className="h-7 w-7 text-destructive" aria-hidden="true" />
              <p className="text-sm">节点详情加载失败或节点已不存在。</p>
              <Button type="button" variant="outline" onClick={() => { void detailQuery.refetch(); }}>
                <RefreshCw className="mr-2 h-4 w-4" />重新加载
              </Button>
            </div>
          ) : (
            <XrayInboundDetailContent
              detail={detailQuery.data}
              runtime={runtimeQuery.data?.items[0] ?? null}
              operations={operationsQuery.data}
              realityScan={realityScanQuery.data ?? null}
              busy={busy || detailQuery.data.inbound.pendingDelete}
              onEditInbound={() => {
                setEditName(detailQuery.data.inbound.name);
                setEditAddress(detailQuery.data.inbound.publicAddress);
                setEditOpen(true);
              }}
              onConfigureExternalProxy={() => {
                setExternalProxyId(detailQuery.data.inbound.externalProxy ? String(detailQuery.data.inbound.externalProxy.id) : "DIRECT");
                setExternalProxySearch("");
                setExternalProxyOpen(true);
              }}
              onSetInboundEnabled={() => setInboundEnabled.mutate({
                id: inboundId,
                isEnabled: !detailQuery.data.inbound.isEnabled,
                expectedGeneration: generation,
              })}
              onSyncInbound={() => {
                setSyncConfirm("");
                setSyncOpen(true);
              }}
              onOperationPageChange={setOperationPage}
              onRescanReality={() => rescanReality.mutate({
                hostId: detailQuery.data.host.id,
                source: "ADMIN_DOMAINS",
                targets: [`${detailQuery.data.inbound.realityTargetHost}:${detailQuery.data.inbound.realityTargetPort}`],
              })}
              onCreateClient={(name) => createClient.mutate({
                inboundId,
                name,
                flow: detailQuery.data.inbound.transport === "grpc" || detailQuery.data.inbound.transport === "xhttp"
                  ? ""
                  : "xtls-rprx-vision",
                expectedGeneration: generation,
              })}
              onUpdateClient={update}
              onRemoveClient={(client) => removeClient.mutate({ id: client.id, expectedGeneration: generation })}
              onShareClient={(client, trigger) => {
                shareTriggerRef.current = trigger;
                setShareTarget({ kind: "VLESS", id: client.id });
              }}
              onCreateAccessEntry={(name) => createAccessEntry.mutate({ inboundId, name, expectedGeneration: generation })}
              onUpdateAccessEntry={updateAccess}
              onRemoveAccessEntry={(entry) => removeAccessEntry.mutate({ id: entry.id, expectedGeneration: generation })}
              onShareAccessEntry={(entry, trigger) => {
                shareTriggerRef.current = trigger;
                const protocol = detailQuery.data.inbound.protocol.toLowerCase();
                setShareTarget({
                  kind: protocol === "vmess" ? "VMESS"
                    : protocol === "shadowsocks" ? "SHADOWSOCKS"
                      : protocol === "hysteria" ? "HYSTERIA2"
                      : protocol === "wireguard" ? "WIREGUARD"
                      : protocol === "http" ? "HTTP"
                      : protocol === "mixed" ? "MIXED"
                      : protocol === "vless" ? "VLESS_ACCESS" : "TROJAN",
                  id: entry.id,
                });
              }}
            />
          )}
        </DialogContent>
      </Dialog>
      {shareTarget?.kind === "VLESS" && (
        <XrayShareDialog key={`vless-${shareTarget.id}`} kind="VLESS" clientId={shareTarget.id} onClose={closeShare} />
      )}
      {shareTarget && shareTarget.kind !== "VLESS" && (
        <XrayShareDialog key={`${shareTarget.kind}-${shareTarget.id}`} kind={shareTarget.kind} accessEntryId={shareTarget.id} onClose={closeShare} />
      )}
      {editOpen && detailQuery.data && (
        <Dialog open onOpenChange={setEditOpen}>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>编辑 Xray 节点</DialogTitle>
              <DialogDescription>{detailQuery.data.inbound.profileId === "TUNNEL_TCP_LOCAL_NONE" ? "修改节点名称；Tunnel 入口固定为目标主机回环地址。" : "修改节点名称和分享链接使用的公网地址。"}</DialogDescription>
            </DialogHeader>
            <form
              className="space-y-4"
              onSubmit={(event) => {
                event.preventDefault();
                updateInbound.mutate({
                  id: inboundId,
                  name: editName,
                  ...(detailQuery.data.inbound.profileId === "TUNNEL_TCP_LOCAL_NONE" ? {} : { publicAddress: editAddress }),
                  expectedGeneration: generation,
                });
              }}
            >
              <div className="space-y-1.5">
                <Label htmlFor="xray-inbound-edit-name">节点名称</Label>
                <Input id="xray-inbound-edit-name" value={editName} maxLength={128} onChange={(event) => setEditName(event.target.value)} />
              </div>
              {detailQuery.data.inbound.profileId !== "TUNNEL_TCP_LOCAL_NONE" && <div className="space-y-1.5">
                <Label htmlFor="xray-inbound-edit-address">公网地址</Label>
                <Input id="xray-inbound-edit-address" value={editAddress} maxLength={253} onChange={(event) => setEditAddress(event.target.value)} />
              </div>}
              <div className="flex justify-end gap-2">
                <Button type="button" variant="outline" disabled={updateInbound.isPending} onClick={() => setEditOpen(false)}>取消</Button>
                <Button type="submit" disabled={updateInbound.isPending || !detailQuery.data.host.isOnline || !editName.trim() || (detailQuery.data.inbound.profileId !== "TUNNEL_TCP_LOCAL_NONE" && !editAddress.trim())}>
                  {updateInbound.isPending ? "正在保存…" : "保存并同步"}
                </Button>
              </div>
            </form>
          </DialogContent>
        </Dialog>
      )}
      {syncOpen && detailQuery.data && (
        <Dialog open onOpenChange={setSyncOpen}>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>重新同步主机 Xray</DialogTitle>
              <DialogDescription>这会为主机上的全部受管节点生成持久 operation，不会安装新版本或执行降级。请输入主机名确认：{detailQuery.data.host.name}</DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="space-y-1.5"><Label htmlFor="xray-sync-confirm-host">主机名</Label><Input id="xray-sync-confirm-host" value={syncConfirm} onChange={(event) => setSyncConfirm(event.target.value)} /></div>
              <div className="flex justify-end gap-2"><Button type="button" variant="outline" disabled={syncInbound.isPending} onClick={() => setSyncOpen(false)}>取消</Button><Button type="button" disabled={syncInbound.isPending || !detailQuery.data.host.isOnline || syncConfirm !== detailQuery.data.host.name} onClick={() => syncInbound.mutate({ hostId: detailQuery.data.host.id })}>{syncInbound.isPending ? "正在创建…" : "确认重新同步"}</Button></div>
            </div>
          </DialogContent>
        </Dialog>
      )}
      {externalProxyOpen && detailQuery.data && (
        <Dialog open onOpenChange={(open) => { if (!open && !setExternalProxy.isPending) { setExternalProxySearch(""); setExternalProxyOpen(false); } }}>
          <DialogContent className="max-h-[90svh] max-w-lg overflow-y-auto">
            <DialogHeader>
              <DialogTitle>配置出口节点</DialogTitle>
              <DialogDescription>选择后会为主机生成并下发包含全部入站的新 generation；恢复直连会移除该入站的专用路由。</DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              {externalProxyQuery.isError ? <div role="alert" className="rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm">出口节点加载失败，请关闭后重试。</div> : <div className="space-y-1.5">
                <Label htmlFor="xray-inbound-external-proxy">出口</Label>
                <Input type="search" aria-label="搜索出口节点" value={externalProxySearch} placeholder="搜索名称、协议或地址" onChange={(event) => setExternalProxySearch(event.target.value)} />
                <Select value={externalProxyId} disabled={externalProxyQuery.isLoading || setExternalProxy.isPending} onValueChange={setExternalProxyId}>
                  <SelectTrigger id="xray-inbound-external-proxy"><SelectValue placeholder="选择出口" /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="DIRECT">直连（direct）</SelectItem>
                    {externalProxyOptions.map((node) => <SelectItem key={node.id} value={String(node.id)}>{node.name} · {node.protocol} · {node.address}:{node.port}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>}
              <p className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">出口定义本身不代表在线。提交后请以当前主机 generation/hash 和运行状态判断是否已经应用。</p>
              <div className="flex justify-end gap-2"><Button type="button" variant="outline" disabled={setExternalProxy.isPending} onClick={() => { setExternalProxySearch(""); setExternalProxyOpen(false); }}>取消</Button><Button type="button" disabled={externalProxyQuery.isLoading || externalProxyQuery.isError || setExternalProxy.isPending || externalProxyId === (detailQuery.data.inbound.externalProxy ? String(detailQuery.data.inbound.externalProxy.id) : "DIRECT")} onClick={() => setExternalProxy.mutate({ inboundId, externalProxyNodeId: externalProxyId === "DIRECT" ? null : Number(externalProxyId), expectedGeneration: generation })}>{setExternalProxy.isPending ? "正在提交…" : "保存并同步"}</Button></div>
            </div>
          </DialogContent>
        </Dialog>
      )}
      {removeOpen && detailQuery.data && (
        <XrayInboundRemoveDialog
          inboundName={detailQuery.data.inbound.name}
          hostName={detailQuery.data.host.name}
          lastInbound={(runtimeQuery.data?.items[0]?.inboundCount ?? 0) === 1}
          pending={removeInbound.isPending}
          disabled={!detailQuery.data.host.isOnline}
          errorCode={removeInbound.error ? String(removeInbound.error.message || "INTERNAL_ERROR") : null}
          onRemove={(confirmName) => removeInbound.mutate({ id: inboundId, expectedGeneration: generation, confirmName })}
          onClose={() => setRemoveOpen(false)}
        />
      )}
    </>
  );
}
