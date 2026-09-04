import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { copyTextToClipboard } from "@/lib/clipboard";
import { downloadTextFile } from "@/lib/fileDownload";
import { trpc } from "@/lib/trpc";
import { getQueryKey } from "@trpc/react-query";
import { useQueryClient } from "@tanstack/react-query";
import { Copy, Download, QrCode, RefreshCw } from "lucide-react";
import QRCode from "qrcode";
import { useEffect, useReducer } from "react";
import { toast } from "sonner";

import {
  initialXrayShareMemory,
  reduceXrayShareMemory,
  type XrayShareMemory,
} from "./xrayShareMemory";
import { XRAY_MIXED_PLAINTEXT_AUTH_WARNING } from "./xrayCreateFlow";

type ViewProps = {
  memory: XrayShareMemory;
  loading: boolean;
  protocolLabel?: "VLESS" | "Trojan" | "VMess" | "Shadowsocks" | "Hysteria 2" | "WireGuard" | "HTTP" | "Mixed";
  onClose: () => void;
  onCopy: () => void;
  onCopySecondary?: () => void;
  onDownload?: () => void;
  onRetry: () => void;
};

function MixedProxyEndpoint({ title, uri, qrDataUrl, displayName, onCopy }: {
  title: "SOCKS5" | "HTTP";
  uri: string;
  qrDataUrl: string | null;
  displayName: string | null;
  onCopy: () => void;
}) {
  return (
    <section className="space-y-3 rounded-lg border border-border/60 p-4" aria-label={`${title} 地址`}>
      <div><h3 className="font-medium">{title} 地址</h3><p className="mt-1 text-xs text-muted-foreground">与另一个入口共用端口、用户名和密码。</p></div>
      {qrDataUrl ? (
        <img
          src={qrDataUrl}
          alt={`${displayName ?? "账户"} ${title} 代理二维码`}
          width={208}
          height={208}
          className="mx-auto rounded-lg border bg-white p-2"
        />
      ) : (
        <div className="mx-auto flex h-52 w-52 items-center justify-center rounded-lg border bg-white">
          <QrCode className="h-8 w-8 text-slate-500" aria-hidden="true" />
        </div>
      )}
      <Textarea readOnly value={uri} aria-label={`${title} 代理地址`} className="min-h-24 break-all font-mono text-xs" />
      <Button type="button" className="w-full" onClick={onCopy}>
        <Copy className="mr-2 h-4 w-4" />复制 {title} 地址
      </Button>
    </section>
  );
}

export function XrayShareDialogView({ memory, loading, protocolLabel = "VLESS", onClose, onCopy, onCopySecondary, onDownload, onRetry }: ViewProps) {
  const isWireGuard = memory.format === "WIREGUARD_CONFIG";
  const isHttp = protocolLabel === "HTTP";
  const isMixed = protocolLabel === "Mixed";
  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent className={isMixed ? "max-w-4xl" : undefined}>
        <DialogHeader>
          <DialogTitle>{isWireGuard ? "WireGuard peer 配置" : isMixed ? "Mixed 管理代理地址" : isHttp ? "HTTP 代理地址" : "客户端分享"}</DialogTitle>
          <DialogDescription>{isWireGuard ? "peer 配置" : isMixed ? "带认证信息的 SOCKS5 与 HTTP 地址" : isHttp ? "带认证信息的代理地址" : "分享材料"}仅保存在当前 Dialog 内存；关闭后立即清除。响应禁止缓存。</DialogDescription>
        </DialogHeader>
        {loading ? (
          <div className={isMixed ? "grid gap-4 sm:grid-cols-2" : "space-y-3"} aria-busy="true">
            <div className="space-y-3"><Skeleton className="mx-auto h-48 w-48" /><Skeleton className="h-20 w-full" /></div>
            {isMixed && <div className="space-y-3"><Skeleton className="mx-auto h-48 w-48" /><Skeleton className="h-20 w-full" /></div>}
          </div>
        ) : memory.phase === "ERROR" ? (
          <div role="alert" className="rounded-lg border border-destructive/30 bg-destructive/5 p-4">
            <p className="text-sm">分享材料加载失败。</p>
            <Button type="button" size="sm" variant="outline" className="mt-3" onClick={onRetry}>
              <RefreshCw className="mr-2 h-4 w-4" />重试
            </Button>
          </div>
        ) : (
          <div className="space-y-4">
            {isMixed && memory.uri && memory.secondaryUri ? (
              <div className="grid gap-4 lg:grid-cols-2">
                <MixedProxyEndpoint title="SOCKS5" uri={memory.uri} qrDataUrl={memory.qrDataUrl} displayName={memory.displayName} onCopy={onCopy} />
                <MixedProxyEndpoint title="HTTP" uri={memory.secondaryUri} qrDataUrl={memory.secondaryQrDataUrl} displayName={memory.displayName} onCopy={() => onCopySecondary?.()} />
              </div>
            ) : (
              <>
                {memory.qrDataUrl ? (
                  <img
                    src={memory.qrDataUrl}
                    alt={`${memory.displayName ?? "客户端"} ${protocolLabel} 二维码`}
                    width={240}
                    height={240}
                    className="mx-auto rounded-lg border bg-white p-2"
                  />
                ) : (
                  <div className="mx-auto flex h-60 w-60 items-center justify-center rounded-lg border bg-white">
                    <QrCode className="h-8 w-8 text-slate-500" aria-hidden="true" />
                  </div>
                )}
                <Textarea readOnly value={memory.uri ?? ""} aria-label={isWireGuard ? "WireGuard peer 配置" : isHttp ? "HTTP 代理地址" : `${protocolLabel} 分享链接`} className="min-h-24 break-all font-mono text-xs" />
              </>
            )}
            {isHttp && <p role="alert" className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">HTTP Basic 凭据不会被 TLS 加密。只应在可信网络、受控管理场景或额外加密隧道内使用；该地址不会进入订阅。</p>}
            {isMixed && <p role="alert" className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">{XRAY_MIXED_PLAINTEXT_AUTH_WARNING}；这两个地址不会进入订阅。</p>}
            {memory.deploymentStatus !== "RUNNING" && (
              <p className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">
                当前状态：{memory.deploymentStatus ?? "UNKNOWN"}。旧配置可能仍有效，远端当前状态需以最新 Agent 报告为准。
              </p>
            )}
            {!isMixed && <div className={isWireGuard ? "grid gap-2 sm:grid-cols-2" : undefined}>
              <Button type="button" className="w-full" onClick={onCopy}>
                <Copy className="mr-2 h-4 w-4" />复制{isWireGuard ? "配置" : isHttp ? "代理地址" : "分享链接"}
              </Button>
              {isWireGuard && <Button type="button" variant="outline" className="w-full" onClick={onDownload}><Download className="mr-2 h-4 w-4" />下载 .conf</Button>}
            </div>}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

type ShareProps =
  | { kind: "VLESS"; clientId: number; onClose: () => void }
  | { kind: "VLESS_ACCESS" | "TROJAN" | "VMESS" | "SHADOWSOCKS" | "HYSTERIA2" | "WIREGUARD" | "HTTP" | "MIXED"; accessEntryId: number; onClose: () => void };

export function XrayShareDialog(props: ShareProps) {
  const clientInput = { clientId: props.kind === "VLESS" ? props.clientId : 1, format: "VLESS_URI" as const };
  const accessEntryId = "accessEntryId" in props ? props.accessEntryId : 1;
  const accessInput = props.kind === "VMESS"
    ? { accessEntryId, format: "VMESS_URI" as const }
    : props.kind === "SHADOWSOCKS"
      ? { accessEntryId, format: "SHADOWSOCKS_URI" as const }
    : props.kind === "HYSTERIA2"
      ? { accessEntryId, format: "HYSTERIA2_URI" as const }
    : props.kind === "WIREGUARD"
      ? { accessEntryId, format: "WIREGUARD_CONFIG" as const }
    : props.kind === "HTTP"
      ? { accessEntryId, format: "HTTP_PROXY_URI" as const }
    : props.kind === "MIXED"
      ? { accessEntryId, format: "MIXED_PROXY_ENDPOINTS" as const }
    : props.kind === "VLESS_ACCESS"
      ? { accessEntryId, format: "VLESS_URI" as const }
      : { accessEntryId, format: "TROJAN_URI" as const };
  const protocolLabel = props.kind === "TROJAN" ? "Trojan"
    : props.kind === "VMESS" ? "VMess"
      : props.kind === "SHADOWSOCKS" ? "Shadowsocks"
        : props.kind === "HYSTERIA2" ? "Hysteria 2"
          : props.kind === "WIREGUARD" ? "WireGuard"
            : props.kind === "HTTP" ? "HTTP"
              : props.kind === "MIXED" ? "Mixed" : "VLESS";
  const queryClient = useQueryClient();
  const [memory, dispatch] = useReducer(reduceXrayShareMemory, undefined, initialXrayShareMemory);
  const clientQuery = trpc.xray.clients.share.useQuery(clientInput, { enabled: props.kind === "VLESS" && memory.phase !== "ERROR", retry: false, staleTime: 0, gcTime: 0, refetchOnMount: "always" });
  const accessQuery = trpc.xray.accessEntries.share.useQuery(accessInput, { enabled: props.kind !== "VLESS" && memory.phase !== "ERROR", retry: false, staleTime: 0, gcTime: 0, refetchOnMount: "always" });
  const query = props.kind === "VLESS" ? clientQuery : accessQuery;
  const resourceId = props.kind === "VLESS" ? props.clientId : props.accessEntryId;

  useEffect(() => { dispatch({ type: "LOAD" }); }, [props.kind, resourceId]);
  useEffect(() => {
    if (query.data && "uri" in query.data && typeof query.data.uri === "string") {
      dispatch({ type: "LOADED", uri: query.data.uri, displayName: query.data.displayName, deploymentStatus: query.data.deploymentStatus, format: "URI" });
    } else if (query.data && "format" in query.data && query.data.format === "WIREGUARD_CONFIG") {
      dispatch({
        type: "LOADED",
        uri: query.data.content,
        displayName: query.data.displayName,
        deploymentStatus: query.data.deploymentStatus,
        format: "WIREGUARD_CONFIG",
        fileName: query.data.fileName,
      });
    } else if (query.data && "format" in query.data && query.data.format === "MIXED_PROXY_ENDPOINTS"
      && typeof query.data.socks5Uri === "string" && typeof query.data.httpUri === "string") {
      dispatch({
        type: "LOADED",
        uri: query.data.socks5Uri,
        secondaryUri: query.data.httpUri,
        displayName: query.data.displayName,
        deploymentStatus: query.data.deploymentStatus,
        format: "MIXED_PROXY_ENDPOINTS",
      });
    } else if (query.data) {
      dispatch({ type: "ERROR" });
      queryClient.removeQueries({ queryKey: getQueryKey(trpc.xray.clients.share, clientInput, "query"), exact: true });
      queryClient.removeQueries({ queryKey: getQueryKey(trpc.xray.accessEntries.share, accessInput, "query"), exact: true });
    }
  }, [query.data]);
  useEffect(() => {
    if (!query.error) return;
    dispatch({ type: "ERROR" });
    queryClient.removeQueries({ queryKey: getQueryKey(trpc.xray.clients.share, clientInput, "query"), exact: true });
    queryClient.removeQueries({ queryKey: getQueryKey(trpc.xray.accessEntries.share, accessInput, "query"), exact: true });
  }, [query.error]);
  useEffect(() => {
    if (!memory.uri || memory.phase !== "LOADED") return;
    let active = true;
    const sources = [
      { slot: "PRIMARY" as const, uri: memory.uri },
      ...(memory.secondaryUri ? [{ slot: "SECONDARY" as const, uri: memory.secondaryUri }] : []),
    ];
    void Promise.all(sources.map(async ({ slot, uri }) => ({
      slot,
      dataUrl: await QRCode.toDataURL(uri, { width: 240, margin: 1, color: { dark: "#000000", light: "#ffffff" } }),
    })))
      .then((results) => {
        if (!active) return;
        results.forEach(({ slot, dataUrl }) => dispatch({ type: "QR_READY", slot, dataUrl }));
      })
      .catch(() => {
        if (!active) return;
        dispatch({ type: "ERROR" });
        queryClient.removeQueries({ queryKey: getQueryKey(trpc.xray.clients.share, clientInput, "query"), exact: true });
        queryClient.removeQueries({ queryKey: getQueryKey(trpc.xray.accessEntries.share, accessInput, "query"), exact: true });
      });
    return () => { active = false; };
  }, [memory.phase, memory.secondaryUri, memory.uri]);

  const clearAndClose = () => {
    dispatch({ type: "CLEAR" });
    queryClient.removeQueries({ queryKey: getQueryKey(trpc.xray.clients.share, clientInput, "query"), exact: true });
    queryClient.removeQueries({ queryKey: getQueryKey(trpc.xray.accessEntries.share, accessInput, "query"), exact: true });
    props.onClose();
  };
  useEffect(() => () => {
    queryClient.removeQueries({ queryKey: getQueryKey(trpc.xray.clients.share, clientInput, "query"), exact: true });
    queryClient.removeQueries({ queryKey: getQueryKey(trpc.xray.accessEntries.share, accessInput, "query"), exact: true });
  }, [props.kind, resourceId, queryClient]);

  const copy = async (slot: "PRIMARY" | "SECONDARY" = "PRIMARY") => {
    const value = slot === "SECONDARY" ? memory.secondaryUri : memory.uri;
    if (!value) return;
    const copied = await copyTextToClipboard(value);
    const label = props.kind === "MIXED" ? `${slot === "PRIMARY" ? "SOCKS5" : "HTTP"} 代理地址`
      : memory.format === "WIREGUARD_CONFIG" ? "配置" : props.kind === "HTTP" ? "代理地址" : "URI";
    toast[copied ? "success" : "error"](copied ? `已复制 ${protocolLabel} ${label}` : "复制失败，请手动复制");
  };
  const download = () => {
    if (memory.format !== "WIREGUARD_CONFIG") return;
    try {
      if (!memory.uri || !memory.fileName) throw new Error("WIREGUARD_CONFIG_INVALID");
      downloadTextFile(memory.fileName, memory.uri, "text/plain;charset=utf-8");
      toast.success("WireGuard 配置已下载");
    } catch {
      toast.error("配置下载失败，请检查浏览器下载权限");
    } finally {
      clearAndClose();
    }
  };

  return (
    <XrayShareDialogView
      memory={memory}
      loading={memory.phase !== "ERROR" && (query.isLoading || memory.phase === "LOADING")}
      protocolLabel={protocolLabel}
      onClose={clearAndClose}
      onCopy={() => { void copy(); }}
      onCopySecondary={() => { void copy("SECONDARY"); }}
      onDownload={download}
      onRetry={() => dispatch({ type: "LOAD" })}
    />
  );
}
