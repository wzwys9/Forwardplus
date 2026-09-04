import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import type { AppRouterOutputs } from "@/lib/trpc";
import { trpc } from "@/lib/trpc";
import { AlertTriangle, ChevronLeft, ChevronRight, Pencil, RefreshCw, Replace, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { formatXrayEndpoint, formatXrayTime } from "./xrayInboundPresentation";

type ExternalProxy = AppRouterOutputs["xray"]["externalProxyNodes"]["list"]["items"][number];
type Preview = AppRouterOutputs["xray"]["externalProxyNodes"]["previewImport"];

const protocolLabels: Record<string, string> = {
  VLESS_REALITY_VISION: "VLESS · Reality · Vision",
  SHADOWSOCKS: "Shadowsocks",
  SOCKS5: "SOCKS5",
};

function errorMessage(code: string): string {
  const labels: Record<string, string> = {
    EXTERNAL_PROXY_INVALID_LINK: "链接不受支持或字段不合法",
    EXTERNAL_PROXY_NOT_FOUND: "出口节点已不存在，请刷新列表",
    EXTERNAL_PROXY_IN_USE: "出口节点仍被引用，请先解除 Xray 节点和转发规则引用",
    EXTERNAL_PROXY_REFERENCE_INVALID: "出口节点数据不完整，请检查主密钥和节点定义",
    SENSITIVE_DATA_UNAVAILABLE: "出口节点凭据无法解密，请检查主密钥",
    CONFIRMATION_MISMATCH: "确认名称不匹配",
  };
  return labels[code] ?? "出口节点操作失败，请稍后重试";
}

function ProtocolBadge({ protocol }: { protocol: string }) {
  return <Badge variant="secondary" className="whitespace-nowrap">{protocolLabels[protocol] ?? protocol}</Badge>;
}

function ImportDialog({ open, onOpenChange, onCreated }: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: () => void;
}) {
  const [uri, setUri] = useState("");
  const [name, setName] = useState("");
  const [preview, setPreview] = useState<Preview | null>(null);
  const previewImport = trpc.xray.externalProxyNodes.previewImport.useMutation();
  const createNode = trpc.xray.externalProxyNodes.create.useMutation();
  const reset = () => {
    setUri("");
    setName("");
    setPreview(null);
    previewImport.reset();
    createNode.reset();
  };
  const close = () => {
    reset();
    onOpenChange(false);
  };
  const runPreview = async () => {
    const raw = uri.trim();
    if (!raw) return;
    setPreview(null);
    try {
      const result = await previewImport.mutateAsync({ uri: raw });
      setPreview(result);
      setName(result.suggestedName || `${protocolLabels[result.protocol] ?? result.protocol} 出口`);
    } catch (error) {
      setUri("");
      toast.error(errorMessage(error instanceof Error ? error.message : ""));
    } finally {
      previewImport.reset();
    }
  };
  const create = async () => {
    const raw = uri.trim();
    try {
      await createNode.mutateAsync({ name: name.trim(), uri: raw });
      createNode.reset();
      toast.success("出口节点已导入");
      reset();
      onOpenChange(false);
      onCreated();
    } catch (error) {
      setUri("");
      setPreview(null);
      createNode.reset();
      toast.error(errorMessage(error instanceof Error ? error.message : ""));
    }
  };
  return (
    <Dialog open={open} onOpenChange={(next) => { if (!next) close(); }}>
      <DialogContent className="max-h-[90svh] max-w-2xl overflow-y-auto">
        <DialogHeader>
          <DialogTitle>导入出口节点</DialogTitle>
          <DialogDescription>支持 VLESS RAW + Reality + Vision、Shadowsocks 和 SOCKS5 单节点链接。原始链接不会保存到普通配置或列表。</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="xray-external-import-uri">节点链接</Label>
            <Textarea id="xray-external-import-uri" value={uri} maxLength={4096} rows={4} spellCheck={false} className="font-mono text-xs" placeholder="vless://、ss:// 或 socks5://" onChange={(event) => { setUri(event.target.value); setPreview(null); }} />
          </div>
          <Button type="button" variant="outline" disabled={!uri.trim() || previewImport.isPending || createNode.isPending} onClick={() => { void runPreview(); }}>
            {previewImport.isPending ? "正在识别…" : "识别并预览"}
          </Button>
          {preview && (
            <div className="space-y-3 rounded-lg border border-border/60 bg-muted/20 p-4">
              <div className="flex flex-wrap items-center gap-2"><ProtocolBadge protocol={preview.protocol} /><span className="font-mono text-sm">{formatXrayEndpoint(preview.address, preview.port)}</span></div>
              <p className="text-xs text-muted-foreground">凭据已识别，但不会在预览中回显。这里只展示可安全确认的公开字段。</p>
              <div className="space-y-1.5"><Label htmlFor="xray-external-import-name">显示名称</Label><Input id="xray-external-import-name" value={name} maxLength={128} onChange={(event) => setName(event.target.value)} /></div>
            </div>
          )}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="outline" disabled={createNode.isPending} onClick={close}>取消</Button>
            <Button type="button" disabled={!preview || !name.trim() || !uri.trim() || createNode.isPending} onClick={() => { void create(); }}>{createNode.isPending ? "正在导入…" : "确认导入"}</Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function DetailDialog({ node, onClose, onChanged }: { node: ExternalProxy; onClose: () => void; onChanged: () => void }) {
  const [name, setName] = useState(node.name);
  const [replacementUri, setReplacementUri] = useState("");
  const [confirmName, setConfirmName] = useState("");
  const renameNode = trpc.xray.externalProxyNodes.rename.useMutation();
  const replaceNode = trpc.xray.externalProxyNodes.replace.useMutation();
  const removeNode = trpc.xray.externalProxyNodes.remove.useMutation();
  const referenced = node.inboundCount + node.ruleCount > 0;
  const busy = renameNode.isPending || replaceNode.isPending || removeNode.isPending;
  const rename = async () => {
    try {
      await renameNode.mutateAsync({ id: node.id, name: name.trim() });
      toast.success("出口节点名称已更新");
      onChanged();
    } catch (error) {
      toast.error(errorMessage(error instanceof Error ? error.message : ""));
    } finally {
      renameNode.reset();
    }
  };
  const replace = async () => {
    const raw = replacementUri.trim();
    try {
      await replaceNode.mutateAsync({ id: node.id, uri: raw });
      setReplacementUri("");
      replaceNode.reset();
      toast.success("出口节点链接已替换");
      onClose();
      onChanged();
    } catch (error) {
      setReplacementUri("");
      replaceNode.reset();
      toast.error(errorMessage(error instanceof Error ? error.message : ""));
    }
  };
  const remove = async () => {
    try {
      await removeNode.mutateAsync({ id: node.id, confirmName });
      toast.success("出口节点已删除");
      setConfirmName("");
      removeNode.reset();
      onClose();
      onChanged();
    } catch (error) {
      setConfirmName("");
      removeNode.reset();
      toast.error(errorMessage(error instanceof Error ? error.message : ""));
    }
  };
  const close = () => {
    setReplacementUri("");
    setConfirmName("");
    renameNode.reset();
    replaceNode.reset();
    removeNode.reset();
    onClose();
  };
  return (
    <Dialog open onOpenChange={(open) => { if (!open) close(); }}>
      <DialogContent className="max-h-[90svh] max-w-2xl overflow-y-auto">
        <DialogHeader><DialogTitle>{node.name}</DialogTitle><DialogDescription>出口定义不代表当前在线；实际状态由引用它的 Xray 部署或转发规则分别报告。</DialogDescription></DialogHeader>
        <div className="space-y-5">
          <dl className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg border p-3"><dt className="text-xs text-muted-foreground">协议</dt><dd className="mt-1"><ProtocolBadge protocol={node.protocol} /></dd></div>
            <div className="rounded-lg border p-3"><dt className="text-xs text-muted-foreground">公开 endpoint</dt><dd className="mt-1 break-all font-mono text-sm">{formatXrayEndpoint(node.address, node.port)}</dd></div>
            <div className="rounded-lg border p-3"><dt className="text-xs text-muted-foreground">Xray 节点引用</dt><dd className="mt-1 text-sm">{node.inboundCount} 个</dd></div>
            <div className="rounded-lg border p-3"><dt className="text-xs text-muted-foreground">转发规则引用</dt><dd className="mt-1 text-sm">{node.ruleCount} 条</dd></div>
          </dl>
          {referenced && <p className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">当前共被 {node.inboundCount + node.ruleCount} 个入口引用。可重命名，但替换链接和删除前必须在 Xray 节点或规则详情中解除引用。</p>}
          <section className="space-y-2"><h3 className="text-sm font-medium">重命名</h3><div className="flex flex-col gap-2 sm:flex-row"><Input aria-label="出口节点名称" value={name} maxLength={128} onChange={(event) => setName(event.target.value)} /><Button type="button" variant="outline" disabled={busy || !name.trim() || name.trim() === node.name} onClick={() => { void rename(); }}><Pencil className="mr-1.5 h-4 w-4" />保存名称</Button></div></section>
          <section className="space-y-2"><h3 className="text-sm font-medium">替换节点链接</h3><Textarea aria-label="替换节点链接" value={replacementUri} maxLength={4096} rows={3} spellCheck={false} disabled={referenced || busy} className="font-mono text-xs" placeholder={referenced ? "解除全部引用后才可替换" : "粘贴新的 vless://、ss:// 或 socks5:// 链接"} onChange={(event) => setReplacementUri(event.target.value)} /><Button type="button" variant="outline" disabled={referenced || busy || !replacementUri.trim()} onClick={() => { void replace(); }}><Replace className="mr-1.5 h-4 w-4" />替换链接</Button></section>
          <section className="space-y-2 rounded-lg border border-destructive/30 p-4"><h3 className="text-sm font-medium text-destructive">删除出口节点</h3><p className="text-xs text-muted-foreground">请输入完整名称“{node.name}”确认。被引用时不能删除。</p><div className="flex flex-col gap-2 sm:flex-row"><Input aria-label="删除确认名称" value={confirmName} disabled={referenced || busy} onChange={(event) => setConfirmName(event.target.value)} /><Button type="button" variant="destructive" disabled={referenced || busy || confirmName !== node.name} onClick={() => { void remove(); }}><Trash2 className="mr-1.5 h-4 w-4" />删除</Button></div></section>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export function XrayExternalProxyNodes({ search, page, importOpen, onImportOpenChange, onPageChange }: {
  search: string;
  page: number;
  importOpen: boolean;
  onImportOpenChange: (open: boolean) => void;
  onPageChange: (page: number) => void;
}) {
  const [selected, setSelected] = useState<ExternalProxy | null>(null);
  const query = trpc.xray.externalProxyNodes.list.useQuery({ page, pageSize: 20, search }, { retry: false, refetchOnWindowFocus: true });
  const totalPages = useMemo(() => Math.max(1, Math.ceil((query.data?.total ?? 0) / (query.data?.pageSize ?? 20))), [query.data]);
  useEffect(() => {
    if (page > totalPages && query.data) onPageChange(totalPages);
  }, [onPageChange, page, query.data, totalPages]);
  const changed = () => { setSelected(null); void query.refetch(); };
  if (query.isLoading) return <div className="space-y-3" aria-busy="true">{[0, 1, 2].map((item) => <Skeleton key={item} className="h-20 w-full" />)}</div>;
  if (query.isError || !query.data) return <Card role="alert" className="border-destructive/30"><CardContent className="flex min-h-48 flex-col items-center justify-center gap-3 text-center"><AlertTriangle className="h-7 w-7 text-destructive" /><p className="text-sm">出口节点加载失败。</p><Button type="button" variant="outline" onClick={() => { void query.refetch(); }}><RefreshCw className="mr-2 h-4 w-4" />重新加载</Button></CardContent></Card>;
  return (
    <>
      {query.data.items.length === 0 ? <Card><CardContent className="flex min-h-56 flex-col items-center justify-center p-6 text-center"><h2 className="font-semibold">{search ? "没有匹配的出口节点" : "尚未导入出口节点"}</h2><p className="mt-1 text-sm text-muted-foreground">导入后可绑定到 Xray 入站，或作为六种本地工具的 TCP 转发目标。</p></CardContent></Card> : <Card><CardContent className="p-0">
        <div className="grid gap-3 p-3 lg:hidden">{query.data.items.map((node) => <article key={node.id} className="space-y-3 rounded-lg border p-4"><div className="flex items-start justify-between gap-3"><div className="min-w-0"><h2 className="truncate font-semibold">{node.name}</h2><p className="mt-1 break-all font-mono text-xs text-muted-foreground">{formatXrayEndpoint(node.address, node.port)}</p></div><ProtocolBadge protocol={node.protocol} /></div><p className="text-xs text-muted-foreground">Xray 引用 {node.inboundCount} · 规则引用 {node.ruleCount} · 更新 {formatXrayTime(node.updatedAt)}</p><Button type="button" size="sm" variant="outline" className="w-full" onClick={() => setSelected(node)}>查看详情</Button></article>)}</div>
        <div className="hidden overflow-x-auto lg:block"><Table className="min-w-[900px]"><TableHeader><TableRow><TableHead>名称</TableHead><TableHead>协议</TableHead><TableHead>公开 endpoint</TableHead><TableHead>Xray 引用</TableHead><TableHead>规则引用</TableHead><TableHead>更新时间</TableHead><TableHead className="text-right">操作</TableHead></TableRow></TableHeader><TableBody>{query.data.items.map((node) => <TableRow key={node.id}><TableCell className="font-medium">{node.name}</TableCell><TableCell><ProtocolBadge protocol={node.protocol} /></TableCell><TableCell className="font-mono text-xs">{formatXrayEndpoint(node.address, node.port)}</TableCell><TableCell>{node.inboundCount}</TableCell><TableCell>{node.ruleCount}</TableCell><TableCell className="whitespace-nowrap text-xs text-muted-foreground">{formatXrayTime(node.updatedAt)}</TableCell><TableCell className="text-right"><Button type="button" size="sm" variant="outline" onClick={() => setSelected(node)}>查看详情</Button></TableCell></TableRow>)}</TableBody></Table></div>
        <nav className="flex flex-col gap-3 border-t px-4 py-3 sm:flex-row sm:items-center sm:justify-between"><p className="text-sm text-muted-foreground">共 {query.data.total} 个出口节点 · 第 {query.data.page} / {totalPages} 页</p><div className="flex gap-2"><Button type="button" size="sm" variant="outline" disabled={page <= 1} onClick={() => onPageChange(page - 1)}><ChevronLeft className="mr-1 h-4 w-4" />上一页</Button><Button type="button" size="sm" variant="outline" disabled={page >= totalPages} onClick={() => onPageChange(page + 1)}>下一页<ChevronRight className="ml-1 h-4 w-4" /></Button></div></nav>
      </CardContent></Card>}
      <ImportDialog open={importOpen} onOpenChange={onImportOpenChange} onCreated={changed} />
      {selected && <DetailDialog node={selected} onClose={() => setSelected(null)} onChanged={changed} />}
    </>
  );
}
