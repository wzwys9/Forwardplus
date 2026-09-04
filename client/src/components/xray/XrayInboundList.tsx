import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  AlertTriangle, ChevronLeft, ChevronRight, CircleCheck, CircleHelp, CirclePause,
  Clock3, Download, RefreshCw, Trash2, Wifi, WifiOff,
} from "lucide-react";
import type { ComponentType } from "react";

import {
  formatXrayEndpoint,
  formatXrayTime,
  inboundStatusPresentation,
  type XrayInboundStatusView,
  type XrayInboundSummary,
} from "./xrayInboundPresentation";

type Props = {
  items: XrayInboundSummary[];
  page: number;
  totalPages: number;
  totalItems: number;
  onPageChange: (page: number) => void;
  onInspectError: (item: XrayInboundSummary) => void;
  onOpenDetail: (item: XrayInboundSummary, trigger: HTMLButtonElement) => void;
  onOpenOperation: (operationId: string, trigger: HTMLButtonElement) => void;
};

const statusIcons: Record<XrayInboundStatusView["icon"], ComponentType<{ className?: string; "aria-hidden"?: boolean }>> = {
  clock: Clock3, download: Download, refresh: RefreshCw, running: CircleCheck, disabled: CirclePause,
  delete: Trash2, error: AlertTriangle, offline: WifiOff, unknown: CircleHelp,
};

function StatusView({ item, onInspectError }: { item: XrayInboundSummary; onInspectError: Props["onInspectError"] }) {
  const view = inboundStatusPresentation(item);
  const Icon = statusIcons[view.icon];
  return (
    <div className="space-y-1.5">
      <Badge variant={view.badge} className="gap-1.5 whitespace-nowrap">
        <Icon className="h-3.5 w-3.5" aria-hidden={true} />{view.label}
      </Badge>
      {view.detail && <p className="max-w-56 text-xs leading-5 text-muted-foreground">{view.detail}</p>}
      {view.canInspectError && (
        <Button type="button" variant="link" size="sm" className="h-auto p-0 text-xs" onClick={() => onInspectError(item)}>
          查看错误
        </Button>
      )}
    </div>
  );
}

function HostView({ item }: { item: XrayInboundSummary }) {
  const Icon = item.host.isOnline ? Wifi : WifiOff;
  return (
    <div>
      <p className="font-medium">{item.host.name}</p>
      <p className="mt-1 flex items-center gap-1 text-xs text-muted-foreground">
        <Icon className="h-3.5 w-3.5" aria-hidden={true} />{item.host.isOnline ? "Agent 在线" : "Agent 离线"}
      </p>
    </div>
  );
}

function MobileRow({ label, children }: { label: string; children: React.ReactNode }) {
  return <div className="flex items-start justify-between gap-4"><span className="shrink-0 text-xs text-muted-foreground">{label}</span><div className="min-w-0 max-w-[72%] break-words text-right text-sm">{children}</div></div>;
}

function protocolSecurityLabel(item: XrayInboundSummary) {
  const protocol = item.protocol.toLowerCase() === "hysteria" ? "Hysteria 2"
    : item.protocol.toLowerCase() === "http" ? "HTTP 管理代理"
      : item.protocol.toLowerCase() === "mixed" ? "Mixed（SOCKS5 + HTTP）"
        : item.protocol.toLowerCase() === "tunnel" ? "Tunnel（本机转发）" : item.protocol;
  const security = item.security.toUpperCase() === "REALITY" ? "Reality" : item.security.toUpperCase();
  return `${protocol} · ${security}`;
}

function externalProxyLabel(item: XrayInboundSummary) {
  return item.externalProxy ? `${item.externalProxy.name}（${item.externalProxy.protocol}）` : "直连";
}

export function XrayInboundList({ items, page, totalPages, totalItems, onPageChange, onInspectError, onOpenDetail, onOpenOperation }: Props) {
  return (
    <Card>
      <CardContent className="p-0">
        <div className="grid gap-3 p-3 xl:hidden">
          {items.map((item) => (
            <article key={item.id} className="rounded-lg border border-border/60 bg-background/40 p-4">
              <div className="flex flex-col items-start gap-3 sm:flex-row sm:justify-between">
                <div className="min-w-0"><h2 className="truncate font-semibold">{item.name}</h2><p className="mt-1 break-all font-mono text-xs text-muted-foreground">{formatXrayEndpoint(item.publicAddress, item.listenPort)}</p></div>
                <StatusView item={item} onInspectError={onInspectError} />
              </div>
              <div className="mt-4 space-y-2.5 border-t border-border/50 pt-3">
                <MobileRow label="所属主机"><HostView item={item} /></MobileRow>
                <MobileRow label="协议 / 安全"><span>{protocolSecurityLabel(item)}</span></MobileRow>
                <MobileRow label="出口"><span>{externalProxyLabel(item)}</span></MobileRow>
                <MobileRow label={item.profileId === "TUNNEL_TCP_LOCAL_NONE" ? "凭据" : "客户端"}>{item.profileId === "TUNNEL_TCP_LOCAL_NONE" ? "无" : `${item.clientCount} 个`}</MobileRow>
                <MobileRow label="更新时间">{formatXrayTime(item.updatedAt)}</MobileRow>
              </div>
              <div className="mt-4 flex gap-2">
                <Button type="button" variant="outline" size="sm" className="flex-1" onClick={(event) => onOpenDetail(item, event.currentTarget)}>查看详情</Button>
                {item.activeOperationId && <Button type="button" size="sm" className="flex-1" onClick={(event) => onOpenOperation(item.activeOperationId!, event.currentTarget)}>查看进度</Button>}
              </div>
            </article>
          ))}
        </div>
        <div className="hidden overflow-x-auto xl:block">
          <Table className="min-w-[1120px]">
            <TableHeader><TableRow><TableHead>节点名称</TableHead><TableHead>所属主机</TableHead><TableHead>监听地址</TableHead><TableHead>协议 / 安全</TableHead><TableHead>出口</TableHead><TableHead>客户端 / 凭据</TableHead><TableHead>部署状态</TableHead><TableHead>更新时间</TableHead><TableHead className="text-right">操作</TableHead></TableRow></TableHeader>
            <TableBody>{items.map((item) => (
              <TableRow key={item.id}>
                <TableCell className="font-medium">{item.name}</TableCell>
                <TableCell><HostView item={item} /></TableCell>
                <TableCell className="font-mono text-xs">{formatXrayEndpoint(item.publicAddress, item.listenPort)}</TableCell>
                <TableCell>{protocolSecurityLabel(item)}</TableCell>
                <TableCell className="max-w-48 truncate" title={externalProxyLabel(item)}>{externalProxyLabel(item)}</TableCell>
                <TableCell>{item.profileId === "TUNNEL_TCP_LOCAL_NONE" ? "无" : item.clientCount}</TableCell>
                <TableCell><StatusView item={item} onInspectError={onInspectError} /></TableCell>
                <TableCell className="whitespace-nowrap text-xs text-muted-foreground">{formatXrayTime(item.updatedAt)}</TableCell>
                <TableCell className="text-right"><div className="flex justify-end gap-2"><Button type="button" variant="outline" size="sm" onClick={(event) => onOpenDetail(item, event.currentTarget)}>查看详情</Button>{item.activeOperationId && <Button type="button" size="sm" onClick={(event) => onOpenOperation(item.activeOperationId!, event.currentTarget)}>查看进度</Button>}</div></TableCell>
              </TableRow>
            ))}</TableBody>
          </Table>
        </div>
        <nav aria-label="Xray 节点分页" className="flex flex-col gap-3 border-t border-border/60 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
          <p className="text-sm text-muted-foreground">共 {totalItems} 个节点 · 第 {page} / {totalPages} 页</p>
          <div className="flex gap-2">
            <Button type="button" variant="outline" size="sm" aria-label="上一页" disabled={page <= 1} onClick={() => onPageChange(page - 1)}><ChevronLeft className="mr-1 h-4 w-4" aria-hidden={true} />上一页</Button>
            <Button type="button" variant="outline" size="sm" aria-label="下一页" disabled={page >= totalPages} onClick={() => onPageChange(page + 1)}>下一页<ChevronRight className="ml-1 h-4 w-4" aria-hidden={true} /></Button>
          </div>
        </nav>
      </CardContent>
    </Card>
  );
}
