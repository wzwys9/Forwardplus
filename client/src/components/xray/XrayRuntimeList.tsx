import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { AppRouterOutputs } from "@/lib/trpc";
import { ChevronLeft, ChevronRight, CircleAlert, CircleCheck, CircleHelp, PackageCheck, PackageX, WifiOff } from "lucide-react";
import type { ReactNode } from "react";

import { formatXrayTime } from "./xrayInboundPresentation";
import { runtimeActionPresentation, runtimeServicePresentation, runtimeVersionPresentation, type XrayRuntimeAction } from "./xrayRuntimePresentation";

type Runtime = AppRouterOutputs["xray"]["runtimes"]["list"]["items"][number];
export type XrayRuntimeListItem = Runtime;
type Catalog = AppRouterOutputs["xray"]["runtimes"]["catalog"];

type Props = {
  items: Runtime[];
  catalog: Catalog;
  page: number;
  totalPages: number;
  totalItems: number;
  onPageChange: (page: number) => void;
  onAction: (runtime: Runtime, action: XrayRuntimeAction, trigger: HTMLButtonElement) => void;
  onOpenOperation: (operationId: string, trigger: HTMLButtonElement) => void;
};

const disabledReasonLabels: Record<string, string> = {
  HOST_OFFLINE: "Agent 离线时不可操作",
  HEARTBEAT_STALE: "心跳过期时不可操作",
  AGENT_UPGRADE_REQUIRED: "需要先升级 Agent",
  PLATFORM_UNSUPPORTED: "主机平台不受支持",
  ARTIFACT_UNAVAILABLE: "缺少已验证制品",
  OPERATION_CONFLICT: "已有操作执行中",
};

function RuntimeActions({ runtime, onAction, onOpenOperation }: Pick<Props, "onAction" | "onOpenOperation"> & { runtime: Runtime }) {
  const actions = runtimeActionPresentation(runtime);
  if (runtime.activeOperationId) {
    return <Button type="button" size="sm" variant="outline" onClick={(event) => onOpenOperation(runtime.activeOperationId!, event.currentTarget)}>查看进度</Button>;
  }
  if (actions.length === 0) return <span className="text-xs text-muted-foreground">无可用操作</span>;
  return (
    <div className="flex flex-wrap justify-end gap-2">
      {actions.map((action) => (
        <Button
          key={action.type}
          type="button"
          size="sm"
          variant={action.type === "SYNC" ? "outline" : action.destructive ? "destructive" : "secondary"}
          disabled={!!action.disabledReason}
          title={action.disabledReason ? disabledReasonLabels[action.disabledReason] ?? action.disabledReason : undefined}
          onClick={(event) => onAction(runtime, action.type, event.currentTarget)}
        >
          {action.label}
        </Button>
      ))}
    </div>
  );
}

function VersionView({ runtime }: { runtime: Runtime }) {
  const view = runtimeVersionPresentation(runtime);
  return (
    <div className="space-y-1">
      <p className="font-mono text-xs">{runtime.installedVersion ?? "—"}</p>
      <div className="flex flex-wrap gap-1.5">
        <Badge variant={view.kind === "UPGRADE_AVAILABLE" ? "default" : view.kind === "NEWER_THAN_TARGET" ? "secondary" : "outline"}>
          {view.label}
        </Badge>
        {view.artifactLabel && <Badge variant="destructive">{view.artifactLabel}</Badge>}
      </div>
      {view.detail && <p className="text-xs text-muted-foreground">{view.detail}</p>}
    </div>
  );
}

function ServiceView({ runtime }: { runtime: Runtime }) {
  const view = runtimeServicePresentation(runtime);
  const Icon = !runtime.isAgentOnline ? WifiOff
    : view.tone === "success" ? CircleCheck
      : view.tone === "danger" ? CircleAlert : CircleHelp;
  return (
    <div className="space-y-1">
      <Badge variant={view.tone === "danger" ? "destructive" : view.tone === "success" ? "default" : "secondary"} className="gap-1.5">
        <Icon className="h-3.5 w-3.5" aria-hidden="true" />{view.label}
      </Badge>
      {view.detail && <p className="max-w-56 text-xs text-muted-foreground">{view.detail}</p>}
      {runtime.lastErrorCode && <p className="text-xs text-destructive">错误码：{runtime.lastErrorCode}</p>}
    </div>
  );
}

function MobileRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4">
      <span className="shrink-0 text-xs text-muted-foreground">{label}</span>
      <div className="min-w-0 max-w-[72%] break-words text-right text-sm">{children}</div>
    </div>
  );
}

export function XrayRuntimeList({ items, catalog, page, totalPages, totalItems, onPageChange, onAction, onOpenOperation }: Props) {
  return (
    <div className="space-y-3">
      <Card>
        <CardContent className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="text-xs text-muted-foreground">面板默认版本</p>
            <p className="mt-1 font-mono text-sm font-medium">{catalog.defaultVersion}</p>
          </div>
          <div className="flex flex-wrap gap-2" aria-label="Xray 制品矩阵">
            {catalog.artifacts.map((artifact) => {
              const Icon = artifact.verified ? PackageCheck : PackageX;
              return (
                <Badge key={`${artifact.os}-${artifact.arch}`} variant={artifact.verified ? "outline" : "destructive"} className="gap-1.5">
                  <Icon className="h-3.5 w-3.5" aria-hidden="true" />
                  {artifact.os}/{artifact.arch} · {artifact.verified ? "已验证" : "缺失"}
                </Badge>
              );
            })}
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardContent className="p-0">
          <div className="grid gap-3 p-3 xl:hidden">
            {items.map((runtime) => (
              <article key={runtime.hostId} className="rounded-lg border border-border/60 bg-background/40 p-4">
                <div className="flex flex-col items-start gap-3 sm:flex-row sm:justify-between">
                  <div><h2 className="font-semibold">{runtime.hostName}</h2><p className="mt-1 text-xs text-muted-foreground">{runtime.inboundCount} 个节点</p></div>
                  <ServiceView runtime={runtime} />
                </div>
                <div className="mt-4 space-y-2.5 border-t border-border/50 pt-3">
                  <MobileRow label="版本"><VersionView runtime={runtime} /></MobileRow>
                  <MobileRow label="运行版本"><span className="font-mono text-xs">{runtime.runningVersion ?? "—"}</span></MobileRow>
                  <MobileRow label="配置">{runtime.configInSync ? "已同步" : "未同步"}</MobileRow>
                  <MobileRow label="Generation">期望 {runtime.desiredGeneration} / 已应用 {runtime.appliedGeneration}</MobileRow>
                  <MobileRow label="最后报告">{formatXrayTime(runtime.lastReportedAt)}</MobileRow>
                  <MobileRow label="操作"><RuntimeActions runtime={runtime} onAction={onAction} onOpenOperation={onOpenOperation} /></MobileRow>
                </div>
              </article>
            ))}
          </div>
          <div className="hidden overflow-x-auto xl:block">
            <Table className="min-w-[980px]">
              <TableHeader><TableRow><TableHead>主机</TableHead><TableHead>Agent</TableHead><TableHead>已装版本</TableHead><TableHead>目标版本</TableHead><TableHead>Xray 状态</TableHead><TableHead>节点数</TableHead><TableHead>配置</TableHead><TableHead>最后报告</TableHead><TableHead className="text-right">操作</TableHead></TableRow></TableHeader>
              <TableBody>{items.map((runtime) => (
                <TableRow key={runtime.hostId}>
                  <TableCell className="font-medium">{runtime.hostName}</TableCell>
                  <TableCell>{runtime.isAgentOnline ? "在线" : "离线"}</TableCell>
                  <TableCell><VersionView runtime={runtime} /></TableCell>
                  <TableCell className="font-mono text-xs">{runtime.targetVersion ?? "—"}</TableCell>
                  <TableCell><ServiceView runtime={runtime} /></TableCell>
                  <TableCell>{runtime.inboundCount}</TableCell>
                  <TableCell><p>{runtime.configInSync ? "已同步" : "未同步"}</p><p className="mt-1 text-xs text-muted-foreground">{runtime.desiredGeneration} / {runtime.appliedGeneration}</p></TableCell>
                  <TableCell className="whitespace-nowrap text-xs text-muted-foreground">{formatXrayTime(runtime.lastReportedAt)}</TableCell>
                  <TableCell><RuntimeActions runtime={runtime} onAction={onAction} onOpenOperation={onOpenOperation} /></TableCell>
                </TableRow>
              ))}</TableBody>
            </Table>
          </div>
          <nav aria-label="Xray 运行环境分页" className="flex flex-col gap-3 border-t border-border/60 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-sm text-muted-foreground">共 {totalItems} 台主机 · 第 {page} / {totalPages} 页</p>
            <div className="flex gap-2">
              <Button type="button" variant="outline" size="sm" aria-label="上一页" disabled={page <= 1} onClick={() => onPageChange(page - 1)}><ChevronLeft className="mr-1 h-4 w-4" />上一页</Button>
              <Button type="button" variant="outline" size="sm" aria-label="下一页" disabled={page >= totalPages} onClick={() => onPageChange(page + 1)}>下一页<ChevronRight className="ml-1 h-4 w-4" /></Button>
            </div>
          </nav>
        </CardContent>
      </Card>
    </div>
  );
}
