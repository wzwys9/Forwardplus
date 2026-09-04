import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "./XrayDialog";
import { Skeleton } from "@/components/ui/skeleton";
import { trpc } from "@/lib/trpc";
import { AlertTriangle, RefreshCw } from "lucide-react";

import { formatXrayTime, type XrayInboundSummary } from "./xrayInboundPresentation";

const operationTypeLabels: Record<string, string> = {
  PORT_PROBE: "端口探测", REALITY_SCAN: "Reality 扫描", INSTALL: "安装", UPGRADE: "升级",
  SYNC: "同步配置", RESTART: "重启运行环境",
};

const operationStatusLabels: Record<string, string> = {
  QUEUED: "排队中", RUNNING: "执行中", SUCCESS: "成功", FAILED: "失败",
  TIMEOUT: "超时", CANCELLED: "已取消",
};

export function XrayOperationErrorDialog({ inbound, onClose }: { inbound: XrayInboundSummary; onClose: () => void }) {
  const query = trpc.xray.operations.list.useQuery({
    page: 1, pageSize: 10, inboundId: inbound.id, sortOrder: "desc",
  }, { retry: false });
  const operation = query.data?.items.find((item) => item.errorCode) ?? query.data?.items[0];

  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><AlertTriangle className="h-5 w-5 text-destructive" aria-hidden={true} />节点操作错误</DialogTitle>
          <DialogDescription>{inbound.name} 的最近脱敏操作结果。不会显示原始配置、命令或密钥。</DialogDescription>
        </DialogHeader>
        {query.isLoading ? (
          <div className="space-y-3" aria-busy="true" aria-label="正在加载操作错误"><Skeleton className="h-16 w-full" /><Skeleton className="h-16 w-full" /></div>
        ) : query.isError ? (
          <div role="alert" className="rounded-lg border border-destructive/30 bg-destructive/5 p-4">
            <p className="text-sm font-medium">操作记录加载失败</p>
            <Button type="button" variant="outline" size="sm" className="mt-3" onClick={() => { void query.refetch(); }}><RefreshCw className="mr-2 h-4 w-4" />重试</Button>
          </div>
        ) : (
          <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-3 rounded-lg border border-border/60 p-4 text-sm">
            <dt className="text-muted-foreground">错误码</dt><dd className="break-all font-mono text-xs">{operation?.errorCode ?? inbound.lastErrorCode ?? "INTERNAL_ERROR"}</dd>
            <dt className="text-muted-foreground">操作</dt><dd>{operationTypeLabels[operation?.type ?? ""] ?? "配置同步"}</dd>
            <dt className="text-muted-foreground">状态</dt><dd>{operationStatusLabels[operation?.status ?? ""] ?? "未知"}</dd>
            <dt className="text-muted-foreground">说明</dt><dd>{operation?.errorMessage ?? "操作未完成，请刷新状态或查看运行环境后重试。"}</dd>
            <dt className="text-muted-foreground">更新时间</dt><dd>{formatXrayTime(operation?.updatedAt ?? inbound.updatedAt)}</dd>
          </dl>
        )}
      </DialogContent>
    </Dialog>
  );
}
