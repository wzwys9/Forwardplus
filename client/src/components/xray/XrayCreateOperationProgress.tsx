import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { trpc } from "@/lib/trpc";
import { AlertTriangle, CheckCircle2, Clock3, RefreshCw } from "lucide-react";

import { operationFailureNextStep } from "./xrayCreateDeployment";
import { operationQueryPolling } from "./xrayOperationPolling";

const statusLabels: Record<string, string> = {
  QUEUED: "等待 Agent", RUNNING: "正在执行", SUCCESS: "操作成功", FAILED: "操作失败",
  TIMEOUT: "操作超时", CANCELLED: "已取消",
};

const stageLabels: Record<string, string> = {
  QUEUED: "等待 Agent 获取任务", DOWNLOADING_ARTIFACT: "下载并验证 Xray 制品",
  VERIFYING_ARTIFACT: "验证 Xray 制品", VALIDATING_CONFIG: "验证并应用配置",
  SWITCHING_CONFIG: "原子切换配置", RESTARTING_RUNTIME: "重启受管 Xray",
  CHECKING_LISTENERS: "检查受管监听器", ROLLING_BACK: "恢复 last-good",
  PROBING_PORT: "检测端口", APPLYING: "等待 Agent 应用期望配置", COMPLETE: "检查运行状态和监听器",
};

const operationTypeLabels: Record<string, string> = {
  INSTALL: "安装", UPGRADE: "升级", RESTART: "重启", SYNC: "同步配置",
  PORT_PROBE: "端口探测", REALITY_SCAN: "Reality 扫描",
};

export function XrayCreateOperationProgress({ operationId, onClose, onShowRuntime, scope = "create" }: { operationId: string; onClose: () => void; onShowRuntime: (hostId: number) => void; scope?: "create" | "runtime" }) {
  const query = trpc.xray.operations.get.useQuery({ operationId }, {
    retry: false,
    refetchInterval: operationQueryPolling,
    refetchOnWindowFocus: false,
  });
  if (query.isLoading) return <div className="space-y-3" aria-busy="true" aria-label="正在恢复操作进度"><Skeleton className="h-20 w-full" /><Skeleton className="h-32 w-full" /></div>;
  if (query.isError || !query.data) return <div role="alert" className="rounded-lg border border-destructive/30 bg-destructive/5 p-4"><p className="font-medium">无法恢复 operation</p><p className="mt-1 text-sm text-muted-foreground">记录可能不存在或当前连接不可用。写入结果不会在浏览器中猜测。</p><div className="mt-3 flex gap-2"><Button type="button" variant="outline" onClick={() => { void query.refetch(); }}><RefreshCw className="mr-2 h-4 w-4" />重试</Button><Button type="button" variant="ghost" onClick={onClose}>返回列表</Button></div></div>;

  const operation = query.data;
  const success = operation.status === "SUCCESS";
  const failed = ["FAILED", "TIMEOUT", "CANCELLED"].includes(operation.status);
  const Icon = success ? CheckCircle2 : failed ? AlertTriangle : Clock3;
  return (
    <div className="space-y-5" aria-live="polite">
      <div className="flex items-start gap-3"><span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-muted"><Icon className={`h-5 w-5 ${failed ? "text-destructive" : ""}`} aria-hidden={true} /></span><div><h3 className="font-semibold">{statusLabels[operation.status] ?? "操作状态未知"}</h3><p className="mt-1 text-sm text-muted-foreground">{success ? (operation.type === "SYNC" || operation.type === "UPGRADE" ? "Agent observed state 已精确确认 generation、配置、版本和监听器。" : "Agent 已确认操作完成。") : failed ? "操作未被声明为成功；请按错误码检查后重试。" : "这是持久 operation，刷新页面后仍会从数据库恢复。"}</p></div></div>
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-3 rounded-lg border border-border/60 p-4 text-sm">
        <dt className="text-muted-foreground">Operation</dt><dd className="break-all font-mono text-xs">{operation.operationId}</dd>
        <dt className="text-muted-foreground">操作</dt><dd>{operationTypeLabels[operation.type] ?? operation.type}</dd>
        <dt className="text-muted-foreground">状态</dt><dd><Badge variant={success ? "default" : failed ? "destructive" : "secondary"}>{statusLabels[operation.status] ?? operation.status}</Badge></dd>
        <dt className="text-muted-foreground">当前阶段</dt><dd>{stageLabels[operation.stage] ?? "等待最新 Agent 状态"}</dd>
        <dt className="text-muted-foreground">Generation</dt><dd>{operation.requestedGeneration ?? "-"}</dd>
        {operation.errorCode && <><dt className="text-muted-foreground">错误码</dt><dd className="break-all font-mono text-xs">{operation.errorCode}</dd><dt className="text-muted-foreground">下一步</dt><dd>{operationFailureNextStep(operation.errorCode)}</dd></>}
      </dl>
      <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">{failed && scope === "create" && <Button type="button" variant="outline" onClick={() => onShowRuntime(operation.hostId)}>查看运行环境</Button>}<Button type="button" onClick={onClose}>{success ? "完成" : failed ? "返回列表" : "在后台继续"}</Button></div>
    </div>
  );
}
