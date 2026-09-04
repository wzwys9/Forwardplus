import { XrayCreateOperationProgress } from "@/components/xray/XrayCreateOperationProgress";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { trpc } from "@/lib/trpc";
import { AlertTriangle } from "lucide-react";
import { useState, type FormEvent } from "react";

import type { XrayRuntimeListItem } from "./XrayRuntimeList";
import type { XrayRuntimeAction } from "./xrayRuntimePresentation";

export type XrayRuntimeActionSelection = {
  runtime: XrayRuntimeListItem;
  action: XrayRuntimeAction;
};

const actionCopy: Record<XrayRuntimeAction, { title: string; description: string; submit: string }> = {
  INSTALL: {
    title: "安装受管 Xray",
    description: "Agent 将下载并校验面板批准的固定制品，写入 ForwardX 专属目录。",
    submit: "确认安装",
  },
  UPGRADE: {
    title: "升级受管 Xray",
    description: "新版本会先写入独立目录；配置应用失败时保留或恢复旧二进制和 last-good。",
    submit: "确认升级",
  },
  RESTART: {
    title: "重启受管 Xray",
    description: "只重启 ForwardX 管理的 Xray 子进程，并在启动前验证已提交配置。",
    submit: "确认重启",
  },
  SYNC: {
    title: "重新同步配置",
    description: "面板将重新生成结构化 desired snapshot；普通同步不会安装新版本，也不会降级更高版本。",
    submit: "确认同步",
  },
};

export function XrayRuntimeOperationConfirmation({ selection, confirmation, onConfirmationChange, onSubmit, pending, errorCode }: {
  selection: XrayRuntimeActionSelection;
  confirmation: string;
  onConfirmationChange: (value: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  pending: boolean;
  errorCode: string | null;
}) {
  const copy = actionCopy[selection.action];
  const confirmed = confirmation === selection.runtime.hostName;
  return (
    <form className="space-y-5" onSubmit={onSubmit}>
      <div className="flex items-start gap-3 rounded-lg border border-destructive/30 bg-destructive/5 p-4">
        <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-destructive" aria-hidden="true" />
        <div><p className="font-medium">此操作会改变远端运行环境</p><p className="mt-1 text-sm text-muted-foreground">{copy.description}</p></div>
      </div>
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 rounded-lg border border-border/60 p-4 text-sm">
        <dt className="text-muted-foreground">主机</dt><dd className="break-words font-medium">{selection.runtime.hostName}</dd>
        <dt className="text-muted-foreground">已装版本</dt><dd className="font-mono text-xs">{selection.runtime.installedVersion ?? "未安装"}</dd>
        <dt className="text-muted-foreground">面板目标</dt><dd className="font-mono text-xs">{selection.runtime.targetVersion ?? "默认版本"}</dd>
      </dl>
      <div className="space-y-2">
        <Label htmlFor="xray-runtime-confirmation">输入主机名 <span className="font-mono">{selection.runtime.hostName}</span> 以确认</Label>
        <Input
          id="xray-runtime-confirmation"
          value={confirmation}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => onConfirmationChange(event.target.value)}
        />
      </div>
      {errorCode && <p role="alert" className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">操作未创建：<span className="font-mono text-xs">{errorCode}</span></p>}
      <DialogFooter><Button type="submit" variant="destructive" disabled={!confirmed || pending}>{pending ? "正在创建 operation…" : copy.submit}</Button></DialogFooter>
    </form>
  );
}

export function XrayRuntimeOperationDialog({ selection, operationId, onOperationStarted, onClose }: {
  selection: XrayRuntimeActionSelection | null;
  operationId: string | null;
  onOperationStarted: (operationId: string) => void;
  onClose: () => void;
}) {
  const [confirmation, setConfirmation] = useState("");
  const common = { onSuccess: ({ operationId: id }: { operationId: string }) => onOperationStarted(id) };
  const install = trpc.xray.runtimes.install.useMutation(common);
  const upgrade = trpc.xray.runtimes.upgrade.useMutation(common);
  const restart = trpc.xray.runtimes.restart.useMutation(common);
  const sync = trpc.xray.runtimes.sync.useMutation(common);
  const pending = install.isPending || upgrade.isPending || restart.isPending || sync.isPending;
  const error = install.error ?? upgrade.error ?? restart.error ?? sync.error;
  const errorCode = error ? String(error.message || "INTERNAL_ERROR") : null;
  const copy = selection ? actionCopy[selection.action] : null;

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selection || confirmation !== selection.runtime.hostName || pending) return;
    const { runtime, action } = selection;
    if (action === "INSTALL") install.mutate({ hostId: runtime.hostId, ...(runtime.targetVersion ? { targetVersion: runtime.targetVersion } : {}) });
    else if (action === "UPGRADE" && runtime.targetVersion && runtime.installedVersion) upgrade.mutate({ hostId: runtime.hostId, targetVersion: runtime.targetVersion, expectedInstalledVersion: runtime.installedVersion });
    else if (action === "RESTART") restart.mutate({ hostId: runtime.hostId, confirmHostName: confirmation });
    else if (action === "SYNC") sync.mutate({ hostId: runtime.hostId });
  };

  return (
    <Dialog open onOpenChange={(open) => { if (!open && !pending) onClose(); }}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>{operationId ? "Xray 运行环境操作" : copy?.title ?? "Xray 运行环境操作"}</DialogTitle>
          <DialogDescription>{operationId ? "从数据库恢复持久 operation 的真实进度。" : "确认后由面板创建持久 operation；关闭或刷新不会改变执行结果。"}</DialogDescription>
        </DialogHeader>
        {operationId
          ? <XrayCreateOperationProgress operationId={operationId} scope="runtime" onClose={onClose} onShowRuntime={() => undefined} />
          : selection
            ? <XrayRuntimeOperationConfirmation selection={selection} confirmation={confirmation} onConfirmationChange={setConfirmation} onSubmit={submit} pending={pending} errorCode={errorCode} />
            : null}
      </DialogContent>
    </Dialog>
  );
}
