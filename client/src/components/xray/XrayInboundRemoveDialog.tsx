import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "./XrayDialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { AlertTriangle } from "lucide-react";
import { useState, type FormEvent } from "react";

export function XrayInboundRemoveConfirmation({ inboundName, hostName, lastInbound, confirmation, onConfirmationChange, onSubmit, pending, disabled, errorCode }: {
  inboundName: string;
  hostName: string;
  lastInbound: boolean;
  confirmation: string;
  onConfirmationChange: (value: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  pending: boolean;
  disabled: boolean;
  errorCode: string | null;
}) {
  return (
    <form className="space-y-5" onSubmit={onSubmit}>
      <div className="flex items-start gap-3 rounded-lg border border-destructive/30 bg-destructive/5 p-4">
        <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-destructive" aria-hidden="true" />
        <div>
          <p className="font-medium">先进入待删除，不能立即视为失效</p>
          <p className="mt-1 text-sm text-muted-foreground">
            新 generation 精确应用前，旧节点和已分享凭据可能继续有效。
            {lastInbound ? "这是该主机最后一个节点；应用完成后会停止受管 Xray，但保留已验证二进制。" : "其他节点不会被删除。"}
          </p>
        </div>
      </div>
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-2 rounded-lg border border-border/60 p-4 text-sm">
        <dt className="text-muted-foreground">节点</dt><dd className="break-words font-medium">{inboundName}</dd>
        <dt className="text-muted-foreground">主机</dt><dd className="break-words">{hostName}</dd>
      </dl>
      <div className="space-y-2">
        <Label htmlFor="xray-inbound-remove-confirmation">输入节点名 <span className="font-mono">{inboundName}</span> 以确认</Label>
        <Input
          id="xray-inbound-remove-confirmation"
          value={confirmation}
          autoComplete="off"
          spellCheck={false}
          onChange={(event) => onConfirmationChange(event.target.value)}
        />
      </div>
      {errorCode && <p role="alert" className="rounded-md border border-destructive/30 bg-destructive/5 p-3 text-sm text-destructive">删除未受理：<span className="font-mono text-xs">{errorCode}</span></p>}
      <DialogFooter>
        <Button type="submit" variant="destructive" disabled={confirmation !== inboundName || pending || disabled}>
          {pending ? "正在创建待删除 generation…" : "确认删除节点"}
        </Button>
      </DialogFooter>
    </form>
  );
}

export function XrayInboundRemoveDialog({ inboundName, hostName, lastInbound, pending, disabled, errorCode, onRemove, onClose }: {
  inboundName: string;
  hostName: string;
  lastInbound: boolean;
  pending: boolean;
  disabled: boolean;
  errorCode: string | null;
  onRemove: (confirmName: string) => void;
  onClose: () => void;
}) {
  const [confirmation, setConfirmation] = useState("");
  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!pending && !disabled && confirmation === inboundName) onRemove(confirmation);
  };
  return (
    <Dialog open onOpenChange={(open) => { if (!open && !pending) onClose(); }}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle>删除 Xray 节点</DialogTitle>
          <DialogDescription>删除由持久化 operation 和 Agent observed 状态共同确认。</DialogDescription>
        </DialogHeader>
        <XrayInboundRemoveConfirmation
          inboundName={inboundName}
          hostName={hostName}
          lastInbound={lastInbound}
          confirmation={confirmation}
          onConfirmationChange={setConfirmation}
          onSubmit={submit}
          pending={pending}
          disabled={disabled}
          errorCode={errorCode}
        />
      </DialogContent>
    </Dialog>
  );
}
