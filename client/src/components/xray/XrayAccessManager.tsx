import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { AppRouterOutputs } from "@/lib/trpc";
import { Link2, Pencil, Plus, Power, Trash2 } from "lucide-react";
import { useState } from "react";

type AccessEntry = AppRouterOutputs["xray"]["inbounds"]["detail"]["accessEntries"][number];
type Props = {
  accessEntries: AccessEntry[];
  accessKind?: "STANDARD" | "WIREGUARD_PEER" | "HTTP_BASIC" | "MIXED_USER_PASSWORD";
  appliedGeneration?: number | null;
  hostOnline: boolean;
  busy: boolean;
  onCreate: (name: string) => void;
  onUpdate: (entry: AccessEntry, changes: { name?: string; isEnabled?: boolean }) => void;
  onRemove: (entry: AccessEntry) => void;
  onShare: (entry: AccessEntry, trigger: HTMLButtonElement) => void;
};

function wireGuardAddress(entry: AccessEntry): string | null {
  if (entry.credentialType !== "WIREGUARD_PEER") return null;
  const settings = entry.settings as { credentialType?: unknown; schemaVersion?: unknown; address?: unknown };
  return settings.credentialType === "WIREGUARD_PEER" && settings.schemaVersion === 2 && typeof settings.address === "string"
    ? settings.address
    : null;
}

export function XrayAccessManager({ accessEntries, accessKind = "STANDARD", appliedGeneration, hostOnline, busy, onCreate, onUpdate, onRemove, onShare }: Props) {
  const [newName, setNewName] = useState("");
  const [editing, setEditing] = useState<AccessEntry | null>(null);
  const [editName, setEditName] = useState("");
  const [removing, setRemoving] = useState<AccessEntry | null>(null);
  const isWireGuard = accessKind === "WIREGUARD_PEER";
  const isHttp = accessKind === "HTTP_BASIC";
  const isMixed = accessKind === "MIXED_USER_PASSWORD";
  const isProxyAccount = isHttp || isMixed;
  const accessLabel = isWireGuard ? "peer" : "账户";
  const writeDisabled = busy || !hostOnline;
  const create = () => {
    const name = newName.trim();
    if (!name) return;
    onCreate(name);
    setNewName("");
  };
  return (
    <div className="space-y-4">
      {!hostOnline && <p role="alert" className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">Agent 离线，Xray 运行状态未知；{isWireGuard ? "全部 peer 写操作已禁用" : "全部账户写操作已禁用"}。</p>}
      <div className="flex flex-col gap-2 rounded-lg border border-border/60 p-3 sm:flex-row sm:items-end">
        <div className="min-w-0 flex-1 space-y-1.5">
          <Label htmlFor="xray-new-access-entry">新{accessLabel}名称</Label>
          <Input id="xray-new-access-entry" maxLength={128} value={newName} onChange={(event) => setNewName(event.target.value)} />
        </div>
        <Button type="button" disabled={writeDisabled || !newName.trim() || accessEntries.filter((entry) => !entry.pendingDelete).length >= 32} onClick={create}>
          <Plus className="mr-2 h-4 w-4" />{isWireGuard ? "添加 peer" : "添加账户"}
        </Button>
      </div>
      <div className="space-y-2">
        {accessEntries.map((entry) => {
          const entryWriteDisabled = writeDisabled || entry.pendingDelete;
          const pendingSync = isWireGuard && !entry.pendingDelete
            && typeof appliedGeneration === "number" && entry.desiredGeneration > appliedGeneration;
          const configuredKinds = entry.secretStatus.configuredKinds;
          const address = wireGuardAddress(entry);
          const credentialStatus = isWireGuard
            ? `地址：${address ?? "待分配"} · 凭据${entry.secretStatus.requiredConfigured ? "已配置（隐藏）" : "未配置"}`
            : isProxyAccount
              ? `${isMixed ? "SOCKS5 / HTTP 共用用户名" : "代理用户名"}：${configuredKinds.includes("USERNAME") ? "已配置（隐藏）" : "未配置"} · 密码：${configuredKinds.includes("PASSWORD") ? "已配置（隐藏）" : "未配置"}`
            : entry.credentialType === "UUID"
            ? `UUID：${configuredKinds.includes("UUID") ? "已配置（隐藏）" : "未配置"}`
            : entry.credentialType === "SHADOWSOCKS_KEY"
              ? `Shadowsocks 密钥：${configuredKinds.includes("SHADOWSOCKS_KEY") ? "已配置（隐藏）" : "未配置"}`
              : entry.credentialType === "HYSTERIA_AUTH"
                ? `Hysteria auth：${configuredKinds.includes("HYSTERIA_AUTH") ? "已配置（隐藏）" : "未配置"}`
            : `Password：${configuredKinds.includes("PASSWORD") ? "已配置（隐藏）" : "未配置"}${configuredKinds.includes("SHORT_ID") ? " · shortId：已配置（隐藏）" : ""}`;
          return (
            <article key={entry.id} className="rounded-lg border border-border/60 p-3">
              <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <h4 className="font-medium">{entry.name}</h4>
                    <Badge variant={entry.pendingDelete ? "destructive" : entry.isEnabled ? "default" : "secondary"}>
                      {entry.pendingDelete ? "待删除" : entry.isEnabled ? "已启用" : "已停用"}
                    </Badge>
                    {pendingSync && <Badge variant="secondary">待同步</Badge>}
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">{credentialStatus}</p>
                  {entry.pendingDelete && <p className="mt-2 text-xs text-destructive">应用完成前旧{isWireGuard ? "配置" : isProxyAccount ? "代理地址" : "链接"}可能继续有效。</p>}
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button type="button" size="sm" variant="outline" onClick={(event) => onShare(entry, event.currentTarget)}><Link2 className="mr-1 h-3.5 w-3.5" />{isWireGuard ? "配置 / QR" : isMixed ? "双代理地址 / QR" : isHttp ? "代理地址 / QR" : "分享 / QR"}</Button>
                  <Button type="button" size="sm" variant="outline" disabled={entryWriteDisabled} onClick={() => { setEditing(entry); setEditName(entry.name); }}><Pencil className="mr-1 h-3.5 w-3.5" />改名</Button>
                  <Button type="button" size="sm" variant="outline" disabled={entryWriteDisabled} onClick={() => onUpdate(entry, { isEnabled: !entry.isEnabled })}><Power className="mr-1 h-3.5 w-3.5" />{entry.isEnabled ? "停用" : "启用"}</Button>
                  <Button type="button" size="sm" variant="destructive" disabled={entryWriteDisabled} onClick={() => setRemoving(entry)}><Trash2 className="mr-1 h-3.5 w-3.5" />删除</Button>
                </div>
              </div>
            </article>
          );
        })}
        {accessEntries.length === 0 && <p className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">暂无{accessLabel}。</p>}
      </div>
      {editing && (
        <Dialog open onOpenChange={(open) => { if (!open) setEditing(null); }}>
          <DialogContent><DialogHeader><DialogTitle>修改{accessLabel}名称</DialogTitle><DialogDescription>身份凭据保持不变。</DialogDescription></DialogHeader>
            <div className="space-y-1.5"><Label htmlFor="xray-edit-access-entry">{accessLabel}名称</Label><Input id="xray-edit-access-entry" maxLength={128} value={editName} onChange={(event) => setEditName(event.target.value)} /></div>
            <DialogFooter><Button type="button" variant="outline" onClick={() => setEditing(null)}>取消</Button><Button type="button" disabled={!editName.trim() || writeDisabled || editing.pendingDelete} onClick={() => { onUpdate(editing, { name: editName.trim() }); setEditing(null); }}>保存</Button></DialogFooter>
          </DialogContent>
        </Dialog>
      )}
      {removing && (
        <Dialog open onOpenChange={(open) => { if (!open) setRemoving(null); }}>
          <DialogContent><DialogHeader><DialogTitle>删除{accessLabel}“{removing.name}”</DialogTitle><DialogDescription>将先标记待删除并下发新 generation；应用完成前旧{isWireGuard ? "配置" : isProxyAccount ? "代理地址" : "链接"}可能继续有效。</DialogDescription></DialogHeader>
            <DialogFooter><Button type="button" variant="outline" onClick={() => setRemoving(null)}>取消</Button><Button type="button" variant="destructive" disabled={writeDisabled || removing.pendingDelete} onClick={() => { onRemove(removing); setRemoving(null); }}>确认删除</Button></DialogFooter>
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
}
