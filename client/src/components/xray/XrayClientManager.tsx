import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { AppRouterOutputs } from "@/lib/trpc";
import { Link2, Pencil, Plus, Power, Trash2 } from "lucide-react";
import { useState } from "react";

type Client = AppRouterOutputs["xray"]["inbounds"]["detail"]["clients"][number];
type Props = {
  clients: Client[];
  hostOnline: boolean;
  busy: boolean;
  onCreate: (name: string) => void;
  onUpdate: (client: Client, changes: { name?: string; isEnabled?: boolean }) => void;
  onRemove: (client: Client) => void;
  onShare: (client: Client, trigger: HTMLButtonElement) => void;
};

export function XrayClientManager({ clients, hostOnline, busy, onCreate, onUpdate, onRemove, onShare }: Props) {
  const [newName, setNewName] = useState("");
  const [editing, setEditing] = useState<Client | null>(null);
  const [editName, setEditName] = useState("");
  const [removing, setRemoving] = useState<Client | null>(null);
  const writeDisabled = busy || !hostOnline;
  const create = () => {
    const name = newName.trim();
    if (!name) return;
    onCreate(name);
    setNewName("");
  };
  return (
    <div className="space-y-4">
      {!hostOnline && (
        <p role="alert" className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-sm">
          Agent 离线，Xray 运行状态未知；全部客户端写操作已禁用。
        </p>
      )}
      <div className="flex flex-col gap-2 rounded-lg border border-border/60 p-3 sm:flex-row sm:items-end">
        <div className="min-w-0 flex-1 space-y-1.5">
          <Label htmlFor="xray-new-client">新客户端名称</Label>
          <Input id="xray-new-client" maxLength={128} value={newName} onChange={(event) => setNewName(event.target.value)} />
        </div>
        <Button
          type="button"
          disabled={writeDisabled || !newName.trim() || clients.filter((client) => !client.pendingDelete).length >= 32}
          onClick={create}
        >
          <Plus className="mr-2 h-4 w-4" />添加客户端
        </Button>
      </div>
      <div className="space-y-2">
        {clients.map((client) => {
          const clientWriteDisabled = writeDisabled || client.pendingDelete;
          return (
            <article key={client.id} className="rounded-lg border border-border/60 p-3">
              <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <h4 className="font-medium">{client.name}</h4>
                    <Badge variant={client.pendingDelete ? "destructive" : client.isEnabled ? "default" : "secondary"}>
                      {client.pendingDelete ? "待删除" : client.isEnabled ? "已启用" : "已停用"}
                    </Badge>
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">
                    UUID：{client.credentials.uuidConfigured ? "已配置（隐藏）" : "未配置"} · shortId：{client.credentials.shortIdConfigured ? "已配置（隐藏）" : "未配置"}
                  </p>
                  <p className="mt-1 font-mono text-xs text-muted-foreground">{client.flow || "无 Flow"}</p>
                  {client.pendingDelete && <p className="mt-2 text-xs text-destructive">应用完成前旧链接可能继续有效。</p>}
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button type="button" size="sm" variant="outline" onClick={(event) => onShare(client, event.currentTarget)}>
                    <Link2 className="mr-1 h-3.5 w-3.5" />分享 / QR
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    disabled={clientWriteDisabled}
                    onClick={() => { setEditing(client); setEditName(client.name); }}
                  >
                    <Pencil className="mr-1 h-3.5 w-3.5" />改名
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    disabled={clientWriteDisabled}
                    onClick={() => onUpdate(client, { isEnabled: !client.isEnabled })}
                  >
                    <Power className="mr-1 h-3.5 w-3.5" />{client.isEnabled ? "停用" : "启用"}
                  </Button>
                  <Button type="button" size="sm" variant="destructive" disabled={clientWriteDisabled} onClick={() => setRemoving(client)}>
                    <Trash2 className="mr-1 h-3.5 w-3.5" />删除
                  </Button>
                </div>
              </div>
            </article>
          );
        })}
        {clients.length === 0 && (
          <p className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">暂无客户端。</p>
        )}
      </div>
      {editing && (
        <Dialog open onOpenChange={(open) => { if (!open) setEditing(null); }}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>修改客户端名称</DialogTitle>
              <DialogDescription>身份凭据保持不变。</DialogDescription>
            </DialogHeader>
            <div className="space-y-1.5">
              <Label htmlFor="xray-edit-client">客户端名称</Label>
              <Input id="xray-edit-client" maxLength={128} value={editName} onChange={(event) => setEditName(event.target.value)} />
            </div>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setEditing(null)}>取消</Button>
              <Button
                type="button"
                disabled={!editName.trim() || writeDisabled || editing.pendingDelete}
                onClick={() => { onUpdate(editing, { name: editName.trim() }); setEditing(null); }}
              >
                保存
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
      {removing && (
        <Dialog open onOpenChange={(open) => { if (!open) setRemoving(null); }}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>删除客户端“{removing.name}”</DialogTitle>
              <DialogDescription>将先标记待删除并下发新 generation；应用完成前旧链接可能继续有效。</DialogDescription>
            </DialogHeader>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setRemoving(null)}>取消</Button>
              <Button
                type="button"
                variant="destructive"
                disabled={writeDisabled || removing.pendingDelete}
                onClick={() => { onRemove(removing); setRemoving(null); }}
              >
                确认删除
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
}
