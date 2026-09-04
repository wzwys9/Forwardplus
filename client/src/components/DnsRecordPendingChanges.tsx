import { Pencil, Undo2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { DnsRecordDraft } from "./dnsRecordDraft";

export function DnsRecordPendingChanges({ drafts, lines, locked, failedKey, onEdit, onUndo }: {
  drafts: readonly DnsRecordDraft[];
  lines: readonly { lineId: number; name: string }[];
  locked: boolean;
  failedKey?: string;
  onEdit: (draft: DnsRecordDraft) => void;
  onUndo: (key: string) => void;
}) {
  return <section className="space-y-3 rounded-lg border bg-muted/15 p-4" aria-label="待保存的 DNS 变更">
    <h3 className="font-medium">待保存变更（{drafts.length}）</h3>
    <p className="text-sm text-muted-foreground">包括其他页暂存的修改。未点击保存前不会写入 DNSPod；保存依次执行，失败时停止，已成功的项目不会自动回滚。</p>
    {!drafts.length ? <p className="text-sm text-muted-foreground">暂无修改。使用记录右侧的编辑、删除按钮，或添加解析。</p> : <ul className="space-y-2">
      {drafts.map(draft => <li key={draft.key} className="space-y-2 rounded-lg border bg-background p-3 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant={draft.deleted ? "destructive" : "secondary"}>{draft.deleted ? "待删除" : draft.original ? "待修改" : "待新增"}</Badge>
          {failedKey === draft.key && <Badge variant="destructive">本条未确认成功</Badge>}
          <span className="break-all font-medium">{draft.values.subdomain}</span>
          <Badge variant="outline">{draft.values.recordType}</Badge>
          <span className="text-muted-foreground">{lines.find(line => line.lineId === draft.values.lineId)?.name ?? draft.original?.lineName ?? "线路不可用"} · TTL {draft.values.ttl}</span>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="min-w-0 break-all font-mono text-xs">{draft.values.value}</span>
          <div className="flex shrink-0 gap-2">
            {!draft.deleted && <Button type="button" size="sm" variant="outline" disabled={locked} onClick={() => onEdit(draft)}><Pencil className="mr-1 h-3 w-3" />继续编辑</Button>}
            <Button type="button" size="sm" variant="outline" disabled={locked} onClick={() => onUndo(draft.key)}><Undo2 className="mr-1 h-3 w-3" />撤销</Button>
          </div>
        </div>
      </li>)}
    </ul>}
  </section>;
}
