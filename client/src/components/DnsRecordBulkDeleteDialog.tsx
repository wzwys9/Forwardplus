import { useId, useState } from "react";
import { AlertTriangle, Loader2 } from "lucide-react";
import { trpc } from "@/lib/trpc";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { DnsRecordItem } from "./dnsRecordDraft";

export function DnsRecordBulkDeleteDialog({ zoneId, subdomain, fqdn, disabled, onClose, onConfirm, formatError }: {
  zoneId: number;
  subdomain: string;
  fqdn: string;
  disabled: boolean;
  onClose: () => void;
  onConfirm: (records: readonly DnsRecordItem[]) => void;
  formatError: (error: unknown, fallback: string) => string;
}) {
  const id = useId();
  const [confirmation, setConfirmation] = useState("");
  const preview = trpc.xray.dnsRecords.deletionPreview.useQuery({ zoneId, subdomain }, {
    retry: false, gcTime: 0, staleTime: 0, refetchOnMount: "always", refetchOnWindowFocus: false,
  });
  const data = preview.data;
  const ready = !disabled && !preview.isFetching && !preview.error && data?.zoneId === zoneId
    && data.subdomain === subdomain && data.fqdn === fqdn && data.records.length > 0;

  return <Dialog open onOpenChange={open => { if (!open) onClose(); }}>
    <DialogContent className="flex max-h-[92svh] w-[calc(100%-2rem)] max-w-lg flex-col gap-0 p-0 [&>button]:size-11"
      onInteractOutside={event => event.preventDefault()}>
      <DialogHeader className="shrink-0 border-b p-5 pr-14">
        <DialogTitle>删除全部解析</DialogTitle>
        <DialogDescription className="break-all">{fqdn}</DialogDescription>
      </DialogHeader>
      <form className="flex min-h-0 flex-1 flex-col" onSubmit={event => {
        event.preventDefault();
        if (ready && data && confirmation === fqdn) onConfirm(data.records);
      }}>
        <div className="min-h-0 space-y-4 overflow-y-auto overscroll-contain p-5">
          <p className="text-sm">只删除该子域名所有线路的 <strong>A、AAAA、CNAME</strong>，包含未显示的分页和被搜索隐藏的记录。TXT、MX、NS 等其他类型与其他子域名全部保留。</p>
          {preview.isFetching ? <p role="status" className="flex items-center gap-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />正在读取完整删除预览
          </p> : preview.error ? <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" /><AlertTitle>无法读取删除预览</AlertTitle>
            <AlertDescription>{formatError(preview.error, "暂时无法读取完整记录，请稍后重试。")}</AlertDescription>
            <Button className="mt-3 min-h-11" type="button" variant="outline" onClick={() => { setConfirmation(""); void preview.refetch(); }}>重新读取</Button>
          </Alert> : data && <div className="rounded-lg border bg-muted/20 p-4 text-sm">
            <p className="font-medium">将标记删除 {data.records.length} 条解析，保留 {data.preservedCount} 条其他类型记录。</p>
            <p className="mt-2 text-muted-foreground">{["A", "AAAA", "CNAME"].map(type => `${type}：${data.records.filter(record => record.recordType === type).length}`).join(" · ")}</p>
            {data.records.length === 0 && <p className="mt-2">没有可删除的 A、AAAA 或 CNAME 记录。</p>}
          </div>}
          <p className="text-sm text-muted-foreground">确认只会加入待保存清单；点击管理页的“保存”后才会实际删除。保存前可撤销，保存后无法自动恢复。</p>
          <div className="space-y-2">
            <Label htmlFor={id}>输入完整域名确认</Label>
            <Input id={id} className="min-h-11" value={confirmation} onChange={event => setConfirmation(event.target.value)}
              disabled={!ready} autoComplete="off" spellCheck={false} maxLength={253} placeholder={fqdn} />
          </div>
        </div>
        <DialogFooter className="shrink-0 gap-2 border-t p-4">
          <Button className="min-h-11" type="button" variant="outline" onClick={onClose}>取消</Button>
          <Button className="min-h-11" type="submit" variant="destructive" disabled={!ready || confirmation !== fqdn}>标记全部删除</Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>;
}
