import { useEffect, useId, useMemo, useState, type FormEvent } from "react";
import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Database,
  Loader2,
  Pencil,
  Plus,
  RefreshCw,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";

import { trpc } from "@/lib/trpc";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

const RECORD_TYPES = ["A", "AAAA", "CNAME"] as const;
type RecordType = typeof RECORD_TYPES[number];

export type DnsRecordManagementZone = Readonly<{
  zoneId: number;
  name: string;
  status: "AVAILABLE" | "STALE" | "REMOVED" | "ERROR";
  inUse: boolean;
  quickConfigReferenceCount: number;
  managedRecordCount: number;
  activeOperationCount: number;
  lines: ReadonlyArray<{
    lineId: number;
    providerLineId: string;
    name: string;
    status: "AVAILABLE" | "STALE" | "REMOVED" | "ERROR";
  }>;
}>;

type RecordItem = Readonly<{
  providerRecordId: string;
  subdomain: string;
  fqdn: string;
  recordType: string;
  providerLineId: string;
  lineName: string;
  value: string;
  ttl: number;
  status: string | null;
  recordRevision: string;
}>;

type EditorState = Readonly<{
  mode: "create" | "update";
  record: RecordItem | null;
  subdomain: string;
  recordType: RecordType;
  lineId: string;
  value: string;
  ttl: string;
}>;

const DNS_ERROR_MESSAGES: Record<string, string> = {
  DNS_PROVIDER_NOT_CONFIGURED: "尚未配置 DNSPod 账号。",
  DNS_PROVIDER_VALIDATION_STALE: "DNSPod 账号验证已过期，请先重新验证。",
  DNS_PROVIDER_CATALOG_STALE: "域名或线路目录已过期，请先刷新目录。",
  DNS_PROVIDER_INVALID: "DNS 记录参数不正确，请检查后重试。",
  DNS_PROVIDER_UNAVAILABLE: "DNSPod 暂时不可用，请稍后刷新。",
  DNS_PROVIDER_REQUEST_REJECTED: "DNSPod 拒绝了本次请求，请检查记录内容。",
  DNS_PROVIDER_INVALID_RESPONSE: "DNSPod 返回了无法验证的响应。",
  DNS_ZONE_NOT_FOUND: "所选域名已不在当前账号中，请刷新目录。",
  DNS_ZONE_IN_USE: "该域名正在被快速配置使用，只允许查看。",
  DNS_RECORD_NOT_FOUND: "该记录已不存在，请刷新列表。",
  DNS_RECORD_CHANGED: "该记录已在其他位置发生变化，请刷新后再操作。",
  DNS_WRITE_UNCERTAIN: "DNSPod 写入结果暂时无法确认，请先刷新列表，不要重复提交。",
  SENSITIVE_DATA_UNAVAILABLE: "DNSPod 凭据暂时不可用，请重新验证账号。",
};

function dnsErrorMessage(error: unknown, fallback: string) {
  if (!error || typeof error !== "object") return fallback;
  const candidate = error as { message?: unknown; data?: { xrayCode?: unknown } };
  for (const value of [candidate.data?.xrayCode, candidate.message]) {
    if (typeof value === "string" && DNS_ERROR_MESSAGES[value]) return DNS_ERROR_MESSAGES[value];
  }
  return fallback;
}

function writableRecordType(value: string): value is RecordType {
  return (RECORD_TYPES as readonly string[]).includes(value);
}

function emptyEditor(zone: DnsRecordManagementZone): EditorState {
  const defaultLine = zone.lines.find((line) => line.status === "AVAILABLE" && line.name === "默认")
    ?? zone.lines.find((line) => line.status === "AVAILABLE");
  return {
    mode: "create",
    record: null,
    subdomain: "",
    recordType: "A",
    lineId: defaultLine ? String(defaultLine.lineId) : "",
    value: "",
    ttl: "600",
  };
}

function recordEditor(record: RecordItem, zone: DnsRecordManagementZone): EditorState {
  const line = zone.lines.find((item) => (
    item.status === "AVAILABLE" && item.providerLineId === record.providerLineId
  ));
  return {
    mode: "update",
    record,
    subdomain: record.subdomain,
    recordType: writableRecordType(record.recordType) ? record.recordType : "A",
    lineId: line ? String(line.lineId) : "",
    value: record.value,
    ttl: String(record.ttl),
  };
}

function RecordEditorDialog({
  state,
  zone,
  pending,
  onChange,
  onClose,
  onSubmit,
}: {
  state: EditorState | null;
  zone: DnsRecordManagementZone;
  pending: boolean;
  onChange: (state: EditorState) => void;
  onClose: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}) {
  const id = useId();
  if (!state) return null;
  const availableLines = zone.lines.filter((line) => line.status === "AVAILABLE");
  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent className="flex max-h-[92svh] max-w-xl flex-col gap-0 p-0">
        <DialogHeader className="shrink-0 border-b p-5 pr-12 sm:p-6 sm:pr-12">
          <DialogTitle>{state.mode === "create" ? "添加 DNS 记录" : "编辑 DNS 记录"}</DialogTitle>
          <DialogDescription>{zone.name} · 支持 A、AAAA 和 CNAME</DialogDescription>
        </DialogHeader>
        <form className="flex min-h-0 flex-1 flex-col" onSubmit={onSubmit}>
          <div className="grid min-h-0 flex-1 gap-4 overflow-y-auto overscroll-contain p-5 sm:grid-cols-2 sm:p-6">
            <div className="space-y-2">
              <Label htmlFor={`${id}-subdomain`}>主机记录</Label>
              <Input
                id={`${id}-subdomain`}
                value={state.subdomain}
                onChange={(event) => onChange({ ...state, subdomain: event.target.value })}
                placeholder="例如 www，根域名填写 @"
                maxLength={253}
                spellCheck={false}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${id}-type`}>记录类型</Label>
              <Select value={state.recordType} onValueChange={(recordType: RecordType) => onChange({ ...state, recordType })}>
                <SelectTrigger id={`${id}-type`}><SelectValue /></SelectTrigger>
                <SelectContent>
                  {RECORD_TYPES.map((type) => <SelectItem key={type} value={type}>{type}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2 sm:col-span-2">
              <Label htmlFor={`${id}-line`}>解析线路</Label>
              <Select value={state.lineId} onValueChange={(lineId) => onChange({ ...state, lineId })}>
                <SelectTrigger id={`${id}-line`}><SelectValue placeholder="选择当前域名可用线路" /></SelectTrigger>
                <SelectContent>
                  {availableLines.map((line) => (
                    <SelectItem key={line.lineId} value={String(line.lineId)}>{line.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {!state.lineId && state.mode === "update" && (
                <p className="text-xs text-amber-700 dark:text-amber-300">原线路已不在当前目录中，请重新选择。</p>
              )}
            </div>
            <div className="space-y-2 sm:col-span-2">
              <Label htmlFor={`${id}-value`}>记录值</Label>
              <Input
                id={`${id}-value`}
                value={state.value}
                onChange={(event) => onChange({ ...state, value: event.target.value })}
                placeholder={state.recordType === "A" ? "例如 203.0.113.10" : state.recordType === "AAAA" ? "例如 2001:db8::10" : "例如 origin.example.com"}
                maxLength={2048}
                spellCheck={false}
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${id}-ttl`}>TTL（秒）</Label>
              <Input
                id={`${id}-ttl`}
                type="number"
                min={1}
                max={604800}
                value={state.ttl}
                onChange={(event) => onChange({ ...state, ttl: event.target.value })}
                required
              />
            </div>
          </div>
          <DialogFooter className="shrink-0 gap-2 border-t p-4 sm:p-5">
            <Button type="button" variant="outline" onClick={onClose}>取消</Button>
            <Button type="submit" disabled={pending || !state.lineId}>
              {pending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {state.mode === "create" ? "添加记录" : "保存修改"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export default function DnsRecordManagementCard({
  zones,
  accountValid,
}: {
  zones: readonly DnsRecordManagementZone[];
  accountValid: boolean;
}) {
  const availableZones = useMemo(() => zones.filter((zone) => zone.status === "AVAILABLE"), [zones]);
  const [selectedZoneId, setSelectedZoneId] = useState<number | null>(availableZones[0]?.zoneId ?? null);
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [editor, setEditor] = useState<EditorState | null>(null);
  const [removing, setRemoving] = useState<RecordItem | null>(null);
  const selectedZone = availableZones.find((zone) => zone.zoneId === selectedZoneId) ?? availableZones[0] ?? null;

  useEffect(() => {
    if (selectedZoneId !== null && availableZones.some((zone) => zone.zoneId === selectedZoneId)) return;
    setSelectedZoneId(availableZones[0]?.zoneId ?? null);
  }, [availableZones, selectedZoneId]);

  const recordsQuery = trpc.xray.dnsRecords.list.useQuery({
    zoneId: selectedZone?.zoneId ?? 1,
    search: search || undefined,
    page,
    pageSize: 20,
  }, {
    enabled: accountValid && selectedZone !== null,
    retry: false,
    refetchOnWindowFocus: false,
  });
  const createMutation = trpc.xray.dnsRecords.create.useMutation({ gcTime: 0 });
  const updateMutation = trpc.xray.dnsRecords.update.useMutation({ gcTime: 0 });
  const removeMutation = trpc.xray.dnsRecords.remove.useMutation({ gcTime: 0 });
  const currentZoneInUse = recordsQuery.data?.zone.inUse ?? selectedZone?.inUse ?? false;
  const totalPages = Math.max(1, Math.ceil((recordsQuery.data?.total ?? 0) / 20));
  const mutationPending = createMutation.isPending || updateMutation.isPending;

  useEffect(() => {
    if (page > totalPages) setPage(totalPages);
  }, [page, totalPages]);

  const chooseZone = (value: string) => {
    setSelectedZoneId(Number(value));
    setPage(1);
    setSearchInput("");
    setSearch("");
    setEditor(null);
    setRemoving(null);
  };

  const submitSearch = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setPage(1);
    setSearch(searchInput.trim());
  };

  const submitEditor = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!selectedZone || !editor || currentZoneInUse || !editor.lineId) return;
    const payload = {
      zoneId: selectedZone.zoneId,
      subdomain: editor.subdomain.trim(),
      recordType: editor.recordType,
      lineId: Number(editor.lineId),
      value: editor.value.trim(),
      ttl: Number(editor.ttl),
    };
    try {
      if (editor.mode === "create") {
        await createMutation.mutateAsync(payload);
        toast.success("DNS 记录已添加");
      } else if (editor.record) {
        await updateMutation.mutateAsync({
          ...payload,
          providerRecordId: editor.record.providerRecordId,
          expectedRecordRevision: editor.record.recordRevision,
        });
        toast.success("DNS 记录已更新");
      }
      setEditor(null);
      await recordsQuery.refetch();
    } catch (error) {
      toast.error(dnsErrorMessage(error, "DNS 记录操作失败，请稍后重试。"));
    } finally {
      createMutation.reset();
      updateMutation.reset();
    }
  };

  const confirmRemove = async () => {
    if (!selectedZone || !removing || currentZoneInUse) return;
    try {
      await removeMutation.mutateAsync({
        zoneId: selectedZone.zoneId,
        providerRecordId: removing.providerRecordId,
        expectedRecordRevision: removing.recordRevision,
      });
      setRemoving(null);
      toast.success("DNS 记录已删除");
      await recordsQuery.refetch();
    } catch (error) {
      toast.error(dnsErrorMessage(error, "DNS 记录删除失败，请稍后重试。"));
    } finally {
      removeMutation.reset();
    }
  };

  if (!accountValid) return null;

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
          <div className="flex items-start gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
              <Database className="h-5 w-5" />
            </div>
            <div>
              <CardTitle>DNS 管理</CardTitle>
              <CardDescription className="mt-1.5">实时读取 DNSPod 记录，管理 A、AAAA 和 CNAME。</CardDescription>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" onClick={() => recordsQuery.refetch()} disabled={!selectedZone || recordsQuery.isFetching}>
              {recordsQuery.isFetching ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
              刷新记录
            </Button>
            <Button
              type="button"
              onClick={() => selectedZone && setEditor(emptyEditor(selectedZone))}
              disabled={!selectedZone || currentZoneInUse}
              title={currentZoneInUse ? "该域名正在被快速配置使用" : undefined}
            >
              <Plus className="mr-2 h-4 w-4" />
              添加记录
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-5">
        {availableZones.length === 0 ? (
          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>没有可管理域名</AlertTitle>
            <AlertDescription>请先刷新 DNSPod 域名目录。</AlertDescription>
          </Alert>
        ) : (
          <>
            <div className="grid gap-3 lg:grid-cols-[minmax(14rem,24rem)_1fr] lg:items-end">
              <div className="space-y-2">
                <Label htmlFor="dns-record-zone">域名</Label>
                <Select value={selectedZone ? String(selectedZone.zoneId) : undefined} onValueChange={chooseZone}>
                  <SelectTrigger id="dns-record-zone"><SelectValue placeholder="选择域名" /></SelectTrigger>
                  <SelectContent>
                    {availableZones.map((zone) => <SelectItem key={zone.zoneId} value={String(zone.zoneId)}>{zone.name}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <form className="flex gap-2" onSubmit={submitSearch} role="search">
                <div className="min-w-0 flex-1 space-y-2">
                  <Label htmlFor="dns-record-search">搜索记录</Label>
                  <Input
                    id="dns-record-search"
                    value={searchInput}
                    onChange={(event) => setSearchInput(event.target.value)}
                    placeholder="主机记录、类型、线路或记录值"
                    maxLength={128}
                  />
                </div>
                <Button type="submit" variant="outline" className="mt-7">搜索</Button>
              </form>
            </div>

            {currentZoneInUse && recordsQuery.data?.zone && (
              <Alert>
                <ShieldCheck className="h-4 w-4" />
                <AlertTitle>该域名正在使用，当前只读</AlertTitle>
                <AlertDescription>
                  {recordsQuery.data.zone.quickConfigReferenceCount} 个快速配置、
                  {recordsQuery.data.zone.managedRecordCount} 条托管记录、
                  {recordsQuery.data.zone.activeOperationCount} 个执行中任务正在引用此域名。
                  请通过对应快速配置修改或删除，避免解析与转发拓扑失去一致性。
                </AlertDescription>
              </Alert>
            )}

            {recordsQuery.isLoading ? (
              <div className="flex min-h-40 items-center justify-center rounded-lg border text-sm text-muted-foreground">
                <Loader2 className="mr-2 h-4 w-4 animate-spin text-primary" />
                正在读取 DNSPod 记录
              </div>
            ) : recordsQuery.error ? (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>DNS 记录加载失败</AlertTitle>
                <AlertDescription className="flex flex-wrap items-center justify-between gap-3">
                  <span>{dnsErrorMessage(recordsQuery.error, "暂时无法读取 DNSPod 记录。")}</span>
                  <Button type="button" size="sm" variant="outline" onClick={() => recordsQuery.refetch()}>重新加载</Button>
                </AlertDescription>
              </Alert>
            ) : (recordsQuery.data?.items.length ?? 0) === 0 ? (
              <div className="rounded-lg border border-dashed px-6 py-12 text-center">
                <p className="font-medium">{search ? "没有匹配的 DNS 记录" : "当前域名没有 DNS 记录"}</p>
                <p className="mt-1 text-sm text-muted-foreground">{search ? "可以更换关键词后重新搜索。" : "未被快速配置占用时，可以添加第一条记录。"}</p>
              </div>
            ) : (
              <div className="rounded-lg border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>主机记录</TableHead>
                      <TableHead>类型</TableHead>
                      <TableHead>线路</TableHead>
                      <TableHead>记录值</TableHead>
                      <TableHead>TTL</TableHead>
                      <TableHead>状态</TableHead>
                      <TableHead className="text-right">操作</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {recordsQuery.data?.items.map((record) => {
                      const writable = writableRecordType(record.recordType) && !currentZoneInUse;
                      return (
                        <TableRow key={record.providerRecordId}>
                          <TableCell className="font-medium" title={record.fqdn}>{record.subdomain}</TableCell>
                          <TableCell><Badge variant="outline">{record.recordType}</Badge></TableCell>
                          <TableCell>{record.lineName}</TableCell>
                          <TableCell className="max-w-[22rem] truncate font-mono text-xs" title={record.value}>{record.value}</TableCell>
                          <TableCell>{record.ttl}</TableCell>
                          <TableCell>{record.status === "ENABLE" ? "启用" : record.status === "DISABLE" ? "停用" : record.status ?? "—"}</TableCell>
                          <TableCell>
                            <div className="flex justify-end gap-1">
                              <Button
                                type="button"
                                variant="ghost"
                                size="icon"
                                aria-label={`编辑 ${record.fqdn}`}
                                title={!writable ? currentZoneInUse ? "域名正在使用，当前只读" : "首版只编辑 A、AAAA 和 CNAME" : "编辑记录"}
                                disabled={!writable}
                                onClick={() => selectedZone && setEditor(recordEditor(record, selectedZone))}
                              >
                                <Pencil className="h-4 w-4" />
                              </Button>
                              <Button
                                type="button"
                                variant="ghost"
                                size="icon"
                                className="text-destructive hover:text-destructive"
                                aria-label={`删除 ${record.fqdn}`}
                                title={!writable ? currentZoneInUse ? "域名正在使用，当前只读" : "首版只删除 A、AAAA 和 CNAME" : "删除记录"}
                                disabled={!writable}
                                onClick={() => setRemoving(record)}
                              >
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>
            )}

            {recordsQuery.data && recordsQuery.data.total > 0 && (
              <div className="flex flex-col gap-3 text-sm text-muted-foreground sm:flex-row sm:items-center sm:justify-between">
                <span>共 {recordsQuery.data.total} 条 · 第 {recordsQuery.data.page} / {totalPages} 页</span>
                <div className="flex gap-2">
                  <Button type="button" size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>
                    <ChevronLeft className="mr-1 h-4 w-4" />上一页
                  </Button>
                  <Button type="button" size="sm" variant="outline" disabled={page >= totalPages} onClick={() => setPage((value) => Math.min(totalPages, value + 1))}>
                    下一页<ChevronRight className="ml-1 h-4 w-4" />
                  </Button>
                </div>
              </div>
            )}
          </>
        )}
      </CardContent>

      {selectedZone && (
        <RecordEditorDialog
          state={editor}
          zone={selectedZone}
          pending={mutationPending}
          onChange={setEditor}
          onClose={() => setEditor(null)}
          onSubmit={submitEditor}
        />
      )}

      <Dialog open={removing !== null} onOpenChange={(open) => { if (!open) setRemoving(null); }}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>删除 DNS 记录</DialogTitle>
            <DialogDescription>此操作会直接删除 DNSPod 中的记录，无法由面板自动恢复。</DialogDescription>
          </DialogHeader>
          {removing && (
            <div className="rounded-lg border bg-muted/20 p-4 text-sm">
              <p className="font-medium">{removing.fqdn}</p>
              <p className="mt-1 break-all text-muted-foreground">{removing.recordType} · {removing.lineName} · {removing.value}</p>
            </div>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setRemoving(null)}>取消</Button>
            <Button type="button" variant="destructive" onClick={confirmRemove} disabled={removeMutation.isPending || currentZoneInUse}>
              {removeMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              确认删除
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
