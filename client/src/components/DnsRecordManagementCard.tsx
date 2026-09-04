import { useEffect, useId, useMemo, useRef, useState, type FormEvent } from "react";
import {
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
  Database,
  Loader2,
  Pencil,
  Plus,
  RefreshCw,
  Save,
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
import { saveDnsRecordDrafts, stageDnsRecordDraft, type DnsRecordDraft, type DnsRecordItem as RecordItem } from "./dnsRecordDraft";
import { DnsRecordPendingChanges } from "./DnsRecordPendingChanges";

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

type EditorState = Readonly<{
  mode: "create" | "update";
  record: RecordItem | null;
  subdomain: string;
  recordType: RecordType;
  lineId: string;
  value: string;
  ttl: string;
  draftKey?: string;
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
  DNS_SUBDOMAIN_IN_USE: "该子域名正在被系统使用，请通过对应快速配置调整解析。",
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
  staging,
  onChange,
  onClose,
  onSubmit,
}: {
  state: EditorState | null;
  zone: DnsRecordManagementZone;
  pending: boolean;
  staging: boolean;
  onChange: (state: EditorState) => void;
  onClose: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}) {
  const id = useId();
  if (!state) return null;
  const availableLines = zone.lines.filter((line) => line.status === "AVAILABLE");
  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent className="flex max-h-[92svh] max-w-xl flex-col gap-0 p-0" onInteractOutside={event => event.preventDefault()}>
        <DialogHeader className="shrink-0 border-b p-5 pr-12 sm:p-6 sm:pr-12">
          <DialogTitle>{state.mode === "create" ? "添加 DNS 记录" : "编辑 DNS 记录"}</DialogTitle>
          <DialogDescription>{zone.name} · 支持 A、AAAA 和 CNAME{staging && " · 此处仅暂存，点击管理页的保存后才生效"}</DialogDescription>
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
              {staging ? "暂存修改" : "添加记录"}
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
  const [subdomain, setSubdomain] = useState<string | null>(null);
  const [editor, setEditor] = useState<EditorState | null>(null);
  const [removing, setRemoving] = useState<RecordItem | null>(null);
  const [editing, setEditing] = useState(false);
  const [drafts, setDrafts] = useState<DnsRecordDraft[]>([]);
  const [saving, setSaving] = useState(false);
  const savingRef = useRef(false);
  const draftSequenceRef = useRef(0);
  const [saveFailure, setSaveFailure] = useState<{ message: string; failedKey: string; completed: number } | null>(null);
  const [discardOpen, setDiscardOpen] = useState(false);
  const selectedZone = editing ? zones.find(zone => zone.zoneId === selectedZoneId) ?? null
    : availableZones.find((zone) => zone.zoneId === selectedZoneId) ?? availableZones[0] ?? null;
  const utils = trpc.useUtils();

  useEffect(() => {
    if (editing) return;
    if (selectedZoneId !== null && availableZones.some((zone) => zone.zoneId === selectedZoneId)) return;
    setSelectedZoneId(availableZones[0]?.zoneId ?? null);
    setSubdomain(null);
    setEditor(null);
    setRemoving(null);
    setEditing(false);
    setDrafts([]);
    setSaveFailure(null);
    setPage(1);
  }, [availableZones, selectedZoneId, editing]);

  const groupsQuery = trpc.xray.dnsRecords.groups.useQuery({
    zoneId: selectedZone?.zoneId ?? 1, search: search || undefined, page, pageSize: 20,
  }, {
    enabled: accountValid && selectedZone !== null && subdomain === null,
    retry: false, refetchOnWindowFocus: false,
  });
  const recordsQuery = trpc.xray.dnsRecords.list.useQuery({
    zoneId: selectedZone?.zoneId ?? 1,
    subdomain: subdomain ?? undefined,
    search: search || undefined,
    page,
    pageSize: 20,
  }, {
    enabled: accountValid && selectedZone !== null && subdomain !== null,
    retry: false,
    refetchOnWindowFocus: false,
  });
  const createMutation = trpc.xray.dnsRecords.create.useMutation({ gcTime: 0, retry: false });
  const updateMutation = trpc.xray.dnsRecords.update.useMutation({ gcTime: 0, retry: false });
  const removeMutation = trpc.xray.dnsRecords.remove.useMutation({ gcTime: 0, retry: false });
  const currentSubdomainInUse = subdomain !== null && (recordsQuery.data?.subdomain?.inUse ?? true);
  const activeQuery = subdomain === null ? groupsQuery : recordsQuery;
  const totalPages = Math.max(1, Math.ceil((activeQuery.data?.total ?? 0) / 20));
  const mutationPending = saving || createMutation.isPending || updateMutation.isPending || removeMutation.isPending;
  const draftLocked = mutationPending || !!saveFailure || currentSubdomainInUse || !selectedZone || selectedZone.status !== "AVAILABLE" || !accountValid;

  useEffect(() => {
    if (!drafts.length && !saving) return;
    const preventLeave = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ""; };
    window.addEventListener("beforeunload", preventLeave);
    return () => window.removeEventListener("beforeunload", preventLeave);
  }, [drafts.length, saving]);

  useEffect(() => {
    if (activeQuery.data && page > totalPages) setPage(totalPages);
  }, [activeQuery.data, page, totalPages]);

  const openSubdomain = (name: string | null) => {
    if (editing || savingRef.current) return;
    setSubdomain(name);
    setPage(1);
    setSearchInput("");
    setSearch("");
    setEditor(null);
    setRemoving(null);
  };

  const refreshRecords = async () => {
    await Promise.all([utils.xray.dnsRecords.groups.invalidate(), utils.xray.dnsRecords.list.invalidate()]);
  };

  const chooseZone = (value: string) => {
    if (editing || savingRef.current) return;
    setSelectedZoneId(Number(value));
    setSubdomain(null);
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
    if (!selectedZone || !editor || currentSubdomainInUse || !editor.lineId || mutationPending) return;
    const payload = {
      zoneId: selectedZone.zoneId,
      subdomain: editor.subdomain.trim(),
      recordType: editor.recordType,
      lineId: Number(editor.lineId),
      value: editor.value.trim(),
      ttl: Number(editor.ttl),
    };
    if (subdomain !== null) {
      if (!editing || draftLocked) return;
      const { zoneId: _zoneId, ...values } = payload;
      const key = editor.draftKey ?? editor.record?.providerRecordId ?? `new:${++draftSequenceRef.current}`;
      setDrafts(current => stageDnsRecordDraft(current, {
        key,
        original: editor.record, values, deleted: false,
      }, selectedZone.lines));
      setEditor(null);
      return;
    }
    try {
      if (editor.mode !== "create") return;
      await createMutation.mutateAsync(payload);
      toast.success("DNS 记录已添加");
      openSubdomain(payload.subdomain.toLowerCase());
      await refreshRecords();
    } catch (error) {
      toast.error(dnsErrorMessage(error, "DNS 记录操作失败，请稍后重试。"));
    } finally {
      createMutation.reset();
      updateMutation.reset();
    }
  };

  const confirmRemove = async () => {
    if (!selectedZone || !removing || !editing || draftLocked || removing.inUse) return;
    const fields = recordEditor(removing, selectedZone);
    setDrafts(current => stageDnsRecordDraft(current, {
      key: removing.providerRecordId, original: removing, deleted: true,
      values: { subdomain: fields.subdomain, recordType: fields.recordType, lineId: Number(fields.lineId), value: fields.value, ttl: Number(fields.ttl) },
    }, selectedZone.lines));
    setRemoving(null);
  };

  const editDraft = (draft: DnsRecordDraft) => {
    if (!selectedZone || draftLocked) return;
    setEditor({ mode: draft.original ? "update" : "create", record: draft.original, draftKey: draft.key,
      ...draft.values, lineId: String(draft.values.lineId), ttl: String(draft.values.ttl) });
  };

  const endEditing = () => {
    if (savingRef.current) return;
    setEditing(false); setDrafts([]); setSaveFailure(null); setDiscardOpen(false); setEditor(null); setRemoving(null);
    void refreshRecords().catch(() => toast.error("刷新失败，请重新读取 DNS 记录。"));
  };

  const saveChanges = async () => {
    if (!selectedZone || !editing || draftLocked || !drafts.length || savingRef.current) return;
    savingRef.current = true;
    setSaving(true);
    let completed = 0;
    try {
      const result = await saveDnsRecordDrafts(drafts, selectedZone.zoneId, {
        create: input => createMutation.mutateAsync(input), update: input => updateMutation.mutateAsync(input), remove: input => removeMutation.mutateAsync(input),
      }, key => { completed += 1; setDrafts(current => current.filter(draft => draft.key !== key)); });
      if (result.status === "FAILED") {
        setSaveFailure({ message: dnsErrorMessage(result.error, "保存未完成，请核对远端记录后重新编辑。"), failedKey: result.failedKey, completed });
      } else {
        setEditing(false);
        toast.success(`已保存 ${completed} 条 DNS 变更`);
      }
      await refreshRecords();
    } finally {
      savingRef.current = false; setSaving(false);
      createMutation.reset(); updateMutation.reset(); removeMutation.reset();
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
              <CardDescription className="mt-1.5">按子域名查看解析，点击编辑后统一调整 A、AAAA 和 CNAME，保存才生效。</CardDescription>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button type="button" variant="outline" onClick={() => activeQuery.refetch()} disabled={!selectedZone || activeQuery.isFetching || editing || mutationPending}>
              {activeQuery.isFetching ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}
              刷新记录
            </Button>
            {(subdomain === null || editing) && <Button
              type="button"
              onClick={() => selectedZone && setEditor({ ...emptyEditor(selectedZone), subdomain: subdomain ?? "" })}
              disabled={!selectedZone || currentSubdomainInUse || mutationPending || !!saveFailure}
              title={currentSubdomainInUse ? "该子域名正在被系统使用" : undefined}
            >
              <Plus className="mr-2 h-4 w-4" />
              {subdomain === null ? "添加子域名" : "添加解析"}
            </Button>}
            {subdomain !== null && !editing && <Button type="button" onClick={() => setEditing(true)} disabled={currentSubdomainInUse || recordsQuery.isFetching || !!recordsQuery.error || mutationPending}>
              <Pencil className="mr-2 h-4 w-4" />编辑
            </Button>}
            {editing && <>
              <Button type="button" variant="outline" disabled={mutationPending} onClick={() => drafts.length || saveFailure ? setDiscardOpen(true) : endEditing()}>{saveFailure ? "结束编辑并刷新" : "取消编辑"}</Button>
              <Button type="button" onClick={saveChanges} disabled={draftLocked || !drafts.length || editor !== null || removing !== null}>
                {saving ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Save className="mr-2 h-4 w-4" />}保存{drafts.length > 0 ? `（${drafts.length}）` : ""}
              </Button>
            </>}
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
                <Select value={selectedZone ? String(selectedZone.zoneId) : undefined} disabled={mutationPending || editing} onValueChange={chooseZone}>
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
                    disabled={mutationPending}
                    value={searchInput}
                    onChange={(event) => setSearchInput(event.target.value)}
                    placeholder="主机记录、类型、线路或记录值"
                    maxLength={128}
                  />
                </div>
                <Button type="submit" variant="outline" className="mt-7" disabled={mutationPending}>搜索</Button>
              </form>
            </div>

            {subdomain !== null && (
              <div className="flex flex-wrap items-center gap-3 rounded-lg border bg-muted/15 p-3">
                <Button type="button" variant="outline" size="sm" disabled={mutationPending || editing} onClick={() => openSubdomain(null)}><ChevronLeft className="mr-1 h-4 w-4" />返回子域名列表</Button>
                <span className="min-w-0 break-all font-medium">{subdomain === "@" ? selectedZone?.name : `${subdomain}.${selectedZone?.name}`}</span>
              </div>
            )}

            {subdomain !== null && recordsQuery.data?.subdomain?.inUse && (
              <Alert>
                <ShieldCheck className="h-4 w-4" />
                <AlertTitle>该子域名正在使用，当前只读</AlertTitle>
                <AlertDescription>
                  请通过对应快速配置调整解析。执行中的域名切换和未清理记录也会保持保护；同主域名下其他未占用的子域名可以正常管理。
                </AlertDescription>
              </Alert>
            )}

            {saveFailure && <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>保存未完全成功</AlertTitle><AlertDescription>
              已确认保存 {saveFailure.completed} 条，剩余 {drafts.length} 条未确认或未执行。{saveFailure.message} 当前草稿已保留，不能直接再次保存；请先结束编辑并刷新、核对实际解析后重新编辑。已成功的变更不会被取消或回滚。
            </AlertDescription></Alert>}
            {editing && selectedZone && <DnsRecordPendingChanges drafts={drafts} lines={selectedZone.lines} locked={draftLocked} failedKey={saveFailure?.failedKey}
              onEdit={editDraft} onUndo={key => setDrafts(current => current.filter(draft => draft.key !== key))} />}

            {activeQuery.isLoading ? (
              <div className="flex min-h-40 items-center justify-center rounded-lg border text-sm text-muted-foreground">
                <Loader2 className="mr-2 h-4 w-4 animate-spin text-primary" />
                正在读取 DNSPod 记录
              </div>
            ) : activeQuery.error ? (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertTitle>DNS 记录加载失败</AlertTitle>
                <AlertDescription className="flex flex-wrap items-center justify-between gap-3">
                  <span>{dnsErrorMessage(activeQuery.error, "暂时无法读取 DNSPod 记录。")}</span>
                  <Button type="button" size="sm" variant="outline" onClick={() => activeQuery.refetch()}>重新加载</Button>
                </AlertDescription>
              </Alert>
            ) : (activeQuery.data?.items.length ?? 0) === 0 ? (
              <div className="rounded-lg border border-dashed px-6 py-12 text-center">
                <p className="font-medium">{search ? "没有匹配的 DNS 记录" : "当前域名没有 DNS 记录"}</p>
                <p className="mt-1 text-sm text-muted-foreground">{search ? "可以更换关键词后重新搜索。" : currentSubdomainInUse ? "可通过快速配置的同步功能补齐缺失解析。" : "可以添加第一条记录。"}</p>
              </div>
            ) : subdomain === null ? (
              <div className="rounded-lg border">
                <Table>
                  <TableHeader><TableRow><TableHead>子域名</TableHead><TableHead>解析记录</TableHead><TableHead>使用状态</TableHead><TableHead className="text-right">操作</TableHead></TableRow></TableHeader>
                  <TableBody>{groupsQuery.data?.items.map((group) => (
                    <TableRow key={group.fqdn}>
                      <TableCell className="min-w-40 break-all font-medium">{group.fqdn}</TableCell>
                      <TableCell><span>{group.recordCount} 条</span><div className="mt-1 flex flex-wrap gap-1">{group.recordTypes.map((type) => <Badge key={type} variant="outline">{type}</Badge>)}</div></TableCell>
                      <TableCell><Badge variant={group.inUse ? "secondary" : "outline"}>{group.inUse ? "系统使用中 · 只读" : "可管理"}</Badge></TableCell>
                      <TableCell className="text-right"><Button type="button" variant="outline" size="sm" disabled={mutationPending || removeMutation.isPending} onClick={() => openSubdomain(group.subdomain)}>管理解析<ChevronRight className="ml-1 h-4 w-4" /></Button></TableCell>
                    </TableRow>
                  ))}</TableBody>
                </Table>
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
                      const draft = drafts.find(item => item.key === record.providerRecordId);
                      const writable = editing && writableRecordType(record.recordType) && !record.inUse && !draftLocked;
                      return (
                        <TableRow key={record.providerRecordId}>
                          <TableCell className="font-medium" title={record.fqdn}>{record.subdomain}</TableCell>
                          <TableCell><Badge variant="outline">{record.recordType}</Badge></TableCell>
                          <TableCell>{record.lineName}</TableCell>
                          <TableCell className="max-w-[22rem] truncate font-mono text-xs" title={record.value}>{record.value}</TableCell>
                          <TableCell>{record.ttl}</TableCell>
                          <TableCell>{record.status === "ENABLE" ? "启用" : record.status === "DISABLE" ? "停用" : record.status ?? "—"}{draft && <Badge className="ml-2" variant={draft.deleted ? "destructive" : "secondary"}>{draft.deleted ? "待删除" : "待修改"}</Badge>}</TableCell>
                          <TableCell>
                            {editing ? <div className="flex justify-end gap-1">
                              <Button
                                type="button"
                                variant="ghost"
                                size="icon"
                                aria-label={`编辑 ${record.fqdn}`}
                                title={!writable ? record.inUse ? "子域名正在使用，当前只读" : "只编辑 A、AAAA 和 CNAME" : "编辑记录"}
                                disabled={!writable || draft?.deleted}
                                onClick={() => draft ? editDraft(draft) : selectedZone && setEditor(recordEditor(record, selectedZone))}
                              >
                                <Pencil className="h-4 w-4" />
                              </Button>
                              <Button
                                type="button"
                                variant="ghost"
                                size="icon"
                                className="text-destructive hover:text-destructive"
                                aria-label={`删除 ${record.fqdn}`}
                                title={!writable ? record.inUse ? "子域名正在使用，当前只读" : "只删除 A、AAAA 和 CNAME" : "删除记录"}
                                disabled={!writable || draft?.deleted}
                                onClick={() => setRemoving(record)}
                              >
                                <Trash2 className="h-4 w-4" />
                              </Button>
                            </div> : <span className="block text-right text-xs text-muted-foreground">{record.inUse || !writableRecordType(record.recordType) ? "只读" : "点击上方编辑"}</span>}
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </div>
            )}

            {activeQuery.data && activeQuery.data.total > 0 && (
              <div className="flex flex-col gap-3 text-sm text-muted-foreground sm:flex-row sm:items-center sm:justify-between">
                <span>共 {activeQuery.data.total} {subdomain === null ? "个域名" : "条解析"} · 第 {activeQuery.data.page} / {totalPages} 页</span>
                <div className="flex gap-2">
                  <Button type="button" size="sm" variant="outline" disabled={mutationPending || page <= 1} onClick={() => setPage((value) => Math.max(1, value - 1))}>
                    <ChevronLeft className="mr-1 h-4 w-4" />上一页
                  </Button>
                  <Button type="button" size="sm" variant="outline" disabled={mutationPending || page >= totalPages} onClick={() => setPage((value) => Math.min(totalPages, value + 1))}>
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
          staging={editing}
          onChange={setEditor}
          onClose={() => { if (!mutationPending) setEditor(null); }}
          onSubmit={submitEditor}
        />
      )}

      <Dialog open={removing !== null} onOpenChange={(open) => { if (!open) setRemoving(null); }}>
        <DialogContent className="max-w-md" onInteractOutside={event => event.preventDefault()}>
          <DialogHeader>
            <DialogTitle>标记删除 DNS 记录</DialogTitle>
            <DialogDescription>现在只标记为待删除，可撤销。点击管理页的“保存”后才会从 DNSPod 删除，删除后无法自动恢复。</DialogDescription>
          </DialogHeader>
          {removing && (
            <div className="rounded-lg border bg-muted/20 p-4 text-sm">
              <p className="font-medium">{removing.fqdn}</p>
              <p className="mt-1 break-all text-muted-foreground">{removing.recordType} · {removing.lineName} · {removing.value}</p>
            </div>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => setRemoving(null)}>取消</Button>
            <Button type="button" variant="destructive" onClick={confirmRemove} disabled={draftLocked || removing?.inUse}>
              标记删除
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog open={discardOpen} onOpenChange={setDiscardOpen}>
        <DialogContent className="max-w-md" onInteractOutside={event => event.preventDefault()}>
          <DialogHeader><DialogTitle>{saveFailure ? "结束本次编辑？" : "放弃未保存的修改？"}</DialogTitle>
            <DialogDescription>{saveFailure ? "将丢弃尚未确认的本地草稿并重新读取 DNSPod，请核对真实结果后再编辑。已经保存的变更不会回滚。" : "本次暂存的新增、修改和删除都未写入 DNSPod，放弃后保留原解析。"}</DialogDescription></DialogHeader>
          <DialogFooter><Button type="button" variant="outline" onClick={() => setDiscardOpen(false)}>继续查看草稿</Button><Button type="button" variant="destructive" disabled={mutationPending} onClick={endEditing}>{saveFailure ? "结束并刷新" : "放弃修改"}</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </Card>
  );
}
