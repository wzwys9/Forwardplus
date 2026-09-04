import { useEffect, useRef, useState } from "react";
import { ArrowLeft, CheckCircle2, Copy, Plus, Route, Trash2 } from "lucide-react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "./XrayDialog";
import { XrayQuickConfigPathCard, XrayQuickConfigPathFlow } from "./XrayQuickConfigPathCard";
import { XRAY_QUICK_CONFIG_CARRIERS, type XrayQuickConfigCarrier, type XrayQuickConfigEntryHost, type XrayQuickConfigTarget } from "./xrayQuickConfigFlow";
import {
  changeQuickConfigPath, copyQuickConfigPath, emptyQuickConfigPaths, inspectQuickConfigPaths,
  QUICK_CONFIG_CARRIER_LABELS as labels, QUICK_CONFIG_PATH_LIMIT,
  type QuickConfigPath, type QuickConfigPaths,
} from "./xrayQuickConfigPaths";

type DesignerProps = {
  target: XrayQuickConfigTarget; hosts: readonly XrayQuickConfigEntryHost[];
  loading: boolean; error: boolean; onRetry: () => void; onClose: () => void;
  initialPaths?: QuickConfigPaths;
  onAccept?: (paths: QuickConfigPaths) => void;
};

function PathSummary({ paths, hosts, target }: Pick<DesignerProps, "hosts" | "target"> & { paths: QuickConfigPaths }) {
  const inspection = inspectQuickConfigPaths(paths, hosts, target.host?.id);
  return <section className="min-w-0 space-y-5">
    <div><h3 data-path-summary-title tabIndex={-1} className="font-semibold outline-none">路径汇总</h3><p className="mt-1 text-sm text-muted-foreground">尚未进行端口检测或网络连通性验证</p></div>
    <Alert><Route className="h-4 w-4" /><AlertTitle>设计预览，不是实际下发配置</AlertTitle>
      <AlertDescription>DNS 只指向入口，中转不加入入口解析。所有段使用统一对外端口，末段连接落地原端口；需要在正式向导继续选择引擎、检测端口、确认默认线路，最终提交才创建规则和 DNS。</AlertDescription></Alert>
    {inspection.issues.length === 0 && <p className="flex items-center gap-2 text-sm"><CheckCircle2 className="h-4 w-4" />路径结构检查通过 · 涉及 {inspection.uniqueForwardHostCount} 台转发服务器</p>}
    {XRAY_QUICK_CONFIG_CARRIERS.map((carrier) => <section key={carrier} className="min-w-0 space-y-3 rounded-lg border p-3 sm:p-4">
      <h4 className="font-semibold">{labels[carrier]} · {paths[carrier].length} 条路径</h4>
      {paths[carrier].map((path, index) => <div key={path.id} className="min-w-0 space-y-2 rounded-md bg-muted/25 p-3">
        <p className="text-xs font-medium text-muted-foreground">路径 {index + 1}</p>
        <XrayQuickConfigPathFlow path={path} hosts={hosts} targetName={target.name} targetHostId={target.host?.id} />
      </div>)}
      <div className="min-w-0 space-y-1 text-xs text-muted-foreground"><p className="font-medium">入口 DNS 示意</p>
        {[...new Set(inspection.dnsEntries.filter((entry) => entry.carrier === carrier)
          .map((entry) => `${entry.addressFamily === "IPV4" ? "A" : "AAAA"} → ${entry.address}`))]
          .map((entry) => <p key={entry} className="break-all font-mono">{entry}</p>)}
      </div>
      {[...new Set(inspection.issues.filter((issue) => issue.carrier === carrier).map((issue) => issue.message))]
        .map((message) => <p key={message} className="break-words text-xs text-destructive">{message}</p>)}
    </section>)}
  </section>;
}

/** Accept only transfers a validated in-memory draft to the formal wizard; it never applies it. */
export function XrayQuickConfigPathDesigner(props: DesignerProps) {
  const [paths, setPaths] = useState<QuickConfigPaths>(() => props.initialPaths ?? emptyQuickConfigPaths());
  const [carrier, setCarrier] = useState<XrayQuickConfigCarrier>("TELECOM");
  const [activeId, setActiveId] = useState<string | null>(paths.TELECOM[0]?.id ?? null);
  const [mobileEditing, setMobileEditing] = useState(false);
  const [summary, setSummary] = useState(false);
  const [closing, setClosing] = useState(false);
  const sequence = useRef(0);
  const scrollRef = useRef<HTMLDivElement>(null);
  const editingHeadingRef = useRef<HTMLHeadingElement>(null);
  const listHeadingRef = useRef<HTMLHeadingElement>(null);
  const active = paths[carrier].find((path) => path.id === activeId);
  const total = Object.values(paths).reduce((count, items) => count + items.length, 0);
  const inspection = inspectQuickConfigPaths(paths, props.hosts, props.target.host?.id);
  const currentIssues = [...new Set(inspection.issues.filter((issue) => issue.pathId === active?.id).map((issue) => issue.message))];
  const copyOptions = XRAY_QUICK_CONFIG_CARRIERS.flatMap((source) => source === carrier ? []
    : paths[source].map((path, index) => ({ path, label: `${labels[source]}路径 ${index + 1}` })));

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: 0 });
    const heading = summary ? scrollRef.current?.querySelector<HTMLElement>("[data-path-summary-title]")
      : mobileEditing ? editingHeadingRef.current : listHeadingRef.current;
    heading?.focus({ preventScroll: true });
  }, [carrier, activeId, mobileEditing, summary]);

  useEffect(() => {
    if (total === 0) return;
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ""; };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [total]);

  const requestClose = () => total > 0 ? setClosing(true) : props.onClose();
  const chooseCarrier = (next: XrayQuickConfigCarrier) => {
    setCarrier(next); setActiveId(paths[next][0]?.id ?? null); setMobileEditing(false);
  };
  const addPath = (source?: QuickConfigPath) => {
    if (paths[carrier].length >= QUICK_CONFIG_PATH_LIMIT) return;
    let id: string;
    do { id = `draft-${++sequence.current}`; } while (Object.values(paths).some((items) => items.some((path) => path.id === id)));
    const path = source ? copyQuickConfigPath(source, id) : { id, hops: [null] };
    setPaths((current) => ({ ...current, [carrier]: [...current[carrier], path] }));
    setActiveId(id); setMobileEditing(true);
  };
  const removePath = (id: string) => {
    const remaining = paths[carrier].filter((path) => path.id !== id);
    setPaths((current) => ({ ...current, [carrier]: remaining }));
    listHeadingRef.current?.focus({ preventScroll: true });
    if (id === activeId) { setActiveId(remaining[0]?.id ?? null); setMobileEditing(false); }
  };

  return <>
    <Dialog open onOpenChange={(open) => { if (!open) requestClose(); }}>
      <DialogContent className="flex h-[calc(100dvh-1.5rem)] min-h-0 w-[calc(100vw-1.5rem)] max-h-[calc(100dvh-1.5rem)] max-w-5xl flex-col gap-0 p-0 sm:max-h-[92dvh] sm:p-0 [&>button]:right-2 [&>button]:top-2 [&>button]:h-11 [&>button]:w-11">
        <DialogHeader className="shrink-0 border-b p-4 pr-12 text-left sm:p-5 sm:pr-12">
          <div className="flex flex-wrap items-center gap-2"><DialogTitle>{props.onAccept ? "配置运营商路径" : "路径设计"}</DialogTitle><Badge variant="secondary">{props.onAccept ? "尚未提交" : "仅交互预览"}</Badge></div>
          <DialogDescription className="break-all">落地：{props.target.name} · {props.target.protocol}</DialogDescription>
        </DialogHeader>
        {!summary && <div className={`shrink-0 grid-cols-2 gap-2 border-b p-3 sm:grid-cols-4 ${mobileEditing ? "hidden lg:grid" : "grid"}`} role="group" aria-label="选择运营商">
          {XRAY_QUICK_CONFIG_CARRIERS.map((item) => <Button key={item} type="button" variant="outline" className="h-11 min-w-0 gap-2 px-2 aria-pressed:border-primary aria-pressed:bg-primary/5"
            aria-pressed={carrier === item} onClick={() => chooseCarrier(item)}>{labels[item]}<span className="text-xs text-muted-foreground">{paths[item].length} 条</span></Button>)}
        </div>}
        <div ref={scrollRef} className="min-h-0 min-w-0 flex-1 overflow-y-auto overscroll-contain p-3 sm:p-5" data-path-designer-scroll>
          {props.loading ? <div aria-busy="true" aria-label="正在读取服务器" className="space-y-3"><Skeleton className="h-24 w-full" /><Skeleton className="h-40 w-full" /></div>
            : props.error ? <Alert variant="destructive"><AlertTitle>服务器列表加载失败</AlertTitle><AlertDescription className="space-y-3"><p>已有草稿不会清空。请重试读取面板主机目录。</p><Button type="button" variant="outline" className="h-11" onClick={props.onRetry}>重新加载</Button></AlertDescription></Alert>
              : summary ? <PathSummary paths={paths} hosts={props.hosts} target={props.target} />
                : <div className="grid min-w-0 items-start gap-5 lg:grid-cols-[16rem_minmax(0,1fr)]">
                  <section className={`min-w-0 space-y-3 ${mobileEditing ? "hidden lg:block" : ""}`} aria-label={`${labels[carrier]}路径列表`}>
                    <div><h3 ref={listHeadingRef} tabIndex={-1} className="font-semibold outline-none">{labels[carrier]}的访问路径</h3><p className="mt-1 text-xs text-muted-foreground">一个运营商可以使用多个入口，每条路径最终到达同一落地。</p></div>
                    {paths[carrier].map((path, index) => <div key={path.id} className={`min-w-0 rounded-lg border ${activeId === path.id ? "border-primary/60" : "border-border"}`}>
                      <button type="button" className="block w-full min-w-0 space-y-2 rounded-lg p-3 text-left hover:bg-muted/30 focus-visible:outline-2 focus-visible:outline-ring"
                        aria-label={`编辑${labels[carrier]}路径 ${index + 1}`} aria-pressed={activeId === path.id}
                        onClick={() => { setActiveId(path.id); setMobileEditing(true); }}>
                        <span className="block text-sm font-semibold">路径 {index + 1}<span className="ml-2 text-xs font-normal text-muted-foreground">{path.hops.length === 1 ? "直达落地" : `${path.hops.length - 1} 个中转`}</span></span>
                        <XrayQuickConfigPathFlow path={path} hosts={props.hosts} targetName={props.target.name} targetHostId={props.target.host?.id} />
                      </button>
                      <div className="flex justify-end border-t px-1"><Button type="button" variant="ghost" className="h-11 text-muted-foreground"
                        aria-label={`删除${labels[carrier]}路径 ${index + 1}`} onClick={() => removePath(path.id)}><Trash2 className="mr-1 h-4 w-4" />删除路径</Button></div>
                    </div>)}
                    {paths[carrier].length === 0 && <div className="rounded-lg border border-dashed p-5 text-center text-sm text-muted-foreground"><Route className="mx-auto mb-2 h-5 w-5" />还没有路径<br />先添加一个入口，再按需添加中转。</div>}
                    <Button type="button" variant="outline" className="h-11 w-full" disabled={paths[carrier].length >= QUICK_CONFIG_PATH_LIMIT || !props.hosts.some((host) => host.eligible && host.endpoints.length > 0)}
                      onClick={() => addPath()}><Plus className="mr-2 h-4 w-4" />添加路径</Button>
                    {copyOptions.length > 0 && <Select value="" onValueChange={(id) => { const option = copyOptions.find((item) => item.path.id === id); if (option) addPath(option.path); }} disabled={paths[carrier].length >= QUICK_CONFIG_PATH_LIMIT}>
                      <SelectTrigger className="h-11" aria-label="复制已有路径"><Copy className="mr-2 h-4 w-4 shrink-0" /><SelectValue placeholder="复制其他运营商路径" /></SelectTrigger>
                      <SelectContent className="max-w-[calc(100vw-2rem)]">{copyOptions.map((option) => <SelectItem key={option.path.id} value={option.path.id} className="min-h-11">{option.label}</SelectItem>)}</SelectContent>
                    </Select>}
                    {!props.hosts.some((host) => host.eligible && host.endpoints.length > 0) && <p className="text-sm text-muted-foreground">暂无可选服务器，请先添加主机或恢复 Agent 在线。</p>}
                    <p className="text-xs text-muted-foreground">同一服务器的下一跳需要在所有路径中保持一致。复制的路径可独立调整。</p>
                  </section>
                  <section className={`min-w-0 space-y-4 ${mobileEditing ? "" : "hidden lg:block"}`}>
                    <Button type="button" variant="outline" className="h-11 w-full lg:hidden" onClick={() => setMobileEditing(false)}><ArrowLeft className="mr-2 h-4 w-4" />返回路径列表</Button>
                    {active ? <>
                      <div><h3 ref={editingHeadingRef} tabIndex={-1} className="font-semibold outline-none">{labels[carrier]} · 路径 {paths[carrier].indexOf(active) + 1}</h3><p className="mt-1 text-xs text-muted-foreground">从上往下依次经过；添加中转后，可用上下箭头调整顺序。</p></div>
                      <XrayQuickConfigPathCard path={active} hosts={props.hosts} target={props.target}
                        onChange={(action) => setPaths((current) => ({ ...current, [carrier]: current[carrier].map((path) => path.id === active.id ? changeQuickConfigPath(path, action) : path) }))} />
                      {currentIssues.length > 0 && <div className="space-y-2 rounded-lg border border-destructive/30 bg-destructive/5 p-3" role="status">
                        <h4 className="text-sm font-medium">此路径还需调整</h4>{currentIssues.map((message) => <p key={message} className="break-words text-xs text-destructive">{message}</p>)}
                      </div>}
                    </> : <div className="flex min-h-64 flex-col items-center justify-center rounded-lg border border-dashed p-5 text-center"><Route className="mb-3 h-7 w-7 text-muted-foreground" /><h3 className="font-medium">先选择一条路径</h3><p className="mt-2 text-sm text-muted-foreground">入口 → 可选中转 → 固定落地</p></div>}
                  </section>
                </div>}
        </div>
        <footer className="shrink-0 space-y-2 border-t bg-background p-3 pb-[max(0.75rem,env(safe-area-inset-bottom))] sm:px-5">
          <p className="text-xs text-muted-foreground" role="status">{total} 条路径 · {props.onAccept ? "使用路径后继续引擎与端口检查，不会立即下发" : "仅预览，不下发、不保存到服务器"}</p>
          <div className="grid grid-cols-2 gap-2 sm:flex sm:justify-end">
            <Button type="button" variant="outline" className="h-11 min-w-0 px-2" onClick={requestClose}>{props.onAccept ? "取消调整" : "关闭预览"}</Button>
            <Button type="button" className="h-11 min-w-0 px-2 sm:px-4" disabled={props.loading || props.error || total === 0} onClick={() => setSummary(!summary)}>{summary ? "继续调整路径" : "查看路径汇总"}</Button>
            {props.onAccept && <Button type="button" className="col-span-2 h-11" disabled={props.loading || props.error || inspection.issues.length > 0} onClick={() => props.onAccept?.(structuredClone(paths))}>使用这些路径</Button>}
          </div>
        </footer>
      </DialogContent>
    </Dialog>
    <Dialog open={closing} onOpenChange={setClosing}>
      <DialogContent className="max-w-sm [&>button]:right-2 [&>button]:top-2 [&>button]:h-11 [&>button]:w-11">
        <DialogHeader><DialogTitle>丢弃路径草稿？</DialogTitle><DialogDescription>草稿仅保存在这个窗口中，关闭后不会保留。现有 DNS 和转发规则不受影响。</DialogDescription></DialogHeader>
        <div className="grid gap-2 sm:grid-cols-2"><Button type="button" variant="outline" className="h-11" onClick={() => setClosing(false)}>继续编辑</Button><Button type="button" variant="destructive" className="h-11" onClick={props.onClose}>丢弃并关闭</Button></div>
      </DialogContent>
    </Dialog>
  </>;
}
