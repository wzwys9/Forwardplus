import DashboardLayout from "@/components/DashboardLayout";
import { XrayCreateDialog } from "@/components/xray/XrayCreateDialog";
import { XrayInboundDetailDialog } from "@/components/xray/XrayInboundDetailDialog";
import { XrayInboundList } from "@/components/xray/XrayInboundList";
import { XrayExternalProxyNodes } from "@/components/xray/XrayExternalProxyNodes";
import { XrayOperationErrorDialog } from "@/components/xray/XrayOperationErrorDialog";
import { XrayRuntimeList } from "@/components/xray/XrayRuntimeList";
import { XrayRuntimeOperationDialog, type XrayRuntimeActionSelection } from "@/components/xray/XrayRuntimeOperationDialog";
import { XrayTlsCertificateManager } from "@/components/xray/XrayTlsCertificateManager";
import { XrayManagedServicesPanel } from "@/components/xray/XrayManagedServicesPanel";
import { XrayQuickConfigPanel } from "@/components/xray/XrayQuickConfigPanel";
import type { XrayInboundSummary } from "@/components/xray/xrayInboundPresentation";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs } from "@/components/ui/tabs";
import { SlidingTabsList } from "@/components/ui/sliding-tabs";
import {
  buildXrayLocation,
  resolveXrayLocation,
  XRAY_NODE_STATUSES,
  XRAY_RUNTIME_STATUSES,
  XRAY_MANAGED_SERVICE_STATUSES,
  type XrayUiTab,
} from "@/lib/xrayNavigation";
import { trpc } from "@/lib/trpc";
import { AlertTriangle, Network, Plus, RefreshCw, Route, Server, ServerCog, ShieldCheck, Upload } from "lucide-react";
import { useRef, useState } from "react";
import { useLocation, useSearch } from "wouter";

const nodeStatusLabels: Record<string, string> = {
  WAITING_SYNC: "待同步", INSTALLING: "正在安装", APPLYING: "正在应用", RUNNING: "运行中",
  DISABLED: "已停用", PENDING_DELETE: "待删除", ERROR: "错误", HOST_OFFLINE: "主机离线", UNKNOWN: "未知",
};
const runtimeStatusLabels: Record<string, string> = {
  RUNNING: "运行中", STOPPED: "已停止", ERROR: "错误", UNKNOWN: "未知",
};
const managedServiceStatusLabels: Record<string, string> = {
  WAITING_SYNC: "待同步", RUNNING: "运行中", DISABLED: "已停用", PENDING_DELETE: "待删除", ERROR: "错误",
};

function XrayLoadingState({ label }: { label: string }) {
  return (
    <div className="space-y-3" aria-busy="true" aria-label={label}>
      {[0, 1, 2].map((item) => (
        <div key={item} className="flex items-center gap-3 rounded-lg border border-border/50 bg-card px-4 py-4">
          <Skeleton className="h-9 w-9 rounded-md" />
          <div className="flex-1 space-y-2"><Skeleton className="h-4 w-40" /><Skeleton className="h-3 w-64 max-w-full" /></div>
          <Skeleton className="hidden h-6 w-20 sm:block" />
        </div>
      ))}
    </div>
  );
}

function XrayErrorState({ onRetry }: { onRetry: () => void }) {
  return (
    <Card role="alert" className="border-destructive/30 bg-destructive/5">
      <CardContent className="flex min-h-48 flex-col items-center justify-center gap-3 p-6 text-center">
        <AlertTriangle className="h-8 w-8 text-destructive" aria-hidden="true" />
        <div><h2 className="font-semibold">Xray 数据加载失败</h2><p className="mt-1 text-sm text-muted-foreground">请检查面板连接后重试。</p></div>
        <Button type="button" variant="outline" onClick={onRetry}><RefreshCw className="mr-2 h-4 w-4" />重新加载</Button>
      </CardContent>
    </Card>
  );
}

function XrayEmptyState({ tab, filtered }: { tab: XrayUiTab; filtered: boolean }) {
  const Icon = tab === "nodes" ? Network : tab === "runtime" ? ServerCog : ShieldCheck;
  return (
    <Card><CardContent className="flex min-h-56 flex-col items-center justify-center p-6 text-center">
      <span className="flex h-12 w-12 items-center justify-center rounded-lg bg-muted"><Icon className="h-6 w-6 text-muted-foreground" aria-hidden="true" /></span>
      <h2 className="mt-4 font-semibold">{filtered ? "没有匹配结果" : tab === "nodes" ? "尚未创建 Xray 节点" : tab === "runtime" ? "暂无 Xray 运行环境" : "尚未导入 TLS 证书"}</h2>
      <p className="mt-1 max-w-md text-sm text-muted-foreground">{filtered ? "调整搜索或筛选后重试。" : tab === "certificates" ? "导入主机级 PEM 证书后，可供后续 TLS 节点安全引用。" : "兼容主机和部署状态会在这里集中管理。"}</p>
    </CardContent></Card>
  );
}

function XrayContent() {
  const [pathname, setLocation] = useLocation();
  const search = useSearch();
  const location = `${pathname}${search ? `?${search}` : ""}`;
  const [errorInbound, setErrorInbound] = useState<XrayInboundSummary | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [certificateImportOpen, setCertificateImportOpen] = useState(false);
  const [externalProxyImportOpen, setExternalProxyImportOpen] = useState(false);
  const [managedServiceCreateOpen, setManagedServiceCreateOpen] = useState(false);
  const [runtimeAction, setRuntimeAction] = useState<XrayRuntimeActionSelection | null>(null);
  const detailTriggerRef = useRef<HTMLButtonElement | null>(null);
  const runtimeActionTriggerRef = useRef<HTMLButtonElement | null>(null);
  const state = resolveXrayLocation(location);
  const updateLocation = (patch: Parameters<typeof buildXrayLocation>[1]) => {
    setLocation(buildXrayLocation(location, patch), { replace: true });
  };
  const nodeQuery = trpc.xray.inbounds.list.useQuery({
    page: state.page, pageSize: 12, search: state.search,
    ...(state.hostId ? { hostId: state.hostId } : {}),
    ...(state.status ? { status: state.status as (typeof XRAY_NODE_STATUSES)[number] } : {}),
  }, { enabled: state.tab === "nodes", retry: false, refetchInterval: 15_000, refetchOnWindowFocus: true });
  const runtimeQuery = trpc.xray.runtimes.list.useQuery({
    page: state.page, pageSize: 20, search: state.search,
    ...(state.hostId ? { hostId: state.hostId } : {}),
    ...(state.status ? { status: state.status as (typeof XRAY_RUNTIME_STATUSES)[number] } : {}),
  }, { enabled: state.tab === "runtime", retry: false, refetchInterval: 15_000, refetchOnWindowFocus: true });
  const runtimeCatalogQuery = trpc.xray.runtimes.catalog.useQuery(undefined, { enabled: state.tab === "runtime", retry: false });
  const certificateQuery = trpc.xray.certificates.list.useQuery({
    page: state.page, pageSize: 20, search: state.search,
    ...(state.hostId ? { hostId: state.hostId } : {}),
  }, { enabled: state.tab === "certificates", retry: false, refetchInterval: 30_000, refetchOnWindowFocus: true });
  const hostQuery = trpc.xray.hosts.options.useQuery(undefined, { retry: false, refetchInterval: 15_000, refetchOnWindowFocus: true });
  const managedHostQuery = trpc.xray.managedServices.hostOptions.useQuery(undefined, { enabled: state.tab === "managed-services", retry: false, refetchInterval: 15_000, refetchOnWindowFocus: true });
  const dnsProviderQuery = trpc.xray.dnsProviderAccounts.getGlobal.useQuery(undefined, { enabled: state.tab === "quick-config", retry: false });
  const dnsProviderZonesQuery = trpc.xray.dnsProviderAccounts.zones.useQuery({ refresh: false }, {
    enabled: state.tab === "quick-config" && dnsProviderQuery.data?.configured === true
      && dnsProviderQuery.data.validationStatus === "VALID",
    retry: false,
  });
  const items = state.tab === "nodes" ? nodeQuery.data?.items ?? [] : state.tab === "runtime" ? runtimeQuery.data?.items ?? [] : certificateQuery.data?.items ?? [];
  const statuses = state.tab === "nodes" ? XRAY_NODE_STATUSES : state.tab === "runtime" ? XRAY_RUNTIME_STATUSES
    : state.tab === "managed-services" ? XRAY_MANAGED_SERVICE_STATUSES : [];
  const labels = state.tab === "nodes" ? nodeStatusLabels : state.tab === "managed-services" ? managedServiceStatusLabels : runtimeStatusLabels;
  const filtered = !!(state.search || state.status || state.hostId);
  const activeLoading = state.tab === "external-proxies" ? false : state.tab === "quick-config" ? dnsProviderQuery.isLoading || dnsProviderZonesQuery.isLoading : state.tab === "nodes" ? nodeQuery.isLoading : state.tab === "runtime" ? runtimeQuery.isLoading || runtimeCatalogQuery.isLoading
    : state.tab === "managed-services" ? managedHostQuery.isLoading : certificateQuery.isLoading;
  const activeError = state.tab === "external-proxies" ? false : state.tab === "quick-config" ? dnsProviderQuery.isError || dnsProviderZonesQuery.isError : state.tab === "nodes" ? nodeQuery.isError : state.tab === "runtime" ? runtimeQuery.isError || runtimeCatalogQuery.isError
    : state.tab === "managed-services" ? managedHostQuery.isError : certificateQuery.isError;
  const retryActive = () => {
    if (state.tab === "nodes") void nodeQuery.refetch();
    else if (state.tab === "runtime") {
      void runtimeQuery.refetch();
      void runtimeCatalogQuery.refetch();
    } else if (state.tab === "managed-services") void managedHostQuery.refetch();
    else if (state.tab === "quick-config") {
      void dnsProviderQuery.refetch();
      if (dnsProviderQuery.data?.configured) void dnsProviderZonesQuery.refetch();
    }
    else void certificateQuery.refetch();
  };

  return (
    <main className="mx-auto w-full max-w-[1500px] space-y-5 p-4 sm:p-6 lg:p-8">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"><div><h1 className="text-2xl font-semibold tracking-tight">Xray 管理</h1><p className="mt-1 text-sm text-muted-foreground">集中管理 ForwardX 节点、出口、运行环境、TLS 证书与独立受管服务。</p></div>{state.tab === "nodes" ? <Button type="button" onClick={() => setCreateOpen(true)}><Plus className="mr-2 h-4 w-4" />创建节点</Button> : state.tab === "external-proxies" ? <Button type="button" onClick={() => setExternalProxyImportOpen(true)}><Plus className="mr-2 h-4 w-4" />导入出口节点</Button> : state.tab === "certificates" ? <Button type="button" onClick={() => setCertificateImportOpen(true)}><Upload className="mr-2 h-4 w-4" />导入证书</Button> : state.tab === "managed-services" ? <Button type="button" onClick={() => setManagedServiceCreateOpen(true)}><Plus className="mr-2 h-4 w-4" />创建独立服务</Button> : null}</header>
      <Tabs value={state.tab} onValueChange={(tab) => updateLocation({ tab: tab as XrayUiTab, status: null, page: 1 })}>
        <SlidingTabsList
          ariaLabel="Xray 管理视图"
          activeValue={state.tab}
          items={[{ value: "nodes", label: "节点管理", icon: Network }, { value: "external-proxies", label: "出口节点", icon: Route }, { value: "quick-config", label: "快速配置", icon: Route }, { value: "runtime", label: "运行环境", icon: ServerCog }, { value: "certificates", label: "TLS 证书", icon: ShieldCheck }, { value: "managed-services", label: "独立服务", icon: Server }]}
          className="max-w-4xl"
        />
      </Tabs>
      {state.tab === "quick-config" ? null : state.tab === "external-proxies" ? <section aria-label="筛选出口节点" className="rounded-lg border border-border/60 bg-card p-4"><div className="space-y-1.5"><Label htmlFor="xray-search">搜索</Label><Input id="xray-search" type="search" value={state.search} placeholder="名称或公开地址" onChange={(event) => updateLocation({ search: event.target.value, page: 1 })} /></div></section> : <section aria-label="筛选 Xray 数据" className={`grid gap-3 rounded-lg border border-border/60 bg-card p-4 sm:grid-cols-2 ${state.tab === "certificates" ? "lg:grid-cols-[minmax(0,1fr)_220px_auto]" : "lg:grid-cols-[minmax(0,1fr)_220px_220px_auto]"}`}>
        <div className="space-y-1.5"><Label htmlFor="xray-search">搜索</Label><Input id="xray-search" type="search" value={state.search} placeholder={state.tab === "nodes" ? "节点、主机、公网地址或出口" : state.tab === "runtime" ? "主机名称" : state.tab === "managed-services" ? "服务名称" : "证书名称或 DNS SAN"} onChange={(event) => updateLocation({ search: event.target.value, page: 1 })} /></div>
        <div className="space-y-1.5"><Label htmlFor="xray-host">主机</Label><Select value={state.hostId ? String(state.hostId) : "ALL"} onValueChange={(hostId) => updateLocation({ hostId: hostId === "ALL" ? null : Number(hostId), page: 1 })}><SelectTrigger id="xray-host"><SelectValue placeholder="全部主机" /></SelectTrigger><SelectContent><SelectItem value="ALL">全部主机</SelectItem>{(state.tab === "managed-services" ? managedHostQuery.data ?? [] : hostQuery.data ?? []).map((host) => <SelectItem key={host.id} value={String(host.id)}>{host.name}</SelectItem>)}</SelectContent></Select></div>
        {state.tab !== "certificates" && <div className="space-y-1.5"><Label htmlFor="xray-status">状态</Label><Select value={state.status ?? "ALL"} onValueChange={(status) => updateLocation({ status: status === "ALL" ? null : status, page: 1 })}><SelectTrigger id="xray-status"><SelectValue placeholder="全部状态" /></SelectTrigger><SelectContent><SelectItem value="ALL">全部状态</SelectItem>{statuses.map((status) => <SelectItem key={status} value={status}>{labels[status]}</SelectItem>)}</SelectContent></Select></div>}
        <Button type="button" variant="outline" className="self-end" disabled={activeLoading} onClick={retryActive}><RefreshCw className="mr-2 h-4 w-4" />刷新</Button>
      </section>}
      <section aria-live="polite" aria-label={state.tab === "nodes" ? "Xray 节点结果" : state.tab === "external-proxies" ? "出口节点结果" : state.tab === "quick-config" ? "快速配置结果" : state.tab === "runtime" ? "Xray 运行环境结果" : state.tab === "managed-services" ? "独立服务结果" : "TLS 证书结果"}>
        {state.tab === "quick-config" ? activeLoading ? <XrayLoadingState label="正在检查 DNSPod 配置" /> : activeError || !dnsProviderQuery.data ? <XrayErrorState onRetry={retryActive} /> : <XrayQuickConfigPanel account={dnsProviderQuery.data} zones={dnsProviderZonesQuery.data ?? []} onOpenSettings={() => setLocation("/settings?tab=dns")} />
          : state.tab === "external-proxies" ? <XrayExternalProxyNodes search={state.search} page={state.page} importOpen={externalProxyImportOpen} onImportOpenChange={setExternalProxyImportOpen} onPageChange={(page) => updateLocation({ page })} />
          : activeLoading ? <XrayLoadingState label="正在加载 Xray 数据" />
          : activeError ? <XrayErrorState onRetry={retryActive} />
            : state.tab === "managed-services"
              ? <XrayManagedServicesPanel createOpen={managedServiceCreateOpen} onCreateOpenChange={setManagedServiceCreateOpen} search={state.search} hostId={state.hostId} status={state.status} page={state.page} onPageChange={(page) => updateLocation({ page })} />
            : state.tab === "certificates"
              ? items.length === 0 ? <XrayEmptyState tab={state.tab} filtered={filtered} /> : null
            : items.length === 0 ? <XrayEmptyState tab={state.tab} filtered={filtered} />
              : state.tab === "nodes" && nodeQuery.data
                ? <XrayInboundList items={nodeQuery.data.items} page={nodeQuery.data.page} totalPages={nodeQuery.data.totalPages} totalItems={nodeQuery.data.totalItems} onPageChange={(page) => updateLocation({ page })} onInspectError={setErrorInbound} onOpenDetail={(item, trigger) => { detailTriggerRef.current = trigger; updateLocation({ inboundId: item.id }); }} onOpenOperation={(operationId, trigger) => { runtimeActionTriggerRef.current = trigger; updateLocation({ operationId, operationScope: "runtime" }); }} />
                : state.tab === "runtime" && runtimeQuery.data && runtimeCatalogQuery.data
                  ? <XrayRuntimeList
                      items={runtimeQuery.data.items}
                      catalog={runtimeCatalogQuery.data}
                      page={runtimeQuery.data.page}
                      totalPages={runtimeQuery.data.totalPages}
                      totalItems={runtimeQuery.data.totalItems}
                      onPageChange={(page) => updateLocation({ page })}
                      onAction={(runtime, action, trigger) => {
                        runtimeActionTriggerRef.current = trigger;
                        setRuntimeAction({ runtime, action });
                      }}
                      onOpenOperation={(operationId, trigger) => {
                        runtimeActionTriggerRef.current = trigger;
                        updateLocation({ operationId, operationScope: "runtime" });
                      }}
                    />
                  : null}
      </section>
      {state.tab === "certificates" && <XrayTlsCertificateManager
        items={certificateQuery.data?.items ?? []}
        hosts={hostQuery.data ?? []}
        page={certificateQuery.data?.page ?? state.page}
        totalPages={Math.max(1, Math.ceil((certificateQuery.data?.total ?? 0) / (certificateQuery.data?.pageSize ?? 20)))}
        totalItems={certificateQuery.data?.total ?? 0}
        importOpen={certificateImportOpen}
        onImportOpenChange={setCertificateImportOpen}
        onPageChange={(page) => updateLocation({ page })}
        onChanged={() => { void certificateQuery.refetch(); }}
        onOperationStarted={(operationId) => updateLocation({ operationId, operationScope: "runtime" })}
      />}
      {errorInbound && <XrayOperationErrorDialog inbound={errorInbound} onClose={() => setErrorInbound(null)} />}
      {state.inboundId && <XrayInboundDetailDialog
        inboundId={state.inboundId}
        onOperationStarted={(operationId) => updateLocation({ operationId, operationScope: "runtime" })}
        onClose={() => {
          const trigger = detailTriggerRef.current;
          detailTriggerRef.current = null;
          updateLocation({ inboundId: null });
          void nodeQuery.refetch();
          window.requestAnimationFrame(() => trigger?.focus());
        }}
      />}
      {(createOpen || (state.operationId && state.operationScope !== "runtime")) && <XrayCreateDialog
        operationId={state.operationId}
        onOperationStarted={(operationId) => updateLocation({ operationId, operationScope: null })}
        onClose={() => { setCreateOpen(false); updateLocation({ operationId: null, operationScope: null }); void nodeQuery.refetch(); }}
        onShowRuntime={(hostId) => { setCreateOpen(false); updateLocation({ tab: "runtime", hostId, status: null, page: 1, operationId: null, operationScope: null }); }}
      />}
      {(runtimeAction || (state.operationId && state.operationScope === "runtime")) && <XrayRuntimeOperationDialog
        selection={runtimeAction}
        operationId={state.operationScope === "runtime" ? state.operationId : null}
        onOperationStarted={(operationId) => updateLocation({ operationId, operationScope: "runtime" })}
        onClose={() => {
          const trigger = runtimeActionTriggerRef.current;
          runtimeActionTriggerRef.current = null;
          setRuntimeAction(null);
          updateLocation({ operationId: null, operationScope: null });
          void runtimeQuery.refetch();
          if (state.tab === "certificates") void certificateQuery.refetch();
          window.requestAnimationFrame(() => trigger?.focus());
          window.setTimeout(() => trigger?.focus(), 420);
        }}
      />}
    </main>
  );
}

export default function XrayPage() {
  return <DashboardLayout><XrayContent /></DashboardLayout>;
}
