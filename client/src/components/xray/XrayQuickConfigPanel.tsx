import { useEffect, useMemo, useRef, useState } from "react";
import { Activity, AlertTriangle, ArrowRight, ArrowRightLeft, Copy, ExternalLink, Eye, Loader2, Pencil, RefreshCw, RotateCcw, Route, Search, Server, Trash2 } from "lucide-react";
import { getQueryKey } from "@trpc/react-query";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "./XrayDialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Textarea } from "@/components/ui/textarea";
import { copyTextToClipboard } from "@/lib/clipboard";
import type { AppRouterOutputs } from "@/lib/trpc";
import { trpc } from "@/lib/trpc";
import { XrayQuickConfigDialog } from "./XrayQuickConfigDialog";
import { formatXrayEndpoint } from "./xrayInboundPresentation";
import { xrayQuickConfigEndpointKey, type XrayQuickConfigEditDraft, type XrayQuickConfigEngine, type XrayQuickConfigTarget } from "./xrayQuickConfigFlow";

type DnsAccount = AppRouterOutputs["xray"]["dnsProviderAccounts"]["getGlobal"];
type DnsZone = AppRouterOutputs["xray"]["dnsProviderAccounts"]["zones"][number];
type TargetType = "XRAY_INBOUND" | "EXTERNAL_PROXY_NODE";
type QuickConfigSummary = AppRouterOutputs["xray"]["quickConfigs"]["list"]["items"][number];
type QuickConfigDetail = AppRouterOutputs["xray"]["quickConfigs"]["detail"];
type QuickConfigOperation = AppRouterOutputs["xray"]["quickConfigs"]["operation"];
type QuickConfigRemovePreview = AppRouterOutputs["xray"]["quickConfigs"]["removePreview"];
type QuickConfigEngineCatalog = AppRouterOutputs["xray"]["quickConfigs"]["forwardEngines"];
type QuickConfigEngineSwitchPreview = AppRouterOutputs["xray"]["quickConfigs"]["engineSwitchPreview"];
type QuickConfigShareAccessRef =
  | Readonly<{ type: "LEGACY_CLIENT"; legacyClientId: number }>
  | Readonly<{ type: "ACCESS_ENTRY"; accessEntryId: number }>;
type ManagedInboundAccessEntry = AppRouterOutputs["xray"]["inbounds"]["detail"]["accessEntries"][number];

const activeQuickConfigStates = new Set(["APPLYING", "UPDATING", "DELETING", "COMPENSATING"]);
const terminalOperationStates = new Set(["SUCCESS", "FAILED", "PARTIAL_FAILURE", "CANCELLED"]);
const quickConfigStateLabels: Record<string, string> = {
  APPLYING: "正在应用", ACTIVE: "已生效", UPDATING: "正在更新", DELETING: "正在删除",
  COMPENSATING: "正在回滚", PARTIAL_FAILURE: "部分失败", FAILED: "失败", REMOVED: "已删除",
};
const lineLabels: Record<string, string> = {
  DEFAULT: "默认", TELECOM: "电信", UNICOM: "联通", MOBILE: "移动", EDUCATION: "教育网",
};
const engineLabels: Record<string, string> = {
  iptables: "iptables", nftables: "nftables", realm: "Realm", socat: "socat", gost: "GOST", nginx: "Nginx",
};
const engineDisabledReasonLabels: Record<string, string> = {
  FORWARD_PROTOCOL_DISABLED: "系统设置已关闭这个转发引擎。",
  HOST_OFFLINE: "至少一台入口主机离线。",
  AGENT_CAPABILITY_MISSING: "至少一台入口主机的 Agent 需要升级。",
  UDP_CAPABILITY_REQUIRED: "至少一台入口主机缺少端口探测或监听确认能力。",
  QUICK_CONFIG_HOST_UNAVAILABLE: "至少一台入口主机不满足快速配置条件。",
  QUICK_CONFIG_ADDRESS_UNAVAILABLE: "至少一台入口主机缺少所选 IPv4/IPv6 地址。",
};

function engineLabel(engine: string) {
  return engineLabels[engine] ?? engine;
}

function quickConfigEngine(value: string): XrayQuickConfigEngine | null {
  return value === "iptables" || value === "nftables" || value === "realm"
    || value === "socat" || value === "gost" || value === "nginx"
    ? value
    : null;
}

function quickConfigShareAccessRef(entry: ManagedInboundAccessEntry): QuickConfigShareAccessRef {
  return entry.legacyClientId === null
    ? { type: "ACCESS_ENTRY", accessEntryId: entry.id }
    : { type: "LEGACY_CLIENT", legacyClientId: entry.legacyClientId };
}

function quickConfigShareAccessKey(ref: QuickConfigShareAccessRef): string {
  return ref.type === "ACCESS_ENTRY" ? `ACCESS_ENTRY:${ref.accessEntryId}` : `LEGACY_CLIENT:${ref.legacyClientId}`;
}

function unavailableAccessReason(entry: ManagedInboundAccessEntry): string | null {
  if (entry.pendingDelete) return "待删除";
  if (!entry.isEnabled) return "已停用";
  if (!entry.secretStatus.requiredConfigured) return "凭据未就绪";
  return null;
}

function stateBadgeVariant(state: string): "default" | "secondary" | "destructive" | "outline" {
  if (state === "ACTIVE") return "default";
  if (state === "FAILED" || state === "PARTIAL_FAILURE") return "destructive";
  if (activeQuickConfigStates.has(state)) return "secondary";
  return "outline";
}

function safeCode(error: unknown) {
  const message = error instanceof Error ? error.message : String(error ?? "");
  return /[A-Z][A-Z0-9_]{2,}/.exec(message)?.[0] ?? "INTERNAL_ERROR";
}

const targetReasonLabels: Record<string, string> = {
  TARGET_DISABLED: "落地节点已停用",
  TARGET_PENDING_DELETE: "落地节点正在删除",
  TARGET_PROFILE_INVALID: "节点 profile 无法用于快速配置",
  TARGET_TCP_UNSUPPORTED: "该节点不是可用的 TCP 落地",
  TARGET_ENDPOINT_INVALID: "没有稳定的公网 endpoint",
  TARGET_NOT_SYNCED: "节点尚未完成运行同步",
  TARGET_HOST_OFFLINE: "落地主机当前离线",
};

function gateMessage(account: DnsAccount, zones: readonly DnsZone[]) {
  if (!account.configured) return "先配置全局 DNSPod 账号并同步托管域名，之后才能创建运营商线路。";
  if (account.validationStatus !== "VALID") return "DNSPod 账号验证已失效，请先重新验证。";
  if (Number(account.zoneCount) <= 0) return "DNSPod 账号下没有可用主域名。";
  if (!zones.some((zone) => zone.catalogUsable)) return "域名线路目录缺失、歧义或已过期，请先刷新目录。";
  return null;
}

function TargetCard(props: {
  target: XrayQuickConfigTarget;
  onConfigure: (trigger: HTMLButtonElement) => void;
}) {
  const target = props.target;
  const reason = target.disabledReasonCode
    ? targetReasonLabels[target.disabledReasonCode] ?? "该落地节点暂不可用于快速配置"
    : null;
  return (
    <Card className={target.eligible ? "" : "bg-muted/15"}>
      <CardContent className="flex flex-col gap-4 p-4 sm:flex-row sm:items-center sm:justify-between sm:p-5">
        <div className="flex min-w-0 items-start gap-3">
          <span className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-muted">
            {target.targetType === "XRAY_INBOUND" ? <Server className="h-4 w-4" aria-hidden="true" /> : <ExternalLink className="h-4 w-4" aria-hidden="true" />}
          </span>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="truncate font-medium" title={target.name}>{target.name}</h3>
              <Badge variant="outline">{target.targetType === "XRAY_INBOUND" ? "受管 Xray" : "外部出口"}</Badge>
              <Badge variant={target.eligible ? "secondary" : "outline"}>{target.protocol}</Badge>
            </div>
            <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{formatXrayEndpoint(target.endpoint.address, target.endpoint.port)}</p>
            {target.targetType === "XRAY_INBOUND" && target.host && <p className="mt-1 text-xs text-muted-foreground">落地主机：{target.host.name}</p>}
            {target.shareCapability === "NONE" && <p className="mt-2 text-xs text-amber-700 dark:text-amber-300">可建立转发，但完成后需手动更新客户端连接地址。</p>}
            {reason && <p className="mt-2 text-xs text-destructive">{reason}</p>}
          </div>
        </div>
        <Button
          type="button"
          className="w-full shrink-0 sm:w-auto"
          disabled={!target.eligible}
          onClick={(event) => props.onConfigure(event.currentTarget)}
        >
          配置
        </Button>
      </CardContent>
    </Card>
  );
}

function QuickConfigCard(props: {
  config: QuickConfigSummary;
  onOpen: (trigger: HTMLButtonElement) => void;
}) {
  const config = props.config;
  return (
    <div className="flex flex-col gap-3 border-t px-5 py-4 first:border-t-0 sm:flex-row sm:items-center sm:justify-between">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="break-all font-medium">{config.fqdn}:{config.publicPort}</h3>
          <Badge variant={stateBadgeVariant(config.state)}>{quickConfigStateLabels[config.state] ?? config.state}</Badge>
          <Badge variant="outline">{engineLabel(config.engine)}</Badge>
        </div>
        <p className="mt-1 text-sm text-muted-foreground">{config.targetName} · {config.targetType === "XRAY_INBOUND" ? "受管 Xray" : "外部出口"}</p>
        {config.currentOperationId && <p className="mt-1 text-xs text-muted-foreground">Operation #{config.currentOperationId}</p>}
      </div>
      <Button type="button" variant="outline" className="w-full shrink-0 sm:w-auto" onClick={(event) => props.onOpen(event.currentTarget)}>
        <Eye className="mr-2 h-4 w-4" />查看详情
      </Button>
    </div>
  );
}

function OperationSummary({ operation }: { operation: QuickConfigOperation }) {
  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="font-semibold">最近操作</h3>
        <Badge variant={operation.status === "SUCCESS" ? "default" : operation.status === "FAILED" || operation.status === "PARTIAL_FAILURE" ? "destructive" : "secondary"}>{operation.status}</Badge>
      </div>
      <div className="rounded-lg border p-3 text-sm">
        <p className="font-medium">{operation.type} · {operation.phase}</p>
        <p className="mt-1 text-xs text-muted-foreground">Operation #{operation.operationId}{operation.errorCode ? ` · ${operation.errorCode}` : ""}</p>
      </div>
      <ol className="space-y-2">
        {operation.steps.map((step) => (
          <li key={step.stepKey} className="flex items-start gap-3 rounded-lg border p-3">
            <span className={`mt-1 h-2.5 w-2.5 shrink-0 rounded-full ${step.status === "SUCCESS" ? "bg-emerald-500" : step.status === "FAILED" ? "bg-destructive" : step.status === "RUNNING" ? "animate-pulse bg-primary" : "bg-muted-foreground/35"}`} aria-hidden="true" />
            <div className="min-w-0"><p className="text-sm font-medium">{step.kind} · {step.status}</p><p className="mt-0.5 break-all text-xs text-muted-foreground">{step.subjectSafeId ?? step.subjectType}{step.errorCode ? ` · ${step.errorCode}` : ""}</p></div>
          </li>
        ))}
      </ol>
    </section>
  );
}

function QuickConfigRulesSection({ detail }: { detail: QuickConfigDetail }) {
  const recoveryIncomplete = detail.state === "PARTIAL_FAILURE";
  return (
    <section className="space-y-3">
      <h3 className="font-semibold">正式 {engineLabel(detail.engine)} 规则（{detail.rules.length}）</h3>
      {recoveryIncomplete && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>引擎恢复未完成</AlertTitle>
          <AlertDescription>当前按切换前的拓扑和引擎展示；请以每条规则标出的实际引擎、启用状态和运行状态为准。</AlertDescription>
        </Alert>
      )}
      {detail.rules.length === 0
        ? <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">此配置没有额外转发规则，流量在落地主机直接进入 Xray。</p>
        : <div className="space-y-2">
          {detail.rules.map((rule) => {
            const differsFromTopology = rule.forwardType !== detail.engine;
            const ruleRecoveryIncomplete = differsFromTopology || !rule.isEnabled || rule.pendingDelete;
            return (
              <div key={rule.ruleId} className="rounded-lg border p-3 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{rule.name}</span>
                  <Badge variant="outline">{differsFromTopology || recoveryIncomplete ? `实际 ${engineLabel(rule.forwardType)}` : engineLabel(rule.forwardType)}</Badge>
                  {ruleRecoveryIncomplete && recoveryIncomplete && <Badge variant="destructive">恢复未完成</Badge>}
                  {ruleRecoveryIncomplete && !recoveryIncomplete && detail.state !== "UPDATING" && <Badge variant="destructive">实际配置不一致</Badge>}
                  {!rule.isEnabled && <Badge variant="secondary">已禁用</Badge>}
                  {rule.pendingDelete && <Badge variant="destructive">待删除</Badge>}
                  <Badge variant="outline">{rule.bindingState}</Badge>
                  <Badge variant={rule.runtimeStatus === "running" ? "default" : "secondary"}>{rule.runtimeStatus}</Badge>
                </div>
                <p className="mt-1 text-xs text-muted-foreground">Host #{rule.hostId} · {rule.lineCategories.map((line) => lineLabels[line] ?? line).join(" / ") || "无线路引用"}</p>
              </div>
            );
          })}
        </div>}
    </section>
  );
}

function EngineSwitchEditor(props: {
  currentEngine: XrayQuickConfigEngine;
  selectedEngine: XrayQuickConfigEngine | null;
  catalog: QuickConfigEngineCatalog | undefined;
  catalogLoading: boolean;
  catalogError: boolean;
  preview: QuickConfigEngineSwitchPreview | null;
  errorCode: string | null;
  previewPending: boolean;
  applyPending: boolean;
  onSelect: (engine: XrayQuickConfigEngine) => void;
  onRetryCatalog: () => void;
  onPreview: () => void;
  onBack: () => void;
  onCancel: () => void;
  onApply: () => void;
}) {
  if (props.preview) {
    return (
      <section className="space-y-4 rounded-lg border p-4">
        <div>
          <h3 className="font-semibold">确认切换转发引擎</h3>
          <p className="mt-1 text-sm text-muted-foreground">配置域名、公开端口和 DNS 记录保持不变。</p>
        </div>
        <div className="flex flex-wrap items-center gap-2 rounded-md border bg-muted/20 p-3 text-sm">
          <Badge variant="outline">{engineLabel(props.preview.fromEngine)}</Badge>
          <ArrowRight className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
          <Badge>{engineLabel(props.preview.toEngine)}</Badge>
          <span className="ml-auto font-mono text-xs text-muted-foreground">端口 {props.preview.publicPort}</span>
        </div>
        <Alert>
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>切换期间会短暂中断</AlertTitle>
          <AlertDescription>系统会使用同一端口逐台清理旧引擎、应用并验证新引擎。切换无法做到零中断，请在低流量时段确认。</AlertDescription>
        </Alert>
        <div className="space-y-2">
          <h4 className="text-sm font-medium">受影响主机（{props.preview.affectedHosts.length}）</h4>
          <div className="grid gap-2 sm:grid-cols-2">
            {props.preview.affectedHosts.map((host) => (
              <div key={host.hostId} className="rounded-md border p-3 text-sm">
                <p className="break-words font-medium">{host.name}</p>
                <p className="mt-0.5 text-xs text-muted-foreground">Host #{host.hostId}</p>
              </div>
            ))}
          </div>
        </div>
        {props.preview.warnings.map((warning) => (
          <Alert key={warning.code}>
            <AlertTriangle className="h-4 w-4" />
            <AlertTitle>{warning.code}</AlertTitle>
            <AlertDescription>{warning.message}</AlertDescription>
          </Alert>
        ))}
        {props.errorCode && <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>切换请求失败</AlertTitle><AlertDescription>服务端拒绝本次操作（{props.errorCode}），请返回后刷新能力再重试。</AlertDescription></Alert>}
        <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
          <Button type="button" variant="outline" disabled={props.applyPending} onClick={props.onBack}>返回选择</Button>
          <Button type="button" disabled={props.applyPending} onClick={props.onApply}>
            {props.applyPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ArrowRightLeft className="mr-2 h-4 w-4" />}
            确认切换引擎
          </Button>
        </div>
      </section>
    );
  }

  const selectedItem = props.catalog?.items.find((item) => item.engine === props.selectedEngine);
  const canPreview = !!props.selectedEngine
    && props.selectedEngine !== props.currentEngine
    && selectedItem?.eligible === true;
  return (
    <section className="space-y-4 rounded-lg border p-4">
      <div>
        <h3 className="font-semibold">切换转发引擎</h3>
        <p className="mt-1 text-sm text-muted-foreground">当前使用 {engineLabel(props.currentEngine)}。新引擎必须同时适用于所有入口主机和地址族。</p>
      </div>
      {props.catalogLoading ? <div className="grid gap-2 sm:grid-cols-2" aria-busy="true" aria-label="正在读取引擎能力"><Skeleton className="h-20 w-full" /><Skeleton className="h-20 w-full" /></div>
        : props.catalogError ? <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>引擎能力加载失败</AlertTitle><AlertDescription className="space-y-3"><p>没有能力目录时不会提交切换。</p><Button type="button" size="sm" variant="outline" onClick={props.onRetryCatalog}>重新加载</Button></AlertDescription></Alert>
          : !props.catalog ? <Alert><AlertTriangle className="h-4 w-4" /><AlertTitle>没有可检查的入口主机</AlertTitle><AlertDescription>当前拓扑没有有效的主机与地址族，暂时不能切换引擎。</AlertDescription></Alert>
            : <div className="grid gap-2 sm:grid-cols-2">
              {props.catalog.items.map((item) => {
                const engine = quickConfigEngine(item.engine);
                const disabled = !engine || !item.eligible;
                const reason = item.disabledReasonCode
                  ? engineDisabledReasonLabels[item.disabledReasonCode] ?? "该引擎当前不可用于全部入口主机。"
                  : null;
                return (
                  <button
                    key={item.engine}
                    type="button"
                    disabled={disabled}
                    aria-pressed={props.selectedEngine === item.engine}
                    className={`min-h-20 rounded-md border p-3 text-left transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 ${props.selectedEngine === item.engine ? "border-primary bg-primary/5" : "bg-background"} ${disabled ? "cursor-not-allowed opacity-60" : "hover:bg-muted/50"}`}
                    onClick={() => { if (engine) props.onSelect(engine); }}
                  >
                    <span className="flex flex-wrap items-center gap-2 text-sm font-medium">
                      {item.label}
                      {item.engine === props.currentEngine && <Badge variant="outline">当前</Badge>}
                      {item.isDefault && <Badge variant="secondary">推荐</Badge>}
                    </span>
                    <span className={`mt-1.5 block text-xs ${reason ? "text-destructive" : "text-muted-foreground"}`}>{reason ?? "全部入口主机可用"}</span>
                  </button>
                );
              })}
            </div>}
      {props.selectedEngine === props.currentEngine && <p className="text-xs text-muted-foreground">请选择一个与当前不同的引擎，再获取影响预览。</p>}
      {props.errorCode && <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>预览失败</AlertTitle><AlertDescription>服务端拒绝本次预览（{props.errorCode}），请刷新配置后重试。</AlertDescription></Alert>}
      <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
        <Button type="button" variant="outline" disabled={props.previewPending} onClick={props.onCancel}>取消</Button>
        <Button type="button" disabled={!canPreview || props.previewPending} onClick={props.onPreview}>
          {props.previewPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          获取切换预览
        </Button>
      </div>
    </section>
  );
}

function shareText(value: AppRouterOutputs["xray"]["quickConfigs"]["share"]) {
  if (value.format !== "SOCKS5_ENDPOINT") return value.uri;
  const endpoint = value.endpoint;
  const host = endpoint.host.includes(":") ? `[${endpoint.host}]` : endpoint.host;
  const auth = endpoint.username && endpoint.password
    ? `${encodeURIComponent(endpoint.username)}:${encodeURIComponent(endpoint.password)}@`
    : "";
  return `socks5://${auth}${host}:${endpoint.port}`;
}

function QuickConfigDetailDialog(props: { id: number; onClose: () => void; onEdit?: (detail: QuickConfigDetail) => void }) {
  const queryClient = useQueryClient();
  const utils = trpc.useUtils();
  const [shareRequested, setShareRequested] = useState(false);
  const [shareError, setShareError] = useState<string | null>(null);
  const [shareAccountPickerOpen, setShareAccountPickerOpen] = useState(false);
  const [selectedShareAccessKey, setSelectedShareAccessKey] = useState<string | null>(null);
  const [shareRequestAccessRef, setShareRequestAccessRef] = useState<QuickConfigShareAccessRef | null>(null);
  const [engineSwitchOpen, setEngineSwitchOpen] = useState(false);
  const [selectedEngine, setSelectedEngine] = useState<XrayQuickConfigEngine | null>(null);
  const [engineSwitchPreview, setEngineSwitchPreview] = useState<QuickConfigEngineSwitchPreview | null>(null);
  const [engineSwitchError, setEngineSwitchError] = useState<string | null>(null);
  const [submittedOperationId, setSubmittedOperationId] = useState<number | null>(null);
  const [removePreview, setRemovePreview] = useState<QuickConfigRemovePreview | null>(null);
  const [removeConfirmFqdn, setRemoveConfirmFqdn] = useState("");
  const [lifecycleError, setLifecycleError] = useState<string | null>(null);
  const engineSwitchPreviewMutation = trpc.xray.quickConfigs.engineSwitchPreview.useMutation({ gcTime: 0 });
  const engineSwitchApplyMutation = trpc.xray.quickConfigs.engineSwitchApply.useMutation({ gcTime: 0 });
  const removePreviewMutation = trpc.xray.quickConfigs.removePreview.useMutation({ gcTime: 0 });
  const removeApplyMutation = trpc.xray.quickConfigs.removeApply.useMutation({ gcTime: 0 });
  const retryMutation = trpc.xray.quickConfigs.retry.useMutation({ gcTime: 0 });
  const syncMutation = trpc.xray.quickConfigs.sync.useMutation({ gcTime: 0 });
  const detailQuery = trpc.xray.quickConfigs.detail.useQuery({ id: props.id }, {
    retry: false,
    refetchInterval: (query) => activeQuickConfigStates.has(String(query.state.data?.state)) ? 1_500 : false,
    refetchOnWindowFocus: true,
  });
  const detail = detailQuery.data;
  const inboundDetailQuery = trpc.xray.inbounds.detail.useQuery({ id: detail?.targetId ?? 0 }, {
    enabled: shareAccountPickerOpen && detail?.targetType === "XRAY_INBOUND",
    retry: false,
    refetchOnWindowFocus: true,
  });
  const shareAccessOptions = (inboundDetailQuery.data?.accessEntries ?? []).map((entry) => {
    const accessRef = quickConfigShareAccessRef(entry);
    return {
      entry,
      accessRef,
      key: quickConfigShareAccessKey(accessRef),
      unavailableReason: unavailableAccessReason(entry),
    };
  });
  const selectedShareAccess = shareAccessOptions.find((option) => option.key === selectedShareAccessKey && !option.unavailableReason) ?? null;
  const engineEntries = useMemo(() => {
    const entries = new Map<string, { hostId: number; addressFamily: "IPV4" | "IPV6" }>();
    for (const route of detail?.activeTopology?.routes ?? []) {
      if (route.hostId === null) continue;
      const entry = { hostId: route.hostId, addressFamily: route.addressFamily };
      entries.set(`${entry.hostId}:${entry.addressFamily}`, entry);
    }
    return [...entries.values()];
  }, [detail?.activeTopology?.routes]);
  const engineCatalogQuery = trpc.xray.quickConfigs.forwardEngines.useQuery({ entries: engineEntries }, {
    enabled: engineSwitchOpen && engineEntries.length > 0,
    retry: false,
    refetchOnWindowFocus: true,
  });
  const operationId = detail?.currentOperationId ?? submittedOperationId ?? detail?.lastOperation?.operationId ?? 0;
  const operationQuery = trpc.xray.quickConfigs.operation.useQuery({ operationId }, {
    enabled: operationId > 0,
    retry: false,
    refetchInterval: (query) => terminalOperationStates.has(String(query.state.data?.status)) ? false : 1_200,
    refetchOnWindowFocus: true,
  });
  const shareInput = useMemo(() => shareRequestAccessRef
    ? { id: props.id, accessRef: shareRequestAccessRef }
    : { id: props.id }, [props.id, shareRequestAccessRef]);
  const shareQuery = trpc.xray.quickConfigs.share.useQuery(shareInput, {
    enabled: shareRequested && (detail?.targetType !== "XRAY_INBOUND" || shareRequestAccessRef !== null),
    retry: false,
    staleTime: 0,
    gcTime: 0,
    refetchOnWindowFocus: false,
  });
  const clearShare = (resetSelection = true) => {
    setShareRequested(false);
    queryClient.removeQueries({ queryKey: getQueryKey(trpc.xray.quickConfigs.share, shareInput, "query"), exact: true });
    setShareRequestAccessRef(null);
    if (resetSelection) {
      setShareAccountPickerOpen(false);
      setSelectedShareAccessKey(null);
    }
  };
  useEffect(() => {
    if (!shareRequested || !shareQuery.isError) return;
    setShareError(safeCode(shareQuery.error));
    clearShare(false);
  }, [shareQuery.error, shareQuery.isError, shareRequested]);
  useEffect(() => () => {
    queryClient.removeQueries({ queryKey: getQueryKey(trpc.xray.quickConfigs.share, shareInput, "query"), exact: true });
  }, [queryClient, shareInput]);

  const close = () => {
    clearShare();
    setShareError(null);
    setEngineSwitchOpen(false);
    setSelectedEngine(null);
    setEngineSwitchPreview(null);
    setEngineSwitchError(null);
    setSubmittedOperationId(null);
    setRemovePreview(null);
    setRemoveConfirmFqdn("");
    setLifecycleError(null);
    props.onClose();
  };
  const copyShare = async () => {
    if (!shareQuery.data) return;
    const copied = await copyTextToClipboard(shareText(shareQuery.data));
    toast[copied ? "success" : "error"](copied ? "连接信息已复制并从页面清除" : "复制失败，请重试");
    clearShare();
  };
  const requestExternalShare = () => {
    clearShare();
    setShareError(null);
    setShareRequested(true);
  };
  const requestManagedShare = () => {
    if (!selectedShareAccess) return;
    clearShare(false);
    setShareError(null);
    setShareRequestAccessRef(selectedShareAccess.accessRef);
    setShareAccountPickerOpen(false);
    setShareRequested(true);
  };
  const operation = operationQuery.data ?? detail?.currentOperation ?? detail?.lastOperation ?? undefined;
  const dnsCompensationBlocked = !!detail && !!operation && !detail.currentOperationId
    && detail.state === "PARTIAL_FAILURE" && operation.status === "PARTIAL_FAILURE"
    && operation.errorCode === "DNS_COMPENSATION_FAILED";
  const topologyEditRecoveryPending = !!detail && !!operation && !detail.currentOperationId
    && detail.state === "PARTIAL_FAILURE" && operation.status === "PARTIAL_FAILURE"
    && (operation.type === "EDIT" || operation.type === "RETRY")
    && (detail.desiredTopology?.state === "APPLYING" || detail.desiredTopology?.state === "APPLIED"
      || detail.desiredTopology?.state === "RETIRING");
  const mayRemove = !!detail && !detail.currentOperationId
    && !dnsCompensationBlocked && !topologyEditRecoveryPending
    && (detail.state === "ACTIVE" || detail.state === "FAILED" || detail.state === "PARTIAL_FAILURE");
  const currentEngine = detail ? quickConfigEngine(detail.engine) : null;
  const maySwitchEngine = !!detail && !!currentEngine && detail.state === "ACTIVE" && !detail.currentOperationId;
  const mayEdit = !!detail && !!currentEngine && !!detail.activeTopology && detail.state === "ACTIVE"
    && !detail.currentOperationId && !!props.onEdit;
  const maySync = !!detail && !!detail.activeTopology && detail.state === "ACTIVE" && !detail.currentOperationId;
  const mayRetryOperation = !!detail && !!operation && !detail.currentOperationId
    && (detail.state === "FAILED" && operation.status === "FAILED"
      && (operation.type === "APPLY" || operation.type === "REMOVE" || operation.type === "RETRY")
      || topologyEditRecoveryPending);
  const mayRecoverOldEngine = !!detail && !!operation && !detail.currentOperationId
    && detail.state === "PARTIAL_FAILURE" && detail.activeTopology?.state === "APPLIED"
    && detail.desiredTopology?.state === "ROLLBACK_PENDING" && operation.status === "PARTIAL_FAILURE"
    && (operation.type === "EDIT" || operation.type === "RETRY");
  const mayRecoverDnsCompensation = dnsCompensationBlocked
    && !topologyEditRecoveryPending
    && (operation.type === "APPLY" || operation.type === "RETRY");

  const beginEngineSwitch = () => {
    if (!detail || !maySwitchEngine) return;
    setSelectedEngine(quickConfigEngine(detail.engine));
    setEngineSwitchPreview(null);
    setEngineSwitchError(null);
    setRemovePreview(null);
    setRemoveConfirmFqdn("");
    setLifecycleError(null);
    setEngineSwitchOpen(true);
  };
  const cancelEngineSwitch = () => {
    setEngineSwitchOpen(false);
    setSelectedEngine(null);
    setEngineSwitchPreview(null);
    setEngineSwitchError(null);
    engineSwitchPreviewMutation.reset();
    engineSwitchApplyMutation.reset();
  };
  const selectEngine = (engine: XrayQuickConfigEngine) => {
    setSelectedEngine(engine);
    setEngineSwitchPreview(null);
    setEngineSwitchError(null);
  };
  const previewEngineSwitch = async () => {
    if (!detail || !maySwitchEngine || !selectedEngine || selectedEngine === detail.engine) return;
    setEngineSwitchError(null);
    try {
      const preview = await engineSwitchPreviewMutation.mutateAsync({
        id: detail.id,
        expectedRevision: detail.revision,
        engine: selectedEngine,
      });
      setEngineSwitchPreview(preview);
    } catch (error) {
      setEngineSwitchError(safeCode(error));
    } finally {
      engineSwitchPreviewMutation.reset();
    }
  };
  const applyEngineSwitch = async () => {
    if (!engineSwitchPreview) return;
    setEngineSwitchError(null);
    try {
      const result = await engineSwitchApplyMutation.mutateAsync({ switchToken: engineSwitchPreview.switchToken });
      setSubmittedOperationId(result.operationId);
      setEngineSwitchOpen(false);
      setEngineSwitchPreview(null);
      setSelectedEngine(null);
      toast.success("引擎切换已提交，正在逐台应用");
      await Promise.all([
        utils.xray.quickConfigs.detail.invalidate({ id: props.id }),
        utils.xray.quickConfigs.list.invalidate(),
      ]);
    } catch (error) {
      setEngineSwitchError(safeCode(error));
    } finally {
      engineSwitchApplyMutation.reset();
    }
  };

  const previewRemoval = async () => {
    if (!detail || !mayRemove) return;
    setLifecycleError(null);
    try {
      const preview = await removePreviewMutation.mutateAsync({ id: detail.id, expectedRevision: detail.revision });
      setRemovePreview(preview);
      setRemoveConfirmFqdn("");
    } catch (error) {
      setLifecycleError(safeCode(error));
    } finally {
      removePreviewMutation.reset();
    }
  };
  const applyRemoval = async () => {
    if (!removePreview || removeConfirmFqdn.trim().toLowerCase() !== removePreview.fqdn) return;
    setLifecycleError(null);
    try {
      await removeApplyMutation.mutateAsync({ removeToken: removePreview.removeToken, confirmFqdn: removeConfirmFqdn });
      setRemovePreview(null);
      setRemoveConfirmFqdn("");
      await Promise.all([
        utils.xray.quickConfigs.detail.invalidate({ id: props.id }),
        utils.xray.quickConfigs.list.invalidate(),
        utils.xray.quickConfigs.targetsList.invalidate(),
      ]);
    } catch (error) {
      setLifecycleError(safeCode(error));
    } finally {
      removeApplyMutation.reset();
    }
  };
  const retryOperation = async (mode: "RETRY" | "ENGINE_ROLLBACK" | "DNS_COMPENSATION" = "RETRY") => {
    const permitted = mode === "ENGINE_ROLLBACK" ? mayRecoverOldEngine
      : mode === "DNS_COMPENSATION" ? mayRecoverDnsCompensation
        : mayRetryOperation;
    if (!operation || !permitted) return;
    setLifecycleError(null);
    try {
      const result = await retryMutation.mutateAsync({
        operationId: operation.operationId,
        expectedOperationRevision: operation.operationRevision,
      });
      setSubmittedOperationId(result.operationId);
      toast.success(mode === "ENGINE_ROLLBACK" ? "旧引擎恢复已提交，正在逐台确认"
        : mode === "DNS_COMPENSATION" ? "DNS 补偿恢复已提交，完成后会继续清理未生效规则"
          : "重试已提交，正在继续处理");
      await Promise.all([
        utils.xray.quickConfigs.detail.invalidate({ id: props.id }),
        utils.xray.quickConfigs.list.invalidate(),
      ]);
    } catch (error) {
      setLifecycleError(safeCode(error));
    } finally {
      retryMutation.reset();
    }
  };
  const syncConfiguration = async () => {
    if (!detail || !maySync) return;
    setLifecycleError(null);
    try {
      const result = await syncMutation.mutateAsync({ id: detail.id, expectedRevision: detail.revision });
      setSubmittedOperationId(result.operationId);
      toast.success("同步已提交，正在核对转发规则和 DNS");
      await Promise.all([
        utils.xray.quickConfigs.detail.invalidate({ id: props.id }),
        utils.xray.quickConfigs.list.invalidate(),
      ]);
    } catch (error) {
      setLifecycleError(safeCode(error));
    } finally {
      syncMutation.reset();
    }
  };

  return (
    <Dialog open onOpenChange={(open) => { if (!open) close(); }}>
      <DialogContent className="flex h-[calc(100svh-1rem)] w-[calc(100vw-1rem)] max-h-[92svh] max-w-4xl flex-col gap-0 overflow-hidden p-0">
        <DialogHeader className="shrink-0 border-b p-5 pr-12 sm:p-6 sm:pr-12">
          <DialogTitle>快速配置详情</DialogTitle>
          <DialogDescription>{detail ? `${detail.fqdn}:${detail.publicPort}` : `配置 #${props.id}`}</DialogDescription>
        </DialogHeader>
        <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain p-5 sm:p-6">
          {detailQuery.isLoading ? <div className="space-y-3" aria-busy="true"><Skeleton className="h-24 w-full" /><Skeleton className="h-36 w-full" /><Skeleton className="h-36 w-full" /></div>
            : detailQuery.isError || !detail ? <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>详情加载失败</AlertTitle><AlertDescription className="space-y-3"><p>请检查面板状态后重试。</p><Button type="button" size="sm" variant="outline" onClick={() => { void detailQuery.refetch(); }}>重新加载</Button></AlertDescription></Alert>
              : <div className="space-y-6">
                <section className="rounded-lg border p-4">
                  <div className="flex flex-wrap items-center gap-2"><h2 className="break-all font-semibold">{detail.fqdn}:{detail.publicPort}</h2><Badge variant={stateBadgeVariant(detail.state)}>{quickConfigStateLabels[detail.state] ?? detail.state}</Badge><Badge variant="outline">{engineLabel(detail.engine)}</Badge></div>
                  <p className="mt-2 text-sm text-muted-foreground">{detail.targetName} · {detail.target.protocol} · 原始落地 {formatXrayEndpoint(detail.target.endpoint.address, detail.target.endpoint.port)}</p>
                  <div className="mt-4 flex flex-wrap gap-2"><Button type="button" variant="outline" size="sm" disabled={detailQuery.isFetching || operationQuery.isFetching} onClick={() => { void detailQuery.refetch(); if (operationId > 0) void operationQuery.refetch(); }}><RefreshCw className={`mr-2 h-4 w-4 ${detailQuery.isFetching || operationQuery.isFetching ? "animate-spin" : ""}`} />刷新状态</Button>{detail.state === "ACTIVE" && detail.target.shareCapability !== "NONE" && <Button type="button" size="sm" disabled={shareRequested} onClick={() => { if (detail.targetType === "XRAY_INBOUND") { clearShare(); setShareError(null); setShareAccountPickerOpen(true); } else { requestExternalShare(); } }}><Copy className="mr-2 h-4 w-4" />获取连接信息</Button>}{mayEdit && !engineSwitchOpen && <Button type="button" size="sm" variant="outline" onClick={() => props.onEdit?.(detail)}><Pencil className="mr-2 h-4 w-4" />编辑配置</Button>}{maySwitchEngine && !engineSwitchOpen && <Button type="button" size="sm" variant="outline" onClick={beginEngineSwitch}><ArrowRightLeft className="mr-2 h-4 w-4" />切换引擎</Button>}{mayRetryOperation && <Button type="button" size="sm" variant="outline" disabled={retryMutation.isPending} onClick={() => { void retryOperation(); }}>{retryMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RotateCcw className="mr-2 h-4 w-4" />}重试操作</Button>}{mayRecoverDnsCompensation && <Button type="button" size="sm" variant="outline" disabled={retryMutation.isPending} onClick={() => { void retryOperation("DNS_COMPENSATION"); }}>{retryMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RotateCcw className="mr-2 h-4 w-4" />}恢复 DNS 补偿</Button>}{mayRecoverOldEngine && <Button type="button" size="sm" variant="outline" disabled={retryMutation.isPending} onClick={() => { void retryOperation("ENGINE_ROLLBACK"); }}>{retryMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RotateCcw className="mr-2 h-4 w-4" />}恢复旧引擎</Button>}{maySync && !engineSwitchOpen && <Button type="button" size="sm" variant="outline" disabled={syncMutation.isPending} onClick={() => { void syncConfiguration(); }}>{syncMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}同步配置</Button>}{mayRemove && !engineSwitchOpen && <Button type="button" size="sm" variant="destructive" disabled={removePreviewMutation.isPending || removeApplyMutation.isPending || syncMutation.isPending} onClick={() => { void previewRemoval(); }}>{removePreviewMutation.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Trash2 className="mr-2 h-4 w-4" />}删除快速配置</Button>}</div>
                  {detail.state === "ACTIVE" && detail.targetType === "XRAY_INBOUND" && detail.target.shareCapability !== "NONE" && <p className="mt-3 text-xs text-muted-foreground">受管节点必须明确选择一个已启用账户后才会请求分享材料；页面不会自动选择或预加载敏感连接信息。</p>}
                </section>
                {dnsCompensationBlocked && <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>DNS 补偿尚未完成</AlertTitle><AlertDescription>{topologyEditRecoveryPending ? "编辑前的配置仍保持服务。请先点击“重试操作”继续恢复 DNS 和清理未生效规则。" : "创建前的 DNS 记录仍有未恢复项。为避免遗失原记录，快速配置删除已锁定；请先点击“恢复 DNS 补偿”。"}</AlertDescription></Alert>}
                {shareAccountPickerOpen && detail.targetType === "XRAY_INBOUND" && <section className="space-y-4 rounded-lg border p-4">
                  <div><h3 className="font-semibold">选择授权账号</h3><p className="mt-1 text-sm text-muted-foreground">这里只读取账户名称与可用状态。选择账号并确认前，不会请求 UUID、密码或完整连接链接。</p></div>
                  {inboundDetailQuery.isLoading ? <div className="space-y-2" aria-busy="true" aria-label="正在加载账号"><Skeleton className="h-10 w-full" /><Skeleton className="h-9 w-full" /></div>
                    : inboundDetailQuery.isError ? <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>账号列表加载失败</AlertTitle><AlertDescription className="space-y-3"><p>未读取到账号前不会生成连接信息。</p><Button type="button" size="sm" variant="outline" onClick={() => { void inboundDetailQuery.refetch(); }}>重新加载</Button></AlertDescription></Alert>
                      : shareAccessOptions.length === 0 ? <Alert><AlertTriangle className="h-4 w-4" /><AlertTitle>没有可选账号</AlertTitle><AlertDescription>当前受管节点没有账号，请先在节点详情中创建并启用账号。</AlertDescription></Alert>
                        : <div className="space-y-1.5"><Label htmlFor="quick-config-share-access">授权账号</Label><Select value={selectedShareAccessKey ?? undefined} onValueChange={(value) => { clearShare(false); setShareError(null); setSelectedShareAccessKey(value); }}><SelectTrigger id="quick-config-share-access"><SelectValue placeholder="请选择一个账号" /></SelectTrigger><SelectContent>{shareAccessOptions.map((option) => <SelectItem key={option.key} value={option.key} disabled={!!option.unavailableReason}>{option.entry.name}{option.unavailableReason ? ` · ${option.unavailableReason}` : " · 可用"}</SelectItem>)}</SelectContent></Select></div>}
                  <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end"><Button type="button" variant="outline" disabled={shareRequested} onClick={() => { clearShare(); setShareError(null); }}>取消</Button><Button type="button" disabled={!selectedShareAccess || shareRequested || inboundDetailQuery.isLoading} onClick={requestManagedShare}><Copy className="mr-2 h-4 w-4" />为所选账号生成连接信息</Button></div>
                </section>}
                {engineSwitchOpen && currentEngine && <EngineSwitchEditor
                  currentEngine={currentEngine}
                  selectedEngine={selectedEngine}
                  catalog={engineCatalogQuery.data}
                  catalogLoading={engineCatalogQuery.isLoading}
                  catalogError={engineCatalogQuery.isError}
                  preview={engineSwitchPreview}
                  errorCode={engineSwitchError}
                  previewPending={engineSwitchPreviewMutation.isPending}
                  applyPending={engineSwitchApplyMutation.isPending}
                  onSelect={selectEngine}
                  onRetryCatalog={() => { void engineCatalogQuery.refetch(); }}
                  onPreview={() => { void previewEngineSwitch(); }}
                  onBack={() => { setEngineSwitchPreview(null); setEngineSwitchError(null); }}
                  onCancel={cancelEngineSwitch}
                  onApply={() => { void applyEngineSwitch(); }}
                />}
                {removePreview && <section className="space-y-4 rounded-lg border border-destructive/40 bg-destructive/5 p-4"><div><h3 className="font-semibold text-destructive">确认删除 {removePreview.fqdn}</h3><p className="mt-1 text-sm text-muted-foreground">将先删除 {removePreview.dnsRecords.length} 条面板托管 DNS，再等待 {removePreview.rules.length} 条正式转发规则从 Agent 清理，最后释放端口引用。不会恢复创建前的第三方记录。</p></div><div className="grid gap-2 sm:grid-cols-2"><div className="rounded-md border bg-background p-3 text-sm">DNS 记录：{removePreview.dnsRecords.length}</div><div className="rounded-md border bg-background p-3 text-sm">转发规则：{removePreview.rules.length} · 端口 {removePreview.allocation.port}</div></div>{removePreview.warnings.map((warning) => <Alert key={warning.code}><AlertTriangle className="h-4 w-4" /><AlertTitle>{warning.code}</AlertTitle><AlertDescription>{warning.message}</AlertDescription></Alert>)}<div className="space-y-1.5"><Label htmlFor="quick-config-remove-confirm">输入完整域名确认</Label><Input id="quick-config-remove-confirm" value={removeConfirmFqdn} autoComplete="off" spellCheck={false} placeholder={removePreview.fqdn} onChange={(event) => setRemoveConfirmFqdn(event.target.value)} /></div><div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end"><Button type="button" variant="outline" disabled={removeApplyMutation.isPending} onClick={() => { setRemovePreview(null); setRemoveConfirmFqdn(""); setLifecycleError(null); }}>取消</Button><Button type="button" variant="destructive" disabled={removeApplyMutation.isPending || removeConfirmFqdn.trim().toLowerCase() !== removePreview.fqdn} onClick={() => { void applyRemoval(); }}>{removeApplyMutation.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}删除 DNS、规则和端口引用</Button></div></section>}
                {lifecycleError && <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>快速配置操作失败</AlertTitle><AlertDescription>服务端拒绝本次操作（{lifecycleError}）。请刷新状态后重试；现有数据面不会被页面直接删除。</AlertDescription></Alert>}
                {shareRequested && shareQuery.isLoading && <div className="space-y-2" aria-busy="true"><Skeleton className="h-20 w-full" /><Skeleton className="h-9 w-full" /></div>}
                {shareQuery.data && <section className="space-y-3 rounded-lg border p-4"><div><h3 className="font-semibold">连接信息</h3><p className="mt-1 text-xs text-muted-foreground">敏感内容只保留在当前内存；复制或关闭详情后立即清除。</p></div><Textarea readOnly value={shareText(shareQuery.data)} className="min-h-24 break-all font-mono text-xs" aria-label="快速配置连接信息" /><Button type="button" className="w-full" onClick={() => { void copyShare(); }}><Copy className="mr-2 h-4 w-4" />复制并清除</Button></section>}
                {shareError && <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>连接信息不可用</AlertTitle><AlertDescription className="space-y-3"><p>{detail.targetType === "XRAY_INBOUND" && shareError === "QUICK_CONFIG_TARGET_UNSUPPORTED" ? "所选账号已停用、待删除或不属于该节点，请重新选择。" : `服务端拒绝生成连接信息（${shareError}）。`}</p><Button type="button" size="sm" variant="outline" onClick={() => { setShareError(null); if (detail.targetType === "XRAY_INBOUND") setShareAccountPickerOpen(true); else requestExternalShare(); }}>重试</Button></AlertDescription></Alert>}
                <QuickConfigRulesSection detail={detail} />
                <section className="space-y-3"><h3 className="font-semibold">DNS 记录（{detail.dnsRecords.length}）</h3>{detail.dnsRecords.length === 0 ? <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">尚无托管 DNS 记录。</p> : <div className="space-y-2">{detail.dnsRecords.map((record) => <div key={record.recordRef} className="flex min-w-0 flex-wrap items-center gap-2 rounded-lg border p-3 text-sm"><Badge variant="outline">{record.recordType}</Badge><span className="break-all font-mono text-xs">{record.value}</span><Badge className="ml-auto" variant={record.status === "APPLIED" ? "default" : record.status === "DRIFTED" ? "destructive" : "secondary"}>{record.status}</Badge><span className="w-full text-xs text-muted-foreground">线路 {record.providerLineId} · TTL {record.ttl}{record.lastVerifiedAt ? ` · 最近验证 ${new Date(record.lastVerifiedAt).toLocaleString()}` : ""}</span></div>)}</div>}</section>
                {operation && <OperationSummary operation={operation} />}
                {operationQuery.isError && <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>操作状态加载失败</AlertTitle><AlertDescription><Button type="button" size="sm" variant="outline" onClick={() => { void operationQuery.refetch(); }}>重新加载 operation</Button></AlertDescription></Alert>}
              </div>}
        </div>
      </DialogContent>
    </Dialog>
  );
}

export function XrayQuickConfigPanel(props: {
  account: DnsAccount;
  zones: readonly DnsZone[];
  onOpenSettings: () => void;
}) {
  const [search, setSearch] = useState("");
  const [targetType, setTargetType] = useState<TargetType | "ALL">("ALL");
  const [selectedTarget, setSelectedTarget] = useState<XrayQuickConfigTarget | null>(null);
  const [editSession, setEditSession] = useState<Readonly<{ target: XrayQuickConfigTarget; draft: XrayQuickConfigEditDraft }> | null>(null);
  const [selectedConfigId, setSelectedConfigId] = useState<number | null>(null);
  const dialogTriggerRef = useRef<HTMLButtonElement | null>(null);
  const detailTriggerRef = useRef<HTMLButtonElement | null>(null);
  const gate = gateMessage(props.account, props.zones);
  const quickConfigsQuery = trpc.xray.quickConfigs.list.useQuery({ page: 1, pageSize: 20 }, {
    retry: false,
    refetchInterval: (query) => query.state.data?.items.some((item) => activeQuickConfigStates.has(item.state)) ? 1_500 : false,
    refetchOnWindowFocus: true,
  });
  const targetsQuery = trpc.xray.quickConfigs.targetsList.useQuery({
    search,
    ...(targetType === "ALL" ? {} : { targetType }),
    page: 1,
    pageSize: 100,
  }, {
    enabled: gate === null,
    retry: false,
    refetchOnWindowFocus: true,
  });
  const targets = (targetsQuery.data?.items ?? []) as XrayQuickConfigTarget[];
  const quickConfigs = quickConfigsQuery.data?.items ?? [];

  const closeDialog = () => {
    const trigger = dialogTriggerRef.current;
    dialogTriggerRef.current = null;
    setSelectedTarget(null);
    setEditSession(null);
    window.requestAnimationFrame(() => trigger?.focus());
  };
  const beginEdit = (detail: QuickConfigDetail) => {
    const active = detail.activeTopology;
    const currentEngine = quickConfigEngine(detail.engine);
    if (!active || !currentEngine) return;
    const carrierEndpoints: XrayQuickConfigEditDraft["carrierEndpoints"] = {
      TELECOM: [], UNICOM: [], MOBILE: [], EDUCATION: [],
    };
    for (const route of active.routes) {
      if (route.lineCategory === "DEFAULT" || route.hostId === null) continue;
      const key = xrayQuickConfigEndpointKey(route.hostId, route.addressFamily);
      if (!carrierEndpoints[route.lineCategory].includes(key)) carrierEndpoints[route.lineCategory].push(key);
    }
    const target: XrayQuickConfigTarget = {
      targetType: detail.targetType,
      targetId: detail.targetId,
      targetVersion: detail.target.targetVersion,
      name: detail.targetName,
      protocol: detail.target.protocol,
      endpoint: detail.target.endpoint,
      eligible: true,
      disabledReasonCode: null,
      shareCapability: detail.target.shareCapability,
    };
    dialogTriggerRef.current = detailTriggerRef.current;
    detailTriggerRef.current = null;
    setSelectedConfigId(null);
    setEditSession({
      target,
      draft: {
        quickConfigId: detail.id,
        expectedRevision: detail.revision,
        zoneId: detail.zoneId,
        relativeName: detail.relativeName,
        fqdn: detail.fqdn,
        managedDnsRecords: detail.dnsRecords.filter((record) => record.status !== "REMOVED"
          && active.routes.some((route) => route.routeId === record.routeId)).map((record) => ({
          recordRef: record.recordRef, recordType: record.recordType,
          providerLineId: record.providerLineId, value: record.value, ttl: record.ttl,
          lineName: lineLabels[active.routes.find((route) => route.routeId === record.routeId)?.lineCategory ?? ""] ?? record.providerLineId,
        })),
        carrierEndpoints,
        engine: currentEngine,
        publicPort: active.publicPort,
        defaultRoutes: active.routes.filter((route) => route.lineCategory === "DEFAULT").map((route) => ({
          sourceType: route.sourceType,
          hostId: route.hostId,
          addressFamily: route.addressFamily,
          address: route.address,
        })),
      },
    });
  };
  const closeDetail = () => {
    const trigger = detailTriggerRef.current;
    detailTriggerRef.current = null;
    setSelectedConfigId(null);
    window.requestAnimationFrame(() => trigger?.focus());
  };

  const existingConfigsSection = (
    <Card>
      <CardHeader className="pb-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
          <div><CardTitle>已创建的快速配置</CardTitle><CardDescription className="mt-1.5">查看当前 FQDN、统一端口、实际转发引擎、DNS 记录和持久执行状态。</CardDescription></div>
          <Button type="button" size="sm" variant="outline" disabled={quickConfigsQuery.isFetching} onClick={() => { void quickConfigsQuery.refetch(); }}>{quickConfigsQuery.isFetching ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}刷新</Button>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        {quickConfigsQuery.isLoading ? <div className="space-y-3 px-5 pb-5" aria-busy="true" aria-label="正在加载快速配置"><Skeleton className="h-20 w-full" /><Skeleton className="h-20 w-full" /></div>
          : quickConfigsQuery.isError ? <div className="px-5 pb-5"><Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>快速配置加载失败</AlertTitle><AlertDescription className="space-y-3"><p>已有转发和 DNS 不受页面加载失败影响。</p><Button type="button" size="sm" variant="outline" onClick={() => { void quickConfigsQuery.refetch(); }}>重新加载</Button></AlertDescription></Alert></div>
            : quickConfigs.length === 0 ? <div className="flex min-h-28 flex-col items-center justify-center border-t px-5 py-6 text-center"><Activity className="h-6 w-6 text-muted-foreground" aria-hidden="true" /><p className="mt-2 text-sm font-medium">还没有快速配置</p><p className="mt-1 text-xs text-muted-foreground">从下方选择落地节点开始创建。</p></div>
              : <div aria-live="polite">{quickConfigs.map((config) => <QuickConfigCard key={config.id} config={config} onOpen={(trigger) => { detailTriggerRef.current = trigger; setSelectedConfigId(config.id); }} />)}{(quickConfigsQuery.data?.total ?? 0) > quickConfigs.length && <p className="border-t px-5 py-3 text-center text-xs text-muted-foreground">当前显示最近 {quickConfigs.length} 条。</p>}</div>}
      </CardContent>
    </Card>
  );

  if (gate) {
    return (
      <div className="space-y-4">
        {existingConfigsSection}
        <Card>
          <CardContent className="flex min-h-56 flex-col items-center justify-center p-6 text-center">
            <span className="flex h-12 w-12 items-center justify-center rounded-lg bg-muted"><Route className="h-6 w-6 text-muted-foreground" aria-hidden="true" /></span>
            <h2 className="mt-4 font-semibold">新建快速配置暂不可用</h2>
            <p className="mt-1 max-w-lg text-sm text-muted-foreground">{gate}</p>
            <Button type="button" className="mt-4" onClick={props.onOpenSettings}>前往 DNS 设置</Button>
          </CardContent>
        </Card>
        {selectedConfigId && <QuickConfigDetailDialog id={selectedConfigId} onClose={closeDetail} />}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {existingConfigsSection}
      <Card>
        <CardHeader className="pb-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div>
              <CardTitle>选择落地节点</CardTitle>
              <CardDescription className="mt-1.5">统一配置四运营商入口、IPv4/IPv6、六种转发引擎和 DNSPod 解析。</CardDescription>
            </div>
            <Button type="button" variant="outline" size="sm" onClick={props.onOpenSettings}>DNS 设置</Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_220px_auto]">
            <div className="space-y-1.5">
              <Label htmlFor="quick-config-target-search">搜索落地节点</Label>
              <div className="relative">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
                <Input id="quick-config-target-search" type="search" className="pl-9" value={search} onChange={(event) => setSearch(event.target.value)} placeholder="名称、主机或公开 endpoint" />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="quick-config-target-type">类型</Label>
              <Select value={targetType} onValueChange={(value) => setTargetType(value as TargetType | "ALL")}>
                <SelectTrigger id="quick-config-target-type"><SelectValue /></SelectTrigger>
                <SelectContent><SelectItem value="ALL">全部落地</SelectItem><SelectItem value="XRAY_INBOUND">受管 Xray</SelectItem><SelectItem value="EXTERNAL_PROXY_NODE">外部出口</SelectItem></SelectContent>
              </Select>
            </div>
            <Button type="button" variant="outline" className="self-end" disabled={targetsQuery.isFetching} onClick={() => { void targetsQuery.refetch(); }}>
              {targetsQuery.isFetching ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <RefreshCw className="mr-2 h-4 w-4" />}刷新
            </Button>
          </div>
        </CardContent>
      </Card>

      {targetsQuery.isLoading ? (
        <div className="space-y-3" aria-busy="true" aria-label="正在加载落地节点">
          {[0, 1, 2].map((item) => <Skeleton key={item} className="h-28 w-full" />)}
        </div>
      ) : targetsQuery.isError ? (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>落地节点加载失败</AlertTitle>
          <AlertDescription className="flex flex-wrap items-center justify-between gap-3"><span>请检查面板连接后重试。</span><Button type="button" size="sm" variant="outline" onClick={() => { void targetsQuery.refetch(); }}>重新加载</Button></AlertDescription>
        </Alert>
      ) : targets.length === 0 ? (
        <Card><CardContent className="flex min-h-44 flex-col items-center justify-center p-6 text-center"><Route className="h-7 w-7 text-muted-foreground" aria-hidden="true" /><h2 className="mt-3 font-medium">没有匹配的落地节点</h2><p className="mt-1 text-sm text-muted-foreground">可先创建受管 Xray TCP 节点或导入外部 VLESS、SS、SOCKS5 出口。</p></CardContent></Card>
      ) : (
        <div className="space-y-3" aria-live="polite">
          {targets.map((target) => <TargetCard key={`${target.targetType}:${target.targetId}`} target={target} onConfigure={(trigger) => { dialogTriggerRef.current = trigger; setSelectedTarget(target); }} />)}
          {(targetsQuery.data?.total ?? 0) > targets.length && <p className="text-center text-xs text-muted-foreground">当前显示前 {targets.length} 个结果，请使用搜索缩小范围。</p>}
        </div>
      )}

      {selectedTarget && <XrayQuickConfigDialog
        key={`${selectedTarget.targetType}:${selectedTarget.targetId}`}
        target={selectedTarget}
        account={props.account}
        zones={props.zones}
        onClose={closeDialog}
      />}
      {editSession && <XrayQuickConfigDialog
        key={`edit:${editSession.draft.quickConfigId}:${editSession.draft.expectedRevision}`}
        target={editSession.target}
        account={props.account}
        zones={props.zones}
        edit={editSession.draft}
        onClose={closeDialog}
      />}
      {selectedConfigId && <QuickConfigDetailDialog id={selectedConfigId} onClose={closeDetail} onEdit={beginEdit} />}
    </div>
  );
}
