import { useEffect, useMemo, useReducer, useRef, useState } from "react";
import { AlertTriangle, CheckCircle2, Clock3, Globe2, Loader2, Network, Server } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import type { AppRouterOutputs } from "@/lib/trpc";
import { trpc } from "@/lib/trpc";
import { formatXrayEndpoint } from "./xrayInboundPresentation";
import {
  initialXrayQuickConfigFlowState,
  reduceXrayQuickConfigFlow,
  XRAY_QUICK_CONFIG_CARRIERS,
  XRAY_QUICK_CONFIG_STEPS,
  xrayQuickConfigCarriersComplete,
  xrayQuickConfigEndpointKey,
  type XrayQuickConfigCarrier,
  type XrayQuickConfigDomainCheck,
  type XrayQuickConfigEntryHost,
  type XrayQuickConfigEngine,
  type XrayQuickConfigEditDraft,
  type XrayQuickConfigPortResult,
  type XrayQuickConfigPortSuccess,
  type XrayQuickConfigPreview,
  type XrayQuickConfigStep,
  type XrayQuickConfigTarget,
} from "./xrayQuickConfigFlow";
import { XrayQuickConfigStepNav } from "./XrayQuickConfigStepNav";

type DnsAccount = AppRouterOutputs["xray"]["dnsProviderAccounts"]["getGlobal"];
type DnsZone = AppRouterOutputs["xray"]["dnsProviderAccounts"]["zones"][number];

const carrierLabels: Record<XrayQuickConfigCarrier, string> = {
  TELECOM: "电信",
  UNICOM: "联通",
  MOBILE: "移动",
  EDUCATION: "教育网",
};

const entryReasonLabels: Record<string, string> = {
  HOST_OFFLINE: "Agent 离线或心跳已过期",
  AGENT_CAPABILITY_MISSING: "Agent 缺少端口检查能力",
  UDP_CAPABILITY_REQUIRED: "需要升级 Agent 以支持 UDP 端口检查",
  QUICK_CONFIG_HOST_UNAVAILABLE: "Realm 未启用或主机没有有效公网地址",
};

const domainErrorLabels: Record<string, string> = {
  DOMAIN_INVALID: "域名格式无效，请只填写相对主机记录。",
  DOMAIN_CHECK_INVALID: "域名检查已失效，请重新检查。",
  DOMAIN_CHECK_EXPIRED: "域名检查已过期，请重新检查。",
  DOMAIN_CONFIRMATION_INVALID: "确认内容已变化，请重新检查。",
  DOMAIN_CONFIRMATION_EXPIRED: "域名确认已过期，请重新检查。",
  DOMAIN_CONFIRMATION_REQUIRED: "请先确认域名及冲突处理方式。",
  DOMAIN_CONFLICT_CHANGED: "DNSPod 上的同名记录已变化，请重新检查。",
  DOMAIN_ALREADY_MANAGED: "该域名已由另一个快速配置管理。",
  QUICK_CONFIG_TARGET_CHANGED: "落地节点配置已变化，请关闭向导后重新选择。",
  DNS_PROVIDER_VALIDATION_STALE: "DNSPod 账号验证已过期，请到系统设置重新验证。",
  DNS_PROVIDER_CATALOG_STALE: "DNSPod 线路目录已过期，请到系统设置刷新。",
};

const planningErrorLabels: Record<string, string> = {
  QUICK_CONFIG_PREVIEW_INVALID: "当前选择或短期凭证已失效，请从端口检测重新开始。",
  QUICK_CONFIG_PREVIEW_EXPIRED: "预览已过期，请重新生成。",
  QUICK_CONFIG_TARGET_CHANGED: "落地节点配置已变化，请关闭向导后重新选择。",
  QUICK_CONFIG_TARGET_UNSUPPORTED: "落地节点当前不可用于快速配置。",
  QUICK_CONFIG_HOST_UNAVAILABLE: "入口主机不可用，请返回并调整运营商入口。",
  HOST_OFFLINE: "有入口服务器已离线，请恢复后重新检测。",
  UDP_CAPABILITY_REQUIRED: "有入口服务器缺少 UDP 检测能力，请升级 Agent。",
  GLOBAL_PORT_PROBE_FAILED: "端口检测失败，请稍后重试。",
  GLOBAL_PORT_PROBE_EXPIRED: "端口检测结果已过期，请重新检测。",
  DOMAIN_CONFLICT_CHANGED: "DNSPod 上的同名记录已变化，请返回域名步骤重新检查。",
  DOMAIN_ALREADY_MANAGED: "该域名已由另一个快速配置管理。",
  RULE_APPLY_FAILED: "转发规则未能全部就绪，系统已停止后续 DNS 切换。",
  DNS_COMPENSATION_FAILED: "DNS 回滚未完全成功，请查看执行步骤并人工核对。",
  FORWARD_PROTOCOL_DISABLED: "所选转发引擎已在系统设置中关闭，请返回重新选择。",
};

const engineReasonLabels: Record<string, string> = {
  FORWARD_PROTOCOL_DISABLED: "该转发方式已在系统设置中关闭",
  HOST_OFFLINE: "至少一台所选入口服务器离线",
  AGENT_CAPABILITY_MISSING: "至少一台服务器需要升级 Agent",
  UDP_CAPABILITY_REQUIRED: "至少一台服务器缺少 UDP 端口检查能力",
  QUICK_CONFIG_HOST_UNAVAILABLE: "至少一台服务器当前不满足转发前置条件",
  QUICK_CONFIG_ADDRESS_UNAVAILABLE: "所选 IPv4/IPv6 地址无法由该引擎共同使用",
};

function safeErrorCode(error: unknown) {
  const message = error instanceof Error ? error.message : String(error ?? "");
  return /^[A-Z][A-Z0-9_]{1,63}$/.test(message) ? message : "INTERNAL_ERROR";
}

function safeDomainError(error: unknown) {
  const code = safeErrorCode(error);
  return domainErrorLabels[code] ?? "操作失败，请检查 DNSPod 状态后重试。";
}

function safePlanningError(error: unknown) {
  const code = safeErrorCode(error);
  return planningErrorLabels[code] ?? `操作失败（${code}），请重试。`;
}

type CarrierRoutesInput = Array<{
  carrier: XrayQuickConfigCarrier;
  providerLineId: string;
  endpoints: Array<{ hostId: number; addressFamily: "IPV4" | "IPV6" }>;
}>;

function selectedCarrierRoutes(
  state: ReturnType<typeof initialXrayQuickConfigFlowState>,
  zone: DnsZone | undefined,
): CarrierRoutesInput | null {
  const routes: CarrierRoutesInput = [];
  for (const carrier of XRAY_QUICK_CONFIG_CARRIERS) {
    const line = zone?.carrierLines.find((item) => item.category === carrier);
    if (!line || line.status !== "AVAILABLE") return null;
    const endpoints = state.carrierEndpoints[carrier].flatMap((key) => {
      const [rawHostId, addressFamily] = key.split(":");
      const hostId = Number(rawHostId);
      if (!Number.isSafeInteger(hostId) || hostId <= 0 || (addressFamily !== "IPV4" && addressFamily !== "IPV6")) return [];
      return [{ hostId, addressFamily } satisfies CarrierRoutesInput[number]["endpoints"][number]];
    });
    if (endpoints.length === 0) return null;
    routes.push({ carrier, providerLineId: line.providerLineId, endpoints });
  }
  return routes;
}

function selectedEngineEntries(routes: CarrierRoutesInput | null) {
  if (!routes) return [];
  const entries = new Map<string, { hostId: number; addressFamily: "IPV4" | "IPV6" }>();
  for (const endpoint of routes.flatMap((route) => route.endpoints)) {
    entries.set(`${endpoint.hostId}:${endpoint.addressFamily}`, endpoint);
  }
  return [...entries.values()].sort((left, right) => left.hostId - right.hostId
    || left.addressFamily.localeCompare(right.addressFamily));
}

function targetTypeLabel(target: XrayQuickConfigTarget) {
  return target.targetType === "XRAY_INBOUND" ? "受管 Xray 节点" : "外部出口节点";
}

function DomainRecordList({ title, records, tone }: {
  title: string;
  records: ReadonlyArray<XrayQuickConfigDomainCheck["conflicts"][number]>;
  tone: "warning" | "neutral";
}) {
  if (records.length === 0) return null;
  return (
    <section className={`rounded-lg border p-4 ${tone === "warning" ? "border-amber-500/30 bg-amber-500/5" : "border-border/60 bg-muted/15"}`}>
      <h4 className="text-sm font-medium">{title}</h4>
      <ul className="mt-3 space-y-2">
        {records.map((record) => (
          <li key={record.recordRef} className="flex min-w-0 flex-wrap items-center gap-2 text-sm">
            <Badge variant="outline">{record.recordType}</Badge>
            <span className="max-w-full break-all font-mono text-xs">{record.value}</span>
            <span className="text-xs text-muted-foreground">{record.lineName} · TTL {record.ttl}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

function DomainStep(props: {
  accountId: number;
  target: XrayQuickConfigTarget;
  zones: readonly DnsZone[];
  state: ReturnType<typeof initialXrayQuickConfigFlowState>;
  confirmedValid: boolean;
  editIdentity?: Pick<XrayQuickConfigEditDraft, "quickConfigId" | "expectedRevision">;
  onSetDomain: (zoneId: number | null, relativeName: string) => void;
  onChecked: (check: XrayQuickConfigDomainCheck) => void;
  onConfirmed: (token: string, expiresAt: string) => void;
  onNext: () => void;
}) {
  const [error, setError] = useState<string | null>(null);
  const createCheck = trpc.xray.quickConfigs.domainChecksCreate.useMutation({ gcTime: 0 });
  const confirmCheck = trpc.xray.quickConfigs.domainChecksConfirm.useMutation({ gcTime: 0 });
  const usableZones = props.zones.filter((zone) => zone.catalogUsable);
  const selectedZone = props.zones.find((zone) => zone.zoneId === props.state.zoneId);
  const relativeName = props.state.relativeName.trim();
  const pending = createCheck.isPending || confirmCheck.isPending;
  const confirmationAction = props.state.domainCheck?.conflicts.length
    ? "REPLACE_CONFLICTING_RECORDS" as const
    : "USE_UNUSED_NAME" as const;
  const canConfirm = !!props.state.domainCheck
    && props.state.domainCheck.allowedActions.includes(confirmationAction)
    && !pending;

  const checkDomain = async () => {
    if (!props.state.zoneId || !relativeName) return;
    setError(null);
    try {
      const result = await createCheck.mutateAsync({
        targetRef: {
          targetType: props.target.targetType,
          targetId: props.target.targetId,
          targetVersion: props.target.targetVersion,
        },
        accountId: props.accountId,
        zoneId: props.state.zoneId,
        relativeName,
        ...(props.editIdentity ? { editIdentity: props.editIdentity } : {}),
      });
      props.onChecked(result as XrayQuickConfigDomainCheck);
    } catch (mutationError) {
      setError(safeDomainError(mutationError));
    } finally {
      createCheck.reset();
    }
  };

  const confirmDomain = async () => {
    const check = props.state.domainCheck;
    if (!check || !canConfirm) return;
    setError(null);
    try {
      const result = await confirmCheck.mutateAsync({
        domainCheckToken: check.domainCheckToken,
        action: confirmationAction,
        confirmationHash: check.confirmationHash,
      });
      props.onConfirmed(result.confirmedDomainToken, result.expiresAt);
    } catch (mutationError) {
      setError(safeDomainError(mutationError));
    } finally {
      confirmCheck.reset();
    }
  };

  return (
    <div className="space-y-5">
      <div>
        <h3 className="font-semibold">选择域名并完成实时检查</h3>
        <p className="mt-1 text-sm text-muted-foreground">选择 DNSPod 中的主域名，只填写前缀。例如填写 dfd 与 cocbc.com 将生成 dfd.cocbc.com。</p>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1.5">
          <Label htmlFor="quick-config-zone">主域名</Label>
          <Select
            value={props.state.zoneId ? String(props.state.zoneId) : undefined}
            onValueChange={(value) => { setError(null); props.onSetDomain(Number(value), props.state.relativeName); }}
          >
            <SelectTrigger id="quick-config-zone"><SelectValue placeholder="选择 DNSPod 域名" /></SelectTrigger>
            <SelectContent>
              {props.zones.map((zone) => <SelectItem key={zone.zoneId} value={String(zone.zoneId)} disabled={!zone.catalogUsable}>{zone.name}{zone.catalogUsable ? "" : "（目录不可用）"}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="quick-config-relative-name">相对主机记录</Label>
          <Input
            id="quick-config-relative-name"
            value={props.state.relativeName}
            maxLength={253}
            autoComplete="off"
            spellCheck={false}
            placeholder="例如：dfd 或 hk.dfd"
            onChange={(event) => { setError(null); props.onSetDomain(props.state.zoneId, event.target.value); }}
          />
        </div>
      </div>
      {selectedZone && relativeName && <p className="rounded-lg border bg-muted/20 px-4 py-3 text-sm">将检查：<span className="break-all font-medium">{relativeName}.{selectedZone.name}</span></p>}
      {usableZones.length === 0 && <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>没有可用域名</AlertTitle><AlertDescription>请关闭向导，到系统设置重新验证 DNSPod 账号和线路目录。</AlertDescription></Alert>}
      <div className="flex justify-end">
        <Button type="button" variant="outline" disabled={!props.state.zoneId || !relativeName || pending} onClick={checkDomain}>
          {createCheck.isPending ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Network className="mr-2 h-4 w-4" />}
          {props.state.domainCheck ? "重新检查域名" : "检查域名"}
        </Button>
      </div>
      {error && <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>域名检查失败</AlertTitle><AlertDescription>{error}</AlertDescription></Alert>}
      {props.state.domainCheck && (
        <div className="space-y-3">
          <Alert>
            <CheckCircle2 className="h-4 w-4" />
            <AlertTitle>检查完成：{props.state.domainCheck.fqdn}</AlertTitle>
            <AlertDescription>{props.state.domainCheck.conflicts.length > 0 ? "发现会被替换的同名记录；确认前不会修改 DNSPod。" : "没有发现 A、AAAA 或 CNAME 冲突；仍需确认后才能继续。"}</AlertDescription>
          </Alert>
          <DomainRecordList title="确认后将替换的记录" records={props.state.domainCheck.conflicts} tone="warning" />
          <DomainRecordList title="保留、不删除的其他记录" records={props.state.domainCheck.preservedRecords} tone="neutral" />
          {!props.confirmedValid && (
            <div className="flex justify-end">
              <Button type="button" disabled={!canConfirm} onClick={confirmDomain}>
                {confirmCheck.isPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {props.state.domainCheck.conflicts.length ? "确认替换这些解析" : "确认使用此域名"}
              </Button>
            </div>
          )}
        </div>
      )}
      {props.confirmedValid && <Alert><CheckCircle2 className="h-4 w-4" /><AlertTitle>域名已确认</AlertTitle><AlertDescription>确认仅在当前向导内短期有效；修改域名会清除后续选择。</AlertDescription></Alert>}
      {props.state.confirmedDomainToken && !props.confirmedValid && <Alert variant="destructive"><Clock3 className="h-4 w-4" /><AlertTitle>域名确认已过期</AlertTitle><AlertDescription>已保留输入，请重新检查并确认。</AlertDescription></Alert>}
      <div className="flex justify-end"><Button type="button" disabled={!props.confirmedValid} onClick={props.onNext}>下一步：运营商入口</Button></div>
    </div>
  );
}

function CarrierStep(props: {
  state: ReturnType<typeof initialXrayQuickConfigFlowState>;
  zone: DnsZone | undefined;
  hosts: XrayQuickConfigEntryHost[];
  loading: boolean;
  error: boolean;
  confirmedValid: boolean;
  onToggle: (carrier: XrayQuickConfigCarrier, endpointKey: string) => void;
  onBack: () => void;
  onNext: () => void;
  onRetry: () => void;
}) {
  const complete = xrayQuickConfigCarriersComplete(props.state);
  if (props.loading) return <div className="space-y-5"><div className="space-y-3" aria-busy="true" aria-label="正在加载入口主机"><Skeleton className="h-24 w-full" /><Skeleton className="h-24 w-full" /><Skeleton className="h-24 w-full" /></div><Button type="button" variant="outline" onClick={props.onBack}>返回：域名</Button></div>;
  if (props.error) return <div className="space-y-5"><Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>入口主机加载失败</AlertTitle><AlertDescription className="space-y-3"><p>请检查面板连接后重试。</p><Button type="button" size="sm" variant="outline" onClick={props.onRetry}>重新加载</Button></AlertDescription></Alert><Button type="button" variant="outline" onClick={props.onBack}>返回：域名</Button></div>;
  return (
    <div className="space-y-5">
      <div><h3 className="font-semibold">为四类运营商选择入口</h3><p className="mt-1 text-sm text-muted-foreground">每类至少选择一个“服务器 + 地址族”。同一服务器的 IPv4/IPv6 与多条线路会共用一个统一转发 listener。</p></div>
      {!props.confirmedValid && <Alert variant="destructive"><Clock3 className="h-4 w-4" /><AlertTitle>域名确认已过期</AlertTitle><AlertDescription>可以查看已选入口，但继续前需要返回域名步骤重新检查。</AlertDescription></Alert>}
      {XRAY_QUICK_CONFIG_CARRIERS.map((carrier) => {
        const line = props.zone?.carrierLines.find((item) => item.category === carrier);
        return (
          <fieldset key={carrier} className="rounded-lg border border-border/60 p-4">
            <legend className="px-1 text-sm font-semibold">{carrierLabels[carrier]}</legend>
            <p className="mb-3 text-xs text-muted-foreground">{line?.status === "AVAILABLE" ? `DNSPod 线路：${line.name}` : "该运营商线路目录不可用"}</p>
            <div className="grid gap-2 sm:grid-cols-2">
              {props.hosts.flatMap((host) => host.endpoints.length > 0
                ? host.endpoints.map((endpoint) => {
                    const key = xrayQuickConfigEndpointKey(host.hostId, endpoint.addressFamily);
                    const selected = props.state.carrierEndpoints[carrier].includes(key);
                    return (
                      <button
                        key={key}
                        type="button"
                        disabled={!host.eligible || line?.status !== "AVAILABLE"}
                        aria-pressed={selected}
                        onClick={() => props.onToggle(carrier, key)}
                        className="flex min-w-0 items-start gap-3 rounded-lg border border-border/60 p-3 text-left transition-colors enabled:hover:bg-muted/60 disabled:cursor-not-allowed disabled:opacity-55 aria-pressed:border-primary aria-pressed:bg-primary/5"
                      >
                        <Server className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
                        <span className="min-w-0">
                          <span className="block truncate text-sm font-medium">{host.name} · {endpoint.addressFamily === "IPV4" ? "IPv4" : "IPv6"}</span>
                          <span className="mt-0.5 block break-all font-mono text-xs text-muted-foreground">{endpoint.address}</span>
                          {!host.eligible && <span className="mt-1 block text-xs text-destructive">{entryReasonLabels[host.disabledReasonCode ?? ""] ?? "该主机暂不可用"}</span>}
                        </span>
                      </button>
                    );
                  })
                : [<div key={`${host.hostId}:empty`} className="rounded-lg border border-dashed p-3 text-sm text-muted-foreground"><span className="font-medium text-foreground">{host.name}</span><br />没有有效公网 IPv4/IPv6</div>])}
            </div>
            {props.hosts.length === 0 && <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">暂无受管入口主机。</p>}
          </fieldset>
        );
      })}
      <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between">
        <Button type="button" variant="outline" onClick={props.onBack}>返回：域名</Button>
        <Button type="button" disabled={!complete || !props.confirmedValid} onClick={props.onNext}>下一步：转发引擎</Button>
      </div>
    </div>
  );
}

type ForwardEngineCatalog = AppRouterOutputs["xray"]["quickConfigs"]["forwardEngines"];

function EngineStep(props: {
  catalog: ForwardEngineCatalog | undefined;
  selected: XrayQuickConfigEngine | null;
  loading: boolean;
  error: boolean;
  onSelect: (engine: XrayQuickConfigEngine) => void;
  onBack: () => void;
  onNext: () => void;
  onRetry: () => void;
  lockedEngine?: XrayQuickConfigEngine;
}) {
  const selectedItem = props.catalog?.items.find((item) => item.engine === props.selected);
  const canContinue = !!selectedItem?.eligible;
  return (
    <div className="space-y-5">
      <div><h3 className="font-semibold">选择统一转发引擎</h3><p className="mt-1 text-sm text-muted-foreground">{props.lockedEngine ? "编辑拓扑时保持当前引擎；如需更换，请先退出并使用详情页的“切换引擎”。" : "一种引擎会应用到全部所选入口服务器；服务端已按主机、地址族、全局开关和 Agent 能力计算交集。"}</p></div>
      {props.loading ? <div className="grid gap-3 sm:grid-cols-2" aria-busy="true" aria-label="正在计算共同可用引擎"><Skeleton className="h-24 w-full" /><Skeleton className="h-24 w-full" /><Skeleton className="h-24 w-full" /><Skeleton className="h-24 w-full" /></div>
        : props.error || !props.catalog ? <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>引擎目录加载失败</AlertTitle><AlertDescription className="space-y-3"><p>请确认所选入口仍在线后重试。</p><Button type="button" size="sm" variant="outline" onClick={props.onRetry}>重新计算</Button></AlertDescription></Alert>
          : <div className="grid gap-3 sm:grid-cols-2">{props.catalog.items.map((item) => {
              const selected = props.selected === item.engine;
              return <button key={item.engine} type="button" disabled={!item.eligible || !!props.lockedEngine && item.engine !== props.lockedEngine} aria-pressed={selected} onClick={() => props.onSelect(item.engine)} className="flex min-h-24 items-start justify-between gap-3 rounded-lg border p-4 text-left transition-colors enabled:hover:bg-muted/60 disabled:cursor-not-allowed disabled:opacity-55 aria-pressed:border-primary aria-pressed:bg-primary/5"><span><span className="block font-medium">{item.label}</span><span className="mt-1 block text-xs text-muted-foreground">{props.lockedEngine && item.engine === props.lockedEngine ? "当前引擎（已锁定）" : item.isDefault ? "默认推荐" : "可选转发方式"}</span>{item.disabledReasonCode && <span className="mt-2 block text-xs text-destructive">{engineReasonLabels[item.disabledReasonCode] ?? "当前组合不可用"}</span>}</span>{item.eligible && selected && <CheckCircle2 className="h-5 w-5 shrink-0 text-primary" aria-hidden="true" />}</button>;
            })}</div>}
      {props.catalog && !props.catalog.items.some((item) => item.eligible) && <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>没有共同可用的转发引擎</AlertTitle><AlertDescription>请返回调整入口服务器，或在系统设置中启用并安装相同的转发方式。</AlertDescription></Alert>}
      <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between">
        <Button type="button" variant="outline" onClick={props.onBack}>返回：运营商入口</Button>
        <Button type="button" disabled={!canContinue} onClick={props.onNext}>下一步：端口检测</Button>
      </div>
    </div>
  );
}

function PortStep(props: {
  target: XrayQuickConfigTarget;
  engineLabel: string;
  result: XrayQuickConfigPortResult | null;
  manualPort: string;
  busy: boolean;
  progress: { completedHosts: number; totalHosts: number } | null;
  error: string | null;
  onManualPortChange: (value: string) => void;
  onUseOriginal: () => void;
  onUseManual: (port: number) => void;
  onUseRecommendation: (recommendationToken: string) => void;
  onBack: () => void;
  onNext: () => void;
}) {
  const result = props.result;
  const success = result?.status === "SUCCESS" ? result : null;
  const manualPort = Number(props.manualPort);
  const manualValid = Number.isInteger(manualPort) && manualPort >= 1000 && manualPort <= 65535;
  const showManual = props.target.targetType === "XRAY_INBOUND"
    && (props.manualPort.length > 0 || (result?.status === "CONFLICT" && result.resolution === "MANUAL"));
  return (
    <div className="space-y-5">
      <div><h3 className="font-semibold">检查统一对外端口</h3><p className="mt-1 text-sm text-muted-foreground">先核对全局端口账本，再由所有需要转发的入口并行检查 TCP 和 UDP。检查结果短期有效。</p></div>
      {props.busy && <Alert><Loader2 className="h-4 w-4 animate-spin" /><AlertTitle>正在检测端口 {success?.selectedPort ?? props.target.endpoint.port}</AlertTitle><AlertDescription>{props.progress ? `已完成 ${props.progress.completedHosts} / ${props.progress.totalHosts} 台入口服务器` : "正在创建各入口的 TCP/UDP 检测任务…"}</AlertDescription></Alert>}
      {props.error && <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>端口检测失败</AlertTitle><AlertDescription>{props.error}</AlertDescription></Alert>}
      {result?.status === "CONFLICT" && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>端口 {result.requestedPort} 存在冲突</AlertTitle>
          <AlertDescription>{result.resolution === "MANUAL" ? "请选择一个新的统一对外端口。" : `系统推荐端口 ${result.recommendation.port}，确认后会再次检查所有入口。`}</AlertDescription>
        </Alert>
      )}
      {result?.status === "FAILED" && <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>检测未通过</AlertTitle><AlertDescription>{planningErrorLabels[result.reasonCode] ?? result.reasonCode}</AlertDescription></Alert>}
      {result?.status === "EXPIRED" && <Alert variant="destructive"><Clock3 className="h-4 w-4" /><AlertTitle>检测已过期</AlertTitle><AlertDescription>入口选择仍已保留，请重新检测原端口。</AlertDescription></Alert>}
      {success && <Alert><CheckCircle2 className="h-4 w-4" /><AlertTitle>端口 {success.selectedPort} 检测通过</AlertTitle><AlertDescription>{success.rewritten ? `入口将使用 ${success.selectedPort}，并通过 ${props.engineLabel} 转发到落地原端口 ${props.target.endpoint.port}。` : props.target.targetType === "XRAY_INBOUND" ? `继续使用落地原端口；受管落地主机不会建立多余的 ${props.engineLabel} 规则。` : `全部入口将使用落地原端口，并通过 ${props.engineLabel} 转发到外部节点。`}</AlertDescription></Alert>}
      {showManual && (
        <div className="rounded-lg border p-4">
          <Label htmlFor="quick-config-manual-port">新的统一对外端口</Label>
          <div className="mt-2 flex flex-col gap-2 sm:flex-row">
            <Input id="quick-config-manual-port" inputMode="numeric" value={props.manualPort} placeholder="1000–65535" onChange={(event) => props.onManualPortChange(event.target.value.replace(/\D/g, "").slice(0, 5))} />
            <Button type="button" disabled={!manualValid || props.busy} onClick={() => props.onUseManual(manualPort)}>检测此端口</Button>
          </div>
        </div>
      )}
      {result?.status === "CONFLICT" && result.resolution === "RECOMMENDED" && (
        <div className="rounded-lg border p-4">
          <p className="font-medium">推荐统一端口：{result.recommendation.port}</p>
          <p className="mt-1 text-sm text-muted-foreground">该端口还需在所有入口上完成一次实时 TCP/UDP 检查。</p>
          <Button type="button" className="mt-3" disabled={props.busy} onClick={() => props.onUseRecommendation(result.recommendation.recommendationToken)}>确认并检测推荐端口</Button>
        </div>
      )}
      {!props.busy && !success && !(result?.status === "CONFLICT" && result.resolution === "RECOMMENDED") && (
        <Button type="button" variant="outline" onClick={props.onUseOriginal}>重新检测落地原端口 {props.target.endpoint.port}</Button>
      )}
      <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between">
        <Button type="button" variant="outline" onClick={props.onBack}>返回：转发引擎</Button>
        <Button type="button" disabled={!success || props.busy} onClick={props.onNext}>下一步：默认线路</Button>
      </div>
    </div>
  );
}

function DefaultRouteStep(props: {
  success: XrayQuickConfigPortSuccess;
  engineLabel: string;
  selectedIds: string[];
  expired: boolean;
  previewPending: boolean;
  error: string | null;
  onToggle: (candidateId: string) => void;
  onBack: () => void;
  onPreview: () => void;
  onRecheck: () => void;
}) {
  return (
    <div className="space-y-5">
      <div><h3 className="font-semibold">选择默认线路</h3><p className="mt-1 text-sm text-muted-foreground">运营商未命中时使用这些地址。可以同时选择 IPv4 和 IPv6。</p></div>
      {props.expired && <Alert variant="destructive"><Clock3 className="h-4 w-4" /><AlertTitle>端口检测结果已过期</AlertTitle><AlertDescription className="space-y-3"><p>已保留域名和运营商入口，需要重新检测端口。</p><Button type="button" size="sm" variant="outline" onClick={props.onRecheck}>返回重新检测</Button></AlertDescription></Alert>}
      <div className="grid gap-3 sm:grid-cols-2">
        {props.success.defaultRouteCandidates.map((candidate) => {
          const selected = props.selectedIds.includes(candidate.candidateId);
          return (
            <button key={candidate.candidateId} type="button" aria-pressed={selected} disabled={props.expired || props.previewPending} onClick={() => props.onToggle(candidate.candidateId)} className="flex min-w-0 items-start gap-3 rounded-lg border p-4 text-left transition-colors enabled:hover:bg-muted/60 disabled:opacity-55 aria-pressed:border-primary aria-pressed:bg-primary/5">
              <Globe2 className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              <span className="min-w-0"><span className="block text-sm font-medium">{candidate.label}</span><span className="mt-1 block break-all font-mono text-xs text-muted-foreground">{candidate.address}</span><span className="mt-1 block text-xs text-muted-foreground">{candidate.sourceType === "LANDING" ? "落地直连" : `受管 ${props.engineLabel} 入口`}{candidate.recommended ? " · 默认推荐" : ""}</span></span>
            </button>
          );
        })}
      </div>
      {props.error && <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>无法生成预览</AlertTitle><AlertDescription>{props.error}</AlertDescription></Alert>}
      <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between">
        <Button type="button" variant="outline" disabled={props.previewPending} onClick={props.onBack}>返回：端口检测</Button>
        <Button type="button" disabled={props.selectedIds.length === 0 || props.expired || props.previewPending} onClick={props.onPreview}>{props.previewPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}生成真实预览</Button>
      </div>
    </div>
  );
}

function PreviewStep(props: {
  preview: XrayQuickConfigPreview;
  applyPending: boolean;
  error: string | null;
  onBack: () => void;
  onApply: () => void;
  editing?: boolean;
}) {
  const preview = props.preview;
  return (
    <div className="space-y-5">
      <Alert><Clock3 className="h-4 w-4" /><AlertTitle>目前只是预览</AlertTitle><AlertDescription>{props.editing ? "当前生效配置尚未改变。点击最终确认后，将先建立新规则并验证，再切换 DNS 和清理旧规则。" : "尚未创建转发规则，也没有修改 DNSPod。点击最终确认后才开始持久编排。"}</AlertDescription></Alert>
      <section className="rounded-lg border p-4"><h3 className="font-semibold">{preview.fqdn}:{preview.publicPort}</h3><p className="mt-1 break-all text-sm text-muted-foreground">落地：{preview.target.targetName} · {formatXrayEndpoint(preview.target.address, preview.target.port)}</p>{preview.allocation.rewritten && <Badge className="mt-3" variant="secondary">对外端口已改写</Badge>}</section>
      <section className="space-y-3"><h3 className="font-semibold">转发规则（{preview.rules.length}）</h3>{preview.rules.length === 0 ? <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">全部流量在受管落地主机直达，不需要新建转发规则。</p> : <div className="space-y-2">{preview.rules.map((rule) => <div key={rule.ruleKey} className="rounded-lg border p-3 text-sm"><div className="flex flex-wrap items-center gap-2"><span className="font-medium">{rule.hostName}</span><Badge variant="outline">{rule.engine}</Badge><Badge variant="secondary">{rule.action === "REUSE" ? "复用" : "新建"}</Badge></div><p className="mt-1 break-all font-mono text-xs text-muted-foreground">:{rule.listenPort} → {formatXrayEndpoint(rule.targetAddress, rule.targetPort)}</p></div>)}</div>}</section>
      <section className="space-y-3"><h3 className="font-semibold">DNS 解析（{preview.dnsRecords.length}）</h3><div className="space-y-2">{preview.dnsRecords.map((record, index) => <div key={`${record.routeKind}:${record.providerLineId}:${record.recordType}:${record.value}:${index}`} className="flex min-w-0 flex-wrap items-center gap-2 rounded-lg border p-3 text-sm"><Badge variant="outline">{record.recordType}</Badge><Badge variant="secondary">{record.routeKind === "DEFAULT" ? "默认" : carrierLabels[record.carrier]}</Badge><span className="break-all font-mono text-xs">{record.value}</span><span className="ml-auto text-xs text-muted-foreground">{record.action === "REPLACE" ? "替换" : "新建"}</span></div>)}</div></section>
      <DomainRecordList title="将替换或删除的同名记录" records={preview.conflictingRecords} tone="warning" />
      <DomainRecordList title="将保留的其他记录" records={preview.preservedRecords} tone="neutral" />
      {preview.warnings.length > 0 && <section className="space-y-2">{preview.warnings.map((warning) => <Alert key={warning.code}><AlertTriangle className="h-4 w-4" /><AlertTitle>{warning.code}</AlertTitle><AlertDescription>{warning.message}</AlertDescription></Alert>)}</section>}
      {props.error && <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>提交失败</AlertTitle><AlertDescription>{props.error}</AlertDescription></Alert>}
      <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between">
        <Button type="button" variant="outline" disabled={props.applyPending} onClick={props.onBack}>返回：默认线路</Button>
        <Button type="button" disabled={props.applyPending} onClick={props.onApply}>{props.applyPending && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}{props.editing ? "确认更新配置" : "确认创建规则并写入 DNS"}</Button>
      </div>
    </div>
  );
}

type QuickConfigOperation = AppRouterOutputs["xray"]["quickConfigs"]["operation"];
const terminalOperationStatuses = new Set(["SUCCESS", "FAILED", "PARTIAL_FAILURE", "CANCELLED"]);

function ApplyStep(props: {
  operation: QuickConfigOperation | undefined;
  loading: boolean;
  error: boolean;
  onRetry: () => void;
  onClose: () => void;
}) {
  const operation = props.operation;
  const terminal = !!operation && terminalOperationStatuses.has(operation.status);
  const success = operation?.status === "SUCCESS";
  return (
    <div className="space-y-5">
      <Alert variant={operation && terminal && !success ? "destructive" : "default"}>
        {success ? <CheckCircle2 className="h-4 w-4" /> : terminal ? <AlertTriangle className="h-4 w-4" /> : <Loader2 className="h-4 w-4 animate-spin" />}
        <AlertTitle>{success ? "快速配置已生效" : terminal ? "执行未完全成功" : "正在执行持久编排"}</AlertTitle>
        <AlertDescription>{operation ? `状态 ${operation.status} · 阶段 ${operation.phase}${operation.errorCode ? ` · ${operation.errorCode}` : ""}` : "正在读取 operation 状态…"}</AlertDescription>
      </Alert>
      {props.error && <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>状态加载失败</AlertTitle><AlertDescription className="space-y-3"><p>后台操作不会因页面断开而取消。</p><Button type="button" size="sm" variant="outline" onClick={props.onRetry}>重新加载</Button></AlertDescription></Alert>}
      {operation && <section className="space-y-3"><div className="flex flex-wrap items-center justify-between gap-2"><h3 className="font-semibold">执行步骤</h3><span className="text-xs text-muted-foreground">Operation #{operation.operationId}</span></div><ol className="space-y-2">{operation.steps.map((step) => <li key={step.stepKey} className="flex items-start gap-3 rounded-lg border p-3"><span className={`mt-0.5 h-2.5 w-2.5 shrink-0 rounded-full ${step.status === "SUCCESS" ? "bg-emerald-500" : step.status === "FAILED" ? "bg-destructive" : step.status === "RUNNING" ? "bg-primary animate-pulse" : "bg-muted-foreground/35"}`} aria-hidden="true" /><div className="min-w-0"><p className="text-sm font-medium">{step.kind} · {step.status}</p><p className="mt-0.5 break-all text-xs text-muted-foreground">{step.subjectSafeId ?? step.subjectType}{step.errorCode ? ` · ${step.errorCode}` : ""}{step.attemptCount > 0 ? ` · 尝试 ${step.attemptCount}` : ""}</p></div></li>)}</ol></section>}
      <div className="flex justify-end"><Button type="button" variant={success ? "default" : "outline"} disabled={props.loading && !operation} onClick={props.onClose}>{terminal ? "关闭" : "后台执行并关闭"}</Button></div>
    </div>
  );
}

export function XrayQuickConfigDialog(props: {
  target: XrayQuickConfigTarget;
  account: DnsAccount;
  zones: readonly DnsZone[];
  edit?: XrayQuickConfigEditDraft;
  onClose: () => void;
}) {
  const [state, dispatch] = useReducer(reduceXrayQuickConfigFlow, props.edit, initialXrayQuickConfigFlowState);
  const [now, setNow] = useState(Date.now());
  const [portError, setPortError] = useState<string | null>(null);
  const [previewError, setPreviewError] = useState<string | null>(null);
  const [applyError, setApplyError] = useState<string | null>(null);
  const autoPortDraftRef = useRef<string | null>(null);
  const autoEngineDraftRef = useRef<string | null>(null);
  const utils = trpc.useUtils();
  const portCheckCreate = trpc.xray.quickConfigs.portChecksCreate.useMutation({ gcTime: 0 });
  const previewMutation = trpc.xray.quickConfigs.preview.useMutation({ gcTime: 0 });
  const applyMutation = trpc.xray.quickConfigs.createApply.useMutation({ gcTime: 0 });
  const editPreviewMutation = trpc.xray.quickConfigs.editPreview.useMutation({ gcTime: 0 });
  const editApplyMutation = trpc.xray.quickConfigs.editApply.useMutation({ gcTime: 0 });
  const accountId = props.account.configured ? props.account.accountId : 0;
  const usableZones = props.zones.filter((zone) => zone.catalogUsable);
  const usableZoneKey = usableZones.map((zone) => zone.zoneId).join(":");
  const selectedZone = props.zones.find((zone) => zone.zoneId === state.zoneId);
  const confirmedValid = !!state.confirmedDomainToken && !!state.confirmedDomainExpiresAt
    && Date.parse(state.confirmedDomainExpiresAt) > now;
  const entryHostsQuery = trpc.xray.quickConfigs.entryHostsList.useQuery(undefined, {
    enabled: state.step !== "DOMAIN",
    retry: false,
    refetchInterval: state.step === "CARRIERS" ? 15_000 : false,
    refetchOnWindowFocus: true,
  });
  const entryHosts = (entryHostsQuery.data?.items ?? []) as XrayQuickConfigEntryHost[];
  const carrierRoutes = useMemo(() => selectedCarrierRoutes(state, selectedZone), [selectedZone, state]);
  const engineEntries = useMemo(() => selectedEngineEntries(carrierRoutes), [carrierRoutes]);
  const engineDraftKey = JSON.stringify(engineEntries);
  const engineQuery = trpc.xray.quickConfigs.forwardEngines.useQuery({ entries: engineEntries }, {
    enabled: engineEntries.length > 0 && xrayQuickConfigCarriersComplete(state),
    retry: false,
    refetchInterval: state.step === "ENGINE" ? 15_000 : false,
    refetchOnWindowFocus: true,
  });
  const portResultQuery = trpc.xray.quickConfigs.portChecksResult.useQuery({ portCheckId: state.portCheckId ?? "" }, {
    enabled: !!state.portCheckId,
    retry: false,
    refetchInterval: (query) => query.state.data?.status === "RUNNING" ? 750 : false,
    refetchOnWindowFocus: true,
  });
  const operationQuery = trpc.xray.quickConfigs.operation.useQuery({ operationId: state.applyResult?.operationId ?? 0 }, {
    enabled: !!state.applyResult,
    retry: false,
    refetchInterval: (query) => terminalOperationStatuses.has(String(query.state.data?.status)) ? false : 1_200,
    refetchOnWindowFocus: true,
  });

  useEffect(() => {
    if (state.zoneId && usableZones.some((zone) => zone.zoneId === state.zoneId)) return;
    dispatch({ type: "SET_DOMAIN", zoneId: usableZones[0]?.zoneId ?? null, relativeName: state.relativeName });
  }, [state.relativeName, state.zoneId, usableZoneKey, usableZones]);

  useEffect(() => {
    if (!state.confirmedDomainExpiresAt) return;
    const expiresAt = Date.parse(state.confirmedDomainExpiresAt);
    const timer = window.setTimeout(() => setNow(Date.now()), Math.max(0, expiresAt - Date.now() + 50));
    return () => window.clearTimeout(timer);
  }, [state.confirmedDomainExpiresAt]);

  useEffect(() => {
    if (state.portResult?.status !== "SUCCESS") return;
    const expiresAt = Date.parse(state.portResult.expiresAt);
    const timer = window.setTimeout(() => setNow(Date.now()), Math.max(0, expiresAt - Date.now() + 50));
    return () => window.clearTimeout(timer);
  }, [state.portResult]);

  useEffect(() => {
    const result = portResultQuery.data;
    if (!result || result.status === "RUNNING") return;
    setNow(Date.now());
    dispatch({ type: "PORT_CHECK_FINISHED", result });
  }, [portResultQuery.data]);

  useEffect(() => {
    if (!portResultQuery.error) return;
    setPortError(safePlanningError(portResultQuery.error));
    dispatch({ type: "CLEAR_PORT_CHECK" });
  }, [portResultQuery.error]);

  useEffect(() => {
    const catalog = engineQuery.data;
    if (!catalog || engineEntries.length === 0) return;
    if (state.engine) {
      const selected = catalog.items.find((item) => item.engine === state.engine);
      if (!selected?.eligible) {
        autoEngineDraftRef.current = engineDraftKey;
        dispatch({ type: "SET_ENGINE", engine: null });
      }
      return;
    }
    if (autoEngineDraftRef.current === engineDraftKey) return;
    autoEngineDraftRef.current = engineDraftKey;
    const preferred = catalog.items.find((item) => item.engine === (props.edit?.engine ?? catalog.defaultEngine));
    if (preferred?.eligible) dispatch({ type: "SET_ENGINE", engine: preferred.engine });
  }, [engineDraftKey, engineEntries.length, engineQuery.data, props.edit?.engine, state.engine]);

  const startPortCheck = async (choice: { mode: "TARGET_ORIGINAL" } | { mode: "MANUAL"; port: number } | { mode: "RECOMMENDED"; recommendationToken: string }) => {
    if (!state.confirmedDomainToken || !carrierRoutes || !state.engine) return;
    setPortError(null);
    setPreviewError(null);
    try {
      const result = await portCheckCreate.mutateAsync({
        confirmedDomainToken: state.confirmedDomainToken,
        carrierRoutes,
        engine: state.engine,
        choice,
      });
      if (result.status === "RUNNING") dispatch({ type: "PORT_CHECK_STARTED", portCheckId: result.portCheckId });
      else dispatch({ type: "PORT_CHECK_FINISHED", result });
    } catch (error) {
      setPortError(safePlanningError(error));
    }
  };

  const portDraftKey = state.confirmedDomainToken && carrierRoutes && state.engine
    ? `${state.confirmedDomainToken.slice(-32)}:${state.engine}:${JSON.stringify(carrierRoutes)}`
    : null;
  useEffect(() => {
    if (state.step !== "PORT" || !portDraftKey || state.portCheckId || state.portResult || portCheckCreate.isPending
      || autoPortDraftRef.current === portDraftKey) return;
    autoPortDraftRef.current = portDraftKey;
    void startPortCheck(props.edit && props.edit.publicPort !== props.target.endpoint.port
      ? { mode: "MANUAL", port: props.edit.publicPort }
      : { mode: "TARGET_ORIGINAL" });
  }, [portDraftKey, state.portCheckId, state.portResult, state.step]);

  const createPreview = async () => {
    if (!state.confirmedDomainToken || !carrierRoutes || !state.engine || state.portResult?.status !== "SUCCESS" || state.defaultCandidateIds.length === 0) return;
    setPreviewError(null);
    try {
      const previewInput = {
        confirmedDomainToken: state.confirmedDomainToken,
        carrierRoutes,
        engine: state.engine,
        probeResultToken: state.portResult.probeResultToken,
        defaultRoutes: state.defaultCandidateIds.map((candidateId) => ({ candidateId })),
      };
      const preview = props.edit
        ? await editPreviewMutation.mutateAsync({
          ...previewInput,
          quickConfigId: props.edit.quickConfigId,
          expectedRevision: props.edit.expectedRevision,
        })
        : await previewMutation.mutateAsync(previewInput);
      dispatch({ type: "PREVIEW_READY", preview });
      dispatch({ type: "GO_TO_STEP", step: "PREVIEW" });
    } catch (error) {
      setPreviewError(safePlanningError(error));
    }
  };

  const applyPreview = async () => {
    if (!state.preview) return;
    setApplyError(null);
    try {
      const result = props.edit
        ? await editApplyMutation.mutateAsync({ previewToken: state.preview.previewToken })
        : await applyMutation.mutateAsync({ previewToken: state.preview.previewToken });
      dispatch({ type: "APPLY_ACCEPTED", result });
      void utils.xray.quickConfigs.list.invalidate();
      void utils.xray.quickConfigs.targetsList.invalidate();
    } catch (error) {
      setApplyError(safePlanningError(error));
    }
  };

  const completed = useMemo(() => {
    const value = new Set<XrayQuickConfigStep>();
    if (confirmedValid) value.add("DOMAIN");
    if (confirmedValid && xrayQuickConfigCarriersComplete(state)) value.add("CARRIERS");
    const engineAvailable = !!state.engine && !!engineQuery.data?.items.find((item) => item.engine === state.engine)?.eligible;
    if (engineAvailable) value.add("ENGINE");
    const portValid = state.portResult?.status === "SUCCESS" && Date.parse(state.portResult.expiresAt) > now;
    if (portValid) value.add("PORT");
    if (portValid && state.defaultCandidateIds.length > 0) value.add("DEFAULT");
    if (state.preview) value.add("PREVIEW");
    if (operationQuery.data?.status === "SUCCESS") value.add("APPLY");
    return value;
  }, [confirmedValid, engineQuery.data, now, operationQuery.data?.status, state]);
  const activeIndex = XRAY_QUICK_CONFIG_STEPS.indexOf(state.step);
  const navigableFurthestStepIndex = state.applyResult ? -1 : confirmedValid
    ? state.furthestStepIndex
    : Math.min(state.furthestStepIndex, activeIndex);
  const goTo = (step: XrayQuickConfigStep) => {
    if (state.applyResult || applyMutation.isPending || editApplyMutation.isPending) return;
    const nextIndex = XRAY_QUICK_CONFIG_STEPS.indexOf(step);
    if (!confirmedValid && nextIndex > activeIndex) return;
    dispatch({ type: "GO_TO_STEP", step });
  };
  const goBack = () => goTo(XRAY_QUICK_CONFIG_STEPS[Math.max(0, activeIndex - 1)]);
  const goNext = () => goTo(XRAY_QUICK_CONFIG_STEPS[Math.min(XRAY_QUICK_CONFIG_STEPS.length - 1, activeIndex + 1)]);
  const portSuccess = state.portResult?.status === "SUCCESS" ? state.portResult : null;
  const portExpired = !!portSuccess && Date.parse(portSuccess.expiresAt) <= now;
  const portProgress = portResultQuery.data?.status === "RUNNING" ? portResultQuery.data : null;
  const portBusy = portCheckCreate.isPending || !!state.portCheckId;
  const selectedEngineLabel = engineQuery.data?.items.find((item) => item.engine === state.engine)?.label
    ?? state.engine ?? "转发引擎";
  const recheckOriginalPort = () => {
    dispatch({ type: "CLEAR_PORT_CHECK" });
    dispatch({ type: "GO_TO_STEP", step: "PORT" });
    void startPortCheck({ mode: "TARGET_ORIGINAL" });
  };

  return (
    <Dialog open onOpenChange={(open) => { if (!open) props.onClose(); }}>
      <DialogContent className="flex h-[calc(100svh-1rem)] w-[calc(100vw-1rem)] max-h-[92svh] max-w-5xl flex-col gap-0 overflow-hidden p-0">
        <DialogHeader className="shrink-0 border-b p-5 pr-12 sm:p-6 sm:pr-12">
          <DialogTitle>{props.edit ? "编辑快速配置" : "快速配置"} · {props.target.name}</DialogTitle>
          <DialogDescription>{targetTypeLabel(props.target)} · {props.target.protocol} · {formatXrayEndpoint(props.target.endpoint.address, props.target.endpoint.port)}{props.edit ? " · 落地目标已锁定" : ""}</DialogDescription>
        </DialogHeader>
        <div className="shrink-0 px-5 pt-2 sm:px-6"><XrayQuickConfigStepNav active={state.step} furthestStepIndex={navigableFurthestStepIndex} completed={completed} onSelect={goTo} /></div>
        <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain p-5 sm:p-6">
          {state.step === "DOMAIN" ? <DomainStep
            accountId={accountId}
            target={props.target}
            zones={props.zones}
            state={state}
            confirmedValid={confirmedValid}
            editIdentity={props.edit}
            onSetDomain={(zoneId, relativeName) => dispatch({ type: "SET_DOMAIN", zoneId, relativeName })}
            onChecked={(result) => dispatch({ type: "DOMAIN_CHECKED", result })}
            onConfirmed={(confirmedDomainToken, expiresAt) => {
              dispatch({ type: "DOMAIN_CONFIRMED", confirmedDomainToken, expiresAt });
              if (props.edit) dispatch({ type: "PREFILL_EDIT", draft: props.edit });
            }}
            onNext={goNext}
          /> : state.step === "CARRIERS" ? <CarrierStep
            state={state}
            zone={selectedZone}
            hosts={entryHosts}
            loading={entryHostsQuery.isLoading}
            error={entryHostsQuery.isError}
            confirmedValid={confirmedValid}
            onToggle={(carrier, endpointKey) => dispatch({ type: "TOGGLE_CARRIER_ENDPOINT", carrier, endpointKey })}
            onBack={goBack}
            onNext={goNext}
            onRetry={() => { void entryHostsQuery.refetch(); }}
          /> : state.step === "ENGINE" ? <EngineStep
            catalog={engineQuery.data}
            selected={state.engine}
            loading={engineQuery.isLoading}
            error={engineQuery.isError}
            onSelect={(engine) => { setPortError(null); setPreviewError(null); dispatch({ type: "SET_ENGINE", engine }); }}
            onBack={goBack}
            onNext={goNext}
            onRetry={() => { void engineQuery.refetch(); }}
            lockedEngine={props.edit?.engine}
          /> : state.step === "PORT" ? <PortStep
            target={props.target}
            engineLabel={selectedEngineLabel}
            result={state.portResult}
            manualPort={state.manualPort}
            busy={portBusy}
            progress={portProgress}
            error={portError}
            onManualPortChange={(value) => { setPortError(null); dispatch({ type: "SET_MANUAL_PORT", value }); }}
            onUseOriginal={() => { dispatch({ type: "CLEAR_PORT_CHECK" }); void startPortCheck({ mode: "TARGET_ORIGINAL" }); }}
            onUseManual={(port) => { dispatch({ type: "CLEAR_PORT_CHECK" }); void startPortCheck({ mode: "MANUAL", port }); }}
            onUseRecommendation={(recommendationToken) => { dispatch({ type: "CLEAR_PORT_CHECK" }); void startPortCheck({ mode: "RECOMMENDED", recommendationToken }); }}
            onBack={goBack}
            onNext={goNext}
          /> : state.step === "DEFAULT" && portSuccess ? <DefaultRouteStep
            success={portSuccess}
            engineLabel={selectedEngineLabel}
            selectedIds={state.defaultCandidateIds}
            expired={portExpired}
            previewPending={previewMutation.isPending || editPreviewMutation.isPending}
            error={previewError}
            onToggle={(candidateId) => { setPreviewError(null); dispatch({ type: "TOGGLE_DEFAULT_ROUTE", candidateId }); }}
            onBack={goBack}
            onPreview={() => { void createPreview(); }}
            onRecheck={recheckOriginalPort}
          /> : state.step === "PREVIEW" && state.preview ? <PreviewStep
            preview={state.preview}
            applyPending={applyMutation.isPending || editApplyMutation.isPending}
            error={applyError}
            onBack={goBack}
            onApply={() => { void applyPreview(); }}
            editing={!!props.edit}
          /> : state.step === "APPLY" && state.applyResult ? <ApplyStep
            operation={operationQuery.data}
            loading={operationQuery.isLoading}
            error={operationQuery.isError}
            onRetry={() => { void operationQuery.refetch(); }}
            onClose={props.onClose}
          /> : <Alert variant="destructive"><AlertTriangle className="h-4 w-4" /><AlertTitle>当前步骤依赖已失效</AlertTitle><AlertDescription>请返回上一步重新生成。</AlertDescription></Alert>}
        </div>
      </DialogContent>
    </Dialog>
  );
}
