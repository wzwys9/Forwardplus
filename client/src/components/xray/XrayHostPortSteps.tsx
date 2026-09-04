import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { AlertTriangle, CheckCircle2, Clock3, RefreshCw, Server, WifiOff } from "lucide-react";

import {
  hostUnavailableMessage,
  portReservationsReady,
  portProbePresentation,
  validManualPort,
  xrayPortProbePresentation,
  type XrayCreateAction,
  type XrayCreateState,
  type XrayHostOption,
  xrayBasicSetupReady,
} from "./xrayCreateFlow";

type Props = {
  section: "BASIC" | "PORT";
  state: XrayCreateState;
  hosts: XrayHostOption[];
  hostsLoading: boolean;
  now: number;
  listenerNetwork?: "TCP" | "UDP";
  listenerNetworks?: readonly ("TCP" | "UDP")[];
  onAction: (action: XrayCreateAction) => void;
  onProbe: () => void;
  onBack?: () => void;
  onNext: () => void;
};

function HostStep({
  state,
  hosts,
  hostsLoading,
  onAction,
  onNext,
}: Omit<Props, "now" | "onProbe" | "onBack">) {
  const selected = hosts.find((host) => host.id === state.hostId);
  const canContinue = xrayBasicSetupReady(state, hosts);
  return (
    <div className="space-y-5">
      <div><h3 className="font-semibold">主机和基本信息</h3><p className="mt-1 text-sm text-muted-foreground">不可用主机仍会显示原因，但不能进入部署流程。</p></div>
      <fieldset className="space-y-2"><legend className="text-sm font-medium">选择主机</legend>
        {hostsLoading ? <div className="space-y-2" aria-label="正在加载主机"><Skeleton className="h-16 w-full" /><Skeleton className="h-16 w-full" /></div> : (
          <div className="max-h-56 space-y-2 overflow-y-auto pr-1">
            {hosts.map((host) => <button key={host.id} type="button" disabled={!host.canCreateXrayInbound} aria-pressed={state.hostId === host.id} aria-describedby={`xray-host-${host.id}-reason`} onClick={() => onAction({ type: "SELECT_HOST", host })} className="flex w-full items-start gap-3 rounded-lg border border-border/60 p-3 text-left transition-colors enabled:hover:bg-muted/60 disabled:cursor-not-allowed disabled:opacity-65 aria-pressed:border-primary aria-pressed:bg-primary/5">
              {host.canCreateXrayInbound ? <Server className="mt-0.5 h-4 w-4 shrink-0" aria-hidden={true} /> : <WifiOff className="mt-0.5 h-4 w-4 shrink-0" aria-hidden={true} />}
              <span className="min-w-0"><span className="block text-sm font-medium">{host.name}</span><span id={`xray-host-${host.id}-reason`} className="mt-0.5 block text-xs text-muted-foreground">{hostUnavailableMessage(host)}</span></span>
            </button>)}
            {hosts.length === 0 && <p className="rounded-lg border border-dashed p-4 text-sm text-muted-foreground">暂无主机，请先添加 ForwardX Agent。</p>}
          </div>
        )}
      </fieldset>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-1.5"><Label htmlFor="xray-create-name">节点名称</Label><Input id="xray-create-name" maxLength={128} value={state.name} onChange={(event) => onAction({ type: "SET_NAME", value: event.target.value })} placeholder="例如：香港 Reality" /></div>
        <div className="space-y-1.5"><Label htmlFor="xray-create-address">公网地址</Label><Input id="xray-create-address" maxLength={253} value={state.publicAddress} onChange={(event) => onAction({ type: "SET_PUBLIC_ADDRESS", value: event.target.value })} placeholder="公网 IPv4 或域名" /></div>
      </div>
      {selected && !selected.canCreateXrayInbound && <p role="alert" className="flex gap-2 rounded-lg border border-destructive/30 bg-destructive/5 p-3 text-sm"><AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" aria-hidden={true} />{hostUnavailableMessage(selected)}；已填写内容会保留。</p>}
      <div className="flex justify-end"><Button type="button" disabled={!canContinue} onClick={onNext}>下一步：选择协议</Button></div>
    </div>
  );
}

function ProbeStatus({ network, probe }: {
  network: "TCP" | "UDP";
  probe: ReturnType<typeof xrayPortProbePresentation>;
}) {
  const pending = probe.phase === "QUEUED" || probe.phase === "RUNNING";
  const StatusIcon = probe.phase === "RESERVED" ? CheckCircle2
    : pending ? RefreshCw
      : probe.phase === "FAILED" || probe.phase === "EXPIRED" ? AlertTriangle : Clock3;
  return (
    <div aria-live="polite" className="rounded-lg border border-border/60 p-4">
      <div className="flex flex-wrap items-center gap-2">
        <StatusIcon className="h-4 w-4" aria-hidden={true} />
        <span className="text-sm font-medium">{network}</span>
        <Badge variant={probe.phase === "FAILED" || probe.phase === "EXPIRED" ? "destructive" : probe.phase === "RESERVED" ? "default" : "secondary"}>{probe.label}</Badge>
      </div>
      <p className="mt-2 text-sm text-muted-foreground">{probe.message}</p>
    </div>
  );
}

function PortStep({ state, hosts, now, listenerNetwork = "TCP", listenerNetworks, onAction, onProbe, onBack, onNext }: Omit<Props, "hostsLoading">) {
  const host = hosts.find((item) => item.id === state.hostId);
  const networks = listenerNetworks ?? [listenerNetwork];
  const dualNetwork = networks.length === 2;
  const probe = portProbePresentation(state, now);
  const secondaryProbe = xrayPortProbePresentation(state.secondaryProbe, now);
  const pending = probe.phase === "QUEUED" || probe.phase === "RUNNING"
    || secondaryProbe.phase === "QUEUED" || secondaryProbe.phase === "RUNNING";
  const canProbe = !!host?.canCreateXrayInbound && validManualPort(state) && !pending;
  const ready = portReservationsReady(state, networks, now);
  const networkLabel = dualNetwork ? "TCP + UDP 同端口" : `${networks[0]} 端口`;
  return (
    <div className="space-y-5">
      <div><h3 className="font-semibold">{networkLabel}检测与短期预留</h3><p className="mt-1 text-sm text-muted-foreground">范围固定为 1000–65535；AUTO 和 MANUAL 都由目标 Agent 对 {dualNetwork ? "TCP、UDP" : networks[0]} socket 真实 bind/close 探测。{dualNetwork ? "两种网络必须在同一端口分别预留。" : ""}</p></div>
      {host && <div className="rounded-lg border border-border/60 p-3"><p className="text-sm font-medium">{host.name}</p><p className="mt-1 text-xs text-muted-foreground">{hostUnavailableMessage(host)}</p></div>}
      <div className="grid grid-cols-2 gap-2" role="group" aria-label="端口分配方式">
        <Button type="button" variant={state.portMode === "AUTO" ? "default" : "outline"} aria-pressed={state.portMode === "AUTO"} onClick={() => onAction({ type: "SET_PORT_MODE", mode: "AUTO" })}>自动分配</Button>
        <Button type="button" variant={state.portMode === "MANUAL" ? "default" : "outline"} aria-pressed={state.portMode === "MANUAL"} onClick={() => onAction({ type: "SET_PORT_MODE", mode: "MANUAL" })}>手动端口</Button>
      </div>
      {state.portMode === "MANUAL" && <div className="space-y-1.5"><Label htmlFor="xray-manual-port">监听端口</Label><Input id="xray-manual-port" inputMode="numeric" value={state.manualPort} aria-describedby="xray-manual-port-help" onChange={(event) => onAction({ type: "SET_MANUAL_PORT", value: event.target.value })} placeholder="1000–65535" /><p id="xray-manual-port-help" className="text-xs text-muted-foreground">必须在主机端口策略范围内，且最终部署前仍会重新校验。</p></div>}
      <div className={dualNetwork ? "grid gap-3 sm:grid-cols-2" : ""}>
        <ProbeStatus network={networks[0] ?? "TCP"} probe={probe} />
        {dualNetwork && <ProbeStatus network={networks[1] ?? "UDP"} probe={secondaryProbe} />}
      </div>
      {host && !host.canCreateXrayInbound && <p role="alert" className="text-sm text-destructive">{hostUnavailableMessage(host)}；已保留表单，请恢复后重试。</p>}
      <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between"><Button type="button" variant="outline" onClick={onBack}>返回传输</Button><Button type="button" disabled={!canProbe} onClick={onProbe}>{probe.canReprobe && probe.phase !== "IDLE" ? `重新探测${dualNetwork ? " TCP + UDP" : ""}` : state.portMode === "AUTO" ? `自动检测${dualNetwork ? "同端口" : "可用端口"}` : "检测并预留端口"}</Button></div>
      {ready && <div className="flex justify-end"><Button type="button" onClick={onNext}>下一步：配置安全</Button></div>}
    </div>
  );
}

export function XrayHostPortSteps(props: Props) {
  return props.section === "BASIC" ? <HostStep {...props} /> : <PortStep {...props} />;
}
