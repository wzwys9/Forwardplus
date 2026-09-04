import { ArrowDown, ArrowUp, LockKeyhole, Plus, Trash2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { formatXrayEndpoint } from "./xrayInboundPresentation";
import { xrayQuickConfigEndpointKey, type XrayQuickConfigEntryHost, type XrayQuickConfigTarget } from "./xrayQuickConfigFlow";
import { QUICK_CONFIG_HOP_LIMIT, quickConfigPathEndpoint, type QuickConfigPath, type QuickConfigPathAction } from "./xrayQuickConfigPaths";

function EndpointPicker(props: {
  label: string; endpointKey: string | null; hosts: readonly XrayQuickConfigEntryHost[];
  onChange: (key: string) => void;
}) {
  const selected = quickConfigPathEndpoint(props.endpointKey, props.hosts);
  const host = props.hosts.find((item) => item.hostId === selected?.hostId);
  return <div className="min-w-0 space-y-2">
    <Select value={host ? String(host.hostId) : ""} onValueChange={(value) => {
      const next = props.hosts.find((item) => String(item.hostId) === value);
      const endpoint = next?.endpoints.find((item) => item.addressFamily === selected?.addressFamily)
        ?? next?.endpoints.find((item) => item.addressFamily === "IPV4") ?? next?.endpoints[0];
      if (next?.eligible && endpoint) props.onChange(xrayQuickConfigEndpointKey(next.hostId, endpoint.addressFamily));
    }}>
      <SelectTrigger className="h-11 min-w-0" aria-label={`${props.label}服务器`}><SelectValue placeholder="选择服务器" /></SelectTrigger>
      <SelectContent className="max-h-72 max-w-[calc(100vw-2rem)]">
        {props.hosts.map((item) => <SelectItem key={item.hostId} value={String(item.hostId)}
          disabled={!item.eligible || item.endpoints.length === 0} className="min-h-11 break-all">
          {item.name}{!item.eligible || item.endpoints.length === 0 ? " · 暂不可用" : ""}
        </SelectItem>)}
      </SelectContent>
    </Select>
    {host && <div className="grid grid-cols-2 gap-2">
      {(["IPV4", "IPV6"] as const).map((family) => <Button key={family} type="button" variant="outline"
        className="h-11 min-w-0 aria-pressed:border-primary aria-pressed:bg-primary/5"
        aria-label={`${props.label.trim()} 使用 ${family === "IPV4" ? "IPv4" : "IPv6"}`}
        aria-pressed={selected?.addressFamily === family}
        disabled={!host.eligible || !host.endpoints.some((endpoint) => endpoint.addressFamily === family)}
        onClick={() => props.onChange(xrayQuickConfigEndpointKey(host.hostId, family))}>
        {family === "IPV4" ? "IPv4" : "IPv6"}
      </Button>)}
    </div>}
    {selected && <p className="break-all font-mono text-xs text-muted-foreground">{selected.address}</p>}
    {props.endpointKey && (!selected || !selected.eligible) && <p className="text-xs text-destructive">原选择已不可用，请重新选择。</p>}
  </div>;
}

function NextHop() {
  return <div className="flex items-center gap-2 py-2 pl-4 text-xs text-muted-foreground"><ArrowDown className="h-4 w-4" aria-hidden="true" />下一跳</div>;
}

export function XrayQuickConfigPathCard(props: {
  path: QuickConfigPath; hosts: readonly XrayQuickConfigEntryHost[]; target: XrayQuickConfigTarget;
  onChange: (action: QuickConfigPathAction) => void;
}) {
  const directLanding = props.path.hops.length === 1 && !!props.target.host
    && quickConfigPathEndpoint(props.path.hops[0], props.hosts)?.hostId === props.target.host.id;
  return <div className="min-w-0" aria-label="逐跳路径编辑">
    {props.path.hops.map((key, index) => <div key={index}>
      {index > 0 && <NextHop />}
      <section className="min-w-0 space-y-3 rounded-lg border bg-background p-3 sm:p-4" aria-label={index === 0 ? "入口" : `中转 ${index}`}>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h4 className="flex items-center gap-2 text-sm font-semibold"><span className="flex h-6 w-6 items-center justify-center rounded-full bg-muted text-xs">{index + 1}</span>{index === 0 ? "入口服务器" : `中转 ${index}`}</h4>
          {index === 0 ? <Badge variant="secondary">DNS 指向这里</Badge> : <div className="flex gap-1">
            <Button type="button" variant="ghost" className="h-11 w-11 p-0" aria-label={`上移中转 ${index}`}
              disabled={index === 1} onClick={() => props.onChange({ type: "MOVE", index, direction: -1 })}><ArrowUp className="h-4 w-4" /></Button>
            <Button type="button" variant="ghost" className="h-11 w-11 p-0" aria-label={`下移中转 ${index}`}
              disabled={index === props.path.hops.length - 1} onClick={() => props.onChange({ type: "MOVE", index, direction: 1 })}><ArrowDown className="h-4 w-4" /></Button>
            <Button type="button" variant="ghost" className="h-11 w-11 p-0 text-destructive" aria-label={`删除中转 ${index}`}
              onClick={() => props.onChange({ type: "REMOVE", index })}><Trash2 className="h-4 w-4" /></Button>
          </div>}
        </div>
        <EndpointPicker label={index === 0 ? "入口" : `中转 ${index} `} endpointKey={key} hosts={props.hosts}
          onChange={(endpointKey) => props.onChange({ type: "SET", index, endpointKey })} />
      </section>
    </div>)}
    <Button type="button" variant="outline" className="my-3 h-11 w-full border-dashed" disabled={directLanding || props.path.hops.length >= QUICK_CONFIG_HOP_LIMIT}
      onClick={() => props.onChange({ type: "ADD" })}><Plus className="mr-2 h-4 w-4" />添加中转服务器</Button>
    {props.path.hops.length >= QUICK_CONFIG_HOP_LIMIT && <p className="mb-3 text-xs text-muted-foreground">本版最多添加 8 个中转服务器。</p>}
    {directLanding && <p className="mb-3 text-sm text-muted-foreground">本机直达落地，不需要转发段。要添加中转，请先改选另一台入口服务器。</p>}
    <section className="min-w-0 space-y-2 rounded-lg border bg-muted/30 p-3 sm:p-4">
      <h4 className="flex items-center gap-2 text-sm font-semibold"><LockKeyhole className="h-4 w-4" aria-hidden="true" />最终落地 · 已锁定</h4>
      <p className="break-all text-sm">{props.target.name} · {props.target.protocol}</p>
      <p className="break-all font-mono text-xs text-muted-foreground">{formatXrayEndpoint(props.target.endpoint.address, props.target.endpoint.port)}</p>
    </section>
  </div>;
}

export function XrayQuickConfigPathFlow(props: {
  path: QuickConfigPath; hosts: readonly XrayQuickConfigEntryHost[]; targetName: string; targetHostId?: number;
}) {
  const ingress = quickConfigPathEndpoint(props.path.hops[0], props.hosts);
  if (props.path.hops.length === 1 && props.targetHostId !== undefined && ingress?.hostId === props.targetHostId) {
    return <p className="break-all text-sm">本机直达落地 · {props.targetName}<span className="ml-1 text-xs text-muted-foreground">{ingress.addressFamily === "IPV4" ? "IPv4" : "IPv6"}</span></p>;
  }
  return <ol className="min-w-0 space-y-1 text-sm">
    {props.path.hops.map((key, index) => {
      const endpoint = quickConfigPathEndpoint(key, props.hosts);
      return <li key={index} className="flex min-w-0 items-start gap-2">
        <span className="shrink-0 text-xs text-muted-foreground">{index === 0 ? "入口" : `↓ ${index}`}</span>
        <span className="min-w-0 break-all">{endpoint?.hostName ?? "未选择服务器"}
          {endpoint && <span className="ml-1 text-xs text-muted-foreground">{endpoint.addressFamily === "IPV4" ? "IPv4" : "IPv6"}</span>}
        </span>
      </li>;
    })}
    <li className="flex items-start gap-2"><span className="shrink-0 text-xs text-muted-foreground">落地</span><span className="min-w-0 break-all">{props.targetName}</span></li>
  </ol>;
}
