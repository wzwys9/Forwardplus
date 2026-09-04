import type { AppRouterOutputs } from "@/lib/trpc";
import { formatXrayEndpoint } from "./xrayInboundPresentation";
import { QUICK_CONFIG_CARRIER_LABELS } from "./xrayQuickConfigPaths";

type Detail = AppRouterOutputs["xray"]["quickConfigs"]["detail"];
export function XrayQuickConfigTopologyPaths({ detail }: { detail: Detail }) {
  const topology = detail.activeTopology ?? detail.desiredTopology;
  if (!topology) return null;
  return <section className="min-w-0 space-y-3"><h3 className="font-semibold">访问路径</h3>
    <div className="grid min-w-0 gap-3 sm:grid-cols-2">{topology.routes.map(route => <div key={route.routeId} className="min-w-0 rounded-lg border p-3 text-sm">
      <h4 className="mb-2 font-medium">{route.lineCategory === "DEFAULT" ? "默认" : QUICK_CONFIG_CARRIER_LABELS[route.lineCategory]} · {route.addressFamily === "IPV4" ? "IPv4" : "IPv6"}</h4>
      {route.routeMode === "DIRECT" ? <p className="break-all">直达落地 · {formatXrayEndpoint(route.address, topology.publicPort)}</p>
        : <ol className="space-y-2">{[{ hostId: route.hostId, address: route.address }, ...route.relays].map((hop, index) => <li key={`${hop.hostId}:${index}`} className="break-all">
          {index === 0 ? "入口" : `↓ 中转 ${index}`} · Host #{hop.hostId}<span className="block font-mono text-xs text-muted-foreground">{formatXrayEndpoint(hop.address, topology.publicPort)}</span>
        </li>)}<li className="break-all">↓ 落地 · {detail.targetName}<span className="block font-mono text-xs text-muted-foreground">{formatXrayEndpoint(topology.targetAddress, topology.targetPort)}</span></li></ol>}
    </div>)}</div>
  </section>;
}
