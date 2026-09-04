import type { AppRouterOutputs } from "@/lib/trpc";
import { ServerCog } from "lucide-react";

import { runtimeServicePresentation, runtimeVersionPresentation } from "./xrayRuntimePresentation";

export type XrayHostRuntimeSummary = AppRouterOutputs["xray"]["runtimes"]["list"]["items"][number];

export function XrayHostRuntimeLink({ runtime }: { runtime: XrayHostRuntimeSummary }) {
  const service = runtimeServicePresentation(runtime);
  const version = runtimeVersionPresentation(runtime);
  const versionLabel = runtime.installedVersion ?? version.label;
  return (
    <a
      href={`/xray?tab=runtime&hostId=${runtime.hostId}`}
      className="flex min-w-0 items-center gap-2 rounded-md border border-border/40 bg-background/30 px-2.5 py-2 text-xs transition-colors hover:border-primary/40 hover:bg-primary/5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
      aria-label={`查看 ${runtime.hostName} 的 Xray 运行环境`}
      title={service.detail ?? "查看 Xray 运行环境"}
    >
      <ServerCog className="h-3.5 w-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
      <span className="min-w-0 truncate">
        Xray：{versionLabel} · {service.label} · {runtime.inboundCount} 个节点
      </span>
    </a>
  );
}
