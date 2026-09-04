import {
  XRAY_QUICK_CONFIG_CARRIERS, xrayQuickConfigEndpointKey,
  type XrayQuickConfigCarrier, type XrayQuickConfigEntryHost,
} from "./xrayQuickConfigFlow";

export const QUICK_CONFIG_PATH_LIMIT = 32;
export const QUICK_CONFIG_HOP_LIMIT = 9; // One ingress and up to eight relays.
export const QUICK_CONFIG_CARRIER_LABELS: Record<XrayQuickConfigCarrier, string> = {
  TELECOM: "电信", UNICOM: "联通", MOBILE: "移动", EDUCATION: "教育网",
};
export type QuickConfigPath = { id: string; hops: Array<string | null> };
export type QuickConfigPaths = Record<XrayQuickConfigCarrier, QuickConfigPath[]>;
export type QuickConfigPathAction =
  | { type: "ADD" }
  | { type: "SET"; index: number; endpointKey: string }
  | { type: "REMOVE"; index: number }
  | { type: "MOVE"; index: number; direction: -1 | 1 };

export function emptyQuickConfigPaths(): QuickConfigPaths {
  return { TELECOM: [], UNICOM: [], MOBILE: [], EDUCATION: [] };
}

export function copyQuickConfigPath(path: QuickConfigPath, id: string): QuickConfigPath {
  return { id, hops: [...path.hops] };
}

export function changeQuickConfigPath(path: QuickConfigPath, action: QuickConfigPathAction): QuickConfigPath {
  const hops = [...path.hops];
  if (action.type === "ADD") {
    if (hops.length >= QUICK_CONFIG_HOP_LIMIT) return path;
    hops.push(null);
  } else {
    if (action.index < 0 || action.index >= hops.length) return path;
    if (action.type === "SET") hops[action.index] = action.endpointKey;
    else {
      if (action.index === 0) return path;
      if (action.type === "REMOVE") hops.splice(action.index, 1);
      else {
        const destination = action.index + action.direction;
        if (destination < 1 || destination >= hops.length) return path;
        [hops[action.index], hops[destination]] = [hops[destination], hops[action.index]];
      }
    }
  }
  return { ...path, hops };
}

export function quickConfigPathEndpoint(key: string | null, hosts: readonly XrayQuickConfigEntryHost[]) {
  for (const host of hosts) {
    const endpoint = host.endpoints.find((item) => xrayQuickConfigEndpointKey(host.hostId, item.addressFamily) === key);
    if (endpoint) return { ...endpoint, hostId: host.hostId, hostName: host.name, eligible: host.eligible };
  }
  return null;
}

type PathIssueCode = "MISSING_PATH" | "MISSING_ENDPOINT" | "ENDPOINT_UNAVAILABLE"
  | "REPEATED_HOST" | "LANDING_AS_RELAY" | "NEXT_HOP_CONFLICT";
export type QuickConfigPathIssue = {
  carrier: XrayQuickConfigCarrier; pathId: string | null; code: PathIssueCode; message: string;
};

/** A draft consistency check, NOT a port probe or proof of network reachability. */
export function inspectQuickConfigPaths(paths: QuickConfigPaths, hosts: readonly XrayQuickConfigEntryHost[], landingHostId?: number) {
  const issues: QuickConfigPathIssue[] = [];
  const dnsEntries: Array<{ carrier: XrayQuickConfigCarrier; pathId: string; addressFamily: "IPV4" | "IPV6"; address: string }> = [];
  const listeners = new Map<number, Array<{ next: string; carrier: XrayQuickConfigCarrier; pathId: string }>>();
  for (const carrier of XRAY_QUICK_CONFIG_CARRIERS) {
    if (paths[carrier].length === 0) issues.push({ carrier, pathId: null, code: "MISSING_PATH", message: "尚未添加路径" });
    for (const path of paths[carrier]) {
      const addIssue = (code: PathIssueCode, message: string) => issues.push({ carrier, pathId: path.id, code, message });
      const seen = new Set<number>();
      path.hops.forEach((key, index) => {
        const endpoint = quickConfigPathEndpoint(key, hosts);
        if (!key) { addIssue("MISSING_ENDPOINT", `请为${index === 0 ? "入口" : `中转 ${index}`}选择服务器与地址`); return; }
        if (!endpoint || !endpoint.eligible) { addIssue("ENDPOINT_UNAVAILABLE", "所选服务器离线、地址失效或暂不可用，请重新选择"); return; }
        if (seen.has(endpoint.hostId)) addIssue("REPEATED_HOST", "同一路径不能重复经过同一服务器（IPv4/IPv6 也视为同一台）");
        seen.add(endpoint.hostId);
        if (endpoint.hostId === landingHostId && path.hops.length > 1) {
          addIssue("LANDING_AS_RELAY", "落地主机不能再次作为中转；如需本机端口改写，请使用当前正式快速配置");
        }
        if (index === 0) dnsEntries.push({ carrier, pathId: path.id, addressFamily: endpoint.addressFamily, address: endpoint.address });
        if (endpoint.hostId === landingHostId && path.hops.length === 1) return;
        const next = index === path.hops.length - 1 ? "LANDING" : path.hops[index + 1];
        if (!next) return;
        const entries = listeners.get(endpoint.hostId) ?? [];
        entries.push({ next, carrier, pathId: path.id });
        listeners.set(endpoint.hostId, entries);
      });
    }
  }
  for (const [hostId, entries] of listeners) {
    if (new Set(entries.map((entry) => entry.next)).size < 2) continue;
    const hostName = hosts.find((host) => host.hostId === hostId)?.name ?? `Host #${hostId}`;
    for (const entry of entries) issues.push({ ...entry, code: "NEXT_HOP_CONFLICT",
      message: `${hostName} 的下一跳不一致。同一服务器共用监听，不能按运营商或 IPv4/IPv6 分流到不同下一跳。请统一后续路径或改用其他服务器。` });
  }
  return { issues, dnsEntries, uniqueForwardHostCount: listeners.size };
}
