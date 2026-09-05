import {
  XRAY_QUICK_CONFIG_CARRIERS, xrayQuickConfigEndpointKey,
  type XrayQuickConfigCarrier, type XrayQuickConfigEntryHost,
} from "./xrayQuickConfigFlow";

export const QUICK_CONFIG_PATH_LIMIT = 32;
export const QUICK_CONFIG_HOP_LIMIT = 9; // One ingress and up to eight relays.
export const QUICK_CONFIG_CARRIER_LABELS: Record<XrayQuickConfigCarrier, string> = {
  TELECOM: "电信", UNICOM: "联通", MOBILE: "移动", EDUCATION: "教育网",
};
export type QuickConfigPath = { id: string; hops: Array<string | null>; entryFamilies?: Array<"IPV4" | "IPV6"> };
export type QuickConfigPaths = Record<XrayQuickConfigCarrier, QuickConfigPath[]>;
export type QuickConfigPathAction =
  | { type: "ADD" }
  | { type: "SET"; index: number; endpointKey: string }
  | { type: "TOGGLE_ENTRY_FAMILY"; family: "IPV4" | "IPV6" }
  | { type: "REMOVE"; index: number }
  | { type: "MOVE"; index: number; direction: -1 | 1 };

export function emptyQuickConfigPaths(): QuickConfigPaths {
  return { TELECOM: [], UNICOM: [], MOBILE: [], EDUCATION: [] };
}

export function copyQuickConfigPath(path: QuickConfigPath, id: string): QuickConfigPath {
  return { ...path, id, hops: [...path.hops], ...(path.entryFamilies ? { entryFamilies: [...path.entryFamilies] } : {}) };
}

export function quickConfigEntryKeys(path: QuickConfigPath): string[] {
  const match = path.hops[0]?.match(/^([1-9]\d*):(IPV4|IPV6)$/);
  if (!match) return [];
  return (path.entryFamilies ?? [match[2] as "IPV4" | "IPV6"]).map(family => `${match[1]}:${family}`);
}

function expandedPaths(path: QuickConfigPath): QuickConfigPath[] {
  const entries = quickConfigEntryKeys(path);
  return entries.length ? entries.map(key => ({ id: path.id, hops: [key, ...path.hops.slice(1)] })) : [path];
}

export function mergeQuickConfigPaths(paths: QuickConfigPaths): QuickConfigPaths {
  const result = emptyQuickConfigPaths();
  for (const carrier of XRAY_QUICK_CONFIG_CARRIERS) {
    for (const path of paths[carrier]) {
      const keys = quickConfigEntryKeys(path);
      const existing = result[carrier].find(item => keys.length > 0
        && item.hops[0]?.split(":")[0] === path.hops[0]?.split(":")[0]
        && JSON.stringify(item.hops.slice(1)) === JSON.stringify(path.hops.slice(1))
        && !quickConfigEntryKeys(item).some(key => keys.includes(key)));
      if (existing) existing.entryFamilies = [...quickConfigEntryKeys(existing), ...keys]
        .map(key => key.split(":")[1] as "IPV4" | "IPV6").sort();
      else result[carrier].push(copyQuickConfigPath(path, path.id));
    }
  }
  return result;
}

export function changeQuickConfigPath(path: QuickConfigPath, action: QuickConfigPathAction): QuickConfigPath {
  const hops = [...path.hops];
  if (action.type === "TOGGLE_ENTRY_FAMILY") {
    const keys = quickConfigEntryKeys(path);
    if (!keys.length) return path;
    const families = keys.map(key => key.split(":")[1] as "IPV4" | "IPV6");
    if (families.length === 1 && families.includes(action.family)) return path;
    const entryFamilies = families.includes(action.family) ? families.filter(family => family !== action.family) : [...families, action.family].sort();
    hops[0] = `${keys[0].split(":")[0]}:${entryFamilies[0]}`;
    return { ...path, hops, entryFamilies };
  }
  if (action.type === "ADD") {
    if (hops.length >= QUICK_CONFIG_HOP_LIMIT) return path;
    hops.push(null);
  } else {
    if (action.index < 0 || action.index >= hops.length) return path;
    if (action.type === "SET") {
      hops[action.index] = action.endpointKey;
      if (action.index === 0) return { ...path, hops, entryFamilies: [action.endpointKey.split(":")[1] as "IPV4" | "IPV6"] };
    }
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
  | "REPEATED_HOST" | "LANDING_AS_RELAY" | "NEXT_HOP_CONFLICT" | "PATH_LIMIT" | "DUPLICATE_ENTRY" | "ADDRESS_FAMILY_UNSUPPORTED";
export type QuickConfigPathIssue = {
  carrier: XrayQuickConfigCarrier; pathId: string | null; code: PathIssueCode; message: string;
};

/** A draft consistency check, NOT a port probe or proof of network reachability. */
export function inspectQuickConfigPaths(paths: QuickConfigPaths, hosts: readonly XrayQuickConfigEntryHost[], landingHostId?: number) {
  const endpointByKey = new Map(hosts.flatMap(host => host.endpoints.map(endpoint => [
    xrayQuickConfigEndpointKey(host.hostId, endpoint.addressFamily),
    { ...endpoint, hostId: host.hostId, hostName: host.name, eligible: host.eligible },
  ] as const)));
  const issues: QuickConfigPathIssue[] = [];
  const dnsEntries: Array<{ carrier: XrayQuickConfigCarrier; pathId: string; addressFamily: "IPV4" | "IPV6"; address: string }> = [];
  const listeners = new Map<number, Array<{ next: string; carrier: XrayQuickConfigCarrier; pathId: string }>>();
  for (const carrier of XRAY_QUICK_CONFIG_CARRIERS) {
    if (paths[carrier].length > 32 || Object.values(paths).flat().length > 64) issues.push({ carrier, pathId: null, code: "PATH_LIMIT", message: "每类最多 32 条路径，四类合计最多 64 条" });
    const ingress = new Set<string>();
    if (paths[carrier].flatMap(quickConfigEntryKeys).length > 32) issues.push({ carrier, pathId: null, code: "PATH_LIMIT", message: "每类运营商最多 32 个入口地址（双栈计两个地址）" });
    if (paths[carrier].length === 0) issues.push({ carrier, pathId: null, code: "MISSING_PATH", message: "尚未添加路径" });
    for (const path of paths[carrier].flatMap(expandedPaths)) {
      const addIssue = (code: PathIssueCode, message: string) => issues.push({ carrier, pathId: path.id, code, message });
      if (!path.hops.length || path.hops.length > 9) addIssue("PATH_LIMIT", "每条路径需要入口，且最多 8 个中转");
      if (path.hops[0] && ingress.has(path.hops[0])) addIssue("DUPLICATE_ENTRY", "同一运营商不能重复添加相同入口地址，请修改已有路径");
      if (path.hops[0]) ingress.add(path.hops[0]);
      const seen = new Set<number>();
      path.hops.forEach((key, index) => {
        const endpoint = key ? endpointByKey.get(key) : null;
        if (!key) { addIssue("MISSING_ENDPOINT", `请为${index === 0 ? "入口" : `中转 ${index}`}选择服务器与地址`); return; }
        if (!endpoint || !endpoint.eligible) { addIssue("ENDPOINT_UNAVAILABLE", "所选服务器离线、地址失效或暂不可用，请重新选择"); return; }
        if (seen.has(endpoint.hostId)) addIssue("REPEATED_HOST", "同一路径不能重复经过同一服务器（IPv4/IPv6 也视为同一台）");
        seen.add(endpoint.hostId);
        if (endpoint.hostId === landingHostId && path.hops.length > 1) {
          addIssue("LANDING_AS_RELAY", "落地主机不能再次作为中转；本机直达路径不能再添加中转");
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
    const locations = [...new Set(entries.map(entry => `${QUICK_CONFIG_CARRIER_LABELS[entry.carrier]}路径 ${paths[entry.carrier].findIndex(path => path.id === entry.pathId) + 1}`))].join("、");
    for (const entry of entries) issues.push({ ...entry, code: "NEXT_HOP_CONFLICT",
      message: `${hostName} 的下一跳不一致（${locations}）。同一服务器共用监听，请统一后续路径或改用其他服务器。` });
  }
  if (listeners.size > 64) issues.push({ carrier: "TELECOM", pathId: null, code: "PATH_LIMIT", message: "一个快速配置最多使用 64 台转发服务器" });
  if (dnsEntries.length > 64) issues.push({ carrier: "TELECOM", pathId: null, code: "PATH_LIMIT", message: "四类运营商合计最多 64 个入口地址（双栈计两个地址）" });
  return { issues, dnsEntries, uniqueForwardHostCount: listeners.size };
}

export function quickConfigPathsFromEntries(entries: Record<XrayQuickConfigCarrier, string[]>): QuickConfigPaths {
  const paths = emptyQuickConfigPaths();
  for (const carrier of XRAY_QUICK_CONFIG_CARRIERS) paths[carrier] = entries[carrier].map((key, index) => ({ id: `${carrier}-${index}`, hops: [key] }));
  return mergeQuickConfigPaths(paths);
}

export function quickConfigPathInput(path: QuickConfigPath) {
  const hops: Array<{ hostId: number; addressFamily: "IPV4" | "IPV6" }> = [];
  for (const key of path.hops) {
    const match = key?.match(/^([1-9]\d*):(IPV4|IPV6)$/);
    if (!match || !Number.isSafeInteger(Number(match[1]))) return null;
    hops.push({ hostId: Number(match[1]), addressFamily: match[2] as "IPV4" | "IPV6" });
  }
  if (!hops.length || hops.length > 9) return null;
  return { ...hops[0], ...(hops.length > 1 ? { relays: hops.slice(1) } : {}) };
}

export function quickConfigPathInputs(path: QuickConfigPath) {
  return expandedPaths(path).map(quickConfigPathInput);
}
