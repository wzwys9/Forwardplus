import { quickConfigPathEngineCompatible } from "../../../../shared/xrayQuickConfigForwardEngines";
import type { XrayQuickConfigCarrier, XrayQuickConfigEngine, XrayQuickConfigEntryHost, XrayQuickConfigTarget } from "./xrayQuickConfigFlow";
import { changeQuickConfigPath, inspectQuickConfigPaths, quickConfigEntryKeys, quickConfigPathEndpoint,
  type QuickConfigPath, type QuickConfigPathAction, type QuickConfigPathIssue, type QuickConfigPaths } from "./xrayQuickConfigPaths";

function familyIssues(path: QuickConfigPath, hosts: readonly XrayQuickConfigEntryHost[], target: XrayQuickConfigTarget,
  engine: XrayQuickConfigEngine) {
  const issues: Array<{ index: number; message: string }> = [];
  const entries = quickConfigEntryKeys(path);
  for (let index = 0; index < path.hops.length; index++) {
    const keys = index === 0 ? entries : [path.hops[index]];
    const last = index === path.hops.length - 1;
    const next = last ? target.endpoint : quickConfigPathEndpoint(path.hops[index + 1], hosts);
    if (!next) continue;
    for (const key of keys) {
      const source = quickConfigPathEndpoint(key, hosts);
      if (!source || path.hops.length === 1 && source.hostId === target.host?.id) continue;
      if (!quickConfigPathEngineCompatible(engine, [[source]], next.address, undefined, hosts)) {
        const kernel = engine === "iptables" || engine === "nftables";
        issues.push({ index, message: kernel ? `${source.hostName}：${engine} 不支持此段跨 IPv4/IPv6 或域名下一跳`
          : `${source.hostName} 未登记下一跳需要的出站地址族，请添加双栈中转或调整下一跳地址` });
      }
    }
  }
  return issues;
}

export function inspectQuickConfigPathDraft(paths: QuickConfigPaths, hosts: readonly XrayQuickConfigEntryHost[],
  target: XrayQuickConfigTarget, engine?: XrayQuickConfigEngine | null) {
  const result = inspectQuickConfigPaths(paths, hosts, target.host?.id);
  if (engine) for (const carrier of Object.keys(paths) as XrayQuickConfigCarrier[]) {
    for (const path of paths[carrier]) for (const issue of familyIssues(path, hosts, target, engine)) {
      result.issues.push({ carrier, pathId: path.id, code: "ADDRESS_FAMILY_UNSUPPORTED", message: issue.message });
    }
  }
  return result;
}

const identity = (issue: QuickConfigPathIssue) => `${issue.carrier}:${issue.pathId}:${issue.code}:${issue.message}`;

/** Return a visible reason only when the action introduces a new hard conflict.
 * Existing invalid drafts must remain editable; empty hops aren't decisions yet. */
export function quickConfigPathActionReason(paths: QuickConfigPaths, carrier: XrayQuickConfigCarrier, pathId: string,
  action: QuickConfigPathAction, hosts: readonly XrayQuickConfigEntryHost[], target: XrayQuickConfigTarget,
  engine?: XrayQuickConfigEngine | null): string | null {
  return createQuickConfigPathActionChecker(paths, carrier, pathId, hosts, target, engine)(action);
}

export function createQuickConfigPathActionChecker(paths: QuickConfigPaths, carrier: XrayQuickConfigCarrier, pathId: string,
  hosts: readonly XrayQuickConfigEntryHost[], target: XrayQuickConfigTarget, engine?: XrayQuickConfigEngine | null) {
  const path = paths[carrier].find(item => item.id === pathId);
  const previous = new Set(inspectQuickConfigPaths(paths, hosts, target.host?.id).issues.map(identity));
  const before = new Set(path && engine ? familyIssues(path, hosts, target, engine).map(issue => `${issue.index}:${issue.message}`) : []);
  const cache = new Map<string, string | null>();
  const check = (action: QuickConfigPathAction): string | null => {
  if (!path) return "路径已不存在";
  const changed = changeQuickConfigPath(path, action);
  if (action.type === "SET") {
    const endpoint = quickConfigPathEndpoint(action.endpointKey, hosts);
    if (!endpoint?.eligible) return "服务器离线、引擎不兼容或地址不可用";
  }
  const nextPaths = { ...paths, [carrier]: paths[carrier].map(item => item.id === pathId ? changed : item) };
  const structural = inspectQuickConfigPaths(nextPaths, hosts, target.host?.id).issues.find(issue =>
    (issue.code === "PATH_LIMIT" || issue.carrier === carrier && issue.pathId === pathId) &&
    issue.code !== "MISSING_ENDPOINT" && issue.code !== "MISSING_PATH" && !previous.has(identity(issue)));
  if (structural) return structural.message;
  if (!engine) return null;
  const failures = familyIssues(changed, hosts, target, engine).filter(issue => !before.has(`${issue.index}:${issue.message}`));
  if (!failures.length) return null;
  // A process engine can complete an unfinished last leg by adding a dual-stack
  // bridge. Do not gray out the IPv4 ingress just because the landing is IPv6.
  if (engine !== "iptables" && engine !== "nftables" && changed.hops.length < 9
    && failures.every(issue => issue.index === changed.hops.length - 1)) {
    const canBridge = hosts.some(host => host.eligible && host.endpoints.some(endpoint => {
      const bridged = { ...changed, hops: [...changed.hops, `${host.hostId}:${endpoint.addressFamily}`] };
      const probe = { ...nextPaths, [carrier]: nextPaths[carrier].map(item => item.id === pathId ? bridged : item) };
      return !inspectQuickConfigPathDraft(probe, hosts, target, engine).issues.some(issue => issue.carrier === carrier && issue.pathId === pathId);
    }));
    if (canBridge) return null;
  }
  return failures[0].message;
  };
  return (action: QuickConfigPathAction) => {
    const key = JSON.stringify(action);
    if (!cache.has(key)) cache.set(key, check(action));
    return cache.get(key)!;
  };
}
