export const XRAY_UI_TABS = ["nodes", "external-proxies", "quick-config", "runtime", "certificates", "managed-services"] as const;
export type XrayUiTab = typeof XRAY_UI_TABS[number];

export const XRAY_NODE_STATUSES = [
  "WAITING_SYNC", "INSTALLING", "APPLYING", "RUNNING", "DISABLED",
  "PENDING_DELETE", "ERROR", "HOST_OFFLINE", "UNKNOWN",
] as const;
export const XRAY_RUNTIME_STATUSES = ["RUNNING", "STOPPED", "ERROR", "UNKNOWN"] as const;
export const XRAY_MANAGED_SERVICE_STATUSES = ["WAITING_SYNC", "RUNNING", "DISABLED", "PENDING_DELETE", "ERROR"] as const;

export type XrayLocationState = {
  tab: XrayUiTab;
  search: string;
  status: string | null;
  hostId: number | null;
  page: number;
  operationId: string | null;
  operationScope: "runtime" | null;
  inboundId: number | null;
};

type XrayUiAccessInput = {
  authLoading: boolean;
  userRole: string | null | undefined;
  featureLoading: boolean;
  featureError: boolean;
  featureEnabled: boolean;
};

export function resolveXrayUiAccess(input: XrayUiAccessInput): "WAIT" | "LOGIN" | "HOME" | "ALLOW" {
  if (input.authLoading) return "WAIT";
  if (!input.userRole) return "LOGIN";
  if (input.userRole !== "admin") return "HOME";
  if (input.featureLoading) return "WAIT";
  if (input.featureError) return "HOME";
  return input.featureEnabled ? "ALLOW" : "HOME";
}

export function shouldShowXraySidebar(userRole: string | null | undefined, featureEnabled: boolean, featureError = false): boolean {
  return userRole === "admin" && featureEnabled && !featureError;
}

function allowedStatuses(tab: XrayUiTab): ReadonlySet<string> {
  return new Set(tab === "nodes" ? XRAY_NODE_STATUSES : tab === "runtime" ? XRAY_RUNTIME_STATUSES
    : tab === "managed-services" ? XRAY_MANAGED_SERVICE_STATUSES : []);
}

function positiveInteger(value: unknown, fallback: number): number {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

export function resolveXrayLocation(location: string): XrayLocationState {
  const query = String(location || "").split("?")[1]?.split("#")[0] ?? "";
  const params = new URLSearchParams(query);
  const rawTab = params.get("tab");
  const tab: XrayUiTab = rawTab === "external-proxies" || rawTab === "quick-config" || rawTab === "runtime" || rawTab === "certificates" || rawTab === "managed-services" ? rawTab : "nodes";
  const search = String(params.get("search") ?? "").trim().slice(0, 128);
  const rawStatus = String(params.get("status") ?? "");
  const status = allowedStatuses(tab).has(rawStatus) ? rawStatus : null;
  const hostId = positiveInteger(params.get("hostId"), 0) || null;
  const page = positiveInteger(params.get("page"), 1);
  const rawOperationId = String(params.get("operationId") ?? "");
  const operationId = /^[A-Za-z0-9._:-]{1,64}$/.test(rawOperationId) ? rawOperationId : null;
  const operationScope = operationId && params.get("operationScope") === "runtime" ? "runtime" : null;
  const inboundId = positiveInteger(params.get("inboundId"), 0) || null;
  return { tab, search, status, hostId, page, operationId, operationScope, inboundId };
}

export function buildXrayLocation(location: string, patch: Partial<XrayLocationState>): string {
  const current = resolveXrayLocation(location);
  const nextTab = XRAY_UI_TABS.includes(patch.tab as XrayUiTab) ? patch.tab as XrayUiTab : current.tab;
  const nextSearch = String(patch.search ?? current.search).trim().slice(0, 128);
  const requestedStatus = patch.status === undefined ? current.status : patch.status;
  const nextStatus = requestedStatus && allowedStatuses(nextTab).has(requestedStatus) ? requestedStatus : null;
  const nextHostId = patch.hostId === undefined ? current.hostId : positiveInteger(patch.hostId, 0) || null;
  const nextPage = patch.page === undefined ? current.page : positiveInteger(patch.page, 1);
  const requestedOperationId = patch.operationId === undefined ? current.operationId : patch.operationId;
  const nextOperationId = requestedOperationId && /^[A-Za-z0-9._:-]{1,64}$/.test(requestedOperationId) ? requestedOperationId : null;
  const requestedOperationScope = patch.operationScope === undefined ? current.operationScope : patch.operationScope;
  const nextOperationScope = nextOperationId && requestedOperationScope === "runtime" ? "runtime" : null;
  const nextInboundId = patch.inboundId === undefined ? current.inboundId : positiveInteger(patch.inboundId, 0) || null;
  const params = new URLSearchParams();
  if (nextTab !== "nodes") params.set("tab", nextTab);
  if (nextSearch) params.set("search", nextSearch);
  if (nextStatus) params.set("status", nextStatus);
  if (nextHostId) params.set("hostId", String(nextHostId));
  if (nextPage > 1) params.set("page", String(nextPage));
  if (nextOperationId) params.set("operationId", nextOperationId);
  if (nextOperationScope) params.set("operationScope", nextOperationScope);
  if (nextInboundId) params.set("inboundId", String(nextInboundId));
  const query = params.toString();
  return `/xray${query ? `?${query}` : ""}`;
}
