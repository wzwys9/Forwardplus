export const XRAY_INBOUND_STATUSES = [
  "WAITING_SYNC", "INSTALLING", "APPLYING", "RUNNING", "DISABLED",
  "PENDING_DELETE", "ERROR", "HOST_OFFLINE", "UNKNOWN",
] as const;

export type XrayInboundStatus = (typeof XRAY_INBOUND_STATUSES)[number];

export type XrayInboundSummary = {
  id: number;
  name: string;
  host: { id: number; name: string; isOnline: boolean; lastHeartbeat: Date | string | null };
  publicAddress: string;
  listenAddress?: string;
  listenPort: number;
  protocol: string;
  security: string;
  profileId?: string | null;
  clientCount: number;
  desiredEnabled: boolean;
  pendingDelete: boolean;
  deploymentStatus: XrayInboundStatus;
  lastErrorCode: string | null;
  activeOperationId: string | null;
  activeOperationType: string | null;
  externalProxy?: { id: number; name: string; protocol: string; address: string; port: number } | null;
  updatedAt: Date | string;
};

export type XrayInboundStatusView = {
  label: string;
  detail: string | null;
  icon: "clock" | "download" | "refresh" | "running" | "disabled" | "delete" | "error" | "offline" | "unknown";
  badge: "default" | "secondary" | "destructive" | "outline";
  canInspectError: boolean;
};

const STATUS_VIEWS: Record<XrayInboundStatus, Omit<XrayInboundStatusView, "canInspectError">> = {
  WAITING_SYNC: { label: "待同步", detail: "等待 Agent 获取期望配置", icon: "clock", badge: "secondary" },
  INSTALLING: { label: "正在安装", detail: "正在部署受管 Xray", icon: "download", badge: "secondary" },
  APPLYING: { label: "正在应用", detail: "正在验证并切换配置", icon: "refresh", badge: "secondary" },
  RUNNING: { label: "运行中", detail: "已在本机监听", icon: "running", badge: "default" },
  DISABLED: { label: "已停用", detail: "节点不会进入期望配置", icon: "disabled", badge: "outline" },
  PENDING_DELETE: { label: "待删除", detail: "应用完成前旧配置可能仍有效", icon: "delete", badge: "outline" },
  ERROR: { label: "应用失败", detail: null, icon: "error", badge: "destructive" },
  HOST_OFFLINE: { label: "运行状态未知", detail: "Agent 离线，Xray 运行状态未知", icon: "offline", badge: "outline" },
  UNKNOWN: { label: "状态未知", detail: "刷新或查看运行环境以诊断", icon: "unknown", badge: "outline" },
};

export function inboundStatusPresentation(item: XrayInboundSummary): XrayInboundStatusView {
  const status = item.host.isOnline ? item.deploymentStatus : "HOST_OFFLINE";
  const base = STATUS_VIEWS[status];
  const errorDetail = status === "ERROR" && item.lastErrorCode ? `错误码：${item.lastErrorCode}` : base.detail;
  return { ...base, detail: errorDetail, canInspectError: status === "ERROR" };
}

export function formatXrayEndpoint(address: string, port: number): string {
  const value = String(address || "").trim();
  const authority = value.includes(":") && !(value.startsWith("[") && value.endsWith("]")) ? `[${value}]` : value;
  return `${authority}:${port}`;
}

export function formatXrayTime(value: Date | string | null): string {
  if (!value) return "未报告";
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) return "未报告";
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false,
  }).format(date);
}
