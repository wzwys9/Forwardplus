type RuntimePresentationInput = {
  isAgentOnline: boolean;
  installedVersion: string | null;
  targetVersion: string | null;
  serviceStatus: "RUNNING" | "STOPPED" | "ERROR" | "UNKNOWN";
  hasUpgrade: boolean;
  isNewerThanTarget: boolean;
  unavailableReasonCode: string | null;
  activeOperationId?: string | null;
};

export type XrayRuntimeAction = "INSTALL" | "UPGRADE" | "SYNC" | "RESTART";

export type RuntimeActionPresentation = {
  type: XrayRuntimeAction;
  label: string;
  destructive: boolean;
  disabledReason: string | null;
};

function actionDisabledReason(runtime: RuntimePresentationInput, needsArtifact: boolean): string | null {
  if (runtime.activeOperationId) return "OPERATION_CONFLICT";
  if (!runtime.isAgentOnline) return "HOST_OFFLINE";
  if (runtime.unavailableReasonCode && (needsArtifact || runtime.unavailableReasonCode !== "ARTIFACT_UNAVAILABLE")) {
    return runtime.unavailableReasonCode;
  }
  return null;
}

export function runtimeActionPresentation(runtime: RuntimePresentationInput): RuntimeActionPresentation[] {
  if (!runtime.installedVersion) {
    return [{ type: "INSTALL", label: "安装", destructive: true, disabledReason: actionDisabledReason(runtime, true) }];
  }
  if (runtime.hasUpgrade) {
    return [{ type: "UPGRADE", label: `升级至 ${runtime.targetVersion ?? "目标版本"}`, destructive: true, disabledReason: actionDisabledReason(runtime, true) }];
  }
  if (runtime.isNewerThanTarget) {
    return runtime.serviceStatus === "RUNNING"
      ? [{ type: "RESTART", label: "重启", destructive: true, disabledReason: actionDisabledReason(runtime, false) }]
      : [];
  }
  const actions: RuntimeActionPresentation[] = [];
  if (runtime.targetVersion && runtime.installedVersion === runtime.targetVersion) {
    actions.push({ type: "SYNC", label: "同步配置", destructive: true, disabledReason: actionDisabledReason(runtime, false) });
  }
  if (runtime.serviceStatus === "RUNNING") {
    actions.push({ type: "RESTART", label: "重启", destructive: true, disabledReason: actionDisabledReason(runtime, false) });
  }
  return actions;
}

export type RuntimeVersionPresentation = {
  kind: "UNINSTALLED" | "CURRENT" | "UPGRADE_AVAILABLE" | "NEWER_THAN_TARGET" | "UNKNOWN";
  label: string;
  detail: string | null;
  artifactLabel: string | null;
};

export function runtimeVersionPresentation(runtime: RuntimePresentationInput): RuntimeVersionPresentation {
  const artifactLabel = runtime.unavailableReasonCode === "ARTIFACT_UNAVAILABLE" ? "缺少已验证制品" : null;
  if (!runtime.installedVersion) {
    return { kind: "UNINSTALLED", label: "未安装", detail: null, artifactLabel };
  }
  if (runtime.isNewerThanTarget) {
    return { kind: "NEWER_THAN_TARGET", label: "高于目标版本", detail: "不自动降级", artifactLabel };
  }
  if (runtime.hasUpgrade) {
    return { kind: "UPGRADE_AVAILABLE", label: "可升级", detail: runtime.targetVersion ? `目标 ${runtime.targetVersion}` : null, artifactLabel };
  }
  if (runtime.targetVersion && runtime.installedVersion === runtime.targetVersion) {
    return { kind: "CURRENT", label: "当前版本", detail: null, artifactLabel };
  }
  return { kind: "UNKNOWN", label: "版本状态未知", detail: null, artifactLabel };
}

export function runtimeServicePresentation(runtime: RuntimePresentationInput): {
  label: string;
  detail: string | null;
  tone: "success" | "neutral" | "danger" | "warning";
} {
  if (!runtime.isAgentOnline) {
    return { label: "运行状态未知", detail: "Agent 离线，Xray 运行状态未知", tone: "warning" };
  }
  if (runtime.serviceStatus === "RUNNING") return { label: "运行中", detail: null, tone: "success" };
  if (runtime.serviceStatus === "STOPPED") return { label: "已停止", detail: null, tone: "neutral" };
  if (runtime.serviceStatus === "ERROR") return { label: "错误", detail: null, tone: "danger" };
  return { label: "未知", detail: null, tone: "warning" };
}
