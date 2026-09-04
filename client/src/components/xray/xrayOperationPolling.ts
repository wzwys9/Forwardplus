const TERMINAL_XRAY_OPERATION_STATUSES = new Set(["SUCCESS", "FAILED", "TIMEOUT", "CANCELLED"]);

export function xrayOperationRefetchInterval(input: {
  status?: unknown;
  createdAt?: unknown;
  now?: number;
  hidden?: boolean;
}): number | false {
  if (TERMINAL_XRAY_OPERATION_STATUSES.has(String(input.status ?? ""))) return false;
  if (input.hidden) return 15_000;
  const createdAt = new Date(input.createdAt as string | number | Date).getTime();
  const elapsed = Number.isFinite(createdAt) ? Math.max(0, (input.now ?? Date.now()) - createdAt) : 0;
  if (elapsed < 15_000) return 1_000;
  if (elapsed < 60_000) return 2_500;
  return 5_000;
}

export function operationQueryPolling(query: { state: { data?: { status?: unknown; createdAt?: unknown } } }) {
  const data = query.state.data;
  return xrayOperationRefetchInterval({
    status: data?.status,
    createdAt: data?.createdAt,
    hidden: typeof document !== "undefined" && document.visibilityState === "hidden",
  });
}
