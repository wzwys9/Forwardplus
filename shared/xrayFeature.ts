export const XRAY_UI_POLICY_VERSION = "1";

export function isXrayUiFeatureEnabled(
  value: unknown,
  usesCurrentDefaultOnPolicy = false,
): boolean {
  if (!usesCurrentDefaultOnPolicy) return true;
  if (value === undefined) return true;
  if (typeof value !== "string") return false;
  return ["1", "true", "on"].includes(value.trim().toLowerCase());
}
