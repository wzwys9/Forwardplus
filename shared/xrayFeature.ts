export function isXrayUiFeatureEnabled(
  value: unknown,
  migratedFromForwardx = false,
): boolean {
  if (value === undefined) return migratedFromForwardx;
  if (typeof value !== "string") return false;
  return ["1", "true", "on"].includes(value.trim().toLowerCase());
}
