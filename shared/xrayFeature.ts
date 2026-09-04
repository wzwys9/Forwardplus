export function isXrayUiFeatureEnabled(value: unknown): boolean {
  if (typeof value !== "string") return false;
  return ["1", "true", "on"].includes(value.trim().toLowerCase());
}
