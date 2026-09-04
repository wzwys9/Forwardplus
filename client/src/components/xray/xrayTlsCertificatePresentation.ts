export type XrayTlsCertificateStatus = "VALID" | "EXPIRING_30" | "EXPIRING_14" | "EXPIRING_7" | "EXPIRED";

export function certificateStatusPresentation(status: XrayTlsCertificateStatus) {
  if (status === "VALID") return { label: "有效", tone: "success" as const };
  if (status === "EXPIRING_30") return { label: "30 天内到期", tone: "warning" as const };
  if (status === "EXPIRING_14") return { label: "14 天内到期", tone: "warning" as const };
  if (status === "EXPIRING_7") return { label: "7 天内到期", tone: "danger" as const };
  return { label: "已过期", tone: "danger" as const };
}

export function certificateDraftError(input: { certificatePem: string; privateKeyPem: string }): string | null {
  const encoder = new TextEncoder();
  if (!input.certificatePem.trim()) return "请提供完整证书链 PEM";
  if (encoder.encode(input.certificatePem).byteLength > 16 * 1024) return "证书链不能超过 16 KiB";
  if (!input.privateKeyPem.trim()) return "请提供未加密私钥 PEM";
  if (encoder.encode(input.privateKeyPem).byteLength > 8 * 1024) return "私钥不能超过 8 KiB";
  return null;
}
