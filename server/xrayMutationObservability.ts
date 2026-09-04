import { recordConfigAuditEvent, type AuditResourceType } from "./configAudit";
import { appendXrayStructuredLog, projectXrayAuditFields } from "./xrayObservability";

type XrayAuditResourceType = Extract<AuditResourceType, "xray_inbound" | "xray_client" | "xray_access_entry" | "xray_tls_certificate" | "xray_runtime" | "xray_managed_service" | "xray_managed_service_account">;

export async function recordXrayMutationObservability(input: {
  event: string;
  resourceType: XrayAuditResourceType;
  resourceId: number;
  hostId: number;
  action: "create" | "update" | "delete" | "dispatch";
  fields: unknown;
  before?: unknown;
}) {
  const after = projectXrayAuditFields(input.fields);
  const before = input.before === undefined ? undefined : projectXrayAuditFields(input.before);
  appendXrayStructuredLog("info", input.event, after);
  return recordConfigAuditEvent({
    resourceType: input.resourceType,
    resourceId: input.resourceId,
    hostId: input.hostId,
    action: input.action,
    before,
    after,
  });
}
