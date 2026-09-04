import net from "node:net";

import { XRAY_AGENT_ERROR_CODES, XrayObservedListenerSchema } from "../shared/xrayTypes";
import { paginateItems, pageResult, pageWindowForTotal } from "../shared/pagination";
import { AGENT_VERSION } from "../shared/versions";
import {
  findKnownXrayProfileById,
  listKnownXrayProfiles,
  resolveStoredXrayInboundDefinition,
} from "../shared/xrayProfiles";
import { isAgentVersionAtLeast, compareVersions } from "./agentRouteUtils";
import { boolLiteral, quoteIdentifier } from "./dbCompat";
import { queryRaw } from "./dbRuntime";
import { HOST_ONLINE_TTL_MS } from "./hostHeartbeatPolicy";
import { listXrayAccessEntries } from "./repositories/xrayAccessRepository";
import { getXrayRuntimeReport, listXrayClientsByInbound } from "./repositories/xrayRepository";
import { XRAY_ARTIFACT_MANIFEST, XRAY_DEFAULT_VERSION } from "./xrayArtifacts";

export const XRAY_DEPLOYMENT_STATUSES = [
  "WAITING_SYNC", "INSTALLING", "APPLYING", "RUNNING", "DISABLED", "PENDING_DELETE", "ERROR", "HOST_OFFLINE", "UNKNOWN",
] as const;
export type XrayDeploymentStatus = (typeof XRAY_DEPLOYMENT_STATUSES)[number];

export const XRAY_UNAVAILABLE_REASONS = [
  "AGENT_OFFLINE", "HEARTBEAT_STALE", "AGENT_UPGRADE_REQUIRED", "PLATFORM_UNSUPPORTED", "ARTIFACT_UNAVAILABLE", "PUBLIC_IPV4_MISSING",
] as const;
export type XrayUnavailableReason = (typeof XRAY_UNAVAILABLE_REASONS)[number];

const SAFE_ERROR_CODES = new Set<string>([
  ...XRAY_AGENT_ERROR_CODES,
  "HOST_NOT_FOUND", "HOST_OFFLINE", "HEARTBEAT_STALE", "AGENT_CAPABILITY_MISSING", "PLATFORM_UNSUPPORTED",
  "ARTIFACT_UNAVAILABLE", "PUBLIC_ADDRESS_REQUIRED", "PORT_OUT_OF_RANGE", "PORT_RESERVATION_EXPIRED",
  "PORT_RESERVATION_MISMATCH", "REALITY_TARGET_INVALID", "INBOUND_NOT_FOUND", "CLIENT_NOT_FOUND",
  "CONFIG_GENERATION_CONFLICT", "OPERATION_CONFLICT", "DOWNGRADE_NOT_ALLOWED", "SENSITIVE_DATA_UNAVAILABLE",
  "UDP_CAPABILITY_REQUIRED",
]);

type DatabaseRow = Record<string, unknown>;

function numberValue(value: unknown, fallback = 0): number {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : fallback;
}

function booleanValue(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || value === "true";
}

function nullableString(value: unknown): string | null {
  if (value === null || value === undefined || value === "") return null;
  return String(value);
}

function dateValue(value: unknown): Date | null {
  if (value === null || value === undefined || value === "") return null;
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? new Date(value.getTime()) : null;
  if (typeof value === "number" || /^\d+(?:\.\d+)?$/.test(String(value))) {
    const numeric = Number(value);
    const date = new Date(numeric < 10_000_000_000 ? numeric * 1000 : numeric);
    return Number.isFinite(date.getTime()) ? date : null;
  }
  const date = new Date(String(value));
  return Number.isFinite(date.getTime()) ? date : null;
}

function safeErrorCode(value: unknown): string | null {
  const code = nullableString(value);
  return code ? (SAFE_ERROR_CODES.has(code) ? code : "INTERNAL_ERROR") : null;
}

function genericRuntimeErrorMessage(errorCode: string | null): string | null {
  return errorCode ? "Managed Xray runtime reported an error" : null;
}

function genericOperationErrorMessage(type: string, errorCode: string | null): string | null {
  return errorCode ? `Xray ${type.toLowerCase()} operation did not complete` : null;
}

function heartbeatState(row: DatabaseRow) {
  const lastHeartbeat = dateValue(row.lastHeartbeat);
  const storedOnline = booleanValue(row.isOnline);
  const fresh = !!lastHeartbeat && Date.now() - lastHeartbeat.getTime() <= HOST_ONLINE_TTL_MS;
  return { lastHeartbeat, storedOnline, fresh, isOnline: storedOnline && fresh };
}

function ipv4Number(address: string): number {
  return address.split(".").reduce((value, part) => value * 256 + Number(part), 0) >>> 0;
}

function isUsablePublicIpv4(value: unknown): value is string {
  const address = String(value ?? "").trim();
  if (net.isIP(address) !== 4) return false;
  const ip = ipv4Number(address);
  const inRange = (base: string, bits: number) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (ip & mask) === (ipv4Number(base) & mask);
  };
  return ![
    ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
    ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
    ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
  ].some(([base, bits]) => inRange(base as string, bits as number));
}

function hostPublicIpv4(row: DatabaseRow): string | null {
  if (isUsablePublicIpv4(row.ipv4)) return String(row.ipv4).trim();
  if (isUsablePublicIpv4(row.ip)) return String(row.ip).trim();
  return null;
}

function capabilityPlatform(row: DatabaseRow) {
  return { os: nullableString(row.supportedOS), arch: nullableString(row.supportedArch) };
}

function artifactRowMatchesManifest(row: DatabaseRow): boolean {
  const entry = XRAY_ARTIFACT_MANIFEST.find((candidate) => (
    candidate.version === row.artifactVersion && candidate.os === row.artifactOS && candidate.arch === row.artifactArch
  ));
  return !!entry
    && row.artifactPackageFormat === entry.packageFormat
    && row.artifactStorageKey === entry.storageKey
    && row.artifactSha256 === entry.sha256
    && Number(row.artifactFileSize) === entry.fileSize
    && row.artifactStatus === "VERIFIED"
    && row.artifactSource === entry.source
    && row.artifactVerifiedAt !== null
    && row.artifactVerifiedAt !== undefined;
}

function unavailableReason(row: DatabaseRow, requirePublicIpv4: boolean): XrayUnavailableReason | null {
  const heartbeat = heartbeatState(row);
  if (!heartbeat.storedOnline) return "AGENT_OFFLINE";
  if (!heartbeat.fresh) return "HEARTBEAT_STALE";
  if (!isAgentVersionAtLeast(nullableString(row.agentVersion), AGENT_VERSION)) return "AGENT_UPGRADE_REQUIRED";
  const { os, arch } = capabilityPlatform(row);
  const capabilityVersion = numberValue(row.capabilitySchemaVersion);
  if (capabilityVersion !== 1) return os || arch || row.capabilityErrorCode ? "PLATFORM_UNSUPPORTED" : "AGENT_UPGRADE_REQUIRED";
  if (os !== "linux" || (arch !== "amd64" && arch !== "arm64")) return "PLATFORM_UNSUPPORTED";
  if (!booleanValue(row.supportsArtifactInstall) || !booleanValue(row.supportsPortProbe) || !booleanValue(row.supportsRealityScan)) {
    return "AGENT_UPGRADE_REQUIRED";
  }
  if (!artifactRowMatchesManifest(row)) return "ARTIFACT_UNAVAILABLE";
  if (requirePublicIpv4 && !hostPublicIpv4(row)) return "PUBLIC_IPV4_MISSING";
  return null;
}

function hostCapabilityJoinSql() {
  const q = quoteIdentifier;
  return `LEFT JOIN ${q("xray_runtime_reports")} r ON r.${q("hostId")} = h.${q("id")}
    LEFT JOIN ${q("xray_artifacts")} a ON a.${q("version")} = ? AND a.${q("os")} = r.${q("supportedOS")} AND a.${q("arch")} = r.${q("supportedArch")}`;
}

function hostCapabilityColumns() {
  const q = quoteIdentifier;
  return [
    `h.${q("id")} AS ${q("hostId")}`, `h.${q("name")} AS ${q("hostName")}`, `h.${q("ip")} AS ${q("ip")}`,
    `h.${q("ipv4")} AS ${q("ipv4")}`, `h.${q("isOnline")} AS ${q("isOnline")}`, `h.${q("lastHeartbeat")} AS ${q("lastHeartbeat")}`,
    `h.${q("agentVersion")} AS ${q("agentVersion")}`,
    ...["capabilitySchemaVersion", "supportedOS", "supportedArch", "supportsArtifactInstall", "supportsPortProbe", "supportsRealityScan", "capabilityErrorCode"]
      .map((column) => `r.${q(column)} AS ${q(column)}`),
    `a.${q("version")} AS ${q("artifactVersion")}`, `a.${q("os")} AS ${q("artifactOS")}`, `a.${q("arch")} AS ${q("artifactArch")}`,
    `a.${q("packageFormat")} AS ${q("artifactPackageFormat")}`, `a.${q("storageKey")} AS ${q("artifactStorageKey")}`,
    `a.${q("sha256")} AS ${q("artifactSha256")}`, `a.${q("fileSize")} AS ${q("artifactFileSize")}`,
    `a.${q("status")} AS ${q("artifactStatus")}`, `a.${q("source")} AS ${q("artifactSource")}`,
    `a.${q("verifiedAt")} AS ${q("artifactVerifiedAt")}`,
  ].join(", ");
}

export async function listXrayHostOptions() {
  const q = quoteIdentifier;
  const rows = await queryRaw<DatabaseRow>(
    `SELECT ${hostCapabilityColumns()} FROM ${q("hosts")} h ${hostCapabilityJoinSql()} ORDER BY h.${q("name")} ASC, h.${q("id")} ASC`,
    [XRAY_DEFAULT_VERSION],
  );
  return rows.map((row) => {
    const heartbeat = heartbeatState(row);
    const reason = unavailableReason(row, true);
    const platform = capabilityPlatform(row);
    return {
      id: numberValue(row.hostId),
      name: String(row.hostName ?? ""),
      publicIpv4: hostPublicIpv4(row),
      isOnline: heartbeat.isOnline,
      lastHeartbeat: heartbeat.lastHeartbeat,
      capabilityVersion: numberValue(row.capabilitySchemaVersion),
      os: platform.os,
      arch: platform.arch,
      canCreateXrayInbound: reason === null,
      unavailableReasonCode: reason,
    };
  });
}

export async function getXrayProfileCatalog(hostId?: number) {
  const runtime = hostId === undefined ? null : await getXrayRuntimeReport(hostId);
  const supportsUdp = runtime?.capabilitySchemaVersion === 1
    && runtime.supportsUdpPortProbe === true
    && runtime.supportsUdpListenerReadiness === true;
  return listKnownXrayProfiles().map(({ status, ...profile }) => {
    const requiresUdp = profile.listenerNetworks.includes("UDP");
    const unavailableReasonCode = requiresUdp && hostId !== undefined && !supportsUdp
      ? "UDP_CAPABILITY_REQUIRED" as const
      : status !== "AVAILABLE"
        ? "NOT_IMPLEMENTED" as const
        : null;
    return { ...profile, isAvailable: unavailableReasonCode === null, unavailableReasonCode };
  });
}

function parseListeners(value: unknown) {
  try {
    const raw = JSON.parse(String(value ?? "[]"));
    if (!Array.isArray(raw) || raw.length > 256) return [];
    const parsed = raw.map((listener) => XrayObservedListenerSchema.safeParse(listener));
    return parsed.every((listener) => listener.success) ? parsed.map((listener) => listener.data!) : [];
  } catch {
    return [];
  }
}

function activeOperation(status: unknown) {
  return status === "QUEUED" || status === "RUNNING";
}

function operationRuntimeStage(value: unknown): "INSTALL" | "INSTALL_COMPLETE" | null {
  try {
    const parsed = JSON.parse(String(value ?? ""));
    return parsed?.schemaVersion === 1 && (parsed.stage === "INSTALL" || parsed.stage === "INSTALL_COMPLETE")
      ? parsed.stage
      : null;
  } catch {
    return null;
  }
}

function inboundStatus(row: DatabaseRow): XrayDeploymentStatus {
  if (booleanValue(row.pendingDelete)) return "PENDING_DELETE";
  if (!booleanValue(row.inboundEnabled)) return "DISABLED";
  if (!heartbeatState(row).isOnline) return "HOST_OFFLINE";
  const operationStatus = String(row.operationStatus ?? "");
  const operationType = String(row.operationType ?? "");
  if (["FAILED", "TIMEOUT", "CANCELLED"].includes(operationStatus)) return "ERROR";
  const lastErrorGeneration = numberValue(row.runtimeErrorGeneration, -1);
  if (row.runtimeErrorCode && lastErrorGeneration >= numberValue(row.inboundDesiredGeneration)) return "ERROR";
  if (activeOperation(operationStatus) && (operationType === "INSTALL" || operationType === "UPGRADE"
    || operationRuntimeStage(row.operationRequestMetaJson) === "INSTALL")) return "INSTALLING";
  if (operationStatus === "RUNNING" && operationType === "SYNC") return "APPLYING";
  if (operationStatus === "QUEUED" && operationType === "SYNC") return "WAITING_SYNC";
  const desiredGeneration = numberValue(row.deploymentDesiredGeneration);
  const appliedGeneration = numberValue(row.appliedGeneration);
  const desiredHash = nullableString(row.desiredConfigHash);
  const appliedHash = nullableString(row.appliedConfigHash);
  const targetVersion = nullableString(row.targetVersion);
  const listenerNetworks = resolveStoredXrayInboundDefinition(row)?.profile.listenerNetworks
    .map((network) => network.toLowerCase())
    .filter((network): network is "tcp" | "udp" => network === "tcp" || network === "udp") ?? [];
  const listeners = parseListeners(row.listenersJson);
  const listenerReady = listenerNetworks.length > 0 && listenerNetworks.every((network) => listeners.some((listener) => (
    listener.runtimeTag === row.runtimeTag && listener.network === network
      && listener.port === numberValue(row.listenPort) && listener.status === "READY"
  )));
  if (desiredHash && desiredGeneration === appliedGeneration && desiredHash === appliedHash
    && row.runtimeServiceStatus === "RUNNING" && row.installedVersion === targetVersion && row.runningVersion === targetVersion
    && listenerReady) return "RUNNING";
  if (desiredGeneration > appliedGeneration || (desiredHash && desiredHash !== appliedHash)) return "WAITING_SYNC";
  if (row.runtimeServiceStatus === "ERROR") return "ERROR";
  return "UNKNOWN";
}

async function inboundRows(inboundId?: number): Promise<DatabaseRow[]> {
  const q = quoteIdentifier;
  const where = inboundId ? `WHERE i.${q("id")} = ?` : "";
  const params: unknown[] = [XRAY_DEFAULT_VERSION];
  if (inboundId) params.push(inboundId);
  return queryRaw<DatabaseRow>(
    `SELECT ${hostCapabilityColumns()},
      i.${q("id")} AS ${q("inboundId")}, i.${q("name")} AS ${q("inboundName")}, i.${q("runtimeTag")} AS ${q("runtimeTag")},
      i.${q("publicAddress")} AS ${q("publicAddress")}, i.${q("listenAddress")} AS ${q("listenAddress")}, i.${q("listenPort")} AS ${q("listenPort")},
      i.${q("protocol")} AS ${q("protocol")}, i.${q("transport")} AS ${q("transport")}, i.${q("security")} AS ${q("security")},
      i.${q("profileId")} AS ${q("profileId")}, i.${q("specVersion")} AS ${q("specVersion")},
      i.${q("specJson")} AS ${q("specJson")}, i.${q("tlsCertificateId")} AS ${q("tlsCertificateId")},
      tc.${q("id")} AS ${q("tlsCertificatePublicId")}, tc.${q("name")} AS ${q("tlsCertificateName")},
      i.${q("externalProxyNodeId")} AS ${q("externalProxyNodeId")}, ep.${q("name")} AS ${q("externalProxyName")},
      ep.${q("protocol")} AS ${q("externalProxyProtocol")}, ep.${q("address")} AS ${q("externalProxyAddress")},
      ep.${q("port")} AS ${q("externalProxyPort")},
      i.${q("realityTargetHost")} AS ${q("realityTargetHost")}, i.${q("realityTargetPort")} AS ${q("realityTargetPort")},
      i.${q("realityServerName")} AS ${q("realityServerName")}, i.${q("realityPublicKey")} AS ${q("realityPublicKey")},
      CASE WHEN i.${q("realityPrivateKeyEncrypted")} IS NOT NULL AND i.${q("realityPrivateKeyEncrypted")} <> '' THEN 1 ELSE 0 END AS ${q("hasRealityPrivateKey")},
      i.${q("fingerprint")} AS ${q("fingerprint")}, i.${q("spiderX")} AS ${q("spiderX")}, i.${q("isEnabled")} AS ${q("inboundEnabled")},
      i.${q("pendingDelete")} AS ${q("pendingDelete")}, i.${q("desiredGeneration")} AS ${q("inboundDesiredGeneration")},
      i.${q("createdAt")} AS ${q("inboundCreatedAt")}, i.${q("updatedAt")} AS ${q("inboundUpdatedAt")},
      ((SELECT COUNT(*) FROM ${q("xray_access_entries")} a
          WHERE a.${q("inboundId")} = i.${q("id")} AND a.${q("pendingDelete")} = ${boolLiteral(false)})
       + (SELECT COUNT(*) FROM ${q("xray_clients")} c
          WHERE c.${q("inboundId")} = i.${q("id")} AND c.${q("pendingDelete")} = ${boolLiteral(false)}
            AND NOT EXISTS (SELECT 1 FROM ${q("xray_access_entries")} mapped WHERE mapped.${q("legacyClientId")} = c.${q("id")}))) AS ${q("clientCount")},
      d.${q("targetVersion")} AS ${q("targetVersion")}, d.${q("desiredGeneration")} AS ${q("deploymentDesiredGeneration")},
      d.${q("desiredConfigHash")} AS ${q("desiredConfigHash")}, d.${q("lastOperationId")} AS ${q("lastOperationId")},
      r.${q("isInstalled")} AS ${q("isInstalled")}, r.${q("installedVersion")} AS ${q("installedVersion")}, r.${q("runningVersion")} AS ${q("runningVersion")},
      r.${q("serviceStatus")} AS ${q("runtimeServiceStatus")}, r.${q("appliedGeneration")} AS ${q("appliedGeneration")},
      r.${q("appliedConfigHash")} AS ${q("appliedConfigHash")}, r.${q("listenersJson")} AS ${q("listenersJson")},
      r.${q("processId")} AS ${q("processId")}, r.${q("reportedAt")} AS ${q("runtimeReportedAt")},
      r.${q("lastErrorCode")} AS ${q("runtimeErrorCode")}, o.${q("requestedGeneration")} AS ${q("runtimeErrorGeneration")},
      o.${q("operationId")} AS ${q("operationId")}, o.${q("type")} AS ${q("operationType")}, o.${q("status")} AS ${q("operationStatus")},
      o.${q("errorCode")} AS ${q("operationErrorCode")}, o.${q("requestMetaJson")} AS ${q("operationRequestMetaJson")}
    FROM ${q("xray_inbounds")} i
    JOIN ${q("hosts")} h ON h.${q("id")} = i.${q("hostId")}
    ${hostCapabilityJoinSql()}
    LEFT JOIN ${q("xray_tls_certificates")} tc ON tc.${q("id")} = i.${q("tlsCertificateId")}
    LEFT JOIN ${q("xray_external_proxy_nodes")} ep ON ep.${q("id")} = i.${q("externalProxyNodeId")}
    LEFT JOIN ${q("xray_host_deployments")} d ON d.${q("hostId")} = i.${q("hostId")}
    LEFT JOIN ${q("xray_operations")} o ON o.${q("operationId")} = d.${q("lastOperationId")}
    ${where}`,
    params,
  );
}

function projectExternalProxySummary(row: DatabaseRow) {
  if (row.externalProxyNodeId === null || row.externalProxyNodeId === undefined) return null;
  return {
    id: numberValue(row.externalProxyNodeId),
    name: String(row.externalProxyName ?? ""),
    protocol: String(row.externalProxyProtocol ?? ""),
    address: String(row.externalProxyAddress ?? ""),
    port: numberValue(row.externalProxyPort),
  };
}

function projectInboundSummary(row: DatabaseRow) {
  const heartbeat = heartbeatState(row);
  return {
    id: numberValue(row.inboundId),
    name: String(row.inboundName ?? ""),
    host: { id: numberValue(row.hostId), name: String(row.hostName ?? ""), isOnline: heartbeat.isOnline, lastHeartbeat: heartbeat.lastHeartbeat },
    publicAddress: String(row.publicAddress ?? ""),
    listenAddress: String(row.listenAddress ?? ""),
    listenPort: numberValue(row.listenPort),
    protocol: String(row.protocol ?? "").toUpperCase(),
    security: String(row.security ?? "").toUpperCase(),
    profileId: nullableString(row.profileId),
    externalProxy: projectExternalProxySummary(row),
    clientCount: numberValue(row.clientCount),
    desiredEnabled: booleanValue(row.inboundEnabled),
    pendingDelete: booleanValue(row.pendingDelete),
    deploymentStatus: inboundStatus(row),
    activeOperationId: activeOperation(row.operationStatus) ? nullableString(row.operationId) : null,
    activeOperationType: activeOperation(row.operationStatus) && OPERATION_TYPES.has(String(row.operationType))
      ? String(row.operationType) : null,
    lastErrorCode: safeErrorCode(row.operationErrorCode) ?? safeErrorCode(row.runtimeErrorCode),
    updatedAt: dateValue(row.inboundUpdatedAt) ?? new Date(0),
  };
}

export async function listXrayInboundSummaries(input: {
  page?: number;
  pageSize?: number;
  search?: string;
  hostId?: number;
  status?: XrayDeploymentStatus;
  isEnabled?: boolean;
  sortBy?: "updatedAt" | "name" | "listenPort" | "deploymentStatus";
  sortOrder?: "asc" | "desc";
}) {
  let items = (await inboundRows()).map(projectInboundSummary);
  const search = String(input.search ?? "").trim().toLocaleLowerCase();
  if (search) items = items.filter((item) => [item.name, item.host.name, item.publicAddress, item.externalProxy?.name ?? ""]
    .some((value) => value.toLocaleLowerCase().includes(search)));
  if (input.hostId) items = items.filter((item) => item.host.id === input.hostId);
  if (input.status) items = items.filter((item) => item.deploymentStatus === input.status);
  if (input.isEnabled !== undefined) items = items.filter((item) => item.desiredEnabled === input.isEnabled);
  const sortBy = input.sortBy ?? "updatedAt";
  const direction = input.sortOrder === "asc" ? 1 : -1;
  items.sort((left, right) => {
    let compared = 0;
    if (sortBy === "updatedAt") compared = left.updatedAt.getTime() - right.updatedAt.getTime();
    else if (sortBy === "listenPort") compared = left.listenPort - right.listenPort;
    else if (sortBy === "deploymentStatus") compared = left.deploymentStatus.localeCompare(right.deploymentStatus);
    else compared = left.name.localeCompare(right.name);
    return compared === 0 ? direction * (left.id - right.id) : direction * compared;
  });
  return paginateItems(items, input, 12);
}

function projectInbound(row: DatabaseRow) {
  const tlsCertificateId = row.tlsCertificateId === null || row.tlsCertificateId === undefined
    ? null
    : numberValue(row.tlsCertificateId);
  const profileId = nullableString(row.profileId);
  const definition = resolveStoredXrayInboundDefinition(row);
  const isTunnel = definition?.profile.id === "TUNNEL_TCP_LOCAL_NONE";
  return {
    id: numberValue(row.inboundId), hostId: numberValue(row.hostId), name: String(row.inboundName ?? ""), runtimeTag: String(row.runtimeTag ?? ""),
    publicAddress: String(row.publicAddress ?? ""), listenAddress: String(row.listenAddress ?? ""), listenPort: numberValue(row.listenPort),
    protocol: String(row.protocol ?? ""), transport: String(row.transport ?? ""), security: String(row.security ?? ""),
    profileId,
    externalProxy: projectExternalProxySummary(row),
    listenerNetworks: definition?.profile.listenerNetworks ?? [],
    advisoryCode: findKnownXrayProfileById(profileId)?.advisoryCode ?? null,
    tunnelTargetAddress: isTunnel ? String(definition.spec.targetAddress ?? "") : null,
    tunnelTargetPort: isTunnel ? numberValue(definition.spec.targetPort) : null,
    tlsCertificate: tlsCertificateId === null ? null : {
      id: tlsCertificateId,
      name: nullableString(row.tlsCertificateName),
      configured: row.tlsCertificatePublicId !== null && row.tlsCertificatePublicId !== undefined,
    },
    realityTargetHost: String(row.realityTargetHost ?? ""), realityTargetPort: numberValue(row.realityTargetPort),
    realityServerName: String(row.realityServerName ?? ""), realityPublicKey: String(row.realityPublicKey ?? ""),
    hasRealityPrivateKey: booleanValue(row.hasRealityPrivateKey), fingerprint: String(row.fingerprint ?? ""), spiderX: String(row.spiderX ?? ""),
    isEnabled: booleanValue(row.inboundEnabled), pendingDelete: booleanValue(row.pendingDelete), desiredGeneration: numberValue(row.inboundDesiredGeneration),
    createdAt: dateValue(row.inboundCreatedAt) ?? new Date(0), updatedAt: dateValue(row.inboundUpdatedAt) ?? new Date(0),
  };
}

export async function getXrayInboundDetail(id: number) {
  const rows = await inboundRows(id);
  const row = rows[0];
  if (!row) return null;
  const [clients, accessEntries, operations] = await Promise.all([
    listXrayClientsByInbound(id),
    listXrayAccessEntries(id),
    listXrayOperations({ page: 1, pageSize: 20, inboundId: id, sortOrder: "desc" }),
  ]);
  const status = inboundStatus(row);
  const desiredGeneration = numberValue(row.deploymentDesiredGeneration);
  const appliedGeneration = numberValue(row.appliedGeneration);
  const desiredConfigHash = nullableString(row.desiredConfigHash);
  const appliedConfigHash = nullableString(row.appliedConfigHash);
  return {
    inbound: projectInbound(row),
    clients,
    accessEntries,
    host: {
      id: numberValue(row.hostId), name: String(row.hostName ?? ""),
      isOnline: heartbeatState(row).isOnline, lastHeartbeat: heartbeatState(row).lastHeartbeat,
    },
    deployment: {
      status,
      targetVersion: nullableString(row.targetVersion),
      desiredGeneration,
      appliedGeneration,
      desiredConfigHash,
      appliedConfigHash,
      configInSync: !!desiredConfigHash && desiredGeneration === appliedGeneration && desiredConfigHash === appliedConfigHash,
      lastErrorCode: safeErrorCode(row.operationErrorCode) ?? safeErrorCode(row.runtimeErrorCode),
    },
    runtime: {
      serviceStatus: runtimeServiceStatus(row.runtimeServiceStatus),
      installedVersion: nullableString(row.installedVersion),
      runningVersion: nullableString(row.runningVersion),
      processId: row.processId === null || row.processId === undefined ? null : numberValue(row.processId),
      reportedAt: dateValue(row.runtimeReportedAt),
      listeners: parseListeners(row.listenersJson),
      lastErrorCode: safeErrorCode(row.runtimeErrorCode),
      lastErrorMessage: genericRuntimeErrorMessage(safeErrorCode(row.runtimeErrorCode)),
    },
    operations: operations.items,
  };
}

async function runtimeRows(): Promise<DatabaseRow[]> {
  const q = quoteIdentifier;
  return queryRaw<DatabaseRow>(
    `SELECT ${hostCapabilityColumns()},
      d.${q("targetVersion")} AS ${q("targetVersion")}, d.${q("desiredGeneration")} AS ${q("desiredGeneration")},
      d.${q("desiredConfigHash")} AS ${q("desiredConfigHash")}, r.${q("isInstalled")} AS ${q("isInstalled")},
      r.${q("installedVersion")} AS ${q("installedVersion")}, r.${q("runningVersion")} AS ${q("runningVersion")},
      r.${q("serviceStatus")} AS ${q("serviceStatus")}, r.${q("appliedGeneration")} AS ${q("appliedGeneration")},
      r.${q("appliedConfigHash")} AS ${q("appliedConfigHash")}, r.${q("lastErrorCode")} AS ${q("lastErrorCode")},
      r.${q("lastErrorMessage")} AS ${q("lastErrorMessage")}, r.${q("reportedAt")} AS ${q("reportedAt")},
      o.${q("operationId")} AS ${q("lastOperationId")}, o.${q("type")} AS ${q("lastOperationType")},
      o.${q("status")} AS ${q("lastOperationStatus")},
      (SELECT COUNT(*) FROM ${q("xray_inbounds")} i WHERE i.${q("hostId")} = h.${q("id")}) AS ${q("inboundCount")}
    FROM ${q("hosts")} h ${hostCapabilityJoinSql()}
    LEFT JOIN ${q("xray_host_deployments")} d ON d.${q("hostId")} = h.${q("id")}
    LEFT JOIN ${q("xray_operations")} o ON o.${q("operationId")} = d.${q("lastOperationId")}`,
    [XRAY_DEFAULT_VERSION],
  );
}

function runtimeServiceStatus(value: unknown): "RUNNING" | "STOPPED" | "ERROR" | "UNKNOWN" {
  const status = String(value ?? "UNKNOWN");
  return status === "RUNNING" || status === "STOPPED" || status === "ERROR" ? status : "UNKNOWN";
}

function projectRuntime(row: DatabaseRow) {
  const desiredGeneration = numberValue(row.desiredGeneration);
  const appliedGeneration = numberValue(row.appliedGeneration);
  const desiredConfigHash = nullableString(row.desiredConfigHash);
  const appliedConfigHash = nullableString(row.appliedConfigHash);
  const installedVersion = nullableString(row.installedVersion);
  const targetVersion = nullableString(row.targetVersion);
  const reason = unavailableReason(row, false);
  const errorCode = safeErrorCode(row.lastErrorCode);
  const lastOperationStatus = OPERATION_STATUSES.has(String(row.lastOperationStatus)) ? String(row.lastOperationStatus) : null;
  return {
    hostId: numberValue(row.hostId), hostName: String(row.hostName ?? ""), isAgentOnline: heartbeatState(row).isOnline,
    capabilityVersion: numberValue(row.capabilitySchemaVersion), canManageXray: reason === null, unavailableReasonCode: reason,
    installedVersion, runningVersion: nullableString(row.runningVersion), targetVersion,
    serviceStatus: runtimeServiceStatus(row.serviceStatus), desiredGeneration, appliedGeneration,
    configInSync: !!desiredConfigHash && desiredGeneration === appliedGeneration && desiredConfigHash === appliedConfigHash,
    inboundCount: numberValue(row.inboundCount),
    hasUpgrade: !!installedVersion && !!targetVersion && compareVersions(installedVersion, targetVersion) < 0,
    isNewerThanTarget: !!installedVersion && !!targetVersion && compareVersions(installedVersion, targetVersion) > 0,
    activeOperationId: activeOperation(lastOperationStatus) ? nullableString(row.lastOperationId) : null,
    activeOperationType: activeOperation(lastOperationStatus) && OPERATION_TYPES.has(String(row.lastOperationType))
      ? String(row.lastOperationType) : null,
    lastReportedAt: dateValue(row.reportedAt), lastErrorCode: errorCode, lastErrorMessage: genericRuntimeErrorMessage(errorCode),
  };
}

export async function listXrayRuntimeSummaries(input: {
  page?: number;
  pageSize?: number;
  search?: string;
  hostId?: number;
  hostIds?: number[];
  status?: "RUNNING" | "STOPPED" | "ERROR" | "UNKNOWN";
  version?: string;
  sortBy?: "hostName" | "lastReportedAt" | "desiredGeneration";
  sortOrder?: "asc" | "desc";
}) {
  let items = (await runtimeRows()).map(projectRuntime);
  const search = String(input.search ?? "").trim().toLocaleLowerCase();
  if (search) items = items.filter((item) => item.hostName.toLocaleLowerCase().includes(search));
  if (input.hostId) items = items.filter((item) => item.hostId === input.hostId);
  if (input.hostIds) {
    const hostIds = new Set(input.hostIds);
    items = items.filter((item) => hostIds.has(item.hostId));
  }
  if (input.status) items = items.filter((item) => item.serviceStatus === input.status);
  if (input.version) items = items.filter((item) => item.installedVersion === input.version || item.targetVersion === input.version);
  const sortBy = input.sortBy ?? "hostName";
  const direction = input.sortOrder === "desc" ? -1 : 1;
  items.sort((left, right) => {
    let compared = 0;
    if (sortBy === "lastReportedAt") compared = (left.lastReportedAt?.getTime() ?? 0) - (right.lastReportedAt?.getTime() ?? 0);
    else if (sortBy === "desiredGeneration") compared = left.desiredGeneration - right.desiredGeneration;
    else compared = left.hostName.localeCompare(right.hostName);
    return compared === 0 ? direction * (left.hostId - right.hostId) : direction * compared;
  });
  return paginateItems(items, input, 20);
}

export async function getXrayRuntimeCatalog() {
  const q = quoteIdentifier;
  const rows = await queryRaw<DatabaseRow>(
    `SELECT ${q("version")} AS ${q("artifactVersion")}, ${q("os")} AS ${q("artifactOS")},
            ${q("arch")} AS ${q("artifactArch")}, ${q("packageFormat")} AS ${q("artifactPackageFormat")},
            ${q("storageKey")} AS ${q("artifactStorageKey")}, ${q("sha256")} AS ${q("artifactSha256")},
            ${q("fileSize")} AS ${q("artifactFileSize")}, ${q("status")} AS ${q("artifactStatus")},
            ${q("source")} AS ${q("artifactSource")}, ${q("verifiedAt")} AS ${q("artifactVerifiedAt")}
       FROM ${q("xray_artifacts")} WHERE ${q("version")} = ?`,
    [XRAY_DEFAULT_VERSION],
  );
  return {
    defaultVersion: XRAY_DEFAULT_VERSION,
    artifacts: XRAY_ARTIFACT_MANIFEST.map((entry) => ({
      os: entry.os,
      arch: entry.arch,
      verified: rows.some((row) => row.artifactOS === entry.os && row.artifactArch === entry.arch && artifactRowMatchesManifest(row)),
    })),
  };
}

const OPERATION_TYPES = new Set(["PORT_PROBE", "REALITY_SCAN", "INSTALL", "UPGRADE", "SYNC", "RESTART"]);
const OPERATION_STATUSES = new Set(["QUEUED", "RUNNING", "SUCCESS", "FAILED", "TIMEOUT", "CANCELLED"]);

function operationStage(type: string, status: string, requestMeta: unknown, errorCode: string | null) {
  if (status === "SUCCESS" || status === "CANCELLED") return "COMPLETE";
  if (["FAILED", "TIMEOUT"].includes(status)) {
    if (["ARTIFACT_NOT_FOUND", "ARTIFACT_SIZE_MISMATCH", "ARTIFACT_HASH_MISMATCH", "ARTIFACT_ARCH_MISMATCH", "XRAY_VERSION_MISMATCH"].includes(errorCode ?? "")) return "VERIFYING_ARTIFACT";
    if (errorCode === "RUNTIME_NOT_READY") return "CHECKING_LISTENERS";
    if (errorCode === "ROLLBACK_FAILED") return "ROLLING_BACK";
    if (errorCode === "RUNTIME_START_FAILED") return "RESTARTING_RUNTIME";
  }
  if ((type === "SYNC" || type === "UPGRADE") && operationRuntimeStage(requestMeta) === "INSTALL_COMPLETE") {
    return status === "RUNNING" ? "APPLYING" : "VALIDATING_CONFIG";
  }
  if (status === "QUEUED") return "QUEUED";
  if (type === "PORT_PROBE") return "PROBING_PORT";
  if (type === "INSTALL" || type === "UPGRADE" || operationRuntimeStage(requestMeta) === "INSTALL") return "DOWNLOADING_ARTIFACT";
  if (type === "RESTART") return "RESTARTING_RUNTIME";
  if (type === "SYNC") return "VALIDATING_CONFIG";
  return "QUEUED";
}

function projectOperation(row: DatabaseRow) {
  const type = OPERATION_TYPES.has(String(row.type)) ? String(row.type) : "SYNC";
  const status = OPERATION_STATUSES.has(String(row.status)) ? String(row.status) : "FAILED";
  const errorCode = safeErrorCode(row.errorCode);
  return {
    operationId: String(row.operationId ?? ""), hostId: numberValue(row.hostId),
    inboundId: row.inboundId === null || row.inboundId === undefined ? null : numberValue(row.inboundId),
    type, status, stage: operationStage(type, status, row.requestMetaJson, errorCode),
    requestedGeneration: row.requestedGeneration === null || row.requestedGeneration === undefined ? null : numberValue(row.requestedGeneration),
    errorCode, errorMessage: genericOperationErrorMessage(type, errorCode), attemptCount: numberValue(row.attemptCount),
    createdAt: dateValue(row.createdAt) ?? new Date(0), startedAt: dateValue(row.startedAt), finishedAt: dateValue(row.finishedAt),
    expiresAt: dateValue(row.expiresAt), updatedAt: dateValue(row.updatedAt) ?? new Date(0),
  };
}

const operationColumns = [
  "operationId", "hostId", "inboundId", "type", "requestedGeneration", "status", "requestMetaJson", "errorCode", "attemptCount",
  "createdAt", "startedAt", "finishedAt", "expiresAt", "updatedAt",
];

export async function listXrayOperations(input: {
  page?: number;
  pageSize?: number;
  hostId?: number;
  inboundId?: number;
  type?: string;
  status?: string;
  sortOrder?: "asc" | "desc";
}) {
  const q = quoteIdentifier;
  const where: string[] = [];
  const params: unknown[] = [];
  for (const [column, value] of [["hostId", input.hostId], ["inboundId", input.inboundId], ["type", input.type], ["status", input.status]] as const) {
    if (value !== undefined) {
      where.push(`${q(column)} = ?`);
      params.push(value);
    }
  }
  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const countRows = await queryRaw<{ count: number }>(`SELECT COUNT(*) AS ${q("count")} FROM ${q("xray_operations")} ${whereSql}`, params);
  const totalItems = numberValue(countRows[0]?.count);
  const window = pageWindowForTotal(input, totalItems, 20);
  const direction = input.sortOrder === "asc" ? "ASC" : "DESC";
  const rows = await queryRaw<DatabaseRow>(
    `SELECT ${operationColumns.map((column) => q(column)).join(", ")} FROM ${q("xray_operations")} ${whereSql}
      ORDER BY ${q("createdAt")} ${direction}, ${q("id")} ${direction} LIMIT ? OFFSET ?`,
    [...params, window.pageSize, window.offset],
  );
  return pageResult(rows.map(projectOperation), totalItems, window, 20);
}

export async function getXrayOperationSummary(operationId: string) {
  const q = quoteIdentifier;
  const rows = await queryRaw<DatabaseRow>(
    `SELECT ${operationColumns.map((column) => q(column)).join(", ")} FROM ${q("xray_operations")} WHERE ${q("operationId")} = ? LIMIT 1`,
    [operationId],
  );
  return rows[0] ? projectOperation(rows[0]) : null;
}
