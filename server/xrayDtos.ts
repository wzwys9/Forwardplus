export type XrayInboundDto = {
  id: number;
  hostId: number;
  name: string;
  runtimeTag: string;
  publicAddress: string;
  listenAddress: string;
  listenPort: number;
  protocol: string;
  transport: string;
  security: string;
  realityTargetHost: string;
  realityTargetPort: number;
  realityServerName: string;
  realityPublicKey: string;
  hasRealityPrivateKey: boolean;
  fingerprint: string;
  spiderX: string;
  isEnabled: boolean;
  pendingDelete: boolean;
  desiredGeneration: number;
  createdByUserId: number;
  createdAt: Date;
  updatedAt: Date;
};

export type XrayClientDto = {
  id: number;
  inboundId: number;
  name: string;
  statsKey: string;
  flow: string;
  ownerUserId: number | null;
  isEnabled: boolean;
  pendingDelete: boolean;
  desiredGeneration: number;
  sortOrder: number;
  credentials: {
    uuidConfigured: boolean;
    shortIdConfigured: boolean;
  };
  createdAt: Date;
  updatedAt: Date;
};

export type XrayHostDeploymentDto = {
  id: number;
  hostId: number;
  targetVersion: string | null;
  desiredGeneration: number;
  desiredConfigHash: string | null;
  lastOperationId: string | null;
  createdAt: Date;
  updatedAt: Date;
};

export type XrayRuntimeServiceStatus = "RUNNING" | "STOPPED" | "ERROR" | "UNKNOWN";

export type XrayRuntimeReportDto = {
  id: number;
  hostId: number;
  capabilitySchemaVersion: number;
  supportedOS: string | null;
  supportedArch: string | null;
  supportsArtifactInstall: boolean;
  supportsPortProbe: boolean;
  supportsUdpPortProbe: boolean;
  supportsUdpListenerReadiness: boolean;
  supportsRealityScan: boolean;
  capabilityErrorCode: string | null;
  isInstalled: boolean;
  installedVersion: string | null;
  runningVersion: string | null;
  serviceStatus: XrayRuntimeServiceStatus;
  processId: number | null;
  appliedGeneration: number;
  appliedConfigHash: string | null;
  binarySha256: string | null;
  lastErrorCode: string | null;
  lastErrorMessage: string | null;
  reportedAt: Date | null;
  updatedAt: Date;
};

export type XrayArtifactDto = {
  id: number;
  version: string;
  os: string;
  arch: string;
  packageFormat: string;
  sha256: string;
  fileSize: number;
  status: string;
  verifiedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
};

export type XrayOperationDto = {
  id: number;
  operationId: string;
  hostId: number;
  inboundId: number | null;
  type: string;
  requestedGeneration: number | null;
  status: string;
  errorCode: string | null;
  errorMessage: string | null;
  attemptCount: number;
  createdByUserId: number;
  createdAt: Date;
  startedAt: Date | null;
  finishedAt: Date | null;
  expiresAt: Date | null;
  updatedAt: Date;
};

function numberValue(value: unknown): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function nullableNumber(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function stringValue(value: unknown): string {
  return typeof value === "string" ? value : String(value ?? "");
}

function nullableString(value: unknown): string | null {
  if (value === null || value === undefined || value === "") return null;
  return String(value);
}

function booleanValue(value: unknown): boolean {
  if (value === true || value === 1 || value === "1") return true;
  return typeof value === "string" && value.trim().toLowerCase() === "true";
}

function dateValue(value: unknown): Date {
  if (value instanceof Date) return new Date(value.getTime());
  if (typeof value === "number" || (typeof value === "string" && /^\d+(?:\.\d+)?$/.test(value.trim()))) {
    const seconds = Number(value);
    return new Date(seconds * 1000);
  }
  const parsed = new Date(String(value ?? ""));
  return Number.isFinite(parsed.getTime()) ? parsed : new Date(0);
}

function nullableDate(value: unknown): Date | null {
  return value === null || value === undefined || value === "" ? null : dateValue(value);
}

function stableErrorCode(value: unknown): string | null {
  const code = nullableString(value);
  if (!code) return null;
  return /^[A-Z][A-Z0-9_]{0,63}$/.test(code) ? code : "INTERNAL_ERROR";
}

function runtimeStatus(value: unknown): XrayRuntimeServiceStatus {
  const normalized = String(value ?? "").toUpperCase();
  return normalized === "RUNNING" || normalized === "STOPPED" || normalized === "ERROR" ? normalized : "UNKNOWN";
}

export function toXrayInboundDto(row: Record<string, unknown>): XrayInboundDto {
  return {
    id: numberValue(row.id),
    hostId: numberValue(row.hostId),
    name: stringValue(row.name),
    runtimeTag: stringValue(row.runtimeTag),
    publicAddress: stringValue(row.publicAddress),
    listenAddress: stringValue(row.listenAddress),
    listenPort: numberValue(row.listenPort),
    protocol: stringValue(row.protocol),
    transport: stringValue(row.transport),
    security: stringValue(row.security),
    realityTargetHost: stringValue(row.realityTargetHost),
    realityTargetPort: numberValue(row.realityTargetPort),
    realityServerName: stringValue(row.realityServerName),
    realityPublicKey: stringValue(row.realityPublicKey),
    hasRealityPrivateKey: booleanValue(row.hasRealityPrivateKey),
    fingerprint: stringValue(row.fingerprint),
    spiderX: stringValue(row.spiderX),
    isEnabled: booleanValue(row.isEnabled),
    pendingDelete: booleanValue(row.pendingDelete),
    desiredGeneration: numberValue(row.desiredGeneration),
    createdByUserId: numberValue(row.createdByUserId),
    createdAt: dateValue(row.createdAt),
    updatedAt: dateValue(row.updatedAt),
  };
}

export function toXrayClientDto(row: Record<string, unknown>): XrayClientDto {
  return {
    id: numberValue(row.id),
    inboundId: numberValue(row.inboundId),
    name: stringValue(row.name),
    statsKey: stringValue(row.statsKey),
    flow: stringValue(row.flow),
    ownerUserId: nullableNumber(row.ownerUserId),
    isEnabled: booleanValue(row.isEnabled),
    pendingDelete: booleanValue(row.pendingDelete),
    desiredGeneration: numberValue(row.desiredGeneration),
    sortOrder: numberValue(row.sortOrder),
    credentials: {
      uuidConfigured: booleanValue(row.hasUuid),
      shortIdConfigured: booleanValue(row.hasShortId),
    },
    createdAt: dateValue(row.createdAt),
    updatedAt: dateValue(row.updatedAt),
  };
}

export function toXrayHostDeploymentDto(row: Record<string, unknown>): XrayHostDeploymentDto {
  return {
    id: numberValue(row.id),
    hostId: numberValue(row.hostId),
    targetVersion: nullableString(row.targetVersion),
    desiredGeneration: numberValue(row.desiredGeneration),
    desiredConfigHash: nullableString(row.desiredConfigHash),
    lastOperationId: nullableString(row.lastOperationId),
    createdAt: dateValue(row.createdAt),
    updatedAt: dateValue(row.updatedAt),
  };
}

export function toXrayRuntimeReportDto(row: Record<string, unknown>): XrayRuntimeReportDto {
  const lastErrorCode = stableErrorCode(row.lastErrorCode);
  return {
    id: numberValue(row.id),
    hostId: numberValue(row.hostId),
    capabilitySchemaVersion: numberValue(row.capabilitySchemaVersion),
    supportedOS: nullableString(row.supportedOS),
    supportedArch: nullableString(row.supportedArch),
    supportsArtifactInstall: booleanValue(row.supportsArtifactInstall),
    supportsPortProbe: booleanValue(row.supportsPortProbe),
    supportsUdpPortProbe: booleanValue(row.supportsUdpPortProbe),
    supportsUdpListenerReadiness: booleanValue(row.supportsUdpListenerReadiness),
    supportsRealityScan: booleanValue(row.supportsRealityScan),
    capabilityErrorCode: stableErrorCode(row.capabilityErrorCode),
    isInstalled: booleanValue(row.isInstalled),
    installedVersion: nullableString(row.installedVersion),
    runningVersion: nullableString(row.runningVersion),
    serviceStatus: runtimeStatus(row.serviceStatus),
    processId: nullableNumber(row.processId),
    appliedGeneration: numberValue(row.appliedGeneration),
    appliedConfigHash: nullableString(row.appliedConfigHash),
    binarySha256: nullableString(row.binarySha256),
    lastErrorCode,
    lastErrorMessage: lastErrorCode ? "Managed Xray runtime reported an error" : null,
    reportedAt: nullableDate(row.reportedAt),
    updatedAt: dateValue(row.updatedAt),
  };
}

export function toXrayArtifactDto(row: Record<string, unknown>): XrayArtifactDto {
  return {
    id: numberValue(row.id),
    version: stringValue(row.version),
    os: stringValue(row.os),
    arch: stringValue(row.arch),
    packageFormat: stringValue(row.packageFormat),
    sha256: stringValue(row.sha256),
    fileSize: numberValue(row.fileSize),
    status: stringValue(row.status),
    verifiedAt: nullableDate(row.verifiedAt),
    createdAt: dateValue(row.createdAt),
    updatedAt: dateValue(row.updatedAt),
  };
}

export function toXrayOperationDto(row: Record<string, unknown>): XrayOperationDto {
  const errorCode = stableErrorCode(row.errorCode);
  return {
    id: numberValue(row.id),
    operationId: stringValue(row.operationId),
    hostId: numberValue(row.hostId),
    inboundId: nullableNumber(row.inboundId),
    type: stringValue(row.type),
    requestedGeneration: nullableNumber(row.requestedGeneration),
    status: stringValue(row.status),
    errorCode,
    errorMessage: errorCode ? "Managed Xray operation did not complete" : null,
    attemptCount: numberValue(row.attemptCount),
    createdByUserId: numberValue(row.createdByUserId),
    createdAt: dateValue(row.createdAt),
    startedAt: nullableDate(row.startedAt),
    finishedAt: nullableDate(row.finishedAt),
    expiresAt: nullableDate(row.expiresAt),
    updatedAt: dateValue(row.updatedAt),
  };
}
