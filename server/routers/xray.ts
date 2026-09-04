import { TRPCError } from "@trpc/server";
import { z } from "zod";

import { adminProcedure, router } from "../_core/trpc";
import {
  createXrayAccessEntryForInbound,
  getXrayAccessEntryShare,
  removeXrayAccessEntryForInbound,
  updateXrayAccessEntryForInbound,
  XrayAccessServiceError,
} from "../xrayAccessService";
import {
  createXrayClient,
  getXrayClientShare,
  listXrayClients,
  removeXrayClient,
  updateXrayClient,
  XrayClientServiceError,
} from "../xrayClientService";
import {
  createXrayInbound,
  createXrayInboundV2,
  removeXrayInbound,
  setXrayInboundExternalProxy,
  setXrayInboundEnabled,
  updateXrayInbound,
  XrayInboundCreateError,
} from "../xrayInboundService";
import {
  createXrayPortProbeOperation,
  getXrayPortProbeOperationResult,
  withConsumedXrayPortReservation,
  XrayPortOperationError,
} from "../xrayPortOperations";
import {
  createXrayRealityScanOperation,
  getXrayRealityScanOperationResult,
  XrayRealityOperationError,
} from "../xrayRealityOperations";
import {
  createXrayRuntimeInstall,
  createXrayRuntimeRestart,
  createXrayRuntimeSync,
  createXrayRuntimeUpgrade,
  XrayRuntimeServiceError,
} from "../xrayRuntimeService";
import {
  getXrayInboundDetail,
  getXrayOperationSummary,
  getXrayProfileCatalog,
  getXrayRuntimeCatalog,
  listXrayHostOptions,
  listXrayInboundSummaries,
  listXrayOperations,
  listXrayRuntimeSummaries,
  XRAY_DEPLOYMENT_STATUSES,
} from "../xrayQueryService";
import { appendXrayStructuredLog } from "../xrayObservability";
import { normalizeXrayTunnelTargetAddress } from "../../shared/xrayProfiles";
import {
  importManagedXrayTlsCertificate,
  listManagedXrayTlsCertificates,
  removeManagedXrayTlsCertificate,
  rotateManagedXrayTlsCertificate,
  XrayTlsCertificateServiceError,
} from "../xrayTlsCertificateService";
import {
  createXrayManagedServiceAccount,
  createXrayAmneziaWgService,
  createXrayMtprotoService,
  getXrayManagedServiceCatalog,
  getXrayManagedServiceDetail,
  getXrayManagedServiceShare,
  listXrayManagedServiceHostOptions,
  listXrayManagedServices,
  removeXrayManagedService,
  removeXrayManagedServiceAccount,
  setXrayManagedServiceEnabled,
  updateXrayManagedService,
  updateXrayAmneziaWgService,
  updateXrayManagedServiceAccount,
  XrayManagedServiceError,
} from "../xrayManagedServiceService";
import {
  createXrayExternalProxyNode,
  buildXrayExternalProxyRelayShare,
  buildXrayExternalProxyShare,
  getXrayExternalProxyNodeDetail,
  listXrayExternalProxyNodes,
  previewXrayExternalProxyImport,
  removeXrayExternalProxyNode,
  renameXrayExternalProxyNode,
  replaceXrayExternalProxyNode,
  XrayExternalProxyServiceError,
} from "../xrayExternalProxyService";
import {
  DnsProviderAccountServiceError,
  getGlobalDnsProviderAccountService,
  listGlobalDnsProviderZonesService,
  removeGlobalDnsProviderAccount,
  revalidateGlobalDnsProviderAccount,
  upsertGlobalDnsProviderAccount,
} from "../dnsProviderAccountService";
import {
  createDnsProviderRecord,
  DnsProviderRecordServiceError,
  listDnsProviderRecords,
  removeDnsProviderRecord,
  updateDnsProviderRecord,
} from "../dnsProviderRecordService";
import {
  confirmQuickConfigDomainCheck,
  createQuickConfigDomainCheck,
  listQuickConfigTargets,
  XrayQuickConfigServiceError,
} from "../xrayQuickConfigService";
import {
  createQuickConfigPortCheck,
  getQuickConfigPortCheckResult,
  previewQuickConfig,
  previewQuickConfigEdit,
  XrayQuickConfigPlanningError,
} from "../xrayQuickConfigPlanningService";
import {
  listXrayQuickConfigForwardEngines,
  XrayQuickConfigForwardEngineCatalogError,
} from "../xrayQuickConfigForwardEngineService";
import {
  applyXrayQuickConfigEngineSwitch,
  previewXrayQuickConfigEngineSwitch,
  XrayQuickConfigEngineSwitchError,
} from "../xrayQuickConfigEngineSwitchService";
import {
  applyQuickConfigPreview,
  XrayQuickConfigOperationError,
} from "../xrayQuickConfigOperationService";
import {
  applyQuickConfigEditPreview,
  XrayQuickConfigEditError,
} from "../xrayQuickConfigEditService";
import {
  applyQuickConfigRemove,
  previewQuickConfigRemove,
  XrayQuickConfigLifecycleError,
} from "../xrayQuickConfigLifecycleService";
import {
  retryQuickConfigOperation,
  XrayQuickConfigRetryError,
} from "../xrayQuickConfigRetryService";
import {
  createXrayQuickConfigSync,
  XrayQuickConfigSyncError,
} from "../xrayQuickConfigSyncService";
import {
  getXrayQuickConfigDetail,
  getXrayQuickConfigOperation,
  listXrayQuickConfigs,
  XrayQuickConfigQueryError,
} from "../xrayQuickConfigQueryService";
import {
  getXrayQuickConfigDerivedShare,
  XrayQuickConfigShareError,
} from "../xrayQuickConfigShareService";
import { xrayQuickConfigEntryHostsListProcedure } from "./xrayQuickConfigEntryHosts";

const positiveId = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const generation = z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER);
const page = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER).default(1);
const pageSize = z.number().int().min(1).max(100);
const sortOrder = z.enum(["asc", "desc"]);
const certificatePem = z.string().min(1).max(16 * 1024);
const privateKeyPem = z.string().min(1).max(8 * 1024);
const dnsProviderCredential = z.string().trim().min(8).max(128)
  .regex(/^[^\u0000-\u001f\u007f]+$/);

const dnsProviderUpsertInput = z.object({
  expectedBindingRevision: positiveId,
  expectedAccountRevision: positiveId.nullable(),
  name: z.string().trim().min(1).max(128),
  secretId: dnsProviderCredential,
  secretKey: dnsProviderCredential,
}).strict();

const dnsProviderRevisionInput = z.object({
  expectedAccountRevision: positiveId,
  expectedBindingRevision: positiveId,
}).strict();

const dnsProviderRemoveInput = dnsProviderRevisionInput.extend({
  confirmName: z.string().min(1).max(128),
}).strict();

const dnsRecordType = z.enum(["A", "AAAA", "CNAME"]);
const dnsRecordWriteInput = z.object({
  zoneId: positiveId,
  subdomain: z.string().trim().min(1).max(253),
  recordType: dnsRecordType,
  lineId: positiveId,
  value: z.string().trim().min(1).max(2_048),
  ttl: z.number().int().min(1).max(604_800),
}).strict();
const dnsProviderRecordId = z.string().min(1).max(128).regex(/^\d+$/);
const dnsRecordRevision = z.string().length(64).regex(/^[a-f0-9]{64}$/);

const quickConfigTargetType = z.enum(["XRAY_INBOUND", "EXTERNAL_PROXY_NODE"]);
const quickConfigTargetRef = z.object({
  targetType: quickConfigTargetType,
  targetId: positiveId,
  targetVersion: z.string().length(64).regex(/^[a-f0-9]{64}$/),
}).strict();
const quickConfigEditIdentity = z.object({
  quickConfigId: positiveId,
  expectedRevision: positiveId,
}).strict();
const quickConfigDomainCreateInput = z.object({
  targetRef: quickConfigTargetRef,
  accountId: positiveId,
  zoneId: positiveId,
  relativeName: z.string().trim().min(1).max(253),
  editIdentity: quickConfigEditIdentity.optional(),
}).strict();
const quickConfigDomainConfirmInput = z.object({
  domainCheckToken: z.string().min(1).max(4096).regex(/^[A-Za-z0-9._-]+$/),
  action: z.enum(["USE_UNUSED_NAME", "REPLACE_CONFLICTING_RECORDS"]),
  confirmationHash: z.string().length(64).regex(/^[a-f0-9]{64}$/),
}).strict();
const quickConfigToken = z.string().min(1).max(64 * 1024).regex(/^[A-Za-z0-9._-]+$/);
const quickConfigForwardEngine = z.enum(["iptables", "nftables", "realm", "socat", "gost", "nginx"]);
const quickConfigEndpoint = z.object({
  hostId: positiveId,
  addressFamily: z.enum(["IPV4", "IPV6"]),
}).strict();
const quickConfigCarrierRoutes = z.array(z.object({
  carrier: z.enum(["TELECOM", "UNICOM", "MOBILE", "EDUCATION"]),
  providerLineId: z.string().min(1).max(128).regex(/^[^\u0000-\u001f\u007f]+$/),
  endpoints: z.array(quickConfigEndpoint).min(1).max(32).superRefine((items, ctx) => {
    const keys = items.map((item) => `${item.hostId}:${item.addressFamily}`);
    if (new Set(keys).size !== keys.length) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Endpoints must be unique within a carrier" });
    }
  }),
}).strict()).length(4).superRefine((items, ctx) => {
  const carriers = items.map((item) => item.carrier);
  if (new Set(carriers).size !== 4) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Each carrier must appear exactly once" });
  }
});
const quickConfigPortChoice = z.discriminatedUnion("mode", [
  z.object({ mode: z.literal("TARGET_ORIGINAL") }).strict(),
  z.object({ mode: z.literal("MANUAL"), port: z.number().int().min(1000).max(65535) }).strict(),
  z.object({ mode: z.literal("RECOMMENDED"), recommendationToken: quickConfigToken }).strict(),
]);
const quickConfigPortCheckCreateInput = z.object({
  confirmedDomainToken: quickConfigToken,
  carrierRoutes: quickConfigCarrierRoutes,
  engine: quickConfigForwardEngine,
  choice: quickConfigPortChoice,
  replaceProbeResultToken: quickConfigToken.optional(),
}).strict();
const quickConfigPreviewInput = z.object({
  confirmedDomainToken: quickConfigToken,
  carrierRoutes: quickConfigCarrierRoutes,
  engine: quickConfigForwardEngine,
  probeResultToken: quickConfigToken,
  defaultRoutes: z.array(z.object({
    candidateId: z.string().regex(/^qdc_[A-Za-z0-9_-]{43}$/),
  }).strict()).min(1).max(64).superRefine((items, ctx) => {
    if (new Set(items.map((item) => item.candidateId)).size !== items.length) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Default route candidates must be unique" });
    }
  }),
}).strict();
const quickConfigState = z.enum([
  "APPLYING", "ACTIVE", "UPDATING", "DELETING", "COMPENSATING", "PARTIAL_FAILURE", "FAILED", "REMOVED",
]);
const quickConfigListInput = z.object({
  search: z.string().max(128).optional(),
  state: quickConfigState.optional(),
  targetType: quickConfigTargetType.optional(),
  accountId: positiveId.optional(),
  page: z.number().int().positive().optional(),
  pageSize: z.number().int().min(1).max(100).optional(),
}).strict();
const quickConfigShareAccessRef = z.discriminatedUnion("type", [
  z.object({ type: z.literal("LEGACY_CLIENT"), legacyClientId: positiveId }).strict(),
  z.object({ type: z.literal("ACCESS_ENTRY"), accessEntryId: positiveId }).strict(),
]);

function setSensitiveResponseHeaders(response: { setHeader(name: string, value: string): unknown }) {
  response.setHeader("Cache-Control", "private, no-store, max-age=0");
  response.setHeader("Pragma", "no-cache");
}

const inboundListInput = z.object({
  page,
  pageSize: pageSize.default(12),
  search: z.string().trim().max(128).default(""),
  hostId: positiveId.optional(),
  status: z.enum(XRAY_DEPLOYMENT_STATUSES).optional(),
  isEnabled: z.boolean().optional(),
  sortBy: z.enum(["updatedAt", "name", "listenPort", "deploymentStatus"]).default("updatedAt"),
  sortOrder: sortOrder.default("desc"),
}).strict();

const runtimeStatuses = ["RUNNING", "STOPPED", "ERROR", "UNKNOWN"] as const;
const runtimeListInput = z.object({
  page,
  pageSize: pageSize.default(20),
  search: z.string().trim().max(128).default(""),
  hostId: positiveId.optional(),
  hostIds: z.array(positiveId).min(1).max(100).refine((ids) => new Set(ids).size === ids.length, "Host ids must be unique").optional(),
  status: z.enum(runtimeStatuses).optional(),
  version: z.string().trim().min(1).max(64).optional(),
  sortBy: z.enum(["hostName", "lastReportedAt", "desiredGeneration"]).default("hostName"),
  sortOrder: sortOrder.default("asc"),
}).strict().refine((input) => input.hostId === undefined || input.hostIds === undefined, {
  message: "hostId and hostIds are mutually exclusive",
});

const operationTypes = ["PORT_PROBE", "REALITY_SCAN", "INSTALL", "UPGRADE", "SYNC", "RESTART"] as const;
const operationStatuses = ["QUEUED", "RUNNING", "SUCCESS", "FAILED", "TIMEOUT", "CANCELLED"] as const;
const operationListInput = z.object({
  page,
  pageSize: pageSize.default(20),
  hostId: positiveId.optional(),
  inboundId: positiveId.optional(),
  type: z.enum(operationTypes).optional(),
  status: z.enum(operationStatuses).optional(),
  sortOrder: sortOrder.default("desc"),
}).strict();

const operationId = z.string().trim().min(1).max(64).regex(/^[A-Za-z0-9._:-]+$/);
const portProbeCreateInput = z.object({
  hostId: positiveId,
  mode: z.enum(["AUTO", "MANUAL"]),
  manualPort: z.number().int().min(1000).max(65535).optional(),
  network: z.enum(["TCP", "UDP"]).default("TCP"),
  replaceReservationIds: z.array(z.string().uuid()).min(1).max(2).optional(),
}).strict().superRefine((input, ctx) => {
  if (input.mode === "MANUAL" && input.manualPort === undefined) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["manualPort"], message: "Manual port is required" });
  }
  if (input.mode === "AUTO" && input.manualPort !== undefined) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["manualPort"], message: "Automatic probe does not accept a manual port" });
  }
  if (input.replaceReservationIds && new Set(input.replaceReservationIds).size !== input.replaceReservationIds.length) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["replaceReservationIds"], message: "Replacement reservations must be unique" });
  }
});
const realityScanCreateInput = z.object({
  hostId: positiveId,
  source: z.enum(["DEFAULT_CANDIDATES", "ADMIN_DOMAINS"]),
  targets: z.array(z.string().trim().min(1).max(260)).min(1).max(64).optional(),
}).strict().superRefine((input, ctx) => {
  if (input.source === "ADMIN_DOMAINS" && input.targets === undefined) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["targets"], message: "Administrator targets are required" });
  }
  if (input.source === "DEFAULT_CANDIDATES" && input.targets !== undefined) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["targets"], message: "Default scan does not accept custom targets" });
  }
});
const clientName = z.string().trim().min(1).max(128);
const inboundCreateInput = z.object({
  hostId: positiveId,
  name: z.string().trim().min(1).max(128),
  publicAddress: z.string().trim().min(1).max(253),
  portReservationId: operationId,
  listenPort: z.number().int().min(1000).max(65535),
  reality: z.object({
    targetHost: z.string().trim().min(1).max(253),
    targetPort: z.number().int().min(1).max(65535),
    serverName: z.string().trim().min(1).max(253),
    fingerprint: z.literal("chrome"),
    spiderX: z.string().trim().min(1).max(256),
  }).strict(),
  initialClients: z.array(z.object({
    name: clientName,
    flow: z.literal("xtls-rprx-vision"),
  }).strict()).min(1).max(32),
}).strict().superRefine((input, ctx) => {
  const names = input.initialClients.map((client) => client.name.toLocaleLowerCase());
  if (new Set(names).size !== names.length) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["initialClients"], message: "Client names must be unique" });
  }
});

const inboundCreateV2SharedBase = {
  hostId: positiveId,
  name: z.string().trim().min(1).max(128),
  publicAddress: z.string().trim().min(1).max(253),
  listenPort: z.number().int().min(1000).max(65535),
  initialAccessEntries: z.array(z.object({ name: clientName }).strict()).min(1).max(32),
};
const inboundCreateV2Base = {
  ...inboundCreateV2SharedBase,
  portReservationId: operationId,
};
const inboundCreateV2Reality = {
  reality: z.object({
    targetHost: z.string().trim().min(1).max(253),
    targetPort: z.number().int().min(1).max(65535),
    serverName: z.string().trim().min(1).max(253),
    fingerprint: z.literal("chrome"),
    spiderX: z.string().trim().min(1).max(256),
  }).strict(),
};
const inboundCreateV2Tls = {
  tlsCertificateId: positiveId,
  serverName: z.string().trim().min(1).max(253)
    .regex(/^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/),
};
const inboundPathSpec = z.object({
  path: z.string().min(1).max(128).regex(/^\/[A-Za-z0-9._~/-]*$/),
}).strict();
const inboundGrpcSpec = z.object({
  serviceName: z.string().min(1).max(128).regex(/^[A-Za-z0-9._~-]+$/),
}).strict();
const inboundTunnelTargetAddress = z.string().trim().min(1).max(253).transform((value, ctx) => {
  const normalized = normalizeXrayTunnelTargetAddress(value);
  if (!normalized) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "Tunnel target address is invalid" });
    return z.NEVER;
  }
  return normalized;
});
const inboundCreateV2Input = z.discriminatedUnion("profileId", [
  z.object({
    ...inboundCreateV2Base,
    ...inboundCreateV2Reality,
    profileId: z.literal("VLESS_RAW_REALITY_VISION"),
    spec: z.object({}).strict(),
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    ...inboundCreateV2Reality,
    profileId: z.literal("VLESS_GRPC_REALITY"),
    spec: inboundGrpcSpec,
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    ...inboundCreateV2Reality,
    profileId: z.literal("VLESS_XHTTP_REALITY"),
    spec: inboundPathSpec,
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    ...inboundCreateV2Reality,
    profileId: z.literal("TROJAN_RAW_REALITY"),
    spec: z.object({}).strict(),
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    ...inboundCreateV2Tls,
    profileId: z.literal("VLESS_RAW_TLS"),
    spec: z.object({}).strict(),
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    ...inboundCreateV2Tls,
    profileId: z.literal("VLESS_RAW_TLS_VISION"),
    spec: z.object({}).strict(),
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    ...inboundCreateV2Tls,
    profileId: z.literal("VMESS_RAW_TLS"),
    spec: z.object({}).strict(),
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    profileId: z.literal("SHADOWSOCKS_2022_RAW_NONE"),
    spec: z.object({}).strict(),
  }).strict(),
  z.object({
    ...inboundCreateV2SharedBase,
    portReservations: z.object({ tcp: operationId, udp: operationId }).strict(),
    profileId: z.literal("SHADOWSOCKS_2022_RAW_TCP_UDP_NONE"),
    spec: z.object({}).strict(),
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    profileId: z.literal("WIREGUARD_UDP_NONE"),
    spec: z.object({}).strict(),
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    profileId: z.literal("HTTP_RAW_NONE"),
    spec: z.object({}).strict(),
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    profileId: z.literal("MIXED_RAW_NONE"),
    spec: z.object({}).strict(),
  }).strict(),
  z.object({
    hostId: positiveId,
    name: z.string().trim().min(1).max(128),
    listenPort: z.number().int().min(1000).max(65535),
    portReservationId: operationId,
    profileId: z.literal("TUNNEL_TCP_LOCAL_NONE"),
    spec: z.object({
      targetAddress: inboundTunnelTargetAddress,
      targetPort: z.number().int().min(1).max(65535),
    }).strict(),
    initialAccessEntries: z.array(z.never()).length(0),
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    ...inboundCreateV2Tls,
    profileId: z.literal("TROJAN_RAW_TLS"),
    spec: z.object({}).strict(),
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    ...inboundCreateV2Tls,
    profileId: z.literal("VLESS_WEBSOCKET_TLS"),
    spec: inboundPathSpec,
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    ...inboundCreateV2Tls,
    profileId: z.literal("TROJAN_WEBSOCKET_TLS"),
    spec: inboundPathSpec,
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    ...inboundCreateV2Tls,
    profileId: z.literal("VLESS_GRPC_TLS"),
    spec: inboundGrpcSpec,
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    ...inboundCreateV2Tls,
    profileId: z.literal("TROJAN_GRPC_TLS"),
    spec: inboundGrpcSpec,
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    ...inboundCreateV2Tls,
    profileId: z.literal("VLESS_HTTP_UPGRADE_TLS"),
    spec: inboundPathSpec,
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    ...inboundCreateV2Tls,
    profileId: z.literal("TROJAN_HTTP_UPGRADE_TLS"),
    spec: inboundPathSpec,
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    ...inboundCreateV2Tls,
    profileId: z.literal("VLESS_XHTTP_TLS"),
    spec: inboundPathSpec,
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    ...inboundCreateV2Tls,
    profileId: z.literal("TROJAN_XHTTP_TLS"),
    spec: inboundPathSpec,
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    ...inboundCreateV2Tls,
    profileId: z.literal("VLESS_MKCP_TLS"),
    spec: z.object({}).strict(),
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    ...inboundCreateV2Tls,
    profileId: z.literal("TROJAN_MKCP_TLS"),
    spec: z.object({}).strict(),
  }).strict(),
  z.object({
    ...inboundCreateV2Base,
    ...inboundCreateV2Tls,
    profileId: z.literal("HYSTERIA2_TLS"),
    spec: z.object({}).strict(),
  }).strict(),
]).superRefine((input, ctx) => {
  const names = input.initialAccessEntries.map((entry) => entry.name.toLocaleLowerCase());
  if (new Set(names).size !== names.length) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["initialAccessEntries"], message: "Access entry names must be unique" });
  }
});

const inboundUpdateInput = z.object({
  id: positiveId,
  name: z.string().trim().min(1).max(128).optional(),
  publicAddress: z.string().trim().min(1).max(253).optional(),
  listenPort: z.number().int().min(1000).max(65535).optional(),
  portReservationId: operationId.optional(),
  expectedGeneration: generation,
}).strict().superRefine((input, ctx) => {
  if (input.name === undefined && input.publicAddress === undefined && input.listenPort === undefined) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: "At least one inbound field is required" });
  }
  if ((input.listenPort === undefined) !== (input.portReservationId === undefined)) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["portReservationId"], message: "Port changes require a reservation" });
  }
});

function internalXrayTrpcError(): never {
  appendXrayStructuredLog("error", "API_INTERNAL_ERROR", { errorCode: "INTERNAL_ERROR" });
  throw new TRPCError({ code: "INTERNAL_SERVER_ERROR", message: "INTERNAL_ERROR" });
}

function inboundCreateTrpcError(error: unknown): never {
  if (!(error instanceof XrayInboundCreateError)) return internalXrayTrpcError();
  const code = error.code === "HOST_NOT_FOUND" || error.code === "INBOUND_NOT_FOUND"
      || error.code === "EXTERNAL_PROXY_NOT_FOUND" ? "NOT_FOUND"
    : error.code === "CONFIG_GENERATION_CONFLICT" || error.code === "OPERATION_CONFLICT"
      || error.code === "GLOBAL_PORT_CONFLICT" || error.code === "GLOBAL_PORT_LEGACY_CONFLICT"
      || error.code === "GLOBAL_PORT_SCAN_PENDING" || error.code === "GLOBAL_PORT_EXTERNAL_OCCUPIED" ? "CONFLICT"
      : error.code === "HOST_OFFLINE" || error.code === "AGENT_CAPABILITY_MISSING"
        || error.code === "UDP_CAPABILITY_REQUIRED" ? "PRECONDITION_FAILED" : "BAD_REQUEST";
  throw new TRPCError({ code, message: error.code, cause: error });
}

function clientTrpcError(error: unknown): never {
  if (!(error instanceof XrayClientServiceError)) return internalXrayTrpcError();
  const code = error.code === "HOST_NOT_FOUND" || error.code === "INBOUND_NOT_FOUND" || error.code === "CLIENT_NOT_FOUND"
    ? "NOT_FOUND"
    : error.code === "CONFIG_GENERATION_CONFLICT" || error.code === "OPERATION_CONFLICT" ? "CONFLICT"
      : error.code === "HOST_OFFLINE" || error.code === "AGENT_CAPABILITY_MISSING" ? "PRECONDITION_FAILED"
        : error.code === "SENSITIVE_DATA_UNAVAILABLE" ? "INTERNAL_SERVER_ERROR" : "BAD_REQUEST";
  throw new TRPCError({ code, message: error.code, cause: error });
}

function accessTrpcError(error: unknown): never {
  if (!(error instanceof XrayAccessServiceError)) return internalXrayTrpcError();
  const code = error.code === "HOST_NOT_FOUND" || error.code === "INBOUND_NOT_FOUND" || error.code === "CLIENT_NOT_FOUND"
    ? "NOT_FOUND"
    : error.code === "CONFIG_GENERATION_CONFLICT" || error.code === "OPERATION_CONFLICT" ? "CONFLICT"
      : error.code === "HOST_OFFLINE" || error.code === "AGENT_CAPABILITY_MISSING"
        || error.code === "UDP_CAPABILITY_REQUIRED" ? "PRECONDITION_FAILED"
        : error.code === "SENSITIVE_DATA_UNAVAILABLE" ? "INTERNAL_SERVER_ERROR" : "BAD_REQUEST";
  throw new TRPCError({ code, message: error.code, cause: error });
}

function portProbeTrpcError(error: unknown): never {
  if (!(error instanceof XrayPortOperationError)) return internalXrayTrpcError();
  const code = error.code === "HOST_NOT_FOUND" ? "NOT_FOUND"
    : error.code === "HOST_OFFLINE" || error.code === "AGENT_CAPABILITY_MISSING" || error.code === "UDP_CAPABILITY_REQUIRED"
      || error.code === "PORT_RESERVATION_EXPIRED"
      ? "PRECONDITION_FAILED"
      : error.code === "PORT_IN_USE" || error.code === "OPERATION_CONFLICT" ? "CONFLICT"
        : error.code === "PORT_RESERVATION_MISMATCH" ? "FORBIDDEN" : "BAD_REQUEST";
  throw new TRPCError({ code, message: error.code, cause: error });
}

function realityScanTrpcError(error: unknown): never {
  if (!(error instanceof XrayRealityOperationError)) return internalXrayTrpcError();
  const code = error.code === "HOST_NOT_FOUND" ? "NOT_FOUND"
    : error.code === "HOST_OFFLINE" || error.code === "AGENT_CAPABILITY_MISSING" ? "PRECONDITION_FAILED"
      : error.code === "OPERATION_CONFLICT" ? "CONFLICT" : "BAD_REQUEST";
  throw new TRPCError({ code, message: error.code, cause: error });
}

function runtimeTrpcError(error: unknown): never {
  if (!(error instanceof XrayRuntimeServiceError)) return internalXrayTrpcError();
  const code = error.code === "HOST_NOT_FOUND" ? "NOT_FOUND"
    : error.code === "HOST_OFFLINE" || error.code === "AGENT_CAPABILITY_MISSING"
      || error.code === "PLATFORM_UNSUPPORTED" || error.code === "ARTIFACT_UNAVAILABLE" || error.code === "RUNTIME_NOT_READY"
      ? "PRECONDITION_FAILED"
      : error.code === "OPERATION_CONFLICT" || error.code === "XRAY_VERSION_MISMATCH" || error.code === "DOWNGRADE_NOT_ALLOWED" ? "CONFLICT"
        : "BAD_REQUEST";
  throw new TRPCError({ code, message: error.code, cause: error });
}

function certificateTrpcError(error: unknown): never {
  if (!(error instanceof XrayTlsCertificateServiceError)) return internalXrayTrpcError();
  const code = error.code === "HOST_NOT_FOUND" || error.code === "CERTIFICATE_NOT_FOUND" ? "NOT_FOUND"
    : error.code === "HOST_OFFLINE" || error.code === "AGENT_CAPABILITY_MISSING" ? "PRECONDITION_FAILED"
      : error.code === "CERTIFICATE_CONFLICT" || error.code === "CERTIFICATE_IN_USE"
        || error.code === "CONFIG_GENERATION_CONFLICT" || error.code === "OPERATION_CONFLICT" ? "CONFLICT"
        : error.code === "SENSITIVE_DATA_UNAVAILABLE" || error.code === "INVALID_CERTIFICATE_DATA"
          ? "INTERNAL_SERVER_ERROR" : "BAD_REQUEST";
  throw new TRPCError({ code, message: error.code, cause: error });
}

function managedServiceTrpcError(error: unknown): never {
  if (error instanceof XrayPortOperationError) return portProbeTrpcError(error);
  if (!(error instanceof XrayManagedServiceError)) return internalXrayTrpcError();
  const code = error.code === "HOST_NOT_FOUND" || error.code === "MANAGED_SERVICE_NOT_FOUND"
    || error.code === "MANAGED_SERVICE_ACCOUNT_NOT_FOUND" ? "NOT_FOUND"
    : error.code === "HOST_OFFLINE" || error.code === "MANAGED_SERVICE_CAPABILITY_MISSING"
      || error.code === "MANAGED_SERVICE_ARTIFACT_UNAVAILABLE" || error.code === "PORT_RESERVATION_EXPIRED"
      ? "PRECONDITION_FAILED"
      : error.code === "MANAGED_SERVICE_GENERATION_CONFLICT" || error.code === "LAST_ACTIVE_ACCOUNT_REQUIRED"
        ? "CONFLICT"
        : error.code === "PORT_RESERVATION_MISMATCH" ? "FORBIDDEN"
          : error.code === "SENSITIVE_DATA_UNAVAILABLE" ? "INTERNAL_SERVER_ERROR" : "BAD_REQUEST";
  throw new TRPCError({ code, message: error.code, cause: error });
}

function externalProxyTrpcError(error: unknown): never {
  if (!(error instanceof XrayExternalProxyServiceError)) return internalXrayTrpcError();
  const code = error.code === "EXTERNAL_PROXY_NOT_FOUND" ? "NOT_FOUND"
    : error.code === "EXTERNAL_PROXY_IN_USE" ? "CONFLICT"
      : error.code === "SENSITIVE_DATA_UNAVAILABLE" || error.code === "EXTERNAL_PROXY_REFERENCE_INVALID"
        ? "INTERNAL_SERVER_ERROR" : "BAD_REQUEST";
  throw new TRPCError({ code, message: error.code, cause: error });
}

function dnsProviderAccountTrpcError(error: unknown): never {
  if (!(error instanceof DnsProviderAccountServiceError)) return internalXrayTrpcError();
  const code = error.code === "DNS_PROVIDER_IN_USE" || error.code === "DNS_PROVIDER_CONFLICT"
    ? "CONFLICT"
    : error.code === "DNS_PROVIDER_NOT_CONFIGURED" || error.code === "DNS_PROVIDER_VALIDATION_STALE"
      || error.code === "DNS_PROVIDER_CATALOG_STALE" || error.code === "DNS_PROVIDER_LINE_MISSING"
      || error.code === "DNS_PROVIDER_LINE_AMBIGUOUS" || error.code === "DNS_PROVIDER_NO_ZONES"
      ? "PRECONDITION_FAILED"
      : error.code === "SENSITIVE_DATA_UNAVAILABLE" ? "INTERNAL_SERVER_ERROR" : "BAD_REQUEST";
  throw new TRPCError({ code, message: error.code, cause: error });
}

function dnsProviderRecordTrpcError(error: unknown): never {
  if (!(error instanceof DnsProviderRecordServiceError)) return internalXrayTrpcError();
  const code = error.code === "DNS_ZONE_NOT_FOUND" || error.code === "DNS_RECORD_NOT_FOUND"
    ? "NOT_FOUND"
    : error.code === "DNS_ZONE_IN_USE" || error.code === "DNS_RECORD_CHANGED"
      ? "CONFLICT"
      : error.code === "DNS_PROVIDER_NOT_CONFIGURED" || error.code === "DNS_PROVIDER_VALIDATION_STALE"
        || error.code === "DNS_PROVIDER_CATALOG_STALE"
        ? "PRECONDITION_FAILED"
        : error.code === "DNS_PROVIDER_UNAVAILABLE" || error.code === "DNS_PROVIDER_INVALID_RESPONSE"
          || error.code === "DNS_WRITE_UNCERTAIN"
          ? "BAD_GATEWAY"
          : error.code === "SENSITIVE_DATA_UNAVAILABLE" ? "INTERNAL_SERVER_ERROR" : "BAD_REQUEST";
  throw new TRPCError({ code, message: error.code, cause: error });
}

function quickConfigTrpcError(error: unknown): never {
  if (error instanceof XrayQuickConfigSyncError) {
    const code = error.code === "QUICK_CONFIG_NOT_FOUND" ? "NOT_FOUND"
      : error.code === "QUICK_CONFIG_REVISION_CONFLICT" || error.code === "QUICK_CONFIG_OPERATION_CONFLICT"
        || error.code === "QUICK_CONFIG_SYNC_CONFLICT" || error.code === "GLOBAL_PORT_CONFLICT"
        || error.code === "DNS_RECORD_DRIFT"
        ? "CONFLICT"
        : error.code === "SENSITIVE_DATA_UNAVAILABLE" ? "INTERNAL_SERVER_ERROR"
          : "PRECONDITION_FAILED";
    throw new TRPCError({ code, message: error.code, cause: error });
  }
  if (error instanceof XrayQuickConfigEditError) {
    const code = error.code === "QUICK_CONFIG_NOT_FOUND" ? "NOT_FOUND"
      : error.code === "QUICK_CONFIG_REVISION_CONFLICT" || error.code === "QUICK_CONFIG_OPERATION_CONFLICT"
      || error.code === "DNS_PROVIDER_CONFLICT_CHANGED" || error.code === "DNS_RECORD_DRIFT"
      ? "CONFLICT"
      : error.code === "QUICK_CONFIG_PREVIEW_INVALID" ? "BAD_REQUEST" : "PRECONDITION_FAILED";
    throw new TRPCError({ code, message: error.code, cause: error });
  }
  if (error instanceof XrayQuickConfigRetryError) {
    const code = error.code === "QUICK_CONFIG_NOT_FOUND" ? "NOT_FOUND"
      : error.code === "QUICK_CONFIG_REVISION_CONFLICT" || error.code === "QUICK_CONFIG_OPERATION_CONFLICT"
        || error.code === "DNS_RECORD_DRIFT" || error.code === "GLOBAL_PORT_CONFLICT"
        ? "CONFLICT" : "PRECONDITION_FAILED";
    throw new TRPCError({ code, message: error.code, cause: error });
  }
  if (error instanceof XrayQuickConfigEngineSwitchError) {
    const code = error.code === "QUICK_CONFIG_NOT_FOUND" ? "NOT_FOUND"
      : error.code === "QUICK_CONFIG_REVISION_CONFLICT" || error.code === "QUICK_CONFIG_OPERATION_CONFLICT"
        ? "CONFLICT"
        : error.code === "SENSITIVE_DATA_UNAVAILABLE" ? "INTERNAL_SERVER_ERROR"
          : error.code === "QUICK_CONFIG_PREVIEW_INVALID" ? "BAD_REQUEST" : "PRECONDITION_FAILED";
    throw new TRPCError({ code, message: error.code, cause: error });
  }
  if (error instanceof XrayQuickConfigForwardEngineCatalogError) {
    throw new TRPCError({ code: "PRECONDITION_FAILED", message: error.code, cause: error });
  }
  if (error instanceof XrayQuickConfigShareError) {
    const code = error.code === "QUICK_CONFIG_NOT_FOUND" ? "NOT_FOUND"
      : error.code === "SENSITIVE_DATA_UNAVAILABLE" ? "INTERNAL_SERVER_ERROR" : "PRECONDITION_FAILED";
    throw new TRPCError({ code, message: error.code, cause: error });
  }
  if (error instanceof XrayQuickConfigQueryError) {
    throw new TRPCError({ code: "NOT_FOUND", message: error.code, cause: error });
  }
  if (error instanceof XrayQuickConfigLifecycleError) {
    const code = error.code === "QUICK_CONFIG_NOT_FOUND" ? "NOT_FOUND"
      : error.code === "QUICK_CONFIG_REVISION_CONFLICT" || error.code === "QUICK_CONFIG_OPERATION_CONFLICT"
        || error.code === "DNS_RECORD_DRIFT" || error.code === "DNS_PROVIDER_CONFLICT"
        ? "CONFLICT"
        : error.code === "SENSITIVE_DATA_UNAVAILABLE" ? "INTERNAL_SERVER_ERROR"
          : error.code === "QUICK_CONFIG_REMOVE_TOKEN_INVALID" ? "BAD_REQUEST" : "PRECONDITION_FAILED";
    throw new TRPCError({ code, message: error.code, cause: error });
  }
  if (error instanceof XrayQuickConfigOperationError) {
    const code = error.code === "DOMAIN_ALREADY_MANAGED" || error.code === "QUICK_CONFIG_APPLY_CONFLICT"
      || error.code === "DNS_PROVIDER_CONFLICT_CHANGED" ? "CONFLICT"
      : error.code === "RULE_APPLY_FAILED" || error.code === "DNS_APPLY_FAILED"
        ? "PRECONDITION_FAILED" : "BAD_REQUEST";
    throw new TRPCError({ code, message: error.code, cause: error });
  }
  if (error instanceof XrayQuickConfigPlanningError) {
    const code = error.code === "QUICK_CONFIG_TARGET_CHANGED" ? "CONFLICT"
      : error.code === "QUICK_CONFIG_TARGET_UNSUPPORTED" || error.code === "QUICK_CONFIG_HOST_UNAVAILABLE"
        || error.code === "QUICK_CONFIG_ADDRESS_UNAVAILABLE" || error.code === "FORWARD_PROTOCOL_DISABLED"
        || error.code === "AGENT_CAPABILITY_MISSING" || error.code === "HOST_OFFLINE"
        || error.code === "UDP_CAPABILITY_REQUIRED"
        || error.code === "GLOBAL_PORT_PROBE_FAILED" || error.code === "GLOBAL_PORT_PROBE_EXPIRED"
        || error.code === "QUICK_CONFIG_PREVIEW_EXPIRED"
        ? "PRECONDITION_FAILED"
        : error.code === "SENSITIVE_DATA_UNAVAILABLE" ? "INTERNAL_SERVER_ERROR" : "BAD_REQUEST";
    throw new TRPCError({ code, message: error.code, cause: error });
  }
  if (!(error instanceof XrayQuickConfigServiceError)) return internalXrayTrpcError();
  const code = error.code === "DOMAIN_ALREADY_MANAGED" || error.code === "DOMAIN_CONFLICT_CHANGED"
      || error.code === "QUICK_CONFIG_TARGET_CHANGED" || error.code === "DNS_PROVIDER_CONFLICT"
    ? "CONFLICT"
    : error.code === "QUICK_CONFIG_TARGET_UNSUPPORTED" || error.code === "DOMAIN_CHECK_EXPIRED"
      || error.code === "DOMAIN_CONFIRMATION_EXPIRED" || error.code === "DNS_PROVIDER_NOT_CONFIGURED"
      || error.code === "DNS_PROVIDER_VALIDATION_STALE" || error.code === "DNS_PROVIDER_CATALOG_STALE"
      || error.code === "DNS_PROVIDER_LINE_MISSING" || error.code === "DNS_PROVIDER_LINE_AMBIGUOUS"
      || error.code === "DNS_PROVIDER_NO_ZONES"
      ? "PRECONDITION_FAILED"
      : error.code === "SENSITIVE_DATA_UNAVAILABLE" ? "INTERNAL_SERVER_ERROR" : "BAD_REQUEST";
  throw new TRPCError({ code, message: error.code, cause: error });
}

const clientCreateInput = z.object({
  inboundId: positiveId,
  name: clientName,
  flow: z.enum(["xtls-rprx-vision", ""]),
  expectedGeneration: generation,
}).strict();

const clientUpdateInput = z.object({
  id: positiveId,
  name: clientName.optional(),
  flow: z.enum(["xtls-rprx-vision", ""]).optional(),
  isEnabled: z.boolean().optional(),
  expectedGeneration: generation,
}).strict().refine((input) => input.name !== undefined || input.flow !== undefined || input.isEnabled !== undefined, {
  message: "At least one client field is required",
});

export const xrayRouter = router({
  profiles: router({
    catalog: adminProcedure
      .input(z.object({ hostId: positiveId.optional() }).strict().optional())
      .query(({ input }) => getXrayProfileCatalog(input?.hostId)),
  }),
  hosts: router({
    options: adminProcedure.query(() => listXrayHostOptions()),
  }),
  dnsProviderAccounts: router({
    getGlobal: adminProcedure.query(async ({ ctx }) => {
      setSensitiveResponseHeaders(ctx.res);
      try {
        return await getGlobalDnsProviderAccountService();
      } catch (error) {
        dnsProviderAccountTrpcError(error);
      }
    }),
    upsertGlobal: adminProcedure
      .input(dnsProviderUpsertInput)
      .mutation(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await upsertGlobalDnsProviderAccount({ ...input, userId: ctx.user.id });
        } catch (error) {
          dnsProviderAccountTrpcError(error);
        }
      }),
    revalidateGlobal: adminProcedure
      .input(dnsProviderRevisionInput)
      .mutation(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await revalidateGlobalDnsProviderAccount(input);
        } catch (error) {
          dnsProviderAccountTrpcError(error);
        }
      }),
    removeGlobal: adminProcedure
      .input(dnsProviderRemoveInput)
      .mutation(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await removeGlobalDnsProviderAccount(input);
        } catch (error) {
          dnsProviderAccountTrpcError(error);
        }
      }),
    zones: adminProcedure
      .input(z.object({ refresh: z.boolean().optional() }).strict().optional())
      .query(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await listGlobalDnsProviderZonesService(input ?? {});
        } catch (error) {
          dnsProviderAccountTrpcError(error);
        }
      }),
  }),
  dnsRecords: router({
    list: adminProcedure
      .input(z.object({
        zoneId: positiveId,
        search: z.string().trim().max(128).optional(),
        recordType: z.string().trim().min(1).max(16).regex(/^[A-Za-z][A-Za-z0-9]{0,15}$/).optional(),
        page,
        pageSize: pageSize.default(20),
      }).strict())
      .query(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await listDnsProviderRecords(input);
        } catch (error) {
          dnsProviderRecordTrpcError(error);
        }
      }),
    create: adminProcedure
      .input(dnsRecordWriteInput)
      .mutation(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await createDnsProviderRecord(input);
        } catch (error) {
          dnsProviderRecordTrpcError(error);
        }
      }),
    update: adminProcedure
      .input(dnsRecordWriteInput.extend({
        providerRecordId: dnsProviderRecordId,
        expectedRecordRevision: dnsRecordRevision,
      }).strict())
      .mutation(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await updateDnsProviderRecord(input);
        } catch (error) {
          dnsProviderRecordTrpcError(error);
        }
      }),
    remove: adminProcedure
      .input(z.object({
        zoneId: positiveId,
        providerRecordId: dnsProviderRecordId,
        expectedRecordRevision: dnsRecordRevision,
      }).strict())
      .mutation(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await removeDnsProviderRecord(input);
        } catch (error) {
          dnsProviderRecordTrpcError(error);
        }
      }),
  }),
  quickConfigs: router({
    entryHostsList: xrayQuickConfigEntryHostsListProcedure,
    forwardEngines: adminProcedure
      .input(z.object({ entries: z.array(quickConfigEndpoint).min(1).max(128) }).strict())
      .query(async ({ input }) => {
        try {
          return await listXrayQuickConfigForwardEngines(input);
        } catch (error) {
          quickConfigTrpcError(error);
        }
      }),
    targetsList: adminProcedure
      .input(z.object({
        search: z.string().trim().max(128).default(""),
        targetType: quickConfigTargetType.optional(),
        page,
        pageSize: pageSize.default(20),
      }).strict().optional())
      .query(async ({ input }) => {
        try {
          return await listQuickConfigTargets(input ?? {});
        } catch (error) {
          quickConfigTrpcError(error);
        }
      }),
    domainChecksCreate: adminProcedure
      .input(quickConfigDomainCreateInput)
      .mutation(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await createQuickConfigDomainCheck({ ...input, userId: ctx.user.id });
        } catch (error) {
          quickConfigTrpcError(error);
        }
      }),
    domainChecksConfirm: adminProcedure
      .input(quickConfigDomainConfirmInput)
      .mutation(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await confirmQuickConfigDomainCheck({ ...input, userId: ctx.user.id });
        } catch (error) {
          quickConfigTrpcError(error);
        }
      }),
    portChecksCreate: adminProcedure
      .input(quickConfigPortCheckCreateInput)
      .mutation(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await createQuickConfigPortCheck({ ...input, userId: ctx.user.id });
        } catch (error) {
          quickConfigTrpcError(error);
        }
      }),
    portChecksResult: adminProcedure
      .input(z.object({ portCheckId: quickConfigToken }).strict())
      .query(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await getQuickConfigPortCheckResult({ ...input, userId: ctx.user.id });
        } catch (error) {
          quickConfigTrpcError(error);
        }
      }),
    preview: adminProcedure
      .input(quickConfigPreviewInput)
      .mutation(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await previewQuickConfig({ ...input, userId: ctx.user.id });
        } catch (error) {
          quickConfigTrpcError(error);
        }
      }),
    editPreview: adminProcedure
      .input(quickConfigPreviewInput.extend({
        quickConfigId: positiveId,
        expectedRevision: positiveId,
      }).strict())
      .mutation(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await previewQuickConfigEdit({ ...input, userId: ctx.user.id });
        } catch (error) {
          quickConfigTrpcError(error);
        }
      }),
    createApply: adminProcedure
      .input(z.object({ previewToken: quickConfigToken }).strict())
      .mutation(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await applyQuickConfigPreview({ previewToken: input.previewToken, userId: ctx.user.id });
        } catch (error) {
          quickConfigTrpcError(error);
        }
      }),
    editApply: adminProcedure
      .input(z.object({ previewToken: quickConfigToken }).strict())
      .mutation(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await applyQuickConfigEditPreview({ previewToken: input.previewToken, userId: ctx.user.id });
        } catch (error) {
          quickConfigTrpcError(error);
        }
      }),
    engineSwitchPreview: adminProcedure
      .input(z.object({
        id: positiveId,
        expectedRevision: positiveId,
        engine: quickConfigForwardEngine,
      }).strict())
      .mutation(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await previewXrayQuickConfigEngineSwitch({ ...input, userId: ctx.user.id });
        } catch (error) {
          quickConfigTrpcError(error);
        }
      }),
    engineSwitchApply: adminProcedure
      .input(z.object({ switchToken: quickConfigToken }).strict())
      .mutation(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await applyXrayQuickConfigEngineSwitch({ ...input, userId: ctx.user.id });
        } catch (error) {
          quickConfigTrpcError(error);
        }
      }),
    removePreview: adminProcedure
      .input(z.object({ id: positiveId, expectedRevision: positiveId }).strict())
      .mutation(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await previewQuickConfigRemove({ ...input, userId: ctx.user.id });
        } catch (error) {
          quickConfigTrpcError(error);
        }
      }),
    removeApply: adminProcedure
      .input(z.object({
        removeToken: quickConfigToken,
        confirmFqdn: z.string().trim().min(1).max(253),
      }).strict())
      .mutation(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await applyQuickConfigRemove({ ...input, userId: ctx.user.id });
        } catch (error) {
          quickConfigTrpcError(error);
        }
      }),
    retry: adminProcedure
      .input(z.object({ operationId: positiveId, expectedOperationRevision: positiveId }).strict())
      .mutation(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await retryQuickConfigOperation({ ...input, userId: ctx.user.id });
        } catch (error) {
          quickConfigTrpcError(error);
        }
      }),
    sync: adminProcedure
      .input(z.object({ id: positiveId, expectedRevision: positiveId }).strict())
      .mutation(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await createXrayQuickConfigSync({ ...input, userId: ctx.user.id });
        } catch (error) {
          quickConfigTrpcError(error);
        }
      }),
    list: adminProcedure
      .input(quickConfigListInput.optional())
      .query(async ({ input }) => {
        try {
          return await listXrayQuickConfigs(input ?? {});
        } catch (error) {
          quickConfigTrpcError(error);
        }
      }),
    detail: adminProcedure
      .input(z.object({ id: positiveId }).strict())
      .query(async ({ input }) => {
        try {
          return await getXrayQuickConfigDetail(input.id);
        } catch (error) {
          quickConfigTrpcError(error);
        }
      }),
    operation: adminProcedure
      .input(z.object({ operationId: positiveId }).strict())
      .query(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await getXrayQuickConfigOperation(input.operationId);
        } catch (error) {
          quickConfigTrpcError(error);
        }
      }),
    share: adminProcedure
      .input(z.object({
        id: positiveId,
        accessRef: quickConfigShareAccessRef.optional(),
      }).strict())
      .query(async ({ input, ctx }) => {
        setSensitiveResponseHeaders(ctx.res);
        try {
          return await getXrayQuickConfigDerivedShare({
            quickConfigId: input.id,
            userId: ctx.user.id,
            accessRef: input.accessRef,
          });
        } catch (error) {
          quickConfigTrpcError(error);
        }
      }),
  }),
  externalProxyNodes: router({
    previewImport: adminProcedure
      .input(z.object({ uri: z.string().min(1).max(4096) }).strict())
      .mutation(({ input, ctx }) => {
        ctx.res.setHeader("Cache-Control", "private, no-store, max-age=0");
        ctx.res.setHeader("Pragma", "no-cache");
        try { return previewXrayExternalProxyImport(input.uri); } catch (error) { externalProxyTrpcError(error); }
      }),
    list: adminProcedure
      .input(z.object({
        page,
        pageSize: pageSize.default(20),
        search: z.string().trim().max(128).default(""),
        protocol: z.enum(["VLESS_REALITY_VISION", "SHADOWSOCKS", "SOCKS5"]).optional(),
      }).strict().optional())
      .query(async ({ input }) => {
        try { return await listXrayExternalProxyNodes(input ?? {}); } catch (error) { externalProxyTrpcError(error); }
      }),
    detail: adminProcedure
      .input(z.object({ id: positiveId }).strict())
      .query(async ({ input }) => {
        try { return await getXrayExternalProxyNodeDetail(input.id); } catch (error) { externalProxyTrpcError(error); }
      }),
    share: adminProcedure
      .input(z.object({ id: positiveId, relayRuleId: positiveId.optional() }).strict())
      .mutation(async ({ input, ctx }) => {
        ctx.res.setHeader("Cache-Control", "private, no-store, max-age=0");
        ctx.res.setHeader("Pragma", "no-cache");
        try {
          const uri = input.relayRuleId === undefined
            ? await buildXrayExternalProxyShare(input.id)
            : await buildXrayExternalProxyRelayShare({ id: input.id, relayRuleId: input.relayRuleId });
          return { uri };
        } catch (error) {
          externalProxyTrpcError(error);
        }
      }),
    create: adminProcedure
      .input(z.object({ name: z.string().trim().min(1).max(128), uri: z.string().min(1).max(4096) }).strict())
      .mutation(async ({ input, ctx }) => {
        try { return await createXrayExternalProxyNode({ ...input, createdByUserId: ctx.user.id }); } catch (error) { externalProxyTrpcError(error); }
      }),
    rename: adminProcedure
      .input(z.object({ id: positiveId, name: z.string().trim().min(1).max(128) }).strict())
      .mutation(async ({ input }) => {
        try { return await renameXrayExternalProxyNode(input); } catch (error) { externalProxyTrpcError(error); }
      }),
    replace: adminProcedure
      .input(z.object({ id: positiveId, uri: z.string().min(1).max(4096) }).strict())
      .mutation(async ({ input }) => {
        try { return await replaceXrayExternalProxyNode(input); } catch (error) { externalProxyTrpcError(error); }
      }),
    remove: adminProcedure
      .input(z.object({ id: positiveId, confirmName: z.string().min(1).max(128) }).strict())
      .mutation(async ({ input }) => {
        try { return await removeXrayExternalProxyNode(input); } catch (error) { externalProxyTrpcError(error); }
      }),
  }),
  portProbes: router({
    create: adminProcedure
      .input(portProbeCreateInput)
      .mutation(async ({ input, ctx }) => {
        try {
          return await createXrayPortProbeOperation({ ...input, userId: ctx.user.id });
        } catch (error) {
          portProbeTrpcError(error);
        }
      }),
    result: adminProcedure
      .input(z.object({ operationId }).strict())
      .query(async ({ input, ctx }) => {
        try {
          return await getXrayPortProbeOperationResult(input.operationId, ctx.user.id);
        } catch (error) {
          portProbeTrpcError(error);
        }
      }),
  }),
  realityScans: router({
    create: adminProcedure
      .input(realityScanCreateInput)
      .mutation(async ({ input, ctx }) => {
        try {
          return await createXrayRealityScanOperation({ ...input, userId: ctx.user.id });
        } catch (error) {
          realityScanTrpcError(error);
        }
      }),
    result: adminProcedure
      .input(z.object({ operationId }).strict())
      .query(async ({ input, ctx }) => {
        try {
          return await getXrayRealityScanOperationResult(input.operationId, ctx.user.id);
        } catch (error) {
          realityScanTrpcError(error);
        }
      }),
  }),
  certificates: router({
    list: adminProcedure
      .input(z.object({
        hostId: positiveId.optional(),
        search: z.string().trim().max(128).default(""),
        page,
        pageSize: pageSize.default(20),
      }).strict().optional())
      .query(async ({ input }) => {
        try {
          return await listManagedXrayTlsCertificates(input ?? {});
        } catch (error) {
          certificateTrpcError(error);
        }
      }),
    import: adminProcedure
      .input(z.object({
        hostId: positiveId,
        name: z.string().trim().min(1).max(128),
        certificatePem,
        privateKeyPem,
      }).strict())
      .mutation(async ({ input, ctx }) => {
        try {
          return await importManagedXrayTlsCertificate({ ...input, userId: ctx.user.id });
        } catch (error) {
          certificateTrpcError(error);
        }
      }),
    rotate: adminProcedure
      .input(z.object({
        id: positiveId,
        certificatePem,
        privateKeyPem,
        expectedGeneration: generation,
      }).strict())
      .mutation(async ({ input, ctx }) => {
        try {
          return await rotateManagedXrayTlsCertificate({ ...input, userId: ctx.user.id });
        } catch (error) {
          certificateTrpcError(error);
        }
      }),
    remove: adminProcedure
      .input(z.object({ id: positiveId, confirmName: z.string().min(1).max(128) }).strict())
      .mutation(async ({ input, ctx }) => {
        try {
          return await removeManagedXrayTlsCertificate({ ...input, userId: ctx.user.id });
        } catch (error) {
          certificateTrpcError(error);
        }
      }),
  }),
  managedServices: router({
    catalog: adminProcedure.query(() => getXrayManagedServiceCatalog()),
    hostOptions: adminProcedure.query(() => listXrayManagedServiceHostOptions()),
    list: adminProcedure
      .input(z.object({
        page,
        pageSize: pageSize.default(20),
        search: z.string().trim().max(128).default(""),
        hostId: positiveId.optional(),
        status: z.enum(["WAITING_SYNC", "RUNNING", "DISABLED", "PENDING_DELETE", "ERROR"]).optional(),
      }).strict().optional())
      .query(async ({ input }) => {
        try { return await listXrayManagedServices(input ?? {}); } catch (error) { managedServiceTrpcError(error); }
      }),
    detail: adminProcedure
      .input(z.object({ id: positiveId }).strict())
      .query(async ({ input }) => {
        try { return await getXrayManagedServiceDetail(input.id); } catch (error) { managedServiceTrpcError(error); }
      }),
    createMtproto: adminProcedure
      .input(z.object({
        hostId: positiveId,
        name: z.string().trim().min(1).max(128),
        publicAddress: z.string().trim().min(1).max(253),
        listenPort: z.number().int().min(1000).max(65535),
        portReservationId: operationId,
        fakeTlsDomain: z.string().trim().min(1).max(253),
        initialAccounts: z.array(z.object({ name: clientName }).strict()).min(1).max(32),
      }).strict().superRefine((input, ctx) => {
        const names = input.initialAccounts.map((account) => account.name.toLocaleLowerCase());
        if (new Set(names).size !== names.length) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["initialAccounts"], message: "Account names must be unique" });
      }))
      .mutation(async ({ input, ctx }) => {
        try {
          return await withConsumedXrayPortReservation({
            reservationId: input.portReservationId, hostId: input.hostId, userId: ctx.user.id,
            port: input.listenPort, network: "tcp",
          }, () => createXrayMtprotoService({ ...input, userId: ctx.user.id }));
        } catch (error) { managedServiceTrpcError(error); }
      }),
    createAmneziawg: adminProcedure
      .input(z.object({
        hostId: positiveId,
        name: z.string().trim().min(1).max(128),
        publicAddress: z.string().trim().min(1).max(253),
        listenPort: z.number().int().min(1000).max(65535),
        portReservationId: operationId,
        initialPeers: z.array(z.object({ name: clientName }).strict()).min(1).max(32),
      }).strict().superRefine((input, ctx) => {
        const names = input.initialPeers.map((peer) => peer.name.toLocaleLowerCase());
        if (new Set(names).size !== names.length) ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["initialPeers"], message: "Peer names must be unique" });
      }))
      .mutation(async ({ input, ctx }) => {
        try {
          return await withConsumedXrayPortReservation({ reservationId: input.portReservationId, hostId: input.hostId,
            userId: ctx.user.id, port: input.listenPort, network: "udp" },
          () => createXrayAmneziaWgService({ ...input, userId: ctx.user.id }));
        } catch (error) { managedServiceTrpcError(error); }
      }),
    update: adminProcedure
      .input(z.object({
        id: positiveId,
        name: z.string().trim().min(1).max(128).optional(),
        publicAddress: z.string().trim().min(1).max(253).optional(),
        fakeTlsDomain: z.string().trim().min(1).max(253).optional(),
        listenPort: z.number().int().min(1000).max(65535).optional(),
        portReservationId: operationId.optional(),
        hostId: positiveId.optional(),
        expectedGeneration: generation,
      }).strict().superRefine((input, ctx) => {
        if (input.name === undefined && input.publicAddress === undefined && input.fakeTlsDomain === undefined && input.listenPort === undefined) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, message: "At least one service field is required" });
        }
        const changesPort = input.listenPort !== undefined;
        if ((input.portReservationId !== undefined) !== changesPort || (input.hostId !== undefined) !== changesPort) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["portReservationId"], message: "Port changes require a host-bound reservation" });
        }
      }))
      .mutation(async ({ input, ctx }) => {
        try {
          const update = () => updateXrayManagedService({ ...input, userId: ctx.user.id });
          return input.listenPort === undefined
            ? await update()
            : await withConsumedXrayPortReservation({
              reservationId: input.portReservationId, hostId: input.hostId, userId: ctx.user.id,
              port: input.listenPort, network: "tcp",
            }, update);
        } catch (error) { managedServiceTrpcError(error); }
      }),
    updateAmneziawg: adminProcedure
      .input(z.object({
        id: positiveId,
        name: z.string().trim().min(1).max(128).optional(),
        publicAddress: z.string().trim().min(1).max(253).optional(),
        listenPort: z.number().int().min(1000).max(65535).optional(),
        portReservationId: operationId.optional(),
        hostId: positiveId.optional(),
        expectedGeneration: generation,
      }).strict().superRefine((input, ctx) => {
        if (input.name === undefined && input.publicAddress === undefined && input.listenPort === undefined) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, message: "At least one service field is required" });
        }
        const changesPort = input.listenPort !== undefined;
        if ((input.portReservationId !== undefined) !== changesPort || (input.hostId !== undefined) !== changesPort) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, path: ["portReservationId"], message: "Port changes require a host-bound reservation" });
        }
      }))
      .mutation(async ({ input, ctx }) => {
        try {
          const update = () => updateXrayAmneziaWgService({ ...input, userId: ctx.user.id });
          return input.listenPort === undefined ? await update() : await withConsumedXrayPortReservation({
            reservationId: input.portReservationId, hostId: input.hostId, userId: ctx.user.id,
            port: input.listenPort, network: "udp",
          }, update);
        } catch (error) { managedServiceTrpcError(error); }
      }),
    setEnabled: adminProcedure
      .input(z.object({ id: positiveId, isEnabled: z.boolean(), expectedGeneration: generation }).strict())
      .mutation(async ({ input, ctx }) => {
        try { return await setXrayManagedServiceEnabled({ ...input, userId: ctx.user.id }); } catch (error) { managedServiceTrpcError(error); }
      }),
    remove: adminProcedure
      .input(z.object({ id: positiveId, expectedGeneration: generation, confirmName: z.string().min(1).max(128) }).strict())
      .mutation(async ({ input, ctx }) => {
        try { return await removeXrayManagedService({ ...input, userId: ctx.user.id }); } catch (error) { managedServiceTrpcError(error); }
      }),
    share: adminProcedure
      .input(z.object({ accountId: positiveId }).strict())
      .query(async ({ input, ctx }) => {
        ctx.res.setHeader("Cache-Control", "private, no-store, max-age=0");
        ctx.res.setHeader("Pragma", "no-cache");
        try { return await getXrayManagedServiceShare(input.accountId); } catch (error) { managedServiceTrpcError(error); }
      }),
    accounts: router({
      create: adminProcedure
        .input(z.object({ serviceId: positiveId, name: clientName, expectedGeneration: generation }).strict())
        .mutation(async ({ input, ctx }) => {
          try { return await createXrayManagedServiceAccount({ ...input, userId: ctx.user.id }); } catch (error) { managedServiceTrpcError(error); }
        }),
      update: adminProcedure
        .input(z.object({ id: positiveId, name: clientName.optional(), isEnabled: z.boolean().optional(), expectedGeneration: generation }).strict()
          .refine((input) => input.name !== undefined || input.isEnabled !== undefined, "At least one account field is required"))
        .mutation(async ({ input, ctx }) => {
          try { return await updateXrayManagedServiceAccount({ ...input, userId: ctx.user.id }); } catch (error) { managedServiceTrpcError(error); }
        }),
      remove: adminProcedure
        .input(z.object({ id: positiveId, expectedGeneration: generation }).strict())
        .mutation(async ({ input, ctx }) => {
          try { return await removeXrayManagedServiceAccount({ ...input, userId: ctx.user.id }); } catch (error) { managedServiceTrpcError(error); }
        }),
    }),
  }),
  inbounds: router({
    list: adminProcedure
      .input(inboundListInput.optional())
      .query(({ input }) => listXrayInboundSummaries(input ?? {})),
    detail: adminProcedure
      .input(z.object({ id: positiveId }).strict())
      .query(async ({ input }) => {
        const detail = await getXrayInboundDetail(input.id);
        if (!detail) throw new TRPCError({ code: "NOT_FOUND", message: "Xray inbound not found" });
        return detail;
      }),
    create: adminProcedure
      .input(inboundCreateInput)
      .mutation(async ({ input, ctx }) => {
        try {
          return await createXrayInbound({ ...input, userId: ctx.user.id });
        } catch (error) {
          inboundCreateTrpcError(error);
        }
      }),
    setExternalProxy: adminProcedure
      .input(z.object({
        inboundId: positiveId,
        externalProxyNodeId: positiveId.nullable(),
        expectedGeneration: generation,
      }).strict())
      .mutation(async ({ input, ctx }) => {
        try {
          return await setXrayInboundExternalProxy({ ...input, userId: ctx.user.id });
        } catch (error) {
          inboundCreateTrpcError(error);
        }
      }),
    createV2: adminProcedure
      .input(inboundCreateV2Input)
      .mutation(async ({ input, ctx }) => {
        try {
          return await createXrayInboundV2({ ...input, userId: ctx.user.id });
        } catch (error) {
          inboundCreateTrpcError(error);
        }
      }),
    update: adminProcedure
      .input(inboundUpdateInput)
      .mutation(async ({ input, ctx }) => {
        try {
          return await updateXrayInbound({ ...input, userId: ctx.user.id });
        } catch (error) {
          inboundCreateTrpcError(error);
        }
      }),
    setEnabled: adminProcedure
      .input(z.object({ id: positiveId, isEnabled: z.boolean(), expectedGeneration: generation }).strict())
      .mutation(async ({ input, ctx }) => {
        try {
          return await setXrayInboundEnabled({ ...input, userId: ctx.user.id });
        } catch (error) {
          inboundCreateTrpcError(error);
        }
      }),
    remove: adminProcedure
      .input(z.object({ id: positiveId, expectedGeneration: generation, confirmName: z.string().min(1).max(128) }).strict())
      .mutation(async ({ input, ctx }) => {
        try {
          return await removeXrayInbound({ ...input, userId: ctx.user.id });
        } catch (error) {
          inboundCreateTrpcError(error);
        }
      }),
  }),
  clients: router({
    list: adminProcedure
      .input(z.object({ inboundId: positiveId }).strict())
      .query(async ({ input }) => {
        try {
          return await listXrayClients(input.inboundId);
        } catch (error) {
          clientTrpcError(error);
        }
      }),
    create: adminProcedure
      .input(clientCreateInput)
      .mutation(async ({ input, ctx }) => {
        try {
          return await createXrayClient({ ...input, userId: ctx.user.id });
        } catch (error) {
          clientTrpcError(error);
        }
      }),
    update: adminProcedure
      .input(clientUpdateInput)
      .mutation(async ({ input, ctx }) => {
        try {
          return await updateXrayClient({ ...input, userId: ctx.user.id });
        } catch (error) {
          clientTrpcError(error);
        }
      }),
    remove: adminProcedure
      .input(z.object({ id: positiveId, expectedGeneration: generation }).strict())
      .mutation(async ({ input, ctx }) => {
        try {
          return await removeXrayClient({ ...input, userId: ctx.user.id });
        } catch (error) {
          clientTrpcError(error);
        }
      }),
    share: adminProcedure
      .input(z.object({ clientId: positiveId, format: z.literal("VLESS_URI") }).strict())
      .query(async ({ input, ctx }) => {
        ctx.res.setHeader("Cache-Control", "private, no-store, max-age=0");
        ctx.res.setHeader("Pragma", "no-cache");
        try {
          return await getXrayClientShare(input.clientId);
        } catch (error) {
          clientTrpcError(error);
        }
      }),
  }),
  accessEntries: router({
    create: adminProcedure
      .input(z.object({ inboundId: positiveId, name: clientName, expectedGeneration: generation }).strict())
      .mutation(async ({ input, ctx }) => {
        try {
          return await createXrayAccessEntryForInbound({ ...input, userId: ctx.user.id });
        } catch (error) {
          accessTrpcError(error);
        }
      }),
    update: adminProcedure
      .input(z.object({
        id: positiveId,
        name: clientName.optional(),
        isEnabled: z.boolean().optional(),
        expectedGeneration: generation,
      }).strict().refine((input) => input.name !== undefined || input.isEnabled !== undefined, {
        message: "At least one access entry field is required",
      }))
      .mutation(async ({ input, ctx }) => {
        try {
          return await updateXrayAccessEntryForInbound({ ...input, userId: ctx.user.id });
        } catch (error) {
          accessTrpcError(error);
        }
      }),
    remove: adminProcedure
      .input(z.object({ id: positiveId, expectedGeneration: generation }).strict())
      .mutation(async ({ input, ctx }) => {
        try {
          return await removeXrayAccessEntryForInbound({ ...input, userId: ctx.user.id });
        } catch (error) {
          accessTrpcError(error);
        }
      }),
    share: adminProcedure
      .input(z.object({
        accessEntryId: positiveId,
        format: z.enum(["TROJAN_URI", "VLESS_URI", "VMESS_URI", "SHADOWSOCKS_URI", "HYSTERIA2_URI", "WIREGUARD_CONFIG", "HTTP_PROXY_URI", "MIXED_PROXY_ENDPOINTS"]),
      }).strict())
      .query(async ({ input, ctx }) => {
        ctx.res.setHeader("Cache-Control", "private, no-store, max-age=0");
        ctx.res.setHeader("Pragma", "no-cache");
        try {
          return await getXrayAccessEntryShare(input.accessEntryId, input.format);
        } catch (error) {
          accessTrpcError(error);
        }
      }),
  }),
  runtimes: router({
    catalog: adminProcedure.query(() => getXrayRuntimeCatalog()),
    list: adminProcedure
      .input(runtimeListInput.optional())
      .query(({ input }) => listXrayRuntimeSummaries(input ?? {})),
    install: adminProcedure
      .input(z.object({ hostId: positiveId, targetVersion: z.string().trim().min(1).max(64).optional() }).strict())
      .mutation(async ({ input, ctx }) => {
        try {
          return await createXrayRuntimeInstall({ ...input, userId: ctx.user.id });
        } catch (error) {
          runtimeTrpcError(error);
        }
      }),
    upgrade: adminProcedure
      .input(z.object({ hostId: positiveId, targetVersion: z.string().trim().min(1).max(64), expectedInstalledVersion: z.string().trim().min(1).max(64) }).strict())
      .mutation(async ({ input, ctx }) => {
        try {
          return await createXrayRuntimeUpgrade({ ...input, userId: ctx.user.id });
        } catch (error) {
          runtimeTrpcError(error);
        }
      }),
    restart: adminProcedure
      .input(z.object({ hostId: positiveId, confirmHostName: z.string().min(1).max(128) }).strict())
      .mutation(async ({ input, ctx }) => {
        try {
          return await createXrayRuntimeRestart({ ...input, userId: ctx.user.id });
        } catch (error) {
          runtimeTrpcError(error);
        }
      }),
    sync: adminProcedure
      .input(z.object({ hostId: positiveId }).strict())
      .mutation(async ({ input, ctx }) => {
        try {
          return await createXrayRuntimeSync({ ...input, userId: ctx.user.id });
        } catch (error) {
          runtimeTrpcError(error);
        }
      }),
  }),
  operations: router({
    list: adminProcedure
      .input(operationListInput.optional())
      .query(({ input }) => listXrayOperations(input ?? {})),
    get: adminProcedure
      .input(z.object({ operationId }).strict())
      .query(async ({ input }) => {
        const operation = await getXrayOperationSummary(input.operationId);
        if (!operation) throw new TRPCError({ code: "NOT_FOUND", message: "Xray operation not found" });
        return operation;
      }),
  }),
});
