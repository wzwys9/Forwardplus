import type { AppRouterOutputs } from "@/lib/trpc";
import type { QuickConfigPaths } from "./xrayQuickConfigPaths";

export const XRAY_QUICK_CONFIG_STEPS = [
  "DOMAIN",
  "CARRIERS",
  "ENGINE",
  "PORT",
  "DEFAULT",
  "PREVIEW",
  "APPLY",
] as const;

export type XrayQuickConfigStep = (typeof XRAY_QUICK_CONFIG_STEPS)[number];
export type XrayQuickConfigCarrier = "TELECOM" | "UNICOM" | "MOBILE" | "EDUCATION";
export type XrayQuickConfigEngine = "iptables" | "nftables" | "realm" | "socat" | "gost" | "nginx";

export type XrayQuickConfigTarget = {
  targetType: "XRAY_INBOUND" | "EXTERNAL_PROXY_NODE";
  targetId: number;
  targetVersion: string;
  name: string;
  protocol: string;
  endpoint: { address: string; port: number };
  eligible: boolean;
  disabledReasonCode: string | null;
  shareCapability: "VLESS_URI" | "SHADOWSOCKS_URI" | "SOCKS5_ENDPOINT" | "NONE";
  host?: { id: number; name: string };
};

export type XrayQuickConfigDomainRecord = {
  recordRef: string;
  recordType: "A" | "AAAA" | "CNAME" | "TXT" | "MX" | "CAA" | "OTHER";
  providerLineId: string;
  lineName: string;
  value: string;
  ttl: number;
};

export type XrayQuickConfigDomainCheck = {
  fqdn: string;
  conflicts: XrayQuickConfigDomainRecord[];
  preservedRecords: XrayQuickConfigDomainRecord[];
  ownedRecordRefs?: string[];
  allowedActions: Array<"USE_UNUSED_NAME" | "REPLACE_CONFLICTING_RECORDS">;
  confirmationHash: string;
  domainCheckToken: string;
  expiresAt: string;
};

export type XrayQuickConfigEntryEndpoint = {
  addressFamily: "IPV4" | "IPV6";
  address: string;
};

export type XrayQuickConfigEntryHost = {
  hostId: number;
  name: string;
  eligible: boolean;
  disabledReasonCode: string | null;
  endpoints: XrayQuickConfigEntryEndpoint[];
};

export type XrayQuickConfigPortResult = Exclude<
  AppRouterOutputs["xray"]["quickConfigs"]["portChecksResult"],
  { status: "RUNNING" }
>;
export type XrayQuickConfigPortSuccess = Extract<XrayQuickConfigPortResult, { status: "SUCCESS" }>;
export type XrayQuickConfigPreview = AppRouterOutputs["xray"]["quickConfigs"]["preview"]
  | AppRouterOutputs["xray"]["quickConfigs"]["editPreview"];
export type XrayQuickConfigApplyResult = AppRouterOutputs["xray"]["quickConfigs"]["createApply"]
  | AppRouterOutputs["xray"]["quickConfigs"]["editApply"];

export type XrayQuickConfigEditDraft = Readonly<{
  carrierPaths?: QuickConfigPaths;
  quickConfigId: number;
  expectedRevision: number;
  zoneId: number;
  relativeName: string;
  fqdn?: string;
  managedDnsRecords?: XrayQuickConfigDomainRecord[];
  carrierEndpoints: Record<XrayQuickConfigCarrier, string[]>;
  engine: XrayQuickConfigEngine;
  publicPort: number;
  defaultRoutes: Array<Readonly<{
    sourceType: "LANDING" | "MANAGED_HOST";
    hostId: number | null;
    addressFamily: "IPV4" | "IPV6";
    address: string;
  }>>;
}>;

export function xrayQuickConfigEditIdentity(
  draft: XrayQuickConfigEditDraft,
): Pick<XrayQuickConfigEditDraft, "quickConfigId" | "expectedRevision"> {
  return {
    quickConfigId: draft.quickConfigId,
    expectedRevision: draft.expectedRevision,
  };
}

export type XrayQuickConfigFlowState = {
  carrierPaths: QuickConfigPaths | null;
  editDomainMode: "KEEP" | "CHANGE" | null;
  step: XrayQuickConfigStep;
  furthestStepIndex: number;
  zoneId: number | null;
  relativeName: string;
  domainCheck: XrayQuickConfigDomainCheck | null;
  confirmedDomainToken: string | null;
  confirmedDomainExpiresAt: string | null;
  carrierEndpoints: Record<XrayQuickConfigCarrier, string[]>;
  engine: XrayQuickConfigEngine | null;
  manualPort: string;
  editDefaultRoutes: XrayQuickConfigEditDraft["defaultRoutes"];
  portCheckId: string | null;
  portResult: XrayQuickConfigPortResult | null;
  replaceProbeResult: { token: string; expiresAt: string } | null;
  defaultCandidateIds: string[];
  preview: XrayQuickConfigPreview | null;
  applyResult: XrayQuickConfigApplyResult | null;
};

export type XrayQuickConfigFlowAction =
  | { type: "SET_CARRIER_PATHS"; paths: QuickConfigPaths }
  | { type: "SET_DOMAIN_MODE"; mode: "KEEP" | "CHANGE"; zoneId: number; relativeName: string }
  | { type: "SET_DOMAIN"; zoneId: number | null; relativeName: string }
  | { type: "DOMAIN_CHECKED"; result: XrayQuickConfigDomainCheck }
  | { type: "DOMAIN_CONFIRMED"; confirmedDomainToken: string; expiresAt: string }
  | { type: "TOGGLE_CARRIER_ENDPOINT"; carrier: XrayQuickConfigCarrier; endpointKey: string }
  | { type: "SET_ENGINE"; engine: XrayQuickConfigEngine | null }
  | { type: "SET_MANUAL_PORT"; value: string }
  | { type: "PORT_CHECK_STARTED"; portCheckId: string }
  | { type: "PORT_CHECK_FINISHED"; result: XrayQuickConfigPortResult }
  | { type: "CLEAR_PORT_CHECK" }
  | { type: "TOGGLE_DEFAULT_ROUTE"; candidateId: string }
  | { type: "PREVIEW_READY"; preview: XrayQuickConfigPreview }
  | { type: "APPLY_ACCEPTED"; result: XrayQuickConfigApplyResult }
  | { type: "GO_TO_STEP"; step: XrayQuickConfigStep };

export const XRAY_QUICK_CONFIG_CARRIERS: readonly XrayQuickConfigCarrier[] = [
  "TELECOM",
  "UNICOM",
  "MOBILE",
  "EDUCATION",
];

export function initialXrayQuickConfigFlowState(draft?: XrayQuickConfigEditDraft): XrayQuickConfigFlowState {
  return {
    carrierPaths: draft?.carrierPaths ?? null,
    editDomainMode: draft ? "KEEP" : null,
    step: "DOMAIN",
    furthestStepIndex: 0,
    zoneId: draft?.zoneId ?? null,
    relativeName: draft?.relativeName ?? "",
    domainCheck: null,
    confirmedDomainToken: null,
    confirmedDomainExpiresAt: null,
    carrierEndpoints: draft?.carrierEndpoints ?? { TELECOM: [], UNICOM: [], MOBILE: [], EDUCATION: [] },
    engine: draft?.engine ?? null,
    manualPort: draft ? String(draft.publicPort) : "",
    editDefaultRoutes: draft?.defaultRoutes ?? [],
    portCheckId: null,
    portResult: null,
    replaceProbeResult: null,
    defaultCandidateIds: [],
    preview: null,
    applyResult: null,
  };
}

export function xrayQuickConfigEndpointKey(hostId: number, addressFamily: "IPV4" | "IPV6") {
  return `${hostId}:${addressFamily}`;
}

export function xrayQuickConfigCarriersComplete(state: XrayQuickConfigFlowState) {
  return XRAY_QUICK_CONFIG_CARRIERS.every((carrier) => state.carrierEndpoints[carrier].length > 0);
}

function replacementProbeResult(state: XrayQuickConfigFlowState) {
  return state.portResult?.status === "SUCCESS"
    ? { token: state.portResult.probeResultToken, expiresAt: state.portResult.expiresAt }
    : state.replaceProbeResult;
}

export function activeXrayQuickConfigReplacementProbeToken(
  state: XrayQuickConfigFlowState,
  now = Date.now(),
): string | undefined {
  const replacement = replacementProbeResult(state);
  const expiresAt = replacement ? Date.parse(replacement.expiresAt) : Number.NaN;
  return replacement && Number.isFinite(expiresAt) && expiresAt > now ? replacement.token : undefined;
}

export function reduceXrayQuickConfigFlow(
  state: XrayQuickConfigFlowState,
  action: XrayQuickConfigFlowAction,
): XrayQuickConfigFlowState {
  if (action.type === "SET_DOMAIN" || action.type === "SET_DOMAIN_MODE") {
    if (action.type === "SET_DOMAIN" && state.zoneId === action.zoneId && state.relativeName === action.relativeName) return state;
    return {
      ...initialXrayQuickConfigFlowState(),
      ...(state.editDomainMode === null ? {} : {
        editDomainMode: state.editDomainMode,
        carrierEndpoints: state.carrierEndpoints, carrierPaths: state.carrierPaths, engine: state.engine, manualPort: state.manualPort,
        editDefaultRoutes: state.editDefaultRoutes,
      }),
      ...(action.type === "SET_DOMAIN_MODE" ? { editDomainMode: action.mode } : {}),
      zoneId: action.zoneId,
      relativeName: action.relativeName,
    };
  }
  if (action.type === "DOMAIN_CHECKED") {
    return {
      ...state,
      domainCheck: action.result,
      confirmedDomainToken: null,
      confirmedDomainExpiresAt: null,
      carrierEndpoints: state.editDomainMode === null ? { TELECOM: [], UNICOM: [], MOBILE: [], EDUCATION: [] } : state.carrierEndpoints,
      carrierPaths: state.editDomainMode === null ? null : state.carrierPaths,
      engine: state.editDomainMode === null ? null : state.engine,
      manualPort: state.editDomainMode === null ? "" : state.manualPort,
      portCheckId: null,
      portResult: null,
      replaceProbeResult: null,
      defaultCandidateIds: [],
      preview: null,
      applyResult: null,
      furthestStepIndex: 0,
    };
  }
  if (action.type === "DOMAIN_CONFIRMED") {
    return {
      ...state,
      confirmedDomainToken: action.confirmedDomainToken,
      confirmedDomainExpiresAt: action.expiresAt,
      furthestStepIndex: Math.max(state.furthestStepIndex, 1),
    };
  }
  if (action.type === "TOGGLE_CARRIER_ENDPOINT" || action.type === "SET_CARRIER_PATHS") {
    if (action.type === "SET_CARRIER_PATHS" && XRAY_QUICK_CONFIG_CARRIERS.every(carrier =>
      JSON.stringify(action.paths[carrier].map(path => path.hops)) === JSON.stringify(
        state.carrierPaths?.[carrier].map(path => path.hops) ?? state.carrierEndpoints[carrier].map(key => [key]),
      ))) return state;
    const endpoints = { ...state.carrierEndpoints };
    if (action.type === "SET_CARRIER_PATHS") {
      for (const carrier of XRAY_QUICK_CONFIG_CARRIERS) endpoints[carrier] = action.paths[carrier].flatMap(path => path.hops[0] ? [path.hops[0]] : []);
    } else {
      const current = endpoints[action.carrier];
      endpoints[action.carrier] = current.includes(action.endpointKey) ? current.filter(key => key !== action.endpointKey) : [...current, action.endpointKey];
    }
    return {
      ...state,
      carrierEndpoints: endpoints,
      carrierPaths: action.type === "SET_CARRIER_PATHS" ? structuredClone(action.paths) : null,
      engine: null,
      manualPort: "",
      portCheckId: null,
      portResult: null,
      replaceProbeResult: replacementProbeResult(state),
      defaultCandidateIds: [],
      preview: null,
      applyResult: null,
      furthestStepIndex: Math.min(state.furthestStepIndex, 1),
    };
  }
  if (action.type === "SET_ENGINE") {
    if (state.engine === action.engine) return state;
    return {
      ...state,
      engine: action.engine,
      manualPort: "",
      portCheckId: null,
      portResult: null,
      replaceProbeResult: replacementProbeResult(state),
      defaultCandidateIds: [],
      preview: null,
      applyResult: null,
      furthestStepIndex: action.engine
        ? Math.max(Math.min(state.furthestStepIndex, 2), 2)
        : Math.min(state.furthestStepIndex, 2),
    };
  }
  if (action.type === "SET_MANUAL_PORT") {
    return {
      ...state,
      manualPort: action.value,
      portCheckId: null,
      portResult: null,
      replaceProbeResult: replacementProbeResult(state),
      defaultCandidateIds: [],
      preview: null,
      applyResult: null,
      furthestStepIndex: Math.min(state.furthestStepIndex, 3),
    };
  }
  if (action.type === "PORT_CHECK_STARTED") {
    return {
      ...state,
      portCheckId: action.portCheckId,
      portResult: null,
      replaceProbeResult: null,
      defaultCandidateIds: [],
      preview: null,
      applyResult: null,
      furthestStepIndex: Math.min(state.furthestStepIndex, 3),
    };
  }
  if (action.type === "PORT_CHECK_FINISHED") {
    const success = action.result.status === "SUCCESS" ? action.result : null;
    return {
      ...state,
      portCheckId: null,
      portResult: action.result,
      replaceProbeResult: null,
      defaultCandidateIds: success
        ? success.defaultRouteCandidates.filter((candidate) => state.editDefaultRoutes.length > 0
          ? state.editDefaultRoutes.some((route) => route.sourceType === candidate.sourceType
            && route.hostId === candidate.hostId && route.addressFamily === candidate.addressFamily
            && route.address === candidate.address)
          : candidate.recommended).map((candidate) => candidate.candidateId)
        : [],
      preview: null,
      applyResult: null,
      furthestStepIndex: success
        ? Math.max(state.furthestStepIndex, 4)
        : Math.min(state.furthestStepIndex, 3),
    };
  }
  if (action.type === "CLEAR_PORT_CHECK") {
    return {
      ...state,
      portCheckId: null,
      portResult: null,
      replaceProbeResult: replacementProbeResult(state),
      defaultCandidateIds: [],
      preview: null,
      applyResult: null,
      furthestStepIndex: Math.min(state.furthestStepIndex, 3),
    };
  }
  if (action.type === "TOGGLE_DEFAULT_ROUTE") {
    const selected = state.defaultCandidateIds.includes(action.candidateId);
    return {
      ...state,
      defaultCandidateIds: selected
        ? state.defaultCandidateIds.filter((candidateId) => candidateId !== action.candidateId)
        : [...state.defaultCandidateIds, action.candidateId],
      preview: null,
      applyResult: null,
      furthestStepIndex: Math.min(state.furthestStepIndex, 4),
    };
  }
  if (action.type === "PREVIEW_READY") {
    return {
      ...state,
      preview: action.preview,
      applyResult: null,
      furthestStepIndex: Math.max(state.furthestStepIndex, 6),
    };
  }
  if (action.type === "APPLY_ACCEPTED") {
    return { ...state, step: "APPLY", applyResult: action.result, furthestStepIndex: 6 };
  }
  const index = XRAY_QUICK_CONFIG_STEPS.indexOf(action.step);
  if (state.applyResult && action.step !== "APPLY") return state;
  if (index < 0 || index > state.furthestStepIndex + 1) return state;
  if (index >= 1 && !state.confirmedDomainToken) return state;
  if (index >= 2 && !xrayQuickConfigCarriersComplete(state)) return state;
  if (index >= 3 && !state.engine) return state;
  if (index >= 4 && state.portResult?.status !== "SUCCESS") return state;
  if (index >= 5 && state.defaultCandidateIds.length === 0) return state;
  if (index >= 6 && !state.preview) return state;
  return {
    ...state,
    step: action.step,
    furthestStepIndex: Math.max(state.furthestStepIndex, index),
  };
}
