import {
  XRAY_QUICK_CONFIG_DEFAULT_FORWARD_ENGINE,
  XRAY_QUICK_CONFIG_FORWARD_ENGINE_ADDRESS_FAMILIES,
  XRAY_QUICK_CONFIG_FORWARD_ENGINE_MIN_AGENT_VERSION,
  XRAY_QUICK_CONFIG_FORWARD_ENGINES,
  xrayQuickConfigForwardEngineLabel,
  type XrayQuickConfigForwardEngineCatalogItem,
  type XrayQuickConfigForwardEngineDisabledReasonCode,
} from "../shared/xrayQuickConfigForwardEngines";
import { isForwardplusAgentVersionAtLeast } from "./agentRouteUtils";
import { inList, quoteIdentifier } from "./dbCompat";
import { queryRaw } from "./dbRuntime";
import { getForwardProtocolSettings } from "./forwardProtocolSettings";
import { listXrayQuickConfigEntryHosts } from "./xrayQuickConfigEntryHosts";

export class XrayQuickConfigForwardEngineCatalogError extends Error {
  readonly code = "QUICK_CONFIG_HOST_UNAVAILABLE" as const;

  constructor() {
    super("QUICK_CONFIG_HOST_UNAVAILABLE");
    this.name = "XrayQuickConfigForwardEngineCatalogError";
  }
}

export type XrayQuickConfigForwardEngineSelection = Readonly<{
  hostId: unknown;
  addressFamily: unknown;
}>;

export type XrayQuickConfigForwardEngineCatalog = Readonly<{
  defaultEngine: typeof XRAY_QUICK_CONFIG_DEFAULT_FORWARD_ENGINE;
  items: XrayQuickConfigForwardEngineCatalogItem[];
}>;

type AddressFamily = "IPV4" | "IPV6";
type NormalizedSelection = Readonly<{ hostId: number; addressFamily: AddressFamily }>;
type Row = Record<string, unknown>;

const REASON_PRIORITY: readonly XrayQuickConfigForwardEngineDisabledReasonCode[] = [
  "FORWARD_PROTOCOL_DISABLED",
  "HOST_OFFLINE",
  "AGENT_CAPABILITY_MISSING",
  "UDP_CAPABILITY_REQUIRED",
  "QUICK_CONFIG_HOST_UNAVAILABLE",
  "QUICK_CONFIG_ADDRESS_UNAVAILABLE",
];

function invalidSelection(): never {
  throw new XrayQuickConfigForwardEngineCatalogError();
}

function normalizeSelections(value: readonly XrayQuickConfigForwardEngineSelection[]): NormalizedSelection[] {
  if (!Array.isArray(value) || value.length > 128) invalidSelection();
  const unique = new Map<string, NormalizedSelection>();
  for (const item of value) {
    const hostId = Number(item?.hostId);
    const addressFamily = item?.addressFamily;
    if (!Number.isSafeInteger(hostId) || hostId <= 0
      || (addressFamily !== "IPV4" && addressFamily !== "IPV6")) {
      invalidSelection();
    }
    unique.set(`${hostId}:${addressFamily}`, { hostId, addressFamily });
  }
  return [...unique.values()].sort((left, right) => left.hostId - right.hostId
    || left.addressFamily.localeCompare(right.addressFamily));
}

function firstReason(
  reasons: readonly XrayQuickConfigForwardEngineDisabledReasonCode[],
): XrayQuickConfigForwardEngineDisabledReasonCode | null {
  return REASON_PRIORITY.find((candidate) => reasons.includes(candidate)) ?? null;
}

export async function listXrayQuickConfigForwardEngines(input: {
  entries: readonly XrayQuickConfigForwardEngineSelection[];
}): Promise<XrayQuickConfigForwardEngineCatalog> {
  const selections = normalizeSelections(input?.entries);
  const hostIds = [...new Set(selections.map((selection) => selection.hostId))];
  const q = quoteIdentifier;
  const ids = inList(hostIds);
  const [entryHostCatalog, protocolSettings, versionRows] = await Promise.all([
    listXrayQuickConfigEntryHosts(),
    getForwardProtocolSettings(),
    hostIds.length ? queryRaw<Row>(
      `SELECT ${q("id")}, ${q("agentVersion")}, ${q("agentDistribution")} FROM ${q("hosts")} WHERE ${q("id")} IN ${ids.sql}`,
      ids.params,
    ) : Promise.resolve([] as Row[]),
  ]);
  const entryHosts = new Map(entryHostCatalog.items.map((host) => [host.hostId, host]));
  const agentIdentities = new Map(versionRows.map((row) => [Number(row.id), {
    version: String(row.agentVersion ?? ""),
    distribution: String(row.agentDistribution ?? ""),
  }]));

  const sharedHostReasons: XrayQuickConfigForwardEngineDisabledReasonCode[] = [];
  for (const selection of selections) {
    const host = entryHosts.get(selection.hostId);
    if (!host) invalidSelection();
    if (!host.endpoints.some((endpoint) => endpoint.addressFamily === selection.addressFamily)) {
      sharedHostReasons.push("QUICK_CONFIG_ADDRESS_UNAVAILABLE");
    }
    if (host.disabledReasonCode && !(host.disabledReasonCode === "QUICK_CONFIG_HOST_UNAVAILABLE"
      && host.endpoints.length > 0)) {
      sharedHostReasons.push(host.disabledReasonCode);
    }
    const identity = agentIdentities.get(selection.hostId);
    if (!isForwardplusAgentVersionAtLeast(
      identity?.version,
      identity?.distribution,
      XRAY_QUICK_CONFIG_FORWARD_ENGINE_MIN_AGENT_VERSION,
    )) {
      sharedHostReasons.push("AGENT_CAPABILITY_MISSING");
    }
  }

  return {
    defaultEngine: XRAY_QUICK_CONFIG_DEFAULT_FORWARD_ENGINE,
    items: XRAY_QUICK_CONFIG_FORWARD_ENGINES.map((engine) => {
      const reasons = [...sharedHostReasons];
      if (protocolSettings[engine] === false) reasons.push("FORWARD_PROTOCOL_DISABLED");
      if (selections.some((selection) => !XRAY_QUICK_CONFIG_FORWARD_ENGINE_ADDRESS_FAMILIES[engine]
        .includes(selection.addressFamily))) {
        reasons.push("QUICK_CONFIG_ADDRESS_UNAVAILABLE");
      }
      const disabledReasonCode = firstReason(reasons);
      return {
        engine,
        label: xrayQuickConfigForwardEngineLabel(engine),
        isDefault: engine === XRAY_QUICK_CONFIG_DEFAULT_FORWARD_ENGINE,
        eligible: disabledReasonCode === null,
        disabledReasonCode,
      };
    }),
  };
}
