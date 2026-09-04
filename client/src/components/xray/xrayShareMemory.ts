export type XrayShareMemory = {
  phase: "EMPTY" | "LOADING" | "LOADED" | "ERROR";
  uri: string | null;
  secondaryUri: string | null;
  qrDataUrl: string | null;
  secondaryQrDataUrl: string | null;
  displayName: string | null;
  deploymentStatus: string | null;
  format: "URI" | "WIREGUARD_CONFIG" | "MIXED_PROXY_ENDPOINTS" | null;
  fileName: string | null;
};

export type XrayShareMemoryAction =
  | { type: "LOAD" }
  | { type: "LOADED"; uri: string; secondaryUri?: string | null; displayName: string; deploymentStatus: string; format?: "URI" | "WIREGUARD_CONFIG" | "MIXED_PROXY_ENDPOINTS"; fileName?: string | null }
  | { type: "QR_READY"; slot?: "PRIMARY" | "SECONDARY"; dataUrl: string }
  | { type: "ERROR" }
  | { type: "CLEAR" };

export function initialXrayShareMemory(): XrayShareMemory {
  return { phase: "EMPTY", uri: null, secondaryUri: null, qrDataUrl: null, secondaryQrDataUrl: null, displayName: null, deploymentStatus: null, format: null, fileName: null };
}

export function reduceXrayShareMemory(state: XrayShareMemory, action: XrayShareMemoryAction): XrayShareMemory {
  if (action.type === "CLEAR") return initialXrayShareMemory();
  if (action.type === "LOAD") return { ...initialXrayShareMemory(), phase: "LOADING" };
  if (action.type === "LOADED") return {
    phase: "LOADED",
    uri: action.uri,
    secondaryUri: action.secondaryUri ?? null,
    qrDataUrl: null,
    secondaryQrDataUrl: null,
    displayName: action.displayName,
    deploymentStatus: action.deploymentStatus,
    format: action.format ?? "URI",
    fileName: action.fileName ?? null,
  };
  if (action.type === "QR_READY") {
    if (state.phase !== "LOADED") return state;
    if (action.slot === "SECONDARY") {
      return state.secondaryUri ? { ...state, secondaryQrDataUrl: action.dataUrl } : state;
    }
    return state.uri ? { ...state, qrDataUrl: action.dataUrl } : state;
  }
  return { ...initialXrayShareMemory(), phase: "ERROR" };
}
