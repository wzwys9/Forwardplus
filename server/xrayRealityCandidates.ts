export const XRAY_REALITY_CANDIDATE_LIST_VERSION = "v2" as const;
export type XrayRealityCandidateListVersion = typeof XRAY_REALITY_CANDIDATE_LIST_VERSION;

// Changes to this approved list require a new version so historical scan
// operations cannot be reused as evidence for the current defaults.
export const XRAY_REALITY_DEFAULT_CANDIDATES = Object.freeze([
  "www.cloudflare.com:443",
  "www.amazon.com:443",
  "aws.amazon.com:443",
  "www.samsung.com:443",
  "www.nvidia.com:443",
  "www.amd.com:443",
  "www.intel.com:443",
  "www.sony.com:443",
  "dl.google.com:443",
] as const);
