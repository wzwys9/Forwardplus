export const FORWARDPLUS_AGENT_DISTRIBUTION = "forwardplus" as const;
export const FORWARDX_AGENT_DISTRIBUTION = "forwardx" as const;

export type AgentDistribution =
  | typeof FORWARDPLUS_AGENT_DISTRIBUTION
  | typeof FORWARDX_AGENT_DISTRIBUTION;

const KNOWN_AGENT_DISTRIBUTIONS = new Set<AgentDistribution>([
  FORWARDPLUS_AGENT_DISTRIBUTION,
  FORWARDX_AGENT_DISTRIBUTION,
]);

export function normalizeAgentDistribution(value: unknown): AgentDistribution | null {
  const normalized = String(value || "").trim().toLowerCase();
  return KNOWN_AGENT_DISTRIBUTIONS.has(normalized as AgentDistribution)
    ? normalized as AgentDistribution
    : null;
}

export function normalizeAgentBuildId(value: unknown): string | null {
  const normalized = String(value || "").trim();
  if (!normalized || normalized.length > 64 || !/^[A-Za-z0-9._-]+$/.test(normalized)) return null;
  return normalized;
}

function normalizeVersion(value: unknown) {
  return String(value || "").trim().replace(/^v/i, "");
}

function compareVersions(left: unknown, right: unknown) {
  const leftParts = normalizeVersion(left).split(/[.-]/).map((part) => Number.parseInt(part, 10) || 0);
  const rightParts = normalizeVersion(right).split(/[.-]/).map((part) => Number.parseInt(part, 10) || 0);
  const length = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (leftParts[index] || 0) - (rightParts[index] || 0);
    if (difference !== 0) return difference > 0 ? 1 : -1;
  }
  return 0;
}

export type AgentUpgradeIdentity = {
  version: string | null | undefined;
  distribution: string | null | undefined;
  targetVersion: string | null | undefined;
  targetDistribution?: string | null;
  currentSupportedVersion?: string | null;
};

export function isAgentUpgradeSatisfied(input: AgentUpgradeIdentity) {
  const version = normalizeVersion(input.version);
  const targetVersion = normalizeVersion(input.targetVersion);
  const distribution = normalizeAgentDistribution(input.distribution);
  const targetDistribution = normalizeAgentDistribution(
    input.targetDistribution || FORWARDPLUS_AGENT_DISTRIBUTION,
  );
  if (!version || !targetVersion || !distribution || !targetDistribution || distribution !== targetDistribution) {
    return false;
  }
  if (input.currentSupportedVersion && compareVersions(targetVersion, input.currentSupportedVersion) < 0) {
    return version === targetVersion;
  }
  return compareVersions(version, targetVersion) >= 0;
}

export function doesAgentNeedUpgrade(input: AgentUpgradeIdentity) {
  return !isAgentUpgradeSatisfied(input);
}

export function isForwardplusAgent(distribution: unknown) {
  return normalizeAgentDistribution(distribution) === FORWARDPLUS_AGENT_DISTRIBUTION;
}
