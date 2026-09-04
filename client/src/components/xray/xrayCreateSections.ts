import type { XrayCreateProfileOption } from "./xrayCreateFlow";

type Protocol = XrayCreateProfileOption["protocol"];
type Transport = XrayCreateProfileOption["transport"];
type Security = XrayCreateProfileOption["security"];

function unique<T>(values: readonly T[]): T[] {
  return [...new Set(values)];
}

export function createProfileAxes(
  profiles: readonly XrayCreateProfileOption[],
  protocol?: Protocol,
  transport?: Transport,
): { protocols: Protocol[]; transports?: Transport[]; securities?: Security[] } {
  const protocols = unique(profiles.map((profile) => profile.protocol));
  if (!protocol) return { protocols };
  const protocolProfiles = profiles.filter((profile) => profile.protocol === protocol);
  const transports = unique(protocolProfiles.map((profile) => profile.transport));
  if (!transport) return { protocols, transports };
  return {
    protocols,
    transports,
    securities: unique(protocolProfiles.filter((profile) => profile.transport === transport).map((profile) => profile.security)),
  };
}

export function selectProfileForAxes(
  profiles: readonly XrayCreateProfileOption[],
  axes: { protocol: Protocol; transport?: Transport; security?: Security },
): XrayCreateProfileOption | null {
  return profiles.find((profile) => profile.protocol === axes.protocol
    && (axes.transport === undefined || profile.transport === axes.transport)
    && (axes.security === undefined || profile.security === axes.security)) ?? null;
}
