import crypto from "node:crypto";
import net from "node:net";

import { XrayAmneziawgObfuscationSchema } from "../shared/xrayTypes";
import {
  canonicalXrayWireGuardKey,
  canonicalXrayWireGuardPrivateKey,
  deriveXrayWireGuardPublicKey,
  generateXrayWireGuardKeyPair,
  generateXrayWireGuardPreSharedKey,
} from "./xrayWireGuard";

export const AMNEZIAWG_MANAGED_SERVICE_KIND = "AMNEZIAWG" as const;
export const AMNEZIAWG_TARGET_VERSION = "v3.1.20260814" as const;
export const AMNEZIAWG_SUBNET = "10.8.1.0/24" as const;
export const AMNEZIAWG_MTU = 1420 as const;
export const AMNEZIAWG_DNS = ["1.1.1.1", "1.0.0.1"] as const;
export const AMNEZIAWG_MAX_PEERS = 32;

export const AMNEZIAWG_SERVER_PRIVATE_KEY = "AMNEZIAWG_SERVER_PRIVATE_KEY" as const;
export const AMNEZIAWG_HEADER_PROTECTION_KEY = "AMNEZIAWG_HEADER_PROTECTION_KEY" as const;
export const AMNEZIAWG_PEER_PRIVATE_KEY = "AMNEZIAWG_PRIVATE_KEY" as const;
export const AMNEZIAWG_PEER_PRE_SHARED_KEY = "AMNEZIAWG_PRE_SHARED_KEY" as const;

type Obfuscation = ReturnType<typeof XrayAmneziawgObfuscationSchema.parse>;
export type AmneziaWgStoredSpec = Omit<Obfuscation, "headerProtectionKey">;

const hostnamePattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const peerAddressPattern = /^10\.8\.1\.(?:[2-9]|[1-9]\d|1\d{2}|2[0-4]\d|25[0-4])\/32$/;

function randomRange(minimum: number, maximum: number, spanMinimum: number, spanMaximum: number) {
  const lower = crypto.randomInt(minimum, maximum - spanMaximum + 1);
  return `${lower}-${lower + crypto.randomInt(spanMinimum, spanMaximum + 1)}`;
}

export function generateAmneziaWgServiceMaterial() {
  let s1 = crypto.randomInt(40, 141);
  let s2 = crypto.randomInt(40, 221);
  if (s1 + 56 === s2) s2 = s2 === 220 ? 219 : s2 + 1;
  const jmin = crypto.randomInt(40, 81);
  const headerProtectionKey = crypto.randomBytes(32).toString("base64");
  const storedSpec: AmneziaWgStoredSpec = {
    jc: crypto.randomInt(3, 9), jmin, jmax: crypto.randomInt(Math.max(jmin, 180), 321),
    s1, s2, s3: crypto.randomInt(20, 56), s4: crypto.randomInt(12, 33),
    h1: randomRange(100_000, 500_000_000, 10_000, 50_000),
    h2: randomRange(600_000_000, 1_400_000_000, 10_000, 50_000),
    h3: randomRange(1_500_000_000, 2_400_000_000, 10_000, 50_000),
    h4: randomRange(2_500_000_000, 4_000_000_000, 10_000, 50_000),
    i1: `<r ${crypto.randomInt(64, 201)}>`,
    contentPaddingAddition: randomRange(8, 41, 8, 24),
    rekeyAfterTime: randomRange(90, 181, 10, 40), rekeyTimeout: randomRange(3, 15, 2, 8),
    rejectAfterTime: randomRange(180, 361, 20, 80), keepaliveTimeout: randomRange(8, 25, 2, 10),
    maxHandshakeAttempts: randomRange(10, 41, 5, 20), randomTrailers: true, disableCookies: true,
  };
  parseAmneziaWgStoredSpec(storedSpec);
  const server = generateXrayWireGuardKeyPair();
  return { storedSpec, serverPrivateKey: server.privateKey, headerProtectionKey } as const;
}

export function parseAmneziaWgStoredSpec(value: unknown): AmneziaWgStoredSpec {
  const parsed = typeof value === "string" ? JSON.parse(value) : value;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || "headerProtectionKey" in parsed) throw new Error("Invalid AmneziaWG spec");
  const validated = XrayAmneziawgObfuscationSchema.parse({
    ...parsed,
    headerProtectionKey: Buffer.alloc(32, 1).toString("base64"),
  });
  const { headerProtectionKey: _secret, ...storedSpec } = validated;
  return storedSpec;
}

export function parseAmneziaWgPeerSettings(settingsVersion: unknown, settingsJson: unknown): { address: string; publicKey: string } {
  if (Number(settingsVersion) !== 1) throw new Error("Invalid AmneziaWG peer settings");
  const parsed = JSON.parse(String(settingsJson ?? ""));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || Object.keys(parsed).sort().join(",") !== "address,publicKey"
    || typeof parsed.address !== "string" || !peerAddressPattern.test(parsed.address)) throw new Error("Invalid AmneziaWG peer settings");
  return { address: parsed.address, publicKey: canonicalXrayWireGuardKey(parsed.publicKey) };
}

export function allocateAmneziaWgPeerAddress(settings: readonly { settingsVersion?: unknown; settingsJson?: unknown }[]): string {
  const used = new Set(settings.map((row) => parseAmneziaWgPeerSettings(row.settingsVersion, row.settingsJson).address));
  for (let suffix = 2; suffix <= 254; suffix += 1) {
    const address = `10.8.1.${suffix}/32`;
    if (!used.has(address)) return address;
  }
  throw new Error("AmneziaWG peer address pool exhausted");
}

export function generateAmneziaWgPeerMaterial() {
  return { ...generateXrayWireGuardKeyPair(), preSharedKey: generateXrayWireGuardPreSharedKey() } as const;
}

export function buildAmneziaWgClientShare(input: {
  name: string; peerPrivateKey: string; peerAddress: string; preSharedKey: string; serverPrivateKey: string;
  publicAddress: string; listenPort: number; obfuscation: Obfuscation;
}) {
  const peerPrivateKey = canonicalXrayWireGuardPrivateKey(input.peerPrivateKey);
  const serverPrivateKey = canonicalXrayWireGuardPrivateKey(input.serverPrivateKey);
  const preSharedKey = canonicalXrayWireGuardKey(input.preSharedKey);
  if (peerPrivateKey === serverPrivateKey || Buffer.from(preSharedKey, "base64").every((byte) => byte === 0)
    || !peerAddressPattern.test(input.peerAddress)) throw new Error("Invalid AmneziaWG share");
  const publicAddress = String(input.publicAddress).trim().toLowerCase();
  const endpoint = net.isIP(publicAddress) === 6 ? `[${publicAddress}]:${input.listenPort}` : `${publicAddress}:${input.listenPort}`;
  if ((!net.isIP(publicAddress) && !hostnamePattern.test(publicAddress)) || !Number.isInteger(input.listenPort)
    || input.listenPort < 1000 || input.listenPort > 65535) throw new Error("Invalid AmneziaWG share");
  const o = XrayAmneziawgObfuscationSchema.parse(input.obfuscation);
  const content = [
    "[Interface]", `PrivateKey = ${peerPrivateKey}`, `Address = ${input.peerAddress}`,
    `DNS = ${AMNEZIAWG_DNS.join(", ")}`, `MTU = ${AMNEZIAWG_MTU}`,
    `Jc = ${o.jc}`, `Jmin = ${o.jmin}`, `Jmax = ${o.jmax}`, `S1 = ${o.s1}`, `S2 = ${o.s2}`,
    `S3 = ${o.s3}`, `S4 = ${o.s4}`, `H1 = ${o.h1}`, `H2 = ${o.h2}`, `H3 = ${o.h3}`, `H4 = ${o.h4}`,
    `I1 = ${o.i1}`, `HeaderProtectionKey = ${o.headerProtectionKey}`,
    `ContentPaddingAddition = ${o.contentPaddingAddition}`, `RekeyAfterTime = ${o.rekeyAfterTime}`,
    `RekeyTimeout = ${o.rekeyTimeout}`, `RejectAfterTime = ${o.rejectAfterTime}`,
    `KeepaliveTimeout = ${o.keepaliveTimeout}`, `MaxHandshakeAttempts = ${o.maxHandshakeAttempts}`,
    "RandomTrailers = on", "DisableCookies = on", "", `# ${String(input.name).replace(/[\r\n#]/g, " ").trim()}`,
    "[Peer]", `PublicKey = ${deriveXrayWireGuardPublicKey(serverPrivateKey)}`, `PresharedKey = ${preSharedKey}`,
    "AllowedIPs = 0.0.0.0/0", `Endpoint = ${endpoint}`, "PersistentKeepalive = 25", "",
  ].join("\n");
  const stem = String(input.name).normalize("NFKD").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 64) || "amneziawg-peer";
  return { kind: "AMNEZIAWG_CONFIG" as const, content, fileName: `forwardx-${stem}.conf`, vpnUri: `vpn://${Buffer.from(content, "utf8").toString("base64url")}` };
}
