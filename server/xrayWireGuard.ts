import crypto from "node:crypto";
import { isIP } from "node:net";

const privateKeyPkcs8Prefix = Buffer.from("302e020100300506032b656e04220420", "hex");
const publicKeySpkiPrefix = Buffer.from("302a300506032b656e032100", "hex");
const hostnamePattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const peerAddressPattern = /^10\.0\.0\.(?:[2-9]|[1-9]\d|1\d{2}|2[0-4]\d|25[0-4])\/32$/;

function invalidWireGuardInput(): never {
  throw new Error("Invalid Xray WireGuard input");
}

export function canonicalXrayWireGuardKey(value: unknown): string {
  const key = String(value ?? "");
  if (!/^[A-Za-z0-9+/]{43}=$/.test(key)) invalidWireGuardInput();
  const decoded = Buffer.from(key, "base64");
  if (decoded.length !== 32 || decoded.toString("base64") !== key) invalidWireGuardInput();
  return key;
}

export function canonicalXrayWireGuardPrivateKey(value: unknown): string {
  const key = canonicalXrayWireGuardKey(value);
  const decoded = Buffer.from(key, "base64");
  if ((decoded[0] & 7) !== 0 || (decoded[31] & 128) !== 0 || (decoded[31] & 64) !== 64) {
    invalidWireGuardInput();
  }
  return key;
}

export function canonicalXrayWireGuardPeerAddress(value: unknown): string {
  const address = String(value ?? "");
  if (!peerAddressPattern.test(address)) invalidWireGuardInput();
  return address;
}

export function deriveXrayWireGuardPublicKey(privateKeyValue: unknown): string {
  try {
    const privateKey = Buffer.from(canonicalXrayWireGuardPrivateKey(privateKeyValue), "base64");
    const privateKeyObject = crypto.createPrivateKey({
      key: Buffer.concat([privateKeyPkcs8Prefix, privateKey]),
      format: "der",
      type: "pkcs8",
    });
    const encodedPublicKey = crypto.createPublicKey(privateKeyObject).export({ format: "der", type: "spki" });
    if (!Buffer.isBuffer(encodedPublicKey)
      || encodedPublicKey.length !== publicKeySpkiPrefix.length + 32
      || !encodedPublicKey.subarray(0, publicKeySpkiPrefix.length).equals(publicKeySpkiPrefix)) {
      invalidWireGuardInput();
    }
    return encodedPublicKey.subarray(publicKeySpkiPrefix.length).toString("base64");
  } catch {
    invalidWireGuardInput();
  }
}

export function generateXrayWireGuardKeyPair(): Readonly<{ privateKey: string; publicKey: string }> {
  const privateKey = crypto.randomBytes(32);
  privateKey[0] &= 248;
  privateKey[31] &= 127;
  privateKey[31] |= 64;
  const canonicalPrivateKey = privateKey.toString("base64");
  return Object.freeze({
    privateKey: canonicalPrivateKey,
    publicKey: deriveXrayWireGuardPublicKey(canonicalPrivateKey),
  });
}

export function generateXrayWireGuardPreSharedKey(): string {
  let key: Buffer;
  do key = crypto.randomBytes(32); while (key.every((byte) => byte === 0));
  return key.toString("base64");
}

function wireGuardEndpoint(publicAddressValue: unknown, listenPortValue: unknown): string {
  const publicAddress = String(publicAddressValue ?? "").trim().toLowerCase();
  const listenPort = Number(listenPortValue);
  if (!Number.isSafeInteger(listenPort) || listenPort < 1000 || listenPort > 65535) invalidWireGuardInput();
  const ipVersion = isIP(publicAddress);
  if (ipVersion === 6) return `[${publicAddress}]:${listenPort}`;
  if (ipVersion === 4 || hostnamePattern.test(publicAddress)) return `${publicAddress}:${listenPort}`;
  return invalidWireGuardInput();
}

function wireGuardFileName(displayNameValue: unknown): string {
  const displayName = String(displayNameValue ?? "").trim();
  if (!displayName || displayName.length > 128 || /[\u0000-\u001f\u007f]/.test(displayName)) invalidWireGuardInput();
  const stem = displayName.normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64)
    .replace(/-+$/g, "");
  return `forwardx-${stem || "wireguard-peer"}.conf`;
}

export type XrayWireGuardClientConfigInput = Readonly<{
  peerPrivateKey: string;
  peerAddress: string;
  serverPrivateKey: string;
  preSharedKey: string;
  publicAddress: string;
  listenPort: number;
  displayName: string;
}>;

export function buildXrayWireGuardClientConfig(input: XrayWireGuardClientConfigInput): Readonly<{
  content: string;
  fileName: string;
}> {
  const peerPrivateKey = canonicalXrayWireGuardPrivateKey(input?.peerPrivateKey);
  const serverPrivateKey = canonicalXrayWireGuardPrivateKey(input?.serverPrivateKey);
  const preSharedKey = canonicalXrayWireGuardKey(input?.preSharedKey);
  if (peerPrivateKey === serverPrivateKey) invalidWireGuardInput();
  const peerAddress = canonicalXrayWireGuardPeerAddress(input?.peerAddress);
  const endpoint = wireGuardEndpoint(input?.publicAddress, input?.listenPort);
  const content = [
    "[Interface]",
    `PrivateKey = ${peerPrivateKey}`,
    `Address = ${peerAddress}`,
    "DNS = 1.1.1.1, 1.0.0.1",
    "MTU = 1420",
    "",
    "[Peer]",
    `PublicKey = ${deriveXrayWireGuardPublicKey(serverPrivateKey)}`,
    `PresharedKey = ${preSharedKey}`,
    "AllowedIPs = 0.0.0.0/0",
    `Endpoint = ${endpoint}`,
    "PersistentKeepalive = 25",
    "",
  ].join("\n");
  return Object.freeze({ content, fileName: wireGuardFileName(input?.displayName) });
}
