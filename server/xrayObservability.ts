import { appendPanelLog, type PanelLogLevel } from "./_core/panelLogger";

const XRAY_SENSITIVE_KEY = /(?:^|[^a-z0-9])(?:agent.?token|token|authorization|proxy.?username|username|password|passwd|secret|private.?key|pre.?shared.?key|psk|header.?protection.?key|shadowsocks.?key|hysteria.?auth|reality.?private|(?:wireguard|amneziawg).?config|certificate(?:.?chain)?.?pem|uuid|short.?id|stats.?key|fingerprint|key.?version|config.?json|share.?uri|vpn.?uri|http.?proxy.?uri|mixed.?proxy.?endpoints|socks5.?uri|(?:vless|vmess|trojan|ss|hysteria2|wireguard|amneziawg|mtproto|telegram).?uri|credential|ciphertext|encrypted(?:.?value)?|envelope|master.?key)(?:$|[^a-z0-9])/i;
const UUID_PATTERN = /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi;
const XRAY_URI_PATTERN = /(?:vless|vmess|trojan|ss|hysteria2|wireguard|amneziawg|vpn|socks5|tg):\/\/[^\s"'<>]+|https?:\/\/[^\s:@"'<>]+:[^\s@"'<>]+@[^\s"'<>]+/gi;
const BEARER_PATTERN = /(authorization\s*:\s*(?:bearer\s+)?)[^\s,"';]+/gi;
const SENSITIVE_ASSIGNMENT_PATTERN = /((?:agent.?token|token|authorization|proxy.?username|username|password|passwd|secret|private.?key|pre.?shared.?key|psk|header.?protection.?key|shadowsocks.?key|hysteria.?auth|reality.?private|(?:wireguard|amneziawg).?config|certificate(?:.?chain)?.?pem|uuid|short.?id|stats.?key|fingerprint|key.?version|config.?json|share.?uri|vpn.?uri|http.?proxy.?uri|mixed.?proxy.?endpoints|socks5.?uri|(?:vless|vmess|trojan|ss|hysteria2|wireguard|amneziawg|mtproto|telegram).?uri|credential|ciphertext|encrypted(?:.?value)?|envelope|master.?key)["']?\s*[:=]\s*["']?)[^\s,"';}]+/gi;
const SENSITIVE_FILENAME_PATTERN = /((?:private.?key|certificate|uuid|short.?id|token|secret|config.?json)[-_.])[A-Za-z0-9_-]{8,}/gi;
const SAFE_VERSION = /^v?\d+\.\d+\.\d+$/;
const SAFE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SAFE_RUNTIME_STATUSES = new Set(["RUNNING", "STOPPED", "ERROR", "UNKNOWN"]);
const SAFE_LISTENER_STATUSES = new Set(["READY", "MISSING", "WRONG_PROCESS", "UNKNOWN"]);

export function isXraySensitiveKey(key: unknown) {
  const normalized = String(key ?? "").replace(/([a-z0-9])([A-Z])/g, "$1 $2");
  return XRAY_SENSITIVE_KEY.test(` ${normalized} `);
}

function scrubParsedJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(scrubParsedJson);
  if (!value || typeof value !== "object") return typeof value === "string" ? scrubXraySensitiveText(value, false) : value;
  return Object.fromEntries(Object.entries(value).map(([key, child]) => (
    [key, isXraySensitiveKey(key) ? "[REDACTED]" : scrubParsedJson(child)]
  )));
}

export function scrubXraySensitiveText(value: unknown, parseJson = true): string {
  const text = String(value ?? "");
  const trimmed = text.trim();
  if (parseJson && ((trimmed.startsWith("{") && trimmed.endsWith("}")) || (trimmed.startsWith("[") && trimmed.endsWith("]")))) {
    try {
      return JSON.stringify(scrubParsedJson(JSON.parse(trimmed)));
    } catch {
      // Continue with command/log text scrubbing.
    }
  }
  return text
    .replace(XRAY_URI_PATTERN, (uri) => `${uri.slice(0, uri.indexOf(":"))}://[REDACTED]`)
    .replace(BEARER_PATTERN, "$1[REDACTED]")
    .replace(SENSITIVE_ASSIGNMENT_PATTERN, "$1[REDACTED]")
    .replace(SENSITIVE_FILENAME_PATTERN, "$1[REDACTED]")
    .replace(UUID_PATTERN, "[REDACTED]");
}

function safeVersion(value: unknown) {
  const version = String(value ?? "");
  return SAFE_VERSION.test(version) ? version : null;
}

function hashPrefix(value: unknown) {
  const hash = String(value ?? "").toLowerCase();
  if (/^[0-9a-f]{12}$/.test(hash)) return hash;
  return /^[0-9a-f]{64}$/.test(hash) ? hash.slice(0, 12) : null;
}

export function projectXraySupportState(value: unknown) {
  const input = value && typeof value === "object" ? value as Record<string, unknown> : {};
  const status = String(input.serviceStatus ?? "UNKNOWN");
  const listeners = Array.isArray(input.listeners) ? input.listeners.slice(0, 256).flatMap((raw) => {
    const listener = raw && typeof raw === "object" ? raw as Record<string, unknown> : {};
    const runtimeTag = String(listener.runtimeTag ?? "");
    const port = Number(listener.port);
    const listenerStatus = String(listener.status ?? "UNKNOWN");
    if (!SAFE_IDENTIFIER.test(runtimeTag) || !Number.isInteger(port) || port < 1 || port > 65535 || !SAFE_LISTENER_STATUSES.has(listenerStatus)) return [];
    return [{ runtimeTag, port, status: listenerStatus }];
  }) : [];
  return {
    installedVersion: safeVersion(input.installedVersion),
    runningVersion: safeVersion(input.runningVersion),
    serviceStatus: SAFE_RUNTIME_STATUSES.has(status) ? status : "UNKNOWN",
    configHashPrefix: hashPrefix(input.appliedConfigHash ?? input.configHash ?? input.configHashPrefix),
    binaryHashPrefix: hashPrefix(input.binarySha256 ?? input.binaryHash ?? input.binaryHashPrefix),
    listeners,
  };
}

const AUDIT_NUMBER_FIELDS = ["userId", "hostId", "inboundId", "clientId", "managedServiceId", "managedServiceAccountId", "artifactId", "generation", "port", "durationMs"] as const;
const AUDIT_IDENTIFIER_FIELDS = ["operationId", "taskType", "status", "runtimeTag", "version", "errorCode"] as const;

export function projectXrayAuditFields(value: unknown) {
  const input = value && typeof value === "object" ? value as Record<string, unknown> : {};
  const output: Record<string, string | number> = {};
  for (const field of AUDIT_NUMBER_FIELDS) {
    const source = field === "generation"
      ? input.generation ?? input.desiredGeneration ?? input.requestedGeneration
      : input[field];
    const parsed = Number(source);
    if (Number.isSafeInteger(parsed) && parsed >= 0) output[field] = parsed;
  }
  for (const field of AUDIT_IDENTIFIER_FIELDS) {
    const parsed = String(input[field] ?? "");
    if (SAFE_IDENTIFIER.test(parsed)) output[field] = parsed;
  }
  const configHashPrefix = hashPrefix(input.configHash ?? input.appliedConfigHash);
  if (configHashPrefix) output.configHashPrefix = configHashPrefix;
  const binaryHashPrefix = hashPrefix(input.binarySha256 ?? input.binaryHash);
  if (binaryHashPrefix) output.binaryHashPrefix = binaryHashPrefix;
  return output;
}

export function xrayStructuredLogMessage(event: string, fields: unknown) {
  const safeEvent = /^[A-Z][A-Z0-9_]{0,63}$/.test(event) ? event : "INTERNAL_EVENT";
  const projected = projectXrayAuditFields(fields);
  const pairs = Object.entries(projected).map(([key, value]) => `${key}=${value}`);
  return `[Xray] event=${safeEvent}${pairs.length ? ` ${pairs.join(" ")}` : ""}`;
}

export function appendXrayStructuredLog(level: PanelLogLevel, event: string, fields: unknown) {
  appendPanelLog(level, xrayStructuredLogMessage(event, fields));
}
