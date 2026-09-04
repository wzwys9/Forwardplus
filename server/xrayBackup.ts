import fs from "node:fs";
import path from "node:path";
import { isIP } from "node:net";

import {
  accessSecretPolicyForCredentialType,
  isXrayAccessSecretKind,
  isXrayInboundSecretKind,
  parseStoredXrayAccessSettings,
} from "../shared/xrayAccess";
import { resolveStoredXrayInboundDefinition } from "../shared/xrayProfiles";
import { XRAY_QUICK_CONFIG_FORWARD_ENGINES } from "../shared/xrayQuickConfigForwardEngines";
import {
  XRAY_EXTERNAL_PROXY_SECRET_KINDS,
  buildXrayExternalProxyUri,
  type XrayExternalProxyDefinition,
  type XrayExternalProxySecretKind,
} from "../shared/xrayExternalProxy";
import type { MigrationSnapshot } from "./migration";
import {
  classifyDnsProviderLineName,
  computeStoredDnsProviderCatalogRevision,
  type StoredDnsProviderCatalogInput,
} from "./dnsProviderCatalog";
import { quoteIdentifier } from "./dbCompat";
import { queryRaw } from "./dbRuntime";
import {
  buildGlobalPortOwnerGroupTag,
  buildGlobalPortReferenceKey,
  type GlobalPortReferenceNetwork,
  type GlobalPortReferenceRole,
  type GlobalPortResourceType,
} from "./globalPortBackfill";
import {
  XraySecretUnavailableError,
  createXraySecretKeyring,
  decryptXraySecret,
  fingerprintXraySecret,
  inspectXraySecretEnvelope,
  loadXrayMasterKeyFile,
  resolveXrayMasterKeyPath,
  restoreXrayMasterKeyFile,
  type XraySecretKeyring,
  xrayAccessSecretContext,
  xrayClientShortIdContext,
  xrayClientUuidContext,
  xrayInboundSecretContext,
  xrayInboundPrivateKeyContext,
  xrayManagedServiceAccountSecretContext,
  xrayManagedServiceInstanceSecretContext,
  xrayDnsProviderAccountSecretContext,
  xrayTlsCertificatePrivateKeyContext,
  xrayExternalProxySecretContext,
  type XrayDnsProviderAccountSecretKind,
} from "./xraySecretCrypto";
import { validateXrayTlsCertificateInput } from "./xrayTlsCertificate";
import { computeXrayQuickConfigDnsTupleHash } from "./xrayQuickConfigDnsTuple";
import {
  AMNEZIAWG_HEADER_PROTECTION_KEY,
  AMNEZIAWG_PEER_PRE_SHARED_KEY,
  AMNEZIAWG_PEER_PRIVATE_KEY,
  AMNEZIAWG_SERVER_PRIVATE_KEY,
  parseAmneziaWgPeerSettings,
  parseAmneziaWgStoredSpec,
} from "./xrayAmneziaWgService";
import { canonicalXrayWireGuardKey, canonicalXrayWireGuardPrivateKey, deriveXrayWireGuardPublicKey } from "./xrayWireGuard";

export type XrayMasterKeyBackupBundle = {
  format: "forwardx-xray-master-key";
  version: 1;
  currentKeyId: string;
  keys: Record<string, string>;
};

const KEY_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;

function unavailable(): XraySecretUnavailableError {
  return new XraySecretUnavailableError();
}

function decodeBackupKey(value: unknown): Buffer {
  const encoded = String(value ?? "");
  if (!/^[A-Za-z0-9_-]{43}$/.test(encoded)) throw unavailable();
  const key = Buffer.from(encoded, "base64url");
  if (key.length !== 32 || key.toString("base64url") !== encoded) throw unavailable();
  return key;
}

export function createXrayMasterKeyBackupBundle(options: { path?: string } = {}): XrayMasterKeyBackupBundle {
  const keyring = loadXrayMasterKeyFile(options);
  const keys = Object.fromEntries([...keyring.keys].map(([keyId, key]) => [keyId, key.toString("base64url")]));
  return {
    format: "forwardx-xray-master-key",
    version: 1,
    currentKeyId: keyring.currentKeyId,
    keys,
  };
}

export function parseXrayMasterKeyBackupBundle(value: unknown): {
  bundle: XrayMasterKeyBackupBundle;
  currentKey: Buffer;
} {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw unavailable();
  const input = value as Record<string, unknown>;
  if (Object.keys(input).sort().join(",") !== "currentKeyId,format,keys,version"
    || input.format !== "forwardx-xray-master-key" || input.version !== 1
    || !KEY_ID_PATTERN.test(String(input.currentKeyId ?? ""))
    || !input.keys || typeof input.keys !== "object" || Array.isArray(input.keys)) {
    throw unavailable();
  }
  const keyEntries = Object.entries(input.keys as Record<string, unknown>);
  if (keyEntries.length !== 1 || keyEntries.some(([keyId]) => !KEY_ID_PATTERN.test(keyId))) throw unavailable();
  const currentKeyId = String(input.currentKeyId);
  const currentEntry = keyEntries.find(([keyId]) => keyId === currentKeyId);
  if (!currentEntry) throw unavailable();
  const currentKey = decodeBackupKey(currentEntry[1]);
  return {
    bundle: {
      format: "forwardx-xray-master-key",
      version: 1,
      currentKeyId,
      keys: { [currentKeyId]: currentKey.toString("base64url") },
    },
    currentKey,
  };
}

export function restoreXrayMasterKeyBackupBundle(
  value: unknown,
  options: { path?: string; allowReplace?: boolean } = {},
) {
  const parsed = parseXrayMasterKeyBackupBundle(value);
  return restoreXrayMasterKeyFile({
    path: options.path,
    keyId: parsed.bundle.currentKeyId,
    key: parsed.currentKey,
    allowReplace: options.allowReplace,
  });
}

export function migrationSnapshotHasXraySecrets(snapshot: MigrationSnapshot): boolean {
  return (snapshot.tables?.xray_inbounds || []).some((row) => typeof row.realityPrivateKeyEncrypted === "string" && row.realityPrivateKeyEncrypted.length > 0)
    || (snapshot.tables?.xray_clients || []).some((row) => (
      (typeof row.uuidEncrypted === "string" && row.uuidEncrypted.length > 0)
      || (typeof row.shortIdEncrypted === "string" && row.shortIdEncrypted.length > 0)
    ))
    || (snapshot.tables?.xray_access_secrets || []).some((row) => typeof row.encryptedValue === "string" && row.encryptedValue.length > 0)
    || (snapshot.tables?.xray_inbound_secrets || []).some((row) => typeof row.encryptedValue === "string" && row.encryptedValue.length > 0)
    || (snapshot.tables?.xray_external_proxy_secrets || []).some((row) => typeof row.encryptedValue === "string" && row.encryptedValue.length > 0)
    || (snapshot.tables?.dns_provider_account_secrets || []).some((row) => typeof row.encryptedValue === "string" && row.encryptedValue.length > 0)
    || (snapshot.tables?.xray_managed_service_secrets || []).some((row) => typeof row.encryptedValue === "string" && row.encryptedValue.length > 0)
    || (snapshot.tables?.xray_managed_service_instance_secrets || []).some((row) => typeof row.encryptedValue === "string" && row.encryptedValue.length > 0)
    || (snapshot.tables?.xray_tls_certificates || []).some((row) => typeof row.privateKeyEncrypted === "string" && row.privateKeyEncrypted.length > 0);
}

function snapshotId(value: unknown): number {
  const id = Number(value);
  if (!Number.isSafeInteger(id) || id <= 0) throw unavailable();
  return id;
}

function snapshotPositiveSafeInteger(value: unknown): number {
  const integer = Number(value);
  if (!Number.isSafeInteger(integer) || integer <= 0) throw unavailable();
  return integer;
}

function snapshotOptionalId(value: unknown): number | null {
  if (value === null || value === undefined || value === "") return null;
  return snapshotId(value);
}

function snapshotBoundedString(value: unknown, maximum: number, pattern?: RegExp): string {
  const text = String(value ?? "");
  if (!text || text.length > maximum || (pattern && !pattern.test(text))) throw unavailable();
  return text;
}

function assertSafeSummaryJson(value: unknown, context: "OPERATION" | "STEP") {
  const raw = String(value ?? "");
  if (!raw || Buffer.byteLength(raw, "utf8") > 16_384) throw unavailable();
  let parsed: unknown;
  try { parsed = JSON.parse(raw); } catch { throw unavailable(); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw unavailable();
  const summary = parsed as Record<string, unknown>;
  if (Object.keys(summary).length === 0) return;
  if (context === "OPERATION" && summary.kind === "CONFIG_SYNC" && summary.schemaVersion === 1
    && Object.keys(summary).every((key) => ["kind", "schemaVersion"].includes(key))) return;
  if (context === "STEP" && summary.kind === "DNS_SYNC_INTENT" && summary.schemaVersion === 1
    && Object.keys(summary).every((key) => ["kind", "schemaVersion", "preexistingExactProviderRecordIds"].includes(key))
    && Array.isArray(summary.preexistingExactProviderRecordIds)
    && summary.preexistingExactProviderRecordIds.length <= 64
    && new Set(summary.preexistingExactProviderRecordIds).size === summary.preexistingExactProviderRecordIds.length
    && summary.preexistingExactProviderRecordIds.every((id) => (
      typeof id === "string" && /^[1-9]\d*$/.test(id) && Number.isSafeInteger(Number(id))
    ))
    && summary.preexistingExactProviderRecordIds.every((id, index, ids) => (
      index === 0 || Number(ids[index - 1]) < Number(id)
    ))) return;
  throw unavailable();
}

function assertSafeDiagnosticText(value: unknown, maximum: number) {
  if (value === null || value === undefined) return;
  const text = String(value);
  if (text.length > maximum || /(?:vless|ss|socks5):\/\//i.test(text)
    || /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/i.test(text)
    || /\b(?:[0-9a-f]{32,}|[A-Za-z0-9_-]{32,})\b/.test(text)
    || /(?:secret(?:id|key)?|password|authorization|token|privatekey|apikey|accesskey|keymaterial|uuid|shortid)\s*[:=]/i.test(text)) {
    throw unavailable();
  }
}

function verifiedSnapshotSecret(input: {
  row: Record<string, any>;
  context: ReturnType<typeof xrayAccessSecretContext>;
  keyring: XraySecretKeyring;
}) {
  const encryptedValue = String(input.row.encryptedValue ?? "");
  const fingerprint = String(input.row.fingerprint ?? "");
  const envelope = inspectXraySecretEnvelope(encryptedValue);
  if (Number(input.row.keyVersion) !== envelope.version || !/^[0-9a-f]{64}$/.test(fingerprint)) throw unavailable();
  const plaintext = decryptXraySecret(encryptedValue, input.context, input.keyring);
  if (fingerprintXraySecret(plaintext, input.context, input.keyring) !== fingerprint) throw unavailable();
  return { fingerprint, plaintext };
}

function snapshotEpochSeconds(value: unknown): number {
  if (value instanceof Date) return Math.floor(value.getTime() / 1000);
  if (typeof value === "number" && Number.isSafeInteger(value) && value > 0) {
    return value > 10_000_000_000 ? Math.floor(value / 1000) : value;
  }
  const parsed = Date.parse(String(value ?? ""));
  if (!Number.isFinite(parsed) || parsed <= 0) throw unavailable();
  return Math.floor(parsed / 1000);
}

export function assertMigrationSnapshotXraySecretsAvailable(
  snapshot: MigrationSnapshot,
  options: { path?: string; keyring?: XraySecretKeyring } = {},
) {
  const hasEncryptedSecrets = migrationSnapshotHasXraySecrets(snapshot);
  const hasGenericRecords = (snapshot.tables?.xray_access_entries?.length ?? 0) > 0
    || (snapshot.tables?.xray_access_secrets?.length ?? 0) > 0
    || (snapshot.tables?.xray_inbound_secrets?.length ?? 0) > 0
    || (snapshot.tables?.xray_external_proxy_nodes?.length ?? 0) > 0
    || (snapshot.tables?.xray_external_proxy_secrets?.length ?? 0) > 0
    || (snapshot.tables?.dns_provider_accounts?.length ?? 0) > 0
    || (snapshot.tables?.dns_provider_account_secrets?.length ?? 0) > 0
    || (snapshot.tables?.dns_provider_global_bindings?.length ?? 0) > 0
    || (snapshot.tables?.dns_provider_zones?.length ?? 0) > 0
    || (snapshot.tables?.dns_provider_record_lines?.length ?? 0) > 0
    || (snapshot.tables?.xray_quick_configs?.length ?? 0) > 0
    || (snapshot.tables?.xray_quick_config_domain_claims?.length ?? 0) > 0
    || (snapshot.tables?.xray_quick_config_topology_revisions?.length ?? 0) > 0
    || (snapshot.tables?.xray_quick_config_routes?.length ?? 0) > 0
    || (snapshot.tables?.xray_quick_config_rule_bindings?.length ?? 0) > 0
    || (snapshot.tables?.xray_quick_config_dns_records?.length ?? 0) > 0
    || (snapshot.tables?.xray_quick_config_dns_record_backups?.length ?? 0) > 0
    || (snapshot.tables?.xray_quick_config_operations?.length ?? 0) > 0
    || (snapshot.tables?.xray_quick_config_operation_steps?.length ?? 0) > 0
    || (snapshot.tables?.global_port_allocations?.length ?? 0) > 0
    || (snapshot.tables?.global_port_allocation_references?.length ?? 0) > 0
    || (snapshot.tables?.global_port_probe_runs?.length ?? 0) > 0
    || (snapshot.tables?.global_port_probe_results?.length ?? 0) > 0
    || (snapshot.tables?.global_port_scan_leases?.length ?? 0) > 0
    || (snapshot.tables?.xray_managed_services?.length ?? 0) > 0
    || (snapshot.tables?.xray_managed_service_accounts?.length ?? 0) > 0
    || (snapshot.tables?.xray_managed_service_secrets?.length ?? 0) > 0
    || (snapshot.tables?.xray_managed_service_instance_secrets?.length ?? 0) > 0
    || (snapshot.tables?.xray_tls_certificates?.length ?? 0) > 0
    || (snapshot.tables?.xray_inbounds || []).some((row) => row.externalProxyNodeId !== null && row.externalProxyNodeId !== undefined)
    || (snapshot.tables?.forward_rules || []).some((row) => row.targetExternalProxyNodeId !== null && row.targetExternalProxyNodeId !== undefined);
  if (!hasEncryptedSecrets && !hasGenericRecords) return;
  const keyring = options.keyring || (hasEncryptedSecrets ? loadXrayMasterKeyFile(options) : undefined);
  const requireKeyring = () => {
    if (!keyring) throw unavailable();
    return keyring;
  };
  try {
    const inboundById = new Map<number, Record<string, any>>();
    for (const row of snapshot.tables?.xray_inbounds || []) {
      if (row.id !== undefined) {
        const id = snapshotId(row.id);
        if (inboundById.has(id)) throw unavailable();
        inboundById.set(id, row);
      }
      if (row.realityPrivateKeyEncrypted) {
        decryptXraySecret(
          String(row.realityPrivateKeyEncrypted),
          xrayInboundPrivateKeyContext(String(row.runtimeTag ?? "")),
          requireKeyring(),
        );
      }
    }
    const legacyClientById = new Map<number, Record<string, any>>();
    for (const row of snapshot.tables?.xray_clients || []) {
      if (row.id !== undefined) {
        const id = snapshotId(row.id);
        if (legacyClientById.has(id)) throw unavailable();
        legacyClientById.set(id, row);
      }
      const statsKey = String(row.statsKey ?? "");
      if (row.uuidEncrypted) {
        const context = xrayClientUuidContext(statsKey);
        decryptXraySecret(String(row.uuidEncrypted), context, requireKeyring());
      }
      if (row.shortIdEncrypted) {
        const context = xrayClientShortIdContext(statsKey);
        decryptXraySecret(String(row.shortIdEncrypted), context, requireKeyring());
      }
    }

    const accessById = new Map<number, Record<string, any>>();
    const accessKinds = new Map<number, Set<string>>();
    const accessSecrets = new Map<number, Map<string, Record<string, any>>>();
    for (const row of snapshot.tables?.xray_access_entries || []) {
      const id = snapshotId(row.id);
      if (accessById.has(id) || !inboundById.has(snapshotId(row.inboundId))
        || !parseStoredXrayAccessSettings({ credentialType: row.credentialType, settingsJson: row.settingsJson })) {
        throw unavailable();
      }
      accessById.set(id, row);
      accessKinds.set(id, new Set());
      accessSecrets.set(id, new Map());
    }
    const globalUuidFingerprints = new Set<string>();
    const inboundShortIdFingerprints = new Set<string>();
    for (const row of snapshot.tables?.xray_access_secrets || []) {
      const accessEntryId = snapshotId(row.accessEntryId);
      const access = accessById.get(accessEntryId);
      if (!access || !isXrayAccessSecretKind(row.kind)) throw unavailable();
      const policy = accessSecretPolicyForCredentialType(access.credentialType);
      const allowed = policy ? new Set([...policy.required, ...policy.optional]) : null;
      const kinds = accessKinds.get(accessEntryId);
      if (!allowed?.has(row.kind) || !kinds || kinds.has(row.kind)) throw unavailable();
      kinds.add(row.kind);
      accessSecrets.get(accessEntryId)?.set(row.kind, row);
      const { fingerprint } = verifiedSnapshotSecret({
        row,
        context: xrayAccessSecretContext(String(access.statsKey ?? ""), row.kind),
        keyring: requireKeyring(),
      });
      if (row.kind === "UUID") {
        if (globalUuidFingerprints.has(fingerprint)) throw unavailable();
        globalUuidFingerprints.add(fingerprint);
      } else if (row.kind === "SHORT_ID") {
        const identity = `${snapshotId(access.inboundId)}:${fingerprint}`;
        if (inboundShortIdFingerprints.has(identity)) throw unavailable();
        inboundShortIdFingerprints.add(identity);
      }
    }
    for (const [accessEntryId, access] of accessById) {
      const policy = accessSecretPolicyForCredentialType(access.credentialType);
      const kinds = accessKinds.get(accessEntryId);
      if (!policy || !kinds || policy.required.some((kind) => !kinds.has(kind))) throw unavailable();
      if (access.legacyClientId !== null && access.legacyClientId !== undefined) {
        const legacy = legacyClientById.get(snapshotId(access.legacyClientId));
        const secrets = accessSecrets.get(accessEntryId);
        if (!legacy || snapshotId(legacy.inboundId) !== snapshotId(access.inboundId)
          || String(legacy.statsKey ?? "") !== String(access.statsKey ?? "")
          || String(legacy.flow ?? "xtls-rprx-vision") !== "xtls-rprx-vision"
          || secrets?.get("UUID")?.encryptedValue !== legacy.uuidEncrypted
          || secrets?.get("SHORT_ID")?.encryptedValue !== legacy.shortIdEncrypted
          || secrets?.get("UUID")?.fingerprint !== legacy.uuidFingerprint
          || secrets?.get("SHORT_ID")?.fingerprint !== legacy.shortIdFingerprint) {
          throw unavailable();
        }
      }
    }

    const inboundKinds = new Set<string>();
    for (const row of snapshot.tables?.xray_inbound_secrets || []) {
      const inboundId = snapshotId(row.inboundId);
      const inbound = inboundById.get(inboundId);
      if (!inbound || !isXrayInboundSecretKind(row.kind)) throw unavailable();
      const identity = `${inboundId}:${row.kind}`;
      if (inboundKinds.has(identity)) throw unavailable();
      inboundKinds.add(identity);
      if (row.kind === "REALITY_PRIVATE_KEY" && inbound.realityPrivateKeyEncrypted
        && row.encryptedValue !== inbound.realityPrivateKeyEncrypted) throw unavailable();
      verifiedSnapshotSecret({
        row,
        context: xrayInboundSecretContext(String(inbound.runtimeTag ?? ""), row.kind),
        keyring: requireKeyring(),
      });
    }

    const certificateHosts = new Map<number, number>();
    for (const row of snapshot.tables?.xray_tls_certificates || []) {
      const id = snapshotId(row.id);
      const hostId = snapshotId(row.hostId);
      if (certificateHosts.has(id)) throw unavailable();
      certificateHosts.set(id, hostId);
      const certificateTag = String(row.certificateTag ?? "");
      if (!/^forwardx-cert-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(certificateTag)) {
        throw unavailable();
      }
      const context = xrayTlsCertificatePrivateKeyContext(certificateTag);
      const privateKeyEncrypted = String(row.privateKeyEncrypted ?? "");
      const envelope = inspectXraySecretEnvelope(privateKeyEncrypted);
      if (Number(row.keyVersion) !== envelope.version || !/^[0-9a-f]{64}$/.test(String(row.privateKeyFingerprint ?? ""))) {
        throw unavailable();
      }
      const privateKeyPem = decryptXraySecret(privateKeyEncrypted, context, requireKeyring());
      if (fingerprintXraySecret(privateKeyPem, context, requireKeyring()) !== row.privateKeyFingerprint) throw unavailable();
      const validated = validateXrayTlsCertificateInput({
        certificatePem: row.certificateChainPem,
        privateKeyPem,
        enforceValidity: false,
      });
      let dnsNames: unknown;
      try {
        dnsNames = JSON.parse(String(row.dnsNamesJson ?? ""));
      } catch {
        throw unavailable();
      }
      if (validated.certificateChainPem !== row.certificateChainPem
        || validated.privateKeyPem !== privateKeyPem
        || validated.leafFingerprintSha256 !== row.leafFingerprintSha256
        || JSON.stringify(validated.dnsNames) !== JSON.stringify(dnsNames)
        || validated.subject !== row.subject
        || validated.issuer !== row.issuer
        || validated.serialNumber !== row.serialNumber
        || validated.notBefore !== snapshotEpochSeconds(row.notBefore)
        || validated.notAfter !== snapshotEpochSeconds(row.notAfter)
        || validated.keyAlgorithm !== row.keyAlgorithm) {
        throw unavailable();
      }
    }
    for (const inbound of inboundById.values()) {
      if (inbound.tlsCertificateId === null || inbound.tlsCertificateId === undefined) continue;
      const certificateHostId = certificateHosts.get(snapshotId(inbound.tlsCertificateId));
      if (certificateHostId === undefined || certificateHostId !== snapshotId(inbound.hostId)) throw unavailable();
    }

    const externalNodes = new Map<number, Record<string, any>>();
    for (const row of snapshot.tables?.xray_external_proxy_nodes || []) {
      const id = snapshotId(row.id);
      const nodeTag = String(row.nodeTag ?? "");
      if (externalNodes.has(id)
        || !/^forwardx-external-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(nodeTag)) {
        throw unavailable();
      }
      externalNodes.set(id, row);
    }
    const externalSecrets = new Map<number, Map<XrayExternalProxySecretKind, string>>();
    for (const row of snapshot.tables?.xray_external_proxy_secrets || []) {
      const nodeId = snapshotId(row.externalProxyNodeId);
      const node = externalNodes.get(nodeId);
      const kind = String(row.kind) as XrayExternalProxySecretKind;
      if (!node || !(XRAY_EXTERNAL_PROXY_SECRET_KINDS as readonly string[]).includes(kind)) throw unavailable();
      const values = externalSecrets.get(nodeId) ?? new Map<XrayExternalProxySecretKind, string>();
      if (values.has(kind)) throw unavailable();
      const verified = verifiedSnapshotSecret({
        row,
        context: xrayExternalProxySecretContext(String(node.nodeTag), kind),
        keyring: requireKeyring(),
      });
      values.set(kind, verified.plaintext);
      externalSecrets.set(nodeId, values);
    }
    for (const [nodeId, node] of externalNodes) {
      let spec: Record<string, unknown>;
      try {
        const parsed = JSON.parse(String(node.specJson ?? ""));
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw unavailable();
        spec = parsed;
      } catch {
        throw unavailable();
      }
      const values = externalSecrets.get(nodeId) ?? new Map<XrayExternalProxySecretKind, string>();
      const base = {
        address: String(node.address ?? ""), port: Number(node.port), displayName: String(node.name ?? ""), specVersion: Number(node.specVersion),
      };
      let definition: XrayExternalProxyDefinition;
      if (node.protocol === "VLESS_REALITY_VISION") {
        if (values.size !== 2 || !values.has("VLESS_UUID") || !values.has("VLESS_SHORT_ID")) throw unavailable();
        definition = { ...base, protocol: node.protocol, spec, credentials: {
          uuid: values.get("VLESS_UUID")!, shortId: values.get("VLESS_SHORT_ID")!,
        } } as XrayExternalProxyDefinition;
      } else if (node.protocol === "SHADOWSOCKS") {
        if (values.size !== 1 || !values.has("SHADOWSOCKS_PASSWORD")) throw unavailable();
        definition = { ...base, protocol: node.protocol, spec, credentials: {
          password: values.get("SHADOWSOCKS_PASSWORD")!,
        } } as XrayExternalProxyDefinition;
      } else if (node.protocol === "SOCKS5") {
        if (values.size !== 0 && (values.size !== 2 || !values.has("SOCKS_USERNAME") || !values.has("SOCKS_PASSWORD"))) throw unavailable();
        definition = { ...base, protocol: node.protocol, spec, credentials: values.size === 0 ? {} : {
          username: values.get("SOCKS_USERNAME")!, password: values.get("SOCKS_PASSWORD")!,
        } } as XrayExternalProxyDefinition;
      } else {
        throw unavailable();
      }
      try { buildXrayExternalProxyUri(definition); } catch { throw unavailable(); }
    }
    for (const inbound of inboundById.values()) {
      if (inbound.externalProxyNodeId !== null && inbound.externalProxyNodeId !== undefined
        && !externalNodes.has(snapshotId(inbound.externalProxyNodeId))) throw unavailable();
    }
    for (const rule of snapshot.tables?.forward_rules || []) {
      if (rule.targetExternalProxyNodeId !== null && rule.targetExternalProxyNodeId !== undefined
        && !externalNodes.has(snapshotId(rule.targetExternalProxyNodeId))) throw unavailable();
    }

    const snapshotUserIds = new Set<number>();
    for (const row of snapshot.tables?.users || []) {
      const id = snapshotId(row.id);
      if (snapshotUserIds.has(id)) throw unavailable();
      snapshotUserIds.add(id);
    }
    const dnsAccounts = new Map<number, Record<string, any>>();
    const dnsAccountTags = new Set<string>();
    for (const row of snapshot.tables?.dns_provider_accounts || []) {
      const id = snapshotId(row.id);
      const accountTag = String(row.accountTag ?? "");
      if (dnsAccounts.has(id) || dnsAccountTags.has(accountTag)
        || !/^forwardx-dns-account-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(accountTag)
        || row.provider !== "DNSPOD"
        || !snapshotUserIds.has(snapshotId(row.createdByUserId))
        || !["UNVERIFIED", "VALID", "INVALID", "ERROR", "EXPIRED"].includes(String(row.verificationStatus))) throw unavailable();
      snapshotPositiveSafeInteger(row.revision);
      dnsAccounts.set(id, row);
      dnsAccountTags.add(accountTag);
    }
    const dnsSecretKinds = new Map<number, Set<XrayDnsProviderAccountSecretKind>>();
    const dnsSecretIds = new Set<number>();
    for (const row of snapshot.tables?.dns_provider_account_secrets || []) {
      const id = snapshotId(row.id);
      const accountId = snapshotId(row.accountId);
      const account = dnsAccounts.get(accountId);
      const kind = String(row.kind) as XrayDnsProviderAccountSecretKind;
      const kinds = dnsSecretKinds.get(accountId) ?? new Set<XrayDnsProviderAccountSecretKind>();
      if (!account || dnsSecretIds.has(id) || !["DNSPOD_SECRET_ID", "DNSPOD_SECRET_KEY"].includes(kind) || kinds.has(kind)) throw unavailable();
      verifiedSnapshotSecret({
        row,
        context: xrayDnsProviderAccountSecretContext(String(account.accountTag), kind),
        keyring: requireKeyring(),
      });
      dnsSecretIds.add(id);
      kinds.add(kind);
      dnsSecretKinds.set(accountId, kinds);
    }
    if ([...dnsAccounts].some(([accountId]) => {
      const kinds = dnsSecretKinds.get(accountId);
      return kinds?.size !== 2 || !kinds.has("DNSPOD_SECRET_ID") || !kinds.has("DNSPOD_SECRET_KEY");
    })) throw unavailable();

    const dnsBindings = snapshot.tables?.dns_provider_global_bindings || [];
    const hasDnsProviderData = dnsAccounts.size > 0
      || (snapshot.tables?.dns_provider_account_secrets?.length ?? 0) > 0
      || (snapshot.tables?.dns_provider_zones?.length ?? 0) > 0
      || (snapshot.tables?.dns_provider_record_lines?.length ?? 0) > 0
      || (snapshot.tables?.xray_quick_configs?.length ?? 0) > 0
      || (snapshot.tables?.xray_quick_config_dns_records?.length ?? 0) > 0
      || (snapshot.tables?.xray_quick_config_dns_record_backups?.length ?? 0) > 0
      || (snapshot.tables?.xray_quick_config_operations?.length ?? 0) > 0;
    if (dnsBindings.length > 1 || (hasDnsProviderData && dnsBindings.length !== 1)) throw unavailable();
    if (dnsBindings.length === 1) {
      const binding = dnsBindings[0];
      snapshotId(binding.id);
      snapshotPositiveSafeInteger(binding.revision);
      if (binding.scopeKey !== "XRAY_QUICK_CONFIG") throw unavailable();
      if (binding.accountId !== null && binding.accountId !== undefined
        && !dnsAccounts.has(snapshotId(binding.accountId))) {
        throw unavailable();
      }
    }

    const dnsZones = new Map<number, Record<string, any>>();
    const dnsZoneKeys = new Set<string>();
    const dnsZoneNames = new Set<string>();
    const dnsCatalogRevisions = new Map<number, string>();
    for (const row of snapshot.tables?.dns_provider_zones || []) {
      const id = snapshotId(row.id);
      const accountId = snapshotId(row.accountId);
      const providerZoneId = String(row.providerZoneId ?? "");
      const name = String(row.name ?? "");
      const zoneKey = `${accountId}:${providerZoneId}`;
      const nameKey = `${accountId}:${name}`;
      if (!dnsAccounts.has(accountId) || dnsZones.has(id) || !providerZoneId || !name
        || dnsZoneKeys.has(zoneKey) || dnsZoneNames.has(nameKey)
        || !["AVAILABLE", "STALE", "REMOVED", "ERROR"].includes(String(row.status))
        || !/^[0-9a-f]{64}$/.test(String(row.catalogRevision ?? ""))) throw unavailable();
      dnsZones.set(id, row);
      dnsZoneKeys.add(zoneKey);
      dnsZoneNames.add(nameKey);
      const existingCatalogRevision = dnsCatalogRevisions.get(accountId);
      if (existingCatalogRevision && existingCatalogRevision !== row.catalogRevision) throw unavailable();
      dnsCatalogRevisions.set(accountId, String(row.catalogRevision));
    }
    const dnsLineKeys = new Set<string>();
    const dnsLineIds = new Set<number>();
    const dnsLinesByZone = new Map<number, Record<string, any>[]>();
    for (const row of snapshot.tables?.dns_provider_record_lines || []) {
      const id = snapshotId(row.id);
      const zoneId = snapshotId(row.zoneId);
      const zone = dnsZones.get(zoneId);
      const providerLineId = String(row.providerLineId ?? "");
      const lineKey = `${zoneId}:${providerLineId}`;
      if (!zone || dnsLineIds.has(id) || !providerLineId || dnsLineKeys.has(lineKey)
        || !["DEFAULT", "TELECOM", "UNICOM", "MOBILE", "EDUCATION", "OTHER"].includes(String(row.category))
        || !["AVAILABLE", "STALE", "REMOVED", "ERROR"].includes(String(row.status))
        || (row.status === "AVAILABLE" && zone.status !== "AVAILABLE")
        || (row.status === "AVAILABLE" && classifyDnsProviderLineName(row.name) !== row.category)
        || String(row.catalogRevision ?? "") !== String(zone.catalogRevision ?? "")) throw unavailable();
      dnsLineIds.add(id);
      dnsLineKeys.add(lineKey);
      const lines = dnsLinesByZone.get(zoneId) ?? [];
      lines.push(row);
      dnsLinesByZone.set(zoneId, lines);
    }
    for (const accountId of dnsAccounts.keys()) {
      const accountZones = [...dnsZones.values()].filter((zone) => snapshotId(zone.accountId) === accountId);
      if (accountZones.length === 0) continue;
      const storedCatalog: StoredDnsProviderCatalogInput[] = accountZones.map((zone) => ({
          providerZoneId: String(zone.providerZoneId),
          name: String(zone.name),
          status: zone.status,
          lines: (dnsLinesByZone.get(snapshotId(zone.id)) ?? [])
            .map((line) => ({
              providerLineId: String(line.providerLineId),
              name: String(line.name),
              status: line.status,
              category: line.category,
            })),
        }));
      const expectedRevision = computeStoredDnsProviderCatalogRevision(storedCatalog);
      if (accountZones.some((zone) => zone.catalogRevision !== expectedRevision)
        || accountZones.some((zone) => (dnsLinesByZone.get(snapshotId(zone.id)) ?? [])
          .some((line) => line.catalogRevision !== expectedRevision))) throw unavailable();
    }

    const hostRows = new Map((snapshot.tables?.hosts || []).map((row) => [snapshotId(row.id), row]));
    const hostIds = new Set(hostRows.keys());
    const quickConfigs = new Map<number, Record<string, any>>();
    const quickConfigTags = new Set<string>();
    for (const row of snapshot.tables?.xray_quick_configs || []) {
      const id = snapshotId(row.id);
      const configTag = snapshotBoundedString(row.configTag, 128);
      const targetType = String(row.targetType ?? "");
      const xrayInboundId = snapshotOptionalId(row.xrayInboundId);
      const externalProxyNodeId = snapshotOptionalId(row.externalProxyNodeId);
      const dnsAccountId = snapshotId(row.dnsAccountId);
      const zoneId = snapshotId(row.zoneId);
      const zone = dnsZones.get(zoneId);
      if (quickConfigs.has(id) || quickConfigTags.has(configTag)
        || !/^[0-9a-f]{64}$/.test(String(row.targetVersion ?? ""))
        || !["APPLYING", "ACTIVE", "UPDATING", "DELETING", "COMPENSATING", "PARTIAL_FAILURE", "FAILED", "REMOVED"].includes(String(row.state))
        || !dnsAccounts.has(dnsAccountId) || !zone || snapshotId(zone.accountId) !== dnsAccountId
        || !snapshotUserIds.has(snapshotId(row.createdByUserId))) throw unavailable();
      snapshotPositiveSafeInteger(row.revision);
      snapshotBoundedString(row.relativeName, 253);
      snapshotBoundedString(row.fqdn, 253);
      if ((targetType === "XRAY_INBOUND" && (!xrayInboundId || externalProxyNodeId !== null || !inboundById.has(xrayInboundId)))
        || (targetType === "EXTERNAL_PROXY_NODE" && (!externalProxyNodeId || xrayInboundId !== null || !externalNodes.has(externalProxyNodeId)))
        || !["XRAY_INBOUND", "EXTERNAL_PROXY_NODE"].includes(targetType)) throw unavailable();
      quickConfigs.set(id, row);
      quickConfigTags.add(configTag);
    }
    if (quickConfigs.size > 0) {
      if (dnsBindings.length !== 1 || snapshotOptionalId(dnsBindings[0].accountId) === null) throw unavailable();
      const boundAccountId = snapshotId(dnsBindings[0].accountId);
      if ([...quickConfigs.values()].some((row) => snapshotId(row.dnsAccountId) !== boundAccountId)) throw unavailable();
    }

    const domainClaimIds = new Set<number>();
    const domainClaimKeys = new Set<string>();
    const claimedQuickConfigs = new Set<number>();
    for (const row of snapshot.tables?.xray_quick_config_domain_claims || []) {
      const id = snapshotId(row.id);
      const claimKey = snapshotBoundedString(row.claimKey, 64, /^[0-9a-f]{64}$/);
      const quickConfigId = snapshotId(row.quickConfigId);
      const quickConfig = quickConfigs.get(quickConfigId);
      const dnsAccountId = snapshotId(row.dnsAccountId);
      const zoneId = snapshotId(row.zoneId);
      snapshotPositiveSafeInteger(row.revision);
      if (domainClaimIds.has(id) || domainClaimKeys.has(claimKey) || claimedQuickConfigs.has(quickConfigId)
        || !quickConfig || dnsAccountId !== snapshotId(quickConfig.dnsAccountId)
        || zoneId !== snapshotId(quickConfig.zoneId)
        || snapshotBoundedString(row.normalizedRelativeName, 253) !== String(quickConfig.relativeName)) throw unavailable();
      domainClaimIds.add(id); domainClaimKeys.add(claimKey); claimedQuickConfigs.add(quickConfigId);
    }
    if ([...quickConfigs].some(([id, row]) => row.state !== "REMOVED" && !claimedQuickConfigs.has(id))) throw unavailable();

    const allocationIds = new Map<number, Record<string, any>>();
    const allocationTags = new Set<string>();
    const allocationPorts = new Set<number>();
    const inactiveAllocationStates = new Set(["FREE", "PENDING_SCAN", "EXTERNAL_OCCUPIED", "LEGACY_CONFLICT"]);
    for (const row of snapshot.tables?.global_port_allocations || []) {
      const id = snapshotId(row.id);
      const allocationTag = snapshotBoundedString(row.allocationTag, 128);
      const port = Number(row.port);
      const status = String(row.status ?? "");
      const primaryOwnerType = row.primaryOwnerType === null || row.primaryOwnerType === undefined ? null : snapshotBoundedString(row.primaryOwnerType, 32);
      const primaryOwnerTag = row.primaryOwnerTag === null || row.primaryOwnerTag === undefined ? null : snapshotBoundedString(row.primaryOwnerTag, 128);
      const reservationTokenHash = row.reservationTokenHash === null || row.reservationTokenHash === undefined
        ? null : String(row.reservationTokenHash);
      if (allocationIds.has(id) || allocationTags.has(allocationTag) || allocationPorts.has(port)
        || !Number.isSafeInteger(port) || port < 1 || port > 65535
        || !["RESERVED", "ACTIVE", "RELEASING", "PENDING_SCAN", "FREE", "EXTERNAL_OCCUPIED", "LEGACY_CONFLICT"].includes(status)
        || !["XRAY_INBOUND", "FORWARD_RULE", "MANAGED_SERVICE", "TUNNEL", "QUICK_CONFIG", null].includes(primaryOwnerType)
        || (inactiveAllocationStates.has(status) ? primaryOwnerType !== null || primaryOwnerTag !== null : !primaryOwnerType || !primaryOwnerTag)
        || (status === "RESERVED" ? reservationTokenHash === null || row.reservedUntil === null || row.reservedUntil === undefined : reservationTokenHash !== null)) throw unavailable();
      snapshotPositiveSafeInteger(row.version);
      if (reservationTokenHash !== null && !/^[0-9a-f]{64}$/.test(reservationTokenHash)) throw unavailable();
      allocationIds.set(id, row); allocationTags.add(allocationTag); allocationPorts.add(port);
    }

    const topologyIds = new Map<number, Record<string, any>>();
    const topologyKeys = new Set<string>();
    const activeTopologyByQuickConfig = new Set<number>();
    for (const row of snapshot.tables?.xray_quick_config_topology_revisions || []) {
      const id = snapshotId(row.id);
      const quickConfigId = snapshotId(row.quickConfigId);
      const revisionNumber = snapshotPositiveSafeInteger(row.revisionNumber);
      const allocationId = snapshotId(row.portAllocationId);
      const allocation = allocationIds.get(allocationId);
      const state = String(row.state ?? "");
      const activeSlot = snapshotOptionalId(row.activeSlot);
      const publicPort = Number(row.publicPort);
      const targetPort = Number(row.targetPort);
      const quickConfig = quickConfigs.get(quickConfigId);
      const target = quickConfig?.targetType === "XRAY_INBOUND"
        ? inboundById.get(snapshotId(quickConfig.xrayInboundId))
        : externalNodes.get(snapshotId(quickConfig?.externalProxyNodeId));
      const expectedTargetAddress = quickConfig?.targetType === "XRAY_INBOUND"
        ? String(target?.publicAddress ?? "") : String(target?.address ?? "");
      const expectedTargetPort = quickConfig?.targetType === "XRAY_INBOUND"
        ? Number(target?.listenPort) : Number(target?.port);
      const key = `${quickConfigId}:${revisionNumber}`;
      if (topologyIds.has(id) || topologyKeys.has(key) || !quickConfigs.has(quickConfigId) || !allocation
        || !(XRAY_QUICK_CONFIG_FORWARD_ENGINES as readonly unknown[]).includes(row.engine)
        || !["STAGED", "APPLYING", "APPLIED", "RETIRING", "RETIRED", "ROLLBACK_PENDING", "ABANDONED"].includes(state)
        || !Number.isSafeInteger(publicPort) || publicPort < 1 || publicPort > 65535 || publicPort !== Number(allocation.port)
        || !Number.isSafeInteger(targetPort) || targetPort < 1 || targetPort > 65535
        || !target || String(row.targetAddress) !== expectedTargetAddress || targetPort !== expectedTargetPort
        || !snapshotUserIds.has(snapshotId(row.createdByUserId))
        || (state === "APPLIED" ? activeSlot !== 1 : activeSlot !== null)
        || (activeSlot === 1 && activeTopologyByQuickConfig.has(quickConfigId))) throw unavailable();
      snapshotBoundedString(row.targetAddress, 253);
      topologyIds.set(id, row); topologyKeys.add(key);
      if (activeSlot === 1) activeTopologyByQuickConfig.add(quickConfigId);
    }

    const routeIds = new Map<number, Record<string, any>>();
    const routeTags = new Set<string>();
    const routeKeys = new Set<string>();
    for (const row of snapshot.tables?.xray_quick_config_routes || []) {
      const id = snapshotId(row.id);
      const routeTag = snapshotBoundedString(row.routeTag, 128);
      const quickConfigId = snapshotId(row.quickConfigId);
      const quickConfig = quickConfigs.get(quickConfigId);
      const topologyRevisionId = snapshotId(row.topologyRevisionId);
      const topology = topologyIds.get(topologyRevisionId);
      const sourceType = String(row.sourceType ?? "");
      const routeMode = String(row.routeMode ?? "");
      const hostId = snapshotOptionalId(row.hostId);
      const address = snapshotBoundedString(row.address, 253);
      const addressFamily = String(row.addressFamily ?? "");
      const host = hostId === null ? undefined : hostRows.get(hostId);
      const expectedManagedAddress = addressFamily === "IPV4"
        ? String(host?.ipv4 || (isIP(String(host?.ip ?? "")) === 4 ? host?.ip : "") || "")
        : String(host?.ipv6 || (isIP(String(host?.ip ?? "")) === 6 ? host?.ip : "") || "");
      const expectedLandingAddress = String(topology?.targetAddress ?? "");
      const providerLine = quickConfig
        ? (dnsLinesByZone.get(snapshotId(quickConfig.zoneId)) ?? [])
          .find((line) => String(line.providerLineId) === String(row.providerLineId))
        : undefined;
      const key = [quickConfigId, topologyRevisionId, row.lineCategory, sourceType, hostId ?? "", row.addressFamily, address].join(":");
      if (routeIds.has(id) || routeTags.has(routeTag) || routeKeys.has(key)
        || !quickConfig || !topology || snapshotId(topology.quickConfigId) !== quickConfigId
        || !providerLine || String(providerLine.category) !== String(row.lineCategory)
        || !["DEFAULT", "TELECOM", "UNICOM", "MOBILE", "EDUCATION"].includes(String(row.lineCategory))
        || !["MANAGED_HOST", "LANDING"].includes(sourceType)
        || !["IPV4", "IPV6"].includes(addressFamily)
        || !["DIRECT", "FORWARD"].includes(routeMode)
        || !["PLANNED", "APPLYING", "APPLIED", "RETIRING", "RETIRED", "FAILED"].includes(String(row.state))
        || !Number.isSafeInteger(Number(row.sortOrder)) || Number(row.sortOrder) < 0
        || (routeMode === "FORWARD" && (!hostId || !hostIds.has(hostId)))
        || (sourceType === "MANAGED_HOST" && (!hostId || !hostIds.has(hostId) || routeMode !== "FORWARD" || address !== expectedManagedAddress))
        || (sourceType === "LANDING" && (routeMode !== "DIRECT" || address !== expectedLandingAddress))
        || isIP(address) !== (addressFamily === "IPV4" ? 4 : 6)) throw unavailable();
      snapshotBoundedString(row.providerLineId, 128);
      routeIds.set(id, row); routeTags.add(routeTag); routeKeys.add(key);
    }

    const operationIds = new Map<number, Record<string, any>>();
    const operationTags = new Set<string>();
    const activeOperationByQuickConfig = new Set<number>();
    const terminalOperationStatuses = new Set(["SUCCESS", "FAILED", "PARTIAL_FAILURE", "CANCELLED"]);
    for (const row of snapshot.tables?.xray_quick_config_operations || []) {
      const id = snapshotId(row.id);
      const operationTag = snapshotBoundedString(row.operationTag, 128);
      const quickConfigId = snapshotId(row.quickConfigId);
      const status = String(row.status ?? "");
      const activeSlot = snapshotOptionalId(row.activeSlot);
      if (operationIds.has(id) || operationTags.has(operationTag) || !quickConfigs.has(quickConfigId)
        || !["APPLY", "EDIT", "REMOVE", "RETRY"].includes(String(row.type))
        || !["QUEUED", "RUNNING", "COMPENSATING", "SUCCESS", "FAILED", "PARTIAL_FAILURE", "CANCELLED"].includes(status)
        || !["RECHECKING_DOMAIN", "RESERVING_PORT", "CREATING_RULES", "WAITING_RULES_READY", "APPLYING_DNS", "VERIFYING_DNS", "FINALIZING", "DNS_REMOVING", "DNS_REMOVED", "RULES_REMOVING", "RULES_REMOVED", "PORT_RELEASING", "RESTORING_DNS", "REMOVING_NEW_RULES", "RELEASING_REFERENCES", "COMPLETED"].includes(String(row.phase))
        || (terminalOperationStatuses.has(status) ? activeSlot !== null : activeSlot !== 1)
        || (activeSlot === 1 && activeOperationByQuickConfig.has(quickConfigId))
        || !snapshotUserIds.has(snapshotId(row.createdByUserId))) throw unavailable();
      snapshotPositiveSafeInteger(row.revision);
      snapshotPositiveSafeInteger(row.expectedRevision);
      snapshotPositiveSafeInteger(row.executionFence);
      assertSafeSummaryJson(row.requestSummaryJson, "OPERATION");
      assertSafeDiagnosticText(row.errorCode, 64);
      assertSafeDiagnosticText(row.errorMessage, 512);
      operationIds.set(id, row); operationTags.add(operationTag);
      if (activeSlot === 1) activeOperationByQuickConfig.add(quickConfigId);
    }
    for (const [id, row] of operationIds) {
      const quickConfigId = snapshotId(row.quickConfigId);
      for (const field of ["fromTopologyRevisionId", "toTopologyRevisionId"] as const) {
        const topologyId = snapshotOptionalId(row[field]);
        if (topologyId !== null && snapshotId(topologyIds.get(topologyId)?.quickConfigId) !== quickConfigId) throw unavailable();
      }
      const retryId = snapshotOptionalId(row.retryOfOperationId);
      if (retryId !== null) {
        const retryTarget = operationIds.get(retryId);
        if (row.type !== "RETRY" || !retryTarget || snapshotId(retryTarget.quickConfigId) !== quickConfigId
          || !["FAILED", "PARTIAL_FAILURE"].includes(String(retryTarget.status)) || retryId === id) throw unavailable();
      } else if (row.type === "RETRY") throw unavailable();
    }
    for (const [quickConfigId, row] of quickConfigs) {
      for (const field of ["activeTopologyRevisionId", "desiredTopologyRevisionId"] as const) {
        const topologyId = snapshotOptionalId(row[field]);
        if (topologyId !== null && snapshotId(topologyIds.get(topologyId)?.quickConfigId) !== quickConfigId) throw unavailable();
      }
      const activeTopologyId = snapshotOptionalId(row.activeTopologyRevisionId);
      if (activeTopologyId !== null) {
        const activeTopology = topologyIds.get(activeTopologyId);
        if (activeTopology?.state !== "APPLIED" || snapshotOptionalId(activeTopology.activeSlot) !== 1) throw unavailable();
      }
      const currentOperationId = snapshotOptionalId(row.currentOperationId);
      if (currentOperationId !== null) {
        const operation = operationIds.get(currentOperationId);
        if (!operation || snapshotId(operation.quickConfigId) !== quickConfigId
          || terminalOperationStatuses.has(String(operation.status)) || snapshotOptionalId(operation.activeSlot) !== 1) throw unavailable();
      }
    }
    if ([...topologyIds.values()].some((row) => snapshotOptionalId(row.activeSlot) === 1
      && snapshotOptionalId(quickConfigs.get(snapshotId(row.quickConfigId))?.activeTopologyRevisionId) !== snapshotId(row.id))) {
      throw unavailable();
    }
    if ([...operationIds.values()].some((row) => snapshotOptionalId(row.activeSlot) === 1
      && snapshotOptionalId(quickConfigs.get(snapshotId(row.quickConfigId))?.currentOperationId) !== snapshotId(row.id))) {
      throw unavailable();
    }

    const ruleIds = new Set((snapshot.tables?.forward_rules || []).map((row) => snapshotId(row.id)));
    for (const row of snapshot.tables?.forward_rules || []) {
      const quickConfigId = snapshotOptionalId(row.xrayQuickConfigId);
      if (quickConfigId !== null && !quickConfigs.has(quickConfigId)) throw unavailable();
    }
    const boundForwardRules = new Set<number>();
    const ruleBindingIds = new Set<number>();
    const ruleBindingTags = new Set<string>();
    const topologyRuleKeys = new Set<string>();
    const bindingTopologyByForwardRule = new Map<number, number>();
    for (const row of snapshot.tables?.xray_quick_config_rule_bindings || []) {
      const id = snapshotId(row.id);
      const bindingTag = snapshotBoundedString(row.bindingTag, 128);
      const quickConfigId = snapshotId(row.quickConfigId);
      const topologyRevisionId = snapshotId(row.topologyRevisionId);
      const forwardRuleId = snapshotId(row.forwardRuleId);
      const topology = topologyIds.get(topologyRevisionId);
      const rule = (snapshot.tables?.forward_rules || []).find((candidate) => snapshotId(candidate.id) === forwardRuleId);
      const key = `${topologyRevisionId}:${forwardRuleId}`;
      if (ruleBindingIds.has(id) || ruleBindingTags.has(bindingTag) || topologyRuleKeys.has(key)
        || !topology || snapshotId(topology.quickConfigId) !== quickConfigId || !rule
        || snapshotId(rule.xrayQuickConfigId) !== quickConfigId
        || !["PLANNED", "APPLYING", "READY", "RETIRING", "REMOVED", "FAILED"].includes(String(row.state))) throw unavailable();
      ruleBindingIds.add(id); ruleBindingTags.add(bindingTag); topologyRuleKeys.add(key); boundForwardRules.add(forwardRuleId);
      bindingTopologyByForwardRule.set(forwardRuleId, topologyRevisionId);
    }
    if ((snapshot.tables?.forward_rules || []).some((row) => snapshotOptionalId(row.xrayQuickConfigId) !== null
      && !boundForwardRules.has(snapshotId(row.id)))) throw unavailable();
    for (const route of routeIds.values()) {
      if (route.routeMode !== "FORWARD") continue;
      const topologyRevisionId = snapshotId(route.topologyRevisionId);
      const topology = topologyIds.get(topologyRevisionId);
      const hasMatchingRule = (snapshot.tables?.xray_quick_config_rule_bindings || []).some((binding) => {
        if (snapshotId(binding.topologyRevisionId) !== topologyRevisionId) return false;
        const rule = (snapshot.tables?.forward_rules || [])
          .find((candidate) => snapshotId(candidate.id) === snapshotId(binding.forwardRuleId));
        return rule
          && snapshotId(rule.hostId) === snapshotId(route.hostId)
          && String(rule.forwardType).toLowerCase() === String(topology?.engine).toLowerCase()
          && String(rule.protocol).toLowerCase() === "tcp"
          && Number(rule.sourcePort) === Number(topology?.publicPort)
          && String(rule.targetIp) === String(topology?.targetAddress)
          && Number(rule.targetPort) === Number(topology?.targetPort);
      });
      if (!hasMatchingRule) throw unavailable();
    }

    const dnsRecordIds = new Set<number>();
    const dnsRecordTags = new Set<string>();
    const providerRecordKeys = new Set<string>();
    for (const row of snapshot.tables?.xray_quick_config_dns_records || []) {
      const id = snapshotId(row.id);
      const quickConfigId = snapshotId(row.quickConfigId);
      const quickConfig = quickConfigs.get(quickConfigId);
      const route = routeIds.get(snapshotId(row.routeId));
      const dnsAccountId = snapshotId(row.dnsAccountId);
      const zoneId = snapshotId(row.zoneId);
      const providerRecordId = row.providerRecordId === null || row.providerRecordId === undefined
        ? null : snapshotBoundedString(row.providerRecordId, 128);
      const providerRecordKey = providerRecordId === null ? null : `${dnsAccountId}:${providerRecordId}`;
      const remoteTupleHash = String(row.remoteTupleHash ?? "");
      const recordType = String(row.recordType ?? "") as "A" | "AAAA";
      const value = snapshotBoundedString(row.value, 253);
      const ttl = Number(row.ttl);
      const expectedTupleHash = ["A", "AAAA"].includes(recordType)
        ? computeXrayQuickConfigDnsTupleHash({
          fqdn: String(row.fqdn), recordType, providerLineId: String(row.providerLineId), value, ttl,
        }) : "";
      if (dnsRecordIds.has(id) || dnsRecordTags.has(String(row.recordTag))
        || (providerRecordKey !== null && providerRecordKeys.has(providerRecordKey))
        || !quickConfig || !route || snapshotId(route.quickConfigId) !== quickConfigId
        || dnsAccountId !== snapshotId(quickConfig.dnsAccountId) || zoneId !== snapshotId(quickConfig.zoneId)
        || row.fqdn !== quickConfig.fqdn || row.providerLineId !== route.providerLineId
        || !["A", "AAAA"].includes(recordType)
        || recordType !== (route.addressFamily === "IPV4" ? "A" : "AAAA") || value !== route.address
        || !["DESIRED", "APPLIED", "DELETE_PENDING", "REMOVED", "DRIFTED", "UNKNOWN"].includes(String(row.status))
        || (row.status !== "DESIRED" && providerRecordId === null)
        || !Number.isSafeInteger(ttl) || ttl <= 0 || ttl > 86400
        || !Number.isSafeInteger(Number(row.appliedRevision)) || Number(row.appliedRevision) <= 0
        || remoteTupleHash !== expectedTupleHash) throw unavailable();
      snapshotBoundedString(row.recordTag, 128);
      dnsRecordIds.add(id); dnsRecordTags.add(String(row.recordTag));
      if (providerRecordKey !== null) providerRecordKeys.add(providerRecordKey);
    }

    const backupIds = new Set<number>();
    const backupProviderKeys = new Set<string>();
    const backupOrderKeys = new Set<string>();
    const backupsPerOperation = new Map<number, number>();
    for (const row of snapshot.tables?.xray_quick_config_dns_record_backups || []) {
      const id = snapshotId(row.id);
      const operationId = snapshotId(row.operationId);
      const operation = operationIds.get(operationId);
      const quickConfig = operation ? quickConfigs.get(snapshotId(operation.quickConfigId)) : undefined;
      const dnsAccountId = snapshotId(row.dnsAccountId);
      const zoneId = snapshotId(row.zoneId);
      const zone = dnsZones.get(zoneId);
      const providerRecordId = snapshotBoundedString(row.providerRecordId, 128);
      const snapshotOrder = Number(row.snapshotOrder);
      const recordType = String(row.recordType ?? "") as "A" | "AAAA" | "CNAME";
      const fqdn = snapshotBoundedString(row.fqdn, 253);
      const providerLineId = snapshotBoundedString(row.providerLineId, 128);
      const value = snapshotBoundedString(row.value, 2048);
      const ttl = Number(row.ttl);
      const expectedTupleHash = ["A", "AAAA", "CNAME"].includes(recordType)
        ? computeXrayQuickConfigDnsTupleHash({ fqdn, recordType, providerLineId, value, ttl }) : "";
      const providerKey = `${operationId}:${dnsAccountId}:${providerRecordId}`;
      const orderKey = `${operationId}:${snapshotOrder}`;
      if (backupIds.has(id) || backupProviderKeys.has(providerKey) || backupOrderKeys.has(orderKey) || !operation || !quickConfig
        || !dnsAccounts.has(dnsAccountId) || !zone || snapshotId(zone.accountId) !== dnsAccountId
        || snapshotId(quickConfig.dnsAccountId) !== dnsAccountId || snapshotId(quickConfig.zoneId) !== zoneId
        || !["APPLY", "EDIT"].includes(String(operation.type))
        || fqdn !== String(quickConfig.fqdn)
        || !(dnsLinesByZone.get(zoneId) ?? []).some((line) => String(line.providerLineId) === providerLineId)
        || !["A", "AAAA", "CNAME"].includes(recordType)
        || !["CAPTURED", "RESTORING", "RESTORED", "SKIPPED_DRIFTED", "FAILED"].includes(String(row.state))
        || !Number.isSafeInteger(snapshotOrder) || snapshotOrder < 0 || snapshotOrder >= 64
        || !Number.isSafeInteger(ttl) || ttl <= 0 || ttl > 86400
        || String(row.remoteTupleHash ?? "") !== expectedTupleHash) throw unavailable();
      const count = (backupsPerOperation.get(operationId) ?? 0) + 1;
      if (count > 64) throw unavailable();
      backupsPerOperation.set(operationId, count); backupIds.add(id); backupProviderKeys.add(providerKey); backupOrderKeys.add(orderKey);
    }

    const operationStepIds = new Set<number>();
    const operationStepKeys = new Set<string>();
    const idempotencyKeys = new Set<string>();
    for (const row of snapshot.tables?.xray_quick_config_operation_steps || []) {
      const id = snapshotId(row.id);
      const operationId = snapshotId(row.operationId);
      const operation = operationIds.get(operationId);
      const stepKey = snapshotBoundedString(row.stepKey, 128);
      const idempotencyKey = snapshotBoundedString(row.idempotencyKey, 128);
      const operationStepKey = `${operationId}:${stepKey}`;
      const subjectType = String(row.subjectType ?? "");
      if (operationStepIds.has(id) || operationStepKeys.has(operationStepKey) || idempotencyKeys.has(idempotencyKey)
        || !operation
        || !["DOMAIN_RECHECK", "PORT_RESERVE", "RULE_CREATE", "RULE_VERIFY", "DNS_CREATE", "DNS_REPLACE", "DNS_DELETE", "DNS_VERIFY", "DNS_RESTORE", "RULE_DELETE", "RULE_VERIFY_REMOVED", "REFERENCE_RELEASE"].includes(String(row.kind))
        || !["DOMAIN", "PORT", "RULE", "DNS_RECORD", "ALLOCATION", "TOPOLOGY"].includes(subjectType)
        || !["PENDING", "RUNNING", "SUCCESS", "FAILED", "SKIPPED", "COMPENSATED"].includes(String(row.status))
        || !Number.isSafeInteger(Number(row.attemptCount)) || Number(row.attemptCount) < 0) throw unavailable();
      if (row.subjectId !== null && row.subjectId !== undefined) {
        const subjectId = snapshotBoundedString(row.subjectId, 128);
        const quickConfigId = snapshotId(operation.quickConfigId);
        if (subjectType === "DOMAIN") {
          if (subjectId !== String(quickConfigs.get(quickConfigId)?.fqdn ?? "")) throw unavailable();
        } else if (subjectType === "PORT") {
          const port = Number(subjectId);
          if (!/^[1-9]\d*$/.test(subjectId) || !Number.isSafeInteger(port) || port > 65535) throw unavailable();
        } else {
          if (!/^[1-9]\d*$/.test(subjectId)) throw unavailable();
          const resourceId = snapshotId(subjectId);
          if (subjectType === "RULE") {
            const rule = (snapshot.tables?.forward_rules || []).find((candidate) => snapshotId(candidate.id) === resourceId);
            if (!rule || snapshotOptionalId(rule.xrayQuickConfigId) !== quickConfigId) throw unavailable();
          } else if (subjectType === "DNS_RECORD") {
            const record = (snapshot.tables?.xray_quick_config_dns_records || []).find((candidate) => snapshotId(candidate.id) === resourceId);
            if (!record || snapshotId(record.quickConfigId) !== quickConfigId) throw unavailable();
          } else if (subjectType === "TOPOLOGY") {
            if (snapshotId(topologyIds.get(resourceId)?.quickConfigId) !== quickConfigId) throw unavailable();
          } else if (![...topologyIds.values()].some((topology) => (
            snapshotId(topology.quickConfigId) === quickConfigId && snapshotId(topology.portAllocationId) === resourceId
          ))) throw unavailable();
        }
      }
      assertSafeSummaryJson(row.requestSummaryJson, "STEP");
      if (row.resultSummaryJson !== null && row.resultSummaryJson !== undefined) assertSafeSummaryJson(row.resultSummaryJson, "STEP");
      assertSafeDiagnosticText(row.errorCode, 64);
      operationStepIds.add(id); operationStepKeys.add(operationStepKey); idempotencyKeys.add(idempotencyKey);
    }

    const rowsById = (rows: Record<string, any>[]) => new Map(rows.map((row) => [snapshotId(row.id), row]));
    const forwardRulesById = rowsById(snapshot.tables?.forward_rules || []);
    const managedServicesById = rowsById(snapshot.tables?.xray_managed_services || []);
    const tunnelsById = rowsById(snapshot.tables?.tunnels || []);
    const tunnelExitNodesById = rowsById(snapshot.tables?.tunnel_exit_nodes || []);
    const tunnelHopsById = rowsById(snapshot.tables?.tunnel_hops || []);
    const mappedTunnelExitsById = rowsById(snapshot.tables?.forward_rule_tunnel_exits || []);
    const resourceRows = new Map<string, Map<number, Record<string, any>>>([
      ["XRAY_INBOUND", inboundById],
      ["FORWARD_RULE", forwardRulesById],
      ["MANAGED_SERVICE", managedServicesById],
      ["TUNNEL", tunnelsById],
      ["TUNNEL_EXIT_NODE", tunnelExitNodesById],
      ["TUNNEL_HOP", tunnelHopsById],
      ["FORWARD_RULE_TUNNEL_EXIT", mappedTunnelExitsById],
      ["QUICK_CONFIG", quickConfigs],
    ]);
    type ListenerDescriptor = {
      port: number;
      hostId: number;
      network: "TCP" | "UDP" | "BOTH";
      role: "PUBLIC_LISTENER" | "MIMIC";
      slot?: "PRIMARY" | "MAPPED";
    };
    const storedPort = (value: unknown) => {
      const port = Number(value);
      if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw unavailable();
      return port;
    };
    const optionalStoredPort = (value: unknown) => (
      value === null || value === undefined || value === "" || Number(value) === 0 ? null : storedPort(value)
    );
    const storedBoolean = (value: unknown) => value === true || value === 1 || value === "1" || value === "true";
    const forwardNetwork = (value: unknown): "TCP" | "UDP" | "BOTH" => {
      const protocol = String(value ?? "").trim().toLowerCase();
      if (protocol === "tcp") return "TCP";
      if (protocol === "udp") return "UDP";
      if (protocol === "both") return "BOTH";
      throw unavailable();
    };
    const tunnelNetwork = (row: Record<string, any>): "TCP" | "UDP" => (
      String(row.mode ?? "").trim().toLowerCase() === "forwardx"
        && String(row.forwardxVersion ?? "").trim().toLowerCase() === "v2" ? "UDP" : "TCP"
    );
    const listenerDescriptors = (resourceType: string, resourceId: number): ListenerDescriptor[] => {
      if (resourceType === "XRAY_INBOUND") {
        const inbound = inboundById.get(resourceId);
        if (!inbound) throw unavailable();
        const definition = resolveStoredXrayInboundDefinition({
          protocol: inbound.protocol,
          transport: inbound.transport,
          security: inbound.security,
          profileId: inbound.profileId,
          specVersion: inbound.specVersion,
          specJson: inbound.specJson,
        });
        if (!definition) throw unavailable();
        return definition.profile.listenerNetworks.map((network) => ({
          port: storedPort(inbound.listenPort),
          hostId: snapshotId(inbound.hostId),
          network: network.toUpperCase() as "TCP" | "UDP",
          role: "PUBLIC_LISTENER",
        }));
      }
      if (resourceType === "MANAGED_SERVICE") {
        const service = managedServicesById.get(resourceId);
        if (!service) throw unavailable();
        const network = service.kind === "MTPROTO_FAKE_TLS" ? "TCP" : service.kind === "AMNEZIAWG" ? "UDP" : null;
        if (!network) throw unavailable();
        return [{
          port: storedPort(service.listenPort), hostId: snapshotId(service.hostId), network, role: "PUBLIC_LISTENER",
        }];
      }
      if (resourceType === "FORWARD_RULE") {
        const rule = forwardRulesById.get(resourceId);
        if (!rule || storedBoolean(rule.isForwardGroupTemplate)) throw unavailable();
        const descriptors: ListenerDescriptor[] = [{
          port: storedPort(rule.sourcePort), hostId: snapshotId(rule.hostId),
          network: forwardNetwork(rule.protocol), role: "PUBLIC_LISTENER",
        }];
        const tunnelId = snapshotOptionalId(rule.tunnelId);
        const exitPort = optionalStoredPort(rule.tunnelExitPort);
        const tunnel = tunnelId === null ? undefined : tunnelsById.get(tunnelId);
        if (exitPort !== null && tunnel) descriptors.push({
          port: exitPort, hostId: snapshotId(tunnel.exitHostId),
          network: forwardNetwork(rule.protocol), role: "PUBLIC_LISTENER", slot: "PRIMARY",
        });
        return descriptors;
      }
      if (resourceType === "TUNNEL") {
        const tunnel = tunnelsById.get(resourceId);
        if (!tunnel) throw unavailable();
        const descriptors: ListenerDescriptor[] = [{
          port: storedPort(tunnel.listenPort), hostId: snapshotId(tunnel.exitHostId),
          network: tunnelNetwork(tunnel), role: "PUBLIC_LISTENER",
        }];
        const mimicPort = optionalStoredPort(tunnel.mimicPort);
        if (mimicPort !== null) descriptors.push({
          port: mimicPort, hostId: snapshotId(tunnel.exitHostId), network: "UDP", role: "MIMIC",
        });
        return descriptors;
      }
      if (resourceType === "TUNNEL_EXIT_NODE" || resourceType === "TUNNEL_HOP") {
        const resource = resourceType === "TUNNEL_EXIT_NODE"
          ? tunnelExitNodesById.get(resourceId) : tunnelHopsById.get(resourceId);
        if (!resource) throw unavailable();
        const tunnel = tunnelsById.get(snapshotId(resource.tunnelId));
        if (!tunnel) throw unavailable();
        const descriptors: ListenerDescriptor[] = [];
        const listenPort = resourceType === "TUNNEL_HOP"
          ? optionalStoredPort(resource.listenPort) : storedPort(resource.listenPort);
        if (listenPort !== null) descriptors.push({
          port: listenPort, hostId: snapshotId(resource.hostId),
          network: tunnelNetwork(tunnel), role: "PUBLIC_LISTENER",
        });
        const mimicPort = optionalStoredPort(resource.mimicPort);
        if (mimicPort !== null) descriptors.push({
          port: mimicPort, hostId: snapshotId(resource.hostId), network: "UDP", role: "MIMIC",
        });
        return descriptors;
      }
      if (resourceType === "FORWARD_RULE_TUNNEL_EXIT") {
        const mappedExit = mappedTunnelExitsById.get(resourceId);
        const rule = mappedExit ? forwardRulesById.get(snapshotId(mappedExit.ruleId)) : undefined;
        if (!mappedExit || !rule) throw unavailable();
        return [{
          port: storedPort(mappedExit.tunnelExitPort), hostId: snapshotId(mappedExit.exitHostId),
          network: forwardNetwork(rule.protocol), role: "PUBLIC_LISTENER", slot: "MAPPED",
        }];
      }
      return [];
    };
    const expectedOwner = (resourceType: string, resourceId: number): {
      ownerGroupTag: string;
      primaryOwnerType: "XRAY_INBOUND" | "FORWARD_RULE" | "MANAGED_SERVICE" | "TUNNEL" | "QUICK_CONFIG";
    } => {
      if (resourceType === "XRAY_INBOUND") {
        return {
          ownerGroupTag: buildGlobalPortOwnerGroupTag("XRAY_INBOUND", String(inboundById.get(resourceId)?.runtimeTag ?? "")),
          primaryOwnerType: "XRAY_INBOUND",
        };
      }
      if (resourceType === "MANAGED_SERVICE") {
        return {
          ownerGroupTag: buildGlobalPortOwnerGroupTag("MANAGED_SERVICE", String(managedServicesById.get(resourceId)?.serviceTag ?? "")),
          primaryOwnerType: "MANAGED_SERVICE",
        };
      }
      if (resourceType === "QUICK_CONFIG") {
        return {
          ownerGroupTag: buildGlobalPortOwnerGroupTag("QUICK_CONFIG", String(quickConfigs.get(resourceId)?.configTag ?? "")),
          primaryOwnerType: "QUICK_CONFIG",
        };
      }
      if (resourceType === "TUNNEL") return {
        ownerGroupTag: buildGlobalPortOwnerGroupTag("TUNNEL", resourceId),
        primaryOwnerType: "TUNNEL",
      };
      if (resourceType === "TUNNEL_EXIT_NODE") {
        return {
          ownerGroupTag: buildGlobalPortOwnerGroupTag("TUNNEL", snapshotId(tunnelExitNodesById.get(resourceId)?.tunnelId)),
          primaryOwnerType: "TUNNEL",
        };
      }
      if (resourceType === "TUNNEL_HOP") {
        return {
          ownerGroupTag: buildGlobalPortOwnerGroupTag("TUNNEL", snapshotId(tunnelHopsById.get(resourceId)?.tunnelId)),
          primaryOwnerType: "TUNNEL",
        };
      }
      const resolveForwardOwner = (forwardRuleId: number) => {
        const forwardRule = forwardRulesById.get(forwardRuleId);
        if (!forwardRule) throw unavailable();
        const quickConfigId = snapshotOptionalId(forwardRule.xrayQuickConfigId);
        if (quickConfigId !== null) {
          const quickConfig = quickConfigs.get(quickConfigId);
          if (!quickConfig) throw unavailable();
          return {
            ownerGroupTag: buildGlobalPortOwnerGroupTag("QUICK_CONFIG", String(quickConfig.configTag ?? "")),
            primaryOwnerType: "QUICK_CONFIG" as const,
          };
        }
        const parentId = snapshotOptionalId(forwardRule?.forwardGroupRuleId) ?? forwardRuleId;
        if (!forwardRulesById.has(parentId)) throw unavailable();
        return {
          ownerGroupTag: buildGlobalPortOwnerGroupTag("FORWARD_RULE", parentId),
          primaryOwnerType: "FORWARD_RULE" as const,
        };
      };
      if (resourceType === "FORWARD_RULE") return resolveForwardOwner(resourceId);
      if (resourceType === "FORWARD_RULE_TUNNEL_EXIT") {
        return resolveForwardOwner(snapshotId(mappedTunnelExitsById.get(resourceId)?.ruleId));
      }
      throw unavailable();
    };
    const allocationReferenceIds = new Set<number>();
    const referenceKeys = new Set<string>();
    const owningGroupsByAllocation = new Map<number, Set<string>>();
    const referenceCountByAllocation = new Map<number, number>();
    const sourceReferences = snapshot.tables?.global_port_allocation_references || [];
    for (const row of sourceReferences) {
      const id = snapshotId(row.id);
      const referenceKey = snapshotBoundedString(row.referenceKey, 255);
      const allocationId = snapshotId(row.allocationId);
      const resourceType = String(row.resourceType ?? "");
      const resourceId = snapshotId(row.resourceId);
      const allocation = allocationIds.get(allocationId);
      const ownerGroupTag = snapshotBoundedString(row.ownerGroupTag, 128);
      const hostId = snapshotOptionalId(row.hostId);
      const referenceInput = {
        resourceType: resourceType as GlobalPortResourceType,
        resourceId,
        hostId,
        network: String(row.network) as GlobalPortReferenceNetwork,
        role: String(row.role) as GlobalPortReferenceRole,
      };
      const allowedReferenceKeys = new Set([
        buildGlobalPortReferenceKey(referenceInput),
        buildGlobalPortReferenceKey({ ...referenceInput, slot: "PRIMARY" }),
        buildGlobalPortReferenceKey({ ...referenceInput, slot: "MAPPED" }),
      ]);
      const canonicalOwner = expectedOwner(resourceType, resourceId);
      if (allocationReferenceIds.has(id) || referenceKeys.has(referenceKey) || !allocation
        || !resourceRows.get(resourceType)?.has(resourceId)
        || !["TCP", "UDP", "BOTH", "NONE"].includes(String(row.network))
        || !["TARGET", "PUBLIC_LISTENER", "OWNERSHIP", "MIMIC"].includes(String(row.role))
        || (hostId !== null && !hostIds.has(hostId))
        || !allowedReferenceKeys.has(referenceKey)
        || ownerGroupTag !== canonicalOwner.ownerGroupTag) throw unavailable();
      const slot = referenceKey.endsWith(":PRIMARY") ? "PRIMARY"
        : referenceKey.endsWith(":MAPPED") ? "MAPPED" : undefined;
      const isOwning = storedBoolean(row.isOwning);
      if (resourceType !== "QUICK_CONFIG") {
        const descriptorMatches = listenerDescriptors(resourceType, resourceId).some((descriptor) => (
          descriptor.port === Number(allocation.port) && descriptor.hostId === hostId
          && descriptor.network === String(row.network) && descriptor.role === String(row.role)
          && descriptor.slot === slot
        ));
        if (!isOwning || !descriptorMatches) throw unavailable();
      } else {
        const quickConfig = quickConfigs.get(resourceId);
        const targetInbound = quickConfig?.targetType === "XRAY_INBOUND"
          ? inboundById.get(snapshotId(quickConfig.xrayInboundId)) : undefined;
        const targetSourceExists = !!targetInbound && sourceReferences.some((sourceReference) => (
          snapshotId(sourceReference.allocationId) === allocationId
          && sourceReference.resourceType === "XRAY_INBOUND"
          && snapshotId(sourceReference.resourceId) === snapshotId(targetInbound.id)
          && storedBoolean(sourceReference.isOwning)
        ));
        const topologyUsesAllocation = [...topologyIds.values()].some((topology) => (
          snapshotId(topology.quickConfigId) === resourceId
          && snapshotId(topology.portAllocationId) === allocationId
          && Number(topology.publicPort) === Number(allocation.port)
        ));
        if (isOwning) {
          if (!topologyUsesAllocation) throw unavailable();
        } else if (!targetInbound || !targetSourceExists
          || storedPort(targetInbound.listenPort) !== Number(allocation.port)
          || !["TARGET", "PUBLIC_LISTENER"].includes(String(row.role))
          || (String(row.role) === "PUBLIC_LISTENER" && !topologyUsesAllocation)) {
          throw unavailable();
        }
      }
      if (resourceType === "FORWARD_RULE") {
        const rule = forwardRulesById.get(resourceId);
        const quickConfigId = snapshotOptionalId(rule?.xrayQuickConfigId);
        if (quickConfigId !== null) {
          const topologyId = bindingTopologyByForwardRule.get(resourceId);
          const topology = topologyId ? topologyIds.get(topologyId) : undefined;
          const protocol = String(rule?.protocol ?? "").trim().toLowerCase();
          const ruleNetwork = protocol === "tcp" ? "TCP" : protocol === "udp" ? "UDP" : protocol === "both" ? "BOTH" : null;
          if (!topology || snapshotId(topology.quickConfigId) !== quickConfigId
            || snapshotId(topology.portAllocationId) !== allocationId
            || Number(rule?.sourcePort) !== Number(allocation.port)
            || snapshotId(rule?.hostId) !== hostId
            || rule?.forwardType !== topology.engine || ruleNetwork !== String(row.network)
            || String(row.role) !== "PUBLIC_LISTENER"
            || Number(rule?.targetPort) !== Number(topology.targetPort)
            || String(rule?.targetIp) !== String(topology.targetAddress)) throw unavailable();
        }
      }
      if (isOwning) {
        const groups = owningGroupsByAllocation.get(allocationId) ?? new Set<string>();
        groups.add(`${canonicalOwner.primaryOwnerType}:${ownerGroupTag}`);
        owningGroupsByAllocation.set(allocationId, groups);
        if (allocation.status !== "LEGACY_CONFLICT"
          && (ownerGroupTag !== allocation.primaryOwnerTag
            || canonicalOwner.primaryOwnerType !== allocation.primaryOwnerType)) throw unavailable();
      }
      referenceCountByAllocation.set(allocationId, (referenceCountByAllocation.get(allocationId) ?? 0) + 1);
      allocationReferenceIds.add(id); referenceKeys.add(referenceKey);
    }
    for (const [id, row] of allocationIds) {
      const groups = owningGroupsByAllocation.get(id) ?? new Set<string>();
      if (row.status === "LEGACY_CONFLICT") {
        if (groups.size < 2) throw unavailable();
      } else if (inactiveAllocationStates.has(String(row.status))) {
        if (groups.size !== 0 || (referenceCountByAllocation.get(id) ?? 0) !== 0) throw unavailable();
      } else if (groups.size !== 1) {
        throw unavailable();
      }
    }

    const probeRuns = new Map<number, Record<string, any>>();
    const probeTags = new Set<string>();
    for (const row of snapshot.tables?.global_port_probe_runs || []) {
      const id = snapshotId(row.id);
      const probeTag = snapshotBoundedString(row.probeTag, 128);
      const allocationId = snapshotOptionalId(row.allocationId);
      const candidatePort = Number(row.candidatePort);
      const allocation = allocationId === null ? null : allocationIds.get(allocationId);
      if (probeRuns.has(id) || probeTags.has(probeTag)
        || (allocationId !== null && !allocation)
        || !Number.isSafeInteger(candidatePort) || candidatePort < 1 || candidatePort > 65535
        || (allocation && candidatePort !== Number(allocation.port))
        || !["CANDIDATE", "RECLAIM"].includes(String(row.purpose))
        || !["QUEUED", "RUNNING", "SUCCESS", "FAILED", "EXPIRED"].includes(String(row.status))
        || !/^[0-9a-f]{64}$/.test(String(row.hostSetHash ?? ""))
        || !Number.isSafeInteger(Number(row.expectedHostCount)) || Number(row.expectedHostCount) < 0) throw unavailable();
      const createdByUserId = snapshotOptionalId(row.createdByUserId);
      if (createdByUserId !== null && !snapshotUserIds.has(createdByUserId)) throw unavailable();
      assertSafeDiagnosticText(row.errorCode, 64);
      if (allocationId !== null && snapshotPositiveSafeInteger(row.allocationVersion) !== Number(allocation?.version)) throw unavailable();
      probeRuns.set(id, row); probeTags.add(probeTag);
    }
    const probeResultIds = new Set<number>();
    const probeResultKeys = new Set<string>();
    const xrayOperationsByStableId = new Map<string, Record<string, any>>();
    for (const operation of snapshot.tables?.xray_operations || []) {
      snapshotId(operation.id);
      const operationId = snapshotBoundedString(operation.operationId, 64);
      if (xrayOperationsByStableId.has(operationId)) throw unavailable();
      xrayOperationsByStableId.set(operationId, operation);
    }
    for (const row of snapshot.tables?.global_port_probe_results || []) {
      const id = snapshotId(row.id);
      const probeRunId = snapshotId(row.probeRunId);
      const probeRun = probeRuns.get(probeRunId);
      const hostId = snapshotId(row.hostId);
      const network = String(row.network ?? "");
      const xrayOperationId = snapshotBoundedString(row.xrayOperationId, 64);
      const operation = xrayOperationsByStableId.get(xrayOperationId);
      let requestMeta: Record<string, unknown> | null = null;
      try {
        const parsed = JSON.parse(String(operation?.requestMetaJson ?? ""));
        requestMeta = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
      } catch { requestMeta = null; }
      const key = `${probeRunId}:${hostId}:${network}`;
      if (probeResultIds.has(id) || probeResultKeys.has(key) || !probeRun || !hostIds.has(hostId)
        || !["tcp", "udp"].includes(network)
        || !["FREE", "OCCUPIED", "OFFLINE", "UNSUPPORTED", "ERROR", "EXPIRED"].includes(String(row.status))
        || !operation || operation.type !== "PORT_PROBE" || snapshotId(operation.hostId) !== hostId
        || !requestMeta || requestMeta.schemaVersion !== 1 || requestMeta.network !== network
        || !Array.isArray(requestMeta.candidates)
        || !requestMeta.candidates.some((candidate) => Number(candidate) === Number(probeRun.candidatePort))) throw unavailable();
      probeResultIds.add(id); probeResultKeys.add(key);
    }

    const scanLeases = snapshot.tables?.global_port_scan_leases || [];
    const hasQuickConfigPersistence = quickConfigs.size > 0 || allocationIds.size > 0
      || (snapshot.tables?.xray_quick_config_domain_claims?.length ?? 0) > 0
      || (snapshot.tables?.xray_quick_config_topology_revisions?.length ?? 0) > 0
      || (snapshot.tables?.xray_quick_config_routes?.length ?? 0) > 0
      || (snapshot.tables?.xray_quick_config_rule_bindings?.length ?? 0) > 0
      || (snapshot.tables?.xray_quick_config_dns_records?.length ?? 0) > 0
      || (snapshot.tables?.xray_quick_config_dns_record_backups?.length ?? 0) > 0
      || operationIds.size > 0 || operationStepIds.size > 0
      || allocationReferenceIds.size > 0 || probeRuns.size > 0 || probeResultIds.size > 0;
    if (scanLeases.length > 1 || (hasQuickConfigPersistence && scanLeases.length !== 1)) throw unavailable();
    if (scanLeases.length === 1) {
      const lease = scanLeases[0];
      snapshotId(lease.id);
      if (lease.scopeKey !== "GLOBAL_PORT_RECLAIM") throw unavailable();
      if (lease.leaseOwnerHash !== null && lease.leaseOwnerHash !== undefined
        && !/^[0-9a-f]{64}$/.test(String(lease.leaseOwnerHash))) throw unavailable();
    }

    const managedServices = new Map<number, { kind: "MTPROTO_FAKE_TLS" | "AMNEZIAWG"; serviceTag: string; fakeTlsDomain?: string }>();
    for (const row of snapshot.tables?.xray_managed_services || []) {
      const id = snapshotId(row.id);
      const serviceTag = String(row.serviceTag ?? "");
      const kind = String(row.kind ?? "");
      let spec: unknown;
      try { spec = JSON.parse(String(row.specJson ?? "")); } catch { throw unavailable(); }
      if (managedServices.has(id)) throw unavailable();
      if (kind === "MTPROTO_FAKE_TLS") {
        if (!/^forwardx-mtproto-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(serviceTag)
          || !spec || typeof spec !== "object" || Array.isArray(spec) || Object.keys(spec).length !== 1
          || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(String((spec as { fakeTlsDomain?: unknown }).fakeTlsDomain ?? ""))) throw unavailable();
        managedServices.set(id, { kind, serviceTag, fakeTlsDomain: String((spec as { fakeTlsDomain: string }).fakeTlsDomain) });
      } else if (kind === "AMNEZIAWG") {
        if (!/^forwardx-amneziawg-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(serviceTag)) throw unavailable();
        parseAmneziaWgStoredSpec(spec);
        managedServices.set(id, { kind, serviceTag });
      } else {
        throw unavailable();
      }
    }
    const managedAccounts = new Map<number, Record<string, any>>();
    const managedAccountTags = new Set<string>();
    for (const row of snapshot.tables?.xray_managed_service_accounts || []) {
      const id = snapshotId(row.id);
      const accountTag = String(row.accountTag ?? "");
      const service = managedServices.get(snapshotId(row.serviceId));
      if (managedAccounts.has(id) || managedAccountTags.has(accountTag) || !service) throw unavailable();
      if (service.kind === "MTPROTO_FAKE_TLS") {
        if (!/^forwardx-mtproto-account-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(accountTag)
          || (row.settingsVersion !== undefined && Number(row.settingsVersion) !== 1)
          || (row.settingsJson !== undefined && String(row.settingsJson) !== "{}")) throw unavailable();
      } else if (!/^forwardx-amneziawg-peer-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(accountTag)) {
        throw unavailable();
      } else {
        parseAmneziaWgPeerSettings(row.settingsVersion, row.settingsJson);
      }
      managedAccounts.set(id, row);
      managedAccountTags.add(accountTag);
    }
    for (const [serviceId, service] of managedServices) {
      if (service.kind !== "AMNEZIAWG") continue;
      const peers = [...managedAccounts.values()].filter((account) => snapshotId(account.serviceId) === serviceId);
      const settings = peers.map((peer) => parseAmneziaWgPeerSettings(peer.settingsVersion, peer.settingsJson));
      if (peers.length < 1 || peers.length > 32 || new Set(settings.map((item) => item.address)).size !== settings.length
        || new Set(settings.map((item) => item.publicKey)).size !== settings.length) throw unavailable();
    }
    const managedSecretKinds = new Map<number, Set<string>>();
    const awgPeerPrivateKeys = new Map<number, string>();
    for (const row of snapshot.tables?.xray_managed_service_secrets || []) {
      const accountId = snapshotId(row.accountId);
      const secretKind = String(row.kind);
      const account = managedAccounts.get(accountId);
      const service = account && managedServices.get(snapshotId(account.serviceId));
      if (!account || !service) throw unavailable();
      const kinds = managedSecretKinds.get(accountId) ?? new Set<string>();
      if (kinds.has(secretKind)) throw unavailable();
      kinds.add(secretKind); managedSecretKinds.set(accountId, kinds);
      const expectedKinds = service.kind === "MTPROTO_FAKE_TLS"
        ? ["MTPROTO_SECRET"] : [AMNEZIAWG_PEER_PRIVATE_KEY, AMNEZIAWG_PEER_PRE_SHARED_KEY];
      if (!expectedKinds.includes(secretKind)) throw unavailable();
      const verified = verifiedSnapshotSecret({
        row,
        context: xrayManagedServiceAccountSecretContext(String(account.accountTag), secretKind as "MTPROTO_SECRET" | "AMNEZIAWG_PRIVATE_KEY" | "AMNEZIAWG_PRE_SHARED_KEY"),
        keyring: requireKeyring(),
      });
      if (service.kind === "MTPROTO_FAKE_TLS") {
        const domainHex = Buffer.from(service.fakeTlsDomain ?? "", "utf8").toString("hex");
        if (!/^ee[0-9a-f]+$/.test(verified.plaintext) || verified.plaintext.length !== 2 + 32 + domainHex.length
          || !verified.plaintext.endsWith(domainHex)) throw unavailable();
      } else if (secretKind === AMNEZIAWG_PEER_PRIVATE_KEY) {
        const settings = parseAmneziaWgPeerSettings(account.settingsVersion, account.settingsJson);
        const privateKey = canonicalXrayWireGuardPrivateKey(verified.plaintext);
        if (deriveXrayWireGuardPublicKey(privateKey) !== settings.publicKey) throw unavailable();
        awgPeerPrivateKeys.set(accountId, privateKey);
      } else {
        const preSharedKey = canonicalXrayWireGuardKey(verified.plaintext);
        if (Buffer.from(preSharedKey, "base64").every((byte) => byte === 0)) throw unavailable();
      }
    }
    if ([...managedAccounts].some(([accountId, account]) => {
      const kind = managedServices.get(snapshotId(account.serviceId))?.kind;
      const expected = kind === "AMNEZIAWG" ? [AMNEZIAWG_PEER_PRIVATE_KEY, AMNEZIAWG_PEER_PRE_SHARED_KEY] : ["MTPROTO_SECRET"];
      const actual = managedSecretKinds.get(accountId);
      return !actual || expected.some((secretKind) => !actual.has(secretKind)) || actual.size !== expected.length;
    })) throw unavailable();
    const instanceKinds = new Map<number, Set<string>>();
    const awgServerPrivateKeys = new Map<number, string>();
    for (const row of snapshot.tables?.xray_managed_service_instance_secrets || []) {
      const serviceId = snapshotId(row.serviceId); const service = managedServices.get(serviceId);
      const secretKind = String(row.kind);
      const kinds = instanceKinds.get(serviceId) ?? new Set<string>();
      if (!service || service.kind !== "AMNEZIAWG" || kinds.has(secretKind)
        || ![AMNEZIAWG_SERVER_PRIVATE_KEY, AMNEZIAWG_HEADER_PROTECTION_KEY].includes(secretKind as typeof AMNEZIAWG_SERVER_PRIVATE_KEY)) throw unavailable();
      kinds.add(secretKind); instanceKinds.set(serviceId, kinds);
      const verified = verifiedSnapshotSecret({ row,
        context: xrayManagedServiceInstanceSecretContext(service.serviceTag,
          secretKind as typeof AMNEZIAWG_SERVER_PRIVATE_KEY | typeof AMNEZIAWG_HEADER_PROTECTION_KEY),
        keyring: requireKeyring(),
      });
      if (secretKind === AMNEZIAWG_SERVER_PRIVATE_KEY) {
        awgServerPrivateKeys.set(serviceId, canonicalXrayWireGuardPrivateKey(verified.plaintext));
      } else {
        const headerProtectionKey = canonicalXrayWireGuardKey(verified.plaintext);
        if (Buffer.from(headerProtectionKey, "base64").every((byte) => byte === 0)) throw unavailable();
      }
    }
    if ([...managedServices].some(([serviceId, service]) => service.kind === "AMNEZIAWG"
      && (instanceKinds.get(serviceId)?.size !== 2))) throw unavailable();
    if ([...managedAccounts].some(([accountId, account]) => {
      const serviceId = snapshotId(account.serviceId);
      return managedServices.get(serviceId)?.kind === "AMNEZIAWG"
        && awgPeerPrivateKeys.get(accountId) === awgServerPrivateKeys.get(serviceId);
    })) throw unavailable();
  } catch (error) {
    throw unavailable();
  }
}

export function createXrayMasterKeyBackupBundleForSnapshot(
  snapshot: MigrationSnapshot,
  options: { path?: string } = {},
): XrayMasterKeyBackupBundle | undefined {
  try {
    return createXrayMasterKeyBackupBundle(options);
  } catch (error) {
    if (migrationSnapshotHasXraySecrets(snapshot)) throw error;
    return undefined;
  }
}

async function targetHasXraySecrets() {
  const q = quoteIdentifier;
  const rows = await queryRaw<{ count: unknown }>(
    `SELECT (
       (SELECT COUNT(*) FROM ${q("xray_inbounds")} WHERE ${q("realityPrivateKeyEncrypted")} IS NOT NULL AND ${q("realityPrivateKeyEncrypted")} <> '')
       + (SELECT COUNT(*) FROM ${q("xray_clients")} WHERE (${q("uuidEncrypted")} IS NOT NULL AND ${q("uuidEncrypted")} <> '')
          OR (${q("shortIdEncrypted")} IS NOT NULL AND ${q("shortIdEncrypted")} <> ''))
       + (SELECT COUNT(*) FROM ${q("xray_access_secrets")} WHERE ${q("encryptedValue")} IS NOT NULL AND ${q("encryptedValue")} <> '')
       + (SELECT COUNT(*) FROM ${q("xray_inbound_secrets")} WHERE ${q("encryptedValue")} IS NOT NULL AND ${q("encryptedValue")} <> '')
       + (SELECT COUNT(*) FROM ${q("xray_external_proxy_secrets")} WHERE ${q("encryptedValue")} IS NOT NULL AND ${q("encryptedValue")} <> '')
       + (SELECT COUNT(*) FROM ${q("xray_managed_service_secrets")} WHERE ${q("encryptedValue")} IS NOT NULL AND ${q("encryptedValue")} <> '')
       + (SELECT COUNT(*) FROM ${q("xray_managed_service_instance_secrets")} WHERE ${q("encryptedValue")} IS NOT NULL AND ${q("encryptedValue")} <> '')
       + (SELECT COUNT(*) FROM ${q("xray_tls_certificates")} WHERE ${q("privateKeyEncrypted")} IS NOT NULL AND ${q("privateKeyEncrypted")} <> '')
     ) AS ${q("count")}`,
  );
  if (Number(rows[0]?.count ?? 0) > 0) return true;
  const providerRows = await queryRaw<{ count: unknown }>(
    `SELECT COUNT(*) AS ${q("count")} FROM ${q("dns_provider_account_secrets")} WHERE ${q("encryptedValue")} IS NOT NULL AND ${q("encryptedValue")} <> ''`,
  ).catch(() => []);
  return Number(providerRows[0]?.count ?? 0) > 0;
}

export async function prepareXrayMasterKeyBackupRestore(
  snapshot: MigrationSnapshot,
  value: unknown,
  options: { path?: string } = {},
): Promise<{
  restored: boolean;
  reason: "installed" | "matched" | "not-required";
  commit: () => { restored: boolean; reason: "installed" | "matched" | "not-required" };
  rollback: () => void;
}> {
  const noChange = (reason: "matched" | "not-required") => ({
    restored: false as const,
    reason,
    commit: () => ({ restored: false as const, reason }),
    rollback: () => undefined,
  });
  const sourceHasSecrets = migrationSnapshotHasXraySecrets(snapshot);
  if (sourceHasSecrets && value === undefined) throw unavailable();
  if (value === undefined) return noChange("not-required");
  const parsed = parseXrayMasterKeyBackupBundle(value);
  const sourceKeyring = createXraySecretKeyring({
    currentKeyId: parsed.bundle.currentKeyId,
    keys: { [parsed.bundle.currentKeyId]: parsed.currentKey },
  });
  if (sourceHasSecrets) assertMigrationSnapshotXraySecretsAvailable(snapshot, { keyring: sourceKeyring });
  const targetHasSecrets = await targetHasXraySecrets();
  if (targetHasSecrets) {
    if (!sourceHasSecrets) return noChange("not-required");
    const existing = loadXrayMasterKeyFile({ path: options.path, keyId: parsed.bundle.currentKeyId });
    if (!existing.keys.get(parsed.bundle.currentKeyId)?.equals(parsed.currentKey)) throw unavailable();
    return noChange("matched");
  }
  const filePath = path.resolve(options.path || resolveXrayMasterKeyPath());
  const existingStat = fs.lstatSync(filePath, { throwIfNoEntry: false });
  const previousKey = existingStat
    ? loadXrayMasterKeyFile({ path: filePath, keyId: parsed.bundle.currentKeyId }).keys.get(parsed.bundle.currentKeyId)
    : undefined;
  let commitAttempted = false;
  const result = { restored: true as const, reason: "installed" as const };
  return {
    ...result,
    commit: () => {
      commitAttempted = true;
      restoreXrayMasterKeyFile({
        path: filePath,
        keyId: parsed.bundle.currentKeyId,
        key: parsed.currentKey,
        allowReplace: true,
      });
      return result;
    },
    rollback: () => {
      if (!commitAttempted) return;
      const current = loadXrayMasterKeyFile({ path: filePath, keyId: parsed.bundle.currentKeyId });
      if (!current.keys.get(parsed.bundle.currentKeyId)?.equals(parsed.currentKey)) throw unavailable();
      if (previousKey) {
        restoreXrayMasterKeyFile({
          path: filePath,
          keyId: parsed.bundle.currentKeyId,
          key: previousKey,
          allowReplace: true,
        });
      } else {
        const stat = fs.lstatSync(filePath, { throwIfNoEntry: false });
        if (!stat || !stat.isFile() || stat.isSymbolicLink()) throw unavailable();
        fs.rmSync(filePath);
      }
      commitAttempted = false;
    },
  };
}
