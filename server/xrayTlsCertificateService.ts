import { AGENT_VERSION } from "../shared/versions";
import { isForwardplusAgentVersionAtLeast } from "./agentRouteUtils";
import { pushAgentRefresh } from "./agentEvents";
import { quoteIdentifier } from "./dbCompat";
import { queryRaw } from "./dbRuntime";
import { generateXrayHostConfig } from "./xrayConfigGenerator";
import { withKeyedTaskLock } from "./keyedTaskLock";
import { recordXrayMutationObservability } from "./xrayMutationObservability";
import { getHostById } from "./repositories/hostRepository";
import {
  getXrayRuntimeReport,
  mutateXrayHostConfigurationResource,
  XrayRepositoryError,
} from "./repositories/xrayRepository";
import {
  createXrayTlsCertificate,
  getXrayTlsCertificateLocation,
  listXrayTlsCertificates,
  removeXrayTlsCertificate,
  rotateXrayTlsCertificate,
  XrayTlsCertificateRepositoryError,
  type XrayTlsCertificateDto,
} from "./repositories/xrayTlsCertificateRepository";
import {
  loadXrayMasterKeyFile,
  XraySecretUnavailableError,
} from "./xraySecretCrypto";
import { XrayTlsCertificateValidationError } from "./xrayTlsCertificate";

export type XrayTlsCertificateServiceErrorCode =
  | "HOST_NOT_FOUND"
  | "HOST_OFFLINE"
  | "AGENT_CAPABILITY_MISSING"
  | "CERTIFICATE_NOT_FOUND"
  | "CERTIFICATE_INVALID"
  | "PRIVATE_KEY_INVALID"
  | "CERTIFICATE_KEY_MISMATCH"
  | "CERTIFICATE_EXPIRED"
  | "CERTIFICATE_NOT_YET_VALID"
  | "CERTIFICATE_CONFLICT"
  | "CERTIFICATE_IN_USE"
  | "CONFIRMATION_MISMATCH"
  | "CONFIG_GENERATION_CONFLICT"
  | "OPERATION_CONFLICT"
  | "SENSITIVE_DATA_UNAVAILABLE"
  | "INVALID_CERTIFICATE_DATA";

export class XrayTlsCertificateServiceError extends Error {
  constructor(readonly code: XrayTlsCertificateServiceErrorCode) {
    super(code);
    this.name = "XrayTlsCertificateServiceError";
  }
}

function serviceError(error: unknown): never {
  if (error instanceof XrayTlsCertificateServiceError) throw error;
  if (error instanceof XrayTlsCertificateValidationError
    || error instanceof XrayTlsCertificateRepositoryError
    || error instanceof XrayRepositoryError
    || error instanceof XraySecretUnavailableError) {
    throw new XrayTlsCertificateServiceError(error.code as XrayTlsCertificateServiceErrorCode);
  }
  throw error;
}

function positiveInteger(value: unknown, code: XrayTlsCertificateServiceErrorCode): number {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number <= 0) throw new XrayTlsCertificateServiceError(code);
  return number;
}

function generation(value: unknown): number {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) throw new XrayTlsCertificateServiceError("CONFIG_GENERATION_CONFLICT");
  return number;
}

async function requireWritableHost(hostId: number): Promise<void> {
  const host = await getHostById(hostId);
  if (!host) throw new XrayTlsCertificateServiceError("HOST_NOT_FOUND");
  if (!host.isOnline) throw new XrayTlsCertificateServiceError("HOST_OFFLINE");
  const runtime = await getXrayRuntimeReport(hostId);
  if (!isForwardplusAgentVersionAtLeast(host.agentVersion, host.agentDistribution, AGENT_VERSION) || !runtime || runtime.capabilitySchemaVersion !== 1
    || runtime.supportedOS !== "linux" || (runtime.supportedArch !== "amd64" && runtime.supportedArch !== "arm64")
    || !runtime.supportsArtifactInstall || !runtime.supportsPortProbe || !runtime.supportsRealityScan) {
    throw new XrayTlsCertificateServiceError("AGENT_CAPABILITY_MISSING");
  }
}

async function assertNoActiveHostWrite(hostId: number): Promise<void> {
  const q = quoteIdentifier;
  const rows = await queryRaw<{ count: unknown }>(
    `SELECT COUNT(*) AS ${q("count")} FROM ${q("xray_operations")}
      WHERE ${q("hostId")} = ? AND ${q("status")} IN (?, ?)
        AND ${q("type")} IN (?, ?, ?, ?)`,
    [hostId, "QUEUED", "RUNNING", "INSTALL", "UPGRADE", "SYNC", "RESTART"],
  );
  if (Number(rows[0]?.count ?? 0) > 0) throw new XrayTlsCertificateServiceError("OPERATION_CONFLICT");
}

export async function listManagedXrayTlsCertificates(input: {
  hostId?: unknown;
  search?: unknown;
  page?: unknown;
  pageSize?: unknown;
} = {}): Promise<{ items: XrayTlsCertificateDto[]; page: number; pageSize: number; total: number }> {
  try {
    const hostId = input.hostId === undefined ? undefined : positiveInteger(input.hostId, "HOST_NOT_FOUND");
    const page = input.page === undefined ? 1 : positiveInteger(input.page, "INVALID_CERTIFICATE_DATA");
    const pageSize = input.pageSize === undefined ? 20 : positiveInteger(input.pageSize, "INVALID_CERTIFICATE_DATA");
    if (pageSize > 100) throw new XrayTlsCertificateServiceError("INVALID_CERTIFICATE_DATA");
    const search = String(input.search ?? "").trim().toLocaleLowerCase();
    if ([...search].length > 128) throw new XrayTlsCertificateServiceError("INVALID_CERTIFICATE_DATA");
    const rows = (await listXrayTlsCertificates(hostId === undefined ? {} : { hostId }))
      .filter((item) => !search || item.name.toLocaleLowerCase().includes(search)
        || item.dnsNames.some((name) => name.includes(search)));
    const offset = (page - 1) * pageSize;
    return { items: rows.slice(offset, offset + pageSize), page, pageSize, total: rows.length };
  } catch (error) {
    serviceError(error);
  }
}

export async function importManagedXrayTlsCertificate(input: {
  hostId: unknown;
  name: unknown;
  certificatePem: string;
  privateKeyPem: string;
  userId: unknown;
}): Promise<XrayTlsCertificateDto> {
  try {
    const hostId = positiveInteger(input.hostId, "HOST_NOT_FOUND");
    const userId = positiveInteger(input.userId, "OPERATION_CONFLICT");
    await requireWritableHost(hostId);
    const certificate = await withKeyedTaskLock(`xray-host:${hostId}`, async () => {
      await requireWritableHost(hostId);
      return createXrayTlsCertificate({
        hostId,
        name: String(input.name ?? ""),
        certificatePem: input.certificatePem,
        privateKeyPem: input.privateKeyPem,
        createdByUserId: userId,
      }, { keyring: loadXrayMasterKeyFile() });
    });
    await recordXrayMutationObservability({
      event: "TLS_CERTIFICATE_IMPORTED",
      resourceType: "xray_tls_certificate",
      resourceId: certificate.id,
      hostId,
      action: "create",
      fields: { userId, hostId, certificateId: certificate.id, status: certificate.status },
    });
    return certificate;
  } catch (error) {
    serviceError(error);
  }
}

export async function rotateManagedXrayTlsCertificate(input: {
  id: unknown;
  certificatePem: string;
  privateKeyPem: string;
  expectedGeneration: unknown;
  userId: unknown;
}): Promise<{ certificate: XrayTlsCertificateDto; operationId: string | null; desiredGeneration: number | null }> {
  try {
    const id = positiveInteger(input.id, "CERTIFICATE_NOT_FOUND");
    const userId = positiveInteger(input.userId, "OPERATION_CONFLICT");
    const expectedGeneration = generation(input.expectedGeneration);
    const initial = await getXrayTlsCertificateLocation(id);
    await requireWritableHost(initial.hostId);
    const keyring = loadXrayMasterKeyFile();

    if (initial.referenceCount === 0) {
      const certificate = await withKeyedTaskLock(`xray-host:${initial.hostId}`, async () => {
        await requireWritableHost(initial.hostId);
        const latest = await getXrayTlsCertificateLocation(id);
        if (latest.hostId !== initial.hostId || latest.referenceCount !== 0) {
          throw new XrayTlsCertificateServiceError("CONFIG_GENERATION_CONFLICT");
        }
        return rotateXrayTlsCertificate({ id, certificatePem: input.certificatePem, privateKeyPem: input.privateKeyPem }, { keyring });
      });
      await recordXrayMutationObservability({
        event: "TLS_CERTIFICATE_ROTATED",
        resourceType: "xray_tls_certificate",
        resourceId: id,
        hostId: initial.hostId,
        action: "update",
        fields: { userId, hostId: initial.hostId, certificateId: id, status: certificate.status },
      });
      return { certificate, operationId: null, desiredGeneration: null };
    }

    const rotated = await mutateXrayHostConfigurationResource({
      hostId: initial.hostId,
      expectedGeneration,
      createdByUserId: userId,
      precondition: async () => {
        await requireWritableHost(initial.hostId);
        await assertNoActiveHostWrite(initial.hostId);
        const latest = await getXrayTlsCertificateLocation(id);
        if (latest.hostId !== initial.hostId || latest.referenceCount < 1) {
          throw new XrayTlsCertificateServiceError("CONFIG_GENERATION_CONFLICT");
        }
      },
      mutate: async () => ({
        certificate: await rotateXrayTlsCertificate({
          id,
          certificatePem: input.certificatePem,
          privateKeyPem: input.privateKeyPem,
        }, { keyring }),
      }),
      finalize: async () => {
        const generated = await generateXrayHostConfig(initial.hostId, keyring);
        return { targetVersion: generated.targetVersion, desiredConfigHash: generated.configHash };
      },
    });
    try {
      pushAgentRefresh(initial.hostId, "xray-tls-certificate-rotate", { urgent: true });
    } catch {
      // Heartbeat fallback delivers the committed desired state.
    }
    await recordXrayMutationObservability({
      event: "TLS_CERTIFICATE_ROTATED",
      resourceType: "xray_tls_certificate",
      resourceId: id,
      hostId: initial.hostId,
      action: "update",
      fields: {
        userId, hostId: initial.hostId, certificateId: id, operationId: rotated.operationId,
        generation: rotated.desiredGeneration, status: "QUEUED",
      },
    });
    return {
      certificate: rotated.certificate,
      operationId: rotated.operationId,
      desiredGeneration: rotated.desiredGeneration,
    };
  } catch (error) {
    serviceError(error);
  }
}

export async function removeManagedXrayTlsCertificate(input: {
  id: unknown;
  confirmName: unknown;
  userId: unknown;
}): Promise<{ id: number; removed: true }> {
  try {
    const id = positiveInteger(input.id, "CERTIFICATE_NOT_FOUND");
    const userId = positiveInteger(input.userId, "OPERATION_CONFLICT");
    const initial = await getXrayTlsCertificateLocation(id);
    await requireWritableHost(initial.hostId);
    const removed = await withKeyedTaskLock(`xray-host:${initial.hostId}`, async () => {
      await requireWritableHost(initial.hostId);
      const latest = await getXrayTlsCertificateLocation(id);
      if (latest.hostId !== initial.hostId) throw new XrayTlsCertificateServiceError("CERTIFICATE_NOT_FOUND");
      return removeXrayTlsCertificate({ id, confirmName: String(input.confirmName ?? "") });
    });
    await recordXrayMutationObservability({
      event: "TLS_CERTIFICATE_REMOVED",
      resourceType: "xray_tls_certificate",
      resourceId: id,
      hostId: initial.hostId,
      action: "delete",
      before: { userId, hostId: initial.hostId, certificateId: id },
      fields: { userId, hostId: initial.hostId, certificateId: id },
    });
    return removed;
  } catch (error) {
    serviceError(error);
  }
}
