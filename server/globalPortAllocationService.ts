import crypto from "node:crypto";

import { quoteIdentifier } from "./dbCompat";
import {
  executeRaw,
  insertAndGetId,
  nowDate,
  queryRaw,
  rawAffectedRows,
  withDatabaseTransaction,
} from "./dbRuntime";
import {
  buildGlobalPortOwnerGroupTag,
  buildGlobalPortReferenceKey,
  type GlobalPortPrimaryOwnerType,
  type GlobalPortReferenceNetwork,
  type GlobalPortReferenceRole,
  type GlobalPortResourceType,
  type NumericGlobalPortPrimaryOwnerType,
  type TaggedGlobalPortPrimaryOwnerType,
} from "./globalPortBackfill";

export type GlobalPortAllocationStatus =
  | "RESERVED"
  | "ACTIVE"
  | "RELEASING"
  | "PENDING_SCAN"
  | "FREE"
  | "EXTERNAL_OCCUPIED"
  | "LEGACY_CONFLICT";

export type GlobalPortAllocationErrorCode =
  | "GLOBAL_PORT_INVALID"
  | "GLOBAL_PORT_CONFLICT"
  | "GLOBAL_PORT_LEGACY_CONFLICT"
  | "GLOBAL_PORT_RESERVATION_EXPIRED"
  | "GLOBAL_PORT_RESERVATION_INVALID"
  | "GLOBAL_PORT_SCAN_PENDING"
  | "GLOBAL_PORT_EXTERNAL_OCCUPIED";

export class GlobalPortAllocationError extends Error {
  constructor(readonly code: GlobalPortAllocationErrorCode) {
    super(code);
    this.name = "GlobalPortAllocationError";
  }
}

export type GlobalPortOwner =
  | Readonly<{ type: TaggedGlobalPortPrimaryOwnerType; stableIdentity: string }>
  | Readonly<{ type: NumericGlobalPortPrimaryOwnerType; stableIdentity: number }>;

export type GlobalPortReferenceInput = Readonly<{
  resourceType: GlobalPortResourceType;
  resourceId: number;
  hostId: number | null;
  network: GlobalPortReferenceNetwork;
  role: GlobalPortReferenceRole;
  isOwning: boolean;
  slot?: "PRIMARY" | "MAPPED";
}>;

export type GlobalPortAllocationDto = Readonly<{
  allocationId: number;
  port: number;
  status: GlobalPortAllocationStatus;
  version: number;
  primaryOwnerType: GlobalPortPrimaryOwnerType | null;
  primaryOwnerTag: string | null;
  reservedUntil: string | null;
}>;

type Row = Record<string, unknown>;
const RESERVATION_TTL_MS = 60_000;
const RECLAIM_DELAY_MS = 12 * 60 * 60 * 1_000;
const MAX_SAFE_REVISION = Number.MAX_SAFE_INTEGER;

function positiveId(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) throw new GlobalPortAllocationError("GLOBAL_PORT_INVALID");
  return parsed;
}

function storedListenerPort(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > 65_535) {
    throw new GlobalPortAllocationError("GLOBAL_PORT_INVALID");
  }
  return parsed;
}

function newListenerPort(value: unknown): number {
  const parsed = storedListenerPort(value);
  if (parsed < 1_000) throw new GlobalPortAllocationError("GLOBAL_PORT_INVALID");
  return parsed;
}

function version(value: unknown): number {
  const parsed = positiveId(value);
  if (parsed >= MAX_SAFE_REVISION) throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
  return parsed;
}

function validDate(value: unknown): Date {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new GlobalPortAllocationError("GLOBAL_PORT_INVALID");
  }
  return new Date(value);
}

function dateFromDatabase(value: unknown): Date | null {
  if (value === null || value === undefined || value === "") return null;
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value : null;
  const number = Number(value);
  const parsed = Number.isFinite(number)
    ? new Date(number < 10_000_000_000 ? number * 1_000 : number)
    : new Date(String(value));
  return Number.isFinite(parsed.getTime()) ? parsed : null;
}

function allocationStatus(value: unknown): GlobalPortAllocationStatus {
  if (value === "RESERVED" || value === "ACTIVE" || value === "RELEASING"
    || value === "PENDING_SCAN" || value === "FREE" || value === "EXTERNAL_OCCUPIED"
    || value === "LEGACY_CONFLICT") return value;
  throw new GlobalPortAllocationError("GLOBAL_PORT_INVALID");
}

function ownerType(value: unknown): GlobalPortPrimaryOwnerType | null {
  if (value === null || value === undefined) return null;
  if (value === "XRAY_INBOUND" || value === "FORWARD_RULE" || value === "MANAGED_SERVICE"
    || value === "TUNNEL" || value === "QUICK_CONFIG") return value;
  throw new GlobalPortAllocationError("GLOBAL_PORT_INVALID");
}

function ownerTag(owner: GlobalPortOwner): string {
  try {
    if (owner.type === "FORWARD_RULE" || owner.type === "TUNNEL") {
      return buildGlobalPortOwnerGroupTag(owner.type, Number(owner.stableIdentity));
    }
    return buildGlobalPortOwnerGroupTag(owner.type, String(owner.stableIdentity));
  } catch {
    throw new GlobalPortAllocationError("GLOBAL_PORT_INVALID");
  }
}

function referenceKey(reference: GlobalPortReferenceInput): string {
  try {
    return buildGlobalPortReferenceKey(reference);
  } catch {
    throw new GlobalPortAllocationError("GLOBAL_PORT_INVALID");
  }
}

function tokenHash(token: string): string {
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw new GlobalPortAllocationError("GLOBAL_PORT_RESERVATION_INVALID");
  return crypto.createHash("sha256").update("forwardx-global-port-reservation:v1\n").update(token).digest("hex");
}

function secureHashEqual(actual: unknown, expected: string): boolean {
  if (typeof actual !== "string" || !/^[a-f0-9]{64}$/.test(actual)) return false;
  return crypto.timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
}

function isUniqueConstraintError(error: unknown): boolean {
  const candidate = error as { code?: unknown; errno?: unknown; message?: unknown };
  const code = String(candidate?.code ?? "");
  const message = String(candidate?.message ?? "");
  return code === "ER_DUP_ENTRY" || code === "23505" || code === "SQLITE_CONSTRAINT_UNIQUE"
    || code === "SQLITE_CONSTRAINT_PRIMARYKEY" || Number(candidate?.errno) === 1062
    || /unique constraint|duplicate key|UNIQUE constraint failed/i.test(message);
}

function conflictForStatus(status: GlobalPortAllocationStatus): GlobalPortAllocationError {
  if (status === "LEGACY_CONFLICT") return new GlobalPortAllocationError("GLOBAL_PORT_LEGACY_CONFLICT");
  if (status === "PENDING_SCAN" || status === "RELEASING") {
    return new GlobalPortAllocationError("GLOBAL_PORT_SCAN_PENDING");
  }
  if (status === "EXTERNAL_OCCUPIED") return new GlobalPortAllocationError("GLOBAL_PORT_EXTERNAL_OCCUPIED");
  return new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
}

function allocationDto(row: Row): GlobalPortAllocationDto {
  const status = allocationStatus(row.status);
  const primaryOwnerType = ownerType(row.primaryOwnerType);
  const primaryOwnerTag = row.primaryOwnerTag == null ? null : String(row.primaryOwnerTag);
  const reservationTokenHash = row.reservationTokenHash == null ? null : String(row.reservationTokenHash);
  const reservedUntil = dateFromDatabase(row.reservedUntil);
  const expectsOwner = status === "RESERVED" || status === "ACTIVE" || status === "RELEASING";
  const expectsReservation = status === "RESERVED";
  if ((primaryOwnerType === null) !== (primaryOwnerTag === null) || (primaryOwnerTag?.length ?? 0) > 128
    || expectsOwner !== (primaryOwnerType !== null)
    || expectsReservation !== (reservationTokenHash !== null && reservedUntil !== null)
    || (reservationTokenHash !== null && !/^[a-f0-9]{64}$/.test(reservationTokenHash))) {
    throw new GlobalPortAllocationError("GLOBAL_PORT_INVALID");
  }
  return {
    allocationId: positiveId(row.id),
    port: storedListenerPort(row.port),
    status,
    version: version(row.version),
    primaryOwnerType,
    primaryOwnerTag,
    reservedUntil: reservedUntil?.toISOString() ?? null,
  };
}

async function allocationByPort(port: number): Promise<Row | null> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Row>(
    `SELECT * FROM ${q("global_port_allocations")} WHERE ${q("port")} = ? LIMIT 1`,
    [port],
  );
  return rows[0] ?? null;
}

async function allocationById(id: number): Promise<Row | null> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Row>(
    `SELECT * FROM ${q("global_port_allocations")} WHERE ${q("id")} = ? LIMIT 1`,
    [id],
  );
  return rows[0] ?? null;
}

async function allocationForReference(reference: GlobalPortReferenceInput): Promise<{
  allocation: GlobalPortAllocationDto;
  ownerGroupTag: string;
} | null> {
  const q = quoteIdentifier;
  const rows = await queryRaw<Row>(
    `SELECT r.${q("ownerGroupTag")} AS ${q("ownerGroupTag")}, a.*
       FROM ${q("global_port_allocation_references")} r
       JOIN ${q("global_port_allocations")} a ON a.${q("id")} = r.${q("allocationId")}
      WHERE r.${q("referenceKey")} = ? LIMIT 1`,
    [referenceKey(reference)],
  );
  if (!rows[0]) return null;
  return { allocation: allocationDto(rows[0]), ownerGroupTag: String(rows[0].ownerGroupTag ?? "") };
}

async function insertReference(input: {
  allocationId: number;
  ownerGroupTag: string;
  reference: GlobalPortReferenceInput;
  now: Date;
}): Promise<boolean> {
  const key = referenceKey(input.reference);
  const q = quoteIdentifier;
  const existing = await queryRaw<Row>(
    `SELECT * FROM ${q("global_port_allocation_references")} WHERE ${q("referenceKey")} = ? LIMIT 1`,
    [key],
  );
  if (existing[0]) {
    const row = existing[0];
    if (positiveId(row.allocationId) !== input.allocationId || String(row.ownerGroupTag) !== input.ownerGroupTag
      || String(row.resourceType) !== input.reference.resourceType || positiveId(row.resourceId) !== input.reference.resourceId
      || (row.hostId == null ? null : positiveId(row.hostId)) !== input.reference.hostId
      || String(row.network) !== input.reference.network || String(row.role) !== input.reference.role
      || (row.isOwning === true || row.isOwning === 1 || row.isOwning === "1") !== input.reference.isOwning) {
      throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    }
    return false;
  }
  try {
    await insertAndGetId("global_port_allocation_references", {
      referenceKey: key,
      allocationId: input.allocationId,
      resourceType: input.reference.resourceType,
      resourceId: positiveId(input.reference.resourceId),
      ownerGroupTag: input.ownerGroupTag,
      hostId: input.reference.hostId == null ? null : positiveId(input.reference.hostId),
      network: input.reference.network,
      role: input.reference.role,
      isOwning: input.reference.isOwning,
      createdAt: input.now,
      updatedAt: input.now,
    });
    return true;
  } catch (error) {
    if (isUniqueConstraintError(error)) throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    throw error;
  }
}

export async function inspectGlobalPortAllocation(portValue: unknown): Promise<GlobalPortAllocationDto | null> {
  const port = storedListenerPort(portValue);
  const row = await allocationByPort(port);
  return row ? allocationDto(row) : null;
}

export async function inspectGlobalPortReferenceAllocation(
  reference: GlobalPortReferenceInput,
): Promise<GlobalPortAllocationDto | null> {
  return (await allocationForReference(reference))?.allocation ?? null;
}

export async function assertGlobalPortAvailable(portValue: unknown, allowedOwner?: GlobalPortOwner): Promise<void> {
  const port = newListenerPort(portValue);
  const row = await allocationByPort(port);
  if (!row || allocationStatus(row.status) === "FREE") return;
  if (allowedOwner && allocationStatus(row.status) === "ACTIVE"
    && row.primaryOwnerType === allowedOwner.type && row.primaryOwnerTag === ownerTag(allowedOwner)) return;
  throw conflictForStatus(allocationStatus(row.status));
}

export async function reserveGlobalPortAllocation(input: {
  port: unknown;
  owner: GlobalPortOwner;
  now?: Date;
  ttlMs?: number;
}): Promise<GlobalPortAllocationDto & { reservationToken: string }> {
  const port = newListenerPort(input.port);
  const now = validDate(input.now ?? nowDate());
  const ttlMs = input.ttlMs ?? RESERVATION_TTL_MS;
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1_000 || ttlMs > RESERVATION_TTL_MS) {
    throw new GlobalPortAllocationError("GLOBAL_PORT_INVALID");
  }
  const primaryOwnerTag = ownerTag(input.owner);
  const reservationToken = crypto.randomBytes(32).toString("base64url");
  const reservationTokenHash = tokenHash(reservationToken);
  const reservedUntil = new Date(now.getTime() + ttlMs);

  try {
    const result = await withDatabaseTransaction(async () => {
      const existing = await allocationByPort(port);
      if (!existing) {
        const allocationId = await insertAndGetId("global_port_allocations", {
          allocationTag: `global-port:v1:${port}`,
          port,
          status: "RESERVED",
          primaryOwnerType: input.owner.type,
          primaryOwnerTag,
          reservationTokenHash,
          reservedUntil,
          scanNotBefore: null,
          lastErrorCode: null,
          version: 1,
          createdAt: now,
          updatedAt: now,
        });
        return allocationById(allocationId);
      }
      const current = allocationDto(existing);
      if (current.status !== "FREE") throw conflictForStatus(current.status);
      const q = quoteIdentifier;
      const changed = await executeRaw(
        `UPDATE ${q("global_port_allocations")} SET ${q("status")} = 'RESERVED', ${q("primaryOwnerType")} = ?, ${q("primaryOwnerTag")} = ?, ${q("reservationTokenHash")} = ?, ${q("reservedUntil")} = ?, ${q("scanNotBefore")} = NULL, ${q("lastErrorCode")} = NULL, ${q("version")} = ${q("version")} + 1, ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("version")} = ? AND ${q("status")} = 'FREE'`,
        [input.owner.type, primaryOwnerTag, reservationTokenHash, reservedUntil, now,
          current.allocationId, current.version],
      );
      if (rawAffectedRows(changed) !== 1) throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
      return allocationById(current.allocationId);
    });
    if (!result) throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    return { ...allocationDto(result), reservationToken };
  } catch (error) {
    if (error instanceof GlobalPortAllocationError) throw error;
    if (isUniqueConstraintError(error)) throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    throw error;
  }
}

export async function activateReservedGlobalPortAllocation(input: {
  allocationId: unknown;
  expectedVersion: unknown;
  owner: GlobalPortOwner;
  reservationToken: string;
  references: readonly GlobalPortReferenceInput[];
  now?: Date;
}): Promise<GlobalPortAllocationDto> {
  const allocationId = positiveId(input.allocationId);
  const expectedVersion = version(input.expectedVersion);
  const now = validDate(input.now ?? nowDate());
  const primaryOwnerTag = ownerTag(input.owner);
  if (!Array.isArray(input.references) || input.references.length < 1 || input.references.length > 256
    || input.references.some((reference) => !reference.isOwning)) {
    throw new GlobalPortAllocationError("GLOBAL_PORT_INVALID");
  }
  return withDatabaseTransaction(async () => {
    const row = await allocationById(allocationId);
    if (!row || version(row.version) !== expectedVersion || allocationStatus(row.status) !== "RESERVED"
      || row.primaryOwnerType !== input.owner.type || row.primaryOwnerTag !== primaryOwnerTag) {
      throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    }
    const expiresAt = dateFromDatabase(row.reservedUntil);
    if (!expiresAt || expiresAt.getTime() <= now.getTime()) {
      throw new GlobalPortAllocationError("GLOBAL_PORT_RESERVATION_EXPIRED");
    }
    if (!secureHashEqual(row.reservationTokenHash, tokenHash(input.reservationToken))) {
      throw new GlobalPortAllocationError("GLOBAL_PORT_RESERVATION_INVALID");
    }
    for (const reference of input.references) {
      await insertReference({ allocationId, ownerGroupTag: primaryOwnerTag, reference, now });
    }
    const q = quoteIdentifier;
    const changed = await executeRaw(
      `UPDATE ${q("global_port_allocations")} SET ${q("status")} = 'ACTIVE', ${q("reservationTokenHash")} = NULL, ${q("reservedUntil")} = NULL, ${q("version")} = ${q("version")} + 1, ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("version")} = ? AND ${q("status")} = 'RESERVED'`,
      [now, allocationId, expectedVersion],
    );
    if (rawAffectedRows(changed) !== 1) throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    const updated = await allocationById(allocationId);
    if (!updated) throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    return allocationDto(updated);
  });
}

export async function addActiveGlobalPortOwningReference(input: {
  allocationId: unknown;
  expectedVersion: unknown;
  owner: GlobalPortOwner;
  reference: GlobalPortReferenceInput;
  now?: Date;
}): Promise<GlobalPortAllocationDto> {
  const allocationId = positiveId(input.allocationId);
  const expectedVersion = version(input.expectedVersion);
  const now = validDate(input.now ?? nowDate());
  const primaryOwnerTag = ownerTag(input.owner);
  if (!input.reference.isOwning) throw new GlobalPortAllocationError("GLOBAL_PORT_INVALID");
  return withDatabaseTransaction(async () => {
    const row = await allocationById(allocationId);
    if (!row || version(row.version) !== expectedVersion || allocationStatus(row.status) !== "ACTIVE"
      || row.primaryOwnerType !== input.owner.type || row.primaryOwnerTag !== primaryOwnerTag) {
      throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    }
    const inserted = await insertReference({ allocationId, ownerGroupTag: primaryOwnerTag, reference: input.reference, now });
    if (!inserted) return allocationDto(row);
    const q = quoteIdentifier;
    const changed = await executeRaw(
      `UPDATE ${q("global_port_allocations")} SET ${q("version")} = ${q("version")} + 1, ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("version")} = ? AND ${q("status")} = 'ACTIVE'`,
      [now, allocationId, expectedVersion],
    );
    if (rawAffectedRows(changed) !== 1) throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    const updated = await allocationById(allocationId);
    if (!updated) throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    return allocationDto(updated);
  });
}

/**
 * Claims a listener port for an owning reference. Existing references are
 * idempotent, while an ACTIVE allocation owned by another logical resource is
 * rejected by addActiveGlobalPortOwningReference.
 */
export async function acquireGlobalPortOwningReference(input: {
  port: unknown;
  owner: GlobalPortOwner;
  reference: GlobalPortReferenceInput;
  now?: Date;
}): Promise<GlobalPortAllocationDto> {
  const port = newListenerPort(input.port);
  const existingReference = await allocationForReference(input.reference);
  if (existingReference) {
    if (existingReference.allocation.port !== port || existingReference.allocation.status !== "ACTIVE"
      || existingReference.allocation.primaryOwnerType !== input.owner.type
      || existingReference.allocation.primaryOwnerTag !== ownerTag(input.owner)) {
      throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    }
    return existingReference.allocation;
  }
  const current = await inspectGlobalPortAllocation(port);
  if (current?.status === "ACTIVE") {
    return addActiveGlobalPortOwningReference({
      allocationId: current.allocationId,
      expectedVersion: current.version,
      owner: input.owner,
      reference: input.reference,
      now: input.now,
    });
  }
  const reservation = await reserveGlobalPortAllocation({
    port,
    owner: input.owner,
    now: input.now,
  });
  return activateReservedGlobalPortAllocation({
    allocationId: reservation.allocationId,
    expectedVersion: reservation.version,
    owner: input.owner,
    reservationToken: reservation.reservationToken,
    references: [input.reference],
    now: input.now,
  });
}

export async function attachGlobalPortTargetAlias(input: {
  allocationId: unknown;
  expectedVersion: unknown;
  sourceOwner: GlobalPortOwner;
  aliasOwner: GlobalPortOwner;
  reference: GlobalPortReferenceInput;
  now?: Date;
}): Promise<GlobalPortAllocationDto> {
  const allocationId = positiveId(input.allocationId);
  const expectedVersion = version(input.expectedVersion);
  const sourceOwnerTag = ownerTag(input.sourceOwner);
  const aliasOwnerTag = ownerTag(input.aliasOwner);
  const now = validDate(input.now ?? nowDate());
  if (input.sourceOwner.type !== "XRAY_INBOUND" || input.aliasOwner.type !== "QUICK_CONFIG"
    || input.reference.resourceType !== "QUICK_CONFIG" || input.reference.isOwning
    || (input.reference.role !== "TARGET" && input.reference.role !== "PUBLIC_LISTENER")) {
    throw new GlobalPortAllocationError("GLOBAL_PORT_INVALID");
  }
  return withDatabaseTransaction(async () => {
    const q = quoteIdentifier;
    const row = await allocationById(allocationId);
    if (!row || version(row.version) !== expectedVersion || allocationStatus(row.status) !== "ACTIVE"
      || row.primaryOwnerType !== input.sourceOwner.type || row.primaryOwnerTag !== sourceOwnerTag) {
      throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    }
    const sourceReferences = await queryRaw<Row>(
      `SELECT ${q("resourceId")} FROM ${q("global_port_allocation_references")} WHERE ${q("allocationId")} = ? AND ${q("ownerGroupTag")} = ? AND ${q("resourceType")} = 'XRAY_INBOUND' AND ${q("isOwning")} = ?`,
      [allocationId, sourceOwnerTag, true],
    );
    const sourceInboundIds = new Set(sourceReferences.map((reference) => positiveId(reference.resourceId)));
    if (sourceInboundIds.size !== 1) throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    const sourceInboundId = [...sourceInboundIds][0];
    const quickConfigs = await queryRaw<Row>(
      `SELECT ${q("configTag")}, ${q("xrayInboundId")}, ${q("state")} FROM ${q("xray_quick_configs")} WHERE ${q("id")} = ? LIMIT 1`,
      [positiveId(input.reference.resourceId)],
    );
    const quickConfig = quickConfigs[0];
    if (!quickConfig || String(quickConfig.configTag) !== aliasOwnerTag
      || positiveId(quickConfig.xrayInboundId) !== sourceInboundId || quickConfig.state === "REMOVED") {
      throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    }
    const inserted = await insertReference({ allocationId, ownerGroupTag: aliasOwnerTag, reference: input.reference, now });
    if (!inserted) return allocationDto(row);
    const changed = await executeRaw(
      `UPDATE ${q("global_port_allocations")} SET ${q("version")} = ${q("version")} + 1, ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("version")} = ? AND ${q("status")} = 'ACTIVE'`,
      [now, allocationId, expectedVersion],
    );
    if (rawAffectedRows(changed) !== 1) throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    const updated = await allocationById(allocationId);
    if (!updated) throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    return allocationDto(updated);
  });
}

export async function beginGlobalPortReferenceRelease(input: {
  reference: GlobalPortReferenceInput;
  expectedVersion: unknown;
  now?: Date;
}): Promise<GlobalPortAllocationDto | null> {
  const key = referenceKey(input.reference);
  const expectedVersion = version(input.expectedVersion);
  const now = validDate(input.now ?? nowDate());
  return withDatabaseTransaction(async () => {
    const q = quoteIdentifier;
    const rows = await queryRaw<Row>(
      `SELECT * FROM ${q("global_port_allocation_references")} WHERE ${q("referenceKey")} = ? LIMIT 1`,
      [key],
    );
    const reference = rows[0];
    if (!reference) return null;
    const allocationId = positiveId(reference.allocationId);
    const allocation = await allocationById(allocationId);
    if (!allocation || allocationStatus(allocation.status) !== "ACTIVE"
      || version(allocation.version) !== expectedVersion) {
      throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    }
    const remaining = await queryRaw<Row>(
      `SELECT ${q("ownerGroupTag")}, ${q("isOwning")} FROM ${q("global_port_allocation_references")} WHERE ${q("allocationId")} = ? AND ${q("id")} <> ?`,
      [allocationId, positiveId(reference.id)],
    );
    const primaryOwnerTag = String(allocation.primaryOwnerTag ?? "");
    if (remaining.length > 0 && !remaining.some((row) => String(row.ownerGroupTag) === primaryOwnerTag
      && (row.isOwning === true || row.isOwning === 1 || row.isOwning === "1"))) {
      throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    }
    if (remaining.length > 0) {
      await executeRaw(
        `DELETE FROM ${q("global_port_allocation_references")} WHERE ${q("id")} = ? AND ${q("referenceKey")} = ?`,
        [positiveId(reference.id), key],
      );
    }
    const changed = await executeRaw(remaining.length > 0
      ? `UPDATE ${q("global_port_allocations")} SET ${q("version")} = ${q("version")} + 1, ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("version")} = ? AND ${q("status")} = 'ACTIVE'`
      : `UPDATE ${q("global_port_allocations")} SET ${q("status")} = 'RELEASING', ${q("version")} = ${q("version")} + 1, ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("version")} = ? AND ${q("status")} = 'ACTIVE'`,
      [now, allocationId, expectedVersion],
    );
    if (rawAffectedRows(changed) !== 1) throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    const updated = await allocationById(allocationId);
    if (!updated) throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    return allocationDto(updated);
  });
}

export async function confirmGlobalPortReferenceReleased(input: {
  reference: GlobalPortReferenceInput;
  expectedVersion: unknown;
  now?: Date;
}): Promise<GlobalPortAllocationDto> {
  const key = referenceKey(input.reference);
  const expectedVersion = version(input.expectedVersion);
  const now = validDate(input.now ?? nowDate());
  return withDatabaseTransaction(async () => {
    const q = quoteIdentifier;
    const rows = await queryRaw<Row>(
      `SELECT * FROM ${q("global_port_allocation_references")} WHERE ${q("referenceKey")} = ? LIMIT 1`,
      [key],
    );
    const reference = rows[0];
    if (!reference) throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    const allocationId = positiveId(reference.allocationId);
    const allocation = await allocationById(allocationId);
    if (!allocation || allocationStatus(allocation.status) !== "RELEASING"
      || version(allocation.version) !== expectedVersion) {
      throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    }
    const remaining = await queryRaw<Row>(
      `SELECT ${q("id")} FROM ${q("global_port_allocation_references")} WHERE ${q("allocationId")} = ? AND ${q("id")} <> ? LIMIT 1`,
      [allocationId, positiveId(reference.id)],
    );
    if (remaining.length > 0) throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    await executeRaw(
      `DELETE FROM ${q("global_port_allocation_references")} WHERE ${q("id")} = ? AND ${q("referenceKey")} = ?`,
      [positiveId(reference.id), key],
    );
    const changed = await executeRaw(
      `UPDATE ${q("global_port_allocations")} SET ${q("status")} = 'PENDING_SCAN', ${q("primaryOwnerType")} = NULL, ${q("primaryOwnerTag")} = NULL, ${q("scanNotBefore")} = ?, ${q("version")} = ${q("version")} + 1, ${q("updatedAt")} = ? WHERE ${q("id")} = ? AND ${q("version")} = ? AND ${q("status")} = 'RELEASING'`,
      [new Date(now.getTime() + RECLAIM_DELAY_MS), now, allocationId, expectedVersion],
    );
    if (rawAffectedRows(changed) !== 1) throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    const updated = await allocationById(allocationId);
    if (!updated) throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    return allocationDto(updated);
  });
}

/**
 * Completes the ledger side of a listener removal after its runtime has
 * already converged. The final owning reference still remains present while
 * the allocation is RELEASING, so a crash cannot expose the port as reusable.
 */
export async function releaseGlobalPortReferenceAfterRuntimeCleanup(input: {
  reference: GlobalPortReferenceInput;
  now?: Date;
}): Promise<GlobalPortAllocationDto | null> {
  const now = validDate(input.now ?? nowDate());
  return withDatabaseTransaction(async () => {
    const located = await allocationForReference(input.reference);
    if (!located) return null;
    const releasing = await beginGlobalPortReferenceRelease({
      reference: input.reference,
      expectedVersion: located.allocation.version,
      now,
    });
    if (!releasing || releasing.status !== "RELEASING") return releasing;
    return confirmGlobalPortReferenceReleased({
      reference: input.reference,
      expectedVersion: releasing.version,
      now,
    });
  });
}

/**
 * Atomically promotes a staged listener allocation once the Agent has applied
 * the new port. The old public reference is retained until this point.
 */
export async function promoteStagedGlobalPortOwningReference(input: {
  owner: GlobalPortOwner;
  publicReference: GlobalPortReferenceInput;
  nextPublicReference?: GlobalPortReferenceInput;
  stagedReference: GlobalPortReferenceInput;
  now?: Date;
}): Promise<GlobalPortAllocationDto> {
  const now = validDate(input.now ?? nowDate());
  const expectedOwnerTag = ownerTag(input.owner);
  const nextPublicReference = input.nextPublicReference ?? input.publicReference;
  const promotedRole = input.publicReference.role;
  if (!input.publicReference.isOwning || (promotedRole !== "PUBLIC_LISTENER" && promotedRole !== "MIMIC")
    || !nextPublicReference.isOwning || nextPublicReference.role !== promotedRole
    || !input.stagedReference.isOwning || input.stagedReference.role !== "OWNERSHIP"
    || input.publicReference.resourceType !== input.stagedReference.resourceType
    || input.publicReference.resourceId !== input.stagedReference.resourceId
    || nextPublicReference.resourceType !== input.stagedReference.resourceType
    || nextPublicReference.resourceId !== input.stagedReference.resourceId
    || nextPublicReference.hostId !== input.stagedReference.hostId
    || nextPublicReference.network !== input.stagedReference.network) {
    throw new GlobalPortAllocationError("GLOBAL_PORT_INVALID");
  }
  return withDatabaseTransaction(async () => {
    const source = await allocationForReference(input.publicReference);
    const target = await allocationForReference(input.stagedReference);
    if (!source || !target || source.allocation.status !== "ACTIVE" || target.allocation.status !== "ACTIVE"
      || source.allocation.primaryOwnerType !== input.owner.type
      || target.allocation.primaryOwnerType !== input.owner.type
      || source.allocation.primaryOwnerTag !== expectedOwnerTag
      || target.allocation.primaryOwnerTag !== expectedOwnerTag
      || source.ownerGroupTag !== expectedOwnerTag || target.ownerGroupTag !== expectedOwnerTag) {
      throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    }
    const releasing = await beginGlobalPortReferenceRelease({
      reference: input.publicReference,
      expectedVersion: source.allocation.version,
      now,
    });
    if (!releasing || (releasing.status !== "RELEASING" && releasing.status !== "ACTIVE")) {
      throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    }
    if (releasing.status === "RELEASING") {
      await confirmGlobalPortReferenceReleased({
        reference: input.publicReference,
        expectedVersion: releasing.version,
        now,
      });
    }
    const targetVersion = source.allocation.allocationId === target.allocation.allocationId
      ? releasing.version
      : target.allocation.version;
    const withPublic = await addActiveGlobalPortOwningReference({
      allocationId: target.allocation.allocationId,
      expectedVersion: targetVersion,
      owner: input.owner,
      reference: nextPublicReference,
      now,
    });
    const withoutStaging = await beginGlobalPortReferenceRelease({
      reference: input.stagedReference,
      expectedVersion: withPublic.version,
      now,
    });
    if (!withoutStaging || withoutStaging.status !== "ACTIVE") {
      throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    }
    return withoutStaging;
  });
}

/**
 * Promotes a staged listener after the previous public reference was already
 * released by a different host's complete runtime snapshot. This is the
 * second half of a host move: it refuses to proceed while another public
 * reference for the same logical listener slot still exists anywhere.
 */
export async function promoteOrphanedStagedGlobalPortOwningReference(input: {
  owner: GlobalPortOwner;
  nextPublicReference: GlobalPortReferenceInput;
  stagedReference: GlobalPortReferenceInput;
  now?: Date;
}): Promise<GlobalPortAllocationDto> {
  const now = validDate(input.now ?? nowDate());
  const expectedOwnerTag = ownerTag(input.owner);
  const next = input.nextPublicReference;
  const staged = input.stagedReference;
  if (!next.isOwning || (next.role !== "PUBLIC_LISTENER" && next.role !== "MIMIC")
    || !staged.isOwning || staged.role !== "OWNERSHIP"
    || next.resourceType !== staged.resourceType || next.resourceId !== staged.resourceId
    || next.hostId !== staged.hostId || next.network !== staged.network) {
    throw new GlobalPortAllocationError("GLOBAL_PORT_INVALID");
  }
  return withDatabaseTransaction(async () => {
    const target = await allocationForReference(staged);
    if (!target || target.allocation.status !== "ACTIVE"
      || target.allocation.primaryOwnerType !== input.owner.type
      || target.allocation.primaryOwnerTag !== expectedOwnerTag
      || target.ownerGroupTag !== expectedOwnerTag) {
      throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    }
    const q = quoteIdentifier;
    const publicRows = await queryRaw<Row>(
      `SELECT ${q("referenceKey")}, ${q("ownerGroupTag")}
         FROM ${q("global_port_allocation_references")}
        WHERE ${q("resourceType")} = ? AND ${q("resourceId")} = ? AND ${q("role")} = ?`,
      [next.resourceType, next.resourceId, next.role],
    );
    const expectedSlot = next.slot ?? null;
    const sameLogicalSlot = publicRows.some((row) => {
      const key = String(row.referenceKey ?? "");
      const rowSlot = key.endsWith(":PRIMARY") ? "PRIMARY" : key.endsWith(":MAPPED") ? "MAPPED" : null;
      return rowSlot === expectedSlot;
    });
    if (sameLogicalSlot) throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");

    const withPublic = await addActiveGlobalPortOwningReference({
      allocationId: target.allocation.allocationId,
      expectedVersion: target.allocation.version,
      owner: input.owner,
      reference: next,
      now,
    });
    const withoutStaging = await beginGlobalPortReferenceRelease({
      reference: staged,
      expectedVersion: withPublic.version,
      now,
    });
    if (!withoutStaging || withoutStaging.status !== "ACTIVE") {
      throw new GlobalPortAllocationError("GLOBAL_PORT_CONFLICT");
    }
    return withoutStaging;
  });
}

export async function recoverExpiredGlobalPortReservations(nowValue = nowDate()): Promise<number> {
  const now = validDate(nowValue);
  const q = quoteIdentifier;
  const result = await executeRaw(
    `UPDATE ${q("global_port_allocations")} SET ${q("status")} = 'PENDING_SCAN', ${q("primaryOwnerType")} = NULL, ${q("primaryOwnerTag")} = NULL, ${q("reservationTokenHash")} = NULL, ${q("reservedUntil")} = NULL, ${q("scanNotBefore")} = ?, ${q("version")} = ${q("version")} + 1, ${q("updatedAt")} = ? WHERE ${q("status")} = 'RESERVED' AND ${q("reservedUntil")} IS NOT NULL AND ${q("reservedUntil")} <= ? AND ${q("version")} < ? AND NOT EXISTS (SELECT 1 FROM ${q("global_port_allocation_references")} r WHERE r.${q("allocationId")} = ${q("global_port_allocations")}.${q("id")})`,
    [new Date(now.getTime() + RECLAIM_DELAY_MS), now, now, MAX_SAFE_REVISION],
  );
  return rawAffectedRows(result);
}
