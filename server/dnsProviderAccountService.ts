import {
  DnsPodProviderClient,
  DnsPodProviderError,
  type DnsPodCredentials,
} from "./dnsPodProviderClient";
import {
  DnsProviderRepositoryError,
  getGlobalDnsProviderAccount,
  listGlobalDnsProviderZones,
  loadGlobalDnsProviderCredentials,
  markGlobalDnsProviderValidationFailed,
  refreshGlobalDnsProviderCatalog,
  refreshVerifiedGlobalDnsProviderAccount,
  removeGlobalDnsProviderAccountRecord,
  saveVerifiedGlobalDnsProviderAccount,
  type DnsProviderCatalogInput,
  type DnsProviderGlobalSafeDto,
  type DnsProviderZoneSafeDto,
} from "./repositories/dnsProviderRepository";

export type DnsProviderAccountServiceErrorCode =
  | "DNS_PROVIDER_NOT_CONFIGURED"
  | "DNS_PROVIDER_CONFLICT"
  | "DNS_PROVIDER_IN_USE"
  | "DNS_PROVIDER_INVALID"
  | "DNS_PROVIDER_VALIDATION_STALE"
  | "DNS_PROVIDER_CATALOG_STALE"
  | "DNS_PROVIDER_LINE_MISSING"
  | "DNS_PROVIDER_LINE_AMBIGUOUS"
  | "DNS_PROVIDER_NO_ZONES"
  | "SENSITIVE_DATA_UNAVAILABLE";

export class DnsProviderAccountServiceError extends Error {
  constructor(readonly code: DnsProviderAccountServiceErrorCode) {
    super(code);
    this.name = "DnsProviderAccountServiceError";
  }
}

type DnsPodClient = Pick<DnsPodProviderClient, "validateAccount" | "listZones" | "listRecordCatalog">;
type ClientFactory = (credentials: DnsPodCredentials) => DnsPodClient;
const DEFAULT_CATALOG_SYNC_TIMEOUT_MS = 45_000;

export type DnsProviderAccountServiceOptions = Readonly<{
  clientFactory?: ClientFactory;
  now?: () => Date;
  catalogSyncTimeoutMs?: number;
}>;

function serviceOptions(options: DnsProviderAccountServiceOptions) {
  const catalogSyncTimeoutMs = options.catalogSyncTimeoutMs ?? DEFAULT_CATALOG_SYNC_TIMEOUT_MS;
  if (!Number.isSafeInteger(catalogSyncTimeoutMs) || catalogSyncTimeoutMs < 1_000 || catalogSyncTimeoutMs > 120_000) {
    throw new DnsProviderAccountServiceError("DNS_PROVIDER_INVALID");
  }
  return {
    clientFactory: options.clientFactory ?? ((credentials: DnsPodCredentials) => (
      new DnsPodProviderClient({ credentials })
    )),
    now: options.now ?? (() => new Date()),
    catalogSyncTimeoutMs,
  };
}

function knownServiceError(error: unknown): DnsProviderAccountServiceError | null {
  if (error instanceof DnsProviderAccountServiceError) return error;
  if (error instanceof DnsProviderRepositoryError) {
    return new DnsProviderAccountServiceError(error.code);
  }
  if (error instanceof DnsPodProviderError) {
    return new DnsProviderAccountServiceError(error.code === "DNS_PROVIDER_INVALID"
      ? "DNS_PROVIDER_INVALID"
      : "DNS_PROVIDER_CATALOG_STALE");
  }
  return null;
}

function throwKnownServiceError(error: unknown): never {
  const mapped = knownServiceError(error);
  if (mapped) throw mapped;
  throw error;
}

function validNow(now: () => Date): Date {
  const value = now();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new DnsProviderAccountServiceError("DNS_PROVIDER_INVALID");
  }
  return new Date(value);
}

async function fetchCatalog(
  credentials: DnsPodCredentials,
  clientFactory: ClientFactory,
  timeoutMs: number,
): Promise<DnsProviderCatalogInput[]> {
  const client = clientFactory(credentials);
  let cancelled = false;
  const operation = (async () => {
    await client.validateAccount();
    const zones = await client.listZones();
    if (zones.length === 0) throw new DnsProviderAccountServiceError("DNS_PROVIDER_NO_ZONES");
    if (zones.length > 100) throw new DnsProviderAccountServiceError("DNS_PROVIDER_INVALID");

    const catalog: DnsProviderCatalogInput[] = new Array(zones.length);
    let nextIndex = 0;
    const workers = Array.from({ length: Math.min(4, zones.length) }, async () => {
      while (!cancelled && nextIndex < zones.length) {
        const index = nextIndex;
        nextIndex += 1;
        const zone = zones[index];
        const result = await client.listRecordCatalog(zone);
        catalog[index] = {
          providerZoneId: zone.providerZoneId,
          name: zone.name,
          lines: result.lines,
        };
      }
    });
    await Promise.all(workers);
    if (cancelled) throw new DnsProviderAccountServiceError("DNS_PROVIDER_CATALOG_STALE");
    return catalog;
  })();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      cancelled = true;
      reject(new DnsProviderAccountServiceError("DNS_PROVIDER_CATALOG_STALE"));
    }, timeoutMs);
    timer.unref?.();
  });
  try {
    return await Promise.race([operation, timeout]);
  } finally {
    cancelled = true;
    if (timer) clearTimeout(timer);
  }
}

function assertExpectedAccount(
  account: DnsProviderGlobalSafeDto,
  expectedBindingRevision: number,
  expectedAccountRevision: number | null,
): void {
  if (account.bindingRevision !== expectedBindingRevision
    || account.configured !== (expectedAccountRevision !== null)
    || (account.configured && account.accountRevision !== expectedAccountRevision)) {
    throw new DnsProviderAccountServiceError("DNS_PROVIDER_CONFLICT");
  }
}

export async function getGlobalDnsProviderAccountService(): Promise<DnsProviderGlobalSafeDto> {
  try {
    return await getGlobalDnsProviderAccount();
  } catch (error) {
    throwKnownServiceError(error);
  }
}

export async function upsertGlobalDnsProviderAccount(input: {
  expectedBindingRevision: number;
  expectedAccountRevision: number | null;
  name: string;
  secretId: string;
  secretKey: string;
  userId: number;
}, options: DnsProviderAccountServiceOptions = {}): Promise<DnsProviderGlobalSafeDto> {
  const resolved = serviceOptions(options);
  try {
    const current = await getGlobalDnsProviderAccount();
    assertExpectedAccount(current, input.expectedBindingRevision, input.expectedAccountRevision);
    if (current.configured
      && (current.quickConfigReferenceCount > 0 || current.managedRecordCount > 0)) {
      // Referenced provider identities need the deeper record-by-record rotation proof from 057K.
      throw new DnsProviderAccountServiceError("DNS_PROVIDER_IN_USE");
    }
    const credentials = { secretId: input.secretId, secretKey: input.secretKey };
    const zones = await fetchCatalog(credentials, resolved.clientFactory, resolved.catalogSyncTimeoutMs);
    return await saveVerifiedGlobalDnsProviderAccount({
      expectedBindingRevision: input.expectedBindingRevision,
      expectedAccountRevision: input.expectedAccountRevision,
      name: input.name,
      secretId: credentials.secretId,
      secretKey: credentials.secretKey,
      createdByUserId: input.userId,
      verifiedAt: validNow(resolved.now),
      zones,
    });
  } catch (error) {
    throwKnownServiceError(error);
  }
}

async function saveValidationFailure(input: {
  expectedBindingRevision: number;
  expectedAccountRevision: number;
  attemptedAt: Date;
  error: DnsProviderAccountServiceError;
}): Promise<void> {
  await markGlobalDnsProviderValidationFailed({
    expectedBindingRevision: input.expectedBindingRevision,
    expectedAccountRevision: input.expectedAccountRevision,
    status: input.error.code === "DNS_PROVIDER_INVALID" ? "INVALID" : "ERROR",
    errorCode: input.error.code,
    attemptedAt: input.attemptedAt,
  });
}

export async function revalidateGlobalDnsProviderAccount(input: {
  expectedBindingRevision: number;
  expectedAccountRevision: number;
}, options: DnsProviderAccountServiceOptions = {}): Promise<DnsProviderGlobalSafeDto> {
  const resolved = serviceOptions(options);
  const attemptedAt = validNow(resolved.now);
  try {
    const credentials = await loadGlobalDnsProviderCredentials();
    if (credentials.bindingRevision !== input.expectedBindingRevision
      || credentials.accountRevision !== input.expectedAccountRevision) {
      throw new DnsProviderAccountServiceError("DNS_PROVIDER_CONFLICT");
    }
    try {
      const zones = await fetchCatalog(credentials, resolved.clientFactory, resolved.catalogSyncTimeoutMs);
      return await refreshVerifiedGlobalDnsProviderAccount({ ...input, verifiedAt: attemptedAt, zones });
    } catch (error) {
      const mapped = knownServiceError(error);
      if (!mapped || mapped.code === "DNS_PROVIDER_CONFLICT"
        || mapped.code === "DNS_PROVIDER_NOT_CONFIGURED"
        || mapped.code === "SENSITIVE_DATA_UNAVAILABLE") {
        throw error;
      }
      await saveValidationFailure({ ...input, attemptedAt, error: mapped });
      throw mapped;
    }
  } catch (error) {
    throwKnownServiceError(error);
  }
}

function catalogIsStale(zones: readonly DnsProviderZoneSafeDto[]): boolean {
  return zones.length === 0 || zones.some((zone) => (
    zone.status !== "AVAILABLE" || zone.carrierLines.some((line) => line.status === "STALE")
  ));
}

export async function listGlobalDnsProviderZonesService(
  input: { refresh?: boolean } = {},
  options: DnsProviderAccountServiceOptions = {},
): Promise<DnsProviderZoneSafeDto[]> {
  const resolved = serviceOptions(options);
  try {
    const account = await getGlobalDnsProviderAccount();
    if (!account.configured) throw new DnsProviderAccountServiceError("DNS_PROVIDER_NOT_CONFIGURED");
    if (account.validationStatus !== "VALID") {
      throw new DnsProviderAccountServiceError("DNS_PROVIDER_VALIDATION_STALE");
    }
    const now = validNow(resolved.now);
    const cached = await listGlobalDnsProviderZones(now);
    if (!input.refresh && !catalogIsStale(cached)) return cached;

    const credentials = await loadGlobalDnsProviderCredentials();
    if (credentials.bindingRevision !== account.bindingRevision
      || credentials.accountRevision !== account.accountRevision) {
      throw new DnsProviderAccountServiceError("DNS_PROVIDER_CONFLICT");
    }
    try {
      const zones = await fetchCatalog(credentials, resolved.clientFactory, resolved.catalogSyncTimeoutMs);
      await refreshGlobalDnsProviderCatalog({
        expectedBindingRevision: account.bindingRevision,
        expectedAccountRevision: account.accountRevision,
        refreshedAt: now,
        zones,
      });
      return await listGlobalDnsProviderZones(now);
    } catch (error) {
      const mapped = knownServiceError(error);
      if (!mapped || mapped.code === "DNS_PROVIDER_CONFLICT") throw error;
      if (!input.refresh) return cached;
      throw mapped;
    }
  } catch (error) {
    throwKnownServiceError(error);
  }
}

export async function removeGlobalDnsProviderAccount(input: {
  expectedBindingRevision: number;
  expectedAccountRevision: number;
  confirmName: string;
}): Promise<DnsProviderGlobalSafeDto> {
  try {
    return await removeGlobalDnsProviderAccountRecord(input);
  } catch (error) {
    throwKnownServiceError(error);
  }
}
