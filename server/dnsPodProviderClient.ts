import { createHash, createHmac } from "node:crypto";
import { isIP } from "node:net";

import { normalizeDnsProviderZoneName } from "./dnsProviderCatalog";

export const DNSPOD_ENDPOINT = "https://dnspod.tencentcloudapi.com/" as const;
export const DNSPOD_HOST = "dnspod.tencentcloudapi.com" as const;
export const DNSPOD_SERVICE = "dnspod" as const;
export const DNSPOD_VERSION = "2021-03-23" as const;
export const DNSPOD_CONTENT_TYPE = "application/json; charset=utf-8" as const;

const READ_ACTIONS = [
  "DescribeUserDetail",
  "DescribeDomainList",
  "DescribeDomain",
  "DescribeRecordLineList",
  "DescribeRecordType",
  "DescribeRecordList",
  "DescribeRecord",
] as const;
const WRITE_ACTIONS = ["CreateRecord", "ModifyRecord", "DeleteRecord"] as const;
const ALL_ACTIONS = new Set<string>([...READ_ACTIONS, ...WRITE_ACTIONS]);
const READ_ACTION_SET = new Set<string>(READ_ACTIONS);
const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_TOTAL_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
const DEFAULT_MAX_PAGES = 50;
const PAGE_SIZE = 100;

export type DnsPodAction = typeof READ_ACTIONS[number] | typeof WRITE_ACTIONS[number];
export type DnsPodProviderErrorCode =
  | "DNS_PROVIDER_INVALID"
  | "DNS_PROVIDER_UNAVAILABLE"
  | "DNS_PROVIDER_INVALID_RESPONSE"
  | "DNS_PROVIDER_REQUEST_REJECTED"
  | "DNS_PROVIDER_RECORD_NOT_FOUND";

export class DnsPodProviderError extends Error {
  constructor(
    readonly code: DnsPodProviderErrorCode,
    readonly retryable = false,
    readonly ambiguousWrite = false,
  ) {
    super(code);
    this.name = "DnsPodProviderError";
  }
}

export type DnsPodCredentials = Readonly<{ secretId: string; secretKey: string }>;
export type DnsPodZone = Readonly<{
  providerZoneId: string;
  name: string;
  grade: string;
  status?: string | null;
}>;
export type DnsPodRecordLine = Readonly<{ providerLineId: string; name: string }>;
export type DnsPodRecord = Readonly<{
  providerRecordId: string;
  subdomain: string;
  recordType: string;
  providerLineId: string;
  lineName: string;
  value: string;
  ttl: number;
  status: string | null;
}>;

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
type DnsPodObject = Record<string, unknown>;

function invalidResponse(): never {
  throw new DnsPodProviderError("DNS_PROVIDER_INVALID_RESPONSE");
}

function stableJsonValue(value: unknown): JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(stableJsonValue);
  if (!value || typeof value !== "object") invalidResponse();
  const output: { [key: string]: JsonValue } = {};
  for (const key of Object.keys(value as DnsPodObject).sort()) {
    const entry = (value as DnsPodObject)[key];
    if (entry === undefined) invalidResponse();
    output[key] = stableJsonValue(entry);
  }
  return output;
}

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function hmac(key: string | Buffer, value: string): Buffer {
  return createHmac("sha256", key).update(value, "utf8").digest();
}

function utcDate(timestamp: number): string {
  if (!Number.isSafeInteger(timestamp) || timestamp <= 0) invalidResponse();
  return new Date(timestamp * 1_000).toISOString().slice(0, 10);
}

function validCredentials(value: DnsPodCredentials): DnsPodCredentials {
  const secretId = typeof value?.secretId === "string" ? value.secretId.trim() : "";
  const secretKey = typeof value?.secretKey === "string" ? value.secretKey.trim() : "";
  if (secretId.length < 8 || secretId.length > 128 || secretKey.length < 8 || secretKey.length > 128
    || /[\u0000-\u001f\u007f]/.test(secretId) || /[\u0000-\u001f\u007f]/.test(secretKey)) {
    throw new DnsPodProviderError("DNS_PROVIDER_INVALID");
  }
  return { secretId, secretKey };
}

export function buildDnsPodTc3Request(input: {
  credentials: DnsPodCredentials;
  action: DnsPodAction;
  payload: DnsPodObject;
  timestamp: number;
}): { url: typeof DNSPOD_ENDPOINT; init: RequestInit & { headers: Record<string, string>; body: string } } {
  if (!ALL_ACTIONS.has(input.action)) throw new DnsPodProviderError("DNS_PROVIDER_REQUEST_REJECTED");
  const credentials = validCredentials(input.credentials);
  const body = JSON.stringify(stableJsonValue(input.payload));
  if (Buffer.byteLength(body, "utf8") > 64 * 1024) invalidResponse();
  const canonicalHeaders = `content-type:${DNSPOD_CONTENT_TYPE}\nhost:${DNSPOD_HOST}\nx-tc-action:${input.action.toLowerCase()}\n`;
  const signedHeaders = "content-type;host;x-tc-action";
  const canonicalRequest = ["POST", "/", "", canonicalHeaders, signedHeaders, sha256Hex(body)].join("\n");
  const date = utcDate(input.timestamp);
  const credentialScope = `${date}/${DNSPOD_SERVICE}/tc3_request`;
  const stringToSign = ["TC3-HMAC-SHA256", String(input.timestamp), credentialScope, sha256Hex(canonicalRequest)].join("\n");
  const secretDate = hmac(`TC3${credentials.secretKey}`, date);
  const secretService = hmac(secretDate, DNSPOD_SERVICE);
  const secretSigning = hmac(secretService, "tc3_request");
  const signature = createHmac("sha256", secretSigning).update(stringToSign, "utf8").digest("hex");
  const headers: Record<string, string> = {
    Authorization: `TC3-HMAC-SHA256 Credential=${credentials.secretId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
    "Content-Type": DNSPOD_CONTENT_TYPE,
    Host: DNSPOD_HOST,
    "X-TC-Action": input.action,
    "X-TC-Language": "zh-CN",
    "X-TC-Timestamp": String(input.timestamp),
    "X-TC-Version": DNSPOD_VERSION,
  };
  return {
    url: DNSPOD_ENDPOINT,
    init: { method: "POST", redirect: "error", headers, body },
  };
}

function object(value: unknown): DnsPodObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalidResponse();
  return value as DnsPodObject;
}

function boundedString(value: unknown, maximum = 253): string {
  if (typeof value !== "string" || !value || Buffer.byteLength(value, "utf8") > maximum
    || /[\u0000-\u001f\u007f]/.test(value)) invalidResponse();
  return value;
}

function optionalString(value: unknown, maximum = 128): string | null {
  if (value === null || value === undefined || value === "") return null;
  return boundedString(value, maximum);
}

function positiveInteger(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) invalidResponse();
  return parsed;
}

function nonnegativeInteger(value: unknown): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) invalidResponse();
  return parsed;
}

function providerId(value: unknown): string {
  const id = boundedString(String(value ?? ""), 128);
  if (!/^\d+$/.test(id) || !Number.isSafeInteger(Number(id)) || Number(id) <= 0) invalidResponse();
  return id;
}

function providerIdNumber(value: unknown): number {
  return Number(providerId(value));
}

function mapProviderError(code: string, httpStatus: number): DnsPodProviderError {
  if (/^(?:AuthFailure\.|FailedOperation\.LoginFailed)/.test(code)) {
    return new DnsPodProviderError("DNS_PROVIDER_INVALID");
  }
  if (/^(?:RequestLimitExceeded|FailedOperation\.FrequencyLimit)/.test(code) || httpStatus === 429) {
    return new DnsPodProviderError("DNS_PROVIDER_UNAVAILABLE", true);
  }
  if (/^(?:InternalError|ServiceUnavailable|FailedOperation\.UnknowError)/.test(code) || httpStatus >= 500) {
    return new DnsPodProviderError("DNS_PROVIDER_UNAVAILABLE", true);
  }
  if (/^(?:ResourceNotFound\.|FailedOperation\.NoDataOfRecord)/.test(code)
    || code === "InvalidParameter.RecordIdInvalid") {
    return new DnsPodProviderError("DNS_PROVIDER_RECORD_NOT_FOUND");
  }
  return new DnsPodProviderError("DNS_PROVIDER_REQUEST_REJECTED");
}

async function readBoundedResponse(response: Response, maximumBytes: number): Promise<DnsPodObject> {
  const contentType = response.headers.get("content-type") ?? "";
  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) invalidResponse();
  const advertised = response.headers.get("content-length");
  if (advertised !== null && (!/^\d+$/.test(advertised) || Number(advertised) > maximumBytes)) invalidResponse();
  if (!response.body) invalidResponse();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximumBytes) invalidResponse();
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  let parsed: unknown;
  try { parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { invalidResponse(); }
  const envelope = object(parsed);
  if (Object.keys(envelope).some((key) => key !== "Response")) invalidResponse();
  const payload = object(envelope.Response);
  boundedString(payload.RequestId, 128);
  const providerError = payload.Error;
  if (providerError !== undefined && providerError !== null) {
    const error = object(providerError);
    throw mapProviderError(boundedString(error.Code, 128), response.status);
  }
  if (!response.ok) {
    throw new DnsPodProviderError(response.status >= 500 || response.status === 429
      ? "DNS_PROVIDER_UNAVAILABLE" : "DNS_PROVIDER_REQUEST_REJECTED", response.status >= 500 || response.status === 429);
  }
  return payload;
}

function zonePayload(zone: Pick<DnsPodZone, "providerZoneId" | "name">): DnsPodObject {
  return { Domain: normalizeDnsProviderZoneName(zone.name), DomainId: providerIdNumber(zone.providerZoneId) };
}

function normalizedSubdomain(value: unknown): string {
  const name = boundedString(value, 253).toLowerCase();
  if (name !== "@" && name.split(".").some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw new DnsPodProviderError("DNS_PROVIDER_REQUEST_REJECTED");
  }
  return name;
}

function safeRequestString(value: unknown, maximum: number): string {
  if (typeof value !== "string") throw new DnsPodProviderError("DNS_PROVIDER_REQUEST_REJECTED");
  const text = value.trim();
  if (!text || Buffer.byteLength(text, "utf8") > maximum || /[\u0000-\u001f\u007f]/.test(text)) {
    throw new DnsPodProviderError("DNS_PROVIDER_REQUEST_REJECTED");
  }
  return text;
}

export class DnsPodProviderClient {
  private readonly credentials: DnsPodCredentials;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private readonly sleep: (milliseconds: number) => Promise<void>;
  private readonly requestTimeoutMs: number;
  private readonly totalTimeoutMs: number;
  private readonly maxResponseBytes: number;
  private readonly maxPages: number;

  constructor(options: {
    credentials: DnsPodCredentials;
    fetchImpl?: typeof fetch;
    now?: () => number;
    sleep?: (milliseconds: number) => Promise<void>;
    requestTimeoutMs?: number;
    totalTimeoutMs?: number;
    maxResponseBytes?: number;
    maxPages?: number;
  }) {
    this.credentials = validCredentials(options.credentials);
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.now = options.now ?? Date.now;
    this.sleep = options.sleep ?? ((milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)));
    this.requestTimeoutMs = this.optionInteger(options.requestTimeoutMs, DEFAULT_TIMEOUT_MS, 100, 60_000);
    this.totalTimeoutMs = this.optionInteger(options.totalTimeoutMs, DEFAULT_TOTAL_TIMEOUT_MS, 100, 120_000);
    this.maxResponseBytes = this.optionInteger(options.maxResponseBytes, DEFAULT_MAX_RESPONSE_BYTES, 128, 4 * 1024 * 1024);
    this.maxPages = this.optionInteger(options.maxPages, DEFAULT_MAX_PAGES, 1, 50);
  }

  private optionInteger(value: number | undefined, fallback: number, minimum: number, maximum: number): number {
    const parsed = value ?? fallback;
    if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
      throw new DnsPodProviderError("DNS_PROVIDER_INVALID");
    }
    return parsed;
  }

  private async call(action: DnsPodAction, payload: DnsPodObject): Promise<DnsPodObject> {
    const readOnly = READ_ACTION_SET.has(action);
    const deadline = performance.now() + this.totalTimeoutMs;
    for (let attempt = 0; attempt < (readOnly ? 3 : 1); attempt += 1) {
      const remainingMs = Math.floor(deadline - performance.now());
      if (remainingMs <= 0) throw new DnsPodProviderError("DNS_PROVIDER_UNAVAILABLE");
      const timestamp = Math.floor(this.now() / 1_000);
      const request = buildDnsPodTc3Request({ credentials: this.credentials, action, payload, timestamp });
      try {
        const response = await this.fetchImpl(request.url, {
          ...request.init,
          signal: AbortSignal.timeout(Math.max(1, Math.min(this.requestTimeoutMs, remainingMs))),
        });
        try {
          return await readBoundedResponse(response, this.maxResponseBytes);
        } catch (cause) {
          if (response.status === 429 || response.status >= 500) {
            throw new DnsPodProviderError("DNS_PROVIDER_UNAVAILABLE", true, !readOnly);
          }
          throw cause;
        }
      } catch (cause) {
        const error = cause instanceof DnsPodProviderError
          ? cause
          : new DnsPodProviderError("DNS_PROVIDER_UNAVAILABLE", true, !readOnly);
        if (readOnly && error.retryable && attempt < 2) {
          await this.sleep(400 * (2 ** attempt));
          continue;
        }
        if (!readOnly) {
          const ambiguousWrite = error.ambiguousWrite || error.retryable
            || error.code === "DNS_PROVIDER_INVALID_RESPONSE"
            || error.code === "DNS_PROVIDER_UNAVAILABLE"
            || !(cause instanceof DnsPodProviderError);
          throw new DnsPodProviderError(error.code, false, ambiguousWrite);
        }
        throw new DnsPodProviderError(error.code, false, error.ambiguousWrite);
      }
    }
    throw new DnsPodProviderError("DNS_PROVIDER_UNAVAILABLE");
  }

  async validateAccount(): Promise<void> {
    const response = await this.call("DescribeUserDetail", {});
    object(response.UserInfo);
  }

  async listZones(): Promise<DnsPodZone[]> {
    const zones = new Map<string, DnsPodZone>();
    let offset = 0;
    for (let page = 0; page < this.maxPages; page += 1) {
      const response = await this.call("DescribeDomainList", { Type: "ALL", Offset: offset, Limit: PAGE_SIZE });
      if (!Array.isArray(response.DomainList) || response.DomainList.length > PAGE_SIZE) invalidResponse();
      const totalInfo = object(response.DomainCountInfo);
      const total = nonnegativeInteger(totalInfo.AllTotal ?? totalInfo.DomainTotal);
      const batch = response.DomainList.map((entry) => {
        const row = object(entry);
        const zone: DnsPodZone = {
          providerZoneId: providerId(row.DomainId),
          name: normalizeDnsProviderZoneName(row.Name),
          grade: boundedString(row.Grade, 64),
          status: optionalString(row.Status, 32),
        };
        const previous = zones.get(zone.providerZoneId);
        if (previous && JSON.stringify(previous) !== JSON.stringify(zone)) invalidResponse();
        zones.set(zone.providerZoneId, zone);
        return zone;
      });
      offset += batch.length;
      if (offset >= total) return [...zones.values()];
      if (batch.length < PAGE_SIZE) invalidResponse();
    }
    invalidResponse();
  }

  async listRecordCatalog(zone: DnsPodZone): Promise<{ lines: DnsPodRecordLine[]; recordTypes: string[] }> {
    const domainGrade = safeRequestString(zone.grade, 64);
    const base = zonePayload(zone);
    const [lineResponse, typeResponse] = await Promise.all([
      this.call("DescribeRecordLineList", { ...base, DomainGrade: domainGrade }),
      this.call("DescribeRecordType", { DomainGrade: domainGrade }),
    ]);
    const combined = [lineResponse.LineList, lineResponse.LineGroupList].flatMap((value) => {
      if (value === undefined) return [];
      if (!Array.isArray(value) || value.length > 1_000) invalidResponse();
      return value;
    });
    const lineMap = new Map<string, DnsPodRecordLine>();
    for (const entry of combined) {
      const row = object(entry);
      const line = { providerLineId: boundedString(String(row.LineId ?? ""), 128), name: boundedString(row.Name, 128) };
      const previous = lineMap.get(line.providerLineId);
      if (previous && previous.name !== line.name) invalidResponse();
      lineMap.set(line.providerLineId, line);
    }
    if (!Array.isArray(typeResponse.TypeList) || typeResponse.TypeList.length > 64) invalidResponse();
    const recordTypes = [...new Set(typeResponse.TypeList.map((value) => boundedString(value, 16).toUpperCase()))].sort();
    return { lines: [...lineMap.values()], recordTypes };
  }

  async listRecords(input: { zone: DnsPodZone; subdomain?: string; recordType?: string }): Promise<DnsPodRecord[]> {
    const records = new Map<string, DnsPodRecord>();
    let offset = 0;
    for (let page = 0; page < this.maxPages; page += 1) {
      const payload: DnsPodObject = { ...zonePayload(input.zone), Offset: offset, Limit: PAGE_SIZE, ErrorOnEmpty: "no" };
      if (input.subdomain !== undefined) payload.SubDomain = normalizedSubdomain(input.subdomain);
      if (input.recordType !== undefined) payload.RecordType = safeRequestString(input.recordType, 16).toUpperCase();
      const response = await this.call("DescribeRecordList", payload);
      if (!Array.isArray(response.RecordList) || response.RecordList.length > PAGE_SIZE) invalidResponse();
      const totalInfo = object(response.RecordCountInfo);
      const total = nonnegativeInteger(totalInfo.TotalCount ?? totalInfo.ListCount ?? response.RecordList.length);
      const batch = response.RecordList.map((entry) => this.normalizeListedRecord(entry));
      for (const record of batch) {
        const previous = records.get(record.providerRecordId);
        if (previous && JSON.stringify(previous) !== JSON.stringify(record)) invalidResponse();
        records.set(record.providerRecordId, record);
      }
      offset += batch.length;
      if (offset >= total) return [...records.values()];
      if (batch.length < PAGE_SIZE) invalidResponse();
    }
    invalidResponse();
  }

  async getRecord(input: { zone: DnsPodZone; providerRecordId: string }): Promise<DnsPodRecord> {
    const response = await this.call("DescribeRecord", {
      ...zonePayload(input.zone), RecordId: providerIdNumber(input.providerRecordId),
    });
    return this.normalizeRecordInfo(response.RecordInfo);
  }

  async createRecord(input: DnsPodRecordWriteInput): Promise<{ providerRecordId: string }> {
    const response = await this.call("CreateRecord", this.recordWritePayload(input));
    try { return { providerRecordId: providerId(response.RecordId) }; } catch {
      throw new DnsPodProviderError("DNS_PROVIDER_INVALID_RESPONSE", false, true);
    }
  }

  async updateRecord(input: DnsPodRecordWriteInput & { providerRecordId: string }): Promise<{ providerRecordId: string }> {
    const response = await this.call("ModifyRecord", {
      ...this.recordWritePayload(input), RecordId: providerIdNumber(input.providerRecordId),
    });
    try { return { providerRecordId: providerId(response.RecordId) }; } catch {
      throw new DnsPodProviderError("DNS_PROVIDER_INVALID_RESPONSE", false, true);
    }
  }

  async deleteRecord(input: { zone: DnsPodZone; providerRecordId: string }): Promise<void> {
    await this.call("DeleteRecord", {
      ...zonePayload(input.zone), RecordId: providerIdNumber(input.providerRecordId),
    });
  }

  private normalizeListedRecord(value: unknown): DnsPodRecord {
    const row = object(value);
    const ttl = positiveInteger(row.TTL);
    if (ttl > 604_800) invalidResponse();
    return {
      providerRecordId: providerId(row.RecordId),
      subdomain: boundedString(row.Name, 253),
      recordType: boundedString(row.Type, 16).toUpperCase(),
      providerLineId: boundedString(String(row.LineId ?? ""), 128),
      lineName: boundedString(row.Line, 128),
      value: boundedString(row.Value, 2_048),
      ttl,
      status: optionalString(row.Status, 32),
    };
  }

  private normalizeRecordInfo(value: unknown): DnsPodRecord {
    const row = object(value);
    const ttl = positiveInteger(row.TTL);
    if (ttl > 604_800) invalidResponse();
    const enabled = row.Enabled;
    if (enabled !== undefined && enabled !== null && enabled !== 0 && enabled !== 1) invalidResponse();
    return {
      providerRecordId: providerId(row.Id),
      subdomain: boundedString(row.SubDomain, 253),
      recordType: boundedString(row.RecordType, 16).toUpperCase(),
      providerLineId: boundedString(String(row.RecordLineId ?? ""), 128),
      lineName: boundedString(row.RecordLine, 128),
      value: boundedString(row.Value, 2_048),
      ttl,
      status: enabled === 1 ? "ENABLE" : enabled === 0 ? "DISABLE" : null,
    };
  }

  private recordWritePayload(input: DnsPodRecordWriteInput): DnsPodObject {
    const recordType = safeRequestString(input.recordType, 16).toUpperCase();
    if (!new Set(["A", "AAAA", "CNAME"]).has(recordType)) {
      throw new DnsPodProviderError("DNS_PROVIDER_REQUEST_REJECTED");
    }
    const ttl = Number(input.ttl);
    if (!Number.isSafeInteger(ttl) || ttl < 1 || ttl > 604_800) {
      throw new DnsPodProviderError("DNS_PROVIDER_REQUEST_REJECTED");
    }
    let value = safeRequestString(input.value, 2_048);
    if ((recordType === "A" && isIP(value) !== 4) || (recordType === "AAAA" && isIP(value) !== 6)) {
      throw new DnsPodProviderError("DNS_PROVIDER_REQUEST_REJECTED");
    }
    if (recordType === "CNAME") {
      try { value = normalizeDnsProviderZoneName(value); } catch { throw new DnsPodProviderError("DNS_PROVIDER_REQUEST_REJECTED"); }
    }
    return {
      ...zonePayload(input.zone),
      SubDomain: normalizedSubdomain(input.subdomain),
      RecordType: recordType,
      RecordLine: safeRequestString(input.line.name, 128),
      RecordLineId: safeRequestString(input.line.providerLineId, 128),
      Value: value,
      TTL: ttl,
    };
  }
}

export type DnsPodRecordWriteInput = Readonly<{
  zone: DnsPodZone;
  subdomain: string;
  recordType: "A" | "AAAA" | "CNAME";
  line: DnsPodRecordLine;
  value: string;
  ttl: number;
}>;
