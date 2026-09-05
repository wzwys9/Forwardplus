import assert from "node:assert/strict";
import test from "node:test";

import {
  buildDnsPodTc3Request,
  DnsPodProviderClient,
  DnsPodProviderError,
} from "./dnsPodProviderClient";

const CREDENTIALS = {
  secretId: "AKIDEXAMPLE",
  secretKey: "SECRETKEYEXAMPLE",
} as const;
const FIXED_TIMESTAMP_SECONDS = 1_551_113_065;

function dnsPodResponse(response: Record<string, unknown>, status = 200): Response {
  return new Response(JSON.stringify({ Response: response }), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function requestAction(init?: RequestInit): string {
  return new Headers(init?.headers).get("x-tc-action") ?? "";
}

function requestPayload(init?: RequestInit): Record<string, unknown> {
  const body = init?.body;
  assert.equal(typeof body, "string");
  return JSON.parse(body as string) as Record<string, unknown>;
}

function clientWith(
  fetchImpl: typeof fetch,
  overrides: Partial<ConstructorParameters<typeof DnsPodProviderClient>[0]> = {},
): DnsPodProviderClient {
  return new DnsPodProviderClient({
    credentials: CREDENTIALS,
    fetchImpl,
    now: () => FIXED_TIMESTAMP_SECONDS * 1_000,
    sleep: async () => undefined,
    ...overrides,
  });
}

test("TC3 request is deterministic, canonical, and fixed to the DNSPod endpoint", () => {
  const first = buildDnsPodTc3Request({
    credentials: CREDENTIALS,
    action: "DescribeDomainList",
    payload: { Type: "ALL", Offset: 0, Limit: 100 },
    timestamp: FIXED_TIMESTAMP_SECONDS,
  });
  const reordered = buildDnsPodTc3Request({
    credentials: CREDENTIALS,
    action: "DescribeDomainList",
    payload: { Limit: 100, Type: "ALL", Offset: 0 },
    timestamp: FIXED_TIMESTAMP_SECONDS,
  });

  assert.equal(first.url, "https://dnspod.tencentcloudapi.com/");
  assert.equal(first.init.method, "POST");
  assert.equal(first.init.redirect, "error");
  assert.equal(first.init.body, '{"Limit":100,"Offset":0,"Type":"ALL"}');
  assert.equal(reordered.init.body, first.init.body);
  assert.deepEqual(reordered.init.headers, first.init.headers);
  assert.equal(first.init.headers["Content-Type"], "application/json; charset=utf-8");
  assert.equal(first.init.headers["X-TC-Action"], "DescribeDomainList");
  assert.equal(first.init.headers["X-TC-Timestamp"], String(FIXED_TIMESTAMP_SECONDS));
  assert.equal(first.init.headers["X-TC-Version"], "2021-03-23");
  assert.equal(
    first.init.headers.Authorization,
    "TC3-HMAC-SHA256 Credential=AKIDEXAMPLE/2019-02-25/dnspod/tc3_request, "
      + "SignedHeaders=content-type;host;x-tc-action, "
      + "Signature=4bbe41b47c304d1bc824ceadac21e2dafb101c3b33430d3c8ebef5d1c68badce",
  );
});

test("zone pagination is bounded and fails closed instead of returning a truncated catalog", async () => {
  const offsets: number[] = [];
  const fetchImpl = (async (_input: string | URL | Request, init?: RequestInit) => {
    assert.equal(requestAction(init), "DescribeDomainList");
    const payload = requestPayload(init);
    offsets.push(Number(payload.Offset));
    const offset = Number(payload.Offset);
    return dnsPodResponse({
      DomainList: Array.from({ length: 100 }, (_, index) => ({
        DomainId: offset + index + 1,
        Name: `zone-${offset + index + 1}.example`,
        Grade: "DP_FREE",
      })),
      DomainCountInfo: { AllTotal: 201 },
      RequestId: `request-${offset}`,
    });
  }) as typeof fetch;

  await assert.rejects(
    clientWith(fetchImpl, { maxPages: 2 }).listZones(),
    (error: unknown) => error instanceof DnsPodProviderError
      && error.code === "DNS_PROVIDER_INVALID_RESPONSE",
  );
  assert.deepEqual(offsets, [0, 100]);
});

test("catalog, record listing, and CRUD preserve the dynamic DNSPod line id", async () => {
  const requests: Array<{ action: string; payload: Record<string, unknown> }> = [];
  const fetchImpl = (async (_input: string | URL | Request, init?: RequestInit) => {
    const action = requestAction(init);
    const payload = requestPayload(init);
    requests.push({ action, payload });
    switch (action) {
      case "DescribeRecordLineList":
        return dnsPodResponse({
          LineList: [{ LineId: "37=9", Name: "教育网" }],
          LineGroupList: [],
          RequestId: "line-request",
        });
      case "DescribeRecordType":
        return dnsPodResponse({ TypeList: ["A", "AAAA"], RequestId: "type-request" });
      case "DescribeRecordList":
        return dnsPodResponse({
          RecordList: [{
            RecordId: 770,
            Name: "edge",
            Type: "AAAA",
            LineId: "37=9",
            Line: "教育网",
            Value: "2001:4860:4860::8888",
            TTL: 600,
          }],
          RecordCountInfo: { TotalCount: 1 },
          RequestId: "list-request",
        });
      case "DescribeRecord":
        return dnsPodResponse({
          RecordInfo: {
            Id: 770,
            SubDomain: "edge",
            RecordType: "AAAA",
            RecordLineId: "37=9",
            RecordLine: "教育网",
            Value: "2001:4860:4860::8888",
            TTL: 600,
            Enabled: 1,
          },
          RequestId: "record-request",
        });
      case "CreateRecord":
        return dnsPodResponse({ RecordId: 771, RequestId: "create-request" });
      case "ModifyRecord":
        return dnsPodResponse({ RecordId: 771, RequestId: "modify-request" });
      case "DeleteRecord":
        return dnsPodResponse({ RecordId: 771, RequestId: "delete-request" });
      default:
        throw new Error(`unexpected action ${action}`);
    }
  }) as typeof fetch;
  const client = clientWith(fetchImpl);
  const zone = { providerZoneId: "42", name: "example.com", grade: "DP_FREE" };

  const catalog = await client.listRecordCatalog(zone);
  assert.deepEqual(catalog, {
    lines: [{ providerLineId: "37=9", name: "教育网" }],
    recordTypes: ["A", "AAAA"],
  });
  const records = await client.listRecords({ zone, subdomain: "edge", recordType: "AAAA" });
  assert.equal(records[0]?.providerRecordId, "770");
  assert.deepEqual(await client.getRecord({ zone, providerRecordId: "770" }), {
    ...records[0],
    status: "ENABLE",
  });

  const recordInput = {
    zone,
    subdomain: "edge",
    recordType: "AAAA" as const,
    line: catalog.lines[0]!,
    value: "2001:4860:4860::8888",
    ttl: 600,
  };
  assert.deepEqual(await client.createRecord(recordInput), { providerRecordId: "771" });
  assert.deepEqual(
    await client.updateRecord({ ...recordInput, providerRecordId: "771" }),
    { providerRecordId: "771" },
  );
  await client.deleteRecord({ zone, providerRecordId: "771" });

  const byAction = new Map(requests.map((request) => [request.action, request.payload]));
  assert.deepEqual(byAction.get("DescribeRecordList"), {
    Domain: "example.com",
    DomainId: 42,
    ErrorOnEmpty: "no",
    Limit: 100,
    Offset: 0,
    RecordType: "AAAA",
    SubDomain: "edge",
  });
  assert.deepEqual(byAction.get("DescribeRecord"), {
    Domain: "example.com",
    DomainId: 42,
    RecordId: 770,
  });
  for (const action of ["CreateRecord", "ModifyRecord"] as const) {
    assert.equal(byAction.get(action)?.RecordLineId, "37=9");
    assert.equal(byAction.get(action)?.RecordLine, "教育网");
  }
  assert.equal(byAction.get("DeleteRecord")?.RecordId, 771);
});

test("empty record lists require explicit valid counts and tolerate the null empty container", async () => {
  const zone = { providerZoneId: "42", name: "example.com", grade: "DP_FREE" };
  for (const RecordList of [[], null]) {
    const client = clientWith((async () => dnsPodResponse({
      RecordList, RecordCountInfo: { TotalCount: 0, ListCount: 0 }, RequestId: "empty-list",
    })) as typeof fetch);
    assert.deepEqual(await client.listRecords({ zone }), []);
  }
  for (const invalid of [
    { RecordList: null, RecordCountInfo: { TotalCount: 1 } },
    { RecordCountInfo: { TotalCount: 0 } },
    { RecordList: [], RecordCountInfo: null },
    { RecordList: {}, RecordCountInfo: { TotalCount: 0 } },
    { RecordList: [], RecordCountInfo: {} },
    { RecordList: [], RecordCountInfo: { TotalCount: null } },
    { RecordList: [], RecordCountInfo: { TotalCount: false } },
    { RecordList: [], RecordCountInfo: { ListCount: 0 } },
  ]) {
    const client = clientWith((async () => dnsPodResponse({ ...invalid, RequestId: "invalid-list" })) as typeof fetch);
    await assert.rejects(client.listRecords({ zone }), { code: "DNS_PROVIDER_INVALID_RESPONSE" });
  }
  const missingTotal = clientWith((async () => dnsPodResponse({
    RecordList: Array.from({ length: 100 }, (_, index) => ({
      RecordId: index + 1, Name: "edge", Type: "A", LineId: "0", Line: "默认", Value: "1.1.1.1", TTL: 600,
    })), RecordCountInfo: { ListCount: 100 }, RequestId: "missing-total",
  })) as typeof fetch);
  await assert.rejects(missingTotal.listRecords({ zone }), { code: "DNS_PROVIDER_INVALID_RESPONSE" });
});

test("record listing restarts a temporarily incomplete post-delete snapshot without returning partial data", async () => {
  const zone = { providerZoneId: "42", name: "example.com", grade: "DP_FREE" };
  const offsets: number[] = [];
  const record = (RecordId: number) => ({ RecordId, Name: "edge", Type: "A", LineId: "0", Line: "默认", Value: "1.1.1.1", TTL: 600 });
  const client = clientWith((async (_url, init) => {
    offsets.push(Number(requestPayload(init).Offset));
    const index = offsets.length;
    return dnsPodResponse({
      RecordList: index === 1 ? Array.from({ length: 100 }, (_, i) => record(i + 1)) : [],
      RecordCountInfo: { TotalCount: index === 3 ? 0 : 101 }, RequestId: "post-delete-list",
    });
  }) as typeof fetch);
  assert.deepEqual(await client.listRecords({ zone }), []);
  assert.deepEqual(offsets, [0, 100, 0]);

  let calls = 0;
  const incomplete = clientWith((async () => {
    calls += 1;
    return dnsPodResponse({ RecordList: [], RecordCountInfo: { TotalCount: 1 }, RequestId: "still-incomplete" });
  }) as typeof fetch);
  await assert.rejects(incomplete.listRecords({ zone }), { code: "DNS_PROVIDER_INVALID_RESPONSE" });
  assert.equal(calls, 3);
});

test("record snapshot retries share the original page limit", async () => {
  let calls = 0;
  const client = clientWith((async () => {
    calls += 1;
    return dnsPodResponse({ RecordList: [], RecordCountInfo: { TotalCount: 1 }, RequestId: "bounded-list" });
  }) as typeof fetch, { maxPages: 2 });
  await assert.rejects(client.listRecords({ zone: { providerZoneId: "42", name: "example.com", grade: "DP_FREE" } }), { code: "DNS_PROVIDER_INVALID_RESPONSE" });
  assert.equal(calls, 2);
});

test("a DNSPod-invalid deleted record id is normalized as a missing record without leaking provider details", async () => {
  const fetchImpl = (async (_input: string | URL | Request, init?: RequestInit) => {
    assert.equal(requestAction(init), "DescribeRecord");
    assert.deepEqual(requestPayload(init), {
      Domain: "example.com",
      DomainId: 42,
      RecordId: 770,
    });
    return dnsPodResponse({
      Error: {
        Code: "InvalidParameter.RecordIdInvalid",
        Message: "deleted record leaked SECRETKEYEXAMPLE and AKIDEXAMPLE",
      },
      RequestId: "deleted-record-request-id",
    }, 400);
  }) as typeof fetch;

  await assert.rejects(
    clientWith(fetchImpl).getRecord({
      zone: { providerZoneId: "42", name: "example.com", grade: "DP_FREE" },
      providerRecordId: "770",
    }),
    (error: unknown) => {
      assert.ok(error instanceof DnsPodProviderError);
      assert.equal(error.code, "DNS_PROVIDER_RECORD_NOT_FOUND");
      const exposed = `${String(error)} ${JSON.stringify(error)} ${error.stack ?? ""}`;
      assert.doesNotMatch(
        exposed,
        /SECRETKEYEXAMPLE|AKIDEXAMPLE|deleted-record-request-id|deleted record leaked|RecordIdInvalid/,
      );
      return true;
    },
  );
});

test("transient failures retry at most twice and permanent failures do not retry", async () => {
  const sleeps: number[] = [];
  let calls = 0;
  const transientFetch = (async () => {
    calls += 1;
    return dnsPodResponse({
      Error: {
        Code: "RequestLimitExceeded.RequestLimitExceeded",
        Message: "rate limited",
      },
      RequestId: `rate-${calls}`,
    }, 429);
  }) as typeof fetch;
  const transientClient = clientWith(transientFetch, {
    sleep: async (milliseconds) => { sleeps.push(milliseconds); },
  });

  await assert.rejects(
    transientClient.validateAccount(),
    (error: unknown) => error instanceof DnsPodProviderError
      && error.code === "DNS_PROVIDER_UNAVAILABLE",
  );
  assert.equal(calls, 3);
  assert.equal(sleeps.length, 2);

  let permanentCalls = 0;
  const permanentFetch = (async () => {
    permanentCalls += 1;
    return dnsPodResponse({
      Error: { Code: "AuthFailure.SecretIdNotFound", Message: "not found" },
      RequestId: "auth-request",
    }, 401);
  }) as typeof fetch;
  await assert.rejects(
    clientWith(permanentFetch).validateAccount(),
    (error: unknown) => error instanceof DnsPodProviderError
      && error.code === "DNS_PROVIDER_INVALID",
  );
  assert.equal(permanentCalls, 1);

  let ambiguousWriteCalls = 0;
  const ambiguousWriteFetch = (async () => {
    ambiguousWriteCalls += 1;
    return dnsPodResponse({ RequestId: "write-without-record-id" });
  }) as typeof fetch;
  await assert.rejects(
    clientWith(ambiguousWriteFetch).createRecord({
      zone: { providerZoneId: "42", name: "example.com", grade: "DP_FREE" },
      subdomain: "edge", recordType: "A",
      line: { providerLineId: "0", name: "默认" }, value: "8.8.8.8", ttl: 600,
    }),
    (error: unknown) => error instanceof DnsPodProviderError
      && error.code === "DNS_PROVIDER_INVALID_RESPONSE" && error.ambiguousWrite,
  );
  assert.equal(ambiguousWriteCalls, 1);
});

test("oversized and provider error responses expose only stable redacted errors", async (t) => {
  await t.test("response size limit", async () => {
    const leakedBody = `SECRETKEYEXAMPLE-${"x".repeat(1_024)}`;
    const fetchImpl = (async () => new Response(leakedBody, {
      status: 200,
      headers: {
        "content-type": "application/json",
        "content-length": String(Buffer.byteLength(leakedBody)),
      },
    })) as typeof fetch;

    await assert.rejects(
      clientWith(fetchImpl, { maxResponseBytes: 128 }).validateAccount(),
      (error: unknown) => {
        assert.ok(error instanceof DnsPodProviderError);
        assert.equal(error.code, "DNS_PROVIDER_INVALID_RESPONSE");
        const exposed = `${String(error)} ${JSON.stringify(error)} ${error.stack ?? ""}`;
        assert.doesNotMatch(exposed, /SECRETKEYEXAMPLE|AKIDEXAMPLE|x{64}/);
        return true;
      },
    );
  });

  await t.test("provider message and RequestId redaction", async () => {
    const fetchImpl = (async () => dnsPodResponse({
      Error: {
        Code: "InvalidParameter.DomainInvalid",
        Message: "provider leaked SECRETKEYEXAMPLE and AKIDEXAMPLE",
      },
      RequestId: "raw-provider-request-id",
    }, 400)) as typeof fetch;

    await assert.rejects(
      clientWith(fetchImpl).listZones(),
      (error: unknown) => {
        assert.ok(error instanceof DnsPodProviderError);
        assert.equal(error.code, "DNS_PROVIDER_REQUEST_REJECTED");
        const exposed = `${String(error)} ${JSON.stringify(error)} ${error.stack ?? ""}`;
        assert.doesNotMatch(
          exposed,
          /SECRETKEYEXAMPLE|AKIDEXAMPLE|raw-provider-request-id|provider leaked|DomainInvalid/,
        );
        return true;
      },
    );
  });
});
