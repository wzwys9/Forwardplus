import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

// Exercise the persisted EDIT worker with a real database and an in-memory
// provider. No DNSPod credentials, requests, Agent, or panel process are needed.
const editScenario = String.raw`
  import assert from "node:assert/strict";
  import path from "node:path";
  import { pathToFileURL } from "node:url";

  const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
  const runtime = await load("server/dbRuntime.ts");
  const schema = await load("server/dbSchema.ts");
  const secrets = await load("server/xraySecretCrypto.ts");
  const repository = await load("server/repositories/dnsProviderRepository.ts");
  const provider = await load("server/dnsPodProviderClient.ts");
  const service = await load("server/xrayQuickConfigDnsApplyService.ts");
  const { computeXrayQuickConfigDnsTupleHash: tupleHash } = await load("server/xrayQuickConfigDnsTuple.ts");
  const scenario = process.env.FORWARDX_DNS_REUSE_SCENARIO;
  const creating = scenario === "create-replacements";
  const fqdn = "edge.example.com";
  const lineSpecs = [
    ["DEFAULT", "0", "默认"], ["TELECOM", "10=0", "电信"],
    ["UNICOM", "10=1", "联通"], ["MOBILE", "10=2", "移动"],
    ["EDUCATION", "10=3", "教育网"],
  ];
  const insert = async (table, row) => {
    const keys = Object.keys(row);
    await runtime.executeRaw(
      'INSERT INTO "' + table + '" (' + keys.map((key) => '"' + key + '"').join(", ") + ') VALUES (' + keys.map(() => "?").join(", ") + ')',
      keys.map((key) => row[key]),
    );
  };
  const tuple = (record) => ({ fqdn, recordType: record.recordType, providerLineId: record.providerLineId, value: record.value, ttl: record.ttl });

  try {
    await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
    await schema.ensureDatabaseSchema();
    const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
    await insert("users", { id: 1, username: "admin", password: "hash", role: "admin" });
    const account = await repository.saveVerifiedGlobalDnsProviderAccount({
      expectedBindingRevision: 1, expectedAccountRevision: null, name: "Test DNSPod",
      secretId: "fixture-secret-id", secretKey: "fixture-secret-key", createdByUserId: 1, verifiedAt: new Date(),
      zones: [{ providerZoneId: "42", name: "example.com", lines: lineSpecs.map(([, providerLineId, name]) => ({ providerLineId, name })) }],
    }, { keyring });
    const zone = (await repository.listGlobalDnsProviderZones())[0];
    const dnsAccountId = account.accountId;
    const zoneId = zone.zoneId;

    await insert("xray_quick_configs", {
      id: 1, configTag: "dns-reuse-config", targetType: "XRAY_INBOUND", xrayInboundId: 1,
      targetVersion: "1", dnsAccountId, zoneId, relativeName: "edge", fqdn,
      state: creating ? "APPLYING" : "UPDATING", revision: 2, activeTopologyRevisionId: creating ? null : 1, desiredTopologyRevisionId: 2,
      currentOperationId: 1, createdByUserId: 1,
    });
    for (const id of [1, 2]) await insert("xray_quick_config_topology_revisions", {
      id, quickConfigId: 1, revisionNumber: id, engine: "realm", targetAddress: "8.8.8.8",
      targetPort: 443, publicPort: 443, portAllocationId: 1, state: id === 1 ? "ACTIVE" : "DESIRED", createdByUserId: 1,
    });
    await insert("xray_quick_config_operations", {
      id: 1, operationTag: "dns-reuse-edit", quickConfigId: 1, type: creating ? "APPLY" : "EDIT", status: "RUNNING",
      phase: "APPLYING_DNS", activeSlot: 1, expectedRevision: 1,
      fromTopologyRevisionId: creating ? null : 1, toTopologyRevisionId: 2,
      requestSummaryJson: JSON.stringify(creating ? {} : { kind: "TOPOLOGY_EDIT" }),
      executionOwnerId: "fixture-worker", executionFence: 1,
      executionLeaseUntil: Date.now() + 300_000, createdByUserId: 1,
    });

    const oldRecords = (scenario === "changed-first" || creating ? lineSpecs.slice(0, 1) : lineSpecs)
      .flatMap(([lineCategory, providerLineId, lineName], lineIndex) => ["8.8.8.8", "1.1.1.1"].map((value, index) => ({
        providerRecordId: String(101 + lineIndex * 2 + index), subdomain: "edge", recordType: "A",
        providerLineId, lineName, value, ttl: 600, status: "ENABLE", lineCategory,
      })));
    const desired = scenario === "changed-first" || creating
      ? [{ ...oldRecords[1], value: "9.9.9.9" }, { ...oldRecords[0] }]
      : structuredClone(oldRecords);
    if (scenario === "new-ipv6") desired.splice(4, 0, {
      providerRecordId: null, subdomain: "edge", recordType: "AAAA", providerLineId: "10=0",
      lineName: "电信", value: "2001:4860:4860::8888", ttl: 600, status: "ENABLE", lineCategory: "TELECOM",
    });

    let nextRouteId = 1;
    const persistRecord = async (record, index, topologyRevisionId) => {
      const routeId = nextRouteId++;
      const id = topologyRevisionId === 1 ? 1 + index : 101 + index;
      await insert("xray_quick_config_routes", {
        id: routeId, routeTag: "route-" + routeId, quickConfigId: 1, topologyRevisionId,
        lineCategory: record.lineCategory, providerLineId: record.providerLineId,
        sourceType: "TARGET", addressFamily: record.recordType === "A" ? "IPV4" : "IPV6",
        address: record.value, routeMode: "DIRECT", sortOrder: index, state: "ACTIVE",
      });
      await insert("xray_quick_config_dns_records", {
        id, quickConfigId: 1, routeId, dnsAccountId, zoneId, recordTag: "record-" + id,
        providerRecordId: topologyRevisionId === 1 ? record.providerRecordId : creating ? oldRecords[index].providerRecordId : null,
        ...tuple(record), status: topologyRevisionId === 1 ? "APPLIED" : "DESIRED",
        appliedRevision: topologyRevisionId, remoteTupleHash: tupleHash(tuple(record)),
      });
      return id;
    };
    for (const [index, record] of oldRecords.entries()) {
      if (!creating) await persistRecord(record, index, 1);
      await insert("xray_quick_config_dns_record_backups", {
        id: index + 1, operationId: 1, dnsAccountId, zoneId, providerRecordId: record.providerRecordId,
        ...tuple(record), remoteTupleHash: tupleHash(tuple(record)), snapshotOrder: index, state: "CAPTURED",
      });
    }
    let nextStepId = 1;
    const addStep = async (kind, subjectId) => {
      const id = nextStepId++;
      await insert("xray_quick_config_operation_steps", {
        id, operationId: 1, stepKey: "step-" + id, kind, subjectType: "DNS_RECORD",
        subjectId: String(subjectId), status: "PENDING", idempotencyKey: "dns-reuse-step-" + id, requestSummaryJson: "{}",
      });
    };
    for (const [index, record] of desired.entries()) {
      const id = await persistRecord(record, index, 2);
      await addStep(record.recordType === "AAAA" ? "DNS_CREATE" : "DNS_REPLACE", id);
      await addStep("DNS_VERIFY", id);
    }
    for (let index = 0; index < oldRecords.length + desired.length; index++) await addStep("DNS_RESTORE", index + 1);

    let remote = oldRecords.map(({ lineCategory, ...record }) => structuredClone(record));
    const before = structuredClone(remote);
    let nextProviderId = 1000;
    const writes = [];
    const fromInput = (input, providerRecordId) => ({
      providerRecordId, subdomain: input.subdomain, recordType: input.recordType,
      providerLineId: input.line.providerLineId, lineName: input.line.name,
      value: input.value, ttl: input.ttl, status: "ENABLE",
    });
    const client = {
      listRecords: async () => structuredClone(remote),
      getRecord: async ({ providerRecordId }) => {
        const record = remote.find((item) => item.providerRecordId === providerRecordId);
        if (!record) throw new provider.DnsPodProviderError("DNS_PROVIDER_RECORD_NOT_FOUND");
        return structuredClone(record);
      },
      createRecord: async (input) => {
        const providerRecordId = String(nextProviderId++);
        writes.push({ kind: "CREATE", providerRecordId });
        remote.push(fromInput(input, providerRecordId));
        return { providerRecordId };
      },
      updateRecord: async (input) => {
        const index = remote.findIndex((item) => item.providerRecordId === input.providerRecordId);
        assert.ok(index >= 0);
        writes.push({ kind: "UPDATE", providerRecordId: input.providerRecordId });
        remote[index] = fromInput(input, input.providerRecordId);
        return { providerRecordId: input.providerRecordId };
      },
      deleteRecord: async ({ providerRecordId }) => {
        writes.push({ kind: "DELETE", providerRecordId });
        remote = remote.filter((item) => item.providerRecordId !== providerRecordId);
      },
    };
    const result = await service.applyQuickConfigDnsOperation(1, {
      executionOwnerId: "fixture-worker", executionFence: 1,
    }, { clientFactory: () => client });
    const failedSteps = result.status === "SUCCESS" ? [] : await runtime.queryRaw(
      'SELECT kind, status, errorCode FROM xray_quick_config_operation_steps WHERE errorCode IS NOT NULL',
    );
    assert.equal(result.status, "SUCCESS", JSON.stringify({ result, writes, failedSteps }));
    const applied = await runtime.queryRaw('SELECT * FROM xray_quick_config_dns_records WHERE appliedRevision = 2 ORDER BY id');
    assert.equal(applied.length, desired.length);
    assert.ok(applied.every((record) => record.status === "APPLIED" && record.lastVerifiedAt != null));

    if (creating) {
      // The ordinary APPLY seed preassigns provider IDs in requested order.
      // Preserve its existing replacement behavior; EDIT-only reservations must
      // not reject a valid explicitly confirmed initial replacement.
      assert.deepEqual(writes, [{ kind: "UPDATE", providerRecordId: "101" }, { kind: "UPDATE", providerRecordId: "102" }]);
      assert.equal(remote.find((record) => record.providerRecordId === "101").value, "9.9.9.9");
      assert.equal(remote.find((record) => record.providerRecordId === "102").value, "8.8.8.8");
    } else if (scenario === "changed-first") {
      assert.deepEqual(writes, [{ kind: "UPDATE", providerRecordId: "102" }], "changed records must not consume a later unchanged record's provider ID");
      assert.deepEqual(remote.find((record) => record.providerRecordId === "101"), before[0]);
      assert.equal(applied.find((record) => record.value === "8.8.8.8").providerRecordId, "101");
    } else {
      assert.deepEqual(writes, scenario === "new-ipv6" ? [{ kind: "CREATE", providerRecordId: "1000" }] : []);
      assert.deepEqual(remote.filter((record) => record.recordType === "A"), before);
      for (const record of before) {
        assert.equal(applied.find((item) => tupleHash(tuple(item)) === tupleHash(tuple(record))).providerRecordId, record.providerRecordId);
      }
    }
    // Ownership moves to the new topology; old cleanup cannot delete reused IDs.
    const previous = await runtime.queryRaw('SELECT * FROM xray_quick_config_dns_records WHERE appliedRevision = 1');
    assert.ok(previous.every((record) => record.providerRecordId === null && record.status === "DELETE_PENDING"));
  } finally {
    await runtime.closeDatabase();
  }
`;

function runEditScenario(scenario: string): void {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardplus-dns-reuse-"));
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", editScenario], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        DATABASE_TYPE: "sqlite",
        FORWARDX_TEST_DB: path.join(directory, "panel.db"),
        XRAY_MASTER_KEY_PATH: path.join(directory, "xray-master.key"),
        FORWARDX_DNS_REUSE_SCENARIO: scenario,
      },
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

test("same-domain edit verifies ten unchanged managed records without provider writes", () => {
  runEditScenario("unchanged");
});

test("same-domain edit keeps ten managed A record IDs and only creates the added AAAA record", () => {
  runEditScenario("new-ipv6");
});

test("same-domain edit reserves unchanged record IDs before an earlier changed record is replaced", () => {
  runEditScenario("changed-first");
});

test("ordinary creation retains preassigned provider IDs when replacing confirmed records", () => {
  runEditScenario("create-replacements");
});
