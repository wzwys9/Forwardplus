import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("DNS record service groups names and protects only used subdomains, including both sides of a rename", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-dns-record-service-"));
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";

    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const runtime = await load("server/dbRuntime.ts");
    const schema = await load("server/dbSchema.ts");
    const secrets = await load("server/xraySecretCrypto.ts");
    const provider = await load("server/dnsPodProviderClient.ts");
    const repository = await load("server/repositories/dnsProviderRepository.ts");
    const service = await load("server/dnsProviderRecordService.ts");
    const expectCode = async (promise, code) => assert.rejects(
      promise,
      (error) => error?.code === code || error?.message === code,
    );

    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      const account = await repository.saveVerifiedGlobalDnsProviderAccount({
        expectedBindingRevision: 1,
        expectedAccountRevision: null,
        name: "Primary DNSPod",
        secretId: "secret-id-value",
        secretKey: "secret-key-value",
        createdByUserId: 1,
        verifiedAt: new Date(),
        zones: [{
          providerZoneId: "42",
          name: "example.com",
          lines: [
            { providerLineId: "0", name: "默认" },
            { providerLineId: "10=0", name: "电信" },
            { providerLineId: "10=1", name: "联通" },
            { providerLineId: "10=2", name: "移动" },
            { providerLineId: "10=3", name: "教育网" },
          ],
        }],
      }, { keyring });
      const zone = (await repository.listGlobalDnsProviderZones())[0];
      const defaultLine = zone.lines.find((line) => line.providerLineId === "0");
      let records = [{
        providerRecordId: "101",
        subdomain: "www",
        recordType: "A",
        providerLineId: "0",
        lineName: "默认",
        value: "8.8.8.8",
        ttl: 600,
        status: "ENABLE",
      }, {
        providerRecordId: "102",
        subdomain: "api",
        recordType: "CNAME",
        providerLineId: "0",
        lineName: "默认",
        value: "origin.example.com",
        ttl: 300,
        status: "ENABLE",
      }];
      let nextId = 103;
      let ambiguousCreate = false;
      const client = {
        listRecords: async () => structuredClone(records),
        getRecord: async ({ providerRecordId }) => {
          const record = records.find((item) => item.providerRecordId === providerRecordId);
          if (!record) throw Object.assign(new Error("DNS_PROVIDER_RECORD_NOT_FOUND"), { code: "DNS_PROVIDER_RECORD_NOT_FOUND" });
          return structuredClone(record);
        },
        createRecord: async (input) => {
          if (ambiguousCreate) {
            throw new provider.DnsPodProviderError("DNS_PROVIDER_UNAVAILABLE", false, true);
          }
          const providerRecordId = String(nextId++);
          records.push({
            providerRecordId,
            subdomain: input.subdomain,
            recordType: input.recordType,
            providerLineId: input.line.providerLineId,
            lineName: input.line.name,
            value: input.value,
            ttl: input.ttl,
            status: "ENABLE",
          });
          return { providerRecordId };
        },
        updateRecord: async (input) => {
          const index = records.findIndex((item) => item.providerRecordId === input.providerRecordId);
          records[index] = {
            providerRecordId: input.providerRecordId,
            subdomain: input.subdomain,
            recordType: input.recordType,
            providerLineId: input.line.providerLineId,
            lineName: input.line.name,
            value: input.value,
            ttl: input.ttl,
            status: "ENABLE",
          };
          return { providerRecordId: input.providerRecordId };
        },
        deleteRecord: async ({ providerRecordId }) => {
          records = records.filter((item) => item.providerRecordId !== providerRecordId);
        },
      };
      const options = { clientFactory: () => client, keyring };

      const listed = await service.listDnsProviderRecords({
        zoneId: zone.zoneId,
        search: "www",
        page: 1,
        pageSize: 20,
      }, options);
      assert.equal(listed.total, 1);
      assert.equal(listed.zone.name, "example.com");
      assert.equal(listed.zone.inUse, false);
      assert.match(listed.items[0].recordRevision, /^[a-f0-9]{64}$/);
      assert.equal(JSON.stringify(listed).includes("secret-id-value"), false);

      const created = await service.createDnsProviderRecord({
        zoneId: zone.zoneId,
        subdomain: "edge",
        recordType: "AAAA",
        lineId: defaultLine.lineId,
        value: "2001:4860:4860::8888",
        ttl: 600,
      }, options);
      assert.equal(created.providerRecordId, "103");

      const beforeUpdate = await service.listDnsProviderRecords({ zoneId: zone.zoneId, page: 1, pageSize: 20 }, options);
      const edge = beforeUpdate.items.find((item) => item.providerRecordId === "103");
      await service.updateDnsProviderRecord({
        zoneId: zone.zoneId,
        providerRecordId: edge.providerRecordId,
        expectedRecordRevision: edge.recordRevision,
        subdomain: "edge-v2",
        recordType: "AAAA",
        lineId: defaultLine.lineId,
        value: "2001:4860:4860::8844",
        ttl: 300,
      }, options);
      assert.equal(records.find((item) => item.providerRecordId === "103").subdomain, "edge-v2");

      const current = await service.listDnsProviderRecords({ zoneId: zone.zoneId, page: 1, pageSize: 20 }, options);
      const changed = current.items.find((item) => item.providerRecordId === "103");
      records.find((item) => item.providerRecordId === "103").ttl = 120;
      await expectCode(service.removeDnsProviderRecord({
        zoneId: zone.zoneId,
        providerRecordId: "103",
        expectedRecordRevision: changed.recordRevision,
      }, options), "DNS_RECORD_CHANGED");
      assert.equal(records.some((item) => item.providerRecordId === "103"), true);

      const refreshed = await service.listDnsProviderRecords({ zoneId: zone.zoneId, page: 1, pageSize: 20 }, options);
      const removable = refreshed.items.find((item) => item.providerRecordId === "103");
      await service.removeDnsProviderRecord({
        zoneId: zone.zoneId,
        providerRecordId: "103",
        expectedRecordRevision: removable.recordRevision,
      }, options);
      assert.equal(records.some((item) => item.providerRecordId === "103"), false);

      ambiguousCreate = true;
      await expectCode(service.createDnsProviderRecord({
        zoneId: zone.zoneId,
        subdomain: "uncertain",
        recordType: "A",
        lineId: defaultLine.lineId,
        value: "1.1.1.1",
        ttl: 600,
      }, options), "DNS_WRITE_UNCERTAIN");
      ambiguousCreate = false;

      await runtime.executeRaw(
        "INSERT INTO xray_quick_configs "
          + "(configTag, targetType, targetVersion, dnsAccountId, zoneId, relativeName, fqdn, state, revision, createdByUserId, createdAt, updatedAt) "
          + "VALUES (?, 'EXTERNAL_PROXY_NODE', ?, ?, ?, 'managed', 'managed.example.com', 'ACTIVE', 1, 1, ?, ?)",
        ["quick-config-zone-lock", "b".repeat(64), account.accountId, zone.zoneId, new Date(), new Date()],
      );
      const readOnlyList = await service.listDnsProviderRecords({ zoneId: zone.zoneId, page: 1, pageSize: 20 }, options);
      assert.equal(readOnlyList.zone.inUse, true);
      const free = await service.createDnsProviderRecord({
        zoneId: zone.zoneId, subdomain: "free", recordType: "A",
        lineId: defaultLine.lineId, value: "1.1.1.1", ttl: 600,
      }, options);
      assert.ok(free.providerRecordId);
      await expectCode(service.createDnsProviderRecord({
        zoneId: zone.zoneId,
        subdomain: "MANAGED",
        recordType: "A",
        lineId: defaultLine.lineId,
        value: "1.1.1.1",
        ttl: 600,
      }, options), "DNS_SUBDOMAIN_IN_USE");
      assert.equal(records.some((item) => item.subdomain === "managed"), false);

      await service.createDnsProviderRecord({
        zoneId: zone.zoneId, subdomain: "www", recordType: "AAAA",
        lineId: defaultLine.lineId, value: "2001:4860:4860::8888", ttl: 600,
      }, options);
      const groups = await service.listDnsProviderRecordGroups({ zoneId: zone.zoneId, pageSize: 100 }, options);
      assert.equal(groups.items.find((g) => g.subdomain === "www").recordCount, 2);
      assert.deepEqual(groups.items.find((g) => g.subdomain === "www").recordTypes, ["A", "AAAA"]);
      assert.equal(groups.items.find((g) => g.subdomain === "managed").recordCount, 0);
      assert.equal(groups.items.find((g) => g.subdomain === "managed").inUse, true);
      const matched = await service.listDnsProviderRecordGroups({ zoneId: zone.zoneId, search: "8.8.8.8" }, options);
      assert.equal(matched.items[0].recordCount, 2);
      const paged = await service.listDnsProviderRecordGroups({ zoneId: zone.zoneId, pageSize: 1, page: 2 }, options);
      assert.equal(paged.total, groups.total);
      assert.equal(paged.items[0].fqdn, groups.items[1].fqdn);
      const detail = await service.listDnsProviderRecords({ zoneId: zone.zoneId, subdomain: "www" }, options);
      assert.equal(detail.total, 2);
      assert.equal(detail.subdomain.inUse, false);
      const exactMissing = await service.listDnsProviderRecords({ zoneId: zone.zoneId, subdomain: "ww" }, options);
      assert.equal(exactMissing.total, 0);
      const www = detail.items.find((r) => r.recordType === "A");
      await expectCode(service.updateDnsProviderRecord({
        zoneId: zone.zoneId, providerRecordId: www.providerRecordId,
        expectedRecordRevision: www.recordRevision, subdomain: "managed",
        recordType: "A", lineId: defaultLine.lineId, value: "1.1.1.1", ttl: 600,
      }, options), "DNS_SUBDOMAIN_IN_USE");

      records.push({ ...records[0], providerRecordId: "900", subdomain: "managed" });
      const locked = await service.listDnsProviderRecords({ zoneId: zone.zoneId, subdomain: "managed" }, options);
      assert.equal(locked.items[0].inUse, true);
      assert.equal(locked.subdomain.inUse, true);
      await expectCode(service.updateDnsProviderRecord({
        zoneId: zone.zoneId, providerRecordId: "900", expectedRecordRevision: locked.items[0].recordRevision,
        subdomain: "renamed", recordType: "A", lineId: defaultLine.lineId, value: "1.1.1.1", ttl: 600,
      }, options), "DNS_SUBDOMAIN_IN_USE");
      await expectCode(service.removeDnsProviderRecord({
        zoneId: zone.zoneId, providerRecordId: "900", expectedRecordRevision: locked.items[0].recordRevision,
      }, options), "DNS_SUBDOMAIN_IN_USE");

      const qc = (await runtime.queryRaw("SELECT id FROM xray_quick_configs"))[0];
      await runtime.executeRaw(
        "INSERT INTO xray_quick_config_domain_claims (claimKey, dnsAccountId, zoneId, normalizedRelativeName, quickConfigId, revision, createdAt, updatedAt) VALUES (?, ?, ?, 'next', ?, 1, ?, ?)",
        ["c".repeat(64), account.accountId, zone.zoneId, qc.id, new Date(), new Date()],
      );
      await expectCode(service.createDnsProviderRecord({
        zoneId: zone.zoneId, subdomain: "next", recordType: "A",
        lineId: defaultLine.lineId, value: "1.1.1.1", ttl: 600,
      }, options), "DNS_SUBDOMAIN_IN_USE");
      await runtime.executeRaw(
        "INSERT INTO xray_quick_config_dns_records (quickConfigId, routeId, dnsAccountId, zoneId, recordTag, fqdn, recordType, providerLineId, value, ttl, status, appliedRevision, remoteTupleHash, createdAt, updatedAt) VALUES (?, 1, ?, ?, 'old-dns', 'old.example.com', 'A', '0', '1.1.1.1', 600, 'DELETE_PENDING', 1, ?, ?, ?)",
        [qc.id, account.accountId, zone.zoneId, "d".repeat(64), new Date(), new Date()],
      );
      await runtime.executeRaw("UPDATE xray_quick_configs SET state = 'REMOVED' WHERE id = ?", [qc.id]);
      await expectCode(service.createDnsProviderRecord({
        zoneId: zone.zoneId, subdomain: "old", recordType: "A",
        lineId: defaultLine.lineId, value: "1.1.1.1", ttl: 600,
      }, options), "DNS_SUBDOMAIN_IN_USE");
      await runtime.executeRaw("UPDATE xray_quick_config_dns_records SET status = 'REMOVED'");
      const operationId = await runtime.insertAndGetId("xray_quick_config_operations", {
        operationTag: "domain-switch", quickConfigId: qc.id, type: "EDIT", status: "RUNNING",
        phase: "DNS_REMOVING", expectedRevision: 1, requestSummaryJson: "{}", createdByUserId: 1,
      });
      await runtime.insertAndGetId("xray_quick_config_dns_record_backups", {
        operationId, dnsAccountId: account.accountId, zoneId: zone.zoneId, providerRecordId: "800",
        fqdn: "retiring.example.com", recordType: "A", providerLineId: "0", value: "1.1.1.1",
        ttl: 600, remoteTupleHash: "e".repeat(64), snapshotOrder: 0, state: "CAPTURED",
      });
      await expectCode(service.createDnsProviderRecord({
        zoneId: zone.zoneId, subdomain: "retiring", recordType: "A",
        lineId: defaultLine.lineId, value: "1.1.1.1", ttl: 600,
      }, options), "DNS_SUBDOMAIN_IN_USE");
      await runtime.executeRaw("UPDATE xray_quick_config_operations SET status = 'SUCCESS', phase = 'COMPLETED' WHERE id = ?", [operationId]);
      const released = await service.listDnsProviderRecordGroups({ zoneId: zone.zoneId }, options);
      assert.equal(released.items.some((g) => g.inUse), false);
      await service.createDnsProviderRecord({
        zoneId: zone.zoneId, subdomain: "old", recordType: "A",
        lineId: defaultLine.lineId, value: "1.1.1.1", ttl: 600,
      }, options);

      const bulkBase = records[0];
      const bulkRecords = Array.from({ length: 105 }, (_, i) => ({
        ...bulkBase, providerRecordId: String(2000 + i), subdomain: "bulk",
        recordType: i === 103 ? "AAAA" : i === 104 ? "CNAME" : "A",
      }));
      records.push(...bulkRecords, ...["TXT", "MX", "NS"].map((recordType, i) => ({
        ...bulkBase, providerRecordId: String(3000 + i), subdomain: "bulk", recordType,
      })), { ...bulkBase, providerRecordId: "4000", subdomain: "bulk-other" });
      const beforePreview = structuredClone(records);
      const preview = await service.previewDnsProviderRecordDeletion({ zoneId: zone.zoneId, subdomain: "BULK" }, options);
      assert.equal(preview.fqdn, "bulk.example.com");
      assert.equal(preview.records.length, 105, "preview includes all pages");
      assert.equal(preview.preservedCount, 3);
      assert.ok(preview.records.every(r => r.subdomain === "bulk" && ["A", "AAAA", "CNAME"].includes(r.recordType)));
      assert.deepEqual(records, beforePreview, "preview must never write");
      for (const record of preview.records) {
        await service.removeDnsProviderRecord({ zoneId: zone.zoneId, providerRecordId: record.providerRecordId, expectedRecordRevision: record.recordRevision }, options);
      }
      assert.deepEqual(records.filter(r => r.subdomain === "bulk").map(r => r.recordType), ["TXT", "MX", "NS"]);
      assert.ok(records.some(r => r.providerRecordId === "4000"));
      const emptyPreview = await service.previewDnsProviderRecordDeletion({ zoneId: zone.zoneId, subdomain: "gone" }, options);
      assert.deepEqual(emptyPreview.records, []);
      assert.equal(emptyPreview.preservedCount, 0);
      await runtime.executeRaw("UPDATE xray_quick_configs SET state = 'ACTIVE', fqdn = 'bulk.example.com', relativeName = 'bulk' WHERE id = ?", [qc.id]);
      await expectCode(service.previewDnsProviderRecordDeletion({ zoneId: zone.zoneId, subdomain: "bulk" }, options), "DNS_SUBDOMAIN_IN_USE");

      const originalGet = client.getRecord;
      client.getRecord = async (input) => {
        const result = await originalGet(input);
        await runtime.executeRaw("UPDATE xray_quick_configs SET state = 'ACTIVE', fqdn = 'www.example.com', relativeName = 'www' WHERE id = ?", [qc.id]);
        return result;
      };
      await expectCode(service.removeDnsProviderRecord({
        zoneId: zone.zoneId, providerRecordId: www.providerRecordId, expectedRecordRevision: www.recordRevision,
      }, options), "DNS_SUBDOMAIN_IN_USE");
      assert.ok(records.some((r) => r.providerRecordId === www.providerRecordId));
    } finally {
      await runtime.closeDatabase();
    }
  `;

  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        DATABASE_TYPE: "sqlite",
        FORWARDX_TEST_DB: path.join(directory, "panel.db"),
        XRAY_MASTER_KEY_PATH: path.join(directory, "xray-master.key"),
      },
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
