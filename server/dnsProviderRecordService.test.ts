import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("DNS record service lists records, protects revisions, and locks zones used by quick config", () => {
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
      await expectCode(service.createDnsProviderRecord({
        zoneId: zone.zoneId,
        subdomain: "blocked",
        recordType: "A",
        lineId: defaultLine.lineId,
        value: "1.1.1.1",
        ttl: 600,
      }, options), "DNS_ZONE_IN_USE");
      assert.equal(records.some((item) => item.subdomain === "blocked"), false);
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
