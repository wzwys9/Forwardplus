import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("DNS provider repository stores an account-bound global account and exposes only safe catalog data", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-dns-provider-repository-"));
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";

    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const runtime = await load("server/dbRuntime.ts");
    const schema = await load("server/dbSchema.ts");
    const secrets = await load("server/xraySecretCrypto.ts");
    const repository = await load("server/repositories/dnsProviderRepository.ts");
    const expectCode = async (promise, code) => assert.rejects(
      promise,
      (error) => error?.code === code || error?.message === code,
    );

    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      await schema.ensureDatabaseSchema();
      const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw("INSERT OR REPLACE INTO system_settings (key, value, updatedAt) VALUES ('dnspod_token', 'legacy-ddns-bytes', 123)");

      const beforeDdns = await runtime.queryRaw("SELECT key, value, updatedAt FROM system_settings WHERE key = 'dnspod_token'");
      const verifiedAt = new Date();
      const created = await repository.saveVerifiedGlobalDnsProviderAccount({
        expectedBindingRevision: 1,
        expectedAccountRevision: null,
        name: "Primary DNSPod",
        secretId: "secret-id-value",
        secretKey: "secret-key-value",
        createdByUserId: 1,
        verifiedAt,
        zones: [{
          providerZoneId: "zone-1",
          name: "example.com",
          lines: [
            { providerLineId: "line-default", name: "默认" },
            { providerLineId: "line-telecom", name: "电信" },
            { providerLineId: "line-unicom", name: "联通" },
            { providerLineId: "line-mobile", name: "移动" },
            { providerLineId: "line-education", name: "教育网" },
            { providerLineId: "line-overseas", name: "境外" },
          ],
        }],
      }, { keyring });

      assert.equal(created.configured, true);
      assert.equal(created.accountRevision, 1);
      assert.equal(created.bindingRevision, 2);
      assert.equal(created.validationStatus, "VALID");
      assert.equal(created.secretIdMask, "••••••••");
      assert.equal(created.secretKeyMask, "••••••••");
      assert.equal(created.zoneCount, 1);
      const serialized = JSON.stringify(created);
      for (const forbidden of ["secret-id-value", "secret-key-value", "encryptedValue", "fingerprint", "keyVersion", "accountTag"]) {
        assert.equal(serialized.includes(forbidden), false, forbidden);
      }

      const global = await repository.getGlobalDnsProviderAccount();
      assert.deepEqual(global, created);
      await runtime.executeRaw("UPDATE dns_provider_accounts SET verificationExpiresAt = 1 WHERE id = ?", [created.accountId]);
      assert.equal((await repository.getGlobalDnsProviderAccount()).validationStatus, "EXPIRED");
      await runtime.executeRaw(
        "UPDATE dns_provider_accounts SET verificationExpiresAt = ? WHERE id = ?",
        [new Date(verifiedAt.getTime() + repository.DNS_PROVIDER_VERIFICATION_TTL_MS), created.accountId],
      );
      const credentials = await repository.loadGlobalDnsProviderCredentials({ keyring });
      assert.deepEqual(credentials, {
        accountId: created.accountId,
        accountRevision: 1,
        bindingRevision: 2,
        secretId: "secret-id-value",
        secretKey: "secret-key-value",
      });

      const catalog = await repository.listGlobalDnsProviderZones();
      assert.equal(catalog.length, 1);
      const stableZoneId = catalog[0].zoneId;
      const stableDefaultLineId = catalog[0].lines.find((line) => line.providerLineId === "line-default").lineId;
      assert.equal(catalog[0].catalogUsable, true);
      assert.equal(catalog[0].inUse, false);
      assert.equal(catalog[0].quickConfigReferenceCount, 0);
      assert.equal(catalog[0].managedRecordCount, 0);
      assert.equal(catalog[0].activeOperationCount, 0);
      assert.deepEqual(catalog[0].carrierLines.map((line) => [line.category, line.status]), [
        ["DEFAULT", "AVAILABLE"], ["TELECOM", "AVAILABLE"], ["UNICOM", "AVAILABLE"],
        ["MOBILE", "AVAILABLE"], ["EDUCATION", "AVAILABLE"],
      ]);
      assert.equal(catalog[0].lines.find((line) => line.providerLineId === "line-overseas").category, "OTHER");
      assert.match(catalog[0].catalogRevision, /^[a-f0-9]{64}$/);
      assert.equal(repository.computeDnsProviderCatalogRevision([{
        providerZoneId: "zone-1",
        name: "example.com",
        lines: [
          { providerLineId: "line-overseas", name: "境外" },
          { providerLineId: "line-education", name: "教育网" },
          { providerLineId: "line-mobile", name: "移动" },
          { providerLineId: "line-unicom", name: "联通" },
          { providerLineId: "line-telecom", name: "电信" },
          { providerLineId: "line-default", name: "默认" },
        ],
      }]), catalog[0].catalogRevision);

      await expectCode(repository.saveVerifiedGlobalDnsProviderAccount({
        expectedBindingRevision: 1,
        expectedAccountRevision: 1,
        name: "stale",
        secretId: "new-id",
        secretKey: "new-key",
        createdByUserId: 1,
        verifiedAt,
        zones: [{ providerZoneId: "zone-1", name: "example.com", lines: [] }],
      }, { keyring }), "DNS_PROVIDER_CONFLICT");

      const rotated = await repository.saveVerifiedGlobalDnsProviderAccount({
        expectedBindingRevision: 2,
        expectedAccountRevision: 1,
        name: "Primary DNSPod",
        secretId: "secret-id-value",
        secretKey: "secret-key-value",
        createdByUserId: 1,
        verifiedAt: new Date(),
        zones: [{
          providerZoneId: "zone-1",
          name: "example.com",
          lines: [
            { providerLineId: "line-default", name: "默认" },
            { providerLineId: "line-telecom-a", name: "电信" },
            { providerLineId: "line-telecom-b", name: "电信" },
            { providerLineId: "line-unicom", name: "联通" },
            { providerLineId: "line-mobile", name: "移动" },
          ],
        }],
      }, { keyring });
      assert.equal(rotated.accountRevision, 2);
      assert.equal(rotated.bindingRevision, 3);
      const unavailableCatalog = await repository.listGlobalDnsProviderZones();
      assert.equal(unavailableCatalog[0].zoneId, stableZoneId);
      assert.equal(unavailableCatalog[0].lines.find((line) => line.providerLineId === "line-default").lineId, stableDefaultLineId);
      assert.equal(unavailableCatalog[0].lines.find((line) => line.providerLineId === "line-education").status, "REMOVED");
      assert.equal(unavailableCatalog[0].catalogUsable, false);
      assert.equal(unavailableCatalog[0].carrierLines.find((line) => line.category === "TELECOM").status, "AMBIGUOUS");
      assert.equal(unavailableCatalog[0].carrierLines.find((line) => line.category === "EDUCATION").status, "MISSING");

      await runtime.executeRaw(
        "INSERT INTO xray_quick_configs "
          + "(configTag, targetType, targetVersion, dnsAccountId, zoneId, relativeName, fqdn, state, revision, createdByUserId, createdAt, updatedAt) "
          + "VALUES (?, 'EXTERNAL_PROXY_NODE', ?, ?, ?, 'edge', 'edge.example.com', 'ACTIVE', 1, 1, ?, ?)",
        ["quick-config-zone-lock", "a".repeat(64), created.accountId, stableZoneId, new Date(), new Date()],
      );
      const lockedCatalog = await repository.listGlobalDnsProviderZones();
      assert.equal(lockedCatalog[0].inUse, true);
      assert.equal(lockedCatalog[0].quickConfigReferenceCount, 1);
      await runtime.executeRaw("UPDATE xray_quick_configs SET state = 'REMOVED' WHERE configTag = ?", ["quick-config-zone-lock"]);
      assert.equal((await repository.listGlobalDnsProviderZones())[0].inUse, false);

      await runtime.executeRaw(
        "UPDATE dns_provider_record_lines SET name = '电信' WHERE zoneId = ? AND providerLineId = 'line-default'",
        [stableZoneId],
      );
      await expectCode(repository.listGlobalDnsProviderZones(), "DNS_PROVIDER_INVALID");
      await runtime.executeRaw(
        "UPDATE dns_provider_record_lines SET name = '默认' WHERE zoneId = ? AND providerLineId = 'line-default'",
        [stableZoneId],
      );
      await runtime.executeRaw(
        "UPDATE dns_provider_record_lines SET category = 'OTHER' WHERE zoneId = ? AND providerLineId = 'line-default'",
        [stableZoneId],
      );
      await expectCode(repository.listGlobalDnsProviderZones(), "DNS_PROVIDER_INVALID");
      await runtime.executeRaw(
        "UPDATE dns_provider_record_lines SET category = 'DEFAULT' WHERE zoneId = ? AND providerLineId = 'line-default'",
        [stableZoneId],
      );

      const rows = await runtime.queryRaw("SELECT * FROM dns_provider_account_secrets WHERE accountId = ? ORDER BY kind", [created.accountId]);
      assert.deepEqual(rows.map((row) => row.kind), ["DNSPOD_SECRET_ID", "DNSPOD_SECRET_KEY"]);
      assert.equal(JSON.stringify(rows).includes("secret-id-value"), false);
      assert.equal(JSON.stringify(rows).includes("secret-key-value"), false);
      assert.equal(rows.every((row) => String(row.encryptedValue).startsWith("fwdx-secret:v1:1:")), true);

      await runtime.executeRaw("DELETE FROM dns_provider_account_secrets WHERE accountId = ? AND kind = 'DNSPOD_SECRET_KEY'", [created.accountId]);
      await expectCode(repository.loadGlobalDnsProviderCredentials({ keyring }), "SENSITIVE_DATA_UNAVAILABLE");

      assert.deepEqual(await runtime.queryRaw("SELECT key, value, updatedAt FROM system_settings WHERE key = 'dnspod_token'"), beforeDdns);
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
