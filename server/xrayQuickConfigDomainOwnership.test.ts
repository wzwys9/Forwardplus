import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { isQuickConfigDnsRecordOwned } from "./xrayQuickConfigService";
import { computeXrayQuickConfigDnsTupleHash } from "./xrayQuickConfigDnsTuple";

test("original-domain confirmation only recognizes matching managed record IDs and complete DNS tuples", () => {
  const remote = {
    providerRecordId: "123", subdomain: "edge", recordType: "A", providerLineId: "0",
    lineName: "默认", value: "1.1.1.1", ttl: 600, status: "ENABLE",
  };
  const stored = {
    providerRecordId: "123", fqdn: "edge.example.com", recordType: "A" as const,
    providerLineId: "0", value: "1.1.1.1", ttl: 600,
    remoteTupleHash: computeXrayQuickConfigDnsTupleHash({
      fqdn: "edge.example.com", recordType: "A", providerLineId: "0", value: "1.1.1.1", ttl: 600,
    }),
  };
  assert.equal(isQuickConfigDnsRecordOwned(remote, stored, "example.com"), true);
  for (const drift of [
    { providerRecordId: "999" }, { subdomain: "other" }, { recordType: "CNAME" },
    { providerLineId: "10=0" }, { value: "8.8.8.8" }, { ttl: 120 }, { status: "DISABLE" },
  ]) assert.equal(isQuickConfigDnsRecordOwned({ ...remote, ...drift }, stored, "example.com"), false);
  assert.equal(isQuickConfigDnsRecordOwned(remote, { ...stored, remoteTupleHash: "bad" }, "example.com"), false);
  assert.equal(isQuickConfigDnsRecordOwned(remote, stored, "other.example.com"), false);
});

// A real isolated database exercises authorization/revision reads. The provider
// only exposes an in-memory read; no production credentials or network are used.
const confirmationScenario = String.raw`
  import assert from "node:assert/strict";
  globalThis.fetch = async () => { throw new Error("unexpected network request in domain confirmation test"); };
  const runtime = await import("./server/dbRuntime.ts");
  const schema = await import("./server/dbSchema.ts");
  const secrets = await import("./server/xraySecretCrypto.ts");
  const repository = await import("./server/repositories/dnsProviderRepository.ts");
  const external = await import("./server/xrayExternalProxyService.ts");
  const service = await import("./server/xrayQuickConfigService.ts");
  const scenario = process.env.FORWARDX_DOMAIN_SCENARIO;
  let now = new Date();
  let reads = 0;
  const remote = scenario === "unused" ? [] : [
    { providerRecordId: "1", subdomain: "edge", recordType: "A", providerLineId: "0", lineName: "默认", value: "8.8.8.8", ttl: 600, status: "ENABLE" },
    { providerRecordId: "2", subdomain: "edge", recordType: "TXT", providerLineId: "0", lineName: "默认", value: "preserved", ttl: 600, status: "ENABLE" },
  ];
  const options = {
    now: () => new Date(now),
    tokenSecret: "isolated-domain-confirmation-test-secret",
    dnsPodClientFactory: () => ({ listRecords: async () => { reads++; return structuredClone(remote); } }),
  };
  const expectCode = (promise, code) => assert.rejects(promise, error => {
    assert.equal(error?.code, code);
    return true;
  });

  try {
    await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
    await schema.ensureDatabaseSchema();
    const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
    await runtime.insertAndGetId("users", { id: 1, username: "admin", password: "hash", role: "admin" });
    await runtime.insertAndGetId("users", { id: 2, username: "other-admin", password: "hash", role: "admin" });
    const accountInput = {
      name: "Fixture DNSPod", secretId: "fixture-secret-id", secretKey: "fixture-secret-key", createdByUserId: 1,
      verifiedAt: new Date(), zones: [{ providerZoneId: "42", name: "example.com", lines: [
        { providerLineId: "0", name: "默认" }, { providerLineId: "10=0", name: "电信" },
        { providerLineId: "10=1", name: "联通" }, { providerLineId: "10=2", name: "移动" },
        { providerLineId: "10=3", name: "教育网" },
      ] }],
    };
    const account = await repository.saveVerifiedGlobalDnsProviderAccount({
      ...accountInput, expectedBindingRevision: 1, expectedAccountRevision: null,
    }, { keyring });
    const zone = (await repository.listGlobalDnsProviderZones())[0];
    const node = await external.createXrayExternalProxyNode({
      name: "Fixture landing", uri: "socks5://8.8.4.4:1080", createdByUserId: 1,
    }, { keyring });
    const target = (await service.listQuickConfigTargets()).items.find(item => item.targetId === node.id);
    assert.ok(target?.eligible, "fixture target must be eligible before exercising confirmation");
    const targetRef = { targetType: target.targetType, targetId: target.targetId, targetVersion: target.targetVersion };
    const config = {
      id: 1, configTag: "confirmation-fixture", targetType: target.targetType, externalProxyNodeId: target.targetId,
      targetVersion: target.targetVersion, dnsAccountId: account.accountId, zoneId: zone.zoneId,
      relativeName: "edge", fqdn: "edge.example.com", state: "ACTIVE", revision: 1, activeTopologyRevisionId: 1, createdByUserId: 1,
    };
    const editing = scenario === "edit-revision" || scenario === "unchanged-edit";
    if (editing) await runtime.insertAndGetId("xray_quick_configs", config);
    const checked = await service.createQuickConfigDomainCheck({
      targetRef, accountId: account.accountId, zoneId: zone.zoneId, relativeName: "edge", userId: 1,
      ...(editing ? { editIdentity: { quickConfigId: 1, expectedRevision: 1 } } : {}),
    }, options);
    const confirmInput = {
      domainCheckToken: checked.domainCheckToken, confirmationHash: checked.confirmationHash,
      action: checked.allowedActions[0], userId: 1,
    };
    if (scenario === "expired-check") {
      now = new Date(checked.expiresAt);
      await expectCode(service.confirmQuickConfigDomainCheck(confirmInput, options), "DOMAIN_CHECK_EXPIRED");
    } else {
      const confirmed = await service.confirmQuickConfigDomainCheck(confirmInput, options);
      const resolveInput = { confirmedDomainToken: confirmed.confirmedDomainToken, userId: 1 };
      const before = await service.resolveConfirmedQuickConfigDomain(resolveInput, options);
      assert.equal(before.action, confirmInput.action);
      now = new Date(Date.parse(confirmed.expiresAt) + 1);
      reads = 0;

      let expectedCode;
      if (scenario === "remote-address") {
        remote[0].value = "1.1.1.1";
        expectedCode = "DOMAIN_CONFLICT_CHANGED";
      } else if (scenario === "remote-preserved") {
        remote[1].value = "changed-third-party-TXT";
        expectedCode = "DOMAIN_CONFLICT_CHANGED";
      } else if (scenario === "cross-user") {
        resolveInput.userId = 2;
        expectedCode = "DOMAIN_CONFIRMATION_INVALID";
      } else if (scenario === "account-revision") {
        await runtime.executeRaw('UPDATE dns_provider_accounts SET revision = revision + 1 WHERE id = ?', [account.accountId]);
        expectedCode = "DOMAIN_CONFIRMATION_INVALID";
      } else if (scenario === "binding-revision") {
        await runtime.executeRaw('UPDATE dns_provider_global_bindings SET revision = revision + 1');
        expectedCode = "DOMAIN_CONFIRMATION_INVALID";
      } else if (scenario === "credentials-rotated") {
        await repository.saveVerifiedGlobalDnsProviderAccount({
          ...accountInput, secretKey: "rotated-fixture-key",
          expectedAccountRevision: account.accountRevision, expectedBindingRevision: account.bindingRevision,
        }, { keyring });
        expectedCode = "DOMAIN_CONFIRMATION_INVALID";
      } else if (scenario === "target-version") {
        await runtime.executeRaw('UPDATE xray_external_proxy_nodes SET port = port + 1 WHERE id = ?', [target.targetId]);
        expectedCode = "QUICK_CONFIG_TARGET_CHANGED";
      } else if (scenario === "edit-revision") {
        await runtime.executeRaw('UPDATE xray_quick_configs SET revision = revision + 1 WHERE id = 1');
        expectedCode = "DOMAIN_CHECK_INVALID";
      } else if (scenario === "domain-claimed") {
        await runtime.insertAndGetId("xray_quick_configs", config);
        expectedCode = "DOMAIN_ALREADY_MANAGED";
      }

      if (expectedCode) {
        await expectCode(service.resolveConfirmedQuickConfigDomain(resolveInput, options), expectedCode);
      } else {
        const resolved = await service.resolveConfirmedQuickConfigDomain(resolveInput, options);
        assert.deepEqual(resolved, before, "expiry cannot alter the previously authorized domain/action/revisions");
        assert.equal(reads, 1, "acceptance requires a fresh complete provider record snapshot");
        // Every consumption revalidates the remote set; success is not a cached renewal.
        remote.push({ providerRecordId: "3", subdomain: "edge", recordType: "A", providerLineId: "0", lineName: "默认", value: "9.9.9.9", ttl: 600, status: "ENABLE" });
        await expectCode(service.resolveConfirmedQuickConfigDomain(resolveInput, options), "DOMAIN_CONFLICT_CHANGED");
        assert.equal(reads, 2);
      }
      assert.equal((await runtime.queryRaw('SELECT COUNT(*) AS count FROM forward_rules'))[0].count, 0);
      assert.equal((await runtime.queryRaw('SELECT COUNT(*) AS count FROM xray_quick_config_operations'))[0].count, 0);
    }
  } finally {
    await runtime.closeDatabase();
  }
`;

for (const [scenario, description] of [
  ["unused", "expired confirmed unused domain can continue after live revalidation"],
  ["replacement", "expired confirmed replacement retains only its original record authorization"],
  ["unchanged-edit", "expired original-domain edit confirmation preserves its edit identity after revalidation"],
  ["expired-check", "unconfirmed domain check still expires before it can authorize records"],
  ["remote-address", "expired confirmation rejects changed remote address records"],
  ["remote-preserved", "expired confirmation rejects drift in preserved remote records"],
  ["cross-user", "expired confirmation cannot be consumed by another administrator"],
  ["account-revision", "expired confirmation rechecks the current account revision"],
  ["binding-revision", "expired confirmation rechecks the current binding revision"],
  ["credentials-rotated", "expired confirmation rejects credentials rotated since confirmation"],
  ["target-version", "expired confirmation rechecks the current target version"],
  ["edit-revision", "expired confirmation rechecks the current edit revision"],
  ["domain-claimed", "expired confirmation rejects a domain claimed since confirmation"],
] as const) {
  test(description, () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-domain-confirmation-"));
    try {
      const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", confirmationScenario], {
        cwd: process.cwd(),
        env: {
          ...process.env, DATABASE_TYPE: "sqlite", FORWARDX_TEST_DB: path.join(directory, "panel.db"),
          XRAY_MASTER_KEY_PATH: path.join(directory, "xray-master.key"), FORWARDX_DOMAIN_SCENARIO: scenario,
        },
        encoding: "utf8", timeout: 30_000,
      });
      assert.equal(result.status, 0, result.stderr || result.stdout);
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  });
}
