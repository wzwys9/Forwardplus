import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("all six local forwarding tools materialize external endpoints and derive no-store relay links", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-external-rule-"));
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const db = await load("server/dbRuntime.ts");
    const schema = await load("server/dbSchema.ts");
    const external = await load("server/xrayExternalProxyService.ts");
    const secrets = await load("server/xraySecretCrypto.ts");
    const { rulesRouter } = await load("server/routers/rules.ts");
    const { xrayRouter } = await load("server/routers/xray.ts");
    const headers = new Map();
    const context = (user, capture = false) => ({
      req: { headers: {} },
      res: { clearCookie() {}, setHeader(name, value) { if (capture) headers.set(name, value); } },
      user, authSession: null, authFailureReason: null,
    });
    const admin = { id: 1, username: "admin", role: "admin", accountEnabled: true };
    const member = { id: 2, username: "member", role: "user", accountEnabled: true };
    const expectMessage = async (promise, message) => assert.rejects(promise, (error) => error?.message === message);
    try {
      await db.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      const keyring = secrets.createXrayMasterKeyFile({ path: process.env.XRAY_MASTER_KEY_PATH });
      await db.executeRaw("INSERT INTO system_settings (key, value, updatedAt) VALUES (?, ?, ?)", ["forwardProtocols", JSON.stringify({ nginx: true }), Math.floor(Date.now() / 1000)]);
      await db.executeRaw("INSERT INTO users (id, username, password, role, canAddRules) VALUES (1, 'admin', 'hash', 'admin', 1), (2, 'member', 'hash', 'user', 1)");
      await db.executeRaw("INSERT INTO hosts (id, name, ip, ipv4, entryIp, isOnline, userId) VALUES (1, 'Hong Kong B', '8.8.8.8', '8.8.8.8', '8.8.8.8', 1, 1)");
      const publicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
      const uri = "vless://00000000-0000-4000-8000-000000000501@us.example.com:443/?type=tcp&encryption=none&flow=xtls-rprx-vision&sni=cdn.example.com&fp=random&security=reality&pbk=" + publicKey + "&sid=12ab#US";
      const node = await external.createXrayExternalProxyNode({ name: "US A", uri, createdByUserId: 1 }, { keyring });
      const adminRules = rulesRouter.createCaller(context(admin));
      const memberRules = rulesRouter.createCaller(context(member));
      const xray = xrayRouter.createCaller(context(admin, true));

      await expectMessage(memberRules.create({ hostId: 1, name: "forbidden", forwardType: "socat", protocol: "tcp", sourcePort: 31079, targetExternalProxyNodeId: node.id }), "EXTERNAL_PROXY_UNSUPPORTED");
      await expectMessage(adminRules.create({ hostId: 1, name: "missing", forwardType: "nftables", protocol: "tcp", sourcePort: 31079, targetExternalProxyNodeId: 99999 }), "EXTERNAL_PROXY_NOT_FOUND");
      await expectMessage(adminRules.create({ hostId: 1, name: "udp", forwardType: "nginx", protocol: "udp", sourcePort: 31079, targetExternalProxyNodeId: node.id }), "EXTERNAL_PROXY_UNSUPPORTED");
      await expectMessage(adminRules.create({ hostId: 1, name: "inject", forwardType: "iptables", protocol: "tcp", sourcePort: 31079, targetExternalProxyNodeId: node.id, proxyProtocolSend: true }), "EXTERNAL_PROXY_UNSUPPORTED");
      assert.equal((await db.queryRaw("SELECT COUNT(*) count FROM forward_rules"))[0].count, 0);

      const created = await adminRules.create({
        hostId: 1,
        name: "HK to US",
        forwardType: "iptables",
        protocol: "tcp",
        sourcePort: 31080,
        targetExternalProxyNodeId: node.id,
      });
      const [stored] = await db.queryRaw("SELECT * FROM forward_rules WHERE id = ?", [created.id]);
      assert.equal(stored.targetIp, "us.example.com");
      assert.equal(Number(stored.targetPort), 443);
      assert.equal(Number(stored.targetExternalProxyNodeId), node.id);
      assert.equal(Number(stored.proxyProtocolSend), 0);
      assert.equal(Number(stored.proxyProtocolExitSend), 0);
      assert.equal((await external.getXrayExternalProxyNodeDetail(node.id)).ruleCount, 1);

      const detail = await adminRules.getById({ id: created.id });
      assert.deepEqual(detail.externalProxy, { id: node.id, name: "US A", protocol: "VLESS_REALITY_VISION", address: "us.example.com", port: 443 });
      assert.equal((await adminRules.listPage({ page: 1, pageSize: 12, scope: "all", category: "all", search: "" })).items[0].externalProxy.name, "US A");

      const relayShare = await xray.externalProxyNodes.share({ id: node.id, relayRuleId: created.id });
      assert.match(relayShare.uri, /^vless:\/\/00000000-0000-4000-8000-000000000501@8\.8\.8\.8:31080\?/);
      assert.match(relayShare.uri, /sni=cdn\.example\.com/);
      assert.match(relayShare.uri, /fp=random/);
      assert.match(relayShare.uri, /pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/);
      assert.equal(headers.get("Cache-Control"), "private, no-store, max-age=0");
      await expectMessage(external.buildXrayExternalProxyRelayShare({ id: node.id, relayRuleId: 99999 }, { keyring }), "EXTERNAL_PROXY_REFERENCE_INVALID");

      await expectMessage(adminRules.update({ id: created.id, protocol: "udp" }), "EXTERNAL_PROXY_UNSUPPORTED");
      await expectMessage(adminRules.update({ id: created.id, proxyProtocolExitSend: true }), "EXTERNAL_PROXY_UNSUPPORTED");
      await expectMessage(adminRules.update({ id: created.id, targetExternalProxyNodeId: null }), "EXTERNAL_PROXY_REFERENCE_INVALID");
      for (const forwardType of ["nftables", "realm", "socat", "gost", "nginx"]) {
        await adminRules.update({ id: created.id, forwardType });
        const [updated] = await db.queryRaw("SELECT forwardType, targetIp, targetPort, targetExternalProxyNodeId FROM forward_rules WHERE id = ?", [created.id]);
        assert.deepEqual({ forwardType: updated.forwardType, targetIp: updated.targetIp, targetPort: Number(updated.targetPort), targetExternalProxyNodeId: Number(updated.targetExternalProxyNodeId) }, {
          forwardType, targetIp: "us.example.com", targetPort: 443, targetExternalProxyNodeId: node.id,
        });
      }

      await db.executeRaw("UPDATE forward_rules SET userId = 2 WHERE id = ?", [created.id]);
      const memberView = await memberRules.getById({ id: created.id });
      assert.equal("targetExternalProxyNodeId" in memberView, false);
      assert.equal("externalProxy" in memberView, false);
      await db.executeRaw("UPDATE forward_rules SET userId = 1 WHERE id = ?", [created.id]);

      await adminRules.update({ id: created.id, targetExternalProxyNodeId: null, targetIp: "manual.example.com", targetPort: 8443 });
      const manual = (await db.queryRaw("SELECT targetIp, targetPort, targetExternalProxyNodeId FROM forward_rules WHERE id = ?", [created.id]))[0];
      assert.deepEqual({ targetIp: manual.targetIp, targetPort: Number(manual.targetPort), targetExternalProxyNodeId: manual.targetExternalProxyNodeId }, {
        targetIp: "manual.example.com", targetPort: 8443, targetExternalProxyNodeId: null,
      });
      assert.equal((await external.getXrayExternalProxyNodeDetail(node.id)).ruleCount, 0);
    } finally {
      await db.closeDatabase().catch(() => undefined);
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
        JWT_SECRET: "xray-external-rule-test",
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
