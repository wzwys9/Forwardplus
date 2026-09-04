import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("persisted multihop sync restores every segment and protects relay hosts without live rules", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardplus-multihop-"));
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "-e", String.raw`
      import assert from "node:assert/strict";
      const runtime = await import("./server/dbRuntime.ts");
      const schema = await import("./server/dbSchema.ts");
      const sync = await import("./server/xrayQuickConfigSyncService.ts");
      const topology = await import("./server/xrayQuickConfigTopologyStore.ts");
      const engine = await import("./server/xrayQuickConfigEngineSwitchService.ts");
      const hosts = await import("./server/repositories/hostRepository.ts");
      const { computeXrayQuickConfigDnsTupleHash } = await import("./server/xrayQuickConfigDnsTuple.ts");
      const insert = runtime.insertAndGetId;
      try {
        await runtime.connectDatabase({type:"sqlite",sqlite:{path:process.env.FORWARDPLUS_TEST_DB}});
        await schema.ensureDatabaseSchema();
        await insert("users",{id:1,username:"fixture",password:"hash",role:"admin"});
        for (const id of [1,2]) await insert("hosts",{id,name:"Host "+id,ip:id===1?"8.8.8.8":"1.1.1.1",userId:1});
        await insert("global_port_allocations",{id:1,allocationTag:"port:5326",port:5326,status:"ACTIVE",primaryOwnerType:"QUICK_CONFIG",primaryOwnerTag:"quick-config:test",version:1});
        await insert("xray_quick_configs",{id:1,configTag:"quick-config:test",targetType:"EXTERNAL_PROXY_NODE",externalProxyNodeId:1,targetVersion:"v1",dnsAccountId:1,zoneId:1,relativeName:"edge",fqdn:"edge.example.com",state:"ACTIVE",revision:1,activeTopologyRevisionId:1,createdByUserId:1});
        await insert("xray_quick_config_topology_revisions",{id:1,quickConfigId:1,revisionNumber:1,engine:"realm",targetAddress:"9.9.9.9",targetPort:443,publicPort:5326,portAllocationId:1,state:"APPLIED",activeSlot:1,createdByUserId:1});
        await insert("xray_quick_config_routes",{id:1,routeTag:"route:1",quickConfigId:1,topologyRevisionId:1,lineCategory:"TELECOM",providerLineId:"10=0",sourceType:"MANAGED_HOST",hostId:1,addressFamily:"IPV4",address:"8.8.8.8",routeMode:"FORWARD",relayHopsJson:JSON.stringify([{hostId:2,addressFamily:"IPV4",address:"1.1.1.1"}]),state:"APPLIED"});
        const tuple={fqdn:"edge.example.com",recordType:"A",providerLineId:"10=0",value:"8.8.8.8",ttl:600};
        await insert("xray_quick_config_dns_records",{id:1,quickConfigId:1,routeId:1,dnsAccountId:1,zoneId:1,recordTag:"dns:1",providerRecordId:"1",...tuple,status:"APPLIED",appliedRevision:1,remoteTupleHash:computeXrayQuickConfigDnsTupleHash(tuple)});
        assert.equal(await topology.quickConfigReferencesHost(2),true);
        await assert.rejects(hosts.deleteHost(2), /快速配置路径引用/);
        const operation = await sync.createXrayQuickConfigSync({id:1,expectedRevision:1,userId:1});
        const rules = await runtime.queryRaw('SELECT hostId,sourcePort,targetIp,targetPort,portResourceGroupId FROM forward_rules ORDER BY hostId');
        assert.deepEqual(rules.map(({hostId,sourcePort,targetIp,targetPort})=>({hostId,sourcePort,targetIp,targetPort})),[
          {hostId:1,sourcePort:5326,targetIp:"1.1.1.1",targetPort:5326},
          {hostId:2,sourcePort:5326,targetIp:"9.9.9.9",targetPort:443},
        ]);
        assert.ok(rules.every(rule=>rule.portResourceGroupId>0));
        const references = await runtime.queryRaw('SELECT hostId FROM global_port_allocation_references WHERE resourceType = ?', ["FORWARD_RULE"]);
        assert.deepEqual(references.map(row=>row.hostId).sort(),[1,2]);
        await runtime.executeRaw('UPDATE xray_quick_config_operations SET activeSlot=NULL,status=? WHERE id=?',["SUCCESS",operation.operationId]);
        await runtime.executeRaw('UPDATE xray_quick_configs SET state=?, currentOperationId=NULL, desiredTopologyRevisionId=NULL WHERE id=1',["ACTIVE"]);
        await runtime.executeRaw('UPDATE forward_rules SET isRunning=1, targetIp=? WHERE hostId=2',["4.4.4.4"]);
        const [config]=await runtime.queryRaw('SELECT revision FROM xray_quick_configs WHERE id=1');
        await assert.rejects(engine.previewXrayQuickConfigEngineSwitch({id:1,expectedRevision:config.revision,engine:"gost",userId:1}), error=>error.code==="QUICK_CONFIG_REVISION_CONFLICT");
        await sync.createXrayQuickConfigSync({id:1,expectedRevision:config.revision,userId:1});
        const [repaired]=await runtime.queryRaw('SELECT targetIp,targetPort FROM forward_rules WHERE hostId=2');
        assert.deepEqual(repaired,{targetIp:"9.9.9.9",targetPort:443});
        assert.equal((await runtime.queryRaw('SELECT id FROM forward_rules')).length,2);
        // No Agent/provider worker is part of this fixture. Retire its queued
        // intents; pending lazy imports may still schedule an empty sweep.
        await runtime.executeRaw('UPDATE xray_quick_config_operations SET activeSlot=NULL,status=?',["SUCCESS"]);
        await runtime.executeRaw('UPDATE xray_quick_configs SET currentOperationId=NULL');
      } finally {
        // The isolated child owns the connection. Close only after its event
        // loop drains, not after a guessed number of setImmediate turns.
        process.once("beforeExit", async () => { await runtime.closeDatabase(); });
      }
    `], { cwd: process.cwd(), env: { ...process.env, DATABASE_TYPE: "sqlite", FORWARDPLUS_TEST_DB: path.join(directory, "panel.db") }, encoding: "utf8", timeout: 30_000 });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
});
