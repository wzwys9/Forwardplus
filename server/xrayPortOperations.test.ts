import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("Xray port operations exclude known ports and reserve one concurrent probe result", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-port-operations-"));
  const databasePath = path.join(directory, "operations.db");
  const script = String.raw`
    import assert from "node:assert/strict";
    import crypto from "node:crypto";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const backfill = await import(moduleUrl("server/globalPortBackfill.ts"));
    const reservations = await import(moduleUrl("server/portReservations.ts"));
    const operations = await import(moduleUrl("server/xrayPortOperations.ts"));
    const planning = await import(moduleUrl("server/xrayQuickConfigPlanningService.ts"));
    const { xrayRouter } = await import(moduleUrl("server/routers/xray.ts"));

    const expectCode = async (promise, code) => assert.rejects(promise, (error) => error?.code === code);
    const nowIso = () => new Date().toISOString();
    const successfulResult = (task) => ({
      schemaVersion: 1,
      taskId: task.taskId,
      type: "PORT_PROBE",
      status: "SUCCESS",
      startedAt: nowIso(),
      finishedAt: nowIso(),
      result: {
        ports: task.payload.ports.map((port) => ({ port, available: true, errorCode: null })),
        observedAt: nowIso(),
      },
      error: null,
    });
    const stableValue = (value) => Array.isArray(value)
      ? value.map(stableValue)
      : value && typeof value === "object"
        ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]))
        : value;
    const signPlanningToken = (payload, secret) => {
      const key = crypto.createHmac("sha256", secret)
        .update("forwardx-xray-quick-config-planning-token:v1", "utf8").digest();
      const body = Buffer.from(JSON.stringify(stableValue(payload)), "utf8").toString("base64url");
      const unsigned = "qcp1." + body;
      return unsigned + "." + crypto.createHmac("sha256", key).update(unsigned, "utf8").digest("base64url");
    };
    const makeEquivalentNonCanonicalSignature = (token) => {
      const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
      const parts = token.split(".");
      const last = parts[2].at(-1);
      const index = alphabet.indexOf(last);
      assert.equal(index % 4, 0);
      parts[2] = parts[2].slice(0, -1) + alphabet[index + 1];
      assert.deepEqual(Buffer.from(parts[2], "base64url"), Buffer.from(token.split(".")[2], "base64url"));
      return parts.join(".");
    };

    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      const heartbeat = Math.floor(Date.now() / 1000);
      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin-a', 'hash', 'admin'), (2, 'admin-b', 'hash', 'admin')");
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, isOnline, lastHeartbeat, userId) VALUES (10, 'edge-a', '192.0.2.10', 1, ?, 1), (11, 'edge-b', '192.0.2.11', 1, ?, 1)", [heartbeat, heartbeat]);
      await runtime.executeRaw("INSERT INTO xray_runtime_reports (hostId, capabilitySchemaVersion, supportsPortProbe) VALUES (10, 1, 1), (11, 1, 1)");
      await runtime.executeRaw("INSERT INTO forward_rules (hostId, name, protocol, sourcePort, targetIp, targetPort, userId) VALUES (10, 'known-forward', 'tcp', 12000, '198.51.100.10', 443, 1)");
      await runtime.executeRaw("INSERT INTO forward_rules (hostId, name, protocol, sourcePort, targetIp, targetPort, forwardType, userId) VALUES (10, 'legacy-realm', 'tcp', 28255, '198.51.100.20', 443, 'realm', 1)");
      await runtime.executeRaw("INSERT INTO tunnels (name, entryHostId, exitHostId, listenPort, userId) VALUES ('known-tunnel', 11, 10, 13000, 1)");
      await runtime.executeRaw("INSERT INTO xray_inbounds (hostId, name, runtimeTag, publicAddress, listenPort, realityTargetHost, realityServerName, realityPublicKey, realityPrivateKeyEncrypted, createdByUserId) VALUES (10, 'known-xray', 'xray-known', '203.0.113.10', 14000, 'example.com', 'example.com', 'public', 'encrypted-private', 1)");
      const held = reservations.tryReserveHostPort(10, 15000, "tcp");
      assert.ok(held);
      await backfill.backfillGlobalPortAllocations();

      const [knownInbound] = await runtime.queryRaw("SELECT id FROM xray_inbounds WHERE runtimeTag = 'xray-known' LIMIT 1");
      assert.ok(knownInbound?.id);
      await expectCode(
        operations.createXrayPortProbeOperation({ hostId: 11, userId: 1, mode: "MANUAL", manualPort: 14000 }),
        "PORT_IN_USE",
      );
      const targetAliasProbe = await operations.createXrayPortProbeOperation({
        hostId: 11,
        userId: 1,
        mode: "MANUAL",
        manualPort: 14000,
        targetAlias: { inboundId: Number(knownInbound.id), port: 14000 },
      });
      const [targetAliasTask] = await operations.takeXrayPortProbeTasks(11, 1);
      assert.deepEqual(targetAliasTask.payload, { network: "tcp", listenAddress: "0.0.0.0", ports: [14000] });
      await operations.completeXrayPortProbeTask(11, successfulResult(targetAliasTask));
      const targetAliasResult = await operations.getXrayPortProbeOperationResult(targetAliasProbe.operationId, 1);
      assert.equal(targetAliasResult.status, "SUCCESS");
      operations.consumeXrayPortReservation({
        reservationId: targetAliasResult.reservationId,
        hostId: 11,
        userId: 1,
        port: 14000,
      });

      const invalidBeforeDispatchProbe = await operations.createXrayPortProbeOperation({
        hostId: 11,
        userId: 1,
        mode: "MANUAL",
        manualPort: 14000,
        targetAlias: { inboundId: Number(knownInbound.id), port: 14000 },
      });
      await runtime.executeRaw("UPDATE xray_inbounds SET runtimeTag = 'xray-changed' WHERE id = ?", [knownInbound.id]);
      assert.deepEqual(await operations.takeXrayPortProbeTasks(11, 1), []);
      const invalidBeforeDispatchResult = await operations.getXrayPortProbeOperationResult(invalidBeforeDispatchProbe.operationId, 1);
      assert.equal(invalidBeforeDispatchResult.status, "FAILED");
      assert.equal(invalidBeforeDispatchResult.errorCode, "PORT_IN_USE");
      await runtime.executeRaw("UPDATE xray_inbounds SET runtimeTag = 'xray-known' WHERE id = ?", [knownInbound.id]);

      const staleTargetAliasProbe = await operations.createXrayPortProbeOperation({
        hostId: 11,
        userId: 1,
        mode: "MANUAL",
        manualPort: 14000,
        targetAlias: { inboundId: Number(knownInbound.id), port: 14000 },
      });
      const [staleTargetAliasTask] = await operations.takeXrayPortProbeTasks(11, 1);
      await runtime.executeRaw("UPDATE xray_inbounds SET runtimeTag = 'xray-changed' WHERE id = ?", [knownInbound.id]);
      await operations.completeXrayPortProbeTask(11, successfulResult(staleTargetAliasTask));
      const staleTargetAliasResult = await operations.getXrayPortProbeOperationResult(staleTargetAliasProbe.operationId, 1);
      assert.equal(staleTargetAliasResult.status, "FAILED");
      assert.equal(staleTargetAliasResult.errorCode, "PORT_IN_USE");
      await runtime.executeRaw("UPDATE xray_inbounds SET runtimeTag = 'xray-known' WHERE id = ?", [knownInbound.id]);

      const usedOnOtherHost = await operations.collectXrayUsedPorts(11);
      assert.equal(usedOnOtherHost.has(28255), true);
      assert.equal(usedOnOtherHost.has(13000), true);
      await expectCode(
        operations.createXrayPortProbeOperation({ hostId: 11, userId: 1, mode: "MANUAL", manualPort: 28255 }),
        "PORT_IN_USE",
      );

      await runtime.executeRaw("UPDATE hosts SET portRangeStart = 13000, portRangeEnd = 13001 WHERE id = 11");
      const crossHostAutomatic = await operations.createXrayPortProbeOperation({ hostId: 11, userId: 1, mode: "AUTO" });
      const [crossHostAutomaticTask] = await operations.takeXrayPortProbeTasks(11, 1);
      assert.deepEqual(crossHostAutomaticTask.payload.ports, [13001]);
      await operations.completeXrayPortProbeTask(11, successfulResult(crossHostAutomaticTask));
      const crossHostAutomaticResult = await operations.getXrayPortProbeOperationResult(crossHostAutomatic.operationId, 1);
      operations.consumeXrayPortReservation({
        reservationId: crossHostAutomaticResult.reservationId,
        hostId: 11,
        userId: 1,
        port: 13001,
      });
      await runtime.executeRaw("UPDATE hosts SET portRangeStart = NULL, portRangeEnd = NULL WHERE id = 11");

      const crossHostRace = await operations.createXrayPortProbeOperation({
        hostId: 11, userId: 1, mode: "MANUAL", manualPort: 28256,
      });
      const [crossHostRaceTask] = await operations.takeXrayPortProbeTasks(11, 1);
      await runtime.executeRaw("INSERT INTO forward_rules (hostId, name, protocol, sourcePort, targetIp, targetPort, userId) VALUES (10, 'probe-race', 'tcp', 28256, '198.51.100.21', 443, 1)");
      await backfill.backfillGlobalPortAllocations();
      await operations.completeXrayPortProbeTask(11, successfulResult(crossHostRaceTask));
      const crossHostRaceResult = await operations.getXrayPortProbeOperationResult(crossHostRace.operationId, 1);
      assert.equal(crossHostRaceResult.status, "FAILED");
      assert.equal(crossHostRaceResult.errorCode, "PORT_IN_USE");
      await runtime.executeRaw("DELETE FROM xray_operations");

      assert.deepEqual(
        operations.generateXrayPortCandidates(new Set([1000, 1002]), 3, (() => {
          const values = [1000, 1001, 1002, 1003, 1004];
          return () => values.shift();
        })()),
        [1001, 1003, 1004],
      );
      assert.equal(operations.generateXrayPortCandidates(new Set(), 99).length, 32);

      const used = await operations.collectXrayUsedPorts(10);
      assert.deepEqual([12000, 13000, 14000, 15000].map((port) => used.has(port)), [true, true, true, true]);
      const udpUsed = await operations.collectXrayUsedPorts(10, "UDP");
      assert.deepEqual([14000, 15000].map((port) => udpUsed.has(port)), [true, false]);
      for (const manualPort of [12000, 13000, 14000, 15000]) {
        await expectCode(operations.createXrayPortProbeOperation({ hostId: 10, userId: 1, mode: "MANUAL", manualPort }), "PORT_IN_USE");
      }
      await expectCode(operations.createXrayPortProbeOperation({ hostId: 10, userId: 1, mode: "MANUAL", manualPort: 999 }), "PORT_OUT_OF_RANGE");
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_operations"))[0].count, 0);

      await runtime.executeRaw("UPDATE hosts SET isOnline = 0 WHERE id = 10");
      await expectCode(operations.createXrayPortProbeOperation({ hostId: 10, userId: 1, mode: "MANUAL", manualPort: 16000 }), "HOST_OFFLINE");
      await runtime.executeRaw("UPDATE hosts SET isOnline = 1, lastHeartbeat = ? WHERE id = 10", [Math.floor(Date.now() / 1000) - 3600]);
      await expectCode(operations.createXrayPortProbeOperation({ hostId: 10, userId: 1, mode: "MANUAL", manualPort: 16000 }), "HOST_OFFLINE");
      await runtime.executeRaw("UPDATE hosts SET isOnline = 1, lastHeartbeat = ? WHERE id = 10", [Math.floor(Date.now() / 1000)]);
      await runtime.executeRaw("UPDATE xray_runtime_reports SET capabilitySchemaVersion = 0 WHERE hostId = 10");
      await expectCode(operations.createXrayPortProbeOperation({ hostId: 10, userId: 1, mode: "MANUAL", manualPort: 16000 }), "AGENT_CAPABILITY_MISSING");
      await runtime.executeRaw("UPDATE xray_runtime_reports SET capabilitySchemaVersion = 1 WHERE hostId = 10");
      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsPortProbe = 0 WHERE hostId = 10");
      await expectCode(operations.createXrayPortProbeOperation({ hostId: 10, userId: 1, mode: "MANUAL", manualPort: 16000 }), "AGENT_CAPABILITY_MISSING");
      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsPortProbe = 1 WHERE hostId = 10");
      await expectCode(
        operations.createXrayPortProbeOperation({ hostId: 10, userId: 1, mode: "MANUAL", manualPort: 16000, network: "UDP" }),
        "UDP_CAPABILITY_REQUIRED",
      );
      assert.equal((await runtime.queryRaw("SELECT COUNT(*) AS count FROM xray_operations"))[0].count, 0);
      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsUdpPortProbe = 1, supportsUdpListenerReadiness = 1");

      const invalidatedUdp = await operations.createXrayPortProbeOperation({ hostId: 10, userId: 1, mode: "MANUAL", manualPort: 16000, network: "UDP" });
      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsUdpPortProbe = 0 WHERE hostId = 10");
      assert.deepEqual(await operations.takeXrayPortProbeTasks(10, 1), []);
      const invalidatedUdpResult = await operations.getXrayPortProbeOperationResult(invalidatedUdp.operationId, 1);
      assert.equal(invalidatedUdpResult.status, "FAILED");
      assert.equal(invalidatedUdpResult.errorCode, "UDP_CAPABILITY_REQUIRED");
      await runtime.executeRaw("UPDATE xray_runtime_reports SET supportsUdpPortProbe = 1 WHERE hostId = 10");

      await runtime.executeRaw("UPDATE hosts SET portRangeStart = 16000, portRangeEnd = 16010 WHERE id = 10");
      await expectCode(operations.createXrayPortProbeOperation({ hostId: 10, userId: 1, mode: "MANUAL", manualPort: 16011 }), "PORT_OUT_OF_RANGE");
      await runtime.executeRaw("UPDATE hosts SET portRangeStart = 17000, portRangeEnd = 17001 WHERE id = 11");
      await runtime.executeRaw("INSERT INTO forward_rules (hostId, name, protocol, sourcePort, targetIp, targetPort, userId) VALUES (11, 'policy-used', 'tcp', 17000, '198.51.100.11', 443, 1)");
      const udpAutomatic = await operations.createXrayPortProbeOperation({ hostId: 11, userId: 1, mode: "AUTO", network: "UDP" });
      const [udpAutomaticTask] = await operations.takeXrayPortProbeTasks(11, 1);
      assert.equal(udpAutomaticTask.payload.network, "udp");
      assert.equal(udpAutomaticTask.payload.ports.length, 1);
      await operations.completeXrayPortProbeTask(11, successfulResult(udpAutomaticTask));
      const udpAutomaticResult = await operations.getXrayPortProbeOperationResult(udpAutomatic.operationId, 1);
      assert.equal(udpAutomaticResult.network, "udp");
      operations.consumeXrayPortReservation({ reservationId: udpAutomaticResult.reservationId, hostId: 11, userId: 1, port: udpAutomaticResult.selectedPort, network: "UDP" });

      const automatic = await operations.createXrayPortProbeOperation({ hostId: 11, userId: 1, mode: "AUTO" });
      const [automaticTask] = await operations.takeXrayPortProbeTasks(11, 1);
      assert.deepEqual(automaticTask.payload.ports, [17001]);
      await operations.completeXrayPortProbeTask(11, successfulResult(automaticTask));
      const automaticResult = await operations.getXrayPortProbeOperationResult(automatic.operationId, 1);
      assert.equal(automaticResult.selectedPort, 17001);
      operations.consumeXrayPortReservation({ reservationId: automaticResult.reservationId, hostId: 11, userId: 1, port: 17001 });

      await runtime.executeRaw("UPDATE hosts SET portRangeEnd = 17010 WHERE id = 11");
      for (const port of [17002, 17003, 17004, 17005]) {
        await operations.createXrayPortProbeOperation({ hostId: 11, userId: 1, mode: "MANUAL", manualPort: port });
      }
      await expectCode(
        operations.createXrayPortProbeOperation({ hostId: 11, userId: 1, mode: "MANUAL", manualPort: 17006 }),
        "OPERATION_CONFLICT",
      );

      const first = await operations.createXrayPortProbeOperation({ hostId: 10, userId: 1, mode: "MANUAL", manualPort: 16000 });
      const second = await operations.createXrayPortProbeOperation({ hostId: 10, userId: 1, mode: "MANUAL", manualPort: 16000 });
      const tasks = await operations.takeXrayPortProbeTasks(10, 4);
      assert.equal(tasks.length, 2);
      assert.deepEqual(tasks.map((task) => task.payload), [
        { network: "tcp", listenAddress: "0.0.0.0", ports: [16000] },
        { network: "tcp", listenAddress: "0.0.0.0", ports: [16000] },
      ]);

      await Promise.all(tasks.map((task) => operations.completeXrayPortProbeTask(10, successfulResult(task))));
      const results = await Promise.all([
        operations.getXrayPortProbeOperationResult(first.operationId, 1),
        operations.getXrayPortProbeOperationResult(second.operationId, 1),
      ]);
      const successes = results.filter((result) => result.status === "SUCCESS");
      const failures = results.filter((result) => result.status === "FAILED");
      assert.equal(successes.length, 1);
      assert.equal(failures.length, 1);
      assert.equal(successes[0].selectedPort, 16000);
      assert.equal(successes[0].network, "tcp");
      assert.equal(failures[0].errorCode, "PORT_IN_USE");
      assert.equal(new Set(successes.map((result) => result.reservationId)).size, 1);
      const reserved = successes[0];

      const udpSamePort = await operations.createXrayPortProbeOperation({ hostId: 10, userId: 1, mode: "MANUAL", manualPort: 16000, network: "UDP" });
      const [udpSamePortTask] = await operations.takeXrayPortProbeTasks(10, 1);
      assert.deepEqual(udpSamePortTask.payload, { network: "udp", listenAddress: "0.0.0.0", ports: [16000] });
      await operations.completeXrayPortProbeTask(10, successfulResult(udpSamePortTask));
      const udpReserved = await operations.getXrayPortProbeOperationResult(udpSamePort.operationId, 1);
      assert.equal(udpReserved.network, "udp");
      await expectCode(Promise.resolve().then(() => operations.validateXrayPortReservation({ reservationId: udpReserved.reservationId, hostId: 10, userId: 1, port: 16000 })), "PORT_RESERVATION_MISMATCH");
      assert.equal(operations.validateXrayPortReservation({ reservationId: udpReserved.reservationId, hostId: 10, userId: 1, port: 16000, network: "UDP" }).network, "udp");

      assert.equal(operations.validateXrayPortReservation({ reservationId: reserved.reservationId, hostId: 10, userId: 1, port: 16000 }).port, 16000);
      await expectCode(Promise.resolve().then(() => operations.validateXrayPortReservation({ reservationId: reserved.reservationId, hostId: 11, userId: 1, port: 16000 })), "PORT_RESERVATION_MISMATCH");
      await expectCode(Promise.resolve().then(() => operations.validateXrayPortReservation({ reservationId: reserved.reservationId, hostId: 10, userId: 2, port: 16000 })), "PORT_RESERVATION_MISMATCH");
      await expectCode(Promise.resolve().then(() => operations.validateXrayPortReservation({ reservationId: reserved.reservationId, hostId: 10, userId: 1, port: 16001 })), "PORT_RESERVATION_MISMATCH");
      await expectCode(Promise.resolve().then(() => operations.validateXrayPortReservation({ reservationId: reserved.reservationId, hostId: 10, userId: 1, port: 16000 }, Date.parse(reserved.expiresAt) + 1)), "PORT_RESERVATION_EXPIRED");

      const reprobe = await operations.createXrayPortProbeOperation({ hostId: 10, userId: 1, mode: "MANUAL", manualPort: 16000 });
      assert.match(reprobe.operationId, /^[A-Za-z0-9._:-]{1,64}$/);
      await expectCode(operations.getXrayPortProbeOperationResult(reprobe.operationId, 2), "PORT_RESERVATION_MISMATCH");
      assert.equal(await operations.hasQueuedXrayPortProbeTasks(10), true);
      const [reprobeTask] = await operations.takeXrayPortProbeTasks(10, 1);
      const accepted = await operations.acceptXrayTaskResults(10, [
        { schemaVersion: 1, taskId: "malformed", privateKey: "must-not-be-accepted" },
        successfulResult(reprobeTask),
      ]);
      assert.deepEqual(accepted, [reprobe.operationId]);
      assert.equal((await operations.getXrayPortProbeOperationResult(reprobe.operationId, 1)).status, "SUCCESS");

      const failedOperation = await operations.createXrayPortProbeOperation({ hostId: 10, userId: 1, mode: "MANUAL", manualPort: 16001 });
      const [failedTask] = await operations.takeXrayPortProbeTasks(10, 1);
      await operations.completeXrayPortProbeTask(10, {
        schemaVersion: 1, taskId: failedTask.taskId, type: "PORT_PROBE", status: "FAILED",
        startedAt: nowIso(), finishedAt: nowIso(), result: null,
        error: { code: "PRIVATE_KEY_LEAK", message: "uuid-secret-marker", retryable: false },
      });
      const failedResult = await operations.getXrayPortProbeOperationResult(failedOperation.operationId, 1);
      assert.equal(failedResult.errorCode, "INTERNAL_ERROR");
      assert.equal(JSON.stringify(await runtime.queryRaw("SELECT errorCode, errorMessage FROM xray_operations WHERE operationId = ?", [failedOperation.operationId])).includes("uuid-secret-marker"), false);
      await runtime.executeRaw("UPDATE xray_operations SET errorCode = ? WHERE operationId = ?", ["PRIVATE_KEY_LEAK", failedOperation.operationId]);
      assert.equal((await operations.getXrayPortProbeOperationResult(failedOperation.operationId, 1)).errorCode, "INTERNAL_ERROR");

      const context = (user) => ({ req: { headers: {} }, res: { clearCookie() {} }, user, authSession: null, authFailureReason: null });
      const caller = xrayRouter.createCaller(context({ id: 1, username: "admin-a", role: "admin", accountEnabled: true }));
      const memberCaller = xrayRouter.createCaller(context({ id: 2, username: "member", role: "user", accountEnabled: true }));
      await assert.rejects(() => memberCaller.portProbes.create({ hostId: 10, mode: "MANUAL", manualPort: 16002 }), (error) => error?.code === "FORBIDDEN");
      await assert.rejects(() => caller.portProbes.create({
        hostId: 11,
        mode: "MANUAL",
        manualPort: 14000,
        targetAlias: { inboundId: Number(knownInbound.id), port: 14000 },
      }), (error) => error?.code === "BAD_REQUEST");
      await assert.rejects(() => caller.portProbes.create({ hostId: 10, mode: "AUTO", manualPort: 16002 }), (error) => error?.code === "BAD_REQUEST");
      const routed = await caller.portProbes.create({ hostId: 10, mode: "MANUAL", manualPort: 16002 });
      assert.equal((await caller.portProbes.result({ operationId: routed.operationId })).status, "QUEUED");
      const [routedTask] = await operations.takeXrayPortProbeTasks(10, 1);
      await operations.completeXrayPortProbeTask(10, successfulResult(routedTask));
      const routedResult = await caller.portProbes.result({ operationId: routed.operationId });
      assert.equal(routedResult.selectedPort, 16002);
      assert.match(routedResult.reservationId, /^[0-9a-f-]{36}$/);
      operations.consumeXrayPortReservation({ reservationId: routedResult.reservationId, hostId: 10, userId: 1, port: 16002 });

      const routedUdp = await caller.portProbes.create({ hostId: 10, mode: "MANUAL", manualPort: 16003, network: "UDP" });
      assert.equal((await caller.portProbes.result({ operationId: routedUdp.operationId })).network, "udp");
      const [routedUdpTask] = await operations.takeXrayPortProbeTasks(10, 1);
      await operations.completeXrayPortProbeTask(10, successfulResult(routedUdpTask));
      const routedUdpResult = await caller.portProbes.result({ operationId: routedUdp.operationId });
      operations.consumeXrayPortReservation({ reservationId: routedUdpResult.reservationId, hostId: 10, userId: 1, port: 16003, network: "UDP" });

      const dualTcpProbe = await caller.portProbes.create({ hostId: 10, mode: "MANUAL", manualPort: 16004, network: "TCP" });
      const [dualTcpTask] = await operations.takeXrayPortProbeTasks(10, 1);
      await operations.completeXrayPortProbeTask(10, successfulResult(dualTcpTask));
      const dualTcp = await caller.portProbes.result({ operationId: dualTcpProbe.operationId });
      const dualUdpProbe = await caller.portProbes.create({ hostId: 10, mode: "MANUAL", manualPort: 16004, network: "UDP" });
      const [dualUdpTask] = await operations.takeXrayPortProbeTasks(10, 1);
      await operations.completeXrayPortProbeTask(10, successfulResult(dualUdpTask));
      const dualUdp = await caller.portProbes.result({ operationId: dualUdpProbe.operationId });
      await expectCode(operations.withConsumedXrayPortReservations({
        tcpReservationId: dualTcp.reservationId,
        udpReservationId: dualTcp.reservationId,
        hostId: 10,
        userId: 1,
        port: 16004,
      }, async () => null), "PORT_RESERVATION_MISMATCH");
      assert.equal(operations.validateXrayPortReservation({ reservationId: dualTcp.reservationId, hostId: 10, userId: 1, port: 16004, network: "TCP" }).network, "tcp");
      assert.equal(operations.validateXrayPortReservation({ reservationId: dualUdp.reservationId, hostId: 10, userId: 1, port: 16004, network: "UDP" }).network, "udp");

      const dualTcpReprobe = await caller.portProbes.create({
        hostId: 10,
        mode: "MANUAL",
        manualPort: 16004,
        network: "TCP",
        replaceReservationIds: [dualTcp.reservationId, dualUdp.reservationId],
      });
      await expectCode(Promise.resolve().then(() => operations.validateXrayPortReservation({ reservationId: dualTcp.reservationId, hostId: 10, userId: 1, port: 16004, network: "TCP" })), "PORT_RESERVATION_EXPIRED");
      await expectCode(Promise.resolve().then(() => operations.validateXrayPortReservation({ reservationId: dualUdp.reservationId, hostId: 10, userId: 1, port: 16004, network: "UDP" })), "PORT_RESERVATION_EXPIRED");
      const [dualTcpReprobeTask] = await operations.takeXrayPortProbeTasks(10, 1);
      await operations.completeXrayPortProbeTask(10, successfulResult(dualTcpReprobeTask));
      const replacementTcp = await caller.portProbes.result({ operationId: dualTcpReprobe.operationId });
      const replacementUdpProbe = await caller.portProbes.create({ hostId: 10, mode: "MANUAL", manualPort: 16004, network: "UDP" });
      const [replacementUdpTask] = await operations.takeXrayPortProbeTasks(10, 1);
      await operations.completeXrayPortProbeTask(10, successfulResult(replacementUdpTask));
      const replacementUdp = await caller.portProbes.result({ operationId: replacementUdpProbe.operationId });
      assert.deepEqual(await operations.withConsumedXrayPortReservations({
        tcpReservationId: replacementTcp.reservationId,
        udpReservationId: replacementUdp.reservationId,
        hostId: 10,
        userId: 1,
        port: 16004,
      }, async (dual) => [dual.tcp.network, dual.udp.network]), ["tcp", "udp"]);

      const batchTcpProbe = await caller.portProbes.create({ hostId: 10, mode: "MANUAL", manualPort: 16008, network: "TCP" });
      const [batchTcpTask] = await operations.takeXrayPortProbeTasks(10, 1);
      await operations.completeXrayPortProbeTask(10, successfulResult(batchTcpTask));
      const batchTcp = await caller.portProbes.result({ operationId: batchTcpProbe.operationId });
      const batchUdpProbe = await caller.portProbes.create({ hostId: 10, mode: "MANUAL", manualPort: 16008, network: "UDP" });
      const [batchUdpTask] = await operations.takeXrayPortProbeTasks(10, 1);
      await operations.completeXrayPortProbeTask(10, successfulResult(batchUdpTask));
      const batchUdp = await caller.portProbes.result({ operationId: batchUdpProbe.operationId });
      await expectCode(Promise.resolve().then(() => operations.releaseXrayPortProbeReservations({
        userId: 2,
        reservations: [
          { reservationId: batchTcp.reservationId, hostId: 10, port: 16008, network: "TCP" },
          { reservationId: batchUdp.reservationId, hostId: 10, port: 16008, network: "UDP" },
        ],
      })), "PORT_RESERVATION_MISMATCH");
      assert.equal(operations.validateXrayPortReservation({ reservationId: batchTcp.reservationId, hostId: 10, userId: 1, port: 16008, network: "TCP" }).port, 16008);
      assert.equal(operations.validateXrayPortReservation({ reservationId: batchUdp.reservationId, hostId: 10, userId: 1, port: 16008, network: "UDP" }).port, 16008);
      const planningSecret = "quick-config-replacement-test-secret";
      const confirmedDomainTokenHash = "b".repeat(64);
      const targetVersion = "a".repeat(64);
      const now = Date.now();
      const replacementToken = signPlanningToken({
        v: 1,
        kind: "PROBE_RESULT",
        nonce: "A".repeat(22),
        runTag: "quick-config-test-run",
        userId: 1,
        confirmedDomainTokenHash,
        targetType: "XRAY_INBOUND",
        targetId: Number(knownInbound.id),
        targetVersion,
        engine: "realm",
        selectedPort: 16008,
        rewritten: true,
        carrierRoutes: [],
        carrierRoutesHash: "c".repeat(64),
        hostSetHash: "d".repeat(64),
        reservations: [
          { reservationId: batchTcp.reservationId, hostId: 10, port: 16008, network: "tcp", operationId: batchTcp.operationId, expiresAt: batchTcp.expiresAt },
          { reservationId: batchUdp.reservationId, hostId: 10, port: 16008, network: "udp", operationId: batchUdp.operationId, expiresAt: batchUdp.expiresAt },
        ],
        candidates: [],
        issuedAt: now,
        expiresAt: Math.min(Date.parse(batchTcp.expiresAt), Date.parse(batchUdp.expiresAt)),
      }, planningSecret);
      await expectCode(Promise.resolve().then(() => planning.releaseQuickConfigProbeResultReservations({
        token: replacementToken,
        userId: 2,
        confirmedDomainTokenHash,
        target: { targetType: "XRAY_INBOUND", targetId: Number(knownInbound.id), targetVersion },
      }, { tokenSecret: planningSecret })), "QUICK_CONFIG_PREVIEW_INVALID");
      assert.equal(operations.validateXrayPortReservation({ reservationId: batchTcp.reservationId, hostId: 10, userId: 1, port: 16008, network: "TCP" }).port, 16008);
      const tamperedReplacementToken = makeEquivalentNonCanonicalSignature(replacementToken);
      assert.notEqual(tamperedReplacementToken, replacementToken);
      await expectCode(Promise.resolve().then(() => planning.releaseQuickConfigProbeResultReservations({
        token: tamperedReplacementToken,
        userId: 1,
        confirmedDomainTokenHash,
        target: { targetType: "XRAY_INBOUND", targetId: Number(knownInbound.id), targetVersion },
      }, { tokenSecret: planningSecret })), "QUICK_CONFIG_PREVIEW_INVALID");
      assert.equal(operations.validateXrayPortReservation({ reservationId: batchUdp.reservationId, hostId: 10, userId: 1, port: 16008, network: "UDP" }).port, 16008);
      planning.releaseQuickConfigProbeResultReservations({
        token: replacementToken,
        userId: 1,
        confirmedDomainTokenHash,
        target: { targetType: "XRAY_INBOUND", targetId: Number(knownInbound.id), targetVersion },
      }, { tokenSecret: planningSecret });
      await expectCode(Promise.resolve().then(() => operations.validateXrayPortReservation({ reservationId: batchTcp.reservationId, hostId: 10, userId: 1, port: 16008, network: "TCP" })), "PORT_RESERVATION_EXPIRED");
      await expectCode(Promise.resolve().then(() => operations.validateXrayPortReservation({ reservationId: batchUdp.reservationId, hostId: 10, userId: 1, port: 16008, network: "UDP" })), "PORT_RESERVATION_EXPIRED");

      const initialImmediateProbe = await operations.createXrayPortProbeOperation({ hostId: 10, userId: 1, mode: "MANUAL", manualPort: 16005 });
      const [initialImmediateTask] = await operations.takeXrayPortProbeTasks(10, 1);
      await operations.completeXrayPortProbeTask(10, successfulResult(initialImmediateTask));
      const initialImmediate = await operations.getXrayPortProbeOperationResult(initialImmediateProbe.operationId, 1);
      await expectCode(
        operations.createXrayPortProbeOperation({ hostId: 10, userId: 1, mode: "MANUAL", manualPort: 16005 }),
        "PORT_IN_USE",
      );
      await expectCode(
        operations.createXrayPortProbeOperation({
          hostId: 10, userId: 2, mode: "MANUAL", manualPort: 16005,
          replaceReservationIds: [initialImmediate.reservationId],
        }),
        "PORT_RESERVATION_MISMATCH",
      );
      assert.equal(operations.validateXrayPortReservation({ reservationId: initialImmediate.reservationId, hostId: 10, userId: 1, port: 16005 }).port, 16005);
      await expectCode(
        operations.createXrayPortProbeOperation({
          hostId: 10, userId: 1, mode: "MANUAL", manualPort: 16006,
          replaceReservationIds: [initialImmediate.reservationId],
        }),
        "PORT_RESERVATION_MISMATCH",
      );
      await expectCode(
        operations.createXrayPortProbeOperation({
          hostId: 10, userId: 1, mode: "MANUAL", manualPort: 16005,
          replaceReservationIds: [initialImmediate.reservationId, initialImmediate.reservationId],
        }),
        "OPERATION_CONFLICT",
      );
      assert.equal(operations.validateXrayPortReservation({ reservationId: initialImmediate.reservationId, hostId: 10, userId: 1, port: 16005 }).port, 16005);
      const repeatedImmediateProbe = await operations.createXrayPortProbeOperation({
        hostId: 10, userId: 1, mode: "MANUAL", manualPort: 16005,
        replaceReservationIds: [initialImmediate.reservationId],
      });
      await expectCode(Promise.resolve().then(() => operations.validateXrayPortReservation({ reservationId: initialImmediate.reservationId, hostId: 10, userId: 1, port: 16005 })), "PORT_RESERVATION_EXPIRED");
      const [repeatedImmediateTask] = await operations.takeXrayPortProbeTasks(10, 1);
      await operations.completeXrayPortProbeTask(10, successfulResult(repeatedImmediateTask));
      const repeatedImmediate = await operations.getXrayPortProbeOperationResult(repeatedImmediateProbe.operationId, 1);
      assert.notEqual(repeatedImmediate.reservationId, initialImmediate.reservationId);
      operations.consumeXrayPortReservation({ reservationId: repeatedImmediate.reservationId, hostId: 10, userId: 1, port: 16005 });

      const occupiedDuringReprobe = await operations.createXrayPortProbeOperation({ hostId: 10, userId: 1, mode: "MANUAL", manualPort: 16006 });
      const [occupiedDuringReprobeTask] = await operations.takeXrayPortProbeTasks(10, 1);
      await operations.completeXrayPortProbeTask(10, successfulResult(occupiedDuringReprobeTask));
      const occupiedDuringReprobeResult = await operations.getXrayPortProbeOperationResult(occupiedDuringReprobe.operationId, 1);
      await runtime.executeRaw("INSERT INTO forward_rules (hostId, name, protocol, sourcePort, targetIp, targetPort, userId) VALUES (11, 'occupied-during-reprobe', 'tcp', 16006, '198.51.100.30', 443, 1)");
      await backfill.backfillGlobalPortAllocations();
      await expectCode(
        operations.createXrayPortProbeOperation({
          hostId: 10, userId: 1, mode: "MANUAL", manualPort: 16006,
          replaceReservationIds: [occupiedDuringReprobeResult.reservationId],
        }),
        "PORT_IN_USE",
      );
      await expectCode(Promise.resolve().then(() => operations.validateXrayPortReservation({ reservationId: occupiedDuringReprobeResult.reservationId, hostId: 10, userId: 1, port: 16006 })), "PORT_RESERVATION_EXPIRED");

      operations.consumeXrayPortReservation({ reservationId: udpReserved.reservationId, hostId: 10, userId: 1, port: 16000, network: "UDP" });
      held.release();
    } finally {
      operations.clearXrayPortOperationStateForTest();
      reservations.clearHostPortReservationsForTest();
      await runtime.closeDatabase();
    }
  `;
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: {
        ...process.env,
        DATABASE_TYPE: "sqlite",
        FORWARDX_TEST_DB: databasePath,
        JWT_SECRET: "xray-port-operations-test-secret",
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
