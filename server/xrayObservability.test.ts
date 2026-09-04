import assert from "node:assert/strict";
import test from "node:test";

import { redactSupportValue } from "./supportBundle";
import {
  projectXrayAuditFields,
  projectXraySupportState,
  scrubXraySensitiveText,
  xrayStructuredLogMessage,
} from "./xrayObservability";

const secrets = {
  token: "xray-token-UNIQUE-031-secret",
  privateKey: "PRIVATEKEYUNIQUE031abcdefghijklmno1234567890_",
  uuid: "03103103-1031-4031-8031-031031031031",
  shortId: "0310310310310310",
  shareUri: "vless://03103103-1031-4031-8031-031031031031@example.com:443?sid=0310310310310310",
  trojanUri: "trojan://PASSWORDUNIQUE031@example.com:443",
  username: "HTTPUSERNAMEUNIQUE052",
  httpProxyUri: "http://HTTPUSERNAMEUNIQUE052:HTTPPASSWORDUNIQUE052@example.com:3128",
  mixedUsername: "MIXEDUSERNAMEUNIQUE052",
  mixedPassword: "MIXEDPASSWORDUNIQUE052",
  mixedSocks5Uri: "socks5://MIXEDUSERNAMEUNIQUE052:MIXEDPASSWORDUNIQUE052@example.com:1080",
  fingerprint: "FINGERPRINTUNIQUE0310123456789abcdef",
  encryptedValue: "fwdx-secret:v1:1:ENVELOPEUNIQUE031",
  certificatePem: "CERTIFICATEPEMUNIQUE046D",
  configJson: '{"inbounds":[{"settings":{"clients":[{"id":"03103103-1031-4031-8031-031031031031"}]}}]}',
};

function assertSecretsAbsent(value: unknown) {
  const encoded = typeof value === "string" ? value : JSON.stringify(value);
  for (const secret of Object.values(secrets)) assert.equal(encoded.includes(secret), false, secret);
}

test("Xray scrubber removes nested JSON, command output, URIs, UUIDs, and sensitive filenames", () => {
  const commandOutput = [
    `Authorization: Bearer ${secrets.token}`,
    `runtime={"uuid":"${secrets.uuid}","shortId":"${secrets.shortId}","privateKey":"${secrets.privateKey}","configJson":${JSON.stringify(secrets.configJson)}}`,
    `failed file=/tmp/privateKey-${secrets.privateKey}.json share=${secrets.shareUri}`,
    `fingerprint=${secrets.fingerprint} encryptedValue=${secrets.encryptedValue} uri=${secrets.trojanUri}`,
    `certificatePem=${secrets.certificatePem}`,
    `mixed={"socks5Uri":"${secrets.mixedSocks5Uri}","httpUri":"http://MIXEDUSERNAMEUNIQUE052:MIXEDPASSWORDUNIQUE052@example.com:1080"}`,
  ].join("\n");
  const scrubbed = scrubXraySensitiveText(commandOutput);
  assertSecretsAbsent(scrubbed);
  assert.match(scrubbed, /\[REDACTED\]/);

  const nested = redactSupportValue({
    safe: "kept",
    diagnostics: JSON.stringify({ commandOutput, credentials: { uuid: secrets.uuid } }),
    configJson: secrets.configJson,
  });
  assertSecretsAbsent(nested);
  assert.equal(nested.safe, "kept");
});

test("Xray support and audit projections are strict allowlists", () => {
  const raw = {
    installedVersion: "26.7.28",
    runningVersion: "26.7.28",
    serviceStatus: "RUNNING",
    appliedConfigHash: "a".repeat(64),
    binarySha256: "b".repeat(64),
    listeners: [{ runtimeTag: "forwardx-inbound-safe", port: 443, status: "READY", uuid: secrets.uuid }],
    ...secrets,
  };
  assert.deepEqual(projectXraySupportState(raw), {
    installedVersion: "26.7.28",
    runningVersion: "26.7.28",
    serviceStatus: "RUNNING",
    configHashPrefix: "aaaaaaaaaaaa",
    binaryHashPrefix: "bbbbbbbbbbbb",
    listeners: [{ runtimeTag: "forwardx-inbound-safe", port: 443, status: "READY" }],
  });
  const audit = projectXrayAuditFields({
    hostId: 7, inboundId: 8, clientId: 9, operationId: "op-safe", generation: 4,
    runtimeTag: "forwardx-inbound-safe", port: 443, status: "QUEUED", configHash: "c".repeat(64),
    ...secrets,
  });
  assert.deepEqual(audit, {
    hostId: 7, inboundId: 8, clientId: 9, operationId: "op-safe", generation: 4,
    runtimeTag: "forwardx-inbound-safe", port: 443, status: "QUEUED", configHashPrefix: "cccccccccccc",
  });
  assertSecretsAbsent(audit);
});

test("structured Xray logs serialize only approved fields and hash prefixes", () => {
  const message = xrayStructuredLogMessage("INBOUND_DELETE_QUEUED", {
    hostId: 7, inboundId: 8, operationId: "op-safe", generation: 5, status: "QUEUED",
    configHash: "d".repeat(64), ...secrets,
  });
  assert.match(message, /^\[Xray\] event=INBOUND_DELETE_QUEUED /);
  assert.match(message, /hostId=7/);
  assert.match(message, /configHashPrefix=dddddddddddd/);
  assertSecretsAbsent(message);
});
