import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("encrypted backup restore round-trips Xray envelopes and never replaces an active foreign key", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-backup-"));
  const certificatePath = path.join(directory, "certificate.pem");
  const privateKeyPath = path.join(directory, "private-key.pem");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "2",
    "-subj", "/CN=backup.example.com", "-keyout", privateKeyPath, "-out", certificatePath,
    "-addext", "basicConstraints=critical,CA:FALSE",
    "-addext", "keyUsage=critical,digitalSignature,keyEncipherment",
    "-addext", "extendedKeyUsage=serverAuth",
    "-addext", "subjectAltName=DNS:backup.example.com",
  ], { stdio: "ignore" });
  const script = String.raw`
    import assert from "node:assert/strict";
    import fs from "node:fs";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const runtime = await load("server/dbRuntime.ts");
    const schema = await load("server/dbSchema.ts");
    const crypto = await load("server/xraySecretCrypto.ts");
    const backup = await load("server/xrayBackup.ts");
    const tls = await load("server/xrayTlsCertificate.ts");
    const amneziawg = await load("server/xrayAmneziaWgService.ts");
    const sourceKeyPath = path.join(process.env.FORWARDX_TEST_ROOT, "source.key");
    const targetKeyPath = path.join(process.env.FORWARDX_TEST_ROOT, "target.key");
    const foreignKeyPath = path.join(process.env.FORWARDX_TEST_ROOT, "foreign.key");
    try {
      const sourceKeyring = crypto.createXrayMasterKeyFile({ path: sourceKeyPath });
      const targetOriginal = crypto.createXrayMasterKeyFile({ path: targetKeyPath });
      const context = crypto.xrayInboundPrivateKeyContext("forwardx-inbound-backup");
      const plaintext = "PRIVATEKEYUNIQUE032-roundtrip";
      const envelope = crypto.encryptXraySecret(plaintext, context, sourceKeyring);
      const statsKey = "forwardx-access-backup";
      const uuid = "00000000-0000-4000-8000-000000000001";
      const shortId = "0102030405060708";
      const uuidContext = crypto.xrayAccessSecretContext(statsKey, "UUID");
      const shortContext = crypto.xrayAccessSecretContext(statsKey, "SHORT_ID");
      const uuidEnvelope = crypto.encryptXraySecret(uuid, uuidContext, sourceKeyring);
      const shortEnvelope = crypto.encryptXraySecret(shortId, shortContext, sourceKeyring);
      const certificateTag = "forwardx-cert-11111111-1111-4111-8111-111111111111";
      const certificateContext = crypto.xrayTlsCertificatePrivateKeyContext(certificateTag);
      const certificate = tls.validateXrayTlsCertificateInput({
        certificatePem: fs.readFileSync(process.env.FORWARDX_TEST_CERT_PATH, "utf8"),
        privateKeyPem: fs.readFileSync(process.env.FORWARDX_TEST_KEY_PATH, "utf8"),
      });
      const certificateKeyEnvelope = crypto.encryptXraySecret(certificate.privateKeyPem, certificateContext, sourceKeyring);
      const awgServiceTag = "forwardx-amneziawg-22222222-2222-4222-8222-222222222222";
      const awgAccountTag = "forwardx-amneziawg-peer-33333333-3333-4333-8333-333333333333";
      const awgService = amneziawg.generateAmneziaWgServiceMaterial();
      const awgPeer = amneziawg.generateAmneziaWgPeerMaterial();
      const awgServerContext = crypto.xrayManagedServiceInstanceSecretContext(awgServiceTag, "AMNEZIAWG_SERVER_PRIVATE_KEY");
      const awgHeaderContext = crypto.xrayManagedServiceInstanceSecretContext(awgServiceTag, "AMNEZIAWG_HEADER_PROTECTION_KEY");
      const awgPeerContext = crypto.xrayManagedServiceAccountSecretContext(awgAccountTag, "AMNEZIAWG_PRIVATE_KEY");
      const awgPskContext = crypto.xrayManagedServiceAccountSecretContext(awgAccountTag, "AMNEZIAWG_PRE_SHARED_KEY");
      const encryptedSecret = (plaintext, context) => ({
        encryptedValue: crypto.encryptXraySecret(plaintext, context, sourceKeyring),
        fingerprint: crypto.fingerprintXraySecret(plaintext, context, sourceKeyring),
        keyVersion: 1,
      });
      const externalNodeTag = "forwardx-external-44444444-4444-4444-8444-444444444444";
      const externalUuidContext = crypto.xrayExternalProxySecretContext(externalNodeTag, "VLESS_UUID");
      const externalShortIdContext = crypto.xrayExternalProxySecretContext(externalNodeTag, "VLESS_SHORT_ID");
      const snapshot = {
        version: 1,
        exportedAt: Date.now(),
        tables: {
          xray_inbounds: [{ id: 1, runtimeTag: "forwardx-inbound-backup", realityPrivateKeyEncrypted: envelope, externalProxyNodeId: 50 }],
          xray_access_entries: [{ id: 10, inboundId: 1, credentialType: "UUID_AND_SHORT_ID", settingsJson: '{"schemaVersion":1,"flow":"XTLS_RPRX_VISION"}', statsKey }],
          xray_access_secrets: [
            { accessEntryId: 10, kind: "UUID", encryptedValue: uuidEnvelope, fingerprint: crypto.fingerprintXraySecret(uuid, uuidContext, sourceKeyring), keyVersion: 1 },
            { accessEntryId: 10, kind: "SHORT_ID", encryptedValue: shortEnvelope, fingerprint: crypto.fingerprintXraySecret(shortId, shortContext, sourceKeyring), keyVersion: 1 },
          ],
          xray_inbound_secrets: [{ inboundId: 1, kind: "REALITY_PRIVATE_KEY", encryptedValue: envelope, fingerprint: crypto.fingerprintXraySecret(plaintext, context, sourceKeyring), keyVersion: 1 }],
          xray_external_proxy_nodes: [{
            id: 50, name: "Backup external", nodeTag: externalNodeTag, protocol: "VLESS_REALITY_VISION",
            address: "edge.example.com", port: 443, specVersion: 1,
            specJson: JSON.stringify({
              serverName: "cdn.example.com", fingerprint: "chrome",
              publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", spiderX: "/",
            }),
          }],
          xray_external_proxy_secrets: [
            { externalProxyNodeId: 50, kind: "VLESS_UUID", ...encryptedSecret(uuid, externalUuidContext) },
            { externalProxyNodeId: 50, kind: "VLESS_SHORT_ID", ...encryptedSecret(shortId, externalShortIdContext) },
          ],
          forward_rules: [{ id: 60, targetExternalProxyNodeId: 50 }],
          xray_managed_services: [{ id: 30, kind: "AMNEZIAWG", serviceTag: awgServiceTag, specJson: JSON.stringify(awgService.storedSpec) }],
          xray_managed_service_accounts: [{
            id: 40, serviceId: 30, accountTag: awgAccountTag, settingsVersion: 1,
            settingsJson: JSON.stringify({ address: "10.8.1.2/32", publicKey: awgPeer.publicKey }),
          }],
          xray_managed_service_secrets: [
            { accountId: 40, kind: "AMNEZIAWG_PRIVATE_KEY", ...encryptedSecret(awgPeer.privateKey, awgPeerContext) },
            { accountId: 40, kind: "AMNEZIAWG_PRE_SHARED_KEY", ...encryptedSecret(awgPeer.preSharedKey, awgPskContext) },
          ],
          xray_managed_service_instance_secrets: [
            { serviceId: 30, kind: "AMNEZIAWG_SERVER_PRIVATE_KEY", ...encryptedSecret(awgService.serverPrivateKey, awgServerContext) },
            { serviceId: 30, kind: "AMNEZIAWG_HEADER_PROTECTION_KEY", ...encryptedSecret(awgService.headerProtectionKey, awgHeaderContext) },
          ],
          xray_tls_certificates: [{
            id: 20,
            hostId: 1,
            name: "Backup TLS",
            certificateTag,
            certificateChainPem: certificate.certificateChainPem,
            privateKeyEncrypted: certificateKeyEnvelope,
            privateKeyFingerprint: crypto.fingerprintXraySecret(certificate.privateKeyPem, certificateContext, sourceKeyring),
            keyVersion: 1,
            leafFingerprintSha256: certificate.leafFingerprintSha256,
            dnsNamesJson: JSON.stringify(certificate.dnsNames),
            subject: certificate.subject,
            issuer: certificate.issuer,
            serialNumber: certificate.serialNumber,
            notBefore: certificate.notBefore,
            notAfter: certificate.notAfter,
            keyAlgorithm: certificate.keyAlgorithm,
          }],
        },
      };
      assert.equal(backup.migrationSnapshotHasXraySecrets(snapshot), true);
      backup.assertMigrationSnapshotXraySecretsAvailable(snapshot, { keyring: sourceKeyring });
      const zeroHeaderProtectionKey = Buffer.alloc(32).toString("base64");
      const zeroHeaderSnapshot = structuredClone(snapshot);
      const zeroHeaderRow = zeroHeaderSnapshot.tables.xray_managed_service_instance_secrets
        .find((row) => row.kind === "AMNEZIAWG_HEADER_PROTECTION_KEY");
      Object.assign(zeroHeaderRow, encryptedSecret(zeroHeaderProtectionKey, awgHeaderContext));
      assert.throws(
        () => backup.assertMigrationSnapshotXraySecretsAvailable(zeroHeaderSnapshot, { keyring: sourceKeyring }),
        (error) => error?.code === "SENSITIVE_DATA_UNAVAILABLE",
      );
      const corrupted = structuredClone(snapshot);
      corrupted.tables.xray_access_secrets[0].fingerprint = "f".repeat(64);
      assert.throws(
        () => backup.assertMigrationSnapshotXraySecretsAvailable(corrupted, { keyring: sourceKeyring }),
        (error) => error?.code === "SENSITIVE_DATA_UNAVAILABLE",
      );
      const corruptedCertificate = structuredClone(snapshot);
      corruptedCertificate.tables.xray_tls_certificates[0].privateKeyFingerprint = "e".repeat(64);
      assert.throws(
        () => backup.assertMigrationSnapshotXraySecretsAvailable(corruptedCertificate, { keyring: sourceKeyring }),
        (error) => error?.code === "SENSITIVE_DATA_UNAVAILABLE",
      );
      const corruptedExternalProxy = structuredClone(snapshot);
      corruptedExternalProxy.tables.xray_external_proxy_secrets[0].fingerprint = "d".repeat(64);
      assert.throws(
        () => backup.assertMigrationSnapshotXraySecretsAvailable(corruptedExternalProxy, { keyring: sourceKeyring }),
        (error) => error?.code === "SENSITIVE_DATA_UNAVAILABLE",
      );
      const duplicate = structuredClone(snapshot);
      const duplicateStatsKey = "forwardx-access-backup-duplicate";
      const duplicateUuidContext = crypto.xrayAccessSecretContext(duplicateStatsKey, "UUID");
      const duplicateShortContext = crypto.xrayAccessSecretContext(duplicateStatsKey, "SHORT_ID");
      duplicate.tables.xray_access_entries.push({ id: 11, inboundId: 1, credentialType: "UUID_AND_SHORT_ID", settingsJson: '{"schemaVersion":1,"flow":"XTLS_RPRX_VISION"}', statsKey: duplicateStatsKey });
      duplicate.tables.xray_access_secrets.push(
        { accessEntryId: 11, kind: "UUID", encryptedValue: crypto.encryptXraySecret(uuid, duplicateUuidContext, sourceKeyring), fingerprint: crypto.fingerprintXraySecret(uuid, duplicateUuidContext, sourceKeyring), keyVersion: 1 },
        { accessEntryId: 11, kind: "SHORT_ID", encryptedValue: crypto.encryptXraySecret("1112131415161718", duplicateShortContext, sourceKeyring), fingerprint: crypto.fingerprintXraySecret("1112131415161718", duplicateShortContext, sourceKeyring), keyVersion: 1 },
      );
      assert.throws(
        () => backup.assertMigrationSnapshotXraySecretsAvailable(duplicate, { keyring: sourceKeyring }),
        (error) => error?.code === "SENSITIVE_DATA_UNAVAILABLE",
      );
      const bundle = backup.createXrayMasterKeyBackupBundleForSnapshot(snapshot, { path: sourceKeyPath });
      assert.ok(bundle);
      assert.equal(JSON.stringify(snapshot).includes(fs.readFileSync(sourceKeyPath, "utf8").trim()), false);

      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();
      const prepared = await backup.prepareXrayMasterKeyBackupRestore(snapshot, bundle, { path: targetKeyPath });
      assert.deepEqual({ restored: prepared.restored, reason: prepared.reason }, {
        restored: true, reason: "installed",
      });
      assert.equal(crypto.loadXrayMasterKeyFile({ path: targetKeyPath }).keys.get("1").equals(targetOriginal.keys.get("1")), true);
      prepared.commit();
      const restored = crypto.loadXrayMasterKeyFile({ path: targetKeyPath });
      assert.equal(restored.keys.get("1").equals(sourceKeyring.keys.get("1")), true);
      assert.equal(restored.keys.get("1").equals(targetOriginal.keys.get("1")), false);
      assert.equal(crypto.decryptXraySecret(envelope, context, restored), plaintext);

      await runtime.executeRaw("INSERT INTO users (id, username, password, role) VALUES (1, 'admin', 'hash', 'admin')");
      await runtime.executeRaw("INSERT INTO hosts (id, name, ip, userId) VALUES (1, 'edge', '127.0.0.1', 1)");
      await runtime.executeRaw(
        "INSERT INTO xray_inbounds (id, hostId, name, runtimeTag, publicAddress, listenPort, realityTargetHost, realityServerName, realityPublicKey, realityPrivateKeyEncrypted, createdByUserId) VALUES (1, 1, 'node', 'forwardx-inbound-backup', '203.0.113.1', 24443, 'example.com', 'example.com', 'public', ?, 1)",
        [envelope],
      );
      crypto.createXrayMasterKeyFile({ path: foreignKeyPath });
      const foreignBundle = backup.createXrayMasterKeyBackupBundle({ path: foreignKeyPath });
      await assert.rejects(
        () => backup.prepareXrayMasterKeyBackupRestore(snapshot, foreignBundle, { path: targetKeyPath }),
        (error) => error?.code === "SENSITIVE_DATA_UNAVAILABLE",
      );
      await assert.rejects(
        () => backup.prepareXrayMasterKeyBackupRestore(snapshot, undefined, { path: targetKeyPath }),
        (error) => error?.code === "SENSITIVE_DATA_UNAVAILABLE",
      );
      assert.equal(crypto.decryptXraySecret(envelope, context, crypto.loadXrayMasterKeyFile({ path: targetKeyPath })), plaintext);

      prepared.rollback();
      assert.equal(crypto.loadXrayMasterKeyFile({ path: targetKeyPath }).keys.get("1").equals(targetOriginal.keys.get("1")), true);
      prepared.commit();
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
        FORWARDX_TEST_ROOT: directory,
        FORWARDX_TEST_CERT_PATH: certificatePath,
        FORWARDX_TEST_KEY_PATH: privateKeyPath,
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("DNS provider backup preflight rejects incomplete secrets and dangling catalog references", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-dns-backup-"));
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const load = (file) => import(pathToFileURL(path.join(process.cwd(), file)).href);
    const crypto = await load("server/xraySecretCrypto.ts");
    const backup = await load("server/xrayBackup.ts");
    const catalog = await load("server/dnsProviderCatalog.ts");
    const dnsTuple = await load("server/xrayQuickConfigDnsTuple.ts");
    const keyring = crypto.createXrayMasterKeyFile({ path: path.join(process.env.FORWARDX_TEST_ROOT, "dns.key") });
    const accountTag = "forwardx-dns-account-55555555-5555-4555-8555-555555555555";
    const catalogRevision = catalog.computeDnsProviderCatalogRevision([{
      providerZoneId: "zone-14", name: "example.com",
      lines: [{ providerLineId: "line-15", name: "默认" }],
    }]);
    const context = (kind) => crypto.xrayDnsProviderAccountSecretContext(accountTag, kind);
    const secret = (id, kind, plaintext) => ({
      id,
      accountId: 10,
      kind,
      encryptedValue: crypto.encryptXraySecret(plaintext, context(kind), keyring),
      fingerprint: crypto.fingerprintXraySecret(plaintext, context(kind), keyring),
      keyVersion: 1,
    });
    const snapshot = {
      version: 1,
      exportedAt: Date.now(),
      tables: {
        users: [{ id: 1, username: "admin" }],
        dns_provider_accounts: [{
          id: 10, accountTag, provider: "DNSPOD", name: "Global DNSPod", revision: 4,
          isDisabled: false, verificationStatus: "VALID", createdByUserId: 1,
        }],
        dns_provider_account_secrets: [
          secret(11, "DNSPOD_SECRET_ID", "AKID-backup"),
          secret(12, "DNSPOD_SECRET_KEY", "secret-key-backup"),
        ],
        dns_provider_global_bindings: [{
          id: 13, scopeKey: "XRAY_QUICK_CONFIG", accountId: 10, revision: 7,
        }],
        dns_provider_zones: [{
          id: 14, accountId: 10, providerZoneId: "zone-14", name: "example.com",
          status: "AVAILABLE", catalogRevision,
        }],
        dns_provider_record_lines: [{
          id: 15, zoneId: 14, providerLineId: "line-15", name: "默认", category: "DEFAULT",
          status: "AVAILABLE", catalogRevision,
        }],
        hosts: [{ id: 2, ip: "203.0.113.2", ipv4: "203.0.113.2" }],
        xray_inbounds: [{
          id: 20, hostId: 2, runtimeTag: "forwardx-inbound-20202020-2020-4020-8020-202020202020",
          publicAddress: "203.0.113.10",
          listenPort: 33333, protocol: "vless", transport: "tcp", security: "reality",
          profileId: "VLESS_RAW_REALITY_VISION", specVersion: 1, specJson: "{}",
        }],
        xray_quick_configs: [{
          id: 21, configTag: "forwardx-quick-config-21212121-2121-4121-8121-212121212121",
          targetType: "XRAY_INBOUND", xrayInboundId: 20, externalProxyNodeId: null,
          targetVersion: "1".repeat(64), dnsAccountId: 10, zoneId: 14,
          relativeName: "edge", fqdn: "edge.example.com", state: "APPLYING", revision: 2,
          activeTopologyRevisionId: null, desiredTopologyRevisionId: 40, currentOperationId: 42,
          createdByUserId: 1,
        }],
        xray_quick_config_domain_claims: [{
          id: 22, claimKey: "2".repeat(64), dnsAccountId: 10, zoneId: 14,
          normalizedRelativeName: "edge", quickConfigId: 21, revision: 1,
        }],
        global_port_allocations: [{
          id: 30, allocationTag: "forwardx-port-allocation-30303030-3030-4030-8030-303030303030",
          port: 33333, status: "ACTIVE", primaryOwnerType: "XRAY_INBOUND",
          primaryOwnerTag: "forwardx-inbound-20202020-2020-4020-8020-202020202020",
          reservationTokenHash: null, version: 3,
        }],
        xray_quick_config_topology_revisions: [{
          id: 40, quickConfigId: 21, revisionNumber: 1, engine: "realm",
          targetAddress: "203.0.113.10", targetPort: 33333, publicPort: 33333,
          portAllocationId: 30, state: "APPLYING", activeSlot: null, createdByUserId: 1,
        }],
        xray_quick_config_routes: [{
          id: 41, routeTag: "forwardx-quick-route-41414141-4141-4141-8141-414141414141",
          quickConfigId: 21, topologyRevisionId: 40, lineCategory: "DEFAULT",
          providerLineId: "line-15", sourceType: "MANAGED_HOST", hostId: 2,
          addressFamily: "IPV4", address: "203.0.113.2", routeMode: "FORWARD",
          sortOrder: 0, state: "PLANNED",
        }],
        forward_rules: [{
          id: 50, hostId: 2, xrayQuickConfigId: 21, forwardType: "realm", protocol: "tcp",
          sourcePort: 33333, targetIp: "203.0.113.10", targetPort: 33333,
        }],
        xray_quick_config_rule_bindings: [{
          id: 51, bindingTag: "forwardx-quick-rule-binding-51515151-5151-4151-8151-515151515151",
          quickConfigId: 21, topologyRevisionId: 40, forwardRuleId: 50, state: "PLANNED",
        }],
        xray_quick_config_operations: [{
          id: 42, operationTag: "forwardx-quick-operation-42424242-4242-4242-8242-424242424242",
          quickConfigId: 21, type: "APPLY", status: "RUNNING", phase: "CREATING_RULES",
          activeSlot: 1, revision: 2, expectedRevision: 2,
          fromTopologyRevisionId: null, toTopologyRevisionId: 40, requestSummaryJson: "{}",
          retryOfOperationId: null, executionOwnerId: "panel-test", executionFence: 1,
          createdByUserId: 1,
        }],
        xray_quick_config_operation_steps: [{
          id: 43, operationId: 42, stepKey: "rule:50:create", kind: "RULE_CREATE",
          subjectType: "RULE", subjectId: "50", status: "PENDING", attemptCount: 0,
          idempotencyKey: "quick-operation-42-rule-50-create", requestSummaryJson: "{}",
        }],
        xray_quick_config_dns_records: [{
          id: 44, quickConfigId: 21, routeId: 41, dnsAccountId: 10, zoneId: 14,
          recordTag: "forwardx-quick-record-44444444-4444-4444-8444-444444444444",
          providerRecordId: null, providerLineId: "line-15", fqdn: "edge.example.com",
          recordType: "A", value: "203.0.113.2", ttl: 600, status: "DESIRED", appliedRevision: 1,
          remoteTupleHash: dnsTuple.computeXrayQuickConfigDnsTupleHash({
            fqdn: "edge.example.com", recordType: "A", providerLineId: "line-15",
            value: "203.0.113.2", ttl: 600,
          }),
        }],
        xray_quick_config_dns_record_backups: [{
          id: 45, operationId: 42, dnsAccountId: 10, zoneId: 14,
          providerRecordId: "dns-record-before-1", fqdn: "edge.example.com", recordType: "CNAME",
          providerLineId: "line-15", value: "old.example.net", ttl: 600,
          remoteTupleHash: dnsTuple.computeXrayQuickConfigDnsTupleHash({
            fqdn: "edge.example.com", recordType: "CNAME", providerLineId: "line-15",
            value: "old.example.net", ttl: 600,
          }), snapshotOrder: 0, state: "CAPTURED",
        }],
        global_port_allocation_references: [{
          id: 31, referenceKey: "global-port-ref:v1:XRAY_INBOUND:20:host-2:TCP:PUBLIC_LISTENER", allocationId: 30,
          resourceType: "XRAY_INBOUND", resourceId: 20,
          ownerGroupTag: "forwardx-inbound-20202020-2020-4020-8020-202020202020",
          hostId: 2, network: "TCP", role: "PUBLIC_LISTENER", isOwning: true,
        }, {
          id: 32, referenceKey: "global-port-ref:v1:QUICK_CONFIG:21:host-2:BOTH:PUBLIC_LISTENER", allocationId: 30,
          resourceType: "QUICK_CONFIG", resourceId: 21,
          ownerGroupTag: "forwardx-quick-config-21212121-2121-4121-8121-212121212121",
          hostId: 2, network: "BOTH", role: "PUBLIC_LISTENER", isOwning: false,
        }],
        global_port_probe_runs: [{
          id: 46, probeTag: "forwardx-port-probe-46464646-4646-4646-8646-464646464646",
          allocationId: 30, allocationVersion: 3, candidatePort: 33333, purpose: "CANDIDATE",
          status: "RUNNING", hostSetHash: "4".repeat(64), expectedHostCount: 1,
          createdByUserId: 1,
        }],
        global_port_probe_results: [{
          id: 47, probeRunId: 46, hostId: 2, network: "tcp",
          xrayOperationId: "forwardx-port-probe-operation-47", status: "FREE",
        }],
        xray_operations: [{
          id: 60, operationId: "forwardx-port-probe-operation-47", hostId: 2,
          type: "PORT_PROBE", requestMetaJson: JSON.stringify({
            schemaVersion: 1, mode: "MANUAL", network: "tcp", candidates: [33333],
          }), createdByUserId: 1,
        }],
        global_port_scan_leases: [{
          id: 48, scopeKey: "GLOBAL_PORT_RECLAIM", leaseOwnerHash: null, leaseUntil: null,
        }],
      },
    };
    const rejects = (candidate) => assert.throws(
      () => backup.assertMigrationSnapshotXraySecretsAvailable(candidate, { keyring }),
      (error) => error?.code === "SENSITIVE_DATA_UNAVAILABLE",
    );

    assert.equal(backup.migrationSnapshotHasXraySecrets(snapshot), true);
    backup.assertMigrationSnapshotXraySecretsAvailable(snapshot, { keyring });

    const activeConfigSync = structuredClone(snapshot);
    activeConfigSync.tables.xray_quick_config_operations[0].type = "EDIT";
    activeConfigSync.tables.xray_quick_config_operations[0].requestSummaryJson = JSON.stringify({
      kind: "CONFIG_SYNC", schemaVersion: 1,
    });
    activeConfigSync.tables.xray_quick_config_operation_steps[0].kind = "DNS_CREATE";
    activeConfigSync.tables.xray_quick_config_operation_steps[0].subjectType = "DNS_RECORD";
    activeConfigSync.tables.xray_quick_config_operation_steps[0].subjectId = "44";
    activeConfigSync.tables.xray_quick_config_operation_steps[0].status = "RUNNING";
    activeConfigSync.tables.xray_quick_config_operation_steps[0].requestSummaryJson = JSON.stringify({
      kind: "DNS_SYNC_INTENT", schemaVersion: 1, preexistingExactProviderRecordIds: ["101", "202"],
    });
    backup.assertMigrationSnapshotXraySecretsAvailable(activeConfigSync, { keyring });

    const tunnelHopOwner = structuredClone(snapshot);
    tunnelHopOwner.tables.tunnels = [{
      id: 70, exitHostId: 2, mode: "forwardx", forwardxVersion: "v1",
      listenPort: 44444, mimicPort: 0,
    }];
    tunnelHopOwner.tables.tunnel_hops = [{
      id: 71, tunnelId: 70, hostId: 2, listenPort: 44444, mimicPort: 0,
    }];
    tunnelHopOwner.tables.global_port_allocations.push({
      id: 33, allocationTag: "global-port:v1:44444", port: 44444, status: "ACTIVE",
      primaryOwnerType: "TUNNEL", primaryOwnerTag: "tunnel:70", reservationTokenHash: null, version: 1,
    });
    tunnelHopOwner.tables.global_port_allocation_references.push({
      id: 34, referenceKey: "global-port-ref:v1:TUNNEL_HOP:71:host-2:TCP:PUBLIC_LISTENER",
      allocationId: 33, resourceType: "TUNNEL_HOP", resourceId: 71,
      ownerGroupTag: "tunnel:70", hostId: 2, network: "TCP",
      role: "PUBLIC_LISTENER", isOwning: true,
    });
    backup.assertMigrationSnapshotXraySecretsAvailable(tunnelHopOwner, { keyring });

    const quickConfigRuleOwner = structuredClone(snapshot);
    const quickConfigTag = quickConfigRuleOwner.tables.xray_quick_configs[0].configTag;
    quickConfigRuleOwner.tables.xray_quick_config_topology_revisions[0].publicPort = 44444;
    quickConfigRuleOwner.tables.xray_quick_config_topology_revisions[0].portAllocationId = 33;
    quickConfigRuleOwner.tables.forward_rules[0].sourcePort = 44444;
    quickConfigRuleOwner.tables.global_port_allocation_references[1].allocationId = 33;
    quickConfigRuleOwner.tables.global_port_allocation_references[1].isOwning = true;
    quickConfigRuleOwner.tables.global_port_allocations.push({
      id: 33, allocationTag: "global-port:v1:44444", port: 44444, status: "ACTIVE",
      primaryOwnerType: "QUICK_CONFIG", primaryOwnerTag: quickConfigTag,
      reservationTokenHash: null, version: 1,
    });
    quickConfigRuleOwner.tables.global_port_allocation_references.push({
      id: 34, referenceKey: "global-port-ref:v1:FORWARD_RULE:50:host-2:TCP:PUBLIC_LISTENER",
      allocationId: 33, resourceType: "FORWARD_RULE", resourceId: 50,
      ownerGroupTag: quickConfigTag, hostId: 2, network: "TCP",
      role: "PUBLIC_LISTENER", isOwning: true,
    });
    backup.assertMigrationSnapshotXraySecretsAvailable(quickConfigRuleOwner, { keyring });

    const legacyConflict = structuredClone(snapshot);
    legacyConflict.tables.global_port_allocations[0].status = "LEGACY_CONFLICT";
    legacyConflict.tables.global_port_allocations[0].primaryOwnerType = null;
    legacyConflict.tables.global_port_allocations[0].primaryOwnerTag = null;
    legacyConflict.tables.forward_rules.push({
      id: 51, hostId: 2, xrayQuickConfigId: null, forwardGroupRuleId: null,
      forwardType: "realm", protocol: "tcp", sourcePort: 33333,
      targetIp: "203.0.113.11", targetPort: 443,
    });
    legacyConflict.tables.global_port_allocation_references.push({
      id: 34, referenceKey: "global-port-ref:v1:FORWARD_RULE:51:host-2:TCP:PUBLIC_LISTENER",
      allocationId: 30, resourceType: "FORWARD_RULE", resourceId: 51,
      ownerGroupTag: "forward-rule:51", hostId: 2, network: "TCP",
      role: "PUBLIC_LISTENER", isOwning: true,
    });
    backup.assertMigrationSnapshotXraySecretsAvailable(legacyConflict, { keyring });

    const mismatchedInboundListener = structuredClone(snapshot);
    mismatchedInboundListener.tables.xray_inbounds[0].listenPort = 33334;
    rejects(mismatchedInboundListener);

    const mismatchedRuleListener = structuredClone(legacyConflict);
    mismatchedRuleListener.tables.forward_rules[1].sourcePort = 33334;
    rejects(mismatchedRuleListener);

    const nonOwningOrdinaryReference = structuredClone(snapshot);
    nonOwningOrdinaryReference.tables.global_port_allocation_references[0].isOwning = false;
    rejects(nonOwningOrdinaryReference);

    const missingSecret = structuredClone(snapshot);
    missingSecret.tables.dns_provider_account_secrets.pop();
    rejects(missingSecret);

    const wrongKind = structuredClone(snapshot);
    wrongKind.tables.dns_provider_account_secrets[1].kind = "DNSPOD_TOKEN";
    rejects(wrongKind);

    const corruptFingerprint = structuredClone(snapshot);
    corruptFingerprint.tables.dns_provider_account_secrets[0].fingerprint = "f".repeat(64);
    rejects(corruptFingerprint);

    const transplantedAccount = structuredClone(snapshot);
    transplantedAccount.tables.dns_provider_accounts[0].accountTag = "forwardx-dns-account-88888888-8888-4888-8888-888888888888";
    rejects(transplantedAccount);

    const unsafeRevision = structuredClone(snapshot);
    unsafeRevision.tables.dns_provider_accounts[0].revision = Number.MAX_SAFE_INTEGER + 1;
    rejects(unsafeRevision);

    const danglingBinding = structuredClone(snapshot);
    danglingBinding.tables.dns_provider_global_bindings[0].accountId = 999;
    rejects(danglingBinding);

    const danglingCreator = structuredClone(snapshot);
    danglingCreator.tables.dns_provider_accounts[0].createdByUserId = 999;
    rejects(danglingCreator);

    const danglingZone = structuredClone(snapshot);
    danglingZone.tables.dns_provider_zones[0].accountId = 999;
    rejects(danglingZone);

    const danglingLine = structuredClone(snapshot);
    danglingLine.tables.dns_provider_record_lines[0].zoneId = 999;
    rejects(danglingLine);

    const tamperedLineName = structuredClone(snapshot);
    tamperedLineName.tables.dns_provider_record_lines[0].name = "电信";
    rejects(tamperedLineName);

    const tamperedZoneName = structuredClone(snapshot);
    tamperedZoneName.tables.dns_provider_zones[0].name = "example.net";
    rejects(tamperedZoneName);

    const missingBinding = structuredClone(snapshot);
    missingBinding.tables.dns_provider_global_bindings = [];
    rejects(missingBinding);

    const unknownScope = structuredClone(snapshot);
    unknownScope.tables.dns_provider_global_bindings[0].scopeKey = "UNAPPROVED_SCOPE";
    rejects(unknownScope);

    const duplicateBinding = structuredClone(snapshot);
    duplicateBinding.tables.dns_provider_global_bindings.push({
      id: 16, scopeKey: "XRAY_QUICK_CONFIG", accountId: 10, revision: 7,
    });
    rejects(duplicateBinding);

    const unboundAccount = structuredClone(snapshot);
    unboundAccount.tables.dns_provider_global_bindings[0].accountId = null;
    rejects(unboundAccount);

    const invalidTargetUnion = structuredClone(snapshot);
    invalidTargetUnion.tables.xray_quick_configs[0].externalProxyNodeId = 999;
    rejects(invalidTargetUnion);

    const mismatchedRouteLine = structuredClone(snapshot);
    mismatchedRouteLine.tables.xray_quick_config_routes[0].lineCategory = "TELECOM";
    rejects(mismatchedRouteLine);

    const crossZoneBackup = structuredClone(snapshot);
    const twoZoneRevision = catalog.computeDnsProviderCatalogRevision([{
      providerZoneId: "zone-14", name: "example.com",
      lines: [{ providerLineId: "line-15", name: "默认" }],
    }, {
      providerZoneId: "zone-16", name: "example.net", lines: [],
    }]);
    crossZoneBackup.tables.dns_provider_zones[0].catalogRevision = twoZoneRevision;
    crossZoneBackup.tables.dns_provider_record_lines[0].catalogRevision = twoZoneRevision;
    crossZoneBackup.tables.dns_provider_zones.push({
      id: 16, accountId: 10, providerZoneId: "zone-16", name: "example.net",
      status: "AVAILABLE", catalogRevision: twoZoneRevision,
    });
    crossZoneBackup.tables.xray_quick_config_dns_record_backups[0].zoneId = 16;
    rejects(crossZoneBackup);

    const danglingTopology = structuredClone(snapshot);
    danglingTopology.tables.xray_quick_configs[0].desiredTopologyRevisionId = 999;
    rejects(danglingTopology);

    const invalidOperationFence = structuredClone(snapshot);
    invalidOperationFence.tables.xray_quick_config_operations[0].executionFence = Number.MAX_SAFE_INTEGER + 1;
    rejects(invalidOperationFence);

    const invalidStepSubjectType = structuredClone(snapshot);
    invalidStepSubjectType.tables.xray_quick_config_operation_steps[0].subjectType = "FORWARD_RULE";
    rejects(invalidStepSubjectType);

    const leakedSummary = structuredClone(snapshot);
    leakedSummary.tables.xray_quick_config_operations[0].requestSummaryJson = JSON.stringify({ reservationTokenHash: "5".repeat(64) });
    rejects(leakedSummary);

    const leakedConfirmationToken = structuredClone(snapshot);
    leakedConfirmationToken.tables.xray_quick_config_operations[0].requestSummaryJson = JSON.stringify({ confirmationToken: "opaque" });
    rejects(leakedConfirmationToken);

    const leakedPrivateKey = structuredClone(snapshot);
    leakedPrivateKey.tables.xray_quick_config_operation_steps[0].requestSummaryJson = JSON.stringify({ privateKey: "opaque" });
    rejects(leakedPrivateKey);

    const invalidSyncEvidence = structuredClone(activeConfigSync);
    invalidSyncEvidence.tables.xray_quick_config_operation_steps[0].requestSummaryJson = JSON.stringify({
      kind: "DNS_SYNC_INTENT", schemaVersion: 1, preexistingExactProviderRecordIds: ["202", "101"],
    });
    rejects(invalidSyncEvidence);

    const danglingManagedRule = structuredClone(snapshot);
    danglingManagedRule.tables.forward_rules[0].xrayQuickConfigId = 999;
    rejects(danglingManagedRule);

    const invalidManagedRecord = structuredClone(snapshot);
    invalidManagedRecord.tables.xray_quick_config_dns_records[0].recordType = "TXT";
    rejects(invalidManagedRecord);

    const invalidAppliedRevision = structuredClone(snapshot);
    invalidAppliedRevision.tables.xray_quick_config_dns_records[0].appliedRevision = 0;
    rejects(invalidAppliedRevision);

    const danglingReference = structuredClone(snapshot);
    danglingReference.tables.global_port_allocation_references[1].resourceId = 999;
    rejects(danglingReference);

    const unsafeAllocationVersion = structuredClone(snapshot);
    unsafeAllocationVersion.tables.global_port_allocations[0].version = 0;
    rejects(unsafeAllocationVersion);

    const nonCanonicalOwner = structuredClone(snapshot);
    nonCanonicalOwner.tables.global_port_allocations[0].primaryOwnerTag = "xray-inbound:20";
    nonCanonicalOwner.tables.global_port_allocation_references[0].ownerGroupTag = "xray-inbound:20";
    rejects(nonCanonicalOwner);

    const oversizedProbeOperation = structuredClone(snapshot);
    oversizedProbeOperation.tables.global_port_probe_results[0].xrayOperationId = "x".repeat(65);
    rejects(oversizedProbeOperation);

    const danglingProbeOperation = structuredClone(snapshot);
    danglingProbeOperation.tables.global_port_probe_results[0].xrayOperationId = "missing-operation";
    rejects(danglingProbeOperation);

    const missingScanLease = structuredClone(snapshot);
    missingScanLease.tables.global_port_scan_leases = [];
    rejects(missingScanLease);

    const duplicateScanLease = structuredClone(snapshot);
    duplicateScanLease.tables.global_port_scan_leases.push({ id: 49, scopeKey: "GLOBAL_PORT_RECLAIM" });
    rejects(duplicateScanLease);

    backup.assertMigrationSnapshotXraySecretsAvailable({
      version: 1,
      exportedAt: Date.now(),
      tables: {},
    }, { keyring });

    backup.assertMigrationSnapshotXraySecretsAvailable({
      version: 1,
      exportedAt: Date.now(),
      tables: {
        dns_provider_global_bindings: [{
          id: 1, scopeKey: "XRAY_QUICK_CONFIG", accountId: null, revision: 1,
        }],
      },
    }, { path: path.join(process.env.FORWARDX_TEST_ROOT, "missing.key") });
  `;
  try {
    const result = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", script], {
      cwd: process.cwd(),
      env: { ...process.env, FORWARDX_TEST_ROOT: directory },
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
