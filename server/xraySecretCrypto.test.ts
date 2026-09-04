import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  XraySecretUnavailableError,
  createXrayMasterKeyFile,
  createXraySecretKeyring,
  decryptXraySecret,
  encryptXraySecret,
  fingerprintXraySecret,
  inspectXraySecretEnvelope,
  loadXrayMasterKeyFile,
  resolveXrayMasterKeyPath,
  restoreXrayMasterKeyFile,
  xrayAccessSecretContext,
  xrayClientShortIdContext,
  xrayClientUuidContext,
  xrayDnsProviderAccountSecretContext,
  xrayInboundPrivateKeyContext,
  xrayInboundSecretContext,
  xrayTlsCertificatePrivateKeyContext,
} from "./xraySecretCrypto";

const secretContext = {
  resourceType: "xray-client",
  resourceId: "client-01JEXAMPLE",
  field: "uuid",
};

function keyring(fill: number, keyId = "1") {
  return createXraySecretKeyring({
    currentKeyId: keyId,
    keys: { [keyId]: Buffer.alloc(32, fill) },
  });
}

function withTempDirectory(run: (directory: string) => void) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-secret-"));
  try {
    run(directory);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

test("Xray secret envelope round-trips with random nonces and no plaintext", () => {
  const keys = keyring(0x11);
  const plaintext = "00000000-0000-4000-8000-000000000001";
  const first = encryptXraySecret(plaintext, secretContext, keys);
  const second = encryptXraySecret(plaintext, secretContext, keys);

  assert.match(first, /^fwdx-secret:v1:1:[A-Za-z0-9_-]+$/);
  assert.notEqual(first, second);
  assert.equal(first.includes(plaintext), false);
  assert.equal(decryptXraySecret(first, secretContext, keys), plaintext);
  assert.equal(decryptXraySecret(second, secretContext, keys), plaintext);
});

test("wrong key, AAD, keyId, and tampering fail without exposing plaintext", () => {
  const plaintext = "test-private-key-do-not-log";
  const envelope = encryptXraySecret(plaintext, secretContext, keyring(0x22));
  const changedTail = `${envelope.slice(0, -1)}${envelope.endsWith("A") ? "B" : "A"}`;
  const cases = [
    () => decryptXraySecret(envelope, secretContext, keyring(0x23)),
    () => decryptXraySecret(envelope, { ...secretContext, resourceId: "client-other" }, keyring(0x22)),
    () => decryptXraySecret(envelope.replace("v1:1:", "v1:missing:"), secretContext, keyring(0x22)),
    () => decryptXraySecret(changedTail, secretContext, keyring(0x22)),
  ];

  for (const operation of cases) {
    assert.throws(operation, (error: unknown) => {
      assert.ok(error instanceof XraySecretUnavailableError);
      assert.equal(error.code, "SENSITIVE_DATA_UNAVAILABLE");
      assert.equal(error.message.includes(plaintext), false);
      assert.equal(error.message.includes(envelope), false);
      return true;
    });
  }
});

test("HMAC fingerprints are stable, context-bound, and non-reversible", () => {
  const keys = keyring(0x33);
  const plaintext = "0123456789abcdef";
  const first = fingerprintXraySecret(plaintext, secretContext, keys);

  assert.match(first, /^[0-9a-f]{64}$/);
  assert.equal(fingerprintXraySecret(plaintext, secretContext, keys), first);
  assert.notEqual(fingerprintXraySecret(`${plaintext}00`, secretContext, keys), first);
  assert.notEqual(fingerprintXraySecret(plaintext, { ...secretContext, field: "shortId" }, keys), first);
  assert.equal(fingerprintXraySecret(plaintext, { ...secretContext, resourceId: "another-resource" }, keys), first);
  assert.equal(first.includes(plaintext), false);
});

test("DNSPod account secrets are isolated by kind and immutable accountTag", () => {
  const keys = keyring(0x35);
  const plaintext = "dnspod-secret-material-do-not-log";
  const accountTag = "forwardx-dns-provider-account-00000000-0000-4000-8000-000000000001";
  const idContext = xrayDnsProviderAccountSecretContext(accountTag, "DNSPOD_SECRET_ID");
  const keyContext = xrayDnsProviderAccountSecretContext(accountTag, "DNSPOD_SECRET_KEY");
  const envelope = encryptXraySecret(plaintext, idContext, keys);
  const transplantedContext = xrayDnsProviderAccountSecretContext(
    "forwardx-dns-provider-account-00000000-0000-4000-8000-000000000002",
    "DNSPOD_SECRET_ID",
  );
  const changedTail = `${envelope.slice(0, -1)}${envelope.endsWith("A") ? "B" : "A"}`;

  assert.deepEqual(idContext, {
    resourceType: "dns-provider-account",
    resourceId: accountTag,
    field: "dnspod-secret-id",
  });
  assert.deepEqual(keyContext, {
    resourceType: "dns-provider-account",
    resourceId: accountTag,
    field: "dnspod-secret-key",
  });
  assert.equal(decryptXraySecret(envelope, idContext, keys), plaintext);

  for (const operation of [
    () => decryptXraySecret(envelope, keyContext, keys),
    () => decryptXraySecret(envelope, transplantedContext, keys),
    () => decryptXraySecret(changedTail, idContext, keys),
  ]) {
    assert.throws(operation, (error: unknown) => {
      assert.ok(error instanceof XraySecretUnavailableError);
      assert.equal(error.code, "SENSITIVE_DATA_UNAVAILABLE");
      assert.equal(error.message.includes(plaintext), false);
      assert.equal(error.message.includes(envelope), false);
      return true;
    });
  }
});

test("DNSPod fingerprints retain the generic HMAC and plaintext-byte contract", () => {
  const keys = keyring(0x33);
  const plaintext = "0123456789abcdef";
  const firstAccount = "forwardx-dns-provider-account-00000000-0000-4000-8000-000000000001";
  const secondAccount = "forwardx-dns-provider-account-00000000-0000-4000-8000-000000000002";
  const secretId = xrayDnsProviderAccountSecretContext(firstAccount, "DNSPOD_SECRET_ID");
  const otherAccountSecretId = xrayDnsProviderAccountSecretContext(secondAccount, "DNSPOD_SECRET_ID");
  const secretKey = xrayDnsProviderAccountSecretContext(firstAccount, "DNSPOD_SECRET_KEY");

  assert.equal(
    fingerprintXraySecret(plaintext, secretContext, keys),
    "563dc717a12de55224a186059e1c54a57e17711b4f946092b867075f35d1f06a",
  );
  assert.equal(
    fingerprintXraySecret(plaintext, secretId, keys),
    fingerprintXraySecret(plaintext, otherAccountSecretId, keys),
  );
  assert.notEqual(
    fingerprintXraySecret(plaintext, secretId, keys),
    fingerprintXraySecret(plaintext, secretKey, keys),
  );
  assert.equal(
    fingerprintXraySecret("密钥-ß", secretContext, keys),
    "8c988f8d71a7c64b297f7efe71ebde28be6f2fc43b66da33a401fedeb3c0c5a7",
  );
  assert.throws(
    () => xrayDnsProviderAccountSecretContext(firstAccount, "UNKNOWN" as never),
    (error: unknown) => error instanceof XraySecretUnavailableError,
  );
});

test("generic access and inbound contexts preserve legacy VLESS envelopes", () => {
  assert.deepEqual(xrayAccessSecretContext("stats-a", "UUID"), xrayClientUuidContext("stats-a"));
  assert.deepEqual(xrayAccessSecretContext("stats-a", "SHORT_ID"), xrayClientShortIdContext("stats-a"));
  assert.deepEqual(
    xrayInboundSecretContext("runtime-a", "REALITY_PRIVATE_KEY"),
    xrayInboundPrivateKeyContext("runtime-a"),
  );

  assert.notDeepEqual(
    xrayAccessSecretContext("stats-a", "PASSWORD"),
    xrayAccessSecretContext("stats-a", "HYSTERIA_AUTH"),
  );
  assert.deepEqual(xrayAccessSecretContext("stats-a", "SHADOWSOCKS_KEY"), {
    resourceType: "xray-access",
    resourceId: "stats-a",
    field: "shadowsocks-key",
  });
  assert.deepEqual(xrayInboundSecretContext("runtime-a", "SHADOWSOCKS_SERVER_KEY"), {
    resourceType: "xray-inbound",
    resourceId: "runtime-a",
    field: "shadowsocks-server-key",
  });
  assert.notDeepEqual(
    xrayAccessSecretContext("runtime-a", "SHADOWSOCKS_KEY"),
    xrayInboundSecretContext("runtime-a", "SHADOWSOCKS_SERVER_KEY"),
  );
  assert.notDeepEqual(
    xrayInboundSecretContext("runtime-a", "TLS_PRIVATE_KEY"),
    xrayInboundSecretContext("runtime-a", "PRIVATE_KEY"),
  );
  assert.deepEqual(xrayTlsCertificatePrivateKeyContext("forwardx-cert-a"), {
    resourceType: "xray-tls-certificate",
    resourceId: "forwardx-cert-a",
    field: "tls-private-key",
  });
  assert.notDeepEqual(
    xrayTlsCertificatePrivateKeyContext("forwardx-cert-a"),
    xrayInboundSecretContext("forwardx-cert-a", "TLS_PRIVATE_KEY"),
  );
});

test("secret envelopes expose only validated version metadata", () => {
  const keys = keyring(0x34, "12");
  const envelope = encryptXraySecret("secret", xrayAccessSecretContext("stats-a", "PASSWORD"), keys);

  assert.deepEqual(inspectXraySecretEnvelope(envelope), { version: 1, keyId: "12" });
  assert.throws(
    () => inspectXraySecretEnvelope(envelope.replace("fwdx-secret:v1", "fwdx-secret:v2")),
    (error: unknown) => error instanceof XraySecretUnavailableError,
  );
  assert.throws(
    () => xrayAccessSecretContext("stats-a", "UNKNOWN" as never),
    (error: unknown) => error instanceof XraySecretUnavailableError,
  );
});

test("master key path follows override, Docker, local production, and development defaults", () => {
  assert.equal(resolveXrayMasterKeyPath({
    env: { XRAY_MASTER_KEY_PATH: "/run/secrets/custom-xray.key" },
    cwd: "/srv/forwardx",
  }), "/run/secrets/custom-xray.key");
  assert.equal(resolveXrayMasterKeyPath({
    env: { NODE_ENV: "production", FORWARDX_PORT_MANAGEMENT: "docker" },
    cwd: "/srv/forwardx",
  }), "/data/xray-master.key");
  assert.equal(resolveXrayMasterKeyPath({
    env: { NODE_ENV: "production" },
    cwd: "/srv/forwardx",
  }), "/opt/forwardx-panel/data/xray-master.key");
  assert.equal(resolveXrayMasterKeyPath({
    env: { NODE_ENV: "development" },
    cwd: "/srv/forwardx",
  }), "/srv/forwardx/data/xray-master.key");
});

test("missing master key is unavailable and is not silently created by the loader", () => {
  withTempDirectory((directory) => {
    const keyPath = path.join(directory, "missing.key");
    assert.throws(() => loadXrayMasterKeyFile({ path: keyPath }), (error: unknown) => {
      assert.ok(error instanceof XraySecretUnavailableError);
      assert.equal(error.code, "SENSITIVE_DATA_UNAVAILABLE");
      return true;
    });
    assert.equal(fs.existsSync(keyPath), false);
  });
});

test("explicit master key creation is atomic, mode 0600, and idempotently reuses the key", () => {
  withTempDirectory((directory) => {
    const keyPath = path.join(directory, "data", "xray-master.key");
    const first = createXrayMasterKeyFile({ path: keyPath });
    const stored = fs.readFileSync(keyPath, "utf8");
    const second = createXrayMasterKeyFile({ path: keyPath });
    const stat = fs.lstatSync(keyPath);

    assert.match(stored, /^[0-9a-f]{64}\n$/);
    assert.equal(stat.isFile(), true);
    assert.equal(stat.mode & 0o777, 0o600);
    assert.equal(second.keys.get(second.currentKeyId)?.equals(first.keys.get(first.currentKeyId)!), true);
    assert.deepEqual(fs.readdirSync(path.dirname(keyPath)), ["xray-master.key"]);
  });
});

test("backup restore installs an exact master key atomically and replaces only when explicitly allowed", () => {
  withTempDirectory((directory) => {
    const keyPath = path.join(directory, "data", "xray-master.key");
    const restoredKey = Buffer.alloc(32, 0x41);
    const restored = restoreXrayMasterKeyFile({ key: restoredKey, path: keyPath });
    assert.equal(restored.keys.get("1")?.equals(restoredKey), true);
    assert.equal(fs.statSync(keyPath).mode & 0o777, 0o600);
    assert.throws(
      () => restoreXrayMasterKeyFile({ key: Buffer.alloc(32, 0x42), path: keyPath }),
      (error: unknown) => error instanceof XraySecretUnavailableError,
    );
    const replaced = restoreXrayMasterKeyFile({
      key: Buffer.alloc(32, 0x43),
      path: keyPath,
      allowReplace: true,
    });
    assert.equal(replaced.keys.get("1")?.equals(Buffer.alloc(32, 0x43)), true);
    assert.deepEqual(fs.readdirSync(path.dirname(keyPath)), ["xray-master.key"]);
  });
});

test("master key loader rejects symlinks, directories, unsafe permissions, and malformed keys", () => {
  withTempDirectory((directory) => {
    const realKey = path.join(directory, "real.key");
    fs.writeFileSync(realKey, `${crypto.randomBytes(32).toString("hex")}\n`, { mode: 0o600 });

    const symlink = path.join(directory, "symlink.key");
    fs.symlinkSync(realKey, symlink);
    const directoryTarget = path.join(directory, "directory.key");
    fs.mkdirSync(directoryTarget);
    const unsafeMode = path.join(directory, "unsafe-mode.key");
    fs.writeFileSync(unsafeMode, `${crypto.randomBytes(32).toString("hex")}\n`, { mode: 0o666 });
    fs.chmodSync(unsafeMode, 0o666);
    const malformed = path.join(directory, "malformed.key");
    fs.writeFileSync(malformed, "not-a-key\n", { mode: 0o600 });

    for (const keyPath of [symlink, directoryTarget, unsafeMode, malformed]) {
      assert.throws(() => loadXrayMasterKeyFile({ path: keyPath }), (error: unknown) => {
        assert.ok(error instanceof XraySecretUnavailableError);
        assert.equal(error.code, "SENSITIVE_DATA_UNAVAILABLE");
        assert.equal(error.message.includes(keyPath), false);
        return true;
      });
    }
  });
});

test("panel installers persist and preserve the approved master key paths", () => {
  const local = fs.readFileSync(path.join(process.cwd(), "scripts/install-panel-local.sh"), "utf8");
  const docker = fs.readFileSync(path.join(process.cwd(), "scripts/install-panel-docker.sh"), "utf8");

  assert.match(local, /key_file="\$\{XRAY_MASTER_KEY_PATH:-\$APP_DIR\/data\/xray-master\.key\}"/);
  assert.match(local, /^XRAY_MASTER_KEY_PATH=\$XRAY_MASTER_KEY_PATH$/m);
  assert.match(local, /ensure_xray_master_key\(\)/);
  assert.match(local, /mktemp "\$key_file\.tmp\.XXXXXX"/);
  assert.match(local, /ln "\$temporary" "\$key_file"/);
  assert.match(local, /chmod 600 "\$key_file"/);
  assert.match(local, /existing Xray master key/i);

  assert.match(docker, /XRAY_MASTER_KEY_PATH: \$\{XRAY_MASTER_KEY_PATH:-\/data\/xray-master\.key\}/);
  assert.match(docker, /^XRAY_MASTER_KEY_PATH=\$xray_master_key_path$/m);
  assert.match(docker, /ensure_xray_master_key\(\)/);
  assert.match(docker, /\/data\/xray-master\.key/);
  assert.match(docker, /mktemp \/data\/xray-master\.key\.tmp\.XXXXXX/);
  assert.match(docker, /ln "\$temporary" "\$key_file"/);
  assert.match(docker, /chmod 600 "\$key_file"/);
});

test("local panel installer creates a persistent mode-0600 master key and preserves it", () => {
  const local = fs.readFileSync(path.join(process.cwd(), "scripts/install-panel-local.sh"), "utf8");
  const functionStart = local.indexOf("ensure_xray_master_key() {");
  const functionEnd = local.indexOf("\nrequire_root() {", functionStart);
  assert.notEqual(functionStart, -1);
  assert.notEqual(functionEnd, -1);
  const ensureFunction = local.slice(functionStart, functionEnd);

  withTempDirectory((directory) => {
    const command = `set -euo pipefail\n${ensureFunction}\nensure_xray_master_key`;
    const environment = { ...process.env, APP_DIR: directory };
    const first = spawnSync("bash", ["-c", command], { encoding: "utf8", env: environment });
    assert.equal(first.status, 0, first.stderr);

    const keyPath = path.join(directory, "data", "xray-master.key");
    const initialKey = fs.readFileSync(keyPath, "utf8");
    assert.match(initialKey, /^[0-9a-f]{64}\n$/);
    assert.equal(fs.statSync(keyPath).mode & 0o777, 0o600);
    assert.equal(first.stdout.includes(initialKey.trim()), false);

    const second = spawnSync("bash", ["-c", command], { encoding: "utf8", env: environment });
    assert.equal(second.status, 0, second.stderr);
    assert.equal(fs.readFileSync(keyPath, "utf8"), initialKey);
    assert.match(second.stdout, /Preserving existing Xray master key/);
    assert.deepEqual(fs.readdirSync(path.dirname(keyPath)), ["xray-master.key"]);
  });
});
