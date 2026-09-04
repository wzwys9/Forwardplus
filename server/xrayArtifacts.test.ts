import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  XRAY_ARTIFACT_MANIFEST,
  XRAY_DEFAULT_VERSION,
  getXrayArtifactManifestEntry,
  prepareDefaultXrayArtifacts,
  resolveXrayArtifactStoragePath,
  verifyXrayArtifactFile,
} from "./xrayArtifacts";

test("the approved Xray artifact manifest is fixed to the official v26.3.27 Linux archives", () => {
  assert.equal(XRAY_DEFAULT_VERSION, "v26.3.27");
  assert.deepEqual(
    XRAY_ARTIFACT_MANIFEST.map(({ version, os: platform, arch, packageFormat, archiveName, sha256, fileSize }) => ({
      version,
      os: platform,
      arch,
      packageFormat,
      archiveName,
      sha256,
      fileSize,
    })),
    [
      {
        version: "v26.3.27",
        os: "linux",
        arch: "amd64",
        packageFormat: "zip",
        archiveName: "Xray-linux-64.zip",
        sha256: "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
        fileSize: 21_136_402,
      },
      {
        version: "v26.3.27",
        os: "linux",
        arch: "arm64",
        packageFormat: "zip",
        archiveName: "Xray-linux-arm64-v8a.zip",
        sha256: "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c",
        fileSize: 19_716_427,
      },
    ],
  );
  for (const entry of XRAY_ARTIFACT_MANIFEST) {
    assert.equal(entry.source, `https://github.com/XTLS/Xray-core/releases/download/v26.3.27/${entry.archiveName}`);
    assert.equal(entry.digestSource, `${entry.source}.dgst`);
    assert.match(entry.storageKey, /^xray\/artifacts\/v26\.3\.27\/linux\/(amd64|arm64)\/Xray-linux-[A-Za-z0-9-]+\.zip$/);
  }

  assert.throws(
    () => getXrayArtifactManifestEntry({ version: "latest", os: "linux", arch: "amd64" }),
    (error: any) => error?.code === "ARTIFACT_UNSUPPORTED",
  );
  assert.throws(
    () => getXrayArtifactManifestEntry({ version: "v26.3.27", os: "linux", arch: "armv7" }),
    (error: any) => error?.code === "ARTIFACT_UNSUPPORTED",
  );
});

test("artifact paths stay below the panel data directory and file verification rejects tampering", async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-artifact-file-"));
  try {
    const storageKey = XRAY_ARTIFACT_MANIFEST[0].storageKey;
    const resolved = resolveXrayArtifactStoragePath(directory, storageKey);
    assert.equal(resolved, path.join(directory, ...storageKey.split("/")));
    for (const unsafe of ["/tmp/xray.zip", "../xray.zip", "xray/../../xray.zip", "xray\\artifacts\\xray.zip", "./xray.zip", ""]) {
      assert.throws(
        () => resolveXrayArtifactStoragePath(directory, unsafe),
        (error: any) => error?.code === "ARTIFACT_PATH_INVALID",
        unsafe,
      );
    }

    const contents = Buffer.from("verified artifact fixture", "utf8");
    const fixture = path.join(directory, "fixture.zip");
    fs.writeFileSync(fixture, contents);
    const expected = {
      fileSize: contents.byteLength,
      sha256: crypto.createHash("sha256").update(contents).digest("hex"),
    };
    assert.deepEqual(await verifyXrayArtifactFile(fixture, expected), expected);
    await assert.rejects(
      verifyXrayArtifactFile(fixture, { ...expected, fileSize: expected.fileSize + 1 }),
      (error: any) => error?.code === "ARTIFACT_INTEGRITY_FAILED",
    );
    await assert.rejects(
      verifyXrayArtifactFile(fixture, { ...expected, sha256: "0".repeat(64) }),
      (error: any) => error?.code === "ARTIFACT_INTEGRITY_FAILED",
    );
    const symlink = path.join(directory, "fixture-link.zip");
    fs.symlinkSync(fixture, symlink);
    await assert.rejects(
      verifyXrayArtifactFile(symlink, expected),
      (error: any) => error?.code === "ARTIFACT_INTEGRITY_FAILED",
    );
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("panel startup prepares both approved architectures before setting the default version", async () => {
  const calls: string[] = [];
  await prepareDefaultXrayArtifacts({
    dataDirectory: "/var/lib/forwardx-test",
    cacheArtifact: async (identity, options) => {
      calls.push(`cache:${identity.version}:${identity.os}:${identity.arch}:${options.dataDirectory}`);
      return { artifactId: calls.length, storageKey: `${identity.arch}.zip`, sha256: "0".repeat(64), fileSize: 1 };
    },
    setDefaultVersion: async (version) => {
      calls.push(`default:${version}`);
    },
  });
  assert.deepEqual(calls, [
    "cache:v26.3.27:linux:amd64:/var/lib/forwardx-test",
    "cache:v26.3.27:linux:arm64:/var/lib/forwardx-test",
    "default:v26.3.27",
  ]);

  const failedCalls: string[] = [];
  await assert.rejects(
    prepareDefaultXrayArtifacts({
      dataDirectory: "/var/lib/forwardx-test",
      cacheArtifact: async (identity) => {
        failedCalls.push(`cache:${identity.arch}`);
        if (identity.arch === "arm64") throw new Error("fixture failure");
        return { artifactId: 1, storageKey: "amd64.zip", sha256: "0".repeat(64), fileSize: 1 };
      },
      setDefaultVersion: async () => {
        failedCalls.push("default");
      },
    }),
    /fixture failure/,
  );
  assert.deepEqual(failedCalls, ["cache:amd64", "cache:arm64"]);
});

test("artifact repository updates identities idempotently and requires a complete verified default", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "forwardx-xray-artifact-repository-"));
  const databasePath = path.join(directory, "artifact.db");
  const dataDirectory = path.join(directory, "data");
  const script = String.raw`
    import assert from "node:assert/strict";
    import path from "node:path";
    import { pathToFileURL } from "node:url";
    const moduleUrl = (file) => pathToFileURL(path.join(process.cwd(), file)).href;
    const runtime = await import(moduleUrl("server/dbRuntime.ts"));
    const schema = await import(moduleUrl("server/dbSchema.ts"));
    const artifacts = await import(moduleUrl("server/xrayArtifacts.ts"));
    const calls = [];
    const fakeFetch = async (url) => {
      calls.push(String(url));
      if (String(url).endsWith(".dgst")) {
        return new Response(
          "MD5= 207068b140fd6e63dcfabce0f16c4b21\n"
            + "SHA1= 030a8e13a9dea34adb77f9309187d75c145590f9\n"
            + "SHA2-256= 23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae\n"
            + "SHA2-512= d079b3471fc710717ed6e3cfd8caef2007e3043e24ed032495c5334109304a3af3fee4c75529d92f540454ea0876fbe23f015f37720f7318c7ad638d2aa875bc\n",
          { status: 200 },
        );
      }
      return new Response("tampered archive", { status: 200 });
    };
    try {
      await runtime.connectDatabase({ type: "sqlite", sqlite: { path: process.env.FORWARDX_TEST_DB } });
      await schema.ensureDatabaseSchema();

      for (let attempt = 0; attempt < 2; attempt += 1) {
        await assert.rejects(
          artifacts.cacheOfficialXrayArtifact(
            { version: "v26.3.27", os: "linux", arch: "amd64" },
            { dataDirectory: process.env.FORWARDX_TEST_DATA, fetchImpl: fakeFetch },
          ),
          (error) => error?.code === "ARTIFACT_INTEGRITY_FAILED",
        );
      }
      const failedRows = await runtime.queryRaw("SELECT * FROM xray_artifacts");
      assert.equal(failedRows.length, 1);
      assert.equal(failedRows[0].status, "INVALID");
      assert.equal(failedRows[0].verifiedAt, null);
      assert.equal(failedRows[0].storageKey, artifacts.XRAY_ARTIFACT_MANIFEST[0].storageKey);
      assert.equal(calls.every((url) => url.startsWith("https://github.com/XTLS/Xray-core/releases/download/v26.3.27/")), true);

      await assert.rejects(
        artifacts.cacheOfficialXrayArtifact(
          { version: "v26.3.27", os: "linux", arch: "riscv64" },
          { dataDirectory: process.env.FORWARDX_TEST_DATA, fetchImpl: async () => { throw new Error("must not fetch"); } },
        ),
        (error) => error?.code === "ARTIFACT_UNSUPPORTED",
      );
      await assert.rejects(
        artifacts.setDefaultXrayVersion("v26.3.27"),
        (error) => error?.code === "ARTIFACT_MANIFEST_INCOMPLETE",
      );

      const now = new Date();
      const first = artifacts.XRAY_ARTIFACT_MANIFEST[0];
      await runtime.executeRaw(
        "UPDATE xray_artifacts SET packageFormat = ?, storageKey = ?, sha256 = ?, fileSize = ?, status = 'VERIFIED', source = ?, verifiedAt = ?, updatedAt = ? WHERE version = ? AND os = ? AND arch = ?",
        [first.packageFormat, first.storageKey, first.sha256, first.fileSize, first.source, now, now, first.version, first.os, first.arch],
      );
      await assert.rejects(
        artifacts.setDefaultXrayVersion("v26.3.27"),
        (error) => error?.code === "ARTIFACT_MANIFEST_INCOMPLETE",
      );

      const second = artifacts.XRAY_ARTIFACT_MANIFEST[1];
      await runtime.executeRaw(
        "INSERT INTO xray_artifacts (version, os, arch, packageFormat, storageKey, sha256, fileSize, status, source, verifiedAt, createdAt, updatedAt) VALUES (?, ?, ?, ?, ?, ?, ?, 'VERIFIED', ?, ?, ?, ?)",
        [second.version, second.os, second.arch, second.packageFormat, second.storageKey, second.sha256, second.fileSize, second.source, now, now, now],
      );
      await artifacts.setDefaultXrayVersion("v26.3.27");
      assert.equal(await artifacts.getDefaultXrayVersion(), "v26.3.27");

      await runtime.executeRaw("UPDATE xray_artifacts SET storageKey = '/tmp/arbitrary.zip' WHERE arch = 'amd64'");
      await assert.rejects(
        artifacts.setDefaultXrayVersion("v26.3.27"),
        (error) => error?.code === "ARTIFACT_MANIFEST_INCOMPLETE",
      );
      assert.equal(await artifacts.getDefaultXrayVersion(), "v26.3.27", "a failed change preserves the prior setting");
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
        FORWARDX_TEST_DB: databasePath,
        FORWARDX_TEST_DATA: dataDirectory,
        JWT_SECRET: "xray-artifact-repository-test-secret",
      },
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
