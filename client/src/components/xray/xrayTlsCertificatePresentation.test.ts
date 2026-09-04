import assert from "node:assert/strict";
import test from "node:test";

import {
  certificateDraftError,
  certificateStatusPresentation,
} from "./xrayTlsCertificatePresentation";

test("TLS certificate UI maps expiry states and enforces browser-side text limits", () => {
  assert.deepEqual(certificateStatusPresentation("VALID"), { label: "有效", tone: "success" });
  assert.deepEqual(certificateStatusPresentation("EXPIRING_7"), { label: "7 天内到期", tone: "danger" });
  assert.deepEqual(certificateStatusPresentation("EXPIRED"), { label: "已过期", tone: "danger" });
  assert.equal(certificateDraftError({ certificatePem: "cert", privateKeyPem: "key" }), null);
  assert.equal(certificateDraftError({ certificatePem: "", privateKeyPem: "key" }), "请提供完整证书链 PEM");
  assert.equal(certificateDraftError({ certificatePem: "a".repeat(16 * 1024 + 1), privateKeyPem: "key" }), "证书链不能超过 16 KiB");
  assert.equal(certificateDraftError({ certificatePem: "cert", privateKeyPem: "a".repeat(8 * 1024 + 1) }), "私钥不能超过 8 KiB");
});
