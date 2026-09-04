import assert from "node:assert/strict";
import test from "node:test";
import {
  createMobileReleaseDownloadToken,
  verifyMobileReleaseDownloadToken,
} from "./mobileReleaseRoute";

test("mobile release download tokens are short-lived and asset-scoped", () => {
  const token = createMobileReleaseDownloadToken(12345, 1_000);
  assert.equal(verifyMobileReleaseDownloadToken(token, 12345, 1_299), true);
  assert.equal(verifyMobileReleaseDownloadToken(token, 12346, 1_299), false);
  assert.equal(verifyMobileReleaseDownloadToken(token, 12345, 1_301), false);
  assert.equal(verifyMobileReleaseDownloadToken(`${token}x`, 12345, 1_100), false);
});
