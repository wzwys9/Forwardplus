import assert from "node:assert/strict";
import test from "node:test";

import { xrayOperationRefetchInterval } from "./xrayOperationPolling";

test("Xray operation polling backs off, slows while hidden, and stops at terminal state", () => {
  const createdAt = "2026-09-01T00:00:00.000Z";
  assert.equal(xrayOperationRefetchInterval({ status: "RUNNING", createdAt, now: Date.parse(createdAt) + 5_000 }), 1_000);
  assert.equal(xrayOperationRefetchInterval({ status: "RUNNING", createdAt, now: Date.parse(createdAt) + 30_000 }), 2_500);
  assert.equal(xrayOperationRefetchInterval({ status: "RUNNING", createdAt, now: Date.parse(createdAt) + 90_000 }), 5_000);
  assert.equal(xrayOperationRefetchInterval({ status: "RUNNING", createdAt, hidden: true }), 15_000);
  assert.equal(xrayOperationRefetchInterval({ status: "SUCCESS", createdAt }), false);
});
