import assert from "node:assert/strict";
import test from "node:test";

import { initialXrayShareMemory, reduceXrayShareMemory } from "./xrayShareMemory";

test("closing a share dialog clears URI and QR memory references", () => {
  const secretUri = "vless://uuid-secret@example.com:443?sid=short-secret";
  const qr = "data:image/png;base64,qr-secret";
  let state = reduceXrayShareMemory(initialXrayShareMemory(), { type: "LOADED", uri: secretUri, displayName: "Alice", deploymentStatus: "RUNNING" });
  state = reduceXrayShareMemory(state, { type: "QR_READY", dataUrl: qr });
  assert.equal(state.uri, secretUri);
  assert.equal(state.qrDataUrl, qr);
  state = reduceXrayShareMemory(state, { type: "CLEAR" });
  assert.deepEqual(state, initialXrayShareMemory());
  assert.equal(JSON.stringify(state).includes("secret"), false);
});

test("late QR generation cannot repopulate cleared share state", () => {
  const cleared = reduceXrayShareMemory(initialXrayShareMemory(), { type: "CLEAR" });
  assert.deepEqual(reduceXrayShareMemory(cleared, { type: "QR_READY", dataUrl: "data:image/png;base64,late" }), cleared);
});

test("WireGuard config and filename are cleared with QR memory", () => {
  const config = "[Interface]\nPrivateKey = SECRET\n";
  let state = reduceXrayShareMemory(initialXrayShareMemory(), {
    type: "LOADED",
    uri: config,
    format: "WIREGUARD_CONFIG",
    fileName: "forwardx-phone.conf",
    displayName: "phone",
    deploymentStatus: "RUNNING",
  });
  state = reduceXrayShareMemory(state, { type: "QR_READY", dataUrl: "data:image/png;base64,secret" });
  assert.equal(state.uri, config);
  assert.equal(state.fileName, "forwardx-phone.conf");
  assert.equal(state.format, "WIREGUARD_CONFIG");
  assert.deepEqual(reduceXrayShareMemory(state, { type: "CLEAR" }), initialXrayShareMemory());
  assert.deepEqual(reduceXrayShareMemory(state, { type: "ERROR" }), {
    ...initialXrayShareMemory(),
    phase: "ERROR",
  });
});

test("Mixed proxy close clears both endpoints and both QR references", () => {
  let state = reduceXrayShareMemory(initialXrayShareMemory(), {
    type: "LOADED",
    uri: "socks5://user:secret@example.com:1080",
    secondaryUri: "http://user:secret@example.com:1080",
    format: "MIXED_PROXY_ENDPOINTS",
    displayName: "operator",
    deploymentStatus: "RUNNING",
  });
  state = reduceXrayShareMemory(state, { type: "QR_READY", slot: "PRIMARY", dataUrl: "data:image/png;base64,socks-secret" });
  state = reduceXrayShareMemory(state, { type: "QR_READY", slot: "SECONDARY", dataUrl: "data:image/png;base64,http-secret" });
  assert.equal(state.qrDataUrl?.includes("socks-secret"), true);
  assert.equal(state.secondaryQrDataUrl?.includes("http-secret"), true);
  const cleared = reduceXrayShareMemory(state, { type: "CLEAR" });
  assert.deepEqual(cleared, initialXrayShareMemory());
  assert.equal(JSON.stringify(cleared).includes("secret"), false);
  assert.deepEqual(
    reduceXrayShareMemory(cleared, { type: "QR_READY", slot: "SECONDARY", dataUrl: "data:image/png;base64,late-secret" }),
    cleared,
  );
});
