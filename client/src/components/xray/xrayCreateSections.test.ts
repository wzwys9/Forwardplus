import assert from "node:assert/strict";
import test from "node:test";

import type { XrayCreateProfileOption } from "./xrayCreateFlow";
import {
  createProfileAxes,
  selectProfileForAxes,
} from "./xrayCreateSections";
import { XRAY_CREATE_SECTIONS, selectableXrayCreateSections } from "./XrayCreateSectionNav";

const profiles: XrayCreateProfileOption[] = [
  { id: "VLESS_RAW_REALITY_VISION", protocol: "VLESS", transport: "RAW", security: "REALITY", clientFlow: "XTLS_RPRX_VISION", listenerNetworks: ["TCP"], clientCredentialType: "UUID_AND_SHORT_ID", shareFormat: "VLESS_URI", testedCoreVersion: "v26.3.27", isAvailable: true, unavailableReasonCode: null },
  { id: "VLESS_GRPC_REALITY", protocol: "VLESS", transport: "GRPC", security: "REALITY", clientFlow: "NONE", listenerNetworks: ["TCP"], clientCredentialType: "UUID_AND_SHORT_ID", shareFormat: "VLESS_URI", testedCoreVersion: "v26.3.27", isAvailable: true, unavailableReasonCode: null },
  { id: "TROJAN_RAW_REALITY", protocol: "TROJAN", transport: "RAW", security: "REALITY", clientFlow: "NONE", listenerNetworks: ["TCP"], clientCredentialType: "PASSWORD", shareFormat: "TROJAN_URI", testedCoreVersion: "v26.3.27", isAvailable: true, unavailableReasonCode: null },
];

test("create sections choose the exact profile before probing its listener port", () => {
  assert.deepEqual(XRAY_CREATE_SECTIONS, [
    "BASIC",
    "PROTOCOL",
    "TRANSPORT",
    "PORT",
    "SECURITY",
    "ACCOUNT",
    "CONFIRM",
  ]);
});

test("profile-driven create UI derives protocol, transport, and security axes only from available profiles", () => {
  assert.deepEqual(createProfileAxes(profiles), { protocols: ["VLESS", "TROJAN"] });
  assert.deepEqual(createProfileAxes(profiles, "VLESS"), { protocols: ["VLESS", "TROJAN"], transports: ["RAW", "GRPC"] });
  assert.deepEqual(createProfileAxes(profiles, "VLESS", "GRPC"), { protocols: ["VLESS", "TROJAN"], transports: ["RAW", "GRPC"], securities: ["REALITY"] });
  assert.equal(selectProfileForAxes(profiles, { protocol: "VLESS", transport: "GRPC", security: "REALITY" })?.id, "VLESS_GRPC_REALITY");
  assert.equal(selectProfileForAxes(profiles, { protocol: "TROJAN", transport: "GRPC", security: "REALITY" }), null);
});

test("completed create sections remain selectable when a forward dependency expires", () => {
  const selectable = selectableXrayCreateSections("SECURITY", new Set(["BASIC"]));

  assert.deepEqual([...selectable], ["BASIC", "PROTOCOL", "TRANSPORT", "PORT", "SECURITY"]);
  assert.equal(selectable.has("ACCOUNT"), false);
  assert.equal(selectable.has("CONFIRM"), false);
});
