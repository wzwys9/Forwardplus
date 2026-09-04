import assert from "node:assert/strict";
import test from "node:test";

import {
  buildXrayLocation,
  resolveXrayLocation,
  resolveXrayUiAccess,
  shouldShowXraySidebar,
} from "./xrayNavigation";

test("Xray UI access is fail-closed for loading, disabled, anonymous, and non-admin states", () => {
  assert.equal(resolveXrayUiAccess({ authLoading: true, userRole: null, featureLoading: true, featureError: false, featureEnabled: false }), "WAIT");
  assert.equal(resolveXrayUiAccess({ authLoading: false, userRole: null, featureLoading: false, featureError: false, featureEnabled: true }), "LOGIN");
  assert.equal(resolveXrayUiAccess({ authLoading: false, userRole: "user", featureLoading: false, featureError: false, featureEnabled: true }), "HOME");
  assert.equal(resolveXrayUiAccess({ authLoading: false, userRole: "admin", featureLoading: true, featureError: false, featureEnabled: false }), "WAIT");
  assert.equal(resolveXrayUiAccess({ authLoading: false, userRole: "admin", featureLoading: false, featureError: false, featureEnabled: false }), "HOME");
  assert.equal(resolveXrayUiAccess({ authLoading: false, userRole: "admin", featureLoading: false, featureError: false, featureEnabled: true }), "ALLOW");
  assert.equal(resolveXrayUiAccess({ authLoading: false, userRole: "admin", featureLoading: false, featureError: true, featureEnabled: true }), "HOME");
  assert.equal(shouldShowXraySidebar("admin", true), true);
  assert.equal(shouldShowXraySidebar("admin", false), false);
  assert.equal(shouldShowXraySidebar("user", true), false);
  assert.equal(shouldShowXraySidebar("admin", true, true), false);
});

test("Xray tabs and filters restore from canonical URL state", () => {
  assert.deepEqual(resolveXrayLocation("/xray"), {
    tab: "nodes", search: "", status: null, hostId: null, page: 1, operationId: null, operationScope: null, inboundId: null,
  });
  assert.deepEqual(resolveXrayLocation("/xray?tab=runtime&search=%20edge-01%20&status=STOPPED&hostId=9&page=3&operationId=sync-123&inboundId=42"), {
    tab: "runtime", search: "edge-01", status: "STOPPED", hostId: 9, page: 3, operationId: "sync-123", operationScope: null, inboundId: 42,
  });
  assert.deepEqual(resolveXrayLocation("/xray?tab=bad&status=STOPPED&hostId=-1&page=0"), {
    tab: "nodes", search: "", status: null, hostId: null, page: 1, operationId: null, operationScope: null, inboundId: null,
  });
  assert.equal(buildXrayLocation("/xray?tab=runtime&status=STOPPED&page=3", {
    tab: "nodes", search: "香港 #1", status: "RUNNING", hostId: 4, page: 2,
  }), "/xray?search=%E9%A6%99%E6%B8%AF+%231&status=RUNNING&hostId=4&page=2");
  assert.equal(buildXrayLocation("/xray?search=edge&status=ERROR&page=2", {
    tab: "runtime", status: "UNKNOWN", page: 1, operationId: "sync-123",
  }), "/xray?tab=runtime&search=edge&status=UNKNOWN&operationId=sync-123");
  assert.equal(buildXrayLocation("/xray?operationId=sync-123", { operationId: null }), "/xray");
  assert.equal(buildXrayLocation("/xray?tab=runtime", { operationId: "upgrade-1", operationScope: "runtime" }), "/xray?tab=runtime&operationId=upgrade-1&operationScope=runtime");
  assert.equal(resolveXrayLocation("/xray?operationScope=runtime").operationScope, null);
  assert.equal(buildXrayLocation("/xray", { inboundId: 42 }), "/xray?inboundId=42");
  assert.equal(resolveXrayLocation("/xray?tab=certificates&status=RUNNING&hostId=7").tab, "certificates");
  assert.equal(resolveXrayLocation("/xray?tab=certificates&status=RUNNING&hostId=7").status, null);
  assert.equal(buildXrayLocation("/xray", { tab: "certificates", hostId: 7 }), "/xray?tab=certificates&hostId=7");
  assert.equal(resolveXrayLocation("/xray?tab=external-proxies&status=RUNNING&hostId=7").tab, "external-proxies");
  assert.equal(resolveXrayLocation("/xray?tab=external-proxies&status=RUNNING&hostId=7").status, null);
  assert.equal(buildXrayLocation("/xray", { tab: "external-proxies" }), "/xray?tab=external-proxies");
  assert.equal(resolveXrayLocation("/xray?tab=quick-config").tab, "quick-config");
  assert.equal(buildXrayLocation("/xray", { tab: "quick-config" }), "/xray?tab=quick-config");
});
