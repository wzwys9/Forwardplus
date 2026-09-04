import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import { DnsRecordPendingChanges } from "./DnsRecordPendingChanges";

test("DNS pending changes distinguish unsaved writes and lock uncertain results", () => {
  const markup = renderToStaticMarkup(<DnsRecordPendingChanges
    drafts={[{ key: "new:1", original: null, values: { subdomain: "www", recordType: "A", lineId: 1, value: "192.0.2.1", ttl: 600 }, deleted: false }]}
    lines={[{ lineId: 1, name: "默认" }]} locked failedKey="new:1" onEdit={() => undefined} onUndo={() => undefined}
  />);
  assert.match(markup, /待新增/);
  assert.match(markup, /未点击保存前不会写入 DNSPod/);
  assert.match(markup, /本条未确认成功/);
  assert.match(markup, /192\.0\.2\.1/);
  assert.equal((markup.match(/disabled=""/g) ?? []).length, 2);
});
