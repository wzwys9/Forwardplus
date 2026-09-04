import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";

import { XrayInboundRemoveConfirmation } from "./XrayInboundRemoveDialog";

function render(confirmation = "", lastInbound = false, disabled = false) {
  return renderToStaticMarkup(
    <XrayInboundRemoveConfirmation
      inboundName="edge-reality"
      hostName="edge-02"
      lastInbound={lastInbound}
      confirmation={confirmation}
      onConfirmationChange={() => undefined}
      onSubmit={() => undefined}
      pending={false}
      disabled={disabled}
      errorCode={null}
    />,
  );
}

test("inbound deletion requires the exact name and never claims immediate invalidation", () => {
  const initial = render();
  assert.match(initial, /先进入待删除/);
  assert.match(initial, /旧节点和已分享凭据可能继续有效/);
  assert.match(initial, /其他节点不会被删除/);
  assert.match(initial, /disabled=""/);
  assert.doesNotMatch(render("edge-reality"), /disabled=""/);
  assert.match(render("edge-reality", false, true), /disabled=""/);
  assert.match(render("edge-reality", true), /停止受管 Xray，但保留已验证二进制/);
});
