import assert from "node:assert/strict";
import test from "node:test";

import { hostDeleteDescription } from "./HostCard";

test("host deletion warning distinguishes panel cleanup from remote Xray uninstall", () => {
  const ordinary = hostDeleteDescription(null);
  assert.match(ordinary, /只会移除面板/);
  assert.match(ordinary, /不会向远端 Agent 下发停止命令/);

  const managed = hostDeleteDescription({ installedVersion: "26.7.28", inboundCount: 2 } as never);
  assert.match(managed, /Xray/);
  assert.match(managed, /显式卸载 Agent/);
  assert.match(managed, /可能继续运行/);
  assert.doesNotMatch(managed, /会同步移除/);
});
