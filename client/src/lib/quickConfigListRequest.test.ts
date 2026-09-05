import assert from "node:assert/strict";
import test from "node:test";
import { fetchQuickConfigList } from "./quickConfigListRequest";

test("list deadline aborts a stuck response body and still permits a later request", async () => {
  let signal: AbortSignal | null | undefined;
  await assert.rejects(fetchQuickConfigList("http://localhost/list", {}, async (_input, init) => {
    signal = init?.signal;
    return new Response(new ReadableStream({ start(controller) {
      init?.signal?.addEventListener("abort", () => controller.error(new Error("aborted")), { once: true });
    } }));
  }, 20), /刷新超时/);
  assert.equal(signal?.aborted, true);
  const response = await fetchQuickConfigList("http://localhost/list", {}, async () => new Response('{"items":[]}'), 100);
  assert.deepEqual(await response.json(), { items: [] });
});

test("list request preserves cancellation and credentials", async () => {
  const abort = new AbortController();
  abort.abort();
  await assert.rejects(fetchQuickConfigList("http://localhost/list", { signal: abort.signal, credentials: "include" }, async (_input, init) => {
    assert.equal(init?.credentials, "include");
    assert.equal(init?.signal?.aborted, true);
    throw new Error("aborted");
  }), /aborted/);
});
