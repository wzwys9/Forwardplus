/** A bounded, independent request for the small quick-config summary list.
 * Include body consumption in the deadline, not only response headers. */
export async function fetchQuickConfigList(input: RequestInfo | URL, init: RequestInit = {},
  fetcher: typeof fetch = globalThis.fetch, timeoutMs = 15_000): Promise<Response> {
  const controller = new AbortController();
  const cancelled = () => controller.abort(init.signal?.reason);
  if (init.signal?.aborted) cancelled();
  else init.signal?.addEventListener("abort", cancelled, { once: true });
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      reject(new Error("列表刷新超时，请重试"));
      controller.abort();
    }, timeoutMs);
  });
  try {
    return await Promise.race([deadline, (async () => {
      const response = await fetcher(input, { ...init, signal: controller.signal });
      const body = await response.arrayBuffer();
      return new Response([204, 205, 304].includes(response.status) ? null : body,
        { status: response.status, statusText: response.statusText, headers: response.headers });
    })()]);
  } finally {
    clearTimeout(timer);
    init.signal?.removeEventListener("abort", cancelled);
  }
}
