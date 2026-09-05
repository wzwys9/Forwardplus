import { expect, test, type Page } from "@playwright/test";
import superjson from "superjson";

test("快速配置列表后台静默、手动刷新结束且失败保留卡片", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  let calls = 0;
  let release: (() => void) | undefined;
  let hold = false;
  let reject = false;
  await page.route("**/fixture-trpc/**", async route => {
    expect(new URL(route.request().url()).pathname).toBe("/fixture-trpc/xray.quickConfigs.list");
    calls += 1;
    if (hold) await new Promise<void>(resolve => { release = resolve; });
    if (reject) {
      await route.fulfill({ status: 500, contentType: "application/json", body: JSON.stringify({
        error: superjson.serialize({ message: "Fixture unavailable", code: -32603,
          data: { code: "INTERNAL_SERVER_ERROR", httpStatus: 500 } }),
      }) });
      return;
    }
    const items = [1, 2, 3, 4].map(id => ({ id, revision: 1, zoneId: 1, dnsAccountId: 1,
      fqdn: `edge${id}.example.com`, relativeName: `edge${id}`, publicPort: 33333 + id,
      targetType: "XRAY_INBOUND", targetId: id, targetName: `示例落地 ${id}`,
      engine: "realm", state: "ACTIVE", currentOperationId: null,
      createdAt: "2026-01-01T00:00:00.000Z", updatedAt: "2026-01-01T00:00:00.000Z" }));
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({ result: {
      data: superjson.serialize({ items, total: 4, page: 1, pageSize: 20 }),
    } }) });
  });
  await page.setViewportSize({ width: 320, height: 740 });
  await page.goto("/tests/fixtures/xray-path-preview.html?list=1");
  const refresh = page.getByRole("button", { name: "刷新", exact: true });
  await expect(page.getByRole("button", { name: "查看详情", exact: true })).toHaveCount(4);
  // One former 1.5 s poll period: terminal configurations must not keep polling.
  await page.waitForTimeout(1700);
  expect(calls).toBe(1);
  hold = true;
  await page.getByRole("button", { name: "模拟后台刷新", exact: true }).click();
  await expect.poll(() => calls).toBe(2);
  await expect(refresh).toHaveAttribute("aria-busy", "false");
  release!();
  await page.waitForResponse(response => response.url().includes("fixture-trpc"));
  release = undefined;
  await refresh.click();
  await expect.poll(() => calls).toBe(3);
  await expect(refresh).toHaveAttribute("aria-busy", "true");
  reject = true;
  release!();
  await expect(page.getByText("列表刷新失败或超时", { exact: true })).toBeVisible();
  await expect(refresh).toHaveAttribute("aria-busy", "false");
  await expect(refresh).toBeEnabled();
  await expect(page.getByRole("button", { name: "查看详情", exact: true })).toHaveCount(4);
  hold = false;
  reject = false;
  await refresh.click();
  await expect(page.getByText("列表刷新失败或超时", { exact: true })).toHaveCount(0);
  await expect(refresh).toHaveAttribute("aria-busy", "false");
  expect(calls).toBe(4);
  expect(errors).toEqual([]);
});

test("正式手机路径步骤保留有序中转并拒绝下一跳冲突", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.setViewportSize({ width: 320, height: 640 });
  await page.goto("/tests/fixtures/xray-path-preview.html?sample=1&formal=1");
  await page.getByRole("button", { name: "编辑运营商路径", exact: true }).click();
  await page.getByRole("button", { name: "编辑电信路径 1" }).click();
  await expect(page.getByRole("button", { name: "中转 2 使用 IPv6" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "中转 2 使用 IPv4" })).toHaveAttribute("aria-pressed", "true");
  await page.getByRole("button", { name: "入口 使用 IPv6" }).click();
  await expect(page.getByRole("button", { name: "入口 使用 IPv4" })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("button", { name: "入口 使用 IPv6" })).toHaveAttribute("aria-pressed", "true");
  const accept = page.getByRole("button", { name: "使用这些路径" });
  await expect(accept).toBeEnabled();
  await expect(accept).toBeInViewport();
  expect(await page.getByRole("dialog").first().evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
  await page.screenshot({ path: "test-results/multihop-formal-mobile.png" });
  await accept.click();
  await page.getByRole("button", { name: "下一步：端口检测" }).click();
  await expect(page.getByRole("heading", { name: "已进入端口检测" })).toBeVisible();
  const paths = JSON.parse(await page.getByTestId("accepted-paths").innerText());
  expect(paths.TELECOM[0].hops).toEqual(["1:IPV4", "2:IPV6", "3:IPV4"]);
  expect(paths.TELECOM[0].entryFamilies).toEqual(["IPV4", "IPV6"]);
  expect(JSON.parse(await page.getByTestId("accepted-inputs").innerText())).toEqual([
    { hostId: 1, addressFamily: "IPV4", relays: [{ hostId: 2, addressFamily: "IPV6" }, { hostId: 3, addressFamily: "IPV4" }] },
    { hostId: 1, addressFamily: "IPV6", relays: [{ hostId: 2, addressFamily: "IPV6" }, { hostId: 3, addressFamily: "IPV4" }] },
  ]);
  expect(errors).toEqual([]);
});

async function mockQuickConfigDialog(page: Page) {
  const requests: Array<{ procedure: string; input: unknown }> = [];
  const unexpected: string[] = [];
  let confirmations = 0;
  const hosts = ["双栈入口", "双栈中转", "仅 IPv4 备选"].map((name, index) => ({
    hostId: index + 1, name, eligible: true, disabledReasonCode: null,
    endpoints: [{ addressFamily: "IPV4", address: `8.8.8.${index + 1}` },
      ...(index < 2 ? [{ addressFamily: "IPV6", address: `2606:4700::${index + 10}` }] : [])],
  }));
  await page.route("**/fixture-trpc/**", async route => {
    const request = route.request();
    const url = new URL(request.url());
    const procedure = url.pathname.split("/").at(-1)!;
    const encoded = request.method() === "POST" ? request.postDataJSON() : JSON.parse(url.searchParams.get("input") ?? "{}");
    const input = superjson.deserialize(encoded);
    requests.push({ procedure, input });
    let result: unknown;
    if (procedure === "xray.quickConfigs.domainChecksCreate") result = {
      fqdn: "edge.example.com", conflicts: [], preservedRecords: [], allowedActions: ["USE_UNUSED_NAME"],
      confirmationHash: "a".repeat(64), domainCheckToken: "fixture-check", expiresAt: "2099-01-01T00:00:00.000Z",
    };
    else if (procedure === "xray.quickConfigs.domainChecksConfirm") result = {
      confirmedDomainToken: `fixture-expired-confirmed-${++confirmations}`, expiresAt: "2000-01-01T00:00:00.000Z",
    };
    else if (procedure === "xray.quickConfigs.entryHostsList") result = { items: hosts };
    else if (procedure === "xray.quickConfigs.forwardEngines") result = {
      defaultEngine: "realm", items: ["realm", "nftables", "gost"].map(engine => ({
        engine, label: engine === "realm" ? "Realm" : engine, isDefault: engine === "realm", eligible: true, disabledReasonCode: null,
      })),
    };
    else if (procedure === "xray.quickConfigs.portChecksCreate") result = {
      status: "SUCCESS", selectedPort: 33333, rewritten: false, probeResultToken: "fixture-probe",
      expiresAt: "2099-01-01T00:00:00.000Z", defaultRouteCandidates: [],
    };
    else { unexpected.push(procedure); result = null; }
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({ result: { data: superjson.serialize(result) } }) });
  });
  return { requests, unexpected };
}

for (const width of [300, 320]) {
  test(`真实向导 ${width}px 引擎前置、过期确认与双栈草稿保留`, async ({ page }) => {
    test.setTimeout(60_000);
    const errors: string[] = [];
    page.on("pageerror", error => errors.push(error.message));
    page.on("console", message => { if (["error", "warning"].includes(message.type())) errors.push(message.text()); });
    const fixture = await mockQuickConfigDialog(page);
    await page.setViewportSize({ width, height: 740 });
    await page.goto("/tests/fixtures/xray-path-preview.html?dialog=1");
    const nav = page.getByRole("navigation", { name: "快速配置步骤" });
    await expect(nav.getByRole("button")).toHaveText(["1域名", "2转发引擎", "3运营商路径", "4端口检测", "5默认线路", "6预览", "7执行"]);
    await page.getByLabel("相对主机记录", { exact: true }).fill("edge");
    await page.getByRole("button", { name: "检查域名", exact: true }).click();
    await page.getByRole("button", { name: "确认使用此域名", exact: true }).click();
    await expect(page.getByText("域名已确认", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "下一步：转发引擎", exact: true }).click();
    await expect(page.getByRole("heading", { name: "选择统一转发引擎" })).toBeVisible();
    await expect(page.getByRole("button", { name: /^Realm/ })).toHaveAttribute("aria-pressed", "true");
    expect(fixture.requests.filter(item => item.procedure.endsWith("forwardEngines")).every(item =>
      JSON.stringify(item.input) === JSON.stringify({ entries: [] }))).toBe(true);
    await page.getByRole("button", { name: "下一步：运营商路径", exact: true }).click();
    await page.getByRole("button", { name: "编辑运营商路径", exact: true }).click();
    await page.getByRole("button", { name: "添加路径", exact: true }).click();
    await page.getByRole("combobox", { name: "入口服务器", exact: true }).click();
    await page.getByRole("option", { name: "双栈入口", exact: true }).click();
    await page.getByRole("button", { name: "入口 使用 IPv6", exact: true }).click();
    await expect(page.getByRole("button", { name: "入口 使用 IPv4", exact: true })).toHaveAttribute("aria-pressed", "true");
    await expect(page.getByRole("button", { name: "入口 使用 IPv6", exact: true })).toHaveAttribute("aria-pressed", "true");
    await page.getByRole("button", { name: "添加中转服务器", exact: true }).click();
    await page.getByRole("combobox", { name: "中转 1 服务器", exact: true }).click();
    await page.getByRole("option", { name: "双栈中转", exact: true }).click();
    await page.getByRole("button", { name: "中转 1 使用 IPv6", exact: true }).click();
    for (const carrier of ["联通", "移动", "教育网"]) {
      await page.getByRole("button", { name: "返回路径列表", exact: true }).click();
      await page.getByRole("group", { name: "选择运营商" }).getByRole("button", { name: new RegExp(`^${carrier}`) }).click();
      await page.getByRole("combobox", { name: "复制已有路径", exact: true }).click();
      await page.getByRole("option", { name: "电信路径 1", exact: true }).click();
    }
    const accept = page.getByRole("button", { name: "使用这些路径", exact: true });
    await expect(accept).toBeEnabled();
    await expect(accept).toBeInViewport();
    await page.screenshot({ path: `test-results/quick-config-dual-stack-${width}.png` });
    await accept.click();
    const summary = await page.getByRole("heading", { name: /^(电信|联通|移动|教育网) · 1 条路径$/ }).count();
    expect(summary).toBe(4);
    await page.getByRole("button", { name: "下一步：端口检测", exact: true }).click();
    await expect.poll(() => fixture.requests.filter(item => item.procedure.endsWith("portChecksCreate")).length).toBe(1);
    const firstPort = fixture.requests.find(item => item.procedure.endsWith("portChecksCreate"))!.input;
    expect(firstPort).toMatchObject({ confirmedDomainToken: "fixture-expired-confirmed-1", engine: "realm",
      carrierRoutes: ["TELECOM", "UNICOM", "MOBILE", "EDUCATION"].map(carrier => ({ carrier, endpoints: [
        { hostId: 1, addressFamily: "IPV4", relays: [{ hostId: 2, addressFamily: "IPV6" }] },
        { hostId: 1, addressFamily: "IPV6", relays: [{ hostId: 2, addressFamily: "IPV6" }] },
      ] })) });

    await nav.getByRole("button", { name: /转发引擎/ }).click();
    await page.getByRole("button", { name: /^nftables/ }).click();
    await page.getByRole("button", { name: "下一步：运营商路径", exact: true }).click();
    await expect(page.getByRole("button", { name: "下一步：端口检测", exact: true })).toBeDisabled();
    await page.getByRole("button", { name: "编辑运营商路径", exact: true }).click();
    await page.getByRole("button", { name: "编辑电信路径 1", exact: true }).click();
    await page.getByRole("combobox", { name: "入口服务器", exact: true }).click();
    await expect(page.getByRole("option", { name: /仅 IPv4 备选/ })).toHaveAttribute("aria-disabled", "true");
    await page.keyboard.press("Escape");
    await expect(page.getByRole("button", { name: "使用这些路径", exact: true })).toBeDisabled();
    await page.getByRole("button", { name: "取消调整", exact: true }).click();
    await page.getByRole("button", { name: "丢弃并关闭", exact: true }).click();
    await page.getByRole("button", { name: "返回：转发引擎", exact: true }).click();
    await page.getByRole("button", { name: /^Realm/ }).click();
    await page.getByRole("button", { name: "下一步：运营商路径", exact: true }).click();
    await expect(page.getByRole("button", { name: "下一步：端口检测", exact: true })).toBeEnabled();
    await expect(page.getByRole("heading", { name: /^(电信|联通|移动|教育网) · 1 条路径$/ })).toHaveCount(4);

    await nav.getByRole("button", { name: /域名/ }).click();
    await page.getByRole("button", { name: "重新检查域名", exact: true }).click();
    await page.getByRole("button", { name: "确认使用此域名", exact: true }).click();
    await page.getByRole("button", { name: "下一步：转发引擎", exact: true }).click();
    await expect(page.getByRole("button", { name: /^Realm/ })).toHaveAttribute("aria-pressed", "true");
    await page.getByRole("button", { name: "下一步：运营商路径", exact: true }).click();
    await expect(page.getByRole("heading", { name: /^(电信|联通|移动|教育网) · 1 条路径$/ })).toHaveCount(4);
    const dialog = page.getByRole("dialog").first();
    expect(await dialog.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
    await page.getByRole("button", { name: "下一步：端口检测", exact: true }).click();
    await expect.poll(() => fixture.requests.filter(item => item.procedure.endsWith("portChecksCreate")).length).toBe(2);
    const lastPort = fixture.requests.filter(item => item.procedure.endsWith("portChecksCreate")).at(-1)!.input;
    expect(lastPort).toMatchObject({ ...(firstPort as object), confirmedDomainToken: "fixture-expired-confirmed-2" });
    expect(fixture.unexpected).toEqual([]);
    expect(errors).toEqual([]);
  });
}

for (const width of [320, 768, 1024, 1440]) {
  test(`路径设计在 ${width}px 可编辑且没有横向溢出`, async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (error) => errors.push(error.message));
    const apiCalls: string[] = [];
    page.on("request", (request) => { if (request.url().includes("/api/")) apiCalls.push(request.url()); });
    await page.setViewportSize({ width, height: width === 320 ? 500 : 900 });
    await page.goto("/tests/fixtures/xray-path-preview.html?sample=1");
    await expect(page.getByRole("heading", { name: "路径设计", exact: true })).toBeVisible();
    if (width < 1024) await page.getByRole("button", { name: "编辑电信路径 1" }).click();
    const next = page.getByRole("button", { name: "查看路径汇总" });
    await expect(next).toBeInViewport();
    const dialog = page.getByRole("dialog").first();
    expect(await dialog.evaluate((element) => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
    expect(await page.locator("[data-path-designer-scroll]").evaluate((element) => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
    const closeButton = dialog.getByRole("button", { name: "Close", exact: true });
    await expect(closeButton).toHaveCSS("height", "44px");
    const closeBox = await closeButton.boundingBox();
    // CSS transforms can produce 43.999996px bounds for an exact 44px button.
    expect(closeBox?.height).toBeGreaterThanOrEqual(43.99);
    await expect(page.getByRole("button", { name: "添加中转服务器" })).toBeVisible();
    await page.screenshot({ path: `test-results/path-preview-${width}.png` });
    await page.getByRole("heading", { name: "最终落地 · 已锁定" }).scrollIntoViewIfNeeded();
    await expect(page.getByRole("heading", { name: "最终落地 · 已锁定" })).toBeInViewport();
    await expect(next).toBeInViewport();
    await next.click();
    await expect(page.getByRole("heading", { name: "路径汇总" })).toBeVisible();
    await expect(page.getByText("尚未进行端口检测或网络连通性验证")).toBeVisible();
    expect(apiCalls).toEqual([]);
    expect(errors).toEqual([]);
  });
}

test("手机添加、选地址、排序、复制、删除与关闭确认", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/tests/fixtures/xray-path-preview.html");
  await page.getByRole("button", { name: "添加路径", exact: true }).click();
  await page.getByRole("combobox", { name: "入口服务器" }).click();
  const choices = await page.getByRole("listbox").boundingBox();
  expect(choices!.x).toBeGreaterThanOrEqual(0);
  expect(choices!.x + choices!.width).toBeLessThanOrEqual(390);
  await page.getByRole("option", { name: "香港 B · 电信入口", exact: true }).click();
  await page.getByRole("button", { name: "添加中转服务器" }).click();
  await page.getByRole("combobox", { name: "中转 1 服务器" }).click();
  await page.getByRole("option", { name: "日本 C · 中转", exact: true }).click();
  await page.getByRole("button", { name: "中转 1 使用 IPv6" }).click();
  await page.getByRole("button", { name: "添加中转服务器" }).click();
  await page.getByRole("combobox", { name: "中转 2 服务器" }).click();
  await page.getByRole("option", { name: "新加坡 D · 中转", exact: true }).click();
  await page.getByRole("combobox", { name: "入口服务器" }).scrollIntoViewIfNeeded();
  await page.screenshot({ path: "test-results/path-preview-mobile.png" });
  await page.getByRole("button", { name: "上移中转 2" }).click();
  await expect(page.getByRole("combobox", { name: "中转 1 服务器" })).toContainText("新加坡");
  await page.getByRole("button", { name: "删除中转 1" }).click();
  await expect(page.getByRole("combobox", { name: "中转 1 服务器" })).toContainText("日本");
  await page.getByRole("button", { name: "返回路径列表" }).click();
  await expect(page.getByRole("heading", { name: "电信的访问路径" })).toBeFocused();
  await page.getByRole("button", { name: "联通", exact: false }).first().click();
  await page.getByRole("combobox", { name: "复制已有路径" }).click();
  await page.getByRole("option", { name: /电信路径 1/ }).click();
  await expect(page.getByRole("combobox", { name: "入口服务器" })).toContainText("香港");
  await page.getByRole("button", { name: "关闭预览", exact: true }).click();
  await expect(page.getByRole("heading", { name: "丢弃路径草稿？" })).toBeVisible();
  await page.getByRole("button", { name: "继续编辑", exact: true }).click();
  await expect(page.getByRole("combobox", { name: "入口服务器" })).toContainText("香港");
  await page.getByRole("button", { name: "关闭预览", exact: true }).click();
  await page.getByRole("button", { name: "丢弃并关闭" }).click();
  await expect(page.getByText("预览已关闭")).toBeVisible();
});

test("受管本机直达不会显示自我转发路径", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/tests/fixtures/xray-path-preview.html?direct=1");
  await expect(page.getByText(/本机直达落地 ·/)).toBeVisible();
  await page.getByRole("button", { name: "编辑电信路径 1" }).click();
  await expect(page.getByRole("button", { name: "添加中转服务器" })).toBeDisabled();
  await expect(page.getByText("本机直达落地，不需要转发段。要添加中转，请先改选另一台入口服务器。")).toBeVisible();
});
