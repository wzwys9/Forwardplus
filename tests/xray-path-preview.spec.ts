import { expect, test } from "@playwright/test";

test("正式手机路径步骤保留有序中转并拒绝下一跳冲突", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.setViewportSize({ width: 320, height: 640 });
  await page.goto("/tests/fixtures/xray-path-preview.html?sample=1&formal=1");
  await page.getByRole("button", { name: "编辑运营商路径", exact: true }).click();
  await page.getByRole("button", { name: "编辑电信路径 1" }).click();
  await page.getByRole("button", { name: "中转 2 使用 IPv6" }).click();
  await expect(page.getByRole("button", { name: "使用这些路径" })).toBeDisabled();
  await page.getByRole("button", { name: "中转 2 使用 IPv4" }).click();
  const accept = page.getByRole("button", { name: "使用这些路径" });
  await expect(accept).toBeEnabled();
  await expect(accept).toBeInViewport();
  expect(await page.getByRole("dialog").first().evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true);
  await page.screenshot({ path: "test-results/multihop-formal-mobile.png" });
  await accept.click();
  await page.getByRole("button", { name: "下一步：转发引擎" }).click();
  await expect(page.getByRole("heading", { name: "已进入转发引擎" })).toBeVisible();
  const paths = JSON.parse(await page.getByTestId("accepted-paths").innerText());
  expect(paths.TELECOM[0].hops).toEqual(["1:IPV4", "2:IPV6", "3:IPV4"]);
  expect(errors).toEqual([]);
});

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
