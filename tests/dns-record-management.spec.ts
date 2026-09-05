import { expect, test, type Page } from "@playwright/test";

async function mockDns(page: Page, types: string[]) {
  let records = types.map((recordType, index) => ({
    providerRecordId: String(index + 1), subdomain: "www", fqdn: "www.example.com", recordType,
    providerLineId: "0", lineName: "默认", value: "192.0.2.1", ttl: 600,
    status: "ENABLE", recordRevision: `revision-${index + 1}`, inUse: false,
  }));
  let inUse = false;
  const writes: string[] = [];
  await page.route("**/fixture-trpc/**", async route => {
    const request = route.request(), url = new URL(request.url());
    const input = JSON.parse(request.method() === "GET" ? url.searchParams.get("input")! : request.postData()!).json;
    const action = url.pathname.split(".").at(-1);
    let data: unknown;
    if (action === "groups") data = { items: [{ subdomain: "www", fqdn: "www.example.com", recordCount: records.length, recordTypes: [...new Set(records.map(r => r.recordType))], inUse }], total: 1, page: 1, pageSize: 20 };
    else if (action === "list") {
      const filtered = records.filter(r => !input.search || r.recordType.includes(input.search));
      data = { items: filtered.slice((input.page - 1) * input.pageSize, input.page * input.pageSize).map(r => ({ ...r, inUse })), total: filtered.length,
        page: input.page, pageSize: input.pageSize, subdomain: { name: "www", fqdn: "www.example.com", inUse }, zone: { zoneId: 1, name: "example.com", inUse } };
    } else if (action === "deletionPreview") {
      expect(input).toEqual({ zoneId: 1, subdomain: "www" });
      const selected = records.filter(r => ["A", "AAAA", "CNAME"].includes(r.recordType));
      data = { zoneId: 1, subdomain: "www", fqdn: "www.example.com", records: selected, preservedCount: records.length - selected.length };
    } else if (action === "remove") {
      expect(request.method()).toBe("POST");
      expect(input.expectedRecordRevision).toBe(`revision-${input.providerRecordId}`);
      const record = records.find(r => r.providerRecordId === input.providerRecordId)!;
      expect(["A", "AAAA", "CNAME"]).toContain(record.recordType);
      writes.push(record.providerRecordId);
      records = records.filter(r => r !== record);
      data = { providerRecordId: record.providerRecordId };
    } else throw new Error(`unexpected DNS action ${action}`);
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({ result: { data: { json: data } } }) });
  });
  return { writes, lock: () => { inUse = true; }, records: () => records };
}

test("手机批量删除覆盖搜索外分页，确认仅暂存，保存保留其他类型", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  const mock = await mockDns(page, [...Array<string>(23).fill("A"), "AAAA", "CNAME", "TXT", "MX", "NS"]);
  await page.setViewportSize({ width: 320, height: 560 });
  await page.goto("/tests/fixtures/dns-record-management.html");
  await page.getByRole("button", { name: "管理解析" }).click();
  await page.getByLabel("搜索记录").fill("CNAME");
  await page.getByRole("button", { name: "搜索", exact: true }).click();
  await expect(page.getByText("共 1 条解析", { exact: false })).toBeVisible();
  await page.getByRole("button", { name: "删除全部解析", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("将标记删除 25 条解析，保留 3 条其他类型记录。")).toBeVisible();
  await expect(dialog.getByRole("button", { name: "标记全部删除" })).toBeDisabled();
  await page.mouse.click(1, 1);
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("button", { name: "取消", exact: true })).toBeInViewport();
  expect(await dialog.evaluate(e => e.scrollWidth <= e.clientWidth + 1)).toBe(true);
  await page.screenshot({ path: "test-results/dns-bulk-delete-mobile.png" });
  await dialog.getByRole("button", { name: "取消", exact: true }).click();
  expect(mock.writes).toEqual([]);
  await page.getByRole("button", { name: "删除全部解析", exact: true }).click();
  await dialog.getByLabel("输入完整域名确认").fill("www.example.com");
  await dialog.getByRole("button", { name: "标记全部删除" }).click();
  await expect(page.getByRole("button", { name: "保存（25）" })).toBeEnabled();
  expect(mock.writes).toEqual([]);
  await page.getByRole("button", { name: "保存（25）" }).click();
  await expect(page.getByRole("button", { name: "编辑", exact: true })).toBeVisible();
  expect(mock.writes).toHaveLength(25);
  expect(mock.records().map(r => r.recordType)).toEqual(["TXT", "MX", "NS"]);
  expect(errors).toEqual([]);
});

test("删空后正常空态，在用子域名禁止批量删除", async ({ page }) => {
  const mock = await mockDns(page, ["A"]);
  await page.goto("/tests/fixtures/dns-record-management.html");
  await page.getByRole("button", { name: "管理解析" }).click();
  await page.getByRole("button", { name: "删除全部解析", exact: true }).click();
  await page.getByLabel("输入完整域名确认").fill("www.example.com");
  await page.getByRole("button", { name: "标记全部删除" }).click();
  await page.getByRole("button", { name: "保存（1）" }).click();
  await expect(page.getByText("当前域名没有 DNS 记录", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "删除全部解析", exact: true }).click();
  await expect(page.getByText("没有可删除的 A、AAAA 或 CNAME 记录。")).toBeVisible();
  await expect(page.getByRole("button", { name: "标记全部删除" })).toBeDisabled();
  await page.getByRole("button", { name: "取消", exact: true }).click();
  mock.lock();
  await page.getByRole("button", { name: "刷新记录", exact: true }).click();
  await expect(page.getByRole("button", { name: "删除全部解析", exact: true })).toBeDisabled();
  expect(mock.writes).toHaveLength(1);
});
