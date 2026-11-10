import { test, expect } from "@playwright/test";
import { readFile, writeFile, readdir } from "node:fs/promises";
import { join } from "node:path";
const origin = "http://127.0.0.1:3417";
test("real directory → Go broker → Next.js → browser stays read-only and private", async ({
  page,
  request,
  context,
}) => {
  const config = JSON.parse(
    await readFile(".test-state/access.json", "utf8"),
  ) as {
    code: string;
    connection: { url: string; token: string };
    directory: string;
  };
  const policyErrors: string[] = [];
  page.on("console", (message) => {
    if (/content security policy|refused to/i.test(message.text()))
      policyErrors.push(message.text());
  });
  const first = await page.goto("/");
  expect(first?.status()).toBe(200);
  const csp = first?.headers()["content-security-policy"] ?? "";
  expect(csp).toContain("frame-ancestors 'none'");
  expect(csp).toContain("'nonce-");
  expect(csp).not.toContain("unsafe-inline");
  await expect(page.getByRole("heading", { name: "欢迎回来" })).toBeVisible();
  await expect(page.getByText("已输入 0 / 64 位")).toBeVisible();
  await page.screenshot({ path: ".test-state/connect.png", fullPage: true });
  const anonymous = await request.get("/api/summary");
  expect(anonymous.status()).toBe(401);
  const crossOrigin = await request.post("/api/session", {
    headers: { Origin: "https://evil.test" },
    data: { code: config.code },
  });
  expect(crossOrigin.status()).toBe(403);
  const evilHost = await request.get("/api/summary", {
    headers: { Host: "evil.test" },
  });
  expect(evilHost.status()).toBe(403);
  await page.getByLabel("本机连接码").fill(config.code);
  await expect(page.getByText("已输入 64 / 64 位")).toBeVisible();
  await page.getByRole("button", { name: "连接管理界面", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "概览", exact: true }),
  ).toBeVisible();
  await expect(page.getByText("本地目录已验证", { exact: true })).toBeVisible();
  const cookies = await context.cookies();
  const cookie = cookies.find((c) => c.name === "locklark_management");
  expect(cookie?.httpOnly).toBe(true);
  expect(cookie?.secure).toBe(true);
  expect(cookie?.sameSite).toBe("Strict");
  const replay = await request.post("/api/session", {
    headers: { Origin: origin },
    data: { code: config.code },
  });
  expect(replay.status()).toBe(401);
  const state = await page.request.get("/api/summary");
  expect(state.status()).toBe(200);
  const body = await state.text();
  for (const value of [
    config.code,
    config.connection.token,
    "never-web-password",
    "never-web-user",
    "never-web-title",
    "snapshot",
    "encryption",
    "signing",
  ])
    expect(body.includes(value)).toBe(false);
  expect(state.headers()["cache-control"]).toContain("no-store");
  const second = await page.request.get("/");
  expect(second.headers()["content-security-policy"]).not.toBe(csp);
  const html = await second.text();
  for (const secret of [
    config.code,
    config.connection.token,
    "never-web-password",
  ]) {
    expect(html.includes(secret)).toBe(false);
  }
  async function scanBundles(path: string): Promise<void> {
    for (const entry of await readdir(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) await scanBundles(child);
      else if (entry.name.endsWith(".js")) {
        const source = await readFile(child, "utf8");
        for (const secret of [config.code, config.connection.token])
          expect(source.includes(secret)).toBe(false);
      }
    }
  }
  await scanBundles(".next/static");
  await page.screenshot({ path: ".test-state/overview.png", fullPage: true });
  await page.getByRole("button", { name: "团队成员", exact: true }).click();
  await expect(page.locator("tbody tr")).toHaveCount(2);
  await page.getByLabel("搜索成员 ID").fill("nomatch");
  await expect(page.getByText("没有匹配的成员")).toBeVisible();
  await page.getByRole("button", { name: "清除筛选条件" }).click();
  await expect(page.locator("tbody tr")).toHaveCount(2);
  await page.getByRole("button", { name: "设备", exact: true }).click();
  await expect(page.locator("tbody tr")).toHaveCount(2);
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(
    page.getByRole("heading", { name: "设备", exact: true }),
  ).toBeVisible();
  await page.screenshot({
    path: ".test-state/mobile-devices.png",
    fullPage: true,
  });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  // A malformed live directory must not leave a trusted-looking cached roster.
  const original = await readFile(config.directory);
  await writeFile(config.directory, "broken");
  await page.getByRole("button", { name: "刷新状态" }).click();
  await expect(
    page.getByRole("heading", { name: "暂时无法取得可信状态" }),
  ).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(0);
  await writeFile(config.directory, original);
  await page.getByRole("button", { name: "刷新状态" }).click();
  await expect(page.locator("tbody tr")).toHaveCount(2);
  await page.getByRole("button", { name: "连接与安全", exact: true }).click();
  await page.route("**/api/session", async (route) => {
    if (route.request().method() === "DELETE") {
      await route.fetch(); // Server revokes, but its response is lost.
      await route.abort();
    } else await route.continue();
  });
  await page.getByRole("button", { name: "结束当前管理会话" }).click();
  await expect(page.getByText("断开连接未完成，请重试。")).toBeVisible();
  await expect(page.locator("tbody tr")).toHaveCount(0);
  await expect(page.locator(".stat-card")).toHaveCount(0);
  await page.getByRole("button", { name: "刷新状态" }).click();
  await expect(page.getByRole("heading", { name: "欢迎回来" })).toBeVisible();
  const revoked = await request.get("/api/summary", {
    headers: { Cookie: `locklark_management=${cookie?.value}` },
  });
  expect(revoked.status()).toBe(401);
  const direct = await request.get(`${config.connection.url}/v1/summary`, {
    headers: {
      Authorization: `Bearer ${config.connection.token}`,
      Origin: origin,
    },
  });
  expect(direct.status()).toBe(403);
  expect(policyErrors).toEqual([]);
});
