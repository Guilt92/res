// Dashboard smoke tests. Needs a running gateway:
//   E2E_BASE_URL (default http://127.0.0.1:8099)
//   E2E_USER / E2E_PASS (default admin / the RES_ADMIN_PASSWORD of the instance)
const { test, expect } = require("@playwright/test");

const USER = process.env.E2E_USER || "admin";
const PASS = process.env.E2E_PASS || "adminpass12345";
const VIEWPORTS = [
  [320, 568], [375, 812], [430, 932], [768, 1024], [1024, 768], [1366, 768], [1920, 1080],
];

async function login(page) {
  await page.goto("/");
  await page.waitForSelector("#login-user", { state: "visible" });
  await page.fill("#login-user", USER);
  await page.fill("#login-pass", PASS);
  await page.click("#login-go");
  await page.waitForSelector("#login-ov", { state: "hidden" });
  await page.waitForSelector("#kpis .kpi, #kpis > *");
}

for (const scheme of ["light", "dark"]) {
  for (const [w, h] of VIEWPORTS) {
    test(`renders cleanly: ${scheme} ${w}x${h}`, async ({ browser }) => {
      const ctx = await browser.newContext({ viewport: { width: w, height: h }, colorScheme: scheme });
      const page = await ctx.newPage();
      const errors = [];
      const failed = [];
      page.on("pageerror", (e) => errors.push(e.message));
      page.on("console", (m) => {
        // The pre-login session probe legitimately answers 401.
        if (m.type() === "error" && !/status of 401/.test(m.text())) errors.push(m.text());
      });
      page.on("requestfailed", (r) => failed.push(r.url()));
      page.on("response", (r) => {
        if (r.status() >= 400 && !(r.status() === 401 && r.url().endsWith("/api/auth/session"))) {
          failed.push(`${r.status()} ${r.url()}`);
        }
      });

      await login(page);
      await page.waitForTimeout(1500);

      expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe(scheme);
      const overflow = await page.evaluate(() => ({
        sw: document.documentElement.scrollWidth,
        cw: document.documentElement.clientWidth,
      }));
      expect(overflow.sw, "no horizontal overflow").toBeLessThanOrEqual(overflow.cw);
      expect(await page.evaluate(() => document.documentElement.getAttribute("data-js-errors"))).toBe("0");
      expect(errors, "no JavaScript/console errors").toEqual([]);
      expect(failed, "no failed requests").toEqual([]);
      await ctx.close();
    });
  }
}

test("theme choice persists across reload", async ({ browser }) => {
  const ctx = await browser.newContext({ viewport: { width: 1366, height: 768 }, colorScheme: "light" });
  const page = await ctx.newPage();
  await login(page);
  await page.click("#theme-toggle");
  await page.click("[data-theme-choice=dark]");
  expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe("dark");
  await page.reload();
  // boot.js applies the stored theme before first paint.
  expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe("dark");
  expect(await page.evaluate(() => localStorage.getItem("res-theme-pref"))).toBe("dark");
  await ctx.close();
});

test("sidebar navigation reaches every section", async ({ browser }) => {
  const ctx = await browser.newContext({ viewport: { width: 1366, height: 768 } });
  const page = await ctx.newPage();
  await login(page);
  const links = await page.$$eval("#sidenav-links a.nav-link", (as) => as.map((a) => a.getAttribute("href")));
  expect(links.length).toBeGreaterThan(5);
  for (const href of links) {
    // Child links live in collapsed groups until the group header is opened.
    const link = page.locator(`#sidenav-links a[href="${href}"]`);
    if (!(await link.isVisible())) {
      await link.locator("xpath=ancestor::div[contains(@class,'nav-group')]/button").click();
    }
    await link.click();
    await expect.poll(() => page.evaluate(() => location.hash)).toBe(href);
    const id = href.replace(/^#/, "");
    expect(await page.$(`#${id}`), `section ${id} exists`).not.toBeNull();
  }
  await ctx.close();
});

test("mobile drawer: keyboard, focus containment and touch targets", async ({ browser }) => {
  const ctx = await browser.newContext({ viewport: { width: 375, height: 812 }, hasTouch: true });
  const page = await ctx.newPage();
  await login(page);

  // Closed drawer must not be reachable by keyboard.
  const offscreen = [];
  for (let i = 0; i < 40; i++) {
    await page.keyboard.press("Tab");
    const right = await page.evaluate(() => document.activeElement.getBoundingClientRect().right);
    if (right <= 0) offscreen.push(i);
  }
  expect(offscreen, "no focus stops inside the closed drawer").toEqual([]);

  // Header and toolbar controls are at least 44x44.
  const small = await page.evaluate(() =>
    [...document.querySelectorAll(".hbar button, .hbar select, .hbar input, #nav-toggle, .title-tools button, .title-tools select, .mini-sel select, .seg button")]
      .filter((e) => e.getBoundingClientRect().width > 0)
      .map((e) => ({ id: e.id || e.className, w: Math.round(e.getBoundingClientRect().width), h: Math.round(e.getBoundingClientRect().height) }))
      .filter((r) => r.w < 44 || r.h < 44));
  expect(small, "header/toolbar touch targets >= 44px").toEqual([]);

  // Open with touch, focus moves in, Escape closes and restores focus.
  await page.tap("#nav-toggle");
  await expect(page.locator("#nav-toggle")).toHaveAttribute("aria-expanded", "true");
  expect(await page.evaluate(() => document.querySelector("#sidenav").contains(document.activeElement))).toBe(true);
  await page.keyboard.press("Escape");
  await expect(page.locator("#nav-toggle")).toHaveAttribute("aria-expanded", "false");
  // visibility flips once the slide-out transition (0.2s) has finished.
  await expect
    .poll(() => page.evaluate(() => getComputedStyle(document.querySelector("#sidenav")).visibility))
    .toBe("hidden");

  // Tapping a link navigates and closes the drawer.
  await page.tap("#nav-toggle");
  await page.tap("#sidenav-links a.nav-link:visible >> nth=2");
  await expect(page.locator("#nav-toggle")).toHaveAttribute("aria-expanded", "false");
  await ctx.close();
});

test("static assets are revalidated with ETags", async ({ request }) => {
  const first = await request.get("/app.js");
  expect(first.status()).toBe(200);
  const etag = first.headers()["etag"];
  expect(etag).toBeTruthy();
  const second = await request.get("/app.js", { headers: { "If-None-Match": etag } });
  expect(second.status()).toBe(304);
  const api = await request.get("/api/health");
  expect(api.headers()["cache-control"]).toBe("no-store");
});

test("desktop layout follows the written specification at 1366x768", async ({ browser }) => {
  const ctx = await browser.newContext({ viewport: { width: 1366, height: 768 } });
  const page = await ctx.newPage();
  await login(page);
  await page.waitForTimeout(1500);
  const m = await page.evaluate(() => {
    const box = (s) => { const r = document.querySelector(s).getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width, h: r.height }; };
    const kpis = [...document.querySelectorAll("#kpis .kpi")].map((e) => e.getBoundingClientRect());
    const widgets = [...document.querySelectorAll(".widgets > .card")].map((e) => e.getBoundingClientRect());
    return {
      side: box("#sidenav"), header: box("#top"), main: box(".card-main"), donut: box(".card-side"),
      kpiCount: kpis.length, kpiSameRow: new Set(kpis.map((r) => Math.round(r.y))).size === 1,
      kpiH: kpis.map((r) => Math.round(r.height)),
      widgetCount: widgets.length, widgetSameRow: new Set(widgets.map((r) => Math.round(r.y))).size === 1,
      radius: getComputedStyle(document.querySelector(".card")).borderRadius,
      h1: getComputedStyle(document.querySelector("h1")).fontSize,
    };
  });
  expect(m.side.w).toBe(205);
  expect(m.side.h).toBeGreaterThanOrEqual(768);
  expect(Math.round(m.header.h)).toBeGreaterThanOrEqual(58);
  expect(Math.round(m.header.h)).toBeLessThanOrEqual(59);
  expect(m.kpiCount).toBe(4);
  expect(m.kpiSameRow).toBe(true);
  for (const h of m.kpiH) { expect(h).toBeGreaterThanOrEqual(88); expect(h).toBeLessThanOrEqual(120); }
  const share = m.main.w / (m.main.w + m.donut.w);
  expect(share).toBeGreaterThan(0.62);
  expect(share).toBeLessThan(0.68);
  expect(Math.abs(m.main.y - m.donut.y)).toBeLessThan(2);
  expect(m.widgetCount).toBe(3);
  expect(m.widgetSameRow).toBe(true);
  expect(m.radius).toBe("8px");
  expect(m.h1).toBe("17px");
  await ctx.close();
});

test("sidebar collapses to an icon rail and the choice persists", async ({ browser }) => {
  const ctx = await browser.newContext({ viewport: { width: 1366, height: 768 } });
  const page = await ctx.newPage();
  await login(page);
  const width = () => page.evaluate(() => Math.round(document.querySelector("#sidenav").getBoundingClientRect().width));
  expect(await width()).toBe(205);
  await page.click("#side-collapse");
  await expect(page.locator("#side-collapse")).toHaveAttribute("aria-expanded", "false");
  await expect.poll(width).toBe(60);
  await page.reload();
  await page.waitForSelector("#kpis .kpi");
  await expect.poll(width).toBe(60);
  await page.click("#side-collapse");
  await expect.poll(width).toBe(205);
  await ctx.close();
});

test("nav groups expand, search jumps to sections", async ({ browser }) => {
  const ctx = await browser.newContext({ viewport: { width: 1366, height: 768 } });
  const page = await ctx.newPage();
  await login(page);
  const group = page.locator("#sidenav-links .nav-group").first();
  const header = group.locator("button.nav-parent");
  await expect(header).toHaveAttribute("aria-expanded", "false");
  await header.click();
  await expect(header).toHaveAttribute("aria-expanded", "true");
  await expect(group.locator("a.nav-link").first()).toBeVisible();
  await header.click();
  await expect(group.locator("a.nav-link").first()).toBeHidden();

  await page.fill("#nav-search", "cache");
  await expect(page.locator("#search-results a")).not.toHaveCount(0);
  await page.locator("#search-results a", { hasText: "Cache" }).first().click();
  await expect.poll(() => page.evaluate(() => location.hash)).toBe("#cache");
  await expect(page.locator("#cache")).not.toHaveClass(/collapsed/);
  await page.fill("#nav-search", "zzzz-no-such-section");
  await expect(page.locator("#search-results")).toContainText("No matching section");
  await ctx.close();
});

test("notifications, account menu, chart controls", async ({ browser }) => {
  const ctx = await browser.newContext({ viewport: { width: 1366, height: 900 } });
  const page = await ctx.newPage();
  await login(page);
  await page.waitForTimeout(1500);

  await page.click("#bell-btn");
  await expect(page.locator("#bell-menu")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.locator("#bell-menu")).toBeHidden();

  await page.click("#profile-btn");
  await expect(page.locator("#profile-menu")).toBeVisible();
  await expect(page.locator("#pm-user")).toHaveText(USER);
  await expect(page.locator("#logout-btn")).toBeVisible();
  await page.mouse.click(600, 300);
  await expect(page.locator("#profile-menu")).toBeHidden();

  // Analytics pane switch + time range selector.
  await expect(page.locator("#w-ch-lat")).toBeVisible();
  await page.click('#an-tabs button[data-pane="ch-qps"]');
  await expect(page.locator("#w-ch-qps")).toBeVisible();
  await expect(page.locator("#w-ch-lat")).toBeHidden();
  await page.selectOption("#range-sel", "15m");
  await expect.poll(() => page.evaluate(() => document.querySelector("#range-sel").value)).toBe("15m");

  // Pie breakdown + bar metric selectors change the titles they drive.
  await page.selectOption("#pie-sel", "transport");
  await expect(page.locator("#pie-title")).toHaveText("Transport");
  await page.selectOption("#bar-sel", "bytes");
  await expect(page.locator("#bar-title")).toHaveText("Payload size (avg bytes)");

  // Upstream list rows are real, keyboard-operable controls.
  const row = page.locator("#up-list .rrow").first();
  if (await row.count()) {
    await row.focus();
    await page.keyboard.press("Enter");
    await expect(page.locator("#up-list .rrow.focus")).toHaveCount(1);
    await page.locator("#up-list .rrow.focus").click();
    await expect(page.locator("#up-list .rrow.focus")).toHaveCount(0);
  }
  await ctx.close();
});
