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
    await page.click(`#sidenav-links a[href="${href}"]`);
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
    [...document.querySelectorAll(".hbar button, .hbar select, #nav-toggle")]
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
  await page.tap("#sidenav-links a.nav-link >> nth=2");
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
