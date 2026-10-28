// Acceptance test: real API + D1 + actual isolated runner. No live-target scan.
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { build } from "esbuild";
import { chromium, expect } from "@playwright/test";
import { createServer } from "node:http";
import { readFile, mkdir } from "node:fs/promises";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
const token = randomBytes(32).toString("hex");
const runnerToken = randomBytes(32).toString("hex");
const origin = "http://localhost:18788";
let browser, mf, server, runner;
try {
  runner = spawn(process.execPath, ["--import", "tsx", "runner/index.ts"], {
    env: {
      ...process.env,
      RUNNER_TOKEN: runnerToken,
      RUNNER_PORT: "18790",
      RUNNER_HOST: "127.0.0.1",
      ALLOWED_HOSTS: "owned.example",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  await Promise.race([
    once(runner.stdout, "data"),
    new Promise((_, reject) => {
      const t = setTimeout(
        () => reject(Error("Runner startup timed out")),
        10000,
      );
      t.unref();
    }),
  ]);
  const health = await fetch("http://127.0.0.1:18790/health", {
    headers: { Authorization: `Bearer ${runnerToken}` },
  });
  if (!health.ok) throw Error("Local runner health failed");
  const bundle = await build({
    stdin: {
      contents:
        "import {handle} from './server/api';export default {fetch:handle}",
      resolveDir: process.cwd(),
    },
    bundle: true,
    format: "esm",
    platform: "browser",
    write: false,
  });
  mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: bundle.outputFiles[0].text,
      compatibilityDate: "2026-10-28",
      d1Databases: ["DB"],
      bindings: {
        API_TOKEN: token,
        DASHBOARD_ORIGIN: origin,
        ALLOWED_HOSTS: "owned.example",
        RUNNER_URL: "http://127.0.0.1:18790",
        RUNNER_TOKEN: runnerToken,
      },
    }),
  );
  const db = await mf.getD1Database("DB");
  for (const sql of (await readFile("migrations/0001_initial.sql", "utf8"))
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean))
    await db.prepare(sql).run();
  const securityHeaders = Object.fromEntries(
    (await readFile("public/_headers", "utf8"))
      .split("\n")
      .filter((l) => l.startsWith("  "))
      .map((l) => {
        const at = l.indexOf(":");
        return [l.slice(0, at).trim(), l.slice(at + 1).trim()];
      }),
  );
  server = createServer(async (req, res) => {
    try {
      if (req.url.startsWith("/api/")) {
        const chunks = [];
        for await (const c of req) chunks.push(c);
        const r = await mf.dispatchFetch(`${origin}${req.url}`, {
          method: req.method,
          headers: req.headers,
          body: chunks.length ? Buffer.concat(chunks) : undefined,
        });
        res.writeHead(r.status, Object.fromEntries(r.headers));
        res.end(Buffer.from(await r.arrayBuffer()));
        return;
      }
      const path = new URL(req.url, origin).pathname;
      if (path.includes("..")) {
        res.writeHead(400).end();
        return;
      }
      const file = path === "/" ? "dist/index.html" : `dist${path}`;
      const body = await readFile(file);
      res.writeHead(200, {
        ...securityHeaders,
        "Content-Type": file.endsWith(".js")
          ? "application/javascript"
          : file.endsWith(".css")
            ? "text/css"
            : file.endsWith(".svg")
              ? "image/svg+xml"
              : "text/html",
      });
      res.end(body);
    } catch (e) {
      res.writeHead(500).end(String(e));
    }
  });
  server.listen(18788, "127.0.0.1");
  await once(server, "listening");
  browser = await chromium.launch({
    executablePath: process.env.CHROMIUM_PATH || "/usr/bin/chromium",
    headless: true,
    args: ["--no-sandbox"],
  });
  const page = await browser.newPage({
    viewport: { width: 1440, height: 1100 },
  });
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto(origin);
  await expect(
    page.getByRole("heading", { name: "Security overview" }),
  ).toBeVisible();
  await mkdir("test-results", { recursive: true });
  await page.screenshot({
    path: "test-results/dashboard-desktop.png",
    fullPage: true,
  });
  await page
    .getByRole("button", { name: "Connect workspace", exact: true })
    .first()
    .click();
  await page
    .getByLabel("Access token")
    .fill("incorrect-test-token-longer-than-thirty-two-characters");
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Connect", exact: true })
    .click();
  await expect(page.getByRole("dialog").getByRole("alert")).toContainText(
    "Invalid access token",
  );
  await page.getByLabel("Access token").fill(token);
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Connect", exact: true })
    .click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(
    page.getByText("WORKSPACE CONNECTED", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Add target", exact: true }).click();
  await page
    .getByLabel("Target URL")
    .fill(
      "https://owned.example/authorized-security-assessment/a-long-endpoint-name-for-responsive-layout-checks",
    );
  await page.getByRole("checkbox").check();
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Add target", exact: true })
    .click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page
    .getByRole("button", { name: "Security Tests", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Security Tests", exact: true }),
  ).toBeVisible();
  await expect(page.getByLabel("Active authorized target")).toHaveValue(/.+/);
  await page.screenshot({
    path: "test-results/security-tests-desktop.png",
    fullPage: true,
  });
  const sqlCard = page.locator("article").filter({
    has: page.getByRole("heading", {
      name: "SQL injection lab",
      exact: true,
    }),
  });
  await sqlCard.getByRole("button", { name: "Run test", exact: true }).click();
  await expect(
    sqlCard.getByRole("button", { name: "View results" }),
  ).toBeVisible({ timeout: 15000 });
  await sqlCard.getByRole("button", { name: "View results" }).click();
  await expect(page.getByRole("dialog")).toContainText(
    "Vulnerable query returned 3 rows; parameterized query returned 0 rows",
  );
  await page.screenshot({
    path: "test-results/results-desktop.png",
    fullPage: true,
  });
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  const xssCard = page.locator("article").filter({
    has: page.getByRole("heading", {
      name: "XSS demonstration",
      exact: true,
    }),
  });
  await xssCard.getByRole("button", { name: "Run test", exact: true }).click();
  await expect(
    xssCard.getByRole("button", { name: "View results" }),
  ).toBeVisible();
  await xssCard.getByRole("button", { name: "View results" }).click();
  await expect(
    page
      .frameLocator('iframe[title="Isolated harmless script demonstration"]')
      .getByText("Harmless script executed inside the isolated lab."),
  ).toBeVisible();
  await expect(page.locator("#lab-proof")).toHaveCount(0);
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "Reports", exact: true }).click();
  const download = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export JSON", exact: true }).click();
  const exported = await download;
  await exported.saveAs("test-results/acceptance-report.json");
  const report = JSON.parse(
    await readFile("test-results/acceptance-report.json", "utf8"),
  );
  if (!report.scans.some((s) => s.test_id === "sql" && s.status === "WARNING"))
    throw Error("Real lab result missing from export");
  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await page
    .getByRole("button", { name: "Emergency stop", exact: true })
    .click();
  await page.getByRole("button", { name: "Stop all checks" }).click();
  await expect(
    page.getByText("Emergency stop is active. New checks are blocked."),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Resume testing", exact: true })
    .first()
    .click();
  await expect(
    page.getByText("Emergency stop is active. New checks are blocked."),
  ).toHaveCount(0);
  await page.setViewportSize({ width: 390, height: 844 });
  await page
    .getByRole("button", { name: "Security Tests", exact: true })
    .click();
  await page.screenshot({
    path: "test-results/security-tests-mobile.png",
    fullPage: true,
  });
  await page.getByRole("button", { name: "Add target", exact: true }).click();
  const box = await page.getByRole("dialog").boundingBox();
  if (
    !box ||
    box.x < 0 ||
    box.x + box.width > 390 ||
    Math.abs(box.x + box.width / 2 - 195) > 2
  )
    throw Error("Mobile dialog is not centered");
  await page.screenshot({
    path: "test-results/dialog-mobile.png",
    fullPage: true,
  });
  await page.keyboard.press("Escape");
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth > innerWidth,
  );
  if (overflow) throw Error("Mobile viewport has horizontal overflow");
  // Real Android-style touch context; authenticate through the same UI.
  const android = await browser.newContext({
    viewport: { width: 360, height: 800 },
    isMobile: true,
    hasTouch: true,
    deviceScaleFactor: 2,
  });
  const phone = await android.newPage();
  phone.on("pageerror", (e) => errors.push(e.message));
  await phone.goto(origin);
  await phone
    .getByRole("button", { name: "Connect workspace", exact: true })
    .tap();
  await phone.getByLabel("Access token").fill(token);
  await phone
    .getByRole("dialog")
    .getByRole("button", { name: "Connect", exact: true })
    .tap();
  await expect(phone.getByRole("dialog")).toHaveCount(0);
  const screenSizes = [
    { width: 320, height: 740 },
    { width: 360, height: 800 },
    { width: 390, height: 844 },
    { width: 412, height: 915 },
    { width: 768, height: 1024 },
    { width: 844, height: 390 },
  ];
  for (const size of screenSizes) {
    await phone.setViewportSize(size);
    for (const name of [
      "Dashboard",
      "Targets",
      "Security Tests",
      "Scan History",
      "Reports",
      "Settings",
    ]) {
      await phone.getByRole("button", { name, exact: true }).tap();
      await expect(
        phone.getByRole("heading", {
          name: name === "Dashboard" ? "Security overview" : name,
          exact: true,
        }),
      ).toBeVisible();
      const overflows = await phone.evaluate(
        () => document.documentElement.scrollWidth > innerWidth + 1,
      );
      if (overflows)
        throw Error(`${name} overflows at ${size.width}x${size.height}`);
      if (size.width < 768 || size.height < 500) {
        await expect(
          phone.getByRole("navigation", { name: "Mobile navigation" }),
        ).toBeVisible();
        const navButtons = await phone
          .getByRole("navigation", { name: "Mobile navigation" })
          .getByRole("button")
          .evaluateAll((buttons) =>
            buttons.map((b) => ({
              width: b.getBoundingClientRect().width,
              height: b.getBoundingClientRect().height,
            })),
          );
        if (navButtons.some((b) => b.width < 44 || b.height < 44))
          throw Error("Phone navigation tap target is too small");
      }
      if (name === "Scan History" && (size.width < 768 || size.height < 500)) {
        const rows = phone.locator(".scan-table tbody tr");
        await expect(rows).toHaveCount(2);
        const row = rows.first();
        await expect(
          row.getByRole("button", { name: "Results" }),
        ).toBeVisible();
        await row.getByRole("button", { name: "Results" }).tap();
        await expect(phone.getByRole("dialog")).toBeVisible();
        const dialogOverflow = await phone
          .getByRole("dialog")
          .evaluate((el) => el.scrollWidth > el.clientWidth + 1);
        if (dialogOverflow)
          throw Error("Phone results have horizontal overflow");
        await phone.getByRole("button", { name: "Close dialog" }).tap();
      }
    }
    await phone.getByRole("button", { name: "Add target", exact: true }).tap();
    const dialog = phone.getByRole("dialog");
    const bounds = await dialog.boundingBox();
    if (
      !bounds ||
      bounds.x < 0 ||
      bounds.y < 0 ||
      bounds.x + bounds.width > size.width + 1 ||
      bounds.y + bounds.height > size.height + 1
    )
      throw Error(`Dialog exceeds ${size.width}x${size.height}`);
    const font = await phone
      .getByLabel("Target URL")
      .evaluate((el) => parseFloat(getComputedStyle(el).fontSize));
    if (size.width < 768 && font < 16)
      throw Error("Phone form text is too small");
    await phone.getByRole("button", { name: "Close dialog" }).tap();
  }
  await phone.setViewportSize({ width: 390, height: 844 });
  for (const name of [
    "Dashboard",
    "Targets",
    "Scan History",
    "Security Tests",
    "Reports",
    "Settings",
  ]) {
    await phone.getByRole("button", { name, exact: true }).tap();
    await phone.screenshot({
      path: `test-results/android-${name.toLowerCase().replaceAll(" ", "-")}.png`,
      fullPage: true,
    });
  }
  await phone.getByRole("button", { name: "Add target", exact: true }).tap();
  await phone.screenshot({ path: "test-results/android-dialog.png" });
  await android.close();
  if (errors.length) throw Error(errors.join("\n"));
  console.log(
    "UI acceptance passed: authentication, allowlisted target, real SQL and XSS labs, results, JSON export, stop/resume, Android touch navigation, all six pages at 320–844px, landscape, and dialogs.",
  );
} finally {
  await browser?.close();
  await mf?.dispose();
  if (server) await new Promise((resolve) => server.close(resolve));
  runner?.kill("SIGTERM");
}
