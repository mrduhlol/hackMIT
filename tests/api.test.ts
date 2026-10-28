import { beforeAll, afterAll, describe, it, expect } from "vitest";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { build } from "esbuild";
import { readFile } from "node:fs/promises";
const token = "test-only-operator-key-with-32-characters";
let mf: Miniflare;
const headers = {
  Authorization: `Bearer ${token}`,
  Origin: "https://panel.example",
  "Content-Type": "application/json",
};
async function call(
  path: string,
  method = "GET",
  body?: unknown,
  custom: Record<string, string> = headers,
) {
  return mf.dispatchFetch(`https://panel.example/api${path}`, {
    method,
    headers: custom,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}
async function state() {
  return (await (await call("/state")).json()) as {
    targets: { id: string }[];
    scans: { id: string; status: string; result: { summary: string } | null }[];
    stopped: boolean;
  };
}
beforeAll(async () => {
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
        DASHBOARD_ORIGIN: "https://panel.example",
        ALLOWED_HOSTS: "owned.example",
      },
    }),
  );
  const db = await mf.getD1Database("DB");
  const sql = await readFile("migrations/0001_initial.sql", "utf8");
  for (const statement of sql
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean))
    await db.prepare(statement).run();
}, 30000);
afterAll(async () => await mf?.dispose());
describe("Pages API inside the Workers runtime", () => {
  it("exposes health without authentication", async () =>
    expect((await call("/health", "GET", undefined, {})).status).toBe(200));
  it("protects all target, scan, report and control endpoints", async () => {
    for (const [path, method] of [
      ["/state", "GET"],
      ["/targets", "POST"],
      ["/scans", "POST"],
      ["/reports", "GET"],
      ["/stop", "POST"],
      ["/resume", "POST"],
      ["/scans/x/cancel", "POST"],
      ["/targets/x", "DELETE"],
    ])
      expect(
        (await call(path, method, method === "POST" ? {} : undefined, {}))
          .status,
      ).toBe(401);
  });
  it("rejects cross-origin and absent-origin writes", async () => {
    expect(
      (
        await call(
          "/targets",
          "POST",
          {},
          { ...headers, Origin: "https://evil.example" },
        )
      ).status,
    ).toBe(403);
    expect(
      (await call("/targets", "POST", {}, { Authorization: `Bearer ${token}` }))
        .status,
    ).toBe(403);
  });
  it("requires backend authorization confirmation and hostname policy", async () => {
    expect(
      (
        await call("/targets", "POST", {
          url: "https://owned.example",
          authorized: false,
        })
      ).status,
    ).toBe(403);
    expect(
      (
        await call("/targets", "POST", {
          url: "https://other.example",
          authorized: true,
        })
      ).status,
    ).toBe(403);
  });
  it("registers an authorized target persistently", async () => {
    expect(
      (
        await call("/targets", "POST", {
          url: "https://owned.example",
          authorized: true,
        })
      ).status,
    ).toBe(201);
    expect((await state()).targets).toHaveLength(1);
    expect(
      (
        await call("/targets", "POST", {
          url: "https://owned.example",
          authorized: true,
        })
      ).status,
    ).toBe(409);
  });
  it("does not expose an unrestricted fetch endpoint", async () => {
    expect(
      (
        await call("/scans", "POST", {
          testId: "headers",
          url: "http://169.254.169.254",
          targetId: "not-registered",
        })
      ).status,
    ).toBe(404);
  });
  it("records runner absence as ERROR, never PASS", async () => {
    const target = (await state()).targets[0];
    expect(
      (await call("/scans", "POST", { testId: "headers", targetId: target.id }))
        .status,
    ).toBe(202);
    await mf.ready;
    let s = await state();
    for (let i = 0; i < 10 && s.scans[0].status === "RUNNING"; i++)
      s = await state();
    expect(s.scans[0].status).toBe("ERROR");
    expect(s.scans[0].result?.summary).toContain("not configured");
  });
  it("validates load and input configuration", async () => {
    const target = (await state()).targets[0];
    expect(
      (
        await call("/scans", "POST", {
          testId: "load",
          targetId: target.id,
          count: 500,
          confirmLoad: true,
        })
      ).status,
    ).toBe(400);
    expect(
      (
        await call("/scans", "POST", {
          testId: "input",
          targetId: target.id,
          inputPath: "https://evil.example",
        })
      ).status,
    ).toBe(400);
  });
  it("exports JSON and escaped printable reports", async () => {
    const r = await call("/reports?format=json");
    expect(r.status).toBe(200);
    expect(
      ((await r.json()) as { scans: unknown[] }).scans.length,
    ).toBeGreaterThan(0);
    const html = await call("/reports?format=html");
    expect(await html.text()).toContain("Sentinel / Security assessment");
    expect(html.headers.get("Content-Disposition")).toContain("attachment");
  });
  it("blocks scans during emergency stop and permits explicit resume", async () => {
    expect((await call("/stop", "POST")).status).toBe(200);
    expect((await state()).stopped).toBe(true);
    expect((await call("/scans", "POST", { testId: "xss" })).status).toBe(429);
    expect((await call("/resume", "POST")).status).toBe(200);
    expect((await state()).stopped).toBe(false);
  });
  it("enforces the global concurrency constraint in D1", async () => {
    const db = await mf.getD1Database("DB");
    await db
      .prepare(
        "INSERT INTO scans(id,test_id,status,started_at) VALUES('test-running','headers','RUNNING',?)",
      )
      .bind(new Date().toISOString())
      .run();
    expect((await call("/scans", "POST", { testId: "xss" })).status).toBe(409);
    await db
      .prepare("UPDATE scans SET status='CANCELLED' WHERE id='test-running'")
      .run();
  });
  it("records cancellation honestly and rejects repeat cancellation", async () => {
    const db = await mf.getD1Database("DB");
    await db
      .prepare(
        "INSERT INTO scans(id,test_id,status,started_at) VALUES('cancel-test','headers','RUNNING',?)",
      )
      .bind(new Date().toISOString())
      .run();
    const response = await call("/scans/cancel-test/cancel", "POST");
    expect(response.status).toBe(200);
    expect(((await response.json()) as { warning: string }).warning).toContain(
      "could not be confirmed",
    );
    expect(
      (await state()).scans.find((s) => s.id === "cancel-test")?.status,
    ).toBe("CANCELLED");
    expect((await call("/scans/cancel-test/cancel", "POST")).status).toBe(409);
  });
  it("rejects invalid report filters", async () => {
    expect((await call("/reports?severity=invalid")).status).toBe(400);
    expect((await call("/reports?format=executable")).status).toBe(400);
  });
  it("enforces the rolling hourly quota atomically", async () => {
    const db = await mf.getD1Database("DB");
    for (let i = 0; i < 30; i++)
      await db
        .prepare(
          "INSERT INTO scans(id,test_id,status,started_at) VALUES(?,'headers','ERROR',?)",
        )
        .bind(`quota-${i}`, new Date().toISOString())
        .run();
    expect((await call("/scans", "POST", { testId: "xss" })).status).toBe(429);
  });
});
