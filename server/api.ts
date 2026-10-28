import { modules, type Scan, type Target, type Result } from "../shared/models";
import { AppError, validateTarget, allowlist } from "../shared/validation";
import { authenticate, boundedJSON } from "./security";
import { reportHTML, validateResult } from "./results";
export interface Env extends Cloudflare.Env {
  API_TOKEN: string;
  DASHBOARD_ORIGIN: string;
  ALLOWED_HOSTS: string;
  RUNNER_URL?: string;
  RUNNER_TOKEN?: string;
}
interface Context {
  waitUntil(p: Promise<unknown>): void;
}
interface ScanRow extends Omit<Scan, "result"> {
  result: string | null;
}
const now = () => new Date().toISOString();
const json = (data: unknown, status = 200) =>
  Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      Vary: "Origin",
    },
  });
async function event(env: Env, action: string, id: string) {
  await env.DB.prepare("INSERT INTO events(action,resource) VALUES(?,?)")
    .bind(action, id)
    .run();
}
async function runner(env: Env, path: string, body: unknown, timeout = 27000) {
  if (!env.RUNNER_URL || !env.RUNNER_TOKEN)
    throw new AppError(
      503,
      "Dedicated runner is not configured. See Settings and README.",
    );
  const u = new URL(env.RUNNER_URL);
  if (
    u.protocol !== "https:" &&
    !(u.protocol === "http:" && ["127.0.0.1", "localhost"].includes(u.hostname))
  )
    throw new AppError(503, "Runner requires HTTPS in production.");
  const r = await fetch(new URL(path, u), {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RUNNER_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
    redirect: "manual",
    signal: AbortSignal.timeout(timeout),
  });
  if (r.status >= 300 && r.status < 400) {
    await r.body?.cancel();
    throw new AppError(
      502,
      "Runner redirect refused. Configure its final HTTPS URL.",
    );
  }
  const result = await boundedJSON(r, 65536);
  if (!r.ok)
    throw new AppError(
      r.status === 429 ? 429 : 502,
      typeof result.error === "string"
        ? result.error
        : "Runner could not complete the check.",
    );
  return result;
}
function parseScan(s: ScanRow): Scan {
  return { ...s, result: s.result ? JSON.parse(s.result) : null };
}
async function run(
  env: Env,
  id: string,
  testId: string,
  url: string | undefined,
  options: Record<string, unknown>,
) {
  let result: Result;
  try {
    if (testId === "xss")
      result = {
        testId,
        status: "WARNING",
        startedAt: now(),
        endedAt: now(),
        findings: [
          {
            title: "Isolated XSS rendering demonstration",
            severity: "info",
            endpoint: "isolated://sandboxed-frame",
            evidence:
              "The dashboard offers a fixed harmless script payload in a sandboxed local frame, alongside escaped text. No target request is sent.",
            impact:
              "Inserting untrusted input into HTML can execute scripts. This demonstration is not a vulnerability finding on any target.",
            remediation:
              "Render untrusted data as text; use a vetted sanitizer when HTML is required.",
          },
        ],
        summary:
          "Local demonstration prepared. Open View Results to compare isolated script execution with text escaping.",
      };
    else
      result = validateResult(
        await runner(env, "/run", { id, testId, url, ...options }),
        testId,
      );
  } catch (e) {
    result = {
      testId,
      status: "ERROR",
      startedAt: now(),
      endedAt: now(),
      findings: [],
      summary:
        e instanceof AppError
          ? e.message
          : "Check could not complete. Runner is unavailable or timed out.",
    };
  }
  await env.DB.batch([
    env.DB.prepare(
      "UPDATE scans SET status=?,result=?,ended_at=?,progress=100 WHERE id=? AND status='RUNNING'",
    ).bind(result.status, JSON.stringify(result), now(), id),
    env.DB.prepare(
      "INSERT INTO events(action,resource) SELECT ?,id FROM scans WHERE id=? AND status=?",
    ).bind(
      result.status === "ERROR" ? "scan.error" : "scan.completed",
      id,
      result.status,
    ),
  ]);
}
export async function handle(
  request: Request,
  env: Env,
  ctx: Context,
): Promise<Response> {
  try {
    const u = new URL(request.url);
    const path = u.pathname.replace(/^\/api/, "");
    if (path === "/health" && request.method === "GET")
      return json({
        ok: true,
        service: "sentinel-api",
        configured: !!env.DB && !!env.API_TOKEN && !!env.DASHBOARD_ORIGIN,
      });
    await authenticate(request, env.API_TOKEN);
    if (!env.DASHBOARD_ORIGIN || !env.DB)
      throw new AppError(503, "Configure DASHBOARD_ORIGIN and D1 binding.");
    const origin = request.headers.get("Origin");
    if (origin && origin !== env.DASHBOARD_ORIGIN)
      throw new AppError(403, "Origin is not permitted.");
    if (
      !["GET", "HEAD"].includes(request.method) &&
      origin !== env.DASHBOARD_ORIGIN
    )
      throw new AppError(403, "An exact dashboard Origin header is required.");
    // Expired jobs retain an honest error even when a background execution was interrupted.
    const expired = await env.DB.prepare(
      "UPDATE scans SET status='ERROR',ended_at=? WHERE status='RUNNING' AND started_at < ? RETURNING id",
    )
      .bind(now(), new Date(Date.now() - 60000).toISOString())
      .all<{ id: string }>();
    for (const s of expired.results)
      await event(env, "scan.error.expired", s.id);
    if (path === "/state" && request.method === "GET") {
      const [targets, scans, events, control] = await Promise.all([
        env.DB.prepare(
          "SELECT * FROM targets ORDER BY authorized_at DESC LIMIT 100",
        ).all<Target>(),
        env.DB.prepare(
          "SELECT * FROM scans ORDER BY started_at DESC LIMIT 100",
        ).all<ScanRow>(),
        env.DB.prepare("SELECT * FROM events ORDER BY id DESC LIMIT 100").all(),
        env.DB.prepare("SELECT stopped FROM controls WHERE id=1").first<{
          stopped: number;
        }>(),
      ]);
      return json({
        targets: targets.results,
        scans: scans.results.map(parseScan),
        events: events.results,
        stopped: !!control?.stopped,
        runnerConfigured: !!env.RUNNER_URL && !!env.RUNNER_TOKEN,
        allowedHosts: allowlist(env.ALLOWED_HOSTS || ""),
      });
    }
    if (path === "/targets" && request.method === "POST") {
      const data = await boundedJSON(request);
      if (data.authorized !== true)
        throw new AppError(
          403,
          "Explicit authorization confirmation is required.",
        );
      const target = validateTarget(
        data.url,
        allowlist(env.ALLOWED_HOSTS || ""),
      );
      const id = crypto.randomUUID();
      const count = await env.DB.prepare(
        "SELECT count(*) as n FROM targets",
      ).first<{ n: number }>();
      if ((count?.n || 0) >= 100)
        throw new AppError(429, "Target limit reached.");
      try {
        await env.DB.prepare(
          "INSERT INTO targets(id,url,authorized_at) VALUES(?,?,?)",
        )
          .bind(id, target.href, now())
          .run();
      } catch {
        throw new AppError(409, "Target is already registered.");
      }
      await event(env, "target.authorized", id);
      return json({ id }, 201);
    }
    if (path.startsWith("/targets/") && request.method === "DELETE") {
      const id = path.split("/")[2];
      const busy = await env.DB.prepare(
        "SELECT id FROM scans WHERE target_id=? AND status='RUNNING'",
      )
        .bind(id)
        .first();
      if (busy)
        throw new AppError(
          409,
          "Cancel the active check before deleting this target.",
        );
      // Keep assessment history; remove only the registered target.
      await env.DB.batch([
        env.DB.prepare(
          "UPDATE scans SET target_id=NULL WHERE target_id=?",
        ).bind(id),
        env.DB.prepare("DELETE FROM targets WHERE id=?").bind(id),
      ]);
      await event(env, "target.deleted", id);
      return json({ ok: true });
    }
    if (path === "/scans" && request.method === "POST") {
      const d = await boundedJSON(request);
      const module = modules.find(
        (m) => m.id === d.testId && m.id !== "report",
      );
      if (!module) throw new AppError(400, "Unknown test module.");
      let target: Target | null = null;
      const lab = ["sql", "xss"].includes(module.id);
      if (!lab) {
        if (typeof d.targetId !== "string")
          throw new AppError(400, "Select an authorized target.");
        target = await env.DB.prepare("SELECT * FROM targets WHERE id=?")
          .bind(d.targetId)
          .first<Target>();
        if (!target) throw new AppError(404, "Target not found.");
        validateTarget(target.url, allowlist(env.ALLOWED_HOSTS || ""));
      }
      if (
        module.id === "load" &&
        (d.confirmLoad !== true ||
          !Number.isInteger(d.count) ||
          Number(d.count) < 1 ||
          Number(d.count) > 5)
      )
        throw new AppError(
          400,
          "Confirm bounded load testing with a request cap of 1–5.",
        );
      if (
        module.id === "input" &&
        (typeof d.inputPath !== "string" ||
          !/^\/[a-zA-Z0-9/_-]{0,200}$/.test(d.inputPath))
      )
        throw new AppError(400, "Provide a designated test path.");
      const options = {
        count: d.count,
        inputPath: d.inputPath,
        labCase: d.labCase === "normal" ? "normal" : "injection",
      };
      const id = crypto.randomUUID();
      try {
        const inserted = await env.DB.prepare(
          "INSERT INTO scans(id,target_id,test_id,status,started_at) SELECT ?,?,?,'RUNNING',? WHERE (SELECT stopped FROM controls WHERE id=1)=0 AND (SELECT count(*) FROM scans WHERE started_at>?)<30 RETURNING id",
        )
          .bind(
            id,
            target?.id || null,
            module.id,
            now(),
            new Date(Date.now() - 3600000).toISOString(),
          )
          .first();
        if (!inserted)
          throw new AppError(
            429,
            "Emergency stop is active or the 30 checks/hour quota is exhausted.",
          );
      } catch (e) {
        if (e instanceof AppError) throw e;
        throw new AppError(
          409,
          "A check is already running. Wait or cancel it first.",
        );
      }
      await event(env, "scan.started", id);
      ctx.waitUntil(run(env, id, module.id, target?.url, options));
      return json({ id }, 202);
    }
    if (/^\/scans\/[^/]+\/cancel$/.test(path) && request.method === "POST") {
      const id = path.split("/")[2];
      const s = await env.DB.prepare("SELECT * FROM scans WHERE id=?")
        .bind(id)
        .first<ScanRow>();
      if (!s) throw new AppError(404, "Scan not found.");
      const cancelled = await env.DB.prepare(
        "UPDATE scans SET status='CANCELLED',ended_at=? WHERE id=? AND status='RUNNING' RETURNING id",
      )
        .bind(now(), id)
        .first();
      if (!cancelled)
        throw new AppError(409, "Only running checks can be cancelled.");
      await event(env, "scan.cancelled", id);
      try {
        await runner(env, "/cancel", { id }, 4000);
      } catch {
        return json({
          ok: true,
          warning:
            "Cancellation recorded. Runner stop could not be confirmed; its hard deadline remains active.",
        });
      }
      return json({ ok: true });
    }
    if ((path === "/stop" || path === "/resume") && request.method === "POST") {
      const stop = path === "/stop";
      if (stop) {
        const updates = await env.DB.batch<{ id: string }>([
          env.DB.prepare("UPDATE controls SET stopped=1 WHERE id=1"),
          env.DB.prepare(
            "UPDATE scans SET status='CANCELLED',ended_at=? WHERE status='RUNNING' RETURNING id",
          ).bind(now()),
        ]);
        await event(env, "emergency.stopped", "global");
        try {
          await runner(
            env,
            "/stop",
            { ids: updates[1].results.map((s) => s.id) },
            4000,
          );
        } catch {
          return json({
            ok: true,
            warning:
              "Stop is active in the API. Runner acknowledgement unavailable; in-flight requests expire within 24 seconds.",
          });
        }
      } else {
        if (env.RUNNER_URL) await runner(env, "/resume", {}, 4000);
        await env.DB.prepare("UPDATE controls SET stopped=0 WHERE id=1").run();
        await event(env, "emergency.resumed", "global");
      }
      return json({ ok: true });
    }
    if (path === "/reports" && request.method === "GET") {
      const status = u.searchParams.get("status");
      const scanId = u.searchParams.get("scanId");
      const requestedSeverity = u.searchParams.get("severity");
      const format = u.searchParams.get("format");
      if (
        status &&
        ![
          "PASS",
          "FAIL",
          "WARNING",
          "ERROR",
          "NOT TESTED",
          "RUNNING",
          "CANCELLED",
        ].includes(status)
      )
        throw new AppError(400, "Invalid report status filter.");
      if (
        requestedSeverity &&
        !["critical", "high", "medium", "low", "info"].includes(
          requestedSeverity,
        )
      )
        throw new AppError(400, "Invalid severity filter.");
      if (format && !["json", "html"].includes(format))
        throw new AppError(400, "Report format must be json or html.");
      if (scanId && scanId.length > 64)
        throw new AppError(400, "Invalid scan ID.");
      const rows = await env.DB.prepare(
        "SELECT * FROM scans WHERE (? IS NULL OR status=?) AND (? IS NULL OR id=?) ORDER BY started_at DESC LIMIT 100",
      )
        .bind(status, status, scanId, scanId)
        .all<ScanRow>();
      let scans = rows.results.map(parseScan);
      const severity = u.searchParams.get("severity");
      if (severity)
        scans = scans.map((s) => ({
          ...s,
          result: s.result
            ? {
                ...s.result,
                findings: s.result.findings.filter(
                  (f) => f.severity === severity,
                ),
              }
            : null,
        }));
      await event(env, "report.exported", scanId || "history");
      if (u.searchParams.get("format") === "html")
        return new Response(reportHTML(scans), {
          headers: {
            "Content-Type": "text/html;charset=utf-8",
            "Content-Disposition":
              'attachment; filename="sentinel-report.html"',
            "Cache-Control": "no-store",
            "Content-Security-Policy":
              "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
          },
        });
      return new Response(
        JSON.stringify(
          {
            generatedAt: now(),
            scope:
              "Single-operator authorized workspace; maximum 100 most recent checks.",
            filters: { status, severity, scanId },
            scans,
          },
          null,
          2,
        ),
        {
          headers: {
            "Content-Type": "application/json",
            "Content-Disposition":
              'attachment; filename="sentinel-report.json"',
            "Cache-Control": "no-store",
          },
        },
      );
    }
    throw new AppError(404, "Endpoint not found.");
  } catch (e) {
    if (!(e instanceof AppError))
      console.error(
        JSON.stringify({
          action: "api.error",
          message: "Unhandled database or runtime failure",
        }),
      );
    return json(
      {
        error:
          e instanceof AppError
            ? e.message
            : "Service unavailable. Check D1 migrations and server configuration.",
      },
      e instanceof AppError ? e.status : 503,
    );
  }
}
