import http from "node:http";
import { timingSafeEqual, createHash } from "node:crypto";
import { execute, type Job } from "./modules";
import { validateTarget, allowlist, AppError } from "../shared/validation";
const token = process.env.RUNNER_TOKEN || "";
if (token.length < 32)
  throw new Error("Set RUNNER_TOKEN to at least 32 random characters.");
const jobs = new Map<string, AbortController>();
const cancelled = new Set<string>();
let stopped = false;
const server = http.createServer(async (req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Cache-Control", "no-store");
  const send = (code: number, value: unknown) => {
    res.writeHead(code);
    res.end(JSON.stringify(value));
  };
  const auth = req.headers.authorization || "";
  if (
    !timingSafeEqual(
      createHash("sha256").update(auth).digest(),
      createHash("sha256").update(`Bearer ${token}`).digest(),
    )
  )
    return send(401, { error: "Authentication required." });
  try {
    if (req.method === "GET" && req.url === "/health")
      return send(200, { ok: true, stopped, busy: jobs.size > 0 });
    if (req.method !== "POST")
      return send(405, { error: "Method not allowed." });
    let bytes = 0;
    const chunks: Buffer[] = [];
    for await (const c of req) {
      bytes += c.length;
      if (bytes > 4096) throw new AppError(413, "Request too large.");
      chunks.push(c);
    }
    const data = JSON.parse(Buffer.concat(chunks).toString()) as Job & {
      id: string;
      ids?: unknown;
    };
    if (req.url === "/stop") {
      stopped = true;
      if (Array.isArray(data.ids))
        for (const id of data.ids)
          if (typeof id === "string" && /^[a-f0-9-]{36}$/.test(id))
            cancelled.add(id);
      for (const j of jobs.values()) j.abort();
      return send(200, { ok: true });
    }
    if (req.url === "/resume") {
      stopped = false;
      return send(200, { ok: true });
    }
    if (typeof data.id !== "string" || !/^[a-f0-9-]{36}$/.test(data.id))
      throw new AppError(400, "Invalid job ID.");
    if (req.url === "/cancel") {
      if (cancelled.size > 1000) cancelled.clear();
      cancelled.add(data.id);
      jobs.get(data.id)?.abort();
      return send(200, { ok: true });
    }
    if (req.url !== "/run") return send(404, { error: "Not found." });
    if (stopped || cancelled.has(data.id))
      return send(409, { error: "Runner stopped or job cancelled." });
    if (jobs.size) return send(429, { error: "Runner is busy." });
    if (data.testId !== "sql")
      validateTarget(data.url, allowlist(process.env.ALLOWED_HOSTS || ""));
    const controller = new AbortController();
    jobs.set(data.id, controller);
    const timer = setTimeout(() => controller.abort(), 24000);
    try {
      const result = await Promise.race([
        execute(data, controller.signal),
        new Promise<never>((_, reject) =>
          controller.signal.addEventListener(
            "abort",
            () => reject(new Error("Aborted")),
            { once: true },
          ),
        ),
      ]);
      send(200, result);
    } catch (e) {
      send(e instanceof AppError ? e.status : 502, {
        error: controller.signal.aborted
          ? "Job cancelled or deadline exceeded."
          : e instanceof AppError
            ? e.message
            : "Runner could not complete the check. Verify connectivity and target configuration.",
      });
    } finally {
      clearTimeout(timer);
      jobs.delete(data.id);
      cancelled.delete(data.id);
    }
  } catch (e) {
    send(e instanceof AppError ? e.status : 400, {
      error: e instanceof AppError ? e.message : "Invalid request.",
    });
  }
});
server.requestTimeout = 30000;
server.headersTimeout = 5000;
server.maxHeadersCount = 40;
server.listen(
  Number(process.env.RUNNER_PORT || 8790),
  process.env.RUNNER_HOST || "127.0.0.1",
  () =>
    console.log(
      "Sentinel runner ready. Bind behind authenticated HTTPS in production.",
    ),
);
