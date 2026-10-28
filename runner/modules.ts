import dns from "node:dns/promises";
import net from "node:net";
import { DatabaseSync } from "node:sqlite";
import { setTimeout as delay } from "node:timers/promises";
import { snapshot, resolvePublic } from "./network";
import { AppError } from "../shared/validation";
import { finalStatus, type Finding, type Result } from "../shared/models";
export interface Job {
  testId: string;
  url?: string;
  count?: number;
  inputPath?: string;
  labCase?: "normal" | "injection";
}
export async function execute(job: Job, signal: AbortSignal): Promise<Result> {
  const startedAt = new Date().toISOString();
  const findings: Finding[] = [];
  let endpoint = job.url || "isolated://synthetic-lab";
  let summary = "";
  let status: Result["status"] | undefined;
  const add = (
    title: string,
    severity: Finding["severity"],
    evidence: string,
    impact: string,
    remediation: string,
  ) =>
    findings.push({ title, severity, endpoint, evidence, impact, remediation });
  if (job.testId === "sql") {
    const db = new DatabaseSync(":memory:");
    try {
      db.exec(
        "CREATE TABLE products(id INTEGER,name TEXT); INSERT INTO products VALUES(1,'Synthetic notebook'),(2,'Synthetic keyboard'),(3,'Synthetic monitor')",
      );
      const input = job.labCase === "injection" ? "1' OR '1'='1" : "1";
      const vulnerable = db
        .prepare(`SELECT name FROM products WHERE id = '${input}'`)
        .all();
      const safe = db
        .prepare("SELECT name FROM products WHERE id = ?")
        .all(input);
      summary = `Synthetic lab only. Vulnerable query returned ${vulnerable.length} rows; parameterized query returned ${safe.length} rows. Input: ${input}`;
      add(
        "Query construction comparison",
        "info",
        summary,
        "Concatenated SQL can change query logic. No external database was accessed.",
        "Bind input as query parameters; do not concatenate user data.",
      );
      status = "WARNING";
    } finally {
      db.close();
    }
  } else {
    const u = new URL(endpoint);
    await resolvePublic(u.hostname);
    signal.throwIfAborted();
    if (job.testId === "dns") {
      const types = ["A", "AAAA", "MX", "NS", "TXT", "CAA"] as const;
      const records = await Promise.all(
        types.map(async (type) => {
          try {
            const data = await dns.resolve(u.hostname, type);
            return `${type}: ${Array.isArray(data) ? data.length : 1} record(s)`;
          } catch (e) {
            if (
              ["ENODATA", "ENOTFOUND"].includes(
                (e as NodeJS.ErrnoException).code || "",
              )
            )
              return `${type}: no records`;
            throw e;
          }
        }),
      );
      summary = records.join("; ");
      add(
        "Public DNS record inventory",
        "info",
        summary,
        "Public DNS records describe routing and service configuration; their existence alone is not a vulnerability.",
        "Review DNS records against your asset inventory.",
      );
      status = "WARNING";
    } else if (job.testId === "ports") {
      const ports = (process.env.ALLOWED_PORTS || "")
        .split(",")
        .filter(Boolean)
        .map(Number);
      if (!ports.length) {
        status = "NOT TESTED";
        summary =
          "No runner ports configured. Set ALLOWED_PORTS to an explicit subset of 80,443,8080,8443.";
      } else {
        if (
          ports.length > 4 ||
          ports.some((p) => ![80, 443, 8080, 8443].includes(p))
        )
          throw new AppError(400, "Invalid runner port policy.");
        for (const port of ports) {
          const addr = await resolvePublic(u.hostname);
          signal.throwIfAborted();
          const open = await new Promise<boolean>((resolve, reject) => {
            const s = net.connect({ host: addr.address, port, signal });
            s.setTimeout(1500);
            s.once("connect", () => {
              s.destroy();
              resolve(true);
            });
            s.once("timeout", () => {
              s.destroy();
              resolve(false);
            });
            s.once("error", (e) => {
              if (signal.aborted) reject(e);
              else resolve(false);
            });
          });
          add(
            `TCP ${port}: ${open ? "reachable" : "not observed open"}`,
            "info",
            `One connection attempt to configured port ${port}.`,
            "Reachability alone is not a vulnerability; timeouts do not prove a port is closed.",
            "Confirm exposure matches the intended service inventory.",
          );
        }
        summary = "Restricted TCP assessment completed.";
        status = "WARNING";
      }
    } else if (job.testId === "load") {
      const count = job.count;
      if (!Number.isInteger(count) || !count || count < 1 || count > 5)
        throw new AppError(400, "Request count must be 1–5.");
      const times: number[] = [];
      const codes: number[] = [];
      for (let i = 0; i < count; i++) {
        signal.throwIfAborted();
        const r = await snapshot(u, signal);
        times.push(r.duration);
        codes.push(r.status);
        if (i < count - 1) await delay(1000, undefined, { signal });
      }
      summary = `${count} sequential HEAD requests; concurrency 1; mean ${Math.round(times.reduce((a, b) => a + b, 0) / times.length)} ms. HTTP statuses: ${codes.join(", ")}.`;
      add(
        "Bounded request measurements",
        "info",
        summary,
        "This tiny sample cannot establish capacity or denial-of-service resistance.",
        "Use application telemetry for performance analysis.",
      );
      status = codes.some((c) => c >= 400) ? "WARNING" : "PASS";
    } else {
      if (job.testId === "input") {
        const paths = (process.env.INPUT_PATHS || "")
          .split(",")
          .filter(Boolean);
        if (
          !job.inputPath ||
          !paths.includes(job.inputPath) ||
          !/^\/[a-zA-Z0-9/_-]*$/.test(job.inputPath)
        )
          throw new AppError(
            403,
            "Input endpoint is not in the runner INPUT_PATHS policy.",
          );
        u.pathname = job.inputPath;
        u.searchParams.set("sentinel_probe", "sentinel-inert-marker-7f31");
      }
      if (job.testId === "tls") u.protocol = "https:";
      endpoint = `${u.origin}${u.pathname}`;
      const r = await snapshot(u, signal, job.testId === "input");
      if (r.status >= 400) {
        status = "ERROR";
        summary = `Target returned HTTP ${r.status}; audit was not completed.`;
      } else if (job.testId === "tls") {
        summary = `HTTPS accepted by the system trust store. ${r.tls?.protocol}; certificate expiry ${r.tls?.validTo}.`;
        if (!r.tls?.authorized)
          throw new Error("TLS verification unavailable.");
        if (!["TLSv1.2", "TLSv1.3"].includes(r.tls.protocol))
          add(
            "Legacy TLS negotiated",
            "medium",
            r.tls.protocol,
            "Older TLS can expose connections to cryptographic weaknesses.",
            "Require TLS 1.2 or later.",
          );
        add(
          "TLS audit scope",
          "info",
          summary,
          "Only one negotiated connection was checked; cipher enumeration and plaintext redirect behavior were not tested.",
          "Use a specialized TLS assessment for complete protocol and cipher coverage.",
        );
        status = finalStatus(findings);
      } else if (job.testId === "headers") {
        const policy = [
          [
            "content-security-policy",
            "medium",
            "Define a restrictive Content-Security-Policy.",
          ],
          [
            "strict-transport-security",
            "medium",
            "Enable HSTS after validating HTTPS for your domains.",
          ],
          [
            "x-content-type-options",
            "low",
            "Set X-Content-Type-Options: nosniff.",
          ],
          ["referrer-policy", "low", "Set a restrictive Referrer-Policy."],
          [
            "permissions-policy",
            "low",
            "Restrict unneeded browser capabilities.",
          ],
        ] as const;
        for (const [name, severity, remediation] of policy) {
          const v = r.headers[name];
          if (!v)
            add(
              `Missing ${name}`,
              severity,
              "Header was absent on the inspected response.",
              "A browser defense is absent; this alone does not prove exploitability.",
              remediation,
            );
          else if (
            name === "x-content-type-options" &&
            String(v).toLowerCase() !== "nosniff"
          )
            add(
              "Invalid content-type protection",
              "low",
              "X-Content-Type-Options does not equal nosniff.",
              "Browsers may ignore an invalid header value.",
              remediation,
            );
        }
        summary = `Inspected headers on HTTP ${r.status}. Policy content effectiveness requires manual review.`;
      } else if (job.testId === "cookies") {
        const cookies = r.headers["set-cookie"] || [];
        if (!cookies.length) {
          status = "NOT TESTED";
          summary =
            "No Set-Cookie headers were observed. Authenticated routes and browser cookies were not inspected.";
        }
        for (let i = 0; i < cookies.length; i++) {
          const attrs = cookies[i]
            .split(";")
            .slice(1)
            .map((x) => x.trim().toLowerCase());
          const missing = [
            !attrs.includes("secure") ? "Secure" : "",
            !attrs.includes("httponly") ? "HttpOnly" : "",
            !attrs.some((x) => /^samesite=(lax|strict|none)$/.test(x))
              ? "SameSite"
              : "",
          ].filter(Boolean);
          if (missing.length)
            add(
              `Cookie ${i + 1} missing ${missing.join(", ")}`,
              "medium",
              `Attribute flags only; cookie names and values were discarded.`,
              "Missing attributes can weaken session protections; some client-readable cookies intentionally omit HttpOnly.",
              "Set appropriate Secure, HttpOnly and SameSite attributes based on cookie purpose.",
            );
          if (attrs.includes("samesite=none") && !attrs.includes("secure"))
            add(
              `Cookie ${i + 1}: SameSite=None without Secure`,
              "medium",
              "SameSite=None and no Secure attribute.",
              "Modern browsers may reject the cookie.",
              "Set Secure with SameSite=None.",
            );
        }
        if (cookies.length)
          summary = `Inspected ${cookies.length} Set-Cookie header(s); no values retained.`;
      } else if (job.testId === "input") {
        const reflected = r.body.includes("sentinel-inert-marker-7f31");
        summary = `HTTP ${r.status}; inert marker ${reflected ? "was" : "was not"} reflected in the first bounded response.`;
        status = "WARNING";
        add(
          "Harmless reflection observation",
          "info",
          summary,
          "Reflection does not demonstrate XSS; absence does not prove input safety.",
          "Review context-aware output encoding and server-side validation.",
        );
      } else throw new AppError(400, "Unsupported runner module.");
    }
  }
  signal.throwIfAborted();
  return {
    testId: job.testId,
    startedAt,
    endedAt: new Date().toISOString(),
    status: status || finalStatus(findings),
    findings,
    summary,
  };
}
