import type { Result, Finding, Status } from "../shared/models";
import { AppError, escapeHTML } from "../shared/validation";
export function validateResult(
  data: Record<string, unknown>,
  testId: string,
): Result {
  const statuses: Status[] = ["PASS", "FAIL", "WARNING", "ERROR", "NOT TESTED"];
  if (
    data.testId !== testId ||
    !statuses.includes(data.status as Status) ||
    typeof data.summary !== "string" ||
    data.summary.length > 4000 ||
    typeof data.startedAt !== "string" ||
    !Number.isFinite(Date.parse(data.startedAt)) ||
    typeof data.endedAt !== "string" ||
    !Number.isFinite(Date.parse(data.endedAt)) ||
    !Array.isArray(data.findings) ||
    data.findings.length > 40
  )
    throw new AppError(502, "Runner returned an invalid result.");
  for (const f of data.findings) {
    if (
      !f ||
      !["critical", "high", "medium", "low", "info"].includes(f.severity) ||
      ["title", "endpoint", "evidence", "impact", "remediation"].some(
        (k) => typeof f[k] !== "string" || f[k].length > 4000,
      )
    )
      throw new AppError(502, "Runner returned invalid findings.");
  }
  if (
    data.status === "PASS" &&
    (data.findings as Finding[]).some((f) => f.severity !== "info")
  )
    throw new AppError(502, "Runner returned an inconsistent success status.");
  return data as unknown as Result;
}
export function reportHTML(
  scans: {
    id: string;
    status: string;
    result: Result | null;
    started_at: string;
  }[],
) {
  const e = escapeHTML;
  return `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Sentinel security report</title><style>body{font:15px/1.6 system-ui;color:#18231d;max-width:900px;margin:48px auto;padding:24px}h1{font-size:34px}h2{border-bottom:1px solid #ccc;padding-bottom:12px}article{break-inside:avoid;padding:16px 0;border-bottom:1px solid #ddd}small{color:#53655b}dt{font-weight:700}dd{margin:0 0 12px;overflow-wrap:anywhere}@media print{body{margin:0}}</style><h1>Sentinel / Security assessment</h1><p>Generated ${e(new Date().toISOString())} · ${scans.length} recorded checks</p><p>Point-in-time observations for authorized targets. Lab records are synthetic demonstrations. PASS applies only to the stated check scope; NOT TESTED, ERROR and CANCELLED are incomplete assessments.</p>${scans.map((s) => `<section><h2>${e(s.result?.testId || "Check")} · ${e(s.status)}</h2><small>${e(s.started_at)} · ${e(s.id)}</small><p>${e(s.result?.summary || "No completed result.")}</p>${(s.result?.findings || []).map((f) => `<article><h3>${e(f.title)} / ${e(f.severity)}</h3><dl><dt>Affected endpoint</dt><dd>${e(f.endpoint)}</dd><dt>Evidence</dt><dd>${e(f.evidence)}</dd><dt>Impact</dt><dd>${e(f.impact)}</dd><dt>Remediation</dt><dd>${e(f.remediation)}</dd></dl></article>`).join("")}</section>`).join("")}</html>`;
}
