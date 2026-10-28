export type Status =
  | "PASS"
  | "FAIL"
  | "WARNING"
  | "ERROR"
  | "NOT TESTED"
  | "RUNNING"
  | "CANCELLED";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export interface Finding {
  title: string;
  severity: Severity;
  endpoint: string;
  evidence: string;
  impact: string;
  remediation: string;
}
export interface Result {
  testId: string;
  status: Status;
  startedAt: string;
  endedAt: string;
  findings: Finding[];
  summary: string;
}
export interface Target {
  id: string;
  url: string;
  authorized_at: string;
}
export interface Scan {
  id: string;
  target_id: string | null;
  test_id: string;
  status: Status;
  started_at: string;
  ended_at: string | null;
  progress: number;
  result: Result | null;
}
export interface Event {
  id: number;
  at: string;
  action: string;
  resource: string;
}
export const modules = [
  {
    id: "tls",
    name: "HTTPS & TLS",
    category: "PASSIVE",
    description:
      "Inspect HTTPS connectivity, certificate validity and protocol negotiation.",
    icon: "lock",
    runner: true,
  },
  {
    id: "headers",
    name: "Security headers",
    category: "PASSIVE",
    description:
      "Review browser protections, content policies and transport headers.",
    icon: "shield",
    runner: true,
  },
  {
    id: "dns",
    name: "DNS reconnaissance",
    category: "PASSIVE",
    description:
      "Retrieve public A, AAAA, MX, NS, TXT and CAA record summaries.",
    icon: "network",
    runner: true,
  },
  {
    id: "cookies",
    name: "Cookie security",
    category: "PASSIVE",
    description:
      "Check cookie attribute flags without retaining cookie values.",
    icon: "cookie",
    runner: true,
  },
  {
    id: "input",
    name: "Input validation",
    category: "SAFE PROBE",
    description:
      "Send one inert marker to a designated, allowlisted test endpoint.",
    icon: "code",
    runner: true,
  },
  {
    id: "xss",
    name: "XSS demonstration",
    category: "ISOLATED LAB",
    description:
      "Compare unsafe rendering and text escaping in a sandboxed local frame.",
    icon: "flask",
    runner: false,
  },
  {
    id: "sql",
    name: "SQL injection lab",
    category: "ISOLATED LAB",
    description:
      "Compare vulnerable and parameterized queries on synthetic records.",
    icon: "database",
    runner: true,
  },
  {
    id: "ports",
    name: "Port exposure",
    category: "DEDICATED RUNNER",
    description:
      "Check only explicitly permitted ports with bounded TCP connections.",
    icon: "radar",
    runner: true,
  },
  {
    id: "load",
    name: "Bounded load test",
    category: "ACTIVE · OPT-IN",
    description:
      "Measure up to 5 sequential requests with a 1-second interval.",
    icon: "gauge",
    runner: true,
  },
  {
    id: "report",
    name: "Security report",
    category: "EXPORT",
    description:
      "Export recorded evidence and remediation as JSON or a printable report.",
    icon: "file",
    runner: false,
  },
] as const;
export type TestId = (typeof modules)[number]["id"];
export function finalStatus(findings: Finding[]): Status {
  return findings.some(
    (f) =>
      f.severity === "critical" ||
      f.severity === "high" ||
      f.severity === "medium",
  )
    ? "FAIL"
    : findings.length
      ? "WARNING"
      : "PASS";
}
