import React, { useEffect, useRef, useState } from "react";
import { Badge, Dialog } from "./components";
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock3,
  Code2,
  Cookie,
  Database,
  FileText,
  FlaskConical,
  Gauge,
  Globe2,
  LayoutDashboard,
  LoaderCircle,
  LockKeyhole,
  Network,
  Plus,
  Radio,
  Search,
  Settings,
  Shield,
  ShieldCheck,
  Square,
  Target as TargetIcon,
  Trash2,
  X,
  Zap,
} from "lucide-react";
import { modules, type Target, type Scan, type Event } from "../shared/models";
import { labDocument, labPayload } from "../shared/lab";
import "./style.css";
interface State {
  targets: Target[];
  scans: Scan[];
  events: Event[];
  stopped: boolean;
  runnerConfigured: boolean;
  allowedHosts: string[];
}
const initial: State = {
  targets: [],
  scans: [],
  events: [],
  stopped: false,
  runnerConfigured: false,
  allowedHosts: [],
};
const nav = [
  ["Dashboard", LayoutDashboard],
  ["Targets", TargetIcon],
  ["Security Tests", ShieldCheck],
  ["Scan History", Clock3],
  ["Reports", FileText],
  ["Settings", Settings],
] as const;
const icons = {
  lock: LockKeyhole,
  shield: Shield,
  network: Network,
  cookie: Cookie,
  code: Code2,
  flask: FlaskConical,
  database: Database,
  radar: Radio,
  gauge: Gauge,
  file: FileText,
};
const time = (s: string) =>
  new Date(s).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
export default function App() {
  const [page, setPage] = useState("Dashboard");
  const [state, setState] = useState<State>(initial);
  useEffect(() => {
    window.scrollTo({ top: 0, behavior: "auto" });
  }, [page]);
  const [token, setToken] = useState("");
  const tokenRef = useRef("");
  const [connected, setConnected] = useState(false);
  const [busy, setBusy] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [modal, setModal] = useState<
    "connect" | "target" | "load" | "input" | "stop" | "delete" | null
  >(null);
  const [selected, setSelected] = useState("");
  const [view, setView] = useState<Scan | null>(null);
  const [notice, setNotice] = useState<{ text: string; error: boolean } | null>(
    null,
  );
  const [category, setCategory] = useState("All tests");
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("");
  const [severity, setSeverity] = useState("");
  const [deleteId, setDeleteId] = useState("");
  const toast = (text: string, error = false) => setNotice({ text, error });
  useEffect(() => {
    if (!notice) return;
    const timer = setTimeout(() => setNotice(null), 6500);
    return () => clearTimeout(timer);
  }, [notice]);
  async function api(path: string, options: RequestInit = {}) {
    const r = await fetch(`/api${path}`, {
      ...options,
      headers: {
        Authorization: `Bearer ${tokenRef.current}`,
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...options.headers,
      },
    });
    if (!r.ok) {
      let message = `Request failed (${r.status}).`;
      try {
        message = ((await r.json()) as { error?: string }).error || message;
      } catch {}
      if (r.status === 401) setConnected(false);
      throw new Error(message);
    }
    return r;
  }
  async function refresh(silent = false) {
    if (!silent) setRefreshing(true);
    try {
      const key = tokenRef.current;
      const data: State = await (await api("/state")).json();
      if (key !== tokenRef.current) return;
      setState(data);
      setConnected(true);
      setSelected((prev) =>
        data.targets.some((t) => t.id === prev)
          ? prev
          : data.targets[0]?.id || "",
      );
    } finally {
      setRefreshing(false);
    }
  }
  useEffect(() => {
    if (!connected) return;
    let live = true;
    const timer = setInterval(() => {
      if (live)
        void refresh(true).catch((e) => {
          setConnected(false);
          toast(e.message, true);
        });
    }, 2500);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [connected]);
  async function action(fn: () => Promise<void>) {
    setBusy(true);
    try {
      await fn();
    } catch (e) {
      toast(e instanceof Error ? e.message : "Request failed.", true);
    } finally {
      setBusy(false);
    }
  }
  async function connect(e: React.FormEvent) {
    e.preventDefault();
    await action(async () => {
      tokenRef.current = token;
      await refresh();
      setToken("");
      setModal(null);
      toast("Workspace connected. Access token is held in memory only.");
    });
  }
  async function run(id: string, extra: Record<string, unknown> = {}) {
    if (!connected) {
      setModal("connect");
      return;
    }
    if (id === "report") {
      setPage("Reports");
      return;
    }
    if (id === "load" && !extra.confirmLoad) {
      setModal("load");
      return;
    }
    if (id === "input" && !extra.inputPath) {
      setModal("input");
      return;
    }
    await action(async () => {
      const response = (await (
        await api("/scans", {
          method: "POST",
          body: JSON.stringify({ testId: id, targetId: selected, ...extra }),
        })
      ).json()) as { id: string };
      await refresh();
      setModal(null);
      toast(`Check started · ${response.id.slice(0, 8)}`);
    });
  }
  async function cancel(id: string) {
    await action(async () => {
      const r = (await (
        await api(`/scans/${id}/cancel`, { method: "POST" })
      ).json()) as { warning?: string };
      await refresh();
      toast(r.warning || "Check cancelled.", !!r.warning);
    });
  }
  async function emergency() {
    await action(async () => {
      const r = (await (
        await api(state.stopped ? "/resume" : "/stop", { method: "POST" })
      ).json()) as { warning?: string };
      await refresh();
      setModal(null);
      toast(
        r.warning ||
          (state.stopped ? "Testing resumed." : "Emergency stop activated."),
        !!r.warning,
      );
    });
  }
  async function exportReport(format: "json" | "html") {
    if (!connected) {
      setModal("connect");
      return;
    }
    await action(async () => {
      const q = new URLSearchParams({ format });
      if (filter) q.set("status", filter);
      if (severity) q.set("severity", severity);
      const r = await api(`/reports?${q}`);
      const url = URL.createObjectURL(await r.blob());
      const a = document.createElement("a");
      a.href = url;
      a.download = `sentinel-report.${format}`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast("Report exported.");
      await refresh(true);
    });
  }
  const active = state.scans.find((s) => s.status === "RUNNING");
  const findings = state.scans
    .filter((s) => !["xss", "sql"].includes(s.test_id))
    .flatMap((s) => s.result?.findings || []);
  const currentTarget = state.targets.find((t) => t.id === selected);
  const filtered = modules.filter(
    (m) =>
      (category === "All tests" ||
        (category === "Passive checks"
          ? m.category === "PASSIVE"
          : category === "Labs"
            ? m.category === "ISOLATED LAB"
            : m.category !== "PASSIVE" && m.category !== "ISOLATED LAB")) &&
      `${m.name} ${m.description}`.toLowerCase().includes(search.toLowerCase()),
  );
  const empty = (
    title: string,
    desc: string,
    icon: React.ReactNode = <Activity size={26} />,
  ) => (
    <div className="empty">
      {icon}
      <strong>{title}</strong>
      <p>{desc}</p>
    </div>
  );
  const targetSelect = (
    <label className="target-select">
      <Globe2 size={16} />
      <span className="sr-only">Active authorized target</span>
      <select value={selected} onChange={(e) => setSelected(e.target.value)}>
        <option value="">Select a target</option>
        {state.targets.map((t) => (
          <option value={t.id} key={t.id}>
            {new URL(t.url).hostname}
            {new URL(t.url).pathname === "/" ? "" : new URL(t.url).pathname}
          </option>
        ))}
      </select>
      <ChevronDown size={14} />
    </label>
  );
  function scanList(limit = 100) {
    const scans = state.scans
      .filter((s) => !filter || s.status === filter)
      .slice(0, limit);
    return scans.length ? (
      <div className="table-wrap">
        <table className="scan-table">
          <thead>
            <tr>
              <th>Check / target</th>
              <th>Status</th>
              <th>Started</th>
              <th>Findings</th>
              <th>
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {scans.map((s) => (
              <tr key={s.id}>
                <td data-label="Check / target">
                  <strong>
                    {modules.find((m) => m.id === s.test_id)?.name || s.test_id}
                  </strong>
                  <small className="mono">
                    {["sql", "xss"].includes(s.test_id)
                      ? "Isolated synthetic lab"
                      : state.targets.find((t) => t.id === s.target_id)?.url ||
                        "Archived target"}
                  </small>
                </td>
                <td data-label="Status">
                  <Badge status={s.status} />
                  {s.status === "RUNNING" && (
                    <small className="live-note">
                      Executing · awaiting result
                    </small>
                  )}
                </td>
                <td data-label="Started" className="muted mono nowrap">
                  {time(s.started_at)}
                </td>
                <td data-label="Findings" className="mono">
                  {s.result ? s.result.findings.length : "—"}
                </td>
                <td data-label="Actions">
                  {s.status === "RUNNING" ? (
                    <button
                      className="text-button danger-text"
                      disabled={busy}
                      onClick={() => void cancel(s.id)}
                    >
                      Cancel
                    </button>
                  ) : (
                    <button className="text-button" onClick={() => setView(s)}>
                      Results <ChevronRight size={14} />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    ) : (
      empty(
        "No checks recorded",
        connected
          ? "Run a security check to start building your assessment history."
          : "Connect your workspace to see real scan history.",
      )
    );
  }
  function testCards() {
    return (
      <div className="test-grid">
        {filtered.map((m) => {
          const Icon = icons[m.icon];
          const latest = state.scans.find((s) => s.test_id === m.id);
          const lab = m.category === "ISOLATED LAB";
          return (
            <article className="test-card" key={m.id}>
              <div className="card-top">
                <span className={`test-icon ${lab ? "lab-icon" : ""}`}>
                  <Icon size={22} />
                </span>
                <span className="eyebrow">{m.category}</span>
              </div>
              <h3>{m.name}</h3>
              <p>{m.description}</p>
              <div className="test-state">
                {latest ? (
                  <Badge status={latest.status} />
                ) : (
                  <span className="not-run">
                    <span />
                    Not run
                  </span>
                )}
                {m.runner && !state.runnerConfigured && (
                  <span className="dependency">Runner required</span>
                )}
              </div>
              <div className="card-actions">
                <button
                  className="run-button"
                  disabled={
                    busy ||
                    !!active ||
                    state.stopped ||
                    (connected && !selected && !lab && m.id !== "report")
                  }
                  onClick={() => void run(m.id)}
                >
                  {m.id === "report" ? (
                    <FileText size={14} />
                  ) : (
                    <Zap size={14} />
                  )}
                  {m.id === "report" ? "Open reports" : "Run test"}
                </button>
                {latest && latest.status !== "RUNNING" ? (
                  <button
                    className="text-button"
                    onClick={() => setView(latest)}
                  >
                    View results <ArrowRight size={13} />
                  </button>
                ) : (
                  <span className="muted small">
                    {lab
                      ? "Synthetic data only"
                      : m.id === "report"
                        ? "Recorded evidence"
                        : "Authorized targets only"}
                  </span>
                )}
              </div>
            </article>
          );
        })}
      </div>
    );
  }
  return (
    <div className="app">
      <aside className="sidebar">
        <a
          aria-label="Sentinel dashboard"
          className="brand"
          href="#"
          onClick={(e) => {
            e.preventDefault();
            setPage("Dashboard");
          }}
        >
          <span className="brand-symbol">
            <ShieldCheck size={25} />
          </span>
          <span>
            sentinel<span className="brand-dot">.</span>
            <small>SECURITY WORKSPACE</small>
          </span>
        </a>
        <div className="workspace-label">
          WORKSPACE <span>01</span>
        </div>
        <nav aria-label="Main navigation">
          {nav.map(([name, Icon]) => (
            <button
              aria-label={name}
              aria-current={page === name ? "page" : undefined}
              key={name}
              className={page === name ? "active" : ""}
              onClick={() => {
                setPage(name);
                setSearch("");
              }}
            >
              <Icon size={18} />
              <span>{name}</span>
              {name === "Security Tests" && <small>10</small>}
              {page === name && <span className="nav-marker" />}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="scope-note">
            <Shield size={19} />
            <strong>Permission comes first</strong>
            <p>
              Test only the assets you own or are explicitly authorized to
              assess.
            </p>
          </div>
          <button className="operator" onClick={() => setPage("Settings")}>
            <span className="avatar">OP</span>
            <span>
              Operator workspace
              <small>
                {connected ? "Authenticated session" : "Session disconnected"}
              </small>
            </span>
            <Settings size={16} />
          </button>
        </div>
      </aside>
      <nav className="mobile-nav" aria-label="Mobile navigation">
        {nav.map(([name, Icon], index) => (
          <button
            key={name}
            aria-label={name}
            aria-current={page === name ? "page" : undefined}
            className={page === name ? "active" : ""}
            onClick={() => {
              setPage(name);
              setSearch("");
            }}
          >
            <Icon size={20} />
            <span>
              {
                [
                  "Overview",
                  "Targets",
                  "Tests",
                  "History",
                  "Reports",
                  "Settings",
                ][index]
              }
            </span>
          </button>
        ))}
      </nav>
      <div className="main-shell">
        <header className="topbar">
          <a
            href="#"
            className="mobile-brand"
            aria-label="Sentinel dashboard"
            onClick={(e) => {
              e.preventDefault();
              setPage("Dashboard");
            }}
          >
            <ShieldCheck size={23} />
            <span>
              sentinel<span className="brand-dot">.</span>
            </span>
          </a>
          <div className="breadcrumb">
            <Shield size={15} />
            <span>Workspace</span>
            <ChevronRight size={13} />
            <strong>{page}</strong>
          </div>
          <div className="top-actions">
            <span className="environment">
              <span />
              {connected ? "WORKSPACE CONNECTED" : "LOCAL WORKSPACE"}
            </span>
            <button
              className="icon-button danger-text"
              aria-label="Emergency controls"
              disabled={!connected || busy}
              onClick={() => setModal("stop")}
            >
              <Square size={15} />
            </button>
            <button
              className="icon-button"
              aria-label="Open connection settings"
              onClick={() => setModal("connect")}
            >
              <LockKeyhole size={17} />
            </button>
            <span className="avatar small-avatar">OP</span>
          </div>
        </header>
        <main>
          <div className="page-heading">
            <div>
              <div className="eyebrow section-kicker">
                AUTHORIZED SECURITY ASSESSMENT
              </div>
              <h1>{page === "Dashboard" ? "Security overview" : page}</h1>
              <p>
                {
                  (
                    {
                      Dashboard:
                        "A clear view of your attack surface. Every finding backed by evidence.",
                      Targets:
                        "Define the assets in scope. Authorization is enforced on the server.",
                      "Security Tests":
                        "Purpose-built checks. Real execution. Clearly defined boundaries.",
                      "Scan History":
                        "A traceable record of every assessment and its outcome.",
                      Reports:
                        "Turn recorded evidence into a useful remediation plan.",
                      Settings:
                        "Connection, execution policies and workspace controls.",
                    } as Record<string, string>
                  )[page]
                }
              </p>
            </div>
            <div className="heading-actions">
              {connected ? (
                <button
                  className="secondary"
                  disabled={refreshing}
                  onClick={() => void action(() => refresh())}
                >
                  <Activity size={15} className={refreshing ? "spin" : ""} />{" "}
                  Refresh
                </button>
              ) : (
                <button
                  className="secondary"
                  onClick={() => setModal("connect")}
                >
                  <LockKeyhole size={15} />
                  Connect workspace
                </button>
              )}
              <button
                className="primary"
                onClick={() => setModal(connected ? "target" : "connect")}
              >
                <Plus size={17} />
                Add target
              </button>
            </div>
          </div>
          {!connected && (
            <div className="connection-banner">
              <LockKeyhole size={18} />
              <div>
                <strong>Your workspace is ready to connect</strong>
                <span>
                  Authenticate with your server access token to manage targets
                  and run checks.
                </span>
              </div>
              <button
                className="text-button"
                onClick={() => setModal("connect")}
              >
                Connect <ArrowRight size={15} />
              </button>
            </div>
          )}
          {state.stopped && (
            <div className="stop-banner">
              <Square size={18} />
              <strong>Emergency stop is active. New checks are blocked.</strong>
              <button
                className="secondary"
                disabled={busy}
                onClick={() => void emergency()}
              >
                Resume testing
              </button>
            </div>
          )}
          {active && (
            <div className="running-banner">
              <LoaderCircle size={18} className="spin" />
              <div>
                <strong>
                  {modules.find((m) => m.id === active.test_id)?.name} is
                  running
                </strong>
                <span>
                  Started {time(active.started_at)} · request deadline enforced
                  by runner
                </span>
              </div>
              <button
                className="text-button"
                onClick={() => void cancel(active.id)}
                disabled={busy}
              >
                Cancel check
              </button>
            </div>
          )}
          {page === "Dashboard" && (
            <>
              <div className="metrics">
                <article>
                  <div>
                    <span>Authorized targets</span>
                    <TargetIcon size={17} />
                  </div>
                  <strong>{connected ? state.targets.length : "—"}</strong>
                  <small>
                    {state.targets.length
                      ? "Registered in this workspace"
                      : "Add your first asset to begin"}
                  </small>
                </article>
                <article>
                  <div>
                    <span>Completed checks</span>
                    <ShieldCheck size={17} />
                  </div>
                  <strong>
                    {connected
                      ? state.scans.filter((s) =>
                          ["PASS", "FAIL", "WARNING"].includes(s.status),
                        ).length
                      : "—"}
                  </strong>
                  <small>Within the latest 100 checks</small>
                </article>
                <article>
                  <div>
                    <span>Actionable observations</span>
                    <Activity size={17} />
                  </div>
                  <strong>
                    {connected
                      ? findings.filter((f) => f.severity !== "info").length
                      : "—"}
                  </strong>
                  <small>Lab demonstrations excluded</small>
                </article>
                <article>
                  <div>
                    <span>Active checks</span>
                    <Radio size={17} />
                  </div>
                  <strong className={active ? "green" : ""}>
                    {connected ? (active ? 1 : 0) : "—"}
                  </strong>
                  <small>
                    {active ? "Execution in progress" : "Concurrency limit: 1"}
                  </small>
                </article>
              </div>
              <div className="overview-grid">
                <section className="panel posture-panel">
                  <div className="panel-heading">
                    <h2>
                      <span className="green-dot" />
                      Assessment scope
                    </h2>
                    <span className="eyebrow">LIVE DATA ONLY</span>
                  </div>
                  <div className="scope-content">
                    <div className="scope-graphic">
                      <ShieldCheck size={48} strokeWidth={1.1} />
                    </div>
                    <div>
                      <span className="eyebrow">YOUR NEXT STEP</span>
                      <h3>
                        {!connected
                          ? "Connect your workspace"
                          : !state.targets.length
                            ? "Define your testing scope"
                            : !state.scans.length
                              ? "Establish your baseline"
                              : "Review, remediate, repeat"}
                      </h3>
                      <p>
                        {!state.targets.length
                          ? "Register an allowlisted hostname, confirm authorization, then start with a passive check."
                          : "Select an authorized target and run a check. Review its evidence and limitations before taking action."}
                      </p>
                      <button
                        className="text-button"
                        onClick={() =>
                          state.targets.length
                            ? setPage("Security Tests")
                            : setModal(connected ? "target" : "connect")
                        }
                      >
                        {state.targets.length
                          ? "Explore security tests"
                          : "Configure your first target"}{" "}
                        <ArrowRight size={15} />
                      </button>
                    </div>
                  </div>
                  <div className="scope-footer">
                    <span>
                      <LockKeyhole size={13} /> Server-enforced allowlist
                    </span>
                    <span>
                      <CheckCircle2 size={13} /> Passive by default
                    </span>
                  </div>
                </section>
                <section className="panel severity-panel">
                  <div className="panel-heading">
                    <h2>Findings by severity</h2>
                    <span className="muted small">Latest 100 checks</span>
                  </div>
                  <div className="severity-bars">
                    {(
                      ["critical", "high", "medium", "low", "info"] as const
                    ).map((s) => {
                      const n = findings.filter((f) => f.severity === s).length;
                      return (
                        <div className={`severity-row ${s}`} key={s}>
                          <span className="severity-dot" />
                          <span className="severity-name">{s}</span>
                          <div className="bar-track">
                            <div
                              style={{
                                width: `${findings.length ? (n / findings.length) * 100 : 0}%`,
                              }}
                            />
                          </div>
                          <strong>{connected ? n : "—"}</strong>
                        </div>
                      );
                    })}
                  </div>
                  <p className="chart-note">
                    Observations are per check; repeated findings are not
                    deduplicated.
                  </p>
                </section>
              </div>
              <section className="panel recent">
                <div className="panel-heading">
                  <div>
                    <h2>Recent assessments</h2>
                    <p>Recent outcomes and supporting evidence.</p>
                  </div>
                  <button
                    className="text-button"
                    onClick={() => setPage("Scan History")}
                  >
                    View history <ArrowRight size={14} />
                  </button>
                </div>
                {scanList(4)}
              </section>
              <div className="section-heading">
                <div>
                  <h2>Start with the essentials</h2>
                  <p>Bounded checks for a stronger security baseline.</p>
                </div>
                <button
                  className="text-button"
                  onClick={() => setPage("Security Tests")}
                >
                  All security tests <ArrowRight size={15} />
                </button>
              </div>
              <div className="quick-grid">
                {modules.slice(0, 3).map((m) => {
                  const Icon = icons[m.icon];
                  return (
                    <button
                      key={m.id}
                      className="quick-card"
                      disabled={busy || !!active || state.stopped}
                      onClick={() => void run(m.id)}
                    >
                      <Icon size={21} />
                      <div>
                        <strong>{m.name}</strong>
                        <span>Passive check</span>
                      </div>
                      <ArrowRight size={16} />
                    </button>
                  );
                })}
              </div>
              <section className="panel activity-panel">
                <div className="panel-heading">
                  <h2>Workspace activity</h2>
                  <span className="eyebrow">AUDIT LOG</span>
                </div>
                {state.events.length ? (
                  <div className="events">
                    {state.events.slice(0, 5).map((e) => (
                      <div key={e.id}>
                        <span className="event-dot" />
                        <span>{e.action.replaceAll(".", " / ")}</span>
                        <code>
                          {e.resource === "global"
                            ? "global"
                            : e.resource.slice(0, 8)}
                        </code>
                        <time>{time(e.at)}</time>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="quiet-empty">
                    No activity yet. Target changes and scan events will appear
                    here.
                  </div>
                )}
              </section>
            </>
          )}
          {page === "Targets" && (
            <>
              <div className="section-heading">
                <h2>
                  Authorized assets{" "}
                  <span className="count">{state.targets.length}</span>
                </h2>
                <span className="muted small">
                  Exact hostname matching · no wildcards
                </span>
              </div>
              <section className="panel">
                {state.targets.length ? (
                  <div className="target-list">
                    {state.targets.map((t) => {
                      const latest = state.scans.find(
                        (s) => s.target_id === t.id,
                      );
                      return (
                        <article key={t.id}>
                          <span className="test-icon">
                            <Globe2 size={22} />
                          </span>
                          <div>
                            <strong className="mono">{t.url}</strong>
                            <small>Authorized {time(t.authorized_at)}</small>
                            <span className="small muted">
                              Connection:{" "}
                              {latest?.status === "ERROR"
                                ? "last check failed"
                                : latest?.result
                                  ? "last result available"
                                  : "not yet checked"}
                            </span>
                          </div>
                          <Badge status="AUTHORIZED" />
                          <button
                            className="secondary"
                            onClick={() => {
                              setSelected(t.id);
                              setPage("Security Tests");
                            }}
                          >
                            Select target <ArrowRight size={14} />
                          </button>
                          <button
                            className="icon-button danger-text"
                            aria-label={`Delete ${t.url}`}
                            onClick={() => {
                              setDeleteId(t.id);
                              setModal("delete");
                            }}
                          >
                            <Trash2 size={17} />
                          </button>
                        </article>
                      );
                    })}
                  </div>
                ) : (
                  empty(
                    "Your scope starts here",
                    "Add an explicitly authorized hostname from your server allowlist.",
                    <Globe2 size={30} />,
                  )
                )}
              </section>
              <div className="info-box">
                <Shield size={20} />
                <div>
                  <strong>Authorization is more than a checkbox</strong>
                  <p>
                    The API requires an exact server allowlist match. The runner
                    rejects private IPs and redirects, and resolves each
                    connection before pinning its destination.
                  </p>
                </div>
              </div>
            </>
          )}
          {page === "Security Tests" && (
            <>
              <div className="test-toolbar">
                {targetSelect}
                <label className="search">
                  <Search size={16} />
                  <input
                    placeholder="Search security tests…"
                    aria-label="Search security tests"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                </label>
              </div>
              <div className="tabs" role="tablist" aria-label="Test category">
                {["All tests", "Passive checks", "Labs", "Other tools"].map(
                  (t) => (
                    <button
                      role="tab"
                      aria-selected={category === t}
                      key={t}
                      className={category === t ? "selected" : ""}
                      onClick={() => setCategory(t)}
                    >
                      {t}
                      {t === "All tests" && <span>10</span>}
                    </button>
                  ),
                )}
              </div>
              {filtered.length
                ? testCards()
                : empty(
                    "No matching tests",
                    "Try a different search or category.",
                  )}
            </>
          )}
          {page === "Scan History" && (
            <>
              <div className="section-heading">
                <h2>Assessment history</h2>
                <label className="filter-label">
                  Status
                  <select
                    aria-label="Filter scan status"
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                  >
                    <option value="">All statuses</option>
                    {[
                      "PASS",
                      "FAIL",
                      "WARNING",
                      "ERROR",
                      "NOT TESTED",
                      "CANCELLED",
                      "RUNNING",
                    ].map((s) => (
                      <option key={s}>{s}</option>
                    ))}
                  </select>
                </label>
              </div>
              <section className="panel">{scanList()}</section>
            </>
          )}
          {page === "Reports" && (
            <>
              <section className="report-hero panel">
                <span className="report-icon">
                  <FileText size={38} />
                </span>
                <div>
                  <span className="eyebrow">EVIDENCE → ACTION</span>
                  <h2>Your assessment, ready to share.</h2>
                  <p>
                    Export recorded outcomes, affected endpoints, evidence and
                    remediation. Lab observations stay explicitly labeled.
                  </p>
                  <div className="report-filters">
                    <label>
                      Status
                      <select
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)}
                      >
                        <option value="">All statuses</option>
                        {[
                          "PASS",
                          "FAIL",
                          "WARNING",
                          "ERROR",
                          "NOT TESTED",
                          "CANCELLED",
                        ].map((s) => (
                          <option key={s}>{s}</option>
                        ))}
                      </select>
                    </label>
                    <label>
                      Severity
                      <select
                        value={severity}
                        onChange={(e) => setSeverity(e.target.value)}
                      >
                        <option value="">All severities</option>
                        {["critical", "high", "medium", "low", "info"].map(
                          (s) => (
                            <option key={s}>{s}</option>
                          ),
                        )}
                      </select>
                    </label>
                  </div>
                  <div className="button-row">
                    <button
                      className="primary"
                      disabled={busy || !state.scans.length}
                      onClick={() => void exportReport("html")}
                    >
                      <ArrowDownToLine size={16} />
                      Export formatted report
                    </button>
                    <button
                      className="secondary"
                      disabled={busy || !state.scans.length}
                      onClick={() => void exportReport("json")}
                    >
                      <Code2 size={16} />
                      Export JSON
                    </button>
                  </div>
                  <small className="muted">
                    The HTML report is printable from your browser. Exports
                    include at most 100 recent checks.
                  </small>
                </div>
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <h2>Report source records</h2>
                </div>
                {scanList()}
              </section>
            </>
          )}
          {page === "Settings" && (
            <div className="settings-grid">
              <section className="panel settings-panel">
                <div className="panel-heading">
                  <h2>Workspace connection</h2>
                  <Badge status={connected ? "CONNECTED" : "DISCONNECTED"} />
                </div>
                <p>
                  Single-operator workspace. Your access token stays in browser
                  memory and is cleared when you disconnect or reload.
                </p>
                <div className="button-row">
                  <button
                    className="secondary"
                    onClick={() => setModal("connect")}
                  >
                    <LockKeyhole size={15} />
                    {connected ? "Replace token" : "Connect workspace"}
                  </button>
                  {connected && (
                    <button
                      className="text-button danger-text"
                      onClick={() => {
                        tokenRef.current = "";
                        setConnected(false);
                        setState(initial);
                        setSelected("");
                        toast("Disconnected. In-memory credentials cleared.");
                      }}
                    >
                      Disconnect
                    </button>
                  )}
                </div>
              </section>
              <section className="panel settings-panel">
                <div className="panel-heading">
                  <h2>Execution policy</h2>
                </div>
                <dl className="policy">
                  <div>
                    <dt>Concurrent checks</dt>
                    <dd>1</dd>
                  </div>
                  <div>
                    <dt>Request quota</dt>
                    <dd>30 checks / hour</dd>
                  </div>
                  <div>
                    <dt>Response limit</dt>
                    <dd>64 KiB</dd>
                  </div>
                  <div>
                    <dt>Runner deadline</dt>
                    <dd>24 seconds</dd>
                  </div>
                  <div>
                    <dt>HTTP redirects</dt>
                    <dd>Rejected</dd>
                  </div>
                  <div>
                    <dt>Network runner</dt>
                    <dd>
                      {!connected
                        ? "Unknown"
                        : state.runnerConfigured
                          ? "Configured · reachability unverified"
                          : "Not configured"}
                    </dd>
                  </div>
                </dl>
              </section>
              <section className="panel settings-panel">
                <div className="panel-heading">
                  <h2>Hostname allowlist</h2>
                  <Shield size={18} />
                </div>
                <p>
                  Managed by the server's ALLOWED_HOSTS environment variable.
                  Adding a target cannot expand this policy.
                </p>
                <div className="allowlist">
                  {state.allowedHosts.length ? (
                    state.allowedHosts.map((h) => (
                      <code key={h}>
                        <Check size={14} />
                        {h}
                      </code>
                    ))
                  ) : (
                    <span className="muted">
                      {connected
                        ? "No hostnames configured."
                        : "Connect to view the server policy."}
                    </span>
                  )}
                </div>
              </section>
              <section className="panel settings-panel danger-panel">
                <div className="panel-heading">
                  <h2>Emergency controls</h2>
                  <Square size={17} />
                </div>
                <p>
                  Stop active work and block new checks globally. If the runner
                  cannot acknowledge, its hard request deadlines still apply.
                </p>
                <button
                  className="danger-button"
                  disabled={!connected || busy}
                  onClick={() => setModal("stop")}
                >
                  <Square size={14} />
                  {state.stopped ? "Resume testing" : "Emergency stop"}
                </button>
              </section>
            </div>
          )}
          <footer>
            <span>
              <ShieldCheck size={13} />
              Built for responsible security work.
            </span>
            <span>Scope first. Evidence always.</span>
          </footer>
        </main>
      </div>
      {modal === "connect" && (
        <Dialog
          notice={notice}
          title="Connect your workspace"
          onClose={() => setModal(null)}
        >
          <form onSubmit={connect}>
            <p className="muted">
              Enter the API_TOKEN configured on your Pages backend. It is held
              in memory for this tab only.
            </p>
            <label>
              Access token
              <input
                autoFocus
                type="password"
                value={token}
                autoComplete="off"
                required
                minLength={32}
                onChange={(e) => setToken(e.target.value)}
                placeholder="Your server access token"
              />
            </label>
            <div className="modal-note">
              <LockKeyhole size={16} />
              Never put your token in a URL or a VITE_ environment variable.
            </div>
            <div className="dialog-actions">
              <button
                type="button"
                className="secondary"
                onClick={() => setModal(null)}
              >
                Cancel
              </button>
              <button className="primary" disabled={busy}>
                {busy ? (
                  <LoaderCircle size={16} className="spin" />
                ) : (
                  <LockKeyhole size={16} />
                )}
                Connect
              </button>
            </div>
          </form>
        </Dialog>
      )}
      {modal === "target" && (
        <Dialog
          notice={notice}
          title="Add an authorized target"
          onClose={() => setModal(null)}
        >
          <form
            onSubmit={(e) => {
              e.preventDefault();
              const d = new FormData(e.currentTarget);
              void action(async () => {
                await api("/targets", {
                  method: "POST",
                  body: JSON.stringify({
                    url: d.get("url"),
                    authorized: d.get("authorized") === "on",
                  }),
                });
                await refresh();
                setModal(null);
                toast("Authorized target registered.");
              });
            }}
          >
            <p className="muted">
              Use the exact public hostname and endpoint you are authorized to
              assess.
            </p>
            <label>
              Target URL
              <input
                type="url"
                name="url"
                placeholder="https://your-domain.com/"
                required
                autoFocus
              />
            </label>
            <small className="muted">
              HTTP or HTTPS · standard ports · no query strings
            </small>
            <label className="checkbox-label">
              <input type="checkbox" name="authorized" required />
              <span>
                I own this website or have explicit authorization to perform
                these security checks.
              </span>
            </label>
            <div className="modal-note">
              <Shield size={17} />
              The hostname must also appear in your server's ALLOWED_HOSTS
              configuration.
            </div>
            <div className="dialog-actions">
              <button
                type="button"
                className="secondary"
                onClick={() => setModal(null)}
              >
                Cancel
              </button>
              <button className="primary" disabled={busy}>
                <Plus size={16} />
                Add target
              </button>
            </div>
          </form>
        </Dialog>
      )}
      {modal === "load" && (
        <Dialog
          notice={notice}
          title="Configure bounded load check"
          onClose={() => setModal(null)}
        >
          <form
            onSubmit={(e) => {
              e.preventDefault();
              const d = new FormData(e.currentTarget);
              void run("load", {
                confirmLoad: true,
                count: Number(d.get("count")),
              });
            }}
          >
            <p className="muted">
              {currentTarget?.url || "Select an authorized target first."} ·
              HEAD requests only, concurrency 1, a 1-second pause between
              requests.
            </p>
            <label>
              Request cap (1–5)
              <input
                type="number"
                name="count"
                min="1"
                max="5"
                defaultValue="3"
                required
              />
            </label>
            <label className="checkbox-label">
              <input type="checkbox" required />
              <span>
                I explicitly authorize this low-volume check and understand its
                scope.
              </span>
            </label>
            <div className="dialog-actions">
              <button
                type="button"
                className="secondary"
                onClick={() => setModal(null)}
              >
                Cancel
              </button>
              <button className="primary" disabled={busy || !selected}>
                Run bounded check
              </button>
            </div>
          </form>
        </Dialog>
      )}
      {modal === "input" && (
        <Dialog
          notice={notice}
          title="Designated input endpoint"
          onClose={() => setModal(null)}
        >
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void run("input", {
                inputPath: new FormData(e.currentTarget).get("path"),
              });
            }}
          >
            <p className="muted">
              Sends a single inert text marker as the sentinel_probe query
              parameter. The endpoint must be in the runner INPUT_PATHS policy.
            </p>
            <label>
              Authorized path
              <input
                name="path"
                placeholder="/security-test"
                pattern="/[a-zA-Z0-9/_-]*"
                required
              />
            </label>
            <div className="dialog-actions">
              <button
                type="button"
                className="secondary"
                onClick={() => setModal(null)}
              >
                Cancel
              </button>
              <button className="primary" disabled={busy || !selected}>
                Run safe probe
              </button>
            </div>
          </form>
        </Dialog>
      )}
      {modal === "stop" && (
        <Dialog
          notice={notice}
          title={
            state.stopped
              ? "Resume security checks?"
              : "Activate emergency stop?"
          }
          onClose={() => setModal(null)}
        >
          <p className="muted">
            {state.stopped
              ? "This permits new checks again and resumes the configured runner."
              : "This cancels active work and blocks new scans. An in-flight runner request may take up to 24 seconds to expire if acknowledgement is unavailable."}
          </p>
          <div className="dialog-actions">
            <button className="secondary" onClick={() => setModal(null)}>
              Cancel
            </button>
            <button
              className="danger-button"
              disabled={busy}
              onClick={() => void emergency()}
            >
              {state.stopped ? "Resume" : "Stop all checks"}
            </button>
          </div>
        </Dialog>
      )}
      {modal === "delete" && (
        <Dialog
          notice={notice}
          title="Remove target?"
          onClose={() => setModal(null)}
        >
          <p className="muted">
            The registered target will be removed. Recorded assessments remain
            available in history.
          </p>
          <div className="dialog-actions">
            <button className="secondary" onClick={() => setModal(null)}>
              Keep target
            </button>
            <button
              className="danger-button"
              disabled={busy}
              onClick={() =>
                void action(async () => {
                  await api(`/targets/${deleteId}`, { method: "DELETE" });
                  await refresh();
                  setModal(null);
                  toast("Target removed.");
                })
              }
            >
              Remove target
            </button>
          </div>
        </Dialog>
      )}
      {view && (
        <Dialog
          notice={notice}
          title={
            modules.find((m) => m.id === view.test_id)?.name ||
            "Assessment result"
          }
          wide
          onClose={() => setView(null)}
        >
          <div className="result-meta">
            <Badge status={view.status} />
            <code>{view.id.slice(0, 8)}</code>
            <span>{time(view.started_at)}</span>
          </div>
          <p className="result-summary">
            {view.result?.summary ||
              "No completed result. Execution was interrupted or cancelled."}
          </p>
          {view.ended_at && (
            <p className="muted small">Ended {time(view.ended_at)}</p>
          )}
          {view.test_id === "xss" && view.result && (
            <div className="lab-demo">
              <div>
                <h3>Vulnerable local rendering</h3>
                <iframe
                  title="Isolated harmless script demonstration"
                  sandbox="allow-scripts"
                  srcDoc={labDocument}
                />
              </div>
              <div>
                <h3>Safely rendered as text</h3>
                <pre>{labPayload}</pre>
              </div>
              <p className="muted small">
                Fixed synthetic payload only. The script changes this frame’s
                text. Network, form and parent access are blocked.
              </p>
            </div>
          )}
          {view.result?.findings.map((f, i) => (
            <article className="finding" key={i}>
              <div>
                <h3>{f.title}</h3>
                <Badge status={f.severity.toUpperCase()} />
              </div>
              <code>{f.endpoint}</code>
              <dl>
                <dt>Evidence</dt>
                <dd>{f.evidence}</dd>
                <dt>Impact</dt>
                <dd>{f.impact}</dd>
                <dt>Remediation</dt>
                <dd>{f.remediation}</dd>
              </dl>
            </article>
          ))}
          {view.result && !view.result.findings.length && (
            <div className="modal-note">
              {view.status === "PASS"
                ? "No issues observed within this check’s stated scope."
                : "No findings were produced. Review the outcome and limitations above."}
            </div>
          )}
          <div className="dialog-actions">
            <button className="secondary" onClick={() => setView(null)}>
              Close results
            </button>
            <button
              className="primary"
              onClick={() => {
                setView(null);
                setPage("Reports");
              }}
            >
              <FileText size={15} />
              Open reports
            </button>
          </div>
        </Dialog>
      )}
      {notice && (
        <div
          className={`toast ${notice.error ? "toast-error" : ""}`}
          role={notice.error ? "alert" : "status"}
        >
          {notice.error ? <Activity size={18} /> : <CheckCircle2 size={18} />}
          <span>{notice.text}</span>
          <button
            className="icon-button"
            onClick={() => setNotice(null)}
            aria-label="Dismiss notification"
          >
            <X size={15} />
          </button>
        </div>
      )}
    </div>
  );
}
