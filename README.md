# Sentinel — authorized security workspace

A React/TypeScript/Tailwind dashboard on Cloudflare Pages, with authenticated Pages Functions, D1 persistence, and a separate Node.js runner for bounded network checks. No scans are simulated and no demonstration metrics are inserted. The workspace is **single operator**, using one server-side access token; it is not a multi-tenant service.

## Run locally

Requirements: Node.js **24 or newer**, npm, and a Chromium browser for the optional UI test. The runner uses Node's built-in SQLite for its isolated lab; it does not run inside Workers.

```bash
npm ci
cp .env.example .dev.vars
```

Edit `.dev.vars`: choose **two different random secrets of at least 32 characters** for `API_TOKEN` and `RUNNER_TOKEN`, set `ALLOWED_HOSTS` to exact public hostnames you are authorized to assess, and keep `DASHBOARD_ORIGIN=http://localhost:8788`. A password manager can generate the secrets. Never commit `.dev.vars`.

```bash
npm run db:local
npm run build
npm run runner       # terminal 1: loads .dev.vars, binds 127.0.0.1:8790
npm run pages:dev    # terminal 2
```

Open **http://localhost:8788**, select **Connect workspace**, and enter your configured `API_TOKEN`. Add a target and confirm ownership/authorization. Select that target in Security Tests and run Security Headers (or another check). Polling updates the history with the real backend outcome. Open Results for evidence, then Reports for filtered JSON or printable HTML. Start with the SQL or XSS lab if no real target is configured: both use explicitly synthetic content, never a live target.

For Vite hot reload, set `DASHBOARD_ORIGIN=http://localhost:5173`, restart Pages dev, and run `npm run dev`. Open localhost:5173; Vite proxies `/api` to localhost:8788. Use the **same exact origin**, including port, as configured on the backend. The token is held only in React memory; reloading the page requires reconnecting.

## What actually works

| Module            | Execution and limits                                                                                                                                                                                                                                                                                                                                                           |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| HTTPS / TLS       | Runner makes an HTTPS HEAD connection pinned to a validated public IP; Node verifies certificate hostname, trust chain and expiry. Reports negotiated protocol and certificate expiry. This is not cipher enumeration, revocation checking, a complete TLS grade, or plaintext redirect testing.                                                                               |
| Security headers  | Runner inspects a genuine HEAD response for CSP, HSTS, content type protection, Referrer-Policy and Permissions-Policy. Missing defenses are observations, not proof of exploitability. Only `nosniff` content is validated; other policy effectiveness needs manual review.                                                                                                   |
| DNS               | Runner retrieves A, AAAA, MX, NS, TXT and CAA records. Stores record counts, not TXT contents or DNS verification tokens. Informational inventory, not a DNS security grade.                                                                                                                                                                                                   |
| Cookie attributes | Runner checks Set-Cookie flags: Secure, HttpOnly, SameSite, plus SameSite=None without Secure. Cookie values/names are discarded. No cookies observed returns **NOT TESTED**, not PASS. No authenticated session crawl.                                                                                                                                                        |
| Safe input        | One GET with an inert `sentinel_probe` marker to a path listed in runner `INPUT_PATHS`. Reports reflection only, never claims XSS or validation safety. No script or SQL payload is sent.                                                                                                                                                                                      |
| XSS lab           | Backend prepares an explicit synthetic lab record. A fixed harmless script is injected into a deliberately vulnerable local document inside an opaque-origin sandbox. It changes only the frame's text. Exact CSP hash permits only that script; network, forms and parent access are blocked. Safe rendering displays the same payload as text. No live website is contacted. |
| SQL lab           | Runner creates a disposable in-memory SQLite database with three synthetic products. Executes a fixed concatenated-query example and a bound-parameter version. No external database or arbitrary SQL input.                                                                                                                                                                   |
| Port exposure     | Dedicated runner attempts one TCP connection per explicitly configured port. `ALLOWED_PORTS` must be a subset of 80,443,8080,8443, max 4 entries. Empty policy returns **NOT TESTED**. A timeout does not prove a port closed.                                                                                                                                                 |
| Bounded load      | Explicit extra confirmation; request cap 1–5, concurrency 1, 1-second intervals, 5-second per-request timeout, 24-second overall job deadline. HEAD only. Reports actual timings and status codes. Not a capacity or denial-of-service test.                                                                                                                                   |
| Reports           | Authenticated JSON and standalone escaped HTML downloads, status/severity filtering, all outcomes and timestamps. Open downloaded HTML and print to PDF if desired. Exports at most the 100 latest records; repeated findings are not deduplicated.                                                                                                                            |

Live network modules and the SQL lab require the supplied runner to be configured and reachable. Missing dependencies produce **ERROR** records. Port and input policies are explicitly disabled until configured. No third-party scanner account is required for the included runner. Arbitrary scanners, remote shell commands, credentials, browser crawling, and destructive modules are not implemented.

## Architecture

- `src/`: dashboard, forms, keyboard-accessible dialogs, polling, reports and results.
- `shared/`: test registry, typed API/result models, public-address and URL validation.
- `functions/api/[[path]].ts`: Cloudflare Pages route adapter.
- `server/`: authentication, bounded JSON parsing, API routes and report rendering.
- `runner/`: authenticated execution service, pinned network transport and test modules.
- `migrations/`: D1 schema, global execution lock and stop state.
- `tests/`: authorization/validation/result tests, Workers-runtime API tests, module tests and browser acceptance checks.

Pages never fetches a user-supplied URL. Only the server-configured runner origin is contacted. The runner independently enforces exact hostname policy, checks **every resolved address**, pins HTTP(S) lookup to a validated address, preserves TLS hostname verification, does not use an ambient HTTP proxy, rejects all redirects, and re-resolves before subsequent connections. IP literals, unsafe schemes, credentials, query strings, nonstandard ports and reserved/internal names are rejected. A response is bounded to 64 KiB; target HTML is never stored or returned. HTTP metadata headers are bounded by Node's parser limits.

D1 is required; there is no silent in-memory fallback. A unique partial index allows **one RUNNING scan globally**, and an atomic insert enforces **30 scan attempts per rolling hour** and the emergency stop. Targets are capped at 100. State and reports return at most 100 records. The runner also allows one active job, with independent deadlines. Retain or delete old assessment and audit records according to your own policy; automatic retention and pagination are not implemented.

All testing, target, report, state and control endpoints require the same single-operator bearer token. Resource identifiers do not bypass authentication. Requests with a foreign Origin are rejected; writes require an exact `DASHBOARD_ORIGIN`. No cross-origin access headers or authentication cookies are used. Sensitive secrets must be sent over HTTPS in production. Hosting static assets is public; if the dashboard shell itself needs identity protection, place the Pages project behind Cloudflare Access in addition to the API token.

The state endpoint reports **configured** runner credentials, not verified runner health. A target is **authorized**, not proven reachable, until a check executes. Progress is honest coarse state: RUNNING → final result; no invented percentage or execution stages. The UI polls every 2.5 seconds. Cancelled results cannot be overwritten by a late completion. Interrupted jobs expire to ERROR after 60 seconds when the next authenticated request reconciles state. There is no background retry scheduler.

## Emergency stop and cancellation

History's Cancel stops a scan, records cancellation, and sends the job ID to the runner's abort endpoint. Global emergency stop records the stop in D1, cancels active records, aborts runner jobs and blocks new work. Resume is explicit. If the runner is unreachable, a warning is displayed; in-flight operations still have a 24-second deadline. Cancellation cannot recall packets already sent. Do not resume until you have checked an unacknowledged runner stop.

## Environment variables

| Name               | Where                          | Purpose                                                                                                                                       |
| ------------------ | ------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `API_TOKEN`        | Pages secret                   | Single-operator token, at least 32 random characters. Never a `VITE_` variable.                                                               |
| `DASHBOARD_ORIGIN` | Pages                          | Exact deployed origin, e.g. `https://security.example.com`. Only one origin.                                                                  |
| `ALLOWED_HOSTS`    | Pages and runner               | Comma-separated exact public DNS hostnames, no schemes/ports/wildcards. Configure the same scope on both services.                            |
| `RUNNER_URL`       | Pages                          | Dedicated runner root URL. HTTPS required except literal localhost/127.0.0.1 for local development.                                           |
| `RUNNER_TOKEN`     | Pages secret and runner secret | Independent service authentication token, at least 32 random characters.                                                                      |
| `RUNNER_HOST`      | Runner                         | Default `127.0.0.1`. Use a controlled interface behind an HTTPS reverse proxy in production.                                                  |
| `RUNNER_PORT`      | Runner                         | Default `8790`.                                                                                                                               |
| `INPUT_PATHS`      | Runner                         | Exact comma-separated designated paths, e.g. `/security-test`. Empty disables input testing. Alphanumeric, slash, underscore and hyphen only. |
| `ALLOWED_PORTS`    | Runner                         | Explicit permitted subset of 80,443,8080,8443. Empty disables TCP testing.                                                                    |
| `DB`               | Pages D1 binding               | Required persistent database; not a string environment variable.                                                                              |

The runner is a single process per workspace. Do not run independent replicas against one workspace unless you add a shared concurrency/cancellation coordinator. Restrict its inbound network to your service infrastructure and outbound network to public target destinations as defense in depth. Node process memory coordinates active cancellation; a process restart stops its sockets, but global stop state in the API remains persistent.

## Deploy to Cloudflare Pages

1. Create a D1 database and replace the placeholder database ID in `wrangler.jsonc`:

   ```bash
   npx wrangler d1 create sentinel
   npx wrangler d1 migrations apply sentinel --remote
   ```

2. Deploy `runner/` on a Node 24+ VM/container you control. Install project dependencies and run `npm run runner` with the environment variables above. Put it behind HTTPS; do not expose the default plaintext loopback listener publicly. Configure the independent runner allowlist and optional input/port policies. No native scanning binaries are needed.
3. In Cloudflare Pages, connect this repository and choose **build command `npm run build`**, **output directory `dist`**. Functions are automatically built from `functions/` by Pages. Bind D1 as `DB`. Set the environment variables and encrypted secrets above in the Pages project, for both production and preview environments as needed. Use separate test credentials/databases for preview. Set the exact final `DASHBOARD_ORIGIN` and redeploy after changes.
4. Optionally deploy directly with `npx wrangler pages deploy dist --project-name sentinel-control`. Create/configure the Pages project first. Keep `functions/` alongside the output in the project root; plain static file upload alone does not provide the API.
5. Verify `GET /api/health`, connect with your operator token, register an allowed authorized target, execute a passive check, inspect its final result and export a report. Health proves API routing, not runner reachability or target safety.
6. Enable Pages Functions logs in the Cloudflare dashboard for operational visibility. Persistent audit events are recorded in D1. Never enable raw request/response logging with credentials or cookie content.

No deployment or live-target assessment is performed automatically by installation.

Cloudflare references: [Pages Functions bindings](https://developers.cloudflare.com/pages/functions/bindings/), [D1 prepared statements](https://developers.cloudflare.com/d1/worker-api/prepared-statements/), [Pages configuration](https://developers.cloudflare.com/pages/functions/wrangler-configuration/).

## API contracts

All except health require `Authorization: Bearer <API_TOKEN>`. Mutation requests must include `Origin: <DASHBOARD_ORIGIN>` and JSON bodies where applicable. JSON request bodies are capped at 8 KiB.

| Route                                                                   | Contract                                                                                                                                                      |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /api/health`                                                       | `{ok, service, configured}`; no secrets                                                                                                                       |
| `GET /api/state`                                                        | `{targets, scans, events, stopped, runnerConfigured, allowedHosts}`                                                                                           |
| `POST /api/targets`                                                     | `{url, authorized:true}` → `201 {id}`                                                                                                                         |
| `DELETE /api/targets/:id`                                               | Removes target; preserves history; active target checks must be cancelled first                                                                               |
| `POST /api/scans`                                                       | `{testId,targetId?,count?,confirmLoad?,inputPath?,labCase?}` → `202 {id}`. Target required except labs. Load confirmation/count and input path are validated. |
| `POST /api/scans/:id/cancel`                                            | `{ok,warning?}`                                                                                                                                               |
| `POST /api/stop`, `POST /api/resume`                                    | Global execution controls → `{ok,warning?}`                                                                                                                   |
| `GET /api/reports?format=json\|html&status=...&severity=...&scanId=...` | Authenticated downloadable report                                                                                                                             |

`Scan` has `id`, `target_id`, `test_id`, `status`, `started_at`, `ended_at`, `progress` (only 0/100), and nullable `result`. `Result` includes `testId`, `status`, `startedAt`, `endedAt`, `summary`, `findings`. Each finding includes `severity`, `title`, `endpoint`, `evidence`, `impact`, `remediation`. Outcomes distinguish PASS, FAIL, WARNING, ERROR, NOT TESTED, RUNNING and CANCELLED. Non-success HTTP responses use `{error:string}`. Internal diagnostics, IP addresses, raw response bodies and secrets are not returned.

The private runner exposes authenticated `GET /health` and `POST /run`, `/cancel`, `/stop`, `/resume`. `/run` uses `{id,testId,url?,count?,inputPath?,labCase?}` and returns a typed `Result`. Only use the API as its caller in production.

## Verification

```bash
npm test
npm run build
npx wrangler pages functions build --outdir .wrangler/functions-build
npm run test:ui
npm audit
```

Tests use explicitly synthetic targets and response fixtures; they do not scan an arbitrary public website. API tests run in Miniflare's real Workers runtime with D1. UI tests use the production build, a real local Pages-compatible API runtime and the supplied runner's synthetic lab. They cover authentication, target registration, actual lab execution, history, exports, emergency stop and small-screen dialog behavior. No live target results are claimed from fixtures. Remote Cloudflare deployment and your configured target's behavior still require validation in your account.

The phone interface uses labeled bottom navigation, a full-width workspace, stacked scan records, larger text and touch controls, and scrollable dialogs that fit the dynamic viewport. Browser acceptance checks exercise all six pages at 320, 360, 390, 412, 768 and 844 pixels, including landscape and synthesized touch input in Chromium. Physical Android hardware and its on-screen keyboard are not covered by this automated check.
