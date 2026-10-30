# ScopeLens — MVP (Phase 1) Build Plan

**Owner:** Aditya Pratap Singh
**Version:** MVP-2.1 · 24 September 2026
**Audience:** the coding agent that builds the software. Follow this document in order.
**Companions (authoritative, do not contradict):** `ScopeLens_Project_Specification.md` (product behaviour, scoring, proof rules) and `ScopeLens_Implementation_Plan.md` (architecture, milestones, sources). This file is the **concrete build sequence** for Phase 1. It does not remove features from those docs — it turns them into ordered, testable tasks.

**Revision MVP-2.1:** preserves the Phase 1 feature scope and section structure while correcting scanner-alert handling, generated-code isolation timing, lab scope registration, milestone dependencies, the M5 benchmark gate and overall-score eligibility. Replace MVP-2.0 with this file; keep the two companion documents authoritative.

---

## 0. Rules for the coding agent (read first)

1. **Build the whole Phase 1 engine, not a slice of it.** Phase 1 = the operator-only, external-unauthenticated, *interactive + adaptive* scanner defined in Spec §15 Phase 1 and Plan M0–M5. It includes the browser, the agent loop, the tool adapters, evidence, verification, scoring and reporting. Do not drop any of these.
2. Do tasks **in milestone order** (§9). A milestone's "Exit gate" must pass before the next one starts. Within a milestone, files can be built in any order.
3. Never fabricate results. A check that did not truly run is `error`/`not_tested`/`blocked`, never `pass`. A finding is `confirmed` only when its registered proof rule is satisfied against a **trusted** artifact (Spec §8.3, §12).
4. **Scope enforcement and worker isolation are not optional and are not "validation we skip for MVP."** They are the safety boundary. The "no extra validation for MVP" instruction applies to *product-authorization UX* (self-service ownership proof), not to scope/egress/isolation controls. Keep those.
5. Keep provider/model selection **configurable** (Spec §14.1). No model name hardcoded in a node.
6. Every task ends with `make test` green for the implemented work, with relevant boundary/recovery/injection tests (§8) included. Missing future capabilities remain explicitly unimplemented, never replaced with passing stubs. The full Phase 1 suites and benchmark gate are required by M5.
7. No secrets in code, logs, or model prompts. Redact before storage and before any LLM call.
8. If a decision is genuinely undefined here, write it in `docs/OPEN_QUESTIONS.md` and pick the simplest option that satisfies the spec; do not stall.
9. **Frontend ownership split (operator decision, 2026-09-25).** The coding agent owns everything *except* the dashboard UI: backend, workers, broker, labs, tests, deploy, docs. **Do not create or edit anything under `frontend/`** — the dashboard (§5.17, F-17) is built separately and reviewed against your API. Your side of the boundary is the **contract**: every endpoint the dashboard needs (§5.17 list) must exist, be typed in `/openapi.json`, have tests, and each SSE event type must be documented in `docs/API_CONTRACT.md` (event name, fields, cursor, redaction guarantees) with an example payload. A dashboard feature whose endpoint is missing is a backend gap, and is yours. If `make lint` touches `frontend/`, leave its typecheck in place but do not change frontend source to make it pass — report it instead.

**Out of scope for Phase 1 (later milestones — do not build now):** authenticated / logged-in scanning, multi-role/tenant authorization tests, GraphQL abuse, request smuggling, hosted browser providers, self-service signup/billing, scheduled monitoring, source/cloud integrations. These are M6/M7 in the Plan. Everything else in the Plan up to M5 is in Phase 1.

---

## 1. What Phase 1 delivers

**One sentence:** an operator registers a URL they own, starts a scan, and the engine crawls + interactively explores the site, runs configuration/exposure checks and a reviewed conditional active pack, adaptively follows up on what it observes, verifies findings against proof rules, and produces a plain-English HTML + JSON report with per-category pilot scores and honest coverage.

**High-level flow (one scan):**

```
Operator registers scope (origin + allowed paths) → starts scan
  → durable Scan + Task ledger created (Postgres), dispatched via Celery
  → LangGraph coordinator runs, all target traffic through the policy broker:
       recon        – crawl (HTTP) + browser exploration (Playwright), build attack-surface map
       plan         – freeze baseline plan (which checks apply to which endpoints)
       execute      – deterministic config checks + ZAP/Nuclei/testssl adapters + conditional active pack
       adapt        – planner proposes bounded follow-ups on observations (≤3 rounds/hypothesis)
       verify       – proof rules run against trusted evidence; confirm / potential / inconclusive
       score        – deterministic scoring + coverage (Spec §9)
       report       – LLM (or template) plain-English write-up; HTML + JSON
  → status completed / completed_partial / cancelled / failed
  → dashboard shows live progress (redacted SSE) then the report
```

**Profile shown in report:** `External configuration + conditional active assessment`. If the operator disables the conditional active pack, the report is named `External configuration assessment` (Spec §10.3) and cannot show an injection/XSS score.

---

## 2. Feature inventory (everything Phase 1 must contain)

Each row is a required subsystem. The "Where" column points at the milestone that builds it and the section with its contract.

| # | Feature | Where |
|---|---|---|
| F-1 | Operator auth (single operator, session cookie), scope registration + allowlist | M0 · §5.1, §6.1 |
| F-2 | Durable scan/task ledger, transactional outbox, Celery dispatch, leases/fencing, reconciler | M1 · §5.2 |
| F-3 | Policy & execution broker: HTTP-aware egress enforcement, scope/redirect/DNS checks, budgets | M1 · §5.3 |
| F-4 | Worker supervisor + isolated workers (Kali-based tool worker, Chromium worker) | M1 foundation; M4 stronger boundary before generated code; M5 deployment validation · §5.4 |
| F-5 | Trusted evidence intake, redaction, object storage, provenance/hash | M1 · §5.5 |
| F-6 | Cancellation + crash recovery (revoke egress, stop process group, mark outcome_unknown) | M1 · §5.6 |
| F-7 | HTTP crawler + recon (endpoints, forms, params, cookies, headers, robots/sitemap) | M2 basic HTTP; M3 browser enrichment · §5.7 |
| F-8 | Deterministic config/exposure checks (TLS, headers, cookies, files, errors, components) | M2 · §5.8 |
| F-9 | Scanner adapters: ZAP Automation Framework, selected Nuclei templates, testssl.sh | M3 · §5.9 |
| F-10 | Interactive browser exploration (Playwright): DOM/a11y actions, SPA routes, network capture | M3 · §5.10 |
| F-11 | LangGraph coordinator + specialist roles + baseline/adaptive ledgers | M4 · §5.11 |
| F-12 | Bounded Bash + governed custom-script path (analysis-local; networked → lab only) | M4 · §5.12 |
| F-13 | Conditional active pack (reflected XSS marker, SQLi behavioural, HTML injection, open redirect, CORS) | M3/M4 · §5.13 |
| F-14 | Evidence verifier + registered proof rules (confirm / potential / inconclusive) | M2→M4 · §5.14 |
| F-15 | Deterministic scoring + coverage + eligibility (Spec §9), versioned `score-v1.0` | M2 · §5.15 |
| F-16 | Report writer (provider-flexible LLM, template fallback), HTML + JSON, redaction/escaping | M2→M5 · §5.16 |
| F-17 | React/TypeScript dashboard: scope intake, live progress (SSE), findings, coverage, scores, export | M2→M5 · §5.17 |
| F-18 | Provider-flexible model adapter (OpenAI / OpenRouter / open endpoint), capability + fallback | M3 browser/vision foundation; M4 full role routing/contracts · §5.18 |
| F-19 | Check registry + release manifest (pinned versions, per-check proof/fixtures/limits) | M0→M5 · §5.19 |
| F-20 | Optional MCP boundary + reviewed Agent Skills loader (off by default, curated) | M4 · §5.20 |
| F-21 | Owned lab fixtures (Juice Shop + vulnerable/fixed pairs), seed/reset, isolation | M0 · §7 |
| F-22 | Audit log of every actor/decision/tool/version/outcome | all · §6.3 |

Nothing here is deferred inside Phase 1. Depth limits (bounded crawl, ≤3 adaptive rounds, conditional pack gated per-check) are *limits on how far a feature runs*, not reasons to omit it.

---

## 3. Technology stack (use exactly this unless §0.8 applies)

| Layer | Choice | Notes |
|---|---|---|
| Language | Python 3.12 (backend), TypeScript (dashboard) | |
| API | FastAPI + Uvicorn | async intake, SSE progress |
| Orchestration | LangGraph | baseline + adaptive nodes; deterministic scheduling around it |
| Model access | small internal adapter over `openai` SDK (any OpenAI-compatible `base_url`) | covers OpenAI, OpenRouter, self-hosted; §5.18 |
| Dispatch | Redis + Celery | delivery only; Postgres owns truth |
| Durable store | PostgreSQL 16 + SQLAlchemy 2 + Alembic | ledger, outbox, leases, findings, scores |
| Evidence store | MinIO (S3-compatible) or local disk behind an S3 client | encrypted at rest, per-scan prefix |
| Browser | Playwright (Python) + Chromium, in its own worker image | §5.10 |
| Tool worker | custom Kali-based image (pinned digest) with ZAP CLI, Nuclei, testssl.sh | §5.4, §5.9 |
| HTTP/parse | `httpx`, `beautifulsoup4` | crawler + broker client |
| Proxy/egress | mandatory forward proxy (mitmproxy in scripting mode) enforcing scope | §5.3 |
| Dashboard | React + Vite + TypeScript, plain fetch/EventSource | functional, not polished |
| Tests | `pytest`, Playwright test utils | |
| Local dev | Docker Compose (api, worker, browser-worker, postgres, redis, minio, proxy, labs) | Compose is dev convenience, not the isolation proof |

Pin every image by digest in the release manifest (§5.19). Do not use floating `:latest` in measured runs.

---

## 4. Repository layout

```
scopelens/
  docs/                     # the three .md docs + OPEN_QUESTIONS.md + MILESTONES.md
  backend/scopelens/
    api/          # FastAPI routers: auth, scopes, scans, events(SSE), findings, report
    domain/       # Pydantic records: Scope, Scan, Task, Hypothesis, CheckResult, Finding, ScoreSnapshot
    orchestration/# LangGraph graph, nodes, specialist roles, baseline + hypothesis ledgers
    execution/    # policy broker, admission, budget reservation, worker supervisor client
    broker/       # egress proxy config + HTTP-aware scope validator
    adapters/     # model adapter; scanner adapters (zap, nuclei, testssl); mcp (optional)
    browser/      # Playwright session controller, action set, evidence capture
    checks/       # deterministic check functions + conditional active pack + registry
    evidence/     # trusted intake, redaction, object-store client, provenance/hash
    verification/ # proof rules, false-positive challenge, potential/inconclusive logic
    scoring/      # deterministic score, coverage, eligibility, caps (score-v1.0)
    persistence/  # SQLAlchemy models, migrations, outbox, leases, reconciler
    writer/       # report text (LLM/template), HTML render, JSON dump, escaping/redaction
    config.py
  frontend/                 # React/TS dashboard
  workers/                  # Dockerfiles for kali-tool worker + browser worker + supervisor
  checks_registry/          # YAML registry entries + profiles + pinned template/config bundles
  skills/                   # reviewed Agent Skills packs (curated, versioned)
  labs/                     # docker-compose for Juice Shop + vulnerable/fixed fixtures, seed/reset scripts
  evaluation/               # M0 manifest/labels; M4 baseline-vs-adaptive runner; M5 held-out harness + report
  tests/                    # unit, contract, integration, browser, recovery, containment, injection
  deploy/                   # docker-compose.dev.yml, .env.example
  Makefile                  # install, run, test, lint, labs-up/down, e2e, manifest
  README.md
```

---

## 5. Subsystem contracts

Only the non-obvious contracts are spelled out. Follow the referenced spec sections for behaviour rules.

### 5.1 Operator auth & scope (F-1)
- Single operator. Login = username + password (bcrypt) from env-seeded account → signed session cookie (`itsdangerous` or FastAPI session). No signup UI.
- **ScopeVersion** (immutable once a scan uses it): scheme, host, port, allowed path prefixes, excluded paths, allowed methods (default `GET`,`HEAD`), allowed check profile, authorization expiry (datetime), owner note, budgets override (optional), and authority domain (`production` or operator-controlled `lab`). In the production profile, reject private/link-local/metadata destinations; raw IPs require explicit authorization, not merely a typed address (Spec §6, §12).
- **Lab scope registration:** only the trusted operator can register a lab service from a fixed deployment allowlist of service identities, approved addresses and ports. Named lab services may resolve to their explicitly approved private container/VM addresses. This does not allow arbitrary private networks, host/control-plane services or cloud metadata. Bind the lab profile to its isolated execution environment; a URL or ordinary scan parameter cannot turn a production scan into a lab scan. Revalidate the binding and destination on every connection.
- Every API call and evidence read is checked against the operator/owner server-side.

### 5.2 Durable ledger & dispatch (F-2)
- `create_scan` writes Scan + initial Task + outbox event **in one transaction**. A dispatcher polls the outbox and enqueues to Celery; unsent rows are reconciled on startup.
- Task has `logical_id`, `attempt_id`, `state` ∈ {planned, admitted, running, succeeded, failed, outcome_unknown}, `lease_token` (fencing int), `reserved_budget`. Executors reject stale fencing tokens.
- Coordinator holds one renewable DB lease per scan. Lease loss ⇒ old run's egress capability revoked before replacement admitted (§5.3, §5.6).
- Treat Celery delivery as at-least-once; idempotency key = (scan_id, logical_id, attempt intent).

### 5.3 Policy & execution broker (F-3) — the scope boundary
- **All** target traffic (crawler, scanner, browser, Bash) goes through a mandatory forward proxy; workers have **no** direct egress (network policy denies it). The broker validates, per request: host==scope host, port allowed, path prefix allowed, method allowed, request/time/response-size budget not exceeded. Revalidate on every redirect and browser subrequest.
- Block: IP literals not in scope, IPv6 tricks, alternate DNS, UDP/QUIC/WebRTC, DNS rebinding (re-resolve + pin), cross-origin subresources (report the coverage gap instead).
- Separate **TLS measurement lane**: a constrained path that reads the *real* upstream certificate/protocol without the intercepting proxy altering it (Spec §17.3). Used only by TLS checks.
- Budgets (Spec §12 starting values, tunable in scope): 2 req/s, 2 in-flight, 300-page cap, depth 4, 5000 total requests, 45-min wall clock, 10-s timeout, 1 MiB body cap. Count redirects/retries. WebSocket connection/message budgets tracked separately.
- Lab traffic uses the same broker, budgets, redirect validation and connection checks. Its only private-address exception is an exact registered lab service/address/port binding (§5.1); it is never a blanket private-network allowlist. Production workers cannot use lab capabilities.
- Fail closed: if enforcement can't be maintained, deny.

### 5.4 Supervisor & isolated workers (F-4)
- A trusted supervisor process (outside untrusted workers) owns run identity, starts/stops process groups, and collects evidence. Workers get **no** DB creds, no control-plane access, no Docker socket, no host mounts, per-scan scratch only.
- Two worker images: `kali-tool` (ZAP CLI, Nuclei, testssl.sh, curl, bash — pinned) and `browser` (Playwright + Chromium). For initial owned-lab runs of reviewed tooling, containers with enforced network/resource isolation are the development baseline. **Before enabling any generated Python/Bash in M4, establish and test a dedicated worker VM or equivalently evaluated stronger boundary** (Plan §8.1), including for scripts that only process local artifacts. A private Docker network alone does not satisfy this gate. Keep the stronger boundary for customer/owned-production execution and validate it on the final deployment in M5; do not defer its first implementation until M5.
- Generated code receives only its permitted per-run artifacts and output location, never host credentials, control-plane access or other scans' data. Local-analysis scripts have no target-network capability; networked scripts require the separately approved lab/staging profile. Missing isolation keeps script execution disabled and leaves M4 incomplete.

### 5.5 Trusted evidence (F-5)
- Only the supervisor/broker/browser-controller may write Evidence. A generated script's stdout is an *untrusted observation*, stored as such.
- Evidence = {run_id, task_id, tool/script hash, timestamp, scope+role, capped content ref (≤1 MiB), integrity hash, redaction_state}. Raw observations stored separately from interpretations. Redact secrets/PII before any model or customer access.

### 5.6 Cancellation & recovery (F-6)
- Cancel: set durable epoch → revoke new admissions + ongoing egress capability (proxy drops the scan's tokens) within 5 s target → supervisor stops the worker process group / browser within 30 s → keep partial evidence + report. Measure these (don't assert them). Never use Celery worker revocation as the mechanism.
- Recovery: on restart, reconcile live run handles + evidence before any retry. A request whose outcome was lost ⇒ `outcome_unknown`, no blind retry of side-effecting work. Spent budgets persist.

### 5.7 Crawler & recon (F-7)
- Same-origin BFS crawl within scope: extract endpoints, forms, input fields, query params, cookies, headers. Fetch robots.txt, sitemap.xml, and a small well-known-files wordlist (list as inventory; don't fetch disallowed-only paths as attacks). Fingerprint server/framework/JS libs (passive header + body signatures).
- Output: **AttackSurfaceMap** {hosts (inventory-only for non-primary), endpoints, params, forms, tech, classification (SPA? REST? has OpenAPI/GraphQL endpoint?)}. This feeds planning.

### 5.8 Deterministic checks (F-8)
Config/exposure checks are pure functions over collected data + broker/TLS-lane results. Minimum Phase 1 set (each becomes ≥1 registry entry with proof rule + fixtures):
TLS cert validity/expiry/protocol, HTTP→HTTPS redirect, HSTS, mixed content, cookie Secure/HttpOnly/SameSite/scope, CSP effective policy, frame protection (CSP frame-ancestors OR X-Frame-Options — count once), X-Content-Type-Options, Referrer-Policy, verbose errors/stack traces, directory listing, exposed sensitive files (bounded, capped, redacted excerpt — no bulk download/repo reconstruction), client-side secret candidates (classify public vs private; never authenticate with them), component/CVE *candidates* (corroborate version — never confirm from a banner alone), HTTP method exposure (advertised ≠ flaw), same-origin API inventory. Follow Spec §10.5 family stances (OBSERVE/ACTIVE/FLAG) exactly.

### 5.9 Scanner adapters (F-9)
- **ZAP**: Automation Framework / API, passive + reviewed rules only in Phase 1 production profile; run in the kali-tool worker, output JSON, normalise alerts → CheckResult. Map plugin IDs through the reviewed control/category registry. **Unmapped alerts remain unscored and awaiting classification**, with their original reported severity, confidence, tool/plugin identity and evidence preserved; never automatically downgrade them to C05/Informational. Tool-reported severity remains distinct from verified product severity. Evidence-supported unresolved Potential High/Critical candidates, including unmapped alerts, trigger overall `Verification pending` (Spec §9.6).
- **Duplicate handling:** merge matching observations into the same finding/root-cause group while retaining every source tool, plugin/template version, evidence reference and affected location. Do not discard duplicate source records. Similar wording alone is insufficient to merge findings. These normalization and provenance rules also apply to Nuclei and other adapters.
- **Nuclei**: pinned engine + a **reviewed subset** of templates (pin the full bundle + template IDs; do not run the whole community set). Results are candidates → verifier decides.
- **testssl.sh**: constrained adapter for the TLS lane where it adds coverage.
- Every adapter has parser fixtures for valid/malformed/empty/truncated/nonzero-exit/timeout/cancel.

### 5.10 Browser exploration (F-10)
- Playwright session = explicit resource: {scan, role, browser id, page/frame ids, scope revision, expiry, controller lease}. **One action owner per context**; never two controllers on one tab. Distinct identities ⇒ distinct contexts.
- Actions (DOM/accessibility first, screenshot+coordinate fallback only when a vision model is configured): observe, navigate, click, type, submit — each checked by the broker for *intent*, not just HTTP method (a click can be a purchase; block logout/delete/pay/email/SMS per Spec §12). Bound depth/state count/action count; detect navigation loops.
- Capture before/after state signature, route, frame, screenshot+DOM refs, and resulting network events as evidence. Downloads stored as untrusted, capped, never executed. Keep browser security protections on. Recreate expired sessions only via known safe navigation — never blind-replay form submissions.

### 5.11 Coordinator & specialist roles (F-11)
- LangGraph nodes: baseline-plan → recon/browse → observe/hypothesise → select bounded task → policy-admit → execute → capture evidence → verify → coverage check → (loop or) score+report. Deterministic scheduling owns budget split; **protect the baseline budget** before adaptive follow-ups.
- Two ledgers: mandatory profile coverage + adaptive hypotheses. Each hypothesis: observed signal, alternative explanation, missing proof, proposed next action, expected evidence, canonical control id, stop condition. ≤3 follow-up rounds/hypothesis; no repeated identical op without new evidence.
- Specialist roles (may share process/model): browser specialist, web/API specialist, config/component specialist, verifier, report writer, deterministic scoring/coverage service. Roles never independently drive one browser context. The LLM proposes; the broker + deterministic policy enforce.

### 5.12 Bash & custom scripts (F-12)
- **Typed functions**: the normal path. **Bash**: adapt installed-tool flags, inspect help, process local artifacts, compose *reviewed* commands inside the worker; every invocation has a task/run record + budgets + artifact caps. Networked Bash in production = reviewed checks with permitted parameter ranges only.
- **Custom generated Python/Bash**: may analyse *local* artifacts automatically only after the stronger isolation gate in §5.4 passes; anything *networked* runs only in the lab/staging profile in Phase 1 under the same stronger boundary. Record script content hash + interpreter/tool versions. No runtime install from arbitrary repos; missing capability → integration request. Generated stdout is untrusted and cannot set `confirmed`.

### 5.13 Conditional active pack (F-13)
Enabled per-check only where a reviewed non-destructive method exists and the endpoint is approved (Spec §10.3, §10.5). Phase 1 pack: reflected XSS (harmless execution marker in the scanner-owned browser — reflection alone ≠ confirmation), SQLi (repeated non-timing behavioural comparison with negative controls; no data extraction/login bypass), HTML injection (harmless render change in own page), open redirect (inspect redirect to a controlled destination; never follow into an unapproved origin), CORS (header behaviour = config; protected-data exposure needs authorized identity → out of Phase 1). Excluded from default production: stored writes, login guessing, command exec, timing probes, real-file traversal, resource claiming, shared-cache mutation, request desync. Those stay FLAG/FIXTURE.

### 5.14 Verifier & proof rules (F-14)
- Each control has a **registered proof rule** evaluated against **trusted** evidence. Signals insufficient on their own: a screenshot, a scanner match, a process exit, a model saying "confirmed", a script printing `confirmed=true`. Use negative controls, baseline comparison, reproducibility.
- Outcomes: `confirmed` / `potential` / `inconclusive`, plus confidence (High/Med/Low + reasons) and severity — three separate dimensions (Spec §8.4). A second LLM may *challenge* but not *confirm*. Any unresolved Potential High/Critical → overall `Verification pending` (Spec §9.6).

### 5.15 Scoring & coverage (F-15) — deterministic, `score-v1.0`
Implement Spec §9.5–§9.10 exactly:
- Deductions per distinct root cause: Critical 65 / High 35 / Medium 15 / Low 3 / Info 0. Category raw = max(0, 100 − Σ). Caps: any Critical ⇒ ≤39, any High ⇒ ≤69 (category and overall). Only after every applicable profile category qualifies: overall = weighted mean of its category scores (fixed weights, evidence-backed fully N/A categories removed + renormalised), then caps, round only for display.
- Coverage = 100 × fully-assessed applicable control weight / total applicable weight. Category numeric score needs ≥80% coverage + all mandatory controls assessed + no unresolved Potential High/Critical. Else `Insufficient coverage` / `Verification pending`. Missing creds / WAF block / tool error / exhausted budget are **never** pass or N/A.
- **Overall eligibility:** every applicable category in the selected profile must meet its coverage, mandatory-control and verification gates. Never omit a blocked, failed, unsupported or insufficiently assessed category to improve the average. Only evidence-backed fully N/A categories can be removed. If none are applicable, show `Not scored`. An interrupted/cancelled scan cannot publish a completed overall rating.
- Any unresolved Potential High/Critical candidate on the assessed target, including unmapped/experimental checks, sets the overall score to `Verification pending`. Confirmed unresolved High/Critical findings apply global caps even if their category is outside the numeric profile (Spec §9.6). Keep severity warnings visible when no number is eligible.
- Field/check drill-down requires all its planned instances to be conclusive; apply Spec §9.7. Category eligibility must not automatically mark every field as assessed.
- Deduplicate by canonical control/root cause + affected component + remediation boundary; equivalent controls counted once; retain all affected locations and source evidence. Unresolved candidates stay visible.
- Category weights: C01 15, C02 15, C03 20, C04 15, C05 15, C06 10, C07 10; C08–C12 shown `Not assessed in this profile`. Overall labelled **External … pilot assessment score — uncalibrated. Not a whole-website security rating.**
- Scoring is pure deterministic Python. Unit tests reproduce every worked example in Spec §9.6 and §9.9.

### 5.16 Report writer (F-16)
- Text fields (title/what/why/fix/references) come from a static template per control **always**; if a model is configured, it may *rephrase* into plainer English given only (control id, severity, redacted evidence) and return JSON with the same keys, validated by Pydantic — on any error/timeout/invalid JSON, use the template. The model can never change severity, control, locations, coverage or scores.
- Render HTML with Jinja2/React `autoescape` on; never `|safe`/`dangerouslySetInnerHTML` on target- or model-derived text. Redact in both HTML and JSON (including hidden fields). Empty state = "No issues found in the checks that completed" + coverage, never "secure". No weaponized payloads in any output.

### 5.17 Dashboard (F-17)
React/TS: scope registration form, scan list + start/cancel, live progress via `EventSource` on the SSE endpoint (redacted events with a monotonic cursor for reconnect — never raw graph state / stdout / secrets), scan summary + attack-surface overview, findings list (filter by severity/confidence) + detail, all 12 category tiles with score-or-reason + coverage, host inventory (tested vs inventory-only), HTML + JSON export buttons, partial/blocked banners.

### 5.18 Model adapter (F-18)
- Config per role (planner, browser interpreter, verification assistant, report writer): base_url, api_key ref, model id, capability manifest (tools/schema/vision/context/streaming), timeouts, token caps, per-scan cost ceiling + hard call-count cap. Record unknown cost as unknown, never 0.
- Validate tool args in app code. Fallback uses a provider/data-policy allowlist + remaining budget + capability check; never send customer evidence to an unapproved provider. A provider change grants no new tools and cannot replay a target action. Contract tests: tool ids/order, strict schema, context overflow, refusal, malformed JSON, rate limit, streaming interrupt, cancel, timeout, missing usage, fallback.

### 5.19 Check registry & manifest (F-19)
- Each executable check = a registry entry (YAML in `checks_registry/`) with the Spec §10.3 fields: stable id, canonical control/root-cause, category, standard mapping, phase/profile, applicability, prerequisites, allowed tool/config version, mandatory flag + coverage weight, allowed destinations/methods/budgets, side-effect expectation, cleanup, stop conditions, detection signal, negative controls, exact confirmation criteria, FP considerations, vulnerable+fixed fixtures, review state (experimental/validated/enabled/retired), last-review/owner.
- Only `enabled` controls count as supported. Release manifest pins app rev, DB schema, all tool/template/browser/skill versions, profile/score versions, model-compatibility results. `make manifest` regenerates it.

### 5.20 MCP & skills (F-20) — curated, off by default
- MCP is an optional tool interface, not the workflow or a security boundary. Default core execution = direct Playwright + scanner adapters. If any MCP is enabled (dev only in Phase 1): pin identity/version/tool schemas, authenticate the caller, constrain outputs, expose only required methods, treat all tool metadata/results as untrusted, disable target-registered WebMCP tools. No default unrestricted filesystem/shell MCP.
- Skills: reviewed Agent Skills packs (discovery interpretation, browser exploration, proof criteria, FP challenge, tool recovery, remediation) loaded by our own loader; application policy controls permissions regardless of a skill's declared tools. Never auto-load marketplace or target-supplied skills.

---

## 6. Cross-cutting invariants

### 6.1 Redaction & escaping
Cookie values, tokens, secrets, PII → `[redacted]` before storage/model/report. All target- and model-derived text is escaped in HTML/JSON. Tested in §8.

### 6.2 Determinism where it matters
Scoring, coverage, dedup, proof-rule evaluation are deterministic and versioned. Same inputs + versions → same output. The LLM touches only planning proposals, browser interpretation, FP *challenges*, and report prose.

### 6.3 Audit (F-22)
Every scan records actor, scope/profile/score versions, each decision, tool/version/redacted-args, request counts, timestamps, outcomes, evidence refs, overrides, scoring calc, exports. Durable events survive worker crashes.

---

## 7. Labs & fixtures (F-21)
- `labs/` Docker Compose: OWASP Juice Shop (pinned digest) + small owned nginx `good`/`bad` vulnerable/fixed pairs for TLS/header/cookie/exposure controls. Isolated Docker network, default-deny outbound (no target callbacks reach the internet), no published ports beyond loopback, synthetic data only.
- Seed/reset scripts + readiness checks; verify positive/negative behaviour independently before a measured run. On Apple Silicon, record arch support / emulation per image; run one stack at a time until resource use is known. Ground-truth/answer-key interfaces are never reachable by scanner workers or model context.
- Register each lab through the operator-only service binding in §5.1. The scanner may reach those named private lab services, but not the host, control plane, another scan or arbitrary private destinations.
- **Evaluation work is part of Phase 1:** create versioned fixture/label/split manifests in M0, implement the equal-budget baseline-versus-adaptive runner in M4, and complete the frozen held-out evaluation harness/report in M5. Use the testbed selection and procedures in Plan §13/§15, including independent fixed cases and reserved VulnerableApp/WAVSEP cases where applicable.
- Keep development, validation and holdout sets separate by independent implementation/scenario family; keep sibling vulnerable/fixed pairs together. Holdout labels/solutions stay evaluator-only. Reset fixtures between runs; record tool/model/provider/prompt/profile versions and budgets. Once holdout results influence tuning, those cases cease to be untouched holdouts.
- Report per-family counts, recall, confirmation precision, false-positive rate, negative conclusive coverage, abstentions/inconclusive outcomes, unmatched findings, runtime, requests and cost. Adjudicate unmatched findings rather than automatically labelling them false positives. Apply the definitions, minimum case counts and uncertainty reporting in Plan §13.
- M5 pilot targets for the claimed supported subset: recall ≥90%, confirmation precision ≥95%, FPR ≤5%, and negative conclusive coverage ≥90%. Include the plan's 95% uncertainty intervals and proposed per-family minimum of 30 positive/60 negative cases across at least three independent scenario groups. These are targets, not achieved results. Insufficiently validated or failing controls remain experimental or disabled, and are not advertised as supported. Do not quietly reduce scope or mark a required feature complete because its validation failed. An unlabeled owned-site smoke scan does not replace this benchmark.

---

## 8. Required test suites (part of "done")
- **Unit**: every check (good/bad/N-A/error), scoring (all Spec §9.6 & §9.9 examples), redaction, dedup, allowlist/scope. Add regressions proving that a blocked category prevents an overall score, only evidenced N/A renormalizes weights, unmapped serious candidates hold scoring, and duplicate alerts retain source evidence without duplicate deductions.
- **Contract**: each scanner adapter parser (valid/malformed/empty/truncated/nonzero/timeout/cancel); model adapter (§5.18 list).
- **Browser**: reaches a fixture state the plain crawler can't; one owner per context; downloads/popups governed; reflection-only XSS and banner-only CVE are *not* confirmed.
- **Recovery**: duplicate dispatch, stale lease, queue loss, crash before/after dispatch, interrupted upload → no uncontrolled duplicate run; outcome_unknown preserved.
- **Cancellation**: measure 5-s admission-stop / 30-s run-stop on labs; egress revoked incl. stale workers.
- **Containment/scope**: disallowed redirect, DNS rebinding, IP literal, IPv6, alt port, private/metadata dest, shared-IP, direct socket, proxy bypass all blocked; an unexpected allow blocks production activation. The named lab fixture must be reachable only through its lab binding, while arbitrary private/control-plane destinations remain blocked. A production scan cannot select lab authority. Before generated-code enablement, test the stronger isolation boundary for local-only and networked script execution, cross-scan file access and resource limits.
- **Injection (prompt)**: hostile page text/screenshot/tool/MCP/skill content cannot expand scope, change policy, install deps, or leak secrets.
- **Evidence**: fabricated stdout / invented artifact id / unsupported model claim cannot become `confirmed`.
- **Report safety**: HTML/JSON escape target content, redact creds/payloads, preserve partial/blocked/uncertain outcomes.
- **E2E**: full scan of `bad` and `good` fixtures + a Juice Shop supported-challenge subset (conditional pack on), ending in real HTML/JSON reports with honest coverage.
- **Evaluation/release**: M4 development/validation baseline-versus-adaptive comparison, followed by M5 frozen held-out evaluation with the metrics, case qualification, repeats and uncertainty rules in Plan §13. Preserve failure/abstention results; a successful E2E run alone is not the accuracy gate.

---

## 9. Milestones (build order) — maps to Plan M0–M5

Each milestone lists deliverables and an **Exit gate** that must pass to proceed.

**M0 — Foundation & labs (F-1, F-19, F-21).**
Repo layout, config, Postgres + Alembic, operator auth, scope registration including the operator-controlled lab binding, typed domain records and persistent Scan record, check-registry schema (start with a few specific controls), labs up with seed/reset, evaluation manifest/labels/split schema, release-manifest skeleton, dashboard workspace.
*Exit:* fresh checkout starts the dev stack, registers one lab scope, resets a fixture and stores a queued scan intent. **All scanner execution/dispatch is disabled in M0**; the broker, Task ledger/outbox and actual dispatch are implemented in M1. No target action may run before M1 enforcement gates pass. README covers setup/reset/teardown without embedded secrets.

**M1 — Execution & lifecycle before agents (F-2..F-6).**
Complete the Task ledger + transactional scan/task/outbox creation + Celery dispatch + leases/fencing + reconciler; policy broker + mandatory proxy + budgets + TLS lane; supervisor + isolated workers; trusted evidence intake; cancellation + recovery. Route all queued scan intents through this enforced admission path before enabling dispatch. Run **one** real read-only check end-to-end through the broker.
*Exit:* recovery/cancellation/containment tests for the implemented M1 paths (§8) pass on labs, including permitted named-lab access and denied production/private crossover; one real bounded HTTP check produces trusted evidence; an unexpected allow blocks activation. Browser/generated-code boundary tests are added when those capabilities are implemented, before their enablement.

**M2 — HTTP crawler + deterministic scanner + reporting + scoring (F-7 basic HTTP, F-8, F-14 basics, F-15, F-16, F-17 basics).**
Basic scoped BFS HTTP crawling and recon (§5.7), including endpoint/form/parameter inventory, robots/sitemap and passive fingerprinting; all §5.8 config/exposure checks with proof rules + fixtures; normalise/dedup; deterministic scoring + coverage + eligibility; report writer (template path) + HTML/JSON; dashboard scope/progress/findings/coverage/score views + all 12 tiles + safe export; one retest flow (fresh evidence; a blocked endpoint can't close a finding).
*Exit:* vulnerable/fixed fixtures give explainable results; missing coverage yields no fabricated number; scoring matches Spec examples & caps; a real end-to-end lab report (not mock findings).

**M3 — Browser + mature tools + start of active pack (F-7 browser enrichment, F-9, F-10, F-13 config parts, F-18 foundation).**
Extend the M2 HTTP inventory with interactive browser states/API observations. Establish the provider-adapter interface and qualified browser/vision route before model-assisted screenshot actions; complete multi-role routing/fallback contracts in M4. Playwright worker (one leased controller/session, DOM/a11y + coordinate fallback where a qualified model is configured), action/state capture, loop/side-effect guards; ZAP AF + selected Nuclei + testssl adapters (pinned bundle); release conditional active checks one at a time behind their gates.
*Exit:* the browser reaches a fixture state the crawler can't and it leads to a properly evidenced assessment; browser + CLI share scope/budgets; negative fixtures prevent reflection-only XSS and banner-only CVE confirmations.

**M4 — Adaptive reasoning, Bash, custom checks, model adapter (F-4 stronger boundary, F-11, F-12, F-13 active, F-14 full, F-18 completion, F-20).**
Implement and validate the dedicated worker VM or equivalently evaluated stronger boundary **before enabling any generated scripts**, including local artifact-analysis code (§5.4). Build the baseline-versus-adaptive evaluation runner on development/validation cases (§7), preserving the untouched holdout for M5. LangGraph nodes (baseline/observe/hypothesise/admit/execute/verify/complete) with protected baseline budget; specialist roles as logical roles with shared atomic budgets; bounded Bash + governed custom-script path; provider-flexible model adapter + contract tests; optional curated MCP/skills loader.
*Exit:* a finding triggers a useful bounded follow-up with captured proof + recorded cost; the generated-code isolation gate passes before execution; fabricated script output can't confirm; equal-budget baseline-vs-adaptive comparison records benefits and regressions with real metrics; provider switching passes contract tests without new authority or replayed actions.

**M5 — Private v1 hardening, held-out evaluation & first owned-site pilot (F-4 deployment validation, evaluation harness, manifest freeze, release tests).**
Validate the stronger worker boundary already built in M4 on the final deployment. Freeze the external profile + supported-control list + rubric + model/tool/prompt versions. Complete and run the held-out evaluation harness defined in §7 and Plan §13/§15, including matched findings, negative controls, uncertainty, coverage and equal-budget baseline-versus-adaptive comparisons. Publish the frozen benchmark report and all exclusions/failures; experimental or insufficiently validated checks are not supported claims. Run release tests (network boundaries, prompt injection, evidence access/redaction, orphan recovery, cancellation, report rendering); backup/restore metadata; evidence expiry/deletion; register owned site scope (staging first), run a bounded production smoke profile after gates pass.
*Exit:* one repeatable lab report + a frozen held-out benchmark report meeting the declared targets for the claimed supported subset + one owned-site pilot report (where authorized) + a frozen release manifest + recoverable deployment. The benchmark report includes per-family counts, recall, precision, FPR, negative conclusive coverage, abstentions, uncertainty and adaptive-versus-baseline cost/benefit. An owned-site report cannot substitute for the benchmark. This enables a private pilot, **not** a public scan-any-URL service.

---

## 10. Definition of done for Phase 1
- [ ] Operator registers an owned scope, runs an interactive+adaptive scan, watches redacted live progress, cancels cleanly, and downloads HTML + JSON.
- [ ] Scope/egress/isolation gates and prompt-injection tests pass; no worker reaches disallowed destinations or control-plane. Named private lab services work only through operator-controlled lab bindings; production cannot inherit those exceptions.
- [ ] The stronger worker isolation boundary is validated before any generated-script execution, including local artifact analysis, and retained for production/customer execution.
- [ ] Every enabled control has a registry entry, proof rule, and vulnerable+fixed fixtures; unsupported controls show as unsupported, never faked.
- [ ] Confirmed findings satisfy their proof rules against trusted evidence; potential/inconclusive kept separate; unmapped alerts retain their reported severity and evidence while awaiting classification; duplicates preserve provenance.
- [ ] Scores/coverage follow Spec §9: all applicable categories qualify before an overall number, only evidence-backed N/A categories are removed, and unresolved serious candidates hold scoring.
- [ ] Browser exploration, scanner adapters, and the conditional active pack do real bounded work with captured evidence.
- [ ] Adaptive follow-ups work within budget; baseline coverage protected; equal-budget comparison recorded.
- [ ] The M5 held-out benchmark report meets declared targets for the supported subset, with counts, uncertainty, coverage, abstentions and failures disclosed. Unvalidated/failing checks remain experimental or disabled and do not count as supported.
- [ ] Provider switching passes the compatibility suite without changing authority.
- [ ] Reports escape/redact everything; partial/blocked/uncertain outcomes visible.
- [ ] `make test` green; `make e2e` green on labs; one authorized owned-site pilot report produced.
- [ ] Release manifest pins every version; README covers setup, scope, labs, running, teardown.
