# ScopeLens — Open Questions & Recorded Decisions

Per Build Plan §0.8: undefined decisions are recorded here with the simplest option that satisfies the spec.
Per the operator's instruction: conflicts between the build plan and a companion are **flagged here, never silently resolved**.

Status legend: **OPEN** = needs operator decision · **DECIDED** = chosen, proceeding · **BLOCKED** = waiting on operator.

---

## Q-1 — Fourth document `ScopeLens_MVP_Build_Spec.md` contradicts the Build Plan (DECIDED)

**Operator decision (2026-09-24): (a) — the Build Spec is a superseded draft.** ScopeLens is
going full-fledged (the operator-only service in the two companions + Build Plan), not the
CLI version. `docs/archive/ScopeLens_MVP_Build_Spec.md` stays archived and governs nothing.
Continue on `ScopeLens_MVP_Build_Plan.md`. Nothing built in M0 changes. No re-planning needed.
This question is closed; do not reopen it or fold any Build Spec constraint back in.

_Original analysis retained below for the record._

**Severity: blocking for the shape of Phase 1. Flagged, not silently resolved.**

The operator's instruction names three documents. The working tree contained a **fourth**, at the repository root:

`ScopeLens_MVP_Build_Spec.md` — "Phase 1 MVP Build Spec (URL in → report out)", v1.0, 24 September 2026.
It has been moved to `docs/archive/` per Project Specification §19 ("Keep any historical copies outside the active specification path to avoid conflicting instructions").

### Why it is not simply the governing document

1. **It is truncated and incomplete.** The file is 6,176 bytes / 109 lines and ends mid-statement, inside a Python class body:

   ```python
   class Fetched(BaseModel):          # one HTTP exchange, written to evidence
       id: str                        # uuid4
       url
   ```

   It references its own §6 (checks), §7 (scoring), §8 (LLM summary), §9 (tests/labs) and §10 (task list). **None of those sections exist in the file.** It cannot be followed literally, as it instructs.

2. **It claims precedence it cannot exercise.** §0 says: *"For Phase 1, this document wins wherever they differ. Do not implement anything from those documents that is not listed here."*

### The conflict, stated concretely

| Subject | `ScopeLens_MVP_Build_Plan.md` (MVP-2.1) | `ScopeLens_MVP_Build_Spec.md` (v1.0) |
|---|---|---|
| Phase 1 shape | Full engine: operator UI, durable ledger, broker, browser, agent loop, scoring, reports | A CLI: `scopelens scan <url>` writing `runs/<id>/report.html` |
| PostgreSQL | Required (§3, §5.2) | §0.2: *"Do not add … PostgreSQL"* |
| Operator auth | Required (F-1, §5.1) | §0.2: *"Do not add … authentication"* |
| React dashboard | Required (F-17, §5.17) | §0.2: *"Do not add … a React frontend"* |
| Celery / Redis | Required (F-2, §5.2) | §0.2: *"Do not add Celery, Redis"* |
| LangGraph | Required (F-11, §5.11) | §0.2: *"Do not add … LangGraph"* |
| Playwright / ZAP / Nuclei | Required (F-9, F-10) | §0.2: *"Do not add … Playwright, Nuclei, ZAP"* |
| Target authorization | Operator allowlist + lab binding (§5.1) | `targets.yaml` + `lab_mode` flag (§3) |
| Scoring | 7 weighted categories C01–C07 (§5.15) | 4 categories (§7, not present) |
| HTTP methods | Broker-enforced allowlist, default `GET`,`HEAD` | §0.3: GET and HEAD only, never submits forms |

**The two documents cannot both be implemented.** They disagree on whether the Phase 1 product is a CLI tool or an operator-only service.

### Resolution applied (proceeding)

M0 is being built **to `ScopeLens_MVP_Build_Plan.md` §9 M0**, because:

- The operator's instruction designates the Build Plan as *"the build sequence you follow"*.
- The operator's M0 deliverable list — *"Postgres + Alembic … operator auth (single seeded account, session cookie, no signup) … minimal React/TS dashboard workspace"* — reproduces Build Plan §9 M0 and is **incompatible with Build Spec §0.2** on all three counts.
- The Build Plan §6 names only two companions as authoritative: `ScopeLens_Project_Specification.md` and `ScopeLens_Implementation_Plan.md`. The Build Spec is not among them, and both companions require the subsystems the Build Spec forbids.

### Operator decision required

> **Does `ScopeLens_MVP_Build_Spec.md` govern any part of Phase 1?**
>
> - **(a) No — it is a superseded draft.** Archive it (done) and continue to Build Plan M0. *[assumed while proceeding]*
> - **(b) Partly.** Name which parts (e.g. the `GET`/`HEAD`-only method restriction, the 15-check subset, the `targets.yaml` allowlist model) and they will be folded into the registry/profile as additional constraints. Note that Build Plan §5.1/§5.3 already default to `GET`,`HEAD` and already require an operator-controlled allowlist, so these may not be real conflicts.
> - **(c) Yes — it supersedes.** M0 as scoped must be abandoned and re-planned against it. It is currently unimplementable as written because §5–§10 are missing; the missing sections would need to be supplied first.

Nothing built so far depends on the answer beyond (c). If (c) is chosen, the work to date is a foundation for the operator-only service described by the two companions and would need re-planning.

---

## Q-2 — DNS resolution during scope registration (DECIDED)

**Question.** Build Plan §5.1 requires the production profile to *"reject private/link-local/metadata destinations"*. Doing so at registration time requires resolving the target hostname, which emits DNS queries. M0's rule is *"do not write any code that sends traffic to a target."*

**Decision.** DNS resolution is treated as **validation, not a target action**. No HTTP request is made to any target anywhere in M0. Resolution is confined to a single module, `scopelens/scope/dns.py`, which is the only module permitted to import `socket`; a test enforces that boundary. The resolver is injected, so tests never touch the network.

**Consequence.** Registering a *production* scope requires working DNS. The M0 exit gate registers a *lab* scope, whose addresses come from the allowlist file rather than DNS, so the gate does not depend on external resolution.

---

## Q-3 — Lab fixture self-checks make HTTP requests (DECIDED)

**Question.** Build Plan §7 requires *"Seed/reset scripts + readiness checks; verify positive/negative behaviour independently before a measured run."* Readiness and verification necessarily issue HTTP requests to the lab fixtures — which are targets. M0 says no code may send traffic to a target.

**Decision.** Readiness and fixture verification live **only** in `labs/scripts/`, use `curl`, and target **only** the loopback-bound lab fixtures on the isolated lab network. They are operator-side fixture tooling, not scanner code. `backend/scopelens/` contains no HTTP client capable of reaching a target, and a test enforces that.

**Rationale.** The M0 prohibition is on *scanner execution and dispatch*; §7 independently mandates fixture readiness checks. Without them the exit gate ("resets a fixture") cannot be verified.

**Consequence.** `make labs-verify` is a real check that fails loudly if a fixture is not serving the expected good/bad difference. It is not part of the scan path and never will be.

---

## Q-4 — Standards mappings in the check registry left partially empty (DECIDED)

**Question.** Build Plan §5.19 requires each registry entry to carry a *"standard mapping"* (OWASP Top 10:2025, WSTG v4.2, ASVS 5.0.0, API Top 10:2023).

**Decision.** Only mappings that can be stated with confidence are populated (WSTG v4.2 `CRYP-01`, `SESS-02`). Remaining mapping fields are left **empty** with `mapping_review: pending`, rather than guessing identifiers.

**Rationale.** Build Plan §0.3 forbids fabricating results. An invented ASVS or OWASP-2025 identifier is a fabricated factual claim in a security product's control catalogue — worse than an empty field, because it looks reviewed.

**Consequence.** A standards-mapping review pass is required before any control is promoted to `enabled`. Tracked for M2.

---

## Q-5 — `AuditEvent` built in M0 (DECIDED)

**Question.** M0's deliverable list names the `ScopeVersion` and `Scan` records. Feature F-22 (audit log of every actor/decision/tool/version/outcome) is marked *"all"* milestones in Build Plan §2.

**Decision.** A minimal append-only `AuditEvent` table is included in M0 and written by auth, scope-registration and scan-creation paths.

**Rationale.** F-22's milestone column is "all", and Build Plan §6.3 / Project Specification §12 require the actor and decision trail from the first real action. Auth, scope registration and scan creation are the first actions that need it.

---

## Q-6 — Lab fixtures: nginx pairs now, Juice Shop opt-in (DECIDED)

**Question.** Build Plan §7 and Plan §14 M0 say *"Bring up Juice Shop and a small owned vulnerable/fixed fixture pair first."* The operator's M0 list says *"the good/bad nginx fixtures."*

**Decision.** The nginx `good`/`bad` fixture pair is the **default** lab stack (it exercises the C01/C02/C04 header, cookie and TLS controls that the starter registry entries target). Juice Shop is defined in the same Compose file behind an opt-in `juice-shop` profile and is **not** started by default.

**Rationale.** Build Plan §7: *"run one stack at a time until resource use is known"* and *"On Apple Silicon, record arch support / emulation per image."* Both are satisfied without dropping Juice Shop.

**Consequence.** `make labs-up` starts the nginx pair only. `make labs-up-juice` starts Juice Shop for M2+ work. Juice Shop's image digest is recorded at first pull; until then it is marked `unpinned` in the release manifest, never assumed pinned.

---

## Q-7 — Session cookie signing library (DECIDED)

**Question.** Build Plan §5.1 permits *"`itsdangerous` or FastAPI session"*.

**Decision.** `itsdangerous` `URLSafeTimedSerializer`, `HttpOnly`, `SameSite=Lax`, `Secure` outside development, server-side `max_age` enforced.

**Rationale.** No server-side session store is needed for a single seeded operator, and it keeps M0 free of Redis (which is M1).

---

## Q-8 — Repository was not under version control (DECIDED)

**Question.** M0's exit gate is *"a fresh checkout starts the dev stack"*, but the working tree had no `.git`.

**Decision.** `git init` with branch `main`, plus a `.gitignore` covering `.env`, virtualenvs, `node_modules`, `__pycache__`, and generated `runs/` output. No commit is created — the operator has not asked for one.

---

# M1 decisions

## Q-9 — `mitmproxy` cannot coexist with `bcrypt` 5.x, so the proxy is its own image (DECIDED)

**Question.** Build Plan §3 names *"mitmproxy in scripting mode"* as the mandatory forward proxy. mitmproxy imports `passlib.apache` unconditionally from `mitmproxy/addons/__init__.py`, and passlib's bcrypt backend calls `bcrypt.hashpw` with a secret longer than 72 bytes.

**Measured.** With `bcrypt==5.0.0` in the same environment, `mitmdump` **fails to start**:

```
File ".../passlib/handlers/bcrypt.py", line 655, in _calc_checksum
    hash = _bcrypt.hashpw(secret, config)
ValueError: password cannot be longer than 72 bytes, truncate manually if necessary
```

This is fatal, not cosmetic. `bcrypt` 5.x removed the silent truncation passlib relies on.

**Decision.** The proxy is a **separate deployable with its own dependency set** (`deploy/proxy.Dockerfile`, `bcrypt==4.3.0`). `mitmproxy` is **not** a dependency of the backend. `backend/scopelens/broker/mitm_addon.py` is mounted into the proxy container and is therefore restricted to the standard library plus `mitmproxy` — a test enforces that it imports nothing from `scopelens`.

**Rationale.** Downgrading the backend's `bcrypt` to satisfy a proxy's transitive dependency would weaken the operator credential to fix an unrelated component. The proxy occupies a different network position and is a separate deployable in any real topology, so separating the environments is the correct fix rather than a workaround.

**Consequence.** The proxy image emits a non-fatal `AttributeError: module 'bcrypt' has no attribute '__about__'` at startup from passlib's version detection, then falls back. Verified harmless: `mitmdump` forwards traffic and generates its CA. Recorded here so the log line is not mistaken for a failure.

---

## Q-10 — The supervisor holds the Docker socket; workers never do (DECIDED, privileged)

**Operator decision (2026-09-25): keep the full Docker socket for now.** No socket-proxy
hardening in M1–M3; revisit after funding. This does **not** waive the §5.4 gate: no
model-generated code runs (M4) until workers are behind a stronger boundary than this.

**Question.** Build Plan §5.4: *"A trusted supervisor process (outside untrusted workers) owns run identity, starts/stops process groups, and collects evidence."* Spawning and stopping an isolated worker container requires the Docker API.

**Decision.** The `supervisor` container mounts `/var/run/docker.sock`. Worker containers are created with:

- **no** Docker socket, host mounts, DB credentials, Redis URL or control-plane network
- `worker_net` only — an `internal: true` network whose sole route outward is the proxy
- a per-scan scratch directory, read-only root filesystem, `cap_drop: [ALL]`, `no-new-privileges`
- CPU/memory/pids limits

**This is the most privileged component in the system and that is stated plainly.** It is the M1 *development baseline* — exactly what §5.4 permits *"for initial owned-lab runs of reviewed tooling"* — and §5.4 requires an equally-evaluated stronger boundary (a dedicated worker VM) **before any generated Python/Bash is enabled in M4**. The M1 container baseline does not satisfy that gate and is not claimed to.

**Residual risk, recorded.** A supervisor compromise is a host compromise. Target-derived bytes reach the supervisor only as evidence it stores opaquely and hashes; it never interprets or executes them. The stronger boundary addresses this properly in M4 and is validated on the deployment in M5.

**Consequence.** `make test` includes a containment test asserting the *worker* configuration has no socket, no mounts and no control-plane network, so a later edit cannot quietly grant one.

---

## Q-11 — The M1 worker image is `tool-worker`, not `kali-tool` (DECIDED)

**Question.** Build Plan §5.4 names a `kali-tool` image containing *"ZAP CLI, Nuclei, testssl.sh, curl, bash — pinned"*.

**Decision.** M1 ships the worker **container boundary** with `curl` and the pinned Python package. It is named `tool-worker`. The Kali base and the ZAP/Nuclei/testssl.sh payload arrive in **M3**, when the scanner adapters that use them are built (F-9 is an M3 feature).

**Rationale.** Naming the M1 image `kali-tool` while it contains none of those tools would advertise a capability that does not exist — the exact failure mode Build Plan §0.3 forbids. The rename is recorded here rather than left as a silent deviation.

**Consequence.** `workers/README.md` records which milestone adds which tool. M3 renames or supersedes the image.

---

## Q-12 — The policy decision service holds the broker logic; the proxy calls it per request (DECIDED)

**Question.** Build Plan §5.3 requires the broker to validate *"host==scope host, port allowed, path prefix allowed, method allowed, request/time/response-size budget not exceeded"* on **every** request, redirect and subrequest.

**Decision.** The decision logic lives in the backend as a single internal endpoint, `POST /internal/broker/authorize`. The mitmproxy addon calls it for every request. The endpoint performs the whole decision in one place:

1. `scope/validator.py::validate_destination` — the same function M0 uses at scope registration, so the registration rule and the enforcement rule cannot drift
2. path-prefix, method and port checks against the frozen `ScopeVersion`
3. cancellation-epoch check
4. lease/fencing check
5. atomic per-request budget reservation

**Rationale.** The user's instruction is that the broker calls *"the existing `scope/validator.py` validate_destination on every request/redirect/subrequest"*. The proxy image cannot import `scopelens` (Q-9), and duplicating the rules in the addon would create two sources of truth for the security boundary. A single decision endpoint keeps one implementation and keeps the budget reservation atomic in PostgreSQL.

**Consequence.** Every proxied request costs one extra control-plane round trip. At the §5.3 budget of 2 requests/second this is irrelevant, and it is measured. The endpoint is **not** published to the host and is reachable only on the control network.

---

## Q-13 — `execution/gate.py` is replaced, not weakened (DECIDED)

**Question.** M0 shipped `execution/gate.py`, whose whole purpose was that no dispatch path existed.

**Decision.** The module is **deleted**. Its two live functions move to their real homes: `assert_execution_not_requested` is replaced by `assert_execution_enabled` plus real admission in `execution/ledger.py`, and `execution_status` is replaced by a status derived from actual configuration. The M0 tests that asserted *no dispatch code exists* are replaced by tests asserting *dispatch is correctly fenced* — the inverse claim, now that the capability legitimately exists.

**Rationale.** The instruction is explicit: *"flip the M0 execution gate on properly — replace execution/gate.py, don't weaken it."* Leaving a disabled gate in place beside the real path would be worse than either option: two switches, one of which lies.

**Consequence.** `SCOPELENS_SCANNER_EXECUTION_ENABLED` now genuinely enables execution, and the containment tests assert the *fences* around it rather than its absence.

---

## Q-14 — DNS pinning has a residual rebinding window (FIXED IN M3; historical analysis retained)

**M3 correction (2026-09-26):** the proxy now pins the actual upstream socket in its
`server_connect` hook, preserving the requested HTTP Host and TLS SNI. A real canary test uses
an unresolvable hostname with a broker-approved address and verifies successful delivery;
no second DNS lookup is needed. Changing the earlier flow object was measured and did not
control the eventual socket, so that implementation was replaced. Per-origin pins remain
fixed for the proxy process lifetime; a changed approved address fails closed and requires
review/restart. `make test-proxy` also verifies denied tunnels, raw bytes and response caps.

_The original M1 analysis follows._


**Question.** Build Plan §5.3 requires the broker to block *"DNS rebinding (re-resolve + pin)"*.

**What is implemented.** Every proxied request re-resolves the scope host and runs the result
through `validate_destination`. The first request records the address set on the **scan row**
(durable, not in memory), and every later request must resolve to the same set. A name that
re-points mid-scan is refused with `resolved_addresses_changed` rather than followed. Both
the destination rule and the pin are independent stops: a rebind to a private address is
caught by the first, and a rebind to a *different public* address by the second.

**Residual window.** The proxy resolves the name again itself in order to open the
connection. A rebind that lands between the broker's check and the proxy's connect would not
be caught for that one request. Closing it requires handing the validated address to the
proxy's connector, which mitmproxy does not expose in a way this addon can use safely.

**Why it is recorded rather than fixed now.** The threat is a target the operator owns
re-pointing its own DNS mid-scan. It is not a cross-tenant attack and not reachable by a
target that does not already control the authorized hostname. The window is bounded by one
request, and the next request re-checks and refuses.

**Consequence.** `tests/integration/test_broker.py::TestDnsRebinding` covers the pinning that
*is* implemented. The residual window is a known gap, not an untested claim, and it belongs
with the M4 network-boundary work rather than being papered over here.

---

## Q-15 — CONNECT bypassed the broker entirely (FIXED; found in M1 review)

**Severity: critical containment failure.** Found by operator review of the M1 audit, not by
the test suite. Reproduced before fixing.

### What was wrong

The addon hooked only `request`. mitmproxy connects upstream **eagerly** on CONNECT, and a
tunnel whose bytes are neither TLS nor HTTP is passed through as **raw TCP** — the `request`
hook never fires, so the broker was never consulted.

Reproduction with the policy service unreachable (i.e. deny-all):

```
proxy replied: HTTP/1.1 200 Connection established
sent raw bytes
CANARY LOG: CONNECTED from ('127.0.0.1', 62953)
            BYTES: b'RAW-TCP-PAYLOAD-NOT-HTTP\r\n\r\n'
```

The proxy is attached to `control`, `labs` and `egress`, so a worker could reach
unauthenticated Redis, PostgreSQL, the API and any internet host — the entire scope
boundary was optional for anyone who opened a tunnel and sent non-HTTP bytes.

### The fix, and what each layer actually does

| Layer | Mechanism | Verified |
|---|---|---|
| 1. Tunnel authorization | `http_connect` requires the egress token (from `x-scopelens-egress` or `Proxy-Authorization: Basic`, since httpx can only set the latter on CONNECT) and authorizes host+port | yes |
| 2. No socket before a decision | `connection_strategy=lazy` | yes |
| 3. Raw TCP disabled | `rawtcp=false` | yes |
| 4. `tcp_start` / `udp_start` kill | `flow.kill()` + a loud log | **no — see below** |
| 5. Inner requests | `request`, unchanged | yes |

**Layer 4 does not hold, and is not claimed to.** Measured: with `tcp_start` and `tcp_message`
both calling `flow.kill()`, the payload still reached the canary. mitmproxy 12 relays the
first message regardless. Those hooks are kept as detection — and would matter if a future
configuration enabled `tcp_hosts` — but `rawtcp=false` is the mechanism that actually stops
raw TCP, by preventing the raw-TCP layer from being selected at all.

### Also fixed alongside

* **Redis had no password** while sharing the control network with the proxy. Now
  `--requirepass` with a generated secret.
* **`/internal/broker/*` was served on the published operator port**, while its docstring
  claimed it was not published. The decision endpoint now runs as a separate `policy` service
  on an unpublished port, with no OpenAPI, no docs and control-network-only attachment.

### Two consequences worth knowing

* **CONNECT now consumes one request of the scan's budget.** It is a network operation against
  the target, so counting it is the conservative choice. The audit trail shows both decisions
  for a scan: `CONNECT 172.28.0.11:8443 allowed`, then `GET 172.28.0.11:8443 allowed`.
* **`CONNECT` is exempt from the scope's method and path allowlists**, because it is how a
  client asks the *proxy* for a tunnel rather than a request to the target: it has no path, and
  its method is not the scope's business. Host and port are the whole of its authorization.
  Without this exemption, `allowed_methods: [GET, HEAD]` made every HTTPS request impossible —
  which the post-fix end-to-end run caught immediately.

### Regression coverage

* `tests/containment/proxy_bypass.py` (21 checks, `make test-proxy`) — reproduces the original
  probe against a real mitmproxy with a canary listener, plus deny-all, unknown-token,
  no-token, out-of-scope-host and allowed-tunnel cases.
* `tests/containment/live_proxy_probe.py` (`make verify-proxy-live`) — live deployment: a real
  token cannot tunnel to `redis:6379` or `postgres:5432`, while the scope's own host is not
  refused for a scope reason.
* `tests/contract/test_containment.py::TestProxyHooksArePresent` — cheap guards asserting the
  hooks exist and both mitmproxy options are set, so removing either fails the fast suite.
* `tests/integration/test_broker.py::TestConnectAuthorization` — the CONNECT rules themselves.

**Review follow-up (2026-09-25).** Re-probed independently on mitmproxy 12.1.2. The deny path
holds without any flags. But with the policy *allowing* a CONNECT, non-HTTP bytes still
reached a canary unless `rawtcp=false` was on the command line — so containment depended
entirely on the compose entrypoint. The addon now forces `rawtcp=False` and
`connection_strategy="lazy"` in its own `configure` hook. Re-measured: an allowed CONNECT
carrying raw bytes delivered nothing to the canary with no flags, and also with
`--set rawtcp=true` given explicitly. The compose flags stay as defence in depth.


## Q-16 — M2 review corrections and coverage interpretation (RESOLVED)

Implemented and verified on 25 September 2026; see `M2_REVIEW.md` and the latest section of `MILESTONES.md`. Unresolved candidates do not complete control coverage merely because a check executed. Legitimate evidence-backed N/A removes weight; absent authorization, capture or prerequisite remains unassessed. The old 69/100 and 100/100 fixture scores are superseded.

The default deployment has no advisory snapshot selected. Component matching is implemented with a frozen operator-configured OSV corpus; missing corpus/version/range support keeps C06 unassessed. This intentionally withholds overall scores in the default live lab reports. Configure a reviewed corpus using `ADVISORY_SNAPSHOTS.md`; never mark a missing corpus as a pass.

M2 backend corrections are complete: 524 tests, real proxy containment, lab reports and fixed/recurrent retests pass. Frontend ownership remains separate; M3 is not started.

## Q-17 — M3 execution decisions and measured limitations (IMPLEMENTED, 2026-09-26)

- Browser: Playwright 1.63.0/Chromium 153.0.8010.12 in a separate non-root worker. Chromium's
  sandbox remains enabled. The reviewed seccomp profile allows `chroot` inside its sandbox
  namespace without granting the container SYS_CHROOT or other capabilities; the first real
  launch failed without that syscall allowance. No generated controller code runs.
- ZAP uses the pinned distribution's offline HAR importer and four passive rules. exim 0.16.0
  predates `sendRequests`; supplying that newer option caused a real nonzero exit and was
  removed. ZAP receives no proxy/scan/provider credentials. Nuclei uses one pinned HTTP template.
- testssl.sh runs the reviewed protocol command through a loopback CONNECT gate inside the
  trusted TLS lane. Each socket gets a fresh broker decision and approved IP; its own DNS and
  phone-out paths are disabled. NPN/ALPN cannot be assessed through that proxy mode, and the
  system OpenSSL reports no GOST engine. Those diagnostics remain visible as **partial tool
  coverage**, not successful checks. Overall scans are therefore `completed_partial` on these
  fixtures even though all selected HTTP/browser stages complete.
- CORS and redirect configuration probes are approved only for the two named lab fixtures in
  the shipped pack. Production approvals are empty. Results remain unscored observations;
  credentialed exposure and full active proof rules are M4.
- The optional vision foundation uses a separate authenticated provider gateway. The policy
  service stays on the control network. No provider is configured by default; no live provider
  qualification or paid call is claimed. The full multi-role/fallback contract suite is M4.
- The shared scan ledger now schedules HTTP/CONNECT/TLS admissions, records unique-page budget
  keys, and retains spend through recovery. The proxy limits concurrent work and response
  transfer. The TLS tool gate is serial. The pilot still uses one proxy and one executing
  coordinator; distributed throughput is not a supported deployment claim.
- Real CLI execution exposed the queue cancellation problem: with one Celery execution slot,
  a cancellation task could wait behind the process it needed to stop. The supervisor now
  checks authority directly every 0.5 seconds while waiting and stops that process group.
  Browser artifacts are emitted as captured, so stopping the worker retains partial evidence.
- Immutable image IDs exceeded the old 64-character evidence tool-version field. Migration
  **0006** widens it to 256 characters; the full digest is retained and the regression is tested.
- Browser response capture uses completed requests, waits for network quiescence between
  actions, and avoids replaying a disclosure action merely because a URL fragment changed.
  A proxy denial is a coverage gap, never a target response that could create a header finding.

The dedicated VM boundary before M4 generated code remains required by the build plan. No
frontend source was changed. These are implementation decisions within the approved milestone;
there is no pending operator decision in this entry.

## Q-18 — Phase 1 backend integration and remaining release qualification (RECORDED)

Operator direction: complete the core backend through scanning, reports and scorecards; no
further UI work. The provider is an OpenAI-compatible endpoint configured locally in `.env`.
No external pilot URL has been supplied.

- The application uses bounded non-streaming JSON proposals. Planner, browser interpretation,
  verifier challenge, script proposal and writer share atomic call/cost reservations. Unknown
  usage consumes its conservative reservation; fallback requires independent provider approval.
  A refusal is not rerouted. The app rejects tool-call/incomplete responses; provider tool calls
  and streaming are not required by this transport. Live compatibility is unqualified until
  the configured provider passes the operator's synthetic qualification run.
- Generated code executes in a dedicated ARM64 Lima/VZ guest with no host mounts. Transient
  systemd units constrain memory, processes, filesystem, runtime and socket families. Local
  analysis has no network; explicit lab RPC uses the existing broker, token and budgets.
  The real VM tests passed Python/Bash, blocked host/control access, output/time limits, ignored
  large stdin, allowed lab requests, cross-scope denial and revoked capabilities. Generated
  stdout, including a fabricated `confirmed=true`, remains an untrusted observation.
- The five active checks now have measured vulnerable/fixed fixtures and reviewed CWE mappings.
  They remain **experimental** pending independent held-out evaluation. CORS confirmation is
  limited to the observed permissive configuration, not authenticated protected-data exposure.
- The evaluator replays proofs from hash-checked trusted artifacts. The current development
  protocol produced five TP and five TN. Its gate correctly fails on independence/sample size;
  it does not convert a perfect ten-case result into a broad accuracy claim.
- Backup/restore was measured into a new database and directory. New evidence is encrypted when
  the key is configured; bootstrap now generates a key for new installations. The existing
  deployment's key was generated locally and never printed. Preserve it separately from backups.
- The frozen release override uses immutable image IDs and removes source mounts. Production
  pilot qualification and final production worker-boundary validation remain open. This does
  not reopen Q-10's accepted supervisor privilege or silently waive any release gate.

Defects fixed during this integration: a closed shared probe client; encoded redirect targets
that were relative rather than external; a redacted proof boolean; shallow JSON mutations
losing hypothesis states; TLS baseline work scheduled after adaptation; browser calls escaping
the common model ledger; blocking sandbox stdin writes; duplicate redirected follow-ups; and
independent vulnerable input locations sharing one remediation deduction.


## Q-19 — Pilot observations and transport fixes (RECORDED)

The operator supplied `https://stage.slicerninja.com/`, `https://arkyon.dev/` and
`http://rekvon.in/`. Exact scopes and bounded pilot reports now exist. This supersedes Q-18's
historical "no target supplied" status. Rekvon's same-host HTTPS redirect received its own
scope; no related hosts or hosting-provider assets were added implicitly.

Pilot failures exposed a proxy pool-key mismatch: socket-time IP rewriting created five open
connections that could not be reused, then stalled request six. Routing now uses the pinned IP
while retaining the authorized Host/SNI. A local 15-request regression and 12-request staging
probe verify the fix. A separate real canary exposed mismatched HTTP Host authority reaching
an approved address; the addon now rejects that disagreement before forwarding.

The previous live-proxy positive assertion checked a reason string in a status line, so it
could pass without demonstrating an allowed response. It now fetches the actual named lab
fixture over HTTPS, checks its body, and revokes the probe capability in a finally block.
The three owned sites' crawl passes now have zero transport errors. See MILESTONES for results.

No change to authorization, scoring gates, unsupported-category handling or the generated-code
VM requirement is implied by these operational fixes. The independent held-out evaluation and
configured-provider qualification are still required. This entry requests no new decision.

## Q-20 — Dedicated reviewed-worker deployment and measured compatibility (RECORDED)

The supervisor now controls a separate `scopelens-workers` VM over mutual TLS when launched
with `make run-worker-vm`; its Docker Desktop socket mount is removed in that deployment.
Workers have no host folders, client keys or control-plane network. A fixed relay carries
their requests to the existing enforcing proxy. The first cross-scan canary caught missing
bridge filtering; explicit bridge netfilter fixed it, and activation is gated on the live
probe. The repaired boundary passes after reboot and on full lab scans.

The owned staging pilot caught a Chromium ARM SIGILL. Disassembly showed SVE `cntd` while
the guest advertised SME without SVE. `arm64.nosme` avoids the incompatible browser path;
the final full pilot rendered 3 browser states and generated reports with the same 5 Low
findings. Sandbox/security flags remain enabled. Provisioning and qualification check this
setting for the pinned deployment; revisit it on a browser/kernel upgrade.

This closes the final local worker-boundary qualification gap, without claiming independent
active-check accuracy or live provider compatibility. No new operator decision is needed.
Commands, failures and final reports are recorded in `MILESTONES.md` and `WORKER_VM.md`.
