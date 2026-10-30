# Milestones

Tracks the ordered build sequence in `ScopeLens_MVP_Build_Plan.md` §9.

**Current milestone: M3 delivered and lab-verified, 26 September 2026. M4 has not started.** See the M3 section at the end for current commands, measurements and limitations.

Every claim below is either backed by a command in this repository or marked as not yet
established. Per Build Plan §0.3, a capability that has not been run is never recorded as
passing.

---

## Corrections completed — 25 September 2026

The M2 review findings R1–R9 are resolved. The following M2 measurements are retained as the historical baseline; M3 is recorded below. The earlier 69/100 and 100/100 fixture scores are superseded: they depended on treating incomplete candidate checks as complete.

| Check | Measured result |
|---|---|
| `uv run pytest -q --tb=short` with PostgreSQL running | **524 passed, 0 skipped** |
| `make test-proxy` | 21 real mitmproxy containment assertions passed, including authorized CONNECT followed by raw bytes |
| `make lint` | Ruff, formatting and frontend typecheck passed |
| `make check-registry` | 17 valid enabled entries |
| `make manifest` | M2 manifest, schema `0004` (`0004_m2_assessment_plan.py`), implemented capabilities updated |
| `uv run python scripts/verify_m2_lab.py` | Both lab scans completed; live fixed and recurrent CSP retests passed; original fixture restored |

| Fixture | Findings | Coverage | Overall score |
|---|---:|---:|---|
| labs-good | 0 | 94.1% | Withheld: component assessment unassessed without a configured advisory snapshot |
| labs-bad | 12: 1 High, 4 Medium, 6 Low, 1 Info | 88.2% | Withheld: incomplete component/candidate assessment |

The good HTML report contains the required empty-state sentence and coverage. Numeric score deductions/caps, including 59 for one High plus two Low, are tested independently; absence of a live overall number is expected under the actual coverage gates.

Changes: actual HTML template escaping; certificate trust/host/time and legacy offers; separately approved one-request HTTP redirect probe; manual scoped redirects and sitemap parsing; content-specific exposure proof with a negative control; effective CSP/frame policy checks; fixed coverage denominator/weights/instances/candidate handling; snapshot-backed component candidates; completed retest lifecycle; typed/resumable SSE including task events; frozen registry/discovery inputs; response evidence links with run/task/source provenance. Bearer redaction was also corrected after a regression test found a leaked credential fragment.

A live CSP retest resolved the original finding after its fixture changed, and reopened it after the original configuration returned. Failed/cancelled/blocked/missing-location and repeated-completion paths are covered by database tests. Existing original scan scores and observations are retained; finding lifecycle state reflects later retests.

Proof linkage was checked against the live evidence store: 18 captured artifacts for good, 20 for bad, and 24 for each retest. All finding proof IDs resolve to trusted records; capture manifests link response artifacts with task/run/source hashes. Raw worker stdout stays untrusted. To repeat after the lab verification:

```sh
docker cp scripts/verify_m2_evidence.py scopelens-dev-supervisor-1:/tmp/verify_m2_evidence.py
docker cp runs/m2-verification/scan_ids.json scopelens-dev-supervisor-1:/tmp/m2_scan_ids.json
docker exec scopelens-dev-supervisor-1 python /tmp/verify_m2_evidence.py
```

Configuration: apply migration 0004. HTTP redirect checking needs `transport_http_port` in the immutable HTTPS scope. Lab TLS uses the generated lab CA; production uses the system trust store. Component matching requires an operator-configured offline advisory corpus, documented in `ADVISORY_SNAPSHOTS.md`; none was configured for the default lab measurement. Unknown versions/ranges remain unassessed, and banner matches never confirm CVEs.

Output and command logs: `runs/m2-verification/` (ignored by git). Repository has no commits, so there is no historical diff baseline. Frontend source was not edited during these backend corrections. ScopeLens dev/lab services are stopped after verification; database and report artifacts are retained.

Measured scan IDs: `labs-good` = `47a9f0b3-2dea-4e10-8206-1bdab1810a8b`, `labs-bad` = `bb7844bd-943b-4482-9a55-bb45b4293f56`, `retest-fixed` = `e18d6557-da09-49bd-92e4-035e456385fd`, `retest-regression` = `957bf48c-fad2-4ea8-be97-682cd539a82b`.

---

## M0 — Foundation & labs (F-1, F-19, F-21)

**Status: complete and approved** (operator decision in `docs/OPEN_QUESTIONS.md` Q-1).
Verified end to end on a fresh checkout.

Delivered: repository layout, `config.py`, PostgreSQL + Alembic, operator auth (one seeded
account, session cookie, no signup), scope registration with the operator-controlled lab
binding, the check-registry schema with three starter controls, the lab fixture pair with
seed/reset/verify, the evaluation manifest schema, the release-manifest skeleton and the
dashboard workspace.

The M0 execution gate (`execution/gate.py`) has since been **deleted** by M1, as instructed
(Q-13). Its guarantee — that no dispatch path existed — is replaced by M1's fences.

---

## M1 — Execution & lifecycle before agents (F-2..F-6)

**Status: complete.** Verified end to end against the lab fixtures.

### Deliverables

| Deliverable (§5.2–§5.6) | Where | State |
|---|---|---|
| Task ledger — `logical_id`, `attempt_id`, state set, `lease_token`, `reserved_budget` | `persistence/models.py`, `domain/task.py` | done |
| Transactional Scan + Task + outbox creation | `execution/ledger.py::create_scan_with_task` | done |
| Celery + Redis dispatch, at-least-once | `dispatch.py`, `tasks.py` | done |
| Idempotency key = (scan_id, logical_id, attempt intent) | `tasks` unique constraint | done |
| One renewable coordinator lease per scan, with fencing | `execution/leases.py`, `execution/heartbeat.py` | done |
| Executors reject stale fencing tokens | `leases.assert_lease_held` | done |
| Reconciler — orphans, stale leases, lost outcomes | `execution/reconciler.py` | done |
| Policy broker behind a mandatory forward proxy | `broker/policy.py`, `broker/mitm_addon.py` | done |
| Broker reuses `scope/validator.py::validate_destination` per request | `broker/policy.py::_check_destination` | done |
| Budgets from §5.3, reserved before execution | `domain/budget.py`, `execution/budget.py` | done |
| Constrained TLS measurement lane | `broker/tls_lane.py`, `broker/tls_lane_service.py` | done |
| Supervisor + isolated worker container | `execution/supervisor.py` | done |
| Trusted evidence intake, redaction, provenance, hash | `evidence/intake.py`, `evidence/store.py` | done |
| Cancellation — durable epoch, egress revoke, process-group stop | `api/scans.py`, `tasks.py::cancel_task` | done |
| Crash recovery — reconcile before retry, `outcome_unknown` | `execution/reconciler.py` | done |
| One real read-only check end to end | `checks/fetch_origin.py` | done |

### Exit gate

> *Recovery/cancellation/containment tests for the implemented M1 paths pass on labs,
> including permitted named-lab access and denied production/private crossover; one real
> bounded HTTP check produces trusted evidence; an unexpected allow blocks activation.*

**One real bounded HTTP check through the broker.** Run against `labs-bad` over HTTPS:

```
STATUS:  completed
REASON:  fetched https://172.28.0.11:8443/ -> HTTP 200
BUDGET   spent {'requests': 1, 'bytes': 1280, 'pages': 0, 'redirects': 0}  reserved 0
```

The response was fetched by a worker in its own container, through the forward proxy, with
every request individually admitted by the policy broker. The broker's audit trail for the
scan records `allowed GET 172.28.0.11 /`.

**Trusted evidence with provenance.**

```
supervisor              trusted=True    1738B  redacted  worker fetch of https://172.28.0.11:8443: status=200
untrusted_observation   trusted=False   1726B  redacted  worker process output, recorded as an observation only
```

The artifact carries `scan_id`, `task_id`, `run_id`, the scope version and its content hash,
a capture timestamp and an integrity hash. Redaction fired on real data: the fixture's
`Set-Cookie` value is stored as `[redacted]`. The worker's own stdout is recorded as an
`UNTRUSTED_OBSERVATION`, so it can never back a confirmation.

**Named lab service reachable only via its binding.** From a container on the worker
network:

| Request | Result |
|---|---|
| Direct to the fixture, bypassing the proxy | `Failed to connect … Could not connect to server` — no route |
| Direct to `1.1.1.1:443` | blocked, `OSError` |
| To the proxy, no egress token | `403 missing_egress_token` |
| To the proxy, bogus token | `403 unknown_egress_token` |
| Through the proxy with a valid token and scope | `200` |

**Proxy-bypass blocked — the claim is now backed by an automated test, not by an
observation.** `make test-proxy` runs `tests/containment/proxy_bypass.py` (21 checks) against
a real mitmproxy: it stands up a raw-TCP canary and an HTTP canary, drives a controllable
policy stub, and reproduces the CONNECT probe that defeated the previous build. It asserts
that **zero connections and zero bytes reach the canary** when the policy denies, when the
policy is unreachable, and when a tunnel carries non-HTTP bytes.

`make verify-proxy-live` adds the live-deployment check: a real scan's real egress token
cannot tunnel to `redis:6379` or `postgres:5432`, while the scope's own host is not refused
for a scope reason — so a blanket denial cannot masquerade as containment.

| Live probe (`make verify-proxy-live`) | Result |
|---|---|
| `CONNECT redis:6379` with a valid token | refused |
| `CONNECT postgres:5432` with a valid token | refused |
| `CONNECT` with an unknown token | refused |
| `CONNECT` to the scope's own host | not refused for a scope reason |
| `/internal/broker/authorize` on the published operator port | `404` |
| Redis without a password | `NOAUTH Authentication required` |

**Denied production/private crossover.** `tests/integration/test_broker.py` — 39 cases.
`TestAuthoritySeparation` asserts that a production scan resolved to a lab address is
refused, and that a lab scope is not a blanket private-network allowlist.

**An unexpected allow blocks activation.** `TestActivationGate` runs all nine forbidden
destination classes as one explicit gate and fails with the activation consequence spelled
out, not merely with a list. A companion test proves the gate *can* fail, so a green run
means something.

**Recovery and cancellation.** `tests/integration/test_dispatch_recovery.py` — 18 cases:
duplicate dispatch leaves one logical task; a live lease held elsewhere stops the run
without starting a worker; queue loss leaves the row dispatchable with the error recorded;
crash before dispatch stays dispatchable; crash after dispatch settles as `outcome_unknown`
with the reason "not retried"; spent budget survives reconciliation while the stale
reservation is released.

**Cancellation deadlines, measured on labs** (Build Plan §5.6):

| Deadline | Measured | Target |
|---|---|---|
| Admission stop — new egress refused | **0.006 s** (max of 3) | ≤ 5 s |
| Run stop — worker process group gone | **5.122 s** | ≤ 30 s |

The admission-stop figure is one durable write. The run-stop is SIGTERM-then-SIGKILL against
a labelled long-running worker, through the real supervisor path.

### Verification

```
make test       405 passed, 0 skipped
make lint       ruff clean, 84 files formatted, dashboard typecheck clean
make manifest   milestone M1, schema 0002
```

Suites: unit (scope validator, lab binding, registry, security, manifest, evaluation),
integration (API, leases, budgets, broker, dispatch/recovery, evidence, coordinator) and
contract (containment, lab fixtures, broker-addon isolation). Dynamic containment runs
separately because it needs a real mitmproxy: `make test-proxy` (21 checks, in the proxy
image) is part of `make test-all`.

### Defect found in M1 review (critical)

**The forward proxy bypassed the broker on CONNECT.** Found by operator review of the M1
audit, not by the test suite — the suite tested the proxy's behaviour against its own
assumptions rather than against an adversary.

The addon hooked only `request`. mitmproxy connects upstream **eagerly** on CONNECT, and a
tunnel carrying bytes that are neither TLS nor HTTP is passed through as **raw TCP**, so
`request` never fired and the broker was never consulted. Reproduced with the policy service
unreachable: the proxy answered `200 Connection established` and the payload reached a canary
listener. Since the proxy is attached to `control`, `labs` and `egress`, a worker could reach
unauthenticated Redis, PostgreSQL, the API and any internet host — the entire scope boundary
was optional for anyone who opened a tunnel and sent non-HTTP bytes.

Fixed across five layers, and recorded in full at `docs/OPEN_QUESTIONS.md` Q-15, including one
correction to the fix as specified: **`flow.kill()` from `tcp_start` does not prevent the
relay** — it was measured, with the payload still arriving — so `rawtcp=false`, which stops the
raw-TCP layer from being selected at all, is the mechanism that holds. The kill hooks remain as
detection and are not claimed to be prevention. **Review follow-up:** that option was only
set on the compose command line, so an *allowed* CONNECT still relayed raw bytes without it
(re-measured). The addon now forces `rawtcp=False` + `connection_strategy="lazy"` in
`configure`; verified with no flags and with `--set rawtcp=true`. See Q-15.

Two things were fixed alongside it: Redis had no password while sharing the control network with
the proxy, and `/internal/broker/*` was served on the published operator port while its own
docstring claimed it was not.

### Defects found by running it, not by reading it

Recorded because the end-to-end run found things the unit tests could not: the tests fake
the worker, so a gap between the worker and the proxy is invisible to them.

1. **The worker never sent its egress token.** The proxy denied every request with
   `missing_egress_token`. The token was issued and passed to the worker, but never attached
   to the HTTP request. Fixed, with a contract test asserting the header name matches in
   both places.
2. **The proxy CA was passed as a path.** The worker has no host mounts, so the path named a
   file it could not see. Now passed as PEM content and written into the worker's own tmpfs.
   Related discovery: mounting the CA volume would not have worked either — its directory is
   mode 700 root-owned, which the unprivileged worker cannot read.
3. **mitmproxy rejected the fixture's self-signed certificate.** Upstream verification is now
   off, deliberately and with the reasoning recorded: this is a scanner, and an expired or
   self-signed certificate is a finding to report rather than a reason to refuse to connect.
   The real certificate is measured independently by the TLS lane.
4. **`stop_all_for_scan` filtered on a label the supervisor never set.** Cancellation could
   not have found any worker. Fixed, with a contract test asserting the coordinator and the
   supervisor agree on the key.
5. **The stop grace period used the whole 30 s deadline**, making the deadline unreachable by
   construction — measured at 30.114 s. Now a separate 5 s grace, measured at 5.122 s.
6. **Broker per-request reservations were never released.** A completed scan kept a permanent
   `budget_reserved` of 1. Fixed with `budget.settle`, which clears both the coordinator's
   reservation and the broker's.
7. **`_check_destination` re-applied the *production* public-address rule to lab addresses**,
   refusing every legitimate lab request. The authority-aware `validate_destination` already
   handles this; the extra loop contradicted it.
8. **Text redaction missed secrets inside JSON bodies**, and the credential patterns were
   anchored so they only matched whole strings. Both fixed; JSON artifacts are now redacted
   structurally, so a `Set-Cookie` value is replaced whole.
9. **`outbox_events` was never truncated between tests.** It has no foreign key to `scans`,
   so `TRUNCATE … CASCADE` did not reach it and 275 stale rows accumulated — a dispatch test
   was examining other tests' work.
10. **`migrations/env.py` ignored an explicitly supplied database URL**, so the suite migrated
    the development database and then failed on a missing table.

### What M1 deliberately does not contain

No crawler, no deterministic checks, no scanner adapters, no browser, no LangGraph, no
adaptive loop, no proof rules, no scoring and no reporting. `release_manifest.json` lists all
ten explicitly and reports **`supported_control_ids: []`** — the three registry controls
remain `experimental`, because no check has been run against its fixtures yet.

The one M1 task type, `fetch_origin`, is named in the manifest as the plumbing proof. It
produces evidence; it does not produce findings.

### Known limitations

- **The worker container is the M1 development baseline, not the M4 boundary.** The
  supervisor holds the Docker socket — the most privileged component in the stack.
  `docs/OPEN_QUESTIONS.md` Q-10 states this plainly and records that §5.4 requires a
  dedicated worker VM before any generated code runs in M4. M1 does not claim otherwise.
- **The TLS lane is exercised by unit tests, not by an end-to-end scan.** The M1 check is a
  single HTTP fetch; wiring the lane into a check is M2 work.
- **DNS pinning has a residual window.** The broker re-resolves and pins on every request,
  but the proxy resolves the name again to open its connection, so a rebind inside that gap
  would not be caught. Recorded as `docs/OPEN_QUESTIONS.md` Q-14.
- **Cancellation was measured against a labelled long-running worker**, not against M1's own
  check, which completes in roughly 0.3 s and cannot be raced deterministically. The code
  path measured is the real one (`DockerWorkerSupervisor.stop_all_for_scan`).
- **One task type, one coordinator, one worker at a time.** Concurrency above one scan is
  untested because M1 caps at one.
- **`release_manifest.json` still records `git.commit: null`** — no commit has been made.

---

## M2 — HTTP crawler + deterministic scanner + reporting + scoring

**Historical planning note (before M2 implementation).** The planned scope below is retained for context; current M2 status is at the top.

Planned, per Build Plan §9 M2: basic scoped BFS HTTP crawling and recon; all §5.8
config/exposure checks with proof rules and fixtures; normalise/dedup; deterministic scoring
+ coverage + eligibility; the template-path report writer with HTML/JSON; dashboard
scope/progress/findings/coverage/score views; one retest flow. The TLS lane is wired into
real checks here.

Milestones M3–M5 are listed in `ScopeLens_MVP_Build_Plan.md` §9 and have not been started.

---

# M2 — Deterministic scanner & reporting

Scope: Build Plan §9 M2 and §5.7, §5.8, §5.14–§5.17. M3+ not started.

## What was built

| Area | Where |
|---|---|
| Scoped BFS crawler, robots/sitemap/well-known, passive fingerprinting | `backend/scopelens/checks/crawl.py` |
| Attack-surface map records | `backend/scopelens/domain/surface.py` |
| Collected-response records | `backend/scopelens/domain/collection.py` |
| Check engine + honesty invariants | `backend/scopelens/checks/engine.py` |
| 17 controls across C01/C02/C04/C05/C06/C07 | `backend/scopelens/checks/controls/` |
| Static report text per control | `backend/scopelens/writer/templates.py` |
| HTML/JSON report writer | `backend/scopelens/writer/report.py`, `report.html.j2` |
| Deterministic scoring `score-v1.0` | `backend/scopelens/scoring/score.py` |
| Findings + dedup | `backend/scopelens/domain/finding.py` |
| Analysis pipeline | `backend/scopelens/checks/analyze.py` |
| Dashboard API + SSE + retest | `backend/scopelens/api/dashboard.py` |
| Registry entries (17) | `checks_registry/controls/` |
| Migrations | `0003_m2_findings_scores.py` |

## Exit gate — measured

**Fixtures verified independently first** (`make labs-verify`, 38 assertions, all pass):
every control's vulnerable/fixed pair is demonstrated to differ rather than assumed to.

**Insecure fixture** (`make run` + scan of `labs-bad`, scan `b6eb236b`…):
`/api/scans/{id}/findings` returned 11 findings — 1 High, 2 Medium, 6 Low, 2 Informational.
The High is `SL-C05-FILES-01` on `/.env` with `evidence_status: confirmed`.

**Secure fixture** (scan of `labs-good`): **0 findings** at every severity, coverage 88.2%.
Nothing was reported as a pass without a trusted artifact behind it.

**Scoring determinism** — 23 unit tests reproduce every worked example in Spec §9.6 and §9.9
verbatim, plus the gates: `uv run pytest -q tests/unit/test_scoring.py` → 23 passed.

## Historical exit-gate claim — superseded by review corrections

The gate was reported as **not met** in the first pass and the blockers were recorded here
rather than glossed. They are now fixed and re-measured, so the original finding is kept below
as the record of what was wrong.

**Current, measured result:**

| Fixture | Verdict | Score | Coverage | Findings |
|---|---|---|---|---|
| `labs-bad` | **Weak observed posture** | **69**/100 | 100.0% | 12 (1 High, 3 Medium, 6 Low, 2 Informational) |
| `labs-good` | **Strong observed posture** | **100**/100 | 100.0% | **0** |

69 is the High cap doing its job: the raw score for the bad fixture would be higher, and
`HIGH_CAP = 69` binds because a High finding is unresolved. The good fixture's HTML report
contains the required empty-state sentence — `export.html` grepped for
`No issues found in the checks that completed` returns a match — followed by the coverage
figure and the qualifier that this is not a statement that the site is secure.

### What was wrong in the first pass, and the fix

1. **No score was published for either fixture** (`Insufficient coverage`, `null`).
   *Cause:* three separate defects, below.
2. **The TLS lane returned no measurement.** `SL-C01-TLS-01` reported
   `the TLS measurement lane produced no certificate for this origin`.

Four defects, in the order they were found:

* **The TLS call deadlocked inside the finalise transaction.** The lane authorizes a
  measurement by querying the database; the coordinator called it from inside phase 3's open
  transaction, so the lane waited on a row the supervisor held while the supervisor waited on
  the lane. It timed out at 20s and the control silently went unassessed. Fixed by taking the
  measurement in **phase 2, outside any transaction** — the same rule as §5.2's "never hold a
  transaction open across a worker call". This is the identical class of defect M1 recorded
  ("holding `FOR UPDATE` across an HTTP call"); it was reintroduced by M2 and is now fixed.
* **`getpeercert()` returns an empty dict when verification is off.** The lane connects with
  `verify_mode = CERT_NONE` on purpose — it exists to describe certificates that would fail
  verification — and Python returns `{}` for `getpeercert()` in that mode rather than the
  decoded certificate. The DER is still available, so `tls_lane.py` now parses
  `getpeercert(binary_form=True)` with `cryptography`. Measured before the fix: decoded `{}`,
  DER 915 bytes.
* **A control that reported a candidate was counted as unassessed.** `SL-C06`/`SL-C07`
  returned `potential` findings — a *successful* assessment — but `is_fully_assessed` treated
  them as outstanding, so their categories fell below the coverage gate and blocked the whole
  score. Fixed: a candidate counts as assessed (the check ran and concluded). This is separate
  from Spec §9.6, which still holds the overall at `Verification pending` for an unresolved
  **High/Critical** candidate.
* **A mandatory-control check silently did not apply**, so `SL-C01-REDIR-01` was still
  reported as an unassessed mandatory control after its N/A handling changed.

### A reading that changed, and why

In the first pass a properly evidenced `Not applicable` was **kept in the coverage
denominator**, and this was flagged for review. It has been changed to the literal reading of
Spec §9.7 — coverage is *fully-assessed **applicable** control weight / total **applicable**
weight*, and an evidence-backed N/A is by definition not applicable, so it leaves both sides.
It cannot inflate a score: a category whose controls are all N/A has no applicable weight left
and is removed from the overall as an evidence-backed fully-N/A category, not scored at 100%.
The change is what lets `SL-C01-REDIR-01` stop blocking C01, and it is called out here rather
than slipped in.

## Deliberate conservative readings (flagged, not silently chosen)

* **Blocked, errored, unreachable and un-reached controls stay in the coverage denominator.**
  Only an evidence-backed N/A leaves it. A control that could not run must never be able to
  raise coverage, which is the abuse Spec §9.7 is written against.
* **`SL-C06-COMPONENT-01` cannot assess CVE applicability** — this build has no advisory
  source, so it reports version disclosure as an Informational candidate and says so. CVE
  corroboration needs a feed and is not implemented.
* **`SL-C07-METHODS-01` and `SL-C05-SECRETS-01` return `potential`, never `confirmed`** —
  their registry stance (Spec §10.5, FLAG) does not permit a confirmation, and a potential
  High/Critical correctly holds the overall score at `Verification pending`.
* **robots `Disallow`-only paths are inventoried, never fetched**, while the bounded
  well-known-files probe *does* fetch its fixed paths. Reading of §5.7 recorded here.

## Commands run

```
make labs-verify          -> 38 assertions, PASS
make worker-image         -> worker rebuilt with the crawl module
make run                  -> 8 services up; /readyz {"status":"ready","schema_revision":"0003"}
POST /api/scopes + /api/scans (labs-bad)   -> 11 findings, 1 High confirmed on /.env
POST /api/scopes + /api/scans (labs-good)  -> 0 findings, coverage 88.2%
uv run pytest -q          -> 428 passed
uv run ruff check ...     -> All checks passed
uv run alembic upgrade/downgrade 0002/0003 -> round trip clean
```

## Defects found by running (not by reading)

1. **The crawler sent no egress token on inner requests.** The token reached the proxy on
   CONNECT but not on the request that followed, so the request hook denied all 11 — every
   URL came back `refused by the policy broker`. Caught only by running a real scan; the unit
   tests passed because they use a fake transport.
2. **`robots.txt` and `sitemap.xml` were fetched with relative URLs**, which httpx cannot
   resolve (`UnsupportedProtocol`).
3. **Header fingerprinting ran only for HTML responses**, so `Server` and `X-Powered-By` were
   ignored on every non-HTML route and a site with no HTML appeared to have no components.
4. **`C03` blocked the overall score** even when the profile deliberately excludes it. A
   profile-excluded category is now removed and the weights renormalised; a category that was
   planned and then not assessed still blocks, which is the distinction Spec §9.7 draws.
5. **The enum `ControlOutcome` was shadowed by the model of the same name** in
   `domain/check.py`, so every helper referencing `ControlOutcome.PASS` would have raised at
   runtime. Found by executing a helper, not by reading it.

## Not done in M2

* `docs/API_CONTRACT.md` (written, but the SSE example payloads are illustrative rather than
  captured from a live stream).
* The frontend (`frontend/`) is untouched per §0 rule 9.
* M3+ not started.

---

## Milestone ledger

| Milestone | State | Gate |
|---|---|---|
| M0 Foundation & labs | complete and approved | fresh-checkout flow verified end to end |
| M1 Execution & lifecycle | **complete and approved** | one real check through the broker; recovery/cancellation/containment measured on labs |
| M2 Deterministic scanner & reporting | **backend corrections complete and verified** | 524 tests; proxy containment; live lab reports and fixed/recurrent retests; dashboard frontend remains separately owned |
| M3 Browser & mature tools | **delivered and lab-verified** | 571 tests; real browser/tool/evidence gate; explicit partial testssl coverage |
| M4 Adaptive reasoning & Bash | not started | — |
| M5 Private v1 hardening & held-out evaluation | not started | — |

---

## M3 — Browser, mature tools and configuration pack (26 September 2026)

**Status: delivered; lab exit gate passed. M4 has not started.** Frontend source remains
unchanged; M3 delivers its typed API and evidence downloads for the separately owned dashboard.

### Delivered

- Durable browser context ownership and ordered action ledger (migration 0005), scope revision,
  expiry and cancellation epoch. DOM/accessibility navigation, disclosure controls and GET
  search forms; optional validated coordinate suggestions through the provider gateway.
- Separate Playwright worker with Chromium sandbox enabled, loop/action/state bounds, immediate
  redacted state/screenshot/network artifacts, and real browser-only endpoint discovery.
- Kali tool image; ZAP passive HAR import and four reviewed rules; one pinned Nuclei HTTP
  template; testssl protocol adapter in a separately admitted, serial TLS connection lane.
  Archive, template, base-image and measured worker-image identities are recorded.
- Scanner parser contracts for valid, empty, malformed, truncated, nonzero, timeout and cancel
  outputs. Tool severity/confidence/evidence are retained; tool matches remain candidates.
  Canonical/route matches link existing finding UUIDs and retain source evidence. Unmapped
  serious candidates hold the overall score at `Verification pending`.
- Conditional CORS/redirect configuration observations on reviewed lab endpoints, without
  off-site redirect following. Production approval list is empty. Full active proofs are M4.
- Shared durable request schedule/page cap and proxy response/concurrency bounds; upstream IP
  pinning at `server_connect`. New real canary cases caught and verified the connection-stage
  distinction and enforced body-transfer termination.
- Supervisor cancellation watcher independent of the Celery execution queue; incremental
  browser evidence survives a stopped worker. Full immutable image identities fit evidence
  metadata after migration 0006.
- Typed browser/scanner APIs, owned evidence download with hash verification, redacted SSE
  actions and HTML/JSON tool observations. See `docs/API_CONTRACT.md`.

### Commands and measured results

| Command | Result |
|---|---|
| `make run-m3` | Builds verified tools and isolated workers; starts labs/dev services with immutable worker image IDs |
| `uv run pytest -q --tb=short` | **571 passed**, no skips |
| `make lint` | Ruff checks/format and existing frontend TypeScript check pass; no frontend source edits |
| `make test-proxy` | Real mitmproxy canaries pass: denied/unavailable policy, raw CONNECT, unresolvable hostname with approved IP, body cap and slot release |
| `make verify-m3` | **Passed** on both owned fixtures; browser-only route, source/run/hash provenance, finding links and authenticated exports verified |
| `uv run python scripts/verify_m3_cancel.py` | Real browser cancellation: durable stop request committed in **0.018 s**, worker stopped in **0.423 s**, partial browser evidence retained |
| `make manifest` | M3 manifest, database schema **0006**, measured image/version bundle, 17 supported deterministic controls |

Final lab scan IDs:

- Good: `07464f5b-c4c3-4e4e-8584-447ae5e7dc09` — **0 findings**, **94.1%** control coverage,
  5 browser actions/states, no browser capture gaps; ZAP 0 alerts, Nuclei 0 alerts.
- Bad: `2c9cbc25-c816-456e-8956-4672128d70a6` — **12 findings**, **88.2%** control coverage,
  9 browser actions/states, no browser capture gaps; ZAP 4 alerts, Nuclei 1 alert. Scanner
  duplicates link the existing findings and preserve provenance; they do not add deductions.
- Both: `/browser-only.json` was reached by browser interaction and absent from HTTP-only
  discovery. Both configuration probes produced paired synthetic-origin observations.
- Cancellation scan: `357a3427-44cc-4174-90d6-1d9b5a18d06e`. The 0.018 s figure measures API
  cancellation commit; the 0.423 s figure measures disappearance of the real worker. These
  are separate measurements, not a claim that every network device was observed at 0.018 s.

Logs and redacted exports: `runs/m3-verification/` (ignored runtime artifacts). Tool/image pins:
`checks_registry/tooling/releases.json`, `runtime.json`, Dockerfiles and `release_manifest.json`.
No source commit exists; the manifest keeps that value unknown.

### Limits that remain explicit

The fixture scans finish as **`completed_partial`** because testssl reports unsupported
proxy-mode NPN/ALPN measurements and unavailable local GOST-engine support. SSL/TLS protocol
measurements ran, including TLS 1.2 and 1.3; the skipped portions are not presented as passes.
These tool observations do not add supported controls or inflate coverage. Both overall scores
remain withheld under the established M2 coverage rules.

The optional provider foundation has contract tests and no live provider qualification. No
paid model call is claimed. Generated scripts, the stronger VM boundary, adaptive reasoning,
full active proof rules, and full provider/fallback contracts remain M4; pilot/release
hardening remains M5. M3 is an owned-lab verification, not a production pilot approval.

### Defects found during implementation

Real runs exposed the Chromium namespace syscall requirement, ZAP importer option/version
mismatch, missing testssl dependencies, premature browser-response capture and duplicate
fragment-triggered actions, command-line-only/DNS connection assumptions, queued cancellation
behind a busy executor, and the evidence image-ID field length. The fixes and retained
limitations are recorded in Q-14 and Q-17 of `OPEN_QUESTIONS.md`.

## M4 backend integration and M5 operational work — 26 September 2026

The operator expanded the task to the entire Phase 1 backend and subsequently excluded further
UI work. The following implementation is measured; this entry **does not sign off the complete
Phase 1 release**, because the independent held-out corpus, live provider qualification and
owned-site pilot remain open.

### Implemented

- LangGraph baseline → observe → plan → admit → execute → verify loop. Baseline includes TLS
  before adaptive work. Hypotheses are durable; an admitted lost outcome is not replayed.
  Exact observed URLs are deduplicated, including redirected aliases, while distinct query
  variants remain separate observations. Model proposals select reviewed candidates only.
- Configurable planner, browser, verification, script and report roles. Strict schemas,
  approved fallback, context/output limits, a shared atomic call/cost ledger, unknown usage
  accounting, refusal handling and template fallback. Transport is deliberately non-streaming
  JSON; unexpected tool calls/incomplete output are rejected rather than executed.
- Paired reflected XSS marker execution, HTML marker rendering, repeated non-timing SQL
  comparisons, open-redirect inspection and CORS configuration proof. Baselines, negative
  controls, unique browser nonces and inconsistent-result abstention are enforced. Separate
  active input locations keep independent remediation/deduction identities.
- Dedicated Lima/VZ VM for generated Python/Bash. No host mounts or direct network; transient
  unprivileged systemd execution with resource/time/output limits. Optional lab-only stdio RPC
  goes through the existing proxy/token/budgets. Generated output cannot confirm a finding.
- Hash-verified curated skills. Remote MCP remains optional and disabled.
- Evidence encryption, expiry/download handling, retention with metadata preservation, encrypted
  metadata/evidence backup and non-destructive restore. Bootstrap generates an encryption key
  for new installations without printing it. Existing installations retain their own key.
- Evaluator protocol, artifact retrieval/hash checks, active proof replay, case matching,
  abstentions, counts/Wilson intervals and a baseline/adaptive comparison runner.
- Frozen backend deployment using immutable image IDs, with source mounts removed. The API,
  policy, dispatcher, supervisor, model gateway, TLS lane and proxy were inspected in this mode.

### Commands and measured results

| Command | Result |
|---|---|
| `uv run pytest -q --tb=short` | **605 passed**, no skips (`runs/phase1-tests-final3.log`) |
| `make lint` | Ruff, format and existing frontend typecheck pass (`runs/phase1-lint-final3.log`) |
| `make test-proxy` | Real proxy canaries pass (`runs/phase1-proxy.log`) |
| `make verify-proxy-live` | Real token cannot tunnel to Redis/Postgres (`runs/phase1-proxy-live.log`) |
| `make run-m4`; `make freeze-release`; `make run-release` | Built, frozen and healthy; no runtime source mounts; source fingerprint matches (`runs/release/`) |
| `make verify-m4` on the frozen deployment | Both paired lab scans pass all active assertions and report export checks (`runs/phase1-final-labs.log`) |
| `make verify-sandbox` | Python/Bash, host/control access denial, output cap, deadline and ignored 900 KB stdin pass (`runs/phase1-sandbox.log`, `runs/m4-verification/sandbox.json`) |
| `make verify-sandbox-rpc` | Allowed lab request, Redis refusal, three-request cap and revoked capability pass; output untrusted (`runs/phase1-sandbox-rpc.log`) |
| Real authenticated supervisor → host gateway → VM call | Completed in **0.241 s**, ignored large input, returned `trusted=false` |
| `uv run python scripts/verify_adaptive_cancel.py --scope-id …` | Real adaptive worker: old token rejected in **0.018 s**, workers gone in **0.404 s**, score withheld and partial evidence retained (`runs/m4-verification/adaptive-cancel.json`) |
| `uv run python -m evaluation.run --scope-id … --output runs/comparison-final` | Same immutable scope/budgets: baseline **74** requests, adaptive **82**; **16 confirmed findings** each; **4** corroborating follow-ups, no measured recall gain |
| `uv run python -m evaluation.run --manifest evaluation/protocols/active-development.yaml --reports runs/m4-verification --output runs/evaluation-final` | **5 TP, 5 TN** after proof replay. Release gate correctly **fails** for split, sample size and independence |
| `make retention-plan` plus DB/API retention test | Real store dry run: 0 expired objects; test proves running evidence preserved, terminal evidence deleted, metadata retained and download returns 410 |
| `scripts/backup_restore.py backup …` then `restore … --database scopelens_restore_phase1_final --evidence-dir runs/restore/phase1-final` | Encrypted backup restored into a new DB/directory: **46 scans, 277 findings, 1448 evidence rows, 2580 audit events**; execution not started |
| `make qualify-models` | Exits **2**, all roles unavailable because unconfigured. This is an unmet external qualification, not a passing test |
| `make manifest` | Schema 0006; 17 previously enabled controls, five experimental controls with verified pairs; M4 runtime and open release qualification recorded |

Final paired lab scans:

- `labs-good`: `aa1a576d-0856-49af-9d9f-e9454b924a58`, **0 findings**, **95.5%** coverage.
- `labs-bad`: `085ab165-ab93-4f57-965d-2f7f3f9710b4`, **17 findings**, **90.9%** coverage.
- All five active checks pass on good and confirm their named condition on bad. Four CSP
  follow-ups corroborate observations on distinct URLs (including a search-query variant).
- Both have real HTML/JSON and category scorecards. Overall score is **withheld**: C06 has no
  advisory snapshot; bad also has an unresolved method-exposure candidate in C07. The testssl
  NPN/ALPN/GOST limitations remain visible as partial tool coverage.
- VM runtime measured separately: Lima **2.2.0**, Python **3.14.4**, Bash **5.3.9**, guest kernel
  **7.0.0-28-generic** (`runs/release/sandbox-runtime.json`). Backend/worker Python remains 3.12.

### Release limitations

The five active controls remain experimental. Ten development cases, used while fixing the
implementation, cannot satisfy the proposed 30-positive/60-negative per-family, three-group
held-out criterion. The evaluator records this failure, and no independent accuracy claim is
made. The comparison measures extra corroboration and cost; it does not establish improved
recall. Model fallbacks were tested with controlled clients; no hosted provider was configured
or qualified. No external site was scanned. A supplied, authorized pilot and final production
worker-boundary validation remain necessary before private production release.

The running API and dedicated sandbox gateway remain available locally. Temporary verification
scan intents were cancelled and their evidence retained. No source commit was created.


## Validation and owned-site pilots — 26 September 2026, follow-up

This entry supersedes the earlier statement that no target had been supplied. The operator
explicitly supplied staging SlicerNinja, Arkyon and Rekvon. All were registered with exact
production scopes. Rekvon's HTTPS origin was registered after observing its HTTP redirect.
The active input pack remains lab-only in these runs; these are configuration-profile pilots.

| Verification | Result / retained evidence |
|---|---|
| `uv run pytest -q` | 645 passed, zero skipped; `runs/final-backend-tests.log` |
| Independent active validation, 26 cases | 13 TP, 12 TN, 0 FP, 0 FN, 1 negative abstention; `runs/validation-active-after-2/` |
| `make test-proxy` | CONNECT/raw TCP, body caps, conflicting Host and 15-request HTTPS reuse; `runs/proxy-host-fixed.log` |
| `make verify-proxy-live` | Redis/Postgres refused, real allowed fixture body fetched; `runs/proxy-live-final.log` |
| OSV snapshot refresh | 121 records, eight selected npm packages, paginated retrieval receipts and SHA-256; `runs/advisory-refresh.log` |
| `scripts/run_owned_pilot.py` on frozen images | All three HTML/JSON reports in `runs/owned-pilot-v3-20260926/`; crawler errors zero |

| Target | Scan | Findings | Completed-control coverage |
|---|---|---:|---:|
| stage.slicerninja.com | 3012aa0e-068c-44e8-a75c-c5266058b733 | 5 Low | 17.6% |
| arkyon.dev | 4f1c3584-8b27-467f-8c25-f641901adf33 | 5 Low | 11.8% |
| rekvon.in (HTTPS) | a2619541-cd03-412b-9b05-839e087fc3fe | 5 Low | 82.4% |

Findings concern HSTS, CSP, frame protection, Referrer-Policy and nosniff. They do not establish
active injection vulnerabilities. Reports retain authentication-required/blocked instances,
rendering gaps, missing component mapping/version evidence and testssl limitations. Overall
scores remain withheld by the existing category gates. Staging's browser reaches app routes;
login, signup, contact, payment and other unapproved state-changing forms are not submitted.

Runtime fixes: repeated SQL comparisons now cover three query contexts; unavailable active
routes abstain; browser/controller action caps agree; third-party failures no longer become
missing target routes; browser redirect metadata survives missing redirect bodies; settling
failures retain visible DOM. Public CDN rotation retains the original validated destination,
while private rebinding remains denied. The proxy releases stalled flows and correctly reuses
pinned upstream connections without changing HTTP Host or TLS SNI. A conflicting Host test
failed before the authority check and passes afterward. See `VALIDATION_PROGRESS.md`.

The new validation set informed fixes and is marked contaminated. It is not the held-out gate.
The eight-package advisory corpus is deliberately limited, and version matches stay potential.
Live provider qualification remains blocked on local `.env` configuration; no provider was
silently selected. Held-out evaluation and final production boundary qualification remain open.
No frontend source was changed during this follow-up.

## Continued backend completion — 26 September 2026

### New measured work

- `make test`: **664 passed, zero skipped**, `runs/backend-final-20260926.log`.
- `uv run ruff check backend evaluation scripts tests deploy/worker_vm` and format check pass.
- `make verify-proxy-live`: excluded query/encoded paths deny for the exact scope reason;
  the permitted fixture still returns its body. `runs/proxy-path-live-final.log`.
- `uv run python scripts/verify_juice_shop.py --output runs/juice-development-20260926`:
  independently health-checked local Juice Shop product search gives a confirmed SQL finding;
  reviewed CORS reflection check passes. Actual HTML/JSON and the partial browser outcome
  are retained. This is source-inspected development evidence, not holdout.
- `make verify-worker-vm`: dedicated daemon, mutual TLS, no shared host folders, isolated
  scratch, blocked peer listener, denied direct egress, positive proxy response and worker
  cancellation. Tested again after reboot. The initial peer-connection failure was fixed by
  explicitly enabling bridge netfilter; its failed log remains in `runs/worker-vm-activate.log`.
- `uv run python scripts/verify_m4_lab.py --output runs/worker-vm/paired-labs`: 0 findings
  on fixed / 17 on vulnerable; all five active outcomes match, with real browser states and
  adaptive corroboration. Runs `156fc93d-44b3-4c85-9600-0e42fc58912c` and
  `c086ecdb-9eac-4fbb-96ce-9704272dd5eb`.
- `uv run python -m scripts.verify_m3_cancel --source-scan 156fc93d-44b3-4c85-9600-0e42fc58912c --worker-vm --output runs/worker-vm/browser-cancel.json`:
  actual browser cancellation commits in **0.026 s**, stops in **0.267 s**, retains partial
  evidence and withholds the cancelled scan's score.
- Live provider qualification attempted with the current `.env`: all attempted roles
  unavailable; no configured provider call or paid qualification is claimed.

### Defects preserved in the record

Path query/encoding exclusion bypass; missing browser completion on worker interruption;
cross-worker connection bypass before bridge filtering; and a platform-specific Chromium
SIGILL on the new ARM VM. The latter reproduced on staging. Disassembly showed an SVE `cntd`
instruction on a guest advertising SME without SVE. Provisioning now applies `arm64.nosme`;
the same browser diagnostic then completed with two captured states and no SIGILL. Browser
sandboxing and seccomp remain on. See `WORKER_VM.md` and `VALIDATION_PROGRESS.md`.

`make run-worker-vm` is the final-deployment command; `make run-release` remains the earlier
Docker Desktop development topology. The supervisor no longer receives the Docker Desktop
socket when the worker-VM override is applied. Other projects' containers were left alone.

Final staging deployment run: `4f655c2e-beed-45a0-b02c-2a1db8749807`, artifacts at
`runs/owned-pilot-worker-vm-final-20260926`. 39 crawled pages / 0 crawler errors, browser
completed with 3 states / 6 actions, 5 Low configuration findings, 17.6% completed-control
coverage. HTML/JSON exports are real; the overall score remains withheld. Earlier crashing run
`8d0d3a02-92ff-4667-a2c5-11c56648aa1a` is retained separately. Final boundary repeat after
the ARM fix: `runs/worker-vm-sme-boundary.log`.

The final local production-worker boundary gate is met on this recorded deployment. Still
open: live provider compatibility and the independent held-out benchmark. The five active
controls remain experimental. Phase 1 release sign-off is not claimed.

## Live provider integration — 26 September 2026

Operator supplied permission to use the existing local OpenAI or Command Code key. Command
Code authentication succeeded; the ignored `.env` now selects `zai-org/GLM-5.3` for planner,
verification, report writer and script proposal, and `z-ai/glm-5.3-flash` for browser images.
Keys were not copied into source or evidence. The OpenAI key was not needed.

`make qualify-models` passes all five synthetic roles, including a real rendered screenshot
with an independently checked button rectangle. `checks_registry/model_qualification.json`
records usage, configuration, prompt version and adapter hash. The manifest accepts only
matching adapter/configuration evidence. This is a development compatibility test, not a
quality comparison between model vendors.

Defects found in the live integration:

1. Default reasoning caused Flash verification/script requests to exceed the existing
   30-second timeout. Added optional per-role `reasoning_effort`; low-effort GLM-5.3 text
   requests and Flash screenshot requests passed. The initial failures are retained in
   `runs/model-qualification-initial.json`.
2. A browser `{}` response was instructed by the prompt but rejected by the coordinate
   schema. It now records `abstained` without a fallback attempt or proposed click.
3. A schema failure discarded known usage at the aggregate level. Known costs are now
   preserved; missing usage remains unknown.
4. The coordinator published terminal status before report enrichment finished. It now
   commits evidence, enters `reporting`, revokes target egress, enriches outside a DB
   transaction with the heartbeat running, then settles. Integration tests check a separate
   NOWAIT row lock, live lease/running task during enrichment and cancellation winning over
   completion. Existing recovery and cancellation suites remain green.

Verification: `make test` → **671 passed, no skips** in
`runs/backend-provider-final-20260926.log`; Ruff check/format pass.
`runs/model-provider-labs-20260926` contains a complete paired run: zero findings on good,
17 on bad, all five active checks respectively pass/confirm. Real generated scripts ran in
the dedicated sandbox VM on both scans and stayed `trusted=false`, `network=none`.
The bad scan used live planning, verification and report rewriting. That first paired run
exposed defect 4; its early exports are retained as pre-fix evidence, not final prose proof.

Post-fix deployed repeat:

```
uv run python scripts/verify_m4_lab.py --fixtures labs-bad --require-models \
  --output runs/model-provider-final-lab-20260926
```

Passed. Scan `0f260833-2e7c-4286-94c7-59fb825cdb51` moved through queued → testing →
reporting → completed_partial. All five active controls confirmed the expected lab conditions;
17 findings, 4 completed planner calls, 4 verification calls, a completed generated script,
and 16 model-written explanations. One writer response failed validation and retained its
static template; a malformed browser response produced no model-selected click. All 27 calls
were settled at terminal status, all had known token usage, estimated total $0.05222595 at the
configured rates. This is not the provider invoice. The generated analysis remained untrusted
and had no network. Final reports and the machine-readable integration summary are in that
output directory. Synthetic screenshot selection separately passed. Failures were retained;
no claim of perfect provider reliability is made.

The dedicated-worker VM override remains active after deployment. The only outstanding
release qualification listed in `COMPLETION.md` is the independent held-out benchmark.
The five active controls remain experimental until that gate is met.
