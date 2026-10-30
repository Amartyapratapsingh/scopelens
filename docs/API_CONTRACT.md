# ScopeLens API contract

The contract the dashboard depends on (Build Plan §5.17). Every endpoint is typed in
`/openapi.json`. Dashboard regressions are exercised by `tests/integration/test_dashboard_api.py`; auth, scope and scan lifecycle tests live in their corresponding integration modules.

Base path `/api`. All endpoints except login require the operator session cookie.
Errors use the standard FastAPI shape: `{"detail": "..."}`.

**A note on 404 vs 403.** A resource belonging to another operator returns **404**, never 403.
A 403 would confirm that the id exists.

---

## Authentication

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/auth/login` | `{"username","password"}` → sets the session cookie |
| `POST` | `/api/auth/logout` | Clears the session |
| `GET` | `/api/auth/me` | The signed-in operator |

## Scopes

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/scopes` | List scope versions |
| `POST` | `/api/scopes` | Register a scope version |
| `GET` | `/api/scopes/{id}` | One scope version, with its authority |

Scope registration accepts `authority_domain` (`production` or `lab`), `lab_service` and
`lab_port` when lab authority is selected. **A production scope can never select lab
authority** — production and lab inputs are distinct validated request variants.

Optional `transport_http_port` on an HTTPS scope approves exactly one HTTP GET `/` on the same host. Redirect destinations are inspected but not followed. Lab ports must be allowed by the named binding. Missing approval leaves the redirect check unassessed.

## Scans

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/scans` | List scans |
| `POST` | `/api/scans` | `{"scope_version_id"}` → queue a scan |
| `GET` | `/api/scans/{id}` | Scan detail (status, tasks, budget) |
| `POST` | `/api/scans/{id}/cancel` | Cancel: revoke admissions, stop the process group, keep partial evidence |

Cancelling a queued scan that has no task, coordinator lease or execution history returns `cancelled`
immediately, with `status_reason: "cancelled before dispatch"`, a finish timestamp and
a `scan.cancel` audit row in the same transaction. This also settles an older queued
intent that already has a cancellation timestamp. No worker-stop notification is needed
for such an intent. Repeating cancellation of a terminal scan returns its existing state.
Reconciliation settles queued scans with a positive cancellation epoch and no lease,
recording `scan.reconcile` with outcome `cancelled`. The dispatcher consumes terminal
scan notifications without launching execution. Cancellation notifications for terminal
scans with task, lease, start or historical dispatch records still reach the supervisor
to stop existing workers. Consumed execution notifications audited as skipped do not
count as historical dispatch.

## Dashboard

| Method | Path | Returns |
|---|---|---|
| `GET` | `/api/scans/{id}/summary` | Verdict, score, coverage, severity counts |
| `GET` | `/api/scans/{id}/findings` | Findings, filterable |
| `GET` | `/api/findings/{id}` | One finding, with report text |
| `GET` | `/api/scans/{id}/categories` | **All 12** category tiles |
| `GET` | `/api/scans/{id}/hosts` | Host inventory |
| `GET` | `/api/scans/{id}/export.json` | JSON export (redacted) |
| `GET` | `/api/scans/{id}/export.html` | HTML report (escaped, redacted) |
| `GET` | `/api/scans/{id}/events` | SSE progress stream |
| `POST` | `/api/findings/{id}/retest` | Queue a fresh scan against the finding's scope |

### Finding filters

`GET /api/scans/{id}/findings` accepts repeatable query parameters. Each is an **exact match**
against the enum value, not a substring search:

| Parameter | Values |
|---|---|
| `severity` | `critical` `high` `medium` `low` `informational` |
| `confidence` | `high` `medium` `low` |
| `evidence_status` | `confirmed` `potential` `inconclusive` |

```
GET /api/scans/9f.../findings?severity=high&severity=critical&evidence_status=confirmed
```

### Example — `GET /api/scans/{id}/summary`

```json
{
  "scan_id": "3e1a91b5-8896-4aa2-bd41-1986ef2c9d26",
  "target_origin": "https://172.28.0.11:8443",
  "profile": "external-configuration",
  "status": "completed",
  "status_reason": "HTTP crawl completed; captured endpoints, responses and discovery gaps",
  "created_at": "2026-09-25T17:10:34.092167Z",
  "started_at": "2026-09-25T17:10:34.654294Z",
  "finished_at": "2026-09-25T17:10:35.256782Z",
  "findings_count": 12,
  "verdict": "Insufficient coverage",
  "overall_score": null,
  "overall_state": "insufficient_coverage",
  "overall_reason": "every applicable category must meet its gate before an overall score is published; a blocked or insufficiently assessed category is never dropped to improve the average (Spec \u00a79.7)",
  "overall_label": "External configuration assessment pilot score \u2014 uncalibrated. Not a whole-website security rating.",
  "coverage_percent": 88.2,
  "severity_counts": {
    "critical": 0,
    "high": 1,
    "medium": 4,
    "low": 6,
    "informational": 1
  },
  "score_version": "score-v1.0"
}
```

`overall_score` is `null` whenever the gates are not met, and `overall_reason` says which gate.
The dashboard must render the reason rather than a zero (Spec §9.4).

The summary also includes `discovery`, which is `null` until a crawl artifact exists.
When present it contains `pages_fetched` and nullable `stopped_by`, for example
`{"pages_fetched": 110, "stopped_by": "crawl time budget reached (120s)"}`.
These fields describe captured crawl progress, not vulnerability coverage. The dashboard
loads `/api/scans/{id}/hosts` separately to show discovered hosts, evidence, and the
distinction between the assessment target and inventory-only hosts. A discovered hostname
does not become an assessed target automatically.

### Example — a finding (`GET /api/findings/{id}`)

```json
{
  "id": "2a0f1c9b7d4e5f60",
  "check_id": "SL-C05-FILES-01",
  "canonical_control": "exposure.sensitive_files",
  "root_cause": "sensitive-file-exposed",
  "category": "C05",
  "category_title": "Data exposure and privacy",
  "title": "A well-known sensitive path is served to any visitor",
  "severity": "high",
  "evidence_status": "confirmed",
  "confidence": "high",
  "confidence_reasons": [
    "/.env contains file-specific assignment syntax, distinct from the negative-control response",
    "Missing or truncated required paths do not complete coverage; raw secret values are redacted"
  ],
  "status": "open",
  "retest_state": null,
  "locations": [
    {"route": "/.env", "parameter": null, "header": null,
     "detail": "served with HTTP 200, 2160 byte(s), content-type text/plain"}
  ],
  "evidence_refs": ["3f8c1e..."],
  "what": "A file that should never be reachable is served to any visitor ...",
  "why": "Files like these typically contain exactly what an attacker needs next ...",
  "fix": "Remove the files from the web root ...",
  "references": ["https://owasp.org/www-project-web-security-testing-guide/v42/"]
}
```

`what` / `why` / `fix` come from a static per-control template (`writer/templates.py`) and are
always present. No model is involved, and no weaponized payload appears in any field.

### Example — a category tile (`GET /api/scans/{id}/categories`)

All twelve tiles are always returned. A tile outside the profile carries a reason, never a
substituted `0` or `100`:

```json
[
  {
    "category": "C01", "title": "Transport and encryption", "weight": 15,
    "in_profile": true, "state": "insufficient_coverage", "score": null,
    "coverage_percent": 50.0,
    "reason": "mandatory control(s) not fully assessed: SL-C01-TLS-01",
    "caps_applied": [], "confirmed_counts": {}
  },
  {
    "category": "C08", "title": "Authentication", "weight": 0,
    "in_profile": false, "state": "not_assessed", "score": null,
    "coverage_percent": 0.0,
    "reason": "Not assessed in this profile",
    "caps_applied": [], "confirmed_counts": {}
  }
]
```

### Example — host inventory (`GET /api/scans/{id}/hosts`)

The existing `host`, `role`, and `evidence` fields remain unchanged. Rows also carry
`sources` (`crawl`, `link`, `certificate-transparency`, `dns`), `observations`
(`source`, `provider`, UTC `observed_at`, `wildcard`), `dns_status` (`resolvable`,
`unresolved`, `unavailable`, `not_checked`), `dns_addresses`, and nullable
`dns_observed_at`. DNS addresses are observations, never approved destinations.
Wildcard certificate names describe certificate coverage, not an enumerated live host.
Only the approved primary origin has role `primary`; every CT-discovered host retains
`inventory_only`, including names that resolve or match an owned-domain setting.

The control-plane coordinator queries the approved origin's registrable domain through
fixed CT and public DNS providers. The pinned Public Suffix List includes private suffixes.
Source responses, time, host count and resolution rate are bounded. A cached snapshot is
saved as supervisor evidence and scan metadata; dashboard reads and exports perform no
network I/O. No target HTTP request or vulnerability coverage is earned by CT/DNS inventory.
Lab/IP origins skip public discovery. `SCOPELENS_PASSIVE_DISCOVERY_ENABLED=false` disables
collection. It is enabled by default for production-origin assessments.

JSON exports include `host_discovery` with `version`, `registrable_domain`, `observed_at`,
`state`, `coverage_notes`, `target_http_requests` (zero), and `dns_provider`. States are
`complete`, `partial`, `source_unavailable`, `not_applicable`, and `not_run` for older scans.
An unavailable source is a recorded gap; an empty inventory is not complete enumeration.

```json
[
  {"host": "172.28.0.11", "role": "primary",
   "evidence": "the registered scope origin; the only host actively tested in this profile"},
  {"host": "cdn.example.com", "role": "inventory_only",
   "evidence": "subresource on /"}
]
```

Only `primary` is tested. `inventory_only` hosts are listed and are **not** assessed
(Spec §7.2).

---

## SSE progress stream

`GET /api/scans/{id}/events?cursor=<n>`

`Content-Type: text/event-stream`. `cursor` is the last `id:` the client received; omit it to
start from the beginning. Native EventSource reconnects may send `Last-Event-ID`; the larger of that header and the query cursor is used. Invalid or negative header values return 400. The cursor is the audit row's monotonic `seq`. Same-scan event insertion is serialized through transaction commit so a later committed event cannot skip an earlier uncommitted one. Clients should tolerate delivery replay around disconnects and deduplicate by id.

Every frame carries `id:` (the cursor), `event:` (the type) and `data:` (a JSON object). Data
is redacted and constructed field by field — raw worker stdout, graph state and secrets never
appear on the stream.

The stream closes after 500 events with a `stream.limit` event, so the client reconnects on a
fresh cursor rather than holding one connection open indefinitely.

### Event types

Only these audit actions are streamed. It is an **allowlist**: a new action is not streamed
until someone decides it should be.

| `event:` | Emitted when | Example `data:` |
|---|---|---|
| `scan.create` | A scan is queued | `{"cursor":41,"at":"2026-09-24T21:45:39Z","type":"scan.create","scan_id":"b6eb…","action":"scan.create","outcome":"queued","status":"queued"}` |
| `task.admit` | The coordinator admits the task and issues the egress capability | `{"cursor":42,"type":"task.admit","scan_id":"b6eb…","action":"task.admit","outcome":"admitted","task_state":"testing","status":"testing"}` |
| `broker.admit` | The broker decides one request | `{"cursor":47,"type":"broker.admit","scan_id":"b6eb…","action":"broker.admit","outcome":"allowed","method":"GET","route":"/robots.txt","allowed":true}` |
| `outbox.dispatch` | The outbox dispatcher hands work to Celery | `{"cursor":43,"type":"outbox.dispatch","scan_id":"b6eb…","action":"outbox.dispatch","outcome":"dispatched","logical_id":"scan:b6eb…:crawl:1"}` |
| `evidence.record` | A trusted artifact is stored | `{"cursor":52,"type":"evidence.record","scan_id":"b6eb…","action":"evidence.record","outcome":"recorded"}` |
| `score.ready` | Analysis finished; the verdict is final | `{"cursor":61,"type":"score.ready","scan_id":"b6eb…","action":"score.ready","outcome":"insufficient_coverage","verdict":"Insufficient coverage","coverage_percent":76.5,"status":"completed"}` |
| `task.settle` | The task reaches a terminal state | `{"cursor":62,"type":"task.settle","scan_id":"b6eb…","action":"task.settle","outcome":"succeeded","task_state":"succeeded","status":"completed"}` |
| `scan.cancel` | A cancellation was requested or took effect | `{"cursor":64,"type":"scan.cancel","scan_id":"b6eb…","action":"scan.cancel","outcome":"cancelled","reason":"operator requested"}` |
| `scan.reconcile` | The reconciler acted on an orphan or stale lease | `{"cursor":70,"type":"scan.reconcile","scan_id":"b6eb…","action":"scan.reconcile","outcome":"outcome_unknown","reason":"lease expired mid-attempt"}` |
| `retest.request` | A retest scan was queued for a finding | `{"cursor":81,"type":"retest.request","scan_id":"c1a2…","action":"retest.request","outcome":"queued","finding_id":"2a0f1c9b7d4e5f60"}` |
| `retest.complete` | Fresh assessment settles the original finding | `{"cursor":82,"at":"2026-09-25T17:10:38Z","type":"retest.complete","scan_id":"c1a2…","action":"retest.complete","outcome":"fixed","finding_id":"2a0f1c9b7d4e5f60"}` |
| `stream.limit` | The connection hit its event cap and the client should reconnect | `{"reconnect": true}` |

Note `score.ready` is emitted **after** the findings it summarises, so a client that renders on
that event has the full picture.

### Raw frame example

```
id: 61
event: score.ready
data: {"cursor":61,"at":"2026-09-24T21:46:00.812Z","type":"score.ready","scan_id":"b6eb236b-dc52-4dc3-b682-a47393f84620","action":"score.ready","outcome":"insufficient_coverage","verdict":"Insufficient coverage","coverage_percent":76.5,"status":"completed"}

```

---

## Retest

`POST /api/findings/{id}/retest` → `202`

```json
{
  "finding_id": "2a0f1c9b7d4e5f60",
  "scan_id": "c1a2b3d4-…",
  "scope_version_id": "7e…",
  "state": "requested",
  "detail": "a fresh scan was queued against the same scope; the finding stays open until that scan reaches the location and reaches a conclusive outcome"
}
```

A retest is a **new scan**, not a re-read of stored data — Spec §9.8 requires a fixed issue to
be closed by a successful relevant retest, which means fresh evidence. Completion reconciliation closes a finding only after a conclusive successful check of its original locations. The request endpoint itself never closes one. If the retest is blocked by the broker, the location was not reached, so the
finding **stays open**: an endpoint that could not be reached is not an endpoint that was
fixed.

---

## Export

| Format | Media type | Notes |
|---|---|---|
| `export.html` | `text/html` | Self-contained. Jinja2 autoescape on; the template uses no `\|safe`. All target-derived text renders as text. |
| `export.json` | `application/json` | The same structured data. Redacted identically — a JSON file is a file a person opens. |

Both set `content-disposition: attachment`.

The report's empty state is fixed by Spec §9.3: a scan with no findings renders
**"No issues found in the checks that completed"** together with the coverage figure, plus an
explicit qualifier that this is not a statement that the site is secure. The word "secure" is
never used as a verdict, and the overall label is always *"External configuration assessment
pilot score — uncalibrated. Not a whole-website security rating."*


### M2 contract details added during review

- `retest_state`: `requested`, `fixed`, `still_present`, or `incomplete`. Repeating a request while one is pending returns 409. Confirmed recurrence reopens a resolved finding. Failed, cancelled, blocked, missing-capture and normalized-only locations cannot establish a fix.
- JSON export includes `assessment_plan`: the frozen registry, sampling rule, optional advisory snapshot, discovered instances and capture-manifest reference. Each check outcome includes required/completed instances and incomplete reasons, plus proof references.
- `ProgressEvent` defines the SSE data fields in the OpenAPI operation's `x-sse-event-schema`. Common fields are cursor, at, type, scan_id, action and outcome. Optional fields are status, task_state, finding_id, reason, verdict, coverage_percent, method, route, allowed and logical_id. Only applicable fields are emitted; examples above are illustrative, not fields guaranteed on every event.
- All findings retain captured proof references. The capture manifest links actual response artifacts, scope and TLS records; worker stdout remains a separate untrusted observation.

## M3 additions (26 September 2026)

All routes below require the existing operator session. Unknown or foreign scan/evidence IDs
return 404. Models are included in `/openapi.json`.

### `GET /api/scans/{id}/browser` → `BrowserView`

```json
{"context_id":"cdbef01c-410c-4e0b-a3eb-9c5356bf6cc3","role":"unauthenticated","status":"completed","actions":6,"states":6,"gaps":[],"evidence_refs":["5f3f7ff7-1584-44de-9c36-dcf8ba54d311"],"limitations":["Unauthenticated read-only exploration"]}
```

An unstarted browser returns `context_id: null`, `status: "not_tested"`, zero counts and no
references. Counts reflect captured work, not estimated completion. The full limitation list
also identifies blocked cross-origin resources/WebSockets/service workers, cancelled downloads,
closed popups, and the configured-provider requirement for coordinate suggestions.
Completed browser stages report `completed`; interrupted/failed stages report `incomplete`
and retain their gaps and captured states. A terminal scan cannot report an `active` browser.
The durable context lease is closed independently of whether exploration completed.
Gap objects preserve JSON metadata, including bounded `pending_requests` arrays,
numeric `pending_request_count` and boolean `pending_metadata_limited`. These values
describe incomplete navigation; they are not coerced to strings or discarded.

### `GET /api/scans/{id}/scanners` → `ScannerResult[]`

```json
[{"tool":"nuclei","version":"3.11.1","state":"completed","errors":[],"assessed_rule_ids":[],"output_hash":"<sha256>","template_hash":"<sha256>","observations":[{"tool":"nuclei","tool_version":"3.11.1","rule_id":"scopelens-csp-observation","title":"HTML response without enforced CSP","reported_severity":"info","reported_confidence":null,"locations":["https://example.test/"],"evidence":"redacted observation","evidence_refs":["5f3f7ff7-1584-44de-9c36-dcf8ba54d311"],"status":"potential","mapped_control":"SL-C04-CSP-01","finding_id":null,"output_hash":"<sha256>"}]}]
```

States: `completed`, `partial`, `error`, `timeout`, `cancelled`, `not_tested`. An empty alert
list does not independently prove coverage. `assessed_rule_ids` records completed testssl
inventory measurements and excludes WARN/FATAL diagnostic IDs. An ID is not a passing
canonical control. Native ALPN/NPN observations are informational negotiated-handshake
inventory through the same admitted TLS connection gate. Unsupported/failed handshakes
remain explicit gaps; they do not establish pass or N/A.
Reported tool severities remain unchanged. A mapped observation links an existing finding only
when control and affected route agree; its source status remains `potential`. Unmapped serious
evidence-backed candidates hold the overall score at `Verification pending`. Observations,
errors and source versions appear in HTML and JSON exports, separately from verified findings.

For `external-configuration`, the empty conditional pack is deliberately outside the profile.
Its scanner state remains `not_tested`, with an empty error list and
`not_in_profile_controls: [{"check_id":"SL-C04-CORS-01","state":"not_in_profile","reason":"Not in profile"}, ...]`
covering the five omitted active controls. The JSON report also lists these records in
`out_of_profile_controls`; HTML labels each one **Not in profile**. These are exclusion
metadata, separate from scoring `check_outcomes`. They grant no pass or N/A and do not
change coverage, category gates or withheld scores. Only the exact empty-pack diagnostic
is removed; actual failures and active-profile missing endpoint approvals remain visible.
Original stored scanner artifacts retain their provenance.

The JSON export's `attack_surface.stats` additionally records `time_allowance_seconds`,
`elapsed_seconds`, `budget_extensions` and `pending_frontier`. Crawl continuations retain
the current in-memory frontier without repeating visited URLs. They can borrow up to 70%
of the already approved collection-process deadline; the ZAP stage is reduced by elapsed
crawl time while 20% remains reserved for the final network check and artifact flushing.
These are execution measurements, not claims of complete website discovery or durable
cross-process recovery. Existing page, depth, request and broker authority caps still apply.

`assessment_plan.conditional_probes` freezes reviewed endpoint selection before dispatch.
Only `external-dast` gains the reviewed read-only CORS default on its canonical approved
GET seed. It sends paired Origin headers, follows no redirects, and creates no query input.
The configuration profile still omits the active pack. Redirect/SQL/XSS/HTML inputs and
expanded role-specific workflows continue to require their explicit reviewed plans.

### Evidence metadata and download

`GET /api/scans/{id}/evidence` now also returns nullable `producer_hash`, `run_id` and
`tool_version`. A browser artifact's producer is `reviewed_browser_capture`; its role is
unauthenticated and its worker image ID/source hash are recorded.

`GET /api/scans/{id}/evidence/{evidence_id}/download` returns the stored redacted bytes as an
attachment (`application/octet-stream`, `X-Content-Type-Options: nosniff`, CSP `sandbox`).
Content hash is verified before serving; an integrity mismatch returns 409. Missing storage
returns 404. JSON browser-state artifacts include `context_id`, `page_id`, `frame_ids`,
`frame_urls`, `state_hash`, escaped/redacted text and accessibility snapshot, and a masked JPEG
as `screenshot_jpeg` base64. Never insert captured text into HTML. Display screenshots as images
only after authenticated download; do not execute or navigate to evidence contents.

### Progress stream

The existing `progress` SSE frame format and monotonic audit cursor are unchanged. These audit
actions are now included; no raw DOM, screenshot, model input, stdout or credentials are sent:

```json
{"cursor":101,"at":"2026-09-26T00:00:00+00:00","type":"browser.open","scan_id":"<id>","action":"browser.open","outcome":"allowed","reason":""}
{"cursor":102,"at":"2026-09-26T00:00:01+00:00","type":"browser.admit","scan_id":"<id>","action":"browser.admit","outcome":"allowed","reason":""}
{"cursor":103,"at":"2026-09-26T00:00:02+00:00","type":"browser.complete","scan_id":"<id>","action":"browser.complete","outcome":"allowed","reason":""}
{"cursor":104,"at":"2026-09-26T00:00:03+00:00","type":"browser.close","scan_id":"<id>","action":"browser.close","outcome":"allowed","reason":""}
{"cursor":105,"at":"2026-09-26T00:00:04+00:00","type":"model.complete","scan_id":"<id>","action":"model.complete","outcome":"unavailable"}
```

`browser.complete`'s SSE outcome is the policy decision; consult the captured action/evidence
for action success. Model gateway/vision routes are internal, absent from the operator schema,
and inaccessible to workers except the fixed authenticated broker command channel.

The private browser admission command adds optional `probe_task` (1–128 characters).
Its reply adds `reviewed_probe`, true only for an admitted capture with validated
probe authority. The expanded collector uses that verdict to select its local active
budget; absent/false verdicts retain the exploration cap.
Only a validated frozen XSS/HTML/DOM-XSS GET navigation uses active accounting; other
actions and invalid references retain the exploration cap. Admission preserves ordering,
in-flight ownership, scope checks and registry task caps. Scan-wide
`assessment_plan.reviewed_browser_actions` records admitted attempts, including failures,
and survives context handoff. `SCOPELENS_BROWSER_MAX_ACTIVE_ACTIONS` bounds these attempts
(default 500); target HTTP still spends the shared request budget exactly once.

## Adaptive execution and generated analysis

The JSON report's `assessment_plan.hypotheses` records each bounded follow-up: ID, observed
signal hash, canonical control, alternative explanation, expected evidence, round, stop
condition and outcome. An admitted but interrupted operation remains `outcome_unknown`.
The graph completes its baseline before selecting optional hypotheses. Repeated admitted IDs
are not replayed. `adaptive.plan` and `adaptive.complete` are redacted SSE event names using
the existing ProgressEvent schema, for example:

```json
{"cursor":123,"type":"adaptive.complete","action":"adaptive.complete","scan_id":"uuid","outcome":"corroborated"}
```

`assessment_plan.model_calls` records role, prompt version, provider/model identity, attempts,
usage when supplied, monetary reservation and measured cost or null. No API key, generated
source or raw provider response is present. `generated_analysis` identifies the source hash,
state and untrusted evidence reference. It cannot create a confirmed finding.

Evidence downloads return HTTP 410 after the configured retention period; the finding and
its original hash remain in the report. Expired bytes are removed by the retention command.
HTML and JSON exports use the same deterministic finding/score data and validated optional
`what`/`why`/`fix` prose. Model prose cannot change the score, severity or references.

## Per-scan adaptive selection

`POST /api/scans` accepts optional `adaptive: true | false | null`. `false` selects the baseline
for a reproducible comparison; `null` uses the server setting. `true` never enables adaptation
when the server disables it, and grants no additional scope, methods or budget. The frozen
assessment plan records `adaptive_requested`. The scope remains immutable and shared by both
comparison runs.

Browser interpretation now uses the same scan-wide model reservation ledger as planner,
verifier, script proposal and report writer. The provider gateway has one authenticated
`/complete` entry point; it is not part of the operator API. Proposals cannot execute tools.

### Model-backed report completion (26 September 2026)

When report prose is configured, the scan stays `reporting` while the provider calls finish.
The task remains running and the coordinator renews its lease; target egress is revoked at
entry to reporting. Only after explanations are stored (or deterministic templates retained
for unsuccessful calls) does the scan become terminal. Cancellation during reporting yields
`cancelled`. Consumers waiting for a terminal status therefore receive the completed report
snapshot, rather than racing a later prose update.

Model-call records distinguish a browser `abstained` response (no suitable coordinate) from
`unavailable`. Both cause no model-selected click. Known token costs survive schema failures;
transport outcomes without usage remain unknown and retain their budget reservation.

## Expansion configuration and cleanup admission

The expansion remains under qualification. These routes configure scans; accepting a recipe
does not establish that the requested checks completed or earned coverage.

| Method | Route | Contract |
|---|---|---|
| POST | `/api/assessments/configurations` | Create an immutable, owner/scope-bound configuration; returns ID, hash, creation time and typed configuration. |
| GET | `/api/assessments/configurations/{id}` | Read an owned configuration; another owner or missing ID receives 404. |
| POST | `/api/assessments/credentials` | Store an encrypted secret with scope and expiry; return only its opaque reference. |
| POST | `/api/scans` | Expanded profiles require `assessment_configuration_id`; snapshot configuration and hash with the scan/task/outbox transaction. |

`AssessmentConfiguration.browser_workflows` accepts the typed `BrowserWorkflowRecipe` schema
in OpenAPI. Recipes require `staging-stateful-v1`, declared identities, disposable records,
an explicit write/reset pair and approved request origins/methods/paths. Viewer, foreign-page
and upload-form URLs are checked too. Recipe IDs must be unique across HTTP, read and browser
recipes. The configuration does not widen scope or grant worker network access.

The coordinator dispatches these recipes to the isolated browser worker after HTTP
collection. A successor browser context requires the previous context to be closed;
workers cannot reopen or take over it through the browser RPC. The successor retains
the scan's egress capability, cancellation epoch and shared request budget.

Experimental report controls are `SL-C03-STOREDXSS-01`, `SL-C04-CSRF-01` and
`SL-C10-UPLOAD-01`. Findings require captures bound to one recipe/run and trusted
identity probes. Coverage also requires a clean durable cleanup row and captured
restored state. Cleanup failure preserves established findings and their evidence,
but leaves the recipe incomplete. These controls are not independently qualified.

Authenticated HTTP input checks use a separate client per role and verify the declared identity
before and after the request series. The report evaluator binds these observations to the frozen
profile, request template, task and plan. Missing or failed identity proof leaves the input
unassessed even if the worker claims success. Authenticated browser input checks use three fresh
contexts for baseline and repeated markers. Every context requires before/after identity facts
bound to the frozen template, task and plan. Browser controls require the reviewed browser
capture source; relabeling an HTTP observation cannot satisfy browser proof. Both vulnerable
and fixed authenticated HTML fixtures passed the deployed report gate on 28 September.

Example configuration shape, with actual recipe fields supplied by the operator:

Session probes default to JSON. HTML account pages can opt in with
`response_format: "html"`, a bounded `html_selector`, `identity_pointer: "/identity"`
and `expected_identity: "sha256:<64 lowercase hex characters>"`. The digest is the
SHA-256 of the selected element's UTF-8 text after trimming leading/trailing
whitespace. Internal whitespace, case and Unicode remain unchanged. Only one
element may match. The parser requires an HTML content type, strict UTF-8 and a
bounded response; login forms, unsafe elements and ambiguous matches fail verification.

Credentials remain encrypted references in `supplied_headers`, for example a
`Cookie` reference. Manual browser login does not configure automatic CAPTCHA
completion or grant permission to submit forms. Never put the cookie value in
the configuration or use an account email as the HTML expected identity.
HTML observations retain the digest and frozen probe binding, not raw account text.
Missing HTML account text alone does not prove logout or expiry. A successful
session check is an identity prerequisite, not a vulnerability or completed control.
These additions require rebuilt images; accepting configuration is not evidence
that a deployed authenticated scan has completed.

```json
{
  "scope_version_id": "00000000-0000-4000-8000-000000000001",
  "templates": [],
  "policies": [],
  "identities": [],
  "browser_workflows": []
}
```

The proxy-local assessment channel is internal, not an operator API. It requires both a live
scan egress token and a separate fixed-worker capability. Cleanup claims are serialized in
PostgreSQL by target origin and resource across recipes and scope revisions. Renewing a scope
does not clear an unresolved mutation. Cancellation denies target requests and every
control operation, including `cleanup_failed` and `clean` updates. Existing `pending` or
`mutation_sent` state remains durable and prevents another scan from claiming the resource.
A new scan token alone cannot clear it. The operator recovery API below requires fresh
authority and trusted readback proof. No failed update may erase captured evidence.

### Controlled callback configuration and proof

`AssessmentConfiguration.callback_recipes` is an immutable list of up to 20 named recipes.
Each has `id` and `recipe`; the recipe schema is in OpenAPI. A recipe requires the staging
profile, an approved target method/path, an explicitly configured collector origin, distinct
known target/scanner peer addresses, and the bounded canary family `ssrf` or `xxe`. The API
rejects configuration when the collector is disabled or any authority binding is missing.
The operator configures collector origins and its signing key locally; the API never returns
that key. The optional receiver has no published host port in the local lab deployment.

Worker control calls require both the live egress token and the fixed-worker capability.
The control service reconstructs ownership and the frozen recipe; workers cannot supply a
new collector, peer attribution, or task owner. Every target request still passes the normal
broker scope, method, path and budget checks. Private proxy capture commits the actual request
and upstream status; this capture route is unavailable through the worker command interface.

Reports expose experimental controls `SL-C07-SSRF-02` and `SL-C03-XXE-02`. Confirmation requires
three exact broker dispatch records, two target-peer HTTP receipts, a quiet negative control,
and closed observation windows with verified signed records. Raw callback URLs, nonce tokens
and private signing material are excluded from evidence exports. Worker diagnostics cannot
confirm findings. No callback, unknown attribution, repeated dispatch, revoked authority or
incomplete proof remains inconclusive; absence of a callback never yields `pass`. Proof states
only controlled HTTP interaction, with no claim of internal data or local-file access.


### Read-only cleanup recovery

| Method | Path | Result |
|---|---|---|
| GET | `/api/cleanup-recoveries/pending` | Owner's unresolved cleanup rows: `id`, original `scope_version_id`, `scan_id`, `recipe_id`, `resource_id`, `state`, `updated_at`. |
| POST | `/api/cleanup-recoveries` | `202` with a new durable recovery scan and task. Original resource stays fenced. |
| GET | `/api/cleanup-recoveries/{recovery_id}` | Owner-bound recovery status and typed verification result. |

POST accepts exactly these fields; a client cannot submit `clean`, evidence, or a target URL:

```json
{
  "cleanup_id": "<original cleanup row UUID>",
  "scope_version_id": "<fresh scope revision UUID>",
  "assessment_configuration_id": "<fresh credential configuration UUID>"
}
```

The fresh scope must be a newer, unexpired revision with the same owner, origin and authority
domain. The original scan must be terminal. The fresh immutable configuration supplies the
original cleanup identity with the same login/probe semantics and credential field names;
credential references and expiry may change. References must belong to the new scope.
The original frozen recipe supplies the GET readback, seed and before-state assertions.
Readback credentials must be in the identity profile; inline request credential references
and readback bodies are refused. The recovery scan receives only that identity and readback
contract. It does not execute the original mutation or cleanup POST. The operator must repair
the disposable resource separately when its readback does not match the original state.

Response shape:

```json
{
  "id": "<new recovery scan UUID>",
  "cleanup_id": "<original cleanup row UUID>",
  "scope_version_id": "<fresh scope UUID>",
  "status": "completed",
  "result": {
    "verified": true,
    "reason": "original_state_verified_under_fresh_authority",
    "evidence_ref": "<trusted evidence UUID>",
    "verified_at": "2026-09-28T12:00:00Z"
  }
}
```

`result` is null while queued. A failed attempt has `verified: false`; `evidence_ref` and
`verified_at` may be null if capture never completed. Cancellation uses the existing scan
cancel route. Progress and evidence use the existing scan SSE and evidence routes. Recovery
does not produce findings or a scorecard. The finalizer loads the persisted artifact,
checks its integrity, supervisor provenance, current task/run/lease and live fresh authority,
then verifies independent identity facts before and after readback and both original state
assertions. Only the unchanged original cleanup row can become clean. Its original scan,
recipe and resource references remain, and audit events retain the previous state and evidence
references. Missing, blocked, stale or mismatched proof leaves the fence intact.

Errors: `404` for resources outside the operator's ownership or a configuration outside its
scope; `409` for an active original scan, pending recovery, changed identity/authority or an
already clean row; `422` for invalid input or unusable credential references; `503` when
execution or the dedicated recovery runtime is disabled. A recovery task cannot fall through
to generic crawling, browser exploration, adaptive execution or model reporting.

### Additive capability and reach metadata

`GET /api/scans/{scan_id}/summary` now includes typed `capabilities` and `reach` fields,
matching JSON/HTML report exports. `capabilities` separates installed tools, executable
reviewed checks, independently qualified families, experimental registry inventory, and
observed tools. Unmeasured totals are `null`, not zero. `reach` publishes discovered counts,
planned/fully-assessed/blocked/error/unassessed/N/A totals, role/route groups and explicit gaps.
See [REPORT_CAPABILITIES_AND_REACH.md](REPORT_CAPABILITIES_AND_REACH.md) for field semantics,
frozen measurement requirements and legacy compatibility. Raw request catalogues, input
plans and capability snapshots are private; report consumers use these safe projections.

## Bounded OpenAPI/HAR discovery intake and plan history

`POST /api/assessments/imports` takes an authenticated operator JSON envelope:

```json
{"scope_version_id":"<owned scope UUID>","kind":"openapi","role_id":"anonymous","document":{"openapi":"3.0.0","paths":{}}}
```

`kind` is `openapi` (OpenAPI 3 JSON) or `har` (HAR JSON); `role_id` defaults to
`anonymous`. Parsing is offline: no server URL or external `$ref` is fetched. Intake
limits are 1 MiB, depth 24, 30,000 nodes, 2,000 members per object/list and 500
normalized templates. Overflow is rejected or recorded as a bounded parser gap.
Invalid/oversized input returns a generic 422 (413 for streaming byte overflow),
without echoing raw input. This sanitization also applies to assessment configuration
and credential request-validation errors.

The typed response `CatalogueImport` contains `scope_version_id`, `kind`, `role_id`,
`source_sha256` (canonical document JSON), `catalogue_sha256` (canonical normalized
catalogue JSON), and `catalogue` (templates and gaps). Raw documents, HAR response
bodies and imported sample values are discarded; credential inputs retain unresolved
`refresh:` references. These hashes identify the supplied material and are not
vulnerability evidence or execution authorization. Paths and input names are retained
as schema metadata; credential-like opaque path segments are omitted.

Include normalized records in `AssessmentConfiguration.imports` (at most eight) to
persist them with the immutable configuration. Scope UUID and identity role must
match that configuration; hashes are checked. Import-only templates remain
`baseline_complete=false`. To run one, provide an explicit reviewed `templates`
entry using its ID, fresh ordinary baseline/credential references, and a matching
`ActionPolicy`. A GET import does not acquire authority automatically. Resource-only
and unapproved origins remain in the catalogue as unassessed work. The broker still
checks each actual request.

`GET /api/assessments/scans/{scan_id}/plans` is owner-bound and returns:

```json
{"scan_id":"<UUID>","revisions":[{"plan":{"id":"<plan hash>","revision":1,"previous_id":null,"scope_version":"<UUID>","catalogue_hash":"<hash>","profile":"external-active-v2","tasks":[],"denominator":0,"carried_task_ids":[]},"catalogue":{"template_ids":[],"instance_count":0,"gap_count":0},"run_id":"<run identity>"}],"execution_claims":0}
```

The history response exposes IDs, task states, hashes and counts only. Stored catalogue baselines, input keys and credential references stay private.

Revisions are coordinator-side, with a maximum of 32 snapshots; there is no new
operator resume/revise dispatch endpoint. Re-entering the expansion stage preserves
prior tasks, catalogue and denominator. Claims are saved under the scan lock before
worker dispatch; completed **and unknown-outcome** tasks/recipe groups are not
replayed. A claim is an execution reservation, not proof of completion. Reporting
can reuse admitted earlier captures only when both task and template exactly match
the durable earlier revision; identity proof keeps its original plan binding.

Verification: `tests/unit/test_import_intake.py`,
`tests/integration/test_import_intake_api.py`; deployed owned-lab command:
`PYTHONPATH=.:backend .venv/bin/python scripts/verify_import_intake_lab.py`.
The deployed command tests import-to-report. The two-invocation database test covers
revision persistence and replay prevention separately.

## Credentialed CORS recipes (B4, experimental)

`AssessmentConfiguration.cors_recipes` accepts at most 20 immutable read-only recipes:

```json
{
  "id": "owned-cors-record",
  "foreign_url": "https://controlled-foreign.example/foreign",
  "foreign_scope_version_id": "<owned related scope UUID>",
  "foreign_grant_id": "controlled-page-grant",
  "anonymous_identity_id": "anonymous",
  "target": {
    "id": "synthetic-record",
    "owner_identity": "A",
    "request": {"method": "GET", "url": "https://target.example/owned-record"},
    "marker_pointer": "/private",
    "marker": "operator-known-synthetic-marker",
    "synthetic": true
  }
}
```

Both identities must be declared; the owner must use cookies, with a same-origin GET
identity probe and no supplied authentication headers. The anonymous identity starts
in a different empty context. Target GET has no body or credential-header overrides.
The foreign URL must be a distinct origin with an exact, same-owner, unexpired related
scope and `scan` grant; resource-only grants cannot authorize this assessment.
All login/probe/record/foreign requests remain broker-scoped and budgeted. Login can
create a disposable test session; the protected record is never mutated.

The fixed browser collector uses a native page `fetch` with ambient cookies,
`redirect: "error"` and `cache: "no-store"`; it neither injects Authorization nor
replaces the response with an API-client fetch. Browser security stays enabled.
The proof contains a before identity probe, authenticated marker baseline, anonymous
denial, exact controlled foreign page, two native reads, and a direct after identity
probe with no re-login. Contexts, request origins, timestamps, recipe and immutable
identity/grant configuration are bound. Only the declared synthetic marker is retained;
other response values, cookie values and credentials are discarded. Partial facts are
emitted before browser disposal on error/cancellation.

`SL-C04-CORSDATA-01` confirmation requires two actual browser-readable marker responses
and the complete independent identity/negative sequence in a unique supervisor-admitted
browser artifact. Worker verdict booleans, HTTP header reflection alone, public markers,
mixed execution attempts and missing proof cannot confirm. A blocked cross-origin read
is **inconclusive**, not pass; it remains in coverage. Revision claims prevent the same
recipe being replayed after a completed or unknown-outcome admission.

The registry entry remains **experimental**. The owned-lab gate uses distinct ports
8080/8081 on one host: this demonstrates cross-origin **same-site** behavior, not general
cross-site third-party-cookie behavior. Browser cookie restrictions on another deployment
may leave a check inconclusive.

Local verification: `tests/browser/test_credentialed_cors_runtime.py` and
`tests/integration/test_cors_configuration_api.py`. Deployed gate command (requires the
updated API/browser images and existing .16 lab fixture):
`PYTHONPATH=.:backend .venv/bin/python scripts/verify_credentialed_cors_lab.py`.

### Frozen request-template review (`request-template-review-v1`)

`GET /api/assessments/scans/{scan_id}/plans/{plan_id}/templates?offset=0&limit=100`

This authenticated, owner-bound endpoint displays a persisted discovery revision. Obtain
`plan_id` from the existing scan plan-history endpoint. It does not approve inputs, update
configuration, or execute requests. A ready count describes the frozen planner decision;
it does not establish successful execution or current permission to execute.

The typed `PlanTemplateReviewView` response contains:

- `version`, `scan_id`, `scope_version_id`, `profile`, `plan_id`, `revision`, `catalogue_hash`.
- `total`, `offset`, `next_offset` (null at the end); `limit` is 1–200, default 100.
  Templates are sorted by their immutable IDs. Select the same plan ID across pages.
- `templates[]`: `id`, display `origin`, query-free display `route`, `method`, `role_id`,
  `content_type`, `baseline_complete`, `baseline_observed`, `label_redacted`.
- Each template's `inputs[]`: opaque `id`, `location`, display `name`/`pointer`,
  `occurrence`, `value_type`, `required`, `mutable`, `refresh_required`, `label_redacted`.
  The stable input ID is `stable_id([template.id, original_input.key])`; the original key
  is never returned. Repeated parameters keep distinct IDs and occurrence numbers.
  `refresh_required` indicates a private reference exists; no reference is returned.
- Each template's `tasks`: `planned`, `ready`, `blocked`, `carried`, sorted `control_ids`.
  Ready and blocked partition planned; carried may overlap either count.

Baseline values, credential references, JSON sample structures, raw input keys, request
or response bodies, provenance URLs, policy/cleanup references, executable authority and
execution claims are absent. Display strings receive credential-pattern redaction; known
private strings are scrubbed if repeated in labels, and path input values are replaced.
An invalid absolute-URL route label is withheld; query and fragment values are omitted.
Display labels are untrusted text and must be escaped by HTML consumers. IDs and frozen
hashes remain the binding keys; display strings must never be used as request instructions.

The server validates the persisted revision ID, catalogue digest, scan scope/profile,
primary origin and task-to-template/input binding. A missing or foreign-owned scan returns
404; a missing revision returns 404; an inconsistent stored snapshot returns a generic
409 without private validation input. Legacy scans without persisted revisions return 404
rather than reconstructing a revision from current mutable fields. Existing plan-history
and report response formats remain unchanged.

### Host investigation priorities (`host-priority-v1`)

`GET /api/scans/{scan_id}/host-priorities`

Each priority row additionally carries `role` and all provenance/DNS fields described
for `/hosts`. The top-level `discovery` object has the same shape as export
`host_discovery`. Its `coverage_notes` retain source outages and host/count/time caps.
These fields are additive; priority points still grant no scope or action authority.

Authenticated, owner-bound, read-only. Uses this scan's observed host inventory and the
operator's latest completed/completed_partial report per host. Foreign-owner reports
are excluded before selection. A missing or foreign scan returns 404. No scans are
created and no execution permission is changed.

Typed `HostPriorityPlan` fields:

- `version`, stable content `revision`, `owned_domains`, `ordering`, `limitation`.
- `hosts[]`: `host`, `owned_domain_match`, `priority` (`focus`, `standard`,
  `inventory_only`), `rank_points` (investigation order, **not** a security score),
  `evidence_level` (`observed`, `name_hint_only`, `unassessed`), nullable
  `latest_scan_id`/`latest_scan_status`.
- `signals[]`: `code`, plain-text `explanation`, nullable source `scan_id`.
- `next_steps[]`: `code`, plain-text `description`, `readiness` (`ready_to_plan`,
  `needs_review`, `needs_test_accounts`). Ready-to-plan does not mean dispatched.

Example host entry (abbreviated):

```json
{"host":"portal.school.test","owned_domain_match":true,"priority":"focus","rank_points":45,"evidence_level":"observed","latest_scan_id":null,"latest_scan_status":"completed_partial","signals":[{"code":"observed_forms","explanation":"Forms recorded; existence does not prove a vulnerability.","scan_id":null}],"next_steps":[{"code":"identity_workflows","description":"Use dedicated test identities and disposable records.","readiness":"needs_test_accounts"}]}
```

`SCOPELENS_DISCOVERY_OWNED_DOMAINS` supplies explicit domain matching for triage only;
empty means inventory-only. External hosts have no assessment next steps. Same-IP
neighbors are not inferred to be owned. The latest report is evidence about its recorded
origin and paths, not proof of complete host coverage. Render strings as escaped text.

### Plain-language finding descriptions

The dashboard and report writer share reviewed copy for all 46 shipped controls in
`backend/scopelens/writer/plain_language.json`. Each description states the observed
weakness, conditional impact, practical fix, and the limit of what was demonstrated.
Potential/inconclusive findings remain explicitly unverified. Recorded routes, raw
redacted detail, evidence references, severity, and confirmation state are preserved.
Cached model prose cannot replace reviewed descriptions for these controls. Unknown
control IDs retain their existing description rather than receiving an invented one.
These wording changes do not add assessment coverage or prove account takeover,
password guessing, marks changes, or database extraction.

### Trusted capability producer integration

The existing `capabilities` response shape is unchanged. The coordinator now collects
offline version/binary/source measurements from configured immutable worker images and
binds them to the scan plan before dispatch. A complete, matching measurement permits
numeric installed/executable totals; missing, stale or failed measurement keeps the
corresponding total null. Experimental controls remain a separate inventory and
independently qualified totals remain unknown without matching curator evidence.
Private `capability_measurement` is excluded from exports with the other binding fields.
The staged `zap_active_grants` ledger is also excluded. No public ZAP task endpoint or
response field is added. A supervisor-derived native launcher and signed proxy
transport now exist, but the shipped reviewed manifest is empty and deployment
acceptance remains pending. An explicitly approved good/bad lab active-v2 XSS task,
or a production external-dast XSS task with a v2 exact-origin approval, can produce
a `zap-active` row in the existing `scanner_results` array. V1 pins confer lab
authority only; v2 pins require exact scheme/host/port and operator/date/decision
records. HTTP and broker-CA-verified HTTPS use the existing signed task transport.
Its field schema is unchanged, all observations remain potential, and no completed
control instance or proof credit is inferred. Native launcher diagnostics are stored
on the evidence envelope outside `data`, under `launcher_diagnostics`; they do not
add fields to the public scanner-result schema. Diagnostics contain exception class,
phase, observed exit code or null, capture availability and a bounded redacted stderr
tail. Optional `requests` diagnostics record HTTP status or null and a trusted-proxy
broker verdict (`allow`, `deny`, `unknown`, or `not_requested` for a local catalog
refusal), independently of upstream HTTP success. Optional `worker_local_api`
telemetry records the fixed local operation, phase, HTTP status or null, exception
class and deadline-expiry flag; it is validated worker telemetry, not authority.
These fields remain on the evidence envelope outside public scanner `data`.
They are diagnostic evidence only and cannot earn confirmation or coverage. The shipped v2 manifest is empty,
so all origins remain blocked. Activation and deployed acceptance are separate.
The new `/internal/broker/zap-task/authorize` and `/zap-task/alive` routes are private
control-plane endpoints, absent from the operator API. They require exact signed
request commitments and live task/scan authority. They are not worker capabilities.
This source integration has PostgreSQL/local tests; updated worker-VM measurement and
export acceptance are still pending. See `RUNTIME_CAPABILITY_MEASUREMENT.md` and
`EXPANSION_ACCEPTANCE.md`. No new operator endpoint or input field is introduced.
