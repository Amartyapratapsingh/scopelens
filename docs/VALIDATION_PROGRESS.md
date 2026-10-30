# Active-check validation, 26 September 2026

## Scan-completeness work, 11 October 2026

Code commits `8c438d3` and `8a982ed` add bounded crawl continuations, frozen read-only
CORS defaults for the active profile, native TLS negotiation inventory, a pinned GOST
engine dependency and the larger advisory corpus. The clean deployment candidate is
`8a982ed`. Its API, crawler/tool and browser images were built from
`/tmp/scopelens-scan-completeness-deploy`, not the shared working tree. The image IDs,
source fingerprint and commit are in `runs/scan-completeness-20261011/runtime-freeze.json`.
Clean `make lint` passed. The affected coordinator, expiry, crawl, advisory and scanner
batch passed 77 tests. The clean candidate's full suite returned 1,879 passes and three
stale lab-network assertions; the fixture owners corrected those assertions in the shared
checkout. The final shared full suite passed 1,948 tests with zero failures in 318.59
seconds using `scopelens_test_scan_completeness`. Its `make lint` passed. Logs are
`runs/scan-completeness-20261011/final-full-suite.log` and `final-lint.log`.
After the browser export repair and additional shared tests, the latest full suite passed
1,964 tests with zero failures in 299.39 seconds on the same isolated DB. Logs are
`post-export-fix-full-suite.log` and passing `post-export-fix-lint.log` in that directory.

Crawl continuations preserve the existing in-memory frontier and visited set in 30-second
slices, up to 70% of the already approved worker/scan process allowance. Remaining ZAP
time shrinks by the actual crawl elapsed time; 20% is reserved for the final network check
and artifact flushing. Page, depth, request and destination ceilings remain enforced.
Per-scope lowered depth is now honored. Stats record elapsed time, allowance, extension
count and pending frontier. This does not implement durable cross-process crawl recovery.

The conditional active pack is deliberately excluded from `external-configuration` by
spec §10.3. Its absent active endpoints cannot be fixed by granting injection coverage.
The new production default applies only to `external-dast`: paired Origin headers on its
canonical approved GET seed, no redirect following, new query input or credentials.
The selected probes and review version freeze before dispatch. Explicit reviewed origin
entries and expanded role/endpoint plans retain their authority boundary.

Follow-up commits `ba4c7cd` and `c208c00` remove the misleading empty conditional-pack
diagnostic from configuration-profile presentation. JSON, HTML and the scanner API label
the five omitted active controls `not_in_profile` / **Not in profile**, separately from
canonical scoring outcomes. Only the trusted scan profile determines those labels;
worker-supplied exclusion claims are discarded. Actual tool failures and active-profile
missing endpoint approvals remain visible. Original stored artifacts and plans retain
their diagnostic provenance.

A same-scan regression re-runs control analysis and scoring on identical captures with
and without that diagnostic: nonzero coverage, all category scores, withheld scores and
canonical outcomes are identical. A read-only comparison against all three saved owned
exports also retained 17.6% coverage and every score/outcome unchanged, with no target
traffic (`profile-exclusion-presentation-comparison.json`). Focused tests: 56 passed.
The final full suite passed 2,038 tests with zero failures in 340.00 seconds on this lane's
isolated DB; lint passed. Logs are `profile-exclusion-full-suite.log` and
`profile-exclusion-final-lint.log`. The interrupted pre-trust-guard run is retained as
`profile-exclusion-full-suite-pre-trust-check.log`. These source/presentation checks are
separate from the orchestrator's grouped immutable deployment qualification.

Native OpenSSL ALPN/NPN offers use the same revalidating, per-connection TLS gate as
testssl. Only completed handshakes contribute inventory IDs; WARN/FATAL IDs no longer
appear in `assessed_rule_ids`. This grants no canonical-control pass. The Kali build
installs `libengine-gost-openssl=3.0.3+git20251212.7f6d61a-2` and actually checks the engine.
Its build check passed in the measured `8a982ed` image. That image used an apt version
pin. The follow-up freezes the exact amd64 and arm64 `.deb` bytes in the existing
vendored-tool workflow, with SHA-256 pins in `checks_registry/tooling/releases.json`.
`scripts/fetch_m3_tools.py` verifies them when fetching; the Kali Dockerfile verifies
them again before `dpkg -i`, then requires `openssl engine gost -t -c` to succeed.
The amd64 package SHA-256 is
`318b907c6099f6777f8b2e2156caef5a6f031c3345ceec8a81eb0716d6ae4b61`;
arm64 is `36de14ae70b0cd1060a340417f7b71cb640a9899a9d990e267c125ff76a9e152`.
Download receipts are in `gost-package-downloads.json` under this lane's evidence
directory. Retaining those vendored bytes avoids dependence on continued mirror
availability; a fresh cache still requires the recorded source URL to remain available.
This follow-up does not retroactively change the measured image or claim deployment.
Verification used isolated committed base `938ae99` plus only the GOST patch:
2,045 tests passed in 320.74 seconds on `scopelens_test_scan_completeness`, and
`make lint` passed. The three focused checks exercise valid bytes, tampering and an
unknown architecture. Logs are `gost-full-suite.log` and `gost-lint.log`; the base,
patched-file hashes and actual package control metadata are recorded in
`gost-source-validation.json`. No API response shape changed in this follow-up.
The requested repeat at exact committed `2565512` used the clean worktree
`/tmp/scopelens-gost-clean-2565512` and the same isolated database: 2,045 tests passed
in 323.53 seconds and `make lint` passed. Git status was clean before and after;
Python import origin and `REPO_ROOT` resolve to that worktree. Evidence is
`gost-clean-commit-validation.json`, `gost-clean-import-origin.json`,
`gost-clean-full-suite.log` and `gost-clean-lint.log`. This is the source qualification
result for the GOST supplement; the local image check and separate uv environment
qualification are recorded below.
The local arm64 image build at exact `2565512` subsequently passed with its own tag
`scopelens/kali-tool:gost-pin-2565512` and image ID
`sha256:2fa49461c6f857b3eb0f0250f2e2900e5eb08b2846c83b7dce23053f2a73426b`.
The build verified the manifest hash before `dpkg -i`; `openssl engine gost -t -c`
reported available and exited zero. Evidence is `gost-local-image-build.log` and
`gost-local-image-build-receipt.json`. The existing `:dev` tag still matches the
deployed `c208c00` freeze. This local image was not deployed, and its source remains
reserved for the next incremental build rather than the current benchmark runtime.
A final repeat at exact `2565512` used its own
`UV_PROJECT_ENVIRONMENT=/tmp/scopelens-gost-uv-2565512`, with no shared `.venv` link.
`uv run --frozen --no-sync pytest -q` passed all 2,045 tests in 317.74 seconds on
`scopelens_test_scan_completeness`. `make lint UV="uv run --frozen --no-sync"` passed
Ruff checks, formatting for 406 files and frontend type checking. The clean worktree
stayed clean, and Python loaded this worktree through that separate environment.
Evidence is `gost-own-uv-validation.json`, `gost-own-uv-full-suite.log` and
`gost-own-uv-lint.log`. Both architectures have verified package bytes; only the
arm64 image was built and checked locally.
Attribution: `8c438d3` also contains backend-gaps' concurrent supervisor changes for
`SCOPELENS_FOLLOWUP_INPUT`, `SCOPELENS_BROWSER_MAX_REQUESTS` and conversion of Docker
client construction exceptions to `SupervisorError`. That history is retained; those
hunks are not claimed as scan-completeness work.

Lab contract follow-up `5be330b` merges every supplementary compose file defining an
allowlisted fixture into `fixture_compose()`, while preserving rejection of duplicate
service definitions. Session-expiry A/B and academic-faults now use the common dedicated
fixture checks: only `labs_net`, no published ports, exact registered address and no
edge `proxy_pass`. Existing held-out ingress checks remain separate and unchanged.
All 20 contract tests passed, including new inventory-completeness and duplicate-service
regressions. No fixture isolation assertion was skipped or relaxed.
The requested custody follow-up at exact `5be330b` ran `test_holdout_custody.py`,
`test_lab_binding.py`, `test_api.py` and the lab contract file: 83 tests passed in
10.59 seconds. It used its own `UV_PROJECT_ENVIRONMENT` and the lane test database;
git status stayed clean. Evidence is `fixture-custody-followup-validation.json` and
`fixture-custody-followup-tests.log`. The change note was sent to holdout-benchmark.
The exact clean `5be330b` worktree passed all 2,046 tests in 311.98 seconds on
`scopelens_test_scan_completeness`; `make lint` passed. Git status stayed clean and
the receipt verifies imports resolve to that worktree. Evidence is
`fixture-clean-commit-validation.json`, `fixture-clean-full-suite.log` and
`fixture-clean-lint.log` in this lane's evidence directory. No live scan or deployment
was performed for this contract follow-up.

The measured `8a982ed` Docker build needed a real copy of `workers/vendor` inside its
worktree because Docker could not copy through a symlink outside the build context.
The four archives in that retained copy were rechecked against its own frozen tooling
manifest; all hashes match. `vendor-copy-verification.json` records those hashes and
confirms the directory is a real copy. These checks made no stack change. The later GOST
packages require the same in-context copy when the grouped rebuild includes `2565512`.

The reviewed OSV corpus increased from the original eight npm packages/121 records to
18 package identities/651 records across npm, PyPI and Maven. Both shipped profile copies
enforce SHA256 `c4a1a13a6a9bcda89880b90d0f1ca0311b13522e85222b5ec438f5be5053e20f`.
Stable numeric three-part PyPI/Maven ECOSYSTEM ranges have tested fixed boundaries.
Unknown versions, qualifiers, distro banners and unmapped components stay unassessed;
banner/advisory matches stay Potential. Retrieval receipts and original revisions are
inside each pinned snapshot.

Failed lab scan `3b8055a0-3870-4047-b20b-ee5dc00413e9` queued at 15:59:39 UTC on 6 October.
Its scope expired at 16:08:37; it was dispatched at 16:28:52 and launched no worker.
The old generic reason was `worker admission revoked before start`. The coordinator now
rejects expired queued authority before acquiring a lease, reserving budget or setting a
start timestamp, and records an explicit renewal instruction. The regression observes
zero worker launches and zero request spend. It does not renew authority automatically.

The operator approved seven-day renewal of only the three earlier owned HTTPS scopes.
`renewed-owned-scopes.json` preserves each previous scope ID and exact copied authority,
including the original 100-page, 500-request, depth-3, 600-second limits. No customer or
third-party target is authorized by this work.
The literal before/after authority diff is `renewed-owned-scope-diffs.json` in the same
directory. Only `authorization_expires_at` and `owner_note` changed; origins, methods,
path prefixes, exclusions, profile and budgets match each expired source version.
Generated IDs, version numbers, creation times and content hashes necessarily differ.
The renewal note is a descriptive paraphrase recorded when transcript approval arrived;
it does not exactly match the later-delivered requested reason string
`operator renewal 2026-10-11 for scan-completeness before/after rerun`. The receipt records
that mismatch. Existing immutable versions and their measured scan references were retained.

| Target | Historical before status | Before control coverage | After status | After coverage |
|---|---|---:|---|---:|
| stage.slicerninja.com | completed_partial | 17.6% | completed | 17.6% |
| arkyon.dev | completed_partial | 11.8% | completed | 17.6% |
| rekvon.in HTTPS | completed_partial | 82.4% | completed_partial | 17.6% |

Historical before reports are `runs/owned-pilot-v3-20260926`; their compact comparison is
`runs/scan-completeness-20261011/before-owned-pilots.json`. Every before overall score was
withheld. Every after run uses the same gates and cannot use absence of an
applicable feature, a scanner error or a missing component mapping as a pass or N/A.

After scans were `7e69f72f-eb01-4131-8d41-a5c51364247e` (staging),
`75f5c454-b372-4bc9-b057-692e83b3c87f` (Arkyon) and
`cc0fb4d0-4dec-40fc-8470-c99d15f61a27` (Rekvon), all on frozen `8a982ed` and the
original 100-page, 500-request, depth-3, 600-second budgets. Their reports are under
`runs/scan-completeness-20261011/after-owned-pilots`; compact results are
`after-owned-pilots.json`. All three overall scores remain withheld. ZAP, Nuclei and
testssl completed without errors on all three. Conditional active endpoints remain
`not_tested`, as required for the configuration profile; this does not grant coverage.

Staging captured 100 pages versus 39 before. It stopped at the explicit page cap after
80.909 seconds, with 107 frontier entries pending, zero crawl errors and 103 crawl
requests (359 total admitted requests). This is bounded discovery, not an exhaustive
crawl. Arkyon captured 16 pages in 10.635 seconds, Rekvon 18 in 11.508 seconds; both
exhausted their frontier without crawl errors. No live pilot needed a duration extension;
the continuation mechanics are exercised by a mocked-transport regression, not claimed
as live multi-hour recovery.

Arkyon's sensitive-file control changed from inconclusive to pass after all three
reviewed paths were assessed. Rekvon's coverage regressed: browser pending-background
requests on `/` and `/app/` plus a read timeout left six previously passing negative
controls inconclusive (listing, mixed content, errors, secrets, API inventory and methods).
Foreign font and Clerk CDN requests were blocked by the scope guard. The browser's
1.5-second idle deadline does not identify the pending transfers in this artifact, so
the cause is not fully diagnosed. Those gaps remain; no N/A or pass substitutes were
introduced. Full control deltas are in `owned-control-deltas.json`. Historical 26 September
versus 11 October site runs are not a controlled code-only experiment.

Staging's browser API export returned 500 because `BrowserView.gaps` accepted only
string values, while capture metadata includes nested pending-request arrays, integer
counts and booleans. Commit `9907d91` preserves JSON metadata and adds an HTTP regression
(19 dashboard tests passed; lint passed). The raw failure and receipt remain alongside
the scan; JSON/HTML/scanner/evidence exports succeeded. This source fix awaits the
orchestrator's grouped immutable deployment and is not claimed live on `8a982ed`.
A read-only check after the verified `c208c00` deployment now returns HTTP 200 for
the existing staging scan's browser export: 6 states, 10 actions and 87 retained
gaps. The receipt and actual response are `stage-browser-c208-readonly-receipt.json`
and `stage-browser-c208-readonly.json`. This checks the export fix without another
Stage scan.

Stage timing review uses the stored `8a982ed` capture and scoped audit rows, not a
new scan. Its `/app/#signin` action ran for 37.916 seconds; the document-ready gap
reports 42 pending requests but retains only 20 descriptions. All 20 retained
descriptions are same-origin scripts. Twelve have no broker policy admission
during that action, with pending ages of 29.7 to 29.8 seconds. Given the 30-second
document wait, those request starts occurred after action admission. Missing
admissions are consistent with waiting before policy admission, subject to the
audit omission described below. The other two document gaps have
4/20 and 3/20 listed scripts without an admission during their action windows.
All 359 recorded broker decisions for the scan were allowed, but the browser
export also has nine `broker_denied` gaps. The exception audit omission diagnosed
by discovery-auth prevents using those audit rows as proof that no requests
were refused.
Those nine URLs are images/video under `/assets/`; none overlaps the listed
pending scripts. Thus the script observations support the admission-queue
hypothesis, but missing admissions alone do not prove it. They do not isolate
the two-slot concurrency gate from the 2 rps pacing rule: audit rows omit
rate-wait durations, actual upstream-dispatch times and the crawl/browser producer. Gaps record relative
request ages without absolute event timestamps. The retained excerpt also cannot
identify the unlisted pending requests. Evidence is
`stage-browser-admission-correlation.json`; no budget or timeout was changed.
The deployed `c208c00` proxy independently clamps both its global semaphore and
per-token concurrency to two; a future scope limit of four alone cannot exceed
that implementation cap.

The historical Rekvon causality review is recorded in `rekvon-causal-comparison.json`.
Both crawls reached 18 pages with 21 requests, depth 3 and zero errors; browser state
and action counts are unchanged. All six changed control statuses cite incomplete `/`
and `/app/` instances. Google Fonts and the Clerk CDN were already blocked in the
September receipt, so a newly added Clerk dependency does not explain this difference.
`d8b259a` to `8a982ed` changes no browser, analysis or scoring source paths, but the
pre-today checkout has not been proven identical to the September worker images.
`rekvon-baseline-image-inventory.json` preserves the read-only Docker inventory:
some legacy API/policy/browser images remain, but a complete historical digest bundle
was not established. No baseline deployment or scan was performed over the current
`c208c00` benchmark freeze. The pending-request mechanism explains the lost coverage;
underlying site-versus-code causality remains unresolved pending controlled evidence.

The network-disabled resource repeat completed all 11 ZAP batches on 110 synthetic
800 KB captures, with no adapter errors or cgroup OOM kills. Scratch use after ZAP was
zero; after Nuclei template validation (exit 0) it was 32 KiB. Individual batch timings
are in `runs/scan-completeness-20261011/resource-repeat.log`. Coordinator reports of
overlap with a fixture health check were corrected to no overlap, then back to overlap;
the invalidated holdout attempt retains these messages in
`runs/holdout-benchmark/admission-00/lock-incident-addendum.json`. No synchronized
start/end receipt resolves the interval, so timings remain an uncontrolled measurement,
not a serial benchmark. This Docker Desktop resource experiment proves neither a live Nuclei
assessment nor worker-VM containment. The container was removed after completion.

The dedicated worker VM finished creation and clean `8a982ed` provisioning. The boundary
qualification passed before activation: authenticated Docker control, isolated files,
direct egress denial, enforcing proxy and cancellation. The receipt is
`runs/scan-completeness-20261011/worker-vm-boundary.json`; provisioning and activation logs
are beside it. A previous duplicate startup attempt was interrupted before provisioning
or activation and produced no scan evidence.

After fixture reset, both paired active assessments completed. Fixed fixture scan
`af8715ff-c31d-404e-b01e-821d0f99bcd6` retained zero findings and all five active-control
passes. Vulnerable fixture scan `0b877e97-f54c-4dbf-9f0d-2cebf8089744` retained 17 findings,
all five active-control confirmations and a corroborated adaptive follow-up. ZAP,
Nuclei, conditional-config and testssl completed without errors on both. Native ALPN/NPN
inventory completed; the earlier missing-engine and proxy-unsupported diagnostics are
absent. No warning was converted into a security pass.

| Paired fixture | Before status | After status | Coverage before / after | Overall before / after |
|---|---|---|---:|---|
| labs-good | completed_partial | completed | 95.5% / 95.5% | withheld / withheld |
| labs-bad | completed_partial | completed | 36.4% / 36.4% | withheld / withheld |

Before evidence is `runs/worker-vm/paired-labs` and compact `before-paired-labs.json` in
this lane's directory; after evidence and compact receipts are under `paired-labs`.
The fixed fixture still cannot receive an overall score: its nginx component has no
reliable ecosystem/version mapping, leaving C06 below its gate. Owned pilot results above
remain subject to their actual coverage gaps.

## Final follow-up: path scope, Juice Shop and worker VM

The final 26-case validation repeat (`runs/validation-active-final-20260926`, scan
`0e9f22d5-f3e6-4194-9d4f-b4294f6e4859`) again produced 13 TP, 12 TN, one negative abstention,
zero FP/FN. It remains contaminated validation and does not pass the independent holdout gate.

Preparing the Juice Shop challenge-API exclusions exposed a real scope defect: query strings,
encoded segments and path normalization could evade an excluded path. Ten initial tests
failed. Admission now evaluates raw, decoded and normalized path interpretations and rejects
ambiguous forms. Fifteen regressions and the deployed proxy probe pass. The live probe checks
the exact `path_explicitly_excluded` reason, plus a permitted fixture response; blanket denial
cannot pass. Logs: `runs/scope-paths-before.log`, `runs/proxy-path-live-final.log`.

Pinned Juice Shop v19.2.1 ran only at the approved internal `juice-shop` binding. Evaluator-only
health queries independently observed the public product-search behavior. The reviewed SQL
pack now supports bounded LIKE-context comparisons alongside its original comparison context:
18 GET probes, no UNION, schema access, credentials or extraction. A real SQLite regression
distinguishes interpolation from a fixed bound-parameter query. Challenge/answer-key routes
are excluded from the scanner; evaluator results are not sent to it.

Scan `312deb18-f054-4b7d-8873-786f3a4afb15` confirmed SQL behavior at `/rest/products/search`.
The CORS reflection control passed. One finding and real HTML/JSON are retained under
`runs/juice-development-20260926`. This known, source-inspected development target is not
holdout evidence. Its browser exhausted its stage deadline; the overall scan remains partial.
That exposed another defect: a terminated browser could still appear `active`. The integration
now emits an incomplete summary when missing, preserves crawl evidence after browser startup
failure, closes the context lease, and prevents terminal scans displaying active browsers.

Reviewed scanner and browser workers now run in a dedicated VM, separate from the control
plane and the generated-script VM. See `WORKER_VM.md`. A live peer-listener probe caught
missing bridge filtering; activation failed until bridge netfilter was enabled. The repaired
boundary passes after reboot, including positive proxy reachability, blocked direct egress,
cross-scan file/network isolation, required Docker client certificates and process stop.
Logs: `runs/worker-vm-activate.log` (failure), `runs/worker-vm-final-boundary.log` (pass).

Full paired VM assessments (`runs/worker-vm/paired-labs`) produced 0 fixed-fixture findings
and 17 vulnerable-fixture findings. All five active controls passed/confirmed respectively,
and the adaptive follow-up was corroborated. The fixed fixture's browser captured 5 states
in 11 actions. Actual browser cancellation committed in 0.026 s and stopped in 0.267 s,
retaining partial evidence (`runs/worker-vm/browser-cancel.json`).

Full suite: 664 passed, zero skips (`runs/backend-final-20260926.log`). Configured-provider
qualification still reports unavailable for every attempted role; no paid call was made.

The operator requested completion of the backend and supplied three owned targets:
`https://stage.slicerninja.com/`, `https://arkyon.dev/`, and `http://rekvon.in/`.
The external run starts with staging, after the local validation fixes pass.

## New validation application

`labs-validation` is a stateless application at the exact internal binding
`172.28.0.15:8080`. It has no external route, credentials or persistent data.
Its loopback evaluator port is `127.0.0.1:8085`.

The 26-case protocol has 13 vulnerable and 13 fixed conditions across XSS, HTML injection,
SQL behavioural checks, redirects and CORS configuration. The evaluator health checker uses
different markers and assertions from the scanner, performs real HTTP/browser checks, and
runs separately from scanner workers. Labels are never passed to a scanner or model.
Each SQL request starts a fresh database; browser health cases use fresh contexts.
The protocol, fixture, oracle and scanner source are hashed before each run.

This is one additional validation implementation, not an independent multi-project holdout.
The cases are marked contaminated after their first results informed fixes. They cannot
satisfy the 30-positive/60-negative, three-group per-family release gate.

## Observed defects

First run `b99cf441-bd05-4b7c-9bff-b9b1bb47306f`:
11 true positives, 2 false negatives, 10 true negatives, 3 negative abstentions, 0 false positives.

- SQL probes only exercised single-quoted string queries. Double-quoted and numeric
  query contexts were missed. Added bounded repeated comparisons for all three contexts;
  a reviewed endpoint may supply an ordinary baseline value.
- Policy defaulted to 24 browser actions while the worker was configured for 40. The last
  HTML check stopped early. The deployment now gives both the same limit; a contract test
  checks this relationship.
- HTTP 400/404/405/410/422 responses could become clean redirect/CORS assessments.
  They now remain inconclusive. Ten regression cases first reproduced the failure.
- SQL proof collapsed duplicate sample names into a dictionary, so a seventh duplicate
  could be accepted as valid proof. Duplicate or incomplete sets are now rejected.
- A development coordinator retained its old imported verifier after a source edit while
  the newly built collector ran the new probes. The intermediate run is retained as failed
  integration evidence. Coordinator processes must restart after edits; external pilot runs
  use rebuilt frozen images without source mounts.

Unit/integration suite after these fixes: 620 passed, zero skipped.

## Verified result after fixes

Run `26ba9d53-5bd3-417a-b926-3861c27cfa8e`: **13 TP, 12 TN, 0 FP, 0 FN, 1 negative
abstention**. The empty SQL result case cannot distinguish baseline from negative input and
correctly remains inconclusive. Negative conclusive coverage is 12/13, or 92.3%.
The small-sample 95% intervals and per-family counts are in
`runs/validation-active-after-2/result.json`; HTML/JSON reports and pre-run hashes are beside it.
The 13/13 positive result has a 95% recall interval of approximately 77.2% to 100%, so this
must not be presented as a general 100% detection claim. The independent release gate remains open.

Commands run: `uv run pytest -q` (620 pass); Ruff check/format (pass);
`make test-proxy` and `make verify-proxy-live` (pass); independent fixture health checks;
`uv run python -m evaluation.validate_active --output runs/validation-active-after-2`.

## Pilot transport defects and corrections

The first three external reports are saved under `runs/owned-pilot-20260926`. They are
partial diagnostics, not completed pilot acceptance: staging reported five low-severity
header conditions, Arkyon was blocked by rotating CDN DNS, and Rekvon had no assessment.

A trace of the deployed proxy showed two response flows retaining both global request slots.
Subsequent requests then waited without reaching the broker. A local real-proxy regression
with two stalled HTTPS response bodies reproduced failure of a later healthy request.
The proxy now expires request flows after ten seconds, releases slots on client disconnect,
and cancels waiting request tasks. The regression completes five later requests in roughly
0.05 seconds each. HTTP CONNECT/raw TCP denial tests still pass.

DNS handling now preserves the original approved destination set for the scan's lifetime.
Fresh DNS answers are still checked for private/metadata addresses, but CDN address ordering
or public rotation cannot make the scanner follow a new destination. The proxy receives only
the original pin and preserves Host/SNI. Pin creation is locked; proxy pin lookup is scoped
to the client connection, so separate scans of one CDN host cannot overwrite one another.
Tests cover public rotation, order changes, unchanged durable pins, and private rebinding.
This replaces the earlier policy of rejecting every public DNS change.

The complete automated suite passed 621 tests after the transport changes. The temporary
trace addon was removed, and the proxy was redeployed without source mounts before the
repaired pilot. The repaired pilot's runtime freeze is retained inside its output directory.


## Connection reuse, browser and advisory follow-up

The original connection regression exercised only five healthy requests. Pilot audit timings
showed precisely every sixth request timing out. A longer local test reproduced this independently
of the website. Rewriting the upstream address only during `server_connect` made mitmproxy's
pool unable to match its already-open connections, exhausting its five-connection limit.
The proxy now uses the approved address as its routing key, preserving HTTP Host and TLS SNI.
Fifteen sequential local requests reuse one healthy connection; twelve requests against the
operator's staging CSS also complete, including requests six and twelve. Raw tunnel and denied
connection canaries remain closed. See `runs/proxy-pool-fixed.log`,
`runs/proxy-reuse-fixed.log` and `runs/proxy-regression-final.log`.

The live containment probe previously looked for a denial reason in the HTTP status line,
which could not prove successful permitted traffic. It now requires a real HTTPS 200 and the
named fixture's body with the same token that cannot reach Redis/Postgres. It revokes its token
in `finally` and creates no dispatch job. `runs/real-positive-proxy-live.log` passes.

Browser redirect headers are retained without asking Chromium for an unavailable redirect body.
A settling timeout preserves visible DOM evidence and remains a rendering limitation. Third-party
failures stay in the browser report instead of being converted to missing target-origin routes.
SQL registry budgets now cover the full 18-GET comparison set and worst-case CONNECT overhead.

A packaged OSV snapshot contains 121 records for eight selected npm packages, with paginated
retrieval receipts and hashes. Named library banners can supply version candidates. Unsupported
ranges and missing versions remain unassessed; banner matching cannot confirm a CVE. API
classification now requires observed JSON/document structure rather than an API-shaped 404 URL.
See `COMPONENT_ADVISORIES.md`. The full suite passed 645 tests with zero skips; Ruff passed.

Repaired external pilots use `runs/owned-pilot-v3-20260926`; older iterations remain diagnostic
records. Staging and Arkyon now have zero crawler transport errors. Scope-blocked resources,
rendering gaps, authentication-required endpoints and testssl limitations remain visible, so
neither overall score nor complete assessment is claimed. All four model roles remain unset.


The extended proxy regression also reproduced conflicting HTTP Host authority reaching an
approved address. The proxy now rejects mismatched URL/Host identity before admission.
`runs/proxy-host-before.log` fails that case; `runs/proxy-host-fixed.log` passes it.

All three v3 pilots completed the crawler without transport errors. Each reported five Low
header conditions. Control coverage: staging 17.6%, Arkyon 11.8%, Rekvon HTTPS 82.4%.
All overall scores remain withheld where category gates fail. HTTP Rekvon redirected to HTTPS;
HTTPS was registered as its own production scope. No cross-origin wildcard was added.


## Owned-site rate authorization, 2026-10-11

The operator approved new immutable scope versions for the three owned HTTPS origins only.
Each copies the prior current version exactly, changes `budgets_override.max_in_flight` from
2 to 4 and `requests_per_second` from 2.0 to 5.0, and sets the exact owner note
`operator raised rate 2026-10-11 (4 in flight, 5/s)`. The existing per-site
2026-10-18 authorization expiry is unchanged. Paths `/`, methods GET/HEAD,
external-configuration profile, exclusions, page cap 100, request cap 500, depth 3,
wall allowance 600 seconds and every other authorization field are unchanged.

The new scope IDs are Stage `d350c2f1-8d4e-4c75-b903-4267c0e2da49`, Arkyon
`120b8ee8-8a0c-4c27-b33d-f071169c6a6e`, and Rekvon
`134ef86a-bf69-480a-a1be-40cf5ae3e0e7`. Stored database authorization was compared
field by field with the submitted request. The only authorization differences are the
two rates and owner note; IDs, version numbers, creation timestamps and content hashes
are derived changes. Full before/after requests and the verified diff are in
`runs/scan-completeness-20261011/raised-rate-owned-scopes.json`.

The earlier unchanged-budget Rekvon helper was terminated while waiting for the stack lock,
with exit 143 and no scan POST. Measurements use a separate helper hold per site and
assert the deployed `c208c009e01a45df4abbb8bb7bb6f2259492d30b` runtime freeze before
posting. On that frozen runtime, both the proxy-wide and per-token semaphore are still
hard-capped at two. The scope authorizes four concurrent requests, but this build can
execute at most two upstream requests concurrently. Further inspection of frozen
`execution/ledger.py::budget_limits_for` shows both scope ceilings are clipped with
`min(deployment_default, scope_override)`. The deployment defaults remain 2 concurrent
requests and 2.0 requests/s, so these scopes do not execute at the approved 4/5 rate.
The scope records are correct; this runtime/configuration does not activate the increase.
The local settings/database verification is retained in `raised-rate-effective-limits.json`;
`raised-rate-deployed-api-settings.json` independently confirms the live API defaults
are 2 concurrent requests and 2.0 requests/s. The standalone proxy has no Settings
module; its policy decisions come from the API, in addition to its own semaphore cap.
Pending third-party and long-poll requests continue blocking the same controls.
All three authorized runs finished on the frozen build. Each used one site per helper
hold; the Stage polling connection failed once and was reattached to the existing scan
under a new helper hold, without a second scan POST.

| Origin | Previous 8a982ed status | Previous coverage | c208c00 status | c208 coverage |
|---|---|---:|---|---:|
| stage.slicerninja.com | completed | 17.6% | completed_partial | 11.8% |
| arkyon.dev | completed | 17.6% | completed | 82.4% |
| rekvon.in | completed_partial | 17.6% | completed | 17.6% |

All overall scores remain withheld. These measurements use the newly approved scope
records but the effective runtime remains 2 concurrent requests and 2/s, so none is
evidence that actual 4/5 throughput was tested. Historical September coverage remains
17.6%, 11.8% and 82.4% respectively; the unchanged-budget c208 Rekvon job never posted.
The aggregate comparison is `runs/scan-completeness-20261011/raised-rate-measured-comparison.json`.

Rekvon scan `c8a28da6-0759-4f13-b64f-a3544cdd1a36` has two
`background_requests_pending` gaps and no `document_ready_timeout`. The `/` gap lists
all 14 pending requests, with `pending_metadata_limited=false`: ten same-origin images
under `/assets/faces/` (`meera.jpg`, `aman.jpg`, `rohan.jpg`, `kavya.jpg`, `kabir.jpg`,
`sara.jpg`, `vikram.jpg`, `priya.jpg`, `devm.jpg`, `nisha.jpg`) and four fonts under
`/assets/fonts/` (`HankenGrotesk.ttf`, `Gloock-Regular.ttf`, `IBMPlexMono-Medium.ttf`,
`NotoSerifDevanagari.ttf`). Their retained pending ages are 2.1–2.2 seconds. No listed
pending request is third-party or a long poll. The `/app/` gap records count zero and
an empty list at metadata capture; the gap still blocks controls. It is not converted
to pass or N/A. All six affected controls remain inconclusive: `SL-C01-MIXED-01`,
`SL-C05-ERRORS-01`, `SL-C05-LISTING-01`, `SL-C05-SECRETS-01`,
`SL-C07-INVENTORY-01` and `SL-C07-METHODS-01`. The prior ReadTimeout is absent.

The root browser navigation was admitted at 14:05:31.242941Z and completed at
14:05:39.231097Z. Five listed image URLs have no recorded admission before completion
and have their first later same-URL admission at 14:05:39.631799–14:05:41.929264Z.
This supports an admission-queue hypothesis, with explicit limits: request-start and
gap times are bounded rather than absolute, audit rows precede rate sleep and dispatch,
the producing caller is not retained, and budget-exception denials are missing from
audit on this build. The data cannot prove which specific request waited or isolate
rate waiting, concurrency, DNS and upstream latency. Full redacted lists and timing
observations are in `rekvon.in-c208-raised-rate/{browser-pending-gaps.json,browser-admission-correlation.json}`.

Arkyon scan `4350d568-9f82-4c77-b4c9-f47129504500` has no background-pending or
document-ready timeout gaps. Its browser completed with three existing third-party
guard gaps and three request failures. The earlier `/assets/aditya.webp` response
capture failure is absent, so HSTS and the six negative controls changed from
inconclusive to pass with captured evidence. This explains the measured coverage
gain without attributing it to a throughput increase that did not execute. Raw
exports, empty pending lists and the read-only correlation are in
`arkyon.dev-c208-raised-rate/`.

Stage scan `80fa29f2-c530-49a5-87ad-cc4015f29013` lost its coordinator lease. The
reported expired lease deadline is 14:13:53.586463Z; settlement at 14:14:10.701847Z
marked the task `outcome_unknown` and scan `completed_partial`. The browser is
`not_tested`; testssl is `not_tested` with `revoked or unknown scan`. There are no
ZAP, Nuclei or conditional-config scanner results in this scan. Empty browser pending
lists provide no rendered-coverage evidence. Crawl metadata reports 100 pages, two
errors, a page-cap stop and 107 pending frontier entries. The exact missed-renewal
cause is unresolved. API/proxy image identities match c208 and their start times
precede the run, so neither container restarted during it. The initial polling
RemoteProtocolError and resumed same-scan collection are preserved in
`stage.slicerninja.com-c208-raised-rate/{initial-poller-error.json,lifecycle-receipt.json}`.
No retry scan was submitted.

Each new browser export returned HTTP 200, including Stage's honest `not_tested`
view. The previous Stage scan `7e69f72f-eb01-4131-8d41-a5c51364247e` browser export
also returned HTTP 200 in each run. Per-site `receipt.json`, `export-http-statuses.json`,
`scope-receipt.json`, `runtime-freeze.json` and raw exports are retained in the three
`*-c208-raised-rate/` folders. Commands were the mandatory helper wrapping
`run_owned_raised_rate.py <approved-host>`, the same-scan Stage
`resume_owned_raised_rate.py`, and read-only `analyze_browser_admission.py` and
`compare_raised_rates.py`. This follow-up changes documentation and operator evidence
only; no product source, timeout, control rule or runtime was changed. No new product
test suite is claimed. The approved rate increase still needs the reviewed broker
ceiling/concurrency change and a later measured deployment.


## Stage coordinator lease diagnosis, read-only, 2026-10-11

No cause-specific source fix is claimed for scan `80fa29f2-c530-49a5-87ad-cc4015f29013`.
The deployed supervisor reports a 30-second lease TTL and 10-second renew interval.
`LeaseHeartbeat` already runs in an independent daemon thread, starts before capability
measurement/discovery/worker execution, and uses its own transactional session. The
foreground worker wait does not directly schedule renewal. The module hashes match the
frozen c208 sources, and supervisor/dispatcher/policy/Postgres container start times
precede the run with restart count zero.

The terminal expiry 14:13:53.586463Z implies the last successful renewal used
`now=14:13:23.586463Z` with the deployed TTL; its actual commit time is not retained.
Docker logs for 14:12:30–14:14:30 show a 22.356-second API log gap at
14:13:21.762–14:13:44.118 and a 21.283-second policy log gap at
14:13:23.035–14:13:44.318. These are gaps between logged responses, not measurements
of heartbeat scheduling or database blocking. The supervisor reports
`no_live_coordinator_lease` at 14:13:59.332 and settles `outcome_unknown` at
14:14:10.723. Dispatcher logs show one enqueue and no replacement/restart in this window.

Postgres completed a checkpoint at 14:13:03.391: 286.010 seconds total, 269.530 seconds
write, 15.710 seconds sync, and 66,417 sync files. A new checkpoint began at
14:13:17.411. This establishes substantial shared database I/O activity, but does not
prove that it blocked this renewal. No database error or deadlock is logged in the
window. The later read-only configuration check reports `log_lock_waits=off` and
`log_min_duration_statement=-1`; historical wait durations are unavailable.

The renewal thread records transient error class only in its in-memory status, waits
another full interval after an attempt, and logs neither attempt timing nor exceptions.
A subsequent terminal LeaseLost overwrites that transient detail. The retained evidence
cannot distinguish host/thread starvation, database connection/lock/I/O waits, or a
transient renewal failure followed by a late retry. None is reported as the established
root cause. A database wait or scheduling delay exceeding the remaining TTL must still
fence the old coordinator; no expired lease was revived and no grace period was added.

An isolated diagnostic based on exact c208 used its own UV environment
`/tmp/scopelens-lease-diagnosis-uv-c208` and private database
`scopelens_test_scan_completeness`. With scaled TTL 2 seconds and renewal interval
0.1 seconds, a 2.5-second blocking foreground sleep preserved the lease and produced
multiple renewals. Stopping the heartbeat let the lease expire; both authority checks
and renewal then raised LeaseLost. These two diagnostic checks plus the 15 existing
lease tests passed: 17 tests in 9.68 seconds. This rules out foreground I/O blocking
alone at that seam; it is not a reproduction of historical CPU, GIL or I/O starvation.
No production source changed, and no new full-suite/lint qualification is claimed.

Evidence is retained under `runs/scan-completeness-20261011/stage-lease-diagnosis/`:
redacted API/supervisor/dispatcher/policy/Postgres/model-gateway logs,
`deployed-heartbeat-settings.json`, `container-identities.txt`, `log-intervals.json`,
`postgres-observability-settings.json`, and the diagnostic harness, focused test log
and receipt. The existing same-scan lifecycle receipt preserves the expiry reason.
Commands used bounded `docker logs --since/--until --timestamps`, selected-value
`docker exec`/inspect reads, read-only SQL settings, `uv sync --frozen` in an isolated
c208 worktree, and the private-database focused pytest invocation. No deploy or
rescan occurred. Distinguishing a future recurrence requires per-attempt renewal
start/end/error and scheduling/DB-wait telemetry; that instrumentation is not present
or deployed by this investigation.


## Heartbeat renewal observability, 2026-10-11

Source commit `570b972` adds bounded diagnostics to the existing independent lease
heartbeat. Every failed renewal and every successful renewal taking longer than half
the existing renew interval logs at WARNING; terminal LeaseLost logs at ERROR. Each
record includes scan ID, UTC attempt timestamp, monotonic duration, error class only
and remaining TTL from the last successfully committed expiry. Exception messages,
tracebacks, database URLs, tokens and credentials are not logged. A failed commit
does not advance the diagnostic expiry. Terminal lease-loss detail retains the prior
renewal error class instead of overwriting it. TTL, interval, scheduler, lease checks
and fencing are unchanged. Public API response shapes are unchanged.

The three unit tests cover slow successful renewal, the strict half-interval threshold
for quiet success, and a failed commit followed by terminal loss with retained error
class and no exception text. The first full run found the two capture tests passed
alone but failed after database tests; Alembic `fileConfig` disables existing loggers.
An ordered lease-plus-observability run reproduced 2 failures and 16 passes. Test-only
commit `cea22be` temporarily re-enables this logger in its fixture and restores the
prior state afterward; all logging assertions remain. The same ordered run then
passed 18 tests in 8.79 seconds. Production source did not change in this follow-up.
The first full result, 2 failures and 2,193 passes in 340.66 seconds, and its successful
lint are preserved as failed qualification evidence.

Final clean qualification passed in exact `cea22be`: **2,195 tests passed**, zero
failures/skips, in 339.59 seconds. `make lint` passed Ruff, format checks for 423
files and the frontend typecheck. Git status was clean before and after. The independent worktree
`/tmp/scopelens-heartbeat-clean-cea22be`, UV environment
`/tmp/scopelens-heartbeat-uv-cea22be` and private database
`scopelens_test_scan_completeness`. Vendored archives were copied and hash-verified;
frontend dependencies were copied without changing source. The shared Python
environment is not linked, and imported module origin was verified inside the clean
worktree. Commands were `uv run --frozen --no-sync pytest -q` and
`make lint UV="uv run --frozen --no-sync"`, with the private test database override.
Evidence under `stage-lease-diagnosis/` includes
`observability-before.log`, `observability-order-repro.log`,
`observability-order-fixed.log`, the first-run `observability-*` qualification files
and fresh `observability-final-*` receipts/logs. No deployment or rescan is performed
by this change.

### Queued cancellation repair, 11 October 2026, source only

Cancellation now settles a queued intent with no task or coordinator lease even when
it already has a cancellation timestamp. The response is `cancelled` with reason
`cancelled before dispatch`; the epoch, finish timestamp and `scan.cancel` audit
commit together. No worker-stop event is created for that never-dispatched intent.
Reconciliation settles queued scans with positive cancellation epochs and no lease
row once, preserving the epoch and recording a `scan.reconcile` audit. Existing
lease recovery and running-scan handling remain in their existing paths.

The dispatcher consumes terminal execution notifications as skipped and audits the
reason, so they no longer remain pending or enqueue target work. A necessary cleanup
exception retains `scan.cancel` delivery for cancelled scans with task or lease
records: the existing running cancellation route marks a scan terminal before asking
the supervisor to stop its workers. Suppressing that notification would change
running cancellation. The API contract documents the exception explicitly.

The new integration tests cover first/repeated legacy cancellation, atomic rollback
when audit fails, all four terminal states across execution/cancellation topics,
preserved worker cleanup, idempotent reconciliation with and without planned tasks,
and untouched uncancelled/leased/running scans. The initial focused run reproduced
16 failures. After the repair, the new tests plus existing dispatch/recovery and API
tests passed **78 tests in 8.60 seconds**, with no skips. Command: `python -m pytest
-q --tb=short tests/integration/test_queued_cancellation.py
tests/integration/test_dispatch_recovery.py tests/integration/test_api.py`, using the
independent heartbeat UV environment and `scopelens_test_scan_completeness`. Ruff
check and format check passed for the four affected Python files. This is focused
validation of the shared working tree, not clean full-suite qualification.

Evidence: `runs/scan-completeness-20261011/queued-cancellation/before.log` and
`focused.log`. Full suite and `make lint` are deferred until the parent confirms the
benchmark has finished. No deploy, reconciliation against the live database, or scan
was run. The historical queued scan is not claimed repaired in the deployed stack.

The follow-up strengthens cleanup preservation for every terminal state with task,
lease, start or actual dispatch history, including an older dispatch receipt whose
task row is absent. Consumed terminal execution entries audited as skipped do not
count as historical dispatch. A shared cancellation helper applies that conservative
history check to the API and dispatcher. The API contract is updated accordingly.

Two integration cases now follow a running scan's cancellation from the real API
through dispatch, the real `cancel_task` and `DockerWorkerSupervisor.stop_all_for_scan`.
Each starts a real two-process local group. The cooperative case verifies both exit
on SIGTERM; the resistant case verifies SIGTERM followed by SIGKILL and both exits.
The test checks per-scan worker labels and the supervisor's `stopped` audit. The
Docker transport is substituted, so this proves the source cancellation path and
real process termination, not live Docker-container qualification. Queue consumption
runs after the dispatch transaction commits, matching asynchronous delivery. An
initial synchronous-consumer harness blocked on the dispatcher audit lock and was
interrupted; its partial output is preserved as `supervisor-harness-interrupted.log`.

The final focused run passed **90 tests, no failures/skips, in 17.74 seconds** using
the same private database and independent UV environment. Changed-file Ruff and
format checks pass. `focused-78.log` preserves the initial repair result;
`supervisor-focused-89.log` preserves the preceding follow-up result and `focused.log`
contains the final 90-test run. Full-suite qualification and `make lint` still await
the benchmark-done signal. No live stack or target action was performed.

### Final owned-site 4/5 rescans, 11 October UTC / 12 October IST

After the benchmark, grouped qualification/deploy and backend-gaps' lab gate, the
parent issued `RESCAN GO` in message `0b09e636-0097-43eb-a611-eeca85586418`.
The measured deployment was exactly `db730a029304014f94f7ae4e4b441414a85642c6`,
source freeze `611e5a1c4f5c171fcd323bb83fbab3c4bfd9829656042f75da7b5b9b33e673d2`.
Each site ran under a separate `/tmp/scopelens-with-lock.sh scan-completeness` hold.
No full suite overlapped the scans. No additional target, retry, deployment, scope
extension, budget increase or timeout change was performed by this measurement.

| Site | Prior c208 status / coverage, effective 2/2 | db730a0 status / coverage, effective 4/5 | New scan ID |
|---|---|---|---|
| stage.slicerninja.com | completed_partial / 11.8% | completed / 17.6% | `0d8a665a-3de9-410e-899b-88cf757fdbe8` |
| arkyon.dev | completed / 82.4% | completed / 82.4% | `9471a045-0461-4033-8449-ae55b5655743` |
| rekvon.in | completed / 17.6% | completed_partial / 17.6% | `adb08041-1347-4131-b1a8-31bc8e649ba1` |

All overall scores remain withheld because applicable category gates are not met.
All six exports per site, including browser export, returned HTTP 200. ZAP, Nuclei
and testssl completed on all three sites, including the Stage 100-page crawl.
The conditional active pack remains `not_tested` outside external-configuration;
its omitted controls remain `not_in_profile`. No gap is relabelled pass or N/A.

Stage and Arkyon retain no `background_requests_pending` or `document_ready_timeout`
gaps. Stage browser completion therefore improved, but missing captures remain:
13 `broker_denied` gaps, 43 `request_failed` gaps and the unchanged 100-page stop
with 107 frontier entries. Its six negative controls remain inconclusive. Arkyon's
corresponding six controls are conclusive passes. Crawl discovery finished for
Arkyon and Rekvon with zero pending frontier; Stage correctly stopped at its cap.

Rekvon browser export is `incomplete`, with one root `background_requests_pending`
gap, one `ReadTimeout`, and scan reason `HTTP crawl results were saved; browser
exploration did not finish: timed out`. The root gap lists all 16 pending requests
without metadata truncation, aged 1.9–2.0 seconds: twelve same-origin images under
`/assets/faces/` (`aditya`, `ananya`, `meera`, `aman`, `rohan`, `kavya`, `kabir`,
`sara`, `vikram`, `priya`, `devm`, `nisha`, all `.jpg`) and four same-origin fonts
under `/assets/fonts/` (`HankenGrotesk.ttf`, `Gloock-Regular.ttf`,
`IBMPlexMono-Medium.ttf`, `NotoSerifDevanagari.ttf`). No document-ready timeout gap
is retained. The separate Google Fonts and Clerk/jsdelivr scope guards persist;
they are not the hosts in this pending list.

All six Rekvon controls remain inconclusive: `SL-C01-MIXED-01`,
`SL-C05-ERRORS-01`, `SL-C05-LISTING-01`, `SL-C05-SECRETS-01`,
`SL-C07-INVENTORY-01` and `SL-C07-METHODS-01`. None recovered. The root action
window is 21:59:41.047217–21:59:48.596009 UTC. Every pending URL has a candidate
broker admission within that window; two also have later admissions. These matches
do not prove which browser request was queued: audit time precedes rate sleep and
upstream dispatch, same-URL crawl requests are indistinguishable, and absolute
browser request-start/gap timestamps are not retained. Effective 4/5 is verified
by admission audits, not inferred from observed request intervals. The rate increase
did not resolve Rekvon's timeout. No policy or timeout adjustment is claimed.

The exact `budget.increase` rows are Stage sequence 62067 at 21:52:44.851613 UTC,
Arkyon 62514 at 21:57:14.813280 UTC and Rekvon 62602 at 21:58:59.432745 UTC.
Each records approved/effective `max_in_flight: 4`, `requests_per_second: 5.0`,
against defaults 2/2. The immutable scope IDs remain `d350c2f1-8d4e-4c75-b903-4267c0e2da49`,
`120b8ee8-8a0c-4c27-b33d-f071169c6a6e` and
`134ef86a-bf69-480a-a1be-40cf5ae3e0e7`, respectively. Their previously reviewed
rate-version diff changes only concurrency 2→4, rate 2→5 and owner note
`operator raised rate 2026-10-11 (4 in flight, 5/s)`. Expiry remains 18 October;
origin, paths, methods, profile, page/request caps and other budgets are unchanged.
This measurement creates no new scope version.

No `heartbeat renewal`, `LeaseLost` or lease-loss warning line was retained from
the five control-plane containers within any scan window. Stage's mid-run lease
observation confirms its expiry advanced beyond the initial lease. Final lease rows
were released normally. Absence of warnings does not count successful renewals or
establish that every renewal was fast.

Evidence root: `runs/scan-completeness-20261012/`. Aggregate
`owned-rescan-comparison.json` links all per-site `*-db730a0-4x5/` folders with
scan, scope/freeze, JSON/HTML/browser/scanner exports, exact pending lists,
`budget-increase-audit.json`, `admission-timing.json`,
`pending-admission-correlation.json`, final leases and filtered logs.
The earlier scope diff receipt remains
`runs/scan-completeness-20261011/raised-rate-owned-scopes.json`.
Fresh clean full-suite and lint qualification started only after all three scans
became terminal and their helper holds ended; its result is recorded below.

Final clean qualification of exact `db730a0` passed **2,382 tests**, zero failures
or skips, in 405.70 seconds. `make lint` passed Ruff, formatting and the frontend
typecheck. Worktree `/tmp/scopelens-scan-final-db730a0` was clean before and after;
UV environment `/tmp/scopelens-scan-final-uv-db730a0` is independent, with no shared
`.venv` link, and imported package origin was verified inside the clean worktree.
Tests used `scopelens_test_scan_completeness`. Six vendored archives were copied
and hash-verified against the manifest; frontend dependencies were real copies,
with no frontend source edit. Commands were `uv run --frozen --no-sync pytest -q
--tb=short` and `make lint UV="uv run --frozen --no-sync"`. Receipts/logs:
`final-validation.json`, `final-full-suite.log` and `final-lint.log` in the evidence
root. This qualifies the cancellation and heartbeat changes together with the
committed grouped source; it does not resolve the remaining coverage gaps.

At 22:05:58 UTC another host suite, PID 51229 in
`/tmp/scopelens-grouped-c32ff6a-venv`, was observed overlapping this qualification.
Both suites started after the owned scans ended; no live scan overlapped this suite.
`concurrent-host-observation.json` preserves the observation. The functional pass
stands, but suite duration is not an isolated host performance measurement.
