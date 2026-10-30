# Scanner expansion implementation

Approved: 26 September 2026. Scope: B1–B7 in SCANNER_EXPANSION_PROPOSAL.md; backend only.

### Qualified timeout repair deployment and failed native gate — 12 October 2026

Exact source `c32ff6a3eb32045914db88f71b0813742c14967d` passed the clean
2,408-test suite with zero failures/skips and `make lint`, then completed the
grouped build, worker VM verification and frozen deployment. The deployed source
fingerprint is `2ddfda8c096047130ee60e2556fbb006687f86a2f5eba1220b78a1a2e45b72f9`.
Sandbox verification was skipped because the port-8099 gateway was unavailable.

The operator-selected wait for unrelated host tests was honored before the
unchanged helper-held native lab gate. Vulnerable scan
`881a6d78-67b7-4bdf-8a43-913776e6e54f` completed partial; native state was error,
observed worker exit was 1, and the grant closed after one admitted request with
no candidates. Trusted response diagnostics record HTTP 502 after broker allowance
in 3.513 seconds. Worker stderr records `URL_NOT_IN_CONTEXT` and HTTP 400 from
`ascan/action/scan`. The upstream 502 cause is unresolved; the fixed fixture was
not run. This gate did not satisfy native acceptance or activate production origins.

Official configuration restoration was proven and independently rechecked:
all six control images match release pins, readiness is schema 0009, browser active
ceiling is 1,200, ZAP is disabled, shipped approvals remain empty, temporary mount
and signing environment are absent, and the stack lock is released. Evidence:
`runs/backend-gaps-native-lab-c32ff6a/` and
`runs/c32ff6a-continuation-20261012/`. No additional scan or retry followed.

### Native API deadline and response diagnostics repair — 12 October 2026

Every local ZAP API operation now receives a timeout equal to the remaining
absolute worker task deadline, including synchronous `core/action/accessUrl`.
Expired operations perform no request; a response completing past the deadline
fails with a fixed deadline error. Header and body timeouts retain the observed
HTTP status when headers arrived, or null when no status was observed. Atomic,
bounded worker telemetry records only operation, phase, exception class, status
and deadline state. The supervisor validates its fields and captures it before
container removal; worker telemetry confers no broker authority or proof credit.

For each native target request, the trusted proxy overwrites any upstream verdict
header and stamps its actual `allow`, `deny` or `unknown` decision on the response.
The supervisor retains this verdict separately from HTTP status, before reading
the body. Thus an upstream 502 after broker allowance is distinct from a broker
403 denial, a local task-catalog refusal and a missing verdict. The private verdict
header is consumed by the supervisor and is not forwarded into the native response
headers. Signed task, scope, exact origin, payload catalog, budget, cancellation,
rate and concurrency checks are unchanged; shipped approvals remain empty.

Focused regressions cover slow seed headers/bodies within the deadline, expiry
before/during an operation, status retained after deadline or body failure, bounded
telemetry intake, producer evidence retention and upstream verdict spoofing. Existing
signed-task/origin negative tests also pass: 185 focused tests in 24.48 seconds.
`make lint` passed. Full clean qualification, deployment
and one further owned-lab paired gate remain pending after the concurrent rescans.
No Docker, live scan or stack mutation was performed for this source repair.
Evidence: `runs/backend-gaps-native-timeout-focused.log` and
`runs/backend-gaps-native-timeout-validation.json`. The public scanner-result field
schema is unchanged; optional evidence-envelope diagnostics are documented in
`API_CONTRACT.md`. Native deployment acceptance remains unmet.

### Native deployed retry failed; official restoration proven — 12 October 2026

Native rule 40012 was measured on verified deployment
`db730a029304014f94f7ae4e4b441414a85642c6`, frozen source fingerprint
`611e5a1c4f5c171fcd323bb83fbab3c4bfd9829656042f75da7b5b9b33e673d2`.
The paired gate failed on the vulnerable case, scan
`a4d6f742-7291-4ef2-9623-bb83db611d34`, which completed partial. The fixed
case was not run. Its native grant closed after one admitted request, with no
candidate observations. The public result reports `process exit 1` and
`native request denied; assessment incomplete`.

Trusted diagnostic evidence records an actual observed worker exit code of 1 and a
bounded, redacted traceback ending in `httpx.ReadTimeout` during the local ZAP
`core/action/accessUrl` seed operation. The saved broker audit allowed the exact
signed seed. The generic native denial text also covers any HTTP response of 400
or above; the response status was not retained, so it does not establish a broker
authorization denial. Source inspection found a one-second local API timeout,
including this synchronous seed operation through Docker IPC and the trusted proxy.
This is a timing defect candidate, not yet a validated correction.

Official restoration was proven before releasing the stack lock: all six control
image IDs match the freeze and `images.env`; temporary manifest mounts and signing
environment are absent; ZAP is disabled; browser active ceiling 1,200 is preserved;
`/readyz` is ready at schema 0009; the shipped empty manifest is unchanged and the
temporary manifest was deleted. No production origins were enabled. Evidence:
`runs/backend-gaps-native-lab-db730a0/receipts.json`, `labs-bad-report.json` and
`labs-bad-native-evidence.json` in the same directory. Native deployment acceptance
remains unmet. No public API fields or proof/scoring rules changed in this gate.

### Atomic native request publication — 11 October 2026

The worker now writes a mode-0600 exclusive temporary file in the request directory,
flushes and fsyncs it, then publishes it with `os.replace`. The reader skips only exact
32-hex `.tmp` names; other filename, entry-count, symlink and size guards remain.
A deterministic interleaving of the real bridge and reader reproduced JSONDecodeError
with the old partial writer. With atomic publication, the reader sees no request during
writing or before rename, and reads the complete JSON only after rename. Failed fsync
cleans up the unpublished file; temporary symlink collisions are neither followed nor
removed. No request payload, grant, scope, budget or public API field changed.

Focused publication/diagnostic/launcher/contract/origin tests passed 93 cases; Ruff and
formatting passed. Evidence: `runs/backend-gaps-native-publication-focused.log` and
`runs/backend-gaps-native-publication-validation.json`. This fixes a reproduced local
race, not an independently established cause of the historical deployed failure.
No Docker, stack or live work was performed. Full clean validation, build and paired
native retry remain deferred until the benchmark ends.

### Native launcher failure evidence — 11 October 2026

Source now records the actual launcher exception class and its `launch`, `grant`,
`transport` or `read` phase. Worker exit status comes only from an exited Docker
container; a created/running container's default code is not treated as an exit.
Failures without an observed exit retain `exit_code: null` and `no exit observed`,
instead of fabricating `process exit 1`. Closure/removal and exit-probe failures retain
separate exception classes. No exception message or credential-bearing URL is copied.

Before forced removal, the supervisor requests a non-following stderr tail of 40 lines,
reads at most 16 KiB/64 blocks and retains at most 4 KiB after redaction. Incomplete
lines at the read boundary are dropped. Known scan/grant/signing credentials and the
standard credential patterns are scrubbed; truncation or unavailable capture is explicit.
The native daemon's stdout/stderr now reach worker stderr rather than DEVNULL, so
startup failures are available for this capture. Diagnostics are attached to the stored
`scanner_result` evidence envelope as `launcher_diagnostics`. The public scanner data
schema, proof rules and scoring are unchanged.

Focused tests exercise container creation/start, grant creation/liveness, transport
construction/proxy failure, file-channel read, result read, real worker exit and cleanup
failure. They verify redaction, read/retention ceilings, capture before removal, grant
closure and the unchanged public field set. The focused suite passed 85 tests; Ruff
and formatting passed for the five changed Python files. Evidence:
`runs/backend-gaps-native-diagnostics-focused.log` and
`runs/backend-gaps-native-diagnostics-validation.json`. Full-suite validation, deployment
and the native paired gate remain deferred until the measured benchmark ends.

The reviewed path after grant creation is signing, container start, broker-client/CA
construction, grant-liveness check, Docker state/IPC read and exact signed forwarding.
Mocked failures now identify each boundary. A partially published worker request remains
a source-level race candidate, not a proven cause of the historical failure. The pinned
API `Integer` startup defect was independently reproduced and repaired in `b2be0cc`.

### Offline native startup diagnosis and source repair — 11 October 2026

A bounded standalone container using the exact frozen b0b123a Kali image
`sha256:de37a2cdbb5f9c529f4632f417791ba18f37d31fdfb9533e6595773ae16388b8`
reproduced a deterministic startup error with networking disabled, no mounts and no
broker or supervisor credentials. ZAP accepted version/proxy/context/rule setup, then
returned HTTP 400 `missing_parameter` at `setOptionTargetParamsInjectable`, before
any seed request. The three option setters require case-sensitive `Integer`; the
worker supplied `integer`. Correcting only that spelling made all three setters
return HTTP 200 in the same pinned image. The diagnostic deliberately stopped before
`accessUrl`, with zero target requests. Every diagnostic container was removed.

Source now uses `Integer` for the injectable/RPC/thread settings. Local API failures
retain only the fixed operation and HTTP status, avoiding an HTTPStatusError URL that
contains the ephemeral API key. Focused launcher/contract tests passed 37 cases; Ruff
checks and formatting passed for both changed Python files. The regression first failed
on the HTTP and HTTPS setup paths with the uncorrected option names.

Evidence: `runs/backend-gaps-native-offline-repro.json`,
`runs/backend-gaps-native-offline-repro-api-detail.json`,
`runs/backend-gaps-native-offline-repro-corrected.json` and
`runs/backend-gaps-native-offline-validation.json`. This establishes a blocking native
startup defect and its isolated correction. It does not establish that the historical
masked launcher failure had no additional causes. A full clean suite, new build and
paired native lab gate remain pending after the benchmark. The deployed b0b123a runtime,
shipped empty allowlist, broker authority and public API shapes are unchanged.

### Deployed capability acceptance and failed native ZAP gate — 11 October 2026

Measured the frozen deployed commit `b0b123add84182fb8ec9327ec9951e98711d7d8c`
from its clean worktree and private UV environment, using separate stack-helper holds.
Release fingerprint: `0b0a3f045f967d29e74d4330fc9edb24be187a0b338a25394e2041ae88169dcb`.
No source/image rebuild was performed for these gates.

The **strict trusted capability export gate passed** on fresh owned labs-good scan
`232c3ccd-3312-4e81-8cf7-35698de018a3` (`completed_partial`). The supervisor evidence
and export replay measured five installed tools, including Chromium, and twelve
executable controls for external-configuration. Backend-source digest:
`d02f97c8d2246cc8cd6e07e3cb2a9926481548a25e741faeebadc15c14d7f8a9`.
No requirement was relaxed. This accepts numeric inventory and trusted export parity;
it does not accept full assessment completion, detection coverage or independent family
qualification. A pytest rerun began after gate admission and overlapped its final seconds;
the receipt records the start and completion bounds. Evidence:
`runs/backend-gaps-capability-b0b123a/{receipts.json,report.json}`.

The **native ZAP paired gate did not pass**. Owned labs-bad scan
`c04b29c0-103a-4f68-9e0a-150ee10eb408` completed_partial with a native scanner error,
no observations and a closed grant with zero admitted requests. The good case was not
run after that failure. The launcher reports process exit 1 and a trusted-channel/launcher
exception, but its default exit code and broad exception handling do not establish the
underlying Java or transport failure. The pinned archive's core JAR and ascanrules78
hashes match the proposal. Root cause needs a retained, bounded runtime diagnostic;
no native detection acceptance or production approval activation is claimed.

The uncommitted temporary lab-only rule 40012 manifest was restricted to exact good/bad
HTTP origins and its exact content and hash are in the receipt. Hash:
`a166ac0713dbe30afb4e0ab675ce2500164c5108cdc3a682ce4e1f35bd190952`.
The first setup attempt omitted the immutable assessment configuration required by the
expanded profile and created no scan. The corrected runner supplied an empty immutable
configuration without changing deployed source or native pass criteria.

Both attempts proved restoration: running control image IDs equal release image pins,
temporary mounts/signing environment are absent, ZAP active is disabled, `/readyz` is
ready at schema 0009, the official browser active-action ceiling remains 1200, and the
shipped empty manifest hash is unchanged. Temporary manifests were deleted and each
helper hold released. The only excluded DB intent was the expired legacy queued scan
`c87c7906-1c89-4d23-969d-05ca20506d07`, with expiry recorded; no row was mutated.
API pending-scan and host test-process guards passed before the native restart.
Evidence: `runs/backend-gaps-native-lab-b0b123a/receipts.json`,
`runs/backend-gaps-native-lab-b0b123a-retry/{receipts.json,labs-bad-report.json,labs-bad-report.html}`,
and `runs/backend-gaps-native-startup-archive-diagnostic.json`.
The shipped approved-rule list remains empty. Further runtime diagnosis, rebuild and
paired measurement wait until the benchmark completes.

### Inert origin-scoped native ZAP and HTTPS source — 11 October 2026

Implemented `zap-active-allowlist-v2` with exact scheme/host/port approvals and
required operator/date/decision records. Dispatch, grant creation, every broker
request and post-admission liveness enforce the exact approved origin. Pin hashes
include the origins and approval record; changes revoke live grants. V1 remains
compatible for owned good/bad active-v2 labs and cannot grant production authority.
The shipped v2 rule list is empty, so no rule, origin or production task is enabled.

The trusted launcher supports HTTPS through the existing authenticated broker
CONNECT/MITM lane with strict broker CA verification and signed inner GETs. Native
ZAP remains network-none and credential-free; its local HTTP projection maps only
the exact bound input to the real HTTPS URL. Native candidate URLs map back to the
logical URL. This is query/body reflection transport, not native TLS analysis.
Existing task/scope/container/epoch/payload/budget/cancel and no-reissue guards
remain mandatory. No broker policy/proxy hook or detector/proof rule was changed
in this implementation. Public API response shapes are unchanged.

Source validation and the paired native deployed gate are separate. No deployment,
lab acceptance, origin activation or new external-dast scope version is claimed.
Operator-authorized activation for the three owned sites still requires the lab
gate and the orchestrator's explicit go-ahead; it will be a separate approval commit.
Schema and transport rationale: `docs/ZAP_ACTIVE_ALLOWLIST_PROPOSAL.md`.

Clean committed validation at `54e83752a3b22d571f45a386181cf43c99b430af`
passed **2,177 tests without skips** in 538.09 seconds; `make lint` passed
(Ruff, formatting and frontend typecheck). The worktree used its own UV environment,
private `scopelens_test_backend_gaps` database and real hash-verified vendor copy.
The focused ZAP/origin/grant/proxy suite passed 102 tests. Evidence:
`runs/backend-gaps-grouped-54e83752a3b22d571f45a386181cf43c99b430af/validation.json`
and adjacent suite/lint logs; `runs/backend-gaps-zap-v2-focused.log`.
Runtime source fingerprint: `0ee49eec4365443dbc49cbc0f6b1e33eb92d5dc7b98ad92973b71fcb4c63aed7`.
This records source validation only, not deployment or native acceptance.

### Credentialed CORS observations on c208c00 — 11 October 2026

The helper-locked owned browser fixture check recorded **vulnerable confirmed; fixed
inconclusive (blocked read observed)** on deployed commit
`c208c009e01a45df4abbb8bb7bb6f2259492d30b`, with no rebuild. Bad scan
`b5b86dca-c70f-4b2a-8266-6086b4364322` completed with a confirmed protected-data read;
fixed `2d18143e-df70-438a-b2a7-d5c619dc00a8` completed_partial with native blocked-read
proof and an inconclusive outcome. Both redacted JSON/HTML and exact boolean presence
facts verified. This is cross-origin same-site port coverage, not cross-site cookie-policy
qualification. Evidence: `runs/backend-gaps-cors-c208c00/`, log with the same prefix.

The fixed fixture demonstrates two unreadable credential-bearing requests from the
configured foreign origin. This does not prove absence across all origins or establish
why every browser fetch failed. The registered control confirms exposure only; this
fixed instance remains incomplete with no scoring or coverage credit. Passing the
fixture assertions does not promote the control outcome to pass.

The strict trusted capability inventory gate on the bad scan failed. Private supervisor
source/image/snapshot bindings matched c208c00, and Playwright/ZAP/Nuclei/testssl measured;
Chromium was omitted because its actual version banner is `Google Chrome for Testing
153.0.8010.12`. A helper-locked offline check of the exact browser image proved the
executable exits zero. The narrow parser fix recognizes that exact prefix for Chromium
only; failed binaries and other tools still fail closed. Numeric installed inventory
remains unaccepted until the fixed probe/API/worker candidate is rebuilt and remeasured.
Diagnostics are in `runs/backend-gaps-capability-c208c00-diagnostic.json` and
`runs/backend-gaps-chromium-probe-diagnostic.log`.

A read-only comparison of both CORS scans and discovery-auth's two authenticated-browser
scans found a trusted measurement and valid snapshot in all four. They share the same
source, images, probe and four measured tool records, with `installation_complete=false`;
the installed-tools total is unknown in all four, and the executable-check count is 12.
All four pass trusted export parity and all four fail the strict measured-inventory
requirement. The browser gate permits honest unknown inventory; the dedicated capability
gate requires a measured total. The producer runs before every real Docker-supervised
scan, rather than only selected profiles. Comparison evidence:
`runs/backend-gaps-c208-capability-comparison.json`. No verifier was relaxed.

The branded-banner fix is commit `3be582242c95463763ca276bce3393a6deeaf9ab`. Its isolated two-file patch
against native-launcher commit 2519598 passed all 2,084 tests without skips in 315.53
seconds; `make lint` passed. Source/test hashes matched the committed patch.
Logs: `runs/backend-gaps-branded-chromium-final-{suite,lint}.log`, 34 focused tests in
`runs/backend-gaps-branded-chromium-tests.log`. The exact-image sealed probe did not run while the benchmark held the lock; its
unstarted waiter was cancelled without touching that lock. No rebuild or numeric
inventory acceptance is claimed.

The inert native launcher is committed as `2519598`; its clean committed full suite
passed 2,079 tests without skips in 334.40 seconds and `make lint` passed. Logs:
`runs/backend-gaps-native-zap-2519598-{suite,lint}.log`. This does not validate the later
branded-banner fix. Native ZAP lab acceptance and operator allowlist approval remain
pending; the shipped manifest is empty and external-dast remains blocked.

### Inert native ZAP launcher and trusted channel — 11 October 2026

Added a network-none native worker with loopback API/bridge only, and supervisor-owned
Docker file IPC. The supervisor derives actual container ID, retains all capabilities,
and signs the exact anonymous GET. New private internal broker routes compare actual
proxy requests to signed commitments; the proxy never falls back to ordinary scan
admission for a malformed signed task. It removes signatures/tokens before upstream
transmission, rechecks grant lifetime after rate scheduling and stops response chunks
when a task closes. Task grant expiry is bounded by remaining scan wall-clock budget.
Immutable image, native JAR, addon and configuration identities are checked.

The shipped approved-rule manifest is empty and zero-dispatch is explicitly tested.
The initial eligible route is the frozen good/bad HTTP lab active-v2 XSS fixture pair;
external-dast, other services/routes, HTTPS and all unreviewed values remain refused.
`docs/ZAP_ACTIVE_ALLOWLIST_PROPOSAL.md` records proposed 40012 finite inputs and deferred
40018/40040 candidates with request estimates, mutation constraints and control mapping.
No operator approval, native tool qualification or deployed gate success is inferred.
The earlier no-transport statements below are historical. Public API shapes are preserved.

### Clean source validation at 211f452 — 11 October 2026

As requested, the backend-gaps full suite ran in a detached committed worktree at
`211f4529e6dd7507fbd1c17bd0b3550a5a9f702f`, not the shared source tree. The dedicated
`scopelens_test_backend_gaps` run passed 2,040 tests without skips in 320.85 seconds.
Clean `make lint` passed (404 formatted files and frontend typecheck).
Tracked candidate files remained unchanged. Logs and a structured validation receipt
are in `runs/backend-gaps-clean-211f452-{suite,lint}.log` and
`runs/backend-gaps-clean-211f452-validation.json`. These counts overlap prior suites.

The initial dependency symlink caused uv to rebind the shared editable package during
lint setup; this was immediately restored. The worktree now uses an independent
uv-frozen virtual environment. Pytest always used explicit candidate backend PYTHONPATH;
frontend node_modules/vendor symlinks are dependencies, not uncommitted source.
No image build, deploy, worker provisioning or measured live gate occurred. Later main
changes require their own selected-candidate validation; no deployed acceptance is added.

### CORS redaction diagnosis and staged ZAP policy — 11 October 2026

A stack-locked CORS retry created `c637136c-0057-48e9-8566-9e63b58a5ce4` and reached
real browser reads. The gate failed because stored structured evidence replaced both
credential-presence booleans with `[redacted]` strings. The route itself aborts requests
with an Authorization header; the redacted string was not evidence of such a header.
Commit `4457995` retains exact typed boolean presence facts and keeps every non-boolean
value under those keys redacted. Security tests: 57 passed, including 24 new cases.
The verifier preserves failed redacted artifacts. Fresh bad/fixed scans after a matching
image rebuild are pending; no deployed acceptance is claimed. Logs/artifacts:
`runs/backend-gaps-cors-retry.log`, `runs/backend-gaps-cors-retry/`,
`runs/backend-gaps-cors-redaction-tests.log`.

`broker/zap_task.py` adds a default-disabled, lab-only supervisor-signed policy foundation.
Fixture pins exercise exact request guards, scope/task/worker binding, cancellation,
expiry, replay rejection, shared scan accounting, and concurrent task ceilings. No pin
is added to the production registry. There is no internal API/proxy route or trusted
container-channel adapter, and no native active launcher. The VM TCP relay's common
peer address is insufficient for worker identity; an authenticated control-channel
adapter must derive actual container identity before signing. Do not enable the policy
or external-dast until that transport, reviewed engine/configuration pins, and a genuine
vulnerable/fixed deployed gate exist. Private grant records are excluded from exports. Policy commit `900a214` passed 25
PostgreSQL integration tests (`runs/backend-gaps-zap-grant-tests-final.log`). An earlier
overlapping contract/browser/policy batch passed 76 tests
(`runs/backend-gaps-zap-grant-tests.log`); these counts are not added together.
The complete suite after resumed changes passed 2,034 tests with no skips in 373 seconds
(`runs/backend-gaps-resumed-complete-suite.log`); `make lint` passed
(`runs/backend-gaps-resumed-lint.log`, 401 formatted files and frontend typecheck).
These are shared-checkout source results; clean grouped-candidate and deployed gates
remain pending.

Read-only stack inspection found labs-edge and labs-validation healthy. The original
edge restart cause was nginx's absent labs-validation upstream; integration restoration
resolved it. This lane did not restart or deploy the recovered edge.

### Backend expansion source integration and acceptance audit — 11 October 2026

The trusted producer now measures immutable configured images with the sealed
`runtime-probe-v2` before ordinary coordinator workers, outside a database transaction
with the lease heartbeat active. Image references are frozen to measured IDs. Every
selected image must report a matching backend source digest. Cancellation, epoch, live
lease and scope expiry are rechecked before persistence. Failed/stale probes remove
snapshots rather than inventing inventory. Newly frozen expansion and adaptive plans
rebind the cached measurement. Supported passive prerequisites are checked separately
from tool inventory. Experimental and independent qualification inventories stay
separate. Recovery tasks receive no ordinary measurement.

Capability integration and unit/PostgreSQL tests landed in shared commit `8fffef4`.
Adaptive context work is commit `d0ed379`: anonymous GET reflection uses a fresh brokered
browser context and exact frozen task binding; supplied-session access uses isolated
role clients, exact read-only probe URLs and a global 12-request ceiling; callback
investigations read supervisor-owned stored receipts without issuing target requests,
new nonces or replaying dispatch. Login, write and authenticated browser reflection gaps
remain explicit. Adaptive access records do not merge separate attempts into baseline
access proof/coverage. Registered proof rules and deterministic scoring remain authoritative.

Credentialed CORS had a deployed attempt, not a passing gate. With the stack lock held,
owned workflow/validation fixtures were restored. The workflow fixture became healthy;
edge startup retained an upstream-health limitation. The verifier created scan
`37e6601d-1366-4556-b612-68d0e33abb90`; the supervisor could not connect to
`host.docker.internal:23976` and Lima had no matching worker VM at that time. No control
outcome or worker evidence existed. Cancellation returned 200; the verifier failed before
the fixed case. Logs: `runs/backend-gaps-cors-live.log` and
`runs/backend-gaps-lab-recovery.log`. VM restoration belongs to the integration lane.

`EXPANSION_ACCEPTANCE.md` accounts for every experimental registry entry. Missing pack
gates are explicitly not accepted with reasons; local fixture pairs are not treated as
deployed acceptance. ZAP active remains blocked/unimplemented. Its empty reviewed rule
allowlist and absent task-specific broker accounting/launcher are documented; scan-wide
admission cannot enforce exact action, method, input, request and time constraints.
No control qualification or new score coverage is claimed.

Validation uses dedicated PostgreSQL database `scopelens_test_backend_gaps`. Commands
ran sequentially against that database:

```sh
PYTHONPATH=backend .venv/bin/python /tmp/backend_gaps_test_runner.py .venv/bin/pytest \
  tests/integration/test_coordinator_capability_producer.py \
  tests/integration/test_coordinator.py tests/integration/test_cors_configuration_api.py \
  tests/unit/test_capability_producer.py tests/unit/test_runtime_capability_measurement.py \
  tests/unit/test_report_capability_reach.py tests/unit/test_adaptive_graph_loop.py \
  tests/unit/test_followup_contexts.py tests/unit/test_expansion_adaptive.py \
  tests/contract/test_containment.py -q --tb=short
make lint
PYTHONPATH=.:backend .venv/bin/python scripts/verify_credentialed_cors_lab.py
```

The affected command passed **163 tests** (`runs/backend-gaps-affected-final.log`), and
lint passed (`runs/backend-gaps-final-lint.log`). Separate capability/coordinator/report
and CORS API commands passed 79 and 7 tests; the browser/adaptive batch passed 55.
These overlapping counts are not summed. Collection succeeded with 1,948 tests.
The first full run produced 1,908 passes / 19 failures while shared source was changing.
Thirteen graph-harness failures were corrected and the affected rerun passed; one stale
source-inspection containment assertion passed fresh; shared lab overlay and holdout
manifest assertions were updated by their owning lanes. The second run retained three
old, already collected lab/holdout assertions (1,945 passes / 3 failures); fresh current
assertions then passed 34 tests. A full run passed 1,955 tests with no skips
in 377.68 seconds (`runs/backend-gaps-final-suite-green.log`). After the seven new
export-verifier tests were added, the complete current suite passed **1,962 tests with
no skips** in 373.28 seconds (`runs/backend-gaps-complete-suite.log`).
`runs/backend-gaps-final-suite.log` preserves the first result. An earlier local image
probe executed without owning the live stack lock is
excluded from accepted gate evidence and does not establish runtime acceptance.

API fields/endpoints are unchanged; `API_CONTRACT.md` describes when existing capability
totals can become numeric and the private measurement exclusion. Updated source has not
yet been measured on the dedicated VM. No frontend edit or database migration was made.

Commit `40eacdc` executes the embedded sealed probe in regression tests: source digest
parity and actual ZAP/Nuclei/testssl version-banner parsing pass (22 tests). Commit
`fe12389` adds the read-only `scripts/verify_runtime_capability_lab.py` gate and repairs
the authenticated-browser verifier's blanket unknown-count assumption. Its supervisor
database replay rejects fabricated counts, stale source/scan bindings, modified probe
measurements and private export leakage. The later export/native-browser fixture batch
passed **11 tests** (`runs/backend-gaps-capability-export-tests.log`); these overlap prior
checks and are not added to the full-suite count. Lint with these files included passed
(`runs/backend-gaps-final-lint-green.log`, 397 formatted files). The new verifier requires
a matching updated deployment and owned lab scan; no deployed producer result is claimed.

The complete-suite command was:

```sh
PYTHONPATH=backend .venv/bin/python /tmp/backend_gaps_test_runner.py .venv/bin/pytest -q --tb=short
make lint
```

The local runner derives the dedicated database URL from `Settings().database_url` and
sets `SCOPELENS_TEST_DATABASE_URL` to the `scopelens_test_backend_gaps` database; no base
URL or credential is printed. The integration lane has since restored and activated
its older `8a982ed` candidate. That does not accept this newer API/coordinator/worker
source or rerun the failed CORS gate. The live stack lock remained with other lanes
during this final test run; no deployment, reset or measured live gate was launched here.

| Stage | Status | Evidence |
|---|---|---|
| B1 Discovery and request plans | OpenAPI/HAR intake deployed; request-intent capture and durable revisions tested | Deployed imports, opaque-route discovery and safe operation-review API passed. Revisions remain coordinator-side with no public replay operation |
| B2 Broader input testing | HTTP and browser transport/proof connected | Authenticated HTTP/browser pairs and discovered query/form/JSON/path SQL plus DOM evidence passed on the worker VM |
| B3 Exposure/tool packs | Exposure packs and five pinned Nuclei templates connected | ZAP remains offline passive HAR analysis; active task enforcement/launcher and pack deployment gates remain |
| B4 Identity and access comparisons | Identity collectors/proof and native CORS source connected | CORS focused tests pass; latest deployed attempt had no reachable worker daemon. Broader access/session and final CORS gates remain |
| B5 Stateful/API/server checks | Browser workflows, callbacks and read-only cleanup recovery integrated | Six browser cases, four callback cases and two explicitly synthetic recovery cases passed on the deployed worker VM; broader HTTP pack gates remain |
| B6 Adaptive investigation | Fresh observation loop and additional browser/access/callback contexts connected in source | Earlier loop fixes deployed; new context dispatch has local proof tests, with VM acceptance and equal-budget comparison pending |
| B7 Qualification and scorecards | Pilot scoring/reach deployed; offline evaluator and trusted measurement producer connected | Saved browser proofs replay as TP/TN; development data cannot qualify. New producer VM/export acceptance and independent qualification remain |

Separate modules can be authored concurrently. A stage is not complete until integrated, tested
and exercised through the real backend; unit-level modules alone are not completion evidence.
All new active controls remain experimental until independent qualification. Existing owned
site URL authorization does not supply missing test identities or disposable staging records.

## Session log — 28 September 2026: browser workflow package (handoff task 1)

Scope: task 1 of docs/SCANNER_TASK_HANDOFF.md only (stored-marker, CSRF and upload-policy
browser workflows). Tasks 2–5 were not attempted and remain with the main agent.

Files touched: `backend/scopelens/browser/workflow_checks.py`,
`tests/browser/test_browser_workflows.py`. `backend/scopelens/domain/browser_workflow.py`
was reviewed and needed no change.

Defects found in review and fixed in `browser/workflow_checks.py`:

1. `journal.mark(..., "mutation_sent")` was re-issued on every mutation attempt. The
   production cleanup RPC (`expansion/control.py`) only admits
   `pending -> mutation_sent`; the second mark raises `PermissionError`, which the module
   did not catch, losing the whole result and its evidence. Now marked once per claim,
   before the first send. Pinned by `test_workflow_respects_journal_transition_state_machine`
   (a fixture journal mirroring the production transition table).
2. Cleanup-RPC failure could discard the result: `PermissionError` was absent from both
   except clauses and the `cleanup_failed` journal mark was not failure-suppressed. The
   finally block now matches the reviewed HTTP sibling (`workflows/assessment.py`):
   partial evidence is always returned and the failed mark is best-effort.
3. Duplicated `cleanup_sessions.verify(...)` call in the cleanup path (copy-paste
   artifact of the interrupted session).

Tests added (12 total in the file, was 4): unresolved `mutation_sent`/`cleanup_failed`
states fence new mutations; cleanup-channel failure retains all four evidence refs and
leaves the journal fenced; mid-run cancellation stops further mutations, retains partial
evidence and still restores the record through the separate cleanup channel; recipe
rejects shared writer/viewer identity and CSRF without a controlled foreign page.

Verification (commands and actual results):

- `uv run pytest tests/browser/test_browser_workflows.py -v` → 12 passed.
- `uv run pytest tests/browser/ tests/test_workflow_expansion.py tests/test_identity_browser.py tests/test_identity_expansion.py -q` → 79 passed.
- `uv run ruff check backend/scopelens/browser/workflow_checks.py tests/browser/test_browser_workflows.py` and `ruff format --check` on the same two files → clean.
- Full suite `uv run pytest -q` (PostgreSQL up) → 813 passed, 8 failed — all eight
  failures are pre-existing expansion-integration gaps in main-agent-owned areas
  (registry expects 22 shipped entries vs 43; manifest claims stale; undeclared
  egress-capable modules: `callbacks/probes.py`, `checks/expanded_active.py`,
  `checks/packs/exposure.py`, `identities/assessment.py`, `identities/lifecycle.py`,
  `identities/sessions.py`, `workflows/assessment.py`). None involve the files touched
  here; `browser/workflow_checks.py` is declared in `EGRESS_CAPABLE`.
- `ruff format --check` over the whole backend also flags pre-existing formatting in
  `backend/scopelens/execution/coordinator.py` and `backend/scopelens/writer/report.py`
  (not touched; shared-file ownership).

Remaining limitations for task 1 (not claims of integration): the package is exercised
only through local fixtures; it is not yet dispatched from an isolated browser worker,
not part of the immutable assessment configuration/API, and `browser_workflows` cleanup
authorization is not yet in the control channel — those are handoff task 2 and the
shared-file changes the main agent owns.

Expected behaviour under scan-wide egress revocation (to be confirmed through the real
broker): the control channel denies every operation, including the `cleanup_failed`
mark, so the durable journal row stays `pending`/`mutation_sent` and the resource
remains fenced against new mutations. The returned result keeps `cleanup_state`
`cleanup_failed` and every evidence ref; the failed mark itself is best-effort
(`suppress(PermissionError, ValueError)`) so a revoked control plane cannot discard
the partial evidence. Explicit fresh-authority recovery is the only path back to
`clean`; it must not replay the original test mutation.

## Main-agent verification — 28 September 2026

- Re-ran the preserved browser workflow suite: **12 passed**. The three reported fixes are
  present. No external website was fetched or scanned during this verification.
- Reproduced **7 failures / 814 passes** in the full backend suite before corrections;
  the eighth failure in the earlier report did not recur. Log:
  `runs/backend-review-before-20260928.log`.
- Corrected registry/manifest assertions for 22 legacy controls plus 21 expansion controls.
  The 17 enabled controls still require verified fixtures and reviewed mappings; all 26
  experimental controls remain separate and unsupported. No review state was promoted.
- Reviewed the seven newly flagged HTTP-capable modules. They use injected clients or
  IdentitySessions, not independent client construction. Recorded each transport dependency
  and added seven import-alias-aware checks that reject unbound HTTP client construction.
  This source check complements, and does not replace, deployed network containment tests.
- Added immutable `browser_workflows` configuration and cleanup admission, shared recipe-ID
  uniqueness, declared identity validation and viewer/foreign/upload URL scope validation.
  This enables configuration and control-channel admission only. Isolated browser worker
  dispatch and report proof aggregation remain unfinished.
- Added PostgreSQL-backed tests through the production policy application's HTTP routes.
  For both `pending` and `mutation_sent`, scan cancellation denies subsequent target
  authorization and both cleanup marks. Durable state is unchanged. A fresh scan/capability
  cannot reclaim or clear the resource. This verifies the real decision handlers and ledger,
  not a deployed mitmproxy/worker round trip. See `tests/integration/test_cleanup_revocation.py`.
- Targeted integration/invariant suite: **81 passed** in
  `runs/expansion-review-after-20260928.log`. Manifest-specific recheck after regeneration:
  **18 passed** in `runs/manifest-review-tests-20260928.log`.
- Corrected formatting and regenerated the source manifest. It records **43 controls,
  17 supported, 26 experimental**, with explicit pending integration and no new qualified
  families. It does not attest that current source is deployed in the pinned worker images.
- `make lint` passes, including the existing frontend typecheck. No frontend files changed.
- Final complete suite: **831 passed, 0 failed, 0 skipped** in 90.64 seconds.
  Log: `runs/backend-review-final-20260928.log`.

Task 1 module review is accepted. B5 remains **integration pending** until deployed workflow
and HTML/JSON report checks pass. Fresh-authority cleanup recovery still needs an operator
API and deployed verification; cancellation does not grant a cleanup exception.

## Backend connections and AI pipeline report — 28 September 2026

Main-agent work after accepting task 1:

- Connected HTTP identity, session and workflow observations to independent proof evaluation.
  Captures are bound to the frozen rule/recipe and one execution attempt. Only references
  admitted by the supervisor for the scan are accepted; provisional worker refs and verdicts
  cannot confirm. Missing instances remain in coverage. Cleanup needs both captured restored
  state and the durable ledger's clean state; unresolved cleanup preserves findings but
  prevents full coverage.
- Added configuration-time credential checks for owner, scope, expiry and availability.
  Error responses do not disclose credential values/references. Use-time checks remain.
- Added explicit versioned pilot rubrics for expanded profiles, including authentication,
  authorization, file handling and workflow categories where appropriate. Existing
  score-v1.0 behaviour is preserved. Reports use persisted rubric metadata, show per-control
  instance coverage and cleanup, and expose identity IDs/roles without login recipes.
- Connected the expanded, hash-pinned OSV corpus to profile freezing and passive component
  fingerprinting: 12 package identities / 194 records. Version matches remain potential;
  Linux/kernel, Microsoft-product and general live web-research coverage is not implemented.
- Added the fixed expanded browser worker and local fixture/launch tests. This is **not**
  dispatched by the coordinator yet. Fresh browser controller lease transitions, intake,
  browser workflow proof/report aggregation and deployed verification remain pending.
- Generic HTTP input checks explicitly block authenticated templates until their identity
  transport is integrated. They must not silently run under the anonymous client. Recorded
  probe errors now reach the independent evaluator. Reviewed adaptive HTTP/exposure artifacts
  retain their accepted provenance without granting identity-proof authority.
- Refreshed the source manifest to distinguish completed source connections from unfinished
  deployment and qualification. No registry control was promoted. No frontend source changed.

Verification:

- Full suite: **934 passed**, no skips/failures, 113.96 s;
  `runs/backend-expansion-final-20260928.log`. This complete run predates the final explicit
  authenticated-template guard and adaptive-provenance regression tests; those changes are
  covered by the later focused run: **47 passed** in `runs/expanded-evidence-final.log`.
- Component/proof/coordinator integration: **74 passed**;
  `runs/expansion-final-targeted.log`.
- New browser collector plus preserved task-1 module: **22 passed**;
  `runs/expanded-browser-worker-tests.log`.
- `make lint` passed, including frontend typechecking without frontend edits;
  `runs/expansion-final-lint.log`. Subsequent changed Python files were rechecked/formatted.
- No public site scan or live provider invocation was performed for this verification.

User-requested architecture artifact: `docs/reports/scopelens-backend-ai-report.html`.
It covers 16 pipeline branches, five AI roles, exact current source/data relationships,
version-disclosure limits, and pending work. The main diagram passed all nine showcase
checks and desktop containment at 1440×900, 1600×1000, 1920×1080 and 2048×1320.
Report browser checks verified all 16 rows, the AI filter, source links, and 390px mobile
containment. Screenshots were inspected. This is a source audit, not a target scan report.

Still open: browser dispatch/lease/proof integration; callback scan/control/receipt/report
integration; authenticated generic-input transport; broader reviewed scanner execution;
operator cleanup recovery API; independent qualification; rebuilt/deployed worker images and
end-to-end lab verification. Vendor-advisory research and a fresh observation/hypothesis loop
are explicitly missing from the current AI pipeline.

## Backend runtime integration — 28 September 2026

The backend is running at `http://127.0.0.1:8090` with the dedicated worker VM
configuration. No frontend files were changed. The operator will supply UI references
and direction before frontend work resumes.

Completed in source and focused tests:

- Browser workflows are dispatched to the existing isolated browser image with a new,
  coordinator-owned context lease after the preceding context closes. Worker RPC cannot
  reopen or take over a closed context. Captures retain producer, image, run and recipe
  bindings; report proof is recomputed from admitted observations and identity probes.
- Three experimental browser controls are registered: stored XSS, CSRF and upload serving.
  They remain experimental; development fixtures are not independent qualification.
- CSRF requires a cookie-authenticated viewer and evidence of ambient session cookies.
  Anonymous/header-only identities cannot establish CSRF proof.
- Control-channel HTTP/JSON failures become bounded permission errors. Partial evidence
  survives failed cleanup RPCs. A blocked or unclean browser workflow marks its collector
  incomplete rather than declaring successful completion.
- Authenticated HTTP input tasks use separate role clients, expiring credential references
  and identity verification before/after the request series. Report evaluation independently
  checks the frozen identity/task/template/plan binding. Missing or contradictory proof
  cannot confirm a finding. Generic authenticated browser-input proof remains incomplete.
- The five-template Nuclei expansion runner is connected to the fixed HTTP worker. Engine
  and template hashes, exact target binding, proxy use, caps and cancellation are checked.
  Candidate matches cannot grant assessed coverage or confirm vulnerabilities.
- API and policy share a persistent encrypted credential volume (API writable, policy
  read-only). Only those services receive its key. Existing installations use the
  non-rotating `scripts/initialize_identity_key.py`; new installations generate a separate
  key. The initializer was run locally without printing the key.
- Cleanup claims now serialize by stable target origin/resource across scope revisions.
  Renewing a scope cannot forget a previous unresolved mutation. Five database-backed
  revocation/revision tests passed (`runs/cleanup-scope-revision-tests.log`).

Measured deployed browser gate so far (`runs/verify-expanded-browser-final.log`):

| Case | Deployed result | Cleanup and exports |
|---|---|---|
| Stored XSS, vulnerable | Confirmed issue | Complete; HTML/JSON saved |
| Stored XSS, fixed | Pass | Complete; HTML/JSON saved |
| CSRF, vulnerable | Confirmed issue | Complete; HTML/JSON saved |
| CSRF, fixed | Pass | Complete; HTML/JSON saved |
| Upload serving, vulnerable | Inconclusive; worker deadline | Resource remains fenced; partial evidence retained |
| Upload serving, fixed | Not run after preceding gate failed | No result claimed |

These deployed runs precede the latest ambient-cookie proof requirement, completion-summary
change and authenticated HTTP/expanded-tool wiring. Those changes require image refresh and
new deployed verification. The upload runtime hang is being diagnosed; B5 is not signed off.

Validation: `make test` passed 1,023 tests in 141.37 seconds before the two added
scope-revision cases; authenticated input/report-proof focus passed 87 tests. The new
credential-volume/key focus passed 13 tests. Nuclei's separate pinned-image fixture collected
five vulnerable candidates and zero fixed candidates through the proxy; this does not
constitute deployed scan/report qualification. Logs are under `runs/`.

Callback runtime/client preparation also has 36 passing focused tests. It uses durable,
signed closure timestamps and an independent stored-receipt verifier. Configuration,
closure-table migration, private RPC routing, trusted request capture and deployed dispatch
remain unfinished. Operator cleanup recovery and independent expansion qualification also
remain open. No external target was scanned during this integration session.

### Deployed browser gate completed

The final frozen deployment passed all six cases in
`runs/backend-browser-final-live.log`; reports and receipts are in
`runs/expanded-browser-final/`. Stored XSS, CSRF and upload serving each confirmed the
vulnerable case and passed its fixed counterpart, with verified cleanup and HTML/JSON
exports. Upload previously hung inside Chromium's page close while its form response was
unfinished. The collector now waits for the matching request to finish with a 10-second
limit. Fresh VM delayed-response/timeout probes also returned with retained evidence and
verified cleanup (`runs/upload-vm-timeout-diagnosis.log`).

Authenticated HTTP redirect checks passed the full deployed credential-to-report path
on both vulnerable/fixed fixtures (`runs/backend-authenticated-live.log`). A subsequent
review added exact frozen method/path checks to report proof; route/method tampering and
missing catalogues are rejected. The final suite passed **1,035 tests**, and lint passed.

The synthetic browser fixture was explicitly restarted for the updated routes. With no
active lab scan, its seed and empty records were verified through container loopback;
one prior unresolved lab cleanup row was restored with an `operator-lab-maintenance`
audit event. This was an isolated lab reset, not a delivered general recovery API.

Browser workflow dispatch/proof/report integration is now measured. The controls remain
experimental. Next work is generic authenticated browser-input proof and callback
configuration/control/dispatch integration; operator recovery and independent qualification
remain open. UI implementation waits for the operator's references and direction.

### Authenticated browser inputs and callback dispatch deployed, 28 September

The dedicated VM deployment and `/readyz` report schema `0009`. No frontend files changed.

- `runs/backend-authenticated-browser-live.log`: bad `f03b8efb-15d7-4a2e-befd-05475500d9fc`
  confirmed HTML rendering; fixed `bb21a644-9534-4028-86ca-413f3ad1b97f` passed. Each task
  used three fresh browser contexts with before/after identity observations. The report verifier
  requires the reviewed browser producer and rejects HTTP evidence substituted for browser proof.
  HTML, JSON and redacted proof are in `runs/authenticated-browser-deployed/`.
- `runs/backend-callback-live.log`: SSRF bad `5fb3f5b8-5bde-4ffc-b70d-f3548d1689c6`
  and XXE bad `93b107ba-963f-457d-b043-2e3376d28361` confirmed controlled HTTP canary
  interaction. Fixed counterparts `4baff7cf-651a-4a50-861a-3de577ba416c` and
  `b7a360fa-cab4-4200-82de-358b7e46f1d9` remained **inconclusive**, with no finding.
  Absence of a callback is not proof of resistance. Reports are in `runs/callbacks-deployed/`.
- Each callback case stored three broker-observed request/response records and three signed
  nonce closures. Vulnerable cases had two target-peer receipts; fixed cases had zero.
  The supervisor reconstructs proof from private records, discards worker-supplied callback
  snapshots, and stores a safe trusted snapshot without bearer URLs. Multiple recipes for
  one control retain incomplete coverage instead of dropping missing instances.
- The receiver is an optional `callbacks` service at lab address `172.28.0.17:8091`, with no
  host port or control routes. The synthetic fixture at `.18:8080` can call only that exact
  numeric collector through its application allowlist. The XML fixture recognizes the reviewed
  marker shape; it does not constitute independent validation of a real XML parser family.
- Real-proxy capture tests (`runs/callback-proxy-capture-tests.log`) verified exact original
  URL/body commitments and response status; unavailable capture blocks dispatch. Workers cannot
  invoke the private capture endpoint through their proxy-local command interface. Callback
  bearer paths are redacted in plain and percent-encoded audit text.
- The proxy containment suite passed (`runs/backend-callback-proxy-suite.log`). The first full
  suite found stale schema/network inventory assertions and a local-environment-dependent
  disabled-feature test. These were corrected; final full-suite verification follows the
  recovery integration. None of these development gates promotes experimental registry controls.

Read-only operator cleanup recovery is now being wired under fresh scope authority. It must
verify restoration from new trusted identity/readback evidence and must never replay the old
mutation. Independent expansion qualification remains open.

### Read-only cleanup recovery deployed

`runs/backend-cleanup-recovery-live.log` records two successful recovery tasks,
`a9a58f84-80ea-4019-b25f-fec7ea3c8c1f` and `433e0513-585b-41c9-85dc-7e077777849a`.
The gate deliberately injected two new synthetic pending intents and audited them as such.
It did not change historical fences and did not execute an original mutation. Each recovery
used a fresh scope revision and newly scoped credential, authenticated before/after readback,
stored trusted evidence, and released only its own original row. The first left the second
pending until its separate verification. No target mutation or cleanup POST was sent.
Artifacts and explicit fault-injection disclosure are in `runs/cleanup-recovery-deployed/`.

The recovery task type is `cleanup_recovery_verify`. Its dedicated worker cannot fall through
to crawling, browser exploration, adaptive execution, TLS probes or report-model calls. It
produces a typed recovery result and evidence, not a vulnerability scorecard. Module/API/
coordinator tests cover wrong origin/identity, old authority, changed fences, corrupted or
untrusted evidence, and blocked readback. `runs/cleanup-recovery-final-tests.log`: 24 passed.

B6 control flow also now re-observes after each follow-up and retains partial baseline
obligations. It checks shared reservations and live epoch/lease/expiry before admission;
bookkeeping-only changes cannot trigger repetitions. `runs/adaptive-observation-loop-tests.log`
contains 32 passing focused tests. Broader reviewed follow-up dispatch and deployed equal-budget
comparison remain open. These fixes were included in the recovery deployment.

### Imported plans, browser discovery and reach reports deployed

The unchanged combined source passed **1,286 tests**, with no skips or failures, in
`runs/backend-import-final-suite.log`. Lint passed in `runs/backend-import-final-lint.log`.
The API and worker images were rebuilt, frozen, installed in the worker VM and deployed with
the callback service still enabled. `/readyz` remains ready at schema `0009`.

- Bounded OpenAPI/HAR intake discards captured sample/header/body values. OpenAPI path examples
  revert to their unresolved route template. Imports cannot authorize their own execution;
  an explicit reviewed baseline and action policy are required. Byte, structure and local-reference
  expansion bounds reject oversized/recursive documents without echoing raw input in errors.
- Plan revisions preserve the denominator and persist execution claims before dispatch.
  Already admitted work, including unknown outcomes, is not replayed. Trusted earlier proof
  survives only with an identical persisted task/template binding. Tests use a second database
  connection to prove the scan lock is released before worker execution. The operator endpoint
  exposes safe read-only history; there is no public resume/revise execution endpoint.
- The explorer now emits normalized request intentions, including SPA POST shapes it blocks.
  A real Chromium test discovered query, form and JSON operations while sending no POST.
  Credential samples became refresh references. Imported incomplete source-map templates cannot
  enter the exposure collector through a secondary discovery list.
- Deployed OpenAPI/bad `733c29b9-5ea6-4cfc-9609-7db131393d8b` confirmed the protected redirect;
  HAR/fixed `1d174bf1-92a3-47b0-9748-41063ba05a76` passed. Both scans completed. Configuration,
  claims, history, identity proof and HTML/JSON were checked. See `runs/backend-import-live.log`
  and `runs/import-intake-deployed/`.
- Deployed browser/bad `a90925e4-e6fb-4e26-99f1-c80fe7126687` confirmed HTML rendering;
  browser/fixed `20561172-cc36-48da-82a6-8def10e06136` passed. Both retained `completed_partial`
  for the independent crawl limitation. Their protected input proof completed, and the new
  request-intention artifact was stored with trusted browser provenance. See
  `runs/backend-browser-reach-live.log` and `runs/authenticated-browser-reach-deployed/`.
- Report HTML/JSON and the typed summary API agree on role/route reach and balanced instance
  counts. Private catalogues, revision snapshots, request baselines, credential references and
  execution claims stay out of exports. Unmeasured installed/executable/independently qualified
  totals remain unknown. Missing or malformed qualification provenance cannot create a count
  or crash reporting. No trusted measurement producer or independent qualification is claimed.

No external target was scanned, no registry review state was promoted, and no frontend file
was changed. Broader discovered-operation acceptance, credentialed CORS, constrained active
scanner tasks, remaining pack deployment gates and evaluator integration still require work.

### Native CORS source and discovery acceptance work in progress

The native credentialed-CORS collector, immutable recipe/grant validation and report proof
aggregation passed 110 focused regressions and 17 API/credential tests. Logs are
`runs/cors-final-focused-tests.log` and `runs/cors-api-tests.log`. The browser tests exercise
the production guarded context and observe actual ambient-cookie requests at the synthetic
fixture. The control remains experimental. An automatic cybersecurity review stopped the
subagent during a final header-handling follow-up; that follow-up and the deployed CORS gate
are pending, and were not reassigned to evade the review.

A separate development discovery fixture now exposes opaque query, form, runtime JSON and
OpenAPI path inputs. Tests discover all four, keep unreviewed POSTs blocked, then distinguish
the vulnerable/fixed in-memory read-only implementations. The runtime JSON route is absent
from static discovery. `runs/backend-discovery-fixture-tests.log` records 17 passing tests;
`runs/backend-discovery-contract-tests.log` records 36 passing fixture/manifest contracts.
The paired optional services have exact lab bindings, an internal network and no host ports.
The deployed discovery gate is still pending at this entry.

UI work remains on hold for the operator's references and direction.

### Offline expansion evaluation connected

The evaluator now supports freeze, collect, measure, qualify and compare. Collection only
reads existing authorized scan/report/evidence APIs; ground-truth labels remain evaluator-local.
Exact task/template/plan/role/input binding, producer, hashes and identity facts are checked
before deterministic proof replay. Unsupported families receive no automatic proof credit.
The deployed HTML pair independently replays as one true positive and one true negative.
`runs/expansion-evaluator-gate-final/gate-receipt.json` records the result. Its freeze is
post-hoc, one positive/negative pair is too small, and no independent curator or holdout exists;
qualification correctly fails. Unknown historical costs, fingerprints and budget ceilings stay
unknown. The comparison command refuses an ineligible baseline pair. Focused tests: 69 passed
in `runs/expansion-evaluator-tests.log`. Contract: `EXPANSION_EVALUATION_CLI.md`.

### Deployed discovery pair and combined verification

The combined source passed **1,362 tests**, no failures or skips, in
`runs/backend-discovery-final-suite.log`. Lint passed in `runs/backend-discovery-final-lint.log`.
Images were built, frozen and installed on the worker VM. The backend remains ready at schema
0009 with the callback service retained. The final CORS follow-up/deployed gate described above
is still pending; its focused tests do not replace that gate.

`make labs-up-discovery` and `make verify-discovery` reproduce the new isolated development
pair. See `DISCOVERY_LAB.md`. The following runs supplied no endpoint templates to the scanner:

| Variant | Discovery scan | Assessment scan | Outcome |
|---|---|---|---|
| Vulnerable | c6e9b389-7c04-49af-89a5-4e63c7ba2716 | c91ac098-3513-4b2b-8203-dfa291aca067 | Four SQL input locations and one DOM-only issue confirmed |
| Fixed | a500d267-6399-4264-8207-012e4f056f5b | e7e73e2e-fefe-4c5a-b4cb-0bba19090863 | All four SQL locations passed; browser negatives passed without corresponding confirmation |

Discovery completed for both. Assessments remain `completed_partial`, preserving unrelated
blocked/inconclusive tasks and their denominators. Eight completed SQL/DOM artifacts per scan
were separately replayed through the deterministic proof function in
`runs/backend-discovery-proof-replay.log`. Reports and receipts are in `runs/discovery-deployed`;
live output is `runs/backend-discovery-live.log`.

The first harness attempt incorrectly reconstructed schemas from redacted public artifacts.
The scanner had already discovered all four kinds; fields such as cookie values, credential
references and authority metadata are deliberately scrubbed from exports. The evaluator now
reads the persisted catalogue locally with exact scan/scope binding. Export redaction was not
weakened. Operator-facing safe request-template review remains a separate backend contract gap.
No external targets or UI files were touched. These cases are development validation, not
independent qualification.

### Safe discovery review API deployed

`GET /api/assessments/scans/{scan_id}/plans/{plan_id}/templates` now provides typed,
owner-bound, paginated metadata for one exact persisted revision. The projection validates
scope/origin/profile/catalogue/plan/task binding, exposes stable opaque input IDs and strips
baselines, credential references, provenance and execution authority. Malformed snapshots get
a generic 409; absent or other-owner records get 404. It performs no discovery or target action.

The added API/projector plus existing import/expansion API regressions passed **35 tests** in
`runs/request-template-review-tests.log`. The earlier full suite of 1,362 passed before this
addition; it is not presented as a full rerun of the added endpoint. Final lint passed in
`runs/backend-review-api-final-lint.log`.

The updated images were frozen, installed on the worker VM and deployed. The independent
read-only check in `scripts/verify_discovery_review_lab.py` passed on both discovery scans and
both assessment scans above: 19 templates each, all four input locations, identical discovered
and assessed IDs, stable pagination, 401 unauthenticated, 404 absent plan, 422 invalid page size,
and no forbidden private fields. No target requests were made. Evidence:
`runs/backend-review-api-live.log`, `runs/discovery-review-deployed.json`.

The future `make verify-discovery` command now uses this API instead of its initial local
DB catalogue reader. Its source joins proof inputs by the same stable opaque identifier.
The measured active scans were not repeated merely to test a read-only projection; the API
check validates identical bindings against their saved results. `/readyz` remains ready at
schema 0009. No UI work started. Remaining backend work in B3/B4/B5/B6/B7 stays open.

### Academic workflow development cases — 29 September 2026

Added the feature inventory and acceptance sequence in `ACADEMIC_WORKFLOW_FEATURES.md`.
Existing identity and workflow engines now have a local academic fixture pair for
cross-student record access and unauthorized marks/attendance changes. Tests use two
students plus staff, authorized view controls, independent read-back, restoration,
wrong-credential handling, and cross-property resource fencing after failed cleanup.
The development recipe helpers accept explicit loopback origins only.

Eleven academic cases passed; the combined identity/workflow/configuration API suite
passed 69 tests with no failures/skips. Lint passed. Logs are under
`runs/academic-workflows/`. This establishes local development behavior only. The new
academic cases have not passed deployed broker/supervisor provenance, independent proof
replay or release qualification. B4/B5 remain open. No external target was scanned,
no real academic record was changed, and no registry state was promoted.

### Student ERP session verification — 5 October 2026

A normal login to the operator-supplied student ERP URL succeeded using the
dedicated test account. A paired read-only request to the existing Home route
returned the matching account header with the session and no account header
without cookies. This does not demonstrate an anonymous login bypass. No major
authenticated vulnerability has been confirmed, and no academic record was changed.

Opt-in HTML identity probes are implemented in source with bounded extraction,
digest-only identity observations and immutable probe binding. The implementation
agent reported 250 unit tests and 209 existing synthetic integration/browser tests
passing; the primary agent independently reran the new HTML suite: 48 passed.
These are source/local test results, not deployed customer assessment evidence.

The private account receipt distinguishes browser login verification from scanner
verification. Session import, deployment and an end-to-end authenticated scanner
check remain pending. Cross-student and staff permission tests also require separate
test identities and explicitly disposable records; none are inferred from the
single student login. No authenticated automated customer scan is claimed complete.

### Cookie-only identity integration and deployed lab gate — 5 October 2026

Fixed a configuration gap: declaring identities without a permission matrix,
workflow or lifecycle policy previously emitted no independent session observation.
The fixed collector now performs one bounded GET/HEAD probe per nonanonymous
identity using supplied encrypted references. It does not perform login, follow
redirects, mutate records or fall back to anonymous access. Observations bind the
original immutable configuration and complete probe contract and contain only an
identity digest. They project actor readiness without earning a control pass or
vulnerability credit.

The primary agent independently ran the new 35 readiness tests, the existing
250 HTML/session/proof/readiness tests, 49 academic fixture/driver tests and 10
credential API tests. Each command passed; these overlapping suites are not added
into a total. The implementation agent's focused regression batch passed 154 tests.
`make lint` passed after formatting four existing files. No database migration.

Rebuilt backend, tool, Kali and browser images, froze their IDs, installed workers
on the dedicated VM and passed `scripts.verify_worker_vm`. Updated the backend with
the release and worker-VM overlays. The independent deployed gate
`scripts.verify_html_identity_lab.py` passed against the exact owned
`labs-academic-b` binding:

| Case | Scan | Actor readiness | Trusted session observations |
|---|---|---|---:|
| Valid supplied session | `979a2a36-147b-4056-827c-8be77fe50e07` | `verified_probe` | 1 |
| Invalid supplied session | `333bb093-0fda-4c9a-8621-186c0c9b379c` | `failed_probe` | 1 |

Both scans completed. Stored evidence hashes, supervisor provenance, frozen
configuration binding and independent observation replay were checked. No permission
or lifecycle case earned coverage from these readiness observations. No raw fixture
account text or cookies appeared in the saved receipts. Evidence is under
`runs/html-identity-deployed/`; build, deployment, isolation and lint logs use the
`runs/html-identity-*` prefix. Restored the missing lab validation service so the
lab edge forwarder could start; no customer server was interrupted by lab recovery.

The customer browser is user-controlled. The browser tool explicitly paused access;
session import and a customer authenticated scan remain pending return of control.
No customer scan or major customer finding is claimed from these synthetic gates.

### Fresh student session and scanner transport gap — 5 October 2026

After browser control returned, a fresh home request showed that the earlier
session had expired. One normal login with the existing encrypted test credentials
succeeded. A fresh read-only home request matched the exact account-header digest.
Imported the session into the encrypted owner/scope-bound store and created a new
immutable cookie-only assessment configuration. No cookie or account text appears
in this log.

Scanner run `ea88da4b-13c8-4bd5-a7ab-caeb49628f0a` finished partial. Its trusted
identity observation reports `identity_probe_transport_unavailable` with no HTTP
response, so scanner session readiness is still unverified. No permission case was
configured or proven and no major customer finding is claimed. The broker admitted
the intended home GET. Separately, browser navigation incorrectly started at `/`
outside the approved `/auerp` application prefix. Source now selects a permitted,
nonexcluded entry path and preserves the existing broker boundary. Transport
failures now emit fixed error categories without exception text or secrets.
These source fixes still require deployment and another bounded scanner check.

### Deployed application entry repair and owned HTTPS diagnosis — 5 October 2026

The coordinator's permitted-entry fix alone did not reach the crawler/browser callers: both rebuilt the root URL. Local regressions reproduced these failures before the fix. The crawler and browser controller now use a canonical permitted application seed; the exposure pack also filters out-of-scope root probes before target I/O. Fixed transport error categories are included in the deployment. No TLS, scope or budget enforcement was weakened.

Rebuilt and froze the API/coordinator plus tool, Kali and browser images, installed them on the dedicated VM with the existing provisioning script, passed VM containment/cancellation and the live broker boundary gate, and applied the release/worker-VM overlays. All seven nonterminal scan states were checked before restarts; only the existing 26 September queued intent remained. `/readyz` and immutable runtime image checks passed. The source fingerprint is `c7e5c7b382b456e3e2da7d9d0c648ad744da4f7af8a08be2f214820255cf4073`.

The deployed academic HTML gate passed for valid scan `59b0067f-0034-4a9b-9b63-1d44c82d69be` and invalid scan `729769ee-2bbd-4587-9a58-40f0aa976b83`; both completed. The owned HTTPS `/app` gate passed for valid scan `5bb9cfe9-6fd9-4b83-9258-72b75880322f` and invalid scan `f00a95f7-5c6d-4fb0-abfe-0c1b6208b77e`. Trusted crawler responses and browser states started at `/app`, and independent identity replay matched valid/invalid expectations. Each case produced one trusted session observation and earned no readiness control pass. HTTPS scans remain partial because `conditional-config` and `testssl` tool coverage is incomplete in this narrow scope.

Focused suites passed separately: 74 source regressions, 133 browser/authenticated-input regressions and 45 containment/scope/discovery contract tests. Python lint and formatting passed. Full commands, receipts and remaining limits are documented in `HTTPS_IDENTITY_TRANSPORT.md`; logs and receipts are under `runs/https-transport-diagnosis/`.

The HTTPS pair passed through the deployed VM even before rebuilding. These owned results do not reproduce or resolve the customer-specific transport failure. No new customer request, customer authority refresh or plaintext customer credential access was made during this task. Existing partial customer evidence is preserved; authenticated customer scanner readiness and major customer findings remain unverified.
