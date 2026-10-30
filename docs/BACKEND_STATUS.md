# Backend status

The current instruction is to complete the Phase 1 backend through reports and scorecards;
UI work is excluded. Milestone boundaries do not require another kickoff prompt.

## Windows transfer checkpoint, 12 October 2026

Final backend code `ebf0af8` is clean-qualified: 2,447 passed, zero failed/skipped,
plus lint and TypeScript checks. Grouped deployment, dedicated worker VM verification,
proxy containment, and local sandbox VM checks passed. All final service image IDs
match the release freeze and ready schema is 0009. See
[repairs and measured limitations](FINISH_BEFORE_WINDOWS.md) for the authoritative
current checkpoint; the sections below retain historical states.

Arkyon's final recheck recovered 82.4% and six conclusive controls after fixing
response-body capture across navigation. Stage completed17.6%. Rekvon now completes
without the prior root asset gap/ReadTimeout, but `/app/` remains unresolved and
coverage stays17.6%. The same original4/5 scopes/budgets were used, and audits verify
effective limits. No incomplete check was converted to a pass without evidence.

All five detectors remain experimental by operator decision. Native ZAP now completes
and hands off its result cleanly, but the unchanged rule misses the vulnerable fixture;
paired acceptance remains failed, production ZAP disabled and shipped approvals empty.
No detector tuning or new production routes/scopes are included. Windows WSL2 setup,
source/history/vendor archives and evidence are prepared for transfer. Windows runtime
acceptance and the Mac-only VM topology are explicitly separate.

## Timeout repair qualified and deployed — 12 October 2026

The clean exact `c32ff6a3eb32045914db88f71b0813742c14967d` checkout passed
2,408 tests with no failures or skips in 395.96 seconds, plus `make lint`.
The continuation verified and retained those existing results rather than rerunning
the suite. The prior `db730a0` release records were archived before deployment.

The grouped build, worker VM provisioning and boundary verification, and frozen
service activation completed successfully. Deployed source fingerprint is
`2ddfda8c096047130ee60e2556fbb006687f86a2f5eba1220b78a1a2e45b72f9`.
All six control service image IDs match the release pins; `/readyz` reports ready
at schema 0009. The browser active ceiling remains 1,200, ZAP remains disabled,
and the shipped approval list remains empty. Sandbox checks were skipped because
the gateway on port 8099 was unavailable; no sandbox acceptance is claimed.

The unchanged owned-lab gate runner was prepared for this deployment, with the
same temporary manifest hash `a166ac0713dbe30afb4e0ab675ce2500164c5108cdc3a682ce4e1f35bd190952`.
The operator chose to wait for unrelated host tests to finish. The runner waited
without holding the stack lock, then repeated its preflight and ran the vulnerable
fixture as scan `881a6d78-67b7-4bdf-8a43-913776e6e54f`.

The native gate failed. The scan completed partial; the native worker exited 1,
its grant closed after one admitted request, and no candidates were observed.
Trusted response telemetry records HTTP 502 with broker decision `allow` and
3.513 seconds elapsed. Worker stderr records `URL_NOT_IN_CONTEXT` at
`ascan/action/scan`, with local API HTTP 400. These are the retained failures;
the underlying cause of the allowed request's HTTP 502 is not established.
The fixed fixture was not run, and no production origin was activated.

Official restoration passed, then a separate continuation check reverified all
six pinned control images, ready schema 0009, active browser ceiling 1,200,
absence of temporary manifests/signing environment, empty shipped approvals,
no unexpected pending scan, and absence of the stack lock.
Evidence is in `runs/c32ff6a-continuation-20261012/`, including the qualification
receipt, deployment log, deployed-state and final-restoration receipts, host-test
wait observations, and previous release archive. Native reports and hash-verified
trusted diagnostics are in `runs/backend-gaps-native-lab-c32ff6a/`.
Native acceptance and production activation remain unmet.

## Native API deadline and response diagnostics repair — 12 October 2026

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

## Native deployed retry failed; official restoration proven — 12 October 2026

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

## Atomic native request publication — 11 October 2026

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

## Native launcher failure evidence — 11 October 2026

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

## Offline native startup diagnosis and source repair — 11 October 2026

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

## Deployed capability acceptance and failed native ZAP gate — 11 October 2026

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

## Inert origin-scoped native ZAP and HTTPS source — 11 October 2026

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

## Credentialed CORS observations on c208c00 — 11 October 2026

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

## Inert native ZAP transport implementation — 11 October 2026

The native launcher and supervisor-derived Docker container channel are now implemented
in source. The network-none ZAP worker receives no capabilities or Docker socket.
The trusted supervisor signs exact requests from its created container; the mandatory
proxy binds observed requests to signatures, spends task/scan budgets and rechecks task
liveness after scheduling and during response streaming. Grant deadlines include the
remaining scan wall-clock budget. Cancel/close revokes transmission; task tombstones
prohibit reissue. Native executable JAR/addon/config hashes are checked before scanning.

The operator manifest `checks_registry/tooling/zap-active.json` remains empty, so dispatch
makes zero active requests and does not access Docker. Only the owned good/bad HTTP
active-v2 XSS fixture pair is eligible when an approved pin exists. External-dast remains
blocked. Native observations receive no proof or scoring credit. The proposed allowlist
and exclusions are in `docs/ZAP_ACTIVE_ALLOWLIST_PROPOSAL.md`; no rule is approved and
no native deployed acceptance is claimed. Matching-image CORS/native/capability gates
remain pending. The historical "no launcher" statements below describe earlier commits.
Public API response shapes are unchanged; private internal broker routes were added.

## Clean backend-gaps source validation — 11 October 2026

Detached worktree `/tmp/scopelens-backend-gaps-tests-211f452` retained exact tracked
commit `211f4529e6dd7507fbd1c17bd0b3550a5a9f702f` throughout validation. Its complete
suite passed **2,040 tests, no skips**, in 320.85 seconds using
`scopelens_test_backend_gaps`; `make lint` passed with 404 formatted files and frontend
typechecking. Logs: `runs/backend-gaps-clean-211f452-suite.log` and
`runs/backend-gaps-clean-211f452-lint.log`; structured receipt:
`runs/backend-gaps-clean-211f452-validation.json`.
This supersedes the shared-checkout result for this exact source commit, and does not
validate later main commits. No build/deploy/live gate was performed in this run.

## Backend gate retry and staged ZAP grants — 11 October 2026

The credentialed CORS retry reached native browser proof in scan
`c637136c-0057-48e9-8566-9e63b58a5ce4`, but is **not accepted**. Evidence redaction
converted `cookie_present` and `authorization_present` booleans into strings, so the
verifier rejected the bad case before running fixed. Commit `4457995` preserves only
these two exact boolean fields; strings, numbers, containers and similarly named keys
remain redacted. Fresh bad/fixed scans on rebuilt API/worker images are still required.
Existing stored proof cannot recover the removed values. Redacted artifacts are in
`runs/backend-gaps-cors-retry/`; this is a failed gate, not accepted evidence.

ZAP has a staged supervisor-signed broker policy in `broker/zap_task.py`, disabled by
default and admissible only for owned lab active-v2 scopes. It binds each grant to its
scope version/expiry, cancellation epoch, actual worker container ID, task and reviewed
rule/config hash; exact GET URLs, finite input values, empty body, nonce replay protection,
request accounting and deadline are checked under the scan row lock. Its signing key
and token must remain supervisor-side. The worker VM relay hides individual worker peer
addresses, so an ordinary worker-provided ID cannot establish ownership. There is **no
trusted container-channel transport or native active launcher**, and the reviewed rule
registry remains empty. These policy tests do not establish worker transport isolation.
External-dast integration and native labs-good/labs-bad acceptance remain blocked.

After these resumed changes, the complete suite passed **2,034 tests with no skips**
(`runs/backend-gaps-resumed-complete-suite.log`, 373 seconds), and `make lint` passed
(`runs/backend-gaps-resumed-lint.log`). The grant integration batch passed 25 tests;
these overlap the complete suite. A clean grouped-candidate build and live gates are
still required; these source checks confer no deployment acceptance.

The earlier labs-edge restart was caused by nginx resolving the absent
`labs-validation` upstream. After the integration lane restored the service, both edge
and validation were observed healthy on this retry. No edge change or restart was made
by this lane during the retry.

## Backend expansion source update — 11 October 2026

The supervisor capability producer is connected to coordinator dispatch in source.
Its sealed offline probe measures configured immutable images, binary versions/hashes
and backend source identity. A source/image/plan mismatch leaves capability totals
unknown. It admits supported passive controls only and does not promote experimental
controls or infer completion from installed tools. Private measurements are excluded
from API/export plans. Existing response shapes are unchanged.

Adaptive dispatch now supports anonymous GET browser reflection, read-only access
investigations with already supplied sessions, and verification of stored callback
receipts. Each retains prerequisite checks, budgets, durable claims and registered
proof rules. Login-based access and authenticated browser reflection follow-ups remain
blocked. Access follow-up evidence remains separate from baseline coverage so distinct
attempts are not mixed into one access proof. No callback or mutation request is replayed.
These are source/local results, not deployed adaptive-gain evidence.

The credentialed CORS gate is **not accepted**. The owned fixture became healthy, but
scan `37e6601d-1366-4556-b612-68d0e33abb90` could not reach the configured worker daemon
and was cancelled before a control outcome. Updated-image capability and adaptive VM
gates remain pending. Constrained ZAP active execution is **not implemented**: the
reviewed allowlist remains empty and no trusted task transport/native launcher exists. A staged broker policy now exists
but has not accepted native execution.
The [acceptance ledger](EXPANSION_ACCEPTANCE.md) lists all 29 experimental controls,
their fixture evidence and missing deployed gates. Historical acceptance there does
not accept the latest source changes.

The final complete full-suite run passed **1,962 tests with no skips**
(`runs/backend-gaps-complete-suite.log`). The affected PostgreSQL/proof/containment
suite separately passed 163 tests. The read-only capability export verifier and
native browser fixture checks passed 11 tests; this overlapping batch is not added to
the full-suite total. `make lint` passed with the verifier included
(`runs/backend-gaps-final-lint-green.log`). Earlier shared-suite failures and their
corrected harness/manifest expectations remain recorded in `EXPANSION_PROGRESS.md`.
The capability export gate now verifies the supervisor database's private measurements;
it has not yet passed on a deployed scan. No new deployed acceptance is claimed here.

## Update — 28 September 2026

The backend is running at `http://127.0.0.1:8090` with the dedicated worker VM. The
operator will provide UI references and direction separately; frontend source remains untouched.

The authenticated HTTP path has passed deployed vulnerable/fixed redirect checks, including
API credential storage, policy-service resolution, separate identity sessions, before/after
identity proof and redacted HTML/JSON export. Reports are in `runs/authenticated-inputs-deployed`.
Report verification now also rejects method/path substitution against the frozen request template.

Browser workflow dispatch, context ownership, evidence intake, cleanup and report aggregation
are connected. The latest deployed six-case gate is recorded in `runs/backend-browser-final-live.log`.
The upload response/page-close defect was reproduced and fixed in the VM; delayed-response and
timeout cases retain evidence and verify cleanup. Development passes do not promote these
experimental controls into independently qualified ones.

Most recent full suite: **1,362 tests passed** (`runs/backend-discovery-final-suite.log`).
The subsequent safe review API passed **35 affected tests** (`runs/request-template-review-tests.log`)
and its deployed read-only check across four real scans (`runs/backend-review-api-live.log`).
Final lint passed (`runs/backend-review-api-final-lint.log`). Since the earlier integration baseline, authenticated browser input
proof and all four controlled callback cases passed the deployed VM gate. Read-only cleanup
recovery also passed two explicitly synthetic pending-intent cases under fresh authority.
Reports/receipts are in `runs/authenticated-browser-deployed`, `runs/callbacks-deployed` and
`runs/cleanup-recovery-deployed`. The pending intents were fault-injected test records, not
claims of recovery from a real interrupted mutation; no mutation was sent or replayed.

OpenAPI/HAR intake and immutable configuration passed both deployed cases; coordinator-side
plan revisions and no-replay claims passed durable integration tests. Request-intention capture
and capability/reach reports also passed deployed browser evidence and API/export checks.
The browser pair retains partial crawl status; that limitation is not hidden by its completed
input proof. See `runs/import-intake-deployed` and `runs/authenticated-browser-reach-deployed`.


The isolated discovery pair also passed: the scanner discovered query, form, nested JSON and
OpenAPI path inputs without supplied endpoint templates, then confirmed the vulnerable SQL/DOM
cases and produced passing negative evidence on the fixed application. Both active reports remain
partial for unrelated gaps. `runs/discovery-deployed` contains reports and receipts; saved proof
replay passed in `runs/backend-discovery-proof-replay.log`. The updated verification command uses
the new review API, whose template/input IDs match those measured scans. The offline expansion
evaluator also replays the earlier browser pair and correctly refuses independent qualification.

The safe operation-review API is deployed, with frozen plan binding, pagination and privacy checks.
The expansion still needs final credentialed CORS verification,
constrained ZAP active task support, a trusted capability measurement producer, broader
adaptive dispatch and remaining pack acceptance, and independent qualification. Work continues
on these backend gaps.
See [expansion progress](EXPANSION_PROGRESS.md) for exact scope and evidence.

The following baseline results are retained from 26 September; they are not new scans.

## Implemented and exercised

HTTP crawl, interactive Playwright exploration, ZAP/Nuclei/testssl adapters, deterministic
checks, five paired active checks, baseline-first LangGraph follow-ups, configurable model
roles with shared call/cost reservations, curated skills, dedicated-VM Python/Bash analysis,
lab-only broker RPC, proof verification, scoring, retests, SSE, HTML/JSON reporting, evidence
encryption/expiry, encrypted backup/restore, and frozen deployment without source mounts.

The frozen deployment's paired lab run produced **0 findings on labs-good** and **17 on
labs-bad**. Each of the five active controls passed on the fixed fixture and confirmed its
named condition on the vulnerable fixture. Adaptive CSP follow-ups were corroborated. Redirect aliases are now deduplicated before scheduling.
The reports contain all category tiles, supported coverage and reasons for withheld scores.

**671 tests passed with no skips.** Ruff, formatting and the existing frontend typecheck pass.
Real proxy canaries and VM local/network containment checks pass. Details and commands are in
`MILESTONES.md`; runtime artifacts are in git-ignored `runs/`.

## Release gates still open

- Independent held-out benchmark: the ten development cases matched correctly, but one
  positive/negative pair per family does not meet the plan's 30-positive/60-negative,
  three-independent-group criterion. The evaluator explicitly fails this gate. Active
  controls remain experimental; no independent accuracy claim is made.
Live model compatibility is now measured: Command Code serves GLM-5.3 for planning,
verification assistance, report writing and script proposals, and GLM-5.3 Flash for screenshots.
All five synthetic role checks pass. Provider credentials are configured in ignored `.env`.
See `MODEL_CONFIGURATION.md`; this is compatibility evidence, not an independent quality benchmark.

The reviewed-worker deployment boundary is now measured on its dedicated VM: real proxy,
direct-egress and peer-isolation probes pass after reboot; the paired full lab scans pass;
browser cancellation takes 0.026 s to commit / 0.267 s to stop. The final staging pilot also
completed through that VM after fixing an ARM Chromium compatibility issue. Details:
`WORKER_VM.md`, `runs/worker-vm`, `runs/owned-pilot-worker-vm-final-20260926`.

A frozen OSV advisory bundle covers eight selected npm packages (121 records). Missing
mappings/versions and unsupported ranges still leave C06 unassessed. Banner matches remain
potential findings. Tool-level testssl NPN/ALPN/GOST limitations remain explicit.

**This is a working backend candidate, not a completed Phase 1 release sign-off.**

## Latest owned-site results

| Target | Crawler pages | Crawler errors | Confirmed findings | Completed-control coverage |
|---|---:|---:|---:|---:|
| stage.slicerninja.com | 39 | 0 | 5 Low | 17.6% |
| arkyon.dev | 37 | 0 | 5 Low | 11.8% |
| rekvon.in (HTTPS) | 18 | 0 | 5 Low | 82.4% |

These are configuration-profile pilots, not active-injection qualifications. Each reports
HSTS, CSP, frame protection, Referrer-Policy and nosniff header conditions. No overall score
is published because applicable-category gates remain unmet. Reached pages and control
coverage measure different things: blocked instances, rendering and component gaps are retained.
Artifacts: `runs/owned-pilot-v3-20260926`. See `VALIDATION_PROGRESS.md` for defects and fixes.
The final staging VM repeat is `4f655c2e-beed-45a0-b02c-2a1db8749807`; the same 39 pages and
five findings were reproduced, with 3 browser states in 6 actions. Its browser completes while
retaining blocked external fonts and incomplete route transitions as coverage limitations.

Additional active validation: 26 independently health-checked cases produced 13 TP, 12 TN,
zero FP/FN and one negative abstention. This is a contaminated validation set, not the required
held-out benchmark. Five active controls remain experimental.

Pinned local Juice Shop product search separately produced one confirmed SQL finding and
a passing CORS-reflection check. This is development evidence; it does not establish an
SQL vulnerability on any of the three owned production sites.

Live-model end-to-end repeat: `runs/model-provider-final-lab-20260926` contains 17 expected
lab findings, 16 GLM explanations plus one template fallback, successful VM-generated local
analysis, and a terminal report with no model calls in flight. The browser's malformed reply
was rejected. All five synthetic role checks pass; fallbacks and limitations remain explicit.

## Held-out corpus admission, 11 October 2026

The opt-in pinned VulnerableApp/WAVSEP/BenchmarkJava/private stack now has 485 admitted
condition cases on 322 native inputs, after a complete 614-case independent oracle pass.
The oracle verified 40 blocked answer/admin routes and metadata isolation for every
candidate. XSS/HTML share 163 inputs; repeats and that overlap do not increase
independent sample counts. Source manifests, upstream curator references and exclusions
are recorded in `HOLDOUT_BENCHMARK.md` and the evaluator-only holdout package.

Upstream-labelled qualification sample counts are XSS 81 positive/99 negative/3 groups,
SQL 57/60/3, redirect 2/4/2, HTML 0/0/0 and CORS 0/0/0. Private and derived HTML labels
are supplemental, without independent curator credit. The qualification subsets
are dominated by BenchmarkJava (XSS 97.8%, SQL 94.0%); project
counts do not establish balanced implementation diversity. The named `c208c00` backend
was deployed and verified, and evaluator `30fef8a` scored two baseline trials and one
adaptive trial. All three
fail every family gate. Their independent XSS counts (TP/FP/FN/TN/A−) are 0/0/81/2/97
and 1/0/80/3/96; adaptive XSS counts are 1/0/80/1/98. SQL counts are 2/0/55/1/59
in all three. Saved SQL response hashes establish
broker page-cap refusals for 54 FN and 56 negative abstentions in each trial. These
are end-to-end authority failures, not established conditional detector accuracy.
The coordinator paused the remaining schedule at the first adaptive trial boundary.
Per-family denominators, abstentions, Wilson95 intervals and saved reach analysis are
in `HOLDOUT_BENCHMARK.md`. The release gate remains open; all five controls remain experimental.

Earlier holdout-lane verification: clean committed evaluator `45afd99` passed 2,040 tests with
no skips in 331.43 seconds on its isolated database; `make lint` passed. Its backend
source matches the named `c208c00` candidate. Evidence is in
`runs/holdout-benchmark/full-suite-evaluator-final.log` and `.json`. The initial partial
summary is `runs/holdout-benchmark/scored-c208-30fef8a/summary-initial-three.json` and
reports `complete=false`, `passed=false`; tests are not accuracy evidence.

### Harness-corrected held-out attempt, still incomplete

The same frozen corpus was evaluated again on verified deployment `b0b123a` with
`ffc6fcb`, after coordinator-reviewed authority/transport repairs. It stopped during
trial 1 at the unchanged 1,020-second evaluator deadline. BenchmarkJava was cancelled;
WAVSEP was partial after browser exploration timed out. No scheduled score was
published and no subsequent trial began. The attempt is not release qualification.

The saved cancellation assessment gives independent TP/FP/FN/TN/A− counts of
XSS `15/0/66/16/83`, SQL `42/0/15/1/59` and redirect `2/0/0/2/2`.
All 110 BenchmarkJava SQL conditions have captures without 403 responses. Browser
admission covers 33/176 XSS and 30/168 HTML conditions, with 189 reviewed actions.
The frozen browser plan requires 1,032 capture actions to finish every series, above
the deployed ceiling of 500. The cancelled scan stopped before reaching that cap;
the recorded cancellation cause is the evaluator deadline. Host test overlap is
reported without attributing the timeout to it.

Evidence is under `runs/holdout-benchmark/scored-b0-ffc6fcb/`, especially
`schedule-failure.json`, `summary-incomplete.json` and
`repeat-1-baseline/timeout-followup/`. `HOLDOUT_BENCHMARK.md` reports intervals,
all missed-case reach stages and repeated-exposure provenance. Neither attempt
passes the release gate. All five controls remain experimental; no detector, proof,
case or label was changed using held-out outcomes.

The operator-authorized time-extended b0 run scored all six reserved trials on
unchanged cases and labels, with D wall 2,700 seconds, evaluator wait 2,820 seconds,
request cap 5,000 and active-browser ceiling 1,200. Curated XSS recall is 50/81 to
55/81, or 61.73% to 67.90%; SQL is 41/57 to 42/57, or 71.93% to 73.68%. Every family
gate fails. Zero observed labelled-family FP does not establish population FPR:
XSS conclusive negative coverage is 70/99 to 75/99 and SQL only 1/60. HTML/CORS
have no upstream-curated samples; redirect has only 2 positive, 4 negative and
2 groups. All five controls remain experimental.

Evidence is in `runs/holdout-benchmark/scored-b0-wall2700-scope-visibility-resume/`.
`summary-six.json` is complete and candidate-stable, reports `passed=false` and no
qualified family, and retains the strict evaluator-freeze difference. The first
three scores used `874d0ff`, the last three `617343a`; only evaluator commit/source
hashes differ in that comparison. The visibility guard passed an isolated 2,379-test
suite and `make lint`, with no deployed runtime or proof change. Earlier score files
and frozen corpus hashes remain unchanged. `final-report.md` includes all family
counts, denominators, 95% intervals, abstentions and missed-case reach stages;
integrity and per-trial authority receipts accompany it.

Every BenchmarkJava scan ended partial, recording 63 to 81 browser session-expiry
denials despite the extended wall budget. Docker shutdown and the scope API race
left separate exposures unscored, with their original files retained. The sandbox
outage left generated analysis `outcome_unknown` for D in adaptive repeat 3 and all
four targets in adaptive repeat 2. No adaptive effectiveness or untouched-first-
exposure qualification is claimed. The schedule is finished; the release gate
remains unmet.
