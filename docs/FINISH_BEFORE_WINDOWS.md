# Repairs before the Windows transfer

The operator asked to finish outstanding functional repairs on the current laptop
before producing the transfer ZIP. Saved benchmark scores and past scan evidence
remain unchanged. The source repairs below do not change detector payloads, proof
rules, scoring, labels, frozen benchmark cases, or target authority.

## Final handoff status

The operator chose to finish backend repairs and keep all five detectors experimental.
The exact final code commit `ebf0af848c1bac9ec592f1ed2fa23e9a4a39dc5e` passed
2,447 tests with zero failures/skips in 417.73 seconds, plus Ruff/format checks and
TypeScript typecheck, in a clean private worktree/environment and private test DB.
It was built, frozen, provisioned to the dedicated worker VM, boundary-verified,
and deployed. All six control images match the release pins; `/readyz` is ready0009.
The final checkpoint has no active API scans or stack lock. The sole old expired
queued intent remains documented under its previously authorized exact exception.

The isolated proxy containment checks passed, including a real signed HTTPS inner
request, responsiveness under concurrent asset admission, destination pinning,
queue limits and callback capture. The dedicated sandbox VM passed local Python/Bash,
containment, output-cap and deadline checks. Its HTTP gateway on port 8099 remains
unavailable, so no live generated-analysis gateway acceptance is claimed.

Owned scopes and budgets were unchanged, and actual admission audits confirm 4/5:

| Site | Final measured result | Remaining limitation |
| --- | --- | --- |
| Stage | Completed, 17.6%, browser completed | Crawl cap and failed/denied requests remain in the report. |
| Rekvon | Completed, 17.6%, browser completed | Root assets and ReadTimeout recovered; `/app/` zero-count background gap still blocks six controls. |
| Arkyon | Completed, 82.4%, browser completed; six controls conclusive | Rechecked on final body-order repair; no pending gaps or lost image capture. |

Arkyon's final scan is `bcf2b40a-794c-4217-a468-269a5c3ba18c`. Stage/Rekvon were
measured on `240e2d9` before the final small body-order change; the final Arkyon
recheck is on `ebf0af8`. These source differences are disclosed, not pooled into
an isolated causal experiment. Overall scores remain withheld where coverage is
insufficient. Every export returned HTTP200.

Native transport/startup/result handoff now completes with observed exit0, captured
and acknowledged output, and no native errors. The unchanged rule configuration
produced zero candidates on the vulnerable owned fixture in the `240e2d9` gate,
so the paired detection contrast failed and the fixed case was not run. No production
activation prerequisite was met. ZAP is disabled, the shipped approval manifest is
empty, and no new active production scopes or attack routes were created. The final
body-order repair changes only ordinary browser capture, not native code; no detector
tuning or further native exposure follows the operator's experimental decision.

All original benchmark scores, case labels and earlier failed evidence remain
retained. No family passed its held-out release gate. Windows uses Ubuntu WSL2 and
Docker Desktop; installation and runtime acceptance must be performed on that laptop.
The Mac's Lima VM boundary is not ported to Windows, so the fresh setup disables
generated scripts and native ZAP. See `WINDOWS_SETUP.md` and the package's
`START_HERE.md`. Final evidence is under `runs/finish-before-windows-20261012/`.

## Native ZAP and lab readiness

The `c32ff6a` native lab seed received an upstream HTTP 502 despite broker allowance.
The lab's nginx error log records `Host is unreachable` while connecting to
`172.28.0.14:8080/bad/xss` for that exact seed. Its dynamic fixture container had
stopped with exit 255 during the earlier Docker interruption and had no live IP.
The old readiness script still returned success because it checked nginx's static
health endpoints only. This mechanism is established for the latest gate; it is
not asserted as the sole cause of earlier failures with missing diagnostics.

The dynamic fixture now has a healthcheck and restart policy, and both nginx
fixtures depend on its health. Readiness checks the real `/active/xss` route through
both origins. The fixture was restarted under the shared helper, and both dynamic
routes now pass readiness.

Separately, the native context pattern required a query string. The pinned
[ZAP 2.17 Context implementation](https://raw.githubusercontent.com/zaproxy/zaproxy/v2.17.0/zap/src/main/java/org/zaproxy/zap/model/Context.java)
removes queries before full context matching, making the old pattern reject its
own seed. The new pattern matches only the exact projected origin and path.
Query names, values and unchanged fields remain bound by the existing task grant;
the native request cap, deadline, rule configuration and origin approval are unchanged.

Three worker-call regressions reproduce `URL_NOT_IN_CONTEXT` against the old code
and pass after repair. Tests include HTTP, HTTPS projection, nondefault ports, and
rejection of neighboring paths and hosts. Two readiness regressions retain the
unavailable-fixture failure. The first mocked setup run failed before context
configuration because its test process stub omitted `DEVNULL`; that initial log
is retained and is not treated as a valid context reproduction. The corrected
baseline log contains the three intended failures.

## Browser session and proxy responsiveness

Browser sessions previously had an absolute 15-minute expiry. The policy now
renews that same idle interval after an allowed operation by the active owner,
bounded by the immutable scope authorization expiry. Lease, cancellation, owner,
ordering, action, task and request checks still happen before renewal. Expired,
idle, denied and closed sessions are not revived; no action allowance is increased.
Eight regressions cover activity beyond the initial expiry and the refusal cases.

An isolated real-mitmproxy regression reproduces a browser control `ReadTimeout`
at 10.006 seconds while six local assets wait on slow policy admissions. Blocking
policy HTTP calls were running on the proxy event loop. Asynchronous request and
CONNECT hooks now await those same calls in threads. All authorization and later
liveness checks remain in place, including the unchanged stream checks. Cancellation
can still consume an admission completed by a policy call already in progress;
it cannot cause the canceled request hook to forward target traffic.

The fixed regression returns browser control in 0.009 seconds and completes all six
assets with HTTP 200. This establishes a local failure and repair, not retrospective
proof of the specific Rekvon `ReadTimeout`. The regression is part of `make test-proxy`.

## Native HTTPS inner request

The supervisor's verified HTTPS transport was present, but the real proxy's signed
request guard still allowed only HTTP. A new regression reproduces that refusal.
The guard now accepts HTTP or HTTPS inner requests only; task policy must still
validate the signed exact URL, origin, worker identity, nonce and budget. The
CONNECT request remains token-only and rejects signed-task headers. A separate
real-proxy local TLS test requires the broker CA and tunnel hostname, verifies the
signed HTTPS URL offered to task policy, and checks that authority headers do not
reach the target. This transport test uses a local policy canary; actual signing
and grant checks remain covered by the PostgreSQL integration tests.

## Image and font settlement

A real Chromium fixture with a 2.3-second image response reproduces state capture
while a known image is still pending after the initial 1.5-second settling interval.
The explorer now gives fully tracked image/font transfers at most five additional
seconds, bounded by its configured request timeout, and requires network quiet
before omitting the pending gap. Scripts, fetch/long-polling requests, incomplete
metadata and a busy network without tracked requests keep their previous gaps.
Exact request objects are tracked until their response capture has finished;
requestfinished callbacks can yield while reading bodies, so a zero pending count
alone is not sufficient. Failed, non-2xx or truncated captures do not excuse a gap.
An unfinished transfer remains incomplete. The state capture implementation and
proof evaluators are unchanged; this only delays capture within the existing worker
and scan bounds. Local reproduction does not prove every historical site gap has
the same cause; the owned-site recheck remains necessary.

## Windows development

`WINDOWS_SETUP.md` and `scripts/setup_windows_wsl.sh` provide an Ubuntu WSL2 path
with Docker Desktop integration, locked dependency installation, fresh credentials,
and a prerequisite/archive integrity check. Existing `.env` files are preserved.
The helper is shell-syntax checked; Windows runtime acceptance must still be measured
on the Windows laptop. The dedicated Apple Silicon Lima worker and generated-code
VM topology is not ported to Windows. Generated scripts stay disabled in the fresh
Windows setup, and old Mac image pins are retained as historical evidence only.

## Validation and acceptance

Focused checks so far: native context/readiness/origin/deadline 44 passed; browser
session/policy/reviewed accounting/expanded dispatch 49 passed; proxy and signed-task
authority 124 passed. The real proxy responsiveness regression passed separately.
Clean committed full qualification, deployment, and the native paired gate remain
pending. No native acceptance or production rule activation is claimed from these
source checks. Logs are under `runs/finish-before-windows-20261012/`.

The clean predecessor `421ecf5` full suite passed 2,421 tests and lint. The next
`5101cf5` qualification retained 2,423 passes and one failure: a one-second lab
readiness budget could cross an integer-clock boundary before its first probe.
Readiness now always makes that first probe. A deterministic clock-boundary test
reproduces the old failure, and the corrected transport/readiness batch passes
13 tests. The earlier failed logs remain retained. A new complete qualification
is required for these final repairs.

The six completed held-out scores still fail their family release gates. Repairs to
transport or admission do not promote detector accuracy or supply the missing
independently curated populations. `HOLDOUT_BENCHMARK.md` remains the release record.

## Native seed visibility and anonymous transport

The trusted native HTTP client now clears target cookies before every request.
It already withheld Set-Cookie from the worker, but httpx's client-side cookie jar
could replay cookies on the next request. A regression reproduces that leak and
passes after repair; request authority and anonymous header restrictions are unchanged.

The clean `6fd8e17` checkout passed 2,427 tests without failures or skips in
414.18 seconds, plus lint and TypeScript checks. Its grouped deployment and worker
VM boundary checks passed. Its native lab seed then reached the fixture with HTTP
200 and broker allowance, but ZAP refused scan startup with `URL_NOT_FOUND`.
The fixed fixture was not run; official restoration passed. This is retained in
`runs/backend-gaps-native-lab-6fd8e17/` and is not native acceptance.

The pinned [CoreAPI implementation](https://raw.githubusercontent.com/zaproxy/zaproxy/v2.17.0/zap/src/main/java/org/zaproxy/zap/extension/api/CoreAPI.java)
queues site-tree insertion asynchronously after sending the seed. The
[ActiveScanAPI implementation](https://raw.githubusercontent.com/zaproxy/zaproxy/v2.17.0/zap/src/main/java/org/zaproxy/zap/extension/ascan/ActiveScanAPI.java)
refuses a missing tree node before creating any scan. An isolated network-none
fixture also observed this refusal; a subsequent run completed, consistent with
an intermittent startup boundary. Its first diagnostic had an omitted API key
on the diagnostic-only history read and is retained separately from the corrected run.

Scan startup now retries only the explicit HTTP 400 `url_not_found` response,
for at most two seconds within the same absolute task deadline. The seed is sent
once. Unknown refusals, malformed responses and ambiguous transport failures never
retry. Only a fixed refusal code is inspected; error bodies, API keys and URLs are
not included in exception diagnostics. Three delayed-history regressions fail on
the prior worker; boundary tests cover refusal classification, deadline exhaustion
and secret-free telemetry. Rule configuration, payload catalogue, target authority,
request cap and deadline are unchanged. This follow-up needs its own clean qualification
and deployed paired gate before any acceptance claim.

The clean history-wait checkout `fb1adf2` passed 2,437 tests without failures or
skips in 410.28 seconds, plus lint. A second isolated, network-none reflected
fixture then established an alert collection defect: the engine had one alert,
but filtering with the original seed query returned zero; filtering with its
origin/path returned the alert. This test also observed the transient missing
history node and successfully started the scan after that refusal.

Alert retrieval now uses the seed's query-free origin/path. Each returned alert
still passes the existing logical projection and task binding validation; unknown
rules, outside origins/paths, altered unrelated query fields and unapproved input
values remain errors. No parser, proof requirement, payload or detector configuration
changed. Six HTTP/HTTPS worker regressions reproduce the dropped alert before repair.
The final source receives focused checks and owned-lab acceptance, then a complete
exact-commit suite before packaging; native production approvals remain empty.

## Native result handoff

The `777af61` deployed worker started the native scan and exited with observed code
0, with two admitted HTTP 200 responses. Its result still failed collection:
Docker archive access could not read the worker's tmpfs result. A bounded standalone
Docker reproduction confirms archive access fails even while that tmpfs file exists,
and that stopping the container loses the mount's contents.

The worker now publishes its complete result atomically and waits for a trusted
acknowledgement for at most five seconds inside the original task deadline. The
supervisor reads it while the worker is alive using an isolated, fixed Python
reader. Only `result.json` and `local-api.json` are accepted; directory descriptors,
no-follow opens, regular-file checks and byte limits precede output. It then writes
a fixed acknowledgement and still requires the worker's observed exit code 0.
Local API telemetry is collected before acknowledgement too. The transport does not
extract anything onto the host or change grants, request accounting, payloads,
origins or deadlines. A real network-none Docker reproduction reads the exact bytes,
acknowledges them, and observes exit 0; both diagnostic containers were removed.
Tests cover the real IPC scripts, publication lifetime, acknowledgement order,
deadline exhaustion, oversized files, FIFOs, symlinks and path traversal.

The prior native attempt remains failed and officially restored. Its daemon reported
zero alerts on the vulnerable fixture under the existing reviewed configuration.
A completed native process will not be relabeled as successful detection; the paired
candidate contrast is still required. The operator chose to keep all five detectors
experimental rather than reopen detector improvements. No payload expansion or
threshold tuning is included in these backend repairs.

## Arkyon response-body lifetime

The three `240e2d9` rechecks all finished with actual audited limits 4/5. Rekvon's
root image/font gap and browser timeout disappeared, while its `/app/` zero-count
background-activity gap remained blocking. Stage had no pending browser gaps.
Arkyon's previously intermittent image capture failure returned on
`/assets/aditya.webp`; its saved detail says navigation removed Chromium's response
body before collection. Its coverage therefore fell from 82.4% to 17.6%, and the
six affected controls correctly remained inconclusive.

The collector fetched headers before reading the body. Those header RPCs can yield
to another navigation. A real Chromium regression navigates during that exact
window and reproduces the lost body against the verified prior capture function.
Reading the completed body first preserves it across navigation. The retained
response fields and proof rules are unchanged; failed bodies still record gaps.
The new regression and slow-static-asset regression pass. The first test bootstrap
omitted required CrawlConfig arguments and is retained as an invalid reproduction;
the corrected baseline and forced-parent replay contain the intended failure.
The final exact-commit suite and Arkyon recheck follow this small ordering repair.
