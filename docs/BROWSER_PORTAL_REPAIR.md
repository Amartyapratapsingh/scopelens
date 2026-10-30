# Portal browser diagnosis, 30 September 2026

The public portal repeat `47177a9f-4493-40cd-a514-4aad69a4bf1f` remains incomplete.
It captured zero browser states. Its stored HTTP login response has a body, while
Chromium timed out waiting for DOMContentLoaded and then for the body locator.
The previous 15-second script regression validates a readiness improvement but does
not demonstrate that the portal's transport failure is resolved.

## Evidence and deterministic checks

Saved reports are under `runs/college-subdomains/portal-browser-recheck/`. Read-only
inspection of that scan's evidence and broker admission rows found:

- Browser response artifacts for the root redirect, login HTML, four stylesheets,
  `Ajax.js`, `AjaxUtil.js`, jQuery 1.7.1 and jQuery 1.9.1.
- Admissions for jQuery 1.11.1 and `zebra_dialog.js`, without matching completed
  browser response artifacts. Admission alone does not establish a completed transfer.
- The final browser asset GET admission at 23:51:05 UTC, followed by repeated CONNECT
  admissions starting at 23:51:31 UTC. Persisted response timestamps are artifact
  ingestion times and cannot measure transfer durations.

An offline replay of the captured HTML and stored textual asset excerpts, with
unrecorded resources aborted, reaches a body and `document.readyState == complete`.
It does not reproduce the transport delays or transfer framing of the real site.

A second replay passed the stored page and assets through a loopback HTTP fixture,
the real `Bridge`, `Controller.route`, response capture and `Controller.act`, using
sandboxed Chromium in a disposable VM worker with `network_mode=none`. It captured
one state, 21 responses and 123 characters of body text in 0.86 seconds. The fixture
used a synthetic token and no customer traffic. This rules out a universal failure
of the saved page's parser or the worker's normal response callback path. It does not
exclude a failure triggered by HTTP/2, proxy queuing, real transfer timing or headers.

## Ranked hypotheses

| Rank | Hypothesis and prediction | Result |
|---|---|---|
| 1 | Asset transport or proxy admission stalls. An unfinished classic script in the head should leave DOMContentLoaded unset and the body absent. | The isolated streaming fixture reproduces this exact zero-state failure. A real proxy fixture also reproduced unresolved queued requests and passes after the admission repair. |
| 2 | Synchronous worker response callbacks prevent pending routes from advancing. Removing the callbacks should change the normal captured-page replay. | Replay with the real callbacks captures 21 responses and a state, so the callback path alone does not reproduce the failure. |
| 3 | The bridge closes an inactive connection while assets wait for admission. Keeping the transport active should distinguish closure from an unfinished response. | A script response that sends a byte each second still reproduces zero states. Bridge idle closure is unnecessary for this failure class. |
| 4 | The recorded login page or its JavaScript prevents parsing. Offline replay should also fail. | The textual replay reaches a complete document. Missing binary assets and normalized textual excerpts limit this conclusion. |

## Confirmed local proxy cause and repair

The previous broker started a 10-second response deadline before a request acquired
its admission semaphore. A burst of assets could spend that deadline waiting for a
slot. Expiration canceled the mitmproxy request hook without completing its HTTP
response, leaving queued asset transfers unresolved.

`tests/containment/proxy_queue.py` reproduces this in the real mitmproxy runtime using
24 concurrent requests to a loopback fixture. Each fixture response takes one second.
Before the repair, four requests ended in client `TimeoutError` at 15 seconds. After
the repair, all 24 returned HTTP 200, with the final response at 12.13 seconds. The
subsequent request also succeeds, demonstrating that admission slots are released.
The existing real HTTPS keepalive regression passes after the repair.

The broker now starts the 10-second upstream deadline after semaphore admission and
the policy's rate wait. Admission itself has a separate 120-second bound. A timed-out
or canceled admission completes with HTTP 504 or 503 and releases its slots, instead
of leaving a request hook unresolved. Per-request authorization, token liveness,
scope, response byte caps, connection pinning and cancellation remain enforced.

This establishes a local cause and repair for unresolved queued asset transfers. It
does not prove that the saved customer capture failed for this same reason. The
portal's initial DOM still needs a recheck through the deployed repaired transport.

## Worker change

The worker now tracks in-scope request start, completion and failure events. On
`document_ready_timeout`, it records the pending request count and at most 20 redacted
URL/method/resource-type/age descriptions. It retains at most 500 request objects;
`pending_metadata_limited` indicates when the descriptions do not cover every pending
request. It never stores diagnostic request headers or bodies.

Response evidence still requires `requestfinished`. A response-start event is not
credited as a complete capture. A missing body still fails state capture and the
reviewed action completes with `result=failed` and no after-state hash. Scope guards,
broker admission, cancellation, redaction and Chromium sandbox settings remain active.
No timeout was increased for this diagnostic change.

## Regression command

Run from the trusted supervisor after deploying the matching worker image:

```sh
docker exec -i scopelens-dev-supervisor-1 python - < scripts/verify_browser_transport.py
```

The disposable container has no network access. A loopback fixture is its only server.
The fast script case must capture a browser state. The unfinished script case sends
headers and periodic bytes but never finishes within the capture window. It must produce
zero states, a pending script diagnostic, no completed response artifact for that script,
and a failed action completion. `--worker-source` allows testing a supplied source file
inside the supervisor without rebuilding or replacing a deployed image.

Focused unit coverage checks pending accounting, completion/failure handling, URL
redaction, bounded metadata retention, and failed action completion. The existing
parsed-document regression continues to pass.

The source-overlay VM regression passed on 29 September: the fast case captured one
state and two responses in 0.69 seconds; the unfinished script produced zero states,
one completed document response and a 30-second pending-script diagnostic, then failed
body capture at 34.58 seconds. Evidence is saved in
`runs/scanner-resource-validation/browser-transport.jsonl`. Five focused unit tests passed,
and the changed Python files passed lint. Source-overlay testing does not deploy an image.

The integrated backend suite passed all 1,533 tests on 30 September in 280.45 seconds,
with no failures or skips. Log: `runs/academic-workflows/full-tests-after.log`.

## Deployed public recheck

The repaired deployment completed public scan `cad05813-e5d3-4313-bef8-be15a3b9faff`
of the previously authorized college portal. It captured **two browser states and two
actions**, compared with zero states before the queue repair. Thirty-one pages were
collected; the report remains `completed_partial` with 11.8% coverage. Third-party assets
were denied by scope, a background-request gap remains, and one image response was lost
when navigation changed. The password-reset route was blocked by the action guard.

Saved artifacts: `runs/college-subdomains/portal-queue-recheck/portal.alliance.edu.in/`.
Four configuration findings are confirmed and a component advisory remains potential.
This result does not establish logged-in academic access or a whole-application score.
Those checks require dedicated customer test identities and records.
