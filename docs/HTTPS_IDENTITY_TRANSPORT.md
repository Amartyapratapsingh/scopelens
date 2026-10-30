# Owned HTTPS identity and application entry gate

This is a development gate for the existing inspecting-proxy and dedicated-worker-VM deployment. It does not contact the student ERP or establish current customer session readiness.

The exact `labs-good` binding serves HTTPS on `172.28.0.12:8443`. `/app` is a small public application entry page. `/app/identity-home` returns the synthetic account header only for the fixture's fixed supplied cookie, and returns 401 for an invalid cookie. The scanner runs no login recipe. The scope permits GET/HEAD under `/app` only.

Run after rebuilding, freezing and provisioning the worker images, and applying the release and worker-VM overlays:

```sh
.venv/bin/python -m scripts.verify_html_identity_lab --fixture https --output runs/https-transport-diagnosis/post-deploy-https
```

The default `--fixture academic` keeps the existing `labs-academic-b` gate. `--output` selects a separate receipt directory. The gate uses the configured local operator account and saves neither credentials nor raw fixture account text. It downloads stored evidence through the authorized API, checks content hashes and trusted supervisor provenance, replays the frozen configuration/probe binding, checks actor readiness and asserts that readiness earns zero control coverage. For the HTTPS variant it also requires trusted crawler responses and browser states at `/app`, with all their captured URLs inside that application scope. Receipts are saved before outcome assertions so failed gates retain their observations.

The worker verifies the inspecting proxy CA. This gate tests that hop and the admitted HTTPS request path. It does not replace independent upstream certificate measurements or prove a customer's HTTPS endpoint behaves identically. No TLS verification, scope, redirect or budget flags were relaxed for this gate.

## Measured deployment on 5 October 2026

The source tests first reproduced two caller defects: the crawler and browser controller seeded `/` after the coordinator had selected an application entry path. Both callers now retain the permitted seed, and the exposure pack filters root probes outside the declared path scope before sending them. The broker remains the enforcement boundary.

Evidence is under `runs/https-transport-diagnosis/`:

- `crawler-red.log` and `browser-red.log` record the failing caller regressions.
- `source-regression.log`: 74 passed.
- `caller-regression.log`: 133 passed.
- `containment-contract.log`: 45 passed.
- `lint.log` and `format.log`: checks passed.
- `api-build.log`, `tool-build.log`, `kali-build.log`, `browser-build.log`, `freeze.log`, `worker-vm-provision.log` and `deploy.log` record the build and installation.
- `worker-vm-boundary.log` verifies authenticated VM control, file isolation, denied direct egress, the enforcing proxy and cancellation.
- `live-proxy-boundary.log` verifies the authorized fixture and rejection of control-plane destinations, unknown tokens and excluded paths.
- `deployed-runtime.json`, `fixture-binding.json` and `final-scan-state.json` bind the running images, source, owned fixture and final lifecycle state.

| Gate | Case | Scan | Trusted identity replay | Lifecycle |
|---|---|---|---|---|
| Academic HTTP | Valid | `59b0067f-0034-4a9b-9b63-1d44c82d69be` | Verified | Completed |
| Academic HTTP | Invalid | `729769ee-2bbd-4587-9a58-40f0aa976b83` | Failed | Completed |
| HTTPS under `/app` | Valid | `5bb9cfe9-6fd9-4b83-9258-72b75880322f` | Verified | Completed partial |
| HTTPS under `/app` | Invalid | `f00a95f7-5c6d-4fb0-abfe-0c1b6208b77e` | Failed | Completed partial |

Each case produced exactly one trusted identity observation and zero readiness control coverage. Both HTTPS cases recorded crawler and browser URLs at `/app` and `/app/identity-home`. Their partial status retains incomplete `conditional-config` and `testssl` tool coverage; the gate does not claim complete assessment from successful identity/entry observations.

The HTTPS transport pair also passed before the image rebuild, in `pre-deploy/`. This rules out a general deployed HTTPS identity transport failure for this owned fixture. The customer scanner's transport failure remains unexplained by these synthetic results and needs a separately authorized fresh scope/session check. Existing customer partial evidence remains intact.

The executed validation commands were:

```sh
.venv/bin/pytest -q tests/unit/test_m2_crawler.py tests/unit/test_browser_transport.py tests/unit/test_scope_entry_url.py tests/unit/test_expansion_exposure.py tests/unit/test_identity_readiness.py
.venv/bin/pytest -q tests/browser/test_browser_workflows.py tests/browser/test_browser_policy.py tests/browser/test_authenticated_browser_inputs.py tests/integration/test_authenticated_inputs.py tests/unit/test_html_identity_probe.py
.venv/bin/pytest -q tests/contract/test_containment.py tests/unit/test_scope_paths.py tests/browser/test_request_discovery.py
.venv/bin/ruff check backend tests evaluation scripts
.venv/bin/ruff format --check backend tests evaluation scripts
docker build -f deploy/api.Dockerfile -t scopelens-dev-supervisor .
docker build -f workers/tool-worker.Dockerfile -t scopelens/tool-worker:dev .
docker build -f workers/kali-tool.Dockerfile -t scopelens/kali-tool:dev .
docker build -f workers/browser-worker.Dockerfile -t scopelens/browser-worker:dev .
.venv/bin/python -m scripts.freeze_release
.venv/bin/python scripts/provision_worker_vm.py
.venv/bin/python scripts/verify_worker_vm.py
docker compose --env-file .env --env-file runs/release/images.env -f deploy/docker-compose.dev.yml -f deploy/docker-compose.m4.yml -f deploy/docker-compose.release.yml -f deploy/docker-compose.worker-vm.yml up -d --no-build --wait
docker cp tests/containment/live_proxy_probe.py scopelens-dev-supervisor-1:/tmp/https_live_proxy_probe.py
docker exec scopelens-dev-supervisor-1 python /tmp/https_live_proxy_probe.py
.venv/bin/python -m scripts.verify_html_identity_lab --fixture academic --output runs/https-transport-diagnosis/post-deploy-academic
.venv/bin/python -m scripts.verify_html_identity_lab --fixture https --output runs/https-transport-diagnosis/post-deploy-https
```

All seven nonterminal lifecycle states were checked before disruptive deployment work. Only the existing 26 September queued intent remained; no executing or paused scan was restarted. The final check records the same queued intent. `/readyz` was healthy, and the runtime API/coordinator images matched the frozen image ID. This is development validation, not independent release qualification.

## Response-body failure reproduction, 11 October 2026

The saved customer scanner observation has `status: null` and no transport-error category.
Its broker audit admits the exact home GET about 0.6 seconds before the observation.
The separate TLS lane marked the endpoint reachable; the retained proxy log contains no
entry for that time. These facts do not identify the underlying customer failure.
No customer request, customer login or plaintext credential access was made in this task.

The collector previously set its HTTP status only after reading the entire response body.
Thus `status: null` does not prove that no HTTP headers arrived. A decoding, interrupted
body or timeout error can produce the same record after a successful HTTP response.

An owned loopback HTTPS fixture under `/auerp` reproduces this exact collector symptom.
Its synthetic compression filter advertises gzip but sends uncompressed JSON when the
client accepts gzip. The gate loads the exact `d8b259a` session request method and compares
it with current code against the same fixture. Baseline returns
`identity_probe_transport_unavailable` with `status: null`. Current identity requests
explicitly negotiate `Accept-Encoding: identity`, and the same supplied synthetic session
verifies. This adds no retry and changes no redirect, TLS, origin, response cap or budget rule.

If a server still sends a malformed body, readiness stays blocked. New fixed diagnostics
retain `transport_phase` (`connect`, `tls`, `request_send`, `response_headers`,
`response_body` or `response_body_decode`), nullable `response_status` for observed
headers, and the `decoding` transport category. Pool timeouts use `connection_pool`;
errors without sufficient trace or exception-type evidence use `unknown`. `status` remains null unless
the complete bounded response was read; no digest or control coverage is inferred from
`response_status: 200`. Exception text, cookies and response content are not recorded.

The measured five-case gate passed baseline failure, repaired verification, invalid-session
denial, unconditional broken-body denial and redirect denial. The certificate is explicitly
trusted and the only target is a temporary loopback listener. This gate exercises real HTTPS
and the production collector, with an injected fixture client. It does not establish deployed
broker provenance by itself.

```sh
.venv/bin/python scripts/verify_identity_transport_lab.py
```

Receipt: `runs/discovery-auth/owned-https/compression-receipt.json`.
This proves a failure class and its repair, not the customer root cause. Customer scanner
readiness remains unverified until an operator runs a fresh authorized configuration.

The diagnostics correction uses HTTPX's trace extension with the pinned httpcore 1.0.9
to distinguish actual connection, TLS, send and receive operations. Only fixed labels
and a numeric header status are retained; trace payloads and exception text are ignored.
A `DecodingError` always means `response_body_decode`, including the legacy collector
path where the response was never returned and its status is unavailable. Six offline
tests exercise the real HTTPX/httpcore/h11 path with in-memory socket failures, one at
each phase. The owned HTTPS receipt was regenerated after this correction.

## Operator customer verification

The 5 October scope, imported session and configuration are expired. The operator must
renew explicit authority for `https://student.alliance.edu.in` under `/auerp`, GET/HEAD
only, profile `authenticated-api-v1`. Obtain a fresh normal test-account session in the
operator-controlled browser and store its Cookie through
`POST /api/assessments/credentials` bound to that fresh scope. Create a new immutable,
cookie-only configuration using the returned encrypted reference, a fresh expiry and
the existing exact independent home probe and account-header SHA-256 expectation.
Configure no login recipe, permission matrix, workflow, session-lifecycle policy,
template, callback or related-origin grant for this readiness-only check.

After deployment of the repaired worker image, the operator can run:

```sh
.venv/bin/python -m scripts.verify_identity_readiness_configuration \
  --scope-version-id FRESH_APPROVED_SCOPE_UUID \
  --configuration-id FRESH_COOKIE_ONLY_CONFIGURATION_UUID \
  --output runs/customer-readiness-recheck
```

This command was not run on the customer. It authenticates to the local API, refuses
expired or broader policy, creates one ordinary scan with adaptive work disabled,
checks supervisor evidence hashes and provenance, independently replays the exact
frozen identity probe, and writes a redacted readiness receipt. A failed probe exits
with an error after saving diagnostics. A verified probe proves readiness only,
not permission boundaries or complete assessment. A transport failure with the new
`transport_error`, `transport_phase` and `response_status` fields is the minimum
additional evidence needed to continue customer-specific diagnosis.
