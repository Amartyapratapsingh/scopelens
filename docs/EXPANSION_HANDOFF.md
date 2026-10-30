# Backend expansion handoff — 28 September 2026

## State

B1–B7 was approved. Substantial modules and fixture tests exist, but the expansion is **not
complete end to end**. Do not label the backend finished, promote experimental controls,
or interpret development fixtures as independent qualification. No frontend work is requested.

One discovery/browser agent ended with an automatic cybersecurity review interruption while
working on browser workflow integration. Some files were saved before that interruption;
inspect and test them. The remaining list below is a software completion list, not a request
to bypass another tool's safeguards.

## Implemented and partially integrated

- B1: discovery from crawler/browser observations, forms, JavaScript references, OpenAPI/HAR;
  request templates, typed inputs, secret references, action policies, immutable plan revisions
  and preserved denominators. Modules: `discovery/`, `domain/assessment.py`.
- B2: generic HTTP collectors for SQL comparisons, redirects, CORS configuration and header
  injection; separate real-browser reflected/DOM XSS and HTML rendering collectors.
  Modules: `checks/expanded_active.py`, `browser/expanded_active.py`.
- B3: five exposure packs, five pinned experimental Nuclei templates, component identification,
  expanded advisory snapshot. Modules: `checks/packs/`, `checks_registry/tooling/expansion/`.
- B4: encrypted owner/scope credential store; supplied HTTP/browser identities; JSON/form login;
  object/function/tenant/property comparisons; session lifecycle and credentialed CORS proof.
  Modules: `identities/`, `domain/identity.py`.
- B5: mass assignment, workflow authorization, GraphQL access, private caching, canary traversal,
  benign template evaluation; cleanup persistence and explicit recovery. Callback nonce/receipt
  service plus SSRF/XXE collectors. Browser workflow modules for stored XSS, CSRF and benign
  upload exist but the browser agent was interrupted before completion sign-off.
- B6: new-profile graph candidates and executable SQL/redirect/exposure/component follow-ups;
  reflection/access/callback investigation types retain explicit prerequisite gaps.
- B7: qualification thresholds, sample counts, 95% intervals, equal-budget comparison and
  capability inventory utilities. No independent holdout qualification has been achieved.
- Root integration: four profile enum values; immutable configuration/credential API; scan
  snapshot; migrations 0007/0008; related scan-origin broker handling and separate DNS pins;
  limited fixed-worker control capability for credentials/cleanup; expansion HTTP worker;
  exposure and input-probe proof conversion into existing analysis. Integration is incomplete.

## Work required, in order

### 1. Establish the current baseline

Read `SCANNER_EXPANSION_PROPOSAL.md`, `EXPANSION_TOOLS_IMPLEMENTATION.md`,
`AUTHENTICATED_WORKFLOWS.md` and existing milestone docs. Run the complete backend suite and
lint with PostgreSQL available; report skips. Preserve old-profile behavior. The checkout
contains uncommitted/untracked work: do not replace it or assume a clean baseline.

### 2. Finish discovery/browser execution

- Add `expansion/browser_worker.py` and invoke it from `expansion/integration.py` using the
  existing isolated browser image, proxy Bridge, certificate trust and Chromium sandbox.
- Connect generic browser proof to the frozen input task plan; retain blocked HTTP placeholders
  and use actual browser captures when available. Keep exact task/plan/input/role bindings.
- Finish browser request capture and typed import/review/plan APIs. Modules alone do not expose
  the promised operator OpenAPI/HAR intake or request-template review workflow.
- Complete resource-only origin capabilities. Current broker supports explicit related *scan*
  scopes but deliberately refuses resource-only grants for assessment traffic.
- Bound large catalogue transfer without deleting overflow tasks from coverage; the current
  environment envelope rejects inputs over 100 KB.

### 3. Connect identities and workflow proof to findings

- `expansion/worker.py` collects identity responses and workflow captures, but
  `expansion/analysis.py` currently evaluates only exposure and generic input probes.
- Invoke `evaluate_access_proof`, `evaluate_session_proof`, `evaluate_mutation_proof` and
  `evaluate_read_proof` against supervisor-stored artifacts; replace provisional refs with
  real evidence IDs. Aggregate outcomes by control while retaining every rule/instance.
- Bind authenticated active inputs to the correct live identity; a role name in a template
  must not execute using the anonymous HTTP client.
- Validate supplied credential references at intake for owner/scope/expiry; never persist
  raw credentials accidentally supplied as reference strings.
- Configure and mount the same encrypted credential store/key for API and policy services;
  keep the key and control-plane credentials out of worker containers.
- Exercise PostgreSQL cleanup RPC through the actual proxy. Confirm pending/failed resources
  suppress new mutations across recipes and crashes. Add typed cleanup visibility/recovery API;
  recovery requires fresh authority and must not repeat the original test mutation.

### 4. Finish browser workflows

Inspect `domain/browser_workflow.py`, `browser/workflow_checks.py` and
`tests/browser/test_browser_workflows.py`. Finish stored-marker, benign CSRF and upload-policy
proof using controlled identities and disposable records. Add `browser_workflows` to immutable
configuration/API, worker dispatch and cleanup authorization. Wire credentialed CORS proof.
Handle cleanup RPC rejection after cancellation without discarding partial evidence.
Validate every path on actual vulnerable/fixed browser fixtures, including cleanup failure.

### 5. Connect callback packs

Mount the separate callback collection service and owner-bound management/status API. Connect
SSRF/XXE collectors to scan/task ownership, expiry, cancellation, signed receipts and report
proof. Suppress callback token paths in access logs. Source attribution must use trustworthy
peer identity; ambiguous shared NAT and DNS-only interaction remain inconclusive. Migrations
have callback tables, but service deployment and worker/control dispatch are not finished.

### 6. Finish tool execution and adaptive dispatch

- Wire curated Nuclei template pins and canonical IDs into `adapters/runner.py`; select the
  expanded advisory snapshot only for new profiles. Fixture-running templates is not runtime
  scanner integration.
- Selected ZAP active execution is still blocked: enforce exact method/endpoint/input/budget
  bindings before enabling any rule. Omit rules that cannot be constrained.
- Connect reflection/browser, access/identity and callback adaptive hypotheses to their correct
  execution contexts. Retain budget protection, three-round limit and no duplicate without
  fresh evidence. Run real equal-budget comparisons.

### 7. Finish scorecards, exports and qualification

- New profile names exist, but `scoring/score.py` still uses the old category/rubric behavior,
  including excluding authentication/authorization/file/business categories. Implement and
  document explicit versioned expanded rubrics; retain the old ones reproducibly.
- Include endpoint/input/role completion, blocked tasks, proof state, cleanup/callback state,
  actual request/runtime/model costs, and separate tool/check/qualified-family counts in
  typed APIs and HTML/JSON. Update `docs/API_CONTRACT.md`.
- Freeze manifests and run the complete regression suite plus deployed vulnerable/fixed scans
  using the dedicated worker VM. Inspect downloadable reports, not just collector returns.
- Obtain independently curated holdout cases and run per-family qualification. Do not invent
  independence or fill unmet sample counts with sibling fixtures. External authenticated or
  mutation pilots require supplied test accounts, permission policy and disposable records.

## Deployment constraints

Preserve `deploy/docker-compose.worker-vm.yml` and the existing VM boundary. Use
`make run-worker-vm` rather than restarting a release stack without that override. Rebuild and
transfer changed worker images, regenerate pinned release manifests, migrate databases and
verify the real proxy path before claiming deployed results. Do not expose keys or `.env`.

## Evidence

- Previous verified backend baseline: 671 tests passed, before this expansion.
- Root configuration/API and control-channel tests: 6 passed in
  `runs/expansion-control-tests.log`; earlier API/broker regression run: 89 passed.
- Agent tooling/callback/adaptive/qualification regression run: 55 passed, recorded in
  `EXPANSION_TOOLS_IMPLEMENTATION.md`.
- Agent identity/workflow verification: latest runs cover 56 cases; see
  `AUTHENTICATED_WORKFLOWS.md`. Counts above overlap; do not sum them.
- Handoff rerun: `runs/expansion-handoff-tests-20260928.log` is the current targeted result.
  It includes the interrupted agent's browser workflow tests. Record its actual outcome.

No expansion finding on the operator's public sites is claimed by these fixture tests.
