# ScopeLens scanner expansion proposal

Status: **APPROVED by the operator on 26 September 2026. B1–B7 implementation authorized, including sub-agent delegation.**
Date: 26 September 2026
Scope: backend scanning, evidence, verification, report API and scorecards. No UI work.

## 1. Outcome

Given an approved application, discover its inputs and workflows, test the applicable
vulnerability families, verify findings with reproducible evidence, and explain both results
and omissions in HTML/JSON. Supplied test identities unlock authenticated assessment.

Build on the current backend. Retain its ledger, broker, isolated workers, evidence store,
provider adapter and deterministic scoring. The expansion changes what the scanner discovers,
which reviewed tests it can execute, and how it verifies them.

Approval of B1–B7 would extend the current Phase 1 scope. B4 activates the authenticated work
previously described under M6; B5 includes selected M7 staging capabilities. The existing Phase 1 profiles remain available; new capabilities use the versioned expansion profiles.

## 2. Current limits verified in the repository

| Area | Current implementation | Consequence |
|---|---|---|
| Active checks | `checks_registry/tooling/conditional-pack.json` lists exact lab paths and parameters; production origins are empty | Finding inputs while crawling does not automatically produce active tests for them |
| Adaptive planning | `orchestration/graph.py:candidates_from` proposes only CSP rechecks | Model access alone does not provide broad vulnerability investigation |
| Nuclei | One custom CSP observation template | Installed tooling is much broader than the checks currently enabled |
| HTTP discovery | Links, forms, query inputs, small known-path list; crawler never submits forms | POST/JSON workflows and hidden application states receive limited assessment |
| Sessions | External unauthenticated profile | Protected APIs and user/tenant boundaries remain untested |
| Advisory matching | Snapshot for eight selected npm packages; candidates require corroboration | Missing package identity/version and unsupported ranges limit useful coverage |
| Validation | Own fixtures, 26-case validation set, known Juice Shop case | Independent detection accuracy remains unestablished |

The current 22 registered controls are not 22 independently validated vulnerability classes.
Header observations, inventory, candidates and confirmed exploit conditions must remain distinct.

## 3. Build sequence

Complete one stage and its acceptance checks before the next. Each stage ends in a real lab
scan and downloadable report. Test registration and fixtures are delivered with each capability;
the final benchmark is not a substitute for testing along the way.

### B1. Discover inputs and create executable assessment plans

Deliver:
- Combine crawler links, browser network captures, forms, in-scope JavaScript route references,
  and operator-supplied OpenAPI/HAR inputs into one endpoint catalogue.
- Discover SPA states and API operations; capture query, path, form and JSON input locations,
  HTTP method, content type, ordinary baseline values and origin of discovery.
- Introduce `RequestTemplate`, `InputLocation`, `EndpointInstance`, `ActionPolicy` and
  `AssessmentPlanVersion`. Keep session/CSRF material as refreshable secret references.
- Create a deterministic applicability planner connecting each discovered input to eligible
  reviewed checks. Unlisted lab-specific paths must not be needed for ordinary discovery.
- Deduplicate operations without collapsing different methods, roles, content types or input
  structures. Capture changing response fields so harmless response noise does not look like
  an injection result.
- Add explicit related-origin grants, distinguishing scan targets from resource-only origins.
  A discovered hostname never inherits authority. This permits approved application APIs/CDNs
  without opening arbitrary third-party traffic.
- Freeze the assessment denominator after discovery. Later discoveries create an auditable
  plan revision; failed checks cannot disappear from coverage.

Exit: on a fixture with previously unlisted route names, discover linked pages, a SPA-only
API, a GET input, a form POST and a JSON operation. Produce the expected plan without hand-editing
an endpoint file. Blocked or unclassified actions remain explicit gaps. No unapproved write
is executed merely because OpenAPI or a page describes it.

### B2. Deepen input testing across discovered operations

Deliver:
- Apply the existing XSS, HTML injection, SQL comparison, redirect and CORS checks to B1 plans.
- Support query, approved form/JSON bodies and applicable path inputs, with valid baseline
  requests and refreshed CSRF/session fields. Do not mutate every field blindly.
- Add DOM-based XSS observation and browser confirmation; distinguish reflection, rendered
  markup and script execution. Use unique harmless markers and fresh browser contexts.
- Extend non-timing SQL comparisons to observed contexts, with repeated baselines, negative
  controls and noise-aware comparisons. Database errors alone remain candidates.
- Test redirects with normalization/control cases. Expand CORS analysis to valid combinations
  of origin, credentials and browser enforcement. Protected-data proof depends on B4 identities.
- Add response-header injection checks using a harmless marker header, only where the adapter
  can preserve an unambiguous response boundary.

Exit: the checks run against inputs discovered by B1; vulnerable/fixed variants distinguish
DOM-only execution, reflection without execution, dynamic response noise, valid redirects,
invalid CORS combinations and ineffective header-injection signals. No hand-authored target
location is used in the discovery acceptance test.

### B3. Expand exposure, component and scanner coverage

Deliver:
- Build small technology-specific packs for exposed backups/configuration, debug/status
  interfaces, source-map disclosures, private-key/credential candidates and unauthenticated
  management data. A reachable login page or a public source map alone is not a vulnerability.
- Improve component identification from multiple observations and broaden advisory snapshots
  to the technology families actually supported. Preserve advisory date, package identity,
  version range and applicability uncertainty.
- Add reviewed Nuclei templates in batches selected by observed technology. Pin engine,
  template/helper files and hashes; verify signatures where provided. A signature authenticates
  an author, not the check's safety or correctness.
- Add selected ZAP active rules as reviewed checks with exact method, endpoint, input and
  budget bindings. Validate that rule traffic stays within those bindings; omit rules that
  the adapter cannot constrain.
- Normalize tool results into canonical controls, retain all provenance, and require proof
  rules before confirmation. Two tools repeating the same signal are not independent proof.

Exit: each added pack catches its independently verified vulnerable condition, rejects a
fixed/look-alike fixture, respects the common request ledger, and merges duplicate findings.
Display three separate counts: installed tools, executable checks and validated families.

### B4. Authenticated scanning and access-control comparisons

Deliver:
- API intake for credential references, login recipes and short-lived supplied sessions.
  Models receive role/session references, never credential values.
- Separate browser and HTTP cookie stores for anonymous, user A, user B, administrator and
  tenant identities. Verify login state before each protected workflow; refresh or stop on expiry.
- Introduce `IdentityProfile`, `PermissionMatrix`, `OwnedTestObject` and `RoleComparison`.
  The permission matrix is operator-supplied policy, not an LLM guess about who should see what.
- Test object-level access, function/role access, tenant isolation and property-level reads.
  Use synthetic records owned by the test accounts. HTTP 200 alone is never access proof.
- Test session rotation and logout/revocation against declared session policy. A cookie flag
  check is not a session-lifecycle test.
- Confirm credentialed CORS exposure only when a real browser can read a protected synthetic
  record from the controlled foreign origin.

Exit: authorized access succeeds; forbidden access to a seeded marker record is detected;
redacted or policy-approved shared views do not become false positives; session expiry cannot
turn a redirected login page into a clean authorization result. Cross-role session leakage
and task restart cases have regression coverage.

External prerequisite for owned-site pilots: dedicated test identities and an explicit
permission matrix. Development and integration continue using local seeded applications.

### B5. API, stateful workflow and server-side checks

Deliver these as separate capability packs, each with its own proof and exit gate:

| Pack | Scope | Required confirmation |
|---|---|---|
| REST/GraphQL authorization | Object, function and field access under B4 roles; bounded queries | Forbidden synthetic object/field is returned or changed, contrary to the permission matrix |
| Mass assignment | Reviewed staging writes to disposable records | A protected field changes and an independent read verifies the change |
| Stored XSS | Dedicated staging records with cleanup | Stored harmless marker executes in a separate controlled viewer session |
| CSRF | A benign staging action with a stated cross-origin policy | Real browser performs the forbidden state change, verified independently; token absence alone is insufficient |
| Upload handling | Benign files, content-type handling and read authorization | A specific serving or authorization policy violation is demonstrated; accepting a file is not enough |
| SSRF | Operator-controlled callback service and unique per-attempt nonces | Correlated server-side HTTP interaction that can be distinguished from scanner/browser traffic; DNS-only interaction is weaker evidence |
| XXE | Approved XML workflows and controlled external-entity canary | Correlated entity resolution with appropriate negative controls; never infer local-file access from a callback |
| Path traversal | Designated non-sensitive canary file outside a permitted test directory | Exact pre-seeded canary content returned; arbitrary system files are not test fixtures |
| Template injection | Reviewed benign expression evaluation | Repeatable input-dependent evaluation versus literal/escaped controls, without arbitrary command execution |
| Private-response caching | Controlled users and synthetic records | A second unauthorized context receives the first user's marker under ordinary cache behavior |
| Workflow authorization | Operator-defined state transitions on test records | A declared workflow invariant is violated, confirmed by state read-back |

The callback service needs scoped tokens, signed receipts, nonce expiry, DNS/HTTP timestamps
and explicit callback-origin registration. This is a separate backend service, not an arbitrary
internet callback dependency. Records that cannot be safely reset are excluded from write packs.
Maintain a durable cleanup ledger; failed cleanup is visible and prevents repeating mutations.

GraphQL introspection is inventory by default. This proposal does not include resource-exhaustion
queries, brute-force login, arbitrary command execution, request smuggling, real payments,
external email/SMS, third-party resource claiming, or persistent changes to normal user data.
Those would require separate capability proposals, not a larger payload list here.

Exit: every pack has a real vulnerable/fixed workflow, independent state or callback proof,
negative controls, cancellation checks and verified cleanup where relevant. A missing identity,
canary, policy or reset mechanism produces `blocked`/`not_tested`, never a clean result.

### B6. Broaden adaptive investigation

Deliver:
- Generalize the current CSP-only candidates into registered hypothesis families: reflection,
  noisy SQL differences, role/tenant access differences, version/applicability ambiguity,
  unexpected redirects, exposure and callback observations.
- The model selects a typed reviewed follow-up with its missing proof, alternative explanation,
  expected evidence and stop condition. Application policy validates endpoint, identity, data
  and remaining budget. Generated code does not become a production exploit channel.
- Prioritize by expected proof value and unassessed controls, not severity words from a model.
  Preserve baseline budgets and the current maximum follow-up rounds; reject repeated actions
  with no new evidence.
- Show why a lead was confirmed, rejected, blocked or left inconclusive. Maintain links from
  hypothesis to each request, artifact, proof evaluation and finding.

Exit: a blind development scenario needs a useful second step in at least three different
families. The system rejects plausible false leads and unsupported model claims. Compare
baseline-only and adaptive runs using equal request/time/cost ceilings; report added confirmed
findings and added false positives separately. Extra calls alone are not improvement.

### B7. Qualify capabilities and publish honest reports/scorecards

Deliver:
- Start benchmark preparation during B1, before implementation is tuned to the test cases.
  Freeze candidate code, prompts, tools, profiles, case groups and budgets before held-out runs.
- Use diverse local test applications and fixed counterparts. OWASP Benchmark can contribute
  applicable DAST cases; VAmPI/crAPI and other pinned applications can supply development
  scenarios. Public availability does not make a corpus an untouched holdout.
- Keep sibling variants together. An independent evaluator/curator controls holdout labels;
  scanner/model input cannot contain answers. Any case used to tune a fix becomes validation.
- Preserve the existing per-family release targets: recall >=90%, confirmation precision >=95%,
  false-positive rate <=5%, negative conclusive coverage >=90%; minimum 30 positive/60 negative
  cases across at least three independent scenario groups. Publish sample counts and 95%
  uncertainty intervals. A pooled score cannot hide a weak family.
- Release only families meeting their gates. Insufficient independent cases means experimental,
  not waived validation. The existing five active families still owe this qualification.
- Introduce versioned profiles `external-discovery-v2`, `external-active-v2`,
  `authenticated-api-v1` and `staging-stateful-v1`. Reports name the profile and identities used.
- Version the scoring rubric for new families/categories. Separate hardening observations,
  candidates and confirmed vulnerabilities. Explain severity from demonstrated impact.
- Report endpoint/input/role reach, applicable-control completion, blocked tasks, proof state,
  requests, runtime, model cost and remaining unknowns. None of these percentages is a
  percentage of all vulnerabilities in the website.
- Compare old/new scanners on the same pinned applications and equal budgets, then run the
  authorized staging pilot using only capabilities permitted by its selected profile.

Exit: a reproducible benchmark report and real staging HTML/JSON exports show improvements,
regressions and limitations. New scores cannot be compared with old profiles without stating
the changed denominator and rubric. Do not manufacture a numeric score when eligibility fails.

## 4. Backend contract and implementation areas

Extend existing modules rather than starting a second scan pipeline:

- Discovery/plans: `domain/surface.py`, `checks/crawl.py`, browser network capture,
  new request-template/planning modules and migrations.
- Checks/tools: `checks/active.py`, `browser/active.py`, `adapters/scanners.py`,
  registry schemas and versioned bundles. Keep proof functions separate from collectors.
- Identities/workflows: new identity/session and workflow services, typed API routes,
  encrypted secret references, immutable per-scan policy snapshots and cleanup ledger.
- Broker: explicit origin purposes, identity/action bindings and shared budgets for every
  request, including auth refresh, tools and verification; separate callback receipt intake.
- Adaptation: `orchestration/graph.py` and registered typed follow-up operations.
- Reporting: profile-aware scoring, findings/retest lineage, exports and SSE contracts.

New API contracts cover identity profiles, permission matrices, supplied schemas/captures,
request-template review, assessment plans, workflow recipes and callback status. Every route
has a typed schema, ownership checks, tests and examples in `API_CONTRACT.md`. Redacted SSE
records expose phase/coverage/proof progress; no raw credentials or target response bodies.

## 5. Completion rule and approval scope

For each stage: implement -> targeted unit/contract tests -> real vulnerable and fixed runs ->
inspect proof/report -> run affected recovery/isolation regressions -> record evidence -> next
stage. Run the whole backend suite at stage integration boundaries. Preserve a working report
throughout. No empty adapters or mocked successes count as delivered detection capability.

Approval requested: the full B1–B7 backend expansion, built in the order above. Routine build
steps and local fixture scans do not need repeated approval. Actual staging writes, role tests
and callbacks require the corresponding target policy, test data and credentials; merely naming
an existing production URL does not create those missing inputs. The operator approved the full proposal on 26 September 2026.

## 6. Sources used in this proposal

- [OWASP WSTG v4.2](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/): testing-family taxonomy. Pin stable identifiers rather than silently tracking changing pages.
- [OWASP API Security Top 10](https://api-security.owasp.org/editions/2023/en/0x11-t10/): object, property and function authorization families.
- [OWASP authorization test automation](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html): explicit authorization matrices.
- [ZAP Automation Framework authentication](https://www.zaproxy.org/docs/desktop/addons/automation-framework/authentication/): authentication methods and verification statistics.
- [ZAP active-scan job](https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-ascan/): rule selection and user-bound scans. ScopeLens still owns admission and proof.
- [Nuclei template signing](https://docs.projectdiscovery.io/templates/reference/template-signing): signature properties and limits; helper payloads also need our own bundle hashes.
- [OWASP Benchmark](https://owasp.org/projects/benchmark): runnable detection-tool evaluation cases, including DAST use.
