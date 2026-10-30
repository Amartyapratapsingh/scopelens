# Academic application assessment features

Requested 29 September 2026. Objective: assess access to designated test records and
protected academic workflows, with reproducible evidence and verified restoration.

A serious finding requires observed unauthorized behavior. The feature list cannot
promise that the customer's application contains a serious vulnerability. All customer
findings retain their actual confirmation state and coverage limitations.

## Current integration status — 1 October 2026

| Feature | Current evidence | Remaining gate |
|---|---|---|
| Portal exploration | Deployed public recheck `cad05813-e5d3-4313-bef8-be15a3b9faff` captures two browser states. Proxy queue regression completes all 24 requests. | Authentication requires customer test identities; third-party resources remain outside the scan scope. |
| Identity intake, permissions and cross-student reads | Fresh vulnerable/fixed scans `4fe4b2dd-07a1-4232-be16-24511750c500` and `0da2ae99-7abf-4441-96a8-81c69faab2c8` independently replay persisted trusted proof. | Customer-specific accounts, records and permission declarations. |
| Marks, attendance, protected assignment and staff functions | Paired deployed synthetic cases detect forbidden behavior in the vulnerable fixture and pass the corresponding fixed cases. | Customer-specific cases; no college flaw inferred from the fixture. |
| Approval transitions | Deployed student approval and out-of-order staff approval cases prove the exact forbidden draft-to-approved transitions. | General multi-step sequence exploration is not implemented. |
| Sessions | Rotation, old-cookie revocation and logout now survive trusted evidence redaction and proof replay. Supplied expired identities remain incomplete rather than passing. | Actual timed server-expiry implementation and its deployed gate are in progress. Arbitrary role-change sequences remain unsupported. |
| Cleanup | All six writes in one deployed scan retain individual restoration proof while sharing one resource fence. Database recovery, revocation and malformed-history regressions pass. | Deployed academic fault/cancellation/recovery injection is in progress. |
| Reports and retests | Saved HTML/JSON, trusted evidence hashes, instance denominators and dashboard summaries agree for the verified cases. Reviewed renewal retains the same declared case contract under fresh authority. | Same-origin renewed fixed retests are running. |
| Case selection and coverage | Typed owner-bound readiness and read-only plan APIs rank only declared cases and preserve the baseline. Recommendations confer no execution authority. | Any future scheduler integration must retain the same immutable authority and budgets. |

The latest completed full backend run passes 1,678 tests, with no failures or skips
(`runs/academic-workflows/full-tests-final.log`). This precedes the additional timed
expiry and fault-injection gates. Registry qualification was not promoted by these runs.

The older identity captures were invalidated for verification after cookie fingerprints
were found redacted to identical placeholders. They remain archived, not rewritten or
counted as valid proof. Fresh captures above close that defect. The remaining receipt
and retest status is recorded in `runs/academic-workflows/deployed/`.

The college portal report contains four confirmed configuration findings and one
potential component-advisory candidate. There is no confirmed marks-changing or
attendance-changing college exploit. Overall coverage remains insufficient for a
whole-application score. Synthetic findings establish scanner behavior only.

## Feature inventory and implementation order

| Order | Feature | Existing implementation | Work and acceptance gate |
|---|---|---|---|
| 1 | Reliable portal exploration | Public Playwright explorer and authenticated browser infrastructure exist. The public college portal still captures zero browser states. | Diagnose pending assets and transport/parser progress; capture a real initial state and an allowed transition through the deployed broker. Local slow-script regression alone does not close this gap. |
| 2 | Test-account intake and session verification | Encrypted credential references, login recipes, independent identity probes and isolated sessions exist in `identities/` and immutable assessment configurations. | Complete student A/student B/staff setup guidance and deployed gates. Expired or wrong identities must block checks, never count as passes. |
| 3 | Explicit permission matrix | Object, function, tenant and property comparisons exist in `identities/assessment.py`. | Declare allowed and forbidden views for synthetic academic records. Verify both authorized baselines and denied comparisons; a 200 response alone cannot confirm access. |
| 4 | Cross-student record access | Generic repeated marker comparison exists. | Academic local fixture added this turn. Student B must not see student A's designated record; student A and staff are positive controls. Deployed proof replay remains. |
| 5 | Unauthorized marks changes | Generic synchronous workflow engine and independent state read-back exist. | Academic local recipe added this turn. A designated student action is followed by two staff reads of the same synthetic record, then restoration. Vulnerable/fixed local pairs must differ correctly. |
| 6 | Unauthorized attendance changes | Same workflow engine can assess a separately declared protected property. | Academic local recipe added this turn. Use a separate recipe and shared resource fence. Repeat the vulnerable/fixed, read-back and restoration gates. |
| 7 | Protected-field assignment | Generic mass-assignment recipe and proof rules exist. | Add academic cases for operator-selected protected fields, including an ordinary-field allowed control. Do not infer permission from a field name or a model suggestion. |
| 8 | Staff-only functions and approval sequencing | Function comparisons and workflow authorization primitives exist; academic multi-step sequence coverage is not established. | Add exact expected transitions for a synthetic approval workflow. Verify that student and out-of-order actions cannot produce a staff-approved state. Separate configured, executed and proven coverage. |
| 9 | Session expiry, logout and role separation | Session lifecycle checks exist. | Add deployed academic cases for expired student sessions and role changes. Prove identity before and after comparisons; never infer authentication from a login-page status alone. |
| 10 | Cleanup, cancellation and interrupted operations | Durable claims, separate cleanup channel, resource fencing and fresh-authority recovery exist. | Extend academic deployed cases. A failed reset must preserve evidence and block all further mutations of that resource, including another property. Never replay the original mutation during recovery. |
| 11 | Proof report and retest | Generic findings, trusted evidence intake, deterministic proof evaluation and reporting exist. | Add an academic demonstration report linking actor, expected permission, baseline, observed result, independent read-back and restoration. Retest only against the same designated test case; blocked retest cannot close a finding. |
| 12 | Adaptive selection and coverage | Host priorities and bounded investigation exist. | Connect approved workflow cases to planning without inventing identities, permissions or records. Every unexecuted case must show its reason. Rank by observed application evidence; severity is decided by proof. |

Existing primitives mean these are integration and validation tasks in several places,
not twelve entirely absent engines. Source presence or module tests alone do not establish
that a feature works on the college portal.

## First implementation increment

New files:

- `labs/academic_workflows/app.py`: isolated in-memory synthetic application, two student
  accounts and one staff account, record views, marks/attendance changes and staff reset.
  Vulnerable and fixed variants share the same behavior except their access checks.
- `labs/academic_workflows/scenarios.py`: explicit development identities, permission matrix
  and marks/attendance recipes using existing production domain contracts. These helpers
  accept only explicit HTTP loopback origins and cannot be pointed at a customer hostname.
- `tests/test_academic_workflows.py`: real local HTTP requests through existing identity and
  workflow engines, including fixed negatives, verified cleanup, cleanup failure fencing,
  invalid credentials, and refusal to retarget development recipes outside loopback.

The tests exercise the real collectors and deterministic outcome validation. Their capture
callbacks are local test evidence references. They do not establish deployed supervisor
provenance, broker containment, independent qualification, or customer vulnerability findings.
No registry entry was promoted and no customer scan or production record was changed.

## Customer prerequisites

Before any customer-specific stateful case is configured, obtain dedicated student A,
student B and staff test identities, a staging origin or explicitly designated disposable
records, expected permissions, and an approved restore operation. Store credentials through
the existing encrypted intake. The operator must specify which records and actions are
permitted. Domain ownership alone does not define record-level mutation authority.

Until these exist, public-page exploration can continue and logged-in academic coverage
remains blocked. The current college assessment has no confirmed marks or attendance issue.

## Verification sequence

1. Local HTTP paired cases through the production collectors and proof functions.
2. Frozen lab assessment configuration and credential references through the actual API.
3. Paired scans through the deployed isolated worker and broker, preserving role separation.
4. Independent replay of supervisor-admitted evidence, including restoration and negatives.
5. Report/score/coverage checks and a fixed-version retest.
6. Only then configure the approved customer staging/test-record cases.

The first increment completes step 1 only. Steps 2–5 remain required before claiming that
this academic pack is deployed end to end. Independent holdout qualification is separate.

## Measured results for this increment

`uv run pytest -q tests/test_academic_workflows.py tests/test_identity_expansion.py tests/test_workflow_expansion.py tests/integration/test_expansion_api.py`
passed **69 tests**, with no failures or skips. Eleven are the new academic tests.
`uv run ruff check labs/academic_workflows tests/test_academic_workflows.py` passed.
Logs: `runs/academic-workflows/local-tests.log` and `runs/academic-workflows/lint.log`.
