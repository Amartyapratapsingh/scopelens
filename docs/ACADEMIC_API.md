# Academic assessment readiness API

`academic-readiness-v1` is a read-only presentation of immutable assessment inputs and
stored scan proof. Both routes require the operator session cookie.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/academic/configurations/{configuration_id}/readiness` | Review declared identity, permission, workflow and session prerequisites. |
| GET | `/api/academic/scans/{scan_id}/readiness` | Review the scan's exact frozen configuration, admitted captures, deterministic proof and restoration. |
| GET | `/api/academic/configurations/{configuration_id}/plan` | Rank all declared cases for baseline review and show configuration blockers. |
| GET | `/api/academic/scans/{scan_id}/plan` | Rank declared cases using the same trusted scan proof, with bounded follow-up recommendations. |

A missing or foreign-owned resource returns 404. A scan without a frozen configuration
returns 404. A damaged or mismatched configuration, catalogue, plan revision or capture
returns a generic 409 with `detail: "academic assessment snapshot is inconsistent"`.
No private validation input is echoed. Unavailable, expired or untrusted evidence stays
unproven. These routes create no scans, resolve no credential references, call no model
providers and perform no target requests.

## Stable binding and private fields

The response identifies `configuration_id`, `configuration_hash`, `scope_version_id`,
nullable `scan_id`, `profile`, and a SHA-256 `revision` of the public projection. Repeated
reads with unchanged facts return the same revision. Expiry or newly captured evidence
can change it. The configuration digest and exact scan snapshot must agree before any
readiness facts are published. Stored plan revisions and catalogues retain their existing
scope, profile, digest and task bindings.

Actors, cases and resources use opaque IDs bound to the configuration hash. Role labels,
identity names, record labels, permission IDs, markers, protected values, request bodies,
credential references, field pointers, URLs and query strings are withheld. Public
`family`, `control_id` and reason codes come from fixed contracts. A workflow's academic
meaning comes from the operator's declarations; the API does not infer that a field is
marks, attendance or a staff permission.

## Declarations, admission, execution and proof

`actors[]` records whether a login recipe and independent probe are configured, the
credential reference count, declared expiry, and `identity_evidence`. The latter is
`not_observed`, `verified_probe`, or `failed_probe`. `verified_probe` means the stored
independent probe matched the exact declared identity. It does not establish a current
usable session, session expiry behavior, or a role-change transition.

Each `cases[]` entry includes the opaque actor and owner, explicit expected permission,
control, configuration readiness and blocked reasons. Allowed permission comparisons
remain separate positive controls. Workflow recipes declare a forbidden protected state;
session cases retain the exact declared rotation, old-session or logout policy.

- `configuration_ready` describes configuration prerequisites. It grants no execution authority.
- `admitted` describes a durable admission reservation. It is not proof of execution.
- `execution: observed` requires a stored fixed-collector capture of the bound comparison,
  mutation, or lifecycle observation. Partial or mixed attempts can establish observed
  execution while leaving proof inconclusive.
- `proof` is `not_evaluated`, `inconclusive`, `pass`, or `confirmed_issue`. The existing
  production evaluators recompute it from exact captured identities and designated facts.
  Worker verdict fields are not proof inputs. Partial attempts cannot be stitched together.
- `baseline` and `independent_readback` state what the deterministic proof established.
  A response status alone proves neither unauthorized access nor a protected state change.
- `restoration: verified` requires a trusted cleanup readback of the original seed and
  state, together with the cleanup ledger or its bound append-only transition history.
  The original case's historical restoration remains visible after another recipe claims
  the same resource. `resource_fenced` separately describes the current resource fence
  and blocks further configuration readiness. A confirmed issue survives failed cleanup.
- `unexecuted_reason` is present for every case without a bound execution capture.

`coverage` counts configured, ready, blocked, admitted, executed, proven, fully assessed,
and confirmed cases independently. Fully assessed workflow cases require verified
restoration. These counts cover declared cases, not a percentage of all vulnerabilities.
A case can retain historical proof while current expiry or a new resource fence blocks
its readiness for a later execution.

The scan response also includes `capabilities` count fields and `reach` totals from the
existing production report interfaces. Unknown capability totals stay null. The broader
report reach denominator and this declared-case denominator are distinct.

## Explicit feature gaps

`features[]` records identity setup, permission matrix, protected workflows, protected-field
assignment, approval sequencing and session lifecycle. Missing declarations show fixed
reason codes. Ordinary-field allowed controls are not inferred from a protected-field
recipe. Generic single-action workflow proof does not establish an academic approval
sequence. Explicit multi-step transition contracts, session expiry transitions and role
change transitions remain visible gaps.

The routes prepare approved cases for review and reporting. They do not create identities,
permissions or records, run a sequence, execute recovery, retest a finding, qualify a family,
or establish that the academic pack passed deployed worker and broker gates.

## Selected-case agenda

`academic-plan-v1` derives only from the corresponding readiness projection. It retains
the same owner and snapshot checks, opaque case IDs, configuration binding, coverage
and feature counts. `readiness_revision` identifies the source projection; `revision`
hashes the complete public plan including its recommendation limit.

Each `agenda[]` entry contains its unchanged readiness `case`, a consecutive `order`,
`state: ready|blocked`, explicit `baseline_purpose`, `priority`, `priority_reasons` and
`recommendation`. Ready allowed comparisons come first. Trusted confirmed case proof
receives priority 2; an observed case with inconclusive proof receives priority 1.
Other declarations receive priority 0. Cases use opaque ID tie-breaking for a stable
order. Priority expresses review urgency, without changing finding severity. Worker
verdicts and undeclared proof IDs cannot create agenda entries or confirmed priority.

Blocked cases remain in the agenda with their original reason codes and
`resolve_declared_prerequisites` recommendation. Historical proof cannot remove missing
credential setup, identity expiry, frozen registry exclusion or a cleanup fence.
`ready` describes declared prerequisites only. The existing admission gates still check
credential availability and fresh authority before any later execution.

`budget.baseline_reserved` counts every declared case, including blocked and already
observed cases. This protected baseline count never decreases when optional
recommendations are selected. `baseline_ready` and `baseline_blocked` expose its current
split. These are case counts for review, rather than HTTP request allocations or
execution reservations. `execution_budget_reserved` and `execution_authority` are false.

Both plan routes accept `followup_limit=0..20`, default 3. `followups[]` selects at most
that many existing cases with confirmed proof or incomplete observed proof. Ready cases
rank before blocked cases, then confirmed proof before incomplete proof, then opaque ID.
Every recommendation retains `state`, `blocked_reasons` and `executed: false`.
`followup_selected` and `followup_deferred` show the bounded selection. Changing this
limit preserves all baseline cases and the observed coverage denominator.

The agenda dispatches no scan, mutation, cleanup or retest. The fixed collector keeps
its frozen operator-declared execution order and runs all approved cases through the
existing admission and cleanup controls. No plan endpoint edits customer configuration.
Generic single-action workflow transitions and explicitly allowed permission controls
have factual feature counts. Their presence does not establish academic approval
semantics, general multi-step sequencing, ordinary-field assignment permission or role
change coverage.

## Verification

`uv run pytest -q tests/unit/test_academic_readiness.py tests/unit/test_academic_planning.py`
passes 19 tests. The PostgreSQL route tests are in
`tests/integration/test_academic_readiness_api.py` and
`tests/integration/test_academic_planning_api.py`; all seven route tests pass. The tests cover private-field omission,
owner isolation, authentication, digest binding, no scan dispatch or secret resolution,
partial and mixed proof attempts, repeated access proof, workflow readback and restoration,
resource fences, historical cleanup preservation, session identity checks, and trusted
intake provenance. Planning tests also cover stable agenda hashes, protected baseline
counts, bounded recommendations, undeclared proof IDs and blockers retained after
historical proof. The API proof test admits synthetic test captures through trusted
intake. It verifies projection behavior, not deployed broker provenance or customer findings.
