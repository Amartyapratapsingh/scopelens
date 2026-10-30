# Capability and reach metadata

The JSON/HTML report and `GET /api/scans/{scan_id}/summary` expose the same additive
`capabilities` and `reach` fields. Summary responses type both fields in OpenAPI.
Old stored report dictionaries without these fields still render; old summary inputs may
omit them. The score and its coverage denominator are unchanged.

## Capability counts

Each count has `count` (integer or null), `names`, `evidence_state`, and `reason`.

| Field | Meaning | Evidence required |
|---|---|---|
| `installed_tools` | Measured installed tool names | A complete frozen installation measurement with per-tool version and evidence reference |
| `executable_checks` | Enabled, reviewed controls executable for this scan | Frozen registry plus complete runtime inventory; each control must be supported, have satisfied prerequisites, and be admitted for this profile/authority |
| `independently_qualified_families` | Families meeting independent holdout gates | Frozen `qualification-v2` result and its curation, manifest, pre-run freeze and measurement provenance |
| `experimental_controls` | Experimental entries in this scan's frozen profile registry | Registry inventory; this count claims neither execution nor qualification |
| `observed_tools` | Distinct tools with completed/partial captured scanner results | Tool/version/output hash in this scan's result; a lower bound, not total installed tools |

Missing measurement gives `count: null`, `names: []`, `evidence_state: unknown`.
Zero is reserved for a measured empty set (or no observed tool results for the explicit
lower bound). Neither a template bundle, today’s release manifest nor a static supported
control list establishes installation or independent qualification.

The pure `capability_inventory` helper lives in `scopelens.domain.capabilities` and is
re-exported by `evaluation.expansion`. Thus the installed API package does not depend on
an unpackaged evaluation tree. Report code validates provenance before using its counts.

### Trusted producer contract

The supervisor-side producer and binding rules are in
[`RUNTIME_CAPABILITY_MEASUREMENT.md`](RUNTIME_CAPABILITY_MEASUREMENT.md). The coordinator
now measures and binds its configured immutable images in source. Until
a deployment captures and persists a matching measurement from those images,
installed/executable/qualified totals remain unknown. Never populate these from a
live manifest merely to obtain numeric results. Legacy v1 snapshots are rejected.

A trusted coordinator may persist `assessment_plan.capability_snapshot`, validated by
`domain.report_metadata.CapabilitySnapshot`, **before execution**:

```json
{
  "version": "capability-snapshot-v2",
  "profile": "authenticated-api-v1",
  "scan_id": "<frozen scan id>",
  "scope_version_id": "<frozen scope version id>",
  "candidate_fingerprint": "<64 lowercase hex characters>",
  "registry_sha256": "<64 lowercase hex characters>",
  "configuration_sha256": "<64 lowercase hex characters>",
  "plan_sha256": "<64 lowercase hex characters>",
  "image_bindings": [{"role": "kali", "image_id": "sha256:<64 hex>", "architecture": "arm64", "probe_sha256": "<64 hex>"}],
  "source_sha256": "<64 lowercase hex characters: measured source digest>",
  "verification_ref": "<private measurement evidence reference>",
  "measured_at": "<UTC timestamp>",
  "installation_complete": true,
  "runtime_inventory_complete": true,
  "installed_tools": [
    {"name": "<tool>", "measured_version": "<actual version>", "verification_ref": "<evidence>", "image_id": "sha256:<64 hex>", "binary_sha256": "<64 hex>"}
  ],
  "runtime_controls": [
    {
      "control_id": "<registry control id>",
      "runtime_supported": true,
      "prerequisites_satisfied": true,
      "authority_admitted": true,
      "verification_ref": "<execution/authority measurement evidence>"
    }
  ],
  "qualification": {}
}
```

The producer owns measurement authenticity and must bind it to the frozen candidate,
registry, scope, profile and prerequisites. This is private trusted state, never an
operator/worker-supplied API field. Complete inventory flags mean all relevant entries
were measured, including rejected or unavailable controls; a partial inventory remains
unknown. Only frozen registry entries whose state is `enabled` can enter the executable
count. Experimental entries remain separate even if a worker can call them.

For qualification, persist the result of `evaluation.expansion.qualify` including its
`version`, `partition`, `candidate_fingerprint`, `manifest_sha256` and `families`, augmented
with `verification_ref`, `curator_ref`, `frozen_before_run: true` and `contaminated: false`
from the independent evaluator's recorded provenance. Only `partition: holdout` is
eligible. The evaluator supplies sample counts, uncertainty intervals and per-family
qualification decisions; template matches and development fixtures cannot substitute.
The writer does not independently rerun holdout evaluation or verify private measurement
references. That remains the trusted producer's responsibility.

## Reach

`reach` contains `version: reach-v1`, `profile`, `evidence_state`, `discovered`, totals,
`groups`, `gaps`, `out_of_profile_categories`, and `limitations`.

- `discovered`: route/template/input/role counts from the frozen request catalogue.
  Inputs count template input locations, not input values or arbitrary parameter keys.
- `planned`, `fully_assessed`, `blocked`, `error`, `unassessed`, `not_applicable`:
  disjoint recorded instance counts. The final five sum to `planned`.
- `groups`: the same counts by declared `role_id` and query-free route. Unknown bindings
  are null. A control without a recorded instance list contributes one control-level unit;
  that unit does not imply every possible endpoint was tested.
- `gaps`: stable reasons for incomplete instances, discovered templates without input
  plans, declared identities without bound instances, and recorded discovery gaps.
  Raw discovery errors, executable requests, query values and identity secrets are omitted.
- Missing outcomes for frozen planned tasks or controls remain unassessed. Extra completed
  IDs never increase the denominator or earn completion. Blocked planned tasks stay blocked.
- Completed instances count as fully assessed only for conclusive outcomes with evidence
  references. Aggregate inconclusive/error/blocked states do not become successful merely
  because they contain a completed ID. Evidence-backed N/A is separate from successful tests.
- Aggregate results cannot always attribute each missing instance to a specific block/error.
  These stay `unassessed`; the report states this limitation instead of inventing precision.

Raw `request_catalogue`, `input_assessment_plan`, `assessment_plan_revisions`,
`assessment_execution_claims`, `capability_measurement` and `capability_snapshot` are excluded
from the generic public `assessment_plan` export, alongside the existing private expansion
configuration. Consumers should use the safe `reach`, `capabilities` and
`assessment_summary` projections. This export privacy correction prevents baseline input
values, credential references and private measurement data appearing in reports.

All counts describe recorded assessment work. They do not measure the percentage of all
vulnerabilities found. Declared identities do not establish successful login.

## Verification

`tests/unit/test_report_capability_reach.py` exercises frozen evidence, null unknowns,
profile/review/authority filtering, missing and partial outcomes, balanced instance totals,
secret omission, HTML escaping, typed summary parity and old dictionary compatibility.
The authenticated browser lab verifier additionally requires role A's protected route to
have a completed planned instance, unknown unmeasured capability totals, balanced counts,
no private raw plan fields, and identical summary/export metadata. That verifier must run
against rebuilt deployed services; unit fixtures do not claim a deployed gate.
