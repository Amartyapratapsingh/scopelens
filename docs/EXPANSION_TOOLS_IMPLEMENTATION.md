# Exposure, callback and adaptive expansion implementation

Date: 2026-09-26. Backend implementation and development validation. This document does
not promote experimental families or replace the independent qualification gate.

## B3: exposure and components

`checks/packs/exposure.py` collects bounded GET probes over the existing broker client.
It implements private configuration backups, PHP/Apache diagnostics, Spring management
configuration, private-key material and discovered same-origin source-map private-material
candidates. Controls use independent absent paths retaining the same directory and extension.
A login page, public source map, masked configuration or generic fallback is not a confirmed
vulnerability. Generic publishable API identifiers are not classified as private credentials.

The caller passes `approved_urls` to narrow probes if needed. Negative controls remain subject
to the broker scope. Blocked/truncated controls leave an explicit incomplete outcome. Values
are classified in memory and omitted from retained results; hashes/structures remain.

Five experimental registry entries are in `checks_registry/tooling/expansion/SL-C05-*.yaml`,
applicable only to the four new versioned profiles. `component_fingerprints(responses)` extends
existing advisory inputs from passive captured documents and versioned asset URLs. Package
identity corroboration is distinct from exploitability. AngularJS and Angular stay separate.
The expansion OSV snapshot includes 194 records across 12 package identities, with original
record modification dates, ranges and parent snapshot identity/hash.

Five locally authored Nuclei templates are pinned by SHA256 and selected by observed technology.
They produce candidates; the independent exposure proof rule determines confirmation. Actual
Nuclei 3.11.1 validation and network-disabled loopback execution produced five expected candidate
IDs on the vulnerable fixture and zero on fixed fixtures:
`runs/expansion-tools/nuclei-fixture.jsonl`.

ZAP active scanning remains blocked. `ActiveRuleTask` and `ActiveRulePin` describe an exact
GET query input, finite values, reviewed engine/configuration hashes and request/time ceilings.
The reviewed executable pin registry is empty, and `active_admission` cannot grant execution.
There is no task-authenticated broker capability, durable per-task accounting or active
launcher. ZAP includePaths and worker shape checks are not sufficient input boundaries.
No installed tool is counted as an independently validated vulnerability family. See
`EXPANSION_ACCEPTANCE.md` for the missing owned-lab gate.

## B5: controlled HTTP callbacks

`callbacks/service.py` supplies independent SQLAlchemy `CallbackBase` metadata with
`callback_nonces` and `callback_receipts`. Issue binds owner, scan, task, family, purpose,
expiry, callback origin and exact target/scanner egress addresses. The callback route reads
actual peer IP, ignores X-Forwarded-For, stores no body or arbitrary headers, and signs receipts
with HMAC-SHA256. A scan may revoke all outstanding nonces. Restarts preserve receipt records.

`callbacks/probes.py` sends three requests through the supplied broker-bound client: an inert
negative control and two independently issued positive canaries. SSRF uses an approved GET
query input; XXE uses an approved staging XML POST. Operator policy must explicitly say this
external interaction is forbidden. It cannot classify a legitimate URL-fetching feature as a
vulnerability merely because it fetches the canary.

Confirmation requires both signed target-origin HTTP receipts and no target negative-control
interaction throughout the observation window. Scanner-origin, DNS-only and unknown-source
receipts cannot confirm. Shared NAT makes attribution ambiguous and is rejected at admission.
Missing callbacks remain inconclusive because target egress restrictions may mask behavior.
No metadata access, local-file reads or arbitrary command execution is claimed.

`labs/expansion_callbacks/verify.py` was executed in a network-disabled Linux container against
real HTTP servers and the real SAX external-entity parser. Scanner source was 127.0.0.1;
target callback sockets explicitly bound 127.0.0.2. Both vulnerable SSRF/XXE scenarios produced
two signed target HTTP receipts. Fixed scenarios produced zero and remained inconclusive.
Evidence: `runs/expansion-tools/callback-fixtures.jsonl`.

Deployment must suppress callback token paths from access logs and serve the collector directly
or through a separately authenticated peer-identity relay. A generic forwarding proxy cannot
supply source identity through untrusted headers. These are trusted service APIs; issue/read
management endpoints must use the application's existing ownership checks.

## B6: bounded investigations

`orchestration/expansion.py` defines typed hypotheses for reflection, noisy SQL, access, component
identity, redirects, exposures and callbacks. Existing graph wiring selects these only for new
profiles. Old profiles keep the previous CSP investigation. Baseline finishes first, budgets are
checked against each candidate's request bound, prior admitted IDs are never replayed, and new
evidence is required for another round (maximum three).

Existing HTTP follow-ups repeat reviewed SQL/redirect proof series, recheck exact exposure
locations with fresh independent controls, and reobserve passive component identity. Graph output
captures join the same evidence intake. An LLM selects only a registered candidate ID and cannot
supply a confirmation. Reflection, access and callback hypotheses retain explicit blocked reasons
when their distinct prerequisites are absent.

The 11 October source integration attaches a fresh brokered browser context for anonymous GET
reflection, separate role clients for access proofs using already supplied read-only sessions,
and supervisor-side verification of stored callback receipts. Browser task/template/input/plan
bindings must match the frozen plan. Access clients permit only declared GET/HEAD probes with
a global 12-request ceiling; login, writes and expired supplied sessions are blocked. Adaptive
access records retain their own graph proof and do not merge separate attempts into baseline
access coverage. Callback verification issues no target request, nonce or replayed dispatch.
Login-based access and authenticated browser reflection remain explicit gaps. These paths
passed local proof/context tests; deployed acceptance and equal-budget gain remain pending.

Actual HTTP development fixtures demonstrated useful proof or rejection in SQL, redirect and
exposure families. This is not a held-out equal-budget improvement claim. `verify_followup`
recomputes input proof from captures and leaves version matching as a candidate.

## B7: qualification and comparison contracts

`evaluation/expansion.py` enforces per-declared-family qualification, including families absent
from measured cases. It retains 95% intervals and the existing 30-positive/60-negative/3-group
minimum, recall/precision/false-positive/negative-conclusive-coverage thresholds. Development or
contaminated cases cannot pass an independent holdout gate. Curator/freeze metadata is supplied
by the external evaluator; code does not establish independent curation merely by writing a flag.

Equal-budget comparison refuses mismatched scopes, fixtures, profiles, source fingerprints or
ceilings, exceeded limits and unknown model cost. Added true positives and added false positives
are reported separately. Capability inventory separates measured installed tools, executable
controls and independently qualified families.

Verification command:

```sh
uv run pytest tests/unit/test_active_proofs.py tests/unit/test_expansion_adaptive.py tests/unit/test_expansion_callbacks.py tests/unit/test_expansion_exposure.py tests/unit/test_expansion_tooling.py tests/unit/test_expansion_qualification.py -q
```

Result when recorded: 55 passed. Related files pass Ruff checks. Full pipeline deployment,
worker images, owner-bound API integration and final benchmark evidence are coordinated by the
main implementation task; unit/fixture tests alone do not establish those integration gates.
