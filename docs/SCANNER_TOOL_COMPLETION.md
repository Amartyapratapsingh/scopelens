# Scanner tool completion status

Date: 28 September 2026. Backend adapter work only.

## Active ZAP rule boundary

`backend/scopelens/adapters/zap_active.py` defines frozen rule pins, exact GET input tasks,
request-shape checks, blocked admission and deterministic candidate normalization. A pin
includes the engine version and SHA256, rule configuration SHA256, canonical control,
finite reviewed input values, request ceiling and deadline. A task binds scan, task and
input identity, URL, method, named query input, rule configuration hash and ceilings.
The request contract rejects changed origin/path/method/body, changed fixed query values,
duplicate keys, unreviewed input values and ambiguous encoded paths. Normalization
rejects wrong-rule and outside-task locations, deduplicates instances and retains
task/input/rule/config/output provenance. Process cancellation, timeout, truncation and
nonzero exit never become a completed outcome. Candidates remain `potential` and do not
earn control coverage or confirmation.

The executable pin registry is empty and `active_admission` always returns `blocked`.
No ZAP active process is launched by this module. Existing ZAP execution remains offline
passive HAR analysis. The existing `ActiveRuleBinding` shape check in
`checks/packs/tooling.py` is likewise insufficient to authorize launch.

Root integration required before any production enablement:

1. Review and pin an actual ZAP engine and individual rule/configuration, including every
   generated request value. Reject rules whose traffic cannot be reduced to a finite,
   reviewed request set. The synthetic values in unit tests are not a reviewed rule.
2. Extend the trusted broker with authenticated task grants and enforce scan/task/input,
   rule/config hashes, exact destination/path/method/query/body, finite values,
   per-task request/byte ceilings, deadline, cancellation and redirect denial on **every**
   request. Audit permitted and denied requests against the task identity. A caller-supplied
   boolean or adapter-side shape check is not a broker grant.
3. Connect a dedicated active adapter only after the broker gate exists; verify the engine
   binary/config before launch, isolate process and files, then reconcile broker audit counts
   and task identity with the report. Keep unknown or unbound alerts as incomplete outcomes.
4. Pass a real vulnerable/fixed owned lab pair plus wrong-destination, extra-request,
   redirect, cancellation and cleanup cases through the deployed dedicated worker VM.
   Promotion and capability counts require separately reviewed measurement. Development
   fixtures do not provide independent qualification.

## Existing HTTP tool acceptance

Focused command results on 28 September:

| Verification | Result |
|---|---|
| `uv run pytest tests/unit/test_zap_active_contract.py tests/unit/test_expansion_runner.py tests/contract/test_scanner_parsers.py -q` | 49 passed |
| Pinned Kali image, `--network none`, `labs/expansion_tools/verify_nuclei.py` with read-only template mount | Vulnerable: five expected IDs; fixed: zero |
| Same isolated image, `tests/fixtures/verify_expansion_runner.py` with read-only source/template mounts | Vulnerable: five candidates / five proxy canary requests; fixed: zero candidates / five requests |

The fixture proxy is a local policy canary, not the deployed broker. These runs verify
template selection, candidate mapping and bounded loopback requests. They do not verify
the dedicated VM or production broker ledger. The current five Nuclei templates remain
experimental; their candidate matches require the independent exposure proof path.

Remaining B3/B5 scanner tool gaps: deployed acceptance for the broader HTTP packs,
per-rule ZAP broker enforcement and actual active rule review, and independent holdout
qualification. No public target was scanned for this work.
