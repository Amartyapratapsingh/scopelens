# B3 exposure pack

Five experimental controls and five locally authored, SHA256-pinned Nuclei candidate templates.
`exposure.collect_exposure_pack` accepts the existing broker-bound client; no new client or
network channel is created. At most 24 GETs include same-directory absent controls. Reads
are capped at 64 KiB, redirects are disabled, cancellation is checked during streaming.
Tech-specific probes need observed PHP/Apache/Spring; source maps need discovered same-origin
URLs. `approved_urls` can narrow target probes. Negative controls are still subject to broker
scope/path limits; denied controls leave the associated probe inconclusive.

`evaluate_exposure_pack(result, trusted_evidence_id)` supplies existing ControlOutcome values.
No proof is confirmed or marked pass without a trusted artifact reference from the caller.
Source-map secret shapes remain candidates. Public maps, masked actuator properties, login
pages and fallback pages are not confirmed disclosures. Credentials are never used. Captured
results retain structure, hashes, byte counts and URLs, not response bodies or secret values.

`component_fingerprints(captured_responses)` returns existing TechFingerprint records for the
advisory engine. AngularJS and Angular are separate package identities. `advisories.json`
extends the original eight-package corpus with lodash, axios, moment and AngularJS: 12 package
identities / 194 advisory records. Records retain individual OSV modified dates and ranges;
the parent snapshot is hashed and identified separately in provenance. These are candidate
matches, not proof that a site's exact build is exploitable.

## Tool verification

Nuclei 3.11.1 validated all five templates. `labs/expansion_tools/verify_nuclei.py` ran inside
the installed pinned tool image using `--network none` against loopback synthetic fixtures:
five expected candidate IDs on vulnerable fixtures, zero on fixed fixtures.
Evidence: `runs/expansion-tools/nuclei-fixture.jsonl`.

Use `tooling.reviewed_templates` to verify hashes and select by observed technology. Run only
returned file paths, never the whole directory (which also contains registry YAML). Map each
candidate to its manifest control_id and preserve source/provenance. Independently collected
exposure proof decides confirmation. These tests are development validation, not holdout.

ZAP active execution remains blocked until the tool runner receives an exact authenticated
broker capability binding method/origin/path/input/fixed-values/body/request-count/deadline.
`ActiveRuleBinding.accepts` validates individual requests. `zap_active_admission` is a shape
check only: the trusted broker must verify capability identity and expiry. It must never be
used to grant authority to a worker-supplied dictionary. AF includePaths alone is insufficient.

Sources: https://docs.projectdiscovery.io/templates/protocols/http/basic-http and
https://www.zaproxy.org/docs/desktop/addons/automation-framework/job-ascan/.
