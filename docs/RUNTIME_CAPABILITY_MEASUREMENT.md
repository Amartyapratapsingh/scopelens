# Trusted runtime capability measurement

`execution/capability_probe.py` supplies the supervisor-side measurement primitive.
It resolves each configured worker image to a local immutable Docker image ID and
architecture, then runs a fixed Python probe by that ID with no network, host mounts,
scan environment, target URL or credentials. The container has a read-only root,
bounded memory/CPU/PIDs and a 45-second outer wait. Each command inside the probe
has a 10-second deadline; only a bounded JSON line is accepted. The probe source hash
is recorded with each image binding. Ordinary scan worker output is never consumed
by this path.

The Kali image probes ZAP, Nuclei and testssl; the browser image probes the installed
Playwright package and Chromium executable. The generic tool image has no additional
third-party scanner binary to report. A missing binary produces measured `absent`.
A failed version command, timeout, malformed output, changed image ID, or failed
container means incomplete installation inventory. `installation_complete` then stays
false, and report counts remain unknown. Tool names are counted only when a successful
version command and binary/package file digest are present. The image ID binds the
whole filesystem, including files beyond the direct executable hash.

## Strict deployed replay — 11 October 2026

On frozen `b0b123add84182fb8ec9327ec9951e98711d7d8c`, fresh owned labs-good scan
`232c3ccd-3312-4e81-8cf7-35698de018a3` passed the strict measured-inventory gate:
installed tools count 5 includes Chromium, and external-configuration executable controls
count 12. Trusted source/image/probe/snapshot bindings and export parity matched without
relaxing unknown-count checks. Evidence: `runs/backend-gaps-capability-b0b123a/receipts.json`.
The underlying scan completed_partial. Inventory acceptance does not imply complete
assessment, independent qualification or a detection-rate estimate.

## Coordinator integration

`execution/coordinator.py::_measure_capabilities` now runs this path before ordinary
worker execution, outside a database transaction while the lease heartbeat remains active.
Resolved image IDs replace mutable references for all later launches in that scan.
Cancellation, epoch, lease and scope expiry are checked again before persistence. Recovery
tasks receive no ordinary capability snapshot.

The fixed `runtime-probe-v2` also hashes the sorted relative paths and SHA256 values of
all backend Python source files in each measured image. Every selected image must report
the same digest, and it must match `capability_producer.source_digest()` in the trusted
coordinator. This is a measured backend-source identity, distinct from the evaluator
full-build fingerprint. Image IDs separately bind the complete filesystem and tool payloads.
A release manifest or ordinary worker assertion cannot supply this digest. Missing or
mismatched source removes the snapshot; it does not yield a measured empty inventory.

The implemented sequence is:

1. Resolve the configured image references and set private
   `assessment_plan.capability_expected_images` to the role, image ID, architecture and
   `PROBE_SHA256` tuples returned by the measurement. Include every image that may
   execute this scan. If an image cannot resolve, leave the snapshot absent.
2. Set private `capability_candidate_fingerprint` to a 64-character digest of the
   reviewed candidate source actually built into those images. It must come from the
   trusted build provenance, not the release manifest or a worker declaration.
3. Freeze private `capability_execution_plan` before measurement. The binding also
   hashes the frozen registry, configuration, request catalogue, input assessment plan,
   and adaptive selection. `expansion/integration.py` and the graph admission step
   rebind the cached offline image measurement to each newly frozen plan before its
   workers execute. Images stay pinned to their measured IDs. A source mismatch or
   missing measurement leaves report totals unknown.
4. Call `collect_runtime_measurement(supervisor.client, image_refs=...)`. A failed
   probe returns incomplete inventory. Never replace that result with a guessed
   version or a static `runtime.json` value.
5. Populate `capability_execution_plan.admitted_control_ids` from the trusted scope,
   profile and broker admission checks, and `prerequisites_satisfied_ids` from this
   scan's frozen prerequisites. Then call `runtime_control_decisions(plan,
   profile=...)`. It checks actual Python control registration and source before
   producing one decision for every enabled registry entry. Missing lists yield
   false decisions, never implicit admission. The current producer admits only enabled
   passive implementations with a permitted GET entry, no credential prerequisite,
   and the declared scheme/transport/advisory prerequisites. Unknown active action
   shapes remain unavailable. Actual requests still require live broker admission;
   these decisions do not reserve traffic or establish assessment completion. A missing decision keeps the
   executable total unknown. Experimental entries are excluded even when their
   implementation can run.
6. Call `build_capability_snapshot(plan, scan_id=..., scope_version_id=...,
   profile=..., measurement=..., runtime_controls=...)` and persist its v2 result
   only in the trusted private plan, alongside private `capability_measurement`. Do not accept this field from operators, API
   payloads, or workers. The writer excludes all binding fields from public exports.

The report recomputes scan/scope/profile/candidate, registry, configuration, plan and
image bindings. A mismatch makes installed and executable totals unknown. A complete
per-control inventory is independently required for the executable count. Observed
scanner results remain a separate lower bound.

## Independent qualification

No current family has a qualifying independent held-out record. Keep
`qualification` empty. Future import must use an existing curator-controlled
`qualification-v2` result frozen before its run, with `partition: holdout`,
`contaminated: false`, matching candidate fingerprint, registry digest, image-binding
digest, manifest digest and private evaluator verification reference. The last two
must also be frozen independently in `capability_qualification_manifest_sha256`,
`capability_qualification_verification_ref` and
`capability_qualification_curator_ref`; absent or mismatched values leave the
family count unknown. Development fixtures and saved pilot cases cannot be promoted.

## Local verification

`tests/unit/test_runtime_capability_measurement.py` and
`tests/unit/test_report_capability_reach.py` run without a database or network. They
cover sealed probe launch, timeout behavior, malformed/stale provenance, per-control
admission, qualification mismatch, privacy and observed-result separation. These
tests validate the local contract; they do not claim the configured VM images have
already been measured. `tests/integration/test_coordinator_capability_producer.py` verifies PostgreSQL
persistence, immutable launch IDs, stale-claim removal and cancellation during the
probe. Updated VM image execution and deployed scan exports remain acceptance gates.
The 11 October deployment attempt found no reachable worker daemon; no new deployed
measurement or qualification is claimed. See `EXPANSION_ACCEPTANCE.md`.

The read-only deployed verifier `scripts/verify_runtime_capability_lab.py` accepts an
owned lab scan ID. It loads the private plan directly from the supervisor database,
checks current source/probe hashes, immutable image and measurement bindings, replays
the public projection and requires measured installed/executable totals. It cannot use
an API/worker-supplied snapshot as its authority. After a matching deployment and a
completed owned-lab scan, run under the shared live-stack lock:

```sh
PYTHONPATH=.:backend .venv/bin/python scripts/verify_runtime_capability_lab.py --scan-id <owned-lab-scan-id>
```

Its local tests reject invented counts, stale source/scan bindings, altered measurements
and private export leakage. The authenticated-browser gate now uses the same trusted
database replay when measurements exist; legacy unmeasured fixture assertions remain.
This verifier has not yet passed a deployed measurement gate.
