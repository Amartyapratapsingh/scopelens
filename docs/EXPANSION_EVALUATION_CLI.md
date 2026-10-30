# Offline expansion measurement CLI

`python -m evaluation.expansion_run` connects frozen evaluator inputs, authenticated
read-only scan exports, proof replay, per-family qualification and equal-budget comparison.
It never starts a scan, contacts a target or posts cases/labels to the application.

## Inputs and custody

Keep this package and its input/output files on the evaluator host, outside worker mounts
and model context. Case labels are evaluator-only. Output files are created exclusively
(no overwrite) with mode `0600` and a SHA256 envelope. Use `--expected-sha256` with a digest
recorded separately when loading a freeze, bundle or measurement. Hashes detect accidental
or unauthorized changes relative to that recorded digest; they are not remote attestation
or proof that the local custodian is independent.

Two private inputs are required:

1. `Bindings` from `evaluation/expansion_bundle.py`: a trusted selected-field export of
   immutable scan scope and input bindings. Each target records scan/scope IDs, origin,
   profile, actual candidate/fixture/scope fingerprints and budget ceilings where known,
   mode, and task/template/plan/control/method/route/role/input bindings. Authenticated
   bindings include only the identity probe criteria and expiry needed to replay identity
   facts. Login recipes, headers, baseline input values and credential references are
   rejected by this schema. An evidenced model cost may be supplied; missing cost remains
   null, including when an empty ledger could otherwise tempt an inferred zero.
2. `Protocol`: version `expansion-evaluation-protocol-v1`, partition,
   contamination status, external `curator_ref` when established, declared families and
   cases. Each case binds ID, target alias, family, scenario group, check ID, method,
   query-free route, role ID, input key and one `vulnerable`/`fixed`/`absent` label.
   Different role/input cases on one route remain distinct. Duplicate measurements cannot
   increase sample size. Every case requires an exact declared binding.

Nullable candidate fingerprints, budget ceilings and costs mean unknown, not defaults.
Do not copy today's settings into historical runs. Record a separate trusted export
reference and real UTC export time; the binding exporter owns their authenticity.

## Commands

```sh
python -m evaluation.expansion_run freeze \
  --bindings private/bindings.json --protocol private/protocol.json \
  --output private/freeze.json

python -m evaluation.expansion_run collect \
  --freeze private/freeze.json --expected-sha256 RECORDED_FREEZE_DIGEST \
  --output private/bundle.json

python -m evaluation.expansion_run measure \
  --bundle private/bundle.json --expected-sha256 RECORDED_BUNDLE_DIGEST \
  --output private/measurement.json

python -m evaluation.expansion_run qualify \
  --measurement private/measurement.json \
  --output private/qualification.json

python -m evaluation.expansion_run compare \
  --baseline private/baseline-measurement.json \
  --adaptive private/adaptive-measurement.json \
  --output private/comparison.json
```

Only `collect` accesses the network. It authenticates to `http://127.0.0.1:8090` using
locally configured operator credentials and GETs existing scan details, report JSON,
evidence metadata and evidence downloads. It cannot select another server for those
credentials, follow redirects, or create scans. Targets must already be terminal;
completed-partial scans remain measurable. Missing/untrusted/truncated/unredacted or
hash-mismatched artifacts remain explicit gaps rather than omitted cases.

`freeze` records the evaluator/proof source digest and input hashes. `collect` and
`measure` reject changes to that evaluator source. Re-freezing is allowed as a **new**
measurement; it cannot turn a past run into a prospective freeze. Qualification requires
the binding export and evaluator freeze to precede every scan's recorded start, and a
known consistent candidate fingerprint. Existing deployed artifacts collected after their
runs therefore have `frozen_before_run: false` even if the app itself was built earlier.

## Proof replay and scope

The initial replay registry covers existing reviewed expanded input controls: SQL
behavioral checks, redirect, CORS configuration, header injection, reflected/DOM XSS and
HTML rendering. It uses their current deterministic proof functions without sending new
probes. It checks complete hash-verified supervisor artifacts, exact reviewed producer,
run identity, task/template/plan/control/role/method/route/input binding, and authenticated
before/after identity facts where applicable. Browser families require browser provenance.
Duplicate competing captures, missing identity facts and malformed observations abstain.
A scanner/model/worker verdict string never supplies proof.

Findings earn true-positive credit only when exact captured facts replay successfully,
the report actually claims confirmation, and that planned task has completed with matching
evidence references. Negative completion also requires replayed pass evidence; an empty
report or a bare pass status does not count as a true negative. Missing positive cases are
false negatives; missing negative cases are abstentions. Registered proof replay is an
independent execution of the product predicate, not an independently curated fixture oracle.

Callbacks, stateful workflows, access comparisons and other families have **no automatic
replay credit in this first CLI**. In particular a redacted callback snapshot cannot
replace verification of private nonce ownership, signed receipts and closures against
trusted durable state. A future callback evaluator needs a separately authenticated replay
receipt or appropriate read-only trusted state access; this command invents neither.

## Qualification and comparison

`qualify` calls the existing per-family evaluator: recall ≥90%, precision ≥95%, FPR ≤5%,
negative conclusive coverage ≥90%, at least 30 positive/60 negative cases and three scenario
groups. Outputs include 95% intervals, denominators, reasons and every declared family,
including families with zero measured cases. Development, validation, contaminated,
post-hoc and uncurated runs cannot establish holdout qualification. This implementation
creates no holdout corpus, independent curator or qualified-family claim.

`compare` is same-candidate baseline-versus-adaptive comparison. It checks exact case
identity including scenario group, role and input; profile, candidate, scope, fixture and
evaluator fingerprints; per-target budget ceilings and actual spend. Unknown cost/runtime/
requests or an over-budget target makes the pair incomparable. Aggregate spare budget on
another target cannot conceal an overrun. Output separates extra proven true positives
from extra false positives and records request, runtime and cost differences. Three
predeclared repeats and the external fixture reset/health receipts still belong in a full
benchmark protocol; a single pair is not a statistical improvement claim.

## Local gate

`tests/unit/test_expansion_evaluation_cli.py` covers hash tampering, immutable writes,
producer/binding spoofing, missing or duplicated captures, fabricated pass/confirmation,
unsupported callback replay, browser marker facts, label-free read-only collection,
post-hoc gate failure, role/input uniqueness, scenario-group changes, unknown costs and
per-target budgets. A deployed-artifact gate additionally uses an operator-authenticated
bad/fixed lab pair and independently exported bindings. Its results must be described as
post-hoc development/validation measurements and cannot qualify a family.

### Recorded deployed-artifact gate — 28 September 2026

`runs/expansion-evaluator-gate-final/` contains the immutable freeze, authenticated API
bundle, measurement, qualification result and comparison refusal. The selected completed
HTML input tasks came from scans `a90925e4-e6fb-4e26-99f1-c80fe7126687` (bad) and
`20561172-cc36-48da-82a6-8def10e06136` (fixed). The evaluator made no target requests.

- Bad: registered browser proof replayed `confirmed`; one true positive.
- Fixed: registered browser proof replayed `pass`; one true negative.
- Independent qualification: **failed**, zero qualified families. This is one positive,
  one negative, one scenario group, post-hoc validation with no independent curator.
- Historical candidate/fixture fingerprints, ceilings and model costs absent from the
  selected trusted export remain unknown. No current configuration was substituted.
- Comparison of these baseline records was refused: no adaptive run, unknown historical
  candidate/fixture/budget provenance and unknown model cost. This checks refusal; it is
  not a completed baseline-versus-adaptive experiment.

The real collection exposed and fixed three integration issues: reopening an already
used HTTPX client, YAML parsing JSON Unicode surrogate pairs, and rejecting intake's
legitimate `clean` redaction state. The collector accepts both `clean` and `redacted`;
raw/pending, untrusted and truncated records remain ineligible. These failures and earlier
bundles remain on disk; only the final directory represents the completed gate.

Focused evidence: `runs/expansion-evaluator-tests.log` — 69 tests passed. These include
existing qualification, metric and report compatibility tests alongside the new CLI tests.
