# Evaluation

Implementation Plan §15.4, Build Plan §7. Evaluator code and answer keys remain
outside the runtime backend package.

```
manifest.py    typed records for target build, case, lifecycle, proof, split, run, evaluation
manifests/     one file per split: development.yaml, validation.yaml, holdout.yaml
labels/        evaluator-only label data (empty in M0)
```

## Manifests and protocols

Typed records describe build, lifecycle, proof, partition and named cases. The executable
protocols feed the matcher, trusted-artifact replay and metric calculations below.

`manifests/development.yaml` contains two cases — the `labs-bad`/`labs-good` HSTS pair —
with their build, lifecycle, proof and split records filled in from what
`make labs-verify` actually observed. Validation is empty. The holdout manifest reserves
source-pinned independent cases; reservation alone establishes neither fixture health
nor scanner accuracy. See [the held-out record](../docs/HOLDOUT_BENCHMARK.md) and
[opt-in target setup](../labs/holdout/README.md). Labels are readable only in evaluator
custody and never mounted into targets or workers.

## Why this lives outside `backend/scopelens/`

Labels are an answer key. Build Plan §7 requires that ground-truth and answer-key
interfaces are never reachable by scanner workers or model context. Keeping the
evaluation code in a separate top-level package makes that a structural property rather
than a rule someone has to remember.

## Vocabularies

**Outcome** (`CaseOutcome`) distinguishes `negative_abstention` from `true_negative`. An
abstention is never a clean test — it stays in the negative-conclusive coverage
denominator. `not_measurable` exists because confirmation precision with zero
confirmations is undefined, and reporting 100% there would be a fabricated success.

**Label** (`ExpectedLabel`) applies only to the stated condition. A true weakness
elsewhere in the same application is **not** a false positive; it goes to adjudication
as an unmatched finding.

**Partition** (`Partition`) is development / validation / holdout. `Split` carries
`exposure_history` and a `contaminated` flag, and rejects a record that claims
contamination without saying which run caused it.

## Honesty defaults

Several fields default to `"not established"` rather than a plausible-looking value:
`Lifecycle.cleanup_proof`, `Proof.positive_validation`, `Proof.negative_validation`.
`RunRecord` leaves `model_cost` unset and `cost_known` false rather than recording zero,
because Implementation Plan §16 requires unknown cost to be recorded as unknown.

## Measurement stages

| Milestone | Work |
|---|---|
| M4 | Implemented matcher, independent replay, metrics and equal-budget API runner |
| M5 | Held-out fixture admission, prospective freeze, three predeclared repeats per mode, qualification and published failures; release status is in the held-out record |

Pilot targets on the declared eligible benchmark — recall ≥90%, confirmation precision
≥95%, FPR ≤5%, negative conclusive coverage ≥90% — are **targets, not achieved
results**, and no number in this repository should be read as one.

## Executable evaluator (26 September 2026)

`evaluation/run.py` matches named controls and routes, retrieves authorized evidence, checks
hashes and replays active proof predicates. An evidence ID alone never earns a true positive.
Missing positive results count as false negatives; missing negative results are abstentions.
`metrics.py` reports counts, recall, precision, FPR, negative conclusive coverage and Wilson 95%
intervals. Zero denominators stay undefined. `protocol.py` rejects duplicate measurements.

The executable matching protocol is under `protocols/`; the richer fixture/split records remain
under `manifests/`. The active development protocol has five vulnerable/fixed pairs, deliberately
marked contaminated/development because they informed implementation. They are not holdouts.

```sh
uv run python -m evaluation.run \
  --manifest evaluation/protocols/active-development.yaml \
  --reports runs/m4-verification --output runs/evaluation-active
```

Current result: five true positives, five true negatives; the release gate **fails** for sample
size, independence and split status. A perfect tiny sample is not sufficient for promotion.
Other families need registered independent evidence adjudication before receiving evaluation
credit. A release report must also establish fixture health/reset, frozen source/tool/model
versions, untouched independent scenarios and the plan's required repeated runs.

`--scope-id ID --output DIR` runs baseline then adaptive against the same immutable scope and
budgets, records both reports and fails if source changes during the pair. It is suitable for
the current stateless labs. Stateful benchmark applications require a documented independent
reset between runs; this command does not pretend to perform that reset.

## Expansion artifact evaluator

`python -m evaluation.expansion_run` provides `freeze`, `collect`, `measure`, `qualify`
and `compare` over existing scan artifacts. It adds exact role/input/task matching and
independent replay of the reviewed expanded HTTP/browser input predicates. It creates no
scan requests, independent holdouts or qualification claims. See
[the CLI contract](../docs/EXPANSION_EVALUATION_CLI.md) for private bindings, provenance,
unknown-cost handling and unsupported replay families.
