# Opt-in held-out targets

This stack is separate from the development labs. It requires the existing private
`scopelens_labs_net`; upstream applications and their databases have only an internal
network. Gateway routes are an exact reviewed subset. Administrative, solution,
installer and comparator routes return 404 through the gateways. The evaluator seeds
WAVSEP by direct private administration before measurement.

Source revisions, licenses and base image digests are recorded in
`evaluation/holdout/source-lock.json`. Build and lifecycle commands acquire the shared
stack lock themselves. Use unique receipt/output paths; existing receipts are never
overwritten.

```sh
uv run python -m evaluation.holdout_lab build --receipt runs/holdout-benchmark/build-new.json
uv run python -m evaluation.prepare_holdout
uv run python -m evaluation.holdout_lab reset --receipt runs/holdout-benchmark/reset-new.json
uv run python -m evaluation.run_holdout --admit-only --output runs/holdout-benchmark/admission-new
uv run python -m evaluation.prepare_holdout --admission runs/holdout-benchmark/admission-new/health.json
# Include the admitted public path/input metadata in the shared frozen deployment.
uv run python -m evaluation.run_holdout --candidate-commit COMMIT_SHA --output runs/holdout-benchmark/measurement-new
```

The last command uses the frozen admitted protocol, resets before every trial and runs
three baseline and three adaptive repeats in a fixed randomized order. Both modes have
the same request/time budgets. It starts actual API scans, retrieves trusted evidence,
replays existing proof predicates and reports qualification; repeats do not increase
sample counts. Running it exposes this corpus to the scanner. Do not tune a scanner
using these cases and continue calling the inspected corpus untouched.

Before the first scanner exposure, the evaluator runs independent named-condition
health checks on every candidate. Preserve the complete candidate/admission receipts.
`evaluation.prepare_holdout --admission RECEIPT` can reserve the admitted subset without
changing labels. Failed scanner cases cannot be excluded this way after evaluation.
See `docs/HOLDOUT_BENCHMARK.md` for the measured attempt and exclusions.

Only `routes-*.json`, containing ordinary path/input documentation, is mounted in the
gateway. Labels, source answer keys, health results and reports stay under evaluator
custody outside all scanner images and target mounts. Preparation writes the evaluator
manifest, protocol and oracle with mode 0600. On a fresh checkout, run preparation as
the evaluator account before measurement. Browser health checks receive labels on
their evaluator-only stdin; no answer-key endpoint is served.

MariaDB uses tmpfs. Reset recreates only this stack's containers, replaces Tomcat's
writable layers and seeds synthetic data. No shared Docker volume is removed. SQL
cases are read-only lookup predicates; foreign redirects are observed without being
followed. Ordinary Chromium protections remain enabled. These local ARM measurements
are not production performance claims.
