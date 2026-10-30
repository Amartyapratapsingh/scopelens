# Phase 1 backend completion tracker

Operator direction, 26 September 2026: complete all Phase 1 backend work through scanning,
verification, reports and scorecards. No further UI work. Milestones are progress checkpoints.

## Implementation and lab verification

- [x] Durable baseline-first adaptive graph, bounded hypotheses and persisted outcomes.
- [x] Configurable model roles, shared cost/call reservations, schemas and approved fallback.
- [x] Five reviewed active proof implementations with real vulnerable/fixed fixture pairs.
- [x] Dedicated generated-code VM, bounded Python/Bash and lab-only proxy RPC.
- [x] Curated hash-verified skills. MCP remains optional and disabled; no remote server enabled.
- [x] Report prose adapter with deterministic template fallback.
- [x] Evaluation runner, proof replay, metrics, uncertainty and equal-budget comparison.
- [x] Encryption, retention, encrypted backup/restore and frozen deployment without source mounts.
- [x] Full owned-lab backend journey through captured findings, HTML/JSON and category scorecards.
- [x] Dedicated reviewed-worker VM, real boundary probes after reboot, full paired lab scans,
  measured real-browser cancellation and a report-producing staging pilot.

## Live provider qualification

- [x] Live Command Code qualification: GLM-5.3 text roles and GLM-5.3 Flash vision; all five synthetic role checks pass. See `MODEL_CONFIGURATION.md` and `checks_registry/model_qualification.json`.

The complete live-model lab journey is recorded in `runs/model-provider-final-lab-20260926`: generated analysis, adaptive calls, report explanations and settled call costs.

## Required qualification still incomplete

- [ ] Untouched independent held-out corpus/report meeting the declared per-family release gate.

The separate pinned holdout now reserves 485 independently health-admitted condition
cases on 322 native inputs. XSS/HTML share 163 inputs. Upstream label provenance meets
the count minimum for XSS and SQL; private and derived HTML labels receive no independent
curator credit. BenchmarkJava dominance limits implementation-diversity claims;
the per-project distribution is reported explicitly. Two baseline trials and one
adaptive trial measured the deployed `c208c00` backend with evaluator `30fef8a`;
every family gate failed. The remaining three trials are paused by the coordinator.
Saved SQL response hashes establish broker page-cap refusals for 54 FN
and 56 negative abstentions in each completed trial. These are end-to-end authority
failures, not established conditional detector accuracy. The release checkbox remains open. See
`HOLDOUT_BENCHMARK.md` for exact family denominators, exclusions and pending gates.

The separate same-corpus, harness-corrected attempt on deployed `b0b123a`, evaluated
with `ffc6fcb`, stopped during its first trial at the unchanged 1,020-second evaluator
deadline. It published no scheduled score and started no later trial. Saved cancellation
outputs yield independent XSS `15/0/66/16/83` and SQL `42/0/15/1/59` in
TP/FP/FN/TN/A− order, but are explicitly inadmissible as completed qualification.
All 110 BenchmarkJava SQL cases have captures without 403s; browser coverage is
33/176 XSS and 30/168 HTML conditions. The full browser plan needs 1,032 capture actions,
above the deployed 500-action ceiling. The gate remains open; no further attempt or
budget change was authorized by that initial attempt. The later operator-authorized extension is recorded below.

Owned-site reports exist for all three supplied sites. The final dedicated-VM staging pilot
is `4f655c2e-beed-45a0-b02c-2a1db8749807`: 39 crawled pages, zero crawler errors, 3 browser
states, 5 Low findings, coverage 17.6%; overall withheld. See `WORKER_VM.md` for the measured
ARM compatibility fix and `runs/owned-pilot-worker-vm-final-20260926` for HTML/JSON.

Earlier holdout-lane verification: clean committed evaluator `45afd99` passes 2,040
tests with no skips in 331.43 seconds on its isolated database; lint passes. Its backend
source matches the named `c208c00` candidate. That backend was verified and deployed;
the six-trial schedule is incomplete and its partial summary reports `passed=false`.
Full details and runtime artifact
paths are in `MILESTONES.md`. Overall scores are withheld where component/API coverage is
insufficient. Five active checks remain experimental. This tracker does not mark Phase 1
release complete merely because its backend implementation runs on development fixtures.

The later operator-authorized b0 attempt scored exactly six reserved trials with
the same corpus, D wall 2,700 seconds and active-browser ceiling 1,200. In schedule
order, curated XSS TP/FN is 50/31, 55/26, 55/26, 53/28, 54/27 and 53/28 out of 81
positives; SQL is 42/15, 41/16, 42/15, 42/15, 42/15 and 42/15 out of 57. No labelled
family FP was confirmed, but XSS negative coverage is only 70/99 to 75/99 and SQL
only 1/60. All five family gates fail. HTML and CORS lack independently curated
samples, and redirect lacks 28 positives, 56 negatives and one group.

`runs/holdout-benchmark/scored-b0-wall2700-scope-visibility-resume/summary-six.json`
reports complete and candidate-stable, with `passed=false` and no qualified family.
Its strict comparison also retains the approved evaluator-only change from
`874d0ff` to `617343a`, with the first three scores carried byte-identically.
The latter passed 2,379 isolated tests without skips or failures and `make lint`.
Every D scan is partial with session-expiry refusals. Docker shutdown and an API
scope-visibility race left two separate exposures unscored. The sandbox outage
left generated analysis outcome unknown on D in adaptive repeat 3 and all four
targets in adaptive repeat 2. `final-report.md`, reach records and integrity receipts
retain intervals, abstentions, failure examples and these limitations. The six-score
measurement is finished; a passing release report remains unmet. The checkbox stays
open and all five controls remain experimental.
