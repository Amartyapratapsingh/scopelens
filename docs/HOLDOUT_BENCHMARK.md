# Held-out benchmark

Status, 12 October 2026: **six reserved trials are scored; the release gate failed.**
The time-extended, harness-corrected run measured frozen backend `b0b123a`.
Every family fails qualification in every scored trial. The strict aggregate is
complete with a stable candidate, but also flags the evaluator-only setup change
between scores 3 and 4. All five controls remain experimental. The final results
and limitations are in "Six completed scores" below.

The initial deployed `c208c00` attempt remains paused at its third-trial boundary.
Two baseline trials and one adaptive trial are preserved without rewriting or pooling.
The coordinator paused that attempt after authority failures were established.
This corpus was frozen before its first scanner exposure on 11 October 2026.
The operator classified trials 1–3 as **"probes blocked by our harness/authority;
not a detection measurement"** and authorized a separate six-trial rerun after the
fix is deployed and verified. That rerun must retain this frozen corpus and labels.
The paused attempt is retained separately from every later attempt.

The original scheduler ended after trial 3 with the operator's pause reason, recorded
in `scored-c208-30fef8a/scheduler-ended.json`. Trials 4–6 did not start. The fresh
attempt will use a fixed 60-second gap after each completed trial except the last.
The scheduler waits outside the trial's lock and saves observed intervening lock
tokens in separate gap receipts. It stops on a trial error or interruption rather
than automatically advancing. This scheduling change affects neither the frozen
case list nor the six-trial order.

## Corpus and custody

The opt-in `labs/holdout.compose.yml` uses four implementation groups, kept entirely
in holdout: OWASP VulnerableApp, ZAP-maintained WAVSEP, OWASP BenchmarkJava 1.2 and an
independently authored private fixture. Source pins are:

| Group | Revision |
|---|---|
| VulnerableApp | `c49b26270e0b7e5543288b61fc3726ebaca3d9a0` |
| WAVSEP | `f9cfbe8c6edfc7f8c631b800cd57a18992e2c24e` |
| BenchmarkJava 1.2 | `8b67a88d73b2594570fc21150705283de884620b` |
| Private fixture | `64ea3045a0ba31de075d2b0c2ead856078283029`, file digest in the oracle |

`evaluation/holdout/source-lock.json` records licenses and immutable image digests.
Build/reset utilities use disposable seeded databases and recreate only this stack's
containers. No shared volumes are deleted. Targets have an internal upstream network;
the broker reaches only exact opaque gateway routes. Installer, comparator, solution
and answer-key paths are blocked. Ordinary Chromium protections remain enabled.

The runtime receives only ordinary path/input approvals in the conditional pack and
gateway route maps. Native test names are replaced with opaque paths and a generic
input key. Titles, technology banners, cookies with native paths, error stack traces
and native redirect destinations are removed or rewritten. Foreign redirect results
remain observable and are never followed. The gateway tests preserve the input sink
while checking metadata redaction and answer-key rejection.

Labels, source answer files, manifests, admission receipts and results live only in
the evaluator package/host custody, outside worker images and target mounts. Preparation
sets evaluator files to mode 0600. Health labels enter the evaluator container only on
stdin; no broker-reachable answer-key API exists. Public upstream benchmarks may already
occur in model training; the private implementation supplies additional unfamiliar
behavior but has no independent upstream curator credit.

## Admission and independent labels

An initial 300-case reserve admitted 260 cases. Before any scanner exposure, the
reserve expanded to all deduplicated native query/GET BenchmarkJava functions that
exclude SQL writes and procedure calls. Normalization removes test class/path identifiers,
comments and whitespace before duplicate rejection. Renamed URLs and repeated scans
never increase sample size.

The expanded reserve contains 614 control cases on 387 native target inputs. The same
predeclared independent health probes admitted **485 cases on 322 inputs** and excluded
129 cases whose selected condition was not demonstrated. Those exclusions are not
scanner false negatives, negative relabels or claims that all upstream weaknesses are
absent. The oracle is limited to the named script/markup, read-only boolean lookup,
foreign redirect and credentialed origin-reflection conditions and its declared inputs.
All 614 baseline responses passed metadata isolation; 40 forbidden/admin route probes
returned 404. Complete decisions are in `evaluation/holdout/admission.json` and
`runs/holdout-benchmark/admission-04/health.json`.

The admitted oracle, protocol, rich manifest and admission receipt are byte-identical
to pre-exposure commit `a217236b`. Their SHA-256 values and reserved denominators are
committed in `evaluation/holdout/reserve-freeze.json`, with a copy under
`runs/holdout-benchmark/`. The runtime does not receive this receipt. Each scored trial
also fingerprints the same case list before scanning.

| Family | Admitted positive / negative | Implementation groups | Upstream-labelled qualification positive / negative / groups |
|---|---:|---:|---:|
| Reflected XSS | 82 / 100 | 4 | 81 / 99 / 3 |
| HTML injection | 74 / 100 | 4 | 0 / 0 / 0 |
| Non-timing SQL behavior | 58 / 61 | 4 | 57 / 60 / 3 |
| Open redirect | 3 / 5 | 3 | 2 / 4 / 2 |
| CORS configuration | 1 / 1 | 1 | 0 / 0 / 0 |

For qualification, curator references identify pinned upstream label artifacts and
their SHA-256: Benchmark's expected-results CSV, WAVSEP's labelled case classes and
VulnerableApp's attack-vector/secure-variant source annotations. The evaluator lane
is not an independent curator. Private labels and HTML labels derived from XSS cases
have no curator credit and appear only in supplemental condition measurements.

XSS and HTML share **163 admitted target/input implementations**. Family metrics are
separate; their overlap must not be represented as additional independent inputs or
pooled independent accuracy. Admitted positive/negative counts by project are:

| Family | VulnerableApp | WAVSEP | BenchmarkJava | Private (supplemental) |
|---|---:|---:|---:|---:|
| XSS | 0 / 2 | 1 / 1 | 80 / 96 | 1 / 1 |
| HTML injection | 0 / 2 | 1 / 1 | 72 / 96 | 1 / 1 |
| SQL behavior | 2 / 3 | 1 / 1 | 54 / 56 | 1 / 1 |
| Redirect | 1 / 3 | 1 / 1 | 0 / 0 | 1 / 1 |
| CORS | 0 / 0 | 0 / 0 | 0 / 0 | 1 / 1 |

All HTML counts are supplemental. BenchmarkJava supplies **176/180 (97.8%)** of the
upstream-curated XSS cases and **110/117 (94.0%)** of the SQL cases. The plan declares
30/60/3 but no minimum share per group or maximum dominant-project share. The evaluator's
numerical count predicate is met for XSS and SQL; this heavily concentrated sample does
not establish broad independence across three comparably represented implementations.
Project-ID counts must not be read as a balanced diversity claim. HTML needs 30/60/3 independently
curated cases, redirect needs 28 positive, 56 negative and one further independently
curated group, and CORS needs 30/60/3 independently curated cases.
XSS positives come from two upstream projects; VulnerableApp contributes only
negative XSS cases. HTML is largely shared with XSS and does not supply an independent
HTML qualification population. Case-level Wilson intervals do not model dependence
between implementations that share source templates.

## Measurement protocol and current evidence

`evaluation/run_holdout.py` creates real deployed API scopes/scans, exports HTML/JSON,
retrieves hash-checked trusted captures and replays the existing registered proof
predicates. It records a named commit, release/source/image/model/fixture/evaluator
fingerprints before execution and invalidates changed candidates. Each trial resets
and independently verifies all admitted fixtures before scanner access. Scored trials
and fixture lifecycle commands acquire the shared lock exclusively through
`/tmp/scopelens-with-lock.sh`; the evaluator validates its ownership token and never
creates or removes that lock. The helper releases the lock between scored trials.
Baseline and adaptive modes receive identical tools and request/time ceilings (5,000 requests,
900 seconds, 20 requests/second, two requests in flight per target scope).

Random seed `20261011` freezes trial order: baseline repeat 1, baseline repeat 3,
adaptive repeat 1, adaptive repeat 3, baseline repeat 2, adaptive repeat 2. Repeats do
not add cases. Positive misses, blocks and inconclusive captures count as FN; negative
abstentions remain A−. Conclusive negatives require trusted producer capture and
registered predicate replay. Zero-denominator precision/FPR are not measurable.
Unmatched findings are retained separately as unresolved, not automatic false positives.

The initial deployed attempt measures backend commit
`c208c009e01a45df4abbb8bb7bb6f2259492d30b` using evaluator commit
`30fef8a6f10ee471098378cbb0baf2f1e374cc12`. Evaluator source is outside runtime images.
Its isolated worktree overlays exactly that backend's runtime paths; tracked source
fingerprint `2b24ad9a4ba7e4101ecebd84037b8bb25bfc15488eb0ac392ef98073d7250ef5`
and vendor-inclusive release fingerprint
`7656679bfe4fa705497d56be3c4fd47315fe19f0e67c09fbab9b87010e85d5b7`
are separately checked. The deployed receipt is `runs/release/grouped-commit.json`.
Saved reports are under `runs/holdout-benchmark/scored-c208-30fef8a/`.
All three completed trials report `candidate_changed=false` and fail every family gate.
`summary-initial-three.json` explicitly reports `complete=false`, `passed=false` and
three missing trials; the earlier two-trial snapshot is retained. No repeat is pooled
into a larger denominator.

These are **end-to-end pipeline results, not established conditional detector
accuracy**. The frozen broker charges changed-query probes to the 300-page crawl
ledger. The saved SQL HTTP403 body hash
`b7aba4755e2db8e313f1cbfe4b4f49833ee429db4846edd99d0123ddac4f8076`
exactly matches its JSON denial body: `scope_denied`, `budget_exhausted`,
`shared page cap reached`. In each of the three completed trials, 1,782 such captured
responses affect 110 independently curated SQL cases: **54 FN and 56 negative
abstentions**. The gateway's upstream-error body has a different hash, excluding
upstream rejection for these matched responses. Four further SQL misses are
VulnerableApp cases and are not included in this attribution: `holdout-007-sql`
(FN, retained HTTP200/500), `holdout-008-sql` (A−, HTTP200/500),
`holdout-009-sql` (A−, HTTP200/400), and `holdout-010-sql`
(A−, HTTP200/404/500). All have inconclusive proof replay in each completed trial.

The exception denial path loses `scan_id`, so the persisted audit snapshot contains
850 allowed requests and zero denial rows despite those proven refusals. Audit paths
include query values: `holdout-037-xss` has two admitted requests, both the baseline
`input=hello`; its nonce probes have no matching admissions. Its saved browser403
captures omit response body hashes, so their individual denial source remains
unresolved. Shared HTTP status alone is not used to infer broker origin.

The read-only analysis utilities `evaluation.analyze_holdout_reach` and
`evaluation.analyze_holdout_denials` consume saved trusted capture references only.
They do not request targets, change proof predicates, rescore cases or modify the
frozen runner. Analysis commit `8a2829c` adds the exact-body attribution; nine
focused reach/attribution tests pass. Per-family stages, redacted examples, source
hashes and denial counts are retained in `scored-c208-30fef8a/reach-analysis/`.
No remaining trial will start without the coordinator's new handoff. A later attempt
after harness fixes must have its own candidate/protocol receipt; this exposed corpus
must not be described as a new untouched set.

### Completed initial trials

Counts below use only upstream-curated qualification cases. A− is a negative
abstention. HTML and CORS have zero independent cases and no measurable rates.

| Trial | Family | TP | FP | FN | TN | A− | Recall | Precision | FPR | Negative coverage |
|---|---|---:|---:|---:|---:|---:|---|---|---|---|
| repeat-1-baseline | xss | 0 | 0 | 81 | 2 | 97 | 0/81 [0.00–4.53%] | undefined (0/0) | 0/2 [0.00–65.76%] | 2/99 [0.56–7.07%] |
| repeat-1-baseline | html | 0 | 0 | 0 | 0 | 0 | undefined (0/0) | undefined (0/0) | undefined (0/0) | undefined (0/0) |
| repeat-1-baseline | sql | 2 | 0 | 55 | 1 | 59 | 2/57 [0.97–11.92%] | 2/2 [34.24–100.00%] | 0/1 [0.00–79.35%] | 1/60 [0.29–8.86%] |
| repeat-1-baseline | redirect | 2 | 0 | 0 | 2 | 2 | 2/2 [34.24–100.00%] | 2/2 [34.24–100.00%] | 0/2 [0.00–65.76%] | 2/4 [15.00–85.00%] |
| repeat-1-baseline | cors | 0 | 0 | 0 | 0 | 0 | undefined (0/0) | undefined (0/0) | undefined (0/0) | undefined (0/0) |
| repeat-3-baseline | xss | 1 | 0 | 80 | 3 | 96 | 1/81 [0.22–6.67%] | 1/1 [20.65–100.00%] | 0/3 [0.00–56.15%] | 3/99 [1.04–8.53%] |
| repeat-3-baseline | html | 0 | 0 | 0 | 0 | 0 | undefined (0/0) | undefined (0/0) | undefined (0/0) | undefined (0/0) |
| repeat-3-baseline | sql | 2 | 0 | 55 | 1 | 59 | 2/57 [0.97–11.92%] | 2/2 [34.24–100.00%] | 0/1 [0.00–79.35%] | 1/60 [0.29–8.86%] |
| repeat-3-baseline | redirect | 2 | 0 | 0 | 2 | 2 | 2/2 [34.24–100.00%] | 2/2 [34.24–100.00%] | 0/2 [0.00–65.76%] | 2/4 [15.00–85.00%] |
| repeat-3-baseline | cors | 0 | 0 | 0 | 0 | 0 | undefined (0/0) | undefined (0/0) | undefined (0/0) | undefined (0/0) |
| repeat-1-adaptive | xss | 1 | 0 | 80 | 1 | 98 | 1/81 [0.22–6.67%] | 1/1 [20.65–100.00%] | 0/1 [0.00–79.35%] | 1/99 [0.18–5.50%] |
| repeat-1-adaptive | html | 0 | 0 | 0 | 0 | 0 | undefined (0/0) | undefined (0/0) | undefined (0/0) | undefined (0/0) |
| repeat-1-adaptive | sql | 2 | 0 | 55 | 1 | 59 | 2/57 [0.97–11.92%] | 2/2 [34.24–100.00%] | 0/1 [0.00–79.35%] | 1/60 [0.29–8.86%] |
| repeat-1-adaptive | redirect | 2 | 0 | 0 | 2 | 2 | 2/2 [34.24–100.00%] | 2/2 [34.24–100.00%] | 0/2 [0.00–65.76%] | 2/4 [15.00–85.00%] |
| repeat-1-adaptive | cors | 0 | 0 | 0 | 0 | 0 | undefined (0/0) | undefined (0/0) | undefined (0/0) | undefined (0/0) |

Brackets give Wilson 95% intervals. Zero observed FPs with one to three conclusive
negatives do not establish a low population FPR. The gate uses the declared recall
≥90%, precision ≥95%, FPR ≤5% and negative conclusive coverage ≥90% thresholds.

The following counts include private and derived labels as supplemental conditions;
they cannot replace missing independent qualification cases. Full metric intervals
and individual failures remain in each saved `result.json`.

| Trial | Family | TP | FP | FN | TN | A− |
|---|---|---:|---:|---:|---:|---:|
| repeat-1-baseline | xss | 1 | 0 | 81 | 3 | 97 |
| repeat-1-baseline | html | 1 | 0 | 73 | 3 | 97 |
| repeat-1-baseline | sql | 3 | 0 | 55 | 2 | 59 |
| repeat-1-baseline | redirect | 3 | 0 | 0 | 3 | 2 |
| repeat-1-baseline | cors | 1 | 0 | 0 | 1 | 0 |
| repeat-3-baseline | xss | 2 | 0 | 80 | 4 | 96 |
| repeat-3-baseline | html | 2 | 0 | 72 | 4 | 96 |
| repeat-3-baseline | sql | 3 | 0 | 55 | 2 | 59 |
| repeat-3-baseline | redirect | 3 | 0 | 0 | 3 | 2 |
| repeat-3-baseline | cors | 1 | 0 | 0 | 1 | 0 |
| repeat-1-adaptive | xss | 1 | 0 | 81 | 1 | 99 |
| repeat-1-adaptive | html | 1 | 0 | 73 | 1 | 99 |
| repeat-1-adaptive | sql | 3 | 0 | 55 | 2 | 59 |
| repeat-1-adaptive | redirect | 3 | 0 | 0 | 3 | 2 |
| repeat-1-adaptive | cors | 1 | 0 | 0 | 1 | 0 |

### Execution ceilings and observed work

The same ceilings applied to all three trials. Saved terminal counters describe
admitted requests, not all attempted or refused probes. Scan durations exclude fixture
reset and oracle health. Model-call cost is absent from the terminal API, so equal-cost
effectiveness is unmeasured. This incomplete, authority-blocked attempt does not
establish a causal adaptive-versus-baseline improvement.

| Trial | Gateway / group | Status | Scan seconds | Admitted requests | Page ledger |
|---|---|---|---:|---:|---:|
| repeat-1-baseline | labs-holdout-a / VulnerableApp | completed | 123.44 | 162 | 115 |
| repeat-1-baseline | labs-holdout-b / WAVSEP | completed_partial | 79.97 | 76 | 54 |
| repeat-1-baseline | labs-holdout-c / Private | completed | 90.64 | 100 | 70 |
| repeat-1-baseline | labs-holdout-d / BenchmarkJava | completed | 503.14 | 512 | 300 |
| repeat-3-baseline | labs-holdout-a / VulnerableApp | completed | 138.07 | 162 | 115 |
| repeat-3-baseline | labs-holdout-b / WAVSEP | completed | 89.51 | 88 | 66 |
| repeat-3-baseline | labs-holdout-c / Private | completed | 98.93 | 100 | 70 |
| repeat-3-baseline | labs-holdout-d / BenchmarkJava | completed | 531.55 | 512 | 300 |
| repeat-1-adaptive | labs-holdout-a / VulnerableApp | completed_partial | 165.66 | 150 | 103 |
| repeat-1-adaptive | labs-holdout-b / WAVSEP | completed | 173.57 | 93 | 66 |
| repeat-1-adaptive | labs-holdout-c / Private | completed_partial | 221.96 | 94 | 58 |
| repeat-1-adaptive | labs-holdout-d / BenchmarkJava | completed | 721.67 | 513 | 300 |

`completed` is a lifecycle state, not proof that every input was exercised. The
three BenchmarkJava scans exhausted the 300-page ledger, despite the separate 5,000
request ceiling. Partial browser tasks retain missing-capture abstentions.

### Reach stages in saved initial outputs

| Trial | Family | FN: blocked/error | FN: unresolved | A−: blocked/error | A−: unresolved |
|---|---|---:|---:|---:|---:|
| repeat-1-baseline | xss | 80 | 1 | 96 | 1 |
| repeat-1-baseline | html | 0 | 0 | 0 | 0 |
| repeat-1-baseline | sql | 55 | 0 | 59 | 0 |
| repeat-1-baseline | redirect | 0 | 0 | 2 | 0 |
| repeat-1-baseline | cors | 0 | 0 | 0 | 0 |
| repeat-3-baseline | xss | 80 | 0 | 96 | 0 |
| repeat-3-baseline | html | 0 | 0 | 0 | 0 |
| repeat-3-baseline | sql | 55 | 0 | 59 | 0 |
| repeat-3-baseline | redirect | 0 | 0 | 2 | 0 |
| repeat-3-baseline | cors | 0 | 0 | 0 | 0 |
| repeat-1-adaptive | xss | 80 | 0 | 96 | 2 |
| repeat-1-adaptive | html | 0 | 0 | 0 | 0 |
| repeat-1-adaptive | sql | 55 | 0 | 59 | 0 |
| repeat-1-adaptive | redirect | 0 | 0 | 2 | 0 |
| repeat-1-adaptive | cors | 0 | 0 | 0 | 0 |

`schedule-pause.json` records the stopped outer scheduler and unstarted trials.
The next interleaved job held token `scan-completeness pid=59711
since=2026-10-11T14:04:00Z`; it started after trial 3 released the lock.

For independently curated misses in these trials, stages (a) never discovered,
(b) discovered without a planned/dispatched probe, and (d) response ran without
confirmation each have zero cases. Stage (c) means a retained attested capture
reported an error/HTTP refusal; it does not itself identify the source. Trial 1 has
460 blocked/error misses and four unresolved misses across all labelled conditions.
Its WAVSEP browser task timed out after planning probes, leaving missing attested
captures; those are unresolved rather than assumed never tested. Representative
stage (c) examples are the SQL case `holdout-034-sql` with a proven page-cap response
hash and `holdout-037-xss` with HTTP403 but no body hash. There are no examples for empty
stages. The analysis JSON supplies bounded examples and every case/evidence reference.

### Post-score authority attribution

The coordinator attested the cause from a separate read-only diagnosis at
`runs/discovery-auth/holdout-d-403-diagnosis.json`, SHA-256
`e71de95ba14ca35f6bde847ab900f7a8b02bcc19f3787198fd8a1a8cba14330c`. Its two baseline snapshots show the exact
page-cap denial body and a second failure: browser action 41 is denied for
`action_budget`, but the collector advances its local sequence before admission.
The next 334 attempted actions are then denied for `action_order_or_inflight`.
Forty actions were admitted. This is a transport/authority failure before navigation.

A saved read-only audit snapshot for adaptive trial 1 confirms the same 40/1/334
admission/denial counts, in
`repeat-1-adaptive/browser-authority-attribution.json`. Every completed BenchmarkJava
trial retains 171 XSS and 164 HTML `ActionDenied` series with no navigation captures.
Those series belong in reach stage(c), with this attested browser-authority cause;
they are artifact counts, not additional independently labelled cases. Early browser
series with HTTP403 remain separate from these pre-navigation failures. Their missing
body hashes prevent an individual exact-body attribution, although the diagnosis
identifies the exhausted page ledger as the run-level cause.

The original scores, captures and freeze files are unchanged. This addendum explains
the saved misses and supplies provenance; it does not turn them into successful tests.
The unchanged 40-action cap remains an admission limit, independent of the sequence
repair, and actual admission coverage must be measured in the corrected rerun.

Pre-scan evidence and attempts under `runs/holdout-benchmark/`:

- `build-receipt.json`, `build.log`, `wavsep-build.log`, `benchmarkjava-build.log`: source builds and compiled artifact provenance.
- `candidate-v1/`, `admission-01/`, `admission-02/`: original reserve and complete 300-case admission attempts.
- `candidate-v2/`, `admission-03/`, `admission-04/`: expanded reserve and complete 614-case health/metadata checks; final admission is version 04.
- `admission-00/interruption.json`: invalidated interrupted oracle attempt after shared lock ownership changed; no scanner exposure.
- `admission-00/lock-incident-addendum.json`: coordinator-reported overlap with an offline, network-free resource experiment during that invalidated attempt. The reported start was around 11:37; timezone and end were not established. Conflicting corrections are retained, and this attempt contributes no accepted evidence.
- `admission-diagnostic-01/`: evaluator callback failure before case admission; corrected evaluator only.
- `admission-diagnostic-02/`: corrected 32-case diagnostic, 30 admitted.
- `gateway-refresh-02/`, `admission-04/gateway-refresh.json`: short locked gateway recreation receipts.
- `full-suite-clean.log`: 1,962 passed, no skips, 366.19 seconds on `scopelens_test_holdout_benchmark`.
- `full-suite-evaluator-final.log` and `.json`: latest clean committed evaluator `45afd99`, 2,040 passed with no skips in 331.43 seconds on the same isolated database. Environment and pinned vendor dependencies were linked into the clean source archive.
- `full-suite-summary-commit.log` and `.json`: earlier clean `9c11d61` archive, 2,036 passed and one missing-vendor-binary setup failure; the corrected full rerun above passes.
- `full-suite-final.log`: earlier 1,954 passed / one process-startup timing failure; the failing test passed alone. Latest full run is green.
- `lint-final.log`: initial `make lint` passed. Latest `make lint` also passes. All 13 custody, producer, lock and summary tests pass and are covered by the clean full suite.

The later offline analysis checkout uses evaluator `8a2829c` with the exact
`c208c00` runtime, compatible tests from `45afd99`, the holdout analysis tests and
fixture contracts from `5be330b`. Its full suite passed **2,053 tests with no skips
in 348.85 seconds**, on `scopelens_test_holdout_benchmark`, and `make lint` passed.
Assembly and command receipts are `report-checkout-8a-c208-corrected.json` and
`full-suite-report-8a-c208-corrected.json`, with the corresponding log. Another
lane's full suite started during this run; the observed overlap is recorded in
`full-suite-report-8a-c208-corrected-overlap.json`.

The preceding assembly mixed in later GOST tests while retaining the older c208
runtime. It recorded 2,052 passes and two missing-GOST-key failures, preserved in
`full-suite-report-8a-c208.log` and `.json`. Correcting the test snapshot changed
neither production code nor assertions. The new inter-trial scheduler subsequently
passed its five interruption, failure, handoff and lock-scope tests, alongside all
eleven candidate-pin and offline reach/denial tests.

The checkbox in `COMPLETION.md` remains unchecked. All five controls remain experimental.

## Same independent corpus, harness-corrected rerun

The operator authorized a separate complete six-trial attempt after the authority
failures above. The deployed backend is
`b0b123add84182fb8ec9327ec9951e98711d7d8c`, built from
`/tmp/scopelens-grouped-b0b123a`. The evaluator is
`ffc6fcbae69208dd59a1ea935f7c9cc83d7212ca`, with runtime paths restored exactly
from the deployment commit in `/tmp/scopelens-holdout-rerun-ffc6fcb`. Its tracked
runtime diff against that commit is empty. The vendor-inclusive source fingerprint
is `0b0a3f045f967d29e74d4330fc9edb24be187a0b338a25394e2041ae88169dcb`;
the tracked-only fingerprint is
`fa380956d16b6b6965edf412b16853ff3a240fd763a71e685515564ae63b1174`.
Both match the reviewed release. Worker isolation, egress denial, cancellation,
sandbox/RPC checks and readiness at schema 0009 were verified before authorization.

This is a repeated exposure to the same corpus, following fixes found by inspecting
held-out outputs. It is not an untouched first exposure. Cases, labels, admission
exclusions, implementation groups and all four frozen corpus hashes are unchanged.
The initial c208 scores, exports, captures, health and freeze files are preserved;
their pre-rerun hashes are in `rerun-b0-ffc6fcb-preflight/initial-attempt-integrity.json`.

The coordinator reviewed these changes as transport/authority repairs, without
detector, payload, proof or threshold tuning:

| Fix | Change |
|---|---|
| `2589ba8` | Reviewed probe requests use bounded task accounting rather than the crawl page ledger; action sequence advances only on admission; denials retain audit/logging context. |
| `1b87168`, `12c8b7a` | Approved scope concurrency/rates use separate hard ceilings and bounded proxy capacity. |
| `ac0f922` | Reviewed browser actions use task budgets and a 500-action scan ceiling, while exploration accounting remains separate. |
| `b0b123a` | Approved rate increases are audited at scan admission. |

Patch files, source-review receipts, the complete runtime diff since c208 and the
handoff provenance are saved under `rerun-b0-ffc6fcb-preflight/`. A limited independent
AST comparison confirms unchanged SQL probe generation, proof/evaluation functions
and browser marker value expressions. Collector file bytes change because they now
attach the reviewed authority reference. The deployment also includes the GOST pin,
Chromium capability-probe fix and ZAP-active implementation; its approved-rules
allowlist is empty, so ZAP active remains inert.

The fresh evidence root is `scored-b0-ffc6fcb/`. The same seed and reserved six-trial
order run with a fixed 60-second gap outside each trial's shared stack lock. Admission
coverage is measured from saved captures and read-only terminal audit/ledger snapshots.
The first trial's admission audit records an effective 10 requests/second for the
requested 20; requested rates are not reported as applied rates. Missing captures,
timeouts and budget denials retain their failed/abstaining outcomes. No runtime or
corpus adjustment is made in response to this attempt's results.

The attempt stopped during `repeat-1-baseline`. BenchmarkJava scan
`6103dd24-8a39-4f56-9a51-c9df398960c4` began at 15:26:27 UTC and remained running
at the unchanged 1,020-second evaluator deadline. The evaluator requested cancellation
and exited 1. The API terminal reason says "cancelled by the operator"; the actor in
this attempt was the evaluator deadline handler. No later trial started and no normal
trial `result.json` was published. `schedule-failure.json` records the stop;
`summary-incomplete.json` reports zero scored trials, six missing score files,
`complete=false` and `passed=false`.

VulnerableApp and the private fixture scans completed. WAVSEP completed partially
because browser exploration timed out. BenchmarkJava is cancelled. All four terminal
JSON/HTML exports and trusted capture records were collected after cancellation,
through the shared lock helper, without creating another scan or target request.
The helper released the lock. Any further attempt needs a separate coordinator decision.

### Saved cancellation outputs

The following numbers come from the unchanged evaluator's `measure()` function applied
to those saved terminal outputs. They describe an incomplete scan and are not an
admissible completed trial or release qualification. The explicitly named
`repeat-1-baseline/timeout-followup/post-cancellation-assessment.json` carries
`trial_complete=false`, `release_qualification_admissible=false` and
`candidate_changed=false`. It does not replace the missing scheduled score file.

| Upstream-curated family | Positive / negative / groups | TP | FP | FN | TN | Negative abstentions |
|---|---:|---:|---:|---:|---:|---:|
| Reflected XSS | 81 / 99 / 3 | 15 | 0 | 66 | 16 | 83 |
| HTML injection | 0 / 0 / 0 | 0 | 0 | 0 | 0 | 0 |
| Non-timing SQL behaviour | 57 / 60 / 3 | 42 | 0 | 15 | 1 | 59 |
| Open redirect | 2 / 4 / 2 | 2 | 0 | 0 | 2 | 2 |
| CORS configuration | 0 / 0 / 0 | 0 | 0 | 0 | 0 | 0 |

The evaluator includes positive abstentions in FN. FPR uses conclusive negative
outcomes as its denominator; abstaining negatives are reported separately and reduce
negative conclusive coverage. All intervals below are Wilson 95% intervals.

| Family | Recall | Confirmation precision | FPR | Negative conclusive coverage |
|---|---|---|---|---|
| XSS | 15/81 = 18.52%, 11.56–28.33% | 15/15 = 100%, 79.61–100% | 0/16 = 0%, 0–19.36% | 16/99 = 16.16%, 10.20–24.65% |
| SQL | 42/57 = 73.68%, 61.02–83.35% | 42/42 = 100%, 91.62–100% | 0/1 = 0%, 0–79.35% | 1/60 = 1.67%, 0.29–8.86% |
| Redirect | 2/2 = 100%, 34.24–100% | 2/2 = 100%, 34.24–100% | 0/2 = 0%, 0–65.76% | 2/4 = 50%, 15.00–85.00% |

HTML and CORS have no upstream-curated denominator or interval. The full labelled
populations, including supplemental cases, give TP/FP/FN/TN/A− counts of
XSS `16/0/66/17/83`, HTML `16/0/58/17/83`, SQL `43/0/15/2/59`,
redirect `3/0/0/3/2` and CORS `1/0/0/1/0`. Supplemental outcomes never supply
independent curator credit. Their intervals and every case verdict are retained in
the assessment JSON. XSS/SQL fail recall and negative conclusive coverage even in this
partial derivation. Redirect remains short by 28 positives, 56 negatives and one group;
HTML and CORS are each short by 30 positives, 60 negatives and three curated groups.
No family qualifies.

### Admission and reach

The terminal BenchmarkJava audit records 2,483 allowed broker requests, two ordinary
crawl budget denials, 202 allowed browser actions and no browser admission denials.
Of those browser actions, 189 are reviewed active captures and 13 are exploration.
All 110 SQL conditions have retained response captures, with zero HTTP 403s.
XSS has admitted captures for 33 of 176 planned conditions, using 99 actions;
HTML has captures for 30 of 168, using 90 actions. Each browser family has three cases
with capture errors. No retained named active capture in these families has HTTP 403.
These are measured admission counts, not assumed coverage after a source fix.

The requested 900-second scope wall budget and the evaluator's 1,020-second terminal
wait are separate limits. The recorded stop was evaluator cancellation. This report
does not infer a per-request wall-budget denial or claim measured throughput of ten
requests per second from the configured ceiling.

A separate prospective bound remains. The frozen BenchmarkJava plan contains 344
XSS/HTML condition series, and the unchanged collector requests three browser captures
per series. Completing every series would require 1,032 reviewed actions, exceeding
the deployed 500-action scan ceiling. The cancelled scan stopped at 189 reviewed
actions, so that ceiling was not the observed cancellation cause. Increasing time
alone would still leave this full-plan admission bound. Source and count provenance
are in `timeout-followup/browser-cap-bound.json`. No cap, case, detector or proof
change was made in response.

The saved reach analyzer records every FN and negative abstention below. Stages are
(a) undiscovered input, (b) discovered without a planned probe, (c) retained blocked or
error capture, and (d) retained response without accepted confirmation. A planned
probe with no attested dispatch capture remains unresolved; it is not automatically
classified as never dispatched. Counts are independent curated cases.

| Family / verdict | a | b | c | d | Unresolved |
|---|---:|---:|---:|---:|---:|
| XSS FN | 0 | 0 | 1 | 4 | 61 |
| XSS A− | 0 | 0 | 2 | 0 | 81 |
| SQL FN | 0 | 0 | 1 | 14 | 0 |
| SQL A− | 0 | 0 | 3 | 56 | 0 |
| Redirect A− | 0 | 0 | 2 | 0 | 0 |

Other independent family/verdict rows are zero. Supplemental HTML has FN
`c=2, unresolved=56` and A− `c=1, unresolved=82`. Full records and redacted examples
are in `timeout-followup/reach-analysis.json`. Examples include VulnerableApp
`holdout-007-sql`, `008-sql` and `009-sql` at stage c with retained 500/400 responses;
BenchmarkJava `holdout-035-sql`, `047-xss` and `063-xss` at stage d with HTTP 200;
and WAVSEP `holdout-016-xss`, `017-html` and `018-xss` unresolved after planning.
The XSS examples at stage d have false proof decisions. The SQL example has no
accepted report confirmation. Error status alone does not identify its origin.

`timeout-followup/authority-analysis.json` comes from read-only terminal database
snapshots and producer-hash-verified saved captures. Its limitations keep audit
reference gaps explicit. The earlier `predeadline-authority.json` is a live snapshot,
not the terminal total. `timeout-followup/collection.json` attests the post-cancellation
export collection. A second integrity check confirms all 33 preserved original c208
score/export/capture/health/freeze files and all four frozen corpus hashes are unchanged,
in `original-attempt-integrity-after-cancellation.json`.

Another lane's host Chromium full suites overlapped this attempt. Workers ran in the
VM, but fixture gateways and the database shared host resources. The overlap prevents
a claim of an isolated resource window; it does not establish the cause of the timeout.
Conservative suite windows were 15:17:39–15:24:28 UTC for `6812c13` and
15:31:13–15:39:08 UTC for `cc6f202`, derived from suite-log creation and later
qualification receipts. Exact process end times were not logged. Redacted-log mtimes
are postprocessing times and are not used as pytest completion times. That lane also
reported earlier focused regressions, 102 tests in 93.25 seconds, and baseline replays
of 4.53 and 5.54 seconds. Their individual start/end windows were not established,
so this report does not assign each an overlap interval. Source receipt/log hashes,
conservative bounds and the ancillary-work addendum are in
`scored-b0-ffc6fcb/resource-overlap.json`. This lane ran no host full suite during the
benchmark and kept all scan limits fixed.

The release checkbox remains unchecked and all five controls remain experimental.
The original c208 failure report is preserved. This second attempt is incomplete,
with an unscored cancellation, and cannot close the release gate.

## Authorized time-extended attempt

The operator authorized another complete six-trial attempt of the same frozen corpus
after the aborted 1,020-second attempt. Evaluator change `874d0ff` extends only
BenchmarkJava's submitted scope wall budget from 900 to 2,700 seconds. Its runner
wait is derived from the submitted budget plus 120 seconds, giving 2,820 seconds.
The other three targets retain 900-second scopes and 1,020-second waits. All targets
retain 5,000 requests, 20 requested requests/second and two requested concurrent
requests. System ceilings still apply. Terminal partial scans are scored with their
misses and abstentions. No detector, case, label, trial order or proof rule changes.

Each registration saves its previous and submitted request and changed fields in
`<target>-scope-wall-change.json`. The existing runner creates a fresh immutable scope
for each target/trial with authorization expiry three hours after registration.
The coordinator confirmed that renewal behavior in message `5ed06906`, while retaining
the separate GO2 hold before scans.
The target identity, authorization fields and other budgets remain identical within
each recorded time-budget diff.

The coordinator separately increased the reviewed active browser ceiling from 500 to
1,200 on the same frozen images, before this attempt. That configuration change is
additional to the scope time extension and must be reported independently of the
source/image fingerprints. Read-only allowlisted environment snapshots are prepared
for each trial's start and terminal boundary; these retain no other environment
values. They are not detector changes or new cases.

The prospective evaluator worktree is `/tmp/scopelens-holdout-wall-evaluator-874d0ff`,
with runtime paths restored exactly from `b0b123a`. Offline tracked and vendor-inclusive
fingerprints match that deployed commit, and all four frozen corpus hashes are
unchanged. Preflight evidence is
`runs/holdout-benchmark/rerun-b0-wall2700-874d0ff-preflight/`.
The score root is `scored-b0-wall2700-874d0ff/`. The coordinator issued GO2 in
message `f6652429` after the native gate's official restoration was verified. A
helper-held admission rechecked exact runtime fingerprints/images, readiness, live
1,200-action ceilings, disabled ZAP, unchanged manifests and corpus hashes. The fresh
schedule started at 16:34:38 UTC. It is in progress; no qualification is claimed.
The admission receipt records the coordinator's existing exclusion for an expired
historical queued intent, without changing that row. No active scan or host test job
competed at admission. Read-only post-score analysis retains reach, admission and
runtime-authority configuration snapshots at each trial boundary.

The five new wall-budget regression cases and seven existing scheduler/pin cases
passed together. A stable checkout at `035894b` with exactly this evaluator patch
passed all **2,295 tests with no skips in 386.35 seconds**, on
`scopelens_test_holdout_benchmark`; `make lint` passed, including 431 formatted Python
files and the frontend typecheck. Source-overlay hashes and commands are recorded in
`wall-tests-checkout.json` and `full-suite-wall-budget-isolated.json`.
No UV command repointed the shared editable install.
The validation suite overlapped capability scan `232c3ccd` from about 16:21:12 to
16:21:26 UTC. Suite-wrapper and scan start/end timestamps, source hashes and the
peer's receipt are preserved in `full-suite-wall-budget-isolated-overlap.json`.
This establishes host-resource overlap, without assigning a cause to scan errors or
latency. No held-out benchmark scan was running during that overlap. The lane started
no further test run after the suite completed, leaving the native gate its reserved slot.

The preceding shared-tree suite recorded 2,294 passes and one failure because an
existing browser fixture expected its default ceiling of 500 while loading the
operator's new live value of 1,200. The fixture owner isolated its tested values in
`035894b`; no runtime setting was changed to make tests pass. That first failure and
its redaction receipt remain in `full-suite-wall-budget.log` and related JSON files.
The log's credential-bearing Settings representation was redacted without changing
the assertion or outcome. The original c208 results and aborted b0 attempt remain
preserved. The release gate is still unchecked.

### First completed trial of the time-extended attempt

Baseline repeat 1 is scored and failed. Its candidate source and images remained
stable, and its start/terminal authority settings matched preflight. The other five
trials remain in progress or reserved; this is not the complete six-trial result.

| Upstream-curated family | TP | FP | FN | TN | Negative abstentions | Qualification |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| XSS | 50 | 0 | 31 | 70 | 29 | Failed recall and negative coverage |
| SQL behaviour | 42 | 0 | 15 | 1 | 59 | Failed recall and negative coverage |
| Open redirect | 2 | 0 | 0 | 2 | 2 | Insufficient 2+/4-/2-group sample and negative coverage |
| HTML injection | 0 | 0 | 0 | 0 | 0 | No upstream-curated labels |
| CORS | 0 | 0 | 0 | 0 | 0 | No upstream-curated labels |

XSS recall is 50/81, 61.7%, Wilson 95% interval 50.8–71.6%; precision 50/50,
100%, interval 92.9–100%; FPR 0/70, interval 0–5.2%; negative conclusive coverage
70/99, 70.7%, interval 61.1–78.8%. SQL recall is 42/57, 73.7%, interval
61.0–83.4%; precision 42/42, 100%, interval 91.6–100%; FPR 0/1, interval
0–79.3%; negative coverage 1/60, 1.7%, interval 0.3–8.9%. The evaluator retains
positive inconclusive cases within FN, 31 XSS and 15 SQL in this trial. They do not
become additional cases or true negatives. All intervals and sample denominators
are retained in `repeat-1-baseline/result.json`.

BenchmarkJava ended `completed_partial` at 17:09:18 UTC after admitting 788 reviewed
browser actions and 3,082 broker requests. There were 81 browser denials with the
explicit reason `session_expired`, rather than the active-action ceiling. The durable
session expired at 17:09:15.288347 UTC. Of 176 XSS series, 137 retained responses and
39 recorded capture errors. Of 168 HTML series, 126 retained responses and 43 recorded
capture errors, including one partially admitted series. All 110 SQL series retained
responses with no capture errors or HTTP 403. Two broker records reported
`budget_exhausted`; they lack a probe reference or detailed budget reason, so they
are not automatically attributed to active probes. WAVSEP also ended partially after
browser exploration timed out, retaining its HTTP results. This trial demonstrates
admission beyond the earlier 500-action ceiling, while exposing a separate session
expiry boundary. No setting, detector, case, proof rule or remaining trial was changed
in response to these outputs.

The upstream-curated reach breakdown is XSS FN c11/d19/unresolved1 and negative
abstentions c28/unresolved1; SQL FN c1/d14 and abstentions c3/d56; redirect abstentions
c2. Stages a and b are zero. Supplemental HTML counts are TP58/FP0/FN16/TN71/A-29;
these remain derived labels with XSS endpoint overlap, without qualification credit.
Every missed case and redacted stage example is retained in
`reach-analysis/repeat-1-baseline.json`; admission and capture coverage are in
`repeat-1-baseline-authority.json`, and the separate persisted expiry snapshot is
`repeat-1-baseline-session-expiry.json` in that directory. The release gate remains
unchecked and all controls remain experimental.

### Docker interruption and resumed schedule

Docker Desktop quit cleanly at 17:41:26 UTC on 2026-10-11, during the second
reserved trial, baseline repeat 3. The coordinator identified an app-level shutdown
in Docker's logs; its initiator was not recorded. The scheduler exited without
publishing a score for that trial. Its files remain under the original
`scored-b0-wall2700-874d0ff/repeat-3-baseline/`, labelled interrupted and unscored in
`interruption.json`. Post-restoration terminal row states are saved separately in
`interrupted-terminal-status.json`. Those states do not make it a completed
benchmark trial or contribute accuracy counts.

The coordinator restored the same frozen b0 images, re-verified the worker boundary
and authorized a complete retry of the interrupted trial, followed by the remaining
reserved order. A helper-held preflight at 18:01:59 UTC rechecked both exact source
fingerprints, the four control images, ready schema 0009, active ceiling 1,200,
disabled ZAP, unchanged corpus hashes and the absence of other nonterminal scans
apart from the documented historical queued exclusion. The restart log's hash and
preflight receipts are retained in
`rerun-b0-wall2700-874d0ff-docker-resume-preflight/`.

The resumed root is `scored-b0-wall2700-874d0ff-resumed-docker/`. It carries the
completed baseline repeat 1 score and its evidence byte-for-byte, without rescoring.
The same evaluator `874d0ff2a17ec953f21f2101b6f55325f463b153` and its tested scheduler
functions run the remaining order: baseline repeat 3, adaptive repeat 1, adaptive
repeat 3, baseline repeat 2, adaptive repeat 2. Each new trial resets the fixtures
and creates fresh scopes. The 60-second gaps remain unchanged. Recovery scripts and
hashes are retained as orchestration evidence; evaluator, runtime, case, label and
proof source files were not changed. Exactly six completed scores are intended,
with the interrupted exposure disclosed separately. The resumed schedule is in
progress, without a qualification claim.

The coordinator attested a sandbox gateway outage from 17:16:12 to 17:59:29 UTC.
Read-only local listener observations confirm absence at 17:24:31, 17:28:42 and
17:32:49 UTC, then presence at 18:03:25 UTC. These observations are not continuous
readiness measurements or independent exact outage endpoints. Any adaptive sandbox
execution failures will retain environment attribution, and any later outage will
be recorded separately. The Docker and sandbox interruptions do not change the
frozen corpus or erase the earlier partial and failed results.

The retried baseline repeat 3 is now scored. Its independently curated counts,
TP/FP/FN/TN/A-, are XSS **55/0/26/75/24**, SQL **41/0/16/1/59** and redirect
**1/0/1/1/3**. All family qualifications are false; HTML and CORS still have no
upstream-curated samples. Candidate and authority settings remained stable. D
admitted 843 reviewed actions, with 63 `session_expired` browser denials and two
broker budget denials. The XSS reach breakdown is FN c7/d19 and negative abstentions
c24; SQL FN c2/d14 and abstentions c3/d56; redirect FN c1 and abstentions c2/d1.
Stages a, b and unresolved are zero for these curated cohorts. Full intervals,
case-level failures and redacted examples are retained in this trial's result and
reach-analysis files. The schedule continues with the reserved adaptive trials;
these repeat measurements are not pooled into larger case denominators.

The first adaptive trial is scored as XSS TP55/FP0/FN26/TN74/A-25, SQL
TP42/FP0/FN15/TN1/A-59 and redirect TP2/FP0/FN0/TN2/A-2 for independently
curated cases. Every family still fails qualification. D admitted 834 reviewed
browser actions and recorded 66 `session_expired` browser denials and two broker
budget denials. Its baseline finished before adaptation, but the retained plan
marks baseline completeness false. Adaptation nevertheless ran: planner,
verification and generated analysis completed, with one completed follow-up.
A/B/C completed with complete baselines and generated analysis; their follow-up
counts were 1, 5 and 6. These are measured execution states, not evidence that
adaptation improved detection. The curated reach counts are XSS FN c7/d19 and
abstentions c25, SQL FN c1/d14 and abstentions c3/d56, and redirect abstentions c2.
Stages a, b and unresolved are zero. Source and runtime-authority receipts remain
stable. Full intervals and saved phase evidence remain under `repeat-1-adaptive/`
and `reach-analysis/repeat-1-adaptive*.json` in the resumed root.

The resumed scheduler stopped again at 19:19:29 UTC during adaptive repeat 3.
Its A and B scans completed and were exported, but `POST /api/scans` returned
HTTP 404 after the C scope registration succeeded. C received no scan ID and D
never started. The response body was not retained, so the cause remains
unverified. A read-only snapshot found a C scope registered successfully at that
time, owned by the same operator as A, with no scan row. This alone does not
establish the failed request's scope ID or the cause of the 404. The 17 existing
trial files are hashed in `repeat-3-adaptive/interruption.json`, with the scope
snapshot saved separately. The scheduler exited 1; its read-only observer was
stopped with SIGTERM. No automatic retry or additional target request followed.
`summary-interrupted-three.json` records three completed scores and three missing
trials, so the full six-trial schedule remains incomplete and failed. The earlier
scores and both interrupted exposures are preserved. Further retry requires a
coordinator decision.

The coordinator subsequently authorized an evaluator-only scope visibility guard
and a fresh fourth trial, preserving the remaining order. The API owner reproduced
a response-before-commit race independently with a controlled ASGI boundary test,
then committed the scope-save fix as `cccc952` for a later build. That experiment
reproduces the mechanism, without uniquely tracing the historical 404. The deployed
benchmark runtime remains b0. The evaluator records redacted failed-response bodies
and hashes without headers or login request payloads. It retries scan creation only
after an explicit `scope not found` 404, exact scope visibility within ten seconds,
and at most one additional POST. Unknown 404s and uncertain network errors stop
without a repeated scan POST. Scoring, cases, labels, payloads and proof rules remain
unchanged. New and carried trials will have different evaluator freezes, which the
existing strict aggregate summary must flag rather than silently treat as identical.

The initial guard validation archive omitted the six untracked, pinned vendor
archives, causing three existing binary-pin tests to fail. Its full-suite log and
receipt remain `scope-api-guard-full-suite-02.log` and
`scope-api-guard-validation-02.json`. The archived tests also retained nested-with
style that Ruff rejected; the corrected tests and final remaining-wait timeout
received focused checks. The vendor directory and exact local archive bytes were
then restored, with hashes in `scope-api-guard-assembly-correction.json`. No source
was downloaded and no runtime changed. The missing-vendor regressions and final
harness tests passed 13/13 before a fresh full suite of the corrected snapshot.
Initial validation-wrapper and copy setup errors occurred before successful
assembly and remain in the orchestration history; they did not launch scans.

Saved configured-price model-cost estimates for the three scored trials are
$0.0005413 for baseline repeat 1, $0.0007888 for baseline repeat 3 and $0.0705796
for adaptive repeat 1. All retain the same per-target ceilings of 30 model calls
and $5. These estimates come from terminal export call records, not invoices,
and do not establish equal-cost effectiveness. Baseline usage includes browser
model calls. `saved-phases-three.json` hashes every input export and result and
retains per-target role states, reservations, generated analysis and baseline
completion flags. Positive inconclusive curated cases already counted as FN are
XSS 31/26/26 and SQL 15/16/15 in the completed schedule order; redirect adds one
in baseline repeat 3. These are not extra cases or true negatives.

The corrected archive validation passed **2,379 tests**, without failures or
skips, in 418.65 seconds; `make lint` passed. It contains committed base `ad985f7`
plus the final evaluator helper, runner integration and nine new guard tests.
All three overlays and six vendor files are hashed in
`scope-api-guard-validation-final.json`; the previous failed validation remains
separate. Focused scope, scheduling and candidate-pin checks passed 21/21.
Validation used only `scopelens_test_holdout_benchmark`, with no editable-install
repoint or live scan. The next resumed root is
`scored-b0-wall2700-scope-visibility-resume/`, carrying three earlier completed
trial directories byte-for-byte and reserving adaptive repeat 3, baseline repeat 2
and adaptive repeat 2. Its guarded evaluator will be pinned before first exposure.

The fresh adaptive repeat 3 is the fourth completed score. Curated TP/FP/FN/TN/A-
counts are XSS 53/0/28/72/27, SQL 42/0/15/1/59 and redirect 2/0/0/2/2. Every
qualification remains false, with candidate and runtime-authority receipts stable.
D admitted 807 reviewed actions and 3,102 broker requests, then recorded 75 browser
`session_expired` denials and two broker budget denials. Curated reach is XSS FN
c9/d19 and abstentions c27; SQL FN c1/d14 and abstentions c3/d56; redirect abstentions
c2. Stages a, b and unresolved are zero. Full intervals and case examples remain
in this trial's result and reach files.

The coordinator reported the sandbox gateway stopping at 19:59:25 UTC after its
two-hour process limit. It could not relaunch that server from its session and
requested an operator terminal restart. The coordinator instructed the benchmark
to continue unchanged and disclose affected generated analysis. Local listener
observations show presence at 19:58:35.110073 UTC and absence by
19:59:25.615946 UTC; these are observation bounds rather than an independently
measured exact shutdown. The fourth trial's D generated analysis is saved as
`outcome_unknown` while that listener remained absent. A/B/C completed generated
analysis before the gap. D's baseline finished before adaptation but its completeness
flag is false; one adaptive follow-up is recorded. No generated execution or adaptive
benefit is inferred from the unknown result. The gap and coordinator decision are
saved in `observed-sandbox-gap-2.json` and `coordinator-sandbox-gap-2-decision.json`
under the scope-visibility resume root. No restart or scanner change was attempted
by this lane; the remaining baseline repeat 2 and adaptive repeat 2 continue.

## Six completed scores

The finite scheduler and saved-evidence observer both exited successfully at the
six-score boundary. The final shared stack lock was released; this lane started
no further scan, reset, deployment or test suite. "Complete" describes the reserved
schedule, not complete probe admission: all six BenchmarkJava scans ended partial.
This remains **the same independent corpus, harness-corrected rerun**, with repeated
exposure and all authority, time-budget and environment changes disclosed above.
It is not an untouched first-exposure detection measurement.

Final evidence root:
`runs/holdout-benchmark/scored-b0-wall2700-scope-visibility-resume/`.
`summary-six.json` reports `complete=true`,
`candidate_stable_in_all_trials=true`, `same_frozen_candidate_and_cases=false`,
`qualified_families_in_all_trials=[]` and `passed=false`. The only differing strict
freeze fields are `evaluator_commit` and `evaluator_sha256`: the first three scores
used `874d0ff2a17ec953f21f2101b6f55325f463b153`, and the last three used
`617343addc0c82b68f380296edf77d430887b757`. The latter adds only the approved
scope-visibility setup guard and failure-response receipt. The comparator was
not weakened. Every individual family gate also fails independently of that difference.

The deployed backend for all six scores is
`b0b123add84182fb8ec9327ec9951e98711d7d8c`, with tracked fingerprint
`fa380956d16b6b6965edf412b16853ff3a240fd763a71e685515564ae63b1174`
and vendor-inclusive fingerprint
`0b0a3f045f967d29e74d4330fc9edb24be187a0b338a25394e2041ae88169dcb`.
Runtime settings at each trial's start and terminal boundary match preflight.
All four case/protocol/admission hashes match the pre-exposure reserve; all 81
carried files from the first three scored directories remain byte-identical.
All 24 scope request receipts pass the exact comparison: only D wall 900 to 2700
differs from its prior request, with wait 2820; other targets remain wall 900 and
wait 1020. The request cap stays 5000 and active-browser ceiling stays 1200.

Counts below are **TP/FP/FN/TN/A-** for the upstream-curated population. XSS has
81 positive and 99 negative cases; SQL has 57 and 60; redirect has 2 and 4.
Recall intervals are Wilson 95%, in percent. Repeats never enlarge denominators.

| Reserved order | XSS counts | XSS recall [95% interval] | SQL counts | SQL recall [95% interval] | Redirect counts |
|---|---|---|---|---|---|
| Baseline repeat 1 | 50/0/31/70/29 | 61.73 [50.84, 71.55] | 42/0/15/1/59 | 73.68 [61.02, 83.35] | 2/0/0/2/2 |
| Baseline repeat 3, Docker retry | 55/0/26/75/24 | 67.90 [57.12, 77.06] | 41/0/16/1/59 | 71.93 [59.17, 81.92] | 1/0/1/1/3 |
| Adaptive repeat 1 | 55/0/26/74/25 | 67.90 [57.12, 77.06] | 42/0/15/1/59 | 73.68 [61.02, 83.35] | 2/0/0/2/2 |
| Adaptive repeat 3, scope-race retry | 53/0/28/72/27 | 65.43 [54.59, 74.88] | 42/0/15/1/59 | 73.68 [61.02, 83.35] | 2/0/0/2/2 |
| Baseline repeat 2 | 54/0/27/73/26 | 66.67 [55.85, 75.97] | 42/0/15/1/59 | 73.68 [61.02, 83.35] | 2/0/0/2/2 |
| Adaptive repeat 2 | 53/0/28/70/29 | 65.43 [54.59, 74.88] | 42/0/15/1/59 | 73.68 [61.02, 83.35] | 2/0/0/2/2 |

XSS and SQL miss the 90% recall threshold in every trial. XSS negative conclusive
coverage is 70/99 to 75/99, or 70.71% to 75.76%; SQL coverage is 1/60, or 1.67%.
Both fail the 90% negative coverage requirement. Precision is 100% on confirmed
labelled cases, and observed FPR is zero on conclusive negatives, but this is not
a claim of zero population FPR. SQL's 0/1 FPR has a Wilson upper bound of 79.35%.
HTML and CORS each have zero upstream-curated positives, negatives and groups;
their qualification metrics are N/A, not zero accuracy. Redirect lacks 28 positives,
56 negatives and one group and has only 25% to 50% negative coverage. No family
is promoted. Four unmatched `SL-C04-XCTO-01` findings per trial are retained outside
these named conditions, without inventing labels or classifying them as FP.

`final-report.md` renders all five families for each trial, both upstream-curated
and full labelled populations, including every precision/FPR/coverage denominator
and 95% interval. It also includes FN and abstention counts at stages a/b/c/d and
unresolved for independent, supplemental and combined populations, with up to three
redacted examples per stage. Each `reach-analysis/<trial>.json` retains every miss
record and evidence reference. Empty stage a/b example sets are reported as empty.
Stage c records blocked/error captures; HTTP errors alone do not establish their origin.

For curated XSS, stage-c FN counts in schedule order are 11, 7, 7, 9, 8 and 8;
stage-d FN counts are 19 in every trial. Baseline repeat 1 adds one unresolved FN
and one unresolved negative abstention. Adaptive repeat 2 adds one unresolved FN
and three unresolved negative abstentions. The remaining XSS abstentions are
stage c: 28, 24, 25, 27, 26 and 26. SQL has 14 stage-d FN in each trial, one stage-c
FN except two in baseline repeat 3, and negative abstentions c3/d56 in every trial.
Redirect has one stage-c FN in baseline repeat 3; its negative abstentions are c2
in every trial, plus d1 in baseline repeat 3. Stages a and b are zero for curated
misses in all six. Positive inconclusives are already included in the stated FN.

Measured BenchmarkJava admission remains incomplete:

| Trial | Reviewed browser actions | Broker allows | Browser session-expiry denials | Generated analysis |
|---|---:|---:|---:|---|
| Baseline repeat 1 | 788 | 3082 | 81 | Not requested |
| Baseline repeat 3 | 843 | 3125 | 63 | Not requested |
| Adaptive repeat 1 | 834 | 3129 | 66 | Completed |
| Adaptive repeat 3 | 807 | 3102 | 75 | Outcome unknown |
| Baseline repeat 2 | 824 | 3118 | 69 | Not requested |
| Adaptive repeat 2 | 821 | 3116 | 70 | Outcome unknown |

Each D scan also records two broker `budget_exhausted` denials. Their audit records
and per-case capture attribution remain separate from browser session expiry.
The wall extension and 1200-action ceiling do not establish full admission.
No session-lifetime or detection fix was made using these outcomes.

The first sandbox gap is coordinator-attested at 17:16:12 to 17:59:29 UTC. The second
was reported to start at 19:59:25 UTC, with listener observation bounds recorded
above. The listener was still absent in the final observation at 21:36:08.700034 UTC;
no restoration was observed or performed by this lane. This is not a continuous
readiness measurement or an independently established exact outage end. Adaptive
repeat 3 records D generated analysis `outcome_unknown`; its other three targets
completed it before the gap. Adaptive repeat 2 records `outcome_unknown` for all
four targets. Completed planner/verification/script call records do not prove
generated analysis executed. No equal-cost adaptive effectiveness is claimed.

Configured-price cost estimates in reserved order are $0.0005413, $0.0007888,
$0.0705796, $0.0740958, $0.00070285 and $0.0692888. `saved-phases-six.json` retains
call states, missing numeric costs, reservations, per-target baseline/adaptation
completion flags and input hashes. These estimates are not invoices; call/cost
ceilings remain 30/$5 per target and reservation ceilings are not actual charges.

The saved-output commands were `summarize_saved_phases.py`,
`render_saved_six_report.py` and `python -m evaluation.summarize_holdout`, after
the real deployed API runner and helper-held trial scheduler. No command rescored
cases with changed predicates. `final-report-integrity.json` hashes all rendered
inputs and the rendering utility, verifies carried files/corpus/scope receipts,
and records the exact strict-comparator differences. The latest evaluator-code
validation remains the isolated corrected archive's 2379 passing tests, no skips,
and `make lint`, with prior failures retained separately. Final changes are docs
and saved-output reporting only; this lane ran no host suite during the last three trials.
