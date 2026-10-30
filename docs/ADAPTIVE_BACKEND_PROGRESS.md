# Adaptive backend progress — 28 September 2026

Scope: B6 orchestration and reviewed follow-ups only. This is local source and fixture validation;
the worker VM at `127.0.0.1:8090` was not rebuilt, restarted or scanned for this work.

## Implemented

- Typed hypotheses now bind to the exact frozen plan ID, scope version and catalogue hash.
  Generation refuses a mismatched catalogue. Admission and worker dispatch recheck the
  persisted plan, catalogue, scope identity, authority and shared request budget. The worker
  refuses a changed plan, catalogue, task, control, template or target origin before sending
  a request. A previously admitted hypothesis remains non-replayable.
- A repeated SQL or redirect proof must return the exact reviewed task, template, plan,
  control and family before it can corroborate or contradict a lead. The existing reviewed
  collector supplies the capture series and deterministic evaluator supplies the verdict.
  A new round requires a changed reviewed response or capture field; arbitrary extra fields,
  timestamps and run IDs do not count as fresh evidence.
  Component re-observation uses the existing bounded read-only response collector; it
  remains a potential identity observation, never an exploitability confirmation.
- The ledger records the hypothesis, frozen request binding, child worker run ID, capture
  hashes, request count where the collector supplies it, worker exit code, deterministic proof
  result, challenge result and a terminal stop reason. Adaptive artifact markers carry the
  hypothesis ID, plan ID and run ID. Capture bodies and model prose are not copied into the
  ledger. The final finding association remains in the shared proof aggregation stage; a
  corroborated ledger row alone does not create a finding.
- The CSP recheck now requires an exact URL and route, HTML response, HTTP 200 and proxy
  provenance before considering the missing-header observation corroborated.

## Synthetic development evidence

Focused tests exercise reviewed follow-up collectors against local vulnerable/fixed SQL and
redirect fixtures and a local exposed/clear configuration fixture. The SQL and redirect
positive leads corroborate; their fixed counterparts contradict. The exposure candidate
corroborates only against the exposed fixture and contradicts on the clear fixture. These
are three distinct development families, but the cases are known to the implementation and
do not constitute blinded validation. Tests also reject changed frozen plans/catalogues,
changed task controls and mismatched proof captures without target requests.

Commands and results:

| Command | Result |
|---|---|
| `uv run pytest tests/unit/test_expansion_adaptive.py tests/unit/test_adaptive_graph_loop.py tests/unit/test_active_proofs.py -q` | 39 passed |
| `uv run ruff check backend/scopelens/orchestration/expansion.py backend/scopelens/orchestration/graph.py tests/unit/test_expansion_adaptive.py tests/unit/test_adaptive_graph_loop.py` | clean |
| `uv run ruff format --check` on the same four files | clean |

The offline equal-ceiling evaluator in `evaluation/expansion.py` requires identical case,
scope, fixture, candidate and request/time/cost ceilings, measured usage, and known model
cost. These fixture checks have no measured baseline-only run or model-cost receipt. Therefore
an eligible comparison and added confirmed/false-positive counts are **unknown**, not zero.
Existing `runs/comparison-final` reports use an older report structure and do not supply the
required per-case measurement contract. No independent curator or holdout was created.

## Shared integration and remaining gates

1. In the shared coordinator/proof aggregation path, join final proof and finding IDs to the
   adaptive hypothesis by the emitted `hypothesis_id`, `plan_id` and `run_id` only after the
   final trusted proof gate accepts the capture. Do not treat the ledger's `corroborated`
   state as a finding by itself.
2. Run focused coordinator/report contracts for source `adaptive`, followed by a frozen
   worker-image deployment and local owned fixture pair if approved by the main task. Verify
   the persisted stop reason and exact hypothesis-to-capture/finding chain in JSON/HTML.
3. Collect separate baseline-only and adaptive measurements under the same frozen request,
   time and cost ceilings. Pass both to the existing evaluator and report added confirmed
   findings and false positives separately. Unknown costs or missing proof replay make the
   comparison ineligible. The three development families are not an independent B6 exit gate.

Identity, browser-reflection and callback follow-ups remain explicit blocked gaps until their
own reviewed dispatch and proof contracts are integrated. This work did not modify the CORS
collector or header handling.
