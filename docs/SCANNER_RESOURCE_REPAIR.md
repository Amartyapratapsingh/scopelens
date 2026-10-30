# Scanner resource repair, 29 September 2026

## What failed

The customer repeat scan `ddc74783-91d5-4aa3-ac26-10cf8b4f2236` retained 110 pages but reported ZAP and Nuclei failures. The worker shared a 256 MiB scratch filesystem between imported captures, ZAP's session database, add-ons, logs, and Nuclei temporary files.

A network-disabled worker with 110 synthetic 800 KB HTML responses reproduced full scratch storage. Nuclei then failed to create its temporary files. Increasing scratch storage alone did not produce a successful ZAP assessment. Its process exited with -9; that run did not collect memory-event counters, so the exact kill cause is not proven.

## Changes

- ZAP imports full captured responses in batches of at most 8 MiB of serialized HAR. No response body is dropped to manufacture completion.
- Each batch owns a temporary directory and deletes it before the next batch. Nuclei gets a separate directory after ZAP finishes.
- Subprocess output is drained continuously. Only a 64 KiB diagnostic tail is retained, with a redacted 3,000-character excerpt on failure.
- Scanner workers have a configurable 2 GiB memory allowance. The read-only filesystem, 256 MiB scratch cap, VM boundary, proxy requirements, and cancellation watcher remain in force.
- The collection worker default is 1,800 seconds, bounded by the scan's immutable wall-clock allowance. Crawl receives 50%; ZAP receives 30%, capped at 600 seconds. Other checks and artifact flushing use the remaining allowance. The setting accepts up to six hours, but that does not enlarge scope budgets or remove page/request limits.
- A ZAP timeout now reports its actual time allowance. Failure of a later batch preserves earlier observations and marks the aggregate partial. Remaining batches are never reported as assessed.
- The summary API exposes captured page count and crawl stop reason. The dashboard displays discovered hosts and distinguishes them from the assessment target.

## Verification

Artifacts are in `runs/scanner-resource-validation/`.

| Run | Result |
|---|---|
| `before.txt` | Scratch exhausted; Nuclei failed with no space left |
| `larger-only.txt` | Larger scratch alone did not complete ZAP |
| `after-memory.txt` | Batching released scratch, but the old 120-second ZAP allowance interrupted later batches |
| `timing.txt` | All 11 batches completed in 153.66 seconds total; no errors or memory kills; scratch usage after ZAP was zero; Nuclei template validation exited 0 |

The resource experiment used `network_mode=none`. It assessed synthetic captures only. Nuclei's validation result is a template/resource check, not evidence of scanning a website. `scripts/verify_scanner_resources.py` preserves the experiment for reruns inside the supervisor against its configured worker image.

Focused automated tests: 70 passed across scanner resources, worker containment, coordinator lifecycle, and dashboard APIs. These cover actual subprocess log flooding and timeout behavior, stage allowances constrained by scan/worker limits, partial batches, and summary fields. Touched Python files pass Ruff.

## Resource repeat, 11 October 2026

The clean `8a982ed` worker image repeated the network-disabled 110-capture experiment
with the same 256 MiB scratch and 2 GiB memory caps. All 11 ZAP batches completed with
empty adapter error lists and zero `oom_kill` counters. Scratch use returned to zero
after ZAP and 32 KiB after Nuclei template validation, which exited 0. The worker was
removed after the experiment. Evidence is
`runs/scan-completeness-20261011/resource-repeat.log`; exact image IDs are in that
directory's `runtime-freeze.json`.

This ran on Docker Desktop with `network_mode=none`, not as a live scan or worker-VM
boundary test. Coordinator messages reported overlap with an unrelated fixture health
check, then no overlap, then corrected that to overlap. The invalidated holdout attempt
retains that history in `runs/holdout-benchmark/admission-00/lock-incident-addendum.json`;
no synchronized start/end receipt establishes the interval. The resource result remains
valid; batch timing is not a serial performance comparison. Live Nuclei, paired-lab and owned
pilot completion still require the newly created VM and deployed measurements.

## Remaining limits

This repair does not add authenticated test accounts, automatic authorization of discovered hosts, certificate-transparency discovery, or resumable multi-hour crawl checkpoints. The earlier customer report stays partial. No severe customer vulnerability was established by this resource test. A deployed lab assessment is recorded separately under `runs/scanner-resource-validation/lab/`.

## Deployed lab result

Scan `a08c5aa7-867b-4b76-94f0-fbba67fee8cb` finished against the isolated `labs-bad` fixture. Both ZAP and Nuclei returned `completed` with no adapter errors and attached evidence. The overall scan remains `completed_partial`; this repair does not conceal other unsupported or incomplete checks.
