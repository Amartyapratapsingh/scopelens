# Scanner implementation handoff

Date: 28 September 2026
Product scope: docs/SCANNER_EXPANSION_PROPOSAL.md, B1–B7. Backend only.

## CURRENT ASSIGNMENT — TASK 1 ONLY

Operator correction: Command Code owns **only task 1**, the interrupted browser workflow
package (stored marker, CSRF and upload-policy checks) and its focused tests. **Tasks 2–5
below are retained for context and belong to the main agent. Do not implement them.**
If any work on tasks 2–5 was already started, preserve it and report the touched files.
Shared integration/API/database/scoring/report files remain with the main agent.

Workspace check on 28 September: latest edits are in browser/workflow_checks.py and
 tests/browser/test_browser_workflows.py, including cleanup and cancellation regression work.
Their newest changes have not yet received main-agent sign-off.

## Context

The browser-workflow agent was interrupted by an automatic cybersecurity review. The message
identified a broad cybersecurity concern, not the specific operation that triggered it.
Saved files are incomplete work requiring review. Other items below are unfinished integration,
not confirmed policy restrictions. Follow the receiving tool's own rules; this handoff does
not request bypassing safeguards or changing the approved scope.

## Task 1 assigned to Command Code; tasks 2–5 owned by main agent

1. **Review and finish the browser workflow package.** Inspect
   `backend/scopelens/domain/browser_workflow.py`,
   `backend/scopelens/browser/workflow_checks.py`, and
   `tests/browser/test_browser_workflows.py`.
   The approved features are stored harmless-marker browser confirmation, a benign CSRF
   workflow, and benign upload/serving-policy assessment on disposable local test records.
   Verify identity separation, independent state evidence, cancellation and cleanup. Saved
   code is not a completed capability. In particular, cleanup RPC failure must not discard
   partial evidence, and an unresolved cleanup must prevent another mutation.

2. **Complete the isolated browser execution adapter.** Generic discovered-input collectors
   exist in `backend/scopelens/browser/expanded_active.py`. The separate
   `backend/scopelens/expansion/browser_worker.py` is missing. It must use the existing worker
   VM, broker/proxy Bridge, certificate trust, Chromium sandbox, scoped contexts and fixed
   collectors. Do not grant execution merely because a target page describes an action.
   Return bound task/plan/input/role artifacts for trusted intake and independent evaluation.

3. **Complete callback scanner integration.** Existing modules are
   `backend/scopelens/callbacks/` and `backend/scopelens/domain/callback.py`.
   Finish scoped collector deployment and worker dispatch for approved SSRF/XXE lab fixtures.
   Preserve signed receipts, nonce expiry, cancellation, negative controls and trustworthy
   target-versus-scanner source attribution. Ambiguous source/NAT or DNS-only observations
   do not establish confirmation. Coordinate operator API and persistence changes with the
   main agent rather than editing those shared files concurrently.

4. **Finish reviewed scanner-tool execution.** Wire the curated Nuclei bundle into
   `backend/scopelens/adapters/runner.py`, preserving template hashes and canonical result
   mappings. ZAP active execution remains disabled pending enforceable exact method,
   endpoint, input and budget bindings. Keep unconstrainable rules disabled and report why.
   Installed tools and candidate matches are not validated vulnerabilities.

5. **Finish context-aware adaptive follow-ups.** New SQL/redirect/exposure/component paths
   exist in `backend/scopelens/orchestration/expansion.py` and `graph.py`.
   Browser, identity/access and callback follow-ups still need their specific execution
   contexts. Preserve typed reviewed actions, baseline budget, maximum rounds, no duplicate
   action without fresh evidence, and deterministic proof. Model text cannot confirm findings.

## Ownership

The main agent retains shared configuration APIs, database integration, proof aggregation,
score rubrics, reports and overall deployment/regression verification. Supply concrete
contracts and a list of required shared-file changes. Coordinate before editing
`expansion/integration.py`, `expansion/analysis.py`, API routers, persistence models/migrations,
scoring or report files. Do not edit frontend/.

## Verification and delivery

- Review existing work before adding or replacing files. The checkout is largely untracked;
  do not reset, discard it, or assume the previous release image contains these changes.
- Work one task at a time. Run real vulnerable and fixed local fixtures, validate proof
  artifacts and cleanup, and record exact commands/results including failures and skips.
- Preserve partial, blocked and inconclusive outcomes. Keep controls experimental until
  independent qualification; these development fixtures are not a holdout benchmark.
- Start with local isolated labs. External authenticated/stateful pilots need dedicated test
  credentials, explicit permission policy, disposable records and reset procedures; the
  previously supplied public URLs alone do not provide those prerequisites.
- Preserve the dedicated worker VM deployment override and existing egress/cancellation
  controls. Never expose .env or credentials in logs, reports or model input.
- Deliver implemented files, runtime contracts, test commands/results, remaining limitations
  and evidence for each claim. Do not claim the entire backend is complete.

Read also docs/EXPANSION_HANDOFF.md, docs/EXPANSION_TOOLS_IMPLEMENTATION.md and
 docs/AUTHENTICATED_WORKFLOWS.md for existing interfaces and evidence.
