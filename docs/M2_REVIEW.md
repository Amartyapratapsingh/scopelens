# M2 implementation review

Reviewed 25 September 2026 against the current working tree and the Phase 1 documents.

**Original review decision: M2 needed corrections before M3. These corrections are now implemented and verified; see the resolution record below.** The crawler, controls, scoring, report writer and dashboard API exist. Passing the current suite does not establish the claimed M2 exit gate.

## Original verification performed

- `make test-all`: 428 tests passed with PostgreSQL running; the real mitmproxy containment suite also passed.
- `make lint`: Ruff checks, formatting and frontend typecheck passed.
- Ran direct, synthetic-input reproductions against the actual scoring functions, check functions, report renderer and crawler. No external target was scanned.
- The repository has no commits, so this is a review of the current files, not a historical diff.
- The reported live lab scores of 69 and 100 were not independently rerun in this review. The defects below mean those numbers cannot establish correctness beyond those fixtures.
- No backend or frontend source was changed during review.

## Required corrections

### R1. Enable escaping for the actual report template

`backend/scopelens/writer/report.py:64` selects autoescape for `.html` and `.xml`, but `render_html()` loads `report.html.j2` at line 265. The autoescape predicate returns `False` for that name. Rendering the actual template with markup in host evidence retains the raw tag in the exported HTML.

Use unconditional HTML autoescape or an explicit selector that matches the actual template. Verify the exported document, including findings, evidence, locations and inventory, with target-derived markup. Test JSON redaction independently; HTML escaping is not JSON serialization.

Acceptance: markup remains text in the rendered export, and the test calls `render_html()` rather than a separately configured Jinja environment. This is Build Plan §5.16 work.

### R2. Restore the specified coverage and eligibility rules

`backend/scopelens/domain/check.py:90` counts any Potential proof as fully assessed, even when the outcome is Inconclusive and the proof is unsatisfied. Specification §9.7 explicitly allows only Pass and Confirmed issue to be conclusive. §8.4 also says unresolved candidates keep affected checks inconclusive.

Reproduced: replace C06's passing control with Inconclusive plus an unsatisfied Potential proof, while the other categories pass. C06 gets 100% coverage and the overall gets 100.

Separate completed informational inventory from unresolved vulnerability assessments. Do not make an inconclusive assessment conclusive to obtain a score.

Also correct these scorer defects:

- `scoring/score.py:245`: coverage uses counts, ignoring the registry's `coverage_weight`. Use the versioned assessment plan's weights, mandatory controls and required instances. A required instance that was blocked, errored or not reached remains unfinished.
- The same function removes N/A controls but then applies the 80% gate to an entirely N/A category. Reproduced: evidence-backed fully N/A C06 becomes Insufficient coverage and blocks the overall. Handle fully N/A before the coverage percentage gate, exclude it with a reason, and show Not scored if nothing is applicable.
- `scoring/score.py:366`: the global candidate hold checks only candidates retained on scored categories. Reproduced: an unresolved Potential High in C09 leaves the overall at 100. Evaluate all serious unresolved candidates on the assessed target, including excluded/unmapped categories, as §9.6 requires.

Acceptance: regression cases for all three scorer defects, conclusive-only coverage, mandatory missing instances and non-unit weights. A low-severity candidate need not impose the separate serious-candidate hold, but its inconclusive control must still affect coverage.

### R3. Implement the cleartext redirect check without inventing N/A

`checks/controls/transport.py:134` returns N/A whenever `cleartext_probe` is absent. Specification §12 explicitly says that without a separately approved transport-only HTTP origin, the check is **unassessed**.

Search of the backend finds the optional field and the check, but no path that populates it. `checks/analyze.py` never supplies it. This required check is currently skipped and removed from coverage on every normal scan.

Add the explicit transport-only authorization and bounded probe through the broker. Do not infer authority for another origin. Missing authorization must remain unassessed; a failed probe must not become N/A. Preserve any genuine, evidenced inapplicability separately.

Acceptance: authorized redirect, authorized cleartext content, missing authorization, denied redirect destination and failed probe. Do not require the good fixture to score 100 when required work lacks authorization.

### R4. Correct the exposed-file proof and incomplete-probe outcomes

`checks/controls/exposure.py:190` confirms exposure from a status 200 at a sensitive path. It does not establish that the response contains the claimed file, and does not even require a nonempty body despite the proof text claiming one.

Reproduced: `/.env` returning a normal HTML "Page not found" page with status 200 becomes a **confirmed High**. A common SPA fallback would have the same problem.

Also reproduced: only `/.env` returns 404, while `/.git/config` is blocked and `/backup.sql` times out. The control returns Pass and claims all three probes returned no content.

Require capped content evidence appropriate to the file type and a negative control for fallback/custom-error pages. Preserve per-path outcomes. A confirmed issue may be reported immediately, but it does not complete missing instances. Never collect full repositories or use discovered credentials.

Acceptance: real synthetic exposure, fixed path, empty 200, SPA fallback, custom error 200, blocked path and truncated/insufficient evidence.

### R5. Finish the transport and effective browser-policy checks

The current implementations return incorrect conclusive outcomes:

| Input to the actual check | Current result |
|---|---|
| TLS measurement for `example.test`, SAN only `unrelated.test`, notBefore in 2029, expiry in 2030, self_signed false | Pass, "certificate valid" |
| Normal `<a href="http://example.test/docs">` navigation link | Confirmed Medium mixed content |
| CSP `default-src * 'unsafe-inline'` | Pass, "an enforcing CSP is present" |
| CSP `frame-ancestors *` | Pass, frame protection present |

Relevant functions are in `checks/controls/transport.py:36`, `:260`, and `checks/controls/browser.py:33`, `:112`. TLS checks do not establish hostname, notBefore or chain trust; the lane collects with verification off. The registry acknowledges that trust is not assessed, while the check reports validity. A negotiated modern protocol also does not prove that old protocols are disabled.

Implement the promised checks or keep each missing assessment explicitly unassessed. Validate certificates against an explicit trust configuration, including the lab CA when appropriate. Distinguish ordinary navigation from loaded mixed resources. Evaluate the protection delivered by CSP/frame policy, not only directive presence; review duplicate/combined policy behavior as part of the same correction.

`transport.py:333` also uses the current wall clock during analysis. Use the recorded scan measurement time so replaying the same evidence does not change expiry findings later.

Acceptance: the examples above plus valid/fixed and unsupported-data cases. Test the actual measurement-to-check path for TLS, with no database transaction held across its network call.

### R6. Complete sitemap and redirect discovery

- `checks/crawl.py:575` asks BeautifulSoup for the XML parser, but the declared environment has no XML builder. Direct execution raises `FeatureNotFound`; the broad exception turns every valid sitemap into a parsing gap. Add a suitable pinned parser to the actual worker environment or use an available XML parser.
- `checks/crawl.py:211` disables automatic redirects, but no manual `Location` follow-up exists. A mock root returning `302 Location: /home` never causes `/home` to be requested, and the crawl records no limitation for the omission.

Acceptance: a sitemap-only route is reached; an allowed redirect reaches the destination through the broker; denied destinations, loops and redirect limits produce explicit outcomes. Keep request/budget accounting and scope checks for every hop.

### R7. Complete the retest lifecycle

`api/dashboard.py:475` queues a new crawl, then writes `retest_state="requested"` and `retest_scan_id`. There is no completion consumer of that link anywhere in the backend. A successful clean retest therefore cannot resolve the original finding or finish its requested state.

Implement completion reconciliation using fresh evidence for the original control and affected locations. Preserve the original scan's historical report. Report fixed, still present and incomplete/blocked results explicitly; an unreachable location cannot close an issue. Make duplicate completion/recovery idempotent.

Acceptance: vulnerable-to-fixed, still-vulnerable, blocked/missing-location, failed/cancelled and repeated-completion retests, checked through the API and persisted records.

### R8. Restore the required component assessment scope

`checks/controls/components.py:16` declares the advisory feed outside Phase 1. Build Plan §5.8 includes component/CVE candidates and requires version corroboration. The implementation currently reports version disclosure only.

Deliver the declared component candidate assessment with versioned advisory provenance and honest applicability limits. Banner-only observations must remain candidates and cannot confirm a vulnerability. If any required part remains unavailable, record that as unfinished work instead of silently removing it from Phase 1 or presenting the category as fully assessed.

### R9. Add the missing M2 verification and correct the handoff record

`docs/API_CONTRACT.md:4` says `tests/integration/test_dashboard_api.py` exercises every endpoint. That file does not exist. The current test run includes 23 scoring tests, but no dedicated crawler, control, report or dashboard API suites. Existing passing M1 tests do not cover those paths.

Add tests for each correction above and the M2 contract: control positive/negative/N/A/error cases, evidence requirements, deduplication, owner-scoped dashboard endpoints, filters, report exports, SSE cursor reconnection/redaction and retest completion. Match examples to emitted events and typed endpoint behavior. Do not assert only that a test double returns what it was configured to return.

Then run the real vulnerable/fixed lab pipeline and report the scores and coverage it actually produces. A clean fixture may legitimately have no overall number when required work is unassessed. Do not force 69/100 or 100% coverage as acceptance targets by weakening eligibility.

Update `MILESTONES.md`, `API_CONTRACT.md` and applicable open questions so current status, commands, limitations and review outcomes agree. Preserve historical observations as dated history. Keep registry/manifest claims consistent with tested support.

## Ownership and next step

The backend agent should fix R1–R9 before starting M3. This work includes backend report rendering and API behavior. Do not edit `frontend/`; dashboard design and implementation remain separate, per Build Plan §0 rule 9. Preserve the M1 proxy's forced `rawtcp=False` and `connection_strategy="lazy"` protections.

No new product decisions are needed to begin these corrections. They follow the existing Phase 1 requirements. This review does not add worker-VM or Docker-socket hardening to M2.


## Resolution record — 25 September 2026

| Finding | Resolution and regression evidence |
|---|---|
| R1 | Unconditional autoescape on the actual `.html.j2` renderer; actual HTML/JSON export tests in `test_dashboard_api.py`. |
| R2 | Conclusive outcomes only, weighted control coverage, explicit required/completed instances, global serious candidates, legitimate all-N/A exclusion. `test_m2_scoring_regressions.py`, `test_m2_controls.py`, original scoring suite. |
| R3 | Immutable explicit `transport_http_port`, one broker-admitted GET, no follow; unavailable probe is unassessed. `test_transport_authorization.py`, crawler tests, live lab redirect results. |
| R4 | Content signatures plus negative control and per-path completeness. Empty/soft-404/blocked/truncated cases in `test_m2_controls.py`; real bad/fixed fixture reports. |
| R5 | Real verified TLS with capture-time evaluation and separate legacy offers; effective CSP/frame policy handling; navigation excluded from mixed resources. `test_m2_tls.py`, control tests and actual lab CA validation. |
| R6 | Stdlib XML parser, bounded manual redirects, preserved gaps. `test_m2_crawler.py`. |
| R7 | Completion reconciliation, fresh location coverage, idempotence and recurrence reopening. Database tests plus live CSP fixed→resolved→recurrent→open flow. |
| R8 | Offline OSV snapshot loader, explicit package mapping/version matching, frozen source/hash; candidates only. `test_m2_advisories.py`; no configured corpus means unassessed. |
| R9 | Real dashboard API/export/ownership/SSE tests, per-scan committed event ordering, updated OpenAPI extension, API contract and milestone/manifest documentation. |

Additional review fixes include TLS denial semantics and fresh cancellation checks between handshakes, no budget reservation for duplicate denied transport probes, missing captures retained in coverage, and capture manifests that reference actual response artifacts with task/run/source provenance.

Final verification: **524 tests passed, no skips**, `make lint`, `make test-proxy` (21 assertions), registry validation and manifest generation. Live reports: good **0 findings / 94.1% coverage**; bad **12 findings / 88.2% coverage**. Both withhold the overall number under the actual coverage gates. The earlier 69/100 and 100/100 claims are not retained as acceptance criteria. Full commands, scan IDs and configuration limits are in `MILESTONES.md`.
