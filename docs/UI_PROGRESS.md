# UI progress

## Pass 1 — 28 September 2026

Implemented the shared Nexchat-inspired styling, homepage navigation, hero URL intake and interactive product preview. The `/dashboard` route is an explicitly labeled preview, with URL draft preservation; it does not dispatch scans or bypass authentication. The previous operator interface is preserved in `frontend/src/OperatorApp.tsx` and its existing stylesheet/API adapter for subsequent integration. It is not mounted by this pass.

### Delivered

- React/TypeScript/Vite retained; Tailwind Vite integration and Phosphor icons added.
- Self-hosted Manrope, Inter Tight and Geist fonts, with OFL license files.
- Semantic color tokens, dark surfaces, silver headings, blue CTA treatment and responsive layout.
- Hero fade/translate/scale timing follows observed reference values. Product preview uses a CSS ease-out approximation of the reference's sampled spring. Decorative glows are CSS treatments, not the original image assets.
- Native modal mobile navigation with explicit keyboard focus wrapping, Escape dismissal and focus restoration.
- URL form validates HTTP(S), rejects credentials/query/fragment, and opens a draft in the preview route. No scan starts.
- Example findings filter, expandable evidence/remediation, report view and example JSON download work.
- Findings assistant is labeled “Coming next”; no live assistant response is fabricated.
- Reduced-motion mode disables travel/entrances and leaves content visible.

### Verification

- `pnpm --dir frontend build` passed, including TypeScript checks.
- Real-browser checks: Medium/Low filtering, finding detail open/close, invalid URL error, valid URL transfer, report download, mobile menu focus wrap/Escape restoration, reduced-motion zero animations.
- Download parsed successfully: `demo: true`, three illustrative findings.
- Preview navigation recorded no `/api/` requests.
- No horizontal overflow at actual CSS widths 1440, 390 and 360. Browser zoom meant requested 768 testing was bracketed at 767 and 769 CSS pixels; both had no overflow. Avoid claiming an exact 768 measurement.
- Screenshots and example download saved in `runs/ui-pass-1/`.

### Remaining UI work

Homepage capability/process/report sections, FAQ and full footer. Full dashboard layout and real API connection with loading/empty/error/session states. Live chatbot integration. Final reference and accessibility comparison across all screens. No authentication screen is requested; backend authorization must remain intact.

Local preview: http://127.0.0.1:5173/.

## Pass 2 — Animated capabilities and process

Added the asymmetric capability cards and three-step process, adapting the supplied keyboard/search/typing-code reference to ScopeLens. No backend changes or scans in this pass.

- Website-entry illustration types a fixed example URL with matching keyboard highlights.
- Discovery illustration reveals three example routes.
- The full-width response card types a harmless HTTP response example, then highlights missing policy evidence. It never executes code or sends requests.
- Each illustration begins when at least 20% visible, runs once, pauses its timer offscreen or when the document is hidden, and has explicit pause/play/replay controls.
- Reduced-motion mode renders complete text and discovered states with no animations. Screen readers receive stable illustration descriptions instead of character-by-character announcements.
- Added scope → assessment → report process cards and a dashboard CTA. Navigation now links to Capabilities and How it works.
- Entrance reveal is 850 ms from 50 px below. The keyboard ticks at 115 ms, discovery at 100 ms, code typing at 26 ms. These are ScopeLens-specific animation timings, not a claim of identical timing to Nexchat's Lottie assets.

Verification: production build and TypeScript pass. Real-browser pause kept evidence step 11 unchanged; offscreen pause kept step 13 unchanged; resume advanced the sequence; reduced-motion showed all three routes and full response with zero animations. No horizontal overflow at measured CSS widths 1440, 1025, 810, 769, 390 and 360. Desktop and mobile screenshots saved in `runs/ui-pass-2/`.

Still to build: dedicated report/assistant showcase, FAQ, closing homepage section/full footer, and the live dashboard/API/assistant integration.

## Pass 2 refinement — 29 September 2026

User requested a stronger visual blend and continuous reference-style motion.

- Homepage product preview now fades through a deep black gradient into the following section, with a dotted texture continuing behind it. Focus or an expanded finding clears the overlay for reading; the standalone dashboard has no fade.
- Website, discovery and evidence demonstrations now loop automatically with a 1.8-second completed-state hold. Pause/play remains available throughout the cycle. Offscreen/hidden-tab pausing and reduced-motion static content are preserved.
- Binary background now scrolls as two matching groups on a seamless 28-second cycle. Its play state follows the code card's visibility and pause control.
- Browser verified automatic cycle rollover, paused typing and binary transform unchanged across samples, reduced-motion disabling all animations, and no mobile overflow. Production build passes.

This supersedes pass 2's earlier “runs once” and replay-button behavior.

### Playback controls removed

Removed the decorative illustration play/pause buttons and static-motion labels at the user's request. Automatic looping, hidden/offscreen suspension and OS reduced-motion support remain. The artwork retains its spacing. Production build passes; browser confirms zero playback controls and automatic cycle rollover. This supersedes the visible-control behavior described above.

## Pass 3 — FAQ and dashboard foundation (29 September 2026)

Added the reference-inspired FAQ: silver-gradient heading, six numbered dark accordion cards, circular plus/minus controls, first answer expanded. Answers explain ScopeLens assessments, supported-check limits, AI, scores, permitted targets, and report exports. Native buttons expose expanded state and panel relationships; Enter toggles the focused question.

Replaced `/dashboard`'s preview-only page with a responsive workspace:

- Sidebar navigation for Overview, Assessments, Findings, Reports, and Websites.
- Real API reads for scans, scopes, assessment summary, findings, category scores, and SSE activity. Unavailable values render as dashes, not invented zeroes.
- Assessment history/search, selection, severity filters, expandable evidence/remediation details, category coverage, HTML/JSON report links.
- Existing-scope scan creation, cancellation, and finding retest actions wired to their existing endpoints. Starting a scan requires an explicit submit; homepage URL drafts never start a scan.
- Loading, empty, connection-error, and missing-session states. No login UI or backend authentication changes. Example assessment is an explicit, separately labeled view.
- Existing scopes displayed with expiry. Creating/editing scope configuration and the real assistant/chat interface remain for a later dashboard pass.

Verification:

- `pnpm --dir frontend build`: TypeScript and production build pass.
- Real browser: FAQ click opens one answer and closes the previous answer; Enter closes the focused answer.
- Homepage/FAQ and dashboard: no document overflow at measured CSS widths 360, 390, 810, 1150, 1440.
- Live backend rejected this browser's missing session; dashboard displays the authorized-session message and disables new assessments correctly. No secrets loaded, authentication bypasses, or target scans performed.
- Isolated browser test fixtures (temporary fetch/EventSource replacement, removed after testing): finding expands with remediation; severity filter excludes a medium finding when High is selected; score 85/100 renders; HTML/JSON links match backend routes; explicit new-assessment submit sends the selected scope ID. This checks UI contracts, not successful deployed scan execution, report download delivery, or real SSE reconnection.
- Screenshots in `runs/ui-pass-3/`: FAQ, desktop/mobile dashboard, and populated assessment (explicit test fixture). Browser returned to the real API afterward.

Still pending: authenticated end-to-end dashboard actions, scope registration/editing screens, richer exploration/evidence views, real chatbot integration, and final homepage closing/footer pass. Backend completion is not implied by this frontend pass.

## Local URL-to-scan flow (29 September 2026)

At the user's request, prioritized immediate scanner testing over other UI integrations.

- Added a URL form that registers a 24-hour production scope using the exact entered origin and path, then starts the existing `external-dast` scan and selects it. Scope creation failures and dispatch failures appear inline. Repeat submit is fenced while the request is in flight. A created scope is retained for retry when dispatch fails.
- Added explicit local development session bootstrap to the Vite server. `make frontend` opts in; direct Vite runs default off. Loopback address, exact local Host/Origin, POST, and a custom header are required. It obtains the normal HttpOnly session from backend login using server-side `.env` credentials. No passwords are returned or bundled; production builds have no bootstrap endpoint. No backend authentication or scan policy changes.
- Selected assessments now appear before scan history. Status reason and progress are visible while running. Overview history is limited to the latest eight entries.
- `pnpm --dir frontend test:local`: URL-scope and session-boundary tests pass. Live checks confirm foreign origin/host, absent origin/header return 403; GET returns 405; valid local bootstrap returns 204 and the authenticated API returns 200.
- Production build passes. URL form and assessment layout have no document overflow at 390 and 1440 CSS pixels.
- A real form submission for the previously authorized `https://stage.slicerninja.com/` created scan `9a0c0bae-3247-44f8-849a-e8701fb9ad82`, advanced from queued to testing to reporting. Runtime flags report browser, scanner tools, and adaptive execution enabled. These settings indicate availability, not proof that every check executed successfully; report coverage remains authoritative.

Live form verification finished: scan `9a0c0bae-3247-44f8-849a-e8701fb9ad82` reached `completed_partial`, with 5 findings, 9.1% coverage, and no overall score (`insufficient_coverage`). The status explicitly identifies incomplete testssl coverage. Both HTML and JSON report exports returned HTTP 200. Browser reload restored the selected scan and displayed all five findings. This verifies URL-to-report operation, not full scanner coverage; the testssl/coverage limitation remains visible for follow-up.

## Radar selected and timeout diagnosis

Operator selected motion option 01. The live status card uses the radar sweep, shows immediately while submitting, scrolls into view, follows backend scan phases, and stops on terminal/paused states. No play/pause controls. Browser fixture checks: five running artwork animations, zero in reduced-motion mode, terminal state removes the running indicator, zero scan-start requests during the test. Timeout/interrupted partial scans now say "Scan stopped before completion" instead of "Report ready".

Read-only diagnosis of scan `e909a103-bfa6-4432-addb-b9a445ef31f2`: saved status records worker stop at 301 seconds. Broker budget records 217 admitted requests and 187 pages; only stdout observation evidence survived, with no crawl surface bundle. Source inspection found the crawler's old wall limit was request timeout × 60 (600 seconds by default), while its supervisor terminates the process at 300 seconds. Crawl artifacts are emitted only after crawl return. This mismatch can erase assessment coverage for a busy crawl. A separate issue eagerly consumed all tool results before printing any.

Prepared backend changes, NOT deployed while another scan is active:
- Coordinator supplies a crawl allowance capped at 40% of worker runtime and the scope wall-clock budget (120 seconds with the current 300-second worker).
- Crawler checks that allowance before requests/redirect hops and while receiving bodies, records the stop reason, and returns already collected responses for artifact emission.
- Scanner results are emitted as each tool finishes instead of being buffered behind all tools.
- Focused crawler + containment suites: 35 passed. Ruff passes for touched backend files; frontend production build passes.

This is a tested source patch, not verification that the interrupted public scan now succeeds. Deploy the coordinator/worker image changes only after running assessments finish and the no-interruption constraint can be met. The worker's hard limit stays in place; later tools may still exhaust it, but earlier emitted artifacts are retained. No server restarts or new target scans were performed during this diagnosis.

### Follow-up: actual AI participation and long-run limits

Inspected the failed scan's saved report and live supervisor settings. Its public model ledger contains one attempt: role `script`, model `zai-org/GLM-5.3`, provider `https://api.commandcode.ai/provider/v1`, result `APITimeoutError`, overall state `unavailable`, cost unknown. No completed planner call or follow-up hypotheses are recorded; browser artifact is null and scanner_results is empty. Thus enabling adaptive execution did not produce successful AI reasoning in this run.

Live settings: worker runtime 300 seconds; overall wall clock 2700 seconds; 300 pages; depth 4; 5000 requests; 2 requests/second and 2 in flight; 10-second request timeout; 6 adaptive tasks, 3 rounds; 30 model calls; $5 model budget; planner timeout 60 seconds. These are independent ceilings. A five-hour mode is not implemented by the prior crawl-preservation patch.

Current host behavior: DNS resolution/address validation is implemented in scope registration and broker handling. Crawler `_record_host` stores non-primary linked hosts as `inventory_only` and never fetches them. No general subdomain enumeration or reverse-IP/shared-host scanning pipeline was found. Related hosts require distinct authorized scopes before assessment.

A reliable longer assessment requires configurable overall duration, checkpointed/resumable crawl batches and per-tool tasks, independent tool deadlines, progressive evidence ingestion, and model retry/fallback with explicit unavailable states. Merely increasing the monolithic worker timeout will not address the all-at-end capture problem or provider timeout.

## GLM fallback and circuit breaker (29 September 2026)

Added GPT-5.6 Sol with medium reasoning as the configured fallback for the GLM-5.3 text roles. Added a Redis-backed shared circuit, two-failure threshold, 60-second cooldown, single leased recovery probe and stale-result fencing. Gateway now honors the configured 60-second provider timeout rather than silently capping it at 30 seconds. Coordinator reserves both attempt slots and their budget allowance, and its gateway timeout covers the complete route chain. Refusals do not trigger fallback. Details and limitations: `docs/MODEL_FALLBACK.md`.

Validation before deployment: 58 focused tests passed; four live text-role fallback checks passed with an injected primary timeout. `runs/fallback-chain-qualification.json` records actual fallback attempts. Qualified synthetic script proposals were not executed.

Updated local `.env` through server-side tooling without printing credentials. Built new API and crawler images, froze their IDs, loaded the crawler image into the dedicated worker VM, and recreated local backend services with the worker-VM override. No running scan existed at deployment; the prior scans were terminal and one unrelated old queue entry remained untouched. Redis, Postgres, frontend and animation-study servers were not restarted. The runtime check confirms GPT-5.6 Sol/medium for all three text-role configurations, reachable shared Redis and the dedicated worker VM connection.

The earlier tested crawl/artifact-preservation patch is now included in the deployed image. Existing worker/overall limits are unchanged; this is not a five-hour resumable-scan implementation.

Repeat scan `ddc74783-91d5-4aa3-ac26-10cf8b4f2236` uses the same scope as failed scan `e909a103-bfa6-4432-addb-b9a445ef31f2`, `https://www.alliance.edu.in`, with adaptive assessment requested. Results are being captured in `runs/fallback-validation/`. Do not infer completion from submission or enabled settings.

### Repeat-scan result

Repeat scan finished at 2026-09-28 20:48:26 UTC after 6 minutes 48 seconds. It returned `completed_partial`, with 110 fetched pages, seven browser actions, five findings (four Low and one Informational), and saved HTML/JSON exports. Coverage is 4.5%; an overall numeric score is correctly withheld.

All 15 logical model calls completed. The complete ledger shows one real fallback: a planner attempt on GLM-5.3 returned `ValueError` after 42.249 seconds, then GPT-5.6 Sol completed the same proposal call in 5.304 seconds. The adapter reports only the exception class for the primary, so the record does not distinguish schema failure from an incomplete response. Other completed calls include browser interpretation, planning, verification, local-artifact script generation and report prose. The generated local analysis also completed in its existing isolated execution path. Six adaptive hypotheses ended as three corroborated and three inconclusive; those states are not equivalent to six confirmed vulnerabilities.

Remaining scan limitations, separate from provider fallback:
- Crawl reached its explicit 120-second allowance; the retained evidence fixes the prior zero-evidence failure but does not establish complete site coverage.
- ZAP returned exit 1, failed to write its log/report output, and produced malformed/missing JSON.
- Nuclei returned exit 1 with `no space left on device` in its worker scratch area. This is a concrete resource defect for the scanner worker to investigate with a local reproduction.
- testssl remains partial for engine/GOST and proxy-unsupported checks.
- The conditional configuration pack records no reviewed endpoints enabled for this origin/profile. No additional endpoint authority was invented for the repeat test.

Results: `runs/fallback-validation/summary.json`, `repeat-export.json`, `repeat-export.html`. Provider fallback is tested and deployed; scanner completeness and multi-hour resumable execution are not claimed complete.

## 29 September: discovered hosts and scanner resource repair

The dashboard now requests the existing hosts endpoint and displays source evidence, search,
show-all, and assessment-target versus discovered-only labels. The saved customer scan lists
42 hosts, including `portal.alliance.edu.in` and `student.alliance.edu.in`. Browser checks
covered those entries, search, expansion, mobile overflow, and a failed refresh retaining the
last inventory without creating a scan. TypeScript and the production frontend build passed.

The summary now provides nullable `discovery` with page count and stop reason. The deployed
API was checked against the original saved report and returned 110 pages and its 120-second
stop reason. Original reports have not been rewritten as complete.

Scanner batching, scratch cleanup, bounded subprocess logs, and coordinated time allowances
are deployed. See `docs/SCANNER_RESOURCE_REPAIR.md` for measurements and remaining limits.
The offline 110-page experiment completed all 11 batches; the subsequent deployed lab run
completed both ZAP and Nuclei with evidence. Public portal/student assessments use separately
registered scopes after the operator confirmed all college-owned subdomains.

## 2026-09-29 — Evidence-based host investigation order

Discovered-host inventory now displays the backend's read-only priority plan, with
expandable reasons, concrete next steps, missing-test-account labels, and a link to the
latest owner-visible assessment. Owned applications appear before external dependencies;
all inventory entries remain searchable. Priority is explicitly separate from vulnerability
severity and security scores. No scan is started by viewing or expanding a host.

Verification: frontend production build and `frontend/tests/host-inventory.browser.mjs`
passed (42 rows, evidence ordering, details, search, mobile overflow, failed refresh,
zero mutation requests). Live API confirmed 42 entries and 10 configured-domain matches.
See `HOST_PRIORITIZATION.md` for backend and browser-readiness verification.
