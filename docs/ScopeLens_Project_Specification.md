# ScopeLens — Project Specification

**Owner:** Aditya Pratap Singh  
**Version:** 1.1 · 24 September 2026  
**Status:** Implementation baseline; capabilities and accuracy remain unproven until tested.  
**Companion:** `ScopeLens_Implementation_Plan.md`

## How to use these two documents

This is the primary specification: what ScopeLens is, its users, scope, behavior, scan catalogue, confirmation boundaries, reporting and pilot scoring. The companion plan explains how to build it, the architecture and dependencies, milestones, testbeds and release gates. Keep both files in `docs/`. They replace the earlier requirements and architecture-audit handoff; a third audit document is not required.

Product behavior, permitted assessment scope and scoring are defined here. The plan defines implementation order and technical acceptance. If a conflict appears, flag and resolve it explicitly; never silently relax scope, proof or coverage rules. An experimental capability is not a supported product claim.

**Decisions recorded in this revision:** ScopeLens is the project name. Model access stays provider-flexible: direct OpenAI, OpenRouter-supported models and qualified open-model endpoints. Self-hosted labs come first; Aditya's explicitly registered owned sites are the first real-world pilot targets. Numeric category/field scores remain in v1, clearly labelled **Pilot assessment score — uncalibrated** and subject to evidence/coverage gates. The pasted severity-only suggestion does not remove the earlier numeric-score requirement.

**Delivery boundary:** v1 is the operator-only, external unauthenticated profile with interactive public-browser coverage. Authenticated API/role testing is an explicit next milestone, with lab fixtures prepared early. Using a rich authenticated lab does not imply that v1 can already test all its features. No production scan or benchmark has been run while preparing these documents.

## Contents

- [1. Overview & Vision](#1-overview--vision)
- [2. Guiding Principles](#2-guiding-principles)
- [3. Goals & Non-Goals (MVP v1)](#3-goals--non-goals-mvp-v1)
- [4. Users & Personas](#4-users--personas)
- [5. Scope — Full Vision vs the MVP v1 Slice](#5-scope--full-vision-vs-the-mvp-v1-slice)
- [6. FR-1 — Target Intake & Scan Lifecycle](#6-fr-1--target-intake--scan-lifecycle)
- [7. FR-2 — Reconnaissance & Attack Surface Mapping](#7-fr-2--reconnaissance--attack-surface-mapping)
- [8. FR-3 — Vulnerability Detection & Safe Confirmation](#8-fr-3--vulnerability-detection--safe-confirmation)
- [9. FR-4 — Reporting & Dashboard](#9-fr-4--reporting--dashboard)
- [10. Vulnerability Test Catalog](#10-vulnerability-test-catalog)
- [11. System Architecture (high-level)](#11-system-architecture-high-level)
- [12. Authorization, Execution Controls & Audit](#12-authorization-execution-controls--audit)
- [13. Quality, Platform Security & Data Requirements](#13-quality-platform-security--data-requirements)
- [14. Technology Direction & Tool Selection](#14-technology-direction--tool-selection)
- [15. Phases, Evaluation & Acceptance Criteria](#15-phases-evaluation--acceptance-criteria)
- [16. Requirement Decisions, Review Status & Sources](#16-requirement-decisions-review-status--sources)
- [17. Adaptive Tools, Browser Control, MCP & Skills](#17-adaptive-tools-browser-control-mcp--skills)
- [18. Durable Execution, Evidence Integrity & Release Gates](#18-durable-execution-evidence-integrity--release-gates)
- [19. References, precedence and handoff](#19-references-precedence-and-handoff)

## 1. Overview & Vision

**What it is.** A SaaS platform that runs automated, agentic dynamic application security testing (DAST) — a self-serve security assessment for web properties, with continuous operation on the roadmap. A user submits a target; an orchestrator agent maps the target's attack surface and then coordinates specialized sub-agents that drive a security toolchain inside an isolated sandbox to detect and safely confirm vulnerabilities. Results are presented in a professional dashboard as plain-English findings with remediation guidance.
**Category.** Agentic DAST / automated web pentesting — the space occupied by tools like OWASP ZAP, Nuclei, Burp Suite, Detectify, StackHawk, Intruder.io and Pentera. The differentiator is an LLM-orchestrated agent layer that reasons about the specific target and adapts its test plan, rather than replaying a fixed script, and that produces reports a non-security stakeholder can act on.
**Why it matters.** Scanner findings often need interpretation and validation; human penetration testing adds contextual depth but requires specialist time. The product goal is repeatable automated checks, evidence-backed confirmation and clear reporting. Accuracy and equivalence to a human assessment must be measured, not assumed.
**One-liner.** Verify your site, assess its exposed security controls, and get clear evidence and prioritized fixes.

## 2. Guiding Principles

These are product laws, not preferences. Every feature is checked against them.

1. **Plain-English findings, no weaponized payloads.** Reports explain *what* is wrong, *where*, *why it matters*, and *how to fix it* — in language a non-security stakeholder understands. They never ship a copy-paste exploit string (e.g. the actual injection query). This is a reporting and usability requirement; authorization and execution controls remain necessary regardless of how the report is written.
2. **Confirm, don't guess.** A finding is labelled confirmed only when its defined evidence criteria are met, through direct observation or controlled verification as appropriate. Reported-but-not-real findings are the fastest way to lose trust, so unverified signals retain Potential or Inconclusive evidence status and confidence reasons; severity remains a separate dimension.
3. **Non-destructive by design.** Testing is designed to minimize impact: no intentional deletion, modification or extraction of real records, account lockout or availability disruption. Even crawling can trigger side effects. Production checks avoid state changes; controlled writes require an approved lab/staging fixture and cleanup. Some flaw validation exercises vulnerable behavior, so use the smallest approved proof and stop when it is sufficient.
4. **Consent before execution.** No scan runs against a target the user has not been authorized to test. (The private prototype uses a recorded scope and operator allowlist; public self-service requires domain-control verification plus authority and scope acknowledgement — see §12.)
5. **Auditable and accountable.** Every scan records who ran it, against what, when, and what was done — a defensible trail for both the operator and the customer.

## 3. Goals & Non-Goals (MVP v1)

**Goals — v1 is successful if:**

- An authorized Operator submits an approved target URL and gets a completed or explicitly partial assessment with coverage and limitations.
- The engine performs bounded reconnaissance (crawl + inventory-only subdomain/linked-host discovery + tech fingerprinting) to build a map of the observed attack surface before testing.
- The engine runs a curated set of high-confidence passive and active-non-destructive checks against that surface.
- Findings are safely confirmed to keep the false-positive rate low.
- Results render in an HTML dashboard with plain-English write-ups, severity, location, evidence, and remediation — no raw exploit payloads.
- All work runs inside an isolated sandbox and is fully logged.
- Every security category and assessed input location displays a score where evidence is sufficient, or an explicit unassessed state, plus coverage (§9.4–§9.10).

**Non-Goals — explicitly not in v1** (tracked in §15):

- Polished/production UI design (v1 dashboard is functional HTML only).
- Self-service ownership-verification UI (deferred during the private Operator-only prototype). A manually configured target allowlist and recorded authorization are mandatory from the first scan; self-service launch cannot defer the authorization gate.
- Authenticated / logged-in-area scanning.
- Exhaustive coverage of all \~50 checks (v1 ships a confident subset — see §10).
- Exhaustive SPA state exploration, authenticated multi-role workflows and full GraphQL abuse testing. Bounded interactive browser exploration is included in v1.
- Continuous / scheduled monitoring, multi-tenant billing, and auto-remediation.

## 4. Users & Personas

- **Operator (v1 = you).** Submits targets, monitors scans, reviews raw findings. Technical; can read evidence and tune the engine.
- **Security-conscious founder / developer (primary future buyer).** Owns a web app, has no dedicated security team, wants to know what's exposed and how to fix it. Reads the dashboard, needs plain English and clear remediation — not CVSS jargon alone.
- **Agency / consultant (secondary buyer).** Runs scans on behalf of their own clients; needs clean reports they can white-label and hand off.
- **Compliance / non-technical stakeholder (report consumer).** Doesn't run scans but reads the output; cares about severity, trend, and "are we okay?" — the strongest reason plain-English reporting is a product law.

For v1, only the Operator persona needs to be served end-to-end; the report is written for the founder/developer from day one.

## 5. Scope — Full Vision vs the MVP v1 Slice

**The tension to name up front.** The target vision is broad — take a URL, crawl it, discover subdomains, find linked hosts, and test web apps, REST APIs, GraphQL APIs and SPAs across \~50 vulnerability classes. That is the right *destination*. But an MVP that tries to do all of it does none of it reliably and never ships. The recommendation is to build the full architecture so the broad scope plugs in later, while v1 proves the core loop on a deliberately narrow slice.
**Full product scope (the destination):**

- Recon: deep crawl, subdomain enumeration, linked/related-host discovery, technology and framework fingerprinting, full endpoint + parameter inventory.
- Targets: classic multi-page web apps, SPAs (JS-rendered), REST APIs, and GraphQL APIs.
- Coverage: the full \~50-check catalog in §10, including business-logic and API-specific classes.
- Modes: unauthenticated and authenticated; one-off and continuous monitoring.

**MVP v1 slice (what actually ships first):**

- **Input:** a single target URL.
- **Recon:** same-origin crawl (scheme + host + port, bounded depth/page cap) + lightweight subdomain discovery (passive sources) + linked-host listing + tech fingerprinting. Discovered hosts are *inventoried and shown* but only the primary target is actively tested in v1.
- **Targets:** server-rendered applications, bounded public SPA interaction and approved REST endpoints. The browser agent operates menus, dialogs, forms and routes using DOM/accessibility observations with visual fallback. Deep authenticated workflows and GraphQL abuse tests remain later.
- **Coverage:** the curated v1 profile in §10.3, subject to per-check confirmation and release gates; the broader catalogue remains the roadmap.
- **Mode:** unauthenticated only in the first release; authenticated test-identity support follows in milestone M6 of the plan.
- **Output:** functional HTML dashboard.

This keeps every ambitious scope item on the roadmap (§15) while giving v1 a boundary it can actually hit. Initial crawl caps and check boundaries are defined in §12 and §10.3. They are pilot defaults to validate, not unresolved architecture questions.

## 6. FR-1 — Target Intake & Scan Lifecycle

**Intake**

- User submits a single target URL (v1). System normalizes it (scheme, host, port, path) and resolves DNS.
- Basic input validation: reject malformed URLs, reject disallowed targets (localhost, RFC-1918 private ranges, cloud-metadata IPs, and any explicit denylist) to prevent the platform being used to hit internal infrastructure.
- A scan is created only after the target passes the configured authorization and scope checks, then enters `queued`, tied to the Operator and immutable scope/profile versions.

**Lifecycle states**
`queued` → `recon` → `planning` → `testing` → `confirming` → `reporting` → `completed`. Terminal alternates: `completed_partial` (limits or missing coverage), `failed` (with reason), and `cancelled` (Operator-initiated). An optional `paused` state must preserve remaining budgets and revalidate authorization before resuming.
**Requirements**

- Scans run **asynchronously** as background jobs; the UI never blocks on a scan.
- Each scan gets a unique id and a live status the dashboard can poll (current phase, progress, count of findings so far).
- Operator can **cancel** an in-flight scan; the engine tears down its sandbox cleanly on cancel or failure.
- Concurrency: v1 may cap simultaneous scans (e.g. one at a time) to keep the sandbox model simple; the queue holds the rest.
- Every state transition and every tool invocation is logged (§12).
- Idempotency/dedupe: use Operator/tenant, normalized target, scope, profile and credential-role set. A duplicate within that identity returns the running scan; it must never disclose another tenant's scan.

## 7. FR-2 — Reconnaissance & Attack Surface Mapping

Recon runs before any vulnerability testing and produces the **attack-surface map** every later phase works from. Requests are bounded and monitored; discovery is not assumed to be free of side effects.
**7.1 Crawling & content discovery**

- Fetch and parse the target, following in-scope links to a bounded depth and page cap (v1 stays on the approved primary origin and paths).
- Extract endpoints, forms, input fields, query parameters, cookies, and headers.
- Discover common paths (robots.txt, sitemap.xml, and a wordlist of well-known files/dirs) to surface unlinked content, respecting politeness limits (§12).
- For SPAs, v1 explores a bounded set of interactive DOM/page states and captures resulting API calls. Track route, role, frame, state signature and action history. Cap interactions and replay only approved safe navigation; exhaustive state discovery is not promised.

**7.2 Subdomain & host discovery**

- Passive subdomain enumeration (certificate-transparency logs, public DNS datasets) plus light active resolution.
- Identify linked/related hosts referenced by the target (asset domains, APIs, third-party embeds).
- Output a host inventory. In v1 these are *listed and shown on the dashboard* but not actively tested — active multi-host testing is a scope expansion (§15).

**7.3 Fingerprinting & classification**

- Identify server, framework, CMS, language, and notable JS libraries with versions where possible.
- Detect the presence of REST endpoints (and any OpenAPI/Swagger spec), GraphQL endpoints, and whether the app is server-rendered or a SPA.
- Flag WAF/CDN presence, since it changes how tests should be paced and interpreted.

**7.4 Output**

- A structured attack-surface map: hosts, endpoints, parameters, forms, detected tech, and classification. This feeds the planning phase, which decides *which* checks from §10 apply to *which* endpoints.

## 8. FR-3 — Vulnerability Detection & Safe Confirmation

I want ScopeLens to distinguish a real, evidenced weakness from a suspicious response. I use the following detection and confirmation rules: **collect the least-impact evidence sufficient for the stated claim, within the approved scope, and omit executable exploit payloads from customer reports.**
**8.1 Passive detection**
Observes responses already gathered during recon, such as headers, cookies, error details and delivered JavaScript. Dedicated file discovery, protocol handshakes, browser validation and endpoint probes are separate bounded network operations. Component/CVE matches and suspected secrets need applicability checks. Passive analysis itself adds no target traffic, but the underlying collection is not zero risk.
**8.2 Active, non-destructive detection**
Sends crafted-but-benign inputs to inputs, parameters, and endpoints to see whether the app behaves in a way that reveals a weakness — within reviewed limits. Production mode excludes destructive operations, password guessing and side-effecting workflows; markers and HTTP GET requests are not automatically harmless.
**8.3 Safe confirmation — the false-positive control**
The distinction that matters: **confirmation** (internal — did the flaw actually trigger?) is separate from **disclosure** (external — what the report shows). The engine confirms; the report describes.

- Confirmation uses the least intrusive approved proof sufficient for the stated condition, avoiding harmful effects. Illustrative *categories* of bounded signal (not payloads):
  - *Reflection/execution context*: reflection is a candidate signal; confirmed XSS requires a harmless execution marker in an isolated scanner-controlled browser, where the test is approved. No action is performed in another user's session.
  - *Differential/behavioral*: use repeated controlled comparisons and baseline/negative controls; a single response difference or slow response is insufficient. Timing-based confirmation is excluded from the default production profile and requires separate staging approval and strict delay budgets.
  - *Out-of-band*: for blind classes, use a dedicated operator-controlled callback with per-test correlation; distinguish a server callback from browser/link-preview/security-scanner activity. This can establish a fetch primitive, not automatically access to internal resources. No internal or metadata probing.
- Each confirmation stores **redacted evidence** (sanitized request/response excerpt showing the condition) sufficient for a security reviewer, but the copy-paste weaponized input is **not** included in customer-facing output.
- Anything the engine cannot safely confirm retains a *Potential* or *Inconclusive* evidence status with confidence reasons; its possible severity remains separate and it is never presented as a confirmed vulnerability.

**8.4 Evidence status, confidence and severity**
Keep three dimensions separate: evidence status = Confirmed / Potential / Inconclusive; confidence = High / Medium / Low with reasons; severity = Critical / High / Medium / Low / Informational. Informational is not a confidence tier. A confirmed missing defense may be Low severity; an unconfirmed account-takeover hypothesis may have potentially High impact. Candidate impact must never be presented as demonstrated impact. Only confirmed, unresolved scored weaknesses affect posture scores; unresolved candidates remain visible and keep affected checks inconclusive.

## 9. FR-4 — Reporting & Dashboard

The deliverable is the report. v1 targets a *functional* HTML dashboard — professional structure, not polished visual design (§3).
**9.1 Dashboard views**

- **Scan summary:** target, scan status/date, an at-a-glance risk posture (counts by severity), and the attack-surface overview (hosts, endpoints, detected tech).
- **Findings list:** all findings, filterable/sortable by severity and confidence.
- **Finding detail:** the full write-up per finding (schema below).
- **Host inventory:** discovered subdomains/linked hosts, flagged as tested vs. inventory-only.

**9.2 Finding schema** (each finding carries)

- **Title** — plain-English name of the issue.
- **Severity** — Critical / High / Medium / Low / Info (v1). CVSS score optional/later.
- **Evidence status and confidence** — separate fields as defined in §8.4.
- **Location** — affected URL(s), parameter/field, or header.
- **What it is** — plain-English description of the weakness.
- **Why it matters** — business impact in stakeholder terms (what an attacker could achieve).
- **Evidence** — redacted request/response excerpt proving the condition. **No weaponized payload.**
- **Remediation** — concrete, prioritized fix guidance.
- **References** — OWASP/WSTG/CWE links for the reviewer who wants depth.

**9.3 Requirements**

- Reports are generated from structured finding data (not free-text), so the same data can drive the dashboard, a downloadable export, and future formats.
- v1 export: at least a self-contained HTML report; JSON export of findings for programmatic use. PDF is a fast-follow.
- The plain-English + no-payload rules (§2) are enforced at the reporting layer, not left to the model's discretion per finding.
- Empty-state and partial-scan handling: a scan that finds nothing still produces a clean "no confirmed issues found in completed checks" report with coverage. Blocked or incomplete tests cannot be presented as clean passes.

### 9.4 Required scorecards — every category and tested location

The product SHALL display a **0–100 Pilot assessment score — uncalibrated**, where higher is better, for every category with sufficient evidence. Each tile also shows coverage, confirmed severity counts, unresolved candidates, profile, scan time and the reason for any missing score. Use `Not assessed`, `Insufficient coverage`, or evidence-backed `Not applicable` when a number would be misleading. Never silently substitute 0 or 100 for an unknown result.

Offer drill-down at three levels: overall profile → security category → canonical check and affected route/parameter. An input field such as a search parameter shows its applicable checks and outcomes; it does not get a SQL, XSS or other pass merely because a different field was tested. A field score, when eligible, uses the same rubric restricted to that field, and never replaces the category's worst-impact warnings.

### 9.5 Categories and fixed profile weights

These weights are a proposed product rubric, **not OWASP weights or CVSS**. Freeze them in `score-v1.0` after pilot review; any change creates a new version. Each confirmed root cause has exactly one primary scoring category; other mappings are informational links, preventing double deduction. Freeze control-to-category mapping in the profile; agents cannot move a finding to a lower-weight category. For a root-cause group, deduct the highest evidence-supported severity among its unresolved instances.

| ID | Security field | External unauthenticated v1 weight | Future extended profile weight | What belongs here |
|---|---|---:|---:|---|
| C01 | Transport and encryption | 15 | 8 | HTTPS, certificate, TLS and mixed-content behavior |
| C02 | Server and session-cookie configuration | 15 | 8 | Cookie/deployment configuration; extended profile adds logging/alerting evidence |
| C03 | Injection resistance | 20 | 15 | SQL, NoSQL, command, template and other server-side injection |
| C04 | Browser and cross-origin security | 15 | 10 | XSS, effective browser policies, CORS and browser trust boundaries |
| C05 | Data exposure and privacy | 15 | 8 | Sensitive files, errors, caching, referrer and credential leakage |
| C06 | Components and dependency exposure | 10 | 6 | Corroborated component advisories and applicable integrity controls |
| C07 | API exposure and integration controls | 10 | 10 | API inventory, schema/limits, WebSockets and integration boundaries |
| C08 | Authentication and session lifecycle | — | 10 | Login, recovery, MFA, token validation, rotation and revocation |
| C09 | Authorization and tenant isolation | — | 10 | Object, function, property and tenant permissions |
| C10 | File handling and server-side request controls | — | 8 | Upload/inclusion/traversal, SSRF and parser/file controls |
| C11 | Business rules, integrity and abuse controls | — | 5 | Workflows, replay, concurrency, cost controls and fail-closed behavior |
| C12 | Domain and asset lifecycle | — | 2 | Explicitly approved host lifecycle checks and dangling-resource indicators |
| **Total** | | **100** | **100** | |

Scoring ownership examples: API resource ceilings and webhook authenticity/replay belong to C07; end-to-end workflow abuse and transaction idempotency belong to C11. Insecure credential submission belongs to C05, with C01 as a reference-only mapping. Assign each registry control one owner before the scan.

V1's overall number is labelled **External unauthenticated pilot assessment score — uncalibrated**. It must not be labelled a whole-website security score. The other five category tiles remain visible as `Not assessed in this profile`. The future extended profile also covers only its declared tests; it is not a certificate of complete security.

### 9.6 Deterministic scoring formula

The score measures unresolved, confirmed weaknesses observed under the selected profile. It does not estimate breach probability or percentage of the website that is secure. All deductions and caps must be inspectable.

| Confirmed severity | Deduction per distinct root cause | Required qualification |
|---|---:|---|
| Critical | 65 points | Evidence supports the stated critical impact within the approved conditions |
| High | 35 points | Evidence supports the stated high impact |
| Medium | 15 points | Contextual, material weakness with documented impact |
| Low | 3 points | Limited-impact weakness or applicable defense gap |
| Informational | 0 points | Discovery, context or observation without a scored weakness |

For a category: **raw score = max(0, 100 − sum of deductions for its confirmed unresolved root causes)**.

Apply these non-compensating caps to categories and the overall profile score: any unresolved confirmed Critical caps the score at **39**; any High caps it at **69**. Use the lower of the raw score and relevant cap. Global caps include confirmed unresolved High/Critical findings on the same authorized assessed target even if their category is excluded from that numeric profile; out-of-scope inventory targets do not affect its score. Critical/High status must remain prominent even if coverage prevents publishing a numeric score.

Any unresolved Potential High/Critical candidate on the assessed target, including experimental/unmapped checks, puts the overall score into `Verification pending`; apply the category gate when its mapping is known. Confirmed risks and coverage remain visible.

For an eligible overall profile: **overall score = weighted mean of eligible category scores using the fixed profile weights, then apply the global severity cap and round to the nearest integer**. Calculate with full precision and round only for display. Evidence-backed fully N/A categories are removed and remaining fixed weights renormalized, with exclusions shown. Missing/blocked categories must not be dropped to produce a higher overall score.

Examples, assuming the coverage gate passes:
- One High and two Low root causes: 100 − 35 − 6 = **59/100**.
- One Medium root cause: **85/100**.
- One Critical root cause: **35/100**; the overall profile can never exceed 39 while that finding is unresolved.
- Zero confirmed findings with 10% coverage: **Insufficient coverage**, not 100/100.
- One missing protection affecting 500 pages: one root-cause deduction, with all 500 affected locations listed.

These coefficients and bands are initial product choices. Calibrate against expert-reviewed pilot cases before marketing the rating as meaningful. They are not a validated industry risk model. If CVSS is provided for an individual vulnerability, keep its version and vector separate; never derive the site score by simply reversing an average CVSS value.

### 9.7 Coverage and eligibility rules

Test execution state is Not started / Running / Finished. Test outcome is Pass within tested conditions / Confirmed issue / Inconclusive / Blocked / Error / Not tested / Not applicable. Only Pass within tested conditions and Confirmed issue are conclusive assessed outcomes; evidence-backed N/A removes that instance/control from the applicable denominator. Finding evidence status and confidence are separate fields.

A canonical control is a stable security requirement, not a tool template or request. Multiple scanner templates may implement the same control. A test instance is **control × normalized endpoint/input × role/context**. Normalize route parameters without merging different permission boundaries. Retain instance counts and samples in the report.

Before execution, freeze a versioned assessment plan with applicable control IDs, control weights, required instances, sampling rules and mandatory flags. Default control weight is 1; any exceptions are profile-defined before results. Discovery may expand the plan through an auditable revision. The agent cannot delete failed or expensive work from the denominator.

- A control is fully assessed only when all instances required by its declared sampling plan have a conclusive outcome. One failure confirms a finding immediately, but does not complete the remaining coverage.
- **Category control coverage = 100 × fully assessed applicable control weight / total applicable control weight in the profile plan.** Unsupported planned controls and unknown applicability remain in the denominator as unassessed.
- Show instance completion separately, plus discovered/reached routes, parameter locations, authenticated roles and crawl limits. Planned coverage is not a claim that all website routes were discovered.
- A numeric category score requires at least **80% control coverage**, all profile-mandatory controls assessed, and no unresolved Potential High/Critical candidate in the category. Otherwise show `Insufficient coverage` or `Verification pending`, with confirmed risks still visible.
- A numeric overall score requires every applicable category in that profile to meet its gate. If no categories are applicable, show `Not scored`.
- For field/check drill-down, require all of that field/check's planned instances to be conclusive. Zero applicable controls yields evidence-backed N/A or Not assessed, never a numeric pass. Confirmed findings remain visible while the field score is pending.
- Missing credentials, WAF/CDN denial, unreachable pages, unsupported technology, tool errors and exhausted budgets are **never a pass or N/A**.
- N/A requires a recorded reason and evidence of absence/inapplicability; failing to discover a feature is insufficient. Operator attestations are identified separately from observed evidence.
- If a profile deliberately samples endpoints, label the score `Sampled assessment` and show the strategy and sample size. A clean sample cannot assert that untested endpoints passed.
- An interrupted/cancelled scan cannot publish a completed overall rating. Eligible category results may be shown with an explicit partial-scan banner.
- Engine implementation coverage (supported controls / product backlog) is separate from assessment coverage (completed work on this target).

### 9.8 Rating labels, deduplication and finding lifecycle

| Score | Customer-facing label |
|---:|---|
| 90–100 | Strong observed posture |
| 70–89 | Needs improvement |
| 40–69 | Weak observed posture |
| 0–39 | Poor observed posture |
| No number | Not assessed / Insufficient coverage / Verification pending / Not applicable |

A score of 100 means no scored weaknesses were observed under the eligible declared profile; it never means invulnerable. Display open Medium/Low issues and unfinished non-mandatory coverage even in the highest band.

Deduplicate by canonical control/root cause, affected component and remediation boundary. Two tools observing the same weakness count once. Independent weaknesses with different fixes count separately. Equivalent protections, such as effective CSP frame restrictions versus a legacy frame header, are not charged twice. Similar descriptions alone are insufficient to merge findings. Reviewable merges/splits retain their history.

Accepted risk and dismissals do not automatically remove deductions. A verified false positive may be excluded with reviewer evidence; a fixed issue requires a successful relevant retest. A blocked retest or inaccessible endpoint is not proof of repair. An intentionally removed feature can be resolved only with evidence of its removal and no equivalent exposed route. Preserve prior confirmed issues when a later scan loses coverage; mark them `Previously confirmed — current status unverified` until resolved, and retain their effect for the same comparable scope.

### 9.9 Scoring examples for dashboard design

The following is illustrative product data, not a real assessment:

| Field | Score | Coverage | Display explanation |
|---|---:|---:|---|
| Transport | 97/100 | 100% | One Low issue; all planned checks completed |
| Injection | 65/100 | 100% | One confirmed High issue |
| Browser security | 85/100 | 90% | One Medium issue; required checks complete; remaining checks shown |
| Authentication | Not assessed | 0% | Login testing is outside this v1 profile |
| Authorization | Not assessed | 0% | Test roles and owned records were not supplied |

The overall external score is calculated only after all required external categories qualify. Even if its weighted average is higher, the confirmed High issue caps it at 69. The dashboard must show the reason for the cap and the findings responsible for every deduction.

### 9.10 Report schema additions and comparisons

Add stable finding ID, canonical control ID, primary score category, check/tool/configuration version, scope and scan IDs, endpoint/parameter/role, evidence status, confidence reasons, evidence reference/hash, first/last observed time, root-cause group, lifecycle status and retest result. Store proposed deductions and applied caps in a deterministic calculation record.

Report objects include profile/scoring versions, authorization/scope references, planned/executed controls and instances, N/A evidence, blocked reasons, suspected findings, score eligibility, score breakdown and coverage. Render target-supplied content as escaped text so the security report itself cannot execute it. Redaction applies to HTML and JSON exports, including hidden fields.

Compare scores only when scope, profile, scoring version, role set and sampling strategy match, and coverage is comparable. Show scope changes separately. If a rule update changes an old score, preserve the historical published score and label any recalculation. Do not advertise improvement solely because fewer areas were tested.

## 10. Vulnerability Test Catalog

The detection backlog, in plain English, to be mapped per test to versioned OWASP Top 10:2025, WSTG v4.2, ASVS 5.0.0 and API Top 10:2023 references where applicable. Items tagged **[v1]** are candidates for the curated MVP profile, subject to the evidence and release gates in §10.1–§10.3; a tag is not a detection guarantee. The rest are the roadmap toward full coverage.
**Injection**

- **[conditional v1]** SQL Injection — input is interpreted as query logic instead of data; can expose or alter records or bypass login.
- NoSQL Injection — same idea against Mongo-style databases via operator/object manipulation.
- **[staging/later]** OS Command Injection — input reaches a system shell; can run commands on the server.
- Server-Side Template Injection — input rendered by a template engine can lead to code execution.
- LDAP / XPath Injection — input manipulates directory/XML queries to bypass auth or extract data.
- CRLF / HTTP Response Splitting — newline injection forges headers or splits responses.
- **[staging/later]** Host Header Injection — a forged Host header poisons links, reset flows, or caches.

**Cross-Site Scripting**

- **[conditional v1]** Reflected XSS — untrusted input can execute in a browser when a crafted link is opened; reflection alone is not confirmation.
- **[authenticated/staging]** Stored XSS — script saved server-side and served to every viewer.
- DOM-based XSS — client JS writes untrusted data into the page and executes it.
- **[conditional v1]** HTML Injection — untrusted markup changes page content; validate harmless rendering effects without interacting with other users.

**Access Control / Authorization**

- Broken Access Control — users reach actions or data they shouldn't.
- IDOR / BOLA — changing an ID in a request to read someone else's record.
- Privilege escalation — normal user gains admin (vertical) or another user's scope (horizontal).
- **[conditional lab/staging]** Path / Directory Traversal — file access escapes its intended directory; confirm using an approved canary file, without reading real system/customer files.
- Forced browsing — enumerating hidden admin/unlinked URLs.

**Authentication / Session**

- Weak or default credentials still valid.
- No brute-force protection / no lockout.
- Session fixation — forcing a known session ID onto a victim.
- **[authenticated]** Weak session identifiers, inadequate expiry or failed invalidation. Finite observation cannot prove that a session never expires; test a specified policy and time window.
- Insecure password-reset flow enabling account takeover.
- JWT weaknesses — weak secret, unsigned tokens, unverified tokens.
- Missing or bypassable MFA.

**Cross-Origin / Request Forgery**

- CSRF — tricking a logged-in browser into an unwanted action.
- **[v1]** CORS misconfiguration — over-permissive origins leak data to other sites.
- **[v1]** Clickjacking — framing the site to steal clicks (missing frame protection).
- **[conditional v1]** Open Redirect — an unrestricted destination can send visitors from a trusted-looking link to another website.

**Server-Side**

- **[conditional staging]** SSRF — a server fetches an unintended destination; callback-only tests must establish the relevant restriction failure, not assume that all URL fetching is a flaw.
- XXE — abusing XML parsing to read local files or reach internal systems.
- Insecure Deserialization — crafted serialized objects trigger code execution or logic abuse.

**File Handling**

- Unrestricted file upload — a malicious file the server executes or serves.
- Local / Remote File Inclusion — app includes attacker-controlled files.

**Misconfiguration & Exposure** (mostly passive → strong v1 block)

- **[v1]** Missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).
- **[v1]** Directory listing enabled.
- **[v1]** Verbose errors / stack traces leaking versions, paths, secrets.
- **[v1]** Exposed sensitive files — `.git`, `.env`, backups, config files reachable.
- **[v1]** Secrets in client-side JS — API keys/tokens in front-end code.
- **[v1]** Exposed admin or debug interfaces.
- **[v1 observation]** HTTP method exposure. PUT/DELETE may be legitimate API methods; confirmation requires an unintended permission or behavior. Do not invoke destructive methods merely to see whether they work.
- **[v1]** Missing cookie flags (HttpOnly / Secure / SameSite).

**Transport / Crypto**

- **[v1]** Cleartext HTTP, mixed content, outdated TLS protocols/ciphers, expired certs.
- **[v1 observable exposure; internal logs later]** Sensitive data in URLs/responses, such as tokens or personal data. Internal log review requires customer telemetry access.

**Components & Supply Chain**

- **[v1]** Known-vulnerable server / CMS / framework with public CVEs.
- **[v1]** Outdated or abandoned JS libraries.

**APIs** (basic in v1, deep later)

- Excessive data exposure — an API returns fields the requesting identity is not permitted to access.
- Mass assignment — client sets fields it shouldn't (e.g. a role field).
- Broken function-level authorization — hidden API actions reachable without the right role.
- GraphQL introspection / unbounded queries.
- **[v1 observation; contextual testing later]** Rate-limit behavior. Missing rate-limit headers or no throttling within a small sample does not establish a vulnerability; endpoint policy and bounded approved validation are required.

**Business Logic & Misc**

- Business-logic flaws — abusing legitimate features (negative quantities, coupon stacking).
- Race conditions — timing abuse to double-spend or skip checks.
- **[v1 inventory; validation later]** Potential dangling DNS / subdomain takeover. Inventory is not proof of claimability. Never register or claim a third-party resource during a scan; v1 does not actively test discovered hosts.
- Web cache poisoning / deception.
- Prototype pollution.

### 10.1 Additional tests and explicit subchecks

The original catalogue covers many major families. These additions close gaps or split broad entries into separately reportable controls. They are proposed product requirements, not a guarantee that every class can be detected from a URL. **V1** = external, bounded checks; **V2** = authenticated/contextual checks; **V3** = controlled staging, integration evidence or human-assisted review.

| Add-on ID | Test or extension | Plain-English failure being checked | Phase / evidence boundary | Primary category |
|---|---|---|---|---|
| ADD-01 | Effective security policies | A header exists but its rules do not deliver the intended browser protection. | V1; evaluate effective CSP/frame/content-type policy, not presence alone. | C04 |
| ADD-02 | Cookie scope and isolation | A sensitive cookie is exposed to a broader application/domain context than needed. | V1 attribute review; V2 for demonstrated cross-application impact. | C02 |
| ADD-03 | Sensitive response caching | Private responses remain in an inappropriate shared or browser cache. | V1 when observable; V2 for seeded authenticated records and cross-user isolation. | C05 |
| ADD-04 | Referrer and credential transport | Links or form destinations leak sensitive values or send credentials over insecure transport. | V1 inspect without submitting real credentials. | C05 |
| ADD-05 | API inventory and version drift | Older or undocumented API routes remain exposed after a replacement. | V1 same-origin inventory; a customer baseline is required to call something undocumented/unapproved. | C07 |
| ADD-06 | HTTP parameter pollution | Layers disagree about repeated input fields, changing an intended security decision. | V2 bounded read-only cases; parser difference alone is not a vulnerability. | C03 |
| ADD-07 | Account enumeration | Login or recovery behavior reveals whether a specific account exists. | V2 with synthetic identities and a small approved request budget. | C08 |
| ADD-08 | Identity lifecycle | Disabled, unverified or deprovisioned identities retain unintended access. | V2 with test accounts and stated policy. | C08 |
| ADD-09 | Session rotation, logout and revocation | A supposedly ended or replaced session still works. | V2; include password change, idle/absolute expiry and refresh-token handling. | C08 |
| ADD-10 | OAuth/OIDC/SSO trust | A login integration accepts the wrong destination, client, issuer or account binding. | V2 approved test identity provider/flow; no unsolicited actions on external providers. | C08 |
| ADD-11 | Cross-tenant isolation | A user from one customer organization can access another organization's records. | V2 with two test tenants, roles and owned records. | C09 |
| ADD-12 | WebSocket security | A real-time connection permits an unintended origin/user to read or send messages. | V1 inventory; V2 handshake and message authorization with test data. | C07 |
| ADD-13 | Browser messaging and storage trust | A page trusts an unexpected sender or exposes sensitive data in browser storage. | V2 browser-assisted validation of messaging and storage behavior. | C04 |
| ADD-14 | Resource and cost controls | A request can consume excessive computation, returned data or billable services. | V1 observations only; V3 budgeted staging validation, without exhausting resources. | C07 |
| ADD-15 | Sensitive business-flow automation | Offers, reservations or messaging can be repeated beyond the intended business rules. | V2/V3 fixtures and explicit business limits; distinct from generic rate limiting. | C11 |
| ADD-16 | Webhook authenticity and replay | An unverified or repeated external event is accepted as legitimate. | V3 mock integration, test events and cleanup. | C07 |
| ADD-17 | Unsafe consumption of external APIs | Untrusted upstream responses control a sensitive downstream action. | V3 customer-owned mock upstream; do not test the third-party service. | C07 |
| ADD-18 | HTTP request desynchronization | Frontend and backend disagree about where a request starts or ends. | V3 dedicated environment; excluded from shared production scans. | C07 |
| ADD-19 | Exceptional conditions and fail-closed behavior | Invalid data or a dependency failure leaves a permission or transaction rule unenforced. | V1 error disclosure only; V3 controlled fault scenarios. | C05 for disclosure; separate C11 control for fail-closed behavior |
| ADD-20 | Logging and alerting effectiveness | Important security events are missing or produce no expected alert. | V3 customer telemetry; outside the v1 C02 profile/denominator; externally unobservable results remain Not assessed. | C02 |
| ADD-21 | Software and data integrity | External scripts or imported artifacts are trusted without appropriate integrity controls. | V1 relevant visible configuration; repository/build assurance is a separate future integration. | C06 |
| ADD-22 | Cache isolation and key correctness | One user's private or attacker-influenced response can be served to another. | V2/V3 isolated records/cache; extends poisoning/deception, never modifies a public shared cache by default. | C05 |

Expand existing umbrella items into separate registered controls: GraphQL discovery, field/object authorization and query limits; JWT integrity, issuer/audience/expiry and lifecycle; upload validation, storage access and serving behavior; prototype pollution detection versus demonstrated impact; and race conditions versus idempotency. One subcheck passing must not mark the umbrella family as fully covered.

### 10.2 Mandatory interpretation rules

- An admin page, GraphQL introspection, an API method, a version string or a discovered subdomain is inventory until its security significance is established.
- Public wildcard CORS can be intentional. Confirm access to a protected response from an unauthorized origin before reporting a data-exposure vulnerability.
- API fields absent from the UI are not inherently unauthorized. Use a role/field policy.
- Distinguish public client identifiers from private secrets. Do not exercise a discovered credential against any service. Stop collection after minimal redacted evidence.
- A component fingerprint is not conclusive CVE applicability. Corroborate exact component/version/configuration and account for vendor backports; unresolved matches remain potential.
- A component appearing old is a maintenance observation unless an applicable weakness or declared lifecycle violation is established.
- Do not mark an entire vulnerability class absent after a few clean probes. Report the endpoint, role, input and conditions actually tested.
- WAF presence or a blocked probe is not evidence that application code is secure. Report blocking and coverage separately.
- Advanced classes with no approved safe proof stay potential or unassessed; neither tool output nor model confidence substitutes for evidence.

### 10.3 V1 launch profile and check registry

The **initial core** covers certificate validity, approved TLS configuration, HTTP-to-HTTPS behavior, HSTS, mixed content, credential form destinations, effective browser policies, cookie attributes/scope, directory listing, bounded file-exposure indicators, verbose errors, secret candidates, corroborated component advisories, and same-origin API inventory. Broad items must be split into canonical check IDs before implementation is accepted.

The **conditional active pack** includes reflected XSS browser confirmation, SQL injection behavioral checks, HTML injection, open redirects and cross-origin behavior only where the test has a reviewed non-destructive method and the endpoint is approved. A profile that omits that pack is named `External configuration assessment`; it cannot inherit an injection score or be compared directly with the external DAST profile.

Stored writes, login guessing, command execution, delay-based probes, retrieval of real system/customer files through traversal, resource claiming, shared-cache mutation and multi-user request desynchronization are excluded from default v1 production execution. Publicly exposed-response checks may collect only the minimum capped excerpt needed to classify exposure, immediately redact secrets and stop. Repository reconstruction, bulk download and use of exposed credentials are prohibited. If minimal evidence cannot establish the condition, retain a Potential finding. They remain on the contextual/staging roadmap, with their observation-only capabilities identified separately.

Every executable check must have a registry entry containing:
- Stable ID, canonical control/root-cause mapping, category and mapped standard version/reference where applicable.
- Availability/phase, applicability evidence, prerequisite credentials/fixtures, allowed environment and approved tool/configuration version.
- Mandatory status and fixed coverage weight in each profile; unsupported planned checks remain unassessed.
- Allowed destinations, methods, response-size/time/request budgets, side-effect expectations, cleanup and stop conditions.
- Detection signal, negative controls, exact confirmation criteria, false-positive considerations and per-instance outcomes.
- Vulnerable and fixed benchmark fixtures, known blind spots, last review date and owner.

The initial engineering handoff must turn the named core and conditional checks into this registry. The requirements define the registry schema and release gate; they do not pretend the tool integrations or their evidence rules already exist.

### 10.4 Coverage statements and standards mapping

The dashboard separately answers: what the product can test; what this profile promises; what applies to this target; what actually ran; and what was confirmed. No checklist is presented as exhaustive coverage of every weakness.

Map each implemented check to relevant versioned guidance. Use OWASP Top 10 as broad awareness categories, WSTG as test guidance, ASVS as requirements, and API Top 10 for API risk families. A standards mapping does not demonstrate compliance with all requirements. Controls such as internal logging, at-rest encryption, backups, source-code quality and build-chain integrity generally require evidence beyond an external URL.

### 10.5 Per-family confirmation stance

These are ScopeLens defaults, not claims that these checks are implemented. **OBSERVE** can confirm a directly visible configuration/exposure without exercising a suspected exploit. **ACTIVE** permits a reviewed, bounded confirmation method on an explicitly approved endpoint after its release gate. **FLAG** means detect and flag a candidate if evidence exists; do not actively confirm that class in the production v1 profile. **FIXTURE** denotes a later enabled lab/staging or supplied-test-identity profile, not implicit permission to run it now. A flag is not automatically a finding; no supporting observation means Not tested or Not assessed.

Each row below is a catalogue family. Implement separate canonical controls for distinct subchecks; these family IDs must never be counted as 54 independently validated scanner checks. The 22 ADD items retain their narrower phase/evidence restrictions in §10.1. If a row and a check-specific rule differ, use the narrower allowance until reviewed.

| Family ID | Family | Production v1 stance | Confirmation boundary / later evidence |
|---|---|---|---|
| F01 | SQL injection | ACTIVE, conditional v1 | Repeated non-timing comparisons on an approved read-only input, with negative controls; no data extraction or login bypass demonstration. |
| F02 | NoSQL injection | FLAG in v1 | FIXTURE: synthetic records and expected query/permission outcomes. |
| F03 | OS command injection | FLAG | FIXTURE only, with a reviewed minimal proof; no command execution on production. |
| F04 | Server-side template injection | FLAG | FIXTURE: harmless evaluation evidence; no server compromise chain. |
| F05 | LDAP / XPath injection | FLAG | FIXTURE: seeded directory/XML data and expected permissions. |
| F06 | CRLF / response splitting | FLAG | FIXTURE: isolated response parsing; no shared-client or cache contamination. |
| F07 | Host-header injection | FLAG | FIXTURE: mock reset/link generation and isolated cache. |
| F08 | Reflected XSS | ACTIVE, conditional v1 | Harmless execution marker in the scanner-owned browser; reflection alone is insufficient. |
| F09 | Stored XSS | FLAG in v1 | FIXTURE/authenticated: disposable content and scanner-only viewers; verify cleanup. |
| F10 | DOM XSS | FLAG in initial v1 | FIXTURE/browser pack: harmless execution and source-to-sink evidence; promote only after its own release gate. |
| F11 | HTML injection | ACTIVE, conditional v1 | Harmless rendering change in the scanner-owned page; no misleading content served to other people. |
| F12 | Broken access control | FLAG in v1 | FIXTURE/authenticated: explicit permission matrix and seeded test identities. |
| F13 | IDOR / BOLA | FLAG in v1 | FIXTURE/authenticated: user A can access user B synthetic object contrary to policy. |
| F14 | Privilege escalation | FLAG in v1 | FIXTURE/authenticated: isolated role boundary; no access to real users or administration. |
| F15 | Path / directory traversal | FLAG | FIXTURE: predefined canary file; no real system/customer-file retrieval. |
| F16 | Forced browsing | OBSERVE/ACTIVE inventory | An accessible URL is not proof of unauthorized access; FIXTURE role comparison for that claim. |
| F17 | Weak / default credentials | FLAG | No production guessing; FIXTURE using explicitly seeded credentials and account policy. |
| F18 | Brute-force / lockout controls | FLAG | FIXTURE: small policy-defined attempt window; never exhaust or lock real accounts. |
| F19 | Session fixation | FLAG in v1 | FIXTURE/authenticated: only supplied test sessions and identities. |
| F20 | Session randomness, expiry, invalidation | FLAG in v1 | FIXTURE/authenticated: policy-specific rotation/expiry checks; finite samples cannot prove randomness or endless lifetime. |
| F21 | Password reset | FLAG in v1 | FIXTURE: test accounts and local mail sink, no external mail/SMS. |
| F22 | JWT integrity and validation | FLAG in v1 | FIXTURE/authenticated: signature, issuer/audience/time policy; no key cracking or using discovered secrets. |
| F23 | MFA | FLAG in v1 | FIXTURE: synthetic enrolled identity and documented workflow; absence alone may be policy-dependent. |
| F24 | CSRF | FLAG in v1 | FIXTURE/authenticated: harmless test action with an expected state change and cleanup. |
| F25 | CORS | OBSERVE; ACTIVE conditional | Header behavior may be confirmed as configuration; protected-data exposure requires authorized test identities and browser evidence. |
| F26 | Clickjacking | OBSERVE/ACTIVE, conditional | Evaluate effective frame policy and harmless framing; do not induce a real user action. |
| F27 | Open redirect | ACTIVE, conditional v1 | Inspect redirect behavior to a controlled destination; never follow into an unapproved origin. |
| F28 | SSRF | FLAG | FIXTURE: correlated operator callback and violated restriction; no private network/cloud-metadata probing. |
| F29 | XXE | FLAG | FIXTURE: synthetic parser fixture and approved canary/callback; no real-file extraction. |
| F30 | Insecure deserialization | FLAG | FIXTURE: instrumented harmless effect; no production code execution. |
| F31 | File upload | FLAG in v1 | FIXTURE/authenticated: harmless files, isolated storage, serving checks and cleanup. |
| F32 | Local / remote file inclusion | FLAG | FIXTURE: named synthetic files or controlled endpoint; no real system files. |
| F33 | Security headers and effective policy | OBSERVE | Assess actual policy and applicability; equivalent controls count once. |
| F34 | Directory listing | OBSERVE/ACTIVE bounded | Minimal directory response demonstrates listing; no recursive download. |
| F35 | Verbose errors / stack traces | OBSERVE | Confirm the disclosed information, not an inferred exploit; unusual error generation uses reviewed checks. |
| F36 | Exposed sensitive files | ACTIVE bounded, conditional | Minimum capped/redacted excerpt; no repository reconstruction, bulk download or credential use. |
| F37 | Client-side secret candidates | OBSERVE/FLAG | Classify public identifiers versus private material; do not authenticate with discovered credentials. |
| F38 | Admin / debug interfaces | OBSERVE/ACTIVE inventory | Login/interface presence is inventory; report a weakness only with separate exposure/permission evidence. |
| F39 | HTTP method exposure | OBSERVE/FLAG | Advertised methods are not flaws; do not execute destructive verbs to prove support. |
| F40 | Cookie flags | OBSERVE | Evaluate sensitive-cookie purpose, flags and equivalent protections in context. |
| F41 | HTTP, mixed content, TLS and certificates | OBSERVE/ACTIVE bounded | Observe browser content and use the constrained real-TLS lane; no availability stress. |
| F42 | Sensitive data in URLs/responses | OBSERVE | Minimal redacted evidence; internal logging requires supplied telemetry. |
| F43 | Component / CVE applicability | OBSERVE/FLAG | Corroborate version/configuration/backports; a banner or CVE match alone is not proof of exploitation. |
| F44 | Old / abandoned JavaScript libraries | OBSERVE/FLAG | Maintenance observation unless applicable weakness or declared lifecycle violation is established. |
| F45 | API excessive data exposure | FLAG in v1 | FIXTURE/authenticated: supplied field/role policy and synthetic records. |
| F46 | Mass assignment | FLAG in v1 | FIXTURE: permitted and forbidden synthetic field changes, with cleanup. |
| F47 | Function-level authorization | FLAG in v1 | FIXTURE/authenticated: role matrix and synthetic operations; hidden routes alone are inventory. |
| F48 | GraphQL discovery, introspection and query limits | OBSERVE/FLAG | Introspection is not inherently a flaw; FIXTURE authorization checks and bounded cost tests later. |
| F49 | Rate-limit behavior | OBSERVE/FLAG | No headers or a small unthrottled sample is not proof; FIXTURE policy-defined low-volume checks. |
| F50 | Business-logic flaws | FLAG in v1 | FIXTURE: explicit business rules and mock transactions/services. |
| F51 | Race conditions / idempotency | FLAG | FIXTURE: bounded synthetic concurrency, resettable records and no real financial effects. |
| F52 | Dangling DNS / takeover | OBSERVE inventory | Corroborate stale ownership indicators; never claim/register resources as proof. |
| F53 | Cache poisoning / deception | FLAG | FIXTURE: dedicated cache and canary users; no production shared-cache mutation. |
| F54 | Prototype pollution | FLAG | FIXTURE: isolate affected process/browser and prove relevant security effect, not only property mutation. |

## 11. System Architecture (high-level)

I want ScopeLens to investigate what it observes, choose a relevant next check, and stop when the evidence is sufficient or its budget is exhausted. The components below make that behavior explicit; framework choices are in §14.
**Components**

- **API / web layer** — accepts scan requests, serves the dashboard, exposes scan status and results. Stateless; talks to the queue and datastore.
- **Job queue + scan worker** — pulls queued scans and drives the lifecycle (§6). One worker owns one scan's sandbox.
- **Coordinator and planner** — LangGraph maintains an obligatory baseline plan alongside an adaptive hypothesis ledger. Agents interpret new observations, choose relevant follow-up actions and seek sufficient evidence. This applies to all supported vulnerability families; port discovery is only an optional example. The coordinator cannot silently drop required coverage or expand scope.
- **Specialist roles** — browser exploration/testing; web/API investigation; configuration/component assessment; and evidence verification. Discovery, parsing, scheduling, policy and scoring are primarily deterministic. Roles may share a process/model. Browser sessions have one action owner; parallel agents never independently drive the same tab.
- **Tool layer** — wrappers around established security tooling (crawler, scanner engines, header/TLS checkers, subdomain enumeration, fingerprinting). Each wrapper normalizes tool output into the common finding schema. The agents *drive* tools; they don't replace them.
- **Sandbox** — ephemeral curated Kali-based CLI workers and a separate Chromium worker; dedicated ZAP images may be used where practical. Containers share a host kernel, so customer/generated-code jobs require a dedicated worker VM or equivalently evaluated boundary. No privileged mode, host mounts, host network or Docker socket. An external supervisor and network controls enforce the approved execution lane (§17).
- **Datastore** — targets, scans, findings, evidence, and the audit log.
- **Evidence, verification and reporting** — a trusted collector records observations separately from interpretations. The verifier applies proof rules and may request bounded follow-ups. A deterministic service scores eligible results; the report writer explains them without changing evidence or scores.

**Data flow (one scan)**
`Approved request → durable scan/outbox → dispatch and lease → baseline discovery/browser exploration → hypothesis and task selection → policy admission → isolated action → trusted evidence → verification or bounded follow-up → coverage check → scores/report → teardown. Audit records are persisted throughout. Cancellation revokes execution authority before teardown; unfinished results remain partial.`
**Design notes**

- Agents propose actions; a **policy layer** enforces approved test profiles, scope and resource limits independently of model decisions. Approved probes can still cause unanticipated side effects, so monitor target health and record limitations rather than claiming zero impact.
- The tool layer is pluggable so new checks (and eventually multi-host/API/SPA depth) slot in without reworking the orchestrator.
- LLM cost and latency are controlled by doing deterministic work (crawling, tool runs, signature checks) in code and reserving the model for planning, adaptation, and write-up.

## 12. Authorization, Execution Controls & Audit

**Private prototype vs public launch.** V1 can be Operator-only with a manually maintained approved-origin allowlist and written scope record. It must not be a publicly accessible scan-any-URL endpoint. Self-service launch requires domain-control proof plus an authority/scope acknowledgement. The exact UX remains deferred; the enforcement requirement does not.

**Scope enforcement.** Pin scheme, hostname, port, approved paths, exclusions, permitted methods/checks and authorization expiry. Enforce HTTP-level scope through a trusted HTTP-aware execution path or inspecting proxy, with direct worker egress denied. Revalidate every request, redirect and browser subrequest. A CONNECT tunnel or IP allowlist alone cannot enforce encrypted path/method scope (§17.3). Include IPv4/IPv6, alternate address encodings, DNS changes/rebinding, localhost, private/link-local and cloud-metadata destinations. Discovered hosts/shared IPs are not automatically authorized. The LLM cannot broaden scope or bypass gateway decisions. For HTTP-to-HTTPS validation, record a separately approved transport-only HTTP origin limited to the initial redirect check; it is not permission to crawl another origin. Without that authorization, the check is unassessed.

**Dependencies.** Certificate/DNS/reference-data services and controlled callbacks use separately allowlisted infrastructure access. Target content cannot direct workers to arbitrary destinations. Cross-origin resources are blocked unless specifically approved; report resulting rendering gaps. Development labs use a separate isolated lab profile allowing only named lab services, not an exception that lets public SaaS users reach internal infrastructure.

**Initial limits to validate in the lab.** One concurrent scan; 2 requests/second and 2 in-flight target requests across all tools combined; 300-page cap; crawl depth 4; 5,000 total outbound target requests; 45-minute wall-clock budget; 10-second request timeout; 1 MiB evidence/body collection cap per response. These are conservative starting product settings, not guarantees that a site can tolerate them. Limit expensive TLS/browser operations separately within the same budget. Count redirects and retries. Operators may lower limits; any increase is audited and bounded.

Honor throttling responses and stop on sustained health degradation or repeated errors. Block logout/delete/payment/email/SMS workflows and unapproved state changes. Before any production form submission, establish that the action is approved and low impact; the HTTP verb is insufficient. No denial-of-service, credential stuffing, persistence, lateral movement or bulk data extraction.

**Cancellation.** Target acceptance goals: stop admitting outbound requests within five seconds of cancellation, revoke per-scan capabilities, terminate dedicated runs within 30 seconds and retain a partial report. Use the execution supervisor, not programmatic Celery worker termination. These deadlines must be measured before being advertised as guarantees. In-flight requests may already have reached the target; teardown cannot undo them. Resume rechecks scope expiry, remaining budgets and task idempotency.

**Audit.** Record actor, target/scope/profile versions, decisions, tool/version/arguments with secrets redacted, request counts, timestamps, outcomes, evidence references, overrides, scoring calculations and exports. Stream durable events throughout the scan; worker crashes must not erase the history.

## 13. Quality, Platform Security & Data Requirements

- Models propose bounded actions through typed tools, isolated Bash and the governed custom-script path (§17). Bash cannot override network/filesystem/resource policy. Install dependencies only through the reviewed release pipeline. Target pages, screenshots, tool/MCP output and skills cannot change permissions or scores.
- Use an independent verification component and deterministic scoring service. The LLM writes explanations from evidence and cannot invent findings, assign coverage or silently alter scores.
- Scanner workers have no direct route to the control-plane database or other customers' workers. Apply CPU/memory/disk/runtime quotas, immutable tool images and per-scan scratch storage. Container isolation alone is not the complete security boundary.
- Record versions of scanners, templates, browser engines and vulnerability data. Review updates and software licenses before enabling them.
- Separate secrets, evidence and metadata. Encrypt stored data and transport, authorize every read/export, and redact tokens/PII before model use. Response truncation is disclosed and can make a check inconclusive.
- Proposed retention: evidence 30 days; scan/finding/audit metadata 90 days for the prototype. Make customer deletion and public-launch retention policies explicit. No unlimited evidence retention by default.
- Credentials, private keys and discovered tokens never enter application logs or model prompts. Reports escape HTML and remove executable payloads even in downloadable JSON.
- Keep durable checkpoints, budgets and cost counters. Track worker time, model usage and scan failures; a budget limit produces a partial report with reasons.
- Do not allow a high-confidence unsupported claim simply because a model repeated a scanner message. Explanations distinguish observed behavior from possible impact.

## 14. Technology Direction & Tool Selection

These choices are proposed implementation defaults; the requirement is the capability, not a commitment to one vendor.

| Layer | Suggested starting point | Requirement |
|---|---|---|
| API/backend | Python + FastAPI | Async scan intake, tenant/Operator boundaries and typed results |
| Stateful coordinator | LangGraph | Baseline plus hypothesis loops, checkpoints and bounded delegation |
| Background work | Redis + Celery dispatch; PostgreSQL ledger/outbox | Idempotent admission, leases/fencing, reconciliation and durable budgets |
| Browser/discovery | Playwright Python + Chromium | DOM and visual interaction, session ownership, scoped traffic and evidence; hosted provider later |
| Primary scanner | ZAP Automation Framework | Curated rules, structured outputs and documented check mapping |
| Additional checks | Selected Nuclei templates, constrained testssl.sh adapter, custom HTTP checks | Pinned engine/templates/assets and per-check proof criteria; Nmap only in a separately approved host profile |
| Metadata/evidence | PostgreSQL plus encrypted object storage | Durable results, access controls, retention and auditable links |
| Worker isolation | Dedicated worker VM/sandbox with curated Kali and browser containers | External supervisor, network lanes, resource budgets and no privileged host access |
| Dashboard | Functional HTML/TypeScript | Scorecards, coverage, evidence, limitations and export |

Logical sub-agents may initially share a process. Start with discovery, configuration/input-check specialists, independent verification and reporting; add autonomous planning complexity only where benchmark results improve. All parallel workers share one target budget and coordinate side effects. Do not auto-chain a newly found vulnerability into deeper compromise.

### 14.1 Provider-flexible model contract

ScopeLens SHALL accept a model configuration independently for planner, browser interpretation, verification assistance and report writing. Supported integration targets are direct OpenAI, OpenRouter and qualified open-model endpoints. No particular model, pricing tier or inference host is mandatory. An open model may run through a hosted service or self-hosted endpoint; local inference is optional.

The adapter exposes structured decisions/tool requests, normalized finish/error reasons, model identity, usage, timeouts and cancellation. Validate tool arguments in application code. Maintain tested capabilities per model/provider: tools, schema adherence, vision, context budget and streaming. A text-only model can use DOM observations but cannot be assumed to interpret screenshots. Unsupported capability must use an approved compatible route or produce a clear limitation.

Fallbacks use a configured provider/data-policy allowlist, remaining budget and capability check; never send customer evidence to an unapproved provider. A provider change does not grant new tools or repeat an already executed target action. Record requested and actual provider/model where supplied, routing policy and fallback reason. Fix models/routing for evaluation runs so benchmark comparisons are meaningful. API keys and raw credentials stay outside prompts and graph state. The plan §16 defines adapter acceptance.

## 15. Phases, Evaluation & Acceptance Criteria

**Phase 1 — Operator-only interactive external MVP.** Approved origins, enforced execution lanes, curated tool/Bash workers, bounded local Chromium interaction, baseline plus adaptive verification, trusted evidence, category/field scores, coverage, HTML/JSON and cancellation. Start validation in owned labs; production profile activation depends on containment/evidence gates. Authentication and contextual categories remain explicitly unassessed.

**Phase 2 — Authenticated application assessment.** Customer test users/roles/tenants, session handling, object/function/property authorization, stored-content fixtures, browser state coverage and targeted retesting. Required permissions/business expectations are supplied, not guessed.

**Phase 3 — Controlled advanced assessment.** Staging callbacks, mock integrations, request desynchronization, cache isolation, bounded resource/failure scenarios, business logic and telemetry validation. Deep GraphQL/SPA work and approved multi-origin testing are separate supported profiles.

**Later product features.** Self-service verification before public use; scheduled monitoring, organizations/billing, polished UI, additional report formats and optional source/cloud integrations. Automated remediation is a separately authorized product capability.

The mandatory testbed and owned-site pilot rules are in §15.1. Detailed benchmark procedure and milestone acceptance are in the companion implementation plan.

| Gate | Acceptance requirement |
|---|---|
| Authorization | Expired, unapproved, redirected and DNS-rebinding destinations are blocked in boundary tests. |
| Coverage honesty | Every planned control/instance has an outcome; skipped/blocked/error/missing-role work never becomes Pass or N/A. |
| Evidence | Every confirmed finding satisfies its registered proof criteria, includes minimized evidence and distinguishes demonstrated from potential impact. |
| False positives | Evaluate both vulnerable and fixed fixtures per check; publish counts and failure cases. Pilot targets: recall ≥90%, confirmation precision ≥95%, and false-positive rate ≤5% on eligible independently labelled cases, with denominators, abstention and uncertainty reported as defined in the plan §13. These are not achieved or universal accuracy claims. |
| Scoring | Same inputs/version produce the same number; duplicates do not multiply deductions; equivalent controls are not double-counted; Critical/High caps always apply. |
| Unknowns | Missing credentials/tool errors cannot produce a better finalized score; a zero-finding scan with inadequate coverage is not scored. |
| Lifecycle | Retests require new relevant evidence; a 404, WAF block or removed scan row alone does not close an issue. |
| Isolation | Cross-tenant evidence access fails; workers cannot reach disallowed internal/control-plane services. |
| Prompt injection | Malicious target content cannot expand scope, install tools, disclose secrets or modify the scoring policy. |
| Stop/recovery | Cancellation and crash recovery respect budgets, stop deadlines and side-effect rules; partial work remains auditable. |
| Report safety | HTML/JSON cannot execute target content or expose raw credentials/payloads. |
| Resource limits | Target request, time, response-size and cost budgets hold across parallel agents and retries. |

Do not set a launch claim such as “all 50 vulnerabilities supported” until every claimed control has a reviewed registry entry and passes its release fixtures. Detection rate on the benchmark does not measure all real-world weaknesses or reproduce a human pentest.

### 15.1 Testbeds, ground truth and first owned-site pilots

Use privately self-hosted lab applications, with synthetic data, pinned builds, repeatable seed/reset routines and isolated networking. Start with Juice Shop plus small vulnerable/fixed fixtures; add VAmPI/DVWA, then crAPI and DVGA as their feature milestones need them. Do not run every lab simultaneously by default. WebGoat, NodeGoat and bWAPP are optional breadth candidates, not required production dependencies.

Maintain separate **development**, **validation** and **held-out evaluation** manifests. Reserve selected VulnerableApp and ZAP-maintained WAVSEP cases plus independent fixed fixtures for evaluation. Partition by independent implementation/scenario family, not random URLs that share the same flawed code. Never expose expected labels, solutions, challenge success endpoints or answer-key APIs to runtime agents. The evaluator may access them separately. Public benchmark knowledge may already be in model training; include private variants and document that limitation.

DVGA difficulty modes are not negative controls. DVWA Impossible variants and VAmPI vulnerability-off cases are negative-control candidates only for independently verified, named conditions at a pinned revision. No entire deliberately vulnerable app is assumed clean. Additional unlabelled findings need adjudication; unmatched benchmark output is not automatically a false positive. The companion plan §13/§15 defines metrics, manifests, isolation and reset rules.

The first real targets are Aditya's owned sites, entered explicitly in an authorization/scope record. Begin with staging, then a bounded production smoke assessment after containment, evidence and cancellation gates. Ownership does not authorize a hosting provider, CDN, payment service or a shared IP. Owned sites validate discovery, workflows and operational behavior; without labels they do not establish precision or recall. No hostname is inferred from the pasted reference to Arkyon/personal sites.

`example.com` is a documentation domain, not an authorized security benchmark. Use a local static fixture for smoke testing basic HTTP handling. Do not target third-party hosted training instances during early builds; self-host the selected projects. No live testing is authorized by this document alone.

## 16. Requirement Decisions, Review Status & Sources

### 16.1 Current implementation baseline

| Decision | Requirement / selected default |
|---|---|
| Name | ScopeLens |
| Model access | Provider-flexible: direct OpenAI, OpenRouter, qualified open-model endpoints |
| First real targets | Explicitly registered owned sites after lab gates |
| Initial user | Operator-only prototype |
| Initial access | Unauthenticated; role-dependent checks deferred and clearly unassessed |
| Scope | One approved origin; related hosts inventory-only |
| Authorization UX | May be deferred privately; allowlist and scope enforcement may not |
| Score direction | 0–100, higher is better; separate coverage and severity |
| Score scope | External profile in v1; extended assessment only when corresponding evidence is available |
| Score algorithm | Fixed category weights, root-cause deductions, severe-finding caps and coverage gates |
| Scan depth | Bounded defaults in §12; measured and adjustable within approval |
| Proof | Defined per check, minimal impact, no executable payloads in reports |
| Evaluation | Declared vulnerable/fixed fixtures and reproducible scoring tests |

### 16.2 Final recommended defaults and validation status

- Use the full external profile with curated configuration and conditional input/browser checks; name a narrower configuration-only profile distinctly.
- Start Operator-only with local Chromium and isolated worker infrastructure. A hosted browser is a later interchangeable provider only after equivalent controls are demonstrated.
- Allow bounded Bash with installed dependencies. Generated scripts may analyze local evidence; networked generated checks begin in an approved lab/staging profile. Broader production use requires its own validation gate.
- Retain the category weights, deductions and 80% gate as an explicitly uncalibrated pilot rubric; review against expert-labelled cases before public rating claims.
- Keep budget and retention defaults from §12–§13 as tunable pilot settings. Concrete deployment sizing and model choice follow measured resource/cost benchmarks.

These defaults form the build baseline. Numeric scoring remains a visible pilot feature; severity and coverage are always shown. No claim of a calibrated whole-site rating is permitted. Per-tool integrations, containment tests, evidence fixtures and end-to-end benchmarks remain engineering release gates. No live website scans were performed during this review.

### 16.3 Primary reference baseline

References were checked on 23 September 2026. The architecture, scores, budgets, phase assignments and release targets in this document are product proposals. Standard references ground coverage terminology; they do not endorse the custom score or certify the product.

- OWASP Top 10:2025 — broad risk categories: https://top10.owasp.org/2025/
- OWASP WSTG v4.2 — versioned web testing guidance: https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/
- OWASP ASVS 5.0.0 — verification requirements and versioned reference conventions: https://github.com/OWASP/ASVS/tree/v5.0.0
- OWASP API Security Top 10:2023 — API risk families, including inventory, resource use and upstream trust: https://api-security.owasp.org/editions/2023/en/0x11-t10/
- FIRST CVSS v4.0 user guide — individual vulnerability severity, distinct from whole-system risk: https://www.first.org/cvss/v4.0/user-guide
- ZAP Automation Framework: https://www.zaproxy.org/docs/automate/automation-framework/
- OWASP Juice Shop: https://owasp.org/projects/juice-shop
- IANA example domains: https://www.iana.org/help/example-domains


## 17. Adaptive Tools, Browser Control, MCP & Skills

### 17.1 Baseline and adaptive work

Keep the required checklist separate from a queue of hypotheses. Each hypothesis records observed signals, alternative explanations, missing proof, a proposed next action, expected evidence, canonical control IDs and stop conditions. Every tool/browser result may inform follow-up selection. Protect baseline budget; adaptive work cannot erase skipped tests or inflate coverage.

Use at most three follow-up rounds per hypothesis as an initial pilot default, with no repeated identical operation without new evidence or a documented transient-error reason. Follow-ups must stay within the original scope, impact profile and shared budget. Record why work ended: sufficient evidence, disproved hypothesis, no useful permitted action, blocked access or exhausted budget.

### 17.2 Execution interfaces

- **Typed functions:** stable inputs/outputs and registered proof rules for common checks; wrappers can call existing scanners.
- **Bash:** adapt installed-tool parameters, inspect help, process local artifacts and compose approved commands inside the worker. Production networked execution is limited to reviewed checks and permitted configurations/parameter ranges; new networked commands follow the lab/staging custom-check path. Path/method restrictions alone cannot ensure harmless request content. Tool availability and valid options come from a pinned manifest/help, not model memory.
- **Custom Python/Bash:** generated analysis or verification artifacts with code hashes, declared capabilities and independent evidence capture. Proposed default is networked lab/staging use first; production retains reviewed check execution until a separate gate is met.
- **Browser:** observe DOM/accessibility/screenshot/network state, select an action, check policy, act and reassess. Both DOM and coordinate actions use the same controller.

Every interface uses the same broker, scope revision, capability, task ID and budgets. Prompt or command filtering is not the isolation boundary. Do not install packages or clone/execute arbitrary repositories during customer scans. Missing functionality becomes a reviewed integration item. A newly generated check can propose evidence but cannot create its own scored control or confirmation rule.

### 17.3 Execution lanes and networking

HTTP tools/browser traffic use a trusted HTTP-aware broker or mandatory inspecting proxy with direct egress denied. A plain HTTPS CONNECT proxy cannot inspect paths, methods or inner request counts. If TLS inspection is used, record it, validate upstream identity and test tool compatibility. Fail closed when enforcement cannot be maintained.

Use a separate constrained TLS measurement path for real upstream certificate/protocol checks, so the proxy does not distort findings. Optional host-service discovery has its own explicit approved IP/port profile; a domain or shared CDN address is not automatic authorization for all services. Tools requiring unavailable network privileges stay unavailable in that profile.

Enforce DNS/destination/redirect checks externally; handle browser subrequests, WebSockets, downloads, UDP/QUIC and other alternate egress. WebSocket message/connection budgets are additional to HTTP counts. Scope policy is never supplied by a target page. If cross-origin dependencies are blocked, report the resulting application-coverage gap.

### 17.4 Browser sessions

Represent each session explicitly with tenant, scan, role, browser/provider ID, page/frame IDs, scope revision, expiry and controller lease. One owner serializes actions. Distinct identities have distinct contexts; unrelated scans also require appropriate process/VM isolation. A context is not a complete security boundary.

Capture a replayable approved action sequence and relevant before/after state. Reconstruct safe navigation after expiry; never blindly repeat form submissions. Track service-worker/cache/browser-setting changes as evidence limitations. Screenshots support but do not independently prove server-side permission failures.

The provider interface supports local Chromium now and a hosted browser later. Provider migration requires equivalent scope, session, evidence, credential and cancellation tests; CDP connectivity alone is insufficient.

### 17.5 MCP choices

MCP is an optional tool interface, not the workflow or security boundary. Prefer direct Playwright and scanner adapters for core execution. Microsoft Playwright MCP can be a curated sidecar; Chrome DevTools MCP is optional diagnostics. Do not let both control one page concurrently. Disable target-registered WebMCP tools by default.

Current LangChain MCP support lives under `langchain.mcp`; the old `langchain-mcp-adapters` repository is archived. The current integration is beta, so isolate and version-pin it. The old Browserbase MCP reference repository is also archived; evaluate current hosted services or SDKs separately.

ZAP's MCP add-on is not enabled in default scan images. Its external MCP importer can invoke discovered tools with placeholder arguments. Use AF/API until the add-on and target-MCP testing have explicit approval and side-effect controls.

For every MCP server, pin identity/version/tool schemas, authenticate the actual caller, constrain outputs and expose only required methods. Protocol state or a browser handle does not confer authorization. Tool metadata/results remain untrusted data. Reject target-directed tool/server installation or scope changes.

### 17.6 Skills

Use reviewed Agent Skills-format knowledge packs for discovery interpretation, browser exploration, proof criteria, false-positive challenge, tool recovery and remediation explanation. Load only applicable material. Skill metadata and bundled scripts are versioned; application policy controls permissions regardless of a skill's stated tools.

Selected Trail of Bits security/audit skills are useful for development and future source-assisted assessments. They are not automatic URL-only scanner capabilities. Review attribution/license obligations before adapting content. Versioned OWASP references inform our own check packs. Never auto-load marketplace or target-provided skills into customer scans.

## 18. Durable Execution, Evidence Integrity & Release Gates

### 18.1 Scheduling and recovery

Create scan/task records with transactional outbox events in PostgreSQL. Redis/Celery delivers work; repeated delivery is expected and must be safe. One coordinator holds a renewable database lease with a fencing token. Executors reject stale tokens. Lease expiry/loss revokes the old run's ongoing egress capability as well as new admissions; replacement work waits for reconciliation so an orphan cannot keep scanning concurrently.

Track logical operation IDs separately from attempts and states: planned, admitted, running, succeeded, failed and outcome_unknown. Reserve shared budgets atomically before admission and reconcile observed usage. Persist spent budget across recovery. A graph checkpoint is not proof that an external action ran exactly once.

Supervised scanners have stable run handles. On restart, reconcile real processes and evidence before launching or retrying. If a request may have reached the target but its outcome was lost, mark outcome_unknown and do not blindly repeat side effects. A reconciler handles orphaned workers, stale leases and partial evidence.

Cancellation revokes outbound authority and new admissions first, then stops the specific worker/browser process group through the trusted supervisor. It cannot reverse already-sent requests. Do not use programmatic Celery worker termination as the product's cancellation mechanism.

### 18.2 Trusted evidence and output

Trusted collectors associate actual network/browser artifacts with run/task IDs, tool/script hashes, timestamps, scope and role. Generated script stdout/JSON is an untrusted observation. The verifier applies proof rules to captured artifacts; a second LLM agreeing is not sufficient confirmation. Integrity hashes do not by themselves prove a claim true.

Keep raw observations separate from interpretations and preserve minimal evidence. Redact secrets before model calls and customer output. Dashboard SSE uses a dedicated redacted event schema with sequence IDs; never forward raw LangGraph values streams or unfiltered stdout. Private graph channels are not a privacy guarantee.

Experimental checks map to reviewed controls before affecting the scoring rubric. Serious unmapped candidates remain prominent and must not permit an unjustified reassuring rating. Existing scoring denominator, eligibility, caps and deduplication remain deterministic and versioned.

### 18.3 Additional launch acceptance scenarios

- Duplicate outbox/queue delivery and two coordinators competing for one scan.
- Lease expiry while an old coordinator or worker remains alive.
- Crash after outbound execution but before results/checkpoints are persisted.
- Cancellation during browser fetches, WebSockets and long-running scanner processes.
- Worker attempts direct sockets, alternate DNS/UDP, shared-IP authority confusion or proxy bypass.
- Tool/script prints fabricated success; partial/truncated evidence; compromised-looking tool output.
- Browser popups, downloads, frames, service workers, concurrent controllers and identity isolation.
- Hostile page/screenshot/MCP/skill content tries to change policy, install tools or disclose secrets.
- Adaptive checks versus baseline-only scans on held-out vulnerable and fixed applications, reporting true findings, false positives, inconclusive outcomes, coverage, runtime and model cost.
- Identical inputs yield identical scores; missing coverage cannot improve a finalized result; severe findings cannot be diluted by other categories.

All are required tests, not claimed successful results. Confirm model/tool compatibility and build a release manifest before deployment.

## 19. References, precedence and handoff

Use `ScopeLens_Implementation_Plan.md` for architecture diagrams, agent/tool/MCP/skills decisions, current-source findings, the complete build sequence, testbed manifests, release gates and source links. Framework/tool research was reviewed on 23 September 2026; the testbed and provider-interface additions were checked on 24 September 2026. Repository status can change; pin and test exact versions before implementation.

This specification supersedes `Agentic_Web_Scanner_Requirements_v1.0.md`. The companion plan incorporates and supersedes `ScopeLens_Final_Architecture_Audit.md`. Only the two new filenames belong in the project's active `docs/` handoff. Keep any historical copies outside the active specification path to avoid conflicting instructions.

Do not call an entire family supported until its canonical controls, permitted proof, vulnerable/fixed fixtures and coverage accounting pass release review. The design is ready for implementation planning; production readiness requires measured containment, recovery, evidence and benchmark results.

