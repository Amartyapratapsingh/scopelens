"""Build the source-audit report. Contains no credentials or raw environment dumps."""

from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs/reports/scopelens-backend-ai-report.html"


def code(path):
    return f'<a class="source" href="../../{escape(path)}"><code>{escape(path)}</code></a>'


def cell(s):
    return f"<td>{s}</td>"


pipelines = [
    (
        "Intake and durable execution",
        "Connected in source",
        "code",
        "URL + registered scope + immutable profile/configuration",
        "FastAPI → PostgreSQL scan/task/outbox → Celery → leased coordinator",
        "None. Code checks scope, identities, budgets and cancellation.",
        "A durable scan and audit trail. Queue delivery never establishes a finding.",
        "backend/scopelens/api/scans.py",
    ),
    (
        "HTTP discovery and inventory",
        "Connected in source",
        "code",
        "Approved origin; bounded links, forms, query inputs, robots and sitemap",
        "Crawler → response/surface captures → request catalogue → frozen assessment plan",
        "No AI needed for the baseline crawl or template extraction.",
        "Endpoints, forms, parameters and passive technology hints. OpenAPI/HAR parsers exist; their operator import workflow remains incomplete.",
        "backend/scopelens/discovery/catalogue.py",
    ),
    (
        "TLS and configuration",
        "Connected in source",
        "code",
        "Broker-captured responses; separate real-upstream TLS measurement",
        "TLS lane / captured headers and cookies → deterministic controls → proof rules",
        "None for the checks. AI may rewrite the explanation afterward.",
        "Transport, headers, cookie attributes and configuration evidence. TLS uses its constrained lane, not the proxy certificate.",
        "backend/scopelens/checks/controls",
    ),
    (
        "Generic input comparisons",
        "Partial integration",
        "pending",
        "Frozen request template + input + action policy",
        "Reviewed HTTP comparisons → expanded_active_probe → bound evidence → pure evaluator",
        "Planner may select a reviewed repeat; it does not invent the baseline proof method.",
        "SQL behaviour, redirects, CORS configuration and header checks. Authenticated generic-template execution still needs its identity transport binding.",
        "backend/scopelens/checks/expanded_active.py",
    ),
    (
        "Interactive browser and rendering checks",
        "Core connected; expansion pending",
        "ai",
        "Approved pages; DOM, accessibility controls, browser events",
        "Chromium → safe navigation/actions → browser captures; expanded rendering collectors have local tests",
        "Optional vision fallback suggests a coordinate. Code rechecks the actual element and action.",
        "SPA exploration and controlled browser evidence. Expanded browser worker dispatch, its renewed controller lease, and workflow report proof remain unfinished.",
        "backend/scopelens/browser/worker.py",
    ),
    (
        "Exposure packs",
        "Connected in source; deployment pending",
        "code",
        "Scoped captured URLs and bounded reviewed paths",
        "Fixed exposure collector → stored response facts → deterministic exposure evaluator",
        "Adaptive planner can select a reviewed exposure recheck.",
        "Sensitive-file, source-map, management/debug and related exposure observations. No broad download or repository reconstruction.",
        "backend/scopelens/checks/packs/exposure.py",
    ),
    (
        "Components and known advisories",
        "Expanded connection added this turn",
        "code",
        "Captured component/version hints + pinned local OSV corpus",
        "Fingerprint parser → explicit package mapping → affected-version matcher → candidate finding",
        "No live AI advisory research. Matching is deterministic.",
        "Potential vulnerability with advisory ID, observed version, snapshot source/hash and limitations. The current expanded corpus covers 12 npm package identities, not Linux or all server products.",
        "backend/scopelens/expansion/components.py",
    ),
    (
        "ZAP, Nuclei and testssl",
        "Core connected; expanded pack pending",
        "pending",
        "Captured HAR; selected target; reviewed pinned tool configuration",
        "ZAP passive analysis of captures; reviewed Nuclei template; testssl through TLS lane → normalized alerts",
        "No unrestricted model-selected template execution. Model challenge is optional after evidence.",
        "Core adapters exist. Current Nuclei runtime uses its original reviewed CSP template. Five broader reviewed templates exist but their runner integration is unfinished. ZAP active breadth is not integrated.",
        "backend/scopelens/adapters/runner.py",
    ),
    (
        "Identity and authorization",
        "Proof/report connection added this turn",
        "code",
        "Operator-declared identities, verified sessions, synthetic objects and permission matrix",
        "Separate sessions → owner baseline → repeated other-role reads → rule-bound response series → independent evaluator",
        "AI cannot declare identity or expected permission. It may challenge the resulting observation.",
        "Object, function, tenant and property comparisons. A guessed account or generic HTTP 200 cannot establish a finding. Deployment verification is still pending.",
        "backend/scopelens/expansion/identity_collector.py",
    ),
    (
        "Session lifecycle",
        "Proof/report connection added this turn",
        "code",
        "Declared login/logout policy and synthetic account",
        "Verified initial/new session → cookie fingerprints/replay evidence → deterministic lifecycle proof",
        "No AI needed to decide whether the declared session policy held.",
        "Rotation and revocation checks. Only stored, bound observations count; worker verdict strings do not.",
        "backend/scopelens/identities/lifecycle.py",
    ),
    (
        "HTTP stateful and API workflows",
        "Proof/report connection added this turn",
        "pending",
        "Approved lab/staging recipes; synthetic disposable state; readback and cleanup",
        "Durable cleanup claim → admitted action → repeated independent readback → cleanup verification → proof/report",
        "No AI authority to invent a mutation or expected state.",
        "Mass assignment, workflow authorization, declared GraphQL reads, private-cache comparisons and canary-only file/template probes. Unfinished cleanup retains a fence and incomplete coverage. Operator recovery API remains pending.",
        "backend/scopelens/workflows/assessment.py",
    ),
    (
        "Stateful browser workflows",
        "Module and worker tests; dispatch pending",
        "pending",
        "Reviewed stored-marker, CSRF or benign-upload recipe with separate identities and cleanup",
        "Browser collector → bound observations → cleanup journal. Full deployed path is incomplete.",
        "Existing fixed recipes, not model-authored site mutations.",
        "The externally completed module is preserved. Local tests are not a deployed scan or a completed browser finding-to-report integration.",
        "backend/scopelens/browser/workflow_checks.py",
    ),
    (
        "Callback correlation",
        "Module tested; integration pending",
        "pending",
        "Explicit callback collector, signed nonce and approved synthetic target probe",
        "Issue nonce → admitted probe → independently captured receipt → repeated/negative-control proof",
        "No AI-generated external callback destination.",
        "Callback service/probe modules exist. Scan configuration, production control-channel wiring, receipt intake and report integration remain pending.",
        "backend/scopelens/callbacks/probes.py",
    ),
    (
        "Adaptive investigation",
        "Bounded loop connected; broader loops pending",
        "ai",
        "Observed signals + code-generated candidate list",
        "Observe once → AI selects candidate → deterministic admission → reviewed follow-up → proof check → AI challenge → next candidate",
        "Planner selects one supplied candidate ID. Verification assistant supplies an alternative explanation and missing proof.",
        "Useful bounded follow-ups. The present graph returns to plan after verification; it does not regenerate the full discovery/hypothesis list each round. Challenges are recorded, not automatically converted into new actions.",
        "backend/scopelens/orchestration/graph.py",
    ),
    (
        "Generated local analysis",
        "Optional, guarded path",
        "ai",
        "Redacted route/status/content-type summaries from collected artifacts",
        "Script role → bounded Python/Bash proposal → dedicated VM with network=none → untrusted observation",
        "AI writes local analysis code only on this path.",
        "Its output is not confirmation evidence. This is not an autonomous network exploit-generation channel.",
        "backend/scopelens/orchestration/scripts.py",
    ),
    (
        "Findings, scorecard and exports",
        "Connected in source; new rubrics locally tested",
        "ai",
        "Trusted artifacts, frozen registry, complete planned-control map and deduplicated findings",
        "Pure proof evaluation → findings → coverage/eligibility/caps → versioned score → HTML/JSON → optional prose rewrite",
        "Writer may rewrite what/why/fix. It cannot change severity, evidence, coverage or score.",
        "All 12 categories remain visible. Incomplete checks stay in coverage. Expanded pilot rubrics are explicitly uncalibrated and not directly comparable with legacy scores.",
        "backend/scopelens/checks/analyze.py",
    ),
]
rows = "".join(
    '<tr data-kind="'
    + kind
    + '">'
    + "".join(
        cell(x)
        for x in [
            f'<strong>{name}</strong><span class="state">{state}</span>',
            input_,
            flow,
            ai,
            result + code(path),
        ]
    )
    + "</tr>"
    for name, state, kind, input_, flow, ai, result, path in pipelines
)
ai_rows = [
    (
        "Planner",
        "Reviewed candidate list and a curated procedure",
        "candidate_id + reason",
        "Admission validates scope, remaining budgets, cancellation and prior attempts. Invalid/unavailable output falls back to code selection.",
        "orchestration/graph.py → orchestration/models.py → adapters/roles.py",
    ),
    (
        "Browser vision fallback",
        "Limited DOM text and screenshot, only when that role is configured with vision",
        "One x/y suggestion",
        "The browser controller inspects the actual element and applies action policy. Normal DOM exploration works without vision.",
        "browser/worker.py → broker vision route → model gateway",
    ),
    (
        "Verification assistant",
        "Hypothesis and deterministic follow-up outcome",
        "Alternative explanation + missing proof",
        "Stored as a challenge. No model message is proof and it cannot confirm or change severity.",
        "orchestration/graph.py::verify → call_model(verification)",
    ),
    (
        "Report writer",
        "Control ID, severity, detail and template what/why/fix",
        "Rephrased what / why / fix",
        "Strict response schema; template fallback. Scoring and evidence are already computed.",
        "writer/enrich.py → call_model(report_writer)",
    ),
    (
        "Local script analyst",
        "Capped route/status/content-type summaries",
        "Python/Bash source + purpose",
        "Dedicated VM; network disabled; output stored as untrusted observation. Optional feature flag.",
        "orchestration/scripts.py → call_model(script) → sandbox gateway",
    ),
]
ai_table = "".join("<tr>" + "".join(cell(escape(x)) for x in r) + "</tr>" for r in ai_rows)
source_rows = [
    (
        "The assessed website",
        "During the scan",
        "Only registered scope and explicitly granted related origins, subject to method/path/budget checks. Cross-origin dependencies can be blocked and reported as gaps.",
        "Actual HTTP/browser/tool evidence.",
    ),
    (
        "OSV API",
        "Manual snapshot update, not per-scan AI browsing",
        "scripts/fetch_advisories.py calls https://api.osv.dev/v1/query. Scans consume the saved, hashed dataset.",
        "Affected package/version records and source provenance.",
    ),
    (
        "Advisory links inside OSV records",
        "References in the dataset",
        "CVE aliases and vendor/GitHub references may be present. Their presence does not mean ScopeLens visited those pages during the scan.",
        "Attribution and human follow-up; no runtime page research.",
    ),
    (
        "Pinned scanner rules",
        "Local tool execution",
        "Reviewed templates/configuration only. Automatic template updates and Nuclei Interactsh are disabled in the current runner.",
        "Tool observations normalized and checked against proof requirements.",
    ),
    (
        "Configured model provider",
        "When an enabled AI role is called",
        "The approved OpenAI-compatible endpoint receives the permitted context for that role. No credentials are included in this architecture report.",
        "Structured proposals, challenges or prose; not an advisory database.",
    ),
    (
        "Microsoft MSRC / NVD / Linux distribution advisories",
        "Not integrated as live research",
        "There is no runtime AI web-search/retrieval connector for these sources in the inspected pipeline.",
        "A proposed extension, not a current capability.",
    ),
    (
        "Callback collector",
        "Expansion module only",
        "An explicitly registered collector would receive signed nonces. Production scan integration remains incomplete.",
        "A correlated external observation, only once integrated and verified.",
    ),
]
source_table = "".join("<tr>" + "".join(cell(escape(x)) for x in r) + "</tr>" for r in source_rows)
refs = [
    "backend/scopelens/execution/coordinator.py",
    "backend/scopelens/expansion/integration.py",
    "backend/scopelens/expansion/proof_aggregation.py",
    "backend/scopelens/expansion/components.py",
    "backend/scopelens/orchestration/graph.py",
    "backend/scopelens/orchestration/expansion.py",
    "backend/scopelens/adapters/roles.py",
    "backend/scopelens/orchestration/models.py",
    "backend/scopelens/writer/enrich.py",
    "backend/scopelens/scoring/profiles.py",
    "backend/scopelens/adapters/runner.py",
    "checks_registry/tooling/expansion/advisories.json",
    "scripts/fetch_advisories.py",
    "docs/EXPANSION_PROGRESS.md",
    "docs/EXPANDED_SCORING.md",
]
reference_list = "".join("<li>" + code(p) + "</li>" for p in refs)
diagram = (ROOT / "docs/reports/scopelens-pipeline-diagram.html").read_text()
html = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ScopeLens | Backend and AI pipeline report</title>
<style>
:root{--ink:#142b3b;--muted:#556673;--paper:#f5f4ee;--line:#d8ddd9;--accent:#bd4f24;--green:#236b54;--violet:#6655a2}*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}a{color:var(--accent);text-underline-offset:3px}header{background:var(--ink);color:#fff;padding:48px max(24px,calc((100vw - 1200px)/2)) 40px}.eyebrow{font-size:12px;font-weight:750;letter-spacing:.16em;text-transform:uppercase;color:#cfad8d}h1{font-size:clamp(32px,4.5vw,59px);line-height:1.08;max-width:920px;margin:20px 0}header p{max-width:850px;color:#d8e2e7;font-size:18px}.tags{display:flex;gap:10px;flex-wrap:wrap}.tag{font:12px/1.3 ui-monospace,monospace;border:1px solid #5b6d78;border-radius:4px;padding:7px 10px;color:#e8ecee}nav{position:sticky;top:0;background:#f5f4eef5;z-index:3;border-bottom:1px solid var(--line);display:flex;justify-content:center;gap:24px;flex-wrap:wrap;padding:12px 20px}nav a{font-size:13px;font-weight:700;text-decoration:none;color:var(--ink)}main{max-width:1248px;padding:0 24px;margin:auto}section{padding:46px 0;border-bottom:1px solid var(--line);scroll-margin-top:65px}h2{font-size:29px;line-height:1.2;margin:0 0 20px}h3{font-size:18px;margin:0 0 10px}.lead{font-size:22px;max-width:1000px}.note{border-left:3px solid var(--accent);padding:14px 22px;background:#eee8db;margin:22px 0}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:18px}.card{background:#fff;border:1px solid var(--line);padding:24px}.card p{margin:0;color:var(--muted)}.metric{font-size:34px;line-height:1.3;font-weight:700}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:28px 0}.metrics .card{padding:18px}.metrics p{font-size:13px}.section-label{font:12px/1.2 ui-monospace,monospace;color:var(--accent);margin-bottom:10px}.diagram{border:1px solid var(--line);width:100%;height:800px;background:#fff}.small{font-size:13px;color:var(--muted)}.table-wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:14px;background:#fff}th{text-align:left;background:#e4e9e7;font-size:11px;letter-spacing:.06em;text-transform:uppercase;position:relative}th,td{padding:17px 15px;border-bottom:1px solid var(--line);vertical-align:top}td:first-child{min-width:180px}#pipeline-table{min-width:1030px}#pipeline-table td{width:20%}strong{font-weight:700}.state{display:block;font-size:11px;line-height:1.4;color:var(--green);margin-top:7px;font-weight:650}.source{display:block;font-size:10px;overflow-wrap:anywhere;margin-top:10px}code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.88em;overflow-wrap:anywhere}.filters{display:flex;gap:8px;flex-wrap:wrap;margin:22px 0 14px}button{font:inherit;font-size:13px;border:1px solid var(--line);border-radius:4px;background:#fff;color:var(--ink);padding:9px 15px;cursor:pointer}button[aria-pressed=true]{background:var(--ink);color:#fff}button:focus-visible,a:focus-visible,summary:focus-visible{outline:3px solid #cb632f;outline-offset:3px}.step{counter-increment:steps;position:relative;padding:0 0 24px 54px;min-height:65px}.step:before{content:counter(steps);position:absolute;left:0;top:0;background:var(--ink);color:white;width:32px;height:32px;border-radius:50%;display:grid;place-items:center;font-size:14px}.step p{margin:5px 0;color:var(--muted)}.steps{counter-reset:steps;max-width:1000px}.route{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:22px 0}.route b{background:#e4e9e7;padding:8px 13px;font-size:13px}.route span{color:var(--accent)}.pending{color:#9a481f}details{background:white;border:1px solid var(--line);margin:12px 0;padding:16px 20px}summary{cursor:pointer;font-weight:650}details p{margin-bottom:0}.references{columns:2;padding-left:20px}.references li{break-inside:avoid;margin-bottom:9px}.references .source{font-size:12px}footer{max-width:1248px;margin:auto;padding:32px 24px;font-size:12px;color:var(--muted)}[hidden]{display:none!important}@media(max-width:800px){.grid{grid-template-columns:1fr}.metrics{grid-template-columns:1fr 1fr}nav{gap:12px;position:static}.references{columns:1}.diagram{height:660px}h2{font-size:25px}section{padding:32px 0}.lead{font-size:19px}}@media print{nav,.filters,button,.diagram{display:none}header{background:white;color:#142b3b;padding:24px}header p,.eyebrow,.tag{color:#142b3b}main{max-width:none;padding:0}section{break-inside:auto;padding:25px 0}.table-wrap{overflow:visible}#pipeline-table{min-width:0}table{font-size:10px}th,td{padding:8px}td:first-child{min-width:0}a{color:inherit}.grid{grid-template-columns:repeat(3,1fr)}.card{padding:12px}details{break-inside:avoid}}</style></head><body>
<header><div class="eyebrow">ScopeLens / engineering report / 28 September 2026</div><h1>How the backend finds evidence.<br>Where AI enters the process.</h1><p>A source-based map of the scanner, its advisory data, proof rules and scorecards. Connected code and unfinished integration are shown separately.</p><div class="tags"><span class="tag">Backend only</span><span class="tag">Source audit, not a new website scan</span><span class="tag">Expansion deployment still pending</span></div></header>
<nav aria-label="Report sections"><a href="#answer">Answer</a><a href="#map">Pipeline map</a><a href="#pipelines">All pipelines</a><a href="#ai">AI roles</a><a href="#sources">Sources</a><a href="#example">Worked example</a><a href="#gaps">Gaps</a><a href="#evidence">Evidence</a></nav>
<main><section id="answer"><div class="section-label">01 / What the system actually does</div><h2>AI helps investigate. Evidence decides the finding.</h2><p class="lead">ScopeLens combines fixed checks, browser observations, reviewed scanner tools and optional AI assistance. The model does not independently search the internet for every vulnerability or decide the final score.</p><div class="metrics"><div class="card"><div class="metric">43</div><p>Registry entries. Not 43 distinct vulnerability classes.</p></div><div class="card"><div class="metric">17 / 26</div><p>Enabled / experimental entries. New families are not qualified yet.</p></div><div class="card"><div class="metric">12 / 194</div><p>Package identities / advisory records in the expanded pinned corpus.</p></div><div class="card"><div class="metric">5</div><p>AI roles with explicit, limited output schemas.</p></div></div><div class="note"><strong>Your version-disclosure example:</strong> a visible software/version hint can trigger advisory matching. A website URL usually cannot establish the server's exact Linux distribution, kernel build or vendor patch level. The current expanded advisory corpus is for named npm packages; it is not a Linux, Windows or IIS vulnerability database.</div><p>This report describes inspected source and local tests. It does not claim a vulnerability on any of the URLs discussed earlier, or that the latest source has been deployed into the running worker images.</p></section>
<section id="map"><div class="section-label">02 / Main flow</div><h2>From registered URL to report</h2><div class="route"><b>Scope + profile</b><span>→</span><b>Collect</b><span>→</span><b>Investigate</b><span>→</span><b>Store evidence</b><span>→</span><b>Evaluate proof</b><span>→</span><b>Score + export</b></div><iframe class="diagram" title="Interactive ScopeLens pipeline diagram" srcdoc="__DIAGRAM__"></iframe><p class="small">The diagram shows the main evidence path. The detailed table below records each branch and its current integration status. All target traffic uses the broker; real upstream TLS measurement has its own constrained lane.</p><div class="grid"><div class="card"><h3>One durable scan</h3><p>PostgreSQL stores the plan, tasks, leases, budgets and outcomes. Celery dispatches work. Workers do not decide which scope or credentials they may use.</p></div><div class="card"><h3>Two kinds of output</h3><p>Observations describe what happened. A proof rule determines whether those observations support confirmation, a candidate or an inconclusive result.</p></div><div class="card"><h3>Honest completion</h3><p>Missing credentials, blocked routes, exhausted budgets and unresolved cleanup remain visible. They do not become clean results or disappear from coverage.</p></div></div></section>
<section id="pipelines"><div class="section-label">03 / Every backend branch</div><h2>What connects to what</h2><p>“Connected in source” means a caller exists in the backend. It does not mean every feature flag is enabled or every deployment has been exercised. Expand the report's source links to inspect the implementation.</p><div class="filters" role="group" aria-label="Filter pipelines"><button data-filter="all" aria-pressed="true">All pipelines</button><button data-filter="ai" aria-pressed="false">AI-facing stages</button><button data-filter="pending" aria-pressed="false">Integration gaps</button><button onclick="window.print()">Print / save PDF</button></div><div class="table-wrap"><table id="pipeline-table"><thead><tr><th>Pipeline / status</th><th>Input</th><th>Connections</th><th>AI contribution</th><th>Result / limitation / source</th></tr></thead><tbody>__PIPELINES__</tbody></table></div></section>
<section id="ai"><div class="section-label">04 / Model access and authority</div><h2>Where AI is called</h2><p>Calls go through <code>orchestration/models.py</code> to the internal model gateway, then the configured, approved OpenAI-compatible provider. Calls reserve budget, enforce response schemas and record outcomes. A scan with no enabled model can still run deterministic checks and template reports.</p><div class="note"><strong>Local configuration inspected:</strong> provider host <code>api.commandcode.ai</code>; planner, verification and report writer use <code>zai-org/GLM-5.3</code>; browser vision uses <code>z-ai/glm-5.3-flash</code>. The script role shares the planner configuration. These are non-secret values from the local configuration on 28 September 2026. Container settings can differ; this is not evidence that any role ran on a particular scan.</div><div class="table-wrap"><table><thead><tr><th>Role</th><th>What it receives</th><th>What it returns</th><th>Who checks it</th><th>Code path</th></tr></thead><tbody>__AI__</tbody></table></div><div class="note"><strong>The present reasoning limit:</strong> <code>graph.py</code> creates a candidate list, then lets the model choose from it. After a follow-up, the graph returns to <code>plan</code>, not <code>observe</code>. The verification assistant's challenge is stored, but is not itself transformed into another executable hypothesis. This is a bounded candidate-selection loop, not a general research agent.</div><p>The model adapter currently sends chat messages and expects structured JSON. No runtime web-search or advisory-page browsing tool is exposed through that adapter. The report cannot establish whether a particular model was called on a particular scan without that scan's <code>model_calls</code> ledger.</p></section>
<section id="sources"><div class="section-label">05 / Sites, datasets and network calls</div><h2>Which other sites does it look at?</h2><div class="table-wrap"><table><thead><tr><th>Source</th><th>When used</th><th>Current behaviour</th><th>Purpose</th></tr></thead><tbody>__SOURCES__</tbody></table></div><h3 style="margin-top:28px">Expanded advisory corpus</h3><p>jQuery, Bootstrap, Vue, Angular, React, Next.js, Nuxt, Express, Lodash, Axios, Moment and AngularJS. Snapshot <code>osv-2026-09-26T12:00:02.269110+00:00</code>; 194 records; SHA-256 <code>3f73819dbb0fd98deb44b8714b5d905a3d7ba3686023ced0d90d782c9306936d</code>.</p><p>A package absent from this mapping, an unsupported version range, or an unobserved exact version remains unassessed. A search result, a product name, or a scanner match by itself is not proof that the assessed deployment is vulnerable.</p></section>
<section id="example"><div class="section-label">06 / Illustrative example, not a finding on your websites</div><h2>A disclosed library version</h2><div class="steps"><div class="step"><h3>Capture an observed version</h3><p>Suppose an approved response contains a named jQuery 1.8.3 banner. The fixed collector records the response; passive parsing retains the observed version, capture hash and source. A banner can be inaccurate, so it is still a claim about the deployment.</p></div><div class="step"><h3>Look up the explicit package identity</h3><p>The code maps jQuery to <code>npm:jquery</code> in the pinned OSV corpus. It does not ask AI to guess a CVE from memory.</p></div><div class="step"><h3>Evaluate the affected version range</h3><p>The local matcher finds relevant records. For example, the checked snapshot matches 1.8.3 to <code>GHSA-jpcq-cgw6-v4j6</code>, which carries alias <code>CVE-2020-11023</code>. This is an advisory applicability candidate, not a reproduction of that issue on the site.</p></div><div class="step"><h3>Keep uncertainty visible</h3><p>The report records the version/source and says the exact build, vendor fixes and exploitability remain unverified. No generic version match becomes a confirmed vulnerability.</p></div><div class="step"><h3>Use a supported follow-up if one exists</h3><p>Code may create an approved component re-observation or another reviewed task. AI can prioritize that candidate. The current system does not automatically read the vendor advisory and generate a site-specific reproduction from it.</p></div><div class="step"><h3>Report and score by evidence</h3><p>Unresolved High/Critical candidates can hold the overall rating at “Verification pending.” Confirmed deductions require the corresponding proof. The optional writer explains the result after the deterministic decisions.</p></div></div></section>
<section id="gaps"><div class="section-label">07 / What is still missing</div><h2>The connections still to finish</h2><details open><summary>Vendor-advisory research and applicability reasoning</summary><p>Not implemented: retrieving official vendor advisories at runtime, normalizing exact product/build/platform prerequisites, citing the retrieved evidence and proposing an available reviewed validation method. Microsoft/Linux-specific datasets and version semantics would need explicit support. The model should reason over retrieved source material, while uncertainty and action authority remain enforced by code.</p></details><details open><summary>A stronger observation-to-hypothesis loop</summary><p>The adaptive graph still needs a fresh observation stage after each result, and a typed way to convert a verifier challenge into a bounded new proposal. Identity/browser/callback follow-ups currently have prerequisites or dispatch gaps. A model cannot compensate for a missing collector or proof rule.</p></details><details open><summary>Remaining expansion integration and deployment</summary><p>Expanded browser dispatch/controller renewal and browser workflow report proof; callback configuration/control/receipt/report integration; authenticated generic-input transport; broader reviewed scanner execution; operator cleanup recovery; independent holdout qualification; rebuilding/deploying worker images and running the final backend-to-report lab checks. These are still open. Module tests do not close these gates.</p></details><details><summary>How to tell which AI roles actually ran</summary><p>Inspect each scan's <code>assessment_plan.model_calls</code>, hypothesis ledger, browser gaps, generated-analysis state, recorded tool versions, evidence references and report prose. Code support, enabled configuration, attempted execution and a successful result are four separate facts.</p></details></section>
<section id="evidence"><div class="section-label">08 / Evidence behind this report</div><h2>Repository traceability</h2><p>The latest complete backend suite passed with <strong>934 tests</strong>, including the component-corpus connection. The new identity/workflow proof path separately passed 31 tests against real local HTTP fixtures. Additional targeted component and report checks are recorded in the progress log. This report makes no new public-target scan claim.</p><ul class="references">__REFS__</ul><p class="small">Source links resolve when this HTML remains under <code>docs/reports/</code> in the repository. The report and diagram display offline without external scripts, styles or fonts. Follow-up integration work may change this snapshot; consult <code>docs/EXPANSION_PROGRESS.md</code> for later verification.</p></section></main><footer>Prepared from ScopeLens source and local verification on 28 September 2026. No credentials, provider keys or private response bodies are embedded.</footer>
<script>document.querySelectorAll('[data-filter]').forEach(button=>button.addEventListener('click',()=>{document.querySelectorAll('[data-filter]').forEach(b=>b.setAttribute('aria-pressed',String(b===button)));document.querySelectorAll('#pipeline-table tbody tr').forEach(row=>{row.hidden=button.dataset.filter!=='all'&&row.dataset.kind!==button.dataset.filter})}));</script></body></html>"""
for key, value in {
    "__PIPELINES__": rows,
    "__AI__": ai_table,
    "__SOURCES__": source_table,
    "__REFS__": reference_list,
    "__DIAGRAM__": escape(diagram, quote=True),
}.items():
    html = html.replace(key, value)
OUT.write_text(html)
print(OUT)
