# Host prioritization and browser readiness — 29 September 2026

## Implemented

The dashboard now orders discovered hosts using structured evidence from the operator's
latest completed assessment for each host. Each host has an expandable explanation and
next-step list. The system retains unassessed owned hosts in the proposed assessment
plan instead of treating missing observations as low risk.

Observed forms, inputs, API signals, login boundaries, incomplete browser exploration,
crawl limits, and unresolved advisory candidates influence the order. Hostname words
such as `portal` are weak hints only. Priority points are not vulnerability severity or
a security score. Findings, confirmation status, and score calculations are unchanged.

The response is a read-only plan: it does not queue scans, approve actions, or grant
new destinations. Existing scope, reviewed-action, budget, evidence and proof rules
continue to govern execution. Dedicated student/staff test accounts and disposable
records are still needed for logged-in access-boundary assessments.

## Current college inventory

The main-site report contains 42 observed hosts. Ten match the operator-confirmed
`alliance.edu.in` domain; 32 are external dependencies retained as inventory only.
This is link-derived inventory, not a claim that every college subdomain is discovered.

The deployed API initially ranked `portal.alliance.edu.in` and `student.alliance.edu.in`
first because their saved reports contain forms, inputs, a password form, incomplete
browser exploration, and an unresolved component advisory candidate. `apply` and
`payment` follow for discovery based on weak name hints. Those names do not establish
that payment operations or sensitive information were actually observed.

Config: `SCOPELENS_DISCOVERY_OWNED_DOMAINS=["alliance.edu.in"]`. This is triage metadata;
a matching name still needs its own execution scope. Suffix lookalikes do not match.

## Browser diagnosis

The portal's previous report had no captured browser state. Offline replay of captured
HTML alone loaded successfully, so the HTML by itself did not reproduce the failure.
A synthetic page with a 15-second parser-blocking script reproduced the timeout:
the old worker waited 10 seconds for network idle and then only 3 seconds for body text.

The worker now waits up to 30 seconds for DOMContentLoaded, followed by a bounded
1.5-second settle period. Background requests cannot hold state capture indefinitely.
Timeouts remain visible gaps. Scope, action admission, cancellation and evidence paths
are unchanged. This proves the failure class locally; the customer run must separately
show whether it resolves that site's browser gap.

Deployed worker regression, using a synthetic loopback fixture inside a network-disabled
VM container and the real Controller.act/state methods:

- Before: TimeoutError, 0 states, 13.04 seconds.
- After: captured, 1 state, 15.57 seconds.
- Command: `docker exec -i scopelens-dev-supervisor-1 python - < scripts/verify_browser_readiness.py`.
- Evidence: `runs/scanner-resource-validation/browser-before.txt` and `browser-after.txt`.

## Verification

- 32 focused Python tests passed: host ordering and revisions, domain lookalikes,
  unchanged findings, missing-account state, browser completion/admission, owner-bound
  API access, no scan creation, and typed OpenAPI response.
- Frontend production build passed.
- Browser UI regression passed: 42 inventory rows, portal first, expandable next steps,
  missing-account explanation, filtering, narrow-screen layout, unavailable-data state,
  and no mutation requests from the prioritization view.
- Live API returned 42 hosts, 10 owned matches, and portal/student first.
- Saved live response: `runs/college-subdomains/host-priorities-live.json`.

Public portal recheck: `47177a9f-4493-40cd-a514-4aad69a4bf1f`, on the existing GET/HEAD
scope. Results are saved under `runs/college-subdomains/portal-browser-recheck/`.

## Customer recheck result and inventory repair

The public portal recheck completed_partial with 31 HTTP pages, five confirmed
configuration findings and one potential component advisory (11.8% reported coverage).
It still captured zero browser states: DOMContentLoaded timed out and the body locator
remained unavailable. Thus the local readiness regression passes, but the customer
browser failure is **not resolved**. Several scripts were admitted without a completed
browser response artifact before capture ended; this narrows investigation to asset
loading/transport/parser progress, but does not establish the cause. No additional
severe vulnerability was confirmed by this repeat.

Live verification also exposed an existing inventory defect: the primary `host` field
contained a full origin URL. The report now emits its parsed hostname, so the priority
API can match the existing main-site assessment instead of planning duplicate discovery.
A failing-then-passing regression covers an HTTPS origin with a nondefault port.
The focused report/priorities/dashboard suite passed 54 tests after the repair.
The repaired API image is deployed; no scan was active during either service update.

Remaining depth requirements: resolve the real portal browser gap; review observed inputs
against executable assessment configurations; obtain dedicated test identities for
logged-in paths; assess the remaining owned hosts. This implementation does not claim
that its recommendations automatically execute those tasks or that any host is fully
assessed.
