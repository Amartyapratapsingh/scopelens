# Reviewed probe accounting

Crawl GETs retain the existing full-URL page ledger, including query strings. Active
GET comparisons and their initial browser captures use a separate accounting reference
in `x-scopelens-reviewed-probe`. The proxy removes it before target IO and passes its
value as optional `probe_task` to `/internal/authorize`.

A conditional reference hashes the complete frozen `conditional_probes` entry. The
policy checks the primary approved origin, exact path and approved query parameter.
An expanded input reference names a ready task in the frozen assessment plan; it must
have an admitted execution claim for that plan, the matching scope/profile/catalogue,
and a complete executable template. Method, origin, path and query structure must
match that template, with only the task's approved query/path input allowed to vary.
This reference grants no destination, method, role or input authority independently.

Validated probe GETs spend `max_total_requests` and the existing control's
`allowed_action.max_requests`, recorded under `assessment_plan.reviewed_probe_requests`.
They do not add crawl page keys. Both counters are serialized by the scan row lock;
a refused shared-budget reservation does not spend the task counter. CONNECTs,
subresources and ordinary crawl requests keep their existing accounting. POST tasks
already do not charge the GET page ledger and receive no new annotation.

Browser action numbers advance only after admission. An exhausted action budget stays
exhausted and does not turn subsequent denials into ordering violations. Known-scan
exception denials retain their broker audit attribution. Proxy HTTP and CONNECT denials
log at error level so mitmproxy quiet mode does not hide them.

This changes harness accounting, authority validation and transport metadata only.
Probe values, controls, proof rules, thresholds and browser action caps are unchanged.


The ledger honours an explicit concurrency/rate override in the immutable, audited
scope. `SCOPELENS_SCOPE_MAX_IN_FLIGHT` (default eight) and
`SCOPELENS_SCOPE_MAX_REQUESTS_PER_SECOND` (default ten) bound the effective values.
Without an override the budget defaults remain two concurrent requests and two
requests per second, also bounded by those ceilings. Other budget overrides continue
to lower the defaults. An approved 4/5 scope therefore retains 4/5 with default ceilings;
a 20/20 override becomes 8/10.

At the first successful scan admission, a `budget.increase` audit event records each
approved rate/concurrency value above its deployment default. Its scan subject and
`scope_version_id`, `scope_key` and `scope_version` bind the event to the immutable
authorization. The `increases` map records `default`, `approved` and `effective` per
field, including requests reduced by a ceiling. The event commits atomically with
admission; refused admissions and duplicate task deliveries add no increase event.
The operator's `scope.register` audit also includes `budgets_override` with numeric
`max_in_flight` and `requests_per_second` values when explicitly supplied. It omits
unsupplied defaults, other budget fields and operator notes from that added map.

The proxy honours the effective scope `max_in_flight` returned by policy and applies
the same `SCOPELENS_SCOPE_MAX_IN_FLIGHT` ceiling independently. Compose forwards that
setting to both policy and proxy. Missing policy limits keep the per-scan default of
two; invalid/nonpositive limits deny and release the slot.

`SCOPELENS_PROXY_MAX_IN_FLIGHT` sets the global proxy capacity across scans (default
eight, positive integer), and the Compose proxy service forwards that setting. A
scope approved at four can therefore hold four target requests concurrently; scopes
at two remain limited to two. Slots stay held through the response and release on
completion, error, denial or cancellation. Policy scheduling and the proxy's
`wait_seconds` pacing are unchanged. Raising global proxy capacity does not raise
any scope's approved concurrency, request rate or request budget.

Reviewed XSS, HTML and DOM-XSS GET navigation actions also carry optional `probe_task`
on the browser admission command. The policy validates the same frozen conditional
approval or admitted input-task claim and exact template as HTTP accounting. Ordering,
in-flight ownership, scope, session expiry and action safety checks still apply.
Unannotated actions, invalid claims and other controls use the exploration action cap.

Valid active admissions use each control's existing registry request cap, checked
against both prior browser attempts and target HTTP requests for the same reference.
`assessment_plan.reviewed_browser_actions` stores per-task admitted attempts under the
scan lock. This scan-wide counter survives browser context handoff; failed/blocked
captures spend it too. `SCOPELENS_BROWSER_MAX_ACTIVE_ACTIONS` is the absolute per-scan
active-action ceiling (default 500). Exploration retains `browser_max_actions` and its
current defaults, counting only admissions without validated active authority.

An active admission requires remaining shared request budget. It does not reserve an
extra request: every actual navigation and subrequest still goes through the broker's
atomic request reservation exactly once. A concurrent worker can exhaust the budget
before the navigation, in which case target HTTP is denied. No action annotation grants
an origin, role, write, ZAP signature or request-budget exemption.

The expanded worker sends the same admission command before each reviewed GET capture
and completes it on success or failure. Its local total-action safety bound uses the
active-action setting; the shared policy independently enforces the scan-wide ceiling.
The admission reply's `reviewed_probe` flag selects the active local budget only after
policy validation. Missing/invalid claims, absent admission callbacks and POST captures
use the local exploration cap, with a fallback to the original 30-action library default.
Approved POST captures retain their existing local exploration cap and target HTTP
checks and receive no GET accounting exemption. Worker environment forwarding includes
`SCOPELENS_BROWSER_MAX_ACTIVE_ACTIONS`; no worker-supplied value replaces policy limits.
