# Proposed native ZAP active allowlist

Status on 11 October 2026: the shipped `checks_registry/tooling/zap-active.json`
is `zap-active-allowlist-v2` with **empty `approved_rules`**. No origin or rule is
activated. The operator authorized a future owned labs-good/labs-bad measurement
of 40012 and conditionally approved that rule for three owned sites, subject to
the paired lab gate, the orchestrator's activation go-ahead and new external-dast
scope versions. Those conditions have not been measured or satisfied here.

The v1 compatibility path is limited to lab `external-active-v2` scopes for
`labs-good` and `labs-bad`, and their frozen `GET /active/xss?q=...` input.
The v2 implementation also supports exact-origin-approved production
`external-dast` scopes, including HTTPS. Production dispatch needs a frozen,
reviewed XSS GET input; it does not invent routes or authorize arbitrary endpoints.
GET alone does not prove an endpoint is read-only. No native deployment acceptance
is claimed. Fixture signatures and normalized JSON are not native measurements.

## Origin-scoped approval schema

`zap-active-allowlist-v2` retains the executable, addon, configuration, finite input
values and request/time ceilings from v1. Every pin additionally requires:

- `approved_origins`: one or more exact `{scheme, host, port}` objects. Schemes are
  HTTP/HTTPS, hosts are canonical lowercase ASCII hostnames or canonical IPs, and
  ports are explicit integers. Wildcards, trailing dots, paths and credentials
  are rejected. No implicit subdomain, scheme or port authority is granted.
- `approval`: `{operator, date, decision}` with an ISO date and nonblank operator
  and decision text. This is an operator review record, not a worker claim.

Only rule 40012 is supported by v2. The root accepts only `version` and
`approved_rules`; unexpected fields, missing approval records, duplicate origins,
invalid pins and an empty rule list fail closed. The committed empty root is:

```json
{"version": "zap-active-allowlist-v2", "approved_rules": []}
```

An operator-approved pin's origin and approval record participate in the grant's
canonical pin hash. Dispatch checks the scope origin. Grant creation checks the
scan profile, immutable scope and task origin. Each broker request and each
post-admission liveness check reload the pin and check its exact origin and hash.
Removing an origin, changing the approval record, emptying the manifest or
replacing it with v1 revokes production use. The v1 lab path cannot grant production
authority. All existing task identity, actual Docker container identity, scope
expiry, cancel epoch, finite payload, request/time budget and no-reissue checks
remain mandatory. Production activation will be a separate reviewed commit;
no approval record for the three sites is written by this implementation change.

## HTTPS transport

The trusted supervisor sends real HTTPS using the existing broker CONNECT/MITM
lane, with the scan token only on CONNECT, the separate signed task request on
the inner GET, redirects disabled and certificate/hostname verification against
the mounted broker CA. Missing or invalid CA data fails closed. Signed task
headers remain forbidden on CONNECT. The broker still validates every inner
request; an admitted tunnel does not unlock an active request.

The network-none scanner retains its local HTTP IPC bridge. For HTTPS it sees a
strict HTTP projection with the same hostname, explicit logical HTTPS port,
path and query. Only that exact projection maps back to the logical HTTPS task
URL. The supervisor and broker see and authorize the real HTTPS URL. Native
candidate locations are mapped back before normalization. Rule 40012 operates
on the query and response body; this projection provides no native TLS-analysis
claim. No TLS private key, signing key, grant token or scan token is given to the
scanner. This reuses the existing external transport instead of adding a second
network lane or disabling certificate checks.

## Candidate for the first lab measurement

| Rule ID | Requests it sends | Mutation assessment | Expected requests per input | ScopeLens mapping |
| --- | --- | --- | --- | --- |
| [40012 reflected XSS](https://www.zaproxy.org/docs/alerts/40012/) | One anonymous exact GET seed, reflection eye catcher, and HTML script marker variants in the named query input. Only the finite values below may leave the broker. No browser execution, callbacks or URL payloads. | These owned fixture handlers only return the supplied value. No server state change is intended. Arbitrary customer routes, stored XSS, forms and credentialed sessions are excluded. | Approximately 3–5 GETs for a flat HTML reflection, including the seed. Native control flow may attempt more variants on the escaped fixture. Broker ceiling **8 admitted requests and 60 seconds per input**, within the scan's shared budget. Counts are estimates until a native trace is retained. Unknown variants are denied and make the result partial. | `SL-C03-XSS-01`, potential tool observation only. Existing registered proof rules must independently confirm. No scoring or qualification credit from native alerts. |

Proposed values for this narrow fixture input are `scopelens`, `0W45pz4p`,
`scopelens0W45pz4p`, and `<scrIpt>alert(1);</scRipt>`. This is a finite request
catalog, not blanket permission to run all contexts supported by rule 40012.
An unexpected value, extra query key, changed fixed value, path, origin, method,
request body or credential is refused. A refusal cannot become a clean assessment.

The [official rule source](https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/CrossSiteScriptingScanRule.java)
uses context-dependent payloads. That current source was inspected to prepare this
proposal; it is not a substitute for review of the exact addon bytes below. The
[2.17.0 core constant](https://github.com/zaproxy/zaproxy/blob/v2.17.0/zap/src/main/java/org/parosproxy/paros/Constant.java)
provides the default eye catcher. Operator review and the lab trace must establish
that the finite catalog matches the pinned addon on the intended fixtures.

## Deferred candidates and exclusions

| Rule ID | Requests it sends | Mutation assessment | Requests per input | Mapping and decision |
| --- | --- | --- | --- | --- |
| [40018 SQL injection](https://www.zaproxy.org/docs/alerts/40018/) | Query error/expression variants. Generic configurations can also use boolean, UNION and ORDER BY variants. | A GET handler can execute writes. Generic SQL fragments cannot be declared non-mutating for an unknown backend. | Inspection of current LOW-strength source suggests up to four error and four expression variants, plus baselines/retries. Exact addon count is unmeasured. | `SL-C03-SQL-01`. Deferred, absent from proposed executable catalog. Needs separate finite payload review, read-only fixture contract and measured counts. |
| [40040 CORS header](https://www.zaproxy.org/docs/alerts/40040/) | GETs with different Origin headers, including null and generated origins. | No intended write on reviewed read-only endpoints. Headers must be bound to a reviewed task. | Current source contains up to seven Origin variants and can stop early. Exact pinned count is unmeasured. | `SL-C04-CORS-01`, configuration observation only. Deferred because this initial channel discards scanner headers and has no reviewed Origin catalog. It cannot establish `SL-C04-CORSDATA-01` protected-data exposure. |

The request estimates above came from the official
[SQL rule source](https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SqlInjectionScanRule.java)
and [CORS rule source](https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrulesBeta/src/main/java/org/zaproxy/zap/extension/ascanrulesBeta/CorsScanRule.java).
They need review against exact executable bytes before approval.

All other active rule IDs remain excluded. No timing probes, brute-force rules,
file-writing payloads, SQL write/stacked statements, POST, PUT, PATCH, DELETE,
authentication replay, stored XSS, remote callbacks, spiders or automatic addons
are permitted. Native configuration disables passive scanners and all active
rules before selecting one rule, uses LOW strength/MEDIUM threshold, one thread,
query injection only, no recursion and no followed redirects.

## Proposed executable identity

These hashes were computed from the repository's already pinned ZAP 2.17.0 Linux
archive. They are measurements of local bytes, not operator approval.

| File or configuration | SHA-256 |
| --- | --- |
| Existing release archive | `efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a` |
| `zap-2.17.0.jar` | `015dda4709b5ef79736086bb41e8e2a4e95b04cf6625f14d6bcc02b197c99c0c` |
| `plugin/ascanrules-release-78.zap` | `764a9f803304b6aa266d13f4c39f23b013e206c9e831435cd405871919a021fe` |
| `zap-active-query-v1` native configuration | `7fef0fbec7d67ab43a66afd88b7de2b6d46a68fbae142f2ecea0e29b184269a2` |

Native API setup uses the [ZAP API](https://www.zaproxy.org/docs/api/) and the
[Network addon proxy API](https://www.zaproxy.org/docs/desktop/addons/network/api/).
Only loopback API/bridge sockets exist in the network-none worker. Docker file
IPC carries untrusted request data to the supervisor. The supervisor signs the
actual created container ID and exact request; the proxy checks the signature,
live grant, scope, cancellation epoch and both task/scan budgets. After rate
scheduling it rechecks liveness, strips all capabilities before transmission and
kills a response stream when its task closes or expires. The worker receives no
Docker socket, signing key, grant token or scan egress token.

## Transport design rationale

A separate per-task bearer token, stored only as a hash and enforced by the
broker, is a viable smaller design. It would prove possession of that task's
capability; peer IPs and worker-supplied identity headers would still provide no
additional identity proof. This implementation does not claim that ZAP cannot
present proxy credentials, and no missing upstream feature forced the choice.

The implemented supervisor-mediated design meets the requirement to bind a
request to the container the supervisor actually created while keeping both
scan and task credentials outside the scanner. The worker has no target network
interface and submits bounded request envelopes over Docker file IPC. The
supervisor supplies the actual container ID, canonicalizes the wire request and
signs it with a key the worker never receives. The broker checks that signature
against the live task grant, exact scope version, finite request catalog,
deadline, cancellation epoch and atomic task/scan budgets. An ordinary scan
token or a forged worker identity header cannot substitute for this capability.

The tradeoff is additional trusted IPC and forwarding code. Fixed Docker exec
arguments, bounded envelopes and result archives, no host extraction, immutable
image pins and revocation tests constrain that code. Native scanner output
remains untrusted tool observations and cannot establish proof or scoring
credit. The existing grant token is hashed at rest and retained only by the
supervisor; it is not passed into the worker, logged or exported.

This is the selected implementation in commit `2519598`, rather than a proposal
to replace it with worker-held credentials. The shipped v2 rule manifest remains
empty and all external-dast origins remain disabled. The paired native lab gate and operator
approval of executable rules are separate acceptance requirements.

## Required acceptance evidence

The pending owned-lab gate must retain the committed source SHA, immutable image
ID, executable/addon hashes, exact temporary lab configuration, both scan IDs,
broker request counts/denials, task close/cancellation results and native report
hashes. It must show a vulnerable potential candidate and the escaped fixed
counterpart, while keeping independent registered proof separate. A denied
native payload, timeout or missing output is an incomplete result. It does not
prove the fixed site is clean. External-dast stays disabled until the lab gate and
operator approval are both recorded. No deployment acceptance exists yet.
