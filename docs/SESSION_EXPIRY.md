# Timed server session expiry

`SessionPolicy.expiry_after_seconds` opts a declared identity into a timed server expiry check. It accepts a strict integer from 1 through 60. The default is `None`. Unset values are omitted from serialized policies, preserving existing frozen configuration hashes and execution claims.

For example, an expiry-only policy for an owned synthetic identity is:

```json
{
  "identity_id": "student",
  "cookie_name": "sid",
  "login_rotates": false,
  "expiry_after_seconds": 1
}
```

The identity still needs an explicit login recipe and an independent session probe. Its probe must declare the exact unauthenticated status, JSON pointer, and value. `IdentityProfile.expires_at` controls whether an operator-supplied identity is available to the worker. It does not exercise server session expiry.

The fixed lifecycle collector completes existing rotation, old-session, and logout checks first. It then performs an extra fresh login, verifies the authenticated identity, saves the session cookie, and starts a monotonic clock after verification. It waits at least the declared interval, checking cancellation every 100 milliseconds. It sends the independent probe twice, resetting the saved cookie jar before each request. The replay jar removes the declared cookie's client expiry metadata while retaining its exact value, domain, and path. This forces the server to receive the cookie even after its browser expiry. A response that clears or renews a client cookie cannot change the second replay subject. There is no automatic login during these replays.

A pass requires both post-wait responses to match the declared unauthenticated response. A confirmed issue requires both responses to authenticate the declared identity. Missing requests, a network failure, an undeclared response, mixed replies, malformed fingerprints, incorrect replay binding, or insufficient measured time leave the check blocked or inconclusive. The wait tests an upper bound after verified login. It does not determine the exact instant at which the server expired the session.

The admitted observation has `check: "expiry"`, matching `identity_id` and `proof_id`, and these proof fields:

| Field | Meaning |
| --- | --- |
| `old_cookie_hash`, `new_cookie_hash` | Canonical lowercase SHA-256 fingerprints of independently verified initial and fresh sessions. |
| `replayed_cookie_hash` | Fingerprint of the single saved fresh cookie replayed in both requests. It must equal `new_cookie_hash`. |
| `expiry_after_seconds` | Interval copied from the frozen policy. |
| `expiry_waited_seconds` | Actual elapsed monotonic time at the end of the wait. |
| `expiry_replays` | Exactly two captures with elapsed time measured before each request, response status, verified identity, and declared denial values. |

The existing trusted intake exception preserves only the canonical top-level cookie fingerprints. Raw cookie values never enter the observation. The report requires the instance `session:<identity_id>:expiry`; absence of an admitted expiry observation leaves that instance incomplete. A worker verdict cannot replace the observation.

## Verification and deployed gate hook

The separate fixture in `labs/session_expiry/app.py` expires server sessions after one second using a monotonic clock. Its vulnerable variant keeps the session authenticated. Tests bind it to a temporary loopback port and exercise the production collector and report evaluator. The fixture also covers a cookie-deleting denial, an undeclared status, an incorrect denial body, and a failed second replay.

```sh
.venv/bin/pytest -q tests/unit/test_session_expiry.py tests/test_session_expiry_http.py
```

A deployed gate must first provide an owned synthetic fixture with actual timed server expiry. Add `expiry_after_seconds: 1` to that fixture identity's frozen session policy, create the scan through the normal API, and allow the existing coordinator to admit the policy. The expiry phase adds five broker-governed requests and at least one second to each opted-in policy. Normal request budgets, action admission, authorization expiry, cancellation, worker deadlines, and supervisor intake remain mandatory. This field grants no new role, origin, or action authority.

The separate `labs/session-expiry.compose.yml` overlay defines `labs-session-expiry-a` at `172.28.0.25:8080` and `labs-session-expiry-b` at `172.28.0.26:8080`, with no published ports. The first retains expired sessions and the second expires them after one second. Both expose hash-only server replay counters to the local container verification command.

After the normal deployment process has installed the updated worker/API code, registered the exact owned fixture bindings, and launched the isolated overlay, run:

```sh
PYTHONPATH=backend:. .venv/bin/python scripts/verify_session_expiry_lab.py
```

The gate creates API-admitted scopes, encrypted synthetic credentials, frozen expiry-only configurations, and scans. It downloads the persisted report and supervisor-admitted artifacts and recomputes them through `admitted_artifacts` and `identity_workflow_outcomes`. It requires `session:student:expiry` in both required and completed instances, a pass for the fixed fixture, and a confirmed issue for the vulnerable fixture. It checks actual monotonic timing and uses a fixed `docker exec` command to require the server's receipt of the same expired cookie at least twice. JSON, HTML, finding, summary, and academic readiness projections must agree. Removing trusted references or the expiry observation must leave incomplete coverage. An already-expired profile or a prior logout is insufficient evidence for this gate.

Pending scan bindings and completed receipts are saved under `runs/session-expiry/deployed`. Use `--resume` to verify those same immutable configurations and scans without repeating their mutations. The gate does not start or restart services.

The local HTTP tests do not claim deployed execution. This change does not start or restart services or target customer origins.
