# Authenticated assessments and disposable workflows

The B4 and B5 modules accept explicit operator policy. They never infer ownership or
permission from a model. All registry entries remain experimental pending independent
qualification. The fixtures exercise local synthetic records, not customer accounts.

## B4 contracts

- `IdentityProfile` declares a login recipe or supplied header references and an independent
  session probe. Credentials are encrypted at rest and resolved by owner/scope with expiry.
- `IdentitySessions` requires a fresh broker-bound `httpx.Client` for each role. Every login,
  probe, comparison and logout uses that transport. Redirects are disabled; credential origin
  is pinned to the declared probe origin; responses are capped at 1 MiB.
- `PermissionMatrix` names synthetic records, owner identity and per-role access policy.
  Object/function/tenant/property checks require the authorized marker baseline, verified
  comparison identity before and after each read, and two reproducible comparisons.
- A 403 alone is inconclusive. The policy must name the application's denial or shared/redacted
  response value. Expiry, redirects, missing credentials and WAF challenges cannot earn a pass.
- `BrowserIdentitySessions` receives fresh controller-created proxy-bound contexts. Each
  identity has one action owner; releasing a lease closes the context and discards its state.
  HTTP and browser sessions never share cookie stores or serialize storage state to disk.
- Credentialed CORS confirmation requires an operator-controlled foreign-origin grant, a
  protected baseline unavailable anonymously, and two real browser reads of the exact synthetic
  marker using ambient credentials. Header reflection is insufficient. A failed browser read
  is inconclusive, since browser/network restrictions may explain it.

`identities.proof.select_identity_response` retains only exact operator-declared synthetic
probe/marker/denial values. The supervisor assigns evidence references after checking fixed
collector run/tool provenance. `evaluate_access_proof` recomputes access proof from those
records. A worker's `confirmed` string or arbitrary generated stdout cannot substitute for
trusted intake. No full response body, cookie or credential value belongs in these artifacts.

## B5 contracts

`WorkflowRecipe` declares the disposable record, exact mutation, expected initial and forbidden
states, independent owner read-back, explicit reset and action grant. It supports mass assignment
and workflow authorization. `ReadProbeRecipe` supports GraphQL access, private-response cache
separation, designated canary traversal and benign template expression evaluation. Assertions
use JSON pointers; `/$body` explicitly denotes an exact text-body canary.

All calls receive an `admit(recipe)` function tied to trusted profile/action policy. Declaring
an action-grant identifier in JSON does not grant network or mutation authority by itself.
Transport and broker still enforce exact scope, method, budgets and cancellation.

`CleanupJournal` is injected by the execution service. Its methods are:

- `claim(recipe_id, resource_id) -> bool`: atomically persist pending intent before mutation;
  refuse if **any** recipe has unresolved work on that resource in this owner/scope.
- `mark(recipe_id, resource_id, state)`: states are pending, mutation_sent, cleanup_failed,
  clean. Mutation_sent is persisted before sending because an interrupted request may have run.
- `state(recipe_id, resource_id) -> str | None`: read recovery state.

The module includes a durable SQLite implementation for isolated fixture runners. Deployment
uses the root execution service's PostgreSQL journal and scope-bound resource identifiers.

`run_workflow` receives separate ordinary and cleanup session handles. Both remain broker-bound;
there is no cancellation bypass. If cancellation revokes cleanup egress/RPC, partial findings
remain available and the journal stays unresolved. A new run cannot mutate that resource.
`recover_cleanup` requires a fresh explicit admission, restores and verifies the declared seed,
and never replays the original test mutation. Successful cleanup does not invent the lost result.

Mutation confirmation requires independent owner read-back twice. A response claiming success
is insufficient. Read probes require a baseline, distinct negative controls and repeated exact
marker/evaluation results. Pure proof functions validate the record sequence again at intake.

## Reproduce the local capability tests

```sh
uv run pytest tests/test_identity_expansion.py tests/test_identity_browser.py tests/test_workflow_expansion.py -q
```

The browser tests require the pinned Playwright Chromium installation. They use real local HTTP
servers and Chromium contexts. The traversal fixture reads a canary from a temporary directory;
the template fixture evaluates benign arithmetic in Jinja's sandbox. All fixture data is synthetic.
These tests establish implementation behavior, not independent recall/precision or deployment
containment qualification. The full worker/broker integration is verified by the root runner.

Playwright documents [independent nonpersistent contexts](https://playwright.dev/python/docs/api/class-browsercontext)
and the [request context associated with browser cookies](https://playwright.dev/python/docs/api/class-apirequestcontext).
