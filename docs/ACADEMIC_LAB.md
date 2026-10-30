# Academic development lab

This pack contains only in-memory synthetic student A, student B and staff records.
The public fixture password is test data. Credential values still enter through the
encrypted assessment intake and must never appear in exported evidence or logs.
The pack does not establish customer findings or independent holdout qualification.

## Cases and expected results

| Case | Explicit permission | Vulnerable fixture | Fixed fixture |
|---|---|---|---|
| Student A record view | A and staff allowed; B forbidden | B's repeated marker access confirmed | B's declared denial proven |
| Marks and attendance | Student B cannot write student A's designated record | Each protected write confirmed by two staff reads | Both writes leave the protected value unchanged |
| Protected assignment | Student A cannot assign `academic_status` through profile update | Assigned protected value confirmed | Protected value unchanged |
| Ordinary field control | Student A can update `display_name` | Accepted request leaves selected protected field unchanged | Same control passes |
| Staff function | Staff allowed; A and B forbidden | Forbidden seeded function marker confirmed | Student denials proven |
| Student approval | Student B cannot approve student A's draft | Approved state confirmed | Forbidden request leaves draft unchanged |
| Out-of-order approval | Staff cannot approve a draft before review | Approved state confirmed | Invalid transition leaves draft unchanged |
| Logout | Each identity's cookie must stop authenticating | Cookie replay still authenticates | Cookie replay receives declared unauthenticated response |
| Expired identity | Supplied expired student B identity cannot execute | Local blocking gate | Deployed incomplete comparisons, never a pass |

`WorkflowRecipe` accepts one mutation. Approval coverage means the two exact invalid
`draft -> approved` transitions above. The local HTTP gate also checks the legitimate
`draft -> submitted -> reviewed -> approved` sequence with the declared student and
staff actors, then resets and reads draft. This does not claim general sequence
exploration. The deployed ordinary-field proof establishes an accepted update with
an unchanged protected value. Local HTTP checks separately establish that the
ordinary field persists before reset.

Local tests select each designated protected field from marks, attendance,
academic status and approval state. The operator-supplied recipe defines the permission;
a field's name never grants authorization. Every case uses the same resource fence,
`student-a-record`. A failed reset prevents further mutations, including writes to
another property. Cancellation uses a separate cleanup session. Recovery reads or
resets the baseline and never replays the original mutation.

## Isolated deployment

The new `labs/academic-workflows.compose.yml` overlay adds two fixtures to the existing
internal lab network. Fixtures have no published ports, no external network and no
route to public internet. Their exact bindings must exist in `deploy/lab_services.yaml`:

| Binding | Address | Port |
|---|---|---|
| `labs-academic-a` | `172.28.0.22` | `8080` |
| `labs-academic-b` | `172.28.0.23` | `8080` |

Start only the fixtures from the repository root, using the existing local Docker
context that owns `scopelens_labs_net`:

```sh
docker compose -f labs/docker-compose.yml -f labs/academic-workflows.compose.yml up -d labs-academic-a labs-academic-b
```

The trusted broker must already join the lab network. Workers stay in the dedicated
Lima VM `scopelens-workers`. Preserve `deploy/docker-compose.worker-vm.yml` after the
release overlay so only the supervisor receives its Docker client credentials.
This command does not prepare or restart the application backend. Do not use `make run`.

Development helpers default to explicit HTTP loopback IP origins with a port.
Deployed helpers require both an exact named service and its exact origin. The gate
accepts neither a target URL nor fixture credential argument. Production authority
cannot inherit these lab bindings.

## Local acceptance

```sh
uv run pytest -q tests/test_academic_workflows.py tests/test_academic_lab_driver.py
uv run ruff check labs/academic_workflows tests/test_academic_workflows.py tests/test_academic_lab_driver.py scripts/verify_academic_workflows_lab.py
```

These tests use real local HTTP requests and the existing production collectors and
proof functions. Their `local-test:` references are test captures. They cannot satisfy
the deployed supervisor provenance gate.

## Deployed gate

With the application API already healthy on loopback port 8090 and the lab services
registered, run:

```sh
uv run python -m scripts.verify_academic_workflows_lab
```

The driver logs in through the existing API, creates lab scopes, stores the synthetic
credential through encrypted intake, freezes configurations and queues scans. It
runs paired cases sequentially and cancels scans that exceed their deadline. A
failed or incomplete proof fails the gate. It never treats source code or a worker
verdict as confirmation.

For every academic result it downloads supervisor-admitted captures, verifies their
hashes and run provenance, replays access/session/workflow proof rules and compares
those results with JSON and HTML exports. It requires two staff readbacks, a clean
persistent cleanup ledger and restored-state evidence for writes. It checks the
report's findings, instance counts and score against the dashboard API. Expired
student B coverage must remain incomplete, with no B request sent. Validated receipts
and redacted evidence go to `runs/academic-workflows/deployed` by default.

Individual stateful cases use their own frozen scan configurations while retaining
the same resource fence. The `combined` case runs all six writes in one scan and
requires every recipe to have durable restoration history despite the shared
resource. Each same-case retest retains the original frozen configuration. Simultaneous scans
are unnecessary for the gate and can collide with the shared disposable resource.

If a gate stops after creating a scan, resume its saved scan and receipts rather
than repeat a write:

```sh
uv run python -m scripts.verify_academic_workflows_lab --resume
```

The driver refuses to overwrite existing receipts during a fresh run. Resume checks
each saved scan's exact origin and scope binding, recomputes its immutable configuration
hash, reconstructs the declared case and replays downloaded proofs. Completed cases
queue no new scan. An interrupted case uses its saved scan ID. New execution receives
a fresh scope and credential, since historical authority may have expired. Receipt
updates replace the file atomically.

A repair to
credential fingerprint intake may require fresh identity login/logout captures.
`--resume --refresh-identities` repeats only those identity cases and archives the
previous identity scan IDs. A repeated refresh invocation resumes a refreshed scan
already queued before interruption. Completed academic writes are preserved. Session
fingerprints must remain exact SHA256 digests in admitted evidence; redacted
placeholders cannot establish rotation or replay.

## Same-origin fixed retest

The fixed pair alone does not close findings from the vulnerable origin. The
vulnerable container has one explicit lifecycle flag, `/tmp/academic-fixed`, on its
disposable tmpfs. There is no HTTP administration endpoint. After the vulnerable
gate has produced receipts, the operator can apply the fixture fix without
restarting or resetting the record:

```sh
docker compose -f labs/docker-compose.yml -f labs/academic-workflows.compose.yml exec -T labs-academic-a touch /tmp/academic-fixed
uv run python -m scripts.verify_academic_workflows_lab --fixed-retest
```

The driver resumes only saved vulnerable lab finding IDs. It checks the actual API
origin, original scope, immutable configuration hash, exact recipes and original
finding membership. Expired original authorization requires a reviewed renewal.
The driver prepares a fresh scope for the same origin and a new encrypted credential,
then copies the original case with only the scope ID and credential reference changed.
It supplies those bindings to the retest API. The API must validate the exact original
case contract and record both original and renewed configuration hashes. The original
configuration remains immutable. The driver checks its original hash again after each
retest and independently verifies the fresh scan's new binding and proof.

The gate requires a resolved finding with `retest_state=fixed`; a blocked retest
must not close it. It never
retargets a customer finding or uses the separate fixed host to claim closure.
Retest scan IDs are saved before waiting for proof, so an interrupted invocation
resumes those captures. Renewal bindings and both hashes are saved in
`fixed-retest-authorizations.json`.

The lifecycle flag disappears when the container is recreated. To restore the
vulnerable fixture during development, remove the flag through the same container
lifecycle command. This changes only the synthetic fixture's access checks.

## Limits

Deployed logout and supplied-session expiry are separate cases. Actual server expiry
and role-cookie separation have local HTTP acceptance gates. This stable deployed
gate does not exercise a timed expiry collector or an arbitrary role-change
sequence. Cleanup failure, cancellation and recovery are covered locally; the pack
does not inject deployed failures or change historical cleanup rows.
Public college browser exploration and customer-specific records require their own
gates and authority. No command here scans that portal.

## Deployed measurement on 1 October 2026

The stable owned gate passed all 17 paired cases. The vulnerable and fixed identity
cases each completed 12/12 declared comparisons with exact admitted cookie
fingerprints. Unauthorized record access, staff-function access and logout replay
confirmed on the vulnerable fixture; the fixed fixture passed all three controls.
The malformed historical identity captures were superseded by fresh scans and remain
identified in the archived receipts and gate summary.

The marks, attendance, protected academic-status assignment, ordinary-field control,
student approval, out-of-order staff approval and combined cases passed their expected
vulnerable and fixed gates. Every single workflow completed 1/1 instances; each combined
case completed 6/6. Expected forbidden writes confirmed on the vulnerable fixture and
passed on the fixed fixture. The ordinary-field control passed on both.

The supplied-expiry negative completed 4/6 permission instances. The two expired
student B instances remained incomplete and sent no student B requests. Both aggregate
controls stayed inconclusive, as required.

After both fresh identity gates passed, the lifecycle flag was applied only to the
vulnerable synthetic fixture. Ten current validated original findings then closed through
fresh same-origin retests using the reviewed authority-renewal contract. Each retest
preserved the exact declared case, independently replayed admitted evidence and verified
the unchanged original configuration hash. The seven write findings and three identity
findings all finished with `status=resolved` and `retest_state=fixed`.

Across the paired cases and retests, 105 of 107 declared instances completed. The only
incomplete instances are the two intentionally expired comparisons. All 41 workflow
recipe executions have verified clean restoration. A final read-only resume revalidated
all 17 saved paired receipts without queuing new scans.

Actual configuration and scan readiness/planning GET routes passed typed contract checks
for both fresh identity variants. Each agenda retained all 12 declared cases and matched
its readiness revision, coverage and immutable bindings. Those calls changed neither the
configuration nor its scope's scan count, and granted no execution authority.

The stable designated-case gate is complete. It establishes owned synthetic deployed
behavior and restoration; it does not establish customer findings or independent holdout
qualification. Timed server expiry, arbitrary role changes and injected deployed cleanup
failures remain outside these particular gate results. Validated reports, projections,
receipts and proof artifacts are under `runs/academic-workflows/deployed`. The final
`gate-summary.json` records completion, superseded identity scan IDs, preserved hashes
and each retest's result.
