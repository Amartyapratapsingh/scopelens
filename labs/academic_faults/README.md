# Academic cleanup fault gate

This service contains only the synthetic records and identities from
`labs/academic_workflows`. It imports that fixture and adds failure controls in
`/tmp/academic-faults`, which lives in container tmpfs. No customer data is used.

The exact service is `labs-academic-faults`, `http://172.28.0.24:8080`. The overlay
`labs/academic-faults.compose.yml` attaches it to the existing internal labs network.
It has no published ports, no other network, a read-only filesystem, an unprivileged
user, and no Linux capabilities. Its binding must be admitted in
`deploy/lab_services.yaml` before the API accepts a scope.

## Lifecycle controls

Reset requests from the real staff identity return HTTP 503 by default. A local
`allow-reset` file permits the normal fixture reset handler. A local `hold-mutation`
file holds the marks response after the record changed; `mutation-applied` records
that exact point. A local `release-mutation` file releases the held response.
All files are under `/tmp/academic-faults`. There is no HTTP administration route.

`requests.jsonl` records only method, path and status. It records no body, password,
cookie or session identifier. This ledger is fixture telemetry, not supervisor proof.
A restart restores the in-memory synthetic seed and clears tmpfs. It has no access to
the backend cleanup ledger and cannot release its fences.

## Deployed gate

Start only this additional service after the existing academic scans have finished:

```sh
docker compose -f labs/docker-compose.yml -f labs/academic-faults.compose.yml up -d labs-academic-faults
```

Use the same operator, database and credential encryption configuration as the
running API. The driver is fixed to the local API and exact .24 service; it accepts
no external target URL. It needs Docker access to this fixture and read access to
backend scan and cleanup persistence.

```sh
PYTHONPATH=backend:. .venv/bin/python scripts/verify_academic_recovery_lab.py --output runs/academic-recovery-deployed
```

The driver queues a real marks workflow with stored credentials and immutable
configuration. It requires a `completed_partial` report, trusted supervisor
captures that independently prove the forbidden mutation, a failed reset response,
and a durable `cleanup_failed` fence. A new authorization revision then scans
attendance on the same record. Its write must be suppressed by that resource fence.

Fresh authenticated recovery before repair must fail and leave the original fence
unchanged. The driver saves fixture telemetry, explicitly restarts the fixture to
restore its seed, and queues another fresh read-only recovery. It checks the trusted
recovery artifact against its persisted binding and requires the original fence to
become clean. Recovery may log in and probe identity, but sends no record mutation or
reset.

The cancellation case holds a second real marks mutation response after application.
The driver cancels through the public API at that marker, checks the persisted token
issue epoch is older than the cancel epoch, and checks the original fence remains
`pending` or `mutation_sent`. It releases the held response and observes no later
record write or reset through the supervisor's 30 second stop window. Its outcome
remains unknown. After explicit fixture restart, fresh trusted readback recovers the
fence without replaying the original mutation.

Each queued scan ID is saved before waiting. Validated reports, trusted artifacts,
fixture request snapshots and final receipts are written under the output directory.
The driver refuses to reuse a directory containing queued scans, so a rerun cannot
repeat an interrupted mutation.

If a run stops, inspect its saved scan IDs and `/api/cleanup-recoveries/pending`.
Cancel any still-running source scan through the API. To repair one known pending
academic fault fixture record and recover only that existing fence:

```sh
PYTHONPATH=backend:. .venv/bin/python scripts/verify_academic_recovery_lab.py \
  --output runs/academic-recovery-repair \
  --recover-cleanup CLEANUP_UUID --restore-fixture
```

This mode verifies ownership, the exact .24 origin and the original academic
resource and recipe. It creates fresh identity authority and queues recovery only.
Omit `--restore-fixture` if the fixture was already restored through its lifecycle.
It never inserts a synthetic cleanup row or relabels one as clean itself.

## Local verification

`tests/test_academic_recovery_lab.py` checks the fault fixture's applied marker,
response hold, lifecycle-only reset permission, redacted telemetry, academic contract,
and local resource fence behavior. Local HTTP captures are test observations and
cannot establish deployed intake trust. The deployed gate is the required runtime
verification for the failure, cancellation and recovery path.
