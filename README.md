# ScopeLens

## Get the source

```sh
git clone https://github.com/Amartyapratapsingh/scopelens.git
cd scopelens
```

On Windows, run the setup inside Ubuntu WSL2 with Docker Desktop's Ubuntu integration enabled:

```sh
bash scripts/setup_windows_wsl.sh
bash scripts/start_windows_wsl.sh
```

Open `http://localhost:5173/dashboard`. See [Windows setup](docs/WINDOWS_SETUP.md)
for prerequisites and platform limitations. Downloaded scanner archives, installed dependencies,
local `.env` credentials, databases and scan evidence are not included in this repository.
The setup scripts fetch the pinned tools and generate fresh local configuration.
Only assess websites you own or have permission to test.

The existing proprietary/UNLICENSED project designation is unchanged by this public source publication.
Third-party assets retain their respective license notices.

Operator-only assessment backend: scoped URL → HTTP and browser discovery → reviewed scanners
and input probes → evidence verification → category scorecards → HTML/JSON report.

**Current status:** the backend runs end to end on owned labs. The independent held-out benchmark
and owned-site pilot required for Phase 1 release are not signed off. See
[backend status](docs/BACKEND_STATUS.md), [build plan](docs/ScopeLens_MVP_Build_Plan.md),
[measured milestones](docs/MILESTONES.md), and [API contract](docs/API_CONTRACT.md).

## Start the backend

For a Windows development laptop, use the [Ubuntu WSL2 setup guide](docs/WINDOWS_SETUP.md)
and its setup helper. The existing dedicated Lima VM deployment remains Mac-specific.

Prerequisites: Docker with Compose, Python 3.12 and `uv`. Tool images support the architectures
listed in `checks_registry/tooling/releases.json`; the generated-code VM configuration currently
requires Apple Silicon macOS and Lima 2.2 or later.

```sh
make install-backend
make run
```

`make install-backend` creates `.env` only when absent, generates local credentials and an
evidence encryption key, and installs locked dependencies. `make run` builds pinned workers,
starts the owned labs and all backend services, and waits for readiness. First build downloads
the pinned scanner distributions. API: `http://127.0.0.1:8090`; schema: `/openapi.json`.

Read the operator username/password locally from `.env`. Do not commit that file. Login through
`POST /api/auth/login`; then register a scope and create a scan as described in the API contract.
The supplied labs are `labs-good` and `labs-bad`, HTTPS port 8443 with transport-probe port 80.
Use profile `external-dast` for the reviewed active pack. Production scopes cannot inherit lab
bindings. New production probe endpoints require an explicit reviewed pack entry.

The automated lab journey creates scopes/scans and downloads real reports:

```sh
make verify-m4
```

Exports and measurement logs are under `runs/`, which is git-ignored. `make down` stops services
and keeps metadata/evidence. `make labs-down` removes disposable lab volumes. `make down-hard`
deletes application volumes; use it only when you intend to discard local scan data.

## Scanning and reports

- Scoped HTTP crawl, robots/sitemap discovery, passive fingerprints and API inventory.
- Leased Playwright browser exploration, SPA discovery and captured network/state evidence.
- ZAP passive analysis, reviewed Nuclei templates and constrained testssl measurements.
- 17 deterministic configuration/exposure controls; five experimental paired controls for
  reflected XSS, HTML injection, non-timing SQL behaviour, redirects and CORS configuration.
- Baseline-first LangGraph coordination with bounded, durable follow-ups. Models propose;
  registered proof rules determine confirmation and deterministic code computes scores.
- Authenticated progress SSE, findings, evidence downloads, retests and escaped HTML/JSON exports.
- Durable jobs, fencing, cancellation, bounded network traffic, encrypted evidence, retention
  and backup/restore.

A missing advisory snapshot, hidden component version, blocked endpoint or incomplete test is
not a pass. The scorecard displays a number only where coverage and verification gates permit
one. The current lab reports therefore contain category scores and an explicit reason why the
overall score is withheld. Five active controls have verified fixture pairs but remain
experimental until the independent benchmark supports broader claims.

## Configure models and generated analysis

Use the OpenAI-compatible provider and model you choose in `.env`:
[configuration instructions](docs/MODEL_CONFIGURATION.md). Without model configuration, the
reviewed scanner, deterministic fallback planner and report templates still work. All model
roles share durable call/cost reservations; unknown usage stays unknown.

```sh
make qualify-models  # synthetic prompts; calls only configured approved providers
```

Generated Python/Bash runs in a dedicated VM, separately from reviewed scanner containers:

```sh
make sandbox-up
make sandbox-gateway  # leave running in its own terminal
make verify-sandbox
make verify-sandbox-rpc
```

Enable `SCOPELENS_GENERATED_SCRIPTS_ENABLED=true` in `.env` and restart the backend only after the
VM checks pass. Generated output remains untrusted. Networked generated scripts are limited to
an explicit lab capability through the broker RPC; the guest has no ordinary network access.
The VM has no host directory mounts, Docker socket or control-plane credentials.

## Verify and freeze a deployment

```sh
make test-all
make lint
make verify-m4
make freeze-release
make run-release
```

The release override uses immutable local image IDs and removes runtime source mounts. It is a
repeatable lab candidate, not evidence that the independent benchmark or production boundary
has passed. `runs/release/freeze.json` records image IDs and a source fingerprint. Rebuild and
freeze again after changing code/configuration; never reuse a stale freeze as a new revision.

For an equal-budget comparison, use one immutable **stateless lab** scope:

```sh
uv run python -m evaluation.run --scope-id YOUR_LAB_SCOPE_ID --output runs/comparison
```

This records baseline/adaptive findings, requests, model ledger and corroborations. It does not
claim an accuracy improvement from one pair. Evaluation labels remain outside scanner images.
See [evaluation guide](evaluation/README.md) for the independent release gate.

## Evidence operations

Keep the encryption key in a separate protected backup; losing it prevents decryption.
Existing pre-encryption objects remain readable for migration, while new objects use the key.
Expired downloads return 410; pruning preserves finding/evidence metadata and audit history.

```sh
make retention-plan
make retention-apply
uv run python scripts/backup_restore.py backup runs/backups/backup.enc
uv run python scripts/backup_restore.py restore runs/backups/backup.enc \
  --database scopelens_restore_review --evidence-dir runs/restore/review
```

Restore requires a new database and directory and never overwrites the running database. Before
switching a deployment to restored metadata, reconcile leases/tasks and revoke old capabilities.
Backups include metadata plus evidence and are encrypted; backup and retention coordinate via a
PostgreSQL advisory lock. The supervisor retains privileged Docker access as recorded in Q-10.

## Dedicated worker deployment

The local final-deployment path moves scanner and browser workers into their own VM while
the API, database and trusted broker stay outside it. The supervisor uses mutual TLS to that
VM's Docker daemon; it no longer mounts the Docker Desktop socket in this configuration.
Use `make run-worker-vm` after provisioning, rather than the container-only development target.
See [worker VM setup and measured boundaries](docs/WORKER_VM.md),
[backend status](docs/BACKEND_STATUS.md), and [validation evidence](docs/VALIDATION_PROGRESS.md).

### Credentials for authenticated assessments

New installations generate a separate identity encryption key. For an existing `.env`, run
`python3 scripts/initialize_identity_key.py` once before `make run-worker-vm`. The initializer
preserves an existing nonempty key, sets private file permissions and prints no key value.
Keep this key when restarting the deployment; replacing it makes existing credentials unreadable.

The API writes encrypted credentials to the persistent `identity_credentials` volume. The
policy service mounts that volume read-only. Scanner workers receive expiring credential
references through the scan's private control channel; they have no volume or encryption key.
Use `POST /api/assessments/credentials` to store a scope-bound credential, then reference its
returned ID in the immutable assessment configuration. Values never appear in API responses.

### Local URL-to-report workspace

With the backend already running, `make frontend` serves the workspace at
`http://127.0.0.1:5173/dashboard`. Enter an owned/authorized website URL and click
**Scan website**. The dashboard registers a production scope for that origin/path,
valid for 24 hours, starts an `external-dast` assessment, and opens its results.
The backend still enforces destination policy, budgets, and enabled capabilities.
A hostname that redirects to a different origin may need that final URL submitted
separately. Do not interpret an incomplete assessment as a clean result.

For this local testing workflow, `make frontend` explicitly enables
`SCOPELENS_LOCAL_WORKSPACE=1`. A development-server-only endpoint uses the operator
credentials in the root `.env` to obtain an ordinary HttpOnly backend session.
It accepts only loopback, same-origin POST requests with a custom header; passwords
never enter frontend code or responses. It is absent from production builds and
is disabled when starting Vite without the opt-in flag. Keep this convenience on
an operator-controlled machine. Existing backend authentication remains enabled.

Verify the URL normalization and local-session boundary with
`pnpm --dir frontend test:local`; build with `pnpm --dir frontend build`.
