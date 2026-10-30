# Continue on Windows with WSL2

Run this project inside Ubuntu on WSL2, with Docker Desktop using Linux containers.
The Makefile and lab tooling use Bash and Linux paths. These instructions are for
the container development topology. The existing dedicated worker and generated-code
Lima VM deployment requires Apple Silicon macOS and is not a Windows runtime.

## Install the Windows prerequisites

Open PowerShell as administrator:

```powershell
wsl --install -d Ubuntu
wsl --update
```

Restart Windows if requested, open Ubuntu, and create your Linux user.
Confirm Ubuntu uses version 2 with `wsl --list --verbose` in PowerShell.
[Microsoft's WSL installation guide](https://learn.microsoft.com/en-us/windows/wsl/install)
documents this setup.

Install [Docker Desktop for Windows](https://docs.docker.com/desktop/setup/install/windows-install/).
Enable its WSL2 backend and **Settings > Resources > WSL Integration > Ubuntu**.
Docker's [WSL development guide](https://docs.docker.com/desktop/features/wsl/use-wsl/)
recommends keeping code in the Linux filesystem. Extract the supplied project under
`~/dev/` inside Ubuntu, rather than developing under `/mnt/c/`.

## Install the project

Open an Ubuntu terminal in the extracted `scopelens` directory and run:

```bash
bash scripts/setup_windows_wsl.sh
```

The helper checks Docker access, installs Ubuntu build tools, uv 0.12.11,
Linux Node.js 24, pinned pnpm 10.33.0, Python 3.12, and locked Python/frontend
dependencies, plus Chromium and its system libraries for the host browser tests
and Redis for the disposable circuit-concurrency tests.
It uses the [official uv installer](https://docs.astral.sh/uv/getting-started/installation/)
and [Node.js release downloads](https://nodejs.org/en/download), verifying the Node
archive against the release checksums. See [pnpm installation](https://pnpm.io/installation)
for the package manager installation methods.

`make install` generates fresh local credentials when `.env` is absent. The setup
helper applies the documented non-secret limits only to that newly generated file:
browser active actions 1,200, global proxy concurrency 8, scope concurrency ceiling 8,
and scope rate ceiling 10. Generated scripts and native ZAP remain disabled.
An existing `.env` is preserved. Configure model providers locally using
`MODEL_CONFIGURATION.md`; no provider keys are included in the transfer package.

In each new Ubuntu terminal, make these locally installed tools available:

```bash
export PATH="$HOME/.local/bin:$HOME/.local/node24/bin:$PATH"
```

## Start and verify

```bash
uv run python scripts/check_portable_checkout.py
make run
curl -fsS http://127.0.0.1:8090/readyz
```

Start the dashboard in a second Ubuntu terminal:

```bash
export PATH="$HOME/.local/bin:$HOME/.local/node24/bin:$PATH"
make frontend
```

Alternatively, `bash scripts/start_windows_wsl.sh` checks local prerequisites, starts
the backend and labs, and runs the dashboard in the same terminal. See
`../START_HERE_WINDOWS.md` for the packaged quick-start instructions.

Open `http://localhost:5173/dashboard` on Windows. Read the locally generated
operator credentials from `.env` when using API sign-in. `make run` builds the
worker images and starts the owned fixture services; it downloads Docker base images
and Python/npm dependencies, so this is not an offline installation.

Run the project checks after installation:

```bash
make test-all
make lint
make verify-m4
```

These commands must pass on the new laptop before treating it as a verified runtime.
Source checks performed on the Mac do not establish Windows runtime acceptance.

## Deployment and evidence

The Windows ZIP includes the complete source snapshot, documentation, dependency locks
and pinned scanner archives. It excludes Git history, saved scan evidence, the running
database, Docker volumes, VM disks, certificate private keys and the original `.env`.
Documentation may refer to past Mac scans; fresh scopes and scans on Windows get new IDs.

Build and freeze images on the new laptop before using the release override:

```bash
make m3-images
make worker-image
docker compose --env-file .env -f deploy/docker-compose.dev.yml -f deploy/docker-compose.m4.yml build supervisor proxy
make freeze-release
make run-release
```

Do not use the Mac's saved image IDs as local Windows image pins. The development
and release-container topologies are available through Docker Desktop. The stronger
dedicated worker VM and generated-code VM boundary is not ported or qualified for
Windows; keep generated scripts disabled until an equivalent environment is implemented
and verified. Follow `BACKEND_STATUS.md` for remaining acceptance gates and the
current native ZAP state.
