# Run ScopeLens on a Windows laptop

This package includes the backend, React dashboard, tests, evaluation tools,
Docker definitions, lab apps, and pinned ZAP, Nuclei, testssl and GOST archives
for both x64 and ARM64 Linux. It includes the latest local source changes.

Run the apps through Ubuntu on WSL2 and Docker Desktop. This is a source package;
the first setup needs an internet connection for runtimes, dependencies and Docker
base images. Windows, Ubuntu and Docker Desktop installers are not bundled.

## 1. Install Windows prerequisites

Open PowerShell as administrator:

```powershell
wsl --install -d Ubuntu
wsl --update
```

Restart if Windows requests it. Open Ubuntu and create your Linux user account.
Install [Docker Desktop](https://docs.docker.com/desktop/setup/install/windows-install/),
start it, enable the WSL2 engine, and enable **Settings > Resources > WSL Integration > Ubuntu**.
Docker must use Linux containers. See the [Microsoft WSL guide](https://learn.microsoft.com/en-us/windows/wsl/install)
and [Docker WSL guide](https://docs.docker.com/desktop/features/wsl/).

## 2. Extract and install in Ubuntu

Save `scopelens-windows.zip` to your Windows Downloads folder. Open Ubuntu and run
the following, replacing `YOUR_WINDOWS_USERNAME` with your Windows account folder:

```bash
sudo apt-get update
sudo apt-get install -y unzip
mkdir -p "$HOME/dev"
unzip "/mnt/c/Users/YOUR_WINDOWS_USERNAME/Downloads/scopelens-windows.zip" -d "$HOME/dev"
cd "$HOME/dev/scopelens"
bash scripts/setup_windows_wsl.sh
```

The installer sets up the Python environment, Node.js, pnpm and application dependencies.
It generates fresh local passwords and encryption keys in `.env`. Your API keys and
the Mac's original `.env`, database, scan data, certificates and VM disks are excluded.
Source-control history is excluded too; every source file is included as a snapshot.

## 3. Start both apps

With Docker Desktop running, open Ubuntu:

```bash
cd "$HOME/dev/scopelens"
bash scripts/start_windows_wsl.sh
```

Leave that terminal open. Visit **http://localhost:5173/dashboard** in your Windows
browser. The backend is available at **http://localhost:8090** with its OpenAPI
contract at **http://localhost:8090/openapi.json**. The first build can take a while.

For API login, read `SCOPELENS_OPERATOR_USERNAME` and `SCOPELENS_OPERATOR_PASSWORD`
locally from the newly generated `.env`. Do not share that file.

## AI configuration

The scanner works with deterministic fallbacks until you configure an API provider.
Read `docs/MODEL_CONFIGURATION.md` and `docs/MODEL_COMPARISON.md` for configuration
and the measured model comparison. The tested text-role default is GLM-5.3 through
CommandCode, and the existing screenshot model is GLM-5.3 Flash. Add your own API
keys on the Windows laptop, then restart the backend. API keys are not in this ZIP.

## Stop and restart

Press Ctrl+C to stop the dashboard. In Ubuntu, stop backend containers while preserving
the database and evidence volumes with:

```bash
cd "$HOME/dev/scopelens"
export PATH="$HOME/.local/bin:$HOME/.local/node24/bin:$PATH"
make down
docker compose -f labs/docker-compose.yml down
```

Run the start script again to resume. Avoid `make down-hard` unless you intend to
delete local scan data.

## Verification and platform limits

Run `make test-all`, `make lint` and `make verify-m4` on the new laptop before treating
it as a verified installation. Packaging and source checks on the Mac do not establish
that these checks pass on your Windows hardware.

The dedicated worker VM and generated-code VM currently use macOS Lima and are not
ported to Windows. Use the container development setup described here and leave
generated scripts disabled. The setup script applies that default. Full deployment
details and troubleshooting are in `docs/WINDOWS_SETUP.md`.
