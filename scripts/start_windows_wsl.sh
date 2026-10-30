#!/usr/bin/env bash
set -euo pipefail

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if ! grep -qi microsoft /proc/sys/kernel/osrelease; then
  echo 'Run this launcher in Ubuntu on Windows WSL2.' >&2
  exit 1
fi
export PATH="$HOME/.local/bin:$HOME/.local/node24/bin:$PATH"
cd "$project_root"
for tool in uv pnpm make docker; do
  command -v "$tool" >/dev/null || {
    echo "Missing $tool. Run bash scripts/setup_windows_wsl.sh first." >&2
    exit 1
  }
done
if [ ! -f .env ]; then
  echo 'Run bash scripts/setup_windows_wsl.sh first to initialize this laptop.' >&2
  exit 1
fi
uv run python scripts/check_portable_checkout.py
make run
printf '\nOpen http://localhost:5173/dashboard in your Windows browser.\n'
printf 'Ctrl+C stops the dashboard. To stop backend services too, run: make down\n\n'
exec make frontend
