#!/usr/bin/env bash
set -euo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if ! grep -qi microsoft /proc/sys/kernel/osrelease; then
  echo 'This helper is intended for Ubuntu inside Windows WSL2.' >&2
  exit 1
fi
command -v docker >/dev/null || { echo 'Enable Docker Desktop WSL integration first.' >&2; exit 1; }
docker info >/dev/null
sudo apt-get update
sudo apt-get install -y git make curl unzip openssl build-essential ca-certificates xz-utils redis-server
if ! command -v uv >/dev/null; then
  curl -LsSf https://astral.sh/uv/0.12.11/install.sh | sh
fi
export PATH="$HOME/.local/bin:$HOME/.local/node24/bin:$PATH"
if ! command -v node >/dev/null || [ "$(node -p 'Number(process.versions.node.split(".")[0])')" -lt 24 ]; then
  case "$(uname -m)" in
    x86_64) node_arch=x64 ;;
    aarch64) node_arch=arm64 ;;
    *) echo 'Unsupported Node architecture for this helper.' >&2; exit 1 ;;
  esac
  node_tmp=$(mktemp -d)
  trap 'rm -rf -- "$node_tmp"' EXIT
  curl -fsSLo "$node_tmp/SHASUMS256.txt" https://nodejs.org/dist/latest-v24.x/SHASUMS256.txt
  node_archive=$(awk -v arch="$node_arch" '$2 ~ ("^node-v24\\.[0-9]+\\.[0-9]+-linux-" arch "\\.tar\\.xz$") { print $2 }' "$node_tmp/SHASUMS256.txt")
  [ -n "$node_archive" ] && [ "$(printf '%s\n' "$node_archive" | wc -l)" -eq 1 ]
  curl -fsSLo "$node_tmp/$node_archive" "https://nodejs.org/dist/latest-v24.x/$node_archive"
  (cd "$node_tmp" && sha256sum --check --ignore-missing SHASUMS256.txt)
  mkdir -p "$HOME/.local/node24"
  tar -xJf "$node_tmp/$node_archive" -C "$HOME/.local/node24" --strip-components=1
fi
npm install --global --prefix "$HOME/.local" pnpm@10.33.0
cd "$project_root"
uv python install 3.12
environment_existed=false
[ ! -f .env ] || environment_existed=true
make install
# The host test suite launches Chromium outside the worker containers too.
uv run playwright install --with-deps chromium
if [ "$environment_existed" = false ]; then
  uv run python scripts/initialize_windows_settings.py .env
fi
uv run python scripts/check_portable_checkout.py
printf '\nSetup complete. In each new Ubuntu terminal run:\n  export PATH="$HOME/.local/bin:$HOME/.local/node24/bin:$PATH"\nThen cd to the scopelens folder and run make run.\n'
