"""Check local build prerequisites and frozen archives without starting a scan."""

import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    failures = []
    if sys.version_info[:2] != (3, 12):
        failures.append("Run this check with uv run python so Python 3.12 is selected.")
    commands = {
        "git": ["git", "--version"],
        "make": ["make", "--version"],
        "node": ["node", "--version"],
        "pnpm": ["pnpm", "--version"],
        "docker": ["docker", "info", "--format", "{{.OSType}}"],
        "compose": ["docker", "compose", "version", "--short"],
    }
    for name, command in commands.items():
        if not shutil.which(command[0]):
            failures.append(f"Missing {name}; see docs/WINDOWS_SETUP.md.")
            continue
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=20)
        except (OSError, subprocess.TimeoutExpired):
            failures.append(f"{name} did not respond.")
            continue
        if result.returncode:
            failures.append(
                f"{name} check failed; no command output containing configuration is printed."
            )
            continue
        value = result.stdout.strip()
        if name == "node" and (
            not re.match(r"^v\d+\.\d+\.", value)
            or tuple(map(int, value[1:].split(".")[:2])) < (22, 13)
        ):
            failures.append("Install Node.js 24 LTS inside Ubuntu, or use Node.js 22.13 or newer.")
        elif name == "pnpm" and value != "10.33.0":
            failures.append("Install the repository-pinned pnpm 10.33.0.")
        elif name == "docker" and value != "linux":
            failures.append("Docker must be running Linux containers with Ubuntu WSL integration.")
        elif name == "compose":
            match = re.search(r"(\d+)\.(\d+)\.(\d+)", value)
            if not match or tuple(map(int, match.groups())) < (2, 24, 4):
                failures.append("Docker Compose 2.24.4 or newer is required by release overrides.")
            else:
                print("OK: compose")
        else:
            print(f"OK: {name}")
    for path in (".env.example", "uv.lock", "frontend/pnpm-lock.yaml", "Makefile"):
        if not (ROOT / path).is_file():
            failures.append(f"Required project file is missing: {path}")
    pins = json.loads((ROOT / "checks_registry/tooling/releases.json").read_text())
    for name, pin in pins.items():
        path = ROOT / "workers/vendor" / pin["file"]
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != pin["sha256"]:
            failures.append(
                f"Missing or changed pinned archive: {name}; run uv run python scripts/fetch_m3_tools.py."
            )
        else:
            print(f"OK: pinned {name}")
    for failure in failures:
        print(f"NEEDS ATTENTION: {failure}", file=sys.stderr)
    if failures:
        return 1
    print(
        "Local prerequisites are ready. This check does not qualify the Windows runtime or start scans."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
