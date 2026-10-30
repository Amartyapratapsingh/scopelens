"""Apply documented non-secret transfer settings to an initialized local environment."""

import sys
from pathlib import Path

path = Path(sys.argv[1])
if not path.is_file():
    raise SystemExit("Initialize .env with make install before using this helper.")
settings = {
    "SCOPELENS_BROWSER_MAX_ACTIVE_ACTIONS": "1200",
    "SCOPELENS_PROXY_MAX_IN_FLIGHT": "8",
    "SCOPELENS_SCOPE_MAX_IN_FLIGHT": "8",
    "SCOPELENS_SCOPE_MAX_REQUESTS_PER_SECOND": "10",
    "SCOPELENS_GENERATED_SCRIPTS_ENABLED": "false",
    "SCOPELENS_ZAP_ACTIVE_LAB_ENABLED": "false",
}
remaining = settings.copy()
lines = []
for line in path.read_text().splitlines():
    key = line.partition("=")[0].strip()
    if not line.lstrip().startswith("#") and key in settings:
        lines.append(f"{key}={settings[key]}")
        remaining.pop(key, None)
    else:
        lines.append(line)
if remaining:
    lines += ["", "# Non-secret Windows development transfer settings."]
    lines += [f"{key}={value}" for key, value in remaining.items()]
path.write_text("\n".join(lines) + "\n")
path.chmod(0o600)
print("Applied documented local limits; generated scripts and native ZAP stay disabled.")
