"""Freeze locally built image IDs and source hashes; never write environment secrets."""

import json
import subprocess
from pathlib import Path

from evaluation.run import source_fingerprint

images = {
    "SCOPELENS_RELEASE_API_IMAGE": "scopelens-dev-supervisor",
    "SCOPELENS_RELEASE_PROXY_IMAGE": "scopelens-dev-proxy",
    "SCOPELENS_KALI_WORKER_IMAGE": "scopelens/kali-tool:dev",
    "SCOPELENS_BROWSER_WORKER_IMAGE": "scopelens/browser-worker:dev",
    "SCOPELENS_TOOL_WORKER_IMAGE": "scopelens/tool-worker:dev",
}
ids = {
    key: subprocess.run(
        ["docker", "image", "inspect", name, "--format", "{{.Id}}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    for key, name in images.items()
}
assert all(value.startswith("sha256:") and len(value) == 71 for value in ids.values())
output = Path("runs/release")
output.mkdir(parents=True, exist_ok=True)
(output / "images.env").write_text(
    "\n".join(key + "=" + value for key, value in ids.items()) + "\n"
)
(output / "freeze.json").write_text(
    json.dumps(
        {
            "source_fingerprint": source_fingerprint(),
            "images": ids,
            "qualification": "local lab candidate; see benchmark and provider results",
        },
        indent=2,
    )
    + "\n"
)
print("Frozen image IDs and source fingerprint in runs/release (no secrets)")
