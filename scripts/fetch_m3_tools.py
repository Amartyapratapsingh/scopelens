"""Download pinned upstream tool archives and verify every SHA-256 before use."""

import hashlib
import json
import urllib.request
from pathlib import Path

manifest = json.loads(Path("checks_registry/tooling/releases.json").read_text())
root = Path("workers/vendor")
root.mkdir(exist_ok=True)
for name, item in manifest.items():
    path = root / item["file"]
    if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
        print("Downloading", name, flush=True)
        with urllib.request.urlopen(item["url"], timeout=120) as response:
            data = response.read()
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise RuntimeError(f"{name}: checksum mismatch")
        path.write_bytes(data)
    print(name, "verified", flush=True)
