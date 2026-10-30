"""Verify a vendored tool against the frozen release manifest before installation."""

import hashlib
import json
import sys
from pathlib import Path


def main() -> None:
    manifest_path, name, archive_path = sys.argv[1:]
    manifest = json.loads(Path(manifest_path).read_text())
    expected = manifest[name]["sha256"]
    actual = hashlib.sha256(Path(archive_path).read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit(f"{name}: checksum mismatch")
    print(f"{name}: verified")


if __name__ == "__main__":
    main()
