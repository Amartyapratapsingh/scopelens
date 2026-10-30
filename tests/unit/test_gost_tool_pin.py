"""The installer rejects changed bytes before any GOST package is installed."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

MANIFEST = Path("checks_registry/tooling/releases.json")
VERIFIER = Path("scripts/verify_tool_archive.py")


@pytest.mark.parametrize("arch", ["amd64", "arm64"])
def test_gost_package_bytes_verified_and_tampering_rejected(arch, tmp_path):
    name = f"gost-{arch}"
    entry = json.loads(MANIFEST.read_text())[name]
    assert entry["version"] == "3.0.3+git20251212.7f6d61a-2"
    archive = Path("workers/vendor") / entry["file"]
    command = [sys.executable, str(VERIFIER), str(MANIFEST), name]
    verified = subprocess.run([*command, str(archive)], capture_output=True, text=True)
    assert verified.returncode == 0, verified.stderr
    tampered = tmp_path / archive.name
    tampered.write_bytes(archive.read_bytes() + b"changed")
    rejected = subprocess.run([*command, str(tampered)], capture_output=True, text=True)
    assert rejected.returncode != 0
    assert "checksum mismatch" in rejected.stderr


def test_unknown_architecture_has_no_package_authority(tmp_path):
    archive = tmp_path / "unreviewed.deb"
    archive.write_bytes(b"unknown")
    result = subprocess.run(
        [sys.executable, str(VERIFIER), str(MANIFEST), "gost-unreviewed", str(archive)],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
