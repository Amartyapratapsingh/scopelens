"""A healthy nginx listener cannot hide an unavailable dynamic fixture."""

import os
import subprocess

import pytest

from scopelens.config import REPO_ROOT


@pytest.mark.parametrize("active_ready", [False, True])
def test_readiness_includes_dynamic_fixture_through_both_nginx_origins(tmp_path, active_ready):
    curl = tmp_path / "curl"
    curl.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$*" >> "$READINESS_CALLS"\n'
        'case "$*" in\n'
        '  *"/active/xss"*) test "$ACTIVE_READY" = true ;;\n'
        "  *) exit 0 ;;\n"
        "esac\n"
    )
    curl.chmod(0o755)
    calls = tmp_path / "calls.txt"
    env = {
        **os.environ,
        "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        "READINESS_CALLS": str(calls),
        "ACTIVE_READY": str(active_ready).lower(),
        "LABS_READY_TIMEOUT": "1",
    }
    result = subprocess.run(
        ["sh", str(REPO_ROOT / "labs/scripts/readiness.sh")],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == (0 if active_ready else 1)
    requested = calls.read_text()
    assert "http://127.0.0.1:8081/active/xss?q=scopelens" in requested
    if active_ready:
        assert "http://127.0.0.1:8082/active/xss?q=scopelens" in requested


def test_ready_fixture_is_probed_even_at_a_second_boundary(tmp_path):
    date = tmp_path / "date"
    date.write_text(
        '#!/bin/sh\nif test -f "$DATE_SEEN"; then echo 1; else touch "$DATE_SEEN"; echo 0; fi\n'
    )
    date.chmod(0o755)
    curl = tmp_path / "curl"
    curl.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$READINESS_CALLS"\nexit 0\n')
    curl.chmod(0o755)
    calls = tmp_path / "calls.txt"
    result = subprocess.run(
        ["sh", str(REPO_ROOT / "labs/scripts/readiness.sh")],
        env={
            **os.environ,
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
            "DATE_SEEN": str(tmp_path / "date-seen"),
            "READINESS_CALLS": str(calls),
            "LABS_READY_TIMEOUT": "1",
        },
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0
    assert len(calls.read_text().splitlines()) == 6
