#!/usr/bin/env python3
"""Initialize an existing .env's identity key without rotating or printing secrets."""

from __future__ import annotations

import argparse
import base64
import fcntl
import os
import re
import secrets
import shlex
import sys
import tempfile
from pathlib import Path

KEY = "SCOPELENS_IDENTITY_ENCRYPTION_KEY"
_ASSIGNMENT = re.compile(rf"^\s*(?:export\s+)?{KEY}\s*=\s*(.*)$")


def initialize_identity_key(env_file: Path) -> bool:
    """Return whether a key was added; existing nonempty assignments are preserved.

    Uses only the standard library so this also works before the venv is installed.
    A lock serializes concurrent initializer calls, and replacement is atomic with
    mode 0600 from creation. Read the path after taking the lock because an earlier
    initializer may have replaced the inode while this call waited.
    """
    if env_file.is_symlink():
        raise ValueError("refusing a symlink for the environment file")
    descriptor = os.open(env_file, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "r", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        content = env_file.read_text(encoding="utf-8")
        os.chmod(env_file, 0o600)
        lines = content.splitlines(keepends=True)
        assignments = []
        for number, line in enumerate(lines):
            if match := _ASSIGNMENT.match(line):
                # Quotes and inline comments follow the existing .env conventions.
                # Invalid quoting fails without echoing the line or generating a key.
                values = shlex.split(match.group(1), comments=True, posix=True)
                assignments.append((number, bool(values and any(values))))
        if any(nonempty for _, nonempty in assignments):
            return False
        generated = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
        assignment = f"{KEY}={generated}\n"
        if assignments:
            # Avoid a later blank duplicate overriding the newly generated key.
            indices = {number for number, _ in assignments}
            first = assignments[0][0]
            lines = [
                assignment if number == first else line
                for number, line in enumerate(lines)
                if number == first or number not in indices
            ]
            updated = "".join(lines)
        else:
            updated = (
                content + ("\n" if content and not content.endswith("\n") else "") + assignment
            )
        temp_name = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=env_file.parent,
                prefix=".identity-env-",
                delete=False,
            ) as temp:
                temp_name = temp.name
                os.fchmod(temp.fileno(), 0o600)
                temp.write(updated)
                temp.flush()
                os.fsync(temp.fileno())
            os.replace(temp_name, env_file)
        finally:
            if temp_name and os.path.exists(temp_name):
                os.unlink(temp_name)
        return True


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--env-file", type=Path, default=Path(__file__).resolve().parents[1] / ".env"
    )
    args = parser.parse_args(argv)
    try:
        created = initialize_identity_key(args.env_file)
    except (OSError, ValueError):
        print(
            "Could not initialize identity key; check the .env file and its syntax/permissions.",
            file=sys.stderr,
        )
        return 1
    print(
        "Identity encryption key initialized; environment file mode is 0600."
        if created
        else "Existing identity encryption key preserved; environment file mode is 0600."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
