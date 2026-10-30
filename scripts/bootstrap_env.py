#!/usr/bin/env python3
"""Create a working ``.env`` from ``.env.example`` with freshly generated secrets.

Run via ``make init-env``. Exists so a fresh checkout never starts from a guessable
placeholder credential — the alternative (shipping a default password) is how local
defaults end up in production.

Never overwrites an existing ``.env``.
"""

from __future__ import annotations

import base64
import os
import secrets
import string
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ENV_EXAMPLE = REPO_ROOT / ".env.example"
ENV_FILE = REPO_ROOT / ".env"

PLACEHOLDER = "CHANGE_ME"


def generate_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "-_"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def main() -> int:
    if not ENV_EXAMPLE.exists():
        print(f"error: {ENV_EXAMPLE} not found", file=sys.stderr)
        return 1
    if ENV_FILE.exists():
        print(f"{ENV_FILE.name} already exists — leaving it untouched.")
        return 0

    # No third-party imports here. This script runs from `make init-env`, which is a
    # prerequisite of the venv creation — importing bcrypt to validate a generated
    # password would make the documented fresh-checkout flow fail on a clean machine.
    # The checks below are the ones that actually matter: non-empty and within
    # bcrypt's 72-byte limit.
    db_password = generate_password()
    session_secret = secrets.token_hex(32)
    redis_password = generate_password(32)
    operator_password = generate_password(20)

    if not operator_password or len(operator_password.encode()) > 72:
        print("error: generated operator password is not usable", file=sys.stderr)
        return 1

    content = ENV_EXAMPLE.read_text(encoding="utf-8")
    content = content.replace(
        "# SCOPELENS_EVIDENCE_ENCRYPTION_KEY=",
        "SCOPELENS_EVIDENCE_ENCRYPTION_KEY="
        + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
    )
    content = content.replace(
        "# SCOPELENS_IDENTITY_ENCRYPTION_KEY=",
        "SCOPELENS_IDENTITY_ENCRYPTION_KEY="
        + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
    )
    content = content.replace(
        "# SCOPELENS_CALLBACK_SIGNING_KEY=",
        "SCOPELENS_CALLBACK_SIGNING_KEY=" + secrets.token_hex(32),
    )
    content = content.replace("CHANGE_ME@", f"{db_password}@")
    content = content.replace(
        "SCOPELENS_POSTGRES_PASSWORD=CHANGE_ME", f"SCOPELENS_POSTGRES_PASSWORD={db_password}"
    )
    content = content.replace(
        "SCOPELENS_SESSION_SECRET=CHANGE_ME", f"SCOPELENS_SESSION_SECRET={session_secret}"
    )
    content = content.replace(
        "SCOPELENS_REDIS_PASSWORD=CHANGE_ME", f"SCOPELENS_REDIS_PASSWORD={redis_password}"
    )
    content = content.replace(
        "SCOPELENS_OPERATOR_PASSWORD=CHANGE_ME", f"SCOPELENS_OPERATOR_PASSWORD={operator_password}"
    )

    def assignment_lines(text: str) -> list[str]:
        return [
            line for line in text.splitlines() if "=" in line and not line.lstrip().startswith("#")
        ]

    # Docker Compose interpolates `$` inside .env values. A `$` reaching a value would
    # be silently rewritten, so refuse to write one rather than ship a broken credential.
    if offenders := [ln.split("=", 1)[0].strip() for ln in assignment_lines(content) if "$" in ln]:
        print(f"error: generated a `$` in an env value ({offenders}); aborting", file=sys.stderr)
        return 1

    # A placeholder mentioned in prose is harmless, but an unsubstituted assignment
    # would ship a guessable credential.
    unfilled = [
        line.split("=", 1)[0].strip() for line in assignment_lines(content) if PLACEHOLDER in line
    ]
    if unfilled:
        print(
            "error: placeholder left unfilled for: " + ", ".join(unfilled),
            file=sys.stderr,
        )
        return 1

    # Exclusive creation preserves a concurrently created environment, and the
    # generated keys are private from the first byte, regardless of umask.
    try:
        descriptor = os.open(ENV_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        print(f"{ENV_FILE.name} already exists — leaving it untouched.")
        return 0
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)

    print(f"Wrote {ENV_FILE} (mode 600) with generated secrets.\n")
    print("  Operator sign-in:")
    print("    username: operator")
    print("    password: read SCOPELENS_OPERATOR_PASSWORD locally in .env")
    print("\nThe password is written only to .env. The database stores")
    print("only its bcrypt hash. To rotate it: `make hash-password`, then edit .env.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
