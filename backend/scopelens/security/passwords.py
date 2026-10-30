"""Password hashing (Build Plan §5.1 — bcrypt)."""

from __future__ import annotations

import bcrypt

from scopelens.domain.errors import DomainError

# bcrypt ignores everything past 72 bytes. Refusing an over-long password is
# preferable to silently truncating it, which would make two different passwords
# interchangeable.
MAX_PASSWORD_BYTES = 72

DEFAULT_ROUNDS = 12


class PasswordError(DomainError):
    pass


def hash_password(plain: str, *, rounds: int = DEFAULT_ROUNDS) -> str:
    encoded = plain.encode("utf-8")
    if not encoded:
        raise PasswordError("password must not be empty")
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise PasswordError(
            f"password exceeds bcrypt's {MAX_PASSWORD_BYTES}-byte limit "
            f"({len(encoded)} bytes); choose a shorter one"
        )
    return bcrypt.hashpw(encoded, bcrypt.gensalt(rounds=rounds)).decode("ascii")


def verify_password(plain: str, password_hash: str) -> bool:
    """Constant-time verification. Returns False rather than raising on a bad hash."""
    encoded = plain.encode("utf-8")
    if not encoded or len(encoded) > MAX_PASSWORD_BYTES:
        return False
    try:
        return bcrypt.checkpw(encoded, password_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False
