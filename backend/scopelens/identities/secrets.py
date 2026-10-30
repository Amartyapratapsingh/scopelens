"""Encrypted, owner/scope-bound credential references for trusted services only."""

from __future__ import annotations

import json
import os
import re
import secrets
from datetime import UTC, datetime
from pathlib import Path

from cryptography.fernet import Fernet
from pydantic import SecretStr


class EncryptedSecretStore:
    def __init__(self, root: Path, key: bytes):
        self.root = root
        self.cipher = Fernet(key)
        root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def put(self, value: SecretStr, *, owner: str, scope_id: str, expires_at: datetime) -> str:
        if expires_at.tzinfo is None or expires_at <= datetime.now(UTC):
            raise ValueError("future timezone-aware secret expiry required")
        ref = secrets.token_hex(24)
        payload = json.dumps(
            {
                "value": value.get_secret_value(),
                "owner": owner,
                "scope": scope_id,
                "expires": expires_at.isoformat(),
            }
        ).encode()
        fd = os.open(self.root / ref, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(self.cipher.encrypt(payload))
        return ref

    def resolve(self, ref: str, *, owner: str, scope_id: str) -> SecretStr:
        return self.resolve_with_expiry(ref, owner=owner, scope_id=scope_id)[0]

    def resolve_with_expiry(
        self, ref: str, *, owner: str, scope_id: str
    ) -> tuple[SecretStr, datetime]:
        if not re.fullmatch(r"[0-9a-f]{48}", ref):
            raise ValueError("invalid secret reference")
        raw = json.loads(self.cipher.decrypt((self.root / ref).read_bytes()))
        if raw["owner"] != owner or raw["scope"] != scope_id:
            raise PermissionError("credential reference outside identity authority")
        if datetime.fromisoformat(raw["expires"]) <= datetime.now(UTC):
            raise PermissionError("credential reference expired")
        return SecretStr(raw["value"]), datetime.fromisoformat(raw["expires"])

    def delete(self, ref: str, *, owner: str, scope_id: str) -> None:
        self.resolve(ref, owner=owner, scope_id=scope_id)
        (self.root / ref).unlink()
