"""Evidence object storage (Build Plan §5.5).

Local disk behind a small interface. Build Plan §3 permits "MinIO (S3-compatible) or
local disk behind an S3 client"; the interface exists so the deployment can swap in S3
without touching the intake path.

References are constructed from the scan and a content hash, never from target-supplied
text. A target that could influence its own evidence path could overwrite another scan's
artifact.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Protocol


class EvidenceStoreError(RuntimeError):
    pass


class EvidenceStore(Protocol):
    def put(self, ref: str, content: bytes) -> str:
        """Store content at ``ref``. Returns the ref."""
        ...

    def get(self, ref: str) -> bytes: ...

    def exists(self, ref: str) -> bool: ...


class LocalDiskEvidenceStore:
    """Content-addressed files under ``root``.

    The ref is a relative path built by the caller. It is validated here rather than
    trusted: a ref containing ``..`` would let a bug write outside the evidence root.
    """

    def __init__(self, root: Path, encryption_key: str | None = None) -> None:
        from cryptography.fernet import Fernet

        self._cipher = Fernet(encryption_key.encode()) if encryption_key else None
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    @property
    def root(self) -> Path:
        return self._root

    def _resolve(self, ref: str) -> Path:
        candidate = (self._root / ref).resolve()
        root = self._root.resolve()
        if root != candidate and root not in candidate.parents:
            raise EvidenceStoreError(f"evidence ref escapes the store root: {ref!r}")
        return candidate

    def put(self, ref: str, content: bytes) -> str:
        target = self._resolve(ref)
        target.parent.mkdir(parents=True, exist_ok=True)
        # Written to a temporary sibling and renamed, so a reader never observes a
        # half-written artifact and the integrity hash always matches what is present.
        tmp = target.with_suffix(target.suffix + f".tmp{os.getpid()}")
        try:
            tmp.write_bytes(
                b"SLENC1\n" + self._cipher.encrypt(content) if self._cipher else content
            )
            tmp.chmod(0o600)
            tmp.replace(target)
        finally:
            tmp.unlink(missing_ok=True)
        return ref

    def get(self, ref: str) -> bytes:
        target = self._resolve(ref)
        if not target.exists():
            raise EvidenceStoreError(f"no evidence stored at {ref!r}")
        content = target.read_bytes()
        if content.startswith(b"SLENC1\n"):
            if self._cipher is None:
                raise EvidenceStoreError("encryption key unavailable")
            from cryptography.fernet import InvalidToken

            try:
                return self._cipher.decrypt(content[7:])
            except InvalidToken:
                raise EvidenceStoreError("evidence decryption failed") from None
        return content

    def exists(self, ref: str) -> bool:
        return self._resolve(ref).exists()

    def delete(self, ref: str) -> None:
        self._resolve(ref).unlink(missing_ok=True)


def content_ref(scan_id: str, task_id: str | None, sha256: str, *, suffix: str = ".bin") -> str:
    """Build a ref from internal identifiers only.

    Every component is engine-generated. Nothing here derives from the target, so a
    hostile response cannot steer where its own evidence is written.
    """
    directory = f"{scan_id}/{task_id or 'scan'}"
    return f"{directory}/{sha256}{suffix}"


def sha256_hex(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()
