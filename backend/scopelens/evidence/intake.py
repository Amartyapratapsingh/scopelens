"""Trusted evidence intake (Build Plan §5.5).

The single gate through which an artifact becomes evidence. Its ordering is the point:

1. **Cap** at the configured response ceiling. Over-long content is truncated and marked,
   never silently accepted at full size.
2. **Redact** before anything is stored, hashed or shown. Redacting later would leave a
   window in which the raw bytes exist in a retrievable artifact.
3. **Hash and store** the redacted bytes, so the integrity hash covers exactly what a
   reader can retrieve. Hashing the pre-redaction bytes would make later verification
   fail against the stored artifact.
4. **Record** provenance alongside the reference.

Only trusted writers may call this (§5.5). A worker's own output is registered through
:func:`record_untrusted_observation`, which stamps it ``UNTRUSTED_OBSERVATION`` so the
verifier can refuse to evaluate a proof rule against it.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from scopelens.config import Settings
from scopelens.domain.evidence import EvidenceOrigin, EvidenceRecord, RedactionState
from scopelens.evidence.store import EvidenceStore, content_ref, sha256_hex
from scopelens.persistence.models import EvidenceRow, ScanRow, ScopeVersionRow, TaskRow
from scopelens.security.redaction import redact, redact_text

#: Ceiling from Project Specification §12 / Build Plan §5.3.
DEFAULT_MAX_BYTES = 1024 * 1024
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_SESSION_FINGERPRINT_FIELDS = ("old_cookie_hash", "new_cookie_hash", "replayed_cookie_hash")


class EvidenceIntakeError(RuntimeError):
    pass


def _cap(content: bytes, max_bytes: int) -> tuple[bytes, bool]:
    if len(content) <= max_bytes:
        return content, False
    return content[:max_bytes], True


def _redact_text(
    content: bytes, *, preserve_session_fingerprints: bool = False
) -> tuple[bytes, RedactionState]:
    """Redact secrets/PII from text content.

    Binary content is not rewritten — mangling a PNG would corrupt the artifact — but it
    is *scanned* for credential shapes and refused if any are found, because a secret
    inside a binary artifact is exactly the case a text-only redactor would miss.
    """
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        from scopelens.security.redaction import contains_credential_shape

        if contains_credential_shape(content.decode("latin-1", "ignore")):
            raise EvidenceIntakeError(
                "binary evidence appears to contain credential-shaped material; refusing "
                "to store it rather than storing a secret in a form redaction cannot rewrite"
            ) from None
        return content, RedactionState.CLEAN

    # Two passes, because evidence arrives in two shapes.
    #
    # A JSON artifact is redacted *structurally*, which is exact: the whole value of a
    # sensitive key is replaced, including delimiters the text pattern would leave behind.
    # Anything else falls back to the text scrubber. A structured-only redactor would store
    # a response body containing an API key verbatim while still reporting `redacted`;
    # a text-only one would leave fragments of a cookie header behind.
    rewritten = _redact_json_or_text(
        text, preserve_session_fingerprints=preserve_session_fingerprints
    )

    state = RedactionState.REDACTED if rewritten != text else RedactionState.CLEAN
    return rewritten.encode("utf-8"), state


def _redact_json_or_text(text: str, *, preserve_session_fingerprints: bool = False) -> str:
    """Redact a JSON document structurally, or the raw text if it is not JSON."""
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return redact_text(text)

    redacted = redact(parsed)
    # The fixed session collector emits SHA-256 fingerprints, never cookie values.
    # Restore only these exact fields after the ordinary secret scrub. This exception
    # is unavailable to other producers, artifacts, or nested fields.
    if (
        preserve_session_fingerprints
        and isinstance(parsed, dict)
        and parsed.get("source") == "expansion"
        and parsed.get("kind") == "identity_observation"
        and isinstance(parsed.get("data"), dict)
        and parsed["data"].get("kind") == "session_policy"
        and parsed["data"].get("proof_type") == "session"
        and parsed["data"].get("identity_id")
        and parsed["data"].get("proof_id") == parsed["data"]["identity_id"]
    ):
        for field in _SESSION_FINGERPRINT_FIELDS:
            value = parsed["data"].get(field)
            if isinstance(value, str) and _SHA256_HEX.fullmatch(value):
                redacted["data"][field] = value
    if redacted == parsed:
        # Nothing matched. Re-serialising would change the formatting, which would mark a
        # clean artifact REDACTED and change its hash for no reason.
        return text

    return json.dumps(redacted, indent=2, sort_keys=True, default=str)


def record_evidence(
    session: Session,
    *,
    settings: Settings,
    store: EvidenceStore,
    scan: ScanRow,
    origin: EvidenceOrigin,
    producer: str,
    content: bytes,
    content_type: str | None = None,
    summary: str = "",
    task_id: uuid.UUID | None = None,
    run_id: str | None = None,
    producer_hash: str | None = None,
    tool_version: str | None = None,
    role: str = "unauthenticated",
    captured_at: datetime | None = None,
    suffix: str = ".txt",
    max_bytes: int | None = None,
) -> EvidenceRecord:
    """Store one artifact and return its record. Commits nothing; the caller owns the txn."""
    if scan.scope_version_id is None:
        raise EvidenceIntakeError(
            f"scan {scan.id} has no scope version; evidence cannot be attributed to an "
            "authorization and will not be stored"
        )
    scope_row = session.get(ScopeVersionRow, scan.scope_version_id)
    if scope_row is None:
        raise EvidenceIntakeError(f"scan {scan.id} has no scope version; cannot attribute evidence")

    ceiling = max_bytes or settings.budgets.max_body_bytes
    capped, truncated = _cap(content, ceiling)
    preserve_session_fingerprints = False
    if (
        origin == EvidenceOrigin.SUPERVISOR
        and producer == "reviewed_expansion_capture"
        and isinstance(producer_hash, str)
        and _SHA256_HEX.fullmatch(producer_hash)
        and run_id
        and task_id
        and not truncated
    ):
        task = session.get(TaskRow, task_id)
        if task is not None and task.scan_id == scan.id:
            try:
                payload = json.loads(capped)
            except (ValueError, UnicodeDecodeError):
                payload = None
            preserve_session_fingerprints = (
                isinstance(payload, dict) and payload.get("run_id", run_id) == run_id
            )
    redacted, redaction_state = _redact_text(
        capped, preserve_session_fingerprints=preserve_session_fingerprints
    )

    digest = sha256_hex(redacted)
    ref = content_ref(str(scan.id), str(task_id) if task_id else None, digest, suffix=suffix)
    store.put(ref, redacted)

    row = EvidenceRow(
        scan_id=scan.id,
        task_id=task_id,
        run_id=run_id,
        origin=str(origin),
        producer=producer[:64],
        producer_hash=producer_hash,
        tool_version=tool_version,
        scope_version_id=scope_row.id,
        scope_content_hash=scope_row.content_hash,
        role=role,
        captured_at=captured_at or datetime.now(UTC),
        content_hash=digest,
        content_bytes=len(redacted),
        content_ref=ref,
        truncated=truncated,
        redaction_state=str(redaction_state),
        content_type=(content_type or "")[:128] or None,
        summary=summary[:2000],
    )
    session.add(row)
    session.flush()
    return row_to_domain(row)


def record_json_evidence(
    session: Session,
    *,
    settings: Settings,
    store: EvidenceStore,
    scan: ScanRow,
    origin: EvidenceOrigin,
    producer: str,
    payload: dict[str, Any],
    **kwargs: Any,
) -> EvidenceRecord:
    """Convenience for structured artifacts, serialised deterministically."""
    body = json.dumps(payload, sort_keys=True, indent=2, default=str).encode("utf-8")
    return record_evidence(
        session,
        settings=settings,
        store=store,
        scan=scan,
        origin=origin,
        producer=producer,
        content=body,
        content_type="application/json",
        suffix=".json",
        **kwargs,
    )


def record_untrusted_observation(
    session: Session,
    *,
    settings: Settings,
    store: EvidenceStore,
    scan: ScanRow,
    producer: str,
    content: bytes,
    **kwargs: Any,
) -> EvidenceRecord:
    """Register a script or tool's own output.

    Always ``UNTRUSTED_OBSERVATION``. Build Plan §5.14 is explicit that a script printing
    ``confirmed=true`` is not evidence, so this path exists to store such output *as an
    observation* rather than to launder it into proof.
    """
    return record_evidence(
        session,
        settings=settings,
        store=store,
        scan=scan,
        origin=EvidenceOrigin.UNTRUSTED_OBSERVATION,
        producer=producer,
        content=content,
        **kwargs,
    )


def row_to_domain(row: EvidenceRow) -> EvidenceRecord:
    return EvidenceRecord(
        id=str(row.id),
        scan_id=str(row.scan_id),
        task_id=str(row.task_id) if row.task_id else None,
        run_id=row.run_id,
        origin=EvidenceOrigin(row.origin),
        producer=row.producer,
        producer_hash=row.producer_hash,
        tool_version=row.tool_version,
        scope_version_id=str(row.scope_version_id),
        scope_content_hash=row.scope_content_hash,
        role=row.role,
        captured_at=row.captured_at,
        content_hash=row.content_hash,
        content_bytes=row.content_bytes,
        content_ref=row.content_ref,
        truncated=row.truncated,
        redaction_state=RedactionState(row.redaction_state),
        content_type=row.content_type,
        summary=row.summary,
    )


def verify_integrity(store: EvidenceStore, record: EvidenceRecord) -> bool:
    """Re-hash the stored artifact and compare.

    A mismatch means the artifact changed after capture. It does **not** mean the claim
    it supports is false — Build Plan §5.14: the hash proves the bytes did not change,
    not that they establish anything.
    """
    try:
        stored = store.get(record.content_ref)
    except Exception:  # noqa: BLE001 - any retrieval failure is a failed verification
        return False
    return sha256_hex(stored) == record.content_hash


def evidence_for_scan(session: Session, scan_id: uuid.UUID) -> list[EvidenceRecord]:
    from sqlalchemy import select

    rows = session.scalars(
        select(EvidenceRow).where(EvidenceRow.scan_id == scan_id).order_by(EvidenceRow.captured_at)
    )
    return [row_to_domain(row) for row in rows]
