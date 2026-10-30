"""Expiry keeps metadata and findings; only completed-scan evidence bytes are removed."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text

from scopelens.evidence.store import LocalDiskEvidenceStore
from scopelens.persistence.models import EvidenceRow, ScanRow
from scopelens.persistence.repositories import record_audit
from scopelens.persistence.session import session_scope


def expired(row, days, now=None):
    return row.captured_at <= (now or datetime.now(UTC)) - timedelta(days=days)


def prune(settings, *, apply=False):
    store = LocalDiskEvidenceStore(
        settings.evidence_store_path,
        settings.evidence_encryption_key.get_secret_value()
        if settings.evidence_encryption_key
        else None,
    )
    removed = []
    with session_scope(settings) as db:
        db.execute(text("SELECT pg_advisory_xact_lock(412509)"))
        rows = db.scalars(
            select(EvidenceRow)
            .join(ScanRow)
            .where(
                ScanRow.status.in_(["completed", "completed_partial", "failed", "cancelled"]),
                EvidenceRow.captured_at
                < datetime.now(UTC) - timedelta(days=settings.evidence_retention_days),
            )
        ).all()
        for row in rows:
            if not store.exists(row.content_ref):
                continue
            removed.append(str(row.id))
            if apply:
                store.delete(row.content_ref)
                record_audit(
                    db,
                    actor="retention",
                    action="evidence.expire",
                    subject_type="evidence",
                    subject_id=str(row.id),
                    outcome="deleted",
                    detail={"scan_id": str(row.scan_id), "content_hash": row.content_hash},
                )
    return {"apply": apply, "count": len(removed), "evidence_ids": removed}
