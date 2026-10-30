"""Conservative worker-cleanup history for cancellation and outbox delivery."""

from sqlalchemy import String, cast, select
from sqlalchemy.orm import Session

from scopelens.execution.ledger import SCAN_DISPATCH_TOPIC
from scopelens.persistence.models import (
    AuditEventRow,
    CoordinatorLeaseRow,
    OutboxEventRow,
    ScanRow,
    TaskRow,
)


def may_need_worker_cleanup(session: Session, scan: ScanRow) -> bool:
    """Keep stop delivery whenever execution may have reached a supervisor."""
    if (
        scan.started_at is not None
        or session.get(CoordinatorLeaseRow, scan.id) is not None
        or session.scalar(select(TaskRow.id).where(TaskRow.scan_id == scan.id).limit(1)) is not None
    ):
        return True
    # dispatched_at also marks consumed terminal notifications. Their skipped audit
    # distinguishes them from actual delivery, including old delivery receipts whose
    # task/lease rows are absent.
    skipped = (
        select(AuditEventRow.seq)
        .where(
            AuditEventRow.action == "outbox.dispatch",
            AuditEventRow.subject_type == "outbox_event",
            AuditEventRow.subject_id == cast(OutboxEventRow.id, String),
            AuditEventRow.outcome == "skipped",
        )
        .correlate(OutboxEventRow)
        .exists()
    )
    return (
        session.scalar(
            select(OutboxEventRow.id)
            .where(
                OutboxEventRow.topic == SCAN_DISPATCH_TOPIC,
                OutboxEventRow.payload["scan_id"].as_string() == str(scan.id),
                OutboxEventRow.dispatched_at.is_not(None),
                ~skipped,
            )
            .limit(1)
        )
        is not None
    )
