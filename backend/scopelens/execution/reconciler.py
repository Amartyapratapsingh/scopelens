"""Reconciler (Build Plan §5.2, §5.6).

Runs at startup and on demand. Its job is to make the database agree with reality after
something went wrong — a crash, a queue loss, an expired lease, a worker that outlived its
coordinator.

The governing rule from §5.6: **reconcile before retrying, and never blind-retry
side-effecting work.** A task that might have reached the target becomes
``outcome_unknown``, not ``failed``, because ``failed`` reads as "safe to try again" and
nobody can establish that. Spent budget is never refunded.

What this deliberately does *not* do: requeue work on its own initiative. Reconciliation
settles state and reports; deciding to dispatch again is the dispatcher's job, and it only
ever dispatches rows the outbox says were never delivered.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from scopelens.config import Settings
from scopelens.domain.enums import ScanStatus
from scopelens.domain.task import TaskState
from scopelens.execution import budget as budget_service
from scopelens.execution.leases import expire_stale_leases
from scopelens.execution.ledger import outbox_depth, transition_scan
from scopelens.persistence.models import CoordinatorLeaseRow, ScanRow, TaskRow
from scopelens.persistence.repositories import record_audit
from scopelens.persistence.session import session_scope


@dataclass
class ReconcileReport:
    """What reconciliation found and changed."""

    expired_leases: int = 0
    live_tasks_without_lease: list[str] = field(default_factory=list)
    scans_settled: list[str] = field(default_factory=list)
    queued_scans_cancelled: list[str] = field(default_factory=list)
    reservations_cleared: list[str] = field(default_factory=list)
    pending_outbox: int = 0

    def render(self) -> str:
        lines = [
            "reconcile:",
            f"  expired leases released:        {self.expired_leases}",
            f"  live tasks with no live lease:  {len(self.live_tasks_without_lease)}",
            f"  scans settled as unverifiable:  {len(self.scans_settled)}",
            f"  queued cancellations settled:   {len(self.queued_scans_cancelled)}",
            f"  stranded reservations cleared:  {len(self.reservations_cleared)}",
            f"  outbox rows awaiting dispatch:  {self.pending_outbox}",
        ]
        for scan_id in self.scans_settled:
            lines.append(f"    settled scan {scan_id}")
        return "\n".join(lines)


def reconcile(settings: Settings, *, now: datetime | None = None) -> ReconcileReport:
    """Bring the ledger back in line with reality. Safe to run repeatedly."""
    now = now or datetime.now(UTC)
    report = ReconcileReport()

    with session_scope(settings) as session:
        # 1. Retire expired leases. Releasing (rather than deleting) is what makes the
        #    next acquire bump the fencing token, so a still-running predecessor is
        #    invalidated rather than duplicated.
        expired = expire_stale_leases(session, now=now)
        report.expired_leases = len(expired)

        # 2. Any task still marked live whose scan has no live lease is an orphan: the
        #    process driving it is gone. Its outcome cannot be established.
        orphans = _live_tasks_without_lease(session, now=now)
        report.live_tasks_without_lease = [str(task.id) for task in orphans]

        for task in orphans:
            scan = session.get(ScanRow, task.scan_id)
            if scan is None:
                continue

            admitted = _requests_admitted(session, scan.id)
            task.state = str(TaskState.OUTCOME_UNKNOWN)
            task.finished_at = now
            task.outcome_reason = (
                f"reconciled: no live coordinator lease; {admitted} request(s) were "
                "admitted before the coordinator disappeared, so the outcome cannot be "
                "established and this work is not retried"
            )

            # 3. Release whatever the dead run had reserved. The spend is left intact:
            #    §5.6 requires spent budget to persist across recovery.
            cleared = budget_service.clear_reservations(session, scan_id=scan.id)
            if cleared.requests or cleared.bytes:
                report.reservations_cleared.append(str(scan.id))

            if not ScanStatus(scan.status).is_terminal:
                transition_scan(
                    session,
                    scan=scan,
                    target=ScanStatus.COMPLETED_PARTIAL,
                    reason=(
                        "interrupted: the coordinator stopped without recording an outcome. "
                        "Partial evidence is retained; this is not a completed assessment."
                    ),
                )
                report.scans_settled.append(str(scan.id))

            scan.reconciled_at = now
            record_audit(
                session,
                actor="reconciler",
                action="scan.reconcile",
                subject_type="scan",
                subject_id=str(scan.id),
                outcome=str(TaskState.OUTCOME_UNKNOWN),
                detail={
                    "task_id": str(task.id),
                    "requests_admitted": admitted,
                    "reserved_cleared": cleared.model_dump(),
                },
            )

        # A legacy queued intent may have no coordinator or task to consume its
        # cancellation epoch. Settle it once without admitting any work. A lease row,
        # including a retired one, belongs to the existing execution recovery path.
        cancelled = session.scalars(
            select(ScanRow)
            .where(
                ScanRow.status == str(ScanStatus.QUEUED),
                ScanRow.cancel_epoch > 0,
                ~select(CoordinatorLeaseRow.scan_id)
                .where(CoordinatorLeaseRow.scan_id == ScanRow.id)
                .exists(),
            )
            .with_for_update(of=ScanRow)
        ).all()
        for scan in cancelled:
            # Recheck after obtaining the scan lock: an admission could have created
            # its lease while this query was waiting on that lock.
            if session.get(CoordinatorLeaseRow, scan.id) is not None:
                continue
            reason = "cancelled before dispatch"
            scan.cancel_requested_at = scan.cancel_requested_at or now
            transition_scan(session, scan=scan, target=ScanStatus.CANCELLED, reason=reason)
            scan.reconciled_at = now
            report.queued_scans_cancelled.append(str(scan.id))
            record_audit(
                session,
                actor="reconciler",
                action="scan.reconcile",
                subject_type="scan",
                subject_id=str(scan.id),
                outcome="cancelled",
                detail={"cancel_epoch": scan.cancel_epoch, "reason": reason},
            )

        report.pending_outbox = outbox_depth(session)

    return report


def _live_tasks_without_lease(session: Session, *, now: datetime) -> list[TaskRow]:
    """Live tasks whose scan has no live, unreleased lease."""
    from scopelens.persistence.models import CoordinatorLeaseRow

    rows = session.execute(
        select(TaskRow, CoordinatorLeaseRow)
        .outerjoin(CoordinatorLeaseRow, CoordinatorLeaseRow.scan_id == TaskRow.scan_id)
        .where(TaskRow.state.in_([str(TaskState.ADMITTED), str(TaskState.RUNNING)]))
    ).all()

    orphans: list[TaskRow] = []
    for task, lease in rows:
        if lease is None or lease.released_at is not None or now >= lease.expires_at:
            orphans.append(task)
    # A task whose scan is already settled needs no further action beyond the state fix.
    return orphans


def _requests_admitted(session: Session, scan_id: uuid.UUID) -> int:
    from scopelens.execution.coordinator import count_admitted_requests

    return count_admitted_requests(session, scan_id)
