"""Atomic budget reservation and reconciliation (Build Plan §5.2, §5.3).

Reserve first, reconcile after. The alternative — spend, then record — loses the spend
when a process dies mid-request, and a lost spend is a budget that silently refills.

Every reservation takes a row lock on the scan, so two workers spending the same budget
cannot both see room for the last request.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from scopelens.domain.budget import BudgetLimits, BudgetUsage, check_reservation
from scopelens.persistence.models import ScanRow


class BudgetUnavailable(RuntimeError):
    """The scan row could not be locked for budget accounting."""


def _locked_scan(session: Session, scan_id: uuid.UUID) -> ScanRow:
    scan = session.scalar(select(ScanRow).where(ScanRow.id == scan_id).with_for_update())
    if scan is None:
        raise BudgetUnavailable(f"scan {scan_id} does not exist")
    return scan


def read_usage(scan: ScanRow) -> tuple[BudgetUsage, BudgetUsage]:
    """Return ``(spent, reserved)`` for a scan row, tolerating an empty/partial dict."""
    return (
        BudgetUsage.model_validate(scan.budget_spent or {}),
        BudgetUsage.model_validate(scan.budget_reserved or {}),
    )


def remaining(scan: ScanRow, limits: BudgetLimits) -> BudgetUsage:
    spent, reserved = read_usage(scan)
    committed = spent.committed_with(reserved)
    return BudgetUsage(
        requests=max(0, limits.max_requests - committed.requests),
        pages=max(0, limits.max_pages - committed.pages),
    )


def reserve(
    session: Session, *, scan_id: uuid.UUID, limits: BudgetLimits, usage: BudgetUsage
) -> BudgetUsage:
    """Reserve ``usage`` against the scan's budget, or raise.

    The scan row is locked for the duration, so the check and the increment are one
    atomic step. Raising :class:`BudgetExceeded` is a normal outcome that the caller
    records as a blocked result — never as a pass (Project Specification §9.7).
    """
    scan = _locked_scan(session, scan_id)
    spent, reserved = read_usage(scan)

    check_reservation(spent=spent, reserved=reserved, limits=limits, requested=usage)

    new_reserved = reserved.committed_with(usage)
    scan.budget_reserved = new_reserved.model_dump()
    session.flush()
    return new_reserved


def reconcile(
    session: Session, *, scan_id: uuid.UUID, reserved: BudgetUsage, spent: BudgetUsage
) -> tuple[BudgetUsage, BudgetUsage]:
    """Move a reservation into spend, adjusting for what was actually used.

    Called on every completion path — success, failure *and* cancellation — so a
    reservation cannot be left outstanding by an abnormal exit path that nobody tested.
    """
    scan = _locked_scan(session, scan_id)
    current_spent, current_reserved = read_usage(scan)

    new_spent = current_spent.committed_with(spent)
    new_reserved = current_reserved.minus(reserved)

    scan.budget_spent = new_spent.model_dump()
    scan.budget_reserved = new_reserved.model_dump()
    session.flush()
    return new_spent, new_reserved


def settle(
    session: Session, *, scan_id: uuid.UUID, spent: BudgetUsage
) -> tuple[BudgetUsage, BudgetUsage]:
    """Charge what was actually spent and clear every outstanding reservation.

    Two different reservations can be outstanding at the end of a task: the coordinator's
    own (taken at admission, before anything ran) and the broker's per-request ones (taken
    to stop concurrent admissions oversubscribing the budget). Both are bookkeeping for
    work that has now finished, so both are cleared here.

    Releasing only the coordinator's own reservation leaves the broker's behind, and a
    stranded reservation is worse than a leaked counter: it permanently reduces the budget
    of a scan that has already completed.
    """
    scan = _locked_scan(session, scan_id)
    current_spent, _ = read_usage(scan)

    new_spent = current_spent.committed_with(spent)
    scan.budget_spent = new_spent.model_dump()
    scan.budget_reserved = BudgetUsage().model_dump()
    session.flush()
    return new_spent, BudgetUsage()


def release(session: Session, *, scan_id: uuid.UUID, reserved: BudgetUsage) -> BudgetUsage:
    """Return an unused reservation without spending it."""
    scan = _locked_scan(session, scan_id)
    _, current_reserved = read_usage(scan)
    new_reserved = current_reserved.minus(reserved)
    scan.budget_reserved = new_reserved.model_dump()
    session.flush()
    return new_reserved


def clear_reservations(session: Session, *, scan_id: uuid.UUID) -> BudgetUsage:
    """Release everything outstanding for a scan.

    Used by the reconciler for a scan whose worker is gone. The *spend* is untouched:
    Build Plan §5.6 requires that spent budget persists across recovery, and forgiving
    it would let a crash buy extra requests.
    """
    scan = _locked_scan(session, scan_id)
    _, current_reserved = read_usage(scan)
    scan.budget_reserved = BudgetUsage().model_dump()
    session.flush()
    return current_reserved


def wall_clock_exhausted(
    scan: ScanRow, limits: BudgetLimits, *, now: datetime | None = None
) -> bool:
    """Whether the scan has exceeded its wall-clock budget."""
    if scan.started_at is None:
        return False
    now = now or datetime.now(UTC)
    return (now - scan.started_at).total_seconds() >= limits.wall_clock_seconds
