"""Durable ledger: transactional creation, admission and task transitions (Build Plan §5.2).

The ordering rules here are the whole point of the milestone:

* ``create_scan`` writes the Scan, its first Task and the outbox event in **one
  transaction**. If any part fails, none of it exists — there is no state in which a
  scan is queued with nothing to dispatch it, or a dispatch exists for a scan that does
  not.
* Admission is the **only** way a task leaves ``planned``. It reserves budget, requires
  a live lease, and refuses when the scan is cancelled.
* Every transition records *why*. A task that failed and a task whose outcome was lost
  are different facts, and the ledger keeps them apart.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from scopelens.config import Settings
from scopelens.domain.budget import BudgetLimits, BudgetUsage
from scopelens.domain.enums import ScanStatus
from scopelens.domain.lifecycle import assert_transition
from scopelens.domain.task import TaskState, TaskType
from scopelens.persistence.models import OutboxEventRow, ScanRow, ScopeVersionRow, TaskRow
from scopelens.persistence.repositories import (
    create_scan_row,
    get_scan,
    record_audit,
)

#: Topic carried on the outbox row for a dispatchable task.
SCAN_DISPATCH_TOPIC = "scan.task.dispatch"
#: Topic for "stop the workers belonging to this scan".
#:
#: Cancellation needs two mechanisms because the two deadlines differ by an order of
#: magnitude. Revoking the egress token is immediate and stops new requests within the
#: 5 s target. Stopping a running worker needs the Docker socket, which only the
#: supervisor holds — so it travels through the outbox rather than being attempted from
#: the API, which has no business holding that privilege.
SCAN_CANCEL_TOPIC = "scan.cancel"

#: Logical id of the M1 end-to-end task. Stable across attempts by construction.
FETCH_ORIGIN_LOGICAL_ID = "fetch-origin"


class ExecutionDisabled(RuntimeError):
    """Raised when execution is attempted while it is switched off.

    Replaces the M0 gate. In M0 the guarantee was that no dispatch path existed; from
    M1 the guarantee is that dispatch refuses unless explicitly enabled, and the
    surrounding fences (lease, budget, broker, cancellation epoch) do the real work.
    """


class AdmissionRefused(RuntimeError):
    """Raised when admission is denied: cancelled scan, dead lease, or spent budget."""


def assert_execution_enabled(settings: Settings) -> None:
    if not settings.scanner_execution_enabled:
        raise ExecutionDisabled(
            "scanner execution is disabled (SCOPELENS_SCANNER_EXECUTION_ENABLED=false); "
            "refusing to dispatch. Scans stay queued until it is enabled."
        )


def execution_status(settings: Settings) -> dict[str, str | bool]:
    """Machine-readable execution state, surfaced by the API."""
    return {
        "execution": "enabled" if settings.scanner_execution_enabled else "disabled",
        "execution_enabled": settings.scanner_execution_enabled,
        "dispatch_implemented": True,
        "responsible_milestone": "M1",
        "detail": (
            "Dispatch, the policy broker, leases and budgets are implemented. Target "
            "traffic is admitted only through the forward proxy."
            if settings.scanner_execution_enabled
            else "Execution is switched off by configuration; scans stay queued."
        ),
    }


# --- Creation ----------------------------------------------------------------------


def create_scan_with_task(
    session: Session,
    *,
    operator_id: uuid.UUID,
    scope_version: ScopeVersionRow,
    score_version: str,
    task_type: TaskType = TaskType.FETCH_ORIGIN,
    logical_id: str = FETCH_ORIGIN_LOGICAL_ID,
    actor: str = "system",
) -> tuple[ScanRow, TaskRow]:
    """Create a scan, its first task and its dispatch event — atomically.

    Deliberately does not commit. The caller owns the transaction boundary so that the
    three rows are written together or not at all (§5.2).
    """
    scan = create_scan_row(
        session,
        operator_id=operator_id,
        scope_version=scope_version,
        score_version=score_version,
    )

    task = TaskRow(
        scan_id=scan.id,
        logical_id=logical_id,
        attempt_id=uuid.uuid4().hex,
        task_type=str(task_type),
        state=str(TaskState.PLANNED),
        lease_token=0,
        reserved_budget=BudgetUsage().model_dump(),
        spent_budget=BudgetUsage().model_dump(),
    )
    session.add(task)
    session.flush()

    session.add(
        OutboxEventRow(
            topic=SCAN_DISPATCH_TOPIC,
            # References only. The message names the work; it carries no authority, no
            # credential and no scope — the coordinator re-derives all of that.
            payload={
                "scan_id": str(scan.id),
                "task_id": str(task.id),
                "logical_id": task.logical_id,
                "attempt_id": task.attempt_id,
            },
        )
    )
    session.flush()

    record_audit(
        session,
        actor=actor,
        action="scan.create",
        subject_type="scan",
        subject_id=str(scan.id),
        outcome="queued",
        detail={
            "target_origin": scan.target_origin,
            "profile": scan.profile,
            "scope_version_id": str(scope_version.id),
            "task_id": str(task.id),
            "logical_id": task.logical_id,
            "dispatch": "outbox",
        },
    )
    return scan, task


# --- Outbox ------------------------------------------------------------------------


def pending_outbox_events(session: Session, *, limit: int = 20) -> list[OutboxEventRow]:
    """Undispatched events, oldest first.

    Used both by the steady-state dispatcher and by the startup reconcile — the same
    query, so a row cannot be dispatchable in one path and invisible in the other.
    """
    return list(
        session.scalars(
            select(OutboxEventRow)
            .where(OutboxEventRow.dispatched_at.is_(None))
            .order_by(OutboxEventRow.id)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
    )


def mark_dispatched(
    session: Session, event: OutboxEventRow, *, now: datetime | None = None
) -> None:
    event.dispatched_at = now or datetime.now(UTC)
    event.attempts = event.attempts + 1
    event.last_error = None
    session.flush()


def mark_dispatch_failed(session: Session, event: OutboxEventRow, error: str) -> None:
    """Record a failed delivery attempt.

    The row stays undispatched on purpose: delivery is at-least-once, so the correct
    response to a failure is to try again, not to mark it done. ``attempts`` keeps the
    retries visible rather than silent.
    """
    event.attempts = event.attempts + 1
    event.last_error = error[:2000]
    session.flush()


def outbox_depth(session: Session) -> int:
    return (
        session.scalar(
            select(func.count())
            .select_from(OutboxEventRow)
            .where(OutboxEventRow.dispatched_at.is_(None))
        )
        or 0
    )


def enqueue_cancel(
    session: Session, *, scan: ScanRow, cancel_epoch: int, actor: str
) -> OutboxEventRow:
    """Queue the worker-stop half of a cancellation.

    The durable half — bumping the epoch — has already happened by the time this is
    called. This row only asks the supervisor to stop a process group, so if the row is
    lost the scan is *still* cancelled; the consequence of the loss is a worker running
    until its own timeout, not a scan that keeps reaching the target.
    """
    event = OutboxEventRow(
        topic=SCAN_CANCEL_TOPIC,
        payload={"scan_id": str(scan.id), "cancel_epoch": cancel_epoch, "actor": actor},
    )
    session.add(event)
    session.flush()
    return event


# --- Tasks -------------------------------------------------------------------------


def get_task(session: Session, task_id: uuid.UUID) -> TaskRow | None:
    return session.get(TaskRow, task_id)


def get_task_for_scan(session: Session, scan_id: uuid.UUID) -> list[TaskRow]:
    return list(
        session.scalars(
            select(TaskRow).where(TaskRow.scan_id == scan_id).order_by(TaskRow.created_at)
        )
    )


def tasks_in_state(session: Session, *states: TaskState) -> list[TaskRow]:
    return list(
        session.scalars(
            select(TaskRow)
            .where(TaskRow.state.in_([str(s) for s in states]))
            .order_by(TaskRow.created_at)
        )
    )


def admit_task(
    session: Session,
    *,
    task: TaskRow,
    fencing_token: int,
    reserved: BudgetUsage,
) -> None:
    """Move a task ``planned -> admitted``, stamping the fencing token and reservation.

    Refuses if the task is not planned — including when a second delivery of the same
    message arrives, which is expected under at-least-once delivery.
    """
    if task.state != str(TaskState.PLANNED):
        raise AdmissionRefused(
            f"task {task.id} is {task.state!r}, not 'planned'; refusing to admit it twice"
        )

    scan = session.get(ScanRow, task.scan_id)
    if scan is None:
        raise AdmissionRefused(f"task {task.id} references a scan that does not exist")
    if scan.cancel_requested_at is not None:
        raise AdmissionRefused(
            f"scan {scan.id} was cancelled at {scan.cancel_requested_at.isoformat()}"
        )

    task.state = str(TaskState.ADMITTED)
    task.lease_token = fencing_token
    task.reserved_budget = reserved.model_dump()
    session.flush()


def mark_task_running(session: Session, *, task: TaskRow, attempt_id: str) -> None:
    _assert_attempt(task, attempt_id)
    _assert_state(task, TaskState.ADMITTED, TaskState.RUNNING)
    task.state = str(TaskState.RUNNING)
    task.started_at = datetime.now(UTC)
    session.flush()


def mark_task_succeeded(
    session: Session,
    *,
    task: TaskRow,
    attempt_id: str,
    reason: str = "",
    spent: BudgetUsage | None = None,
) -> None:
    _assert_attempt(task, attempt_id)
    task.state = str(TaskState.SUCCEEDED)
    task.finished_at = datetime.now(UTC)
    task.outcome_reason = reason or None
    if spent is not None:
        task.spent_budget = spent.model_dump()
    session.flush()


def mark_task_failed(
    session: Session,
    *,
    task: TaskRow,
    attempt_id: str,
    reason: str,
    spent: BudgetUsage | None = None,
) -> None:
    _assert_attempt(task, attempt_id)
    task.state = str(TaskState.FAILED)
    task.finished_at = datetime.now(UTC)
    task.outcome_reason = reason[:2000]
    if spent is not None:
        task.spent_budget = spent.model_dump()
    session.flush()


def mark_task_outcome_unknown(
    session: Session, *, task: TaskRow, attempt_id: str, reason: str
) -> None:
    """Record that a request may have reached the target and its result was lost.

    Build Plan §5.6: this state exists so the work is **not** blindly retried. Marking it
    failed instead would invite a retry that duplicates a side effect.
    """
    _assert_attempt(task, attempt_id)
    task.state = str(TaskState.OUTCOME_UNKNOWN)
    task.finished_at = datetime.now(UTC)
    task.outcome_reason = reason[:2000]
    session.flush()


def _assert_attempt(task: TaskRow, attempt_id: str) -> None:
    """Reject a writer that belongs to a different attempt.

    Together with the fencing token this is what stops a slow, superseded attempt from
    writing terminal state over its successor's.
    """
    if task.attempt_id != attempt_id:
        raise AdmissionRefused(
            f"task {task.id} attempt is {task.attempt_id!r}, not {attempt_id!r}; "
            "this writer belongs to a superseded attempt"
        )


def _assert_state(task: TaskRow, from_state: TaskState, to_state: TaskState) -> None:
    if task.state != str(from_state):
        raise AdmissionRefused(
            f"task {task.id} is {task.state!r}, expected {from_state.value!r} "
            f"to move to {to_state.value!r}"
        )


# --- Scan status -------------------------------------------------------------------


def transition_scan(
    session: Session, *, scan: ScanRow, target: ScanStatus, reason: str | None = None
) -> bool:
    """Apply a lifecycle transition, refusing illegal ones.

    Returns False when the transition was already applied — at-least-once dispatch means
    a terminal transition may legitimately arrive twice.
    """
    current = ScanStatus(scan.status)
    if current is target:
        return False
    assert_transition(current, target)
    scan.status = str(target)
    if reason is not None:
        scan.status_reason = reason[:2000]
    if target.is_terminal:
        scan.finished_at = datetime.now(UTC)
        from scopelens.checks.retest import reconcile_retests

        reconcile_retests(session, scan)
    session.flush()
    return True


def is_cancelled(session: Session, scan_id: uuid.UUID) -> bool:
    scan = get_scan(session, scan_id)
    return scan is not None and scan.cancel_requested_at is not None


def audit_budget_increases(
    session: Session,
    *,
    scan: ScanRow,
    scope_version: ScopeVersionRow,
    settings: Settings,
    limits: BudgetLimits,
) -> None:
    """Record approved rate increases in the first successful admission transaction.

    The coordinator calls this before setting ``started_at``, under its exclusive scan
    lease. Requested increases are recorded even if a deployment ceiling reduces the
    effective value below the default. Other budget fields cannot raise the defaults.
    """
    override = scope_version.budgets_override or {}
    increases = {}
    for field in ("requests_per_second", "max_in_flight"):
        default = getattr(settings.budgets, field)
        approved = override.get(field, default)
        if approved > default:
            increases[field] = {
                "default": default,
                "approved": approved,
                "effective": getattr(limits, field),
            }
    if increases:
        record_audit(
            session,
            actor="coordinator",
            action="budget.increase",
            subject_type="scan",
            subject_id=str(scan.id),
            outcome="admitted",
            detail={
                "scope_version_id": str(scope_version.id),
                "scope_key": scope_version.scope_key,
                "scope_version": scope_version.version,
                "increases": increases,
            },
        )


def budget_limits_for(scope_version: ScopeVersionRow, settings: Settings) -> BudgetLimits:
    """Apply explicit approved scope rates within separate deployment ceilings.

    The immutable, audited scope override can raise concurrency/rate, but not the other
    budgets. Without that approval the pilot defaults remain in force. Deployment
    ceilings bound both defaults and overrides (Project Specification §12).
    """
    limits = BudgetLimits.from_budgets(settings.budgets)
    override = scope_version.budgets_override or {}
    return BudgetLimits(
        max_requests=min(
            limits.max_requests, int(override.get("max_total_requests", limits.max_requests))
        ),
        max_pages=min(limits.max_pages, int(override.get("max_pages", limits.max_pages))),
        max_response_bytes=min(
            limits.max_response_bytes,
            int(override.get("max_body_bytes", limits.max_response_bytes)),
        ),
        wall_clock_seconds=min(
            limits.wall_clock_seconds,
            int(override.get("wall_clock_seconds", limits.wall_clock_seconds)),
        ),
        requests_per_second=min(
            settings.scope_max_requests_per_second,
            float(override.get("requests_per_second", limits.requests_per_second)),
        ),
        max_in_flight=min(
            settings.scope_max_in_flight,
            int(override.get("max_in_flight", limits.max_in_flight)),
        ),
        max_redirects_per_fetch=min(
            limits.max_redirects_per_fetch,
            int(override.get("max_redirects_per_fetch", limits.max_redirects_per_fetch)),
        ),
    )
