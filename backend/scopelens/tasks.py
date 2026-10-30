"""Celery application and the dispatched task (Build Plan §5.2, §3).

Celery's job here is narrow: wake a trusted worker up and hand it a reference. It is not
the source of truth and it is not the scheduler. PostgreSQL decides what should happen;
Celery delivers the notification that it is time.

Configuration choices, each with a reason:

* ``task_acks_late = True`` — the message is acknowledged after the work finishes, so a
  coordinator that dies mid-run has its delivery redelivered rather than silently
  dropped. This is what makes delivery at-least-once rather than at-most-once, and the
  task is written to tolerate it.
* ``task_reject_on_worker_lost = True`` — a killed worker returns the message to the
  queue rather than losing it.
* ``worker_prefetch_multiplier = 1`` — a coordinator holds one task at a time. Prefetching
  would let a worker hoard messages it is not yet running, which makes the lease TTL
  meaningless as a liveness signal.
* ``broker_connection_retry_on_startup`` — a Redis restart must not require restarting
  the supervisor by hand.
"""

from __future__ import annotations

import uuid
from typing import Any

from celery import Celery

from scopelens.config import get_settings

TASK_NAME = "scopelens.execute_task"
CANCEL_TASK_NAME = "scopelens.cancel_task"


def build_celery() -> Celery:
    settings = get_settings()
    app = Celery("scopelens", broker=settings.redis_url, backend=settings.redis_url)

    app.conf.update(
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,
        task_track_started=True,
        broker_connection_retry_on_startup=True,
        # Results are not read back — the ledger is the record — but a short expiry keeps
        # Redis from accumulating them if one ever is.
        result_expires=3600,
        task_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
    )
    return app


app = build_celery()


@app.task(name=TASK_NAME, bind=True, max_retries=0)  # type: ignore[untyped-decorator]
def execute_task(
    self: Any,
    *,
    scan_id: str,
    task_id: str,
    logical_id: str,
    attempt_id: str,
) -> dict[str, Any]:
    """Run one dispatched task.

    ``max_retries=0`` is deliberate. Retrying a task that may have reached the target is
    precisely the blind retry Build Plan §5.6 forbids; a task whose outcome is unknown is
    recorded as ``outcome_unknown`` and the reconciler decides what happens next. Celery's
    own redelivery (acks-late) is a different mechanism and remains enabled for messages
    that were never processed at all.
    """
    from scopelens.execution.coordinator import coordinate

    del logical_id  # carried for the idempotency key, not used by the body

    settings = get_settings()
    result = coordinate(
        settings,
        scan_id=uuid.UUID(scan_id),
        task_id=uuid.UUID(task_id),
        attempt_id=attempt_id,
    )
    return {
        "scan_id": result.scan_id,
        "task_id": result.task_id,
        "task_state": result.task_state.value,
        "scan_status": result.scan_status.value if result.scan_status else None,
        "reason": result.reason,
        "requests_admitted": result.requests_admitted,
        "acted": result.acted,
        "evidence_count": len(result.evidence_ids),
    }


@app.task(name=CANCEL_TASK_NAME, bind=True, max_retries=0)  # type: ignore[untyped-decorator]
def cancel_task(self: Any, *, scan_id: str, cancel_epoch: int, actor: str) -> dict[str, Any]:
    """Stop the worker process group for a cancelled scan (Build Plan §5.6).

    Runs in the supervisor because that is the only component with the Docker socket.
    Egress for this scan has already been revoked by the API — by the time this runs, the
    scan cannot reach the target whatever the worker does. This task's job is to stop the
    process that is no longer allowed to do anything, rather than to enforce the policy.

    Deliberately **not** implemented with Celery worker revocation: Celery's own
    documentation discourages programmatic task termination, and terminating a worker
    process would take down unrelated tasks (Project Specification §12).
    """
    from scopelens.execution.supervisor import DockerWorkerSupervisor
    from scopelens.persistence.repositories import record_audit
    from scopelens.persistence.session import session_scope

    del cancel_epoch, actor

    settings = get_settings()
    supervisor = DockerWorkerSupervisor(settings)
    stopped = supervisor.stop_all_for_scan(uuid.UUID(scan_id), timeout_seconds=30.0)

    with session_scope(settings) as session:
        record_audit(
            session,
            actor="supervisor",
            action="scan.cancel.stop_workers",
            subject_type="scan",
            subject_id=scan_id,
            outcome="stopped" if stopped else "nothing_to_stop",
            detail={"workers_stopped": stopped},
        )

    return {"scan_id": scan_id, "workers_stopped": stopped}
