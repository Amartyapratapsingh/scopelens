"""Outbox dispatcher (Build Plan §5.2).

Delivery is **at-least-once** and the code is written to expect it. The dispatcher's
job is narrow: find undispatched outbox rows, hand them to Celery, mark them dispatched.

Two consequences follow directly from at-least-once, and both are deliberate:

* The row is marked dispatched *after* a successful enqueue. A crash in between means
  the event is enqueued twice on the next pass. That is the correct trade — the
  alternative (mark first, enqueue second) loses work silently, which is strictly worse
  than doing it twice. The task's idempotency key absorbs the duplicate.
* A failed enqueue leaves the row undispatched and records the error, so a Redis outage
  delays work instead of discarding it.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy.orm import Session

from scopelens.config import Settings
from scopelens.domain.enums import ScanStatus
from scopelens.execution.cancellation import may_need_worker_cleanup
from scopelens.execution.ledger import (
    SCAN_CANCEL_TOPIC,
    SCAN_DISPATCH_TOPIC,
    ExecutionDisabled,
    assert_execution_enabled,
    mark_dispatch_failed,
    mark_dispatched,
    pending_outbox_events,
)
from scopelens.persistence.models import OutboxEventRow, ScanRow
from scopelens.persistence.repositories import record_audit
from scopelens.persistence.session import session_scope


@dataclass
class DispatchResult:
    examined: int = 0
    enqueued: int = 0
    failed: int = 0
    skipped: int = 0

    def __str__(self) -> str:
        return (
            f"examined={self.examined} enqueued={self.enqueued} "
            f"failed={self.failed} skipped={self.skipped}"
        )


class Sender(Protocol):
    """How a dispatch payload reaches the queue. Injected so tests can simulate."""

    def __call__(self, payload: dict, *, task_id: str, settings: Settings, topic: str) -> None: ...


def dispatch_once(settings: Settings, *, send: Sender | None = None) -> DispatchResult:
    """Drain the outbox once.

    ``send`` is injected so tests can exercise dispatch without a live broker, and so a
    test can simulate a queue outage by passing a sender that raises.
    """
    result = DispatchResult()

    try:
        assert_execution_enabled(settings)
    except ExecutionDisabled:
        # Not an error: execution can be switched off deliberately, and when it is, the
        # honest behaviour is to leave the rows queued rather than fail them.
        with session_scope(settings) as session:
            result.examined = len(pending_outbox_events(session, limit=settings.outbox_batch_size))
        result.skipped = result.examined
        return result

    sender = send or _celery_send

    with session_scope(settings) as session:
        events = pending_outbox_events(session, limit=settings.outbox_batch_size)
        result.examined = len(events)

        for event in events:
            try:
                enqueued = _dispatch_event(session, event, settings, sender)
            except Exception as exc:  # noqa: BLE001 - a delivery failure must not stop the batch
                mark_dispatch_failed(session, event, f"{exc.__class__.__name__}: {exc}")
                record_audit(
                    session,
                    actor="dispatcher",
                    action="outbox.dispatch",
                    subject_type="outbox_event",
                    subject_id=str(event.id),
                    outcome="failed",
                    detail={"topic": event.topic, "error": exc.__class__.__name__},
                )
                result.failed += 1
            else:
                mark_dispatched(session, event)
                record_audit(
                    session,
                    actor="dispatcher",
                    action="outbox.dispatch",
                    subject_type="outbox_event",
                    subject_id=str(event.id),
                    outcome="enqueued" if enqueued else "skipped",
                    detail={
                        "topic": event.topic,
                        **{k: str(v) for k, v in event.payload.items()},
                        **({} if enqueued else {"reason": "scan already terminal"}),
                    },
                )
                if enqueued:
                    result.enqueued += 1
                else:
                    result.skipped += 1

    return result


def _dispatch_event(
    session: Session, event: OutboxEventRow, settings: Settings, sender: Sender
) -> bool:
    payload = dict(event.payload)
    scan = session.get(ScanRow, uuid.UUID(payload["scan_id"]), with_for_update=True)
    if scan is not None and ScanStatus(scan.status).is_terminal:
        # Operator cancellation makes the scan terminal before requesting process
        # cleanup. Preserve stop notifications for existing execution records;
        # terminal execution notifications must never launch work.
        needs_stop = event.topic == SCAN_CANCEL_TOPIC and may_need_worker_cleanup(session, scan)
        if not needs_stop:
            return False

    if event.topic == SCAN_DISPATCH_TOPIC:
        # The Celery task id is derived from the same identity the unique constraint uses,
        # so a duplicate enqueue is visibly the same logical delivery rather than a new one.
        task_id = (
            f"{payload.get('scan_id')}:{payload.get('logical_id')}:{payload.get('attempt_id')}"
        )
        sender(payload, task_id=task_id, settings=settings, topic=event.topic)
        return True

    if event.topic == SCAN_CANCEL_TOPIC:
        sender(
            payload,
            task_id=f"cancel:{payload.get('scan_id')}:{payload.get('cancel_epoch')}",
            settings=settings,
            topic=event.topic,
        )
        return True

    raise ValueError(f"unknown outbox topic {event.topic!r}")


def _celery_send(payload: dict, *, task_id: str, settings: Settings, topic: str) -> None:
    """Enqueue through Celery. Imported lazily so the API need not import Celery."""
    del settings
    from scopelens.tasks import cancel_task, execute_task

    if topic == SCAN_CANCEL_TOPIC:
        cancel_task.apply_async(kwargs=payload, task_id=task_id)
    else:
        execute_task.apply_async(kwargs=payload, task_id=task_id)


def dispatch_forever(settings: Settings, *, interval_seconds: float = 1.0) -> None:
    """Poll the outbox until interrupted.

    Catches per-iteration failures so a transient database blip does not kill the
    dispatch loop — a dispatcher that exits on the first error is a dispatcher that
    stops noticing new work.
    """
    print(f"dispatch: polling the outbox every {interval_seconds}s")
    while True:
        try:
            result = dispatch_once(settings)
            if result.examined:
                print(f"dispatch: {result} at {datetime.now(UTC).isoformat()}")
        except Exception as exc:  # noqa: BLE001 - keep the loop alive
            print(f"dispatch: iteration failed: {exc.__class__.__name__}: {exc}")
        time.sleep(interval_seconds)
