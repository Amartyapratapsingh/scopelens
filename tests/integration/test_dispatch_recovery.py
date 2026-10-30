"""Dispatch, recovery and cancellation (Build Plan §5.2, §5.6; test suite §8).

These are the tests the M1 exit gate names: duplicate dispatch, stale lease, queue loss,
and crash before/after dispatch must all produce **no uncontrolled duplicate run**.

"No uncontrolled duplicate run" is the precise claim. Duplicate *delivery* is expected and
harmless; duplicate *execution against the target* is the failure being prevented.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from scopelens.config import Settings
from scopelens.dispatch import dispatch_once
from scopelens.domain.budget import BudgetUsage
from scopelens.domain.enums import ScanStatus
from scopelens.domain.task import TaskState
from scopelens.execution.leases import acquire_lease
from scopelens.execution.ledger import SCAN_CANCEL_TOPIC, outbox_depth
from scopelens.execution.reconciler import reconcile
from scopelens.persistence.models import CoordinatorLeaseRow, OutboxEventRow, ScanRow, TaskRow
from scopelens.persistence.session import session_scope

pytestmark = pytest.mark.db


class RecordingSender:
    """Records what would have been enqueued, or fails on demand."""

    def __init__(self, *, fail: bool = False) -> None:
        self.sent: list[dict] = []
        self.task_ids: list[str] = []
        self.topics: list[str] = []
        self.fail = fail

    def __call__(self, payload, *, task_id: str, settings: Settings, topic: str) -> None:
        if self.fail:
            raise ConnectionError("redis is unreachable")
        self.sent.append(payload)
        self.task_ids.append(task_id)
        self.topics.append(topic)


def reload_task(session: Session, task_id: uuid.UUID) -> TaskRow:
    row = session.get(TaskRow, task_id)
    assert row is not None
    return row


class TestDispatch:
    def test_a_created_scan_is_dispatched_once(
        self, queued_scan, settings: Settings, db_session: Session
    ) -> None:
        _scan, task = queued_scan
        sender = RecordingSender()

        result = dispatch_once(settings, send=sender)

        assert result.enqueued == 1
        assert result.failed == 0
        assert sender.topics == ["scan.task.dispatch"]
        assert sender.task_ids[0].endswith(task.attempt_id)

    def test_the_row_is_marked_dispatched(
        self, queued_scan, settings: Settings, db_session: Session
    ) -> None:
        _scan, _task = queued_scan
        dispatch_once(settings, send=RecordingSender())

        with session_scope(settings) as session:
            assert outbox_depth(session) == 0

    def test_a_dispatched_row_is_not_dispatched_again(
        self, queued_scan, settings: Settings
    ) -> None:
        sender = RecordingSender()
        dispatch_once(settings, send=sender)
        second = dispatch_once(settings, send=sender)

        assert second.examined == 0
        assert len(sender.sent) == 1

    def test_queue_loss_leaves_the_row_dispatchable(self, queued_scan, settings: Settings) -> None:
        """A Redis outage must delay work, not discard it."""
        _scan, _task = queued_scan

        failed = dispatch_once(settings, send=RecordingSender(fail=True))
        assert failed.failed == 1
        assert failed.enqueued == 0

        with session_scope(settings) as session:
            assert outbox_depth(session) == 1
            event = session.query(OutboxEventRow).one()
            assert event.attempts == 1
            assert "redis is unreachable" in (event.last_error or "")

        recovered = dispatch_once(settings, send=RecordingSender())
        assert recovered.enqueued == 1

    def test_dispatch_is_skipped_while_execution_is_disabled(
        self, queued_scan, settings: Settings
    ) -> None:
        """Rows stay queued rather than being failed — disabling is not an error."""
        disabled = settings.model_copy(update={"scanner_execution_enabled": False})
        sender = RecordingSender()

        result = dispatch_once(disabled, send=sender)

        assert result.skipped == 1
        assert result.failed == 0
        assert sender.sent == []
        with session_scope(settings) as session:
            assert outbox_depth(session) == 1

    def test_duplicate_dispatch_produces_one_logical_task(
        self, queued_scan, settings: Settings, db_session: Session
    ) -> None:
        """At-least-once delivery: two enqueues, still one task in the ledger."""
        scan, _task = queued_scan

        # Simulate the crash-between-enqueue-and-mark window by re-opening the row.
        dispatch_once(settings, send=RecordingSender())
        with session_scope(settings) as session:
            event = session.query(OutboxEventRow).one()
            event.dispatched_at = None

        sender = RecordingSender()
        dispatch_once(settings, send=sender)

        with session_scope(settings) as session:
            tasks = session.query(TaskRow).filter(TaskRow.scan_id == scan.id).all()
        assert len(tasks) == 1, "a duplicate delivery created a second logical task"
        assert sender.sent, "the duplicate delivery should still have been enqueued"


class TestReconcileAfterCrash:
    def test_crash_before_dispatch_leaves_work_dispatchable(
        self, queued_scan, settings: Settings
    ) -> None:
        """The outbox row is written in the same transaction as the scan, so it survives."""
        _scan, _task = queued_scan
        report = reconcile(settings)

        assert report.pending_outbox == 1
        assert report.scans_settled == []

        dispatched = dispatch_once(settings, send=RecordingSender())
        assert dispatched.enqueued == 1

    def test_crash_after_dispatch_marks_the_task_outcome_unknown(
        self, queued_scan, settings: Settings, db_session: Session
    ) -> None:
        """A request may have reached the target, so this must not read as retryable."""
        scan, task = queued_scan

        # Simulate: dispatched, admitted, running, then the coordinator died.
        with session_scope(settings) as session:
            row = session.get(TaskRow, task.id)
            assert row is not None
            row.state = str(TaskState.RUNNING)
            session.add(
                CoordinatorLeaseRow(
                    scan_id=scan.id,
                    holder="dead-coordinator",
                    fencing_token=1,
                    acquired_at=datetime.now(UTC) - timedelta(minutes=5),
                    expires_at=datetime.now(UTC) - timedelta(minutes=4),
                    released_at=None,
                )
            )

        report = reconcile(settings)

        assert str(task.id) in report.live_tasks_without_lease
        with session_scope(settings) as session:
            row = reload_task(session, task.id)
            assert row.state == str(TaskState.OUTCOME_UNKNOWN)
            assert "not retried" in (row.outcome_reason or "")
            sc = session.get(ScanRow, scan.id)
            assert sc is not None
            assert sc.status == str(ScanStatus.COMPLETED_PARTIAL)
            assert sc.reconciled_at is not None

    def test_reconcile_expires_the_stale_lease(self, queued_scan, settings: Settings) -> None:
        scan, _task = queued_scan
        with session_scope(settings) as session:
            session.add(
                CoordinatorLeaseRow(
                    scan_id=scan.id,
                    holder="dead",
                    fencing_token=3,
                    acquired_at=datetime.now(UTC) - timedelta(minutes=5),
                    expires_at=datetime.now(UTC) - timedelta(minutes=4),
                    released_at=None,
                )
            )

        report = reconcile(settings)
        assert report.expired_leases == 1

        # A replacement can now take over, and it gets a higher token.
        with session_scope(settings) as session:
            lease = acquire_lease(session, scan_id=scan.id, holder="replacement", ttl_seconds=30)
            assert lease is not None
            assert lease.fencing_token > 3

    def test_spent_budget_survives_reconciliation(self, queued_scan, settings: Settings) -> None:
        """§5.6: spent budget persists across recovery."""
        scan, task = queued_scan
        with session_scope(settings) as session:
            row = session.get(ScanRow, scan.id)
            assert row is not None
            row.budget_spent = BudgetUsage(requests=7).model_dump()
            row.budget_reserved = BudgetUsage(requests=3).model_dump()
            task_row = session.get(TaskRow, task.id)
            assert task_row is not None
            task_row.state = str(TaskState.ADMITTED)

        reconcile(settings)

        with session_scope(settings) as session:
            row = session.get(ScanRow, scan.id)
            assert row is not None
            assert BudgetUsage.model_validate(row.budget_spent).requests == 7
            assert BudgetUsage.model_validate(row.budget_reserved).requests == 0

    def test_reconcile_is_idempotent(self, queued_scan, settings: Settings) -> None:
        """Running it twice must not double-count or re-settle anything."""
        first = reconcile(settings)
        second = reconcile(settings)

        assert first.pending_outbox == second.pending_outbox == 1
        assert second.expired_leases == 0

    def test_reconcile_settles_only_live_tasks(self, queued_scan, settings: Settings) -> None:
        """A planned task is not an orphan — nothing has tried to run it yet."""
        _scan, task = queued_scan
        report = reconcile(settings)

        assert report.live_tasks_without_lease == []
        with session_scope(settings) as session:
            assert reload_task(session, task.id).state == str(TaskState.PLANNED)


class TestCancellation:
    def test_cancelling_revokes_egress_and_queues_the_stop(
        self, authed_client, queued_scan, settings: Settings
    ) -> None:
        from scopelens.persistence.repositories import get_scan

        scan, _task = queued_scan
        response = authed_client.post(f"/api/scans/{scan.id}/cancel")

        assert response.status_code == 200, response.text
        body = response.json()
        assert body["status"] == ScanStatus.CANCELLED
        assert body["cancel_epoch"] == 1
        assert body["cancel_requested_at"] is not None

        with session_scope(settings) as session:
            row = get_scan(session, scan.id)
            assert row is not None
            assert row.egress_token_hash is None or row.egress_token_epoch < row.cancel_epoch

    def test_cancellation_queues_a_worker_stop_event(
        self, authed_client, queued_scan, settings: Settings
    ) -> None:
        scan, _task = queued_scan
        authed_client.post(f"/api/scans/{scan.id}/cancel")

        with session_scope(settings) as session:
            topics = [e.topic for e in session.query(OutboxEventRow).all()]
        assert SCAN_CANCEL_TOPIC in topics

    def test_cancelling_a_finished_scan_is_idempotent(
        self, authed_client, queued_scan, settings: Settings
    ) -> None:
        scan, _task = queued_scan
        with session_scope(settings) as session:
            row = session.get(ScanRow, scan.id)
            assert row is not None
            row.status = str(ScanStatus.COMPLETED)
            row.finished_at = datetime.now(UTC)

        response = authed_client.post(f"/api/scans/{scan.id}/cancel")

        assert response.status_code == 200
        assert response.json()["status"] == ScanStatus.COMPLETED

    def test_cancelling_an_unknown_scan_is_a_404(self, authed_client) -> None:
        assert authed_client.post(f"/api/scans/{uuid.uuid4()}/cancel").status_code == 404


class TestCancellationLatency:
    """Build Plan §5.6: measure the two deadlines rather than asserting them."""

    def test_egress_revocation_is_immediate(
        self, authed_client, queued_scan, settings: Settings, db_session: Session
    ) -> None:
        """The 5-second admission-stop target.

        Revocation does not depend on the worker, the queue or the supervisor: it is one
        durable write, so the measured time should be a database round trip.
        """
        import time

        from scopelens.broker.policy import BrokerRequest, authorize, issue_egress_token
        from scopelens.execution.leases import acquire_lease as acquire
        from scopelens.scope.dns import StaticResolver

        scan, _task = queued_scan
        token = issue_egress_token(db_session, scan=scan)
        acquire(db_session, scan_id=scan.id, holder="t", ttl_seconds=300)
        db_session.commit()

        # Confirm the token works before cancelling.
        from scopelens.persistence.repositories import get_scope_version, scope_row_to_domain

        scope_row = get_scope_version(db_session, scan.scope_version_id)
        assert scope_row is not None
        scope = scope_row_to_domain(scope_row)
        allowed = authorize(
            db_session,
            settings=settings,
            request=BrokerRequest(
                method="GET",
                scheme=scope.scheme,
                host=scope.host,
                port=scope.port,
                path="/",
                egress_token=token,
            ),
            resolver=StaticResolver({}),
        )
        assert allowed.allowed, allowed.detail

        # Release the row locks `authorize` took. Holding a FOR UPDATE lock across an
        # HTTP call would block the API's own transaction on the same scan row — which
        # hangs rather than fails, so it is worth naming.
        db_session.rollback()

        started = time.monotonic()
        authed_client.post(f"/api/scans/{scan.id}/cancel")
        elapsed = time.monotonic() - started

        assert elapsed < 5.0, f"egress revocation took {elapsed:.3f}s, over the 5s target"

        # The cancel was written by the API's session, not this one. Our sessionmaker uses
        # expire_on_commit=False, so an object loaded before that write keeps its old
        # attributes; without expiring it here this test would read a stale epoch and
        # wrongly observe an allow.
        db_session.expire_all()

        # The very next request is refused, without any worker cooperation.
        denied = authorize(
            db_session,
            settings=settings,
            request=BrokerRequest(
                method="GET",
                scheme=scope.scheme,
                host=scope.host,
                port=scope.port,
                path="/",
                egress_token=token,
            ),
            resolver=StaticResolver({}),
        )
        assert not denied.allowed
        assert denied.denial is not None
        db_session.rollback()

    def test_worker_stop_request_is_queued_within_the_deadline(
        self, authed_client, queued_scan, settings: Settings
    ) -> None:
        """The 30-second run-stop target, measured up to the point the supervisor is asked.

        Stopping the process group itself needs the Docker socket and is measured in the
        end-to-end run; what is asserted here is that the request reaches the outbox
        promptly and would be delivered on the next dispatch tick.
        """
        import time

        scan, _task = queued_scan
        started = time.monotonic()
        authed_client.post(f"/api/scans/{scan.id}/cancel")

        with session_scope(settings) as session:
            cancel_events = (
                session.query(OutboxEventRow)
                .filter(OutboxEventRow.topic == SCAN_CANCEL_TOPIC)
                .all()
            )
        elapsed = time.monotonic() - started

        assert len(cancel_events) == 1
        assert elapsed < 30.0, f"stop request took {elapsed:.3f}s to reach the outbox"
