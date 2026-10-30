"""Cancellation settles legacy queued intents without suppressing worker cleanup."""

import contextlib
import os
import signal
import subprocess
import sys
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import delete, select

from scopelens.dispatch import dispatch_once
from scopelens.domain.enums import ScanStatus
from scopelens.domain.task import TaskState
from scopelens.execution.leases import acquire_lease
from scopelens.execution.ledger import SCAN_CANCEL_TOPIC, SCAN_DISPATCH_TOPIC, outbox_depth
from scopelens.execution.reconciler import reconcile
from scopelens.persistence.models import AuditEventRow, OutboxEventRow, ScanRow, TaskRow
from scopelens.persistence.session import session_scope

pytestmark = pytest.mark.db


def remove_dispatch_intent(session, scan_id):
    session.execute(delete(OutboxEventRow))
    session.execute(delete(TaskRow).where(TaskRow.scan_id == scan_id))
    session.commit()


@pytest.mark.parametrize("already_requested", [False, True])
def test_cancel_settles_never_dispatched_scan(
    authed_client, queued_scan, db_session, settings, already_requested
):
    scan, _ = queued_scan
    remove_dispatch_intent(db_session, scan.id)
    if already_requested:
        scan.cancel_requested_at = datetime.now(UTC)
        scan.cancel_epoch = 3
        db_session.commit()

    response = authed_client.post(f"/api/scans/{scan.id}/cancel")
    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"
    assert response.json()["status_reason"] == "cancelled before dispatch"
    assert response.json()["cancel_epoch"] == (4 if already_requested else 1)
    with session_scope(settings) as session:
        row = session.get(ScanRow, scan.id)
        assert row.finished_at is not None
        assert row.cancel_requested_at is not None
        audit = session.scalar(select(AuditEventRow).where(AuditEventRow.action == "scan.cancel"))
        assert audit.outcome == "cancelled"
        assert audit.detail["reason"] == "cancelled before dispatch"
        assert outbox_depth(session) == 0

    again = authed_client.post(f"/api/scans/{scan.id}/cancel")
    assert again.json() == response.json()


@pytest.mark.parametrize("status", [s for s in ScanStatus if s.is_terminal])
@pytest.mark.parametrize("topic", [SCAN_DISPATCH_TOPIC, SCAN_CANCEL_TOPIC])
def test_dispatch_consumes_terminal_scan_events_without_enqueue(
    queued_scan, db_session, settings, status, topic
):
    scan, _ = queued_scan
    remove_dispatch_intent(db_session, scan.id)
    scan.status = str(status)
    db_session.add(OutboxEventRow(topic=topic, payload={"scan_id": str(scan.id)}))
    db_session.commit()
    sent = []

    result = dispatch_once(settings, send=lambda *args, **kwargs: sent.append((args, kwargs)))
    assert (result.examined, result.skipped, result.enqueued, result.failed) == (1, 1, 0, 0)
    assert sent == []
    with session_scope(settings) as session:
        assert outbox_depth(session) == 0
        audit = session.scalar(
            select(AuditEventRow).where(AuditEventRow.action == "outbox.dispatch")
        )
        assert audit.outcome == "skipped"
        assert audit.detail["reason"] == "scan already terminal"
    assert dispatch_once(settings).examined == 0


def test_terminal_cancel_still_delivers_worker_cleanup(authed_client, queued_scan, settings):
    scan, _ = queued_scan
    with session_scope(settings) as session:
        acquire_lease(session, scan_id=scan.id, holder="worker", ttl_seconds=300)
        row = session.get(ScanRow, scan.id)
        row.status = str(ScanStatus.TESTING)
    assert authed_client.post(f"/api/scans/{scan.id}/cancel").status_code == 200
    topics = []
    result = dispatch_once(settings, send=lambda *args, **kwargs: topics.append(kwargs["topic"]))
    assert topics == [SCAN_CANCEL_TOPIC]
    assert result.enqueued == 1
    assert result.skipped == 1


@pytest.mark.parametrize("status", [s for s in ScanStatus if s.is_terminal])
@pytest.mark.parametrize("history", ["dispatched", "leased"])
def test_terminal_scan_cleanup_keeps_execution_history(
    queued_scan, db_session, settings, status, history
):
    scan, _ = queued_scan
    remove_dispatch_intent(db_session, scan.id)
    scan.status = str(status)
    if history == "leased":
        acquire_lease(db_session, scan_id=scan.id, holder="worker", ttl_seconds=300)
    else:
        db_session.add(
            OutboxEventRow(
                topic=SCAN_DISPATCH_TOPIC,
                payload={"scan_id": str(scan.id)},
                dispatched_at=datetime.now(UTC),
            )
        )
    db_session.add(OutboxEventRow(topic=SCAN_CANCEL_TOPIC, payload={"scan_id": str(scan.id)}))
    db_session.commit()
    topics = []
    result = dispatch_once(settings, send=lambda *args, **kwargs: topics.append(kwargs["topic"]))
    assert topics == [SCAN_CANCEL_TOPIC]
    assert (result.enqueued, result.skipped, result.failed) == (1, 0, 0)


def test_previously_dispatched_scan_still_requests_cleanup(
    authed_client, queued_scan, db_session, settings
):
    scan, _ = queued_scan
    dispatch_once(settings, send=lambda *args, **kwargs: None)
    db_session.execute(delete(TaskRow).where(TaskRow.scan_id == scan.id))
    db_session.commit()
    response = authed_client.post(f"/api/scans/{scan.id}/cancel")
    assert response.json()["status_reason"] == "cancelled by the operator"
    topics = []
    dispatch_once(settings, send=lambda *args, **kwargs: topics.append(kwargs["topic"]))
    assert topics == [SCAN_CANCEL_TOPIC]


def test_consumed_terminal_execution_is_not_dispatch_history(queued_scan, db_session, settings):
    scan, _ = queued_scan
    remove_dispatch_intent(db_session, scan.id)
    scan.status = str(ScanStatus.CANCELLED)
    for topic in (SCAN_DISPATCH_TOPIC, SCAN_CANCEL_TOPIC):
        db_session.add(OutboxEventRow(topic=topic, payload={"scan_id": str(scan.id)}))
    db_session.commit()
    sent = []
    result = dispatch_once(settings, send=lambda *args, **kwargs: sent.append(kwargs["topic"]))
    assert sent == []
    assert (result.skipped, result.enqueued, result.failed) == (2, 0, 0)


@pytest.mark.parametrize("ignores_term", [False, True])
def test_running_cancel_reaches_supervisor_and_stops_process_group(
    authed_client, queued_scan, settings, monkeypatch, ignores_term
):
    """Real local processes exercise TERM/KILL; the Docker transport is substituted."""
    from scopelens import tasks
    from scopelens.execution import supervisor

    scan, task = queued_scan
    dispatch_once(settings, send=lambda *args, **kwargs: None)
    with session_scope(settings) as session:
        acquire_lease(session, scan_id=scan.id, holder="worker", ttl_seconds=300)
        session.get(ScanRow, scan.id).status = str(ScanStatus.TESTING)
        row = session.get(TaskRow, task.id)
        row.state = str(TaskState.RUNNING)
        row.started_at = datetime.now(UTC)

    program = (
        "import signal,time; "
        + ("signal.signal(signal.SIGTERM, signal.SIG_IGN); " if ignores_term else "")
        + "print('ready',flush=True); time.sleep(60)"
    )
    processes = []
    signals = []
    try:
        leader = subprocess.Popen(
            [sys.executable, "-c", program], stdout=subprocess.PIPE, text=True, process_group=0
        )
        processes.append(leader)
        assert leader.stdout.readline().strip() == "ready"
        child = subprocess.Popen(
            [sys.executable, "-c", program],
            stdout=subprocess.PIPE,
            text=True,
            process_group=leader.pid,
        )
        processes.append(child)
        assert child.stdout.readline().strip() == "ready"

        def stop(*, timeout):
            assert timeout == min(settings.worker_stop_grace_seconds, 30)
            signals.append(signal.SIGTERM)
            os.killpg(leader.pid, signal.SIGTERM)
            for process in processes:
                process.wait(timeout=0.1 if ignores_term else 3)

        def kill():
            signals.append(signal.SIGKILL)
            os.killpg(leader.pid, signal.SIGKILL)

        def list_workers(*, filters):
            assert filters == {
                "label": [f"scopelens.scan_id={scan.id}", "scopelens.managed=worker"]
            }
            return [SimpleNamespace(stop=stop, kill=kill)]

        trusted_supervisor = supervisor.DockerWorkerSupervisor(
            settings, client=SimpleNamespace(containers=SimpleNamespace(list=list_workers))
        )
        monkeypatch.setattr(supervisor, "DockerWorkerSupervisor", lambda _: trusted_supervisor)
        monkeypatch.setattr(tasks, "get_settings", lambda: settings)
        deliveries = []

        def deliver(payload, *, task_id, settings, topic):
            assert topic == SCAN_CANCEL_TOPIC
            deliveries.append((task_id, payload))

        cancelled = authed_client.post(f"/api/scans/{scan.id}/cancel")
        assert cancelled.json()["status"] == "cancelled"
        result = dispatch_once(settings, send=deliver)
        assert result.enqueued == 1
        assert result.failed == 0
        assert len(deliveries) == 1
        assert deliveries[0][0] == f"cancel:{scan.id}:1"
        # Queue consumers execute after dispatcher delivery commits. Running the
        # consumer inside its sender would block on the dispatcher's scan audit lock.
        stopped = tasks.cancel_task.run(**deliveries[0][1])
        assert stopped == {"scan_id": str(scan.id), "workers_stopped": 1}
        assert signals == ([signal.SIGTERM, signal.SIGKILL] if ignores_term else [signal.SIGTERM])
        for process in processes:
            assert process.wait(timeout=3) == -(signal.SIGKILL if ignores_term else signal.SIGTERM)
        with session_scope(settings) as session:
            audit = session.scalar(
                select(AuditEventRow).where(AuditEventRow.action == "scan.cancel.stop_workers")
            )
            assert audit.outcome == "stopped"
            assert audit.detail == {"workers_stopped": 1}
    finally:
        if processes:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(processes[0].pid, signal.SIGKILL)
        for process in processes:
            process.wait(timeout=3)
            process.stdout.close()


def test_never_dispatched_cancellation_and_audit_roll_back_together(
    authed_client, queued_scan, db_session, settings, monkeypatch
):
    from scopelens.api import scans

    scan, _ = queued_scan
    remove_dispatch_intent(db_session, scan.id)

    def fail_audit(*args, **kwargs):
        raise RuntimeError("audit unavailable")

    monkeypatch.setattr(scans, "record_audit", fail_audit)
    with pytest.raises(RuntimeError, match="audit unavailable"):
        authed_client.post(f"/api/scans/{scan.id}/cancel")
    with session_scope(settings) as session:
        row = session.get(ScanRow, scan.id)
        assert row.status == "queued"
        assert row.cancel_epoch == 0
        assert row.cancel_requested_at is None
        assert row.finished_at is None


@pytest.mark.parametrize("with_planned_task", [False, True])
def test_reconcile_settles_queued_cancellation_once(
    queued_scan, db_session, settings, with_planned_task
):
    scan, _ = queued_scan
    if not with_planned_task:
        remove_dispatch_intent(db_session, scan.id)
    scan.cancel_epoch = 3
    db_session.commit()
    now = datetime.now(UTC)

    first = reconcile(settings, now=now)
    assert first.queued_scans_cancelled == [str(scan.id)]
    assert reconcile(settings).queued_scans_cancelled == []
    with session_scope(settings) as session:
        row = session.get(ScanRow, scan.id)
        assert row.status == "cancelled"
        assert row.status_reason == "cancelled before dispatch"
        assert row.cancel_epoch == 3
        assert row.cancel_requested_at == now
        assert row.reconciled_at == now
        assert row.finished_at is not None
        audits = list(
            session.scalars(select(AuditEventRow).where(AuditEventRow.action == "scan.reconcile"))
        )
        assert len(audits) == 1
        assert audits[0].outcome == "cancelled"
        assert audits[0].detail["reason"] == "cancelled before dispatch"


@pytest.mark.parametrize("case", ["uncancelled", "leased", "running"])
def test_reconcile_leaves_other_scans_unchanged(queued_scan, db_session, settings, case):
    scan, _ = queued_scan
    if case != "uncancelled":
        scan.cancel_epoch = 1
    if case == "leased":
        acquire_lease(db_session, scan_id=scan.id, holder="worker", ttl_seconds=300)
    if case == "running":
        scan.status = str(ScanStatus.TESTING)
    db_session.commit()

    assert reconcile(settings).queued_scans_cancelled == []
    with session_scope(settings) as session:
        row = session.get(ScanRow, scan.id)
        assert row.status == ("testing" if case == "running" else "queued")
        assert row.cancel_epoch == (0 if case == "uncancelled" else 1)
