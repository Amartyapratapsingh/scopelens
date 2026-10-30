"""Coordinator behaviour (Build Plan §5.2, §5.5, §5.6).

The coordinator is where the ledger's vocabulary is decided, so these tests are mostly
about the *words*: which outcomes are recorded as failed, which as outcome_unknown, and
which as success. That distinction is what stops an interrupted run from reading as
retryable.

The worker is faked. The fake is deliberately pessimistic — an unconfigured
`RecordingSupervisor` returns a failure rather than a success, so a test that forgets to
state its expected worker behaviour fails loudly instead of passing on a fabricated pass.
"""

from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy.orm import Session

from scopelens.config import Settings
from scopelens.domain.budget import BudgetUsage
from scopelens.domain.enums import ScanStatus
from scopelens.domain.evidence import EvidenceOrigin
from scopelens.domain.task import TaskState
from scopelens.execution.coordinator import coordinate
from scopelens.execution.leases import acquire_lease, lease_is_live
from scopelens.execution.ledger import ExecutionDisabled
from scopelens.execution.supervisor import (
    RESULT_MARKER,
    RecordingSupervisor,
    WorkerResult,
    WorkerSpec,
)
from scopelens.persistence.models import AuditEventRow, EvidenceRow, ScanRow, TaskRow

pytestmark = pytest.mark.db


def worker_result(artifact: dict | None, *, exit_code: int = 0, **overrides) -> WorkerResult:
    """Build a WorkerResult carrying a declared result line, as a real worker would."""
    stdout = ""
    if artifact is not None:
        stdout = RESULT_MARKER + json.dumps(artifact) + "\n"
    base = {
        "run_id": "run-1",
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": "",
        "duration_seconds": 0.5,
    }
    base.update(overrides)
    return WorkerResult(**base)  # type: ignore[arg-type]


def success_artifact(**overrides) -> dict:
    base = {
        "ok": True,
        "url": "http://172.28.0.11/",
        "status_code": 200,
        "reason": "fetched",
        "headers": {"server": "nginx/1.27.5"},
        "body_excerpt": "<html>fixture</html>",
        "body_bytes": 21,
        "truncated": False,
        "elapsed_ms": 12,
        "error": None,
        "via_proxy": True,
        "broker_marker_seen": True,
    }
    base.update(overrides)
    return base


def admit_requests(settings: Settings, scan_id: uuid.UUID, count: int) -> None:
    """Write the broker audit rows the coordinator counts to establish admitted requests."""
    from scopelens.persistence.session import session_scope

    with session_scope(settings) as session:
        for _ in range(count):
            session.add(
                AuditEventRow(
                    actor="broker",
                    action="broker.admit",
                    subject_type="scan",
                    subject_id=str(scan_id),
                    outcome="allowed",
                    detail={"method": "GET"},
                )
            )


class TestHappyPath:
    def test_a_successful_run_settles_everything(
        self, settings: Settings, queued_scan, evidence_store
    ) -> None:
        scan, task = queued_scan
        admit_requests(settings, scan.id, 1)
        supervisor = RecordingSupervisor(worker_result(success_artifact()))

        result = coordinate(
            settings,
            scan_id=scan.id,
            task_id=task.id,
            attempt_id=task.attempt_id,
            supervisor=supervisor,
        )

        assert result.acted is True
        assert result.task_state is TaskState.SUCCEEDED
        assert result.scan_status is ScanStatus.COMPLETED
        assert result.requests_admitted == 1
        assert result.worker_succeeded is True

    def test_evidence_is_recorded_with_provenance(
        self, settings: Settings, queued_scan, db_session: Session
    ) -> None:
        scan, task = queued_scan
        admit_requests(settings, scan.id, 1)
        supervisor = RecordingSupervisor(worker_result(success_artifact()))

        result = coordinate(
            settings,
            scan_id=scan.id,
            task_id=task.id,
            attempt_id=task.attempt_id,
            supervisor=supervisor,
        )

        assert result.evidence_ids
        rows = db_session.query(EvidenceRow).filter(EvidenceRow.scan_id == scan.id).all()
        assert rows
        assert any(row.origin == str(EvidenceOrigin.SUPERVISOR) for row in rows)
        for row in rows:
            assert row.run_id == supervisor.run_ids[0]
            assert row.content_hash
            assert row.scope_content_hash

    def test_budget_is_reserved_then_reconciled(
        self, settings: Settings, queued_scan, db_session: Session
    ) -> None:
        """The reservation must not be left outstanding after the run."""
        scan, task = queued_scan
        admit_requests(settings, scan.id, 1)
        supervisor = RecordingSupervisor(worker_result(success_artifact()))

        coordinate(
            settings,
            scan_id=scan.id,
            task_id=task.id,
            attempt_id=task.attempt_id,
            supervisor=supervisor,
        )

        db_session.expire_all()
        row = db_session.get(ScanRow, scan.id)
        assert row is not None
        assert BudgetUsage.model_validate(row.budget_reserved).requests == 0
        assert BudgetUsage.model_validate(row.budget_spent).requests == 1

    def test_the_lease_is_released(
        self, settings: Settings, queued_scan, db_session: Session
    ) -> None:
        scan, task = queued_scan
        admit_requests(settings, scan.id, 1)
        supervisor = RecordingSupervisor(worker_result(success_artifact()))

        coordinate(
            settings,
            scan_id=scan.id,
            task_id=task.id,
            attempt_id=task.attempt_id,
            supervisor=supervisor,
        )

        db_session.expire_all()
        assert not lease_is_live(db_session, scan.id)

    def test_the_task_records_its_outcome_reason(
        self, settings: Settings, queued_scan, db_session: Session
    ) -> None:
        scan, task = queued_scan
        admit_requests(settings, scan.id, 1)
        supervisor = RecordingSupervisor(worker_result(success_artifact()))

        coordinate(
            settings,
            scan_id=scan.id,
            task_id=task.id,
            attempt_id=task.attempt_id,
            supervisor=supervisor,
        )

        db_session.expire_all()
        row = db_session.get(TaskRow, task.id)
        assert row is not None
        assert "HTTP 200" in (row.outcome_reason or "")
        assert row.finished_at is not None


class TestDuplicateAndConcurrentDelivery:
    def test_a_second_delivery_of_the_same_task_does_nothing(
        self, settings: Settings, queued_scan
    ) -> None:
        """At-least-once delivery must not become at-least-twice execution."""
        scan, task = queued_scan
        admit_requests(settings, scan.id, 1)
        supervisor = RecordingSupervisor(worker_result(success_artifact()))

        first = coordinate(
            settings,
            scan_id=scan.id,
            task_id=task.id,
            attempt_id=task.attempt_id,
            supervisor=supervisor,
        )
        second = coordinate(
            settings,
            scan_id=scan.id,
            task_id=task.id,
            attempt_id=task.attempt_id,
            supervisor=supervisor,
        )

        assert first.acted is True
        assert second.acted is False, "the duplicate ran a second time"
        assert "already" in second.reason
        assert len(supervisor.specs) == 1, "the worker was started twice"

    def test_a_live_lease_held_elsewhere_stops_the_run(
        self, settings: Settings, queued_scan, db_session: Session
    ) -> None:
        scan, task = queued_scan
        acquire_lease(db_session, scan_id=scan.id, holder="someone-else", ttl_seconds=300)
        db_session.commit()
        supervisor = RecordingSupervisor(worker_result(success_artifact()))

        result = coordinate(
            settings,
            scan_id=scan.id,
            task_id=task.id,
            attempt_id=task.attempt_id,
            supervisor=supervisor,
        )

        assert result.acted is False
        assert "another coordinator" in result.reason
        assert supervisor.specs == [], "a worker ran despite another coordinator holding the scan"


class TestUncertainOutcomes:
    def test_a_timed_out_worker_is_outcome_unknown_not_failed(
        self, settings: Settings, queued_scan, db_session: Session
    ) -> None:
        """The distinction that stops a blind retry (§5.6)."""
        scan, task = queued_scan
        admit_requests(settings, scan.id, 1)
        supervisor = RecordingSupervisor(
            worker_result(None, exit_code=None, timed_out=True, killed=True, duration_seconds=300)
        )

        result = coordinate(
            settings,
            scan_id=scan.id,
            task_id=task.id,
            attempt_id=task.attempt_id,
            supervisor=supervisor,
        )

        assert result.task_state is TaskState.OUTCOME_UNKNOWN
        assert result.scan_status is ScanStatus.COMPLETED_PARTIAL
        db_session.expire_all()
        row = db_session.get(TaskRow, task.id)
        assert row is not None
        assert row.state == str(TaskState.OUTCOME_UNKNOWN)

    def test_a_killed_worker_is_outcome_unknown(self, settings: Settings, queued_scan) -> None:
        scan, task = queued_scan
        supervise = RecordingSupervisor(
            worker_result(success_artifact(), exit_code=None, killed=True)
        )
        result = coordinate(
            settings,
            scan_id=scan.id,
            task_id=task.id,
            attempt_id=task.attempt_id,
            supervisor=supervise,
        )
        assert result.task_state is TaskState.OUTCOME_UNKNOWN


class TestFailureOutcomes:
    def test_a_broker_block_with_no_admitted_request_is_not_a_pass(
        self, settings: Settings, queued_scan
    ) -> None:
        """§9.7: blocked is never a pass, and never an N/A either."""
        scan, task = queued_scan
        blocked = success_artifact(
            ok=False, status_code=403, reason="transport_error", error="403 from proxy"
        )
        supervisor = RecordingSupervisor(worker_result(blocked, exit_code=1))

        result = coordinate(
            settings,
            scan_id=scan.id,
            task_id=task.id,
            attempt_id=task.attempt_id,
            supervisor=supervisor,
        )

        assert result.task_state is TaskState.FAILED
        assert result.scan_status is ScanStatus.COMPLETED_PARTIAL
        assert result.requests_admitted == 0
        assert "nothing was tested" in result.reason

    def test_a_worker_that_produces_no_artifact_fails(
        self, settings: Settings, queued_scan
    ) -> None:
        scan, task = queued_scan
        supervisor = RecordingSupervisor(worker_result(None, exit_code=1))

        result = coordinate(
            settings,
            scan_id=scan.id,
            task_id=task.id,
            attempt_id=task.attempt_id,
            supervisor=supervisor,
        )

        assert result.task_state is TaskState.FAILED
        assert "no result artifact" in result.reason

    def test_execution_disabled_refuses_to_run(self, settings: Settings, queued_scan) -> None:
        scan, task = queued_scan
        disabled = settings.model_copy(update={"scanner_execution_enabled": False})

        with pytest.raises(ExecutionDisabled):
            coordinate(
                disabled,
                scan_id=scan.id,
                task_id=task.id,
                attempt_id=task.attempt_id,
                supervisor=RecordingSupervisor(),
            )

    def test_an_unknown_scan_does_nothing(self, settings: Settings) -> None:
        result = coordinate(
            settings,
            scan_id=uuid.uuid4(),
            task_id=uuid.uuid4(),
            attempt_id="nope",
            supervisor=RecordingSupervisor(),
        )
        assert result.acted is False
        assert "does not exist" in result.reason


class TestCancellationDuringRun:
    def test_a_scan_cancelled_before_admission_is_not_run(
        self, settings: Settings, queued_scan, db_session: Session
    ) -> None:
        from datetime import UTC, datetime

        scan, task = queued_scan
        scan.cancel_requested_at = datetime.now(UTC)
        scan.status = str(ScanStatus.CANCELLED)
        # Committed, because the coordinator opens its own session and would otherwise
        # not see a cancellation that only exists in this test's transaction.
        db_session.commit()

        supervisor = RecordingSupervisor(worker_result(success_artifact()))
        result = coordinate(
            settings,
            scan_id=scan.id,
            task_id=task.id,
            attempt_id=task.attempt_id,
            supervisor=supervisor,
        )

        assert result.acted is False
        assert supervisor.specs == []


class TestWorkerSpec:
    def test_the_worker_receives_no_credentials(self, settings: Settings, queued_scan) -> None:
        """Build Plan §5.4, asserted at the point the spec is built."""
        scan, task = queued_scan
        supervisor = RecordingSupervisor(worker_result(success_artifact()))

        coordinate(
            settings,
            scan_id=scan.id,
            task_id=task.id,
            attempt_id=task.attempt_id,
            supervisor=supervisor,
        )

        spec: WorkerSpec = supervisor.specs[0]
        for forbidden in (
            "SCOPELENS_DATABASE_URL",
            "SCOPELENS_REDIS_URL",
            "SCOPELENS_SESSION_SECRET",
            "SCOPELENS_OPERATOR_PASSWORD",
        ):
            assert forbidden not in spec.environment

    def test_the_worker_is_pointed_at_the_proxy(self, settings: Settings, queued_scan) -> None:
        """The worker's only route out is the proxy, and it must be told about it."""
        scan, task = queued_scan
        supervisor = RecordingSupervisor(worker_result(success_artifact()))

        coordinate(
            settings,
            scan_id=scan.id,
            task_id=task.id,
            attempt_id=task.attempt_id,
            supervisor=supervisor,
        )

        spec = supervisor.specs[0]
        assert spec.environment["HTTP_PROXY"].startswith("http://")
        assert spec.environment["HTTPS_PROXY"].startswith("http://")
        assert spec.environment["SCOPELENS_EGRESS_TOKEN"]
        assert spec.network == settings.worker_network


@pytest.mark.parametrize("cancel_during_report", [False, True])
def test_report_enrichment_finishes_before_terminal_status(
    settings, queued_scan, monkeypatch, cancel_during_report
):
    from sqlalchemy import select

    from scopelens.config import ModelRoleSettings
    from scopelens.persistence.models import ScanRow, TaskRow
    from scopelens.persistence.session import session_scope

    scan, task = queued_scan
    settings.report_writer_model = ModelRoleSettings(model="test", base_url="http://unused.invalid")
    observed = []

    def enrich(cfg, scan_id):
        with session_scope(cfg) as db:
            # NOWAIT detects holding a scan lock across the provider call.
            row = db.scalar(
                select(ScanRow).where(ScanRow.id == scan_id).with_for_update(nowait=True)
            )
            assert row.status == ScanStatus.REPORTING
            assert row.finished_at is None
            assert db.get(TaskRow, task.id).state == TaskState.RUNNING
            assert lease_is_live(db, scan_id)
            observed.append(True)
            if cancel_during_report:
                from datetime import UTC, datetime

                row.cancel_requested_at = datetime.now(UTC)

    monkeypatch.setattr("scopelens.writer.enrich.enrich", enrich)
    result = coordinate(
        settings,
        scan_id=scan.id,
        task_id=task.id,
        attempt_id=task.attempt_id,
        supervisor=RecordingSupervisor(worker_result(success_artifact())),
    )
    assert observed == [True]
    assert result.scan_status == (
        ScanStatus.CANCELLED if cancel_during_report else ScanStatus.COMPLETED
    )


@pytest.mark.parametrize("worker_seconds,scan_seconds", [(1800, 2700), (1800, 120), (18000, 18000)])
def test_collection_stage_deadlines_fit_worker_and_scan(
    settings, queued_scan, worker_seconds, scan_seconds
):
    scan, task = queued_scan
    settings.worker_max_runtime_seconds = worker_seconds
    settings.budgets.wall_clock_seconds = scan_seconds
    supervisor = RecordingSupervisor(worker_result(success_artifact()))
    coordinate(
        settings,
        scan_id=scan.id,
        task_id=task.id,
        attempt_id=task.attempt_id,
        supervisor=supervisor,
    )
    spec = supervisor.specs[0]
    crawl_seconds = float(spec.environment["SCOPELENS_CRAWL_TIMEOUT"])
    zap_seconds = float(spec.environment["SCOPELENS_ZAP_TIMEOUT"])
    assert spec.max_runtime_seconds == min(worker_seconds, scan_seconds)
    assert crawl_seconds + zap_seconds <= spec.max_runtime_seconds * 0.8
    assert zap_seconds <= 600
    assert crawl_seconds > 0 and zap_seconds > 0
