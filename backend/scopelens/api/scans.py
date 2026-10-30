"""Scan routes (Project Specification §6, Build Plan §5.2, §5.6).

M1 changes what creating a scan means. It is no longer an inert record: it writes the
scan, its first task and the outbox event in one transaction, and the dispatcher picks
the event up. The API still does not execute anything itself — it records intent
durably and reports what the ledger says happened.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from scopelens.api.deps import AppSettings, CurrentOperator, DbSession
from scopelens.broker.policy import revoke_egress
from scopelens.config import Settings, get_settings
from scopelens.domain.budget import BudgetUsage
from scopelens.domain.enums import AuthorityDomain, ProfileName, ScanStatus
from scopelens.domain.evidence import EvidenceOrigin, EvidenceRecord, RedactionState
from scopelens.domain.lab import LabBinding
from scopelens.domain.scan import ExecutionState, ScanCreateRequest
from scopelens.domain.task import TaskState
from scopelens.execution import budget as budget_service
from scopelens.execution.cancellation import may_need_worker_cleanup
from scopelens.execution.ledger import (
    budget_limits_for,
    create_scan_with_task,
    enqueue_cancel,
    execution_status,
    get_task_for_scan,
)
from scopelens.persistence.models import ScanRow, ScopeVersionRow, TaskRow
from scopelens.persistence.repositories import (
    get_scan,
    get_scope_version,
    list_scans,
    record_audit,
    scan_row_to_domain,
    scope_row_to_domain,
)
from scopelens.scope.service import get_lab_allowlist

router = APIRouter(prefix="/api/scans", tags=["scans"])


class TaskView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    logical_id: str
    attempt_id: str
    task_type: str
    state: TaskState
    lease_token: int
    reserved_budget: BudgetUsage
    spent_budget: BudgetUsage
    outcome_reason: str | None
    started_at: datetime | None
    finished_at: datetime | None


class EvidenceView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    origin: EvidenceOrigin
    producer: str
    producer_hash: str | None = None
    run_id: str | None = None
    tool_version: str | None = None
    trusted: bool
    captured_at: datetime
    content_hash: str
    content_bytes: int
    truncated: bool
    redaction_state: RedactionState
    content_type: str | None
    summary: str


class ScanView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    scope_version_id: str
    target_origin: str
    profile: ProfileName
    score_version: str
    status: ScanStatus
    status_reason: str | None
    progress_percent: int
    findings_count: int
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    cancel_epoch: int
    cancel_requested_at: datetime | None
    budget_spent: BudgetUsage
    budget_reserved: BudgetUsage
    execution: ExecutionState
    tasks: list[TaskView] = []


def _task_view(row: TaskRow) -> TaskView:
    return TaskView(
        id=str(row.id),
        logical_id=row.logical_id,
        attempt_id=row.attempt_id,
        task_type=row.task_type,
        state=TaskState(row.state),
        lease_token=row.lease_token,
        reserved_budget=BudgetUsage.model_validate(row.reserved_budget or {}),
        spent_budget=BudgetUsage.model_validate(row.spent_budget or {}),
        outcome_reason=row.outcome_reason,
        started_at=row.started_at,
        finished_at=row.finished_at,
    )


def _to_view(row: ScanRow, session: Session, *, include_tasks: bool = False) -> ScanView:
    record = scan_row_to_domain(row)
    tasks = [_task_view(t) for t in get_task_for_scan(session, row.id)] if include_tasks else []
    return ScanView(
        id=record.id,
        scope_version_id=record.scope_version_id,
        target_origin=record.target_origin,
        profile=record.profile,
        score_version=record.score_version,
        status=record.status,
        status_reason=record.status_reason,
        progress_percent=record.progress_percent,
        findings_count=record.findings_count,
        created_at=record.created_at,
        started_at=record.started_at,
        finished_at=record.finished_at,
        cancel_epoch=row.cancel_epoch,
        cancel_requested_at=row.cancel_requested_at,
        budget_spent=BudgetUsage.model_validate(row.budget_spent or {}),
        budget_reserved=BudgetUsage.model_validate(row.budget_reserved or {}),
        execution=_execution_state(session, row),
        tasks=tasks,
    )


def _execution_state(session: Session, row: ScanRow) -> ExecutionState:
    settings = get_settings()
    base = execution_status(settings)

    limits_note = ""
    scope_row = session.get(ScopeVersionRow, row.scope_version_id)
    if scope_row is not None:
        remaining = budget_service.remaining(row, budget_limits_for(scope_row, settings))
        limits_note = f" Budget remaining: {remaining.requests} requests."

    return ExecutionState(
        execution=str(base["execution"]),
        execution_enabled=bool(base["execution_enabled"]),
        dispatch_implemented=bool(base["dispatch_implemented"]),
        responsible_milestone=str(base["responsible_milestone"]),
        detail=str(base["detail"]) + limits_note,
    )


def _revalidate_scope(row: ScopeVersionRow, settings: Settings) -> None:
    """Re-check a scope's authorization before admitting a scan.

    M1's broker repeats this per request and per redirect. This is the admission check —
    it stops a scan that could never make progress from being dispatched at all.
    """
    record = scope_row_to_domain(row)

    if record.is_expired():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"authorization for {record.origin} expired at "
                f"{record.authorization_expires_at.isoformat()}; renew the scope before scanning"
            ),
        )

    if record.authority_domain is not AuthorityDomain.LAB:
        return

    allowlist = get_lab_allowlist(settings)
    if record.lab_binding is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="lab scope has no binding; it cannot be admitted",
        )
    try:
        allowlist.validate_binding(LabBinding.model_validate(record.lab_binding.model_dump()))
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"lab binding is no longer approved: {exc}",
        ) from exc


@router.get("", response_model=list[ScanView])
def list_all_scans(operator: CurrentOperator, session: DbSession) -> list[ScanView]:
    return [_to_view(row, session) for row in list_scans(session, operator_id=operator.id)]


@router.get("/{scan_id}", response_model=ScanView)
def get_one(scan_id: uuid.UUID, operator: CurrentOperator, session: DbSession) -> ScanView:
    row = get_scan(session, scan_id)
    if row is None or row.operator_id != operator.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")
    return _to_view(row, session, include_tasks=True)


@router.post("", response_model=ScanView, status_code=status.HTTP_202_ACCEPTED)
def create(
    payload: ScanCreateRequest,
    operator: CurrentOperator,
    session: DbSession,
    settings: AppSettings,
) -> ScanView:
    """Create a scan, its first task and its dispatch event — in one transaction.

    The three rows commit together, so there is no state in which a scan exists with
    nothing to dispatch it, or a dispatch exists for a scan that does not.
    """
    try:
        scope_version_id = uuid.UUID(payload.scope_version_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="scope_version_id is not a UUID",
        ) from exc

    scope_row = get_scope_version(session, scope_version_id)
    if scope_row is None or scope_row.operator_id != operator.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scope not found")

    _revalidate_scope(scope_row, settings)

    if not settings.scanner_execution_enabled:
        # Refuse rather than queue work nothing will ever pick up. A scan that silently
        # never runs is worse than an error that says why.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "scanner execution is disabled (SCOPELENS_SCANNER_EXECUTION_ENABLED=false); "
                "refusing to create a scan that nothing would dispatch"
            ),
        )

    configuration = None
    if payload.assessment_configuration_id:
        from scopelens.api.assessments import validate_configuration
        from scopelens.domain.expansion import AssessmentConfiguration
        from scopelens.persistence.models import AssessmentConfigurationRow

        try:
            configuration_id = uuid.UUID(payload.assessment_configuration_id)
        except ValueError as exc:
            raise HTTPException(422, "invalid assessment configuration ID") from exc
        configuration = session.get(AssessmentConfigurationRow, configuration_id)
        if (
            configuration is None
            or configuration.operator_id != operator.id
            or configuration.scope_version_id != scope_row.id
        ):
            raise HTTPException(404, "assessment configuration not found for this scope")
        validate_configuration(
            AssessmentConfiguration.model_validate(configuration.configuration),
            scope_row,
            session,
            operator,
            settings,
        )
    if ProfileName(scope_row.allowed_check_profile).expanded and configuration is None:
        raise HTTPException(422, "expanded profile requires an assessment configuration")

    scan, _task = create_scan_with_task(
        session,
        operator_id=operator.id,
        scope_version=scope_row,
        score_version=settings.score_version,
        actor=operator.username,
    )
    from scopelens.checks.conditional import approvals

    scan.assessment_plan = {
        **(scan.assessment_plan or {}),
        "adaptive_requested": payload.adaptive,
        "conditional_probes": approvals(settings, scope_row_to_domain(scope_row)),
    }
    if configuration is not None:
        scan.assessment_plan = {
            **scan.assessment_plan,
            "expansion_config": configuration.configuration,
            "configuration_id": str(configuration.id),
            "configuration_hash": configuration.content_hash,
        }
    session.commit()
    return _to_view(scan, session, include_tasks=True)


@router.post("/{scan_id}/cancel", response_model=ScanView)
def cancel(
    scan_id: uuid.UUID, operator: CurrentOperator, session: DbSession, settings: AppSettings
) -> ScanView:
    """Cancel a scan.

    Two mechanisms, because the two deadlines differ by an order of magnitude:

    * **Revoke egress now.** Bumping the cancel epoch invalidates the scan's token, so
      the broker refuses every subsequent request immediately — this is the 5-second
      target, and it needs no cooperation from the worker.
    * **Ask the supervisor to stop the process group.** Queued through the outbox to the
      Celery worker that holds the Docker socket — this is the 30-second target.

    The scan is marked cancelled here rather than waiting for either, so a failure in
    the second mechanism cannot leave a scan that keeps running.
    """
    scan = session.scalar(select(ScanRow).where(ScanRow.id == scan_id).with_for_update())
    if scan is None or scan.operator_id != operator.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")

    current = ScanStatus(scan.status)
    if current.is_terminal:
        # Idempotent: cancelling a finished scan reports its real state rather than
        # pretending the cancellation took effect.
        return _to_view(scan, session, include_tasks=True)

    never_dispatched = current is ScanStatus.QUEUED and not may_need_worker_cleanup(session, scan)
    if scan.cancel_requested_at is None or never_dispatched:
        # Legacy intents can already have a cancellation timestamp/epoch but no task
        # capable of finishing the transition. Settle them in this transaction.
        if scan.cancel_requested_at is None:
            scan.cancel_requested_at = datetime.now(UTC)
        scan.status = str(ScanStatus.CANCELLED)
        scan.status_reason = (
            "cancelled before dispatch" if never_dispatched else "cancelled by the operator"
        )
        scan.finished_at = datetime.now(UTC)

    epoch = revoke_egress(session, scan=scan)
    if not never_dispatched:
        enqueue_cancel(session, scan=scan, cancel_epoch=epoch, actor=operator.username)

    record_audit(
        session,
        actor=operator.username,
        action="scan.cancel",
        subject_type="scan",
        subject_id=str(scan.id),
        outcome="cancelled",
        detail={
            "cancel_epoch": epoch,
            "previous_status": current.value,
            "reason": scan.status_reason,
        },
    )
    session.commit()
    return _to_view(scan, session, include_tasks=True)


@router.get("/{scan_id}/evidence", response_model=list[EvidenceView])
def list_evidence(
    scan_id: uuid.UUID, operator: CurrentOperator, session: DbSession
) -> list[EvidenceView]:
    """Evidence captured for a scan.

    Only metadata and the hash are returned. The artifact itself stays behind the
    evidence store so that a read is an explicit act rather than a side effect of
    listing.
    """
    from scopelens.evidence.intake import evidence_for_scan

    scan = get_scan(session, scan_id)
    if scan is None or scan.operator_id != operator.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found")

    return [_evidence_view(record) for record in evidence_for_scan(session, scan.id)]


def _evidence_view(record: EvidenceRecord) -> EvidenceView:
    return EvidenceView(
        id=record.id,
        origin=record.origin,
        producer=record.producer,
        producer_hash=record.producer_hash,
        run_id=record.run_id,
        tool_version=record.tool_version,
        trusted=record.is_trusted,
        captured_at=record.captured_at,
        content_hash=record.content_hash,
        content_bytes=record.content_bytes,
        truncated=record.truncated,
        redaction_state=record.redaction_state,
        content_type=record.content_type,
        summary=record.summary,
    )
