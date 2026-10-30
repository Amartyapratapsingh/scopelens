"""Operator-owned recovery requests; execution stays off until its runtime is wired."""

import uuid
from datetime import datetime

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select

from scopelens.api.assessments import owned_scope, validate_configuration
from scopelens.api.deps import AppSettings, CurrentOperator, DbSession
from scopelens.domain.expansion import AssessmentConfiguration
from scopelens.expansion.recovery import RecoveryRefused, queue_recovery
from scopelens.persistence.models import (
    AssessmentConfigurationRow,
    CleanupRow,
    ScanRow,
    ScopeVersionRow,
)

router = APIRouter(prefix="/api/cleanup-recoveries", tags=["cleanup recovery"])


class RecoveryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cleanup_id: uuid.UUID
    scope_version_id: uuid.UUID
    assessment_configuration_id: uuid.UUID


class CleanupView(BaseModel):
    id: uuid.UUID
    scope_version_id: uuid.UUID
    scan_id: uuid.UUID
    recipe_id: str
    resource_id: str
    state: str
    updated_at: datetime


class RecoveryResult(BaseModel):
    verified: bool
    reason: str
    evidence_ref: str | None = None
    verified_at: datetime | None = None


class RecoveryView(BaseModel):
    id: uuid.UUID
    cleanup_id: uuid.UUID
    scope_version_id: uuid.UUID
    status: str
    result: RecoveryResult | None = None


def _view(scan):
    frozen = scan.assessment_plan or {}
    return RecoveryView(
        id=scan.id,
        cleanup_id=frozen["cleanup_recovery"]["cleanup_id"],
        scope_version_id=scan.scope_version_id,
        status=scan.status,
        result=frozen.get("cleanup_recovery_result"),
    )


@router.get("/pending", response_model=list[CleanupView])
def pending(operator: CurrentOperator, session: DbSession):
    rows = session.scalars(
        select(CleanupRow)
        .join(ScopeVersionRow, CleanupRow.scope_version_id == ScopeVersionRow.id)
        .where(ScopeVersionRow.operator_id == operator.id, CleanupRow.state != "clean")
        .order_by(CleanupRow.updated_at)
    )
    return [
        CleanupView(**{key: getattr(row, key) for key in CleanupView.model_fields}) for row in rows
    ]


@router.post("", response_model=RecoveryView, status_code=202)
def create(
    payload: RecoveryRequest,
    request: Request,
    operator: CurrentOperator,
    session: DbSession,
    settings: AppSettings,
):
    # The application enables this only alongside dedicated dispatch/worker/intake/
    # finalization hooks. A recovery must never fall through to a generic scan.
    if not getattr(request.app.state, "cleanup_recovery_runtime_enabled", False):
        raise HTTPException(503, "cleanup recovery runtime is not enabled")
    if not settings.scanner_execution_enabled:
        raise HTTPException(503, "scanner execution is disabled")
    cleanup = session.get(CleanupRow, payload.cleanup_id)
    original_scope = session.get(ScopeVersionRow, cleanup.scope_version_id) if cleanup else None
    if original_scope is None or original_scope.operator_id != operator.id:
        raise HTTPException(404, "cleanup record not found")
    original_scan = session.get(ScanRow, cleanup.scan_id)
    fresh_scope, revalidate = owned_scope(session, payload.scope_version_id, operator)
    revalidate(fresh_scope, settings)
    row = session.get(AssessmentConfigurationRow, payload.assessment_configuration_id)
    if row is None or row.operator_id != operator.id or row.scope_version_id != fresh_scope.id:
        raise HTTPException(404, "assessment configuration not found for this scope")
    config = AssessmentConfiguration.model_validate(row.configuration)
    validate_configuration(config, fresh_scope, session, operator, settings)
    try:
        scan, _, _ = queue_recovery(
            session,
            cleanup,
            original_scan,
            original_scope,
            fresh_scope,
            config,
            actor=operator.username,
            score_version=settings.score_version,
        )
    except RecoveryRefused as exc:
        raise HTTPException(409, str(exc)) from None
    session.commit()
    return _view(scan)


@router.get("/{recovery_id}", response_model=RecoveryView)
def get(recovery_id: uuid.UUID, operator: CurrentOperator, session: DbSession):
    scan = session.get(ScanRow, recovery_id)
    if (
        scan is None
        or scan.operator_id != operator.id
        or not (scan.assessment_plan or {}).get("cleanup_recovery")
    ):
        raise HTTPException(404, "cleanup recovery not found")
    return _view(scan)
