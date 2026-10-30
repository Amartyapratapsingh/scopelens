"""Owner-bound read-only academic planning and proof presentation."""

import uuid

from fastapi import APIRouter, HTTPException, Query
from sqlalchemy import select

from scopelens.academic.evidence import load_captures
from scopelens.academic.models import AcademicPlan, AcademicReadiness
from scopelens.academic.planning import project_plan
from scopelens.academic.readiness import project_readiness, validate_configuration
from scopelens.academic.validation import validate_frozen_plans
from scopelens.api.deps import AppSettings, CurrentOperator, DbSession
from scopelens.evidence.store import LocalDiskEvidenceStore
from scopelens.expansion.cleanup_history import cleanup_states_for_scan
from scopelens.persistence.models import (
    AssessmentConfigurationRow,
    CleanupRow,
    EvidenceRow,
    ScanRow,
    ScopeVersionRow,
)
from scopelens.writer.report import build_report

router = APIRouter(prefix="/api/academic", tags=["academic"])


def _configuration(session, configuration_id, operator):
    row = session.get(AssessmentConfigurationRow, configuration_id)
    if row is None or row.operator_id != operator.id:
        raise HTTPException(404, "assessment configuration not found")
    scope = session.get(ScopeVersionRow, row.scope_version_id)
    if scope is None or scope.operator_id != operator.id:
        raise HTTPException(404, "assessment configuration not found")
    return row, scope


def _conflict():
    return HTTPException(409, "academic assessment snapshot is inconsistent")


@router.get("/configurations/{configuration_id}/readiness", response_model=AcademicReadiness)
def configuration_readiness(
    configuration_id: uuid.UUID, operator: CurrentOperator, session: DbSession
):
    row, scope = _configuration(session, configuration_id, operator)
    try:
        config = validate_configuration(row.configuration, row.content_hash, row.scope_version_id)
        cleanup = session.scalars(
            select(CleanupRow).where(CleanupRow.scope_version_id == scope.id)
        ).all()
        return project_readiness(
            configuration_id=row.id,
            configuration_hash=row.content_hash,
            config=config,
            profile=scope.allowed_check_profile,
            cleanup_rows=[
                {
                    "recipe_id": r.recipe_id,
                    "resource_id": r.resource_id,
                    "scan_id": str(r.scan_id),
                    "state": r.state,
                }
                for r in cleanup
            ],
        )
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, LookupError):
        raise _conflict() from None


@router.get("/configurations/{configuration_id}/plan", response_model=AcademicPlan)
def configuration_plan(
    configuration_id: uuid.UUID,
    operator: CurrentOperator,
    session: DbSession,
    followup_limit: int = Query(default=3, ge=0, le=20),
):
    return project_plan(
        configuration_readiness(configuration_id, operator, session),
        followup_limit=followup_limit,
    )


@router.get("/scans/{scan_id}/plan", response_model=AcademicPlan)
def scan_plan(
    scan_id: uuid.UUID,
    operator: CurrentOperator,
    session: DbSession,
    settings: AppSettings,
    followup_limit: int = Query(default=3, ge=0, le=20),
):
    return project_plan(
        scan_readiness(scan_id, operator, session, settings),
        followup_limit=followup_limit,
    )


@router.get("/scans/{scan_id}/readiness", response_model=AcademicReadiness)
def scan_readiness(
    scan_id: uuid.UUID, operator: CurrentOperator, session: DbSession, settings: AppSettings
):
    scan = session.get(ScanRow, scan_id)
    if scan is None or scan.operator_id != operator.id:
        raise HTTPException(404, "scan not found")
    frozen = scan.assessment_plan or {}
    if not isinstance(frozen, dict):
        raise _conflict()
    if not frozen.get("configuration_id"):
        raise HTTPException(404, "scan assessment configuration not found")
    try:
        configuration_id = uuid.UUID(frozen["configuration_id"])
    except (ValueError, TypeError, AttributeError):
        raise _conflict() from None
    row, scope = _configuration(session, configuration_id, operator)
    if scope.id != scan.scope_version_id or scan.scope_version.operator_id != operator.id:
        raise HTTPException(404, "scan assessment configuration not found")
    try:
        config = validate_configuration(row.configuration, row.content_hash, scan.scope_version_id)
        validate_frozen_plans(scan)
        evidence_rows = session.scalars(
            select(EvidenceRow)
            .where(EvidenceRow.scan_id == scan.id)
            .order_by(EvidenceRow.captured_at, EvidenceRow.id)
        ).all()
        store = LocalDiskEvidenceStore(
            settings.evidence_store_path,
            settings.evidence_encryption_key.get_secret_value()
            if settings.evidence_encryption_key
            else None,
        )
        artifacts = load_captures(
            session, scan, evidence_rows, store, settings.evidence_retention_days
        )
        cleanup = session.scalars(
            select(CleanupRow).where(CleanupRow.scope_version_id == scan.scope_version_id)
        ).all()
        return project_readiness(
            configuration_id=row.id,
            configuration_hash=row.content_hash,
            config=config,
            profile=scan.profile,
            scan_id=scan.id,
            frozen=frozen,
            artifacts=artifacts,
            cleanup_rows=[
                {
                    "recipe_id": r.recipe_id,
                    "resource_id": r.resource_id,
                    "scan_id": str(r.scan_id),
                    "state": r.state,
                }
                for r in cleanup
            ],
            cleanup_states=cleanup_states_for_scan(session, scan),
            report=build_report(session=session, scan=scan),
        )
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError, LookupError):
        raise _conflict() from None
