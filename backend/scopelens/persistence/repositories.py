"""Repository layer: row <-> domain mapping and the writes M0 needs.

Scope versions are insert-only. There is no ``update_scope_version`` and the ORM
rejects an UPDATE outright, so a scan's authorization cannot be rewritten after the
fact (Build Plan §5.1).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session

from scopelens.config import Budgets
from scopelens.domain.enums import AuthorityDomain, ProfileName, ScanStatus
from scopelens.domain.lab import LabBinding
from scopelens.domain.scan import ScanRecord
from scopelens.domain.scope import LabScopeCreate, ProductionScopeCreate, ScopeVersion
from scopelens.persistence.models import AuditEventRow, OperatorRow, ScanRow, ScopeVersionRow
from scopelens.security.redaction import redact


def utcnow() -> datetime:
    return datetime.now(UTC)


# --- Operator --------------------------------------------------------------------


def get_operator_by_username(session: Session, username: str) -> OperatorRow | None:
    return session.scalar(select(OperatorRow).where(OperatorRow.username == username))


def get_operator(session: Session, operator_id: uuid.UUID) -> OperatorRow | None:
    return session.get(OperatorRow, operator_id)


def upsert_operator(
    session: Session, *, username: str, password_hash: str
) -> tuple[OperatorRow, bool]:
    """Create the operator, or refresh the hash of an existing one.

    Returns ``(row, created)``. Re-seeding an existing account updates the password
    hash so an operator who rotates the credential in ``.env`` is not locked out.
    """
    existing = get_operator_by_username(session, username)
    if existing is not None:
        if existing.password_hash != password_hash:
            existing.password_hash = password_hash
        existing.disabled = False
        return existing, False

    row = OperatorRow(username=username, password_hash=password_hash)
    session.add(row)
    session.flush()
    return row, True


# --- Scope versions --------------------------------------------------------------


def next_scope_version(session: Session, scope_key: str) -> int:
    current = session.scalar(
        select(func.max(ScopeVersionRow.version)).where(ScopeVersionRow.scope_key == scope_key)
    )
    return (current or 0) + 1


def create_scope_version(
    session: Session,
    *,
    operator_id: uuid.UUID,
    payload: ProductionScopeCreate | LabScopeCreate,
    scheme: str,
    host: str,
    port: int,
    lab_binding: LabBinding | None,
) -> ScopeVersionRow:
    """Insert an immutable scope version. The caller resolves host/port first.

    ``content_hash`` is computed *before* the row is added. The immutability listener
    rejects any ORM UPDATE, so setting the hash after the first flush would fail — which
    is the guard doing its job, but it means the hash must be known up front.
    """
    origin = _origin(scheme, host, port)
    version = next_scope_version(session, origin)

    row = ScopeVersionRow(
        id=uuid.uuid4(),
        operator_id=operator_id,
        scope_key=origin,
        version=version,
        authority_domain=str(payload.authority_domain),
        scheme=scheme,
        host=host,
        port=port,
        transport_http_port=payload.transport_http_port,
        allowed_path_prefixes=list(payload.allowed_path_prefixes),
        excluded_paths=list(payload.excluded_paths),
        allowed_methods=list(payload.allowed_methods),
        allowed_check_profile=str(payload.allowed_check_profile),
        authorization_expires_at=payload.authorization_expires_at,
        owner_note=payload.owner_note,
        budgets_override=(
            payload.budgets_override.model_dump() if payload.budgets_override else None
        ),
        lab_binding=lab_binding.model_dump() if lab_binding else None,
        content_hash="",
        created_at=utcnow(),
    )
    row.content_hash = scope_row_to_domain(row).content_hash()

    session.add(row)
    session.flush()
    return row


def _origin(scheme: str, host: str, port: int) -> str:
    from scopelens.domain.scope import default_port

    if port == default_port(scheme):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def get_scope_version(session: Session, scope_version_id: uuid.UUID) -> ScopeVersionRow | None:
    return session.get(ScopeVersionRow, scope_version_id)


def list_scope_versions(session: Session, *, operator_id: uuid.UUID) -> list[ScopeVersionRow]:
    return list(
        session.scalars(
            select(ScopeVersionRow)
            .where(ScopeVersionRow.operator_id == operator_id)
            .order_by(ScopeVersionRow.created_at.desc())
        )
    )


def scope_version_scan_count(session: Session, scope_version_id: uuid.UUID) -> int:
    return (
        session.scalar(
            select(func.count())
            .select_from(ScanRow)
            .where(ScanRow.scope_version_id == scope_version_id)
        )
        or 0
    )


def scope_row_to_domain(row: ScopeVersionRow) -> ScopeVersion:
    binding = LabBinding.model_validate(row.lab_binding) if row.lab_binding else None
    budgets = Budgets.model_validate(row.budgets_override) if row.budgets_override else None
    return ScopeVersion(
        id=str(row.id),
        operator_id=str(row.operator_id),
        version=row.version,
        authority_domain=AuthorityDomain(row.authority_domain),
        scheme=row.scheme,
        host=row.host,
        port=row.port,
        transport_http_port=row.transport_http_port,
        allowed_path_prefixes=tuple(row.allowed_path_prefixes),
        excluded_paths=tuple(row.excluded_paths),
        allowed_methods=tuple(row.allowed_methods),
        allowed_check_profile=ProfileName(row.allowed_check_profile),
        authorization_expires_at=row.authorization_expires_at,
        owner_note=row.owner_note,
        budgets_override=budgets,
        lab_binding=binding,
        created_at=row.created_at,
    )


# --- Scans ------------------------------------------------------------------------


def create_scan_row(
    session: Session,
    *,
    operator_id: uuid.UUID,
    scope_version: ScopeVersionRow,
    score_version: str,
) -> ScanRow:
    """Record a durable scan intent.

    Deliberately writes nothing else. Build Plan §9 M0 requires that a scan cannot
    produce any target action, and there is no outbox table or dispatch call here to
    accidentally do so — those arrive in M1.
    """
    row = ScanRow(
        operator_id=operator_id,
        scope_version_id=scope_version.id,
        target_origin=_origin(scope_version.scheme, scope_version.host, scope_version.port),
        profile=scope_version.allowed_check_profile,
        score_version=score_version,
        status=str(ScanStatus.QUEUED),
        status_reason="queued; awaiting dispatch",
        progress_percent=0,
        findings_count=0,
    )
    session.add(row)
    session.flush()
    return row


def get_scan(session: Session, scan_id: uuid.UUID) -> ScanRow | None:
    return session.get(ScanRow, scan_id)


def list_scans(session: Session, *, operator_id: uuid.UUID, limit: int = 100) -> list[ScanRow]:
    return list(
        session.scalars(
            select(ScanRow)
            .where(ScanRow.operator_id == operator_id)
            .order_by(ScanRow.created_at.desc())
            .limit(limit)
        )
    )


def scan_row_to_domain(row: ScanRow) -> ScanRecord:
    return ScanRecord(
        id=str(row.id),
        operator_id=str(row.operator_id),
        scope_version_id=str(row.scope_version_id),
        target_origin=row.target_origin,
        profile=ProfileName(row.profile),
        score_version=row.score_version,
        status=ScanStatus(row.status),
        status_reason=row.status_reason,
        progress_percent=row.progress_percent,
        findings_count=row.findings_count,
        created_at=row.created_at,
        started_at=row.started_at,
        finished_at=row.finished_at,
    )


# --- Audit ------------------------------------------------------------------------


def record_audit(
    session: Session,
    *,
    actor: str,
    action: str,
    subject_type: str,
    subject_id: str | None = None,
    outcome: str,
    detail: dict[str, Any] | None = None,
) -> AuditEventRow:
    """Append a redacted event; serialize same-scan sequence allocation through commit."""
    scan_id = subject_id if subject_type == "scan" else (detail or {}).get("scan_id")
    if scan_id:
        try:
            scan_uuid = uuid.UUID(str(scan_id))
        except ValueError:
            scan_uuid = None
        if scan_uuid is not None:
            # Held until commit: a later event for this scan cannot become visible first.
            session.execute(select(ScanRow.id).where(ScanRow.id == scan_uuid).with_for_update())
    row = AuditEventRow(
        actor=actor,
        action=action,
        subject_type=subject_type,
        subject_id=subject_id,
        outcome=outcome,
        detail=redact(detail or {}),
        occurred_at=utcnow(),
    )
    session.add(row)
    session.flush()
    return row


def list_audit_events(session: Session, *, limit: int = 200) -> list[AuditEventRow]:
    return list(
        session.scalars(select(AuditEventRow).order_by(AuditEventRow.seq.desc()).limit(limit))
    )


def database_revision(session: Session) -> str | None:
    """Current Alembic revision, or None when the table does not exist yet."""
    try:
        return session.scalar(text("SELECT version_num FROM alembic_version"))
    except ProgrammingError:
        # `alembic_version` is absent on a database that has never been migrated. That
        # is a normal state for a fresh database, not an error worth propagating.
        session.rollback()
        return None
