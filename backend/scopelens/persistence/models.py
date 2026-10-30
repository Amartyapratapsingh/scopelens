"""SQLAlchemy models (Build Plan §5.1, §5.2; Project Specification §6, §12).

M0 persists four records: the operator account, immutable scope versions, the scan
intent, and the audit trail. The Task ledger, outbox and leases are M1 and are not
declared here — declaring a table that nothing writes would overstate what exists.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    event,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from scopelens.persistence.base import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class OperatorRow(Base):
    """The single seeded operator account (Build Plan §5.1). There is no signup."""

    __tablename__ = "operators"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    disabled: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    scope_versions: Mapped[list[ScopeVersionRow]] = relationship(back_populates="operator")
    scans: Mapped[list[ScanRow]] = relationship(back_populates="operator")


class ScopeVersionRow(Base):
    """An immutable, versioned authorization record (Build Plan §5.1).

    Append-only. Changing a scope means creating the next version; an existing version
    is never updated, so a scan's authorization cannot drift underneath it.
    """

    __tablename__ = "scope_versions"
    __table_args__ = (
        UniqueConstraint("scope_key", "version", name="uq_scope_versions_key_version"),
        Index("ix_scope_versions_operator", "operator_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    operator_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("operators.id", ondelete="RESTRICT"), nullable=False
    )

    # Logical identity of the scope (its normalized origin); versions hang off it.
    scope_key: Mapped[str] = mapped_column(String(255), index=True)
    version: Mapped[int] = mapped_column(nullable=False)

    authority_domain: Mapped[str] = mapped_column(String(16), nullable=False)
    scheme: Mapped[str] = mapped_column(String(8), nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(nullable=False)
    transport_http_port: Mapped[int | None] = mapped_column(nullable=True)

    allowed_path_prefixes: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    excluded_paths: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    allowed_methods: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    allowed_check_profile: Mapped[str] = mapped_column(String(64), nullable=False)
    authorization_expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    owner_note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    budgets_override: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    # Present only for lab authority; carries service/address/port/environment.
    lab_binding: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    operator: Mapped[OperatorRow] = relationship(back_populates="scope_versions")
    scans: Mapped[list[ScanRow]] = relationship(back_populates="scope_version")


class ScanRow(Base):
    """A durable scan intent / run (Project Specification §6).

    In M0 every row stays ``queued``. Nothing dispatches it; see ``scopelens.execution``.
    """

    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_operator_created", "operator_id", "created_at"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    operator_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("operators.id", ondelete="RESTRICT"), nullable=False
    )
    scope_version_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("scope_versions.id", ondelete="RESTRICT"), nullable=False
    )

    target_origin: Mapped[str] = mapped_column(String(255), nullable=False)
    profile: Mapped[str] = mapped_column(String(64), nullable=False)
    score_version: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    status_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    progress_percent: Mapped[int] = mapped_column(default=0, nullable=False)
    findings_count: Mapped[int] = mapped_column(default=0, nullable=False)
    assessment_plan: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    transport_probe_used: Mapped[bool] = mapped_column(default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # --- Cancellation (Build Plan §5.6) ----------------------------------------
    # The epoch is the durable cancellation signal. Bumping it is what revokes egress:
    # the broker rejects any request whose scan has a higher epoch than the one its
    # admission was issued under. Monotonic, so a restart cannot resurrect old authority.
    cancel_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    cancel_requested_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    cancelled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # --- Budget accounting (Build Plan §5.2, §5.3) ------------------------------
    # Held separately for spent and reserved so a crash between "reserve" and "execute"
    # is visible rather than silently forgiven. Reconciliation moves reserved -> spent.
    budget_spent: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    budget_reserved: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    # Set when the reconciler has examined this scan after a restart, so recovery is
    # itself auditable rather than an invisible startup side effect.
    reconciled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # --- Egress capability (Build Plan §5.3, §5.6) ------------------------------
    # The scan's only means of reaching the policy broker. Stored as a hash, and tagged
    # with the cancel epoch it was issued under. Cancelling bumps `cancel_epoch`, which
    # makes every token issued under an older epoch invalid on its next use — that is
    # what "the proxy drops the scan's tokens" means mechanically, and why revocation
    # needs no cooperation from the worker.
    egress_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    egress_token_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    # Addresses the scope host resolved to when this scan first reached the broker.
    # Every later request must resolve to the same set, so a name that re-points after
    # admission is denied rather than followed (§5.3, "re-resolve + pin").
    pinned_addresses: Mapped[list[str] | None] = mapped_column(JSONB, nullable=True)

    operator: Mapped[OperatorRow] = relationship(back_populates="scans")
    scope_version: Mapped[ScopeVersionRow] = relationship(back_populates="scans")


class AuditEventRow(Base):
    """Append-only audit trail (Build Plan §6.3, Feature F-22).

    ``seq`` is a monotonic cursor so a consumer can resume without gaps. Durable by
    design: the trail must survive a worker crash, which is why it is a table rather
    than a log line.
    """

    __tablename__ = "audit_events"
    __table_args__ = (Index("ix_audit_events_subject", "subject_type", "subject_id"),)

    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    actor: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    subject_type: Mapped[str] = mapped_column(String(32), nullable=False)
    subject_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)


@event.listens_for(ScopeVersionRow, "before_update")
def _forbid_scope_version_update(mapper: Any, connection: Any, target: ScopeVersionRow) -> None:
    """Scope versions are append-only.

    Enforced at the ORM boundary in addition to the repository layer so that no future
    code path can quietly rewrite an authorization record a scan already relied on.
    """
    raise ValueError(
        f"scope version {target.id} is immutable; create a new version instead of updating it"
    )


# --- M1: durable task ledger, dispatch, leases and evidence ------------------------


class TaskRow(Base):
    """One logical unit of work (Build Plan §5.2).

    ``logical_id`` survives retries; ``attempt_id`` changes per dispatch. The pair plus
    ``scan_id`` is the idempotency key, enforced by a unique constraint so that
    at-least-once Celery delivery cannot create a second logical task by racing.
    """

    __tablename__ = "tasks"
    __table_args__ = (
        UniqueConstraint("scan_id", "logical_id", "attempt_id", name="uq_tasks_attempt"),
        Index("ix_tasks_scan_state", "scan_id", "state"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("scans.id", ondelete="RESTRICT"), nullable=False
    )

    logical_id: Mapped[str] = mapped_column(String(64), nullable=False)
    attempt_id: Mapped[str] = mapped_column(String(64), nullable=False)
    task_type: Mapped[str] = mapped_column(String(32), nullable=False)
    state: Mapped[str] = mapped_column(String(24), nullable=False, index=True)

    # Fencing counter. An executor presenting a lower token than the row's has lost its
    # lease and must refuse to act.
    lease_token: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    reserved_budget: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    spent_budget: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    outcome_reason: Mapped[str | None] = mapped_column(Text, nullable=True)


class OutboxEventRow(Base):
    """Transactional outbox (Build Plan §5.2).

    Written in the same transaction as the `Scan` and its first `Task`, so "the scan was
    created" and "the scan will be dispatched" cannot disagree. The dispatcher polls
    this table; unsent rows are reconciled on startup.
    """

    __tablename__ = "outbox_events"
    __table_args__ = (Index("ix_outbox_unsent", "dispatched_at", "created_at"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    topic: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempts: Mapped[int] = mapped_column(nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class CoordinatorLeaseRow(Base):
    """One renewable lease per scan (Build Plan §5.2).

    A single row per scan, which is what makes "one coordinator per scan" a database
    fact rather than a scheduling hope. Losing the lease revokes the old run's egress
    before a replacement is admitted (§5.3, §5.6).
    """

    __tablename__ = "coordinator_leases"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    holder: Mapped[str] = mapped_column(String(128), nullable=False)
    fencing_token: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1)
    acquired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class EvidenceRow(Base):
    """Trusted evidence (Build Plan §5.5).

    ``origin`` records who wrote this and therefore whether a proof rule may use it.
    Content lives in the evidence store; this row carries the reference and the hash.
    """

    __tablename__ = "evidence"
    __table_args__ = (
        Index("ix_evidence_scan", "scan_id", "captured_at"),
        Index("ix_evidence_task", "task_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("scans.id", ondelete="RESTRICT"), nullable=False
    )
    task_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("tasks.id", ondelete="SET NULL"), nullable=True
    )
    run_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    origin: Mapped[str] = mapped_column(String(32), nullable=False)
    producer: Mapped[str] = mapped_column(String(64), nullable=False)
    producer_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tool_version: Mapped[str | None] = mapped_column(String(256), nullable=True)

    scope_version_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("scope_versions.id", ondelete="RESTRICT"), nullable=False
    )
    scope_content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="unauthenticated")

    captured_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    content_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    content_ref: Mapped[str] = mapped_column(Text, nullable=False)
    truncated: Mapped[bool] = mapped_column(nullable=False, default=False)
    redaction_state: Mapped[str] = mapped_column(String(16), nullable=False)

    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")


# --- M2: findings, scores and crawl surface ---------------------------------------


class FindingRow(Base):
    """One deduplicated finding (Spec §9.8).

    ``dedup_key`` is unique per scan, which is what makes deduplication a database guarantee
    rather than a convention the analysis step has to remember. ``locations`` and
    ``evidence_refs`` are arrays because merging must retain every location, never replace it.
    """

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("scan_id", "dedup_key", name="uq_findings_scan_dedup"),
        Index("ix_findings_scan_severity", "scan_id", "severity"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )

    check_id: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_control: Mapped[str] = mapped_column(String(128), nullable=False)
    root_cause: Mapped[str] = mapped_column(String(128), nullable=False)
    dedup_key: Mapped[str] = mapped_column(String(256), nullable=False)
    category: Mapped[str] = mapped_column(String(8), nullable=False)

    title: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    evidence_status: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence_reasons: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)

    locations: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    evidence_refs: Mapped[list[str]] = mapped_column(JSONB, nullable=False, default=list)
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")

    #: open | resolved | previously_confirmed. Spec §9.8: a blocked retest cannot close a
    #: finding, so only a conclusive retest moves this.
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="open")
    retest_state: Mapped[str | None] = mapped_column(String(32), nullable=True)
    retest_scan_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class ScoreSnapshotRow(Base):
    """A versioned scoring result (Spec §9.10).

    Stored rather than recomputed on read: a retest must not silently change what an earlier
    scan reported, and Spec §9.10 requires a historical published score to be preserved even
    when a rule update would change it.
    """

    __tablename__ = "score_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    score_version: Mapped[str] = mapped_column(String(32), nullable=False)
    profile: Mapped[str] = mapped_column(String(64), nullable=False)
    verdict: Mapped[str] = mapped_column(String(64), nullable=False)
    overall_score: Mapped[int | None] = mapped_column(nullable=True)
    coverage_percent: Mapped[float] = mapped_column(nullable=False, default=0.0)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class CrawlSurfaceRow(Base):
    """The attack-surface map for a scan (Build Plan §5.7).

    One row per scan holding the whole map. Kept as a document because nothing queries
    *inside* it — the dashboard renders it whole, and the host inventory is a projection.
    """

    __tablename__ = "crawl_surfaces"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("scans.id", ondelete="CASCADE"), primary_key=True
    )
    origin: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


class CheckOutcomeRow(Base):
    """Every control outcome, including the inconclusive and blocked ones (Spec §9.7).

    Stored for all outcomes rather than only findings: coverage is computed from these, and a
    blocked control has to stay visible as unassessed rather than vanish from the denominator.
    """

    __tablename__ = "check_outcomes"
    __table_args__ = (
        UniqueConstraint("scan_id", "check_id", name="uq_outcomes_scan_check"),
        Index("ix_outcomes_scan_category", "scan_id", "category"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    check_id: Mapped[str] = mapped_column(String(64), nullable=False)
    canonical_control: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(8), nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    na_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)


class BrowserSessionRow(Base):
    """One context owner per scan; durable action ordering and audit metadata."""

    __tablename__ = "browser_sessions"
    scan_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("scans.id"), primary_key=True)
    owner: Mapped[str] = mapped_column(String(128), nullable=False)
    context_id: Mapped[str] = mapped_column(String(36), nullable=False)
    scope_revision: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    sequence: Mapped[int] = mapped_column(default=0, nullable=False)
    cancel_epoch: Mapped[int] = mapped_column(default=0, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    inflight: Mapped[bool] = mapped_column(default=False, nullable=False)
    actions: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)


class AssessmentConfigurationRow(Base):
    """Immutable expansion inputs; a scan snapshots one owner/scope-bound version."""

    __tablename__ = "assessment_configurations"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    operator_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("operators.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    scope_version_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("scope_versions.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    configuration: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )


@event.listens_for(AssessmentConfigurationRow, "before_update")
def _forbid_assessment_config_update(mapper, connection, target):
    raise ValueError("Assessment configurations are immutable; create a new version")


class CleanupRow(Base):
    __tablename__ = "cleanup_ledger"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    scope_version_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scope_versions.id"), nullable=False
    )
    resource_id: Mapped[str] = mapped_column(String(256), nullable=False)
    recipe_id: Mapped[str] = mapped_column(String(128), nullable=False)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    __table_args__ = (
        UniqueConstraint("scope_version_id", "resource_id", name="uq_cleanup_resource"),
    )
