"""initial schema: operators, scope_versions, scans, audit_events

Creates the M0 durable records (Build Plan §5.1, §5.2, §6.3).

Notes on intent, since these are easy to lose in a later edit:

* ``scope_versions`` has a unique ``(scope_key, version)`` pair and no update path.
  Scope records are append-only; changing a scope creates the next version.
* ``scans`` references ``scope_versions`` with ``ON DELETE RESTRICT``. A scope that a
  scan relied on cannot be deleted out from under its authorization trail.
* ``audit_events.seq`` is a monotonic cursor, so a consumer can resume without gaps.

The Task ledger, outbox and leases are M1 and are deliberately absent.

Revision ID: 0001
Revises:
Create Date: 2026-09-24
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSONB = postgresql.JSONB(astext_type=sa.Text())


def upgrade() -> None:
    op.create_table(
        "operators",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("password_hash", sa.String(length=128), nullable=False),
        sa.Column("disabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_operators_username"), "operators", ["username"], unique=True)

    op.create_table(
        "scope_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("operator_id", sa.Uuid(), nullable=False),
        sa.Column("scope_key", sa.String(length=255), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("authority_domain", sa.String(length=16), nullable=False),
        sa.Column("scheme", sa.String(length=8), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("allowed_path_prefixes", _JSONB, nullable=False),
        sa.Column("excluded_paths", _JSONB, nullable=False),
        sa.Column("allowed_methods", _JSONB, nullable=False),
        sa.Column("allowed_check_profile", sa.String(length=64), nullable=False),
        sa.Column("authorization_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("owner_note", sa.Text(), nullable=False),
        sa.Column("budgets_override", _JSONB, nullable=True),
        sa.Column("lab_binding", _JSONB, nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["operator_id"], ["operators.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scope_key", "version", name="uq_scope_versions_key_version"),
    )
    op.create_index("ix_scope_versions_operator", "scope_versions", ["operator_id"], unique=False)
    op.create_index(
        op.f("ix_scope_versions_scope_key"), "scope_versions", ["scope_key"], unique=False
    )

    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("operator_id", sa.Uuid(), nullable=False),
        sa.Column("scope_version_id", sa.Uuid(), nullable=False),
        sa.Column("target_origin", sa.String(length=255), nullable=False),
        sa.Column("profile", sa.String(length=64), nullable=False),
        sa.Column("score_version", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("status_reason", sa.Text(), nullable=True),
        sa.Column("progress_percent", sa.Integer(), nullable=False),
        sa.Column("findings_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["operator_id"], ["operators.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["scope_version_id"], ["scope_versions.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scans_operator_created", "scans", ["operator_id", "created_at"])
    op.create_index(op.f("ix_scans_status"), "scans", ["status"], unique=False)

    op.create_table(
        "audit_events",
        sa.Column("seq", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("subject_type", sa.String(length=32), nullable=False),
        sa.Column("subject_id", sa.String(length=64), nullable=True),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("detail", _JSONB, nullable=False),
        sa.PrimaryKeyConstraint("seq"),
    )
    op.create_index(op.f("ix_audit_events_action"), "audit_events", ["action"], unique=False)
    op.create_index(
        "ix_audit_events_subject", "audit_events", ["subject_type", "subject_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_audit_events_subject", table_name="audit_events")
    op.drop_index(op.f("ix_audit_events_action"), table_name="audit_events")
    op.drop_table("audit_events")

    op.drop_index(op.f("ix_scans_status"), table_name="scans")
    op.drop_index("ix_scans_operator_created", table_name="scans")
    op.drop_table("scans")

    op.drop_index(op.f("ix_scope_versions_scope_key"), table_name="scope_versions")
    op.drop_index("ix_scope_versions_operator", table_name="scope_versions")
    op.drop_table("scope_versions")

    op.drop_index(op.f("ix_operators_username"), table_name="operators")
    op.drop_table("operators")
