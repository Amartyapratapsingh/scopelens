"""m1: task ledger, outbox, coordinator leases, evidence, scan budget and cancellation

Adds the durable execution records from Build Plan §5.2, §5.5 and §5.6.

Notes on intent, since these are easy to lose in a later edit:

* ``tasks`` is unique on ``(scan_id, logical_id, attempt_id)``. That constraint is the
  idempotency key from §5.2 — it is what makes at-least-once Celery delivery safe, so it
  is a database guarantee rather than a check the dispatcher remembers to perform.
* ``coordinator_leases`` is keyed by ``scan_id``, so "one coordinator per scan" is a
  primary-key fact rather than a scheduling convention.
* ``scans.cancel_epoch`` is monotonic. Bumping it revokes egress; nothing may lower it.
* ``budget_spent`` and ``budget_reserved`` are separate columns on purpose. A crash
  between reserving and executing leaves the reservation visible, so an interrupted
  scan cannot quietly refill its own budget.

The three NOT NULL columns added to the existing ``scans`` table carry server defaults
so this migration is safe to apply to a database that already contains scans.

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-24
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: str | Sequence[str] | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_JSONB = postgresql.JSONB(astext_type=sa.Text())


def upgrade() -> None:
    op.create_table(
        "outbox_events",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("topic", sa.String(length=64), nullable=False),
        sa.Column("payload", _JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_outbox_unsent", "outbox_events", ["dispatched_at", "created_at"], unique=False
    )

    op.create_table(
        "coordinator_leases",
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("holder", sa.String(length=128), nullable=False),
        sa.Column("fencing_token", sa.BigInteger(), nullable=False, server_default="1"),
        sa.Column("acquired_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("scan_id"),
    )

    op.create_table(
        "tasks",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("logical_id", sa.String(length=64), nullable=False),
        sa.Column("attempt_id", sa.String(length=64), nullable=False),
        sa.Column("task_type", sa.String(length=32), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("lease_token", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("reserved_budget", _JSONB, nullable=False, server_default="{}"),
        sa.Column("spent_budget", _JSONB, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("outcome_reason", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "logical_id", "attempt_id", name="uq_tasks_attempt"),
    )
    op.create_index("ix_tasks_scan_state", "tasks", ["scan_id", "state"], unique=False)
    op.create_index(op.f("ix_tasks_state"), "tasks", ["state"], unique=False)

    op.create_table(
        "evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("task_id", sa.Uuid(), nullable=True),
        sa.Column("run_id", sa.String(length=64), nullable=True),
        sa.Column("origin", sa.String(length=32), nullable=False),
        sa.Column("producer", sa.String(length=64), nullable=False),
        sa.Column("producer_hash", sa.String(length=64), nullable=True),
        sa.Column("tool_version", sa.String(length=64), nullable=True),
        sa.Column("scope_version_id", sa.Uuid(), nullable=False),
        sa.Column("scope_content_hash", sa.String(length=64), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("captured_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("content_bytes", sa.BigInteger(), nullable=False),
        sa.Column("content_ref", sa.Text(), nullable=False),
        sa.Column("truncated", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("redaction_state", sa.String(length=16), nullable=False),
        sa.Column("content_type", sa.String(length=128), nullable=True),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["scope_version_id"], ["scope_versions.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["task_id"], ["tasks.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_evidence_scan", "evidence", ["scan_id", "captured_at"], unique=False)
    op.create_index("ix_evidence_task", "evidence", ["task_id"], unique=False)

    op.add_column(
        "scans",
        sa.Column("cancel_epoch", sa.BigInteger(), nullable=False, server_default="0"),
    )
    op.add_column(
        "scans", sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("scans", sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("budget_spent", _JSONB, nullable=False, server_default="{}"))
    op.add_column(
        "scans", sa.Column("budget_reserved", _JSONB, nullable=False, server_default="{}")
    )
    op.add_column("scans", sa.Column("reconciled_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("scans", sa.Column("egress_token_hash", sa.String(length=64), nullable=True))
    op.create_index("ix_scans_egress_token_hash", "scans", ["egress_token_hash"], unique=False)
    op.add_column(
        "scans",
        sa.Column("egress_token_epoch", sa.BigInteger(), nullable=False, server_default="0"),
    )
    op.add_column("scans", sa.Column("pinned_addresses", _JSONB, nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "pinned_addresses")
    op.drop_column("scans", "egress_token_epoch")
    op.drop_index("ix_scans_egress_token_hash", table_name="scans")
    op.drop_column("scans", "egress_token_hash")
    op.drop_column("scans", "reconciled_at")
    op.drop_column("scans", "budget_reserved")
    op.drop_column("scans", "budget_spent")
    op.drop_column("scans", "cancelled_at")
    op.drop_column("scans", "cancel_requested_at")
    op.drop_column("scans", "cancel_epoch")

    op.drop_index("ix_evidence_task", table_name="evidence")
    op.drop_index("ix_evidence_scan", table_name="evidence")
    op.drop_table("evidence")

    op.drop_index(op.f("ix_tasks_state"), table_name="tasks")
    op.drop_index("ix_tasks_scan_state", table_name="tasks")
    op.drop_table("tasks")

    op.drop_table("coordinator_leases")

    op.drop_index("ix_outbox_unsent", table_name="outbox_events")
    op.drop_table("outbox_events")
