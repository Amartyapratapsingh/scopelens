"""m2 findings scores surface outcomes

Revision ID: 83445d83cd7d
Revises: 0002
Create Date: 2026-09-24 21:37:11.314211+00:00

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0003"
down_revision: str | Sequence[str] | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "check_outcomes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("check_id", sa.String(length=64), nullable=False),
        sa.Column("canonical_control", sa.String(length=128), nullable=False),
        sa.Column("category", sa.String(length=8), nullable=False),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("na_reason", sa.Text(), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "check_id", name="uq_outcomes_scan_check"),
    )
    op.create_index(
        "ix_outcomes_scan_category", "check_outcomes", ["scan_id", "category"], unique=False
    )
    op.create_table(
        "crawl_surfaces",
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("origin", sa.String(length=255), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("scan_id"),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("check_id", sa.String(length=64), nullable=False),
        sa.Column("canonical_control", sa.String(length=128), nullable=False),
        sa.Column("root_cause", sa.String(length=128), nullable=False),
        sa.Column("dedup_key", sa.String(length=256), nullable=False),
        sa.Column("category", sa.String(length=8), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("evidence_status", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column("confidence_reasons", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "locations",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
        sa.Column(
            "evidence_refs",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("retest_state", sa.String(length=32), nullable=True),
        sa.Column("retest_scan_id", sa.Uuid(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "dedup_key", name="uq_findings_scan_dedup"),
    )
    op.create_index("ix_findings_scan_severity", "findings", ["scan_id", "severity"], unique=False)
    op.create_table(
        "score_snapshots",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("score_version", sa.String(length=32), nullable=False),
        sa.Column("profile", sa.String(length=64), nullable=False),
        sa.Column("verdict", sa.String(length=64), nullable=False),
        sa.Column("overall_score", sa.Integer(), nullable=True),
        sa.Column("coverage_percent", sa.Float(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_score_snapshots_scan_id"), "score_snapshots", ["scan_id"], unique=False
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_score_snapshots_scan_id"), table_name="score_snapshots")
    op.drop_table("score_snapshots")
    op.drop_index("ix_findings_scan_severity", table_name="findings")
    op.drop_table("findings")
    op.drop_table("crawl_surfaces")
    op.drop_index("ix_outcomes_scan_category", table_name="check_outcomes")
    op.drop_table("check_outcomes")
