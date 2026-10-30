"""Immutable scope-bound expansion configuration snapshots."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "assessment_configurations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "operator_id",
            sa.Uuid(),
            sa.ForeignKey("operators.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "scope_version_id",
            sa.Uuid(),
            sa.ForeignKey("scope_versions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("configuration", postgresql.JSONB(), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "ix_assessment_configurations_operator_id", "assessment_configurations", ["operator_id"]
    )
    op.create_index(
        "ix_assessment_configurations_scope_version_id",
        "assessment_configurations",
        ["scope_version_id"],
    )


def downgrade():
    op.drop_table("assessment_configurations")
