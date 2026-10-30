"""Durable browser context ownership and action ledger."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "browser_sessions",
        sa.Column("scan_id", sa.Uuid(), sa.ForeignKey("scans.id"), primary_key=True),
        sa.Column("owner", sa.String(128), nullable=False),
        sa.Column("context_id", sa.String(36), nullable=False),
        sa.Column("scope_revision", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("cancel_epoch", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("inflight", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("actions", JSONB(), nullable=False, server_default="[]"),
    )


def downgrade():
    op.drop_table("browser_sessions")
