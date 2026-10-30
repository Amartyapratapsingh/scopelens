"""Durable cleanup and signed callback receipt ledgers."""

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "cleanup_ledger",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "scope_version_id", sa.Uuid(), sa.ForeignKey("scope_versions.id"), nullable=False
        ),
        sa.Column("resource_id", sa.String(256), nullable=False),
        sa.Column("recipe_id", sa.String(128), nullable=False),
        sa.Column("scan_id", sa.Uuid(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("state", sa.String(32), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("scope_version_id", "resource_id", name="uq_cleanup_resource"),
    )
    op.create_table(
        "callback_nonces",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("token_hash", sa.String(64), unique=True, nullable=False),
        sa.Column("owner_id", sa.String(128), nullable=False, index=True),
        sa.Column("scan_id", sa.String(128), nullable=False, index=True),
        sa.Column("task_id", sa.String(128), nullable=False),
        sa.Column("family", sa.String(16), nullable=False),
        sa.Column("purpose", sa.String(16), nullable=False),
        sa.Column("expected_peers", sa.Text(), nullable=False),
        sa.Column("scanner_peers", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.Column("expires_at", sa.Float(), nullable=False, index=True),
        sa.Column("revoked", sa.Boolean(), nullable=False),
        sa.Column("receipts", sa.Integer(), nullable=False),
    )
    op.create_table(
        "callback_receipts",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("nonce_id", sa.String(64), nullable=False, index=True),
        sa.Column("data", sa.Text(), nullable=False),
    )


def downgrade():
    op.drop_table("callback_receipts")
    op.drop_table("callback_nonces")
    op.drop_table("cleanup_ledger")
