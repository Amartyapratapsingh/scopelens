"""Private callback closure signatures and trusted broker dispatch commitments."""

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def binding_columns():
    return [
        sa.Column("owner_id", sa.String(128), nullable=False),
        sa.Column("scan_id", sa.String(128), nullable=False, index=True),
        sa.Column("task_id", sa.String(128), nullable=False),
    ]


def upgrade():
    op.create_table(
        "callback_closures",
        sa.Column(
            "nonce_id",
            sa.String(64),
            sa.ForeignKey("callback_nonces.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        *binding_columns(),
        sa.Column("at", sa.Float(), nullable=False),
        sa.Column("signature", sa.String(64), nullable=False),
    )
    op.create_table(
        "callback_dispatch_intents",
        sa.Column(
            "nonce_id",
            sa.String(64),
            sa.ForeignKey("callback_nonces.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        *binding_columns(),
        sa.Column("recipe_digest", sa.String(64), nullable=False),
        sa.Column("callback_url", sa.Text(), nullable=False),
        sa.Column("method", sa.String(16), nullable=False),
        sa.Column("url_sha256", sa.String(64), nullable=False),
        sa.Column("body_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
    )
    op.create_table(
        "callback_dispatch_records",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "nonce_id",
            sa.String(64),
            sa.ForeignKey("callback_dispatch_intents.nonce_id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        *binding_columns(),
        sa.Column("sent_at", sa.Float(), nullable=False),
        sa.Column("response_at", sa.Float(), nullable=True),
        sa.Column("response_status", sa.Integer(), nullable=True),
    )


def downgrade():
    op.drop_table("callback_dispatch_records")
    op.drop_table("callback_dispatch_intents")
    op.drop_table("callback_closures")
