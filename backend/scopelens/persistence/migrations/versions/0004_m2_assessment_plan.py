"""Freeze assessment controls and explicit transport-only authorization."""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scope_versions", sa.Column("transport_http_port", sa.Integer(), nullable=True))
    op.add_column("scans", sa.Column("assessment_plan", JSONB(), nullable=True))
    op.add_column(
        "scans",
        sa.Column("transport_probe_used", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("scans", "transport_probe_used")
    op.drop_column("scans", "assessment_plan")
    op.drop_column("scope_versions", "transport_http_port")
