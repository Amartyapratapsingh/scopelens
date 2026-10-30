"""Store full immutable image identities without truncating their digest."""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column("evidence", "tool_version", existing_type=sa.String(64), type_=sa.String(256))


def downgrade():
    # PostgreSQL refuses the narrowing when longer identities exist; never truncate proof metadata.
    op.alter_column("evidence", "tool_version", existing_type=sa.String(256), type_=sa.String(64))
