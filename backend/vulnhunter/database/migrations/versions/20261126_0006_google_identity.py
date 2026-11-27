"""Add Google identity subject to users.

Revision ID: 20261126_0006
Revises: 20261126_0005
"""

import sqlalchemy as sa
from alembic import op

revision = "20261126_0006"
down_revision = "20261126_0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("google_subject", sa.String(255), nullable=True))
    op.create_unique_constraint("uq_users_google_subject", "users", ["google_subject"])


def downgrade() -> None:
    op.drop_constraint("uq_users_google_subject", "users", type_="unique")
    op.drop_column("users", "google_subject")
