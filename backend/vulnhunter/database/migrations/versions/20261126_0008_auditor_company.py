"""Add company metadata for administratively managed auditors.

Revision ID: 20261126_0008
Revises: 20261126_0007
"""

import sqlalchemy as sa
from alembic import op

revision = "20261126_0008"
down_revision = "20261126_0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("company_name", sa.String(length=150), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "company_name")
