"""Add role constraint for scope authorization and RBAC.

Revision ID: 20261126_0005
Revises: 20261121_0004
"""

from alembic import op
import sqlalchemy as sa

revision = "20261126_0005"
down_revision = "20261121_0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Preserve old accounts while adopting the explicit role vocabulary.
    op.execute("UPDATE users SET role = 'client' WHERE role = 'user'")
    op.alter_column("users", "role", server_default="client")
    op.create_check_constraint(
        "ck_users_role",
        "users",
        "role IN ('admin', 'auditor', 'client')",
    )
    op.add_column(
        "websites",
        sa.Column("verification_token_expires_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("websites", "verification_token_expires_at")
    op.drop_constraint("ck_users_role", "users", type_="check")
    op.execute("UPDATE users SET role = 'user' WHERE role = 'client'")
    op.alter_column("users", "role", server_default="user")
