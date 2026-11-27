"""Allow the read-only guest role used by the public demo.

Revision ID: 20261126_0007
Revises: 20261126_0006
"""

from alembic import op

revision = "20261126_0007"
down_revision = "20261126_0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("ck_users_role", "users", type_="check")
    op.create_check_constraint(
        "ck_users_role",
        "users",
        "role IN ('admin', 'auditor', 'client', 'guest')",
    )


def downgrade() -> None:
    op.execute("UPDATE users SET role = 'client' WHERE role = 'guest'")
    op.drop_constraint("ck_users_role", "users", type_="check")
    op.create_check_constraint(
        "ck_users_role",
        "users",
        "role IN ('admin', 'auditor', 'client')",
    )
