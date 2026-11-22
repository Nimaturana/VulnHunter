"""Add user profile and role fields.

Revision ID: 20261121_0004
Revises: 20261008_0003
"""

from alembic import op
import sqlalchemy as sa

revision = "20261121_0004"
down_revision = "20261008_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("nombre", sa.String(100), nullable=False, server_default="Usuario"))
    op.add_column("users", sa.Column("apellido", sa.String(100), nullable=False, server_default="VulnHunter"))
    op.add_column("users", sa.Column("rut", sa.String(20), nullable=True))
    op.add_column("users", sa.Column("telefono", sa.String(30), nullable=True))
    op.add_column("users", sa.Column("fecha_nacimiento", sa.String(20), nullable=True))
    op.add_column("users", sa.Column("role", sa.String(20), nullable=False, server_default="user"))
    op.create_unique_constraint("uq_users_rut", "users", ["rut"])


def downgrade() -> None:
    op.drop_constraint("uq_users_rut", "users", type_="unique")
    for column in ("role", "fecha_nacimiento", "telefono", "rut", "apellido", "nombre"):
        op.drop_column("users", column)
