"""Persist Celery task tracing and generated PDF metadata.

Revision ID: 20261008_0003
Revises: 20260928_0002
"""

import sqlalchemy as sa
from alembic import op

revision = "20261008_0003"
down_revision = "20260928_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("task_id", sa.String(length=255)))
    op.add_column(
        "scans",
        sa.Column(
            "execution_mode",
            sa.String(length=20),
            nullable=False,
            server_default="background",
        ),
    )
    op.add_column("scans", sa.Column("queued_at", sa.DateTime(timezone=True)))
    op.add_column("scans", sa.Column("worker_started_at", sa.DateTime(timezone=True)))
    op.create_unique_constraint("uq_scans_task_id", "scans", ["task_id"])
    op.create_check_constraint(
        "ck_scans_execution_mode",
        "scans",
        "execution_mode IN ('background', 'celery')",
    )
    op.create_index("ix_scans_task_id", "scans", ["task_id"])

    op.create_table(
        "reports",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            server_default="generating",
        ),
        sa.Column("file_name", sa.String(length=255)),
        sa.Column("storage_path", sa.String(length=1000)),
        sa.Column(
            "media_type",
            sa.String(length=100),
            nullable=False,
            server_default="application/pdf",
        ),
        sa.Column("size_bytes", sa.BigInteger()),
        sa.Column("sha256", sa.String(length=64)),
        sa.Column("error_message", sa.Text()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("generated_at", sa.DateTime(timezone=True)),
        sa.Column("download_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_downloaded_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("scan_id", name="uq_reports_scan_id"),
        sa.CheckConstraint(
            "status IN ('generating', 'generated', 'failed')",
            name="ck_reports_status",
        ),
    )
    op.create_index("ix_reports_id", "reports", ["id"])
    op.create_index(
        "ix_reports_status_generated_at",
        "reports",
        ["status", "generated_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_reports_status_generated_at", table_name="reports")
    op.drop_index("ix_reports_id", table_name="reports")
    op.drop_table("reports")

    op.drop_index("ix_scans_task_id", table_name="scans")
    op.drop_constraint("ck_scans_execution_mode", "scans", type_="check")
    op.drop_constraint("uq_scans_task_id", "scans", type_="unique")
    op.drop_column("scans", "worker_started_at")
    op.drop_column("scans", "queued_at")
    op.drop_column("scans", "execution_mode")
    op.drop_column("scans", "task_id")
