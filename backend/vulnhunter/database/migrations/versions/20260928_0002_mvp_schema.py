"""Complete users, websites, scans, and findings for the MVP.

Revision ID: 20260928_0002
Revises: 20260928_0001
"""

import sqlalchemy as sa
from alembic import op

revision = "20260928_0002"
down_revision = "20260928_0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("UPDATE users SET is_active = true WHERE is_active IS NULL")
    op.execute("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
    op.alter_column("users", "is_active", nullable=False, server_default=sa.text("true"))
    op.alter_column(
        "users", "created_at", nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")
    )

    op.add_column(
        "websites",
        sa.Column("verification_status", sa.String(length=20), nullable=False, server_default="pending"),
    )
    op.add_column("websites", sa.Column("verification_method", sa.String(length=50)))
    op.add_column("websites", sa.Column("verification_token_hash", sa.String(length=255)))
    op.add_column("websites", sa.Column("verified_at", sa.DateTime(timezone=True)))
    op.add_column(
        "websites", sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true"))
    )
    op.execute("UPDATE websites SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
    op.alter_column(
        "websites", "created_at", nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")
    )
    op.create_unique_constraint("uq_websites_user_url", "websites", ["user_id", "url"])
    op.create_check_constraint(
        "ck_websites_verification_status",
        "websites",
        "verification_status IN ('pending', 'verified', 'failed', 'expired')",
    )
    op.create_index("ix_websites_user_id", "websites", ["user_id"])

    op.add_column("scans", sa.Column("requested_by_user_id", sa.Integer()))
    op.add_column("scans", sa.Column("description", sa.String(length=500)))
    op.add_column(
        "scans",
        sa.Column("progress_percentage", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column("scans", sa.Column("current_scanner", sa.String(length=100)))
    op.add_column(
        "scans", sa.Column("errors", sa.Text(), nullable=False, server_default="{}")
    )
    op.execute("UPDATE scans SET scan_types = '[]' WHERE scan_types IS NULL")
    op.execute("UPDATE scans SET status = 'pending' WHERE status IS NULL")
    op.execute("UPDATE scans SET started_at = CURRENT_TIMESTAMP WHERE started_at IS NULL")
    op.execute("UPDATE scans SET total_vulnerabilities = 0 WHERE total_vulnerabilities IS NULL")
    op.alter_column("scans", "scan_types", nullable=False)
    op.alter_column("scans", "status", nullable=False, server_default="pending")
    op.alter_column(
        "scans", "started_at", nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")
    )
    op.alter_column("scans", "total_vulnerabilities", nullable=False, server_default="0")
    op.create_foreign_key(
        "fk_scans_requested_by_user_id_users",
        "scans",
        "users",
        ["requested_by_user_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_check_constraint(
        "ck_scans_status",
        "scans",
        "status IN ('pending', 'running', 'completed', 'partial', 'failed')",
    )
    op.create_check_constraint(
        "ck_scans_progress_percentage",
        "scans",
        "progress_percentage BETWEEN 0 AND 100",
    )
    op.create_check_constraint(
        "ck_scans_total_vulnerabilities", "scans", "total_vulnerabilities >= 0"
    )
    op.create_check_constraint(
        "ck_scans_risk_score", "scans", "risk_score IS NULL OR risk_score BETWEEN 0 AND 100"
    )
    op.create_check_constraint(
        "ck_scans_risk_level",
        "scans",
        "risk_level IS NULL OR risk_level IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')",
    )
    op.create_index("ix_scans_website_id", "scans", ["website_id"])
    op.create_index("ix_scans_requested_by_user_id", "scans", ["requested_by_user_id"])
    op.create_index("ix_scans_status_started_at", "scans", ["status", "started_at"])

    op.add_column(
        "findings",
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
    )
    op.execute("UPDATE findings SET confidence = 'low' WHERE confidence IS NULL")
    op.alter_column("findings", "confidence", nullable=False, server_default="low")
    op.create_check_constraint(
        "ck_findings_severity",
        "findings",
        "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')",
    )
    op.create_check_constraint(
        "ck_findings_confidence",
        "findings",
        "confidence IN ('high', 'medium', 'low')",
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_severity", "findings", ["severity"])


def downgrade() -> None:
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_constraint("ck_findings_confidence", "findings", type_="check")
    op.drop_constraint("ck_findings_severity", "findings", type_="check")
    op.alter_column("findings", "confidence", nullable=True, server_default=None)
    op.drop_column("findings", "created_at")

    op.drop_index("ix_scans_status_started_at", table_name="scans")
    op.drop_index("ix_scans_requested_by_user_id", table_name="scans")
    op.drop_index("ix_scans_website_id", table_name="scans")
    for constraint in (
        "ck_scans_risk_level",
        "ck_scans_risk_score",
        "ck_scans_total_vulnerabilities",
        "ck_scans_progress_percentage",
        "ck_scans_status",
    ):
        op.drop_constraint(constraint, "scans", type_="check")
    op.drop_constraint("fk_scans_requested_by_user_id_users", "scans", type_="foreignkey")
    op.drop_column("scans", "errors")
    op.drop_column("scans", "current_scanner")
    op.drop_column("scans", "progress_percentage")
    op.drop_column("scans", "description")
    op.drop_column("scans", "requested_by_user_id")

    op.drop_index("ix_websites_user_id", table_name="websites")
    op.drop_constraint("ck_websites_verification_status", "websites", type_="check")
    op.drop_constraint("uq_websites_user_url", "websites", type_="unique")
    op.drop_column("websites", "is_active")
    op.drop_column("websites", "verified_at")
    op.drop_column("websites", "verification_token_hash")
    op.drop_column("websites", "verification_method")
    op.drop_column("websites", "verification_status")
