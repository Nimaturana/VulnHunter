"""Relational persistence model for the VulnHunter MVP."""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import relationship

from vulnhunter.database.connection import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(150), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, nullable=False, default=True, server_default=text("true"))
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=text("CURRENT_TIMESTAMP"),
    )

    websites = relationship(
        "Website",
        back_populates="owner",
        cascade="all, delete-orphan",
    )
    requested_scans = relationship(
        "Scan",
        back_populates="requested_by",
        foreign_keys="Scan.requested_by_user_id",
    )


class Website(Base):
    __tablename__ = "websites"
    __table_args__ = (
        UniqueConstraint("user_id", "url", name="uq_websites_user_url"),
        CheckConstraint(
            "verification_status IN ('pending', 'verified', 'failed', 'expired')",
            name="ck_websites_verification_status",
        ),
        Index("ix_websites_user_id", "user_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(500), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=text("CURRENT_TIMESTAMP"),
    )
    verification_status = Column(
        String(20), nullable=False, default="pending", server_default="pending"
    )
    verification_method = Column(String(50), nullable=True)
    verification_token_hash = Column(String(255), nullable=True)
    verified_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, nullable=False, default=True, server_default=text("true"))

    owner = relationship("User", back_populates="websites")
    scans = relationship("Scan", back_populates="website", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'partial', 'failed')",
            name="ck_scans_status",
        ),
        CheckConstraint(
            "progress_percentage BETWEEN 0 AND 100",
            name="ck_scans_progress_percentage",
        ),
        CheckConstraint(
            "total_vulnerabilities >= 0",
            name="ck_scans_total_vulnerabilities",
        ),
        CheckConstraint(
            "risk_score IS NULL OR risk_score BETWEEN 0 AND 100",
            name="ck_scans_risk_score",
        ),
        CheckConstraint(
            "risk_level IS NULL OR risk_level IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')",
            name="ck_scans_risk_level",
        ),
        Index("ix_scans_website_id", "website_id"),
        Index("ix_scans_requested_by_user_id", "requested_by_user_id"),
        Index("ix_scans_status_started_at", "status", "started_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(100), unique=True, nullable=False)
    url = Column(String(500), nullable=False)
    website_id = Column(Integer, ForeignKey("websites.id", ondelete="CASCADE"), nullable=True)
    requested_by_user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    description = Column(String(500), nullable=True)
    scan_types = Column(Text, nullable=False)
    status = Column(String(50), nullable=False, default="pending", server_default="pending")
    started_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=text("CURRENT_TIMESTAMP"),
    )
    completed_at = Column(DateTime(timezone=True), nullable=True)
    progress_percentage = Column(Integer, nullable=False, default=0, server_default="0")
    current_scanner = Column(String(100), nullable=True)
    total_vulnerabilities = Column(Integer, nullable=False, default=0, server_default="0")
    risk_score = Column(Integer, nullable=True)
    risk_level = Column(String(50), nullable=True)
    errors = Column(Text, nullable=False, default="{}", server_default="{}")

    website = relationship("Website", back_populates="scans")
    requested_by = relationship(
        "User",
        back_populates="requested_scans",
        foreign_keys=[requested_by_user_id],
    )
    findings = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')",
            name="ck_findings_severity",
        ),
        CheckConstraint(
            "confidence IN ('high', 'medium', 'low')",
            name="ck_findings_confidence",
        ),
        Index("ix_findings_scan_id", "scan_id"),
        Index("ix_findings_severity", "severity"),
    )

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    type = Column(String(100), nullable=False)
    severity = Column(String(50), nullable=False)
    location = Column(String(500), nullable=True)
    scanner = Column(String(100), nullable=True)
    description = Column(Text, nullable=True)
    recommendation = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    confidence = Column(String(50), nullable=False, default="low", server_default="low")
    created_at = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        server_default=text("CURRENT_TIMESTAMP"),
    )

    scan = relationship("Scan", back_populates="findings")
