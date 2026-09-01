# vulnhunter/database/models.py
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, ForeignKey, Text
)
from sqlalchemy.orm import relationship
from datetime import datetime

from vulnhunter.database.connection import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(150), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    websites = relationship("Website", back_populates="owner")


class Website(Base):
    __tablename__ = "websites"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(500), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="websites")
    scans = relationship("Scan", back_populates="website")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(100), unique=True, nullable=False)
    website_id = Column(Integer, ForeignKey("websites.id"), nullable=False)
    scan_types = Column(Text)
    status = Column(String(50), default="pending")
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    total_vulnerabilities = Column(Integer, default=0)
    risk_score = Column(Integer, nullable=True)
    risk_level = Column(String(50), nullable=True)

    website = relationship("Website", back_populates="scans")
    findings = relationship("Finding", back_populates="scan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    type = Column(String(100), nullable=False)
    severity = Column(String(50), nullable=False)
    location = Column(String(500), nullable=True)
    payload = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    details = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="findings")
