# app/models/scan.py
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(100), unique=True, nullable=False)
    website_id = Column(Integer, ForeignKey("websites.id"), nullable=False)
    scan_types = Column(Text)  # lista de tipos de escaneo (guardada como texto)
    status = Column(String(50), default="pending")
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    total_vulnerabilities = Column(Integer, default=0)
    risk_score = Column(Integer, nullable=True)
    risk_level = Column(String(50), nullable=True)

    # Cada escaneo pertenece a un sitio web
    website = relationship("Website", back_populates="scans")
    # Un escaneo tiene muchos hallazgos (vulnerabilidades)
    findings = relationship("Finding", back_populates="scan")
