# app/models/finding.py
from sqlalchemy import Column, Integer, String, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


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

    # Cada hallazgo pertenece a un escaneo
    scan = relationship("Scan", back_populates="findings")
