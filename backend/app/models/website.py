# app/models/website.py
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base


class Website(Base):
    __tablename__ = "websites"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String(500), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Cada sitio pertenece a un usuario
    owner = relationship("User", back_populates="websites")
    # Un sitio tiene muchos escaneos
    scans = relationship("Scan", back_populates="website")
