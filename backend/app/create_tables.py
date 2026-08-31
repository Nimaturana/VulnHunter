# app/create_tables.py
from app.database import Base, engine

# Importar los 4 modelos para que SQLAlchemy los conozca
from app.models.user import User
from app.models.website import Website
from app.models.scan import Scan
from app.models.finding import Finding

print("Creando tablas en la base de datos...")

# Crea todas las tablas que heredan de Base
Base.metadata.create_all(bind=engine)

print("Tablas creadas correctamente.")
