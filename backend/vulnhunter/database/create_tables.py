# vulnhunter/database/create_tables.py
from vulnhunter.database.connection import Base, engine

# Importar los modelos para que SQLAlchemy los reconozca
from vulnhunter.database.models import User, Website, Scan, Finding

print("Creando tablas en la base de datos...")

# Crea todas las tablas que heredan de Base
Base.metadata.create_all(bind=engine)

print("Tablas creadas correctamente.")
