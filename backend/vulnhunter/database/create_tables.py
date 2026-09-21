from vulnhunter.database.connection import Base, engine
from vulnhunter.database.models import User, Website, Scan, Finding

# ADVERTENCIA: drop_all borra TODAS las tablas y sus datos.
# Se desactiva para no perder los escaneos guardados en PostgreSQL.
# Reactivar solo si se necesita recrear la base desde cero en desarrollo.
# print("Borrando tablas existentes...")
# Base.metadata.drop_all(bind=engine)

print("Creando tablas con la estructura nueva...")
Base.metadata.create_all(bind=engine)

print("Tablas recreadas correctamente.")

# TAREA FUTURA: migrar a Alembic para versionar cambios del esquema
# sin recrear las tablas ni perder datos (reemplazo de create_all/drop_all).

