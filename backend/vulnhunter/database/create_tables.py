from vulnhunter.database.connection import Base, engine
from vulnhunter.database.models import User, Website, Scan, Finding

print("Borrando tablas existentes...")
Base.metadata.drop_all(bind=engine)

print("Creando tablas con la estructura nueva...")
Base.metadata.create_all(bind=engine)

print("Tablas recreadas correctamente.")
