from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import sys
import os

# Agregar el directorio padre al path para importar scanners
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from .routes import scans, stats, system


# Inicializar FastAPI
app = FastAPI(
    title="VulnHunter - Sistema Completo de Seguridad Web",
    description="Sistema profesional de escaneo de vulnerabilidades web: XSS, SQL Injection, Headers de Seguridad, SSL/TLS, Directorios y Archivos Sensibles.",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router)
app.include_router(stats.router)
app.include_router(system.router)


if __name__ == "__main__":
    import uvicorn
    print("🚀 Iniciando VulnHunter API con todos los scanners...")
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)