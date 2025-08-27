# app/main.py
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import List, Dict, Optional
import sys
import os
from datetime import datetime
import uuid

# Agregar el directorio padre al path para importar scanners
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanners.xss_scanner import XSSScanner
from scanners.sql_injection_scanner import SQLInjectionScanner

# Inicializar FastAPI
app = FastAPI(
    title="VulnScanner API",
    description="Sistema de Monitoreo de Vulnerabilidades Web - API para detectar vulnerabilidades en sitios web",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configurar CORS para desarrollo
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En producción cambiar por dominios específicos
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modelos Pydantic para requests/responses
class ScanRequest(BaseModel):
    url: HttpUrl
    scan_types: List[str] = ["xss", "sql_injection"]  # Tipos de escaneo a realizar
    
    class Config:
        schema_extra = {
            "example": {
                "url": "https://example.com",
                "scan_types": ["xss", "sql_injection"]
            }
        }

class VulnerabilityInfo(BaseModel):
    type: str
    location: str
    severity: str
    payload: Optional[str] = None
    field: Optional[str] = None
    parameter: Optional[str] = None
    method: Optional[str] = None
    evidence: Optional[str] = None
    details: Optional[str] = None

class ScanResult(BaseModel):
    scan_id: str
    url: str
    scan_types: List[str]
    status: str  # "running", "completed", "failed"
    started_at: datetime
    completed_at: Optional[datetime] = None
    total_vulnerabilities: int = 0
    results: Dict = {}
    error: Optional[str] = None

class ScanSummary(BaseModel):
    scan_id: str
    url: str
    status: str
    total_vulnerabilities: int
    risk_level: str  # "Low", "Medium", "High", "Critical"
    completed_at: Optional[datetime] = None

# Storage en memoria (en producción usar base de datos)
scans_storage: Dict[str, ScanResult] = {}

# Instancias de scanners
xss_scanner = XSSScanner()
sql_scanner = SQLInjectionScanner()

@app.get("/")
async def root():
    """
    Endpoint de bienvenida
    """
    return {
        "message": "VulnScanner API - Sistema de Monitoreo de Vulnerabilidades Web",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": {
            "scan": "POST /scan - Iniciar nuevo escaneo",
            "results": "GET /scan/{scan_id} - Obtener resultados",
            "list": "GET /scans - Listar escaneos",
            "health": "GET /health - Estado del sistema"
        }
    }

@app.get("/health")
async def health_check():
    """
    Endpoint de salud del sistema
    """
    return {
        "status": "healthy",
        "timestamp": datetime.now(),
        "scanners_available": ["xss", "sql_injection"],
        "active_scans": len([s for s in scans_storage.values() if s.status == "running"])
    }

@app.post("/scan", response_model=ScanResult)
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Iniciar un nuevo escaneo de vulnerabilidades
    """
    # Generar ID único para el escaneo
    scan_id = str(uuid.uuid4())
    
    # Crear registro inicial del escaneo
    scan_result = ScanResult(
        scan_id=scan_id,
        url=str(scan_request.url),
        scan_types=scan_request.scan_types,
        status="running",
        started_at=datetime.now(),
        results={}
    )
    
    # Guardar en storage
    scans_storage[scan_id] = scan_result
    
    # Ejecutar escaneo en background
    background_tasks.add_task(
        perform_scan,
        scan_id,
        str(scan_request.url),
        scan_request.scan_types
    )
    
    return scan_result

@app.get("/scan/{scan_id}", response_model=ScanResult)
async def get_scan_results(scan_id: str):
    """
    Obtener resultados de un escaneo específico
    """
    if scan_id not in scans_storage:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    
    return scans_storage[scan_id]

@app.get("/scans", response_model=List[ScanSummary])
async def list_scans(limit: int = 10, status: Optional[str] = None):
    """
    Listar escaneos realizados
    """
    scans = list(scans_storage.values())
    
    # Filtrar por status si se especifica
    if status:
        scans = [s for s in scans if s.status == status]
    
    # Ordenar por fecha (más recientes primero)
    scans.sort(key=lambda x: x.started_at, reverse=True)
    
    # Limitar resultados
    scans = scans[:limit]
    
    # Convertir a resumen
    summaries = []
    for scan in scans:
        risk_level = calculate_risk_level(scan.total_vulnerabilities, scan.results)
        summaries.append(ScanSummary(
            scan_id=scan.scan_id,
            url=scan.url,
            status=scan.status,
            total_vulnerabilities=scan.total_vulnerabilities,
            risk_level=risk_level,
            completed_at=scan.completed_at
        ))
    
    return summaries

@app.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """
    Eliminar un escaneo
    """
    if scan_id not in scans_storage:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    
    del scans_storage[scan_id]
    return {"message": "Escaneo eliminado exitosamente"}

@app.get("/scan/{scan_id}/report")
async def get_scan_report(scan_id: str):
    """
    Generar reporte detallado de un escaneo
    """
    if scan_id not in scans_storage:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    
    scan = scans_storage[scan_id]
    
    if scan.status != "completed":
        raise HTTPException(status_code=400, detail="El escaneo aún no ha terminado")
    
    # Generar reporte estructurado
    report = generate_detailed_report(scan)
    return report

@app.get("/stats")
async def get_statistics():
    """
    Obtener estadísticas del sistema
    """
    total_scans = len(scans_storage)
    completed_scans = len([s for s in scans_storage.values() if s.status == "completed"])
    running_scans = len([s for s in scans_storage.values() if s.status == "running"])
    failed_scans = len([s for s in scans_storage.values() if s.status == "failed"])
    
    total_vulnerabilities = sum(s.total_vulnerabilities for s in scans_storage.values())
    
    # Estadísticas por tipo de vulnerabilidad
    vuln_types = {}
    for scan in scans_storage.values():
        for scan_type, results in scan.results.items():
            if isinstance(results, dict) and "vulnerabilities" in results:
                for vuln in results["vulnerabilities"]:
                    vuln_type = vuln.get("type", "Unknown")
                    vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
    
    return {
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "running_scans": running_scans,
        "failed_scans": failed_scans,
        "total_vulnerabilities": total_vulnerabilities,
        "vulnerabilities_by_type": vuln_types,
        "success_rate": round((completed_scans / total_scans * 100), 2) if total_scans > 0 else 0
    }

# Funciones auxiliares

async def perform_scan(scan_id: str, url: str, scan_types: List[str]):
    """
    Ejecuta el escaneo en background
    """
    scan = scans_storage[scan_id]
    
    try:
        results = {}
        total_vulnerabilities = 0
        
        # Ejecutar scanners según los tipos solicitados
        if "xss" in scan_types:
            print(f"🔍 Ejecutando XSS scan para {url}")
            xss_result = xss_scanner.scan_url(url)
            results["xss"] = xss_result
            if xss_result["vulnerable"]:
                total_vulnerabilities += len(xss_result["vulnerabilities"])
        
        if "sql_injection" in scan_types:
            print(f"💉 Ejecutando SQL Injection scan para {url}")
            sql_result = sql_scanner.scan_url(url)
            results["sql_injection"] = sql_result
            if sql_result["vulnerable"]:
                total_vulnerabilities += len(sql_result["vulnerabilities"])
        
        # Actualizar resultado
        scan.results = results
        scan.total_vulnerabilities = total_vulnerabilities
        scan.status = "completed"
        scan.completed_at = datetime.now()
        
        print(f"✅ Escaneo {scan_id} completado. Vulnerabilidades: {total_vulnerabilities}")
        
    except Exception as e:
        print(f"❌ Error en escaneo {scan_id}: {str(e)}")
        scan.status = "failed"
        scan.error = str(e)
        scan.completed_at = datetime.now()

def calculate_risk_level(total_vulnerabilities: int, results: Dict) -> str:
    """
    Calcula el nivel de riesgo basado en las vulnerabilidades encontradas
    """
    if total_vulnerabilities == 0:
        return "Low"
    
    high_severity_count = 0
    critical_count = 0
    
    for scan_type, result in results.items():
        if isinstance(result, dict) and "vulnerabilities" in result:
            for vuln in result["vulnerabilities"]:
                severity = vuln.get("severity", "Medium")
                if severity == "High":
                    high_severity_count += 1
                elif severity == "Critical":
                    critical_count += 1
    
    if critical_count > 0:
        return "Critical"
    elif high_severity_count > 0:
        return "High"
    elif total_vulnerabilities > 3:
        return "Medium"
    else:
        return "Low"

def generate_detailed_report(scan: ScanResult) -> Dict:
    """
    Genera un reporte detallado del escaneo
    """
    risk_level = calculate_risk_level(scan.total_vulnerabilities, scan.results)
    
    # Agrupar vulnerabilidades por severidad
    vulnerabilities_by_severity = {"Critical": [], "High": [], "Medium": [], "Low": []}
    
    for scan_type, result in scan.results.items():
        if isinstance(result, dict) and "vulnerabilities" in result:
            for vuln in result["vulnerabilities"]:
                severity = vuln.get("severity", "Medium")
                vuln["scan_type"] = scan_type
                vulnerabilities_by_severity[severity].append(vuln)
    
    return {
        "scan_id": scan.scan_id,
        "url": scan.url,
        "risk_level": risk_level,
        "scan_duration": (scan.completed_at - scan.started_at).total_seconds() if scan.completed_at else 0,
        "summary": {
            "total_vulnerabilities": scan.total_vulnerabilities,
            "critical": len(vulnerabilities_by_severity["Critical"]),
            "high": len(vulnerabilities_by_severity["High"]),
            "medium": len(vulnerabilities_by_severity["Medium"]),
            "low": len(vulnerabilities_by_severity["Low"]),
        },
        "vulnerabilities": vulnerabilities_by_severity,
        "scan_details": scan.results,
        "recommendations": generate_recommendations(vulnerabilities_by_severity)
    }

def generate_recommendations(vulnerabilities_by_severity: Dict) -> List[str]:
    """
    Genera recomendaciones basadas en las vulnerabilidades encontradas
    """
    recommendations = []
    
    if vulnerabilities_by_severity["Critical"] or vulnerabilities_by_severity["High"]:
        recommendations.append("🚨 CRÍTICO: Resolver inmediatamente las vulnerabilidades de alta severidad")
        recommendations.append("🛡️ Implementar validación y sanitización de entrada de datos")
        recommendations.append("🔐 Usar prepared statements para consultas SQL")
        recommendations.append("🌐 Implementar Content Security Policy (CSP)")
    
    if vulnerabilities_by_severity["Medium"]:
        recommendations.append("⚠️ Revisar y corregir vulnerabilidades de severidad media")
        recommendations.append("📋 Implementar headers de seguridad faltantes")
    
    recommendations.append("🔍 Realizar escaneos periódicos de seguridad")
    recommendations.append("👨‍💻 Capacitar al equipo de desarrollo en seguridad web")
    recommendations.append("📚 Seguir las mejores prácticas de OWASP")
    
    return recommendations

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
