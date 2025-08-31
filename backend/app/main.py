# app/main.py
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse  # AGREGADO PARA PDF
from pydantic import BaseModel, HttpUrl
from typing import List, Dict, Optional
import sys
import os
from datetime import datetime
import uuid
import asyncio  # AGREGADO

# Agregar el directorio padre al path para importar scanners
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanners.xss_scanner import XSSScanner
from scanners.sql_injection_scanner import SQLInjectionScanner
from scanners.security_headers_scanner import SecurityHeadersScanner
from scanners.ssl_scanner import SSLScanner
from scanners.directory_scanner import DirectoryScanner

# AGREGADO: Importar generador de PDF
try:
    from .reports.pdf_generator import WebSecurityReportGenerator
    PDF_AVAILABLE = True
    print("✅ PDF generator disponible")
except ImportError as e:
    print(f"⚠️ PDF generator no disponible: {e}")
    PDF_AVAILABLE = False

# Inicializar FastAPI
app = FastAPI(
    title="WebSecure Pro - API de Seguridad Web",  # MEJORADO EL TÍTULO/CAMBIAR NOMBRE ES SOLO PRUEBA 
    description="Sistema profesional de escaneo de vulnerabilidades web - Detecta XSS, SQL Injection y más",
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
    scan_types: List[str] = ["xss", "sql_injection", "security_headers", "ssl_tls"]
    description: Optional[str] = None  # AGREGADO
    
    class Config:
        schema_extra = {
            "example": {
                "url": "http://testphp.vulnweb.com",
                "scan_types": ["xss", "sql_injection", "security_headers", "ssl_tls"],
                "description": "Escaneo de prueba"
            }
        }

class VulnerabilityInfo(BaseModel):  # CORREGIDO: faltaba 'c' en class
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
    duration_seconds: Optional[int] = None  # AGREGADO
    total_vulnerabilities: int = 0
    results: Dict = {}
    vulnerabilities: List[Dict] = []  # AGREGADO: Lista procesada de vulnerabilidades
    risk_score: Optional[int] = None  # AGREGADO
    risk_level: Optional[str] = None  # AGREGADO
    summary: Optional[Dict] = None  # AGREGADO
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
# Nuevos scanners
headers_scanner = SecurityHeadersScanner()
ssl_scanner = SSLScanner()
directory_scanner = DirectoryScanner()

@app.get("/")
async def root():
    """
    Endpoint de bienvenida
    """
    return {
        "message": "WebSecure Pro - Sistema de Monitoreo de Vulnerabilidades Web",
        "version": "1.0.0",
        "docs": "/docs",
        "features": ["XSS Detection", "SQL Injection Detection", "PDF Reports"],
        "pdf_reports": PDF_AVAILABLE,
        "endpoints": {
            "scan": "POST /scan - Iniciar nuevo escaneo",
            "results": "GET /scan/{scan_id} - Obtener resultados",
            "pdf": "GET /scan/{scan_id}/pdf - Descargar reporte PDF",
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
        "scanners_available": ["xss", "sql_injection", "security_headers", "ssl_tls", "directory_scan"],
        "pdf_generator": PDF_AVAILABLE,
        "active_scans": len([s for s in scans_storage.values() if s.status == "running"]),
        "total_scans": len(scans_storage)
    }

@app.post("/scan", response_model=Dict)  # CAMBIADO: retorna Dict en lugar de ScanResult
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
        status="pending",  # CAMBIADO: inicia como pending
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
    
    # MEJORADO: Respuesta más informativa
    return {
        "scan_id": scan_id,
        "status": "pending",
        "message": "Escaneo iniciado correctamente",
        "estimated_time": "2-5 minutos",
        "check_status_url": f"/scan/{scan_id}",
        "pdf_available": PDF_AVAILABLE
    }

@app.get("/scan/{scan_id}")  # CAMBIADO: sin response_model para flexibilidad
async def get_scan_results(scan_id: str):
    """
    Obtener resultados de un escaneo específico
    """
    if scan_id not in scans_storage:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    
    scan_data = scans_storage[scan_id]
    
    # AGREGADO: Calcular duración
    if scan_data.completed_at:
        duration = scan_data.completed_at - scan_data.started_at
        duration_seconds = int(duration.total_seconds())
    else:
        duration = datetime.now() - scan_data.started_at
        duration_seconds = int(duration.total_seconds())
    
    # Convertir a dict para respuesta
    response = {
        "scan_id": scan_data.scan_id,
        "url": scan_data.url,
        "scan_types": scan_data.scan_types,
        "status": scan_data.status,
        "started_at": scan_data.started_at.isoformat(),
        "completed_at": scan_data.completed_at.isoformat() if scan_data.completed_at else None,
        "duration_seconds": duration_seconds,
        "total_vulnerabilities": scan_data.total_vulnerabilities,
        "results": scan_data.results,
        "vulnerabilities": scan_data.vulnerabilities,
        "risk_score": scan_data.risk_score,
        "risk_level": scan_data.risk_level,
        "summary": scan_data.summary,
        "error": scan_data.error
    }
    
    return response

@app.get("/scans", response_model=List[ScanSummary])
async def list_scans(limit: int = 50, offset: int = 0):  # MEJORADO: agregado offset
    """
    Listar escaneos realizados
    """
    scans = list(scans_storage.values())
    
    # Ordenar por fecha (más recientes primero)
    scans.sort(key=lambda x: x.started_at, reverse=True)
    
    # Aplicar paginación
    paginated_scans = scans[offset:offset + limit]
    
    # Convertir a resumen
    summaries = []
    for scan in paginated_scans:
        risk_level = scan.risk_level or calculate_risk_level(scan.total_vulnerabilities, scan.results)
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
    Generar reporte detallado de un escaneo (JSON)
    """
    if scan_id not in scans_storage:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    
    scan = scans_storage[scan_id]
    
    if scan.status != "completed":
        raise HTTPException(status_code=400, detail="El escaneo aún no ha terminado")
    
    # Generar reporte estructurado
    report = generate_detailed_report(scan)
    return report

@app.get("/scan/{scan_id}/pdf")
async def download_pdf_report(scan_id: str):
    """
    Generar y descargar reporte PDF del escaneo
    """
    if not PDF_AVAILABLE:
        raise HTTPException(status_code=503, detail="Generador de PDF no disponible")
    
    if scan_id not in scans_storage:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    
    scan_data = scans_storage[scan_id]
    
    if scan_data.status != "completed":
        raise HTTPException(status_code=400, detail="El escaneo aún no ha completado")
    
    try:
        # CREAR LA INSTANCIA DEL GENERADOR
        generator = WebSecurityReportGenerator()
        
        # Preparar datos para el PDF
        pdf_data = {
            "scan_id": scan_data.scan_id,
            "url": scan_data.url,
            "scan_types": scan_data.scan_types,
            "status": scan_data.status,
            "started_at": scan_data.started_at.isoformat(),
            "completed_at": scan_data.completed_at.isoformat() if scan_data.completed_at else None,
            "duration_seconds": int((scan_data.completed_at - scan_data.started_at).total_seconds()) if scan_data.completed_at else 0,
            "vulnerabilities": scan_data.vulnerabilities,
            "risk_score": scan_data.risk_score,
            "risk_level": scan_data.risk_level,
            "results": scan_data.results
        }
        
        # Crear directorio reports si no existe
        os.makedirs("reports", exist_ok=True)
        
        # Generar reporte PDF usando la instancia
        pdf_path = generator.generate_report(pdf_data)
        
        if not os.path.exists(pdf_path):
            raise HTTPException(status_code=500, detail="Error al generar el reporte PDF")
        
        # Obtener nombre del archivo
        filename = os.path.basename(pdf_path)
        
        # Retornar archivo PDF para descarga
        return FileResponse(
            path=pdf_path,
            filename=filename,
            media_type='application/pdf',
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        print(f"Error generando PDF: {e}")
        raise HTTPException(status_code=500, detail=f"Error al generar PDF: {str(e)}")

# NUEVO: Vista previa del reporte
@app.get("/scan/{scan_id}/report-preview")
async def get_report_preview(scan_id: str):
    """
    Obtener vista previa del reporte antes de generar PDF
    """
    if scan_id not in scans_storage:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    
    scan_data = scans_storage[scan_id]
    
    if scan_data.status != "completed":
        raise HTTPException(status_code=400, detail="El escaneo aún no ha completado")
    
    # Generar vista previa del reporte
    vulnerabilities = scan_data.vulnerabilities or []
    
    # Contar por severidad
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'LOW')
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Generar resumen ejecutivo
    risk_level = scan_data.risk_level or 'UNKNOWN'
    executive_summary = {
        'CRITICAL': "ACCIÓN INMEDIATA REQUERIDA: Se han identificado vulnerabilidades críticas que exponen el sitio web a ataques severos.",
        'HIGH': "ATENCIÓN PRIORITARIA: Las vulnerabilidades identificadas representan un riesgo significativo para la seguridad.",
        'MEDIUM': "REVISIÓN PROGRAMADA: Se han identificado vulnerabilidades que deben ser abordadas en el próximo ciclo de mantenimiento.",
        'LOW': "MANTENIMIENTO RUTINARIO: El sitio web presenta un nivel de seguridad aceptable con oportunidades menores de mejora."
    }.get(risk_level, "Se recomienda revisar los hallazgos detallados.")
    
    preview = {
        "scan_info": {
            "id": scan_id,
            "url": scan_data.url,
            "date": scan_data.completed_at.isoformat() if scan_data.completed_at else None,
            "duration": int((scan_data.completed_at - scan_data.started_at).total_seconds()) if scan_data.completed_at else 0,
            "risk_level": risk_level,
            "risk_score": scan_data.risk_score
        },
        "executive_summary": {
            "total_vulnerabilities": len(vulnerabilities),
            "severity_breakdown": severity_counts,
            "recommendation": executive_summary
        },
        "vulnerability_types": list(set([v.get('type') for v in vulnerabilities])),
        "top_vulnerabilities": vulnerabilities[:5],  # Top 5 más críticas
        "recommendations": generate_preview_recommendations(vulnerabilities)
    }
    
    return preview

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
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    for scan in scans_storage.values():
        if scan.vulnerabilities:
            for vuln in scan.vulnerabilities:
                vuln_type = vuln.get("type", "Unknown")
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
                
                severity = vuln.get("severity", "LOW")
                if severity in severity_counts:
                    severity_counts[severity] += 1

    return {
        "system_status": "operational",
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "running_scans": running_scans,
        "failed_scans": failed_scans,
        "total_vulnerabilities": total_vulnerabilities,
        "vulnerabilities_by_type": vuln_types,
        "vulnerability_breakdown": severity_counts,
        "success_rate": round((completed_scans / total_scans * 100), 2) if total_scans > 0 else 0,
        "pdf_reports_available": PDF_AVAILABLE,
        "version": "1.0.0"
    }

# Funciones auxiliares
async def perform_scan(scan_id: str, url: str, scan_types: List[str]):
    """
    Ejecuta el escaneo en background
    """
    scan = scans_storage[scan_id]
    
    try:
        # Actualizar estado a "running"
        scan.status = "running"
        
        results = {}
        vulnerabilities = []
        total_vulnerabilities = 0
        
        print(f"🔍 Iniciando escaneo de {url}...")
        
        # Ejecutar scanners según los tipos solicitados
        if "xss" in scan_types:
            print(f"🕷️ Ejecutando XSS Scanner...")
            xss_result = await run_xss_scan(url)
            results["xss"] = xss_result
            
            # Procesar resultados XSS
            if xss_result.get("vulnerable", False):
                for vuln in xss_result.get("vulnerabilities", []):
                    vulnerabilities.append({
                        "type": "Cross-Site Scripting (XSS)",
                        "severity": "HIGH",
                        "location": vuln.get("location", url),
                        "description": f"XSS vulnerability found: {vuln.get('type', 'Unknown')}",
                        "recommendation": "Sanitizar y validar todas las entradas de usuario. Implementar CSP headers.",
                        "evidence": vuln.get("payload", "")
                    })
                total_vulnerabilities += len(xss_result["vulnerabilities"])
        
        if "sql_injection" in scan_types:
            print(f"💉 Ejecutando SQL Injection Scanner...")
            sql_result = await run_sql_scan(url)
            results["sql_injection"] = sql_result
            
            # Procesar resultados SQL
            if sql_result.get("vulnerable", False):
                for vuln in sql_result.get("vulnerabilities", []):
                    vulnerabilities.append({
                        "type": "SQL Injection",
                        "severity": "CRITICAL",
                        "location": vuln.get("location", url),
                        "description": f"SQL Injection vulnerability found in {vuln.get('field', 'parameter')}",
                        "recommendation": "Usar prepared statements o ORM. Validar y sanitizar entradas.",
                        "evidence": vuln.get("evidence", "")
                    })
                total_vulnerabilities += len(sql_result["vulnerabilities"])
        
        # Calcular risk score y level
        risk_score, risk_level = calculate_risk_score(vulnerabilities)
        
        # Generar summary
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "LOW")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Actualizar resultado
        scan.results = results
        scan.vulnerabilities = vulnerabilities
        scan.total_vulnerabilities = total_vulnerabilities
        scan.risk_score = risk_score
        scan.risk_level = risk_level
        scan.summary = {
            "total_vulnerabilities": total_vulnerabilities,
            "critical": severity_counts["CRITICAL"],
            "high": severity_counts["HIGH"],
            "medium": severity_counts["MEDIUM"],
            "low": severity_counts["LOW"]
        }
        scan.status = "completed"
        scan.completed_at = datetime.now()
        
        print(f"✅ Escaneo {scan_id} completado. Vulnerabilidades: {total_vulnerabilities}")
        
    except Exception as e:
        print(f"❌ Error en escaneo {scan_id}: {str(e)}")
        scan.status = "failed"
        scan.error = str(e)
        scan.completed_at = datetime.now()

async def run_xss_scan(url: str) -> Dict:
    """Ejecutar scanner XSS de forma asíncrona"""
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, xss_scanner.scan_url, url)
        return result
    except Exception as e:
        print(f"Error en XSS scan: {e}")
        return {"vulnerable": False, "error": str(e)}

async def run_sql_scan(url: str) -> Dict:
    """Ejecutar scanner SQL de forma asíncrona"""
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, sql_scanner.scan_url, url)
        return result
    except Exception as e:
        print(f"Error en SQL scan: {e}")
        return {"vulnerable": False, "error": str(e)}

def calculate_risk_score(vulnerabilities: List[Dict]) -> tuple:
    """Calcular puntuación y nivel de riesgo"""
    if not vulnerabilities:
        return 0, "LOW"
    
    score = 0
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "LOW")
        if severity == "CRITICAL":
            score += 10
        elif severity == "HIGH":
            score += 7
        elif severity == "MEDIUM":
            score += 4
        elif severity == "LOW":
            score += 1
    
    # Determinar nivel de riesgo
    if score >= 10:
        level = "CRITICAL"
    elif score >= 7:
        level = "HIGH"
    elif score >= 4:
        level = "MEDIUM"
    else:
        level = "LOW"
    
    return score, level

def calculate_risk_level(total_vulnerabilities: int, results: Dict) -> str:
    """
    Calcula el nivel de riesgo basado en las vulnerabilidades encontradas
    """
    if total_vulnerabilities == 0:
        return "LOW"
    
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
        return "CRITICAL"
    elif high_severity_count > 0:
        return "HIGH"
    elif total_vulnerabilities > 3:
        return "MEDIUM"
    else:
        return "LOW"

def generate_detailed_report(scan: ScanResult) -> Dict:
    """
    Genera un reporte detallado del escaneo
    """
    risk_level = scan.risk_level or calculate_risk_level(scan.total_vulnerabilities, scan.results)
    
    # Usar vulnerabilidades procesadas si están disponibles
    if scan.vulnerabilities:
        vulnerabilities_by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for vuln in scan.vulnerabilities:
            severity = vuln.get("severity", "MEDIUM")
            if severity in vulnerabilities_by_severity:
                vulnerabilities_by_severity[severity].append(vuln)
    else:
        # Fallback al método original
        vulnerabilities_by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for scan_type, result in scan.results.items():
            if isinstance(result, dict) and "vulnerabilities" in result:
                for vuln in result["vulnerabilities"]:
                    severity = vuln.get("severity", "MEDIUM")
                    vuln["scan_type"] = scan_type
                    if severity in vulnerabilities_by_severity:
                        vulnerabilities_by_severity[severity].append(vuln)

    return {
        "scan_id": scan.scan_id,
        "url": scan.url,
        "risk_level": risk_level,
        "risk_score": scan.risk_score,
        "scan_duration": (scan.completed_at - scan.started_at).total_seconds() if scan.completed_at else 0,
        "summary": {
            "total_vulnerabilities": scan.total_vulnerabilities,
            "critical": len(vulnerabilities_by_severity["CRITICAL"]),
            "high": len(vulnerabilities_by_severity["HIGH"]),
            "medium": len(vulnerabilities_by_severity["MEDIUM"]),
            "low": len(vulnerabilities_by_severity["LOW"]),
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
    
    if vulnerabilities_by_severity["CRITICAL"] or vulnerabilities_by_severity["HIGH"]:
        recommendations.append("🚨 CRÍTICO: Resolver inmediatamente las vulnerabilidades de alta severidad")
        recommendations.append("🛡️ Implementar validación y sanitización de entrada de datos")
        recommendations.append("🔐 Usar prepared statements para consultas SQL")
        recommendations.append("🌐 Implementar Content Security Policy (CSP)")
    
    if vulnerabilities_by_severity["MEDIUM"]:
        recommendations.append("⚠️ Revisar y corregir vulnerabilidades de severidad media")
        recommendations.append("📋 Implementar headers de seguridad faltantes")
    
    recommendations.append("🔍 Realizar escaneos periódicos de seguridad")
    recommendations.append("👨💻 Capacitar al equipo de desarrollo en seguridad web")
    recommendations.append("📚 Seguir las mejores prácticas de OWASP")
    
    return recommendations

def generate_preview_recommendations(vulnerabilities):
    """Generar recomendaciones para la vista previa"""
    recommendations = []
    
    vuln_types = [vuln.get('type', '') for vuln in vulnerabilities]
    
    if any('XSS' in vtype for vtype in vuln_types):
        recommendations.extend([
            "Implementar Content Security Policy (CSP) headers",
            "Sanitizar todas las entradas de usuario"
        ])
    
    if any('SQL Injection' in vtype for vtype in vuln_types):
        recommendations.extend([
            "Usar prepared statements para consultas SQL",
            "Validar parámetros de entrada estrictamente"
        ])
    
    # Recomendaciones generales
    recommendations.extend([
        "Establecer programa regular de escaneos",
        "Implementar monitoreo continuo de seguridad"
    ])
    
    return recommendations[:5]  # Limitar a 5 recomendaciones

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
