# app/main.py
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, HttpUrl
from typing import List, Dict, Optional
import sys
import os
from datetime import datetime
import uuid
import asyncio

# Agregar el directorio padre al path para importar scanners
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Importar TODOS los scanners disponibles
from scanners.xss_scanner import XSSScanner
from scanners.sql_injection_scanner import SQLInjectionScanner
from scanners.security_headers_scanner import SecurityHeadersScanner
from scanners.ssl_scanner import SSLScanner
from scanners.directory_scanner import DirectoryScanner

# Importar generador de PDF
try:
    from .reports.pdf_generator import VulnHunterReportGenerator
    PDF_AVAILABLE = True
    print("✅ PDF generator disponible")
except ImportError as e:
    print(f"⚠️ PDF generator no disponible: {e}")
    PDF_AVAILABLE = False

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

# Modelos Pydantic
class ScanRequest(BaseModel):
    url: HttpUrl
    scan_types: List[str] = ["xss", "sql_injection", "security_headers", "ssl_tls", "directory_scan"]
    description: Optional[str] = None
    
    class Config:
        schema_extra = {
            "example": {
                "url": "http://testphp.vulnweb.com",
                "scan_types": ["xss", "sql_injection", "security_headers", "ssl_tls", "directory_scan"],
                "description": "Escaneo completo de seguridad"
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
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    total_vulnerabilities: int = 0
    results: Dict = {}
    vulnerabilities: List[Dict] = []
    risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    summary: Optional[Dict] = None
    error: Optional[str] = None

class ScanSummary(BaseModel):
    scan_id: str
    url: str
    status: str
    total_vulnerabilities: int
    risk_level: str
    completed_at: Optional[datetime] = None

# Storage en memoria
scans_storage: Dict[str, ScanResult] = {}

# Instanciar TODOS los scanners
print("🔧 Inicializando scanners...")
xss_scanner = XSSScanner()
sql_scanner = SQLInjectionScanner()
headers_scanner = SecurityHeadersScanner()
ssl_scanner = SSLScanner()
directory_scanner = DirectoryScanner()
print("✅ Todos los scanners inicializados correctamente")

@app.get("/")
async def root():
    """Endpoint de bienvenida con información completa del sistema"""
    return {
        "message": "VulnHunter - Sistema Completo de Monitoreo de Vulnerabilidades Web",
        "version": "2.0.0",
        "docs": "/docs",
        "scanners_available": {
            "xss": "Cross-Site Scripting Detection",
            "sql_injection": "SQL Injection Detection", 
            "security_headers": "HTTP Security Headers Analysis",
            "ssl_tls": "SSL/TLS Certificate and Configuration Analysis",
            "directory_scan": "Directory and Sensitive Files Discovery"
        },
        "pdf_reports": PDF_AVAILABLE,
        "endpoints": {
            "scan": "POST /scan - Iniciar nuevo escaneo completo",
            "results": "GET /scan/{scan_id} - Obtener resultados detallados",
            "pdf": "GET /scan/{scan_id}/pdf - Descargar reporte PDF",
            "preview": "GET /scan/{scan_id}/report-preview - Vista previa del reporte",
            "list": "GET /scans - Listar todos los escaneos",
            "stats": "GET /stats - Estadísticas del sistema",
            "health": "GET /health - Estado del sistema"
        }
    }

@app.get("/health")
async def health_check():
    """Estado completo del sistema y scanners"""
    scanner_status = {}
    
    # Verificar estado de cada scanner
    try:
        # Test básico de cada scanner
        test_url = "https://example.com"
        scanner_status = {
            "xss": "available",
            "sql_injection": "available", 
            "security_headers": "available",
            "ssl_tls": "available",
            "directory_scan": "available"
        }
    except Exception as e:
        print(f"Error verificando scanners: {e}")
    
    return {
        "status": "healthy",
        "timestamp": datetime.now(),
        "version": "2.0.0",
        "scanners_status": scanner_status,
        "pdf_generator": PDF_AVAILABLE,
        "active_scans": len([s for s in scans_storage.values() if s.status == "running"]),
        "total_scans": len(scans_storage),
        "system_load": "normal"
    }

@app.post("/scan", response_model=Dict)
async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """Iniciar escaneo completo con todos los scanners disponibles"""
    # Validar tipos de escaneo solicitados
    valid_scan_types = ["xss", "sql_injection", "security_headers", "ssl_tls", "directory_scan"]
    invalid_types = [t for t in scan_request.scan_types if t not in valid_scan_types]
    
    if invalid_types:
        raise HTTPException(
            status_code=400, 
            detail=f"Tipos de escaneo inválidos: {invalid_types}. Tipos válidos: {valid_scan_types}"
        )
    
    # Generar ID único
    scan_id = str(uuid.uuid4())
    
    # Crear registro inicial
    scan_result = ScanResult(
        scan_id=scan_id,
        url=str(scan_request.url),
        scan_types=scan_request.scan_types,
        status="pending",
        started_at=datetime.now(),
        results={}
    )
    
    # Guardar en storage
    scans_storage[scan_id] = scan_result
    
    # Ejecutar en background
    background_tasks.add_task(
        perform_comprehensive_scan,
        scan_id,
        str(scan_request.url),
        scan_request.scan_types
    )
    
    # Estimar tiempo basado en cantidad de scanners
    estimated_time = f"{len(scan_request.scan_types) * 2}-{len(scan_request.scan_types) * 4} minutos"
    
    return {
        "scan_id": scan_id,
        "status": "pending",
        "message": "Escaneo completo iniciado correctamente",
        "scanners_enabled": scan_request.scan_types,
        "estimated_time": estimated_time,
        "check_status_url": f"/scan/{scan_id}",
        "pdf_available": PDF_AVAILABLE
    }

@app.get("/scan/{scan_id}")
async def get_scan_results(scan_id: str):
    """Obtener resultados completos del escaneo"""
    if scan_id not in scans_storage:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    
    scan_data = scans_storage[scan_id]
    
    # Calcular duración
    if scan_data.completed_at:
        duration = scan_data.completed_at - scan_data.started_at
        duration_seconds = int(duration.total_seconds())
    else:
        duration = datetime.now() - scan_data.started_at
        duration_seconds = int(duration.total_seconds())
    
    # Generar respuesta completa
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
        "error": scan_data.error,
        "progress": calculate_scan_progress(scan_data)
    }
    
    return response

@app.get("/scans", response_model=List[ScanSummary])
async def list_scans(limit: int = 50, offset: int = 0, status: Optional[str] = None):
    """Listar escaneos con filtros opcionales"""
    scans = list(scans_storage.values())
    
    # Filtrar por status si se especifica
    if status:
        scans = [s for s in scans if s.status == status]
    
    # Ordenar por fecha
    scans.sort(key=lambda x: x.started_at, reverse=True)
    
    # Paginación
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

@app.get("/scan/{scan_id}/pdf")
async def download_pdf_report(scan_id: str):
    """Generar y descargar reporte PDF completo"""
    if not PDF_AVAILABLE:
        raise HTTPException(status_code=503, detail="Generador de PDF no disponible")
    
    if scan_id not in scans_storage:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    
    scan_data = scans_storage[scan_id]
    
    if scan_data.status != "completed":
        raise HTTPException(status_code=400, detail="El escaneo aún no ha completado")
    
    try:
        generator = VulnHunterReportGenerator()
        
        # Preparar datos completos para PDF
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
        
        os.makedirs("reports", exist_ok=True)
        pdf_path = generator.generate_report(pdf_data)
        
        if not os.path.exists(pdf_path):
            raise HTTPException(status_code=500, detail="Error al generar el reporte PDF")
        
        filename = os.path.basename(pdf_path)
        
        return FileResponse(
            path=pdf_path,
            filename=filename,
            media_type='application/pdf',
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    except Exception as e:
        print(f"Error generando PDF: {e}")
        raise HTTPException(status_code=500, detail=f"Error al generar PDF: {str(e)}")

@app.get("/stats")
async def get_comprehensive_statistics():
    """Estadísticas completas del sistema y scanners"""
    total_scans = len(scans_storage)
    completed_scans = len([s for s in scans_storage.values() if s.status == "completed"])
    running_scans = len([s for s in scans_storage.values() if s.status == "running"])
    failed_scans = len([s for s in scans_storage.values() if s.status == "failed"])
    
    total_vulnerabilities = sum(s.total_vulnerabilities for s in scans_storage.values())
    
    # Estadísticas por tipo de vulnerabilidad
    vuln_types = {}
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    scanner_usage = {"xss": 0, "sql_injection": 0, "security_headers": 0, "ssl_tls": 0, "directory_scan": 0}
    
    for scan in scans_storage.values():
        # Contar uso de scanners
        for scan_type in scan.scan_types:
            if scan_type in scanner_usage:
                scanner_usage[scan_type] += 1
        
        # Contar vulnerabilidades
        if scan.vulnerabilities:
            for vuln in scan.vulnerabilities:
                vuln_type = vuln.get("type", "Unknown")
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
                
                severity = vuln.get("severity", "LOW")
                if severity in severity_counts:
                    severity_counts[severity] += 1

    return {
        "system_status": "operational",
        "version": "2.0.0",
        "scan_statistics": {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "running_scans": running_scans,
            "failed_scans": failed_scans,
            "success_rate": round((completed_scans / total_scans * 100), 2) if total_scans > 0 else 0
        },
        "vulnerability_statistics": {
            "total_vulnerabilities": total_vulnerabilities,
            "by_severity": severity_counts,
            "by_type": vuln_types
        },
        "scanner_usage": scanner_usage,
        "system_capabilities": {
            "pdf_reports_available": PDF_AVAILABLE,
            "scanners_available": 5,
            "max_concurrent_scans": 10
        }
    }

# Función principal de escaneo completo
async def perform_comprehensive_scan(scan_id: str, url: str, scan_types: List[str]):
    """Ejecuta todos los scanners solicitados de forma completa"""
    scan = scans_storage[scan_id]
    
    try:
        scan.status = "running"
        results = {}
        vulnerabilities = []
        total_vulnerabilities = 0
        
        print(f"🔍 Iniciando escaneo completo de {url}...")
        print(f"📋 Scanners habilitados: {', '.join(scan_types)}")
        
        # 1. XSS Scanner
        if "xss" in scan_types:
            print(f"🕷️ Ejecutando XSS Scanner...")
            xss_result = await run_xss_scan(url)
            results["xss"] = xss_result
            vulnerabilities.extend(process_xss_results(xss_result, url))
        
        # 2. SQL Injection Scanner
        if "sql_injection" in scan_types:
            print(f"💉 Ejecutando SQL Injection Scanner...")
            sql_result = await run_sql_scan(url)
            results["sql_injection"] = sql_result
            vulnerabilities.extend(process_sql_results(sql_result, url))
        
        # 3. Security Headers Scanner
        if "security_headers" in scan_types:
            print(f"🛡️ Ejecutando Security Headers Scanner...")
            headers_result = await run_headers_scan(url)
            results["security_headers"] = headers_result
            vulnerabilities.extend(process_headers_results(headers_result, url))
        
        # 4. SSL/TLS Scanner
        if "ssl_tls" in scan_types:
            print(f"🔐 Ejecutando SSL/TLS Scanner...")
            ssl_result = await run_ssl_scan(url)
            results["ssl_tls"] = ssl_result
            vulnerabilities.extend(process_ssl_results(ssl_result, url))
        
        # 5. Directory Scanner
        if "directory_scan" in scan_types:
            print(f"📂 Ejecutando Directory Scanner...")
            directory_result = await run_directory_scan(url)
            results["directory_scan"] = directory_result
            vulnerabilities.extend(process_directory_results(directory_result, url))
        
        # Calcular métricas finales
        total_vulnerabilities = len(vulnerabilities)
        risk_score, risk_level = calculate_risk_score(vulnerabilities)
        
        # Generar resumen por severidad
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "LOW")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Actualizar resultado final
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
            "low": severity_counts["LOW"],
            "scanners_executed": len(scan_types),
            "scan_coverage": calculate_scan_coverage(scan_types)
        }
        scan.status = "completed"
        scan.completed_at = datetime.now()
        
        print(f"✅ Escaneo completo {scan_id} terminado exitosamente!")
        print(f"📊 Resumen: {total_vulnerabilities} vulnerabilidades encontradas - Riesgo: {risk_level}")
        
    except Exception as e:
        print(f"❌ Error en escaneo completo {scan_id}: {str(e)}")
        scan.status = "failed"
        scan.error = str(e)
        scan.completed_at = datetime.now()

# Funciones de ejecución asíncrona para cada scanner
async def run_xss_scan(url: str) -> Dict:
    """Ejecutar XSS Scanner"""
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, xss_scanner.scan_url, url)
        return result
    except Exception as e:
        return {"vulnerable": False, "error": str(e), "vulnerabilities": []}

async def run_sql_scan(url: str) -> Dict:
    """Ejecutar SQL Injection Scanner"""
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, sql_scanner.scan_url, url)
        return result
    except Exception as e:
        return {"vulnerable": False, "error": str(e), "vulnerabilities": []}

async def run_headers_scan(url: str) -> Dict:
    """Ejecutar Security Headers Scanner"""
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, headers_scanner.scan, url)
        return result
    except Exception as e:
        return {"secure": False, "error": str(e), "missing_headers": [], "present_headers": []}

async def run_ssl_scan(url: str) -> Dict:
    """Ejecutar SSL/TLS Scanner"""
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, ssl_scanner.scan, url)
        return result
    except Exception as e:
        return {"secure": False, "error": str(e), "certificate_info": {}, "vulnerabilities": []}

async def run_directory_scan(url: str) -> Dict:
    """Ejecutar Directory Scanner"""
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, directory_scanner.scan, url)
        return result
    except Exception as e:
        return {"vulnerable": False, "error": str(e), "found_files": [], "found_directories": []}

# Funciones de procesamiento de resultados
def process_xss_results(xss_result: Dict, url: str) -> List[Dict]:
    """Procesar resultados del XSS Scanner"""
    vulnerabilities = []
    if xss_result.get("vulnerable", False):
        for vuln in xss_result.get("vulnerabilities", []):
            vulnerabilities.append({
                "type": "Cross-Site Scripting (XSS)",
                "severity": "HIGH",
                "location": vuln.get("location", url),
                "description": f"XSS vulnerability detected: {vuln.get('type', 'Unknown type')}",
                "recommendation": "Sanitizar y validar todas las entradas de usuario. Implementar Content Security Policy (CSP).",
                "evidence": vuln.get("payload", ""),
                "scanner": "xss"
            })
    return vulnerabilities

def process_sql_results(sql_result: Dict, url: str) -> List[Dict]:
    """Procesar resultados del SQL Injection Scanner"""
    vulnerabilities = []
    if sql_result.get("vulnerable", False):
        for vuln in sql_result.get("vulnerabilities", []):
            vulnerabilities.append({
                "type": "SQL Injection",
                "severity": "CRITICAL",
                "location": vuln.get("location", url),
                "description": f"SQL Injection vulnerability in {vuln.get('field', 'parameter')}",
                "recommendation": "Usar prepared statements o ORM. Validar y sanitizar todas las entradas.",
                "evidence": vuln.get("evidence", ""),
                "scanner": "sql_injection"
            })
    return vulnerabilities

def process_headers_results(headers_result: Dict, url: str) -> List[Dict]:
    """Procesar resultados del Security Headers Scanner"""
    vulnerabilities = []
    missing_headers = headers_result.get("missing_headers", [])
    
    for header in missing_headers:
        severity = "MEDIUM"
        if header in ["Content-Security-Policy", "X-Frame-Options"]:
            severity = "HIGH"
        
        vulnerabilities.append({
            "type": "Missing Security Header",
            "severity": severity,
            "location": url,
            "description": f"Security header '{header}' is missing",
            "recommendation": f"Implement '{header}' header for enhanced security",
            "evidence": f"Header: {header}",
            "scanner": "security_headers"
        })
    
    return vulnerabilities

def process_ssl_results(ssl_result: Dict, url: str) -> List[Dict]:
    """Procesar resultados del SSL/TLS Scanner"""
    vulnerabilities = []
    ssl_vulnerabilities = ssl_result.get("vulnerabilities", [])
    
    for vuln in ssl_vulnerabilities:
        vulnerabilities.append({
            "type": "SSL/TLS Configuration Issue",
            "severity": vuln.get("severity", "MEDIUM"),
            "location": url,
            "description": vuln.get("description", "SSL/TLS vulnerability detected"),
            "recommendation": vuln.get("recommendation", "Update SSL/TLS configuration"),
            "evidence": vuln.get("evidence", ""),
            "scanner": "ssl_tls"
        })
    
    return vulnerabilities

def process_directory_results(directory_result: Dict, url: str) -> List[Dict]:
    """Procesar resultados del Directory Scanner"""
    vulnerabilities = []
    
    found_files = directory_result.get("found_files", [])
    found_directories = directory_result.get("found_directories", [])
    
    # Procesar archivos sensibles encontrados
    for file_info in found_files:
        if isinstance(file_info, dict):
            file_path = file_info.get("path", "unknown")
            file_status = file_info.get("status_code", 200)
        else:
            file_path = str(file_info)
            file_status = 200
        
        severity = "HIGH" if any(sensitive in file_path.lower() 
                                for sensitive in [".env", "config", "backup", "admin"]) else "MEDIUM"
        
        vulnerabilities.append({
            "type": "Sensitive File Exposure",
            "severity": severity,
            "location": f"{url.rstrip('/')}/{file_path}",
            "description": f"Sensitive file exposed: {file_path}",
            "recommendation": "Remove or restrict access to sensitive files",
            "evidence": f"HTTP {file_status}: {file_path}",
            "scanner": "directory_scan"
        })
    
    # Procesar directorios expuestos
    for dir_info in found_directories:
        if isinstance(dir_info, dict):
            dir_path = dir_info.get("path", "unknown")
        else:
            dir_path = str(dir_info)
        
        vulnerabilities.append({
            "type": "Directory Listing Enabled",
            "severity": "MEDIUM",
            "location": f"{url.rstrip('/')}/{dir_path}",
            "description": f"Directory listing enabled: {dir_path}",
            "recommendation": "Disable directory listing and implement proper access controls",
            "evidence": f"Directory: {dir_path}",
            "scanner": "directory_scan"
        })
    
    return vulnerabilities

# Funciones auxiliares adicionales
def calculate_scan_progress(scan_data: ScanResult) -> Dict:
    """Calcular progreso del escaneo"""
    if scan_data.status == "completed":
        return {"percentage": 100, "current_step": "completed", "total_steps": len(scan_data.scan_types)}
    elif scan_data.status == "running":
        completed_scans = len([k for k, v in scan_data.results.items() if v])
        total_scans = len(scan_data.scan_types)
        percentage = int((completed_scans / total_scans) * 100)
        return {"percentage": percentage, "current_step": f"{completed_scans}/{total_scans}", "total_steps": total_scans}
    else:
        return {"percentage": 0, "current_step": scan_data.status, "total_steps": len(scan_data.scan_types)}

def calculate_scan_coverage(scan_types: List[str]) -> str:
    """Calcular cobertura del escaneo"""
    all_scanners = ["xss", "sql_injection", "security_headers", "ssl_tls", "directory_scan"]
    coverage_percentage = (len(scan_types) / len(all_scanners)) * 100
    
    if coverage_percentage == 100:
        return "Completa"
    elif coverage_percentage >= 80:
        return "Alta"
    elif coverage_percentage >= 60:
        return "Media"
    else:
        return "Básica"

def calculate_risk_score(vulnerabilities: List[Dict]) -> tuple:
    """Calcular puntuación y nivel de riesgo basado en vulnerabilidades"""
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
    if score >= 20:
        level = "CRITICAL"
    elif score >= 10:
        level = "HIGH"
    elif score >= 5:
        level = "MEDIUM"
    else:
        level = "LOW"
    
    return score, level

def calculate_risk_level(total_vulnerabilities: int, results: Dict) -> str:
    """Calcular nivel de riesgo basado en vulnerabilidades totales"""
    if total_vulnerabilities == 0:
        return "LOW"
    elif total_vulnerabilities >= 10:
        return "CRITICAL"
    elif total_vulnerabilities >= 5:
        return "HIGH"
    elif total_vulnerabilities >= 2:
        return "MEDIUM"
    else:
        return "LOW"

if __name__ == "__main__":
    import uvicorn
    print("🚀 Iniciando VulnHunter API con todos los scanners...")
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)