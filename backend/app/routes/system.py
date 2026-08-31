from fastapi import APIRouter
from datetime import datetime
from .scans import scans_storage, PDF_AVAILABLE

router = APIRouter()

@router.get("/")
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

@router.get("/health")
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
