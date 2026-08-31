from fastapi import APIRouter
from .scans import scans_storage, PDF_AVAILABLE

router = APIRouter()

@router.get("/stats")
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
