from datetime import datetime, timezone

from fastapi import APIRouter

from vulnhunter.config import get_settings
from vulnhunter.scans.service import scan_service

router = APIRouter(tags=["system"])


@router.get("/")
async def root() -> dict:
    settings = get_settings()
    return {
        "message": settings.app_name,
        "version": settings.app_version,
        "docs": "/docs" if settings.docs_enabled else None,
        "scanners_available": scan_service.available_scanners,
        "endpoints": {
            "scan": "POST /scans",
            "results": "GET /scans/{scan_id}",
            "pdf": "GET /scans/{scan_id}/report.pdf",
            "list": "GET /scans",
            "stats": "GET /stats",
            "health": "GET /health",
        },
    }


@router.get("/health")
async def health_check() -> dict:
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc),
        "active_scans": scan_service.active_scan_count,
        "storage": "memory",
        "queue": "fastapi-background-tasks",
    }


@router.get("/stats")
async def statistics() -> dict:
    return scan_service.statistics()
