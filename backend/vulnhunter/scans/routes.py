from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from fastapi.responses import FileResponse

from vulnhunter.scans.models import ScanRequest, ScanSummary
from vulnhunter.scans.service import scan_service

router = APIRouter(tags=["scans"])


@router.post("/scan", status_code=202, include_in_schema=False)
@router.post("/scans", status_code=202)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks) -> dict:
    try:
        scan = scan_service.create_scan(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    background_tasks.add_task(scan_service.perform_scan, scan.scan_id)
    return {
        "scan_id": scan.scan_id,
        "status": scan.status,
        "scanners_enabled": scan.scan_types,
        "check_status_url": f"/scans/{scan.scan_id}",
    }


@router.get("/scans", response_model=list[ScanSummary])
async def list_scans(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status: Optional[str] = None,
) -> list[ScanSummary]:
    return scan_service.list_scans(limit=limit, offset=offset, status=status)


@router.get("/scan/{scan_id}", include_in_schema=False)
@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str) -> dict:
    scan = scan_service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    return scan_service.serialize(scan)


@router.get("/scan/{scan_id}/pdf", include_in_schema=False)
@router.get("/scans/{scan_id}/report.pdf")
async def download_report(scan_id: str) -> FileResponse:
    scan = scan_service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    if scan.status not in {"completed", "partial"}:
        raise HTTPException(status_code=409, detail="El escaneo aún no ha terminado")

    try:
        path = scan_service.generate_report(scan)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="No fue posible generar el reporte") from exc

    return FileResponse(path=path, filename=path.name, media_type="application/pdf")
