import uuid
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import FileResponse

from vulnhunter.config import get_settings
from vulnhunter.auth.dependencies import get_current_user, require_roles
from vulnhunter.database import crud
from vulnhunter.database.connection import SessionLocal, get_db
from vulnhunter.database.models import User, Website
from vulnhunter.security import normalize_role
from vulnhunter.scans.models import ReportInfo, ScanRequest, ScanSummary
from vulnhunter.scans.service import scan_service
from vulnhunter.tasks.dispatcher import enqueue_scan
from vulnhunter.websites.target_policy import TargetPolicyError, normalize_origin, validate_target

router = APIRouter(tags=["scans"])

# Los objetivos no registrados solo pueden someterse a comprobaciones que no
# envían payloads de explotación ni enumeran rutas. Los scanners activos siguen
# requiriendo una autorización de propiedad verificable.
PASSIVE_UNREGISTERED_SCANNERS = {"security_headers", "ssl_tls"}


@router.post("/scan", status_code=202, include_in_schema=False)
@router.post("/scans", status_code=202)
async def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
    db=Depends(get_db),
    current_user: User = Depends(require_roles("admin", "auditor")),
) -> dict:
    origin: str | None = None
    if request.website_id is not None:
        website = db.get(Website, request.website_id)
        if website is None:
            raise HTTPException(status_code=404, detail="Sitio registrado no encontrado")
    else:
        try:
            origin = normalize_origin(str(request.url))
        except TargetPolicyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        candidates = db.query(Website).filter(Website.url == origin).all()
        if len(candidates) > 1:
            raise HTTPException(status_code=409, detail="Usa website_id para identificar el sitio")
        website = candidates[0] if candidates else None

    website_id: int | None = None
    if website is not None:
        if not website.is_active:
            raise HTTPException(status_code=403, detail="El sitio registrado está desactivado")
        if website.verification_status == "verified":
            target = website.url
            website_id = website.id
        else:
            requested_scanners = set(request.scan_types)
            if not requested_scanners.issubset(PASSIVE_UNREGISTERED_SCANNERS):
                raise HTTPException(
                    status_code=403,
                    detail=(
                        "Mientras el sitio esté pendiente selecciona solamente Headers de seguridad "
                        "y SSL/TLS. Los scanners activos requieren autorización."
                    ),
                )
            target = website.url
    else:
        requested_scanners = set(request.scan_types)
        if not requested_scanners.issubset(PASSIVE_UNREGISTERED_SCANNERS):
            raise HTTPException(
                status_code=403,
                detail=(
                    "Para una página no registrada selecciona solamente Headers de seguridad "
                    "y SSL/TLS. XSS, SQL Injection y Directorios requieren autorización."
                ),
            )
        assert origin is not None
        target = origin

    try:
        target_url = validate_target(target)
    except TargetPolicyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        scan = scan_service.create_scan(
            request,
            target_url=target_url,
            website_id=website_id,
            requested_by_user_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    settings = get_settings()
    task_id: str | None = None
    execution_mode = "background"

    if settings.task_queue_enabled:
        execution_mode = "celery"
        task_id = str(uuid.uuid4())
        scan_service.register_task(scan.scan_id, task_id, execution_mode)
        try:
            enqueue_scan(scan.scan_id, task_id)
        except Exception as exc:
            scan_service.mark_failed(scan.scan_id, f"No fue posible publicar la tarea: {exc}")
            raise HTTPException(
                status_code=503,
                detail="La cola de escaneos no está disponible",
            ) from exc
    else:
        scan_service.register_task(scan.scan_id, None, execution_mode)
        background_tasks.add_task(scan_service.perform_scan_and_generate, scan.scan_id)

    return {
        "scan_id": scan.scan_id,
        "status": scan.status,
        "task_id": task_id,
        "execution_mode": execution_mode,
        "scanners_enabled": scan.scan_types,
        "check_status_url": f"/scans/{scan.scan_id}",
    }


@router.get("/scans", response_model=list[ScanSummary])
async def list_scans(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    status: Optional[str] = None,
    current_user: User = Depends(get_current_user),
) -> list[ScanSummary]:
    if normalize_role(current_user.role) in {"admin", "auditor"}:
        return scan_service.list_scans(limit=limit, offset=offset, status=status)
    db = SessionLocal()
    try:
        scans = crud.listar_scans_de_usuario(db, current_user.id)
        if status:
            scans = [scan for scan in scans if scan.status == status]
        return [scan_service._summary_from_database(scan) for scan in scans[offset:offset + limit]]
    finally:
        db.close()


@router.get("/scans/mios", response_model=list[ScanSummary])
async def list_my_scans(current_user: User = Depends(get_current_user)) -> list[ScanSummary]:
    db = SessionLocal()
    try:
        return [scan_service._summary_from_database(scan) for scan in crud.listar_scans_de_usuario(db, current_user.id)]
    finally:
        db.close()


@router.get("/scans/historial")
async def scan_history(
    url: str = Query(..., min_length=1),
    current_user: User = Depends(require_roles("admin", "auditor")),
) -> dict:
    db = SessionLocal()
    try:
        points = []
        for stored in crud.listar_scans_por_url(db, url):
            counts = {"crit": 0, "high": 0, "med": 0, "low": 0}
            for finding in stored.findings:
                key = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med"}.get(
                    finding.severity.upper(), "low"
                )
                counts[key] += 1
            points.append({
                "scan_id": stored.scan_id,
                "fecha": stored.completed_at or stored.started_at,
                "score": stored.risk_score or 0,
                "conteo": counts,
            })
        return {"url": url, "historial": points}
    finally:
        db.close()


@router.get("/scan/{scan_id}", include_in_schema=False)
@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str, current_user: User = Depends(get_current_user)) -> dict:
    if normalize_role(current_user.role) == "client":
        raise HTTPException(status_code=403, detail="El detalle técnico requiere rol auditor")
    _require_scan_access(scan_id, current_user)
    scan = scan_service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    return scan_service.serialize(scan)


@router.get("/scan/{scan_id}/pdf", include_in_schema=False)
@router.get("/scans/{scan_id}/report.pdf")
async def download_report(scan_id: str, current_user: User = Depends(get_current_user)) -> FileResponse:
    _require_scan_access(scan_id, current_user)
    scan = scan_service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    if scan.status not in {"completed", "partial"}:
        raise HTTPException(status_code=409, detail="El escaneo aún no ha terminado")

    try:
        path = scan_service.get_report_path(scan_id) or scan_service.generate_report(scan)
        scan_service.register_report_download(scan_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="No fue posible generar el reporte") from exc

    return FileResponse(path=path, filename=path.name, media_type="application/pdf")


@router.get("/scans/{scan_id}/report", response_model=ReportInfo)
async def report_information(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> ReportInfo:
    _require_scan_access(scan_id, current_user)
    if scan_service.get_scan(scan_id) is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    report = scan_service.get_report_info(scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Reporte aún no generado")
    return ReportInfo(**report)


def _require_scan_access(scan_id: str, current_user: User) -> None:
    db = SessionLocal()
    try:
        stored = crud.obtener_scan(db, scan_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="Escaneo no encontrado")
        role = normalize_role(current_user.role)
        if role in {"admin", "auditor"}:
            return
        owns_website = stored.website is not None and stored.website.user_id == current_user.id
        if not owns_website and stored.requested_by_user_id != current_user.id:
            raise HTTPException(status_code=403, detail="No puedes acceder a este escaneo")
    finally:
        db.close()
