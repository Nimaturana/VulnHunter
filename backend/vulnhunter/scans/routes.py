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


# ---- Endpoint: "mis escaneos" ----
# Devuelve los escaneos guardados en la base que pertenecen a UN usuario.
# Se llama así: GET /scans/mios?user_id=5
# IMPORTANTE: debe ir ANTES de la ruta /scans/{scan_id}, porque si no,
# FastAPI pensaría que "mios" es un scan_id y respondería 404.
@router.get("/scans/mios", response_model=list[ScanSummary])
async def list_my_scans(user_id: int = Query(...)) -> list[ScanSummary]:
    # Importamos aquí dentro (y no arriba) para no tocar los imports del archivo.
    from vulnhunter.database.connection import SessionLocal
    from vulnhunter.database import crud

    db = SessionLocal()                                   # Abrimos una conexión a la base.
    try:
        # Pedimos a la base los escaneos de este usuario (función del crud.py).
        scans = crud.listar_scans_de_usuario(db, user_id=user_id)

        # Convertimos cada escaneo a su "versión resumida" (ScanSummary).
        return [
            ScanSummary(
                scan_id=s.scan_id,
                url=s.url,
                status=s.status,
                total_vulnerabilities=s.total_vulnerabilities or 0,
                risk_level=s.risk_level or "LOW",
                completed_at=s.completed_at,
            )
            for s in scans
        ]
    finally:
        db.close()                                        # Cerramos siempre la conexión.


# ---- Endpoint: historial de escaneos de una url (para la evolución) ----
# Devuelve todos los escaneos de un mismo sitio, del más antiguo al más reciente,
# con el conteo de hallazgos por severidad de cada uno.
# IMPORTANTE: va ANTES de /scans/{scan_id}, igual que /scans/mios.
# Se llama así: GET /scans/historial?url=https://mi-sitio.cl
@router.get("/scans/historial")
async def get_historial(url: str = Query(...)) -> dict:
    from vulnhunter.database.connection import SessionLocal
    from vulnhunter.database import crud

    db = SessionLocal()
    try:
        # Traemos los escaneos de esa url (ordenados del más antiguo al más nuevo).
        scans = crud.listar_scans_de_url(db, url)

        historial = []
        for s in scans:
            # Por cada escaneo, contamos sus hallazgos por severidad.
            findings = crud.obtener_findings_de_scan(db, s.scan_id)
            conteo = {"crit": 0, "high": 0, "med": 0, "low": 0}
            for f in findings:
                sev = (f.severity or "").upper()
                if sev == "CRITICAL":
                    conteo["crit"] += 1
                elif sev == "HIGH":
                    conteo["high"] += 1
                elif sev == "MEDIUM":
                    conteo["med"] += 1
                else:  # LOW e INFO se agrupan como "low".
                    conteo["low"] += 1

            historial.append({
                "scan_id": s.scan_id,
                "fecha": s.completed_at.isoformat() if s.completed_at else None,
                "score": s.risk_score or 0,
                "conteo": conteo,
            })

        return {"url": url, "historial": historial}
    finally:
        db.close()




@router.get("/scan/{scan_id}", include_in_schema=False)
@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str) -> dict:
    scan = scan_service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Escaneo no encontrado")
    return scan_service.serialize(scan)

# ---- Endpoint: detalle de un escaneo CON sus hallazgos (desde la base) ----
# Devuelve los datos del escaneo y la lista de vulnerabilidades encontradas.
# Lee desde PostgreSQL (no desde memoria), así que funciona aunque se reinicie el backend.
# Se llama así: GET /scans/{scan_id}/detalle
@router.get("/scans/{scan_id}/detalle")
async def get_scan_detalle(scan_id: str) -> dict:
    # Importamos aquí dentro para no tocar los imports de arriba.
    from vulnhunter.database.connection import SessionLocal
    from vulnhunter.database import crud

    db = SessionLocal()                                   # Abrimos conexión a la base.
    try:
        # Buscamos el escaneo por su scan_id público (UUID).
        scan = crud.obtener_scan(db, scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Escaneo no encontrado")

        # Traemos los hallazgos de ese escaneo desde la base.
        findings = crud.obtener_findings_de_scan(db, scan_id)

        # Armamos la respuesta con los datos del escaneo y sus hallazgos.
        return {
            "scan_id": scan.scan_id,
            "url": scan.url,
            "status": scan.status,
            "risk_level": scan.risk_level or "LOW",
            "risk_score": scan.risk_score or 0,
            "total_vulnerabilities": scan.total_vulnerabilities or 0,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            # Convertimos cada hallazgo a un diccionario simple para el frontend.
            "findings": [
                {
                    "type": f.type,
                    "severity": f.severity,
                    "location": f.location,
                    "scanner": f.scanner,
                    "description": f.description,
                    "recommendation": f.recommendation,
                    "confidence": f.confidence,
                }
                for f in findings
            ],
        }
    finally:
        db.close()                                        # Cerramos siempre la conexión.

# ---- Endpoint: historial de escaneos de una url (para la evolución) ----
# Devuelve todos los escaneos de un mismo sitio, del más antiguo al más reciente,
# con el conteo de hallazgos por severidad de cada uno.
# Se llama así: GET /scans/historial?url=https://mi-sitio.cl
@router.get("/scans/historial")
async def get_historial(url: str = Query(...)) -> dict:
    # Importamos aquí dentro para no tocar los imports de arriba.
    from vulnhunter.database.connection import SessionLocal
    from vulnhunter.database import crud

    db = SessionLocal()                                   # Abrimos conexión a la base.
    try:
        # Traemos los escaneos de esa url (ya ordenados del más antiguo al más nuevo).
        scans = crud.listar_scans_de_url(db, url)

        historial = []
        for s in scans:
            # Por cada escaneo, contamos sus hallazgos por severidad.
            findings = crud.obtener_findings_de_scan(db, s.scan_id)
            conteo = {"crit": 0, "high": 0, "med": 0, "low": 0}
            for f in findings:
                sev = (f.severity or "").upper()
                if sev == "CRITICAL":
                    conteo["crit"] += 1
                elif sev == "HIGH":
                    conteo["high"] += 1
                elif sev == "MEDIUM":
                    conteo["med"] += 1
                else:  # LOW e INFO se agrupan como "low".
                    conteo["low"] += 1

            historial.append({
                "scan_id": s.scan_id,
                "fecha": s.completed_at.isoformat() if s.completed_at else None,
                "score": s.risk_score or 0,
                "conteo": conteo,
            })

        return {"url": url, "historial": historial}
    finally:
        db.close()                                        # Cerramos siempre la conexión.




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
