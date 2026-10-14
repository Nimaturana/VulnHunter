# vulnhunter/database/crud.py
import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from vulnhunter.database.models import Finding, Report, Scan


def crear_scan(
    db: Session,
    scan_id: str,
    url: str,
    scan_types: list[str],
    *,
    website_id: int | None = None,
    requested_by_user_id: int | None = None,
    description: str | None = None,
) -> Scan:
    """Guarda un escaneo nuevo en estado 'pending'."""
    nuevo = Scan(
        scan_id=scan_id,
        url=url,
        website_id=website_id,
        requested_by_user_id=requested_by_user_id,
        description=description,
        scan_types=json.dumps(scan_types),
        status="pending",
        started_at=datetime.now(timezone.utc),
    )
    db.add(nuevo)
    db.commit()
    db.refresh(nuevo)
    return nuevo


def actualizar_progreso_scan(
    db: Session,
    scan_id: str,
    *,
    status: str,
    progress_percentage: int,
    current_scanner: str | None,
    errors: dict[str, str] | None = None,
) -> Scan | None:
    """Persiste el estado observable de un escaneo en ejecución."""
    scan = obtener_scan(db, scan_id)
    if scan is None:
        return None
    scan.status = status
    scan.progress_percentage = progress_percentage
    scan.current_scanner = current_scanner
    if errors is not None:
        scan.errors = json.dumps(errors)
    db.commit()
    db.refresh(scan)
    return scan


def finalizar_scan(
    db: Session,
    scan_id: str,
    status: str,
    total_vulnerabilities: int,
    risk_score: int,
    risk_level: str,
    errors: dict[str, str] | None = None,
) -> Scan | None:
    """Actualiza un escaneo cuando termina, con sus resultados finales."""
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if scan is None:
        return None
    scan.status = status
    scan.completed_at = datetime.now(timezone.utc)
    scan.total_vulnerabilities = total_vulnerabilities
    scan.risk_score = risk_score
    scan.risk_level = risk_level
    scan.progress_percentage = 100
    scan.current_scanner = None
    scan.errors = json.dumps(errors or {})
    db.commit()
    db.refresh(scan)
    return scan


def registrar_tarea(
    db: Session,
    scan_id: str,
    *,
    task_id: str | None,
    execution_mode: str,
) -> Scan | None:
    """Associate a scan with its execution mechanism and Celery task."""
    scan = obtener_scan(db, scan_id)
    if scan is None:
        return None
    scan.task_id = task_id
    scan.execution_mode = execution_mode
    scan.queued_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(scan)
    return scan


def marcar_inicio_worker(db: Session, scan_id: str) -> Scan | None:
    scan = obtener_scan(db, scan_id)
    if scan is None:
        return None
    scan.worker_started_at = datetime.now(timezone.utc)
    scan.status = "running"
    db.commit()
    db.refresh(scan)
    return scan


def marcar_scan_fallido(db: Session, scan_id: str, error_message: str) -> Scan | None:
    scan = obtener_scan(db, scan_id)
    if scan is None:
        return None
    scan.status = "failed"
    scan.completed_at = datetime.now(timezone.utc)
    scan.current_scanner = None
    scan.errors = json.dumps({"task": error_message})
    db.commit()
    db.refresh(scan)
    return scan


def guardar_findings(db: Session, scan_db_id: int, findings: list) -> None:
    """Inserta cada hallazgo del escaneo en la tabla findings."""
    for f in findings:
        registro = Finding(
            scan_id=scan_db_id,          # id interno del scan (no el scan_id UUID)
            type=f.type,
            severity=f.severity,
            location=f.location,
            scanner=f.scanner,
            description=f.description,
            recommendation=f.recommendation,
            evidence=f.evidence,
            confidence=f.confidence,
        )
        db.add(registro)
    db.commit()


def guardar_estado_reporte(
    db: Session,
    scan_id: str,
    *,
    status: str,
    file_name: str | None = None,
    storage_path: str | None = None,
    size_bytes: int | None = None,
    sha256: str | None = None,
    error_message: str | None = None,
) -> Report | None:
    scan = obtener_scan(db, scan_id)
    if scan is None:
        return None
    report = db.query(Report).filter(Report.scan_id == scan.id).first()
    if report is None:
        report = Report(scan_id=scan.id)
        db.add(report)
    report.status = status
    report.file_name = file_name
    report.storage_path = storage_path
    report.size_bytes = size_bytes
    report.sha256 = sha256
    report.error_message = error_message
    report.generated_at = datetime.now(timezone.utc) if status == "generated" else None
    db.commit()
    db.refresh(report)
    return report


def obtener_reporte(db: Session, scan_id: str) -> Report | None:
    return (
        db.query(Report)
        .join(Scan, Report.scan_id == Scan.id)
        .filter(Scan.scan_id == scan_id)
        .first()
    )


def registrar_descarga_reporte(db: Session, scan_id: str) -> Report | None:
    report = obtener_reporte(db, scan_id)
    if report is None:
        return None
    report.download_count += 1
    report.last_downloaded_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(report)
    return report


def obtener_scan(db: Session, scan_id: str) -> Scan | None:
    """Devuelve un escaneo por su scan_id (UUID) o None si no existe."""
    return db.query(Scan).filter(Scan.scan_id == scan_id).first()


def listar_scans(
    db: Session,
    limit: int = 50,
    offset: int = 0,
    status: str | None = None,
) -> list[Scan]:
    """Lista escaneos, del más reciente al más antiguo."""
    query = db.query(Scan)
    if status:
        query = query.filter(Scan.status == status)
    return query.order_by(Scan.started_at.desc()).offset(offset).limit(limit).all()


def listar_todos_scans(db: Session) -> list[Scan]:
    """Devuelve todos los escaneos (útil para /stats)."""
    return db.query(Scan).all()


def contar_scans_en_ejecucion(db: Session) -> int:
    return db.query(Scan).filter(Scan.status == "running").count()
