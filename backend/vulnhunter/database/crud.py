# vulnhunter/database/crud.py
import json
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from vulnhunter.database.models import Scan, Finding


def crear_scan(db: Session, scan_id: str, url: str, scan_types: list[str]) -> Scan:
    """Guarda un escaneo nuevo en estado 'pending'."""
    nuevo = Scan(
        scan_id=scan_id,
        url=url,
        scan_types=json.dumps(scan_types),   # la lista se guarda como texto JSON
        status="pending",
        started_at=datetime.now(timezone.utc),
    )
    db.add(nuevo)
    db.commit()
    db.refresh(nuevo)
    return nuevo


def finalizar_scan(db: Session, scan_id: str, status: str,
                   total_vulnerabilities: int, risk_score: int,
                   risk_level: str) -> Scan | None:
    """Actualiza un escaneo cuando termina, con sus resultados finales."""
    scan = db.query(Scan).filter(Scan.scan_id == scan_id).first()
    if scan is None:
        return None
    scan.status = status
    scan.completed_at = datetime.now(timezone.utc)
    scan.total_vulnerabilities = total_vulnerabilities
    scan.risk_score = risk_score
    scan.risk_level = risk_level
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


def obtener_scan(db: Session, scan_id: str) -> Scan | None:
    """Devuelve un escaneo por su scan_id (UUID) o None si no existe."""
    return db.query(Scan).filter(Scan.scan_id == scan_id).first()


def listar_scans(db: Session, limit: int = 50, offset: int = 0) -> list[Scan]:
    """Lista escaneos, del más reciente al más antiguo."""
    return (
        db.query(Scan)
        .order_by(Scan.started_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


def listar_todos_scans(db: Session) -> list[Scan]:
    """Devuelve todos los escaneos (útil para /stats)."""
    return db.query(Scan).all()
