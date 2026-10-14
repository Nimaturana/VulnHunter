import asyncio
import hashlib
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vulnhunter.config import get_settings
from vulnhunter.database import crud
from vulnhunter.database.connection import SessionLocal
from vulnhunter.reports.pdf_generator import VulnHunterReportGenerator
from vulnhunter.scanners.directory_scanner import DirectoryScanner
from vulnhunter.scanners.security_headers_scanner import SecurityHeadersScanner
from vulnhunter.scanners.sql_injection_scanner import SQLInjectionScanner
from vulnhunter.scanners.ssl_scanner import SSLScanner
from vulnhunter.scanners.xss_scanner import XSSScanner
from vulnhunter.scans.models import Finding, Scan, ScanRequest, ScanSummary
from vulnhunter.scans.risk import calculate_risk

SCANNER_FACTORIES = {
    "xss": (XSSScanner, "scan_url"),
    "sql_injection": (SQLInjectionScanner, "scan_url"),
    "security_headers": (SecurityHeadersScanner, "scan"),
    "ssl_tls": (SSLScanner, "scan"),
    "directory_scan": (DirectoryScanner, "scan"),
}

SCANNER_LABELS = {
    "xss": "XSS Scanner",
    "sql_injection": "SQL Injection Scanner",
    "security_headers": "Security Headers Scanner",
    "ssl_tls": "SSL/TLS Scanner",
    "directory_scan": "Directory Scanner",
}

logger = logging.getLogger("uvicorn.error")


def _progress_bar(percentage: int, width: int = 24) -> str:
    filled = round(width * percentage / 100)
    return f"[{'█' * filled}{'░' * (width - filled)}] {percentage:>3}%"


def _format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.2f} s"
    minutes, remaining_seconds = divmod(seconds, 60)
    return f"{int(minutes)} min {remaining_seconds:04.1f} s"


def _console_block(*lines: str) -> None:
    """Render human-friendly scan progress without Uvicorn's INFO prefix."""
    print(f"\n{'\n'.join(lines)}", flush=True)


class ScanService:
    """Coordinate scans with PostgreSQL persistence and an in-memory fallback."""

    def __init__(self) -> None:
        self._scans: dict[str, Scan] = {}

    @property
    def available_scanners(self) -> list[str]:
        return list(SCANNER_FACTORIES)

    @property
    def active_scan_count(self) -> int:
        db = SessionLocal()
        try:
            return crud.contar_scans_en_ejecucion(db)
        except Exception:
            return sum(scan.status == "running" for scan in self._scans.values())
        finally:
            db.close()
    
    def create_scan(self, request: ScanRequest) -> Scan:
        invalid = sorted(set(request.scan_types) - set(SCANNER_FACTORIES))
        if invalid:
            raise ValueError(f"Tipos de escaneo inválidos: {', '.join(invalid)}")
        if not request.scan_types:
            raise ValueError("Debe seleccionarse al menos un scanner")

        scan = Scan(
            scan_id=str(uuid.uuid4()),
            url=str(request.url),
            scan_types=list(dict.fromkeys(request.scan_types)),
            started_at=datetime.now(timezone.utc),
        )
        self._scans[scan.scan_id] = scan

        # Guardar el escaneo en la base de datos (estado inicial)-CR
        db = SessionLocal()
        try:
            crud.crear_scan(
                db,
                scan_id=scan.scan_id,
                url=scan.url,
                scan_types=scan.scan_types,
                description=request.description,
            )
        except Exception:
            logger.exception("No se pudo guardar el escaneo en la base de datos")
        finally:
            db.close()
        return scan


    async def perform_scan(self, scan_id: str) -> None:
        scan = self.get_scan(scan_id)
        if scan is None:
            raise ValueError(f"Escaneo no encontrado: {scan_id}")
        self._scans[scan_id] = scan
        scan.status = "running"
        scan.worker_started_at = datetime.now(timezone.utc)
        total_scanners = len(scan.scan_types)
        total_started = time.perf_counter()
        scan_tag = f"SCAN {scan.scan_id[:8]}"

        db = SessionLocal()
        try:
            crud.marcar_inicio_worker(db, scan.scan_id)
        finally:
            db.close()
        self._persist_progress(scan)

        _console_block(
            "╔══════════════════════════════════════════════════════════════════════╗",
            f"║              VULNHUNTER · NUEVO ESCANEO · {scan_tag:<13}       ║",
            "╠══════════════════════════════════════════════════════════════════════╣",
            f"║ ID       : {scan.scan_id}",
            f"║ Objetivo : {scan.url}",
            f"║ Scanners : {total_scanners} ({', '.join(scan.scan_types)})",
            f"║ Progreso : {_progress_bar(0)}",
            "╚══════════════════════════════════════════════════════════════════════╝",
        )

        for index, scanner_name in enumerate(scan.scan_types, start=1):
            scanner_type, method_name = SCANNER_FACTORIES[scanner_name]
            scanner = scanner_type()
            method = getattr(scanner, method_name)
            scanner_label = SCANNER_LABELS.get(scanner_name, scanner_name)
            scanner_started = time.perf_counter()
            scan.current_scanner = scanner_name
            self._persist_progress(scan)

            _console_block(
                f"┌─ [{scan_tag}] SCANNER {index}/{total_scanners} · {scanner_label}",
                "│ Estado   : ejecutando",
                f"│ Objetivo : {scan.url}",
                "└─ Esperando resultado...",
            )
            try:
                raw_result = await asyncio.to_thread(method, scan.url)
                scan.results[scanner_name] = raw_result
                new_findings = self._normalize_findings(scanner_name, raw_result, scan.url)
                scan.findings.extend(new_findings)
                scanner_duration = time.perf_counter() - scanner_started
                if raw_result.get("error"):
                    scan.errors[scanner_name] = str(raw_result["error"])
                    _console_block(
                        f"┌─ [{scan_tag}] ⚠ {scanner_label} · ADVERTENCIA",
                        f"│ Duración : {_format_duration(scanner_duration)}",
                        f"│ Detalle  : {raw_result['error']}",
                        "└─ El escaneo continuará con el siguiente scanner.",
                    )
                else:
                    _console_block(
                        f"┌─ [{scan_tag}] ✓ {scanner_label} · COMPLETADO",
                        f"│ Duración  : {_format_duration(scanner_duration)}",
                        f"│ Hallazgos : {len(new_findings)}",
                        "└─ Resultado incorporado al análisis.",
                    )
            except Exception as exc:
                scan.errors[scanner_name] = str(exc)
                scan.results[scanner_name] = {"error": str(exc), "vulnerabilities": []}
                scanner_duration = time.perf_counter() - scanner_started
                logger.exception(
                    "[%d/%d] ✗ %s falló después de %.2fs",
                    index,
                    total_scanners,
                    scanner_label,
                    scanner_duration,
                )

            scan.progress_percentage = int(index / total_scanners * 100)
            self._persist_progress(scan)
            _console_block(
                f"[{scan_tag}] PROGRESO  {_progress_bar(scan.progress_percentage)}",
                f"          {index}/{total_scanners} scanners · {len(scan.findings)} hallazgo(s) acumulado(s)",
            )

        scan.risk_score, scan.risk_level = calculate_risk(
            [finding.severity for finding in scan.findings]
        )
        scan.completed_at = datetime.now(timezone.utc)
        scan.status = "partial" if scan.errors else "completed"
        scan.current_scanner = None
        scan.progress_percentage = 100
        
        # Guardar los resultados finales en la base de datos-CR
        db = SessionLocal()
        try:
            scan_db = crud.finalizar_scan(
                db,
                scan_id=scan.scan_id,
                status=scan.status,
                total_vulnerabilities=len(scan.findings),
                risk_score=scan.risk_score,
                risk_level=scan.risk_level,
                errors=scan.errors,
            )
            if scan_db is not None:
                crud.guardar_findings(db, scan_db.id, scan.findings)
        except Exception:
            logger.exception("No se pudieron guardar los resultados en la base de datos")
        finally:
            db.close()


        severity_counts = {
            severity: sum(finding.severity == severity for finding in scan.findings)
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        }
        total_duration = time.perf_counter() - total_started
        if scan.errors:
            logger.warning("Scanners con advertencias: %s", ", ".join(scan.errors))

        _console_block(
            "╔══════════════════════════════════════════════════════════════════════╗",
            f"║              ✓ ESCANEO FINALIZADO · {scan_tag:<13}              ║",
            "╠══════════════════════════════════════════════════════════════════════╣",
            f"║ Estado    : {scan.status.upper()}",
            f"║ Duración  : {_format_duration(total_duration)}",
            f"║ Hallazgos : {len(scan.findings)}",
            f"║ Severidad : {severity_counts['CRITICAL']} críticos · {severity_counts['HIGH']} altos · "
            f"{severity_counts['MEDIUM']} medios · {severity_counts['LOW']} bajos",
            f"║ Riesgo    : {scan.risk_level} ({scan.risk_score}/100)",
            f"║ Progreso  : {_progress_bar(100)}",
            "╠══════════════════════════════════════════════════════════════════════╣",
            f"║ PDF       : /scans/{scan.scan_id}/report.pdf",
            "╚══════════════════════════════════════════════════════════════════════╝",
        )

    async def perform_scan_and_generate(self, scan_id: str) -> Path | None:
        """Run every scanner and persist the automatically generated report."""
        self._persist_report(scan_id, status="generating")
        try:
            await self.perform_scan(scan_id)
            completed_scan = self.get_scan(scan_id)
            if completed_scan is None or completed_scan.status not in {"completed", "partial"}:
                return None
            return self.generate_report(completed_scan)
        except Exception as exc:
            self._persist_report(scan_id, status="failed", error_message=str(exc))
            raise

    def register_task(self, scan_id: str, task_id: str | None, execution_mode: str) -> None:
        in_memory = self._scans.get(scan_id)
        if in_memory is not None:
            in_memory.task_id = task_id
            in_memory.execution_mode = execution_mode
            in_memory.queued_at = datetime.now(timezone.utc)

        db = SessionLocal()
        try:
            crud.registrar_tarea(
                db,
                scan_id,
                task_id=task_id,
                execution_mode=execution_mode,
            )
        finally:
            db.close()

    def mark_failed(self, scan_id: str, error_message: str) -> None:
        in_memory = self._scans.get(scan_id)
        if in_memory is not None:
            in_memory.status = "failed"
            in_memory.completed_at = datetime.now(timezone.utc)
            in_memory.errors = {"task": error_message}
            in_memory.current_scanner = None

        db = SessionLocal()
        try:
            crud.marcar_scan_fallido(db, scan_id, error_message)
        finally:
            db.close()

    @staticmethod
    def _persist_progress(scan: Scan) -> None:
        """Best-effort persistence; a temporary DB failure must not abort a scan."""
        db = SessionLocal()
        try:
            crud.actualizar_progreso_scan(
                db,
                scan.scan_id,
                status=scan.status,
                progress_percentage=scan.progress_percentage,
                current_scanner=scan.current_scanner,
                errors=scan.errors,
            )
        except Exception:
            db.rollback()
            logger.exception("No se pudo actualizar el progreso en la base de datos")
        finally:
            db.close()

    def get_scan(self, scan_id: str) -> Scan | None:
        db = SessionLocal()
        try:
            stored = crud.obtener_scan(db, scan_id)
            if stored is not None:
                return self._scan_from_database(stored)
        except Exception:
            logger.warning(
                "No se pudo consultar el escaneo en PostgreSQL; se usará la memoria",
                exc_info=True,
            )
        finally:
            db.close()
        return self._scans.get(scan_id)

    def list_scans(self, limit: int, offset: int, status: str | None) -> list[ScanSummary]:
        db = SessionLocal()
        try:
            stored_scans = crud.listar_scans(
                db,
                limit=limit,
                offset=offset,
                status=status,
            )
            return [self._summary_from_database(scan) for scan in stored_scans]
        except Exception:
            logger.warning(
                "No se pudo listar desde PostgreSQL; se usará la memoria temporal",
                exc_info=True,
            )
        finally:
            db.close()

        scans = list(self._scans.values())
        if status:
            scans = [scan for scan in scans if scan.status == status]
        scans.sort(key=lambda item: item.started_at, reverse=True)
        return [self._summary_from_scan(scan) for scan in scans[offset : offset + limit]]

    def serialize(self, scan: Scan) -> dict[str, Any]:
        data = scan.model_dump(mode="json")
        data["vulnerabilities"] = data.pop("findings")
        data["total_vulnerabilities"] = len(scan.findings)
        total = max(len(scan.scan_types), 1)
        completed_scanners = (
            total
            if scan.status in {"completed", "partial"}
            else min(round(total * scan.progress_percentage / 100), total)
        )
        data["progress"] = {
            "percentage": scan.progress_percentage,
            "completed_scanners": completed_scanners,
            "total_scanners": total,
            "current_scanner": scan.current_scanner,
        }
        return data

    def statistics(self) -> dict[str, Any]:
        storage = "postgresql"
        db = SessionLocal()
        try:
            scans = [self._scan_from_database(scan) for scan in crud.listar_todos_scans(db)]
        except Exception:
            logger.warning(
                "No se pudieron calcular estadísticas desde PostgreSQL; se usará la memoria",
                exc_info=True,
            )
            scans = list(self._scans.values())
            storage = "memory-fallback"
        finally:
            db.close()

        return {
            "total_scans": len(scans),
            "by_status": {
                status: sum(scan.status == status for scan in scans)
                for status in ("pending", "running", "completed", "partial", "failed")
            },
            "total_vulnerabilities": sum(len(scan.findings) for scan in scans),
            "storage": storage,
        }

    @staticmethod
    def _summary_from_scan(scan: Scan) -> ScanSummary:
        return ScanSummary(
            scan_id=scan.scan_id,
            url=scan.url,
            status=scan.status,
            total_vulnerabilities=len(scan.findings),
            risk_level=scan.risk_level,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            progress_percentage=scan.progress_percentage,
            current_scanner=scan.current_scanner,
            task_id=scan.task_id,
            execution_mode=scan.execution_mode,
            queued_at=scan.queued_at,
            report_status=scan.report_status,
        )

    @staticmethod
    def _summary_from_database(scan: Any) -> ScanSummary:
        progress = (
            100
            if scan.status in {"completed", "partial"}
            else scan.progress_percentage
        )
        return ScanSummary(
            scan_id=scan.scan_id,
            url=scan.url,
            status=scan.status,
            total_vulnerabilities=scan.total_vulnerabilities,
            risk_level=scan.risk_level or "LOW",
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            progress_percentage=progress,
            current_scanner=scan.current_scanner,
            task_id=getattr(scan, "task_id", None),
            execution_mode=getattr(scan, "execution_mode", "background"),
            queued_at=getattr(scan, "queued_at", None),
            report_status=(scan.report.status if getattr(scan, "report", None) else "not_generated"),
        )

    @staticmethod
    def _scan_from_database(stored: Any) -> Scan:
        def parse_json(value: str | None, fallback: Any) -> Any:
            if not value:
                return fallback
            try:
                return json.loads(value)
            except (TypeError, json.JSONDecodeError):
                return fallback

        findings = [
            Finding(
                type=item.type,
                severity=item.severity,
                location=item.location or stored.url,
                scanner=item.scanner or "unknown",
                description=item.description or "",
                recommendation=item.recommendation or "",
                evidence=item.evidence or "",
                confidence=item.confidence or "low",
            )
            for item in stored.findings
        ]
        progress = (
            100
            if stored.status in {"completed", "partial"}
            else stored.progress_percentage
        )
        return Scan(
            scan_id=stored.scan_id,
            url=stored.url,
            scan_types=parse_json(stored.scan_types, []),
            status=stored.status,
            started_at=stored.started_at,
            completed_at=stored.completed_at,
            findings=findings,
            risk_score=stored.risk_score or 0,
            risk_level=stored.risk_level or "LOW",
            errors=parse_json(stored.errors, {}),
            current_scanner=stored.current_scanner,
            progress_percentage=progress,
            task_id=getattr(stored, "task_id", None),
            execution_mode=getattr(stored, "execution_mode", "background"),
            queued_at=getattr(stored, "queued_at", None),
            worker_started_at=getattr(stored, "worker_started_at", None),
            report_status=(
                stored.report.status if getattr(stored, "report", None) else "not_generated"
            ),
        )

    def generate_report(self, scan: Scan) -> Path:
        settings = get_settings()
        settings.report_dir.mkdir(parents=True, exist_ok=True)
        output = settings.report_dir / f"VulnHunter_Report_{scan.scan_id[:8]}.pdf"
        data = self.serialize(scan)
        data["duration_seconds"] = int(
            ((scan.completed_at or datetime.now(timezone.utc)) - scan.started_at).total_seconds()
        )
        self._persist_report(scan.scan_id, status="generating")
        try:
            generated = Path(VulnHunterReportGenerator().generate_report(data, str(output)))
            digest = hashlib.sha256(generated.read_bytes()).hexdigest()
            self._persist_report(
                scan.scan_id,
                status="generated",
                file_name=generated.name,
                storage_path=str(generated),
                size_bytes=generated.stat().st_size,
                sha256=digest,
            )
            return generated
        except Exception as exc:
            self._persist_report(
                scan.scan_id,
                status="failed",
                error_message=str(exc),
            )
            raise

    @staticmethod
    def _persist_report(scan_id: str, **values: Any) -> None:
        db = SessionLocal()
        try:
            crud.guardar_estado_reporte(db, scan_id, **values)
        except Exception:
            db.rollback()
            logger.exception("No se pudo persistir el estado del reporte")
        finally:
            db.close()

    @staticmethod
    def get_report_info(scan_id: str) -> dict[str, Any] | None:
        db = SessionLocal()
        try:
            report = crud.obtener_reporte(db, scan_id)
            if report is None:
                return None
            return {
                "scan_id": scan_id,
                "status": report.status,
                "file_name": report.file_name,
                "size_bytes": report.size_bytes,
                "sha256": report.sha256,
                "generated_at": report.generated_at,
                "download_count": report.download_count,
                "last_downloaded_at": report.last_downloaded_at,
            }
        finally:
            db.close()

    @staticmethod
    def get_report_path(scan_id: str) -> Path | None:
        db = SessionLocal()
        try:
            report = crud.obtener_reporte(db, scan_id)
            if report is None or report.status != "generated" or not report.storage_path:
                return None
            path = Path(report.storage_path)
            return path if path.is_file() else None
        finally:
            db.close()

    @staticmethod
    def register_report_download(scan_id: str) -> None:
        db = SessionLocal()
        try:
            crud.registrar_descarga_reporte(db, scan_id)
        finally:
            db.close()

    @staticmethod
    def _normalize_findings(scanner_name: str, result: dict, target_url: str) -> list[Finding]:
        normalized: list[Finding] = []
        for raw in result.get("vulnerabilities", []):
            severity = str(raw.get("severity", "LOW")).upper()
            confidence = "medium" if raw.get("evidence") or raw.get("payload") else "low"
            normalized.append(
                Finding(
                    type=str(raw.get("type", "Unknown finding")),
                    severity=severity,
                    location=str(raw.get("location", target_url)),
                    scanner=scanner_name,
                    description=str(raw.get("description", raw.get("details", ""))),
                    recommendation=str(raw.get("recommendation", "Revisar manualmente el hallazgo")),
                    evidence=str(raw.get("evidence", raw.get("payload", ""))),
                    confidence=confidence,
                )
            )
        return normalized


scan_service = ScanService()
