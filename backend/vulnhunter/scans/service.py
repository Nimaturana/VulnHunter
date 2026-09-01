import asyncio
import logging
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vulnhunter.config import get_settings
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
    """Coordinates scans. In-memory storage is intentionally isolated for later replacement."""

    def __init__(self) -> None:
        self._scans: dict[str, Scan] = {}

    @property
    def available_scanners(self) -> list[str]:
        return list(SCANNER_FACTORIES)

    @property
    def active_scan_count(self) -> int:
        return sum(scan.status == "running" for scan in self._scans.values())

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
        return scan

    async def perform_scan(self, scan_id: str) -> None:
        scan = self._scans[scan_id]
        scan.status = "running"
        total_scanners = len(scan.scan_types)
        total_started = time.perf_counter()
        scan_tag = f"SCAN {scan.scan_id[:8]}"

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

            _console_block(
                f"┌─ [{scan_tag}] SCANNER {index}/{total_scanners} · {scanner_label}",
                f"│ Estado   : ejecutando",
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

    def get_scan(self, scan_id: str) -> Scan | None:
        return self._scans.get(scan_id)

    def list_scans(self, limit: int, offset: int, status: str | None) -> list[ScanSummary]:
        scans = list(self._scans.values())
        if status:
            scans = [scan for scan in scans if scan.status == status]
        scans.sort(key=lambda item: item.started_at, reverse=True)
        return [
            ScanSummary(
                scan_id=scan.scan_id,
                url=scan.url,
                status=scan.status,
                total_vulnerabilities=len(scan.findings),
                risk_level=scan.risk_level,
                completed_at=scan.completed_at,
            )
            for scan in scans[offset : offset + limit]
        ]

    def serialize(self, scan: Scan) -> dict[str, Any]:
        data = scan.model_dump(mode="json")
        data["vulnerabilities"] = data.pop("findings")
        data["total_vulnerabilities"] = len(scan.findings)
        total = max(len(scan.scan_types), 1)
        data["progress"] = {
            "percentage": scan.progress_percentage,
            "completed_scanners": len(scan.results),
            "total_scanners": total,
            "current_scanner": scan.current_scanner,
        }
        return data

    def statistics(self) -> dict[str, Any]:
        scans = list(self._scans.values())
        return {
            "total_scans": len(scans),
            "by_status": {
                status: sum(scan.status == status for scan in scans)
                for status in ("pending", "running", "completed", "partial", "failed")
            },
            "total_vulnerabilities": sum(len(scan.findings) for scan in scans),
            "storage": "memory",
        }

    def generate_report(self, scan: Scan) -> Path:
        settings = get_settings()
        settings.report_dir.mkdir(parents=True, exist_ok=True)
        output = settings.report_dir / f"VulnHunter_Report_{scan.scan_id[:8]}.pdf"
        data = self.serialize(scan)
        data["duration_seconds"] = int(
            ((scan.completed_at or datetime.now(timezone.utc)) - scan.started_at).total_seconds()
        )
        return Path(VulnHunterReportGenerator().generate_report(data, str(output)))

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
