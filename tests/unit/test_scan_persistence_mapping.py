from datetime import datetime, timezone
from types import SimpleNamespace

from vulnhunter.scans.service import ScanService


def _stored_scan(**overrides):
    values = {
        "scan_id": "00000000-0000-0000-0000-000000000001",
        "url": "https://example.test/",
        "scan_types": '["security_headers"]',
        "status": "completed",
        "started_at": datetime.now(timezone.utc),
        "completed_at": datetime.now(timezone.utc),
        "total_vulnerabilities": 1,
        "risk_score": 20,
        "risk_level": "LOW",
        "progress_percentage": 0,
        "current_scanner": None,
        "errors": "{}",
        "findings": [
            SimpleNamespace(
                type="Missing header",
                severity="LOW",
                location="https://example.test/",
                scanner="security_headers",
                description="Header ausente",
                recommendation="Agregar el header",
                evidence="",
                confidence="medium",
            )
        ],
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_completed_legacy_scan_is_presented_with_full_progress():
    stored = _stored_scan(progress_percentage=0)

    summary = ScanService._summary_from_database(stored)
    scan = ScanService._scan_from_database(stored)

    assert summary.progress_percentage == 100
    assert scan.progress_percentage == 100
    assert scan.findings[0].type == "Missing header"


def test_running_scan_preserves_persisted_progress():
    stored = _stored_scan(
        status="running",
        completed_at=None,
        progress_percentage=40,
    )

    summary = ScanService._summary_from_database(stored)

    assert summary.progress_percentage == 40
