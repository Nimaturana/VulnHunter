import asyncio

from celery.utils.log import get_task_logger

from vulnhunter.scans.service import scan_service
from vulnhunter.tasks.celery_app import celery_app

logger = get_task_logger(__name__)


@celery_app.task(bind=True, name="vulnhunter.execute_scan")
def execute_scan(self, scan_id: str) -> dict[str, object]:
    """Execute a persisted scan and generate its PDF in the Celery worker."""
    logger.info("Celery task %s started scan %s", self.request.id, scan_id)
    try:
        report_path = asyncio.run(scan_service.perform_scan_and_generate(scan_id))
        scan = scan_service.get_scan(scan_id)
        if scan is None:
            raise RuntimeError(f"El escaneo {scan_id} desapareció durante la ejecución")
        return {
            "scan_id": scan_id,
            "status": scan.status,
            "total_vulnerabilities": len(scan.findings),
            "risk_level": scan.risk_level,
            "report": str(report_path) if report_path else None,
        }
    except Exception as exc:
        logger.exception("Celery task %s failed scan %s", self.request.id, scan_id)
        try:
            scan_service.mark_failed(scan_id, str(exc))
        except Exception:
            logger.exception("Could not persist task failure for scan %s", scan_id)
        raise
