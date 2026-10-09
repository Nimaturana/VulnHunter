from typing import Any


def enqueue_scan(scan_id: str, task_id: str) -> Any:
    """Import Celery lazily so direct development can run without Redis."""
    from vulnhunter.tasks.scan_tasks import execute_scan

    return execute_scan.apply_async(args=[scan_id], task_id=task_id, queue="scans")
