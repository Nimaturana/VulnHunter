from celery import Celery

from vulnhunter.config import get_settings

settings = get_settings()

celery_app = Celery(
    "vulnhunter",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["vulnhunter.tasks.scan_tasks"],
)

celery_app.conf.update(
    task_default_queue="scans",
    task_track_started=True,
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    result_expires=86400,
    timezone="UTC",
    enable_utc=True,
    broker_connection_retry_on_startup=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_publish_retry=True,
    task_publish_retry_policy={
        "max_retries": 3,
        "interval_start": 0,
        "interval_step": 0.5,
        "interval_max": 1,
    },
)
