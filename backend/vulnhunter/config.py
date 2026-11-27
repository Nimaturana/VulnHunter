import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

# config.py lives in <repository>/backend/vulnhunter/. Going up two levels
# therefore resolves to the repository itself, not to its parent directory.
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _csv_setting(name: str, default: str) -> tuple[str, ...]:
    return tuple(value.strip() for value in os.getenv(name, default).split(",") if value.strip())


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("APP_NAME", "VulnHunter")
    app_version: str = os.getenv("APP_VERSION", "0.1.0")
    environment: str = os.getenv("ENVIRONMENT", "development")
    docs_enabled: bool = os.getenv("DOCS_ENABLED", "true").lower() == "true"
    cors_origins: tuple[str, ...] = _csv_setting(
        "CORS_ORIGINS",
        (
            "http://localhost:3000,http://127.0.0.1:3000,"
            "http://localhost:5173,http://127.0.0.1:5173"
        ),
    )
    report_dir: Path = Path(
        os.getenv("REPORT_DIR", str(REPOSITORY_ROOT / "artifacts" / "reports"))
    )
    task_queue_enabled: bool = os.getenv("TASK_QUEUE_ENABLED", "false").lower() == "true"
    celery_broker_url: str = os.getenv(
        "CELERY_BROKER_URL", os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    celery_result_backend: str = os.getenv(
        "CELERY_RESULT_BACKEND", os.getenv("REDIS_URL", "redis://localhost:6379/1")
    )
    auth_secret_key: str = os.getenv("AUTH_SECRET_KEY", os.getenv("SECRET_KEY", "change-me"))
    access_token_minutes: int = int(os.getenv("ACCESS_TOKEN_MINUTES", "480"))
    allow_private_targets: bool = os.getenv("ALLOW_PRIVATE_TARGETS", "false").lower() == "true"
    verification_timeout_seconds: float = float(os.getenv("VERIFICATION_TIMEOUT_SECONDS", "8"))
    verification_token_minutes: int = int(os.getenv("VERIFICATION_TOKEN_MINUTES", "60"))
    google_client_id: str = os.getenv("GOOGLE_CLIENT_ID", "").strip()
    guest_mode_enabled: bool = os.getenv("GUEST_MODE_ENABLED", "false").lower() == "true"
    guest_session_minutes: int = int(os.getenv("GUEST_SESSION_MINUTES", "60"))


@lru_cache
def get_settings() -> Settings:
    return Settings()
