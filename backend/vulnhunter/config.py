import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


def _csv_setting(name: str, default: str) -> tuple[str, ...]:
    return tuple(value.strip() for value in os.getenv(name, default).split(",") if value.strip())


@dataclass(frozen=True)
class Settings:
    app_name: str = os.getenv("APP_NAME", "VulnHunter")
    app_version: str = os.getenv("APP_VERSION", "0.1.0")
    environment: str = os.getenv("ENVIRONMENT", "development")
    docs_enabled: bool = os.getenv("DOCS_ENABLED", "true").lower() == "true"
    cors_origins: tuple[str, ...] = _csv_setting(
        "CORS_ORIGINS", "http://localhost:3000,http://localhost:5173"
    )
    report_dir: Path = Path(
        os.getenv("REPORT_DIR", str(REPOSITORY_ROOT / "artifacts" / "reports"))
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
