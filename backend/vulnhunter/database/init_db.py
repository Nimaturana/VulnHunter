"""Bring the PostgreSQL schema to the latest Alembic revision."""

import logging
import os
import time
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from sqlalchemy.exc import SQLAlchemyError

from vulnhunter.database.connection import engine

logger = logging.getLogger(__name__)
BACKEND_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_CONFIG = BACKEND_ROOT / "alembic.ini"
MIGRATION_DIR = Path(__file__).resolve().parent / "migrations"
LEGACY_BASELINE_REVISION = "20260928_0001"
APPLICATION_TABLES = {"users", "websites", "scans", "findings"}


def build_alembic_config() -> Config:
    config = Config(str(ALEMBIC_CONFIG))
    config.set_main_option("script_location", str(MIGRATION_DIR))
    return config


def initialize_database() -> None:
    """Apply migrations and adopt databases created by the legacy create_all flow."""
    config = build_alembic_config()
    existing_tables = set(inspect(engine).get_table_names())

    if "alembic_version" not in existing_tables:
        legacy_tables = existing_tables & APPLICATION_TABLES
        if legacy_tables:
            missing_tables = APPLICATION_TABLES - legacy_tables
            if missing_tables:
                raise RuntimeError(
                    "Esquema legado incompleto; faltan tablas: "
                    + ", ".join(sorted(missing_tables))
                )
            logger.info("Adopting legacy database at revision %s.", LEGACY_BASELINE_REVISION)
            command.stamp(config, LEGACY_BASELINE_REVISION)

    command.upgrade(config, "head")


def main() -> None:
    max_attempts = max(1, int(os.getenv("DB_INIT_MAX_ATTEMPTS", "15")))
    retry_delay = max(0.0, float(os.getenv("DB_INIT_RETRY_SECONDS", "2")))

    for attempt in range(1, max_attempts + 1):
        try:
            initialize_database()
            logger.info("Database schema is ready.")
            return
        except SQLAlchemyError:
            if attempt == max_attempts:
                logger.exception("Database initialization failed after %s attempts.", attempt)
                raise
            logger.warning(
                "Database is not ready (attempt %s/%s); retrying in %.1f seconds.",
                attempt,
                max_attempts,
                retry_delay,
            )
            time.sleep(retry_delay)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
