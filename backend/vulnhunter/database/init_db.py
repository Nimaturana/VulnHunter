"""Create missing database tables without deleting existing data."""

import logging
import os
import time

from sqlalchemy.exc import SQLAlchemyError

from vulnhunter.database import models  # noqa: F401 - registers SQLAlchemy models
from vulnhunter.database.connection import Base, engine

logger = logging.getLogger(__name__)


def initialize_database() -> None:
    """Create tables that do not exist yet; never drop existing tables."""
    Base.metadata.create_all(bind=engine)


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
