import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import URL, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(REPOSITORY_ROOT / ".env")


def build_database_url() -> str | URL:
    """Return the hosting URL or construct one from local DB settings."""
    configured_url = os.getenv("DATABASE_URL")
    if configured_url:
        # SQLAlchemy defaults plain postgresql:// to psycopg2. VulnHunter uses
        # psycopg 3, so make the driver explicit for common provider URLs.
        if configured_url.startswith("postgres://"):
            return configured_url.replace("postgres://", "postgresql+psycopg://", 1)
        if configured_url.startswith("postgresql://"):
            return configured_url.replace("postgresql://", "postgresql+psycopg://", 1)
        return configured_url

    return URL.create(
        drivername="postgresql+psycopg",
        username=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", "5432")),
        database=os.getenv("DB_NAME", "vulnhunter_db"),
    )


engine = create_engine(build_database_url(), pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
