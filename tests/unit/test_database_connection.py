from sqlalchemy import URL
from vulnhunter.database.connection import build_database_url


def test_database_url_uses_psycopg_driver_for_docker_url(monkeypatch):
    monkeypatch.setenv(
        "DATABASE_URL",
        "postgresql://vulnhunter:secret@postgres:5432/vulnhunter",
    )

    assert build_database_url() == (
        "postgresql+psycopg://vulnhunter:secret@postgres:5432/vulnhunter"
    )


def test_database_url_can_be_built_from_local_settings(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("DB_USER", "vulnhunter")
    monkeypatch.setenv("DB_PASSWORD", "p@ssword")
    monkeypatch.setenv("DB_HOST", "localhost")
    monkeypatch.setenv("DB_PORT", "5432")
    monkeypatch.setenv("DB_NAME", "vulnhunter")

    url = build_database_url()

    assert isinstance(url, URL)
    assert url.drivername == "postgresql+psycopg"
    assert url.username == "vulnhunter"
    assert url.password == "p@ssword"
    assert url.database == "vulnhunter"
