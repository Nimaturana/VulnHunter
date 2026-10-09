from types import SimpleNamespace

import pytest
from vulnhunter.database import init_db


def test_initialize_database_upgrades_an_empty_database(monkeypatch):
    calls: list[tuple[str, str]] = []

    monkeypatch.setattr(
        init_db,
        "inspect",
        lambda engine: SimpleNamespace(get_table_names=list),
    )
    monkeypatch.setattr(init_db, "build_alembic_config", lambda: "config")
    monkeypatch.setattr(
        init_db.command,
        "upgrade",
        lambda config, revision: calls.append((config, revision)),
    )
    monkeypatch.setattr(
        init_db.command,
        "stamp",
        lambda config, revision: pytest.fail("An empty database must not be stamped"),
    )

    init_db.initialize_database()

    assert calls == [("config", "head")]


def test_initialize_database_adopts_complete_legacy_schema(monkeypatch):
    calls: list[tuple[str, str, str]] = []

    monkeypatch.setattr(
        init_db,
        "inspect",
        lambda engine: SimpleNamespace(
            get_table_names=lambda: ["users", "websites", "scans", "findings"]
        ),
    )
    monkeypatch.setattr(init_db, "build_alembic_config", lambda: "config")
    monkeypatch.setattr(
        init_db.command,
        "stamp",
        lambda config, revision: calls.append(("stamp", config, revision)),
    )
    monkeypatch.setattr(
        init_db.command,
        "upgrade",
        lambda config, revision: calls.append(("upgrade", config, revision)),
    )

    init_db.initialize_database()

    assert calls == [
        ("stamp", "config", init_db.LEGACY_BASELINE_REVISION),
        ("upgrade", "config", "head"),
    ]


def test_initialize_database_rejects_partial_legacy_schema(monkeypatch):
    monkeypatch.setattr(
        init_db,
        "inspect",
        lambda engine: SimpleNamespace(get_table_names=lambda: ["users", "websites"]),
    )
    monkeypatch.setattr(init_db, "build_alembic_config", lambda: "config")

    with pytest.raises(RuntimeError, match="Esquema legado incompleto"):
        init_db.initialize_database()
