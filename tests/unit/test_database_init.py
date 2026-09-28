from vulnhunter.database import init_db


def test_initialize_database_creates_tables_without_dropping(monkeypatch):
    calls = []

    monkeypatch.setattr(
        init_db.Base.metadata,
        "create_all",
        lambda *, bind: calls.append(bind),
    )

    init_db.initialize_database()

    assert calls == [init_db.engine]
