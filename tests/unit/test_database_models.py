from sqlalchemy import CheckConstraint, UniqueConstraint
from vulnhunter.database.models import Finding, Scan, User, Website


def _constraint_names(model, constraint_type):
    return {
        constraint.name
        for constraint in model.__table__.constraints
        if isinstance(constraint, constraint_type)
    }


def test_mvp_database_contains_expected_tables_and_relations():
    assert User.__tablename__ == "users"
    assert Website.__tablename__ == "websites"
    assert Scan.__tablename__ == "scans"
    assert Finding.__tablename__ == "findings"

    assert Website.__table__.c.user_id.foreign_keys
    assert Scan.__table__.c.website_id.foreign_keys
    assert Scan.__table__.c.requested_by_user_id.foreign_keys
    assert Finding.__table__.c.scan_id.foreign_keys


def test_website_authorization_fields_are_persisted():
    columns = Website.__table__.c

    assert "verification_status" in columns
    assert "verification_method" in columns
    assert "verification_token_hash" in columns
    assert "verified_at" in columns
    assert "is_active" in columns
    assert "uq_websites_user_url" in _constraint_names(Website, UniqueConstraint)


def test_scan_progress_requester_and_errors_are_persisted():
    columns = Scan.__table__.c

    assert "requested_by_user_id" in columns
    assert "description" in columns
    assert "progress_percentage" in columns
    assert "current_scanner" in columns
    assert "errors" in columns
    assert "ck_scans_status" in _constraint_names(Scan, CheckConstraint)
    assert "ck_scans_progress_percentage" in _constraint_names(Scan, CheckConstraint)


def test_findings_validate_severity_and_confidence():
    constraints = _constraint_names(Finding, CheckConstraint)

    assert "ck_findings_severity" in constraints
    assert "ck_findings_confidence" in constraints
    assert "created_at" in Finding.__table__.c
