from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from vulnhunter import security
from vulnhunter.auth.dependencies import require_roles
from vulnhunter.scans.models import ScanRequest
from vulnhunter.websites import target_policy
from vulnhunter.websites.service import token_hash, verification_locations, verify_website


def test_access_token_rejects_tampering(monkeypatch):
    settings = SimpleNamespace(auth_secret_key="test-secret", access_token_minutes=5)
    monkeypatch.setattr(security, "get_settings", lambda: settings)
    token = security.crear_access_token(user_id=7, role="auditor")
    claims = security.verificar_access_token(token)
    assert claims["sub"] == "7"
    assert claims["role"] == "auditor"
    with pytest.raises(ValueError):
        security.verificar_access_token(token[:-1] + ("A" if token[-1] != "A" else "B"))


def test_access_token_rejects_expiration(monkeypatch):
    settings = SimpleNamespace(auth_secret_key="test-secret", access_token_minutes=1)
    monkeypatch.setattr(security, "get_settings", lambda: settings)
    monkeypatch.setattr(security.time, "time", lambda: 100)
    token = security.crear_access_token(user_id=9, role="client")
    monkeypatch.setattr(security.time, "time", lambda: 161)
    with pytest.raises(ValueError):
        security.verificar_access_token(token)


def test_guest_token_can_have_a_shorter_expiration(monkeypatch):
    settings = SimpleNamespace(auth_secret_key="test-secret", access_token_minutes=480)
    monkeypatch.setattr(security, "get_settings", lambda: settings)
    monkeypatch.setattr(security.time, "time", lambda: 100)
    token = security.crear_access_token(
        user_id=10,
        role="guest",
        expires_in_minutes=1,
    )
    assert security.verificar_access_token(token)["role"] == "guest"
    monkeypatch.setattr(security.time, "time", lambda: 161)
    with pytest.raises(ValueError):
        security.verificar_access_token(token)


def test_guest_cannot_use_mutating_role_dependency():
    dependency = require_roles("admin", "auditor", "client")
    with pytest.raises(HTTPException) as error:
        dependency(current_user=SimpleNamespace(role="guest"))
    assert error.value.status_code == 403


def test_target_policy_rejects_private_resolution(monkeypatch):
    monkeypatch.setattr(
        target_policy, "get_settings", lambda: SimpleNamespace(allow_private_targets=False)
    )
    monkeypatch.setattr(
        target_policy.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("127.0.0.1", 0))],
    )
    with pytest.raises(target_policy.TargetPolicyError):
        target_policy.validate_target("https://example.test/path")


def test_target_policy_normalizes_to_origin_only():
    assert target_policy.normalize_origin("HTTPS://Example.COM:443/a?x=1#f") == "https://example.com"


def test_scan_request_requires_registered_target_reference():
    with pytest.raises(ValueError):
        ScanRequest()
    assert ScanRequest(website_id=4).website_id == 4


def test_verification_challenge_exposes_no_hash():
    website = SimpleNamespace(url="https://example.test")
    token = "vh_example-token-value"
    locations = verification_locations(website, token)
    assert locations["http_file_url"].endswith("/.well-known/vulnhunter-challenge.txt")
    assert locations["dns_record_name"] == "_vulnhunter-verification.example.test"
    assert token_hash(token) != token


def test_expired_verification_challenge_is_rejected_without_network():
    database = SimpleNamespace(commit=lambda: None)
    website = SimpleNamespace(
        verification_token_expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        verification_status="pending",
    )
    with pytest.raises(ValueError, match="expiró"):
        verify_website(database, website, "http_file", "vh_expired-token-value")
    assert website.verification_status == "expired"
