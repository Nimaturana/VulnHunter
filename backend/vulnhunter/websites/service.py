import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import requests
from sqlalchemy.orm import Session

from vulnhunter.config import get_settings
from vulnhunter.database.models import User, Website
from vulnhunter.security import normalize_role
from vulnhunter.websites.target_policy import TargetPolicyError, validate_target


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def can_manage_website(user: User, website: Website) -> bool:
    return website.user_id == user.id or normalize_role(user.role) in {"admin", "auditor"}


def create_challenge(db: Session, user: User, raw_url: str) -> tuple[Website, str]:
    origin = validate_target(raw_url)
    website = (
        db.query(Website)
        .filter(Website.user_id == user.id, Website.url == origin)
        .first()
    )
    if website is None:
        website = Website(url=origin, user_id=user.id)
        db.add(website)
    token = f"vh_{secrets.token_urlsafe(32)}"
    website.verification_token_hash = token_hash(token)
    website.verification_status = "pending"
    website.verification_method = None
    website.verification_token_expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=get_settings().verification_token_minutes
    )
    website.verified_at = None
    website.is_active = True
    db.commit()
    db.refresh(website)
    return website, token


def verification_locations(website: Website, token: str) -> dict[str, str]:
    host = urlsplit(website.url).hostname
    return {
        "http_file_url": f"{website.url}/.well-known/vulnhunter-challenge.txt",
        "dns_record_name": f"_vulnhunter-verification.{host}",
        "dns_record_value": token,
    }


def verify_website(db: Session, website: Website, method: str, token: str) -> Website:
    now = datetime.now(timezone.utc)
    expires_at = website.verification_token_expires_at
    if expires_at is None or expires_at <= now:
        website.verification_status = "expired"
        db.commit()
        raise ValueError("El desafío expiró; genera uno nuevo")
    if not website.verification_token_hash or not secrets.compare_digest(
        website.verification_token_hash, token_hash(token)
    ):
        raise ValueError("El token no corresponde al desafío vigente")

    # Re-resolve immediately before the outbound request to reduce DNS-rebinding risk.
    validate_target(website.url)
    if method == "http_file":
        _verify_http_file(website, token)
    elif method == "dns_txt":
        _verify_dns_txt(website, token)
    else:
        raise ValueError("Método de verificación no permitido")

    website.verification_status = "verified"
    website.verification_method = method
    website.verified_at = now
    website.verification_token_hash = None
    website.verification_token_expires_at = None
    db.commit()
    db.refresh(website)
    return website


def _verify_http_file(website: Website, token: str) -> None:
    url = f"{website.url}/.well-known/vulnhunter-challenge.txt"
    try:
        response = requests.get(
            url,
            timeout=get_settings().verification_timeout_seconds,
            allow_redirects=False,
            headers={"User-Agent": "VulnHunter-Ownership-Verification/1.0"},
        )
    except requests.RequestException as exc:
        raise ValueError("No fue posible descargar el archivo de verificación") from exc
    if response.status_code != 200:
        raise ValueError(f"El archivo respondió HTTP {response.status_code}")
    if len(response.content) > 4096 or response.text.strip() != token:
        raise ValueError("El archivo no contiene exactamente el token esperado")


def _verify_dns_txt(website: Website, token: str) -> None:
    hostname = urlsplit(website.url).hostname
    record_name = f"_vulnhunter-verification.{hostname}"
    try:
        response = requests.get(
            "https://cloudflare-dns.com/dns-query",
            params={"name": record_name, "type": "TXT"},
            headers={"Accept": "application/dns-json"},
            timeout=get_settings().verification_timeout_seconds,
        )
        response.raise_for_status()
        answers = response.json().get("Answer", [])
    except (requests.RequestException, ValueError) as exc:
        raise ValueError("No fue posible consultar el registro DNS TXT") from exc
    values = {str(item.get("data", "")).strip('"') for item in answers}
    if token not in values:
        raise ValueError(f"No se encontró el token en el registro TXT {record_name}")

