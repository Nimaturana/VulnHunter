from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from vulnhunter.auth.dependencies import get_current_user, require_roles
from vulnhunter.database.connection import get_db
from vulnhunter.database.models import User, Website
from vulnhunter.security import normalize_role
from vulnhunter.websites.models import (
    VerificationChallenge,
    WebsiteCreate,
    WebsiteResponse,
    WebsiteVerifyRequest,
)
from vulnhunter.websites.service import (
    can_manage_website,
    create_challenge,
    verification_locations,
    verify_website,
)
from vulnhunter.websites.target_policy import TargetPolicyError

router = APIRouter(prefix="/websites", tags=["websites"])


def _challenge_response(website: Website, token: str) -> VerificationChallenge:
    locations = verification_locations(website, token)
    return VerificationChallenge(
        website=WebsiteResponse.model_validate(website),
        token=token,
        **locations,
        explanation=(
            "Publica el token como contenido exacto del archivo indicado o como valor "
            "del registro DNS TXT. El token se muestra una sola vez."
        ),
    )


@router.post("", response_model=VerificationChallenge, status_code=201)
def register_website(
    data: WebsiteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "auditor", "client")),
) -> VerificationChallenge:
    try:
        website, token = create_challenge(db, current_user, str(data.url))
    except TargetPolicyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _challenge_response(website, token)


@router.get("", response_model=list[WebsiteResponse])
def list_websites(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[Website]:
    query = db.query(Website)
    if normalize_role(current_user.role) in {"client", "guest"}:
        query = query.filter(Website.user_id == current_user.id)
    return query.order_by(Website.created_at.desc()).all()


@router.post("/{website_id}/challenge", response_model=VerificationChallenge)
def renew_challenge(
    website_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "auditor", "client")),
) -> VerificationChallenge:
    website = db.get(Website, website_id)
    if website is None:
        raise HTTPException(status_code=404, detail="Sitio no encontrado")
    if not can_manage_website(current_user, website):
        raise HTTPException(status_code=403, detail="No puedes administrar este sitio")
    try:
        website, token = create_challenge(db, website.owner, website.url)
    except TargetPolicyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _challenge_response(website, token)


@router.post("/{website_id}/verify", response_model=WebsiteResponse)
def verify_registered_website(
    website_id: int,
    data: WebsiteVerifyRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "auditor", "client")),
) -> Website:
    website = db.get(Website, website_id)
    if website is None:
        raise HTTPException(status_code=404, detail="Sitio no encontrado")
    if not can_manage_website(current_user, website):
        raise HTTPException(status_code=403, detail="No puedes verificar este sitio")
    try:
        return verify_website(db, website, data.method, data.token)
    except (ValueError, TargetPolicyError) as exc:
        if website.verification_status != "expired":
            website.verification_status = "failed"
        db.commit()
        raise HTTPException(status_code=409, detail=str(exc)) from exc

