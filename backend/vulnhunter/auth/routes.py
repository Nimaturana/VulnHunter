"""Endpoints de autenticación: registro y login de usuarios.

Un endpoint es una "dirección" del backend a la que el frontend le hace
peticiones. Aquí definimos dos:
  - POST /auth/register : crea una cuenta nueva.
  - POST /auth/login    : verifica correo y contraseña.
"""

import logging
import secrets

from fastapi import APIRouter, Depends, HTTPException
from google.auth.exceptions import GoogleAuthError
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_id_token
from sqlalchemy.orm import Session

from vulnhunter.auth.dependencies import get_current_user, require_roles
from vulnhunter.auth.models import (
    LoginRequest,
    LoginResponse,
    GoogleLoginRequest,
    AuditorUpsertRequest,
    RegistroRequest,
    RoleUpdateRequest,
    UsuarioResponse,
)
from vulnhunter.database.connection import get_db
from vulnhunter.database import crud_users
from vulnhunter.database.models import User
from vulnhunter.config import get_settings
from vulnhunter.security import crear_access_token, normalize_role, verificar_password

# tags=["auth"] agrupa estas rutas en la documentación automática (/docs).
router = APIRouter(prefix="/auth", tags=["auth"])
logger = logging.getLogger(__name__)


def _login_response(usuario: User, *, expires_in_minutes: int | None = None) -> LoginResponse:
    settings = get_settings()
    token_minutes = expires_in_minutes or settings.access_token_minutes
    token = crear_access_token(
        user_id=usuario.id,
        role=usuario.role,
        expires_in_minutes=token_minutes,
    )
    return LoginResponse(
        access_token=token,
        expires_in=token_minutes * 60,
        user=UsuarioResponse.model_validate(usuario),
    )


@router.post("/register", response_model=UsuarioResponse, status_code=201)
def registrar(datos: RegistroRequest, db: Session = Depends(get_db)) -> UsuarioResponse:
    """Crea una cuenta nueva.

    Valida que el correo y el RUT no estén ya registrados. Si todo está bien,
    guarda el usuario (con la contraseña cifrada) y lo devuelve sin la clave.
    """
    # 1) El correo no puede estar repetido.
    if crud_users.obtener_usuario_por_email(db, datos.email):
        raise HTTPException(status_code=409, detail="Este correo ya está registrado")

    # 2) El RUT tampoco (si viene).
    if datos.rut and crud_users.obtener_usuario_por_rut(db, datos.rut):
        raise HTTPException(status_code=409, detail="Este RUT ya está registrado")

    # 3) Creamos el usuario. crear_usuario cifra la contraseña por dentro.
    usuario = crud_users.crear_usuario(
        db,
        email=datos.email,
        password=datos.password,
        nombre=datos.nombre,
        apellido=datos.apellido,
        rut=datos.rut,
        telefono=datos.telefono,
        fecha_nacimiento=datos.fecha_nacimiento,
    )
    return usuario


@router.post("/login", response_model=LoginResponse)
def login(datos: LoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    """Verifica correo y contraseña.

    Si son correctos, devuelve los datos del usuario (nombre, rol, etc.)
    para que el frontend lo salude y sepa a qué panel llevarlo.
    """
    # 1) Buscamos el usuario por su correo.
    usuario = crud_users.obtener_usuario_por_email(db, datos.email)

    # 2) Si no existe, o la contraseña no coincide, damos el MISMO error.
    #    (Por seguridad, no revelamos cuál de los dos falló.)
    if (
        usuario is None
        or not usuario.is_active
        or not verificar_password(datos.password, usuario.hashed_password)
    ):
        raise HTTPException(status_code=401, detail="Correo o contraseña incorrectos")

    return _login_response(usuario)


@router.post("/google", response_model=LoginResponse)
def login_google(datos: GoogleLoginRequest, db: Session = Depends(get_db)) -> LoginResponse:
    """Validate a Google ID token and create or access a local account."""
    client_id = get_settings().google_client_id
    if not client_id:
        raise HTTPException(status_code=503, detail="Google Sign-In no está configurado")

    try:
        claims = google_id_token.verify_oauth2_token(
            datos.credential,
            google_requests.Request(),
            client_id,
            clock_skew_in_seconds=10,
        )
    except (ValueError, GoogleAuthError) as exc:
        reason = str(exc).lower()
        logger.warning("Google ID token rejected: %s: %s", type(exc).__name__, exc)
        if "audience" in reason or "recipient" in reason:
            detail = "El token pertenece a otro Client ID de Google"
        elif "too early" in reason or "used too early" in reason:
            detail = "El reloj del servidor no está sincronizado con Google"
        elif "expired" in reason:
            detail = "La sesión de Google expiró; inténtalo nuevamente"
        else:
            detail = "Google rechazó la credencial de inicio de sesión"
        raise HTTPException(status_code=401, detail=detail) from exc

    subject = str(claims.get("sub", ""))
    email = str(claims.get("email", "")).strip().lower()
    if not subject or not email or claims.get("email_verified") is not True:
        raise HTTPException(status_code=401, detail="Google no confirmó este correo")

    usuario = db.query(User).filter(User.google_subject == subject).first()
    if usuario is None:
        usuario = crud_users.obtener_usuario_por_email(db, email)
        if usuario is not None and usuario.google_subject not in {None, subject}:
            raise HTTPException(status_code=409, detail="El correo ya usa otra identidad Google")
        if usuario is None:
            usuario = crud_users.crear_usuario(
                db,
                email=email,
                password=secrets.token_urlsafe(48),
                nombre=(str(claims.get("given_name", "")).strip() or "Usuario")[:100],
                apellido=(str(claims.get("family_name", "")).strip() or "Google")[:100],
            )
        usuario.google_subject = subject
        db.commit()
        db.refresh(usuario)

    if not usuario.is_active:
        raise HTTPException(status_code=401, detail="La cuenta está inactiva")
    return _login_response(usuario)


@router.post("/guest", response_model=LoginResponse)
def login_guest(db: Session = Depends(get_db)) -> LoginResponse:
    """Create a short-lived, read-only session for the public product demo."""
    settings = get_settings()
    if not settings.guest_mode_enabled:
        raise HTTPException(status_code=404, detail="La demostración para invitados no está habilitada")

    # EmailStr rejects special-use suffixes such as `.local`. This address is
    # an internal identity only; it is never used to deliver email.
    email = "invitado@demo.vulnhunter.cl"
    usuario = crud_users.obtener_usuario_por_email(db, email)
    if usuario is None:
        usuario = crud_users.crear_usuario(
            db,
            email=email,
            password=secrets.token_urlsafe(48),
            nombre="Visitante",
            apellido="Demo",
            role="guest",
        )
    elif usuario.role != "guest":
        # Never turn a pre-existing non-guest account into a public demo account.
        raise HTTPException(status_code=409, detail="La identidad de demostración no está disponible")

    if not usuario.is_active:
        raise HTTPException(status_code=403, detail="La demostración está deshabilitada")
    guest_minutes = max(5, min(settings.guest_session_minutes, 120))
    return _login_response(usuario, expires_in_minutes=guest_minutes)


@router.get("/me", response_model=UsuarioResponse)
def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user


@router.patch("/users/{user_id}/role", response_model=UsuarioResponse)
def update_role(
    user_id: int,
    data: RoleUpdateRequest,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin")),
) -> User:
    role = normalize_role(data.role)
    if role not in {"admin", "auditor", "client"}:
        raise HTTPException(status_code=422, detail="Rol permitido: admin, auditor o client")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    user.role = role
    db.commit()
    db.refresh(user)
    return user


@router.get("/auditors", response_model=list[UsuarioResponse])
def list_auditors(
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin")),
) -> list[User]:
    """List the auditor accounts managed by an administrator."""
    return (
        db.query(User)
        .filter(User.role == "auditor")
        .order_by(User.company_name.asc().nullslast(), User.email.asc())
        .all()
    )


@router.post("/auditors", response_model=UsuarioResponse)
def save_auditor(
    data: AuditorUpsertRequest,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin")),
) -> User:
    """Create an auditor identity or promote an existing account by email.

    A newly provisioned identity can enter through Google Sign-In using the
    same verified email. No reusable plaintext password is generated or sent.
    """
    email = str(data.email).strip().lower()
    company_name = data.company_name.strip()
    user = crud_users.obtener_usuario_por_email(db, email)
    if user is None:
        display_name = (data.nombre or email.split("@", 1)[0]).strip() or "Auditor"
        user = crud_users.crear_usuario(
            db,
            email=email,
            password=secrets.token_urlsafe(48),
            nombre=display_name[:100],
            apellido="Auditor",
            company_name=company_name,
            role="auditor",
        )
    else:
        if user.role == "admin":
            raise HTTPException(status_code=409, detail="Un administrador no puede convertirse en auditor")
        user.role = "auditor"
        user.company_name = company_name
        if data.nombre and data.nombre.strip():
            user.nombre = data.nombre.strip()[:100]
        user.is_active = True
        db.commit()
        db.refresh(user)
    return user


@router.delete("/auditors/{user_id}", response_model=UsuarioResponse)
def revoke_auditor(
    user_id: int,
    db: Session = Depends(get_db),
    _: User = Depends(require_roles("admin")),
) -> User:
    """Revoke auditor privileges while preserving the account and history."""
    user = db.get(User, user_id)
    if user is None or normalize_role(user.role) != "auditor":
        raise HTTPException(status_code=404, detail="Auditor no encontrado")
    user.role = "client"
    db.commit()
    db.refresh(user)
    return user

