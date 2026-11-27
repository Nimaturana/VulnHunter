"""Funciones de seguridad para el manejo de contraseñas.

Usamos bcrypt para cifrar las contraseñas. NUNCA se guarda la contraseña
real en la base de datos, solo su versión cifrada (hash).
"""

import base64
import bcrypt
import binascii
import hashlib
import hmac
import json
import time

from vulnhunter.config import get_settings


def cifrar_password(password: str) -> str:
    """Convierte una contraseña en texto plano a un hash seguro con bcrypt.

    Se usa al registrar un usuario. El resultado es lo que se guarda
    en la columna 'hashed_password' de la tabla users.
    """
    # bcrypt trabaja con bytes, así que codificamos el texto a bytes.
    password_bytes = password.encode("utf-8")
    # gensalt() genera una "sal" aleatoria para que dos contraseñas iguales
    # produzcan hashes distintos (más seguro).
    hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    # Devolvemos el hash como texto para guardarlo en la base de datos.
    return hashed.decode("utf-8")


def verificar_password(password: str, hashed_password: str) -> bool:
    """Compara una contraseña escrita por el usuario con el hash guardado.

    Se usa al iniciar sesión. Devuelve True si la contraseña es correcta,
    False si no coincide.
    """
    # Codificamos ambos a bytes para que bcrypt los pueda comparar.
    password_bytes = password.encode("utf-8")
    hashed_bytes = hashed_password.encode("utf-8")
    # checkpw vuelve a cifrar la contraseña escrita y la compara con el hash.
    return bcrypt.checkpw(password_bytes, hashed_bytes)


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def crear_access_token(
    *, user_id: int, role: str, expires_in_minutes: int | None = None
) -> str:
    """Create a compact HMAC-signed bearer token without storing a server session."""
    settings = get_settings()
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "role": normalize_role(role),
        "iat": now,
        "exp": now + (expires_in_minutes or settings.access_token_minutes) * 60,
    }
    encoded = _b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(
        settings.auth_secret_key.encode("utf-8"),
        encoded.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return f"{encoded}.{_b64encode(signature)}"


def verificar_access_token(token: str) -> dict:
    """Validate signature and expiration, returning the authenticated claims."""
    try:
        encoded, supplied_signature = token.split(".", 1)
        expected = hmac.new(
            get_settings().auth_secret_key.encode("utf-8"),
            encoded.encode("ascii"),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(expected, _b64decode(supplied_signature)):
            raise ValueError("Firma inválida")
        payload = json.loads(_b64decode(encoded))
        if int(payload["exp"]) <= int(time.time()):
            raise ValueError("Token expirado")
        int(payload["sub"])
        return payload
    except (
        ValueError,
        KeyError,
        TypeError,
        UnicodeDecodeError,
        binascii.Error,
        json.JSONDecodeError,
    ) as exc:
        raise ValueError("Token de acceso inválido o expirado") from exc


def normalize_role(role: str) -> str:
    """Map the legacy `user` role to the new client role."""
    return "client" if role == "user" else role

