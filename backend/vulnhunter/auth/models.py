"""Schemas (moldes de datos) para el registro y login de usuarios.

Estos modelos definen qué datos ENTRAN a los endpoints (lo que manda el
frontend) y qué datos SALEN (lo que responde el backend). FastAPI los usa
para validar automáticamente que lo que llega tenga el formato correcto.
"""

from pydantic import BaseModel, EmailStr, Field


class RegistroRequest(BaseModel):
    """Datos que llegan cuando un usuario se registra (desde el formulario)."""
    email: EmailStr                      # Correo válido (Pydantic valida el formato).
    password: str = Field(min_length=8)  # Contraseña, mínimo 8 caracteres.
    nombre: str = Field(min_length=1, max_length=100)
    apellido: str = Field(min_length=1, max_length=100)
    rut: str | None = Field(default=None, max_length=20)
    telefono: str | None = Field(default=None, max_length=30)
    fecha_nacimiento: str | None = Field(default=None, max_length=20)


class LoginRequest(BaseModel):
    """Datos que llegan cuando un usuario inicia sesión."""
    email: EmailStr
    password: str


class GoogleLoginRequest(BaseModel):
    credential: str = Field(min_length=100, max_length=10000)


class UsuarioResponse(BaseModel):
    """Datos que el backend DEVUELVE del usuario (sin la contraseña).

    Nunca devolvemos la contraseña ni el hash. Solo lo que el frontend
    necesita para saludar y saber a qué panel llevar a la persona.
    """
    id: int
    email: EmailStr
    nombre: str
    apellido: str
    role: str

    # Permite construir este modelo directamente desde el objeto User de la base.
    model_config = {"from_attributes": True}


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UsuarioResponse


class RoleUpdateRequest(BaseModel):
    role: str

