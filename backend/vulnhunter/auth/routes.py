"""Endpoints de autenticación: registro y login de usuarios.

Un endpoint es una "dirección" del backend a la que el frontend le hace
peticiones. Aquí definimos dos:
  - POST /auth/register : crea una cuenta nueva.
  - POST /auth/login    : verifica correo y contraseña.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from vulnhunter.auth.models import RegistroRequest, LoginRequest, UsuarioResponse
from vulnhunter.database.connection import get_db
from vulnhunter.database import crud_users
from vulnhunter.security import verificar_password

# tags=["auth"] agrupa estas rutas en la documentación automática (/docs).
router = APIRouter(prefix="/auth", tags=["auth"])


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


@router.post("/login", response_model=UsuarioResponse)
def login(datos: LoginRequest, db: Session = Depends(get_db)) -> UsuarioResponse:
    """Verifica correo y contraseña.

    Si son correctos, devuelve los datos del usuario (nombre, rol, etc.)
    para que el frontend lo salude y sepa a qué panel llevarlo.
    """
    # 1) Buscamos el usuario por su correo.
    usuario = crud_users.obtener_usuario_por_email(db, datos.email)

    # 2) Si no existe, o la contraseña no coincide, damos el MISMO error.
    #    (Por seguridad, no revelamos cuál de los dos falló.)
    if usuario is None or not verificar_password(datos.password, usuario.hashed_password):
        raise HTTPException(status_code=401, detail="Correo o contraseña incorrectos")

    return usuario

