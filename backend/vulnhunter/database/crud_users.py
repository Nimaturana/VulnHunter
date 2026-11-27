"""Operaciones de base de datos para usuarios (crear, buscar).

Estas funciones manejan el registro y la búsqueda de usuarios.
Las contraseñas se cifran con bcrypt antes de guardarse.
"""

from sqlalchemy import func
from sqlalchemy.orm import Session

from vulnhunter.database.models import User
from vulnhunter.security import cifrar_password


def obtener_usuario_por_email(db: Session, email: str) -> User | None:
    """Busca un usuario por su correo. Devuelve el usuario o None si no existe.

    Se usa para el login (buscar la cuenta) y para evitar correos repetidos
    al registrar.
    """
    return db.query(User).filter(func.lower(User.email) == email.strip().lower()).first()


def obtener_usuario_por_rut(db: Session, rut: str) -> User | None:
    """Busca un usuario por su RUT. Devuelve el usuario o None si no existe.

    Se usa para avisar si un RUT ya está registrado.
    """
    return db.query(User).filter(User.rut == rut).first()


def crear_usuario(
    db: Session,
    *,
    email: str,
    password: str,
    nombre: str,
    apellido: str,
    company_name: str | None = None,
    rut: str | None = None,
    telefono: str | None = None,
    fecha_nacimiento: str | None = None,
    role: str = "client",
) -> User:
    """Crea un usuario nuevo en la base de datos.

    La contraseña llega en texto plano y se cifra con bcrypt ANTES de guardarla.
    Devuelve el usuario ya creado (con su id asignado).
    """
    # Ciframos la contraseña: en la base solo queda el hash, nunca el texto real.
    hashed = cifrar_password(password)

    # Creamos el objeto usuario con todos sus datos.
    nuevo = User(
        email=email.strip().lower(),
        hashed_password=hashed,
        nombre=nombre,
        apellido=apellido,
        company_name=company_name,
        rut=rut,
        telefono=telefono,
        fecha_nacimiento=fecha_nacimiento,
        role=role,
    )

    # Lo agregamos y guardamos en la base de datos.
    db.add(nuevo)
    db.commit()
    # refresh trae de vuelta el usuario con el id que le asignó la base.
    db.refresh(nuevo)
    return nuevo

