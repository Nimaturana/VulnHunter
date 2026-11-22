"""Funciones de seguridad para el manejo de contraseñas.

Usamos bcrypt para cifrar las contraseñas. NUNCA se guarda la contraseña
real en la base de datos, solo su versión cifrada (hash).
"""

import bcrypt


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

