# Base de datos del MVP

PostgreSQL es la persistencia principal de VulnHunter. El esquema se administra
con Alembic y se actualiza automáticamente al iniciar el contenedor de la API.
Las migraciones conservan los registros existentes y reemplazan el antiguo uso
de `Base.metadata.create_all` como mecanismo de actualización.

## Entidades

- `users`: cuenta, correo único, hash de contraseña, estado y creación.
- `websites`: activo web, propietario y verificación de autorización.
- `scans`: ejecución, solicitante, progreso, estado, riesgo y errores.
- `findings`: evidencia normalizada, severidad, recomendación y confianza.

Relaciones principales:

```text
users 1 ─── N websites 1 ─── N scans 1 ─── N findings
  └────────────────────────── N scans (requested_by_user_id)
```

`requested_by_user_id` y `website_id` permanecen opcionales hasta que se
incorporen autenticación y registro de activos al flujo de la API. Una vez
implementadas esas funcionalidades, todo escaneo iniciado por un usuario debe
guardar ambos identificadores.

El token de verificación de un sitio se almacena como
`verification_token_hash`; el token original no debe persistirse.

## Migraciones

Desde el directorio `backend`, para aplicar el esquema manualmente:

```powershell
alembic upgrade head
```

Con Docker Compose no hace falta ejecutar esa orden: el entrypoint de la API
aplica las migraciones antes de iniciar Uvicorn.

Para consultar la revisión activa dentro del contenedor:

```powershell
docker compose --env-file .env.docker -f infra/compose/docker-compose.yml exec api alembic current
```

No se deben editar ni eliminar migraciones que ya hayan sido aplicadas en una
base compartida. Los cambios posteriores se agregan como revisiones nuevas.
