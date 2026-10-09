# Ejecutar VulnHunter con Docker

Docker permite ejecutar el frontend React, la API, PostgreSQL, Redis y el worker
Celery de forma aislada y reproducible.

## 1. Requisitos en Windows

1. Instala WSL 2.
2. Instala Docker Desktop y selecciona el motor basado en WSL 2.
3. Reinicia Windows si el instalador lo solicita.
4. Abre Docker Desktop y espera hasta que indique que el motor está activo.

Comprueba la instalación en una terminal nueva:

```powershell
docker --version
docker compose version
```

## 2. Configuración local

Desde la raíz de VulnHunter crea el archivo privado de variables:

```powershell
Copy-Item .env.docker.example .env.docker
```

Abre `.env.docker` y reemplaza `POSTGRES_PASSWORD` por una contraseña larga.
Este archivo está ignorado por Git y nunca debe subirse a GitHub.

`FRONTEND_PORT` controla la interfaz web y `API_PORT` la API visible en Windows.
Si `8000` está ocupado, usa por ejemplo `API_PORT=8080`; el frontend seguirá
conectándose internamente mediante `/api`.

## 3. Construir e iniciar

```powershell
docker compose --env-file .env.docker -f infra/compose/docker-compose.yml up --build -d
```

La primera construcción descarga las imágenes y puede tardar varios minutos.
Luego revisa el estado:

```powershell
docker compose --env-file .env.docker -f infra/compose/docker-compose.yml ps
```

Cuando `frontend`, `api`, `worker`, `postgres` y `redis` estén saludables, abre:

- Aplicación: <http://localhost:3000/>
- API: <http://localhost:8000/>
- Swagger: <http://localhost:8000/docs>
- Salud: <http://localhost:8000/health>

## 4. Logs y operación diaria

Ver los logs de todos los servicios:

```powershell
docker compose --env-file .env.docker -f infra/compose/docker-compose.yml logs -f
```

Ver solamente la API:

```powershell
docker compose --env-file .env.docker -f infra/compose/docker-compose.yml logs -f api
```

Ver el progreso real de scanners y tareas Celery:

```powershell
docker compose --env-file .env.docker -f infra/compose/docker-compose.yml logs -f worker
```

Detener los servicios conservando datos:

```powershell
docker compose --env-file .env.docker -f infra/compose/docker-compose.yml down
```

Volver a iniciarlos:

```powershell
docker compose --env-file .env.docker -f infra/compose/docker-compose.yml up -d
```

## 5. Persistencia

- PostgreSQL usa el volumen `postgres_data`.
- Redis usa el volumen `redis_data` como broker y backend temporal de Celery.
- Los PDF se guardan en `artifacts/reports` del computador anfitrión.
- PostgreSQL registra `task_id`, ejecución, progreso, estado del PDF, tamaño,
  hash SHA-256 y cantidad de descargas.
- Al reiniciar o reconstruir contenedores los datos se conservan.

El siguiente comando elimina también los volúmenes y los datos de PostgreSQL y
Redis. Úsalo solamente cuando quieras reiniciar completamente el entorno:

```powershell
docker compose --env-file .env.docker -f infra/compose/docker-compose.yml down -v
```

## 6. Qué hace el arranque

Antes de iniciar Uvicorn, el contenedor aplica las migraciones Alembic
versionadas. No borra tablas ni registros existentes. Nginx sirve React y
redirige las solicitudes `/api` a FastAPI; la API publica tareas en Redis y el
worker Celery ejecuta los scanners y genera el PDF.

## 7. Preparación futura para AWS

La misma imagen del backend podrá publicarse en Amazon ECR y ejecutarse en ECS
Fargate. Para una puesta en producción se recomienda separar los componentes:

- ECS Fargate para la API y los workers Celery.
- RDS PostgreSQL para la base de datos.
- S3 para los reportes PDF, en vez del disco del contenedor.
- Secrets Manager para contraseñas y claves.
- CloudWatch para logs y alertas.
- Application Load Balancer, HTTPS y AWS WAF delante de la API.
- ElastiCache/Valkey o Redis administrado para el broker Celery.

No se debe publicar el MVP en Internet antes de implementar autenticación,
verificación de propiedad de los sitios, límites de uso y protección anti-SSRF.
