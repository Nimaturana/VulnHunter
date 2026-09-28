# Ejecutar VulnHunter con Docker

Docker permite ejecutar la API, PostgreSQL y Redis de forma aislada y
reproducible. El frontend se agregará cuando exista una aplicación React
ejecutable.

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

`API_PORT` controla el puerto visible en Windows. Si el puerto `8000` está
ocupado, usa otro disponible, por ejemplo `API_PORT=8080`.

## 3. Construir e iniciar

```powershell
docker compose --env-file .env.docker -f infra/compose/docker-compose.yml up --build -d
```

La primera construcción descarga las imágenes y puede tardar varios minutos.
Luego revisa el estado:

```powershell
docker compose --env-file .env.docker -f infra/compose/docker-compose.yml ps
```

Cuando `api`, `postgres` y `redis` estén saludables, abre las siguientes URLs
(reemplaza `8000` por el valor configurado en `API_PORT`):

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
- Redis usa el volumen `redis_data`.
- Los PDF se guardan en `artifacts/reports` del computador anfitrión.
- Al reiniciar o reconstruir contenedores los datos se conservan.

El siguiente comando elimina también los volúmenes y los datos de PostgreSQL y
Redis. Úsalo solamente cuando quieras reiniciar completamente el entorno:

```powershell
docker compose --env-file .env.docker -f infra/compose/docker-compose.yml down -v
```

## 6. Qué hace el arranque

Antes de iniciar Uvicorn, el contenedor crea únicamente las tablas que falten.
No borra tablas ni registros existentes. Cuando el esquema comience a cambiar,
esta inicialización deberá reemplazarse por migraciones Alembic versionadas.

## 7. Preparación futura para AWS

La misma imagen del backend podrá publicarse en Amazon ECR y ejecutarse en ECS
Fargate. Para una puesta en producción se recomienda separar los componentes:

- ECS Fargate para la API y, posteriormente, los workers.
- RDS PostgreSQL para la base de datos.
- S3 para los reportes PDF, en vez del disco del contenedor.
- Secrets Manager para contraseñas y claves.
- CloudWatch para logs y alertas.
- Application Load Balancer, HTTPS y AWS WAF delante de la API.
- Redis administrado solamente cuando Celery esté realmente integrado.

No se debe publicar el MVP en Internet antes de implementar autenticación,
verificación de propiedad de los sitios, límites de uso y protección anti-SSRF.
