# VulnHunter

VulnHunter es una plataforma en construcción para registrar activos web,
ejecutar evaluaciones de seguridad autorizadas, conservar hallazgos y generar
reportes. El repositorio está organizado como un **monolito modular por
funcionalidades (Package by Feature)**.

> Estado actual: primer MVP. Los scanners, la API y los reportes funcionan en
> memoria, con persistencia inicial de escaneos en PostgreSQL cuando la base de
> datos está disponible. Autenticación, Celery y el frontend se incorporarán en
> fases posteriores. No publiques la API ni escanees terceros sin permiso.

## Estructura

- `backend/vulnhunter/scans`: endpoints, modelos, progreso y coordinación de escaneos.
- `backend/vulnhunter/scanners`: detectores XSS, SQLi, headers, TLS y directorios.
- `backend/vulnhunter/reports`: generación de reportes PDF.
- `backend/vulnhunter/system`: estado de la aplicación y estadísticas.
- `frontend`: aplicación React futura organizada por funcionalidades.
- `tests`: pruebas automatizadas que ya forman parte del MVP.
- `infra`: Docker y composición de servicios.
- `docs`: arquitectura, amenazas, reglas de compromiso y reportes de ejemplo.
- `artifacts`: archivos generados localmente; no se versionan.

## Ejecución tradicional (desarrollo rápido)

Docker no es obligatorio para modificar el backend. FastAPI puede seguir
ejecutándose directamente con el entorno virtual:

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m uvicorn vulnhunter.main:app --reload
```

La documentación local queda en `http://localhost:8000/docs`. Esta modalidad
es útil para trabajar rápidamente en scanners, API o reportes, pero no inicia
PostgreSQL ni Redis. Para probar el sistema completo se recomienda Docker.

## Pruebas

Instala las herramientas de desarrollo una vez desde `backend`:

```powershell
python -m pip install -e ".[dev]"
```

Después ejecuta las pruebas desde la raíz del repositorio:

```powershell
.\backend\.venv\Scripts\python.exe -m pytest -q
```

## Docker Compose

Docker es la modalidad recomendada para integración, demostraciones y pruebas
del sistema completo porque inicia FastAPI, PostgreSQL y Redis juntos.

La primera vez, crea el archivo privado de configuración y cambia su contraseña:

```powershell
Copy-Item .env.docker.example .env.docker
docker compose --env-file .env.docker -f infra/compose/docker-compose.yml up --build -d
```

En los siguientes inicios, si el código no cambió, basta con:

```powershell
docker compose --env-file .env.docker -f infra/compose/docker-compose.yml up -d
```

Si cambió el código Python, una dependencia o el Dockerfile, reconstruye la
imagen:

```powershell
docker compose --env-file .env.docker -f infra/compose/docker-compose.yml up --build -d
```

Para detener los contenedores conservando los datos:

```powershell
docker compose --env-file .env.docker -f infra/compose/docker-compose.yml down
```

La URL depende de `API_PORT` en `.env.docker`. En este equipo se utiliza
`http://localhost:8080/docs` porque Windows tiene ocupado el puerto `8000`.

No ejecutes Uvicorn tradicional y la API Docker simultáneamente usando el mismo
puerto. Antes de una entrega o demostración, valida siempre el proyecto con
Docker.

PostgreSQL recibe una copia de los escaneos y Redis queda preparado para la
fase de colas. El prototipo todavía conserva los escaneos en memoria y usa
tareas de FastAPI como mecanismo principal.

La guía completa de instalación, operación y solución de problemas está en
[`docs/deployment/docker.md`](docs/deployment/docker.md).

## Próximas fases obligatorias

1. Autenticación, organizaciones y roles.
2. Registro y verificación de propiedad de activos.
3. política anti-SSRF aplicada a cada petición y redirección.
4. Completar persistencia PostgreSQL y migraciones Alembic.
5. Celery/Redis y workers aislados.
6. Scanners pasivos y activos con contratos y pruebas de laboratorio.
7. Frontend, alertas, historial y observabilidad.
