# VulnHunter

VulnHunter es una plataforma en construcción para registrar activos web,
ejecutar evaluaciones de seguridad autorizadas, conservar hallazgos y generar
reportes. El repositorio está organizado como un **monolito modular por
funcionalidades (Package by Feature)**.

> Estado actual: primer MVP. Los scanners, la API y los reportes funcionan en
> memoria. Autenticación, PostgreSQL, Celery y el frontend se incorporarán cuando
> exista una primera necesidad funcional. No publiques la API ni escanees terceros
> sin permiso.

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

## Ejecutar el prototipo

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn vulnhunter.main:app --reload
```

La documentación local queda en `http://localhost:8000/docs`.

## Docker Compose

```powershell
docker compose -f infra/compose/docker-compose.yml up --build
```

PostgreSQL y Redis se levantan como infraestructura preparada, pero el
prototipo todavía conserva los escaneos en memoria y usa tareas de FastAPI.

## Próximas fases obligatorias

1. Autenticación, organizaciones y roles.
2. Registro y verificación de propiedad de activos.
3. política anti-SSRF aplicada a cada petición y redirección.
4. Persistencia PostgreSQL y migraciones Alembic.
5. Celery/Redis y workers aislados.
6. Scanners pasivos y activos con contratos y pruebas de laboratorio.
7. Frontend, alertas, historial y observabilidad.
