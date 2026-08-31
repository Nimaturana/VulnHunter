# Arquitectura de VulnHunter

## Estilo

El proyecto usa un **monolito modular organizado por funcionalidades**. Cada
módulo reúne los elementos relacionados con una capacidad del producto:

```text
main.py -> router.py -> scans/routes.py -> scans/service.py
                                      -> scanners/
                                      -> reports/
```

- **scans** reúne rutas, modelos, progreso, scoring y coordinación.
- **scanners** contiene cada detector de vulnerabilidades.
- **reports** genera PDFs y futuras exportaciones.
- **system** contiene el estado de salud y las estadísticas de la API.

Los módulos de autenticación, base de datos y procesamiento distribuido se
agregarán únicamente cuando el MVP los implemente. Este diseño evita carpetas
vacías y permite que el proyecto crezca sin reorganizar el núcleo actual.

## Flujo futuro

```text
Cliente -> API -> autorización del activo -> PostgreSQL -> Redis/Celery
                                                        -> worker aislado
                                                        -> findings
                                                        -> reporte/alerta
```

## Regla de dependencias

`main.py` solo configura FastAPI. Las rutas delegan en servicios, los servicios
coordinan scanners y reportes, y los scanners no importan rutas HTTP.

## Deuda explícita del prototipo

El repositorio en memoria y `BackgroundTasks` están aislados en el servicio de
escaneo para facilitar su reemplazo. No representan la arquitectura final.
