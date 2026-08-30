
# 🛡️ VulnHunter

**VulnHunter** es una plataforma de análisis de seguridad diseñada para detectar vulnerabilidades y debilidades de seguridad en aplicaciones y servicios web.

El proyecto integra un backend desarrollado con **Python y FastAPI**, una serie de módulos de análisis de seguridad y una estructura preparada para incorporar una interfaz web. Los resultados de los análisis pueden ser procesados y generados como reportes para facilitar la identificación y documentación de vulnerabilidades.

> ⚠️ **Uso responsable:** VulnHunter debe utilizarse únicamente contra sistemas, aplicaciones y redes sobre los cuales se tenga autorización explícita para realizar pruebas de seguridad.

---

## 📌 Características

VulnHunter incorpora diferentes módulos orientados al análisis de seguridad:

* 🔎 Escaneo de directorios.
* 💉 Detección de posibles vulnerabilidades de **SQL Injection**.
* 🖥️ Detección de vulnerabilidades de **Cross-Site Scripting (XSS)**.
* 🔐 Análisis de configuración **SSL/TLS**.
* 🛡️ Revisión de **Security Headers**.
* 📊 Generación de reportes de seguridad.
* ⚙️ Ejecución de tareas mediante procesamiento asíncrono.
* 🗄️ Integración con PostgreSQL.
* 🔄 Uso de Redis y Celery para gestionar tareas.
* 🌐 API desarrollada con FastAPI.

Los principales escáneres se encuentran en `backend/scanners/`. ([GitHub][3])

---

## 🏗️ Arquitectura del proyecto

```text
VulnHunter/
│
├── backend/
│   ├── app/
│   │   ├── models/
│   │   ├── reports/
│   │   ├── routes/
│   │   ├── schemas/
│   │   ├── utils/
│   │   ├── workers/
│   │   ├── config.py
│   │   ├── database.py
│   │   └── main.py
│   │
│   ├── reports/
│   ├── scanners/
│   │   ├── directory_scanner.py
│   │   ├── security_headers_scanner.py
│   │   ├── sql_injection_scanner.py
│   │   ├── ssl_scanner.py
│   │   └── xss_scanner.py
│   │
│   ├── docker-compose.yml
│   └── requirements.txt
│
├── frontend/
│
├── docs/
│
├── scripts/
│
├── tests/
│
├── .env.example
├── .gitignore
└── README.md
```

La estructura actual del repositorio contiene estos componentes principales. ([GitHub][1])

---

## ⚙️ Tecnologías utilizadas

### Backend

* **Python**
* **FastAPI**
* **Uvicorn**
* **SQLAlchemy**
* **PostgreSQL**
* **Alembic**
* **Pydantic**
* **Celery**
* **Redis**

### Análisis de seguridad

* Python-Nmap
* Requests
* BeautifulSoup
* LXML

### Reportes

* ReportLab
* Jinja2
* Matplotlib

### Testing y calidad

* Pytest
* Black
* Flake8

Las dependencias se encuentran definidas en `backend/requirements.txt`. ([GitHub][2])

---

## 📋 Requisitos

Antes de ejecutar VulnHunter se recomienda disponer de:

* Python 3.10 o superior.
* PostgreSQL.
* Redis.
* Git.
* Nmap.
* pip.

---

## 🚀 Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/Nimaturana/VulnHunter.git
cd VulnHunter
```

### 2. Crear un entorno virtual

```bash
python -m venv venv
```

### 3. Activar el entorno virtual

**Windows:**

```powershell
venv\Scripts\activate
```

**Linux/macOS:**

```bash
source venv/bin/activate
```

### 4. Instalar las dependencias

```bash
cd backend
pip install -r requirements.txt
```

---

## 🔐 Configuración

El proyecto incluye un archivo `.env.example` que contiene las variables necesarias para configurar la aplicación. ([GitHub][4])

Copiar el archivo:

```bash
cp .env.example .env
```

En Windows:

```powershell
copy .env.example .env
```

Luego configurar las variables correspondientes:

```env
DATABASE_URL=postgresql://usuario:contraseña@localhost:5432/vulnhunter

DB_HOST=localhost
DB_PORT=5432
DB_NAME=vulnhunter
DB_USER=usuario
DB_PASSWORD=contraseña

SECRET_KEY=tu_clave_secreta
DEBUG=True
ENVIRONMENT=development

ALLOWED_HOSTS=localhost,127.0.0.1

MAX_SCAN_TIMEOUT=300
CONCURRENT_SCANS=5
```

**No se deben almacenar credenciales reales dentro del repositorio.**

---

## 🗄️ Base de datos

VulnHunter utiliza **PostgreSQL** como sistema de gestión de base de datos.

Configura PostgreSQL y crea una base de datos para el proyecto.

Ejemplo:

```sql
CREATE DATABASE vulnhunter;
```

Luego configura las credenciales correspondientes en el archivo `.env`.

---

## ▶️ Ejecución

Desde la carpeta `backend`:

```bash
uvicorn app.main:app --reload
```

Por defecto, la API estará disponible en:

```text
http://127.0.0.1:8000
```

### Documentación de la API

FastAPI proporciona automáticamente documentación interactiva:

```text
http://127.0.0.1:8000/docs
```

Y documentación alternativa:

```text
http://127.0.0.1:8000/redoc
```

---

## 🔍 Escáneres

VulnHunter cuenta actualmente con diferentes módulos de análisis ubicados en:

```text
backend/scanners/
```

### SQL Injection

```text
sql_injection_scanner.py
```

Permite analizar posibles puntos vulnerables relacionados con inyección SQL.

### XSS

```text
xss_scanner.py
```

Permite identificar posibles vulnerabilidades de Cross-Site Scripting.

### SSL/TLS

```text
ssl_scanner.py
```

Analiza aspectos relacionados con la configuración SSL/TLS del objetivo.

### Security Headers

```text
security_headers_scanner.py
```

Permite revisar la presencia y configuración de encabezados de seguridad HTTP.

### Directory Scanner

```text
directory_scanner.py
```

Permite realizar reconocimiento de directorios y recursos disponibles en el objetivo.

Los módulos anteriores forman parte de la estructura actual del backend. ([GitHub][3])

---

## 📊 Reportes

Los resultados de los análisis pueden ser almacenados y procesados mediante el sistema de reportes del proyecto.

Los reportes existentes se encuentran dentro de:

```text
backend/reports/
```

Actualmente el repositorio contiene reportes generados en formato PDF. ([GitHub][5])

---

## 🔄 Procesamiento de tareas

VulnHunter incluye **Celery** y **Redis** para permitir la ejecución y gestión de tareas de análisis de forma asíncrona.

Esto permite separar las tareas de escaneo del procesamiento principal de la API y gestionar múltiples análisis.

---

## 🧪 Pruebas

Para ejecutar las pruebas del proyecto:

```bash
pytest
```

Para ejecutar las pruebas mostrando información detallada:

```bash
pytest -v
```

---

## 🧹 Calidad del código

El proyecto incluye herramientas como **Black** y **Flake8** para mantener una estructura y estilo consistente.

Formatear el código:

```bash
black .
```

Analizar posibles problemas:

```bash
flake8 .
```

---

## 🐳 Docker

El backend contiene un archivo:

```text
backend/docker-compose.yml
```

que está destinado a la configuración de los servicios mediante Docker Compose. ([GitHub][6])

Si el entorno Docker está configurado, puede iniciarse mediante:

```bash
cd backend
docker compose up --build
```

Para ejecutar los servicios en segundo plano:

```bash
docker compose up -d --build
```

Para detenerlos:

```bash
docker compose down
```

---

## 📁 Reportes y documentación

Los resultados generados pueden encontrarse en:

```text
backend/reports/
```

La carpeta destinada a documentación del proyecto es:

```text
docs/
```

---

## 🔒 Seguridad y uso responsable

VulnHunter está diseñado para fines de **auditoría, análisis de seguridad y pruebas autorizadas**.

No utilices esta herramienta para:

* Acceder a sistemas sin autorización.
* Realizar ataques contra terceros.
* Interrumpir servicios.
* Obtener información privada sin consentimiento.
* Ejecutar pruebas sobre infraestructura que no te pertenece o para la cual no tienes autorización.

El usuario es responsable de asegurarse de contar con los permisos necesarios antes de realizar cualquier análisis.

---

## 🤝 Contribuciones

Las contribuciones son bienvenidas.

Para contribuir:

1. Realiza un fork del repositorio.
2. Crea una nueva rama:

```bash
git checkout -b feature/nueva-funcionalidad
```

3. Realiza los cambios.
4. Ejecuta las pruebas.
5. Realiza un commit:

```bash
git commit -m "Agregar nueva funcionalidad"
```

6. Envía los cambios:

```bash
git push origin feature/nueva-funcionalidad
```

7. Abre un Pull Request.

---

## 📄 Licencia

Este proyecto se encuentra destinado a fines educativos y de investigación en ciberseguridad.

Si se incorpora una licencia específica al repositorio, esta sección deberá actualizarse para reflejar sus condiciones.

---

## 👨‍💻 Autores

**Nimaturana**
**LagartoChispa**
**
**

Repositorio:

[github.com/Nimaturana/VulnHunter](https://github.com/Nimaturana/VulnHunter)

---

## ⚠️ Disclaimer

VulnHunter es una herramienta de análisis de seguridad.

**El uso de esta herramienta debe realizarse únicamente sobre sistemas para los cuales se posea autorización.**

El autor no se hace responsable por daños, pérdidas o consecuencias derivadas del uso indebido de la herramienta.




