# Configurar inicio de sesión con Google

VulnHunter utiliza Google Identity Services. El navegador recibe un ID token y
lo envía a `POST /auth/google`; el backend valida firma, audiencia, expiración y
correo verificado usando la librería oficial `google-auth`.

## Crear el cliente en Google Cloud

1. En Google Cloud Console abre **Google Auth Platform**.
2. Configura **Branding** con el nombre VulnHunter y un correo de soporte.
3. En **Audience**, usa `External` y mantén la aplicación en modo de pruebas.
4. Agrega como usuarios de prueba los correos del equipo y del profesor.
5. En **Clients**, crea un cliente **Web application**.
6. Agrega estos orígenes JavaScript autorizados:

```text
http://localhost:3000
http://localhost:5173
```

Para AWS agrega además el origen HTTPS real. Un Quick Tunnel cambia de dominio
en cada ejecución, por lo que tendrías que registrar cada URL nueva; para una
demostración estable conviene un dominio o Named Tunnel.

Este flujo popup no necesita una URI de redirección ni un client secret.

## Configurar VulnHunter

Copia el valor terminado en `.apps.googleusercontent.com`:

```env
GOOGLE_CLIENT_ID=123456789-ejemplo.apps.googleusercontent.com
```

Debe ser el mismo ID para backend y frontend. Docker Compose lo entrega al API
y lo incorpora al build de React. Después reconstruye:

```powershell
docker compose --env-file .env.docker -f infra/compose/docker-compose.yml up --build -d
```

Una cuenta Google nueva se crea como `client`. Si ya existe una cuenta local
con el mismo correo verificado, se vincula con ese usuario y conserva su rol.

Nunca guardes un client secret de Google en React ni publiques `.env.docker`.
