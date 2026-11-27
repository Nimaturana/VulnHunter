# Autorización de alcance y control de roles

Antes de ejecutar una prueba activa, el usuario debe estar autenticado y el
sitio debe estar registrado, activo y verificado. Esto reduce el riesgo de usar
VulnHunter contra infraestructura de terceros.

## Roles

| Acción | Administrador | Auditor | Cliente |
|---|---:|---:|---:|
| Administrar roles | Sí | No | No |
| Registrar y verificar un sitio | Sí | Sí | Solo sus sitios |
| Iniciar un escaneo | Sí | Sí | No |
| Consultar evidencia técnica | Sí | Sí | No |
| Ver sus resúmenes y descargar sus PDF | Sí | Sí | Sí |

El backend decide los permisos usando el usuario autenticado. Ya no acepta un
`requested_by_user_id` enviado por el navegador, porque podía ser suplantado.

## Verificación de propiedad

Al registrar `https://empresa.cl`, la API genera un token aleatorio. En la base
de datos solo guarda su SHA-256 y el desafío vence después de 60 minutos. El
propietario demuestra control mediante:

1. **Archivo HTTP:** token exacto en
   `https://empresa.cl/.well-known/vulnhunter-challenge.txt`.
2. **DNS TXT:** registro `_vulnhunter-verification.empresa.cl` con el token.

La comprobación HTTP no sigue redirecciones. La política rechaza loopback,
link-local, redes privadas y direcciones reservadas de forma predeterminada.
Los formularios, enlaces y redirecciones fuera del mismo origen no se recorren.

`ALLOW_PRIVATE_TARGETS=true` existe exclusivamente para laboratorios locales
aislados. En AWS debe permanecer en `false`.

## Cómo probar el flujo

Antes de reconstruir Docker, agrega a tu `.env.docker` un secreto distinto del
de PostgreSQL:

```powershell
$bytes = [Security.Cryptography.RandomNumberGenerator]::GetBytes(48)
[Convert]::ToBase64String($bytes)
```

Copia el resultado en `AUTH_SECRET_KEY=...` y no lo subas a GitHub.

1. Reconstruye Docker y abre `http://localhost:8000/docs`.
2. Crea una cuenta con `POST /auth/register`.
3. Inicia sesión en `POST /auth/login` y copia `access_token`.
4. Pulsa **Authorize** en Swagger y pega el token. Si Swagger indica esquema
   `bearer`, no agregues manualmente la palabra `Bearer`.
5. Un administrador asigna auditor con `PATCH /auth/users/{id}/role` y
   `{"role":"auditor"}`.
6. Registra el sitio con `POST /websites`. Guarda el token mostrado: se entrega
   una sola vez.
7. Publica el archivo o TXT indicado.
8. Ejecuta `POST /websites/{id}/verify` con método y token.
9. Inicia `POST /scans` con `{"website_id": 1}`.
10. El cliente propietario puede listar `/scans/mios` y descargar el PDF, pero
    recibe 403 si intenta iniciar un scan o leer evidencia técnica.

Si no tienes un dominio, sigue `infra/lab/README.md`: el perfil Docker `lab`
permite verificar `http://ownership-lab` dentro de la red local. Nunca actives
`ALLOW_PRIVATE_TARGETS` en AWS.

En una instalación nueva, el primer administrador se crea como operación de
bootstrap en PostgreSQL; el registro público siempre crea un cliente:

```sql
UPDATE users SET role = 'admin' WHERE email = 'administrador@ejemplo.cl';
```

Después debe usarse la API de roles. Nunca debe permitirse elegir `admin` o
`auditor` desde el registro público.

## Límites conocidos del MVP

- El token está en `localStorage`; una versión comercial debería usar cookies
  `HttpOnly`, rotación de sesión y protección CSRF.
- La verificación técnica no reemplaza un contrato ni las reglas de compromiso
  de `docs/rules-of-engagement/template.yml`.
- La defensa completa ante DNS rebinding requiere validar cada conexión y
  filtrar el egreso de red del worker.
- Falta auditoría inmutable de cambios de rol, verificaciones y escaneos.
