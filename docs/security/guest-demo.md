# Demostración pública para invitados

VulnHunter puede exponer una demostración temporal mediante el botón
**Explorar demo como invitado**. El backend crea una sesión de corta duración
con el rol `guest`; no se omite la autenticación ni se comparte una cuenta con
contraseña.

## Controles

- `GUEST_MODE_ENABLED` activa o desactiva el endpoint `POST /auth/guest`.
- `GUEST_SESSION_MINUTES` limita la duración del token (60 minutos por defecto;
  el backend restringe el valor efectivo al intervalo de 5 a 120 minutos).
- El rol `guest` puede consultar exclusivamente recursos asociados a su usuario.
- No puede registrar o verificar sitios, iniciar escaneos, cambiar roles ni abrir
  la configuración administrativa.
- El frontend oculta las acciones de escritura y muestra permanentemente que se
  encuentra en modo de solo lectura.

La interfaz actual usa datos demostrativos en sus vistas generales. No deben
incorporarse datos de clientes reales a esta cuenta.

## Presentación con Quick Tunnel

1. Iniciar VulnHunter con Docker Compose.
2. Comprobar `http://127.0.0.1:3000` y `http://127.0.0.1:8000/health`.
3. Ejecutar:

   ```bash
   cloudflared tunnel --url http://127.0.0.1:3000
   ```

4. Generar el QR con la URL `https://...trycloudflare.com` entregada ese día.
5. Probar el QR desde un teléfono sin sesión previa.
6. Al finalizar, detener `cloudflared` y desactivar el modo invitado si ya no se
   utilizará.

Los Quick Tunnels cambian de URL en cada ejecución y no ofrecen garantía de
disponibilidad; sirven para la demostración, no como despliegue permanente.
