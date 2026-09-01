# Modelo de amenazas inicial

Antes de habilitar escaneos públicos deben mitigarse, como mínimo:

- SSRF contra loopback, redes privadas, link-local y metadata cloud.
- DNS rebinding y redirecciones hacia destinos fuera de alcance.
- Escaneo de activos sin autorización verificable.
- Abuso de workers para denegación de servicio.
- Payloads destructivos o cambios de estado en el objetivo.
- Acceso cruzado a URLs, hallazgos, evidencias y reportes de otro tenant.
- Fuga de cookies, tokens, secretos o datos personales en logs y PDFs.
- Fórmulas de riesgo manipulables y falsos positivos no revisados.

La validación debe ejecutarse en cada petición saliente, no solamente al crear
el escaneo. Los workers deben tener egreso de red restringido y límites de
tiempo, bytes, URLs y concurrencia.
