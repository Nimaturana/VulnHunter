# Laboratorio local de autorización

Este servicio Nginx permite probar el desafío HTTP sin comprar un dominio. No
contiene vulnerabilidades intencionales y está desactivado por defecto.

1. En `.env.docker`, usa temporalmente `ALLOW_PRIVATE_TARGETS=true`.
2. Inicia el perfil con:

```powershell
docker compose --profile lab --env-file .env.docker -f infra/compose/docker-compose.yml up --build -d
```

3. Registra `http://ownership-lab` mediante `POST /websites`.
4. Copia el token recibido en un archivo sin espacios adicionales:
   `infra/lab/challenge/vulnhunter-challenge.txt`.
5. Ejecuta `POST /websites/{id}/verify` con `method=http_file` y el token.
6. Un auditor puede iniciar el scan usando ese `website_id`.

El archivo del token está ignorado por Git. Cuando termines, vuelve a configurar
`ALLOW_PRIVATE_TARGETS=false` antes de trabajar con AWS o un entorno público.
