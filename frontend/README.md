# Frontend de VulnHunter

Interfaz React y TypeScript del MVP. Está organizada por funcionalidades para
mantener separados autenticación, sitios, escaneos, hallazgos, reportes y
configuración.

## Desarrollo

```powershell
npm install
npm run dev
```

La aplicación se abre en `http://127.0.0.1:5173`. La URL del backend se define
con `VITE_API_URL`; copia `.env.example` como `.env.local` cuando necesites
sobrescribirla.

## Validación

```powershell
npm run typecheck
npm run build
```

El cliente HTTP compartido está preparado en `src/shared/api/client.ts`, pero
las pantallas todavía utilizan datos de demostración hasta completar la
integración con FastAPI.
