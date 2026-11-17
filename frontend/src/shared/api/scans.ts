// Funciones que hablan con el backend sobre escaneos (/scans y /scans/mios).
// Reutilizamos apiRequest, que ya sabe armar la URL y manejar errores.
import { apiRequest, ApiError } from "./client";

// --- Forma de los datos que enviamos al pedir un escaneo nuevo ---
// Coincide con lo que espera el backend (ScanRequest en Python).
// Solo 'url' y 'requested_by_user_id' nos importan por ahora; los scanners
// vienen activados por defecto en el backend, así que no hace falta mandarlos.
export type DatosEscaneo = {
  url: string;                      // Sitio que el usuario quiere escanear.
  requested_by_user_id?: number;    // Id del usuario conectado (para amarrar el escaneo a él).
};

// --- Forma de la respuesta al INICIAR un escaneo ---
// Es lo que devuelve POST /scans: confirma que el escaneo arrancó.
export type EscaneoIniciado = {
  scan_id: string;              // Identificador único del escaneo recién creado.
  status: string;              // Estado inicial (normalmente "pending").
  scanners_enabled: string[];  // Lista de scanners que se van a ejecutar.
  check_status_url: string;    // Ruta para consultar el avance del escaneo.
};

// --- Forma del RESUMEN de un escaneo ---
// Coincide con ScanSummary en Python. Es lo que devuelve GET /scans/mios.
export type ResumenEscaneo = {
  scan_id: string;                 // Identificador único del escaneo.
  url: string;                     // Sitio escaneado.
  status: string;                  // Estado: completed, running, pending, etc.
  total_vulnerabilities: number;   // Cantidad de hallazgos encontrados.
  risk_level: string;              // Nivel de riesgo: CRITICAL, HIGH, MEDIUM, LOW, INFO.
  completed_at: string | null;     // Fecha/hora en que terminó (null si aún no termina).
};

// --- Iniciar un escaneo nuevo ---
// Llama a POST /scans enviando la url y el id del usuario conectado.
// El backend responde 202 y empieza a escanear en segundo plano.
export async function iniciarEscaneo(datos: DatosEscaneo): Promise<EscaneoIniciado> {
  return apiRequest<EscaneoIniciado>("/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(datos),
  });
}

// --- Obtener los escaneos de un usuario ---
// Llama a GET /scans/mios?user_id=... y devuelve la lista de sus escaneos.
// Si el usuario no tiene escaneos todavía, devuelve una lista vacía.
export async function obtenerMisEscaneos(userId: number): Promise<ResumenEscaneo[]> {
  return apiRequest<ResumenEscaneo[]>(`/scans/mios?user_id=${userId}`, {
    method: "GET",
  });
}

// --- Consultar el estado de UN escaneo por su id ---
// Llama a GET /scans/{scan_id}. Sirve para ir viendo el avance mientras escanea.
// Devuelve el escaneo completo (lo tipamos flexible porque trae muchos campos).
export async function obtenerEscaneo(scanId: string): Promise<Record<string, unknown>> {
  return apiRequest<Record<string, unknown>>(`/scans/${scanId}`, {
    method: "GET",
  });
}

// Re-exportamos ApiError para poder reconocer errores en quien use estas funciones.
export { ApiError };
