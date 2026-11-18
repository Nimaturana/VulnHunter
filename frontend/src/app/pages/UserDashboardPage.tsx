import { useState, useEffect } from "react";
import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";
import type { Usuario } from "../../shared/api/auth";

// Paleta central para usar los mismos colores que el resto de la app.
import { theme } from "../../shared/styles/theme";

// Funciones para hablar con el backend sobre escaneos.
import { iniciarEscaneo, obtenerEscaneo, obtenerMisEscaneos, 
obtenerDetalleEscaneo, ApiError } from "../../shared/api/scans";
import type { ResumenEscaneo, DetalleEscaneo } from "../../shared/api/scans";

// Componente del detalle v2 de un sitio (archivo separado).
import DetalleSitio from "./DetalleSitio";






const c = theme.colors;

// Props: usuario conectado y onBack (cierra sesión / vuelve a la bienvenida).
type UserDashboardProps = {
  usuario: Usuario | null;
  onBack: () => void;
};


// Colores, nombres de severidad y de riesgo.
const sevColor = { crit: c.severity.critical, high: c.severity.high, med: c.severity.medium, low: c.severity.low };
const sevName = { crit: "Crítica", high: "Alta", med: "Media", low: "Baja" };
const riskName = { crit: "crítico", high: "alto", med: "medio", low: "bajo" };

// Estilo de la etiqueta de riesgo según nivel.
const riskTagStyle: Record<string, { bg: string; color: string }> = {
  crit: { bg: "#FEF2F2", color: c.severity.critical },
  high: { bg: "#FFF7ED", color: c.severity.high },
  med: { bg: "#FEFCE8", color: "#A16207" },
  low: { bg: "#F0FDF4", color: c.severity.low },
};

// Tipo de un hallazgo (vulnerabilidad).
type Finding = {
  s: "crit" | "high" | "med" | "low"; // severidad
  t: string;                          // título
  loc: string;                        // ubicación
  st: "open" | "rev";                 // estado: abierto o en revisión
  d: string;                          // descripción
  r: string;                          // cómo corregirlo
};

// Tipo de un sitio.
type Site = {
  domain: string;
  url: string;
  date: string;
  time: string;
  risk: "crit" | "high" | "med" | "low";
  score: number;        // nivel de riesgo 0-100
  scans: number;        // escaneos realizados
  findings: Finding[];
};

// Datos de ejemplo (luego vendrán del backend). Cada sitio con sus hallazgos reales.
const SITES: Record<string, Site> = {
  "mi-empresa.cl": {
    domain: "mi-empresa.cl", url: "https://mi-empresa.cl", date: "12 oct 2026", time: "10:42", risk: "high", score: 68, scans: 4,
    findings: [
      { s: "high", t: "Cabecera Content-Security-Policy ausente", loc: "/ (todas las páginas)", st: "open",
        d: "El sitio no define una política CSP, lo que facilita ataques de inyección de scripts (XSS) si existe otra vulnerabilidad.",
        r: "Configura la cabecera Content-Security-Policy en tu servidor, empezando por default-src 'self' y ampliando según lo necesario." },
      { s: "high", t: "Versión de WordPress desactualizada (6.2.1)", loc: "/wp-login.php", st: "rev",
        d: "La versión instalada tiene vulnerabilidades públicas conocidas que pueden ser explotadas de forma automatizada.",
        r: "Actualiza WordPress a la última versión estable y revisa que los plugins también estén al día." },
      { s: "high", t: "Formulario de contacto sin protección CSRF", loc: "/contacto", st: "open",
        d: "El formulario acepta envíos sin un token de verificación, lo que permite que terceros envíen solicitudes en nombre de tus visitantes.",
        r: "Agrega un token anti-CSRF a cada formulario y valídalo en el servidor." },
      { s: "med", t: "Cookie de sesión sin atributo Secure", loc: "Cookie: PHPSESSID", st: "open",
        d: "La cookie de sesión puede enviarse por conexiones no cifradas.",
        r: "Marca la cookie con los atributos Secure, HttpOnly y SameSite=Lax." },
      { s: "med", t: "Listado de directorios habilitado", loc: "/wp-content/uploads/", st: "open",
        d: "Cualquier visitante puede ver la lista completa de archivos subidos al sitio.",
        r: "Desactiva el listado de directorios (Options -Indexes en Apache o autoindex off en Nginx)." },
      { s: "med", t: "TLS 1.0 y 1.1 aún habilitados", loc: "mi-empresa.cl:443", st: "rev",
        d: "Versiones antiguas del protocolo TLS con debilidades criptográficas conocidas.",
        r: "Permite solo TLS 1.2 y 1.3 en la configuración del servidor." },
      { s: "low", t: "Versión del servidor visible en cabeceras", loc: "Server: Apache/2.4.41", st: "open",
        d: "Revelar la versión exacta ayuda a un atacante a buscar vulnerabilidades específicas.",
        r: "Oculta la versión con ServerTokens Prod y ServerSignature Off." },
    ],
  },
  "tienda.mi-empresa.cl": {
    domain: "tienda.mi-empresa.cl", url: "https://tienda.mi-empresa.cl", date: "08 oct 2026", time: "16:20", risk: "crit", score: 86, scans: 3,
    findings: [
      { s: "crit", t: "Inyección SQL en parámetro de búsqueda", loc: "/buscar?q=", st: "open",
        d: "El parámetro q se inserta directamente en la consulta a la base de datos, permitiendo leer o modificar información de clientes.",
        r: "Usa consultas parametrizadas (prepared statements) y valida la entrada del usuario." },
      { s: "crit", t: "Panel de administración expuesto sin 2FA", loc: "/admin", st: "open",
        d: "El panel es accesible públicamente y solo requiere usuario y contraseña, sin límite de intentos.",
        r: "Restringe el acceso por IP o VPN, activa autenticación de dos factores y limita los intentos de inicio de sesión." },
      { s: "high", t: "XSS reflejado en página de producto", loc: "/producto?ref=", st: "rev",
        d: "El parámetro ref se muestra en la página sin codificar, permitiendo ejecutar scripts en el navegador del visitante.",
        r: "Codifica toda salida HTML y aplica una política Content-Security-Policy." },
      { s: "med", t: "Falta cabecera Strict-Transport-Security", loc: "/ (todas las páginas)", st: "open",
        d: "Los navegadores podrían conectarse por HTTP antes de redirigir a HTTPS.",
        r: "Añade Strict-Transport-Security: max-age=31536000; includeSubDomains." },
      { s: "low", t: "Archivo robots.txt revela rutas internas", loc: "/robots.txt", st: "open",
        d: "El archivo lista rutas como /backup y /staging que no deberían ser públicas.",
        r: "Elimina las rutas sensibles de robots.txt y protégelas con autenticación." },
    ],
  },
};

// Cuenta cuántos hallazgos hay de cada severidad en un sitio.
const countBySev = (findings: Finding[]) =>
  (["crit", "high", "med", "low"] as const).reduce(
    (o, k) => ({ ...o, [k]: findings.filter((f) => f.s === k).length }),
    {} as Record<"crit" | "high" | "med" | "low", number>
  );

// Tarjeta blanca base.
const card: React.CSSProperties = {
  backgroundColor: c.surface,
  border: `1px solid ${c.border}`,
  borderRadius: "14px",
  boxShadow: "0 1px 2px rgba(16,24,40,.04), 0 4px 16px rgba(16,24,40,.04)",
};

const sevKeys = ["crit", "high", "med", "low"] as const;

function UserDashboard({ usuario, onBack }: UserDashboardProps) {
  // Nombre completo del usuario conectado (ej: "Carlos Méndez"). Si no hay, usamos un texto neutro.
  const nombreCompleto = usuario ? `${usuario.nombre} ${usuario.apellido}` : "Usuario";
  // Iniciales para el avatar (ej: "CM"). Si no hay usuario, "U".
  const iniciales = usuario
    ? `${usuario.nombre[0] ?? ""}${usuario.apellido[0] ?? ""}`.toUpperCase()
    : "U";
  // vista actual: "home" (lista de sitios) o el dominio del sitio en detalle.
  const [detalle, setDetalle] = useState<string | null>(null);
  
    // Guarda el scan_id del escaneo que el usuario abrió en el detalle.
  const [detalleScanId, setDetalleScanId] = useState<string | null>(null);

  
  // hallazgo abierto (para desplegar su descripción). Guarda el índice o null.
  const [abierto, setAbierto] = useState<number | null>(null);

    // ---- Estados del formulario "Nuevo escaneo" ----
  // Controla si el formulario para escanear está abierto o cerrado.
  const [formAbierto, setFormAbierto] = useState(false);
  // Guarda la dirección del sitio que el usuario quiere escanear.
  const [urlNueva, setUrlNueva] = useState("");
  // true mientras el escaneo está en marcha (para deshabilitar el botón y mostrar "Escaneando...").
  const [escaneando, setEscaneando] = useState(false);
  // Mensaje de error del formulario de escaneo (ej: "Ingresa una dirección válida").
  const [errorEscaneo, setErrorEscaneo] = useState("");




    // ---- Estados de los datos reales (traídos del backend) ----
  // Lista de escaneos del usuario que llegan desde /scans/mios.
  const [misEscaneos, setMisEscaneos] = useState<ResumenEscaneo[]>([]);
  // true mientras estamos cargando los datos por primera vez (para mostrar "Cargando…").
  const [cargando, setCargando] = useState(true);

  // ---- Función que trae los escaneos del usuario desde el backend ----
  // La separamos para poder llamarla al abrir el dashboard Y después de escanear.
  const cargarMisEscaneos = async () => {
    // Si no sabemos quién es el usuario, no hay nada que pedir.
    if (!usuario) {
      setCargando(false);
      return;
    }
    try {
      // Pedimos al backend la lista de escaneos de este usuario.
      const datos = await obtenerMisEscaneos(usuario.id);
      setMisEscaneos(datos);
    } catch {
      // Si falla (ej: backend apagado), dejamos la lista vacía.
      setMisEscaneos([]);
    } finally {
      // Pase lo que pase, dejamos de mostrar "Cargando…".
      setCargando(false);
    }
  };

  // ---- Estados del detalle real de un escaneo ----
  // Guarda el detalle (con hallazgos) del escaneo que el usuario abrió. null = no hay detalle abierto.
  const [detalleReal, setDetalleReal] = useState<DetalleEscaneo | null>(null);
  // true mientras cargamos el detalle desde el backend.
  const [cargandoDetalle, setCargandoDetalle] = useState(false);

  // ---- Función que abre el detalle real de un escaneo ----
  // Recibe el scan_id, pide el detalle al backend y lo guarda.
  const abrirDetalle = async (scanId: string) => {
    setCargandoDetalle(true);   // Mostramos "Cargando…".
    setAbierto(null);           // Cerramos cualquier hallazgo desplegado.
    try {
      const datos = await obtenerDetalleEscaneo(scanId);
      setDetalleReal(datos);    // Guardamos el detalle traído.
    } catch {
      setDetalleReal(null);     // Si falla, no mostramos detalle.
    } finally {
      setCargandoDetalle(false);
    }
  };

  

  // ---- Al abrir el dashboard, cargamos los escaneos del usuario una vez. ----
  useEffect(() => {
    cargarMisEscaneos();
    // Se vuelve a ejecutar si cambia el usuario conectado.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [usuario]);


    // ---- Función que ejecuta un escaneo nuevo ----
  // Se llama cuando el usuario aprieta "Escanear" en el formulario.
  // Manda la URL al backend, espera a que el escaneo termine, y avisa.
  const ejecutarEscaneo = async () => {
    // Limpiamos cualquier error anterior.
    setErrorEscaneo("");

    // Validación simple: que haya escrito algo.
    const url = urlNueva.trim();
    if (!url) {
      setErrorEscaneo("Ingresa la dirección de tu sitio (ej: https://mi-sitio.cl).");
      return;
    }

    // Validación simple: que empiece con http:// o https://
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      setErrorEscaneo("La dirección debe empezar con http:// o https://");
      return;
    }

    // Si no sabemos quién es el usuario, no podemos amarrar el escaneo.
    if (!usuario) {
      setErrorEscaneo("No se pudo identificar tu sesión. Vuelve a iniciar sesión.");
      return;
    }

    try {
      // Marcamos que estamos escaneando (esto deshabilita el botón y muestra "Escaneando...").
      setEscaneando(true);

      // 1) Disparamos el escaneo en el backend, mandando la URL y el id del usuario.
      const inicio = await iniciarEscaneo({
        url,
        requested_by_user_id: usuario.id,
      });

      // 2) El escaneo corre en segundo plano en el backend. Vamos preguntando
      //    cada 3 segundos si ya terminó, hasta 40 intentos (unos 2 minutos máx).
      let intentos = 0;
      let termino = false;
      while (intentos < 40 && !termino) {
        // Esperamos 3 segundos antes de volver a preguntar.
        await new Promise((r) => setTimeout(r, 3000));
        // Preguntamos el estado actual del escaneo.
        const estado = await obtenerEscaneo(inicio.scan_id);
        // Si el estado es "completed" o "partial", el escaneo terminó.
        if (estado.status === "completed" || estado.status === "partial") {
          termino = true;
        }
        intentos++;
      }

      // 3) Terminó (o se acabó el tiempo de espera). Cerramos el formulario y limpiamos.
      setEscaneando(false);
      setFormAbierto(false);
      setUrlNueva("");

      // Recargamos la lista de escaneos del usuario para que aparezca el sitio recién analizado.
      await cargarMisEscaneos();
    } catch (error) {
      // Si algo falla, dejamos de escanear y mostramos un mensaje claro.
      setEscaneando(false);
      if (error instanceof ApiError) {
        setErrorEscaneo("El servidor rechazó el escaneo. Revisa la dirección e intenta de nuevo.");
      } else {
        setErrorEscaneo("No se pudo conectar con el servidor. ¿Está encendido el backend?");
      }
    }
  };



  // ---- Agrupamos los escaneos por sitio (url) ----
  // Para cada url distinta, nos quedamos con su escaneo más reciente,
  // y contamos cuántos escaneos tiene ese sitio en total.
  const sitiosReales = (() => {
    // Un mapa: url -> { su escaneo más reciente, cuántos escaneos tiene }.
    const porSitio: Record<string, { ultimo: ResumenEscaneo; total: number }> = {};
    for (const esc of misEscaneos) {
      if (!porSitio[esc.url]) {
        // Primera vez que vemos esta url.
        porSitio[esc.url] = { ultimo: esc, total: 1 };
      } else {
        // Ya existía: sumamos uno y actualizamos el "último" si este es más nuevo.
        porSitio[esc.url].total += 1;
        const actual = porSitio[esc.url].ultimo;
        const fechaNueva = esc.completed_at ?? "";
        const fechaActual = actual.completed_at ?? "";
        if (fechaNueva > fechaActual) porSitio[esc.url].ultimo = esc;
      }
    }
    return Object.values(porSitio);
  })();

  // Traducimos el nivel de riesgo del backend (texto en inglés/mayúsculas) a nuestras claves.
  const nivelARiesgo = (nivel: string): "crit" | "high" | "med" | "low" => {
    const n = (nivel || "").toUpperCase();
    if (n === "CRITICAL") return "crit";
    if (n === "HIGH") return "high";
    if (n === "MEDIUM") return "med";
    return "low";
  };

  // Formatea una fecha ISO ("2026-10-12T10:42:00") a algo legible ("12 oct 2026").
  const formatearFecha = (iso: string | null): string => {
    if (!iso) return "—";
    try {
      const d = new Date(iso);
      return d.toLocaleDateString("es-CL", { day: "2-digit", month: "short", year: "numeric" });
    } catch {
      return "—";
    }
  };




  return (
    <div style={{ minHeight: "100vh", width: "100%", backgroundColor: c.background, color: c.text, fontFamily: "'Inter', Arial, sans-serif", boxSizing: "border-box" }}>
      {/* ───────── BARRA SUPERIOR ───────── */}
      <div style={{ background: c.surface, borderBottom: `1px solid ${c.border}`, position: "sticky", top: 0, zIndex: 10 }}>
        <div style={{ maxWidth: "1200px", margin: "0 auto", height: "68px", display: "flex", alignItems: "center", justifyContent: "space-between", padding: "0 24px" }}>
          {/* Logo: al hacer clic, vuelve a la lista de sitios. */}
          <div style={{ display: "flex", alignItems: "center", gap: "10px", cursor: "pointer" }} onClick={() => setDetalle(null)}>
            <div style={{ width: "34px", height: "34px", borderRadius: "9px", background: c.primary, display: "grid", placeItems: "center", color: "#fff", fontWeight: 700 }}>V</div>
            <div style={{ fontWeight: 700, fontSize: "16px" }}>VulnHunter</div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px", paddingRight: "14px", borderRight: `1px solid ${c.border}` }}>
             <div style={{ width: "34px", height: "34px", borderRadius: "50%", background: "#E0E7FF", color: c.primary, display: "grid", placeItems: "center", fontWeight: 600, fontSize: "13px" }}>{iniciales}</div>
              <div>
                <div style={{ fontSize: "13.5px", fontWeight: 600 }}>{nombreCompleto}</div>
                <div style={{ fontSize: "12px", color: c.muted }}>{usuario?.email ?? ""}</div>
              </div>

            </div>
            <button onClick={onBack} style={{ display: "inline-flex", alignItems: "center", gap: "7px", background: "none", border: 0, color: c.muted, fontWeight: 500, fontSize: "13.5px", cursor: "pointer", padding: "8px 10px", borderRadius: "8px" }}>
              ← Cerrar sesión
            </button>
          </div>
        </div>
      </div>

      <main style={{ maxWidth: "1200px", margin: "0 auto", padding: "40px 24px 64px" }}>
        {/* Si NO hay detalle abierto → mostramos la vista de inicio (sitios). */}
        {detalle === null ? (
          <>
            {/* ENCABEZADO. */}
            <header style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: "28px" }}>
              <div>
                <h1 style={{ margin: 0, fontSize: "30px", fontWeight: 700, letterSpacing: "-0.02em" }}>Hola, {usuario?.nombre ?? ""}</h1>
                <p style={{ color: c.muted, fontSize: "15px", margin: "6px 0 0" }}>Estado de seguridad de tus sitios</p>
              </div>
              {/* Botón que abre/cierra el formulario de nuevo escaneo. */}
              <button
                onClick={() => { setFormAbierto(!formAbierto); setErrorEscaneo(""); }}
                style={{ display: "inline-flex", alignItems: "center", gap: "8px", backgroundColor: c.primary, color: "#fff", border: 0, borderRadius: "9px", padding: "11px 18px", fontWeight: 600, fontSize: "14px", cursor: "pointer", boxShadow: "0 1px 2px rgba(37,99,235,.25)" }}
              >
                + Nuevo escaneo
              </button>
            </header>

            {/* ───────── FORMULARIO DE NUEVO ESCANEO ───────── */}
            {/* Solo se muestra cuando formAbierto es true (al apretar "+ Nuevo escaneo"). */}
            {formAbierto && (
              <div style={{ ...card, padding: "22px 24px", marginBottom: "32px" }}>
                <div style={{ fontSize: "16px", fontWeight: 600, marginBottom: "4px" }}>Escanear un sitio</div>
                <div style={{ fontSize: "13px", color: c.muted, marginBottom: "16px" }}>
                  Escribe la dirección completa de tu sitio web. El análisis puede tardar un par de minutos.
                </div>
                <div style={{ display: "flex", gap: "10px", alignItems: "flex-start" }}>
                  {/* Campo donde el usuario escribe la URL. */}
                  <input
                    type="text"
                    value={urlNueva}
                    onChange={(e) => setUrlNueva(e.target.value)}
                    placeholder="https://mi-sitio.cl"
                    disabled={escaneando}
                    style={{ flex: 1, padding: "11px 14px", borderRadius: "9px", border: `1px solid ${c.border}`, fontSize: "14px", fontFamily: "inherit", outline: "none" }}
                  />
                  {/* Botón que dispara el escaneo. Mientras escanea, se deshabilita y cambia el texto. */}
                  <button
                    onClick={ejecutarEscaneo}
                    disabled={escaneando}
                    style={{ backgroundColor: escaneando ? c.muted : c.primary, color: "#fff", border: 0, borderRadius: "9px", padding: "11px 20px", fontWeight: 600, fontSize: "14px", cursor: escaneando ? "default" : "pointer", whiteSpace: "nowrap" }}
                  >
                    {escaneando ? "Escaneando…" : "Escanear"}
                  </button>
                </div>
                {/* Mensaje de error, si lo hay. */}
                {errorEscaneo && (
                  <div style={{ color: c.severity.critical, fontSize: "13px", marginTop: "10px" }}>{errorEscaneo}</div>
                )}
                {/* Aviso mientras escanea, para que el usuario sepa que debe esperar. */}
                {escaneando && (
                  <div style={{ color: c.muted, fontSize: "13px", marginTop: "10px" }}>
                    Analizando tu sitio… esto puede tardar un par de minutos. No cierres esta ventana.
                  </div>
                )}
              </div>
            )}


            {/* 3 TARJETAS DE RESUMEN. */}
                       {/* 3 TARJETAS DE RESUMEN (con datos reales). */}
            <section style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "20px", marginBottom: "40px" }}>
              {[
                { value: String(sitiosReales.length), label: "Mis sitios", foot: "Sitios asociados a tu cuenta" },
                { value: String(misEscaneos.length), label: "Mis escaneos", foot: "Escaneos realizados en total" },
                {
                  value: String(misEscaneos.reduce((suma, e) => suma + (e.total_vulnerabilities || 0), 0)),
                  label: "Mis hallazgos",
                  foot: "Vulnerabilidades detectadas",
                },
              ].map((r) => (
                <div key={r.label} style={{ ...card, padding: "22px 24px", display: "flex", alignItems: "center", gap: "18px" }}>
                  <div>
                    <div style={{ fontSize: "32px", fontWeight: 700, letterSpacing: "-0.025em", lineHeight: 1 }}>{r.value}</div>
                    <div style={{ fontSize: "14px", fontWeight: 500, marginTop: "6px" }}>{r.label}</div>
                  </div>
                  <div style={{ marginLeft: "auto", fontSize: "12.5px", color: c.muted, textAlign: "right", lineHeight: 1.5 }}>{r.foot}</div>
                </div>
              ))}
            </section>


                      {/* SECCIÓN "MIS SITIOS". */}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "16px" }}>
              <h2 style={{ fontSize: "18px", fontWeight: 600, margin: 0 }}>Mis sitios</h2>
              <span style={{ fontSize: "13px", color: c.muted }}>Solo se muestran los sitios asociados a tu cuenta</span>
            </div>

            {/* CASO 1: todavía estamos cargando los datos del backend. */}
            {cargando ? (
              <div style={{ ...card, padding: "48px 24px", textAlign: "center", color: c.muted }}>
                Cargando tus sitios…
              </div>
            ) : sitiosReales.length === 0 ? (
              /* CASO 2: el usuario no tiene ningún escaneo todavía → estado vacío. */
              <div style={{ ...card, padding: "56px 24px", textAlign: "center" }}>
                {/* Ícono de escudo. */}
                <div style={{ width: "64px", height: "64px", borderRadius: "16px", background: "#EFF4FF", color: c.primary, display: "grid", placeItems: "center", margin: "0 auto 20px", fontSize: "30px" }}>
                  🛡️
                </div>
                <h3 style={{ fontSize: "19px", fontWeight: 700, margin: "0 0 8px" }}>Aún no has analizado ningún sitio</h3>
                <p style={{ fontSize: "14px", color: c.muted, margin: "0 auto 24px", maxWidth: "420px", lineHeight: 1.6 }}>
                  Analiza tu sitio web para descubrir vulnerabilidades y recibir recomendaciones de seguridad.
                </p>
                {/* Botón grande que abre el formulario de escaneo. */}
                <button
                  onClick={() => { setFormAbierto(true); setErrorEscaneo(""); }}
                  style={{ background: c.primary, color: "#fff", border: 0, borderRadius: "11px", padding: "14px 28px", fontWeight: 600, fontSize: "15px", cursor: "pointer", boxShadow: "0 1px 3px rgba(37,99,235,.3)" }}
                >
                  Analizar mi sitio
                </button>
              </div>
            ) : (
              /* CASO 3: el usuario tiene sitios → mostramos las tarjetas reales. */
              <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: "20px" }}>
                {sitiosReales.map(({ ultimo, total }) => {
                  // Datos reales de este sitio.
                  const riesgo = nivelARiesgo(ultimo.risk_level);
                  const tag = riskTagStyle[riesgo];
                  // Dominio legible a partir de la url (sin http:// ni barras).
                  const dominio = ultimo.url.replace(/^https?:\/\//, "").replace(/\/$/, "");
                  return (
                    <div key={ultimo.url} style={{ ...card, padding: "24px", display: "flex", flexDirection: "column", gap: "22px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "12px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
                          <div style={{ width: "44px", height: "44px", borderRadius: "11px", border: `1px solid ${c.border}`, display: "grid", placeItems: "center", fontWeight: 600, fontSize: "16px", color: c.muted }}>
                            {dominio[0]?.toUpperCase() ?? "?"}
                          </div>
                          <div>
                            <div style={{ fontSize: "17px", fontWeight: 600 }}>{dominio}</div>
                            <div style={{ fontSize: "13px", color: c.muted, marginTop: "2px" }}>{ultimo.url}</div>
                          </div>
                        </div>
                        <span style={{ fontSize: "13px", fontWeight: 600, padding: "5px 11px", borderRadius: "999px", background: tag.bg, color: tag.color }}>
                          Riesgo {riskName[riesgo]}
                        </span>
                      </div>

                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", border: `1px solid ${c.border}`, borderRadius: "11px", overflow: "hidden" }}>
                        <div style={{ padding: "14px 16px" }}>
                          <div style={{ fontSize: "12.5px", color: c.muted }}>Vulnerabilidades</div>
                          <div style={{ fontSize: "20px", fontWeight: 700, marginTop: "4px", display: "flex", alignItems: "baseline", gap: "6px" }}>
                            {ultimo.total_vulnerabilities}<small style={{ fontSize: "13px", fontWeight: 500, color: c.muted }}>detectadas</small>
                          </div>
                        </div>
                        <div style={{ padding: "14px 16px", borderLeft: `1px solid ${c.border}` }}>
                          <div style={{ fontSize: "12.5px", color: c.muted }}>Último escaneo</div>
                          <div style={{ fontSize: "16px", fontWeight: 700, marginTop: "6px" }}>
                            {formatearFecha(ultimo.completed_at)}
                          </div>
                        </div>
                      </div>

                      <div style={{ fontSize: "12.5px", color: c.muted }}>
                        {total} {total === 1 ? "escaneo realizado" : "escaneos realizados"}
                      </div>

                      <div style={{ display: "flex", gap: "10px", paddingTop: "18px", borderTop: "1px solid #F1F2F4" }}>
                        {/* Ver detalle: por ahora deshabilitado; lo conectaremos en la etapa 2. */}
                        
                          <button
                          onClick={() => { setDetalle(ultimo.url); setDetalleScanId(ultimo.scan_id); abrirDetalle(ultimo.scan_id); }}
                          style={{ display: "inline-flex", alignItems: "center", gap: "7px", background: c.primary, color: "#fff", border: 0, borderRadius: "9px", padding: "9px 14px", fontWeight: 600, fontSize: "13.5px", cursor: "pointer", boxShadow: "0 1px 2px rgba(37,99,235,.25)" }}
                        >
                          Ver detalle
                        </button>


                        <button style={{ display: "inline-flex", alignItems: "center", gap: "7px", background: "#fff", color: c.text, border: `1px solid ${c.border}`, borderRadius: "9px", padding: "9px 14px", fontWeight: 500, fontSize: "13.5px", cursor: "pointer" }}>
                          Descargar reporte PDF
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </>
        ) : (

          /* ───────── VISTA DE DETALLE DEL SITIO (nuevo componente DetalleSitio v2) ───────── */
          (() => {
            // Si tenemos el scan_id y la url, mostramos el nuevo detalle v2 (DetalleSitio).
            if (detalleScanId && detalle) {
              return (
                <DetalleSitio
                  scanId={detalleScanId}
                  url={detalle}
                  onVolver={() => { setDetalle(null); setDetalleScanId(null); setDetalleReal(null); }}
                />
              );
            }

            // Si no se pudo cargar el detalle, mostramos un mensaje y un botón para volver.
            if (!detalleReal) {
              return (
                <div style={{ ...card, padding: "48px 24px", textAlign: "center", color: c.muted }}>
                  No se pudo cargar el detalle. <span style={{ color: c.primary, cursor: "pointer" }} onClick={() => setDetalle(null)}>Volver a mis sitios</span>
                </div>
              );
            }

            // Traduce la severidad del backend (CRITICAL, HIGH...) a nuestras claves (crit, high...).
            const sevABackend = (sev: string): "crit" | "high" | "med" | "low" => {
              const v = (sev || "").toUpperCase();
              if (v === "CRITICAL") return "crit";
              if (v === "HIGH") return "high";
              if (v === "MEDIUM") return "med";
              return "low"; // LOW e INFO los agrupamos como "low".
            };

            // Dominio legible a partir de la url.
            const dominio = detalleReal.url.replace(/^https?:\/\//, "").replace(/\/$/, "");
            // Lista de hallazgos reales.
            const hallazgos = detalleReal.findings;
            const total = hallazgos.length;
            // Contamos cuántos hallazgos hay de cada severidad.
            const cnt = { crit: 0, high: 0, med: 0, low: 0 };
            for (const h of hallazgos) cnt[sevABackend(h.severity)]++;
            // Riesgo general del escaneo.
            const riesgo = (() => {
              const n = (detalleReal.risk_level || "").toUpperCase();
              if (n === "CRITICAL") return "crit";
              if (n === "HIGH") return "high";
              if (n === "MEDIUM") return "med";
              return "low";
            })();
            const tag = riskTagStyle[riesgo];
            // Datos para la dona (solo severidades con al menos 1 hallazgo).
            const donutData = sevKeys.filter((k) => cnt[k]).map((k) => ({ name: sevName[k], value: cnt[k], color: sevColor[k] }));

            return (
              <>
                {/* Migas de pan: volver a "Mis sitios". */}
                <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "13.5px", color: c.muted, marginBottom: "18px" }}>
                  <span style={{ cursor: "pointer" }} onClick={() => { setDetalle(null); setDetalleReal(null); }}>← Mis sitios</span>
                  <span>/</span>
                  <span style={{ color: c.text, fontWeight: 500 }}>{dominio}</span>
                </div>

                {/* Cabecera del detalle. */}
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "28px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
                    <div style={{ width: "52px", height: "52px", borderRadius: "13px", border: `1px solid ${c.border}`, display: "grid", placeItems: "center", fontWeight: 600, fontSize: "19px", color: c.muted }}>
                      {dominio[0]?.toUpperCase() ?? "?"}
                    </div>
                    <div>
                      <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                        <h1 style={{ margin: 0, fontSize: "26px", fontWeight: 700, letterSpacing: "-0.02em" }}>{dominio}</h1>
                        <span style={{ fontSize: "13px", fontWeight: 600, padding: "5px 11px", borderRadius: "999px", background: tag.bg, color: tag.color }}>
                          Riesgo {riskName[riesgo]}
                        </span>
                      </div>
                      <div style={{ fontSize: "14px", color: c.muted, marginTop: "6px" }}>
                        <span>{total} vulnerabilidades encontradas</span>
                      </div>
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: "10px" }}>
                    <button style={{ display: "inline-flex", alignItems: "center", gap: "7px", background: "#fff", color: c.text, border: `1px solid ${c.border}`, borderRadius: "9px", padding: "9px 14px", fontWeight: 500, fontSize: "13.5px", cursor: "pointer" }}>
                      Descargar reporte PDF
                    </button>
                  </div>
                </div>

                {/* Dos columnas: dona (izquierda) + hallazgos (derecha). */}
                <div style={{ display: "grid", gridTemplateColumns: "360px 1fr", gap: "20px", alignItems: "start" }}>
                  {/* COLUMNA IZQUIERDA: dona + nivel de riesgo. */}
                  <div style={card}>
                    <div style={{ padding: "20px 22px 0" }}>
                      <div style={{ fontSize: "16px", fontWeight: 600 }}>Vulnerabilidades por severidad</div>
                      <div style={{ fontSize: "13px", color: c.muted, marginTop: "3px" }}>Hallazgos de este escaneo</div>
                    </div>
                    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", padding: "18px 22px 22px" }}>
                      <div style={{ position: "relative", width: "200px", height: "200px", margin: "4px 0 20px" }}>
                        <ResponsiveContainer width={200} height={200}>
                          <PieChart>
                            <Pie data={donutData} dataKey="value" innerRadius={62} outerRadius={88} paddingAngle={2} stroke="none">
                              {donutData.map((d) => (<Cell key={d.name} fill={d.color} />))}
                            </Pie>
                          </PieChart>
                        </ResponsiveContainer>
                        <div style={{ position: "absolute", inset: 0, display: "grid", placeItems: "center", textAlign: "center" }}>
                          <div>
                            <div style={{ fontSize: "34px", fontWeight: 700, lineHeight: 1 }}>{total}</div>
                            <div style={{ fontSize: "12.5px", color: c.muted, marginTop: "4px" }}>Total</div>
                          </div>
                        </div>
                      </div>
                      {/* Lista de severidades con conteo y porcentaje. */}
                      <div style={{ width: "100%", display: "grid", gap: "4px" }}>
                        {sevKeys.map((k) => (
                          <div key={k} style={{ display: "grid", gridTemplateColumns: "12px 1fr auto 44px", alignItems: "center", gap: "10px", fontSize: "13.5px", padding: "8px 10px", borderRadius: "8px" }}>
                            <span style={{ width: "10px", height: "10px", borderRadius: "3px", background: sevColor[k] }} />
                            <span>{sevName[k]}</span>
                            <span style={{ fontWeight: 600 }}>{cnt[k]}</span>
                            <span style={{ color: c.muted, textAlign: "right", fontSize: "12.5px" }}>{total ? Math.round((cnt[k] / total) * 100) : 0}%</span>
                          </div>
                        ))}
                      </div>
                      {/* Nivel de riesgo del sitio con barra. */}
                      <div style={{ width: "100%", marginTop: "18px", paddingTop: "18px", borderTop: "1px solid #F1F2F4" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", fontSize: "13px", color: c.muted }}>
                          <span>Nivel de riesgo del sitio</span>
                          <b style={{ color: c.text, fontSize: "14px" }}>{detalleReal.risk_score} / 100</b>
                        </div>
                        <div style={{ height: "6px", borderRadius: "999px", background: "#F3F4F6", marginTop: "10px", overflow: "hidden" }}>
                          <div style={{ width: `${detalleReal.risk_score}%`, height: "100%", borderRadius: "999px", background: `linear-gradient(90deg, ${c.severity.low}, ${c.severity.medium} 45%, ${c.severity.high} 75%, ${c.severity.critical})` }} />
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* COLUMNA DERECHA: lista de hallazgos reales. */}
                  <div style={card}>
                    <div style={{ padding: "20px 22px 16px" }}>
                      <div style={{ fontSize: "16px", fontWeight: 600 }}>Hallazgos</div>
                      <div style={{ fontSize: "13px", color: c.muted, marginTop: "3px" }}>Haz clic en un hallazgo para ver la descripción y cómo corregirlo</div>
                    </div>
                    <div>
                      {total === 0 ? (
                        <div style={{ padding: "24px 22px", color: c.muted, fontSize: "14px" }}>
                          Este escaneo no encontró vulnerabilidades. ¡Buena noticia!
                        </div>
                      ) : (
                        hallazgos.map((f, i) => {
                          const abiertoEste = abierto === i;
                          const sKey = sevABackend(f.severity);
                          const sTag = riskTagStyle[sKey];
                          return (
                            <div key={i} style={{ borderTop: `1px solid #F1F2F4` }}>
                              <div onClick={() => setAbierto(abiertoEste ? null : i)} style={{ display: "grid", gridTemplateColumns: "96px 1fr 20px", alignItems: "center", gap: "16px", padding: "16px 22px", cursor: "pointer" }}>
                                <span style={{ fontSize: "12px", fontWeight: 600, padding: "3px 9px", borderRadius: "999px", background: sTag.bg, color: sTag.color, justifySelf: "start" }}>
                                  {sevName[sKey]}
                                </span>
                                <div>
                                  <div style={{ fontSize: "14px", fontWeight: 500 }}>{f.type}</div>
                                  <div style={{ fontSize: "12.5px", color: c.muted, marginTop: "3px", fontFamily: "ui-monospace, Menlo, monospace" }}>{f.location ?? ""}</div>
                                </div>
                                <span style={{ color: "#9CA3AF", transform: abiertoEste ? "rotate(90deg)" : "none", transition: "transform .2s" }}>›</span>
                              </div>
                              {abiertoEste && (
                                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "24px", padding: "0 22px 20px 134px", fontSize: "13.5px", lineHeight: 1.6, color: "#374151" }}>
                                  <div>
                                    <h4 style={{ fontSize: "12px", fontWeight: 600, color: c.muted, textTransform: "uppercase", letterSpacing: ".05em", marginBottom: "6px" }}>Descripción</h4>
                                    {f.description ?? "Sin descripción."}
                                  </div>
                                  <div>
                                    <h4 style={{ fontSize: "12px", fontWeight: 600, color: c.muted, textTransform: "uppercase", letterSpacing: ".05em", marginBottom: "6px" }}>Cómo corregirlo</h4>
                                    {f.recommendation ?? "Sin recomendación."}
                                  </div>
                                </div>
                              )}
                            </div>
                          );
                        })
                      )}
                    </div>
                  </div>
                </div>
              </>
            );
          })()
        )}
      </main>
    </div>
  );
}

export default UserDashboard;
