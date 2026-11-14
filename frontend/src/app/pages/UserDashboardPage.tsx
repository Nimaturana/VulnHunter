import { useState } from "react";
import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";
import type { Usuario } from "../../shared/api/auth";

// Paleta central para usar los mismos colores que el resto de la app.
import { theme } from "../../shared/styles/theme";

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
  // hallazgo abierto (para desplegar su descripción). Guarda el índice o null.
  const [abierto, setAbierto] = useState<number | null>(null);

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

              <div>
                <div style={{ fontSize: "13.5px", fontWeight: 600 }}>Valentina Rojas</div>
                <div style={{ fontSize: "12px", color: c.muted }}>Mi Empresa SpA</div>
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
              <button style={{ display: "inline-flex", alignItems: "center", gap: "8px", backgroundColor: c.primary, color: "#fff", border: 0, borderRadius: "9px", padding: "11px 18px", fontWeight: 600, fontSize: "14px", cursor: "pointer", boxShadow: "0 1px 2px rgba(37,99,235,.25)" }}>
                + Nuevo escaneo
              </button>
            </header>

            {/* 3 TARJETAS DE RESUMEN. */}
            <section style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "20px", marginBottom: "40px" }}>
              {[
                { value: "2", label: "Mis sitios", foot: "Plan Pyme · hasta 3 sitios" },
                { value: "7", label: "Mis escaneos", foot: "Último hace 2 días" },
                { value: "12", label: "Mis hallazgos", foot: "2 críticos" },
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

            <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: "20px" }}>
              {Object.values(SITES).map((s) => {
                const cnt = countBySev(s.findings);
                const total = s.findings.length;
                const tag = riskTagStyle[s.risk];
                return (
                  <div key={s.domain} style={{ ...card, padding: "24px", display: "flex", flexDirection: "column", gap: "22px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "12px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
                        <div style={{ width: "44px", height: "44px", borderRadius: "11px", border: `1px solid ${c.border}`, display: "grid", placeItems: "center", fontWeight: 600, fontSize: "16px", color: c.muted }}>
                          {s.domain[0].toUpperCase()}
                        </div>
                        <div>
                          <div style={{ fontSize: "17px", fontWeight: 600 }}>{s.domain}</div>
                          <div style={{ fontSize: "13px", color: c.muted, marginTop: "2px" }}>{s.url}</div>
                        </div>
                      </div>
                      <span style={{ fontSize: "13px", fontWeight: 600, padding: "5px 11px", borderRadius: "999px", background: tag.bg, color: tag.color }}>
                        Riesgo {riskName[s.risk]}
                      </span>
                    </div>

                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", border: `1px solid ${c.border}`, borderRadius: "11px", overflow: "hidden" }}>
                      <div style={{ padding: "14px 16px" }}>
                        <div style={{ fontSize: "12.5px", color: c.muted }}>Vulnerabilidades</div>
                        <div style={{ fontSize: "20px", fontWeight: 700, marginTop: "4px", display: "flex", alignItems: "baseline", gap: "6px" }}>
                          {total}<small style={{ fontSize: "13px", fontWeight: 500, color: c.muted }}>abiertas</small>
                        </div>
                      </div>
                      <div style={{ padding: "14px 16px", borderLeft: `1px solid ${c.border}` }}>
                        <div style={{ fontSize: "12.5px", color: c.muted }}>Último escaneo</div>
                        <div style={{ fontSize: "17px", fontWeight: 700, marginTop: "6px", display: "flex", alignItems: "baseline", gap: "6px" }}>
                          {s.date}<small style={{ fontSize: "13px", fontWeight: 500, color: c.muted }}>{s.time} h</small>
                        </div>
                      </div>
                    </div>

                    <div>
                      <div style={{ display: "flex", gap: "3px", height: "8px" }}>
                        {sevKeys.filter((k) => cnt[k]).map((k) => (
                          <span key={k} style={{ flex: cnt[k], background: sevColor[k], borderRadius: "3px" }} />
                        ))}
                      </div>
                      <div style={{ display: "flex", gap: "16px", fontSize: "12.5px", color: c.muted, marginTop: "10px" }}>
                        {sevKeys.map((k) => (
                          <span key={k}>
                            <i style={{ display: "inline-block", width: "8px", height: "8px", borderRadius: "2px", marginRight: "6px", background: sevColor[k] }} />
                            {sevName[k]}<b style={{ color: c.text, fontWeight: 600, marginLeft: "4px" }}>{cnt[k]}</b>
                          </span>
                        ))}
                      </div>
                    </div>

                    <div style={{ display: "flex", gap: "10px", paddingTop: "18px", borderTop: "1px solid #F1F2F4" }}>
                      {/* Ver detalle: abre la vista de detalle de ESTE sitio. */}
                      <button onClick={() => { setDetalle(s.domain); setAbierto(null); }} style={{ display: "inline-flex", alignItems: "center", gap: "7px", background: c.primary, color: "#fff", border: 0, borderRadius: "9px", padding: "9px 14px", fontWeight: 600, fontSize: "13.5px", cursor: "pointer", boxShadow: "0 1px 2px rgba(37,99,235,.25)" }}>
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
          </>
        ) : (
          /* ───────── VISTA DE DETALLE DEL SITIO ───────── */
          (() => {
            const s = SITES[detalle];
            const cnt = countBySev(s.findings);
            const total = s.findings.length;
            const tag = riskTagStyle[s.risk];
            // Datos para la dona (solo severidades con al menos 1 hallazgo).
            const donutData = sevKeys.filter((k) => cnt[k]).map((k) => ({ name: sevName[k], value: cnt[k], color: sevColor[k] }));
            return (
              <>
                {/* Migas de pan: volver a "Mis sitios". */}
                <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "13.5px", color: c.muted, marginBottom: "18px" }}>
                  <span style={{ cursor: "pointer" }} onClick={() => setDetalle(null)}>← Mis sitios</span>
                  <span>/</span>
                  <span style={{ color: c.text, fontWeight: 500 }}>{s.domain}</span>
                </div>

                {/* Cabecera del detalle: identidad + acciones. */}
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "28px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
                    <div style={{ width: "52px", height: "52px", borderRadius: "13px", border: `1px solid ${c.border}`, display: "grid", placeItems: "center", fontWeight: 600, fontSize: "19px", color: c.muted }}>
                      {s.domain[0].toUpperCase()}
                    </div>
                    <div>
                      <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                        <h1 style={{ margin: 0, fontSize: "26px", fontWeight: 700, letterSpacing: "-0.02em" }}>{s.domain}</h1>
                        <span style={{ fontSize: "13px", fontWeight: 600, padding: "5px 11px", borderRadius: "999px", background: tag.bg, color: tag.color }}>
                          Riesgo {riskName[s.risk]}
                        </span>
                      </div>
                      <div style={{ fontSize: "14px", color: c.muted, marginTop: "6px", display: "flex", gap: "14px" }}>
                        <span>Último escaneo: {s.date}, {s.time} h</span>
                        <span>{s.scans} escaneos realizados</span>
                      </div>
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: "10px" }}>
                    <button style={{ display: "inline-flex", alignItems: "center", gap: "7px", background: "#fff", color: c.text, border: `1px solid ${c.border}`, borderRadius: "9px", padding: "9px 14px", fontWeight: 500, fontSize: "13.5px", cursor: "pointer" }}>
                      Descargar reporte PDF
                    </button>
                    <button style={{ display: "inline-flex", alignItems: "center", gap: "7px", background: c.primary, color: "#fff", border: 0, borderRadius: "9px", padding: "9px 14px", fontWeight: 600, fontSize: "13.5px", cursor: "pointer", boxShadow: "0 1px 2px rgba(37,99,235,.25)" }}>
                      Volver a escanear
                    </button>
                  </div>
                </div>

                {/* Dos columnas: dona (izquierda) + hallazgos (derecha). */}
                <div style={{ display: "grid", gridTemplateColumns: "360px 1fr", gap: "20px", alignItems: "start" }}>
                  {/* COLUMNA IZQUIERDA: dona + nivel de riesgo. */}
                  <div style={card}>
                    <div style={{ padding: "20px 22px 0" }}>
                      <div style={{ fontSize: "16px", fontWeight: 600 }}>Vulnerabilidades por severidad</div>
                      <div style={{ fontSize: "13px", color: c.muted, marginTop: "3px" }}>Hallazgos del último escaneo</div>
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
                      {/* Lista de severidades. */}
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
                          <b style={{ color: c.text, fontSize: "14px" }}>{s.score} / 100</b>
                        </div>
                        <div style={{ height: "6px", borderRadius: "999px", background: "#F3F4F6", marginTop: "10px", overflow: "hidden" }}>
                          <div style={{ width: `${s.score}%`, height: "100%", borderRadius: "999px", background: `linear-gradient(90deg, ${c.severity.low}, ${c.severity.medium} 45%, ${c.severity.high} 75%, ${c.severity.critical})` }} />
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* COLUMNA DERECHA: lista de hallazgos desplegables. */}
                  <div style={card}>
                    <div style={{ padding: "20px 22px 16px" }}>
                      <div style={{ fontSize: "16px", fontWeight: 600 }}>Hallazgos</div>
                      <div style={{ fontSize: "13px", color: c.muted, marginTop: "3px" }}>Haz clic en un hallazgo para ver la descripción y cómo corregirlo</div>
                    </div>
                    <div>
                      {s.findings.map((f, i) => {
                        const abiertoEste = abierto === i; // ¿este hallazgo está desplegado?
                        const sTag = riskTagStyle[f.s];
                        return (
                          <div key={i} style={{ borderTop: `1px solid #F1F2F4` }}>
                            {/* Fila: severidad + título + estado + flecha. Al hacer clic se despliega. */}
                            <div onClick={() => setAbierto(abiertoEste ? null : i)} style={{ display: "grid", gridTemplateColumns: "96px 1fr 120px 20px", alignItems: "center", gap: "16px", padding: "16px 22px", cursor: "pointer" }}>
                              <span style={{ fontSize: "12px", fontWeight: 600, padding: "3px 9px", borderRadius: "999px", background: sTag.bg, color: sTag.color, justifySelf: "start" }}>
                                {sevName[f.s]}
                              </span>
                              <div>
                                <div style={{ fontSize: "14px", fontWeight: 500 }}>{f.t}</div>
                                <div style={{ fontSize: "12.5px", color: c.muted, marginTop: "3px", fontFamily: "ui-monospace, Menlo, monospace" }}>{f.loc}</div>
                              </div>
                              <span style={{ fontSize: "12.5px", color: c.muted, display: "inline-flex", alignItems: "center", gap: "6px" }}>
                                <span style={{ width: "7px", height: "7px", borderRadius: "50%", border: `1.5px solid ${f.st === "rev" ? c.primary : "#9CA3AF"}`, background: f.st === "rev" ? "#DBE6FE" : "transparent" }} />
                                {f.st === "rev" ? "En revisión" : "Abierto"}
                              </span>
                              <span style={{ color: "#9CA3AF", transform: abiertoEste ? "rotate(90deg)" : "none", transition: "transform .2s" }}>›</span>
                            </div>
                            {/* Cuerpo desplegable: descripción + cómo corregirlo. */}
                            {abiertoEste && (
                              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "24px", padding: "0 22px 20px 134px", fontSize: "13.5px", lineHeight: 1.6, color: "#374151" }}>
                                <div>
                                  <h4 style={{ fontSize: "12px", fontWeight: 600, color: c.muted, textTransform: "uppercase", letterSpacing: ".05em", marginBottom: "6px" }}>Descripción</h4>
                                  {f.d}
                                </div>
                                <div>
                                  <h4 style={{ fontSize: "12px", fontWeight: 600, color: c.muted, textTransform: "uppercase", letterSpacing: ".05em", marginBottom: "6px" }}>Cómo corregirlo</h4>
                                  {f.r}
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })}
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
