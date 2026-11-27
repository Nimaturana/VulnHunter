import { useEffect, useState } from "react";
// Paleta central del proyecto (mismo estilo claro que el resto).
import { theme } from "../../../shared/styles/theme";

// Atajos para escribir menos.
const c = theme.colors;
const sev = c.severity;

// Props que recibe desde App.tsx:
// - onStart: botón "Comenzar análisis" -> lleva al login.
// - onLogin: botón "Iniciar sesión" -> lleva al login.
type WelcomeProps = {
  onStart: () => void;
  onLogin: () => void;
};

// Fondos suaves para las etiquetas de severidad (versión clara de cada color).
const sevBg = {
  critical: "#FEF2F2",
  high: "#FFF7ED",
  medium: "#FEFCE8",
  low: "#F0FDF4",
};

function Welcome({ onStart, onLogin }: WelcomeProps) {
  // Cambia el borde de la barra superior al hacer scroll (como el script del diseño).
  const [scrolled, setScrolled] = useState(false);
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  // --- Estilos reutilizables ---
  const container = { maxWidth: "1200px", margin: "0 auto", padding: "0 24px" };
  const card = {
    background: c.surface,
    border: `1px solid ${c.border}`,
    borderRadius: "11px",
    boxShadow: "0 1px 2px rgba(16,24,40,.04), 0 4px 16px rgba(16,24,40,.04)",
  } as const;
  const btn = {
    display: "inline-flex",
    alignItems: "center",
    gap: "8px",
    background: c.primary,
    color: "#fff",
    border: 0,
    borderRadius: "10px",
    padding: "14px 22px",
    font: "600 15px Inter, sans-serif",
    cursor: "pointer",
  } as const;
  const btnSec = {
    display: "inline-flex",
    alignItems: "center",
    gap: "8px",
    background: "#fff",
    color: c.text,
    border: `1px solid ${c.border}`,
    borderRadius: "10px",
    padding: "13px 20px",
    font: "500 15px Inter, sans-serif",
    cursor: "pointer",
  } as const;
  // Etiqueta de severidad (pill de color).
  const tag = (color: string, bg: string) => ({
    display: "inline-flex",
    alignItems: "center",
    gap: "5px",
    fontSize: "11px",
    fontWeight: 600,
    padding: "2px 8px",
    borderRadius: "999px",
    background: bg,
    color,
  });

  return (
    <div style={{ background: c.background, color: c.text, minHeight: "100vh", fontFamily: "Inter, sans-serif" }}>
      {/* ===== Barra de navegación ===== */}
      <header
        style={{
          position: "sticky",
          top: 0,
          zIndex: 20,
          background: c.background,
          borderBottom: `1px solid ${scrolled ? c.border : "transparent"}`,
          transition: "border-color .2s",
        }}
      >
        <div className="welcome-container" style={{ ...container, height: "68px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <div style={{ width: "34px", height: "34px", borderRadius: "9px", background: c.primary, display: "grid", placeItems: "center", color: "#fff", fontWeight: 700 }}>V</div>
            <div style={{ fontWeight: 700, fontSize: "16px" }}>VulnHunter</div>
          </div>
          <button onClick={onLogin} style={btnSec}>Iniciar sesión</button>
        </div>
      </header>

      {/* ===== HERO ===== */}
      <section className="welcome-hero" style={{ padding: "80px 0 0", textAlign: "center" }}>
        <div className="welcome-container" style={container}>
          <span style={{ display: "inline-flex", alignItems: "center", gap: "8px", background: "#fff", border: `1px solid ${c.border}`, borderRadius: "999px", padding: "6px 14px 6px 8px", fontSize: "13px", fontWeight: 500, color: c.muted }}>
            <b style={{ background: "#EFF4FF", color: c.primary, fontWeight: 600, fontSize: "12px", padding: "2px 8px", borderRadius: "999px" }}>Seguridad web</b>
            Análisis para sitios autorizados
          </span>
          <h1 className="welcome-title" style={{ fontSize: "56px", fontWeight: 700, lineHeight: 1.06, margin: "26px auto 0", maxWidth: "820px", letterSpacing: "-.035em" }}>
            Encuentra las vulnerabilidades de tu sitio <span style={{ color: c.primary }}>antes que otros.</span>
          </h1>
          <p style={{ fontSize: "18px", color: c.muted, lineHeight: 1.6, maxWidth: "600px", margin: "22px auto 0" }}>
            Detecta vulnerabilidades, evalúa riesgos y genera reportes de seguridad para sitios web autorizados.
          </p>
          <div className="welcome-actions" style={{ display: "flex", gap: "12px", justifyContent: "center", marginTop: "36px" }}>
            <button onClick={onStart} style={btn}>Comenzar análisis →</button>
            <button onClick={onLogin} style={btnSec}>Iniciar sesión</button>
          </div>
          <p style={{ fontSize: "13px", color: "#9CA3AF", marginTop: "18px" }}>
            🛡️ Solo se analizan sitios con propiedad o autorización verificada
          </p>

          {/* Preview del dashboard (decorativo) */}
          <div className="welcome-preview" style={{ margin: "64px auto 0", maxWidth: "1080px" }}>
            <div style={{ background: "#fff", border: `1px solid ${c.border}`, borderRadius: "16px 16px 0 0", borderBottom: 0, boxShadow: "0 24px 60px rgba(16,24,40,.08)", overflow: "hidden", textAlign: "left", height: "520px" }}>
              {/* barra del navegador falso */}
              <div style={{ height: "40px", borderBottom: `1px solid ${c.border}`, display: "flex", alignItems: "center", gap: "7px", padding: "0 16px", background: "#FCFCFD" }}>
                <i style={{ width: "10px", height: "10px", borderRadius: "50%", background: c.border }} />
                <i style={{ width: "10px", height: "10px", borderRadius: "50%", background: c.border }} />
                <i style={{ width: "10px", height: "10px", borderRadius: "50%", background: c.border }} />
                <span style={{ marginLeft: "16px", fontSize: "12px", color: "#9CA3AF", background: c.background, border: `1px solid ${c.border}`, borderRadius: "6px", padding: "3px 12px" }}>app.vulnhunter.cl/dashboard</span>
              </div>
              {/* cuerpo: sidebar + contenido */}
              <div style={{ display: "grid", gridTemplateColumns: "176px 1fr", height: "calc(100% - 40px)" }}>
                <aside style={{ borderRight: `1px solid ${c.border}`, padding: "18px 12px" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: "8px", fontWeight: 700, fontSize: "13px", padding: "0 6px 18px" }}>
                    <span style={{ width: "24px", height: "24px", borderRadius: "7px", background: c.primary, display: "grid", placeItems: "center", color: "#fff", fontSize: "11px" }}>V</span>
                    VulnHunter
                  </div>
                  {["Dashboard", "Sitios", "Escaneos", "Hallazgos", "Reportes", "Configuración"].map((m, i) => (
                    <div key={m} style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "12.5px", fontWeight: 500, color: i === 0 ? c.primary : c.muted, background: i === 0 ? "#EFF4FF" : "transparent", padding: "7px 8px", borderRadius: "7px", marginBottom: "2px" }}>
                      <i style={{ width: "12px", height: "12px", borderRadius: "4px", border: "1.5px solid currentColor", opacity: .7 }} />
                      {m}
                    </div>
                  ))}
                </aside>
                <main style={{ background: c.background, padding: "22px 26px" }}>
                  <h3 style={{ fontSize: "19px", fontWeight: 700 }}>Hola, Carlos</h3>
                  <div style={{ fontSize: "12.5px", color: c.muted, marginTop: "3px" }}>Resumen general de tus sitios</div>
                  {/* 4 tarjetas KPI */}
                  <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: "12px", marginTop: "18px" }}>
                    {[
                      { v: "24", l: "Escaneos totales" },
                      { v: "17", l: "Vulnerabilidades" },
                      { v: "5", l: "Sitios" },
                    ].map((k) => (
                      <div key={k.l} style={{ ...card, padding: "14px" }}>
                        <div style={{ fontSize: "22px", fontWeight: 700 }}>{k.v}</div>
                        <div style={{ fontSize: "12px", color: c.muted, marginTop: "4px" }}>{k.l}</div>
                      </div>
                    ))}
                    <div style={{ ...card, padding: "14px" }}>
                      <div style={{ fontSize: "22px", fontWeight: 700, display: "flex", alignItems: "center", gap: "8px" }}>
                        72 <span style={tag(sev.high, sevBg.high)}>Alto</span>
                      </div>
                      <div style={{ fontSize: "12px", color: c.muted, marginTop: "4px" }}>Nivel de riesgo</div>
                    </div>
                  </div>
                  {/* tabla + dona */}
                  <div style={{ display: "grid", gridTemplateColumns: "1.6fr 1fr", gap: "12px", marginTop: "12px" }}>
                    <div style={card}>
                      <div style={{ fontSize: "13px", fontWeight: 600, padding: "14px 14px 0" }}>Actividad reciente</div>
                      <table style={{ width: "100%", borderCollapse: "collapse", marginTop: "10px" }}>
                        <thead>
                          <tr>
                            {["Sitio", "Fecha", "Riesgo"].map((h) => (
                              <th key={h} style={{ fontSize: "11px", fontWeight: 500, color: c.muted, textAlign: "left", padding: "7px 14px", background: "#FAFAFB", borderTop: `1px solid ${c.border}`, borderBottom: `1px solid ${c.border}` }}>{h}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          <tr><td style={{ fontSize: "12px", padding: "10px 14px", borderBottom: "1px solid #F1F2F4" }}>tienda-ejemplo.cl</td><td style={{ fontSize: "12px", padding: "10px 14px", borderBottom: "1px solid #F1F2F4", color: c.muted }}>06/09/2026</td><td style={{ fontSize: "12px", padding: "10px 14px", borderBottom: "1px solid #F1F2F4" }}><span style={tag(sev.high, sevBg.high)}>Alto</span></td></tr>
                          <tr><td style={{ fontSize: "12px", padding: "10px 14px", borderBottom: "1px solid #F1F2F4" }}>empresa-demo.cl</td><td style={{ fontSize: "12px", padding: "10px 14px", borderBottom: "1px solid #F1F2F4", color: c.muted }}>05/09/2026</td><td style={{ fontSize: "12px", padding: "10px 14px", borderBottom: "1px solid #F1F2F4" }}><span style={tag("#A16207", sevBg.medium)}>Medio</span></td></tr>
                          <tr><td style={{ fontSize: "12px", padding: "10px 14px" }}>portal-prueba.cl</td><td style={{ fontSize: "12px", padding: "10px 14px", color: c.muted }}>04/09/2026</td><td style={{ fontSize: "12px", padding: "10px 14px" }}><span style={tag(sev.low, sevBg.low)}>Bajo</span></td></tr>
                        </tbody>
                      </table>
                    </div>
                    <div style={card}>
                      <div style={{ fontSize: "13px", fontWeight: 600, padding: "14px 14px 0" }}>Por severidad</div>
                      <div style={{ display: "flex", alignItems: "center", gap: "16px", padding: "14px" }}>
                        <svg width="96" height="96" viewBox="0 0 100 100">
                          <circle cx="50" cy="50" r="38" fill="none" stroke="#F3F4F6" strokeWidth="12" />
                          <g transform="rotate(-90 50 50)" fill="none" strokeWidth="12">
                            <circle cx="50" cy="50" r="38" stroke={sev.critical} strokeDasharray="40.1 198.7" strokeDashoffset="0" />
                            <circle cx="50" cy="50" r="38" stroke={sev.high} strokeDasharray="68.2 170.6" strokeDashoffset="-42.1" />
                            <circle cx="50" cy="50" r="38" stroke={sev.medium} strokeDasharray="82.3 156.5" strokeDashoffset="-112.3" />
                            <circle cx="50" cy="50" r="38" stroke={sev.low} strokeDasharray="40.1 198.7" strokeDashoffset="-196.6" />
                          </g>
                          <text x="50" y="56" textAnchor="middle" fontSize="18" fontWeight="700" fill={c.text} fontFamily="Inter">17</text>
                        </svg>
                        <ul style={{ listStyle: "none", display: "grid", gap: "7px", fontSize: "12px", flex: 1, margin: 0, padding: 0 }}>
                          {[
                            { c: sev.critical, l: "Crítica", n: 3 },
                            { c: sev.high, l: "Alta", n: 5 },
                            { c: sev.medium, l: "Media", n: 6 },
                            { c: sev.low, l: "Baja", n: 3 },
                          ].map((s) => (
                            <li key={s.l} style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                              <i style={{ width: "8px", height: "8px", borderRadius: "2px", background: s.c }} />
                              {s.l}<b style={{ marginLeft: "auto", fontWeight: 600 }}>{s.n}</b>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>
                </main>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ===== FUNCIONES ===== */}
      <section id="funciones" style={{ padding: "72px 0" }}>
        <div className="welcome-container" style={container}>
          <div style={{ maxWidth: "620px" }}>
            <div style={{ fontSize: "12px", fontWeight: 600, letterSpacing: ".08em", textTransform: "uppercase", color: c.primary }}>Funciones</div>
            <h2 style={{ fontSize: "36px", fontWeight: 700, lineHeight: 1.15, marginTop: "12px" }}>Todo lo necesario para conocer el estado de seguridad de tus sitios</h2>
          </div>
          <div className="welcome-features" style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: "20px", marginTop: "40px" }}>
            {/* Tarjeta 1: módulos */}
            <div style={{ ...card, borderRadius: "14px", padding: "26px" }}>
              <div style={{ width: "42px", height: "42px", borderRadius: "11px", background: "#EFF4FF", color: c.primary, display: "grid", placeItems: "center", fontSize: "20px" }}>🔍</div>
              <h4 style={{ fontSize: "17px", fontWeight: 600, marginTop: "20px" }}>Análisis de vulnerabilidades</h4>
              <p style={{ fontSize: "14px", color: c.muted, lineHeight: 1.6, marginTop: "8px" }}>Escanea tus sitios en busca de fallas de configuración y de código.</p>
              <div style={{ marginTop: "22px", paddingTop: "18px", borderTop: "1px solid #F1F2F4", display: "flex", flexWrap: "wrap", gap: "6px" }}>
                {["SSL/TLS", "XSS", "Inyección SQL", "Headers de seguridad", "Directorios expuestos"].map((m) => (
                  <span key={m} style={{ fontSize: "12px", fontWeight: 500, border: `1px solid ${c.border}`, borderRadius: "999px", padding: "4px 10px", background: "#fff" }}>{m}</span>
                ))}
              </div>
            </div>
            {/* Tarjeta 2: severidades */}
            <div style={{ ...card, borderRadius: "14px", padding: "26px" }}>
              <div style={{ width: "42px", height: "42px", borderRadius: "11px", background: "#EFF4FF", color: c.primary, display: "grid", placeItems: "center", fontSize: "20px" }}>⚠️</div>
              <h4 style={{ fontSize: "17px", fontWeight: 600, marginTop: "20px" }}>Clasificación de riesgos</h4>
              <p style={{ fontSize: "14px", color: c.muted, lineHeight: 1.6, marginTop: "8px" }}>Cada hallazgo se clasifica por severidad para que sepas qué corregir primero.</p>
              <div style={{ marginTop: "22px", paddingTop: "18px", borderTop: "1px solid #F1F2F4", display: "grid", gap: "8px" }}>
                {[
                  { l: "Crítica", color: sev.critical, w: "30%" },
                  { l: "Alta", color: sev.high, w: "50%" },
                  { l: "Media", color: "#A16207", bar: sev.medium, w: "62%" },
                  { l: "Baja", color: sev.low, w: "30%" },
                ].map((s) => (
                  <div key={s.l} style={{ display: "grid", gridTemplateColumns: "62px 1fr", alignItems: "center", gap: "10px", fontSize: "12px" }}>
                    <span style={{ color: s.color, fontWeight: 600 }}>{s.l}</span>
                    <span style={{ height: "6px", borderRadius: "999px", background: s.bar || s.color, width: s.w }} />
                  </div>
                ))}
              </div>
            </div>
            {/* Tarjeta 3: PDF */}
            <div style={{ ...card, borderRadius: "14px", padding: "26px" }}>
              <div style={{ width: "42px", height: "42px", borderRadius: "11px", background: "#EFF4FF", color: c.primary, display: "grid", placeItems: "center", fontSize: "20px" }}>📄</div>
              <h4 style={{ fontSize: "17px", fontWeight: 600, marginTop: "20px" }}>Reportes de seguridad</h4>
              <p style={{ fontSize: "14px", color: c.muted, lineHeight: 1.6, marginTop: "8px" }}>Genera reportes PDF de cada escaneo para compartir con tu equipo.</p>
              <div style={{ marginTop: "22px", paddingTop: "18px", borderTop: "1px solid #F1F2F4", display: "flex", alignItems: "center", gap: "12px" }}>
                <div style={{ width: "36px", height: "44px", border: `1px solid ${c.border}`, borderRadius: "6px", display: "grid", placeItems: "end center", paddingBottom: "5px", fontSize: "8.5px", fontWeight: 700, color: sev.critical }}>PDF</div>
                <div>
                  <div style={{ fontSize: "13px", fontWeight: 500 }}>Reporte SCAN-001.pdf</div>
                  <div style={{ fontSize: "12px", color: c.muted, marginTop: "2px" }}>tienda-ejemplo.cl · 06/09/2026</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ===== CÓMO FUNCIONA ===== */}
      <section id="como" style={{ padding: "0 0 72px" }}>
        <div className="welcome-container" style={container}>
          <div style={{ maxWidth: "620px" }}>
            <div style={{ fontSize: "12px", fontWeight: 600, letterSpacing: ".08em", textTransform: "uppercase", color: c.primary }}>Cómo funciona</div>
            <h2 style={{ fontSize: "36px", fontWeight: 700, lineHeight: 1.15, marginTop: "12px" }}>De tu sitio a un reporte en tres pasos</h2>
          </div>
          <div className="welcome-steps" style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", marginTop: "40px", ...card, borderRadius: "14px" }}>
            {[
              { n: "01", h: "Registra tu sitio", p: "Agrega el dominio y verifica que eres el propietario o que cuentas con autorización." },
              { n: "02", h: "Ejecuta el escaneo", p: "VulnHunter analiza el sitio con los módulos de seguridad configurados." },
              { n: "03", h: "Revisa y corrige", p: "Consulta los hallazgos por severidad y descarga el reporte PDF." },
            ].map((s, i) => (
              <div key={s.n} style={{ padding: "28px 28px 30px", borderLeft: i === 0 ? "none" : `1px solid ${c.border}` }}>
                <div style={{ fontSize: "13px", fontWeight: 600, color: c.primary }}>{s.n}</div>
                <h4 style={{ fontSize: "16px", fontWeight: 600, marginTop: "12px" }}>{s.h}</h4>
                <p style={{ fontSize: "14px", color: c.muted, lineHeight: 1.6, marginTop: "6px" }}>{s.p}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ===== CTA FINAL ===== */}
      <section style={{ paddingBottom: "72px" }}>
        <div className="welcome-container" style={container}>
          <div className="welcome-cta" style={{ ...card, borderRadius: "16px", padding: "44px 48px", display: "flex", justifyContent: "space-between", alignItems: "center", gap: "40px" }}>
            <div>
              <h3 style={{ fontSize: "26px", fontWeight: 700 }}>Empieza a analizar tus sitios</h3>
              <p style={{ fontSize: "15px", color: c.muted, marginTop: "8px" }}>Inicia sesión para acceder a tu panel de seguridad.</p>
            </div>
            <button onClick={onStart} style={btn}>Comenzar análisis →</button>
          </div>
        </div>
      </section>

      {/* ===== PIE ===== */}
      <footer style={{ borderTop: `1px solid ${c.border}`, background: "#fff" }}>
        <div className="welcome-container" style={{ ...container, minHeight: "72px", display: "flex", alignItems: "center", justifyContent: "space-between", gap: "12px", flexWrap: "wrap", fontSize: "13px", color: "#9CA3AF" }}>
          <span>© 2026 VulnHunter</span>
          <nav style={{ display: "flex", gap: "22px" }}>
            <a style={{ color: c.muted, cursor: "pointer" }}>Privacidad</a>
            <a style={{ color: c.muted, cursor: "pointer" }}>Términos</a>
            <a style={{ color: c.muted, cursor: "pointer" }}>Soporte</a>
          </nav>
        </div>
      </footer>
    </div>
  );
}

export default Welcome;

