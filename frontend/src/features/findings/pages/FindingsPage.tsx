// Paleta central para mantener los mismos colores que el resto del panel.
import { theme } from "../../../shared/styles/theme";

const c = theme.colors;

// Datos de ejemplo de los hallazgos (luego vendrán del backend).
const findings = [
  { vulnerability: "XSS reflejado", severity: "ALTA", site: "https://tienda-ejemplo.cl", status: "Abierto" },
  { vulnerability: "Headers de seguridad faltantes", severity: "MEDIA", site: "https://empresa-demo.cl", status: "Abierto" },
  { vulnerability: "Configuración TLS débil", severity: "BAJA", site: "https://portal-prueba.cl", status: "Revisado" },
  { vulnerability: "Posible inyección SQL", severity: "CRÍTICA", site: "https://tienda-ejemplo.cl", status: "Abierto" },
];

// Etiquetas de severidad: cada nivel con su fondo y color de texto.
const sevTag: Record<string, { bg: string; color: string; label: string }> = {
  "CRÍTICA": { bg: "#FEF2F2", color: c.severity.critical, label: "Crítica" },
  "ALTA": { bg: "#FFF7ED", color: c.severity.high, label: "Alta" },
  "MEDIA": { bg: "#FEFCE8", color: "#A16207", label: "Media" },
  "BAJA": { bg: "#F0FDF4", color: c.severity.low, label: "Baja" },
};

// Tarjeta blanca base.
const card: React.CSSProperties = {
  backgroundColor: c.surface,
  border: `1px solid ${c.border}`,
  borderRadius: "14px",
  boxShadow: "0 1px 2px rgba(16,24,40,.04), 0 4px 16px rgba(16,24,40,.04)",
};

// Encabezados de la tabla.
const thStyle: React.CSSProperties = {
  fontSize: "12px",
  fontWeight: 500,
  color: c.muted,
  textAlign: "left",
  padding: "11px 22px",
  background: "#FAFAFB",
  borderTop: `1px solid ${c.border}`,
  borderBottom: `1px solid ${c.border}`,
};

function Findings() {
  return (
    <main style={{ flex: 1, padding: "36px 44px 48px", background: c.background, color: c.text }}>
      {/* ───────── ENCABEZADO ───────── */}
      <header style={{ marginBottom: "28px" }}>
        <h1 style={{ margin: 0, fontSize: "30px", fontWeight: 700, letterSpacing: "-0.02em" }}>Hallazgos</h1>
        <p style={{ color: c.muted, fontSize: "15px", margin: "6px 0 0" }}>
          Revisa las vulnerabilidades detectadas
        </p>
      </header>

      {/* ───────── TARJETA CON LA TABLA ───────── */}
      <section style={card}>
        {/* Cabecera: título + contador de hallazgos. */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "20px 22px 16px" }}>
          <div style={{ fontSize: "16px", fontWeight: 600 }}>Vulnerabilidades detectadas</div>
          <span style={{ fontSize: "13px", color: c.muted }}>{findings.length} hallazgos</span>
        </div>

        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <th style={{ ...thStyle, width: "30%" }}>Vulnerabilidad</th>
              <th style={thStyle}>Severidad</th>
              <th style={thStyle}>Sitio</th>
              <th style={thStyle}>Estado</th>
              <th style={{ ...thStyle, width: "180px" }}>Acciones</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((finding) => {
              const tag = sevTag[finding.severity];              // etiqueta de severidad
              const abierto = finding.status === "Abierto";      // para el color del estado
              return (
                <tr key={`${finding.vulnerability}-${finding.site}`} style={{ borderBottom: "1px solid #F1F2F4" }}>
                  {/* Columna Vulnerabilidad: nombre en negrita media. */}
                  <td style={{ padding: "14px 22px", fontSize: "14px", fontWeight: 500 }}>{finding.vulnerability}</td>
                  {/* Columna Severidad: etiqueta de color. */}
                  <td style={{ padding: "14px 22px" }}>
                    <span style={{ fontSize: "12px", fontWeight: 600, padding: "3px 9px", borderRadius: "999px", background: tag.bg, color: tag.color }}>
                      {tag.label}
                    </span>
                  </td>
                  {/* Columna Sitio: la url en texto gris. */}
                  <td style={{ padding: "14px 22px", fontSize: "14px", color: c.muted }}>{finding.site}</td>
                  {/* Columna Estado: puntito + texto (azul si Abierto, verde si Revisado). */}
                  <td style={{ padding: "14px 22px", fontSize: "13.5px" }}>
                    <span style={{ display: "inline-flex", alignItems: "center", gap: "7px", fontWeight: 500, color: abierto ? c.primary : c.severity.low }}>
                      <span style={{ width: "7px", height: "7px", borderRadius: "50%", background: abierto ? c.primary : c.severity.low }} />
                      {finding.status}
                    </span>
                  </td>
                  {/* Columna Acciones: botón secundario "Ver detalle". */}
                  <td style={{ padding: "14px 22px" }}>
                    <button style={{ background: "#fff", color: c.text, border: `1px solid ${c.border}`, borderRadius: "9px", padding: "7px 13px", fontWeight: 500, fontSize: "13.5px", cursor: "pointer" }}>
                      Ver detalle
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>
    </main>
  );
}

export default Findings;

