// Traemos la paleta central para usar los mismos colores que el resto del panel.
import { theme } from "../../../shared/styles/theme";

const c = theme.colors;

// Datos de ejemplo de los sitios (luego vendrán del backend).
const sites = [
  { url: "https://tienda-ejemplo.cl", risk: "ALTO", scans: 5, lastScan: "06/09/2026" },
  { url: "https://empresa-demo.cl", risk: "MEDIO", scans: 3, lastScan: "05/09/2026" },
  { url: "https://portal-prueba.cl", risk: "BAJO", scans: 2, lastScan: "04/09/2026" },
];

// Estilos de las etiquetas de riesgo: cada nivel tiene su fondo y color de texto.
const riskTag: Record<string, { bg: string; color: string; label: string }> = {
  ALTO: { bg: "#FFF7ED", color: c.severity.high, label: "Alto" },
  MEDIO: { bg: "#FEFCE8", color: "#A16207", label: "Medio" },
  BAJO: { bg: "#F0FDF4", color: c.severity.low, label: "Bajo" },
};

// Estilo base de las tarjetas blancas (igual que en el Dashboard).
const card: React.CSSProperties = {
  backgroundColor: c.surface,
  border: `1px solid ${c.border}`,
  borderRadius: "14px",
  boxShadow: "0 1px 2px rgba(16,24,40,.04), 0 4px 16px rgba(16,24,40,.04)",
};

// Estilo común de los encabezados de la tabla (th).
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

function Sites() {
  return (
    // Contenedor principal con fondo claro.
    <main style={{ flex: 1, padding: "36px 44px 48px", background: c.background, color: c.text }}>
      {/* ───────── ENCABEZADO ───────── */}
      <header style={{ marginBottom: "28px" }}>
        <h1 style={{ margin: 0, fontSize: "30px", fontWeight: 700, letterSpacing: "-0.02em" }}>Sitios web</h1>
        <p style={{ color: c.muted, fontSize: "15px", margin: "6px 0 0" }}>
          Revisa los sitios web monitoreados por VulnHunter
        </p>
      </header>

      {/* ───────── TARJETA CON LA TABLA ───────── */}
      <section style={card}>
        {/* Cabecera de la tarjeta: título + contador de sitios. */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "20px 22px 16px" }}>
          <div style={{ fontSize: "16px", fontWeight: 600 }}>Sitios monitoreados</div>
          <span style={{ fontSize: "13px", color: c.muted }}>{sites.length} sitios</span>
        </div>

        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <th style={{ ...thStyle, width: "34%" }}>Sitio</th>
              <th style={thStyle}>Riesgo actual</th>
              <th style={thStyle}>Escaneos</th>
              <th style={thStyle}>Último análisis</th>
              <th style={{ ...thStyle, width: "180px" }}>Acciones</th>
            </tr>
          </thead>
          <tbody>
            {/* Recorremos los sitios y dibujamos una fila por cada uno. */}
            {sites.map((site) => {
              const tag = riskTag[site.risk];               // etiqueta de riesgo de esta fila
              const domain = site.url.replace("https://", ""); // dominio sin el "https://"
              return (
                <tr key={site.url} style={{ borderBottom: "1px solid #F1F2F4" }}>
                  {/* Columna Sitio: cuadrito con inicial + dominio + url completa. */}
                  <td style={{ padding: "14px 22px", fontSize: "14px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                      <div style={{ width: "32px", height: "32px", borderRadius: "8px", border: `1px solid ${c.border}`, display: "grid", placeItems: "center", fontWeight: 600, fontSize: "13px", color: c.muted }}>
                        {domain[0].toUpperCase()}
                      </div>
                      <div>
                        <div style={{ fontWeight: 500 }}>{domain}</div>
                        <div style={{ fontSize: "12.5px", color: c.muted }}>{site.url}</div>
                      </div>
                    </div>
                  </td>
                  {/* Columna Riesgo: etiqueta de color. */}
                  <td style={{ padding: "14px 22px" }}>
                    <span style={{ fontSize: "12px", fontWeight: 600, padding: "3px 9px", borderRadius: "999px", background: tag.bg, color: tag.color }}>
                      {tag.label}
                    </span>
                  </td>
                  {/* Columna Escaneos: número en negrita. */}
                  <td style={{ padding: "14px 22px", fontSize: "14px", fontWeight: 600 }}>{site.scans}</td>
                  {/* Columna Último análisis: fecha en gris. */}
                  <td style={{ padding: "14px 22px", fontSize: "14px", color: c.muted }}>{site.lastScan}</td>
                  {/* Columna Acciones: botón secundario "Ver historial". */}
                  <td style={{ padding: "14px 22px" }}>
                    <button style={{ background: "#fff", color: c.text, border: `1px solid ${c.border}`, borderRadius: "9px", padding: "7px 13px", fontWeight: 500, fontSize: "13.5px", cursor: "pointer" }}>
                      Ver historial
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

export default Sites;

