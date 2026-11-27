// Paleta central para mantener los mismos colores que el resto del panel.
import { theme } from "../../../shared/styles/theme";

const c = theme.colors;

// Datos de ejemplo de los reportes (luego vendrán del backend).
const reports = [
  { site: "https://tienda-ejemplo.cl", risk: "ALTO", date: "06/09/2026", scanId: "SCAN-001" },
  { site: "https://empresa-demo.cl", risk: "MEDIO", date: "05/09/2026", scanId: "SCAN-002" },
  { site: "https://portal-prueba.cl", risk: "BAJO", date: "04/09/2026", scanId: "SCAN-003" },
];

// Etiquetas de riesgo con su color de fondo y texto.
const riskTag: Record<string, { bg: string; color: string; label: string }> = {
  ALTO: { bg: "#FFF7ED", color: c.severity.high, label: "Alto" },
  MEDIO: { bg: "#FEFCE8", color: "#A16207", label: "Medio" },
  BAJO: { bg: "#F0FDF4", color: c.severity.low, label: "Bajo" },
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

function Reports({ readOnly = false }: { readOnly?: boolean }) {
  return (
    <main className="responsive-page" style={{ flex: 1, padding: "36px 44px 48px", background: c.background, color: c.text }}>
      {/* ───────── ENCABEZADO ───────── */}
      <header style={{ marginBottom: "28px" }}>
        <h1 style={{ margin: 0, fontSize: "30px", fontWeight: 700, letterSpacing: "-0.02em" }}>Reportes</h1>
        <p style={{ color: c.muted, fontSize: "15px", margin: "6px 0 0" }}>
          Genera y descarga reportes PDF de los escaneos
        </p>
      </header>

      {/* ───────── TARJETA CON LA TABLA ───────── */}
      <section className="responsive-table-card" style={card}>
        {/* Cabecera: título + contador de escaneos disponibles. */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "20px 22px 16px" }}>
          <div style={{ fontSize: "16px", fontWeight: 600 }}>Reportes disponibles</div>
          <span style={{ fontSize: "13px", color: c.muted }}>{reports.length} escaneos disponibles</span>
        </div>

        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <th style={{ ...thStyle, width: "30%" }}>Sitio</th>
              <th style={thStyle}>ID escaneo</th>
              <th style={thStyle}>Riesgo</th>
              <th style={thStyle}>Fecha</th>
              <th style={{ ...thStyle, width: "200px" }}>Acción</th>
            </tr>
          </thead>
          <tbody>
            {reports.map((report) => {
              const tag = riskTag[report.risk];                 // etiqueta de riesgo
              const domain = report.site.replace("https://", "");
              return (
                <tr key={report.scanId} style={{ borderBottom: "1px solid #F1F2F4" }}>
                  {/* Columna Sitio: cuadrito con inicial + dominio + url. */}
                  <td style={{ padding: "14px 22px", fontSize: "14px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                      <div style={{ width: "32px", height: "32px", borderRadius: "8px", border: `1px solid ${c.border}`, display: "grid", placeItems: "center", fontWeight: 600, fontSize: "13px", color: c.muted }}>
                        {domain[0].toUpperCase()}
                      </div>
                      <div>
                        <div style={{ fontWeight: 500 }}>{domain}</div>
                        <div style={{ fontSize: "12.5px", color: c.muted }}>{report.site}</div>
                      </div>
                    </div>
                  </td>
                  {/* Columna ID escaneo: en fuente monoespaciada (estilo "código"). */}
                  <td style={{ padding: "14px 22px", fontSize: "13px", fontFamily: "ui-monospace, Menlo, monospace", color: c.muted }}>
                    {report.scanId}
                  </td>
                  {/* Columna Riesgo: etiqueta de color. */}
                  <td style={{ padding: "14px 22px" }}>
                    <span style={{ fontSize: "12px", fontWeight: 600, padding: "3px 9px", borderRadius: "999px", background: tag.bg, color: tag.color }}>
                      {tag.label}
                    </span>
                  </td>
                  {/* Columna Fecha: en gris. */}
                  <td style={{ padding: "14px 22px", fontSize: "14px", color: c.muted }}>{report.date}</td>
                  {/* Columna Acción: botón azul "Generar PDF". */}
                  <td style={{ padding: "14px 22px" }}>
                    <button disabled={readOnly} style={{ display: "inline-flex", alignItems: "center", gap: "7px", background: readOnly ? "#E5E7EB" : c.primary, color: readOnly ? c.muted : "#fff", border: "none", borderRadius: "9px", padding: "8px 14px", fontWeight: 600, fontSize: "13.5px", cursor: readOnly ? "not-allowed" : "pointer", boxShadow: readOnly ? "none" : "0 1px 2px rgba(37,99,235,.25)" }}>
                      {readOnly ? "Solo lectura" : "Generar PDF"}
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

export default Reports;

