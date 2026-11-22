// Paleta central para mantener los mismos colores que el resto del panel.
import { theme } from "../../../shared/styles/theme";

const c = theme.colors;

// Datos de ejemplo de los escaneos (luego vendrán del backend).
const scans = [
  { url: "https://tienda-ejemplo.cl", status: "Completado", risk: "ALTO", date: "06/09/2026" },
  { url: "https://empresa-demo.cl", status: "Completado", risk: "MEDIO", date: "05/09/2026" },
  { url: "https://portal-prueba.cl", status: "Ejecutándose", risk: "Analizando", date: "05/09/2026" },
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

function Scans() {
  return (
    <main style={{ flex: 1, padding: "36px 44px 48px", background: c.background, color: c.text }}>
      {/* ───────── ENCABEZADO ───────── */}
      <header style={{ marginBottom: "28px" }}>
        <h1 style={{ margin: 0, fontSize: "30px", fontWeight: 700, letterSpacing: "-0.02em" }}>Escaneos</h1>
        <p style={{ color: c.muted, fontSize: "15px", margin: "6px 0 0" }}>
          Revisa el historial y estado de los análisis
        </p>
      </header>

      {/* ───────── TARJETA CON LA TABLA ───────── */}
      <section style={card}>
        <div style={{ padding: "20px 22px 16px" }}>
          <div style={{ fontSize: "16px", fontWeight: 600 }}>Historial de escaneos</div>
        </div>

        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr>
              <th style={{ ...thStyle, width: "34%" }}>Sitio</th>
              <th style={thStyle}>Estado</th>
              <th style={thStyle}>Riesgo</th>
              <th style={thStyle}>Fecha</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((scan) => {
              const domain = scan.url.replace("https://", "");
              // ¿El escaneo está completado? (para el color del puntito de estado)
              const completado = scan.status === "Completado";
              // Buscamos la etiqueta de riesgo; si es "Analizando" no hay etiqueta.
              const tag = riskTag[scan.risk];
              return (
                <tr key={scan.url} style={{ borderBottom: "1px solid #F1F2F4" }}>
                  {/* Columna Sitio: cuadrito con inicial + dominio + url. */}
                  <td style={{ padding: "14px 22px", fontSize: "14px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                      <div style={{ width: "32px", height: "32px", borderRadius: "8px", border: `1px solid ${c.border}`, display: "grid", placeItems: "center", fontWeight: 600, fontSize: "13px", color: c.muted }}>
                        {domain[0].toUpperCase()}
                      </div>
                      <div>
                        <div style={{ fontWeight: 500 }}>{domain}</div>
                        <div style={{ fontSize: "12.5px", color: c.muted }}>{scan.url}</div>
                      </div>
                    </div>
                  </td>
                  {/* Columna Estado: puntito de color + texto (verde si completado, azul si corriendo). */}
                  <td style={{ padding: "14px 22px", fontSize: "13.5px" }}>
                    <span style={{ display: "inline-flex", alignItems: "center", gap: "7px", fontWeight: 500, color: completado ? c.severity.low : c.primary }}>
                      <span style={{ width: "7px", height: "7px", borderRadius: "50%", background: completado ? c.severity.low : c.primary }} />
                      {scan.status}
                    </span>
                  </td>
                  {/* Columna Riesgo: etiqueta de color, o "Analizando" en azul si aún no hay riesgo. */}
                  <td style={{ padding: "14px 22px" }}>
                    {tag ? (
                      <span style={{ fontSize: "12px", fontWeight: 600, padding: "3px 9px", borderRadius: "999px", background: tag.bg, color: tag.color }}>
                        {tag.label}
                      </span>
                    ) : (
                      <span style={{ fontSize: "12px", fontWeight: 600, padding: "3px 9px", borderRadius: "999px", background: "#EFF4FF", color: c.primary }}>
                        Analizando
                      </span>
                    )}
                  </td>
                  {/* Columna Fecha: en gris. */}
                  <td style={{ padding: "14px 22px", fontSize: "14px", color: c.muted }}>{scan.date}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>
    </main>
  );
}

export default Scans;

