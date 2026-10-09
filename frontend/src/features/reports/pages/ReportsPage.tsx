import {
  formatDate,
  reportUrl,
  RISK_LABELS,
  riskColor,
} from "../../../shared/api/scans";
import { useScans } from "../../../shared/hooks/useScans";
import {
  cardStyle,
  errorStyle,
  pageStyle,
  primaryButtonStyle,
  tableCellStyle,
  tableStyle,
  tableWrapStyle,
} from "../../../shared/styles/layout";

function Reports() {
  const { scans, loading, error } = useScans();
  const reports = scans.filter(
    (scan) => scan.status === "completed" || scan.status === "partial",
  );

  return (
    <main style={pageStyle}>
      <header style={{ marginBottom: 28 }}>
        <h1 style={{ margin: 0, fontSize: 30 }}>Reportes</h1>
        <p style={{ color: "#94AFC7", marginTop: 8 }}>
          Descarga el PDF generado por el backend para cada análisis finalizado.
        </p>
      </header>

      {error && <div style={errorStyle}>{error}</div>}

      <section style={cardStyle}>
        <div style={{ display: "flex", justifyContent: "space-between", gap: 16 }}>
          <h3 style={{ marginTop: 0 }}>Reportes disponibles</h3>
          <span style={{ color: "#94AFC7" }}>{reports.length} reporte(s)</span>
        </div>
        <div style={tableWrapStyle}>
          <table style={tableStyle}>
            <thead>
              <tr style={{ color: "#94AFC7" }}>
                <th style={tableCellStyle}>Sitio</th>
                <th style={tableCellStyle}>ID escaneo</th>
                <th style={tableCellStyle}>Riesgo</th>
                <th style={tableCellStyle}>Hallazgos</th>
                <th style={tableCellStyle}>Fecha</th>
                <th style={tableCellStyle}>Acción</th>
              </tr>
            </thead>
            <tbody>
              {reports.map((report) => (
                <tr key={report.scan_id}>
                  <td style={tableCellStyle}>{report.url}</td>
                  <td style={{ ...tableCellStyle, color: "#94AFC7" }}>
                    {report.scan_id.slice(0, 8)}
                  </td>
                  <td style={{ ...tableCellStyle, color: riskColor(report.risk_level) }}>
                    <strong>{RISK_LABELS[report.risk_level]}</strong>
                  </td>
                  <td style={tableCellStyle}>{report.total_vulnerabilities}</td>
                  <td style={{ ...tableCellStyle, color: "#94AFC7" }}>
                    {formatDate(report.completed_at)}
                  </td>
                  <td style={tableCellStyle}>
                    <a href={reportUrl(report.scan_id)} style={primaryButtonStyle}>
                      Descargar PDF
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {loading && <p style={{ color: "#94AFC7" }}>Cargando reportes…</p>}
        {!loading && reports.length === 0 && (
          <p style={{ color: "#94AFC7" }}>
            Los reportes aparecerán cuando termine al menos un escaneo.
          </p>
        )}
      </section>
    </main>
  );
}

export default Reports;
