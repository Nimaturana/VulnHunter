import { useMemo } from "react";

import {
  formatDate,
  RISK_LABELS,
  riskColor,
  type ScanSummary,
} from "../../../shared/api/scans";
import { useScans } from "../../../shared/hooks/useScans";
import {
  cardStyle,
  errorStyle,
  pageStyle,
  tableCellStyle,
  tableStyle,
  tableWrapStyle,
} from "../../../shared/styles/layout";

type SiteSummary = {
  url: string;
  scans: number;
  latest: ScanSummary;
};

function Sites() {
  const { scans, loading, error } = useScans();
  const sites = useMemo<SiteSummary[]>(() => {
    const grouped = new Map<string, SiteSummary>();
    for (const scan of scans) {
      const current = grouped.get(scan.url);
      if (current) current.scans += 1;
      else grouped.set(scan.url, { url: scan.url, scans: 1, latest: scan });
    }
    return [...grouped.values()];
  }, [scans]);

  return (
    <main style={pageStyle}>
      <header style={{ marginBottom: 28 }}>
        <h1 style={{ margin: 0, fontSize: 30 }}>Sitios web</h1>
        <p style={{ color: "#94AFC7", marginTop: 8 }}>
          Vista agrupada de los objetivos analizados por VulnHunter.
        </p>
      </header>

      {error && <div style={errorStyle}>{error}</div>}

      <section style={cardStyle}>
        <div style={{ display: "flex", justifyContent: "space-between", gap: 16 }}>
          <h3 style={{ marginTop: 0 }}>Sitios analizados</h3>
          <span style={{ color: "#94AFC7" }}>{sites.length} sitio(s)</span>
        </div>
        <div style={tableWrapStyle}>
          <table style={tableStyle}>
            <thead>
              <tr style={{ color: "#94AFC7" }}>
                <th style={tableCellStyle}>Sitio</th>
                <th style={tableCellStyle}>Riesgo actual</th>
                <th style={tableCellStyle}>Escaneos</th>
                <th style={tableCellStyle}>Último análisis</th>
                <th style={tableCellStyle}>Hallazgos recientes</th>
              </tr>
            </thead>
            <tbody>
              {sites.map((site) => (
                <tr key={site.url}>
                  <td style={tableCellStyle}>{site.url}</td>
                  <td style={{ ...tableCellStyle, color: riskColor(site.latest.risk_level) }}>
                    <strong>{RISK_LABELS[site.latest.risk_level]}</strong>
                  </td>
                  <td style={tableCellStyle}>{site.scans}</td>
                  <td style={{ ...tableCellStyle, color: "#94AFC7" }}>
                    {formatDate(site.latest.completed_at ?? site.latest.started_at)}
                  </td>
                  <td style={tableCellStyle}>{site.latest.total_vulnerabilities}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {loading && <p style={{ color: "#94AFC7" }}>Cargando sitios…</p>}
        {!loading && sites.length === 0 && (
          <p style={{ color: "#94AFC7" }}>Aún no existen sitios analizados.</p>
        )}
      </section>
      <p style={{ color: "#64748B", fontSize: 13 }}>
        En el siguiente incremento esta vista usará el registro formal y la verificación de propiedad
        de la tabla websites. Por ahora refleja únicamente objetivos ya escaneados.
      </p>
    </main>
  );
}

export default Sites;
