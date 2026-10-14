import { useEffect, useState } from "react";

import {
  getScan,
  RISK_LABELS,
  riskColor,
  type Finding,
} from "../../../shared/api/scans";
import { useScans } from "../../../shared/hooks/useScans";
import {
  cardStyle,
  errorStyle,
  pageStyle,
  secondaryButtonStyle,
  tableCellStyle,
  tableStyle,
  tableWrapStyle,
} from "../../../shared/styles/layout";

type FindingRow = Finding & { scanId: string; url: string };

function Findings() {
  const { scans, loading: scansLoading, error } = useScans();
  const [findings, setFindings] = useState<FindingRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState<FindingRow | null>(null);

  useEffect(() => {
    const finished = scans.filter(
      (scan) => scan.status === "completed" || scan.status === "partial",
    );
    if (finished.length === 0) {
      setFindings([]);
      return;
    }

    let cancelled = false;
    setLoading(true);
    void Promise.all(
      finished.map(async (summary) => {
        const detail = await getScan(summary.scan_id);
        return detail.vulnerabilities.map((finding) => ({
          ...finding,
          scanId: summary.scan_id,
          url: summary.url,
        }));
      }),
    )
      .then((groups) => {
        if (!cancelled) setFindings(groups.flat());
      })
      .catch(() => {
        if (!cancelled) setFindings([]);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [scans]);

  return (
    <main style={pageStyle}>
      <header style={{ marginBottom: 28 }}>
        <h1 style={{ margin: 0, fontSize: 30 }}>Hallazgos</h1>
        <p style={{ color: "#94AFC7", marginTop: 8 }}>
          Evidencias y recomendaciones obtenidas de los escaneos reales.
        </p>
      </header>

      {error && <div style={errorStyle}>{error}</div>}

      <section style={cardStyle}>
        <div style={{ display: "flex", justifyContent: "space-between", gap: 16 }}>
          <h3 style={{ marginTop: 0 }}>Vulnerabilidades detectadas</h3>
          <span style={{ color: "#94AFC7" }}>{findings.length} hallazgo(s)</span>
        </div>
        <div style={tableWrapStyle}>
          <table style={tableStyle}>
            <thead>
              <tr style={{ color: "#94AFC7" }}>
                <th style={tableCellStyle}>Vulnerabilidad</th>
                <th style={tableCellStyle}>Severidad</th>
                <th style={tableCellStyle}>Sitio</th>
                <th style={tableCellStyle}>Scanner</th>
                <th style={tableCellStyle}>Confianza</th>
                <th style={tableCellStyle}>Acción</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((finding, index) => (
                <tr key={`${finding.scanId}-${finding.type}-${finding.location}-${index}`}>
                  <td style={tableCellStyle}>{finding.type}</td>
                  <td style={{ ...tableCellStyle, color: riskColor(finding.severity) }}>
                    <strong>{RISK_LABELS[finding.severity]}</strong>
                  </td>
                  <td style={tableCellStyle}>{finding.url}</td>
                  <td style={tableCellStyle}>{finding.scanner}</td>
                  <td style={tableCellStyle}>{finding.confidence}</td>
                  <td style={tableCellStyle}>
                    <button onClick={() => setSelected(finding)} style={secondaryButtonStyle}>
                      Ver detalle
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {(loading || scansLoading) && <p style={{ color: "#94AFC7" }}>Cargando hallazgos…</p>}
        {!loading && !scansLoading && findings.length === 0 && (
          <p style={{ color: "#94AFC7" }}>No hay hallazgos disponibles.</p>
        )}
      </section>

      {selected && (
        <section style={{ ...cardStyle, marginTop: 20 }}>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 20 }}>
            <h3 style={{ marginTop: 0 }}>{selected.type}</h3>
            <button onClick={() => setSelected(null)} style={secondaryButtonStyle}>
              Cerrar
            </button>
          </div>
          <p><strong>Ubicación:</strong> {selected.location}</p>
          <p><strong>Descripción:</strong> {selected.description || "Sin descripción adicional"}</p>
          <p><strong>Evidencia:</strong> {selected.evidence || "Requiere validación manual"}</p>
          <p><strong>Recomendación:</strong> {selected.recommendation}</p>
        </section>
      )}
    </main>
  );
}

export default Findings;
