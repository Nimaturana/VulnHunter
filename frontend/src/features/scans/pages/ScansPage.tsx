import { useState } from "react";

import {
  formatDate,
  getScan,
  reportUrl,
  RISK_LABELS,
  riskColor,
  STATUS_LABELS,
  type ScanDetail,
} from "../../../shared/api/scans";
import { useScans } from "../../../shared/hooks/useScans";
import {
  cardStyle,
  errorStyle,
  pageStyle,
  primaryButtonStyle,
  secondaryButtonStyle,
  tableCellStyle,
  tableStyle,
  tableWrapStyle,
} from "../../../shared/styles/layout";
import { NewScanDialog } from "../components/NewScanDialog";

function Scans() {
  const { scans, loading, error, refresh } = useScans();
  const [showNewScan, setShowNewScan] = useState(false);
  const [selected, setSelected] = useState<ScanDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);

  const openDetail = async (scanId: string) => {
    setDetailError(null);
    try {
      setSelected(await getScan(scanId));
    } catch (requestError) {
      setDetailError(requestError instanceof Error ? requestError.message : "Error inesperado");
    }
  };

  return (
    <main style={pageStyle}>
      <header
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          gap: 20,
          marginBottom: 28,
        }}
      >
        <div>
          <h1 style={{ margin: 0, fontSize: 30 }}>Escaneos</h1>
          <p style={{ color: "#94AFC7", marginTop: 8 }}>
            Historial persistente y progreso actualizado automáticamente.
          </p>
        </div>
        <div style={{ display: "flex", gap: 10 }}>
          <button onClick={() => void refresh()} style={secondaryButtonStyle}>
            Actualizar
          </button>
          <button onClick={() => setShowNewScan(true)} style={primaryButtonStyle}>
            + Nuevo escaneo
          </button>
        </div>
      </header>

      {(error || detailError) && <div style={errorStyle}>{error ?? detailError}</div>}

      <section style={cardStyle}>
        <div style={tableWrapStyle}>
          <table style={tableStyle}>
            <thead>
              <tr style={{ color: "#94AFC7" }}>
                <th style={tableCellStyle}>Sitio</th>
                <th style={tableCellStyle}>Estado</th>
                <th style={tableCellStyle}>Progreso</th>
                <th style={tableCellStyle}>Ejecución</th>
                <th style={tableCellStyle}>Hallazgos</th>
                <th style={tableCellStyle}>Riesgo</th>
                <th style={tableCellStyle}>PDF</th>
                <th style={tableCellStyle}>Fecha</th>
                <th style={tableCellStyle}>Acciones</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => {
                const finished = scan.status === "completed" || scan.status === "partial";
                return (
                  <tr key={scan.scan_id}>
                    <td style={tableCellStyle}>{scan.url}</td>
                    <td style={tableCellStyle}>{STATUS_LABELS[scan.status]}</td>
                    <td style={tableCellStyle}>
                      <div style={{ minWidth: 110 }}>
                        <div
                          style={{
                            height: 7,
                            borderRadius: 8,
                            backgroundColor: "#1e293b",
                            overflow: "hidden",
                          }}
                        >
                          <div
                            style={{
                              width: `${scan.progress_percentage}%`,
                              height: "100%",
                              backgroundColor: "#29C7F6",
                            }}
                          />
                        </div>
                        <small style={{ color: "#94AFC7" }}>{scan.progress_percentage}%</small>
                      </div>
                    </td>
                    <td style={tableCellStyle}>
                      {scan.execution_mode === "celery" ? "Celery · Redis" : "FastAPI local"}
                      {scan.task_id && (
                        <small style={{ display: "block", color: "#64748B" }}>
                          {scan.task_id.slice(0, 8)}
                        </small>
                      )}
                    </td>
                    <td style={tableCellStyle}>{scan.total_vulnerabilities}</td>
                    <td style={{ ...tableCellStyle, color: riskColor(scan.risk_level) }}>
                      {RISK_LABELS[scan.risk_level]}
                    </td>
                    <td style={tableCellStyle}>
                      {{
                        not_generated: "Pendiente",
                        generating: "Generando…",
                        generated: "Disponible",
                        failed: "Error",
                      }[scan.report_status]}
                    </td>
                    <td style={{ ...tableCellStyle, color: "#94AFC7" }}>
                      {formatDate(scan.completed_at ?? scan.started_at)}
                    </td>
                    <td style={tableCellStyle}>
                      <div style={{ display: "flex", gap: 8 }}>
                        <button
                          onClick={() => void openDetail(scan.scan_id)}
                          style={secondaryButtonStyle}
                        >
                          Ver
                        </button>
                        {finished && (
                          <a href={reportUrl(scan.scan_id)} style={primaryButtonStyle}>
                            PDF
                          </a>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {loading && <p style={{ color: "#94AFC7" }}>Cargando escaneos…</p>}
        {!loading && scans.length === 0 && (
          <p style={{ color: "#94AFC7" }}>No existen escaneos registrados.</p>
        )}
      </section>

      {selected && (
        <section style={{ ...cardStyle, marginTop: 20 }}>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 20 }}>
            <div>
              <h3 style={{ margin: 0 }}>Detalle {selected.scan_id.slice(0, 8)}</h3>
              <p style={{ color: "#94AFC7" }}>{selected.url}</p>
            </div>
            <button onClick={() => setSelected(null)} style={secondaryButtonStyle}>
              Cerrar
            </button>
          </div>
          <p>
            Estado: <strong>{STATUS_LABELS[selected.status]}</strong> · Riesgo:{" "}
            <strong style={{ color: riskColor(selected.risk_level) }}>
              {RISK_LABELS[selected.risk_level]} ({selected.risk_score}/100)
            </strong>
          </p>
          <p>
            Scanners: {selected.progress.completed_scanners}/{selected.progress.total_scanners} ·
            Hallazgos: {selected.total_vulnerabilities}
          </p>
          <p>
            Ejecución: <strong>{selected.execution_mode === "celery" ? "Celery mediante Redis" : "FastAPI local"}</strong>
            {selected.task_id && <> · Tarea: <code>{selected.task_id}</code></>}
          </p>
          <p>Reporte PDF: <strong>{selected.report_status}</strong></p>
          {Object.keys(selected.errors).length > 0 && (
            <div style={errorStyle}>
              {Object.entries(selected.errors).map(([scanner, message]) => (
                <div key={scanner}>{scanner}: {message}</div>
              ))}
            </div>
          )}
        </section>
      )}

      <NewScanDialog
        open={showNewScan}
        onClose={() => setShowNewScan(false)}
        onStarted={async () => refresh()}
      />
    </main>
  );
}

export default Scans;
