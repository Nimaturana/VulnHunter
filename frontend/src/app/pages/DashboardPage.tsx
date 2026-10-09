import { useEffect, useMemo, useState } from "react";

import { NewScanDialog } from "../../features/scans/components/NewScanDialog";
import {
  formatDate,
  getScan,
  getStatistics,
  RISK_LABELS,
  riskColor,
  STATUS_LABELS,
  type Finding,
  type ScanDetail,
  type SystemStats,
} from "../../shared/api/scans";
import { useScans } from "../../shared/hooks/useScans";
import {
  cardStyle,
  errorStyle,
  pageStyle,
  primaryButtonStyle,
  successStyle,
  tableCellStyle,
  tableStyle,
  tableWrapStyle,
} from "../../shared/styles/layout";

const emptyStats: SystemStats = {
  total_scans: 0,
  total_vulnerabilities: 0,
  by_status: { pending: 0, running: 0, completed: 0, partial: 0, failed: 0 },
  storage: "unknown",
};

function Dashboard() {
  const { scans, loading, error, refresh } = useScans();
  const [showNewScan, setShowNewScan] = useState(false);
  const [startedScan, setStartedScan] = useState<string | null>(null);
  const [stats, setStats] = useState<SystemStats>(emptyStats);
  const [latestDetail, setLatestDetail] = useState<ScanDetail | null>(null);

  useEffect(() => {
    void getStatistics().then(setStats).catch(() => undefined);
  }, [scans]);

  useEffect(() => {
    const latestFinished = scans.find(
      (scan) => scan.status === "completed" || scan.status === "partial",
    );
    if (!latestFinished) {
      setLatestDetail(null);
      return;
    }
    void getScan(latestFinished.scan_id).then(setLatestDetail).catch(() => undefined);
  }, [scans]);

  const siteCount = useMemo(() => new Set(scans.map((scan) => scan.url)).size, [scans]);
  const severities = useMemo(() => {
    const counts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const finding of latestDetail?.vulnerabilities ?? []) {
      counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
    }
    return counts;
  }, [latestDetail]);

  const latestRisk = latestDetail?.risk_level ?? "LOW";
  const latestFindings: Finding[] = latestDetail?.vulnerabilities ?? [];
  const cards = [
    { title: "Escaneos realizados", value: stats.total_scans, icon: "🔍" },
    { title: "Hallazgos acumulados", value: stats.total_vulnerabilities, icon: "⚠️" },
    { title: "Escaneos activos", value: stats.by_status.running + stats.by_status.pending, icon: "⏳" },
    { title: "Sitios analizados", value: siteCount, icon: "🌐" },
  ];

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
          <h1 style={{ margin: 0, fontSize: 30 }}>Dashboard de seguridad</h1>
          <p style={{ color: "#94AFC7", marginTop: 8 }}>
            Información real entregada por FastAPI y persistida en PostgreSQL.
          </p>
        </div>
        <button onClick={() => setShowNewScan(true)} style={primaryButtonStyle}>
          + Nuevo escaneo
        </button>
      </header>

      {error && (
        <div style={errorStyle}>
          No se pudo conectar con la API: {error}. Comprueba que FastAPI o Docker estén activos.
        </div>
      )}
      {startedScan && (
        <div style={successStyle}>
          Escaneo {startedScan.slice(0, 8)} iniciado. El progreso se actualizará automáticamente.
        </div>
      )}

      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
          gap: 18,
          marginBottom: 24,
        }}
      >
        {cards.map((card) => (
          <div key={card.title} style={cardStyle}>
            <div style={{ fontSize: 26 }}>{card.icon}</div>
            <p style={{ color: "#94AFC7", marginBottom: 6 }}>{card.title}</p>
            <strong style={{ fontSize: 28 }}>{loading ? "…" : card.value}</strong>
          </div>
        ))}
      </section>

      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
          gap: 20,
          marginBottom: 24,
        }}
      >
        <div style={cardStyle}>
          <h3 style={{ marginTop: 0 }}>Último análisis finalizado</h3>
          {latestDetail ? (
            <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
              <div
                style={{
                  width: 82,
                  height: 82,
                  borderRadius: "50%",
                  border: `8px solid ${riskColor(latestRisk)}`,
                  display: "grid",
                  placeItems: "center",
                  fontSize: 22,
                  fontWeight: 700,
                }}
              >
                {latestDetail.risk_score}
              </div>
              <div>
                <p style={{ color: "#94AFC7", margin: 0 }}>{latestDetail.url}</p>
                <h2 style={{ color: riskColor(latestRisk), margin: "7px 0" }}>
                  {RISK_LABELS[latestRisk]}
                </h2>
                <span>{latestFindings.length} hallazgo(s)</span>
              </div>
            </div>
          ) : (
            <p style={{ color: "#94AFC7" }}>Aún no hay un escaneo finalizado.</p>
          )}
        </div>

        <div style={cardStyle}>
          <h3 style={{ marginTop: 0 }}>Hallazgos del último análisis</h3>
          {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((severity) => (
            <div
              key={severity}
              style={{ display: "flex", justifyContent: "space-between", marginTop: 14 }}
            >
              <span style={{ color: riskColor(severity) }}>{RISK_LABELS[severity]}</span>
              <strong>{severities[severity]}</strong>
            </div>
          ))}
        </div>
      </section>

      <section style={cardStyle}>
        <h3 style={{ marginTop: 0 }}>Últimos escaneos</h3>
        <div style={tableWrapStyle}>
          <table style={tableStyle}>
            <thead>
              <tr style={{ color: "#94AFC7" }}>
                <th style={tableCellStyle}>Sitio</th>
                <th style={tableCellStyle}>Estado</th>
                <th style={tableCellStyle}>Progreso</th>
                <th style={tableCellStyle}>Riesgo</th>
                <th style={tableCellStyle}>Fecha</th>
              </tr>
            </thead>
            <tbody>
              {scans.slice(0, 5).map((scan) => (
                <tr key={scan.scan_id}>
                  <td style={tableCellStyle}>{scan.url}</td>
                  <td style={tableCellStyle}>{STATUS_LABELS[scan.status]}</td>
                  <td style={tableCellStyle}>{scan.progress_percentage}%</td>
                  <td style={{ ...tableCellStyle, color: riskColor(scan.risk_level) }}>
                    {RISK_LABELS[scan.risk_level]}
                  </td>
                  <td style={{ ...tableCellStyle, color: "#94AFC7" }}>
                    {formatDate(scan.completed_at ?? scan.started_at)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!loading && scans.length === 0 && (
          <p style={{ color: "#94AFC7" }}>No hay escaneos. Inicia el primero desde este panel.</p>
        )}
      </section>

      <NewScanDialog
        open={showNewScan}
        onClose={() => setShowNewScan(false)}
        onStarted={async (scanId) => {
          setStartedScan(scanId);
          await refresh();
        }}
      />
    </main>
  );
}

export default Dashboard;
