import { useEffect, useMemo, useState } from "react";
import type { Usuario } from "../../../shared/api/auth";
import { listScans, obtenerMisEscaneos, type RiskLevel, type ScanSummary } from "../../../shared/api/scans";
import { theme } from "../../../shared/styles/theme";

const c = theme.colors;
const DEMO_SITES = [
  { url: "https://tienda-ejemplo.cl", risk: "HIGH" as RiskLevel, scans: 5, lastScan: "06/09/2026" },
  { url: "https://empresa-demo.cl", risk: "MEDIUM" as RiskLevel, scans: 3, lastScan: "05/09/2026" },
  { url: "https://portal-prueba.cl", risk: "LOW" as RiskLevel, scans: 2, lastScan: "04/09/2026" },
];
const riskTag: Record<RiskLevel, { bg: string; color: string; label: string; rank: number }> = {
  CRITICAL: { bg: "#FEF2F2", color: c.severity.critical, label: "Crítico", rank: 5 },
  HIGH: { bg: "#FFF7ED", color: c.severity.high, label: "Alto", rank: 4 },
  MEDIUM: { bg: "#FEFCE8", color: "#A16207", label: "Medio", rank: 3 },
  LOW: { bg: "#F0FDF4", color: c.severity.low, label: "Bajo", rank: 2 },
  INFO: { bg: "#EFF6FF", color: "#2563EB", label: "Informativo", rank: 1 },
};
const card: React.CSSProperties = { background: c.surface, border: `1px solid ${c.border}`, borderRadius: 14, boxShadow: "0 4px 16px rgba(16,24,40,.04)" };
const th: React.CSSProperties = { fontSize: 12, fontWeight: 500, color: c.muted, textAlign: "left", padding: "11px 22px", background: "#FAFAFB", borderTop: `1px solid ${c.border}`, borderBottom: `1px solid ${c.border}` };

export default function Sites({ readOnly = false, currentUser }: { readOnly?: boolean; currentUser: Usuario | null }) {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    if (readOnly) return;
    (currentUser?.role === "admin" ? listScans() : obtenerMisEscaneos()).then(setScans).catch((reason) => setError(reason instanceof Error ? reason.message : "No fue posible cargar los sitios."));
  }, [readOnly, currentUser?.id, currentUser?.role]);

  const sites = useMemo(() => {
    if (readOnly) return DEMO_SITES;
    const grouped = new Map<string, ScanSummary[]>();
    scans.forEach((scan) => grouped.set(scan.url, [...(grouped.get(scan.url) || []), scan]));
    return [...grouped.entries()].map(([url, items]) => {
      const sorted = [...items].sort((a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime());
      const risk = [...items].sort((a, b) => riskTag[b.risk_level].rank - riskTag[a.risk_level].rank)[0]?.risk_level || "INFO";
      return { url, risk, scans: items.length, lastScan: new Intl.DateTimeFormat("es-CL").format(new Date(sorted[0].started_at)) };
    });
  }, [readOnly, scans]);

  return <main className="responsive-page" style={{ flex: 1, padding: "36px 44px 48px", background: c.background, color: c.text }}>
    <header style={{ marginBottom: 28 }}><h1 style={{ margin: 0, fontSize: 30 }}>Sitios web</h1><p style={{ color: c.muted, margin: "6px 0 0" }}>{readOnly ? "Datos de demostración" : "Sitios analizados por tu cuenta"}</p></header>
    {error && <div style={{ color: c.severity.critical, marginBottom: 16 }}>{error}</div>}
    <section className="responsive-table-card" style={card}><div style={{ display: "flex", justifyContent: "space-between", padding: "20px 22px 16px" }}><strong>Sitios monitoreados</strong><span style={{ color: c.muted }}>{sites.length} sitios</span></div>
      {sites.length === 0 ? <div style={{ padding: 36, textAlign: "center", color: c.muted, borderTop: `1px solid ${c.border}` }}>Aún no hay sitios analizados. Inicia tu primer escaneo para registrarlos aquí.</div> : <table style={{ width: "100%", borderCollapse: "collapse" }}><thead><tr><th style={th}>Sitio</th><th style={th}>Riesgo actual</th><th style={th}>Escaneos</th><th style={th}>Último análisis</th></tr></thead><tbody>{sites.map((site) => { const host = new URL(site.url).hostname; const tag = riskTag[site.risk]; return <tr key={site.url} style={{ borderBottom: "1px solid #F1F2F4" }}><td style={{ padding: "14px 22px" }}><strong>{host}</strong><div style={{ color: c.muted, fontSize: 12 }}>{site.url}</div></td><td style={{ padding: "14px 22px" }}><span style={{ background: tag.bg, color: tag.color, padding: "3px 9px", borderRadius: 999, fontSize: 12, fontWeight: 600 }}>{tag.label}</span></td><td style={{ padding: "14px 22px", fontWeight: 600 }}>{site.scans}</td><td style={{ padding: "14px 22px", color: c.muted }}>{site.lastScan}</td></tr>; })}</tbody></table>}
    </section>
  </main>;
}
