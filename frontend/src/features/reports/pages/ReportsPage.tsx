import { useEffect, useState } from "react";
import type { Usuario } from "../../../shared/api/auth";
import { downloadReport, listScans, obtenerMisEscaneos, type RiskLevel, type ScanSummary } from "../../../shared/api/scans";
import { theme } from "../../../shared/styles/theme";

const c = theme.colors;
const DEMO: ScanSummary[] = [
  { scan_id: "SCAN-DEMO-001", url: "https://tienda-ejemplo.cl", status: "completed", risk_level: "HIGH", total_vulnerabilities: 5, started_at: "2026-09-06T10:00:00Z", completed_at: "2026-09-06T10:04:00Z", progress_percentage: 100, current_scanner: null, task_id: null, execution_mode: "celery", queued_at: null, report_status: "generated" },
  { scan_id: "SCAN-DEMO-002", url: "https://empresa-demo.cl", status: "completed", risk_level: "MEDIUM", total_vulnerabilities: 3, started_at: "2026-09-05T10:00:00Z", completed_at: "2026-09-05T10:04:00Z", progress_percentage: 100, current_scanner: null, task_id: null, execution_mode: "celery", queued_at: null, report_status: "generated" },
];
const tags: Record<RiskLevel, [string, string, string]> = { CRITICAL: ["#FEF2F2", c.severity.critical, "Crítico"], HIGH: ["#FFF7ED", c.severity.high, "Alto"], MEDIUM: ["#FEFCE8", "#A16207", "Medio"], LOW: ["#F0FDF4", c.severity.low, "Bajo"], INFO: ["#EFF6FF", c.primary, "Informativo"] };
const card: React.CSSProperties = { background: c.surface, border: `1px solid ${c.border}`, borderRadius: 14 };
const th: React.CSSProperties = { padding: "11px 22px", textAlign: "left", color: c.muted, fontSize: 12, background: "#FAFAFB", borderTop: `1px solid ${c.border}` };

export default function Reports({ readOnly = false, currentUser }: { readOnly?: boolean; currentUser: Usuario | null }) {
  const [reports, setReports] = useState<ScanSummary[]>(readOnly ? DEMO : []);
  const [message, setMessage] = useState("");
  useEffect(() => {
    if (readOnly) { setReports(DEMO); return; }
    (currentUser?.role === "admin" ? listScans() : obtenerMisEscaneos()).then((items) => setReports(items.filter((scan) => scan.status === "completed" || scan.status === "partial"))).catch((reason) => setMessage(reason instanceof Error ? reason.message : "No fue posible cargar los reportes."));
  }, [readOnly, currentUser?.id, currentUser?.role]);

  const download = async (id: string) => { setMessage(""); try { await downloadReport(id); } catch (reason) { setMessage(reason instanceof Error ? reason.message : "No fue posible descargar el PDF."); } };
  return <main className="responsive-page" style={{ flex: 1, padding: "36px 44px 48px", background: c.background, color: c.text }}><header style={{ marginBottom: 28 }}><h1 style={{ margin: 0, fontSize: 30 }}>Reportes</h1><p style={{ color: c.muted }}>{readOnly ? "Reportes de demostración" : "Reportes PDF de tus escaneos completados"}</p></header>{message && <p style={{ color: c.severity.critical }}>{message}</p>}<section className="responsive-table-card" style={card}><div style={{ display: "flex", justifyContent: "space-between", padding: "20px 22px 16px" }}><strong>Reportes disponibles</strong><span style={{ color: c.muted }}>{reports.length} reportes</span></div>{reports.length === 0 ? <div style={{ padding: 36, textAlign: "center", color: c.muted, borderTop: `1px solid ${c.border}` }}>No hay reportes disponibles. Se habilitarán cuando finalice un escaneo.</div> : <table style={{ width: "100%", borderCollapse: "collapse" }}><thead><tr><th style={th}>Sitio</th><th style={th}>ID escaneo</th><th style={th}>Riesgo</th><th style={th}>Fecha</th><th style={th}>Acción</th></tr></thead><tbody>{reports.map((report) => { const tag = tags[report.risk_level]; return <tr key={report.scan_id} style={{ borderTop: `1px solid ${c.border}` }}><td style={{ padding: "14px 22px" }}><strong>{new URL(report.url).hostname}</strong><div style={{ color: c.muted, fontSize: 12 }}>{report.url}</div></td><td style={{ padding: "14px 22px", fontFamily: "monospace" }}>{report.scan_id.slice(0, 12)}</td><td style={{ padding: "14px 22px" }}><span style={{ background: tag[0], color: tag[1], padding: "3px 9px", borderRadius: 999, fontSize: 12 }}>{tag[2]}</span></td><td style={{ padding: "14px 22px" }}>{new Intl.DateTimeFormat("es-CL").format(new Date(report.started_at))}</td><td style={{ padding: "14px 22px" }}><button disabled={readOnly} onClick={() => void download(report.scan_id)} style={{ border: 0, borderRadius: 8, background: readOnly ? "#E5E7EB" : c.primary, color: readOnly ? c.muted : "white", padding: "8px 14px", fontWeight: 600 }}>{readOnly ? "Vista demostrativa" : report.report_status === "generated" ? "Descargar PDF" : "Generar/descargar PDF"}</button></td></tr>; })}</tbody></table>}</section></main>;
}
