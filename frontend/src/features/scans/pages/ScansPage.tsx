import { useEffect, useState } from "react";
import type { Usuario } from "../../../shared/api/auth";
import { listScans, obtenerMisEscaneos, SCANNERS, startScan, type RiskLevel, type ScanSummary } from "../../../shared/api/scans";
import { theme } from "../../../shared/styles/theme";

const c = theme.colors;
const DEMO: ScanSummary[] = [
  { scan_id: "DEMO-001", url: "https://tienda-ejemplo.cl", status: "completed", risk_level: "HIGH", total_vulnerabilities: 5, started_at: "2026-09-06T10:00:00Z", completed_at: "2026-09-06T10:04:00Z", progress_percentage: 100, current_scanner: null, task_id: null, execution_mode: "celery", queued_at: null, report_status: "generated" },
  { scan_id: "DEMO-002", url: "https://empresa-demo.cl", status: "completed", risk_level: "MEDIUM", total_vulnerabilities: 3, started_at: "2026-09-05T10:00:00Z", completed_at: "2026-09-05T10:04:00Z", progress_percentage: 100, current_scanner: null, task_id: null, execution_mode: "celery", queued_at: null, report_status: "generated" },
  { scan_id: "DEMO-003", url: "https://portal-prueba.cl", status: "running", risk_level: "INFO", total_vulnerabilities: 0, started_at: "2026-09-04T10:00:00Z", completed_at: null, progress_percentage: 45, current_scanner: "ssl_tls", task_id: null, execution_mode: "celery", queued_at: null, report_status: "not_generated" },
];
const LABELS: Record<(typeof SCANNERS)[number], { title: string; detail: string }> = {
  xss: { title: "Cross-Site Scripting (XSS)", detail: "Busca reflexiones ejecutables de contenido no confiable." },
  sql_injection: { title: "Inyección SQL", detail: "Evalúa parámetros y formularios con pruebas controladas." },
  security_headers: { title: "Headers de seguridad", detail: "Revisa CSP, HSTS, clickjacking y otras cabeceras." },
  ssl_tls: { title: "SSL/TLS", detail: "Analiza certificado, protocolos y configuración criptográfica." },
  directory_scan: { title: "Directorios expuestos", detail: "Comprueba archivos y rutas potencialmente sensibles." },
};
const PASSIVE_SCANNERS: (typeof SCANNERS)[number][] = ["security_headers", "ssl_tls"];
const riskTag: Record<RiskLevel, { bg: string; color: string; label: string }> = {
  CRITICAL: { bg: "#FEF2F2", color: c.severity.critical, label: "Crítico" }, HIGH: { bg: "#FFF7ED", color: c.severity.high, label: "Alto" }, MEDIUM: { bg: "#FEFCE8", color: "#A16207", label: "Medio" }, LOW: { bg: "#F0FDF4", color: c.severity.low, label: "Bajo" }, INFO: { bg: "#EFF6FF", color: c.primary, label: "Informativo" },
};
const card: React.CSSProperties = { background: c.surface, border: `1px solid ${c.border}`, borderRadius: 14, boxShadow: "0 4px 16px rgba(16,24,40,.04)" };
const th: React.CSSProperties = { fontSize: 12, fontWeight: 500, color: c.muted, textAlign: "left", padding: "11px 22px", background: "#FAFAFB", borderTop: `1px solid ${c.border}`, borderBottom: `1px solid ${c.border}` };

export default function Scans({ readOnly = false, currentUser }: { readOnly?: boolean; currentUser: Usuario | null }) {
  const [scans, setScans] = useState<ScanSummary[]>(readOnly ? DEMO : []);
  const [modal, setModal] = useState(false);
  const [url, setUrl] = useState("");
  const [selected, setSelected] = useState<(typeof SCANNERS)[number][]>([...PASSIVE_SCANNERS]);
  const [message, setMessage] = useState("");
  const [messageKind, setMessageKind] = useState<"success" | "error">("error");
  const [submitting, setSubmitting] = useState(false);
  const [focusedScanId, setFocusedScanId] = useState<string | null>(null);

  const refresh = async () => {
    if (readOnly) { setScans(DEMO); return; }
    setScans(currentUser?.role === "admin" ? await listScans() : await obtenerMisEscaneos());
  };
  useEffect(() => { void refresh().catch((e) => setMessage(e instanceof Error ? e.message : "No fue posible cargar los escaneos.")); }, [readOnly, currentUser?.id, currentUser?.role]);
  useEffect(() => {
    if (readOnly || !scans.some((scan) => scan.status === "pending" || scan.status === "running")) return;
    const timer = window.setInterval(() => {
      void refresh().catch(() => setMessage("No fue posible actualizar el progreso del escaneo."));
    }, 3000);
    return () => window.clearInterval(timer);
  }, [readOnly, scans, currentUser?.id, currentUser?.role]);

  const toggle = (scanner: (typeof SCANNERS)[number]) => setSelected((current) => current.includes(scanner) ? current.filter((item) => item !== scanner) : [...current, scanner]);
  const submit = async () => {
    if (!url.trim()) { setMessageKind("error"); return setMessage("Ingresa una URL válida."); }
    if (!selected.length) { setMessageKind("error"); return setMessage("Selecciona al menos un scanner."); }
    setSubmitting(true); setMessage("");
    try {
      const created = await startScan(url.trim(), selected);
      setFocusedScanId(created.scan_id);
      setModal(false); setUrl(""); setSelected([...PASSIVE_SCANNERS]);
      setMessageKind("success");
      setMessage("Escaneo iniciado correctamente. Puedes seguir su progreso en tiempo real.");
      await refresh();
    }
    catch (e) { setMessageKind("error"); setMessage(e instanceof Error ? e.message : "No fue posible iniciar el escaneo."); }
    finally { setSubmitting(false); }
  };

  const focusedScan = focusedScanId ? scans.find((scan) => scan.scan_id === focusedScanId) : undefined;
  const focusedActive = focusedScan?.status === "pending" || focusedScan?.status === "running";
  const focusedProgress = focusedScan ? Math.max(focusedScan.progress_percentage, focusedActive ? 4 : 0) : 4;

  return <main className="responsive-page" style={{ flex: 1, padding: "36px 44px 48px", background: c.background, color: c.text }}>
    {focusedScanId && <section className={`scan-live-card ${focusedActive || !focusedScan ? "is-active" : "is-finished"}`} aria-live="polite">
      <div className="scan-live-icon" aria-hidden="true">{focusedActive || !focusedScan ? <span /> : "✓"}</div>
      <div className="scan-live-content">
        <div className="scan-live-heading">
          <div><strong>{focusedActive || !focusedScan ? "Escaneo en progreso" : focusedScan.status === "completed" ? "Escaneo completado" : "Escaneo finalizado"}</strong><span>{focusedScan?.url || "Preparando el análisis y asignando los módulos…"}</span></div>
          <b>{focusedScan ? `${focusedProgress}%` : "Iniciando…"}</b>
        </div>
        <div className={`scan-progress-track ${focusedActive || !focusedScan ? "is-active" : ""}`}><div style={{ width: `${focusedScan?.status === "completed" ? 100 : focusedProgress}%` }} /></div>
        <div className="scan-live-meta"><span>{focusedScan?.status === "pending" ? "En cola" : focusedScan?.current_scanner ? LABELS[focusedScan.current_scanner as keyof typeof LABELS]?.title || "Analizando" : focusedActive || !focusedScan ? "Preparando scanners" : `${focusedScan?.total_vulnerabilities || 0} hallazgos encontrados`}</span><button onClick={() => setFocusedScanId(null)}>Ocultar</button></div>
      </div>
    </section>}
    <header className="dashboard-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 28 }}><div><h1 style={{ margin: 0, fontSize: 30 }}>Escaneos</h1><p style={{ color: c.muted, margin: "6px 0 0" }}>{readOnly ? "Historial de demostración" : "Historial real de tus análisis"}</p></div>{!readOnly && <button onClick={() => setModal(true)} style={{ border: 0, borderRadius: 9, background: c.primary, color: "white", padding: "11px 18px", fontWeight: 600, cursor: "pointer" }}>+ Nuevo escaneo</button>}</header>
    {message && <div role="status" style={{ color: messageKind === "success" ? "#166534" : c.severity.critical, background: messageKind === "success" ? "#F0FDF4" : "#FEF2F2", border: `1px solid ${messageKind === "success" ? "#BBF7D0" : "#FECACA"}`, padding: "11px 14px", borderRadius: 9, marginBottom: 16 }}>{message}</div>}
    <section className="responsive-table-card scans-desktop" style={card}><div style={{ padding: "20px 22px 16px" }}><strong>Historial de escaneos</strong></div>{scans.length === 0 ? <div style={{ padding: 36, textAlign: "center", color: c.muted, borderTop: `1px solid ${c.border}` }}>No has realizado escaneos. Utiliza “Nuevo escaneo” para comenzar.</div> : <table style={{ width: "100%", borderCollapse: "collapse" }}><thead><tr><th style={th}>Sitio</th><th style={th}>Estado y progreso</th><th style={th}>Riesgo</th><th style={th}>Hallazgos</th><th style={th}>Fecha</th></tr></thead><tbody>{scans.map((scan) => { const host = new URL(scan.url).hostname; const tag = riskTag[scan.risk_level]; const active = scan.status === "running" || scan.status === "pending"; return <tr key={scan.scan_id} style={{ borderBottom: "1px solid #F1F2F4" }}><td style={{ padding: "14px 22px" }}><strong>{host}</strong><div style={{ color: c.muted, fontSize: 12 }}>{scan.url}</div></td><td style={{ padding: "14px 22px", minWidth: 210 }}><div style={{ display: "flex", justifyContent: "space-between", gap: 10, fontSize: 13, fontWeight: 600, color: active ? c.primary : scan.status === "completed" ? c.severity.low : c.muted }}><span>{active ? (scan.status === "pending" ? "Preparando análisis" : scan.current_scanner ? LABELS[scan.current_scanner as keyof typeof LABELS]?.title || "Analizando" : "Analizando") : scan.status === "completed" ? "Completado" : scan.status}</span><span>{active ? `${scan.progress_percentage}%` : ""}</span></div><div className={`scan-progress-track ${active ? "is-active" : ""}`}><div style={{ width: `${active ? Math.max(scan.progress_percentage, 4) : scan.status === "completed" ? 100 : scan.progress_percentage}%` }} /></div></td><td style={{ padding: "14px 22px" }}><span style={{ background: tag.bg, color: tag.color, padding: "3px 9px", borderRadius: 999, fontSize: 12, fontWeight: 600 }}>{tag.label}</span></td><td style={{ padding: "14px 22px", fontWeight: 600 }}>{scan.total_vulnerabilities}</td><td style={{ padding: "14px 22px", color: c.muted }}>{new Intl.DateTimeFormat("es-CL").format(new Date(scan.started_at))}</td></tr>; })}</tbody></table>}</section>
    <section className="scans-mobile">{scans.length === 0 ? <article className="scan-mobile-card">No has realizado escaneos.</article> : scans.map((scan) => { const active = scan.status === "running" || scan.status === "pending"; return <article className="scan-mobile-card" key={scan.scan_id}><div className="scan-mobile-heading"><div className="scan-mobile-icon">{new URL(scan.url).hostname[0].toUpperCase()}</div><div><strong>{new URL(scan.url).hostname}</strong><span>{scan.url}</span></div></div><dl><div><dt>Estado</dt><dd>{active ? `${scan.progress_percentage}%` : scan.status}</dd></div><div><dt>Hallazgos</dt><dd>{scan.total_vulnerabilities}</dd></div></dl>{active && <div className="scan-progress-track is-active"><div style={{ width: `${Math.max(scan.progress_percentage, 4)}%` }} /></div>}</article>; })}</section>

    {modal && <div className="scan-modal-backdrop"><div className="scan-modal-card" style={card}><div className="scan-modal-heading"><div><h2>Nuevo escaneo</h2><p>Configura el objetivo y los módulos del análisis.</p></div><button onClick={() => setModal(false)} aria-label="Cerrar">×</button></div><label className="scan-url-field">URL del sitio<input type="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://sitio-autorizado.cl" /></label><div className="scan-selector-heading"><div><strong>Scanners</strong><span>{selected.length} de {SCANNERS.length} seleccionados</span></div><button onClick={() => setSelected(selected.length === SCANNERS.length ? [] : [...SCANNERS])}>{selected.length === SCANNERS.length ? "Deseleccionar todos" : "Seleccionar todos"}</button></div><div className="scanner-grid">{SCANNERS.map((scanner) => <label key={scanner} className={selected.includes(scanner) ? "selected" : ""}><input type="checkbox" checked={selected.includes(scanner)} onChange={() => toggle(scanner)} /><span><strong>{LABELS[scanner].title}</strong><small>{LABELS[scanner].detail}</small></span></label>)}</div><div className="scan-modal-footer"><p>🔒 Solo sitios propios o expresamente autorizados.</p><div><button className="secondary" onClick={() => setModal(false)}>Cancelar</button><button className="primary" disabled={submitting || !selected.length} onClick={() => void submit()}>{submitting ? "Iniciando…" : `Iniciar escaneo (${selected.length})`}</button></div></div></div></div>}
  </main>;
}
