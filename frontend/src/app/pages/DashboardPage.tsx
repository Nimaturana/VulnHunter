import { useEffect, useMemo, useState } from "react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from "recharts";
import type { Usuario } from "../../shared/api/auth";
import { getScan, listScans, obtenerMisEscaneos, type ScanDetail, type ScanSummary } from "../../shared/api/scans";
import { theme } from "../../shared/styles/theme";

const c = theme.colors;
const MONTHS = ["Ene", "Feb", "Mar", "Abr", "May", "Jun", "Jul", "Ago", "Sep", "Oct", "Nov", "Dic"];
const DEMO_SCANS: ScanSummary[] = [
  { scan_id: "DEMO-001", url: "https://tienda-ejemplo.cl", status: "completed", risk_level: "CRITICAL", total_vulnerabilities: 5, started_at: "2026-10-14T10:42:00Z", completed_at: "2026-10-14T10:46:00Z", progress_percentage: 100, current_scanner: null, task_id: null, execution_mode: "celery", queued_at: null, report_status: "generated" },
  { scan_id: "DEMO-002", url: "https://empresa-demo.cl", status: "completed", risk_level: "HIGH", total_vulnerabilities: 6, started_at: "2026-10-13T18:05:00Z", completed_at: "2026-10-13T18:09:00Z", progress_percentage: 100, current_scanner: null, task_id: null, execution_mode: "celery", queued_at: null, report_status: "generated" },
  { scan_id: "DEMO-003", url: "https://portal-prueba.cl", status: "completed", risk_level: "MEDIUM", total_vulnerabilities: 6, started_at: "2026-10-12T09:17:00Z", completed_at: "2026-10-12T09:21:00Z", progress_percentage: 100, current_scanner: null, task_id: null, execution_mode: "celery", queued_at: null, report_status: "generated" },
];
const card: React.CSSProperties = { backgroundColor: c.surface, border: `1px solid ${c.border}`, borderRadius: 14, boxShadow: "0 1px 2px rgba(16,24,40,.04), 0 4px 16px rgba(16,24,40,.04)" };

function riskPresentation(score: number) {
  if (score >= 80) return { label: "Crítico", color: c.severity.critical, bg: "#FEF2F2" };
  if (score >= 50) return { label: "Alto", color: c.severity.high, bg: "#FFF7ED" };
  if (score >= 25) return { label: "Medio", color: "#A16207", bg: "#FEFCE8" };
  return { label: "Bajo", color: c.severity.low, bg: "#F0FDF4" };
}

function formatScanDate(value: string) {
  const date = new Date(value);
  return {
    date: new Intl.DateTimeFormat("es-CL", { day: "2-digit", month: "short", year: "numeric" }).format(date),
    time: new Intl.DateTimeFormat("es-CL", { hour: "2-digit", minute: "2-digit" }).format(date),
  };
}

export default function Dashboard({ readOnly = false, currentUser, onNewScan }: { readOnly?: boolean; currentUser: Usuario | null; onNewScan: () => void }) {
  const [scans, setScans] = useState<ScanSummary[]>(readOnly ? DEMO_SCANS : []);
  const [details, setDetails] = useState<ScanDetail[]>([]);
  const [loading, setLoading] = useState(!readOnly);
  const [error, setError] = useState("");

  useEffect(() => {
    if (readOnly) return;
    let cancelled = false;
    async function loadDashboard() {
      setLoading(true);
      setError("");
      try {
        // El administrador ve el sistema completo; cada auditor ve solamente lo suyo.
        const summaries = currentUser?.role === "admin" ? await listScans() : await obtenerMisEscaneos();
        const completed = summaries.filter((scan) => scan.status === "completed" || scan.status === "partial");
        const loadedDetails = await Promise.all(completed.map((scan) => getScan(scan.scan_id)));
        if (!cancelled) { setScans(summaries); setDetails(loadedDetails); }
      } catch (reason) {
        if (!cancelled) setError(reason instanceof Error ? reason.message : "No fue posible cargar el resumen.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    void loadDashboard();
    return () => { cancelled = true; };
  }, [currentUser?.id, currentUser?.role, readOnly]);

  const findings = useMemo(() => details.flatMap((scan) => scan.vulnerabilities), [details]);
  const uniqueSites = useMemo(() => new Set(scans.map((scan) => scan.url)).size, [scans]);
  const riskScore = useMemo(() => readOnly ? 72 : details.reduce((max, scan) => Math.max(max, scan.risk_score || 0), 0), [details, readOnly]);
  const risk = riskPresentation(riskScore);
  const severities = useMemo(() => {
    const counts = readOnly
      ? { CRITICAL: 3, HIGH: 5, MEDIUM: 6, LOW: 3, INFO: 0 }
      : { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    findings.forEach((finding) => { counts[finding.severity] += 1; });
    return [
      { name: "Crítica", value: counts.CRITICAL, color: c.severity.critical },
      { name: "Alta", value: counts.HIGH, color: c.severity.high },
      { name: "Media", value: counts.MEDIUM, color: c.severity.medium },
      { name: "Baja", value: counts.LOW, color: c.severity.low },
      { name: "Informativa", value: counts.INFO, color: "#60A5FA" },
    ];
  }, [findings, readOnly]);
  const totalFindings = severities.reduce((sum, item) => sum + item.value, 0);

  const evolution = useMemo(() => {
    if (readOnly) return [
      { mes: "Jun", escaneos: 2, vulnerabilidades: 9 }, { mes: "Jul", escaneos: 3, vulnerabilidades: 11 },
      { mes: "Ago", escaneos: 4, vulnerabilidades: 8 }, { mes: "Sep", escaneos: 3, vulnerabilidades: 12 },
      { mes: "Oct", escaneos: 5, vulnerabilidades: 14 }, { mes: "Nov", escaneos: 7, vulnerabilidades: 17 },
    ];
    const now = new Date();
    return Array.from({ length: 6 }, (_, index) => {
      const month = new Date(now.getFullYear(), now.getMonth() - (5 - index), 1);
      const monthly = scans.filter((scan) => { const started = new Date(scan.started_at); return started.getFullYear() === month.getFullYear() && started.getMonth() === month.getMonth(); });
      return { mes: MONTHS[month.getMonth()], escaneos: monthly.length, vulnerabilidades: monthly.reduce((sum, scan) => sum + scan.total_vulnerabilities, 0) };
    });
  }, [scans, readOnly]);
  const recent = useMemo(() => [...scans].sort((a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime()).slice(0, 5), [scans]);

  const greeting = readOnly ? "Bienvenido a la demostración" : `Hola, ${currentUser?.nombre || "usuario"}`;
  const kpis = [
    { value: scans.length, label: "Escaneos totales", foot: scans.length ? "registrados en tu cuenta" : "aún no hay escaneos" },
    { value: totalFindings, label: "Vulnerabilidades", foot: `${severities[0].value} críticas detectadas` },
    { value: uniqueSites, label: "Sitios", foot: uniqueSites ? "analizados por tu cuenta" : "aún no hay sitios" },
  ];

  return <main className="responsive-page" style={{ flex: 1, padding: "36px 44px 48px", background: c.background, color: c.text }}>
    <header className="dashboard-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: 28 }}><div><h1 style={{ margin: 0, fontSize: 30, fontWeight: 700 }}>{greeting}</h1><p style={{ color: c.muted, fontSize: 15, margin: "6px 0 0" }}>{readOnly ? "Vista demostrativa de VulnHunter" : "Resumen real de tus sitios y escaneos"}</p></div>{!readOnly && <button onClick={onNewScan} style={{ border: 0, borderRadius: 9, background: c.primary, color: "white", padding: "11px 18px", fontWeight: 600, cursor: "pointer" }}>+ Nuevo escaneo</button>}</header>
    {error && <div role="alert" style={{ ...card, padding: 16, marginBottom: 20, color: c.severity.critical }}>{error}</div>}
    {loading && <div style={{ marginBottom: 18, color: c.muted }}>Cargando información de seguridad…</div>}

    <section className="dashboard-kpis" style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 20, marginBottom: 20 }}>
      {kpis.map((item) => <div key={item.label} style={{ ...card, padding: "20px 22px" }}><div style={{ fontSize: 34, fontWeight: 700, lineHeight: 1 }}>{item.value}</div><div style={{ fontSize: 14, fontWeight: 500, marginTop: 10 }}>{item.label}</div><div style={{ fontSize: 12.5, color: c.muted, marginTop: 3 }}>{item.foot}</div></div>)}
      <div style={{ ...card, padding: "20px 22px" }}><div style={{ fontSize: 34, fontWeight: 700, lineHeight: 1, display: "flex", alignItems: "baseline", gap: 10 }}>{riskScore}<span style={{ fontSize: 12, fontWeight: 600, padding: "3px 9px", borderRadius: 999, background: risk.bg, color: risk.color }}>{risk.label}</span></div><div style={{ fontSize: 14, fontWeight: 500, marginTop: 10 }}>Nivel de riesgo máximo</div><div style={{ height: 6, borderRadius: 999, background: "#F3F4F6", marginTop: 14, overflow: "hidden" }}><div style={{ width: `${riskScore}%`, height: "100%", background: risk.color }} /></div></div>
    </section>

    <section className="dashboard-charts" style={{ display: "grid", gridTemplateColumns: "1.65fr 1fr", gap: 20, marginBottom: 20 }}>
      <div style={{ ...card, padding: "20px 22px" }}><strong>Evolución de escaneos</strong><div style={{ fontSize: 13, color: c.muted, margin: "3px 0 12px" }}>Escaneos y vulnerabilidades de los últimos seis meses</div><ResponsiveContainer width="100%" height={280}><AreaChart data={evolution} margin={{ top: 10, right: 10, left: -10 }}><defs><linearGradient id="fillBrand" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={c.primary} stopOpacity={0.14} /><stop offset="100%" stopColor={c.primary} stopOpacity={0} /></linearGradient></defs><CartesianGrid strokeDasharray="3 4" stroke="#EEF0F3" vertical={false} /><XAxis dataKey="mes" tickLine={false} axisLine={false} /><YAxis allowDecimals={false} tickLine={false} axisLine={false} /><Tooltip /><Area type="monotone" dataKey="vulnerabilidades" stroke="#CBD5E1" strokeWidth={2} strokeDasharray="5 5" fill="none" /><Area type="monotone" dataKey="escaneos" stroke={c.primary} strokeWidth={2.5} fill="url(#fillBrand)" /></AreaChart></ResponsiveContainer></div>
      <div style={{ ...card, padding: "20px 22px" }}><strong>Vulnerabilidades por severidad</strong><div style={{ fontSize: 13, color: c.muted, marginTop: 3 }}>Hallazgos reales de los escaneos</div><div style={{ position: "relative", display: "flex", justifyContent: "center", margin: "8px 0 16px" }}><ResponsiveContainer width={200} height={200}><PieChart><Pie data={severities} dataKey="value" innerRadius={62} outerRadius={88} paddingAngle={totalFindings ? 2 : 0} stroke="none">{severities.map((item) => <Cell key={item.name} fill={item.color} />)}</Pie></PieChart></ResponsiveContainer><div style={{ position: "absolute", inset: 0, display: "grid", placeItems: "center", textAlign: "center" }}><div><div style={{ fontSize: 34, fontWeight: 700 }}>{totalFindings}</div><small style={{ color: c.muted }}>Total</small></div></div></div><div style={{ display: "grid", gap: 4 }}>{severities.map((item) => <div key={item.name} style={{ display: "grid", gridTemplateColumns: "12px 1fr auto 44px", gap: 10, alignItems: "center", padding: "7px 8px", fontSize: 13.5 }}><span style={{ width: 10, height: 10, borderRadius: 3, background: item.color }} /><span>{item.name}</span><strong>{item.value}</strong><span style={{ color: c.muted, textAlign: "right" }}>{totalFindings ? Math.round(item.value / totalFindings * 100) : 0}%</span></div>)}</div></div>
    </section>

    <section className="responsive-table-card dashboard-activity-desktop" style={card}><div style={{ padding: "20px 22px 16px" }}><strong>Actividad reciente</strong><div style={{ color: c.muted, fontSize: 13, marginTop: 3 }}>Últimos escaneos de esta cuenta</div></div>{recent.length === 0 ? <div style={{ padding: "34px 22px", borderTop: `1px solid ${c.border}`, color: c.muted, textAlign: "center" }}>Todavía no hay escaneos registrados.</div> : <table style={{ width: "100%", borderCollapse: "collapse" }}><thead><tr style={{ background: "#FAFAFB" }}>{["Sitio", "Fecha", "Vulnerabilidades", "Nivel de riesgo"].map((title) => <th key={title} style={{ padding: "11px 22px", textAlign: "left", color: c.muted, fontSize: 12 }}>{title}</th>)}</tr></thead><tbody>{recent.map((scan) => { const date = formatScanDate(scan.started_at); const score = scan.risk_level === "CRITICAL" ? 90 : scan.risk_level === "HIGH" ? 65 : scan.risk_level === "MEDIUM" ? 35 : 10; const rowRisk = riskPresentation(score); return <tr key={scan.scan_id} style={{ borderTop: `1px solid ${c.border}` }}><td style={{ padding: "14px 22px" }}><strong>{new URL(scan.url).hostname}</strong><div style={{ color: c.muted, fontSize: 12 }}>{scan.url}</div></td><td style={{ padding: "14px 22px" }}>{date.date}<div style={{ color: c.muted, fontSize: 12 }}>{date.time} h</div></td><td style={{ padding: "14px 22px", fontWeight: 600 }}>{scan.total_vulnerabilities}</td><td style={{ padding: "14px 22px" }}><span style={{ padding: "3px 9px", borderRadius: 999, background: rowRisk.bg, color: rowRisk.color, fontSize: 12, fontWeight: 600 }}>{rowRisk.label}</span></td></tr>; })}</tbody></table>}</section>

    <section className="dashboard-activity-mobile" aria-label="Actividad reciente"><div className="mobile-section-heading"><div><strong>Actividad reciente</strong><span>Últimos escaneos de esta cuenta</span></div></div>{recent.length === 0 ? <article className="activity-mobile-card">Todavía no hay escaneos registrados.</article> : recent.map((scan) => { const date = formatScanDate(scan.started_at); const host = new URL(scan.url).hostname; return <article key={scan.scan_id} className="activity-mobile-card"><div className="activity-mobile-site"><div>{host[0].toUpperCase()}</div><span><strong>{host}</strong><small>{scan.url}</small></span></div><div className="activity-mobile-meta"><span>{date.date} · {date.time}</span><span><strong>{scan.total_vulnerabilities}</strong> hallazgos</span></div></article>; })}</section>
  </main>;
}
