import { useEffect, useState } from "react";
import type { Usuario } from "../../../shared/api/auth";
import { getScan, listScans, obtenerMisEscaneos, type Finding } from "../../../shared/api/scans";
import { theme } from "../../../shared/styles/theme";

const c = theme.colors;
type Row = Finding & { site: string; id: string };
const DEMO: Row[] = [
  { id: "1", type: "XSS reflejado", severity: "HIGH", site: "https://tienda-ejemplo.cl", location: "/buscar?q=", scanner: "xss", description: "Entrada reflejada en un contexto ejecutable.", recommendation: "Codificar la salida y aplicar CSP.", evidence: "<script>…", confidence: "high" },
  { id: "2", type: "Headers de seguridad faltantes", severity: "MEDIUM", site: "https://empresa-demo.cl", location: "/", scanner: "security_headers", description: "Faltan cabeceras recomendadas.", recommendation: "Configurar CSP y HSTS.", evidence: "CSP ausente", confidence: "high" },
  { id: "3", type: "Configuración TLS débil", severity: "LOW", site: "https://portal-prueba.cl", location: "/", scanner: "ssl_tls", description: "Configuración mejorable.", recommendation: "Actualizar configuración TLS.", evidence: "Suite heredada", confidence: "medium" },
];
const tags = { CRITICAL: ["#FEF2F2", c.severity.critical, "Crítica"], HIGH: ["#FFF7ED", c.severity.high, "Alta"], MEDIUM: ["#FEFCE8", "#A16207", "Media"], LOW: ["#F0FDF4", c.severity.low, "Baja"], INFO: ["#EFF6FF", c.primary, "Informativa"] } as const;
const card: React.CSSProperties = { background: c.surface, border: `1px solid ${c.border}`, borderRadius: 14 };
const th: React.CSSProperties = { padding: "11px 22px", textAlign: "left", color: c.muted, fontSize: 12, background: "#FAFAFB", borderTop: `1px solid ${c.border}` };

export default function Findings({ readOnly = false, currentUser }: { readOnly?: boolean; currentUser: Usuario | null }) {
  const [rows, setRows] = useState<Row[]>(readOnly ? DEMO : []);
  const [error, setError] = useState("");
  useEffect(() => {
    if (readOnly) { setRows(DEMO); return; }
    async function load() {
      const scans = currentUser?.role === "admin" ? await listScans() : await obtenerMisEscaneos();
      const completed = scans.filter((scan) => scan.status === "completed" || scan.status === "partial");
      const details = await Promise.all(completed.map((scan) => getScan(scan.scan_id)));
      setRows(details.flatMap((scan) => scan.vulnerabilities.map((finding, index) => ({ ...finding, site: scan.url, id: `${scan.scan_id}-${index}` }))));
    }
    void load().catch((reason) => setError(reason instanceof Error ? reason.message : "No fue posible cargar los hallazgos."));
  }, [readOnly, currentUser?.id, currentUser?.role]);

  return <main className="responsive-page" style={{ flex: 1, padding: "36px 44px 48px", background: c.background, color: c.text }}><header style={{ marginBottom: 28 }}><h1 style={{ margin: 0, fontSize: 30 }}>Hallazgos</h1><p style={{ color: c.muted }}>{readOnly ? "Vulnerabilidades de demostración" : "Vulnerabilidades detectadas en tus escaneos"}</p></header>{error && <p style={{ color: c.severity.critical }}>{error}</p>}<section className="responsive-table-card" style={card}><div style={{ display: "flex", justifyContent: "space-between", padding: "20px 22px 16px" }}><strong>Vulnerabilidades detectadas</strong><span style={{ color: c.muted }}>{rows.length} hallazgos</span></div>{rows.length === 0 ? <div style={{ padding: 36, textAlign: "center", color: c.muted, borderTop: `1px solid ${c.border}` }}>No hay vulnerabilidades registradas. Los resultados aparecerán después de completar un escaneo.</div> : <table style={{ width: "100%", borderCollapse: "collapse" }}><thead><tr><th style={th}>Vulnerabilidad</th><th style={th}>Severidad</th><th style={th}>Sitio</th><th style={th}>Scanner</th><th style={th}>Confianza</th></tr></thead><tbody>{rows.map((row) => { const tag = tags[row.severity]; return <tr key={row.id} style={{ borderTop: `1px solid ${c.border}` }}><td style={{ padding: "14px 22px" }}><strong>{row.type}</strong><div style={{ color: c.muted, fontSize: 12 }}>{row.location}</div></td><td style={{ padding: "14px 22px" }}><span style={{ background: tag[0], color: tag[1], padding: "3px 9px", borderRadius: 999, fontSize: 12, fontWeight: 600 }}>{tag[2]}</span></td><td style={{ padding: "14px 22px", color: c.muted }}>{row.site}</td><td style={{ padding: "14px 22px" }}>{row.scanner}</td><td style={{ padding: "14px 22px" }}>{row.confidence}</td></tr>; })}</tbody></table>}</section></main>;
}
