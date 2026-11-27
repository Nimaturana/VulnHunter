import { useState, useEffect } from "react";
import {
  PieChart, Pie, Cell, ResponsiveContainer,
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
} from "recharts";

// Paleta central de colores del proyecto.
import { theme } from "../../shared/styles/theme";
// Funciones y tipos para hablar con el backend sobre escaneos.
import { downloadReport, obtenerDetalleEscaneo, obtenerHistorial } from "../../shared/api/scans";
import type { DetalleEscaneo, HistorialSitio } from "../../shared/api/scans";

const c = theme.colors;

// ---- Claves de severidad y sus estilos (definidos aquí para que el componente sea autónomo) ----
const sevKeys = ["crit", "high", "med", "low"] as const;
type SevKey = (typeof sevKeys)[number];

// Color de cada severidad (usa la paleta central).
const sevColor: Record<SevKey, string> = {
  crit: c.severity.critical,
  high: c.severity.high,
  med: c.severity.medium,
  low: c.severity.low,
};

// Nombre legible de cada severidad.
const sevName: Record<SevKey, string> = {
  crit: "Crítica",
  high: "Alta",
  med: "Media",
  low: "Baja",
};

// Estilo del badge (fondo suave + texto del color) de cada severidad/riesgo.
const tagStyle: Record<SevKey, { bg: string; color: string }> = {
  crit: { bg: "#FEE2E2", color: c.severity.critical },
  high: { bg: "#FFEDD5", color: c.severity.high },
  med:  { bg: "#FEF9C3", color: "#A16207" },
  low:  { bg: "#DCFCE7", color: c.severity.low },
};

// Traduce la severidad del backend (CRITICAL, HIGH...) a nuestras claves cortas.
function aSev(sev: string): SevKey {
  const v = (sev || "").toUpperCase();
  if (v === "CRITICAL") return "crit";
  if (v === "HIGH") return "high";
  if (v === "MEDIUM") return "med";
  return "low"; // LOW e INFO se agrupan como "low".
}

// Formatea una fecha ISO a algo corto y legible (ej: "17 nov").
function fechaCorta(iso: string | null): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleDateString("es-CL", { day: "2-digit", month: "short" });
  } catch {
    return "—";
  }
}

// Tarjeta blanca base (mismo estilo del resto del panel).
const card: React.CSSProperties = {
  backgroundColor: c.surface,
  border: `1px solid ${c.border}`,
  borderRadius: "14px",
  boxShadow: "0 1px 2px rgba(16,24,40,.04), 0 4px 16px rgba(16,24,40,.04)",
};

// Props del componente.
type DetalleSitioProps = {
  scanId: string;
  url: string;
  onVolver: () => void;
};

function DetalleSitio({ scanId, url, onVolver }: DetalleSitioProps) {
  // Detalle del escaneo (con hallazgos) e historial del sitio.
  const [detalle, setDetalle] = useState<DetalleEscaneo | null>(null);
  const [historial, setHistorial] = useState<HistorialSitio | null>(null);
  const [cargando, setCargando] = useState(true);
  // Hallazgo desplegado (índice) y filtro de severidad activo (null = todas).
  const [abierto, setAbierto] = useState<number | null>(null);
  const [filtro, setFiltro] = useState<SevKey | null>(null);

  // Al abrir, pedimos detalle e historial en paralelo.
  useEffect(() => {
    let activo = true;
    const cargar = async () => {
      setCargando(true);
      try {
        const [det, hist] = await Promise.all([
          obtenerDetalleEscaneo(scanId),
          obtenerHistorial(url),
        ]);
        if (activo) {
          setDetalle(det);
          setHistorial(hist);
        }
      } catch {
        if (activo) {
          setDetalle(null);
          setHistorial(null);
        }
      } finally {
        if (activo) setCargando(false);
      }
    };
    cargar();
    return () => { activo = false; };
  }, [scanId, url]);

  // ---- Mientras carga ----
  if (cargando) {
    return (
      <div style={{ padding: "48px 24px", textAlign: "center", color: c.muted }}>
        Cargando el detalle del escaneo…
      </div>
    );
  }

  // ---- Si no se pudo cargar ----
  if (!detalle) {
    return (
      <div style={{ padding: "48px 24px", textAlign: "center", color: c.muted }}>
        No se pudo cargar el detalle.{" "}
        <span style={{ color: c.primary, cursor: "pointer" }} onClick={onVolver}>
          Volver a mis sitios
        </span>
      </div>
    );
  }

  // ---- Cálculos a partir de los datos reales ----
  const dominio = detalle.url.replace(/^https?:\/\//, "").replace(/\/$/, "");
  const hallazgos = detalle.findings;
  const total = hallazgos.length;

  // Conteo de hallazgos por severidad.
  const cnt: Record<SevKey, number> = { crit: 0, high: 0, med: 0, low: 0 };
  for (const h of hallazgos) cnt[aSev(h.severity)]++;

  // Riesgo general del escaneo.
  const riesgo = aSev(detalle.risk_level);
  const tag = tagStyle[riesgo];

  // Datos para la dona (solo severidades con al menos 1 hallazgo).
  const donutData = sevKeys
    .filter((k) => cnt[k])
    .map((k) => ({ name: sevName[k], value: cnt[k], color: sevColor[k] }));

  // Datos para la línea de evolución (historial, del más antiguo al más nuevo).
  const puntos = historial?.historial ?? [];
  const evolucion = puntos.map((p, i) => ({
    nombre: p.fecha ? fechaCorta(p.fecha) : `Escaneo ${i + 1}`,
    score: p.score,
    total: p.conteo.crit + p.conteo.high + p.conteo.med + p.conteo.low,
  }));

  // Hallazgos filtrados según el chip activo.
  const hallazgosFiltrados = filtro
    ? hallazgos.filter((h) => aSev(h.severity) === filtro)
    : hallazgos;

  return (
    <div style={{ color: c.text, fontFamily: "'Inter', Arial, sans-serif" }}>
      {/* Migas de pan: volver. */}
      <div style={{ fontSize: "13.5px", color: c.muted, marginBottom: "18px" }}>
        <span style={{ cursor: "pointer" }} onClick={onVolver}>← Mis sitios</span>
        <span> / </span>
        <span style={{ color: c.text, fontWeight: 500 }}>{dominio}</span>
      </div>

      {/* Cabecera: dominio + badge de riesgo + botón PDF. */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "24px" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
          <div style={{ width: "52px", height: "52px", borderRadius: "13px", border: `1px solid ${c.border}`, display: "grid", placeItems: "center", fontWeight: 600, fontSize: "19px", color: c.muted }}>
            {dominio[0]?.toUpperCase() ?? "?"}
          </div>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
              <h1 style={{ margin: 0, fontSize: "26px", fontWeight: 700, letterSpacing: "-0.02em" }}>{dominio}</h1>
              <span style={{ fontSize: "13px", fontWeight: 600, padding: "5px 11px", borderRadius: "999px", background: tag.bg, color: tag.color }}>
                Riesgo {sevName[riesgo]}
              </span>
            </div>
            <div style={{ fontSize: "14px", color: c.muted, marginTop: "6px" }}>
              {total} vulnerabilidades encontradas · último escaneo {fechaCorta(detalle.completed_at)}
            </div>
          </div>
        </div>
        <button onClick={() => void downloadReport(scanId)} style={{ display: "inline-flex", alignItems: "center", gap: "7px", background: "#fff", color: c.text, border: `1px solid ${c.border}`, borderRadius: "9px", padding: "9px 14px", fontWeight: 500, fontSize: "13.5px", cursor: "pointer" }}>
          Descargar reporte PDF
        </button>
      </div>

      {/* Fila superior: gauge de riesgo (izq) + dona de severidades (der). */}
      <div style={{ display: "grid", gridTemplateColumns: "360px 1fr", gap: "20px", alignItems: "start", marginBottom: "20px" }}>
        {/* GAUGE DE RIESGO. */}
        <div style={card}>
          <div style={{ padding: "20px 22px 0" }}>
            <div style={{ fontSize: "16px", fontWeight: 600 }}>Nivel de riesgo</div>
            <div style={{ fontSize: "13px", color: c.muted, marginTop: "3px" }}>Puntaje general de este escaneo</div>
          </div>
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", padding: "10px 22px 24px" }}>
            {/* Medidor en forma de media luna (gauge). */}
            <div style={{ position: "relative", width: "220px", height: "130px" }}>
              <ResponsiveContainer width={220} height={130}>
                <PieChart>
                  <Pie
                    data={[
                      { name: "riesgo", value: detalle.risk_score },
                      { name: "resto", value: 100 - detalle.risk_score },
                    ]}
                    dataKey="value"
                    cx="50%"
                    cy="100%"
                    startAngle={180}
                    endAngle={0}
                    innerRadius={70}
                    outerRadius={100}
                    stroke="none"
                  >
                    <Cell fill={sevColor[riesgo]} />
                    <Cell fill="#F3F4F6" />
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div style={{ position: "absolute", bottom: 0, left: 0, right: 0, textAlign: "center" }}>
                <div style={{ fontSize: "38px", fontWeight: 700, lineHeight: 1, color: sevColor[riesgo] }}>
                  {detalle.risk_score}
                </div>
                <div style={{ fontSize: "12.5px", color: c.muted, marginTop: "2px" }}>de 100</div>
              </div>
            </div>
            <span style={{ marginTop: "14px", fontSize: "13px", fontWeight: 600, padding: "5px 13px", borderRadius: "999px", background: tag.bg, color: tag.color }}>
              Riesgo {sevName[riesgo]}
            </span>
          </div>
        </div>

        {/* DONA DE SEVERIDADES. */}
        <div style={card}>
          <div style={{ padding: "20px 22px 0" }}>
            <div style={{ fontSize: "16px", fontWeight: 600 }}>Vulnerabilidades por severidad</div>
            <div style={{ fontSize: "13px", color: c.muted, marginTop: "3px" }}>Hallazgos de este escaneo</div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "24px", padding: "12px 22px 24px", flexWrap: "wrap" }}>
            <div style={{ position: "relative", width: "180px", height: "180px" }}>
              <ResponsiveContainer width={180} height={180}>
                <PieChart>
                  <Pie data={donutData} dataKey="value" innerRadius={56} outerRadius={80} paddingAngle={2} stroke="none">
                    {donutData.map((d) => (<Cell key={d.name} fill={d.color} />))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div style={{ position: "absolute", inset: 0, display: "grid", placeItems: "center", textAlign: "center" }}>
                <div>
                  <div style={{ fontSize: "30px", fontWeight: 700, lineHeight: 1 }}>{total}</div>
                  <div style={{ fontSize: "12px", color: c.muted, marginTop: "3px" }}>Total</div>
                </div>
              </div>
            </div>
            {/* Lista con conteo y porcentaje por severidad. */}
            <div style={{ flex: 1, minWidth: "180px", display: "grid", gap: "4px" }}>
              {sevKeys.map((k) => (
                <div key={k} style={{ display: "grid", gridTemplateColumns: "12px 1fr auto 44px", alignItems: "center", gap: "10px", fontSize: "13.5px", padding: "7px 10px", borderRadius: "8px" }}>
                  <span style={{ width: "10px", height: "10px", borderRadius: "3px", background: sevColor[k] }} />
                  <span>{sevName[k]}</span>
                  <span style={{ fontWeight: 600 }}>{cnt[k]}</span>
                  <span style={{ color: c.muted, textAlign: "right", fontSize: "12.5px" }}>{total ? Math.round((cnt[k] / total) * 100) : 0}%</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* EVOLUCIÓN DE TU SEGURIDAD (línea de historial). */}
      <div style={{ ...card, marginBottom: "20px" }}>
        <div style={{ padding: "20px 22px 0" }}>
          <div style={{ fontSize: "16px", fontWeight: 600 }}>Evolución de tu seguridad</div>
          <div style={{ fontSize: "13px", color: c.muted, marginTop: "3px" }}>
            Cómo ha cambiado el riesgo y la cantidad de hallazgos escaneo tras escaneo
          </div>
        </div>
        <div style={{ padding: "18px 14px 22px" }}>
          {evolucion.length <= 1 ? (
            <div style={{ padding: "24px", textAlign: "center", color: c.muted, fontSize: "13.5px" }}>
              Aún no hay suficiente historial para mostrar la evolución. Vuelve a escanear este sitio más adelante para ver cómo cambia tu seguridad.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={240}>
              <LineChart data={evolucion} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#F1F2F4" />
                <XAxis dataKey="nombre" tick={{ fontSize: 12, fill: c.muted }} />
                <YAxis tick={{ fontSize: 12, fill: c.muted }} />
                <Tooltip />
                <Line type="monotone" dataKey="score" name="Riesgo (0-100)" stroke={c.primary} strokeWidth={2} dot={{ r: 4 }} />
                <Line type="monotone" dataKey="total" name="Hallazgos" stroke={c.severity.high} strokeWidth={2} dot={{ r: 4 }} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* HALLAZGOS con filtros por chips. */}
      <div style={card}>
        <div style={{ padding: "20px 22px 14px" }}>
          <div style={{ fontSize: "16px", fontWeight: 600 }}>Hallazgos</div>
          <div style={{ fontSize: "13px", color: c.muted, marginTop: "3px" }}>Haz clic en un hallazgo para ver la descripción y cómo corregirlo</div>
          {/* Chips de filtro por severidad. */}
          <div style={{ display: "flex", gap: "8px", marginTop: "14px", flexWrap: "wrap" }}>
            <button
              onClick={() => setFiltro(null)}
              style={{ fontSize: "12.5px", fontWeight: 600, padding: "5px 12px", borderRadius: "999px", cursor: "pointer", border: `1px solid ${filtro === null ? c.primary : c.border}`, background: filtro === null ? c.primary : "#fff", color: filtro === null ? "#fff" : c.text }}
            >
              Todas ({total})
            </button>
            {sevKeys.map((k) => (
              <button
                key={k}
                onClick={() => setFiltro(filtro === k ? null : k)}
                disabled={cnt[k] === 0}
                style={{ fontSize: "12.5px", fontWeight: 600, padding: "5px 12px", borderRadius: "999px", cursor: cnt[k] === 0 ? "default" : "pointer", opacity: cnt[k] === 0 ? 0.4 : 1, border: `1px solid ${filtro === k ? sevColor[k] : c.border}`, background: filtro === k ? tagStyle[k].bg : "#fff", color: filtro === k ? tagStyle[k].color : c.text }}
              >
                {sevName[k]} ({cnt[k]})
              </button>
            ))}
          </div>
        </div>
        <div>
          {total === 0 ? (
            <div style={{ padding: "24px 22px", color: c.muted, fontSize: "14px" }}>
              Este escaneo no encontró vulnerabilidades. ¡Buena noticia!
            </div>
          ) : (
            hallazgosFiltrados.map((f, i) => {
              const abiertoEste = abierto === i;
              const sKey = aSev(f.severity);
              const sTag = tagStyle[sKey];
              return (
                <div key={i} style={{ borderTop: `1px solid #F1F2F4` }}>
                  <div onClick={() => setAbierto(abiertoEste ? null : i)} style={{ display: "grid", gridTemplateColumns: "96px 1fr 20px", alignItems: "center", gap: "16px", padding: "16px 22px", cursor: "pointer" }}>
                    <span style={{ fontSize: "12px", fontWeight: 600, padding: "3px 9px", borderRadius: "999px", background: sTag.bg, color: sTag.color, justifySelf: "start" }}>
                      {sevName[sKey]}
                    </span>
                    <div>
                      <div style={{ fontSize: "14px", fontWeight: 500 }}>{f.type}</div>
                      <div style={{ fontSize: "12.5px", color: c.muted, marginTop: "3px", fontFamily: "ui-monospace, Menlo, monospace" }}>{f.location ?? ""}</div>
                    </div>
                    <span style={{ color: "#9CA3AF", transform: abiertoEste ? "rotate(90deg)" : "none", transition: "transform .2s" }}>›</span>
                  </div>
                  {abiertoEste && (
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "24px", padding: "0 22px 20px 134px", fontSize: "13.5px", lineHeight: 1.6, color: "#374151" }}>
                      <div>
                        <h4 style={{ fontSize: "12px", fontWeight: 600, color: c.muted, textTransform: "uppercase", letterSpacing: ".05em", marginBottom: "6px" }}>Descripción</h4>
                        {f.description ?? "Sin descripción."}
                      </div>
                      <div>
                        <h4 style={{ fontSize: "12px", fontWeight: 600, color: c.muted, textTransform: "uppercase", letterSpacing: ".05em", marginBottom: "6px" }}>Cómo corregirlo</h4>
                        {f.recommendation ?? "Sin recomendación."}
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}

export default DetalleSitio;

