// ───────────────────────────────────────────────────────────────
// IMPORTACIONES
// ───────────────────────────────────────────────────────────────

// useState: permite guardar "estados" (datos que cambian) dentro del componente.
// Aquí lo usamos para abrir/cerrar el modal de "Nuevo escaneo".
import { useState } from "react";

// Componentes de la librería Recharts para dibujar los gráficos.
import {
  AreaChart,          // gráfico de área/línea (la evolución de escaneos)
  Area,               // cada línea con relleno dentro del AreaChart
  XAxis,              // eje horizontal (los meses)
  YAxis,              // eje vertical (los valores)
  CartesianGrid,      // las líneas de fondo de la cuadrícula
  Tooltip,            // el cuadrito que aparece al pasar el mouse
  ResponsiveContainer,// hace que el gráfico se adapte al ancho disponible
  PieChart,           // gráfico circular (la dona de severidades)
  Pie,                // la dona en sí
  Cell,               // cada "pedazo" de la dona, para darle su color
} from "recharts";

// Importamos la paleta de colores central desde theme.ts.
// Así todos los colores salen de un solo lugar y son fáciles de cambiar.
import { theme } from "../../shared/styles/theme";

// Atajo: en vez de escribir theme.colors cada vez, usamos c.
const c = theme.colors;

// ───────────────────────────────────────────────────────────────
// DATOS DE EJEMPLO (luego vendrán del backend real)
// ───────────────────────────────────────────────────────────────

// Las 3 primeras tarjetas de resumen (la cuarta, el riesgo, va aparte).
const kpis = [
  { value: "24", label: "Escaneos totales", foot: "vs. mes anterior" },
  { value: "17", label: "Vulnerabilidades", foot: "3 críticas pendientes" },
  { value: "5", label: "Sitios", foot: "monitoreados activamente" },
];

// Datos del gráfico de línea: por cada mes, cuántos escaneos y vulnerabilidades hubo.
const evolucion = [
  { mes: "May", escaneos: 2, vulnerabilidades: 9 },
  { mes: "Jun", escaneos: 3, vulnerabilidades: 11 },
  { mes: "Jul", escaneos: 4, vulnerabilidades: 8 },
  { mes: "Ago", escaneos: 3, vulnerabilidades: 12 },
  { mes: "Sep", escaneos: 5, vulnerabilidades: 14 },
  { mes: "Oct", escaneos: 7, vulnerabilidades: 17 },
];

// Datos de la dona: cantidad de hallazgos por nivel de severidad, con su color.
const severidades = [
  { name: "Crítica", value: 3, color: c.severity.critical },
  { name: "Alta", value: 5, color: c.severity.high },
  { name: "Media", value: 6, color: c.severity.medium },
  { name: "Baja", value: 3, color: c.severity.low },
];
// Suma total de hallazgos (se muestra en el centro de la dona).
const totalSev = severidades.reduce((a, s) => a + s.value, 0);

// Estilos de las "etiquetas" de riesgo (Crítico, Alto, Medio, Bajo) de la tabla.
// Cada una tiene su color de fondo (bg), color de texto y su texto (label).
const riesgoTag: Record<string, { bg: string; color: string; label: string }> = {
  crit: { bg: "#FEF2F2", color: c.severity.critical, label: "Crítico" },
  high: { bg: "#FFF7ED", color: c.severity.high, label: "Alto" },
  med: { bg: "#FEFCE8", color: "#A16207", label: "Medio" },
  low: { bg: "#F0FDF4", color: c.severity.low, label: "Bajo" },
};

// Filas de la tabla "Actividad reciente": sitio, url, fecha, hora,
// cantidad de vulnerabilidades (v) y clave del riesgo (r, que conecta con riesgoTag).
const actividad = [
  { d: "tiendaverde.com", u: "https://tiendaverde.com", f: "14 oct 2026", h: "10:42", v: 5, r: "crit" },
  { d: "portal.clinicasur.mx", u: "https://portal.clinicasur.mx", f: "13 oct 2026", h: "18:05", v: 6, r: "high" },
  { d: "blog.andesviajes.com", u: "https://blog.andesviajes.com", f: "12 oct 2026", h: "09:17", v: 4, r: "med" },
  { d: "app.finanzaspyme.io", u: "https://app.finanzaspyme.io", f: "10 oct 2026", h: "15:30", v: 2, r: "low" },
  { d: "estudiolumen.design", u: "https://estudiolumen.design", f: "08 oct 2026", h: "11:58", v: 0, r: "low" },
];

// Estilo base de las "tarjetas" blancas (se reutiliza en KPIs, gráficos y tabla).
// Fondo blanco, borde gris suave, esquinas redondeadas y una sombra ligera.
const card: React.CSSProperties = {
  backgroundColor: c.surface,
  border: `1px solid ${c.border}`,
  borderRadius: "14px",
  boxShadow: "0 1px 2px rgba(16,24,40,.04), 0 4px 16px rgba(16,24,40,.04)",
};

// ───────────────────────────────────────────────────────────────
// COMPONENTE PRINCIPAL
// ───────────────────────────────────────────────────────────────

function Dashboard() {
  // showNewScan: controla si el modal de "Nuevo escaneo" está abierto (true) o cerrado (false).
  const [showNewScan, setShowNewScan] = useState(false);
  // scanUrl: guarda lo que el usuario escribe en el campo de URL del modal.
  const [scanUrl, setScanUrl] = useState("");

  return (
    // Contenedor principal del contenido (a la derecha de la barra lateral).
    <main style={{ flex: 1, padding: "36px 44px 48px", background: c.background, color: c.text }}>

      {/* ───────── ENCABEZADO: saludo + botón "Nuevo escaneo" ───────── */}
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: "28px" }}>
        <div>
          <h1 style={{ margin: 0, fontSize: "30px", fontWeight: 700, letterSpacing: "-0.02em" }}>Hola, Carlos</h1>
          <p style={{ color: c.muted, fontSize: "15px", marginTop: "6px", margin: "6px 0 0" }}>
            Resumen general de tus sitios
          </p>
        </div>
        {/* Al hacer clic, abrimos el modal poniendo showNewScan en true. */}
        <button
          onClick={() => setShowNewScan(true)}
          style={{
            display: "inline-flex", alignItems: "center", gap: "8px",
            backgroundColor: c.primary, color: "#fff", border: 0, borderRadius: "9px",
            padding: "11px 18px", fontWeight: 600, fontSize: "14px", cursor: "pointer",
            boxShadow: "0 1px 2px rgba(37,99,235,.25)",
          }}
        >
          + Nuevo escaneo
        </button>
      </header>

      {/* ───────── TARJETAS KPI (resumen en números) ───────── */}
      {/* Grid de 4 columnas iguales. */}
      <section style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "20px", marginBottom: "20px" }}>
        {/* Recorremos el arreglo kpis y dibujamos una tarjeta por cada uno. */}
        {kpis.map((k) => (
          <div key={k.label} style={{ ...card, padding: "20px 22px" }}>
            <div style={{ fontSize: "34px", fontWeight: 700, letterSpacing: "-0.025em", lineHeight: 1 }}>{k.value}</div>
            <div style={{ fontSize: "14px", fontWeight: 500, marginTop: "10px" }}>{k.label}</div>
            <div style={{ fontSize: "12.5px", color: c.muted, marginTop: "3px" }}>{k.foot}</div>
          </div>
        ))}

        {/* Cuarta tarjeta: nivel de riesgo (va aparte porque tiene barra y etiqueta). */}
        <div style={{ ...card, padding: "20px 22px" }}>
          <div style={{ fontSize: "34px", fontWeight: 700, letterSpacing: "-0.025em", lineHeight: 1, display: "flex", alignItems: "baseline", gap: "10px" }}>
            72
            {/* Etiqueta "Alto" con fondo naranja claro. */}
            <span style={{ fontSize: "12px", fontWeight: 600, padding: "3px 9px", borderRadius: "999px", background: "#FFF7ED", color: c.severity.high }}>
              Alto
            </span>
          </div>
          <div style={{ fontSize: "14px", fontWeight: 500, marginTop: "10px" }}>Nivel de riesgo</div>
          {/* Barra de progreso: el relleno llega al 72% con un degradado verde→amarillo→naranja. */}
          <div style={{ height: "6px", borderRadius: "999px", background: "#F3F4F6", marginTop: "14px", overflow: "hidden" }}>
            <div style={{ width: "72%", height: "100%", borderRadius: "999px", background: `linear-gradient(90deg, ${c.severity.low}, ${c.severity.medium} 45%, ${c.severity.high} 75%)` }} />
          </div>
        </div>
      </section>

      {/* ───────── GRÁFICOS: línea (izquierda) + dona (derecha) ───────── */}
      <section style={{ display: "grid", gridTemplateColumns: "1.65fr 1fr", gap: "20px", marginBottom: "20px" }}>

        {/* GRÁFICO DE LÍNEA: evolución de escaneos */}
        <div style={{ ...card, padding: "20px 22px" }}>
          <div style={{ fontSize: "16px", fontWeight: 600 }}>Evolución de escaneos</div>
          <div style={{ fontSize: "13px", color: c.muted, marginTop: "3px", marginBottom: "12px" }}>
            Escaneos realizados y vulnerabilidades detectadas
          </div>
          {/* ResponsiveContainer hace que el gráfico ocupe todo el ancho de la tarjeta. */}
          <ResponsiveContainer width="100%" height={280}>
            <AreaChart data={evolucion} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
              {/* defs: define el degradado azul del relleno bajo la línea. */}
              <defs>
                <linearGradient id="fillBrand" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={c.primary} stopOpacity={0.14} />
                  <stop offset="100%" stopColor={c.primary} stopOpacity={0} />
                </linearGradient>
              </defs>
              {/* Cuadrícula de fondo (solo líneas horizontales). */}
              <CartesianGrid strokeDasharray="3 4" stroke="#EEF0F3" vertical={false} />
              {/* Eje X: los meses. */}
              <XAxis dataKey="mes" tickLine={false} axisLine={false} tick={{ fontSize: 12, fill: c.muted }} />
              {/* Eje Y: los valores numéricos. */}
              <YAxis tickLine={false} axisLine={false} tick={{ fontSize: 11.5, fill: "#9CA3AF" }} />
              {/* Tooltip: el cuadrito oscuro al pasar el mouse. */}
              <Tooltip
                contentStyle={{ background: c.text, border: 0, borderRadius: "8px", color: "#fff", fontSize: "12px" }}
                labelStyle={{ color: "#fff", fontWeight: 600 }}
              />
              {/* Línea gris punteada: vulnerabilidades. */}
              <Area type="monotone" dataKey="vulnerabilidades" stroke="#CBD5E1" strokeWidth={2} strokeDasharray="5 5" fill="none" />
              {/* Línea azul con relleno: escaneos. */}
              <Area type="monotone" dataKey="escaneos" stroke={c.primary} strokeWidth={2.5} fill="url(#fillBrand)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* GRÁFICO DE DONA: vulnerabilidades por severidad */}
        <div style={{ ...card, padding: "20px 22px" }}>
          <div style={{ fontSize: "16px", fontWeight: 600 }}>Vulnerabilidades por severidad</div>
          <div style={{ fontSize: "13px", color: c.muted, marginTop: "3px" }}>Hallazgos abiertos</div>
          {/* Contenedor relativo: la dona + el número del centro superpuesto. */}
          <div style={{ position: "relative", display: "flex", justifyContent: "center", margin: "8px 0 16px" }}>
            <ResponsiveContainer width={200} height={200}>
              <PieChart>
                {/* innerRadius > 0 convierte el círculo en dona (hueco al centro). */}
                <Pie data={severidades} dataKey="value" innerRadius={62} outerRadius={88} paddingAngle={2} stroke="none">
                  {/* Un Cell por cada severidad, para pintarlo con su color. */}
                  {severidades.map((s) => (
                    <Cell key={s.name} fill={s.color} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            {/* Número total en el centro de la dona (va encima, posición absoluta). */}
            <div style={{ position: "absolute", inset: 0, display: "grid", placeItems: "center", textAlign: "center" }}>
              <div>
                <div style={{ fontSize: "34px", fontWeight: 700, lineHeight: 1 }}>{totalSev}</div>
                <div style={{ fontSize: "12.5px", color: c.muted, marginTop: "4px" }}>Total</div>
              </div>
            </div>
          </div>
          {/* Lista de severidades debajo de la dona: color, nombre, cantidad y porcentaje. */}
          <div style={{ display: "grid", gap: "4px" }}>
            {severidades.map((s) => (
              <div key={s.name} style={{ display: "grid", gridTemplateColumns: "12px 1fr auto 44px", alignItems: "center", gap: "10px", fontSize: "13.5px", padding: "7px 8px", borderRadius: "8px" }}>
                <span style={{ width: "10px", height: "10px", borderRadius: "3px", background: s.color }} />
                <span>{s.name}</span>
                <span style={{ fontWeight: 600 }}>{s.value}</span>
                {/* Porcentaje = valor de esa severidad sobre el total. */}
                <span style={{ color: c.muted, textAlign: "right", fontSize: "12.5px" }}>{Math.round((s.value / totalSev) * 100)}%</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ───────── TABLA: actividad reciente ───────── */}
      <section style={card}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "20px 22px 16px" }}>
          <div>
            <div style={{ fontSize: "16px", fontWeight: 600 }}>Actividad reciente</div>
            <div style={{ fontSize: "13px", color: c.muted, marginTop: "3px" }}>Últimos escaneos completados</div>
          </div>
          <a href="#" style={{ color: c.primary, fontSize: "13.5px", fontWeight: 500, textDecoration: "none" }}>
            Ver todos los escaneos →
          </a>
        </div>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          {/* Encabezado de la tabla. */}
          <thead>
            <tr style={{ background: "#FAFAFB" }}>
              <th style={{ fontSize: "12px", fontWeight: 500, color: c.muted, textAlign: "left", padding: "11px 22px", borderTop: `1px solid ${c.border}`, borderBottom: `1px solid ${c.border}` }}>Sitio</th>
              <th style={{ fontSize: "12px", fontWeight: 500, color: c.muted, textAlign: "left", padding: "11px 22px", borderTop: `1px solid ${c.border}`, borderBottom: `1px solid ${c.border}` }}>Fecha</th>
              <th style={{ fontSize: "12px", fontWeight: 500, color: c.muted, textAlign: "left", padding: "11px 22px", borderTop: `1px solid ${c.border}`, borderBottom: `1px solid ${c.border}` }}>Vulnerabilidades</th>
              <th style={{ fontSize: "12px", fontWeight: 500, color: c.muted, textAlign: "left", padding: "11px 22px", borderTop: `1px solid ${c.border}`, borderBottom: `1px solid ${c.border}` }}>Nivel de riesgo</th>
            </tr>
          </thead>
          <tbody>
            {/* Recorremos "actividad" y dibujamos una fila por cada sitio. */}
            {actividad.map((row) => {
              // Buscamos el estilo de etiqueta según el riesgo de esta fila.
              const tag = riesgoTag[row.r];
              return (
                <tr key={row.d} style={{ borderBottom: "1px solid #F1F2F4" }}>
                  {/* Columna Sitio: cuadrito con inicial + nombre + url. */}
                  <td style={{ padding: "14px 22px", fontSize: "14px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                      <div style={{ width: "32px", height: "32px", borderRadius: "8px", border: `1px solid ${c.border}`, display: "grid", placeItems: "center", fontWeight: 600, fontSize: "13px", color: c.muted }}>
                        {row.d[0].toUpperCase()}
                      </div>
                      <div>
                        <div style={{ fontWeight: 500 }}>{row.d}</div>
                        <div style={{ fontSize: "12.5px", color: c.muted }}>{row.u}</div>
                      </div>
                    </div>
                  </td>
                  {/* Columna Fecha: fecha arriba, hora abajo en gris. */}
                  <td style={{ padding: "14px 22px", fontSize: "14px" }}>
                    {row.f}<div style={{ color: c.muted, fontSize: "12.5px" }}>{row.h} h</div>
                  </td>
                  {/* Columna Vulnerabilidades: número en negrita. */}
                  <td style={{ padding: "14px 22px", fontSize: "14px", fontWeight: 600 }}>{row.v}</td>
                  {/* Columna Riesgo: etiqueta de color según tag. */}
                  <td style={{ padding: "14px 22px", fontSize: "14px" }}>
                    <span style={{ fontSize: "12px", fontWeight: 600, padding: "3px 9px", borderRadius: "999px", background: tag.bg, color: tag.color }}>
                      {tag.label}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>

      {/* ───────── MODAL "NUEVO ESCANEO" ───────── */}
      {/* Solo se muestra si showNewScan es true (se abre con el botón del encabezado). */}
      {showNewScan && (
        // Capa oscura que cubre toda la pantalla (el fondo del modal).
        <div style={{ position: "fixed", inset: 0, background: "rgba(16,24,40,.45)", display: "flex", justifyContent: "center", alignItems: "center", zIndex: 1000 }}>
          {/* Caja blanca del modal. */}
          <div style={{ width: "460px", background: c.surface, border: `1px solid ${c.border}`, borderRadius: "14px", padding: "28px", boxShadow: "0 20px 50px rgba(16,24,40,.2)" }}>
            <h2 style={{ marginTop: 0, color: c.text }}>Nuevo escaneo</h2>
            <p style={{ color: c.muted, marginBottom: "20px" }}>Ingresa la URL del sitio web que deseas analizar.</p>
            {/* Campo de texto: su valor se guarda en scanUrl al escribir. */}
            <input
              type="url"
              placeholder="https://ejemplo.cl"
              value={scanUrl}
              onChange={(e) => setScanUrl(e.target.value)}
              style={{ width: "100%", padding: "12px", borderRadius: "8px", border: `1px solid ${c.border}`, background: c.background, color: c.text, outline: "none", marginBottom: "22px" }}
            />
            <div style={{ display: "flex", justifyContent: "flex-end", gap: "12px" }}>
              {/* Cancelar: cierra el modal y limpia el campo. */}
              <button
                onClick={() => { setShowNewScan(false); setScanUrl(""); }}
                style={{ background: "transparent", color: c.muted, border: `1px solid ${c.border}`, borderRadius: "8px", padding: "10px 16px", cursor: "pointer" }}
              >
                Cancelar
              </button>
              {/* Iniciar escaneo: por ahora no hace nada; aquí conectaremos el backend luego. */}
              <button style={{ background: c.primary, color: "#fff", border: "none", borderRadius: "8px", padding: "10px 18px", cursor: "pointer", fontWeight: 600 }}>
                Iniciar escaneo
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}

// Exportamos el componente para que el router/layout pueda mostrarlo.
export default Dashboard;

