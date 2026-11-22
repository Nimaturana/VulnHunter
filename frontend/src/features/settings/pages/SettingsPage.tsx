import { useLanguage } from "../../../i18n/language";
import { useState } from "react";
// Paleta central para mantener los mismos colores que el resto del panel.
import { theme } from "../../../shared/styles/theme";

const c = theme.colors;

function Settings() {
  // useLanguage: nos da el idioma actual, la función para cambiarlo, y t() para traducir textos.
  const { language, setLanguage, t } = useLanguage();
  // Estado del tema (visual por ahora). Por defecto "claro", igual que la página.
  // El modo oscuro real se implementará más adelante en todas las pantallas.
  const [darkMode, setDarkMode] = useState(false);

  return (
    <main style={{ flex: 1, padding: "36px 44px 48px", background: c.background, color: c.text }}>
      {/* ───────── ENCABEZADO ───────── */}
      <header style={{ marginBottom: "28px" }}>
        <h1 style={{ margin: 0, fontSize: "30px", fontWeight: 700, letterSpacing: "-0.02em" }}>
          {t("settings.title")}
        </h1>
        <p style={{ color: c.muted, fontSize: "15px", margin: "6px 0 0" }}>
          {t("settings.description")}
        </p>
      </header>

      {/* ───────── SECCIÓN GENERAL ───────── */}
      <section style={{ ...cardStyle, marginBottom: "20px" }}>
        <h3 style={{ marginTop: 0, fontSize: "16px", fontWeight: 600 }}>{t("settings.general")}</h3>

        {/* Fila: Idioma + selector. */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "22px" }}>
          <div>
            <strong style={{ fontSize: "14px", fontWeight: 500 }}>{t("settings.language")}</strong>
            <p style={{ margin: "4px 0 0", color: c.muted, fontSize: "13px" }}>Español / English</p>
          </div>
          {/* Selector de idioma: al cambiar, actualiza el idioma de toda la app. */}
          <select
            value={language}
            onChange={(e) => setLanguage(e.target.value as "es" | "en")}
            style={{
              backgroundColor: "#fff",
              color: c.text,
              border: `1px solid ${c.border}`,
              borderRadius: "9px",
              padding: "9px 14px",
              fontSize: "13.5px",
              fontWeight: 500,
              cursor: "pointer",
            }}
          >
            <option value="es">🇨🇱 Español</option>
            <option value="en">🇬🇧 English</option>
          </select>
        </div>

        {/* Fila: Tema con interruptor Claro / Oscuro. */}
        <div style={{ borderTop: `1px solid ${c.border}`, marginTop: "22px", paddingTop: "22px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <strong style={{ fontSize: "14px", fontWeight: 500 }}>{t("settings.theme")}</strong>
            {/* Muestra el estado actual al lado del título */}
            <p style={{ margin: "4px 0 0", color: c.muted, fontSize: "13px" }}>
              {darkMode ? "🌙 Oscuro" : "☀️ Claro"}
            </p>
          </div>

          {/* Interruptor (toggle). Al hacer clic alterna el estado darkMode. */}
          <button
            onClick={() => setDarkMode(!darkMode)}
            aria-label="Cambiar tema"
            style={{
              width: "52px",
              height: "28px",
              borderRadius: "999px",
              border: "none",
              cursor: "pointer",
              // Azul cuando está en oscuro, gris cuando está en claro.
              backgroundColor: darkMode ? c.primary : c.border,
              position: "relative",
              transition: "background-color .2s",
            }}
          >
            {/* Bolita blanca que se desliza de izquierda a derecha */}
            <span
              style={{
                position: "absolute",
                top: "3px",
                left: darkMode ? "27px" : "3px",
                width: "22px",
                height: "22px",
                borderRadius: "50%",
                backgroundColor: "#fff",
                boxShadow: "0 1px 3px rgba(0,0,0,.2)",
                transition: "left .2s",
              }}
            />
          </button>
        </div>
      </section>
      
      {/* ───────── SECCIÓN ESCANEOS ───────── */}
      <section style={{ ...cardStyle, marginBottom: "20px" }}>
        <h3 style={{ marginTop: 0, fontSize: "16px", fontWeight: 600 }}>{t("settings.scans")}</h3>
        <p style={{ color: c.muted, fontSize: "13px", marginTop: "4px" }}>{t("settings.scanDescription")}</p>

        {/* Lista de módulos de escaneo, cada uno con su casilla marcada por defecto. */}
        {[
          t("settings.ssl"),
          t("settings.xss"),
          t("settings.sqli"),
          t("settings.headers"),
          t("settings.directories"),
        ].map((scanner) => (
          <label key={scanner} style={{ display: "flex", alignItems: "center", gap: "10px", marginTop: "14px", cursor: "pointer", fontSize: "14px" }}>
            <input type="checkbox" defaultChecked />
            {scanner}
          </label>
        ))}
      </section>

      {/* ───────── SECCIÓN REPORTES ───────── */}
      <section style={{ ...cardStyle, marginBottom: "20px" }}>
        <h3 style={{ marginTop: 0, fontSize: "16px", fontWeight: 600 }}>{t("settings.reports")}</h3>

        {/* Opciones de contenido del reporte. */}
        {[
          t("settings.evidence"),
          t("settings.recommendations"),
          t("settings.risk"),
        ].map((option) => (
          <label key={option} style={{ display: "flex", alignItems: "center", gap: "10px", marginTop: "14px", cursor: "pointer", fontSize: "14px" }}>
            <input type="checkbox" defaultChecked />
            {option}
          </label>
        ))}
      </section>

      {/* ───────── SECCIÓN ACERCA DE ───────── */}
      <section style={cardStyle}>
        <h3 style={{ marginTop: 0, fontSize: "16px", fontWeight: 600 }}>{t("settings.about")}</h3>
        <p style={{ color: c.muted, marginBottom: 0, fontSize: "14px" }}>
          VulnHunter · {t("settings.version")} 2.0.0
        </p>
      </section>
    </main>
  );
}

// Estilo base de las tarjetas blancas (igual que en el resto del panel).
const cardStyle: React.CSSProperties = {
  backgroundColor: c.surface,
  border: `1px solid ${c.border}`,
  borderRadius: "14px",
  padding: "22px",
  boxShadow: "0 1px 2px rgba(16,24,40,.04), 0 4px 16px rgba(16,24,40,.04)",
};

export default Settings;

