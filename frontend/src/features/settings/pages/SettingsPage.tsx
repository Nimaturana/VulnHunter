import { useLanguage } from "../../../i18n/language";

function Settings() {
  const { language, setLanguage, t } = useLanguage();

  return (
    <main
      style={{
        flex: 1,
        padding: "32px",
      }}
    >
      <header
        style={{
          marginBottom: "35px",
        }}
      >
        <h1
          style={{
            margin: 0,
            fontSize: "30px",
          }}
        >
          {t("settings.title")}
        </h1>

        <p
          style={{
            color: "#94AFC7",
            marginTop: "8px",
          }}
        >
          {t("settings.description")}
        </p>
      </header>

      {/* GENERAL */}
      <section style={cardStyle}>
        <h3 style={{ marginTop: 0 }}>
          {t("settings.general")}
        </h3>

        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginTop: "25px",
          }}
        >
          <div>
            <strong>{t("settings.language")}</strong>

            <p
              style={{
                margin: "6px 0 0",
                color: "#94AFC7",
                fontSize: "14px",
              }}
            >
              Español / English
            </p>
          </div>

          <select
            value={language}
            onChange={(e) =>
              setLanguage(e.target.value as "es" | "en")
            }
            style={{
              backgroundColor: "#07111F",
              color: "#F8FAFC",
              border: "1px solid #334155",
              borderRadius: "8px",
              padding: "10px 14px",
              cursor: "pointer",
            }}
          >
            <option value="es">🇨🇱 Español</option>
            <option value="en">🇬🇧 English</option>
          </select>
        </div>

        <div
          style={{
            borderTop: "1px solid #1B2B40",
            marginTop: "25px",
            paddingTop: "25px",
            display: "flex",
            justifyContent: "space-between",
          }}
        >
          <strong>{t("settings.theme")}</strong>

          <span
            style={{
              color: "#94AFC7",
            }}
          >
            🌙 {t("settings.dark")}
          </span>
        </div>
      </section>

      {/* ESCANEOS */}
      <section
        style={{
          ...cardStyle,
          marginTop: "20px",
        }}
      >
        <h3 style={{ marginTop: 0 }}>
          {t("settings.scans")}
        </h3>

        <p
          style={{
            color: "#94AFC7",
            fontSize: "14px",
          }}
        >
          {t("settings.scanDescription")}
        </p>

        {[
          t("settings.ssl"),
          t("settings.xss"),
          t("settings.sqli"),
          t("settings.headers"),
          t("settings.directories"),
        ].map((scanner) => (
          <label
            key={scanner}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "10px",
              marginTop: "15px",
              cursor: "pointer",
            }}
          >
            <input type="checkbox" defaultChecked />

            {scanner}
          </label>
        ))}
      </section>

      {/* REPORTES */}
      <section
        style={{
          ...cardStyle,
          marginTop: "20px",
        }}
      >
        <h3 style={{ marginTop: 0 }}>
          {t("settings.reports")}
        </h3>

        {[
          t("settings.evidence"),
          t("settings.recommendations"),
          t("settings.risk"),
        ].map((option) => (
          <label
            key={option}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "10px",
              marginTop: "15px",
              cursor: "pointer",
            }}
          >
            <input type="checkbox" defaultChecked />

            {option}
          </label>
        ))}
      </section>

      {/* ACERCA DE */}
      <section
        style={{
          ...cardStyle,
          marginTop: "20px",
        }}
      >
        <h3 style={{ marginTop: 0 }}>
          {t("settings.about")}
        </h3>

        <p
          style={{
            color: "#94AFC7",
            marginBottom: 0,
          }}
        >
          VulnHunter · {t("settings.version")} 2.0.0
        </p>
      </section>
    </main>
  );
}

const cardStyle = {
  backgroundColor: "#0F1B2D",
  border: "1px solid #1B2B40",
  borderRadius: "12px",
  padding: "22px",
};

export default Settings;
