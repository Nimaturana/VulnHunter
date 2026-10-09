import logo from "../../../assets/vulnhunter-logo.png";

type WelcomeProps = {
  onStart: () => void;
  onLogin: () => void;
};

function Welcome({ onStart, onLogin }: WelcomeProps) {
  return (
    <main
      style={{
        minHeight: "100vh",
        width: "100%",
        backgroundColor: "#07111F",
        color: "#F8FAFC",
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        fontFamily: "Arial, sans-serif",
        padding: "40px",
        position: "relative",
      }}
    >
      {/* INICIAR SESIÓN */}
      <button
        onClick={onLogin}
        style={{
          position: "absolute",
          top: "28px",
          right: "32px",
          backgroundColor: "transparent",
          color: "#D7E6F3",
          border: "1px solid #29C7F6",
          borderRadius: "8px",
          padding: "10px 16px",
          cursor: "pointer",
          fontWeight: "bold",
          fontSize: "14px",
        }}
      >
        Iniciar sesión
      </button>

      <div
        style={{
          width: "100%",
          maxWidth: "760px",
          textAlign: "center",
        }}
      >
        <img
          src={logo}
          alt="VulnHunter"
          style={{
            width: "120px",
            height: "120px",
            objectFit: "contain",
            marginBottom: "12px",
          }}
        />

        <h1
          style={{
            fontSize: "48px",
            margin: "0 0 12px",
          }}
        >
          VulnHunter
        </h1>

        <h2
          style={{
            color: "#29C7F6",
            fontSize: "22px",
            fontWeight: "normal",
            marginBottom: "25px",
          }}
        >
          Análisis de seguridad web
        </h2>

        <p
          style={{
            color: "#94AFC7",
            fontSize: "17px",
            lineHeight: "1.7",
            maxWidth: "620px",
            margin: "0 auto 35px",
          }}
        >
          Detecta vulnerabilidades, evalúa riesgos y genera reportes de
          seguridad para sitios web autorizados.
        </p>

        <button
          onClick={onStart}
          style={{
            backgroundColor: "#1677FF",
            color: "#FFFFFF",
            border: "1px solid #29C7F6",
            borderRadius: "10px",
            padding: "14px 28px",
            fontSize: "16px",
            fontWeight: "bold",
            cursor: "pointer",
            marginBottom: "45px",
          }}
        >
          Comenzar análisis →
        </button>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(3, 1fr)",
            gap: "15px",
          }}
        >
          {[
            "🔍 Análisis de vulnerabilidades",
            "⚠️ Clasificación de riesgos",
            "📄 Reportes de seguridad",
          ].map((feature) => (
            <div
              key={feature}
              style={{
                backgroundColor: "#0F1B2D",
                border: "1px solid #1B2B40",
                borderRadius: "12px",
                padding: "18px",
                color: "#D7E6F3",
                fontSize: "14px",
              }}
            >
              {feature}
            </div>
          ))}
        </div>
      </div>
    </main>
  );
}

export default Welcome;
