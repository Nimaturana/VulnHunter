import { useState } from "react";

type LoginProps = {
  onBack: () => void;
  onLogin: (role: "analyst" | "user") => void;
};

function Login({ onBack, onLogin }: LoginProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const handleLogin = () => {
    /*
      LOGIN TEMPORAL.

      Si el correo contiene "analista",
      entra como analista/admin.

      Cualquier otro correo entra como usuario.

      Más adelante esto se reemplaza por
      autenticación real desde el backend.
    */

    if (email.toLowerCase().includes("analista")) {
      onLogin("analyst");
      return;
    }

    onLogin("user");
  };

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
      }}
    >
      <div
        style={{
          width: "100%",
          maxWidth: "430px",
          backgroundColor: "#0F1B2D",
          border: "1px solid #1B2B40",
          borderRadius: "16px",
          padding: "32px",
          boxShadow: "0 20px 50px rgba(0, 0, 0, 0.35)",
        }}
      >
        <button
          onClick={onBack}
          style={{
            backgroundColor: "transparent",
            border: "none",
            color: "#94AFC7",
            cursor: "pointer",
            padding: 0,
            marginBottom: "25px",
            fontSize: "14px",
          }}
        >
          ← Volver
        </button>

        <h1
          style={{
            margin: "0 0 8px",
            fontSize: "30px",
          }}
        >
          Iniciar sesión
        </h1>

        <p
          style={{
            margin: "0 0 28px",
            color: "#94AFC7",
            lineHeight: "1.6",
          }}
        >
          Accede a VulnHunter para consultar tus análisis, hallazgos y
          reportes de seguridad.
        </p>

        <label
          style={{
            display: "block",
            marginBottom: "8px",
            fontSize: "14px",
          }}
        >
          Correo electrónico
        </label>

        <input
          type="email"
          placeholder="usuario@empresa.cl"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          style={{
            width: "100%",
            padding: "12px",
            borderRadius: "8px",
            border: "1px solid #334155",
            backgroundColor: "#07111F",
            color: "#F8FAFC",
            outline: "none",
            marginBottom: "20px",
          }}
        />

        <label
          style={{
            display: "block",
            marginBottom: "8px",
            fontSize: "14px",
          }}
        >
          Contraseña
        </label>

        <input
          type="password"
          placeholder="••••••••"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={{
            width: "100%",
            padding: "12px",
            borderRadius: "8px",
            border: "1px solid #334155",
            backgroundColor: "#07111F",
            color: "#F8FAFC",
            outline: "none",
            marginBottom: "25px",
          }}
        />

        <button
          onClick={handleLogin}
          disabled={!email || !password}
          style={{
            width: "100%",
            backgroundColor:
              email && password ? "#1677FF" : "#334155",
            color: "#FFFFFF",
            border: "1px solid #29C7F6",
            borderRadius: "8px",
            padding: "12px",
            cursor:
              email && password ? "pointer" : "not-allowed",
            fontWeight: "bold",
          }}
        >
          Iniciar sesión
        </button>

        <div
          style={{
            marginTop: "25px",
            padding: "14px",
            backgroundColor: "#07111F",
            border: "1px solid #1B2B40",
            borderRadius: "8px",
          }}
        >
          <p
            style={{
              margin: 0,
              color: "#64748B",
              fontSize: "12px",
              lineHeight: "1.6",
            }}
          >
            Acceso temporal para desarrollo. La autenticación real se
            implementará posteriormente mediante el backend de VulnHunter.
          </p>
        </div>
      </div>
    </main>
  );
}

export default Login;