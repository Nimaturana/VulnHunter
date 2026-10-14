import { secondaryButtonStyle } from "../../shared/styles/layout";
import Dashboard from "./DashboardPage";

type UserDashboardProps = {
  onBack: () => void;
};

function UserDashboard({ onBack }: UserDashboardProps) {
  return (
    <div
      style={{
        minHeight: "100vh",
        width: "100%",
        backgroundColor: "#07111F",
        color: "#F8FAFC",
        fontFamily: "Arial, sans-serif",
      }}
    >
      <div style={{ padding: "20px 32px 0" }}>
        <button onClick={onBack} style={secondaryButtonStyle}>
          ← Cerrar sesión de demostración
        </button>
        <p style={{ color: "#64748B", fontSize: 13 }}>
          La separación de datos por usuario se habilitará cuando el backend incorpore autenticación.
        </p>
      </div>
      <Dashboard />
    </div>
  );
}

export default UserDashboard;
