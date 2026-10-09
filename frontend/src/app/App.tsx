import { useState } from "react";
import logo from "../assets/vulnhunter-logo.png";

import Login from "../features/auth/pages/LoginPage";
import Welcome from "../features/auth/pages/WelcomePage";
import { useLanguage } from "../i18n/language";
import type {
  AdminPage,
  Screen,
  UserRole,
} from "../shared/types/navigation";
import UserDashboard from "./pages/UserDashboardPage";
import {
  ADMIN_NAVIGATION,
  AdminRouter,
} from "./router";

function App() {
  const { t } = useLanguage();

  const [screen, setScreen] = useState<Screen>("welcome");
  const [userRole, setUserRole] = useState<UserRole>(null);

  const [activePage, setActivePage] =
    useState<AdminPage>("dashboard");

  // =========================
  // BIENVENIDA
  // =========================

  if (screen === "welcome") {
    return (
      <Welcome
        onStart={() => setScreen("login")}
        onLogin={() => setScreen("login")}
      />
    );
  }

  // =========================
  // LOGIN
  // =========================

  if (screen === "login") {
    return (
      <Login
        onBack={() => setScreen("welcome")}
        onLogin={(role) => {
          setUserRole(role);
          setScreen("app");

          if (role === "analyst") {
            setActivePage("dashboard");
          }
        }}
      />
    );
  }

  // =========================
  // PANEL USUARIO / CLIENTE
  // =========================

  if (screen === "app" && userRole === "user") {
    return (
      <UserDashboard
        onBack={() => {
          setUserRole(null);
          setScreen("welcome");
        }}
      />
    );
  }

  // =========================
  // PANEL ANALISTA / ADMIN
  // =========================

  if (screen === "app" && userRole === "analyst") {
    return (
      <div
        style={{
          minHeight: "100vh",
          backgroundColor: "#0B1626",
          color: "#f8fafc",
          fontFamily: "Arial, sans-serif",
          display: "flex",
        }}
      >
        {/* SIDEBAR */}
        <aside
          style={{
            width: "240px",
            minWidth: "240px",
            backgroundColor: "#0B1626",
            borderRight: "1px solid #1B2B40",
            padding: "28px 20px",
          }}
        >
          {/* VOLVER */}
          <button
            onClick={() => {
              setUserRole(null);
              setScreen("welcome");
            }}
            style={{
              backgroundColor: "transparent",
              border: "none",
              color: "#94AFC7",
              cursor: "pointer",
              fontSize: "14px",
              padding: "0",
              marginBottom: "22px",
              display: "flex",
              alignItems: "center",
              gap: "8px",
            }}
          >
            ← {t("menu.back")}
          </button>

          {/* LOGO */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "12px",
              marginBottom: "35px",
              paddingLeft: "4px",
            }}
          >
            <img
              src={logo}
              alt="VulnHunter"
              style={{
                width: "58px",
                height: "58px",
                objectFit: "contain",
              }}
            />

            <span
              style={{
                fontSize: "21px",
                fontWeight: "bold",
                color: "#f8fafc",
              }}
            >
              VulnHunter
            </span>
          </div>

          {/* MENÚ ADMIN */}
          <nav
            style={{
              display: "flex",
              flexDirection: "column",
              gap: "12px",
            }}
          >
            {ADMIN_NAVIGATION.map((item) => (
              <button
                key={item.id}
                onClick={() =>
                  setActivePage(item.id)
                }
                style={
                  activePage === item.id
                    ? activeMenuStyle
                    : menuStyle
                }
              >
                {item.icon} {t(item.labelKey)}
              </button>
            ))}
          </nav>
        </aside>

        <AdminRouter activePage={activePage} />
      </div>
    );
  }

  return null;
}

const menuStyle = {
  backgroundColor: "transparent",
  border: "1px solid transparent",
  color: "#94AFC7",
  padding: "12px 14px",
  borderRadius: "10px",
  textAlign: "left" as const,
  cursor: "pointer",
  fontSize: "15px",
  width: "100%",
};

const activeMenuStyle = {
  ...menuStyle,
  backgroundColor: "#123B66",
  color: "#F8FAFC",
  border: "1px solid #29C7F6",
};

export default App;
