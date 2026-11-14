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
// Traemos la paleta central para usar los mismos colores que el Dashboard.
import { theme } from "../shared/styles/theme";

// Atajo para no escribir theme.colors cada vez.
const c = theme.colors;

function App() {
  const { t } = useLanguage();

  // screen: en qué pantalla general estamos (bienvenida, login o la app).
  const [screen, setScreen] = useState<Screen>("welcome");
  // userRole: con qué rol entró el usuario ("analyst" = admin, "user" = cliente).
  const [userRole, setUserRole] = useState<UserRole>(null);
  const [usuario, setUsuario] = useState<import("../shared/api/auth").Usuario | null>(null);
  // activePage: qué sección del menú admin está seleccionada.
  const [activePage, setActivePage] = useState<AdminPage>("dashboard");

  // ========================= PANTALLA DE BIENVENIDA =========================
  if (screen === "welcome") {
    return (
      <Welcome
        onStart={() => setScreen("login")}
        onLogin={() => setScreen("login")}
      />
    );
  }

  // ========================= PANTALLA DE LOGIN =========================
    // ========================= PANTALLA DE LOGIN =========================
  // En vez de mostrar solo el login, mostramos la BIENVENIDA de fondo
  // y el LOGIN flotando encima como modal (con su fondo difuminado).
  // Así se logra el efecto de "cuadradito al centro con la página atrás".
  if (screen === "login") {
    return (
      <>
        {/* Capa de fondo: la misma pantalla de bienvenida, quieta detrás. */}
        {/* Sus botones no hacen falta aquí, pero los dejamos conectados igual. */}
        <Welcome
          onStart={() => setScreen("login")}
          onLogin={() => setScreen("login")}
        />

        {/* Capa de encima: el login como modal (trae su propio scrim difuminado). */}
        <Login
          onBack={() => setScreen("welcome")}
          onLogin={(role, usuarioLogueado) => {
            setUserRole(role);        // guardamos el rol elegido
            setUsuario(usuarioLogueado); // guardamos el usuario completo (nombre, id, email)
            setScreen("app");         // pasamos a la aplicación
            if (role === "analyst") {
              setActivePage("dashboard"); // el admin arranca en el Dashboard
            }
          }}
        />
      </>
    );
  }



  // ========================= PANEL DEL USUARIO / CLIENTE =========================
  if (screen === "app" && userRole === "user") {
    return (
      <UserDashboard
        usuario={usuario}
        onBack={() => {
          setUserRole(null);
          setUsuario(null);
          setScreen("welcome");
        }}
      />
    );
  }

  // ========================= PANEL DEL ANALISTA / ADMIN =========================
  if (screen === "app" && userRole === "analyst") {
    return (
      // Contenedor general: fondo claro y disposición en fila (barra lateral + contenido).
      <div
        style={{
          minHeight: "100vh",
          backgroundColor: c.background, // fondo gris suave claro
          color: c.text,
          fontFamily: "'Inter', Arial, sans-serif",
          display: "flex",
        }}
      >
        {/* ───────── BARRA LATERAL (ahora blanca) ───────── */}
        <aside
          style={{
            width: "240px",
            minWidth: "240px",
            backgroundColor: c.surface,          // blanco
            borderRight: `1px solid ${c.border}`, // borde gris suave a la derecha
            padding: "28px 20px",
            display: "flex",
            flexDirection: "column",
          }}
        >
          {/* BOTÓN VOLVER: cierra sesión y vuelve a la bienvenida. */}
          <button
            onClick={() => {
              setUserRole(null);
              setScreen("welcome");
            }}
            style={{
              backgroundColor: "transparent",
              border: "none",
              color: c.muted,
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

          {/* LOGO: imagen + nombre VulnHunter. */}
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
              style={{ width: "58px", height: "58px", objectFit: "contain" }}
            />
            <span style={{ fontSize: "21px", fontWeight: "bold", color: c.text }}>
              VulnHunter
            </span>
          </div>

          {/* MENÚ ADMIN: recorre las opciones y marca la activa en azul. */}
          <nav style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            {ADMIN_NAVIGATION.map((item) => (
              <button
                key={item.id}
                onClick={() => setActivePage(item.id)} // cambia la sección activa
                style={activePage === item.id ? activeMenuStyle : menuStyle}
              >
                {item.icon} {t(item.labelKey)}
              </button>
            ))}
          </nav>
        </aside>

        {/* CONTENIDO: muestra la sección activa (Dashboard, Sitios, Escaneos, etc.). */}
        <AdminRouter activePage={activePage} />
      </div>
    );
  }

  return null;
}

// Estilo de cada opción del menú cuando NO está activa (texto gris, sin fondo).
const menuStyle = {
  backgroundColor: "transparent",
  border: "1px solid transparent",
  color: theme.colors.muted,
  padding: "11px 14px",
  borderRadius: "8px",
  textAlign: "left" as const,
  cursor: "pointer",
  fontSize: "14px",
  fontWeight: 500,
  width: "100%",
};

// Estilo de la opción ACTIVA: fondo azul clarito y texto azul (igual que el diseño).
const activeMenuStyle = {
  ...menuStyle,
  backgroundColor: "#EFF4FF",
  color: theme.colors.primary,
  border: "1px solid transparent",
};

export default App;
