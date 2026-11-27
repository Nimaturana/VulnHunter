import { useState } from "react";
// Paleta central del proyecto: mismos colores que el resto del panel claro.
import { theme } from "../../../shared/styles/theme";
// Iconos de la librería lucide-react (ojo abierto / ojo tachado).
import { Eye, EyeOff } from "lucide-react";
// Funciones que hablan con el backend de autenticación.
import { registrarUsuario, iniciarSesion, iniciarSesionGoogle, iniciarSesionInvitado, ApiError, type Usuario } from "../../../shared/api/auth";
import GoogleSignInButton from "../components/GoogleSignInButton";


// Atajo para no escribir "theme.colors" en cada línea.
const c = theme.colors;

// Props que recibe desde App.tsx:
// - onBack: cierra el login y vuelve a la bienvenida.
// - onLogin: decide el rol (analyst o user) y entra al panel.
type LoginProps = {
  onBack: () => void;
  onLogin: (role: "analyst" | "user" | "guest", usuario: Usuario) => void;
};


// Sub-vistas internas de esta pantalla.
// "start"    = elección de método (Google/Microsoft/correo)
// "email"    = login con correo y contraseña
// "register" = formulario de creación de cuenta
// "success"  = pantalla de "Cuenta creada" (paso final del registro)
type View = "start" | "email" | "register" | "success";


// ============================================================
// FUNCIONES DE VALIDACIÓN (ayudantes, van fuera del componente)
// ============================================================

// --- Limpia el RUT: deja solo números y la letra K en mayúscula ---
// Ej: "12.345.678-9" -> "123456789"
function limpiarRut(valor: string): string {
  return valor.replace(/[^0-9kK]/g, "").toUpperCase();
}

// --- Da formato bonito al RUT mientras se escribe ---
// Ej: "123456789" -> "12.345.678-9"
function formatearRut(valor: string): string {
  const limpio = limpiarRut(valor);
  if (limpio.length < 2) return limpio; // muy corto todavía
  const cuerpo = limpio.slice(0, -1);   // todos los dígitos menos el último
  const dv = limpio.slice(-1);          // el dígito verificador (último carácter)
  // Inserta los puntos cada 3 dígitos de derecha a izquierda, y agrega el "-dv".
  return cuerpo.replace(/\B(?=(\d{3})+(?!\d))/g, ".") + "-" + dv;
}

// --- Valida que el RUT sea real usando el dígito verificador ---
// Devuelve true si el dígito escrito coincide con el calculado.
function rutValido(valor: string): boolean {
  const limpio = limpiarRut(valor);
  if (limpio.length < 8) return false;       // demasiado corto para ser un RUT
  const cuerpo = limpio.slice(0, -1);        // números del RUT
  const dv = limpio.slice(-1);               // dígito verificador escrito
  if (!/^\d+$/.test(cuerpo)) return false;   // el cuerpo deben ser solo números

  // Fórmula del dígito verificador chileno (algoritmo módulo 11):
  // se recorren los dígitos de derecha a izquierda multiplicando por 2,3,4,5,6,7
  // y se vuelve a 2 cuando pasa de 7.
  let suma = 0;
  let multiplicador = 2;
  for (let i = cuerpo.length - 1; i >= 0; i--) {
    suma += Number(cuerpo[i]) * multiplicador;
    multiplicador = multiplicador === 7 ? 2 : multiplicador + 1;
  }
  const resto = 11 - (suma % 11);
  // El resultado se traduce: 11 -> "0", 10 -> "K", y el resto queda igual.
  const dvEsperado = resto === 11 ? "0" : resto === 10 ? "K" : String(resto);

  return dvEsperado === dv; // ¿coincide lo escrito con lo calculado?
}

// --- Da formato al teléfono: solo números, agrupados "9 1234 5678" ---
function formatearTelefono(valor: string): string {
  const soloNumeros = valor.replace(/\D/g, "").slice(0, 9); // máx 9 dígitos
  return soloNumeros.replace(/^(\d)(\d{0,4})(\d{0,4}).*/, (_m, a, b, c) =>
    [a, b, c].filter(Boolean).join(" ")
  );
}

// --- Calcula la "fuerza" de una contraseña: devuelve un puntaje de 0 a 4 ---
// Suma 1 punto por cada criterio que cumple.
function fuerzaPassword(pass: string): number {
  if (!pass) return 0;                                   // vacía = 0
  let puntos = 0;
  if (pass.length >= 8) puntos++;                        // al menos 8 caracteres
  if (/[A-Z]/.test(pass) && /[a-z]/.test(pass)) puntos++; // mayúsculas Y minúsculas
  if (/\d/.test(pass)) puntos++;                         // al menos un número
  if (/[^A-Za-z0-9]/.test(pass)) puntos++;              // al menos un símbolo
  return Math.max(1, puntos);                            // mínimo 1 si escribió algo
}


function Login({ onBack, onLogin }: LoginProps) {
  // view: controla qué sub-vista se muestra.
  const [view, setView] = useState<View>("start");

  // Estados del formulario de correo.
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  // Mensaje de error del login (ej: "correo o contraseña incorrectos").
  const [loginError, setLoginError] = useState("");
  const [guestLoading, setGuestLoading] = useState(false);


  // ---- Estados del formulario de REGISTRO ----
  // Cada campo del formulario de "Crear cuenta" guarda lo que el usuario escribe.
  const [regNombre, setRegNombre] = useState("");
  const [regApellido, setRegApellido] = useState("");
  const [regEmail, setRegEmail] = useState("");
  const [regPassword, setRegPassword] = useState("");
  const [regPassword2, setRegPassword2] = useState(""); // confirmar contraseña
  const [regTelefono, setRegTelefono] = useState("");
  const [regRut, setRegRut] = useState("");
  // Guarda mensajes de error de validación por campo (ej: "RUT inválido").
  const [regError, setRegError] = useState("");
  // Controla si la contraseña del registro se muestra (texto) u oculta (puntitos).
  const [verPassword, setVerPassword] = useState(false);


  // ---- LÓGICA DE LOGIN (conectado al backend) ----
  // Envía correo y contraseña a /auth/login. Si son correctos, el backend
  // devuelve el usuario con su role ("admin" o "user") y entramos al panel.
  const handleLogin = async () => {
    // Validación mínima: que no estén vacíos.
    if (!email.trim() || !password) {
      setLoginError("Ingresa tu correo y contraseña.");
      return;
    }

    setLoginError(""); // limpiamos errores anteriores

    try {
      // Llamamos al backend (POST /auth/login).
      const usuario = await iniciarSesion(email.trim(), password);

      // El backend nos dice el role. Lo traducimos al que espera el panel:
      // "admin" -> "analyst" (panel de administrador)
      // "user"  -> "user"    (panel de cliente)
      if (usuario.role === "admin" || usuario.role === "auditor") {
        onLogin("analyst", usuario);
      } else {
        onLogin("user", usuario);
      }

    } catch (error) {
      // 401 = correo o contraseña incorrectos.
      if (error instanceof ApiError && error.status === 401) {
        setLoginError("Correo o contraseña incorrectos.");
      } else {
        // Error de conexión (backend apagado, CORS, sin internet, etc.).
        setLoginError("No se pudo conectar con el servidor. Revisa tu conexión.");
      }
    }
  };

  const completarLogin = (usuario: Usuario) => {
    if (usuario.role === "guest") {
      onLogin("guest", usuario);
      return;
    }
    onLogin(usuario.role === "admin" || usuario.role === "auditor" ? "analyst" : "user", usuario);
  };

  const handleGuestLogin = async () => {
    setLoginError("");
    setGuestLoading(true);
    try {
      completarLogin(await iniciarSesionInvitado());
    } catch (error) {
      if (error instanceof ApiError && error.status === 404) {
        setLoginError("La demostración para invitados no está habilitada.");
      } else {
        setLoginError("No fue posible abrir la demostración. Intenta nuevamente.");
      }
    } finally {
      setGuestLoading(false);
    }
  };

  const handleGoogleCredential = async (credential: string) => {
    setLoginError("");
    try {
      completarLogin(await iniciarSesionGoogle(credential));
    } catch (error) {
      if (error instanceof ApiError) {
        setLoginError(error.message);
      } else {
        setLoginError("No fue posible iniciar sesión con Google.");
      }
    }
  };

  // ---- Validar y crear cuenta (conectado al backend) ----
  // Revisa todos los campos; si algo falla, muestra un error y no avanza.
  // Si todo está bien, envía los datos al backend y guarda el usuario en la base.
  const handleRegistro = async () => {
    // Validación simple de correo (que tenga algo@algo.algo).
    const emailValido = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(regEmail.trim());

    if (!regNombre.trim() || !regApellido.trim()) {
      setRegError("Ingresa tu nombre y apellido.");
      return;
    }
    if (!emailValido) {
      setRegError("Ingresa un correo electrónico válido.");
      return;
    }
    if (regPassword.length < 8) {
      setRegError("La contraseña debe tener al menos 8 caracteres.");
      return;
    }
    if (regPassword !== regPassword2) {
      setRegError("Las contraseñas no coinciden.");
      return;
    }
    // El RUT de empresa es opcional: solo lo validamos si el usuario escribió algo.
    if (regRut.trim() && !rutValido(regRut)) {
      setRegError("El RUT de empresa no es válido. Revisa el número y el dígito verificador.");
      return;
    }

    // Si todas las validaciones pasaron, limpiamos el error y enviamos al backend.
    setRegError("");

    try {
      // Enviamos los datos al backend (POST /auth/register).
      // Solo mandamos rut/telefono/fecha si el usuario los escribió.
      await registrarUsuario({
        email: regEmail.trim(),
        password: regPassword,
        nombre: regNombre.trim(),
        apellido: regApellido.trim(),
        rut: regRut.trim() || undefined,
        telefono: regTelefono.trim() || undefined,
      });


      // Si el backend respondió bien, mostramos la pantalla de "Cuenta creada".
      setView("success");
    } catch (error) {
      // Si el backend devuelve un error controlado (ej: correo o RUT repetido).
      if (error instanceof ApiError) {
        if (error.status === 409) {
          setRegError("Este correo o RUT ya está registrado.");
        } else {
          setRegError("No se pudo crear la cuenta. Intenta de nuevo.");
        }
      } else {
        // Error de conexión (backend apagado, sin internet, CORS, etc.).
        setRegError("No se pudo conectar con el servidor. Revisa tu conexión.");
      }
    }
  };


  // ===== ESTILOS REUTILIZABLES =====
  // Tarjeta blanca central (el modal).
  const card: React.CSSProperties = {
    position: "relative",
    width: "100%",
    maxWidth: "560px",
    backgroundColor: c.surface,
    border: `1px solid ${c.border}`,
    borderRadius: "16px",
    boxShadow: "0 1px 2px rgba(16,24,40,.06), 0 24px 60px rgba(16,24,40,.18)",
    padding: "36px",
  };

  // Botón de proveedor (Google, Microsoft, correo).
  const btnProvider: React.CSSProperties = {
    height: "46px",
    width: "100%",
    border: `1px solid ${c.border}`,
    borderRadius: "10px",
    backgroundColor: c.surface,
    color: c.text,
    fontSize: "14.5px",
    fontWeight: 500,
    cursor: "pointer",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    gap: "11px",
  };

  // Botón principal azul.
  const btnPrimary: React.CSSProperties = {
    height: "46px",
    width: "100%",
    border: "none",
    borderRadius: "10px",
    backgroundColor: c.primary,
    color: "#FFFFFF",
    fontSize: "14.5px",
    fontWeight: 600,
    cursor: "pointer",
  };

  // Campo de texto.
  const input: React.CSSProperties = {
    width: "100%",
    height: "46px",
    border: `1px solid ${c.border}`,
    borderRadius: "10px",
    padding: "0 14px",
    fontSize: "14.5px",
    color: c.text,
    backgroundColor: c.surface,
    marginTop: "7px",
  };

  // Estilo para los títulos de sección del formulario (texto gris en mayúsculas).
  // Ej: "DATOS PERSONALES", "ACCESO", "INFORMACIÓN DE CONTACTO".
  const sectionLabel: React.CSSProperties = {
    fontSize: "11.5px",
    fontWeight: 600,
    letterSpacing: "0.06em",      // separa un poco las letras
    textTransform: "uppercase",   // convierte el texto a MAYÚSCULAS
    color: c.muted,               // gris suave del tema
    marginTop: "22px",
    marginBottom: "4px",
    display: "block",
  };

  // Niveles de fuerza de contraseña: para cada puntaje, su etiqueta y color.
  // El índice coincide con el puntaje que devuelve fuerzaPassword (0 a 4).
  const nivelesPass = [
    { label: "", color: c.border },                 // 0: nada escrito
    { label: "Débil", color: c.severity.critical }, // 1: rojo
    { label: "Aceptable", color: c.severity.high },  // 2: naranja
    { label: "Buena", color: c.severity.medium },    // 3: amarillo
    { label: "Fuerte", color: c.severity.low },      // 4: verde
  ];
  // Calculamos la fuerza actual de la contraseña del registro.
  const fuerzaActual = fuerzaPassword(regPassword);


  return (
    // SCRIM: capa oscura semitransparente con desenfoque que cubre toda la
    // pantalla. Deja ver la bienvenida de fondo, pero opacada. Al hacer clic
    // en el fondo (fuera de la tarjeta) se cierra y vuelve a la bienvenida.
    <div
      className="login-scrim"
      onClick={onBack}
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 50,
        backgroundColor: "rgba(17,24,39,.36)",
        backdropFilter: "blur(3px)",
        display: "flex",
        justifyContent: "center",
        alignItems: "flex-start",
        overflowY: "auto",
        padding: "48px 24px",
        fontFamily: "Inter, Arial, sans-serif",
      }}
    >
      {/* stopPropagation: evita que un clic DENTRO de la tarjeta cierre el modal. */}
      <div className="login-card" style={card} onClick={(e) => e.stopPropagation()}>
        {/* Botón de cerrar (X) arriba a la derecha: vuelve a la bienvenida. */}
        <button
          onClick={onBack}
          aria-label="Cerrar"
          style={{
            position: "absolute",
            top: "14px",
            right: "14px",
            width: "34px",
            height: "34px",
            borderRadius: "9px",
            border: "none",
            background: "none",
            color: c.muted,
            cursor: "pointer",
            fontSize: "18px",
          }}
        >
          ✕
        </button>

        {/* LOGO / MARCA centrado. */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "10px",
            marginBottom: "22px",
            marginTop: "6px",
          }}
        >
          <div
            style={{
              width: "44px",
              height: "44px",
              borderRadius: "12px",
              backgroundColor: c.primary,
              color: "#FFFFFF",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              fontWeight: "bold",
              fontSize: "22px",
            }}
          >
            V
          </div>
          <span style={{ fontSize: "20px", fontWeight: 700 }}>VulnHunter</span>
        </div>

        {/* ===================================================== */}
        {/* SUB-VISTA "start": elección de método de acceso       */}
        {/* ===================================================== */}
        {view === "start" && (
          <>
            <h1 style={{ margin: "0 0 8px", fontSize: "24px", textAlign: "center" }}>
              Inicia sesión o regístrate
            </h1>
            <p style={{ margin: "0 0 28px", color: c.muted, lineHeight: 1.55, fontSize: "14.5px", textAlign: "center" }}>
              Accede a VulnHunter para escanear tus sitios, revisar
              vulnerabilidades y descargar reportes de seguridad.
            </p>

            {/* Botones de proveedores con sus logos reales. */}
            <div style={{ display: "grid", gap: "10px" }}>
              <GoogleSignInButton
                onCredential={(credential) => void handleGoogleCredential(credential)}
                onError={setLoginError}
              />
              {loginError && (
                <p style={{ color: c.severity.critical, fontSize: "13px", margin: "2px 0 0" }}>
                  {loginError}
                </p>
              )}
            </div>

            {/* Divisor con "o" al centro. */}
            <div style={{ display: "flex", alignItems: "center", gap: "12px", fontSize: "12.5px", color: c.muted, margin: "20px 0" }}>
              <div style={{ flex: 1, height: "1px", backgroundColor: c.border }} />
              o
              <div style={{ flex: 1, height: "1px", backgroundColor: c.border }} />
            </div>

            {/* Botón para ir al login con correo. */}
            <button
              style={{ ...btnProvider, backgroundColor: c.background, borderColor: c.background }}
              onClick={() => setView("email")}
            >
              Continuar con correo electrónico
            </button>

            <button
              type="button"
              style={{
                ...btnProvider,
                marginTop: "10px",
                borderColor: c.primary,
                color: c.primary,
                backgroundColor: "#EFF4FF",
                fontWeight: 600,
              }}
              onClick={() => void handleGuestLogin()}
              disabled={guestLoading}
            >
              {guestLoading ? "Preparando demostración…" : "Explorar demo como invitado"}
            </button>
            <p style={{ textAlign: "center", fontSize: "12px", color: c.muted, margin: "8px 0 0" }}>
              Acceso temporal y de solo lectura. No requiere crear una cuenta.
            </p>

            {/* Enlace a registro (lo conectamos en la Parte 2). */}
            <p style={{ textAlign: "center", fontSize: "14px", color: c.muted, marginTop: "20px" }}>
              ¿No tienes cuenta?{" "}
              <span
                onClick={() => setView("register")}
                style={{ color: c.primary, fontWeight: 600, cursor: "pointer" }}
              >
                Crear cuenta en VulnHunter
              </span>
            </p>
          </>
        )}

        {/* ===================================================== */}
        {/* SUB-VISTA "email": inicio de sesión con correo        */}
        {/* ===================================================== */}
        {view === "email" && (
          <>
            {/* Volver a la elección de método. */}
            <button
              onClick={() => setView("start")}
              style={{ backgroundColor: "transparent", border: "none", color: c.muted, cursor: "pointer", padding: 0, marginBottom: "16px", fontSize: "13px" }}
            >
              ← Atrás
            </button>

            <h1 style={{ margin: "0 0 8px", fontSize: "22px", textAlign: "center" }}>
              Inicia sesión con tu correo
            </h1>
            <p style={{ margin: "0 0 24px", color: c.muted, lineHeight: 1.55, fontSize: "14px", textAlign: "center" }}>
              Ingresa los datos de tu cuenta VulnHunter.
            </p>

            {/* Campo: correo */}
            <label style={{ display: "block", fontSize: "13.5px", fontWeight: 500 }}>
              Correo electrónico
            </label>
            <input
              type="email"
              placeholder="nombre@empresa.cl"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              style={input}
            />

            {/* Campo: contraseña */}
            <label style={{ display: "block", fontSize: "13.5px", fontWeight: 500, marginTop: "16px" }}>
              Contraseña
            </label>
            <input
              type="password"
              placeholder="Tu contraseña"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={input}
            />


            {/* Mensaje de error del login (solo aparece si hay un error). */}
            {loginError && (
              <p style={{ color: c.severity.critical, fontSize: "13px", marginTop: "16px", marginBottom: 0 }}>
                {loginError}
              </p>
            )}


            {/* Botón principal: ejecuta la lógica de login. */}
            <button style={{ ...btnPrimary, marginTop: "24px" }} onClick={handleLogin}>
              Iniciar sesión
            </button>

            {/* Enlace a registro (Parte 2). */}
            <p style={{ textAlign: "center", fontSize: "14px", color: c.muted, marginTop: "20px" }}>
              ¿No tienes cuenta?{" "}
              <span
                onClick={() => setView("register")}
                style={{ color: c.primary, fontWeight: 600, cursor: "pointer" }}
              >
                Regístrate ahora
              </span>
            </p>
          </>
        )}
        {/* ===================================================== */}
        {/* SUB-VISTA "register": formulario de creación de cuenta */}
        {/* ===================================================== */}
        {view === "register" && (
          <>
            {/* Volver a la elección de método. */}
            <button
              onClick={() => setView("start")}
              style={{ backgroundColor: "transparent", border: "none", color: c.muted, cursor: "pointer", padding: 0, marginBottom: "16px", fontSize: "13px" }}
            >
              ← Atrás
            </button>

            <h1 style={{ margin: "0 0 8px", fontSize: "22px", textAlign: "center" }}>
              Crear cuenta en VulnHunter
            </h1>
            <p style={{ margin: "0 0 24px", color: c.muted, lineHeight: 1.55, fontSize: "14px", textAlign: "center" }}>
              Completa tus datos para empezar a analizar tus sitios.
            </p>

            {/* --- Fila: Nombre y Apellido (dos columnas) --- */}

            <span
              style={sectionLabel}>Datos personales
            </span>

            <div className="login-form-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "14px" }}>
              <div>
                <label style={{ display: "block", fontSize: "13.5px", fontWeight: 500 }}>Nombre</label>
                <input
                  placeholder="Carlos"
                  value={regNombre}
                  onChange={(e) => setRegNombre(e.target.value)}
                  style={input}
                />
              </div>
              <div>
                <label style={{ display: "block", fontSize: "13.5px", fontWeight: 500 }}>Apellido</label>
                <input
                  placeholder="Méndez"
                  value={regApellido}
                  onChange={(e) => setRegApellido(e.target.value)}
                  style={input}
                />
              </div>
            </div>

            {/* --- Correo --- */}
            <span
              style={sectionLabel}>Acceso
            </span>

            <label style={{ display: "block", fontSize: "13.5px", fontWeight: 500, marginTop: "16px" }}>
              Correo electrónico
            </label>
            <input
              type="email"
              placeholder="nombre@empresa.cl"
              value={regEmail}
              onChange={(e) => setRegEmail(e.target.value)}
              style={input}
            />

            {/* --- Fila: Contraseña y Confirmar (dos columnas) --- */}
            <div className="login-form-grid" style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "14px", marginTop: "16px" }}>
              <div>
                <label style={{ display: "block", fontSize: "13.5px", fontWeight: 500 }}>Contraseña</label>
                {/* Contenedor relativo: permite poner el ojito encima del input. */}
                <div style={{ position: "relative" }}>
                  <input
                    // Si verPassword es true, se muestra como texto; si no, como puntitos.
                    type={verPassword ? "text" : "password"}
                    placeholder="Mínimo 8 caracteres"
                    value={regPassword}
                    onChange={(e) => setRegPassword(e.target.value)}
                    // paddingRight extra para que el texto no choque con el ojito.
                    style={{ ...input, paddingRight: "44px" }}
                  />
                  {/* Botón del ojito: alterna mostrar/ocultar. */}
                  {/* Botón del ojito: alterna mostrar/ocultar la contraseña. */}
                  <button
                    type="button"
                    onClick={() => setVerPassword(!verPassword)}
                    aria-label="Mostrar u ocultar contraseña"
                    style={{
                      position: "absolute",
                      right: "10px",
                      top: "50%",
                      transform: "translateY(-50%)",
                      marginTop: "3px",
                      border: "none",
                      background: "none",
                      cursor: "pointer",
                      color: c.muted,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      padding: 0,
                    }}
                  >
                    {/* Icono profesional de lucide: ojo tachado si está visible, ojo normal si no. */}
                    {verPassword ? <Eye size={18} /> : <EyeOff size={18} />}
                  </button>
                </div>

                {/* Barra de fuerza: 4 rayitas que se llenan según el puntaje. */}
                <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: "4px", marginTop: "8px" }}>
                  {[1, 2, 3, 4].map((n) => (
                    <div
                      key={n}
                      style={{
                        height: "4px",
                        borderRadius: "999px",
                        // Se pinta del color del nivel si la rayita está "alcanzada".
                        backgroundColor: n <= fuerzaActual ? nivelesPass[fuerzaActual].color : c.border,
                      }}
                    />
                  ))}
                </div>

                {/* Texto del nivel ("Débil", "Fuerte", etc.) o una pista si está vacía. */}
                <p style={{ fontSize: "12px", color: c.muted, marginTop: "6px" }}>
                  {regPassword
                    ? <>Seguridad: <b style={{ color: nivelesPass[fuerzaActual].color }}>{nivelesPass[fuerzaActual].label}</b></>
                    : "Usa letras, números y símbolos"}
                </p>

              </div>

              <div>
                <label style={{ display: "block", fontSize: "13.5px", fontWeight: 500 }}>Confirmar contraseña</label>
                <input
                  type="password"
                  placeholder="Repite la contraseña"
                  value={regPassword2}
                  onChange={(e) => setRegPassword2(e.target.value)}
                  style={input}
                />
              </div>
            </div>

            {/* --- Teléfono de contacto --- */}
            <span
              style={sectionLabel}>Información de contacto
            </span>

            <label style={{ display: "block", fontSize: "13.5px", fontWeight: 500, marginTop: "16px" }}>
              Número de contacto
            </label>
            {/* Al escribir, formateamos el teléfono automáticamente. */}
            <input
              type="tel"
              placeholder="9 1234 5678"
              value={regTelefono}
              onChange={(e) => setRegTelefono(formatearTelefono(e.target.value))}
              style={input}
            />


            {/* --- RUT de empresa (opcional, con formateo automático) --- */}
            <label style={{ display: "block", fontSize: "13.5px", fontWeight: 500, marginTop: "16px" }}>
              RUT de empresa <span style={{ color: c.muted, fontWeight: 400 }}>(opcional)</span>
            </label>
            <input
              placeholder="76.123.456-7"
              value={regRut}
              onChange={(e) => setRegRut(formatearRut(e.target.value))}
              style={input}
            />


            {/* Mensaje de error de validación (solo aparece si hay un error). */}
            {regError && (
              <p style={{ color: c.severity.critical, fontSize: "13px", marginTop: "12px" }}>
                {regError}
              </p>
            )}

            {/* El botón "Crear cuenta" lo conectamos en el Paso 4. */}
            <button style={{ ...btnPrimary, marginTop: "20px" }} onClick={handleRegistro}>
              Crear cuenta
            </button>


            {/* Enlace para volver al login. */}
            <p style={{ textAlign: "center", fontSize: "14px", color: c.muted, marginTop: "20px" }}>
              ¿Ya tienes cuenta?{" "}
              <span
                onClick={() => setView("email")}
                style={{ color: c.primary, fontWeight: 600, cursor: "pointer" }}
              >
                Inicia sesión
              </span>
            </p>
          </>
        )}

        {/* Aviso temporal (proveedores "próximamente"). */}
        {/* ===================================================== */}
        {/* SUB-VISTA "success": pantalla de cuenta creada        */}
        {/* ===================================================== */}
        {view === "success" && (
          <div style={{ textAlign: "center" }}>
            {/* Círculo verde con un visto bueno. */}
            <div
              style={{
                width: "56px",
                height: "56px",
                borderRadius: "50%",
                backgroundColor: "#F0FDF4",
                color: c.severity.low,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                margin: "0 auto 20px",
                fontSize: "28px",
              }}
            >
              ✓
            </div>
            <h1 style={{ margin: "0 0 8px", fontSize: "22px" }}>Cuenta creada</h1>
            <p style={{ margin: "0 0 26px", color: c.muted, lineHeight: 1.55, fontSize: "14px" }}>
              Te enviamos un correo a <b style={{ color: c.text }}>{regEmail}</b> para
              verificar tu cuenta.
            </p>
            {/* Botón para iniciar sesión tras registrarse. */}
            {/* No entra directo: lleva a la pantalla de login con el correo ya puesto, */}
            {/* para que el usuario solo escriba su contraseña. Así evitamos el error 422. */}
            <button
              style={btnPrimary}
              onClick={() => {
                setEmail(regEmail);   // Copiamos el correo del registro al campo de login.
                setPassword("");      // La contraseña se deja vacía para que la escriba.
                setLoginError("");    // Limpiamos cualquier error previo del login.
                setView("email");     // Cambiamos a la sub-vista de iniciar sesión.
              }}
            >
              Ir a iniciar sesión
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
export default Login;




