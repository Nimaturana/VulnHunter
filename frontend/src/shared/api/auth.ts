// Funciones que hablan con el backend de autenticación (/auth/register y /auth/login).
// Reutilizamos apiRequest, que ya sabe armar la URL y manejar errores.
import { apiRequest, ApiError, clearAccessToken, setAccessToken } from "./client";

// Forma de los datos que enviamos al registrar un usuario nuevo.
// Coincide con lo que espera el backend (RegistroRequest en Python).
export type DatosRegistro = {
  email: string;
  password: string;
  nombre: string;
  apellido: string;
  rut?: string;
  telefono?: string;
  fecha_nacimiento?: string;
};

// Forma de la respuesta del backend cuando el usuario ya existe o se crea.
// Coincide con UsuarioResponse en Python (sin la contraseña, por seguridad).
export type Usuario = {
  id: number;
  email: string;
  nombre: string;
  apellido: string;
  role: "admin" | "auditor" | "client" | "guest" | "user";
};

export type LoginResponse = {
  access_token: string;
  token_type: "bearer";
  expires_in: number;
  user: Usuario;
};

// --- Registrar un usuario nuevo ---
// Llama a POST /auth/register enviando los datos del formulario.
export async function registrarUsuario(datos: DatosRegistro): Promise<Usuario> {
  return apiRequest<Usuario>("/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(datos),
  });
}

// --- Iniciar sesión ---
// Llama a POST /auth/login con correo y contraseña.
// Si son correctos, el backend devuelve los datos del usuario (incluido su role).
export async function iniciarSesion(email: string, password: string): Promise<Usuario> {
  const session = await apiRequest<LoginResponse>("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  setAccessToken(session.access_token);
  return session.user;
}

export async function iniciarSesionGoogle(credential: string): Promise<Usuario> {
  const session = await apiRequest<LoginResponse>("/auth/google", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ credential }),
  });
  setAccessToken(session.access_token);
  return session.user;
}

export async function iniciarSesionInvitado(): Promise<Usuario> {
  const session = await apiRequest<LoginResponse>("/auth/guest", {
    method: "POST",
  });
  setAccessToken(session.access_token);
  return session.user;
}

export function cerrarSesion(): void {
  clearAccessToken();
}

// Re-exportamos ApiError para poder reconocer errores (ej: 401, 409) en el login.
export { ApiError };

