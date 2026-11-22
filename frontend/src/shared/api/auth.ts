// Funciones que hablan con el backend de autenticación (/auth/register y /auth/login).
// Reutilizamos apiRequest, que ya sabe armar la URL y manejar errores.
import { apiRequest, ApiError } from "./client";

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
  role: "admin" | "user";
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
  return apiRequest<Usuario>("/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
}

// Re-exportamos ApiError para poder reconocer errores (ej: 401, 409) en el login.
export { ApiError };

