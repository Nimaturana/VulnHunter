const configuredApiUrl = import.meta.env.VITE_API_URL?.trim();

export const API_BASE_URL = (configuredApiUrl || "/api").replace(/\/$/, "");
const TOKEN_KEY = "vulnhunter_access_token";

export function setAccessToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearAccessToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

export function getAccessToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

type ApiErrorDetail = {
  loc?: Array<string | number>;
  msg?: string;
  type?: string;
};

function formatApiErrorDetail(detail: unknown): string | null {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => {
        if (!item || typeof item !== "object") return null;
        const error = item as ApiErrorDetail;
        const field = error.loc?.filter((part) => part !== "body").join(".");
        return error.msg ? `${field ? `${field}: ` : ""}${error.msg}` : null;
      })
      .filter((item): item is string => Boolean(item));
    return messages.length ? messages.join(" · ") : null;
  }
  if (detail && typeof detail === "object") {
    try {
      return JSON.stringify(detail);
    } catch {
      return null;
    }
  }
  return null;
}

export async function apiRequest<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const token = getAccessToken();
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: {
      Accept: "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init?.headers,
    },
  });

  if (!response.ok) {
    let message = `La API respondió con estado ${response.status}`;
    try {
      const payload = (await response.json()) as { detail?: unknown };
      message = formatApiErrorDetail(payload.detail) || message;
    } catch {
      // The fallback message remains useful for non-JSON responses.
    }
    throw new ApiError(response.status, message);
  }

  return response.json() as Promise<T>;
}
