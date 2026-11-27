import { useEffect, useRef, useState } from "react";

type GoogleSignInButtonProps = {
  onCredential: (credential: string) => void;
  onError: (message: string) => void;
};

let googleScriptPromise: Promise<void> | null = null;
let initializedClientId = "";
let activeCredentialHandler: ((credential: string) => void) | null = null;

function loadGoogleIdentity(): Promise<void> {
  if (window.google) return Promise.resolve();
  if (googleScriptPromise) return googleScriptPromise;

  googleScriptPromise = new Promise((resolve, reject) => {
    const existing = document.getElementById("google-identity-services") as HTMLScriptElement | null;
    if (existing) {
      existing.addEventListener("load", () => resolve(), { once: true });
      existing.addEventListener("error", () => reject(new Error("Google no pudo cargarse")), {
        once: true,
      });
      return;
    }
    const script = document.createElement("script");
    script.id = "google-identity-services";
    script.src = "https://accounts.google.com/gsi/client?hl=es";
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("Google no pudo cargarse"));
    document.head.appendChild(script);
  });
  return googleScriptPromise;
}

export default function GoogleSignInButton({
  onCredential,
  onError,
}: GoogleSignInButtonProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [loading, setLoading] = useState(true);
  const clientId = import.meta.env.VITE_GOOGLE_CLIENT_ID?.trim() ?? "";
  activeCredentialHandler = onCredential;

  useEffect(() => {
    if (!clientId) {
      setLoading(false);
      onError("Falta configurar GOOGLE_CLIENT_ID para habilitar Google.");
      return;
    }

    let active = true;
    loadGoogleIdentity()
      .then(() => {
        if (!active || !window.google || !containerRef.current) return;
        if (initializedClientId !== clientId) {
          window.google.accounts.id.initialize({
            client_id: clientId,
            callback: (response) => activeCredentialHandler?.(response.credential),
            auto_select: false,
            cancel_on_tap_outside: true,
          });
          initializedClientId = clientId;
        }
        containerRef.current.replaceChildren();
        window.google.accounts.id.renderButton(containerRef.current, {
          type: "standard",
          theme: "outline",
          size: "large",
          text: "continue_with",
          shape: "rectangular",
          logo_alignment: "left",
          width: Math.min(containerRef.current.clientWidth || 400, 400),
          locale: "es",
        });
        setLoading(false);
      })
      .catch(() => {
        if (active) {
          setLoading(false);
          onError("No fue posible cargar el inicio de sesión de Google.");
        }
      });

    return () => {
      active = false;
      activeCredentialHandler = null;
    };
  }, [clientId]);

  return (
    <div style={{ minHeight: "44px", display: "grid", placeItems: "center" }}>
      <div ref={containerRef} style={{ width: "100%", display: "grid", placeItems: "center" }} />
      {loading && <span style={{ fontSize: "13px", color: "#667085" }}>Cargando Google…</span>}
    </div>
  );
}
