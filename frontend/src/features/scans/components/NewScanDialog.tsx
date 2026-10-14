import { useEffect, useState, type FormEvent } from "react";

import { startScan } from "../../../shared/api/scans";
import {
  errorStyle,
  primaryButtonStyle,
  secondaryButtonStyle,
} from "../../../shared/styles/layout";

type NewScanDialogProps = {
  open: boolean;
  onClose: () => void;
  onStarted: (scanId: string) => void | Promise<void>;
};

export function NewScanDialog({ open, onClose, onStarted }: NewScanDialogProps) {
  const [url, setUrl] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) {
      setUrl("");
      setError(null);
      setSubmitting(false);
    }
  }, [open]);

  if (!open) return null;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const result = await startScan(url);
      await onStarted(result.scan_id);
      onClose();
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : "No fue posible iniciar el escaneo",
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="new-scan-title"
      style={{
        position: "fixed",
        inset: 0,
        backgroundColor: "rgba(0, 0, 0, 0.7)",
        display: "grid",
        placeItems: "center",
        padding: "20px",
        zIndex: 1000,
      }}
    >
      <form
        onSubmit={submit}
        style={{
          width: "min(500px, 100%)",
          backgroundColor: "#0F1B2D",
          border: "1px solid #1B2B40",
          borderRadius: "14px",
          padding: "28px",
          boxShadow: "0 20px 50px rgba(0, 0, 0, 0.45)",
        }}
      >
        <h2 id="new-scan-title" style={{ marginTop: 0 }}>
          Nuevo escaneo completo
        </h2>
        <p style={{ color: "#94AFC7", lineHeight: 1.6 }}>
          Se ejecutarán XSS, SQL injection, headers, SSL/TLS y directorios.
          Escanea únicamente sitios propios o con autorización expresa.
        </p>
        {error && <div style={errorStyle}>{error}</div>}
        <label htmlFor="scan-url" style={{ display: "block", marginBottom: 8 }}>
          URL autorizada
        </label>
        <input
          id="scan-url"
          type="url"
          required
          autoFocus
          placeholder="https://ejemplo.cl"
          value={url}
          onChange={(event) => setUrl(event.target.value)}
          style={{
            width: "100%",
            boxSizing: "border-box",
            padding: "12px",
            borderRadius: "8px",
            border: "1px solid #334155",
            backgroundColor: "#07111F",
            color: "#F8FAFC",
            marginBottom: "22px",
          }}
        />
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 12 }}>
          <button type="button" onClick={onClose} style={secondaryButtonStyle}>
            Cancelar
          </button>
          <button
            type="submit"
            disabled={submitting}
            style={{
              ...primaryButtonStyle,
              opacity: submitting ? 0.6 : 1,
              cursor: submitting ? "wait" : "pointer",
            }}
          >
            {submitting ? "Iniciando…" : "Iniciar escaneo"}
          </button>
        </div>
      </form>
    </div>
  );
}
