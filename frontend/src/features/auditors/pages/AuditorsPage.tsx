import { FormEvent, useEffect, useState } from "react";
import { ApiError, guardarAuditor, listarAuditores, revocarAuditor, type Usuario } from "../../../shared/api/auth";
import { theme } from "../../../shared/styles/theme";

const c = theme.colors;

function AuditorsPage() {
  const [auditors, setAuditors] = useState<Usuario[]>([]);
  const [email, setEmail] = useState("");
  const [company, setCompany] = useState("");
  const [name, setName] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const loadAuditors = async () => {
    setLoading(true);
    setError("");
    try {
      setAuditors(await listarAuditores());
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "No fue posible cargar el equipo auditor.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { void loadAuditors(); }, []);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setError("");
    setMessage("");
    try {
      await guardarAuditor({ email, company_name: company, nombre: name || undefined });
      setEmail(""); setCompany(""); setName("");
      setMessage("Auditor autorizado. Podrá ingresar con Google usando ese mismo correo.");
      await loadAuditors();
    } catch (reason) {
      setError(reason instanceof ApiError ? reason.message : "No fue posible guardar el auditor.");
    } finally {
      setSaving(false);
    }
  };

  const revoke = async (auditor: Usuario) => {
    if (!window.confirm(`¿Quitar el rol auditor a ${auditor.email}?`)) return;
    setError(""); setMessage("");
    try {
      await revocarAuditor(auditor.id);
      setMessage("El acceso fue revocado; su cuenta e historial se conservaron.");
      await loadAuditors();
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "No fue posible revocar el acceso.");
    }
  };

  return (
    <main className="responsive-page auditor-page" style={{ padding: "36px 44px 48px", background: c.background, color: c.text, minHeight: "100vh" }}>
      <header style={{ marginBottom: 26 }}>
        <span className="eyebrow">Administración exclusiva</span>
        <h1 style={{ margin: "8px 0 0", fontSize: 30, letterSpacing: "-0.02em" }}>Equipo auditor</h1>
        <p style={{ color: c.muted, margin: "7px 0 0", maxWidth: 680 }}>
          Autoriza a quienes podrán ejecutar escaneos. El permiso queda guardado en PostgreSQL y solo un administrador puede modificarlo.
        </p>
      </header>

      <div className="auditor-layout">
        <form className="auditor-form" onSubmit={submit}>
          <div><h2>Agregar auditor</h2><p>Registra la empresa y el correo corporativo que tendrá el rol.</p></div>
          <label>Empresa<input required minLength={2} maxLength={150} value={company} onChange={(e) => setCompany(e.target.value)} placeholder="Ej. Pyme Seguridad SpA" /></label>
          <label>Correo del auditor<input required type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="auditor@empresa.cl" /></label>
          <label>Nombre <span>(opcional)</span><input maxLength={100} value={name} onChange={(e) => setName(e.target.value)} placeholder="Nombre de contacto" /></label>
          <button type="submit" disabled={saving}>{saving ? "Guardando…" : "+ Autorizar auditor"}</button>
          <small>Si no existe, se aprovisionará una cuenta que podrá vincularse al iniciar sesión con Google.</small>
        </form>

        <section className="auditor-list-card">
          <div className="auditor-list-header">
            <div><h2>Auditores autorizados</h2><p>{auditors.length} {auditors.length === 1 ? "persona autorizada" : "personas autorizadas"}</p></div>
            <button type="button" onClick={() => void loadAuditors()} aria-label="Actualizar lista">↻</button>
          </div>
          {(error || message) && <div className={error ? "auditor-alert error" : "auditor-alert success"}>{error || message}</div>}
          {loading ? <div className="auditor-empty">Cargando equipo…</div> : auditors.length === 0 ? (
            <div className="auditor-empty"><strong>Aún no hay auditores</strong><span>Agrega el primero desde el formulario.</span></div>
          ) : (
            <div className="auditor-list">{auditors.map((auditor) => (
              <article key={auditor.id} className="auditor-item">
                <div className="auditor-avatar">{(auditor.nombre || auditor.email)[0].toUpperCase()}</div>
                <div className="auditor-identity"><strong>{auditor.nombre} {auditor.apellido !== "Auditor" ? auditor.apellido : ""}</strong><span>{auditor.email}</span><em>{auditor.company_name || "Empresa sin especificar"}</em></div>
                <span className="role-badge">Auditor</span>
                <button className="revoke-button" type="button" onClick={() => void revoke(auditor)}>Revocar</button>
              </article>
            ))}</div>
          )}
        </section>
      </div>
    </main>
  );
}

export default AuditorsPage;
