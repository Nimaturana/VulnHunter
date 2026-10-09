const findings = [
  {
    vulnerability: "XSS reflejado",
    severity: "ALTA",
    site: "https://tienda-ejemplo.cl",
    status: "Abierto",
  },
  {
    vulnerability: "Headers de seguridad faltantes",
    severity: "MEDIA",
    site: "https://empresa-demo.cl",
    status: "Abierto",
  },
  {
    vulnerability: "Configuración TLS débil",
    severity: "BAJA",
    site: "https://portal-prueba.cl",
    status: "Revisado",
  },
  {
    vulnerability: "Posible inyección SQL",
    severity: "CRÍTICA",
    site: "https://tienda-ejemplo.cl",
    status: "Abierto",
  },
];

const tableCellStyle = {
  padding: "16px 12px",
};

function Findings() {
  return (
    <main
      style={{
        flex: 1,
        padding: "32px",
      }}
    >
      <header
        style={{
          marginBottom: "35px",
        }}
      >
        <h1
          style={{
            margin: 0,
            fontSize: "30px",
          }}
        >
          Hallazgos
        </h1>

        <p
          style={{
            color: "#94AFC7",
            marginTop: "8px",
          }}
        >
          Revisa las vulnerabilidades detectadas durante los análisis.
        </p>
      </header>

      <section
        style={{
          backgroundColor: "#0F1B2D",
          border: "1px solid #1B2B40",
          borderRadius: "12px",
          padding: "22px",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "20px",
          }}
        >
          <h3 style={{ margin: 0 }}>Vulnerabilidades detectadas</h3>

          <span
            style={{
              color: "#94AFC7",
              fontSize: "14px",
            }}
          >
            {findings.length} hallazgos
          </span>
        </div>

        <table
          style={{
            width: "100%",
            borderCollapse: "collapse",
            textAlign: "left",
          }}
        >
          <thead>
            <tr
              style={{
                color: "#94AFC7",
                borderBottom: "1px solid #334155",
              }}
            >
              <th style={tableCellStyle}>Vulnerabilidad</th>
              <th style={tableCellStyle}>Severidad</th>
              <th style={tableCellStyle}>Sitio</th>
              <th style={tableCellStyle}>Estado</th>
              <th style={tableCellStyle}>Acciones</th>
            </tr>
          </thead>

          <tbody>
            {findings.map((finding) => (
              <tr
                key={`${finding.vulnerability}-${finding.site}`}
                style={{
                  borderBottom: "1px solid #1e293b",
                }}
              >
                <td style={tableCellStyle}>
                  {finding.vulnerability}
                </td>

                <td style={tableCellStyle}>
                  <strong
                    style={{
                      color:
                        finding.severity === "CRÍTICA"
                          ? "#ef4444"
                          : finding.severity === "ALTA"
                            ? "#f97316"
                            : finding.severity === "MEDIA"
                              ? "#eab308"
                              : "#22c55e",
                    }}
                  >
                    {finding.severity}
                  </strong>
                </td>

                <td
                  style={{
                    ...tableCellStyle,
                    color: "#D7E6F3",
                  }}
                >
                  {finding.site}
                </td>

                <td style={tableCellStyle}>
                  <span
                    style={{
                      color:
                        finding.status === "Abierto"
                          ? "#60a5fa"
                          : "#22c55e",
                    }}
                  >
                    ● {finding.status}
                  </span>
                </td>

                <td style={tableCellStyle}>
                  <button
                    style={{
                      backgroundColor: "transparent",
                      color: "#29C7F6",
                      border: "1px solid #29C7F6",
                      borderRadius: "8px",
                      padding: "8px 12px",
                      cursor: "pointer",
                    }}
                  >
                    Ver detalle
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </main>
  );
}

export default Findings;