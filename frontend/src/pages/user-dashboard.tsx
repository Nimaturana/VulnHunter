type UserDashboardProps = {
  onBack: () => void;
};

const userSites = [
  {
    url: "https://mi-empresa.cl",
    risk: "MEDIO",
    lastScan: "20/09/2026",
  },
  {
    url: "https://tienda.mi-empresa.cl",
    risk: "ALTO",
    lastScan: "18/09/2026",
  },
];

const userScans = [
  {
    site: "https://mi-empresa.cl",
    status: "Completado",
    date: "20/09/2026",
  },
  {
    site: "https://tienda.mi-empresa.cl",
    status: "Completado",
    date: "18/09/2026",
  },
];

const cardStyle = {
  backgroundColor: "#0F1B2D",
  border: "1px solid #1B2B40",
  borderRadius: "12px",
  padding: "22px",
};

const tableCellStyle = {
  padding: "14px 10px",
};

function UserDashboard({ onBack }: UserDashboardProps) {
  return (
    <main
      style={{
        minHeight: "100vh",
        width: "100%",
        backgroundColor: "#07111F",
        color: "#F8FAFC",
        fontFamily: "Arial, sans-serif",
        padding: "32px",
        boxSizing: "border-box",
      }}
    >
      {/* VOLVER */}
      <button
        onClick={onBack}
        style={{
          backgroundColor: "transparent",
          border: "none",
          color: "#94AFC7",
          cursor: "pointer",
          fontSize: "14px",
          padding: "0",
          marginBottom: "24px",
        }}
      >
        ← Volver
      </button>

      {/* HEADER */}
      <header
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "35px",
        }}
      >
        <div>
          <h1
            style={{
              margin: 0,
              fontSize: "30px",
            }}
          >
            Hola 👋
          </h1>

          <p
            style={{
              color: "#94AFC7",
              marginTop: "8px",
            }}
          >
            Revisa el estado de seguridad de tus sitios web.
          </p>
        </div>

        <button
          style={{
            backgroundColor: "#1677FF",
            color: "#FFFFFF",
            border: "1px solid #29C7F6",
            borderRadius: "8px",
            padding: "12px 18px",
            cursor: "pointer",
            fontWeight: "bold",
          }}
        >
          + Nuevo escaneo
        </button>
      </header>

      {/* RESUMEN PERSONAL */}
      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(3, 1fr)",
          gap: "18px",
          marginBottom: "25px",
        }}
      >
        <div style={cardStyle}>
          <div
            style={{
              fontSize: "27px",
              marginBottom: "15px",
            }}
          >
            🌐
          </div>

          <p
            style={{
              color: "#94AFC7",
              margin: 0,
            }}
          >
            Mis sitios
          </p>

          <h2
            style={{
              marginBottom: 0,
            }}
          >
            2
          </h2>
        </div>

        <div style={cardStyle}>
          <div
            style={{
              fontSize: "27px",
              marginBottom: "15px",
            }}
          >
            🔍
          </div>

          <p
            style={{
              color: "#94AFC7",
              margin: 0,
            }}
          >
            Mis escaneos
          </p>

          <h2
            style={{
              marginBottom: 0,
            }}
          >
            7
          </h2>
        </div>

        <div style={cardStyle}>
          <div
            style={{
              fontSize: "27px",
              marginBottom: "15px",
            }}
          >
            ⚠️
          </div>

          <p
            style={{
              color: "#94AFC7",
              margin: 0,
            }}
          >
            Mis hallazgos
          </p>

          <h2
            style={{
              marginBottom: 0,
            }}
          >
            12
          </h2>
        </div>
      </section>

      {/* MIS SITIOS */}
      <section
        style={{
          ...cardStyle,
          marginBottom: "25px",
        }}
      >
        <h3 style={{ marginTop: 0 }}>
          Estado de mis sitios
        </h3>

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
              <th style={tableCellStyle}>Sitio</th>
              <th style={tableCellStyle}>Riesgo</th>
              <th style={tableCellStyle}>
                Último análisis
              </th>
              <th style={tableCellStyle}>Acción</th>
            </tr>
          </thead>

          <tbody>
            {userSites.map((site) => (
              <tr
                key={site.url}
                style={{
                  borderBottom: "1px solid #1e293b",
                }}
              >
                <td style={tableCellStyle}>
                  {site.url}
                </td>

                <td style={tableCellStyle}>
                  <strong
                    style={{
                      color:
                        site.risk === "ALTO"
                          ? "#f97316"
                          : site.risk === "MEDIO"
                            ? "#eab308"
                            : "#22c55e",
                    }}
                  >
                    {site.risk}
                  </strong>
                </td>

                <td
                  style={{
                    ...tableCellStyle,
                    color: "#94AFC7",
                  }}
                >
                  {site.lastScan}
                </td>

                <td style={tableCellStyle}>
                  <button
                    style={{
                      backgroundColor:
                        "transparent",
                      color: "#29C7F6",
                      border:
                        "1px solid #29C7F6",
                      borderRadius: "8px",
                      padding: "8px 12px",
                      cursor: "pointer",
                    }}
                  >
                    Ver resultados
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {/* ÚLTIMOS ESCANEOS */}
      <section style={cardStyle}>
        <h3 style={{ marginTop: 0 }}>
          Mis últimos escaneos
        </h3>

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
              <th style={tableCellStyle}>Sitio</th>
              <th style={tableCellStyle}>Estado</th>
              <th style={tableCellStyle}>Fecha</th>
              <th style={tableCellStyle}>Reporte</th>
            </tr>
          </thead>

          <tbody>
            {userScans.map((scan) => (
              <tr
                key={`${scan.site}-${scan.date}`}
                style={{
                  borderBottom: "1px solid #1e293b",
                }}
              >
                <td style={tableCellStyle}>
                  {scan.site}
                </td>

                <td style={tableCellStyle}>
                  <span
                    style={{
                      color: "#22c55e",
                    }}
                  >
                    ● {scan.status}
                  </span>
                </td>

                <td
                  style={{
                    ...tableCellStyle,
                    color: "#94AFC7",
                  }}
                >
                  {scan.date}
                </td>

                <td style={tableCellStyle}>
                  <button
                    style={{
                      backgroundColor: "#1677FF",
                      color: "#FFFFFF",
                      border: "none",
                      borderRadius: "8px",
                      padding: "8px 12px",
                      cursor: "pointer",
                      fontWeight: "bold",
                    }}
                  >
                    📄 Generar PDF
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

export default UserDashboard;