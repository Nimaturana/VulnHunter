const sites = [
  {
    url: "https://tienda-ejemplo.cl",
    risk: "ALTO",
    scans: 5,
    lastScan: "06/09/2026",
  },
  {
    url: "https://empresa-demo.cl",
    risk: "MEDIO",
    scans: 3,
    lastScan: "05/09/2026",
  },
  {
    url: "https://portal-prueba.cl",
    risk: "BAJO",
    scans: 2,
    lastScan: "04/09/2026",
  },
];

const tableCellStyle = {
  padding: "16px 12px",
};

function Sites() {
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
          Sitios web
        </h1>

        <p
          style={{
            color: "#94AFC7",
            marginTop: "8px",
          }}
        >
          Revisa los sitios web que han sido analizados o monitoreados por
          VulnHunter.
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
          <h3 style={{ margin: 0 }}>Sitios monitoreados</h3>

          <span
            style={{
              color: "#94AFC7",
              fontSize: "14px",
            }}
          >
            {sites.length} sitios
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
              <th style={tableCellStyle}>Sitio</th>
              <th style={tableCellStyle}>Riesgo actual</th>
              <th style={tableCellStyle}>Escaneos</th>
              <th style={tableCellStyle}>Último análisis</th>
              <th style={tableCellStyle}>Acciones</th>
            </tr>
          </thead>

          <tbody>
            {sites.map((site) => (
              <tr
                key={site.url}
                style={{
                  borderBottom: "1px solid #1e293b",
                }}
              >
                <td style={tableCellStyle}>{site.url}</td>

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

                <td style={tableCellStyle}>{site.scans}</td>

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
                      backgroundColor: "transparent",
                      color: "#29C7F6",
                      border: "1px solid #29C7F6",
                      borderRadius: "8px",
                      padding: "8px 12px",
                      cursor: "pointer",
                    }}
                  >
                    Ver historial
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

export default Sites;