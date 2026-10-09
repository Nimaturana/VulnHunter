const reports = [
  {
    site: "https://tienda-ejemplo.cl",
    risk: "ALTO",
    date: "06/09/2026",
    scanId: "SCAN-001",
  },
  {
    site: "https://empresa-demo.cl",
    risk: "MEDIO",
    date: "05/09/2026",
    scanId: "SCAN-002",
  },
  {
    site: "https://portal-prueba.cl",
    risk: "BAJO",
    date: "04/09/2026",
    scanId: "SCAN-003",
  },
];

const tableCellStyle = {
  padding: "16px 12px",
};

function Reports() {
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
          Reportes
        </h1>

        <p
          style={{
            color: "#94AFC7",
            marginTop: "8px",
          }}
        >
          Genera y descarga reportes PDF asociados a los escaneos realizados.
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
          <h3 style={{ margin: 0 }}>Reportes disponibles</h3>

          <span
            style={{
              color: "#94AFC7",
              fontSize: "14px",
            }}
          >
            {reports.length} escaneos disponibles
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
              <th style={tableCellStyle}>ID escaneo</th>
              <th style={tableCellStyle}>Riesgo</th>
              <th style={tableCellStyle}>Fecha</th>
              <th style={tableCellStyle}>Acción</th>
            </tr>
          </thead>

          <tbody>
            {reports.map((report) => (
              <tr
                key={report.scanId}
                style={{
                  borderBottom: "1px solid #1e293b",
                }}
              >
                <td style={tableCellStyle}>{report.site}</td>

                <td
                  style={{
                    ...tableCellStyle,
                    color: "#94AFC7",
                  }}
                >
                  {report.scanId}
                </td>

                <td style={tableCellStyle}>
                  <strong
                    style={{
                      color:
                        report.risk === "ALTO"
                          ? "#f97316"
                          : report.risk === "MEDIO"
                            ? "#eab308"
                            : "#22c55e",
                    }}
                  >
                    {report.risk}
                  </strong>
                </td>

                <td
                  style={{
                    ...tableCellStyle,
                    color: "#94AFC7",
                  }}
                >
                  {report.date}
                </td>

                <td style={tableCellStyle}>
                  <button
                    style={{
                      backgroundColor: "#1677FF",
                      color: "#FFFFFF",
                      border: "1px solid #29C7F6",
                      borderRadius: "8px",
                      padding: "8px 14px",
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

export default Reports;