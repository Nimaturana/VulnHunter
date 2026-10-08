const scans = [
  {
    url: "https://tienda-ejemplo.cl",
    status: "Completado",
    risk: "ALTO",
    date: "06/09/2026",
  },
  {
    url: "https://empresa-demo.cl",
    status: "Completado",
    risk: "MEDIO",
    date: "05/09/2026",
  },
  {
    url: "https://portal-prueba.cl",
    status: "Ejecutándose",
    risk: "Analizando",
    date: "05/09/2026",
  },
];

const tableCellStyle = {
  padding: "16px 12px",
};

function Scans() {
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
          Escaneos
        </h1>

        <p
          style={{
            color: "#94AFC7",
            marginTop: "8px",
          }}
        >
          Revisa el historial y estado de los análisis realizados.
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
        <h3
          style={{
            marginTop: 0,
            marginBottom: "20px",
          }}
        >
          Historial de escaneos
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
              <th style={tableCellStyle}>Riesgo</th>
              <th style={tableCellStyle}>Fecha</th>
            </tr>
          </thead>

          <tbody>
            {scans.map((scan) => (
              <tr
                key={scan.url}
                style={{
                  borderBottom: "1px solid #1e293b",
                }}
              >
                <td style={tableCellStyle}>{scan.url}</td>

                <td style={tableCellStyle}>
                  <span
                    style={{
                      color:
                        scan.status === "Completado"
                          ? "#22c55e"
                          : "#60a5fa",
                    }}
                  >
                    ● {scan.status}
                  </span>
                </td>

                <td style={tableCellStyle}>
                  <strong
                    style={{
                      color:
                        scan.risk === "ALTO"
                          ? "#f97316"
                          : scan.risk === "MEDIO"
                            ? "#eab308"
                            : "#60a5fa",
                    }}
                  >
                    {scan.risk}
                  </strong>
                </td>

                <td
                  style={{
                    ...tableCellStyle,
                    color: "#94AFC7",
                  }}
                >
                  {scan.date}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </main>
  );
}

export default Scans;