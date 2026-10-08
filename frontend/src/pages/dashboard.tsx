import { useState } from "react";

const stats = [
  { title: "Escaneos realizados", value: "24", icon: "🔍" },
  { title: "Vulnerabilidades", value: "17", icon: "⚠️" },
  { title: "Críticas", value: "3", icon: "🚨" },
  { title: "Sitios monitoreados", value: "5", icon: "🌐" },
];

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

const vulnerabilities = [
  { severity: "Críticas", value: 3, color: "#ef4444" },
  { severity: "Altas", value: 5, color: "#f97316" },
  { severity: "Medias", value: 6, color: "#eab308" },
  { severity: "Bajas", value: 3, color: "#22c55e" },
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

function Dashboard() {
  const [showNewScan, setShowNewScan] = useState(false);
  const [scanUrl, setScanUrl] = useState("");

  return (
    <main
      style={{
        flex: 1,
        padding: "32px",
      }}
    >
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
            Dashboard de Seguridad
          </h1>

          <p
            style={{
              color: "#94a3b8",
              marginTop: "8px",
            }}
          >
            Resumen general del estado de seguridad de tus sitios web.
          </p>
        </div>

        <button
          onClick={() => setShowNewScan(true)}
          style={{
            backgroundColor: "#1677FF",
            color: "white",
            border: "none",
            borderRadius: "8px",
            padding: "12px 20px",
            cursor: "pointer",
            fontWeight: "bold",
          }}
        >
          + Nuevo escaneo
        </button>
      </header>

      {/* TARJETAS */}
      <section
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap: "18px",
          marginBottom: "25px",
        }}
      >
        {stats.map((stat) => (
          <div key={stat.title} style={cardStyle}>
            <div
              style={{
                fontSize: "27px",
                marginBottom: "15px",
              }}
            >
              {stat.icon}
            </div>

            <p
              style={{
                color: "#94AFC7",
                margin: 0,
                fontSize: "14px",
              }}
            >
              {stat.title}
            </p>

            <h2
              style={{
                fontSize: "28px",
                margin: "7px 0 0",
              }}
            >
              {stat.value}
            </h2>
          </div>
        ))}
      </section>

      {/* ESTADO + VULNERABILIDADES */}
      <section
        style={{
          display: "grid",
          gridTemplateColumns: "1.3fr 1fr",
          gap: "20px",
          marginBottom: "25px",
        }}
      >
        {/* ESTADO GENERAL */}
        <div style={cardStyle}>
          <h3 style={{ marginTop: 0 }}>Estado general de seguridad</h3>

          <div
            style={{
              marginTop: "25px",
              display: "flex",
              alignItems: "center",
              gap: "20px",
            }}
          >
            <div
              style={{
                width: "85px",
                height: "85px",
                borderRadius: "50%",
                border: "8px solid #f97316",
                display: "flex",
                justifyContent: "center",
                alignItems: "center",
                fontSize: "24px",
                fontWeight: "bold",
              }}
            >
              72
            </div>

            <div>
              <p
                style={{
                  margin: 0,
                  color: "#94a3b8",
                }}
              >
                Nivel de riesgo actual
              </p>

              <h2
                style={{
                  color: "#f97316",
                  margin: "6px 0",
                }}
              >
                ALTO
              </h2>

              <p
                style={{
                  color: "#D7E6F3",
                  margin: 0,
                  fontSize: "14px",
                }}
              >
                Se recomienda revisar primero los hallazgos críticos y altos.
              </p>
            </div>
          </div>
        </div>

        {/* SEVERIDADES */}
        <div style={cardStyle}>
          <h3 style={{ marginTop: 0 }}>Vulnerabilidades por severidad</h3>

          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: "13px",
              marginTop: "20px",
            }}
          >
            {vulnerabilities.map((item) => (
              <div
                key={item.severity}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                }}
              >
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "10px",
                  }}
                >
                  <span
                    style={{
                      width: "10px",
                      height: "10px",
                      borderRadius: "50%",
                      backgroundColor: item.color,
                    }}
                  />

                  <span>{item.severity}</span>
                </div>

                <strong>{item.value}</strong>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ÚLTIMOS ESCANEOS */}
      <section style={cardStyle}>
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: "20px",
          }}
        >
          <h3 style={{ margin: 0 }}>Últimos escaneos</h3>

          <button
            style={{
              background: "transparent",
              border: "none",
              color: "#29C7F6",
              cursor: "pointer",
            }}
          >
            Ver todos →
          </button>
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
                color: "#94a3b8",
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
                    color: "#94a3b8",
                  }}
                >
                  {scan.date}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {/* MODAL NUEVO ESCANEO */}
      {showNewScan && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            width: "100%",
            height: "100%",
            backgroundColor: "rgba(0, 0, 0, 0.65)",
            display: "flex",
            justifyContent: "center",
            alignItems: "center",
            zIndex: 1000,
          }}
        >
          <div
            style={{
              width: "460px",
              backgroundColor: "#0F1B2D",
              border: "1px solid #1B2B40",
              borderRadius: "14px",
              padding: "28px",
              boxShadow: "0 20px 50px rgba(0, 0, 0, 0.4)",
            }}
          >
            <h2 style={{ marginTop: 0 }}>Nuevo escaneo</h2>

            <p
              style={{
                color: "#94AFC7",
                marginBottom: "20px",
              }}
            >
              Ingresa la URL del sitio web que deseas analizar.
            </p>

            <input
              type="url"
              placeholder="https://ejemplo.cl"
              value={scanUrl}
              onChange={(e) => setScanUrl(e.target.value)}
              style={{
                width: "100%",
                padding: "12px",
                borderRadius: "8px",
                border: "1px solid #334155",
                backgroundColor: "#07111F",
                color: "#F8FAFC",
                outline: "none",
                marginBottom: "22px",
              }}
            />

            <div
              style={{
                display: "flex",
                justifyContent: "flex-end",
                gap: "12px",
              }}
            >
              <button
                onClick={() => {
                  setShowNewScan(false);
                  setScanUrl("");
                }}
                style={{
                  backgroundColor: "transparent",
                  color: "#94AFC7",
                  border: "1px solid #334155",
                  borderRadius: "8px",
                  padding: "10px 16px",
                  cursor: "pointer",
                }}
              >
                Cancelar
              </button>

              <button
                style={{
                  backgroundColor: "#1677FF",
                  color: "white",
                  border: "none",
                  borderRadius: "8px",
                  padding: "10px 18px",
                  cursor: "pointer",
                  fontWeight: "bold",
                }}
              >
                Iniciar escaneo
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}

export default Dashboard;