import type { CSSProperties } from "react";

import { theme } from "./theme";

export const pageStyle: CSSProperties = {
  flex: 1,
  padding: "32px",
  minWidth: 0,
};

export const cardStyle: CSSProperties = {
  backgroundColor: theme.colors.surface,
  border: `1px solid ${theme.colors.border}`,
  borderRadius: "12px",
  padding: "22px",
};

export const tableWrapStyle: CSSProperties = {
  overflowX: "auto",
};

export const tableStyle: CSSProperties = {
  width: "100%",
  minWidth: "760px",
  borderCollapse: "collapse",
  textAlign: "left",
};

export const tableCellStyle: CSSProperties = {
  padding: "14px 10px",
  borderBottom: "1px solid #1e293b",
};

export const primaryButtonStyle: CSSProperties = {
  backgroundColor: theme.colors.primary,
  color: "#FFFFFF",
  border: `1px solid ${theme.colors.accent}`,
  borderRadius: "8px",
  padding: "10px 16px",
  cursor: "pointer",
  fontWeight: 700,
  textDecoration: "none",
  display: "inline-block",
};

export const secondaryButtonStyle: CSSProperties = {
  backgroundColor: "transparent",
  color: theme.colors.accent,
  border: `1px solid ${theme.colors.accent}`,
  borderRadius: "8px",
  padding: "9px 13px",
  cursor: "pointer",
  textDecoration: "none",
  display: "inline-block",
};

export const errorStyle: CSSProperties = {
  padding: "12px 14px",
  marginBottom: "18px",
  borderRadius: "8px",
  border: "1px solid #ef4444",
  color: "#fecaca",
  backgroundColor: "rgba(127, 29, 29, 0.25)",
};

export const successStyle: CSSProperties = {
  padding: "12px 14px",
  marginBottom: "18px",
  borderRadius: "8px",
  border: "1px solid #22c55e",
  color: "#bbf7d0",
  backgroundColor: "rgba(20, 83, 45, 0.25)",
};
