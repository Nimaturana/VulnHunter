export type Screen = "welcome" | "login" | "app";

export type UserRole = "analyst" | "user" | "guest" | null;

export type AdminPage =
  | "dashboard"
  | "sites"
  | "scans"
  | "findings"
  | "reports"
  | "auditors"
  | "settings";
