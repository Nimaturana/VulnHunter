import Findings from "../features/findings/pages/FindingsPage";
import Reports from "../features/reports/pages/ReportsPage";
import Scans from "../features/scans/pages/ScansPage";
import Settings from "../features/settings/pages/SettingsPage";
import Sites from "../features/sites/pages/SitesPage";
import type { AdminPage } from "../shared/types/navigation";
import Dashboard from "./pages/DashboardPage";
import Auditors from "../features/auditors/pages/AuditorsPage";
import type { Usuario } from "../shared/api/auth";

export const ADMIN_NAVIGATION: ReadonlyArray<{
  id: AdminPage;
  labelKey: string;
  icon: string;
}> = [
  { id: "dashboard", labelKey: "menu.dashboard", icon: "🏠" },
  { id: "sites", labelKey: "menu.sites", icon: "🌐" },
  { id: "scans", labelKey: "menu.scans", icon: "🔍" },
  { id: "findings", labelKey: "menu.findings", icon: "⚠️" },
  { id: "reports", labelKey: "menu.reports", icon: "📄" },
  { id: "auditors", labelKey: "menu.auditors", icon: "👥" },
  { id: "settings", labelKey: "menu.settings", icon: "⚙️" },
];

export const GUEST_NAVIGATION = ADMIN_NAVIGATION.filter(
  (item) => item.id !== "settings" && item.id !== "auditors",
);

export const AUDITOR_NAVIGATION = ADMIN_NAVIGATION.filter(
  (item) => item.id !== "settings" && item.id !== "auditors",
);

export function AdminRouter({
  activePage,
  readOnly = false,
  currentUser,
  onNavigate,
}: {
  activePage: AdminPage;
  readOnly?: boolean;
  currentUser: Usuario | null;
  onNavigate: (page: AdminPage) => void;
}) {
  switch (activePage) {
    case "sites":
      return <Sites readOnly={readOnly} currentUser={currentUser} />;
    case "scans":
      return <Scans readOnly={readOnly} currentUser={currentUser} />;
    case "findings":
      return <Findings readOnly={readOnly} currentUser={currentUser} />;
    case "reports":
      return <Reports readOnly={readOnly} currentUser={currentUser} />;
    case "auditors":
      return <Auditors />;
    case "settings":
      return <Settings />;
    case "dashboard":
    default:
      return <Dashboard readOnly={readOnly} currentUser={currentUser} onNewScan={() => onNavigate("scans")} />;
  }
}
