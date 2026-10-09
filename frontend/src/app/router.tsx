import Findings from "../features/findings/pages/FindingsPage";
import Reports from "../features/reports/pages/ReportsPage";
import Scans from "../features/scans/pages/ScansPage";
import Settings from "../features/settings/pages/SettingsPage";
import Sites from "../features/sites/pages/SitesPage";
import type { AdminPage } from "../shared/types/navigation";
import Dashboard from "./pages/DashboardPage";

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
  { id: "settings", labelKey: "menu.settings", icon: "⚙️" },
];

export function AdminRouter({
  activePage,
}: {
  activePage: AdminPage;
}) {
  switch (activePage) {
    case "sites":
      return <Sites />;
    case "scans":
      return <Scans />;
    case "findings":
      return <Findings />;
    case "reports":
      return <Reports />;
    case "settings":
      return <Settings />;
    case "dashboard":
    default:
      return <Dashboard />;
  }
}
