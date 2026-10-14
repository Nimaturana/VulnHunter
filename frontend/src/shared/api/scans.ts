import { API_BASE_URL, apiRequest } from "./client";

export const SCANNERS = [
  "xss",
  "sql_injection",
  "security_headers",
  "ssl_tls",
  "directory_scan",
] as const;

export type ScanStatus =
  | "pending"
  | "running"
  | "completed"
  | "partial"
  | "failed";

export type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type ScanSummary = {
  scan_id: string;
  url: string;
  status: ScanStatus;
  total_vulnerabilities: number;
  risk_level: RiskLevel;
  started_at: string;
  completed_at: string | null;
  progress_percentage: number;
  current_scanner: string | null;
  task_id: string | null;
  execution_mode: "background" | "celery";
  queued_at: string | null;
  report_status: "not_generated" | "generating" | "generated" | "failed";
};

export type Finding = {
  type: string;
  severity: RiskLevel;
  location: string;
  scanner: string;
  description: string;
  recommendation: string;
  evidence: string;
  confidence: "high" | "medium" | "low";
};

export type ScanDetail = Omit<ScanSummary, "total_vulnerabilities"> & {
  scan_types: string[];
  results: Record<string, unknown>;
  vulnerabilities: Finding[];
  total_vulnerabilities: number;
  risk_score: number;
  errors: Record<string, string>;
  progress: {
    percentage: number;
    completed_scanners: number;
    total_scanners: number;
    current_scanner: string | null;
  };
};

export type SystemStats = {
  total_scans: number;
  by_status: Record<ScanStatus, number>;
  total_vulnerabilities: number;
  storage: string;
};

export type StartScanResponse = {
  scan_id: string;
  status: ScanStatus;
  task_id: string | null;
  execution_mode: "background" | "celery";
  scanners_enabled: string[];
  check_status_url: string;
};

export type ReportInfo = {
  scan_id: string;
  status: "generating" | "generated" | "failed";
  file_name: string | null;
  size_bytes: number | null;
  sha256: string | null;
  generated_at: string | null;
  download_count: number;
  last_downloaded_at: string | null;
};

export function listScans(): Promise<ScanSummary[]> {
  return apiRequest<ScanSummary[]>("/scans?limit=100");
}

export function getScan(scanId: string): Promise<ScanDetail> {
  return apiRequest<ScanDetail>(`/scans/${encodeURIComponent(scanId)}`);
}

export function getStatistics(): Promise<SystemStats> {
  return apiRequest<SystemStats>("/stats");
}

export function getReportInfo(scanId: string): Promise<ReportInfo> {
  return apiRequest<ReportInfo>(`/scans/${encodeURIComponent(scanId)}/report`);
}

export function startScan(url: string): Promise<StartScanResponse> {
  return apiRequest<StartScanResponse>("/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      url,
      scan_types: [...SCANNERS],
      description: "Escaneo iniciado desde el frontend de VulnHunter",
    }),
  });
}

export function reportUrl(scanId: string): string {
  return `${API_BASE_URL}/scans/${encodeURIComponent(scanId)}/report.pdf`;
}

export function formatDate(value: string | null): string {
  if (!value) return "En curso";
  return new Intl.DateTimeFormat("es-CL", {
    dateStyle: "short",
    timeStyle: "short",
  }).format(new Date(value));
}

export const STATUS_LABELS: Record<ScanStatus, string> = {
  pending: "Pendiente",
  running: "Ejecutándose",
  completed: "Completado",
  partial: "Completado con advertencias",
  failed: "Fallido",
};

export const RISK_LABELS: Record<RiskLevel, string> = {
  CRITICAL: "CRÍTICO",
  HIGH: "ALTO",
  MEDIUM: "MEDIO",
  LOW: "BAJO",
  INFO: "INFORMATIVO",
};

export function riskColor(level: RiskLevel): string {
  return {
    CRITICAL: "#ef4444",
    HIGH: "#f97316",
    MEDIUM: "#eab308",
    LOW: "#22c55e",
    INFO: "#60a5fa",
  }[level];
}
