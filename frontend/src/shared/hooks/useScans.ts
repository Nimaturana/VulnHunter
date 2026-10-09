import { useCallback, useEffect, useState } from "react";

import { listScans, type ScanSummary } from "../api/scans";

export function useScans(pollInterval = 2500) {
  const [scans, setScans] = useState<ScanSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const data = await listScans();
      setScans(data);
      setError(null);
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : "No fue posible conectar con VulnHunter API",
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    const hasActiveScan = scans.some(
      (scan) => scan.status === "pending" || scan.status === "running",
    );
    if (!hasActiveScan) return undefined;

    const timer = window.setInterval(() => void refresh(), pollInterval);
    return () => window.clearInterval(timer);
  }, [pollInterval, refresh, scans]);

  return { scans, loading, error, refresh };
}
