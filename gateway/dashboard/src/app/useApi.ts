import { useCallback, useEffect, useState } from "react";
import { apiGet, ApiError } from "@/api";

// Fetch a JSON endpoint on mount; returns { data, loading, reload }. On a 401 it
// calls onAuthExpired so the app can bounce to the login screen.
export function useApi<T = any>(path: string, onAuthExpired?: () => void) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);

  const reload = useCallback(() => {
    setLoading(true);
    apiGet<T>(path)
      .then((d) => setData(d))
      .catch((e) => { if (e instanceof ApiError && e.status === 401) onAuthExpired?.(); })
      .finally(() => setLoading(false));
  }, [path, onAuthExpired]);

  useEffect(() => { reload(); }, [reload]);
  return { data, loading, reload };
}
