"use client";

import { useState, useCallback } from "react";
import type { ShieldEvalResponse } from "./types";

export function useShieldData() {
  const [data, setData] = useState<ShieldEvalResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runEvaluation = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/shield/evaluate");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json: ShieldEvalResponse = await res.json();
      setData(json);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, []);

  return { data, loading, error, runEvaluation };
}
