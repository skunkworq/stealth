"use client";

import { useState, useEffect, useCallback } from "react";

export interface TrainingSample {
  id: string;
  timestamp: string;
  type: string;
  label: string;
  bot_score: number;
  solve_time_ms: number;
  challenge_id: string;
}

export interface TrainingStats {
  total_samples: number;
  by_type: Record<string, number>;
  by_label: Record<string, number>;
  avg_bot_score: number;
}

export interface TrainingFilters {
  type: string;
  label: string;
  minScore: number;
  maxScore: number;
  limit: number;
  offset: number;
}

const DEFAULT_FILTERS: TrainingFilters = {
  type: "all",
  label: "all",
  minScore: 0,
  maxScore: 1,
  limit: 20,
  offset: 0,
};

function buildSearchParams(filters: TrainingFilters): URLSearchParams {
  const params = new URLSearchParams();
  if (filters.type !== "all") params.set("type", filters.type);
  if (filters.label !== "all") params.set("label", filters.label);
  if (filters.minScore > 0) params.set("min_score", String(filters.minScore));
  if (filters.maxScore < 1) params.set("max_score", String(filters.maxScore));
  params.set("limit", String(filters.limit));
  params.set("offset", String(filters.offset));
  return params;
}

async function fetchSamples(
  filters: TrainingFilters
): Promise<{ samples: TrainingSample[]; total: number }> {
  const params = buildSearchParams(filters);
  const res = await fetch(`/api/training/samples?${params.toString()}`);
  return res.ok ? res.json() : { samples: [], total: 0 };
}

async function fetchStats(): Promise<TrainingStats | null> {
  try {
    const res = await fetch("/api/training/stats");
    return res.ok ? res.json() : null;
  } catch {
    return null;
  }
}

export function useTrainingData() {
  const [samples, setSamples] = useState<TrainingSample[]>([]);
  const [stats, setStats] = useState<TrainingStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [totalCount, setTotalCount] = useState(0);
  const [filters, setFilters] = useState<TrainingFilters>(DEFAULT_FILTERS);

  const fetchData = useCallback(async () => {
    setLoading(true);
    try {
      const [samplesRes, statsRes] = await Promise.all([fetchSamples(filters), fetchStats()]);
      setSamples(samplesRes.samples ?? []);
      setTotalCount(samplesRes.total ?? 0);
      if (statsRes) setStats(statsRes);
    } catch (err) {
      console.error("Failed to fetch training data:", err);
    } finally {
      setLoading(false);
    }
  }, [filters]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const refresh = useCallback(() => fetchData(), [fetchData]);

  const exportCSV = useCallback(async () => {
    try {
      const res = await fetch("/api/training/export?format=csv");
      if (!res.ok) throw new Error("Export failed");
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `training-data-${Date.now()}.csv`;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Failed to export CSV:", err);
    }
  }, []);

  return { samples, stats, loading, filters, setFilters, totalCount, refresh, exportCSV };
}
