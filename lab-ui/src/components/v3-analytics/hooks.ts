"use client";

import { useEffect, useState, useRef, useCallback, useMemo } from "react";
import type { V3Assessment, V3Metrics } from "./types";
import { REFETCH_DELAY_MS } from "./constants";

const POLL_INTERVAL_MS = 5000;

export function useV3Data() {
  const [assessments, setAssessments] = useState<V3Assessment[]>([]);
  const [metrics, setMetrics] = useState<V3Metrics | null>(null);
  const loadRef = useRef<(() => Promise<void>) | null>(null);

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const [aRes, mRes] = await Promise.all([
          fetch("/api/recaptcha/v3/assessments"),
          fetch("/api/recaptcha/v3/metrics"),
        ]);
        if (!active) return;
        if (aRes.ok) setAssessments(await aRes.json());
        if (mRes.ok) setMetrics(await mRes.json());
      } catch (err) {
        console.error("Failed to fetch v3 data:", err);
      }
    };
    loadRef.current = load;
    const id = setInterval(load, POLL_INTERVAL_MS);
    load();
    return () => {
      active = false;
      clearInterval(id);
    };
  }, []);

  const refetch = useCallback(async () => {
    await loadRef.current?.();
  }, []);

  return { assessments, metrics, refetch };
}

/** Derive the selected assessment from explicit selection or latest arrival. */
export function useSelectedAssessment(assessments: V3Assessment[]) {
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const selected = useMemo(() => {
    if (selectedId) {
      const found = assessments.find(a => a.id === selectedId);
      if (found) return found;
    }
    // Fall back to latest
    return assessments.length > 0 ? assessments[assessments.length - 1] : null;
  }, [assessments, selectedId]);

  const select = useCallback((record: V3Assessment) => {
    setSelectedId(record.id);
  }, []);

  return { selected, select };
}

/** Wraps the v3 assess POST + delayed refetch. */
export function useV3Assess(refetch: () => Promise<void>) {
  return useCallback(
    async (action: string) => {
      try {
        await fetch("/api/recaptcha/v3/assess", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ action, events: [] }),
        });
        setTimeout(() => refetch(), REFETCH_DELAY_MS);
      } catch (err) {
        console.error("v3 assess failed:", err);
      }
    },
    [refetch]
  );
}
