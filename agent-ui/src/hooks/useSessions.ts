"use client";

import { useState, useCallback } from "react";
import { listSessions, createSession, getSession } from "@/lib/api";
import type { Session } from "@/lib/types";

export function useSessions() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listSessions();
      setSessions(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load sessions");
    } finally {
      setLoading(false);
    }
  }, []);

  const create = useCallback(async (title: string) => {
    setError(null);
    try {
      const session = await createSession({ title });
      setSessions((prev) => [...prev, session]);
      return session;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create session");
      throw err;
    }
  }, []);

  const loadOne = useCallback(async (id: string) => {
    return getSession(id);
  }, []);

  return { sessions, loading, error, refresh, create, loadOne };
}
