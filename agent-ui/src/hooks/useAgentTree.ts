"use client";

import { useState, useCallback } from "react";
import { getAgentTree } from "@/lib/api";
import type { AgentInfo } from "@/lib/types";

export function useAgentTree() {
  const [tree, setTree] = useState<AgentInfo | null>(null);
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async (sessionId: string) => {
    setLoading(true);
    try {
      const data = await getAgentTree(sessionId);
      setTree(data);
    } finally {
      setLoading(false);
    }
  }, []);

  return { tree, loading, refresh };
}
