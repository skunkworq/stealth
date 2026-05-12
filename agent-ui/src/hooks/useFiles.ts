"use client";

import { useState, useCallback } from "react";
import { listFiles } from "@/lib/api";

export function useFiles() {
  const [files, setFiles] = useState<Record<string, string[]>>({});
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async (sessionId: string) => {
    setLoading(true);
    try {
      const data = await listFiles(sessionId);
      setFiles(data);
    } finally {
      setLoading(false);
    }
  }, []);

  return { files, loading, refresh };
}
