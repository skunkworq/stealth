"use client";

import { useEffect, useRef, useCallback } from "react";
import { WSClient } from "@/lib/websocket";
import type { AgentEvent } from "@/lib/types";

export function useWebSocket(onMessage: (ev: AgentEvent) => void) {
  const clientRef = useRef<WSClient | null>(null);

  useEffect(() => {
    const client = new WSClient();
    client.connect(onMessage);
    clientRef.current = client;
    return () => client.disconnect();
  }, [onMessage]);

  const subscribe = useCallback((sessionId: string) => {
    clientRef.current?.subscribe(sessionId);
  }, []);

  return { subscribe };
}
