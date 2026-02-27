"use client";

import { useEffect, useRef, useCallback, useState } from "react";

export interface WebSocketMessage {
  type: string;
  id?: string;
  timestamp?: string;
  ja3?: string;
  ja4?: string;
  cipher_count?: number;
  host?: string;
  message?: string;
  // For packets
  source_ip?: string;
  dest_ip?: string;
  protocol?: string;
  length?: number;
  info?: string;
}

interface UseWebSocketOptions {
  onFingerprint?: (msg: WebSocketMessage) => void;
  onPacket?: (msg: WebSocketMessage) => void;
  onConnected?: () => void;
  onDisconnected?: () => void;
}

export function useWebSocket({ onFingerprint, onPacket, onConnected, onDisconnected }: UseWebSocketOptions = {}) {
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const [connected, setConnected] = useState(false);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${protocol}//${window.location.host}/ws`;

    try {
      const ws = new WebSocket(url);

      ws.onopen = () => {
        setConnected(true);
        onConnected?.();
      };

      ws.onmessage = (event) => {
        try {
          const msg: WebSocketMessage = JSON.parse(event.data);
          if (msg.type === "fingerprint") {
            onFingerprint?.(msg);
          } else if (msg.type === "packet_event") {
            onPacket?.(msg);
          }
        } catch {
          // ignore parse errors
        }
      };

      ws.onerror = () => {
        // Will trigger onclose
      };

      ws.onclose = () => {
        setConnected(false);
        wsRef.current = null;
        onDisconnected?.();
        // Reconnect after 3 seconds
        reconnectTimer.current = setTimeout(connect, 3000);
      };

      wsRef.current = ws;
    } catch {
      // Connection failed, retry
      reconnectTimer.current = setTimeout(connect, 3000);
    }
  }, [onFingerprint, onPacket, onConnected, onDisconnected]);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return { connected };
}
