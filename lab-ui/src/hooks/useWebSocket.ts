"use client";

import { useEffect, useRef, useState, useCallback } from "react";

const RECONNECT_DELAY = 3000;
const RETRY_DELAY = 3000;

export interface WebSocketMessage {
  type: string;
  id?: string;
  timestamp?: string;
  ja3?: string;
  ja4?: string;
  cipher_count?: number;
  host?: string;
  message?: string;
  source_ip?: string;
  dest_ip?: string;
  protocol?: string;
  length?: number;
  info?: string;
  // v3 assessment fields
  action?: string;
  v3_score?: number;
  detection_score?: number;
  behavioral_score?: number;
  event_count?: number;
  vector_count?: number;
  indicator_count?: number;
  // shield detection fields
  catch_rate?: number;
  avg_score?: number;
  threshold?: number;
  profile_count?: number;
}

interface UseWebSocketOptions {
  onFingerprint?: (msg: WebSocketMessage) => void;
  onPacket?: (msg: WebSocketMessage) => void;
  onTrainingSample?: (msg: WebSocketMessage) => void;
  onV3Assessment?: (msg: WebSocketMessage) => void;
  onShieldDetection?: (msg: WebSocketMessage) => void;
  onConnected?: () => void;
  onDisconnected?: () => void;
}

/** Get the WebSocket URL based on the current window location */
function getWebSocketUrl(): string {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  return `${protocol}//${window.location.host}/ws`;
}

/** Process incoming WebSocket messages */
function handleMessage(event: MessageEvent, options: UseWebSocketOptions): void {
  try {
    const msg: WebSocketMessage = JSON.parse(event.data);
    if (msg.type === "fingerprint") options.onFingerprint?.(msg);
    else if (msg.type === "packet_event") options.onPacket?.(msg);
    else if (msg.type === "training_sample") options.onTrainingSample?.(msg);
    else if (msg.type === "v3_assessment") options.onV3Assessment?.(msg);
    else if (msg.type === "shield_detection") options.onShieldDetection?.(msg);
  } catch {
    // ignore parse errors
  }
}

interface WebSocketCallbacks {
  setConnected: (value: boolean) => void;
  setWsRef: (ws: WebSocket | null) => void;
  scheduleReconnect: () => void;
  options: UseWebSocketOptions;
}

/** Create and configure a WebSocket instance */
function createWebSocket(url: string, cbs: WebSocketCallbacks): WebSocket {
  const ws = new WebSocket(url);
  ws.onopen = () => {
    cbs.setConnected(true);
    cbs.options.onConnected?.();
  };
  ws.onmessage = event => handleMessage(event, cbs.options);
  ws.onerror = () => {};
  ws.onclose = () => {
    cbs.setConnected(false);
    cbs.setWsRef(null);
    cbs.options.onDisconnected?.();
    cbs.scheduleReconnect();
  };
  return ws;
}

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const [connected, setConnected] = useState(false);
  const optionsRef = useRef(options);

  useEffect(() => {
    optionsRef.current = options;
  }, [options]);

  const connectRef = useRef<() => void>(() => {});

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    try {
      wsRef.current = createWebSocket(getWebSocketUrl(), {
        setConnected,
        setWsRef: w => {
          wsRef.current = w;
        },
        scheduleReconnect: () => {
          reconnectTimer.current = setTimeout(() => connectRef.current?.(), RECONNECT_DELAY);
        },
        options: optionsRef.current,
      });
    } catch {
      reconnectTimer.current = setTimeout(() => connectRef.current?.(), RETRY_DELAY);
    }
  }, []);

  useEffect(() => {
    connectRef.current = connect;
  }, [connect]);

  useEffect(() => {
    connect();
    return () => {
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return { connected };
}
