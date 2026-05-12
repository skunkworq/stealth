import type { AgentEvent } from "./types";

export type WSControlMessage = {
  type: "subscribe";
  session_id: string;
};

export function createWebSocketUrl(): string {
  const protocol = typeof window !== "undefined" && window.location.protocol === "https:" ? "wss:" : "ws:";
  const host = process.env.NEXT_PUBLIC_WS_HOST ?? (typeof window !== "undefined" ? window.location.host : "localhost:8080");
  return `${protocol}//${host}/ws`;
}

export class WSClient {
  private ws: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private onMessage: ((ev: AgentEvent) => void) | null = null;
  private pendingSubscribe: string | null = null;

  connect(onMessage: (ev: AgentEvent) => void) {
    this.onMessage = onMessage;
    this.tryConnect();
  }

  private tryConnect() {
    if (this.ws?.readyState === WebSocket.OPEN) return;

    const url = createWebSocketUrl();
    this.ws = new WebSocket(url);

    this.ws.onopen = () => {
      console.log("[WS] connected");
      if (this.pendingSubscribe) {
        this.subscribe(this.pendingSubscribe);
      }
    };

    this.ws.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data) as AgentEvent;
        this.onMessage?.(data);
      } catch (err) {
        console.error("[WS] parse error", err);
      }
    };

    this.ws.onclose = () => {
      console.log("[WS] disconnected, reconnecting in 3s...");
      this.reconnectTimer = setTimeout(() => this.tryConnect(), 3000);
    };

    this.ws.onerror = (err) => {
      console.error("[WS] error", err);
    };
  }

  subscribe(sessionId: string) {
    this.pendingSubscribe = sessionId;
    if (this.ws?.readyState === WebSocket.OPEN) {
      const msg: WSControlMessage = { type: "subscribe", session_id: sessionId };
      this.ws.send(JSON.stringify(msg));
    }
  }

  disconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.ws?.close();
    this.ws = null;
  }
}
