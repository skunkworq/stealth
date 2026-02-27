"use client";

import { FingerprintProvider, useFingerprint } from "@/components/FingerprintProvider";
import { OverviewCard } from "@/components/OverviewCard";
import { TLSPanel } from "@/components/TLSPanel";
import { HTTP2Panel } from "@/components/HTTP2Panel";
import { HTTPPanel } from "@/components/HTTPPanel";
import { ConfigPanel } from "@/components/ConfigPanel";
import { BuildOutput } from "@/components/BuildOutput";
import { ControlPanel } from "@/components/ControlPanel";
import { CaptureHistory } from "@/components/CaptureHistory";
import { PacketAnalysisPanel } from "@/components/PacketAnalysisPanel";
import { SignatureTester } from "@/components/SignatureTester";
import { useWebSocket, WebSocketMessage } from "@/hooks/useWebSocket";
import { useToasts, ToastContainer } from "@/components/Toasts";
import { useCallback, useState } from "react";

export default function Home() {
  return (
    <FingerprintProvider>
      <AppContent />
    </FingerprintProvider>
  );
}

function AppContent() {
  const { refresh } = useFingerprint();
  const { toasts, addToast } = useToasts();
  const [wsConnected, setWsConnected] = useState(false);
  const [packets, setPackets] = useState<WebSocketMessage[]>([]);

  const handleFingerprint = useCallback((msg: WebSocketMessage) => {
    const host = msg.host || "Unknown";
    const ja3 = msg.ja3 ? msg.ja3.substring(0, 16) + "…" : "N/A";
    addToast("🔒 Fingerprint Captured", `${host} • ${ja3}`);
    // Auto-refresh to show latest data
    refresh();
  }, [addToast, refresh]);

  const handlePacket = useCallback((msg: WebSocketMessage) => {
    setPackets(prev => {
      const next = [...prev, msg];
      if (next.length > 2000) return next.slice(next.length - 2000);
      return next;
    });
  }, []);

  useWebSocket({
    onFingerprint: handleFingerprint,
    onPacket: handlePacket,
    onConnected: () => setWsConnected(true),
    onDisconnected: () => setWsConnected(false),
  });

  return (
    <div className="min-h-screen bg-background">
      <Header wsConnected={wsConnected} />
      <main className="max-w-[1600px] mx-auto px-4 sm:px-6 py-6">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Left column: fingerprint panels */}
          <div className="lg:col-span-7 xl:col-span-8 space-y-5">
            <OverviewCard />
            <TLSPanel />
            <HTTP2Panel />
            <HTTPPanel />
            <CaptureHistory />
            <PacketAnalysisPanel packets={packets} />
          </div>

          {/* Right column: config + build output (sticky) */}
          <div className="lg:col-span-5 xl:col-span-4">
            <div className="lg:sticky lg:top-6 space-y-5">
              <ControlPanel />
              <ConfigPanel />
              <BuildOutput />
            </div>
          </div>
        </div>
      </main>
      <Footer />
      <ToastContainer toasts={toasts} />
    </div>
  );
}

function Header({ wsConnected }: { wsConnected: boolean }) {
  return (
    <header className="skeuo-panel border-x-0 border-t-0 rounded-none">
      <div className="max-w-[1600px] mx-auto px-4 sm:px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            {/* "Hardware" logo area */}
            <div className="skeuo-inset rounded-lg p-2 flex items-center gap-2">
              <span className="text-xl">🔬</span>
              <div className="w-px h-6 bg-border/30" />
              <div className="flex flex-col">
                <span className="led-green" />
              </div>
            </div>
            <div>
              <h1 className="text-base sm:text-lg font-bold tracking-tight text-foreground">
                Browser Fingerprint Lab
              </h1>
              <p className="text-xs text-muted-foreground">
                Capture, analyze, and compare browser signatures
              </p>
            </div>
          </div>
          <div className="hidden sm:flex items-center gap-3">
            <StatusIndicator wsConnected={wsConnected} />
          </div>
        </div>
      </div>
    </header>
  );
}

function StatusIndicator({ wsConnected }: { wsConnected: boolean }) {
  const { fingerprint, loading, error } = useFingerprint();

  return (
    <div className="skeuo-inset rounded-lg px-3 py-2 flex items-center gap-3">
      <div className="flex items-center gap-1.5">
        <span className={loading ? "led-amber" : error ? "led-red" : "led-green"} />
        <span className="text-[10px] text-muted-foreground uppercase tracking-wider">
          {loading ? "Capturing" : error ? "Error" : "Ready"}
        </span>
      </div>
      <div className="w-px h-4 bg-border/30" />
      <div className="flex items-center gap-1.5">
        <span className={wsConnected ? "led-green" : "led-red"} />
        <span className="text-[10px] text-muted-foreground uppercase tracking-wider">
          WS
        </span>
      </div>
      {fingerprint && (
        <>
          <div className="w-px h-4 bg-border/30" />
          <span className="text-[10px] font-mono text-muted-foreground">
            {fingerprint.id.slice(0, 12)}
          </span>
        </>
      )}
    </div>
  );
}

function Footer() {
  return (
    <footer className="border-t border-border/30 mt-8">
      <div className="max-w-[1600px] mx-auto px-4 sm:px-6 py-4">
        <div className="flex items-center justify-between text-xs text-muted-foreground/50">
          <span>Browser Fingerprint Lab • TLS / HTTP2 / HTTP</span>
          <div className="flex items-center gap-2">
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-glow/40" />
            <span>System Online</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
