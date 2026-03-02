"use client";

import dynamic from "next/dynamic";
import {
  FingerprintProvider,
  useFingerprintRefresh,
  useFingerprint,
} from "@/components/FingerprintProvider";
import { OverviewCard } from "@/components/OverviewCard";
import { TLSPanel } from "@/components/TLSPanel";
import { HTTP2Panel } from "@/components/HTTP2Panel";
import { HTTPPanel } from "@/components/HTTPPanel";
import { ConfigPanel } from "@/components/ConfigPanel";
import { BuildOutput } from "@/components/BuildOutput";
import { ControlPanel } from "@/components/ControlPanel";
import { CaptureHistory } from "@/components/CaptureHistory";
import { PacketAnalysisPanel } from "@/components/PacketAnalysisPanel";
import { useWebSocket, WebSocketMessage } from "@/hooks/useWebSocket";
import { useToasts, ToastContainer } from "@/components/Toasts";
import { useCallback, useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { SCORE_DECIMAL_PLACES } from "@/components/v3-analytics/constants";

const MAIN_CONTENT_ID = "main-content";
const FINGERPRINT_ID_PREVIEW_LENGTH = 12;
const JA3_PREVIEW_LENGTH = 16;
const MAX_PACKETS = 2000;

const CaptchaDashboard = dynamic(
  () => import("@/components/CaptchaDashboard").then(m => ({ default: m.CaptchaDashboard })),
  {
    loading: () => (
      <div className="p-12 text-center text-muted-foreground animate-pulse font-mono text-xs">
        LOADING_CAPTCHA_MODULE…
      </div>
    ),
  }
);

const FingerprintViewer = dynamic(
  () => import("@/components/FingerprintViewer").then(m => ({ default: m.FingerprintViewer })),
  {
    loading: () => (
      <div className="p-12 text-center text-muted-foreground animate-pulse font-mono text-xs">
        LOADING_FINGERPRINT_MODULE…
      </div>
    ),
  }
);

const FingerprintComparison = dynamic(
  () =>
    import("@/components/FingerprintComparison").then(m => ({ default: m.FingerprintComparison })),
  {
    loading: () => (
      <div className="p-12 text-center text-muted-foreground animate-pulse font-mono text-xs">
        LOADING_COMPARISON_MODULE…
      </div>
    ),
  }
);

const ReCaptchaWidget = dynamic(
  () => import("@/components/ReCaptchaWidget").then(m => ({ default: m.ReCaptchaWidget })),
  {
    loading: () => (
      <div className="p-12 text-center text-muted-foreground animate-pulse font-mono text-xs">
        LOADING_RECAPTCHA_MODULE…
      </div>
    ),
  }
);

const V3AnalyticsDashboard = dynamic(
  () =>
    import("@/components/v3-analytics").then(m => ({
      default: m.V3AnalyticsDashboard,
    })),
  {
    loading: () => (
      <div className="p-12 text-center text-muted-foreground animate-pulse font-mono text-xs">
        LOADING_V3_ANALYTICS…
      </div>
    ),
  }
);

const ShieldDashboard = dynamic(
  () =>
    import("@/components/shield-dashboard").then(m => ({
      default: m.ShieldDashboard,
    })),
  {
    loading: () => (
      <div className="p-12 text-center text-muted-foreground animate-pulse font-mono text-xs">
        LOADING_SHIELD_MODULE…
      </div>
    ),
  }
);

export default function Home() {
  return (
    <FingerprintProvider>
      <AppContent />
    </FingerprintProvider>
  );
}

function useAppState() {
  const refresh = useFingerprintRefresh();
  const { addToast } = useToasts();
  const [wsConnected, setWsConnected] = useState(false);
  const [packets, setPackets] = useState<WebSocketMessage[]>([]);
  const [activeTab, setActiveTab] = useState("analysis");

  const handleFingerprint = useCallback(
    (msg: WebSocketMessage) => {
      const host = msg.host || "Unknown";
      const ja3 = msg.ja3 ? `${msg.ja3.substring(0, JA3_PREVIEW_LENGTH)}…` : "N/A";
      addToast("🔒 Fingerprint Captured", `${host} • ${ja3}`);
      refresh();
    },
    [addToast, refresh]
  );

  const handlePacket = useCallback((msg: WebSocketMessage) => {
    setPackets(prev => {
      const next = [...prev, msg];
      if (next.length > MAX_PACKETS) return next.slice(next.length - MAX_PACKETS);
      return next;
    });
  }, []);

  const handleV3Assessment = useCallback(
    (msg: WebSocketMessage) => {
      const action = msg.action || "unknown";
      const score = msg.v3_score?.toFixed(SCORE_DECIMAL_PLACES) ?? "N/A";
      addToast("v3 Assessment", `${action} • score ${score}`);
    },
    [addToast]
  );

  const handleShieldDetection = useCallback(
    (msg: WebSocketMessage) => {
      const rate = msg.catch_rate != null ? `${(msg.catch_rate * 100).toFixed(0)}%` : "N/A";
      const avg = msg.avg_score?.toFixed(3) ?? "N/A";
      addToast("Shield Detection", `catch ${rate} • avg ${avg}`);
    },
    [addToast]
  );

  useWebSocket({
    onFingerprint: handleFingerprint,
    onPacket: handlePacket,
    onV3Assessment: handleV3Assessment,
    onShieldDetection: handleShieldDetection,
    onConnected: () => setWsConnected(true),
    onDisconnected: () => setWsConnected(false),
  });

  return { wsConnected, packets, activeTab, setActiveTab };
}

function SkipLink() {
  return (
    <a
      href={`#${MAIN_CONTENT_ID}`}
      className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-[10001] focus:px-4 focus:py-2 focus:bg-background focus:border focus:border-cyan-glow"
    >
      Skip to main content
    </a>
  );
}

function ModeLabel({ activeTab }: { activeTab: string }) {
  const mode =
    activeTab === "analysis"
      ? "FINGERPRINT_EXTRACTION"
      : activeTab === "captcha"
        ? "ADVERSARIAL_TELEMETRY"
        : activeTab === "recaptcha"
          ? "RECAPTCHA_ANALYSIS"
          : activeTab === "shield"
            ? "SHIELD_EVALUATION"
          : "ML_TRAINING_PIPELINE";

  return (
    <div className="hidden md:flex items-center gap-2">
      <div className="h-px w-24 bg-gradient-to-r from-transparent to-border/30" />
      <span className="text-[10px] text-muted-foreground/40 font-mono uppercase tracking-tighter">
        Mode: {mode}
      </span>
    </div>
  );
}

function TabNavigation() {
  return (
    <TabsList className="skeuo-inset bg-black/40 border-border/10">
      <TabsTrigger
        value="analysis"
        className="data-[state=active]:skeuo-panel data-[state=active]:text-cyan-glow uppercase text-[10px] font-bold tracking-widest px-6"
      >
        Analysis
      </TabsTrigger>
      <TabsTrigger
        value="captcha"
        className="data-[state=active]:skeuo-panel data-[state=active]:text-amber-glow uppercase text-[10px] font-bold tracking-widest px-6"
      >
        CAPTCHA
      </TabsTrigger>
      <TabsTrigger
        value="recaptcha"
        className="data-[state=active]:skeuo-panel data-[state=active]:text-emerald-glow uppercase text-[10px] font-bold tracking-widest px-6"
      >
        reCAPTCHA
      </TabsTrigger>
      <TabsTrigger
        value="training"
        className="data-[state=active]:skeuo-panel data-[state=active]:text-purple-glow uppercase text-[10px] font-bold tracking-widest px-6"
      >
        Training
      </TabsTrigger>
      <TabsTrigger
        value="shield"
        className="data-[state=active]:skeuo-panel data-[state=active]:text-red-glow uppercase text-[10px] font-bold tracking-widest px-6"
      >
        Shield
      </TabsTrigger>
    </TabsList>
  );
}

function MainContent({ packets }: { packets: WebSocketMessage[] }) {
  return (
    <TabsContent value="analysis" className="space-y-5 mt-0">
      <OverviewCard />
      <TLSPanel />
      <HTTP2Panel />
      <HTTPPanel />
      <CaptureHistory />
      <PacketAnalysisPanel packets={packets} />
    </TabsContent>
  );
}

function CaptchaContent() {
  return (
    <TabsContent value="captcha" className="mt-0">
      <CaptchaDashboard />
    </TabsContent>
  );
}

function ReCaptchaContent() {
  return (
    <TabsContent value="recaptcha" className="mt-0">
      <div className="space-y-5">
        <ReCaptchaWidget />
        <V3AnalyticsDashboard />
      </div>
    </TabsContent>
  );
}

function TrainingContent() {
  return (
    <TabsContent value="training" className="mt-0">
      <div className="space-y-5">
        <FingerprintViewer />
        <FingerprintComparison />
      </div>
    </TabsContent>
  );
}

function ShieldContent() {
  return (
    <TabsContent value="shield" className="mt-0">
      <ShieldDashboard />
    </TabsContent>
  );
}

function Sidebar() {
  return (
    <div className="lg:col-span-12 xl:col-span-4">
      <div className="xl:sticky xl:top-6 space-y-5">
        <ControlPanel />
        <ConfigPanel />
        <BuildOutput />
      </div>
    </div>
  );
}

function AppContent() {
  const { wsConnected, packets, activeTab, setActiveTab } = useAppState();

  return (
    <div className="min-h-screen bg-background">
      <SkipLink />
      <Header wsConnected={wsConnected} />
      <main id={MAIN_CONTENT_ID} className="max-w-[1600px] mx-auto px-4 sm:px-6 py-6">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Left column: main area */}
          <div className="lg:col-span-12 xl:col-span-8 space-y-5">
            <Tabs defaultValue="analysis" className="w-full" onValueChange={setActiveTab}>
              <div className="flex items-center justify-between mb-2">
                <TabNavigation />
                <ModeLabel activeTab={activeTab} />
              </div>
              <MainContent packets={packets} />
              <CaptchaContent />
              <ReCaptchaContent />
              <TrainingContent />
              <ShieldContent />
            </Tabs>
          </div>
          <Sidebar />
        </div>
      </main>
      <Footer />
      <ToastContainer toasts={[]} />
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
        <span className="text-[10px] text-muted-foreground uppercase tracking-wider">WS</span>
      </div>
      {fingerprint && (
        <>
          <div className="w-px h-4 bg-border/30" />
          <span className="text-[10px] font-mono text-muted-foreground">
            {fingerprint.id.slice(0, FINGERPRINT_ID_PREVIEW_LENGTH)}
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
