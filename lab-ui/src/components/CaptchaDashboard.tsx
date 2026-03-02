"use client";

import { useEffect, useState, useRef, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToasts } from "@/components/Toasts";
import { CaptchaTraceVisualizer } from "./CaptchaTraceVisualizer";
import { CaptchaTrainer } from "./CaptchaTrainer";
import { ManualCaptchaSolver } from "./ManualCaptchaSolver";
import { TrainingDataBrowser } from "./TrainingDataBrowser";

// Constants
const REFRESH_INTERVAL_MS = 5000;
const PERCENTAGE_MULTIPLIER = 100;
const SUCCESS_RATE_THRESHOLD = 80;

interface CaptchaTypeMetrics {
  count: number;
  successes: number;
  failures: number;
  avg_time_ms: number;
  bot_rate: number;
}

interface GlobalMetrics {
  total_challenges: number;
  success_rate: number;
  avg_solve_time_ms: number;
  by_type: Record<string, CaptchaTypeMetrics>;
  ml_features_stats: Record<string, { mean: number; std_dev: number; min: number; max: number }>;
}

interface CatalogueEntry {
  type: string;
  name: string;
  description: string;
  example: string;
  metrics: string[];
}

// Hook for data fetching and state management
function useCaptchaMetrics() {
  const [metrics, setMetrics] = useState<GlobalMetrics | null>(null);
  const [catalogue, setCatalogue] = useState<CatalogueEntry[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [mRes, cRes] = await Promise.all([
        fetch("/api/captcha/metrics"),
        fetch("/api/captcha/catalogue"),
      ]);

      if (mRes.ok) {
        setMetrics(await mRes.json());
      }
      if (cRes.ok) setCatalogue(await cRes.json());
    } catch (err) {
      console.error("Failed to fetch CAPTCHA data:", err);
    } finally {
      setLoading(false);
    }
  }, []);

  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    fetchData();
    intervalRef.current = setInterval(fetchData, REFRESH_INTERVAL_MS);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [fetchData]);

  return { metrics, catalogue, loading };
}

// Component for individual metric cards
function MetricCard({
  label,
  value,
  icon,
  color,
}: {
  label: string;
  value: string | number;
  icon: string;
  color: string;
}) {
  return (
    <Card className="skeuo-panel bg-black/40 border-white/5 group hover:border-white/10 transition-colors">
      <CardContent className="p-5 flex items-center justify-between">
        <div className="space-y-1">
          <p className="text-[9px] text-muted-foreground uppercase font-bold tracking-widest group-hover:text-muted-foreground/80 transition-colors">
            {label}
          </p>
          <p className={`text-2xl font-bold font-mono ${color} glow-text`}>{value}</p>
        </div>
        <div className="skeuo-inset rounded-full p-3 text-lg bg-black/20 group-hover:bg-black/40 transition-colors">
          {icon}
        </div>
      </CardContent>
    </Card>
  );
}

// Component for the top metrics display
function MetricsCards({ metrics }: { metrics: GlobalMetrics | null }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
      <MetricCard
        label="Total Challenges"
        value={metrics?.total_challenges ?? 0}
        icon="🛡️"
        color="text-cyan-glow"
      />
      <MetricCard
        label="Global Success Rate"
        value={`${((metrics?.success_rate ?? 0) * PERCENTAGE_MULTIPLIER).toFixed(1)}%`}
        icon="✅"
        color="text-emerald-glow"
      />
      <MetricCard
        label="Avg. Solve Time"
        value={`${metrics?.avg_solve_time_ms ?? 0}ms`}
        icon="⚡"
        color="text-amber-glow"
      />
    </div>
  );
}

// Component for bot signal indicator
function BotSignalIndicator({ botRate }: { botRate: number }) {
  return (
    <div className="flex justify-center">
      <div className="w-16 h-1 rounded-full bg-white/10 overflow-hidden">
        <div
          className="h-full bg-red-glow/60 shadow-[0_0_8px_rgba(239,68,68,0.5)]"
          style={{ width: `${botRate * PERCENTAGE_MULTIPLIER}%` }}
        />
      </div>
    </div>
  );
}

// Component for view logs button
function ViewLogsButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="text-[9px] text-muted-foreground/40 hover:text-cyan-glow underline uppercase font-bold tracking-tighter transition-colors"
    >
      View Logs
    </button>
  );
}

// Component for success rate badge
function SuccessRateBadge({ rate }: { rate: number }) {
  const isHigh = rate > SUCCESS_RATE_THRESHOLD;
  return (
    <Badge
      variant="outline"
      className={`font-mono text-[9px] h-5 ${
        isHigh ? "text-emerald-glow border-emerald-glow/30" : "text-amber-glow border-amber-glow/30"
      }`}
    >
      {rate.toFixed(1)}%
    </Badge>
  );
}

// Component for individual challenge type rows
function ChallengeTypeRow({
  entry,
  metrics,
  onViewLogs,
}: {
  entry: CatalogueEntry;
  metrics: CaptchaTypeMetrics;
  onViewLogs: (name: string) => void;
}) {
  const successRate =
    metrics.count > 0 ? (metrics.successes / metrics.count) * PERCENTAGE_MULTIPLIER : 0;

  return (
    <TableRow className="border-white/5 hover:bg-white/5 transition-colors group">
      <TableCell className="py-4">
        <div className="flex flex-col">
          <span className="font-bold text-xs text-foreground group-hover:text-cyan-glow transition-colors">
            {entry.name}
          </span>
          <span className="text-[9px] text-muted-foreground/60 font-mono tracking-tighter">
            {entry.description}
          </span>
        </div>
      </TableCell>
      <TableCell className="text-center font-mono text-xs text-cyan-glow">
        {metrics.count}
      </TableCell>
      <TableCell className="text-center">
        <SuccessRateBadge rate={successRate} />
      </TableCell>
      <TableCell className="text-center font-mono text-[10px] text-muted-foreground">
        {metrics.avg_time_ms}ms
      </TableCell>
      <TableCell className="text-center">
        <BotSignalIndicator botRate={metrics.bot_rate} />
      </TableCell>
      <TableCell className="text-right pr-6">
        <ViewLogsButton onClick={() => onViewLogs(entry.name)} />
      </TableCell>
    </TableRow>
  );
}

// Table header component
function ChallengeTableHeader() {
  return (
    <TableHeader>
      <TableRow className="border-white/10 bg-white/5">
        <TableHead className="text-[9px] uppercase font-bold text-muted-foreground h-10">
          Type
        </TableHead>
        <TableHead className="text-[9px] uppercase font-bold text-muted-foreground text-center h-10">
          Issued
        </TableHead>
        <TableHead className="text-[9px] uppercase font-bold text-muted-foreground text-center h-10">
          Pass Rate
        </TableHead>
        <TableHead className="text-[9px] uppercase font-bold text-muted-foreground text-center h-10">
          Avg Time
        </TableHead>
        <TableHead className="text-[9px] uppercase font-bold text-muted-foreground text-center h-10">
          Bot Signal
        </TableHead>
        <TableHead className="text-[9px] uppercase font-bold text-muted-foreground text-right h-10 pr-6">
          Details
        </TableHead>
      </TableRow>
    </TableHeader>
  );
}

// Component for the challenge types breakdown
function ChallengeTypeList({
  catalogue,
  metrics,
  onViewLogs,
}: {
  catalogue: CatalogueEntry[];
  metrics: GlobalMetrics | null;
  onViewLogs: (name: string) => void;
}) {
  return (
    <Card className="skeuo-panel overflow-hidden border-white/5">
      <CardHeader className="pb-3 border-b border-white/5">
        <CardTitle className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider flex items-center gap-2">
          <span className="text-sm">📊</span>
          Graduated Shield Response Breakdown
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <Table>
          <ChallengeTableHeader />
          <TableBody>
            {catalogue.map(entry => {
              const m = metrics?.by_type[entry.type] || {
                count: 0,
                successes: 0,
                failures: 0,
                avg_time_ms: 0,
                bot_rate: 0,
              };
              return (
                <ChallengeTypeRow
                  key={entry.type}
                  entry={entry}
                  metrics={m}
                  onViewLogs={onViewLogs}
                />
              );
            })}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}

// Component for the dashboard empty state
function DashboardEmptyState() {
  return (
    <Card className="skeuo-panel">
      <CardContent className="p-12 text-center text-muted-foreground animate-pulse font-mono text-xs">
        SYNCING_CAPTCHA_TELEMETRY...
      </CardContent>
    </Card>
  );
}

// Placeholder components (prefixed with underscore as they are unused)
function _AttemptRow() {
  return null;
}

function _RecentAttemptsTable() {
  return null;
}

// Overview tab content component
function OverviewTab({
  metrics,
  catalogue,
  activeChallengeId,
  onCloseVisualizer,
  onViewLogs,
}: {
  metrics: GlobalMetrics | null;
  catalogue: CatalogueEntry[];
  activeChallengeId: string | null;
  onCloseVisualizer: () => void;
  onViewLogs: (name: string) => void;
}) {
  return (
    <TabsContent value="overview" className="space-y-5 m-0 outline-none">
      {activeChallengeId && (
        <div className="space-y-4 animate-in fade-in slide-in-from-top-2 duration-300">
          <div className="flex items-center justify-between">
            <h3 className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">
              Forensic Trace View
            </h3>
            <button
              onClick={onCloseVisualizer}
              className="text-[10px] uppercase font-bold text-red-glow hover:underline"
            >
              Close Visualizer
            </button>
          </div>
          <CaptchaTraceVisualizer challengeId={activeChallengeId} />
          <div className="border-b border-border/10 pb-5" />
        </div>
      )}
      <MetricsCards metrics={metrics} />
      <ChallengeTypeList catalogue={catalogue} metrics={metrics} onViewLogs={onViewLogs} />
    </TabsContent>
  );
}

// Analytics tab placeholder
function AnalyticsTab() {
  return (
    <TabsContent value="analytics" className="m-0 outline-none">
      <Card className="skeuo-panel border-dashed border-white/5">
        <CardContent className="p-20 text-center flex flex-col items-center justify-center space-y-4">
          <div className="text-4xl filter grayscale">📈</div>
          <div className="space-y-1">
            <h3 className="text-sm font-bold text-muted-foreground uppercase">
              ML Insights Engine
            </h3>
            <p className="text-xs text-muted-foreground/40 max-w-xs">
              Connecting to adversarial training node... Feature distribution analysis will appear
              here.
            </p>
          </div>
        </CardContent>
      </Card>
    </TabsContent>
  );
}

// Tab navigation component
function TabNavigation() {
  return (
    <TabsList className="skeuo-inset bg-black/40 border border-white/5 p-1 h-auto">
      <TabsTrigger
        value="overview"
        className="text-[10px] uppercase font-bold px-4 py-1.5 data-[state=active]:bg-cyan-glow/20 data-[state=active]:text-cyan-glow"
      >
        Overview
      </TabsTrigger>
      <TabsTrigger
        value="trainer"
        className="text-[10px] uppercase font-bold px-4 py-1.5 data-[state=active]:bg-amber-glow/20 data-[state=active]:text-amber-glow"
      >
        Training Lab
      </TabsTrigger>
      <TabsTrigger
        value="analytics"
        className="text-[10px] uppercase font-bold px-4 py-1.5 data-[state=active]:bg-purple-glow/20 data-[state=active]:text-purple-glow"
      >
        ML Insights
      </TabsTrigger>
      <TabsTrigger
        value="solver"
        className="text-[10px] uppercase font-bold px-4 py-1.5 data-[state=active]:bg-purple-glow/20 data-[state=active]:text-purple-glow"
      >
        Manual Solver
      </TabsTrigger>
      <TabsTrigger
        value="dataset"
        className="text-[10px] uppercase font-bold px-4 py-1.5 data-[state=active]:bg-red-glow/20 data-[state=active]:text-red-glow"
      >
        Dataset
      </TabsTrigger>
    </TabsList>
  );
}

// Live badge component
function LiveBadge() {
  return (
    <Badge
      variant="outline"
      className="text-[9px] border-emerald-glow/30 text-emerald-glow bg-emerald-glow/5"
    >
      LIVE_FEED • SYNCED
    </Badge>
  );
}

export function CaptchaDashboard() {
  const { metrics, catalogue, loading } = useCaptchaMetrics();
  const [activeChallengeId, setActiveChallengeId] = useState<string | null>(null);
  const { addToast } = useToasts();

  const handleViewLogs = useCallback(
    (name: string) => {
      addToast("🔍 Heuristic Alert", `Analyzing patterns for ${name}...`);
    },
    [addToast]
  );

  if (loading && !metrics) {
    return <DashboardEmptyState />;
  }

  return (
    <Tabs defaultValue="overview" className="space-y-5">
      <div className="flex items-center justify-between">
        <TabNavigation />
        <LiveBadge />
      </div>
      <OverviewTab
        metrics={metrics}
        catalogue={catalogue}
        activeChallengeId={activeChallengeId}
        onCloseVisualizer={() => setActiveChallengeId(null)}
        onViewLogs={handleViewLogs}
      />
      <TabsContent value="trainer" className="m-0 outline-none">
        <CaptchaTrainer />
      </TabsContent>
      <AnalyticsTab />
      <TabsContent value="solver" className="m-0 outline-none">
        <ManualCaptchaSolver />
      </TabsContent>
      <TabsContent value="dataset" className="m-0 outline-none">
        <TrainingDataBrowser />
      </TabsContent>
    </Tabs>
  );
}
