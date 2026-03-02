/* eslint-disable max-lines, max-lines-per-function */
"use client";

import { useEffect, useState, useRef, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Play, Pause, Square } from "lucide-react";

// Canvas rendering constants
const GRID_DASH_LENGTH = 2;
const GRID_DASH_GAP = 4;
const GRID_SPACING = 40;
const CANVAS_PADDING = 20;
const MAX_VISIBLE_KEYS = 5;
const PERCENTAGE_MULTIPLIER = 100;
const CURSOR_RADIUS = 3;
const CLICK_INDICATOR_RADIUS = 5;
const FALLBACK_UNIT = 1;
const PLAYBACK_SPEED_QUARTER = 0.25;
const PLAYBACK_SPEED_HALF = 0.5;
const PLAYBACK_SPEED_NORMAL = 1;
const PLAYBACK_SPEED_DOUBLE = 2;
const PLAYBACK_SPEEDS = [
  PLAYBACK_SPEED_QUARTER,
  PLAYBACK_SPEED_HALF,
  PLAYBACK_SPEED_NORMAL,
  PLAYBACK_SPEED_DOUBLE,
];

// Bot detection thresholds
const BOT_SCORE_THRESHOLD = 0.5;
const STRAIGHTNESS_THRESHOLD = 0.98;
const WARP_SPEED_THRESHOLD = 3000;
const MACH_TIMING_THRESHOLD = 5;
const METRICS_DECIMAL_PLACES = 3;

interface CaptchaEvent {
  type: string;
  timestamp: number;
  x: number;
  y: number;
  key: string;
  delta: number;
}

interface TraceMetrics {
  total_events: number;
  mouse_movements: number;
  keystrokes: number;
  scroll_events: number;
  clicks: number;
  mouse_velocity: number;
  typing_speed: number;
  event_intervals: number;
  straightness: number;
  pauses: number;
  long_pauses: number;
}

interface CaptchaTrace {
  challenge_id: string;
  session_id: string;
  type: string;
  created_at: number;
  started_at: number;
  events: CaptchaEvent[];
  metrics: TraceMetrics;
  bot_score: number;
  is_bot: boolean;
}

interface CanvasContext {
  ctx: CanvasRenderingContext2D;
  width: number;
  height: number;
}

// Draw grid on canvas
function drawGrid({ ctx, width, height }: CanvasContext) {
  ctx.setLineDash([GRID_DASH_LENGTH, GRID_DASH_GAP]);
  ctx.strokeStyle = "rgba(255, 255, 255, 0.05)";
  for (let i = 0; i < width; i += GRID_SPACING) {
    ctx.beginPath();
    ctx.moveTo(i, 0);
    ctx.lineTo(i, height);
    ctx.stroke();
  }
  for (let i = 0; i < height; i += GRID_SPACING) {
    ctx.beginPath();
    ctx.moveTo(0, i);
    ctx.lineTo(width, i);
    ctx.stroke();
  }
}

// Calculate bounds for mouse events
function getBounds(mouseEvents: CaptchaEvent[]) {
  return {
    minX: Math.min(...mouseEvents.map(e => e.x)),
    maxX: Math.max(...mouseEvents.map(e => e.x)),
    minY: Math.min(...mouseEvents.map(e => e.y)),
    maxY: Math.max(...mouseEvents.map(e => e.y)),
  };
}

interface PathDrawProps {
  ctx: CanvasRenderingContext2D;
  events: CaptchaEvent[];
  bounds: { minX: number; maxX: number; minY: number; maxY: number };
  width: number;
  height: number;
}

// Draw mouse path
function drawPath({ ctx, events, bounds, width, height }: PathDrawProps) {
  const { minX, maxX, minY, maxY } = bounds;
  const padding = CANVAS_PADDING;
  const drawWidth = width - padding * 2;
  const drawHeight = height - padding * 2;
  const scaleX = drawWidth / (maxX - minX || 1);
  const scaleY = drawHeight / (maxY - minY || 1);

  ctx.beginPath();
  ctx.strokeStyle = "rgba(16, 185, 129, 0.6)";
  ctx.lineWidth = 2;
  ctx.setLineDash([]);

  let firstMove = true;
  events.forEach(e => {
    if (e.type === "mousemove") {
      const px = padding + (e.x - minX) * scaleX;
      const py = padding + (e.y - minY) * scaleY;
      if (firstMove) {
        ctx.moveTo(px, py);
        firstMove = false;
      } else ctx.lineTo(px, py);
    }
  });
  ctx.stroke();
}

interface CursorDrawProps {
  ctx: CanvasRenderingContext2D;
  lastEvent: CaptchaEvent;
  bounds: { minX: number; minY: number; maxX: number; maxY: number };
}

// Draw cursor position
function drawCursor({ ctx, lastEvent, bounds }: CursorDrawProps) {
  const padding = CANVAS_PADDING;
  const width = ctx.canvas.width - padding * 2;
  const height = ctx.canvas.height - padding * 2;
  const scaleX = width / (bounds.maxX - bounds.minX || 1);
  const scaleY = height / (bounds.maxY - bounds.minY || 1);
  const px = padding + (lastEvent.x - bounds.minX) * scaleX;
  const py = padding + (lastEvent.y - bounds.minY) * scaleY;
  ctx.beginPath();
  ctx.fillStyle = "rgba(16, 185, 129, 0.8)";
  ctx.arc(px, py, CURSOR_RADIUS, 0, Math.PI * 2);
  ctx.fill();
}

interface ClicksDrawProps {
  ctx: CanvasRenderingContext2D;
  events: CaptchaEvent[];
  bounds: { minX: number; maxX: number; minY: number; maxY: number };
}

// Draw click indicators
function drawClicks({ ctx, events, bounds }: ClicksDrawProps) {
  const { minX, maxX, minY, maxY } = bounds;
  const padding = CANVAS_PADDING;
  const width = ctx.canvas.width - padding * 2;
  const height = ctx.canvas.height - padding * 2;
  const scaleX = width / (maxX - minX || 1);
  const scaleY = height / (maxY - minY || 1);

  events
    .filter(e => e.type === "click" || e.type === "mousedown")
    .forEach(e => {
      const px = padding + (e.x - minX) * scaleX;
      const py = padding + (e.y - minY) * scaleY;
      ctx.beginPath();
      ctx.fillStyle = "rgba(244, 63, 94, 0.8)";
      ctx.arc(px, py, CLICK_INDICATOR_RADIUS, 0, Math.PI * 2);
      ctx.fill();
      ctx.strokeStyle = "white";
      ctx.stroke();
    });
}

// Hook for playback state management
function useTracePlayback(trace: CaptchaTrace | null) {
  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState(1);
  const [currentTime, setCurrentTime] = useState(0);
  const animationRef = useRef<number>(0);
  const startTimeRef = useRef<number>(0);

  useEffect(() => {
    if (isPlaying && trace?.events.length) {
      const totalDuration =
        trace.events[trace.events.length - 1].timestamp - trace.events[0].timestamp;

      const animate = (time: number) => {
        const elapsed = (time - startTimeRef.current) * playbackSpeed;
        setCurrentTime(elapsed);
        if (elapsed < totalDuration) {
          animationRef.current = requestAnimationFrame(animate);
        } else {
          setIsPlaying(false);
        }
      };

      startTimeRef.current = performance.now() - currentTime / playbackSpeed;
      animationRef.current = requestAnimationFrame(animate);
      return () => cancelAnimationFrame(animationRef.current);
    }
  }, [isPlaying, trace, playbackSpeed, currentTime]);

  const reset = useCallback(() => {
    setIsPlaying(false);
    setCurrentTime(0);
  }, []);

  const togglePlay = useCallback(() => setIsPlaying(prev => !prev), []);

  return { isPlaying, playbackSpeed, currentTime, setPlaybackSpeed, togglePlay, reset };
}

// Hook for canvas rendering
function useCanvasRenderer(
  trace: CaptchaTrace | null,
  canvasRef: React.RefObject<HTMLCanvasElement | null>
) {
  const drawTrace = useCallback(
    (maxTimestamp: number) => {
      if (!trace || !canvasRef.current || trace.events.length === 0) return;

      const canvas = canvasRef.current;
      const ctx = canvas.getContext("2d");
      if (!ctx) return;

      ctx.clearRect(0, 0, canvas.width, canvas.height);
      drawGrid({ ctx, width: canvas.width, height: canvas.height });

      const mouseEvents = trace.events.filter(e => e.type === "mousemove");
      if (mouseEvents.length === 0) return;

      const bounds = getBounds(mouseEvents);
      const visibleEvents = trace.events.filter(e => e.timestamp <= maxTimestamp);
      const visibleMouseEvents = visibleEvents.filter(e => e.type === "mousemove");

      drawPath({
        ctx,
        events: visibleMouseEvents,
        bounds,
        width: canvas.width,
        height: canvas.height,
      });

      const lastEvent = visibleMouseEvents.pop();
      if (lastEvent) drawCursor({ ctx, lastEvent, bounds });

      drawClicks({ ctx, events: visibleEvents, bounds });
    },
    [trace, canvasRef]
  );

  return { drawTrace };
}

// Header component
function TraceHeader({
  challengeId,
  isBot,
  currentTime,
  totalDuration,
}: {
  challengeId: string;
  isBot: boolean;
  currentTime: number;
  totalDuration: number;
}) {
  return (
    <CardHeader className="pb-3 border-b border-border/10">
      <CardTitle className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="led-green" />
          <span>Expert Replay • {challengeId}</span>
        </div>
        <div className="flex items-center gap-2">
          <Badge
            variant="outline"
            className={
              isBot
                ? "text-red-glow border-red-glow/30"
                : "text-emerald-glow border-emerald-glow/30"
            }
          >
            {isBot ? "BOT_SIGNATURE" : "HUMAN_TRACK"}
          </Badge>
          <span className="text-muted-foreground font-mono text-[9px] text-right min-w-[30px]">
            {((currentTime / totalDuration) * PERCENTAGE_MULTIPLIER).toFixed(0)}%
          </span>
        </div>
      </CardTitle>
    </CardHeader>
  );
}

// Playback controls component
function PlaybackControls({
  isPlaying,
  playbackSpeed,
  currentTime,
  totalDuration,
  onTogglePlay,
  onReset,
  onSpeedChange,
}: {
  isPlaying: boolean;
  playbackSpeed: number;
  currentTime: number;
  totalDuration: number;
  onTogglePlay: () => void;
  onReset: () => void;
  onSpeedChange: (speed: number) => void;
}) {
  return (
    <div className="absolute bottom-4 left-4 right-4 flex items-center gap-4 skeuo-panel bg-black/80 p-2 border-white/5">
      <Button variant="ghost" size="icon" onClick={onTogglePlay} className="h-8 w-8 text-cyan-glow">
        {isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
      </Button>
      <Button
        variant="ghost"
        size="icon"
        onClick={onReset}
        className="h-8 w-8 text-muted-foreground"
      >
        <Square className="h-4 w-4" />
      </Button>
      <div className="flex-1 h-1 bg-white/5 rounded-full overflow-hidden">
        <div
          className="h-full bg-cyan-glow/40"
          style={{
            width: `${(currentTime / (totalDuration || FALLBACK_UNIT)) * PERCENTAGE_MULTIPLIER}%`,
          }}
        />
      </div>
      <div className="flex items-center gap-1">
        {PLAYBACK_SPEEDS.map(speed => (
          <Button
            key={speed}
            variant={playbackSpeed === speed ? "secondary" : "ghost"}
            size="sm"
            onClick={() => onSpeedChange(speed)}
            className="text-[9px] font-bold h-7 px-2"
          >
            {speed}x
          </Button>
        ))}
      </div>
    </div>
  );
}

// Event list component
function EventList({ trace, currentTime }: { trace: CaptchaTrace; currentTime: number }) {
  const startTime = trace.events[0]?.timestamp || 0;
  return (
    <div className="absolute top-4 right-4 flex gap-1 pointer-events-none">
      {trace.events
        .filter(e => e.type === "keydown" && e.timestamp <= startTime + currentTime)
        .slice(-MAX_VISIBLE_KEYS)
        .map(e => (
          <div
            key={`keyevent-${e.timestamp}-${e.type}`}
            className="bg-cyan-glow/20 border border-cyan-glow/40 text-cyan-glow px-2 py-1 rounded text-[10px] font-mono animate-in fade-in zoom-in duration-300"
          >
            {e.key === " " ? "SPACE" : e.key.toUpperCase()}
          </div>
        ))}
    </div>
  );
}

// Canvas component
function TraceCanvas({
  canvasRef,
  trace,
  currentTime,
}: {
  canvasRef: React.RefObject<HTMLCanvasElement | null>;
  trace: CaptchaTrace;
  currentTime: number;
}) {
  return (
    <>
      <canvas
        ref={canvasRef}
        width={800}
        height={400}
        className="w-full h-auto aspect-[2/1] block"
      />
      <EventList trace={trace} currentTime={currentTime} />
    </>
  );
}

// Metric row helper
function MetricRow({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="flex items-center justify-between py-1 border-b border-border/5 last:border-b-0">
      <span className="text-[9px] text-muted-foreground font-mono uppercase tracking-tighter">
        {label}
      </span>
      <span className="text-xs font-bold font-mono text-foreground">{value}</span>
    </div>
  );
}

// Signature flags component
function SignatureFlags({ metrics, isBot }: { metrics: TraceMetrics; isBot: boolean }) {
  return (
    <div className="pt-2 border-t border-border/10">
      <div className="text-[9px] text-muted-foreground uppercase font-bold mb-2">
        Signature Flags
      </div>
      <div className="flex flex-wrap gap-1">
        {metrics.straightness > STRAIGHTNESS_THRESHOLD && (
          <Badge
            variant="outline"
            className="text-[7px] text-red-glow border-red-glow/20 bg-red-glow/5"
          >
            PRECISION_PATH
          </Badge>
        )}
        {metrics.mouse_velocity > WARP_SPEED_THRESHOLD && (
          <Badge
            variant="outline"
            className="text-[7px] text-red-glow border-red-glow/20 bg-red-glow/5"
          >
            WARP_SPEED
          </Badge>
        )}
        {metrics.event_intervals < MACH_TIMING_THRESHOLD && (
          <Badge
            variant="outline"
            className="text-[7px] text-red-glow border-red-glow/20 bg-red-glow/5"
          >
            MACH_TIMING
          </Badge>
        )}
        {!isBot && (
          <Badge
            variant="outline"
            className="text-[7px] text-emerald-glow border-emerald-glow/20 bg-emerald-glow/5"
          >
            ORGANIC_SIGNATURE
          </Badge>
        )}
      </div>
    </div>
  );
}

// Metrics panel component
function MetricsPanel({ trace }: { trace: CaptchaTrace }) {
  const botScore = trace.bot_score ?? 0;
  const { metrics } = trace;

  return (
    <Card className="md:col-span-4 skeuo-panel overflow-hidden flex flex-col">
      <CardHeader className="pb-3 border-b border-border/10">
        <CardTitle className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">
          Heuristic Analytics
        </CardTitle>
      </CardHeader>
      <CardContent className="flex-1 space-y-4 pt-4">
        <div className="skeuo-inset rounded-lg p-3 text-center bg-black/20">
          <div className="text-[9px] text-muted-foreground uppercase font-bold mb-1">
            Behavioral Integrity
          </div>
          <div
            className={`text-3xl font-bold font-mono ${botScore > BOT_SCORE_THRESHOLD ? "text-red-glow" : "text-emerald-glow"} glow-text`}
          >
            {((1 - botScore) * PERCENTAGE_MULTIPLIER).toFixed(1)}%
          </div>
        </div>
        <div className="space-y-2">
          <MetricRow label="Total Events" value={metrics.total_events} />
          <MetricRow label="Mouse Velocity" value={`${metrics.mouse_velocity.toFixed(1)} px/s`} />
          <MetricRow
            label="Path Entropy"
            value={(1 - metrics.straightness).toFixed(METRICS_DECIMAL_PLACES)}
          />
          <MetricRow label="Typing Cadence" value={`${metrics.typing_speed.toFixed(1)} cps`} />
          <MetricRow label="Jitter/Noise" value={`${metrics.event_intervals.toFixed(1)} ms`} />
          <MetricRow label="Stalls (Long Pauses)" value={metrics.long_pauses} />
        </div>
        <SignatureFlags metrics={metrics} isBot={trace.is_bot} />
      </CardContent>
    </Card>
  );
}

export function CaptchaTraceVisualizer({ challengeId }: { challengeId: string }) {
  const [trace, setTrace] = useState<CaptchaTrace | null>(null);
  const [loading, setLoading] = useState(true);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const { drawTrace } = useCanvasRenderer(trace, canvasRef);
  const { isPlaying, playbackSpeed, currentTime, setPlaybackSpeed, togglePlay, reset } =
    useTracePlayback(trace);

  useEffect(() => {
    const fetchTrace = async () => {
      setLoading(true);
      try {
        const res = await fetch(`/api/captcha/trace?challenge_id=${challengeId}`);
        if (res.ok) {
          const data = await res.json();
          setTrace(data);
        }
      } catch (err) {
        console.error("Failed to fetch trace:", err);
      } finally {
        setLoading(false);
      }
    };
    if (challengeId) fetchTrace();
  }, [challengeId]);

  useEffect(() => {
    if (trace && !isPlaying) {
      const start = trace.events[0]?.timestamp || 0;
      drawTrace(start + currentTime);
    }
  }, [trace, isPlaying, currentTime, drawTrace]);

  if (loading)
    return (
      <div className="text-center p-10 text-muted-foreground animate-pulse">
        Initializing Lab Environment...
      </div>
    );
  if (!trace)
    return <div className="text-center p-10 text-red-glow">Trace Data Corrupted or Absent.</div>;

  const totalDuration =
    trace.events.length > 0
      ? trace.events[trace.events.length - 1].timestamp - trace.events[0].timestamp
      : 0;

  return (
    <div className="grid grid-cols-1 md:grid-cols-12 gap-5">
      <Card className="md:col-span-8 skeuo-panel overflow-hidden">
        <TraceHeader
          challengeId={challengeId}
          isBot={trace.is_bot}
          currentTime={currentTime}
          totalDuration={totalDuration}
        />
        <CardContent className="p-0 bg-black/60 relative">
          <TraceCanvas canvasRef={canvasRef} trace={trace} currentTime={currentTime} />
          <PlaybackControls
            isPlaying={isPlaying}
            playbackSpeed={playbackSpeed}
            currentTime={currentTime}
            totalDuration={totalDuration}
            onTogglePlay={togglePlay}
            onReset={reset}
            onSpeedChange={setPlaybackSpeed}
          />
        </CardContent>
      </Card>
      <MetricsPanel trace={trace} />
    </div>
  );
}
