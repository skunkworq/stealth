"use client";

import { useEffect, useState, useRef, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Play, Pause, Square } from "lucide-react";

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

export function CaptchaTraceVisualizer({ challengeId }: { challengeId: string }) {
  const [trace, setTrace] = useState<CaptchaTrace | null>(null);
  const [loading, setLoading] = useState(true);
  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState(1);
  const [currentTime, setCurrentTime] = useState(0);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const animationRef = useRef<number>(0);
  const startTimeRef = useRef<number>(0);

  useEffect(() => {
    const fetchTrace = async () => {
      setLoading(true);
      try {
        const res = await fetch(`/api/captcha/trace?challenge_id=${challengeId}`);
        if (res.ok) {
          const data = await res.json();
          setTrace(data);
          if (data.events.length > 0) {
            startTimeRef.current = data.events[0].timestamp;
          }
        }
      } catch (err) {
        console.error("Failed to fetch trace:", err);
      } finally {
        setLoading(false);
      }
    };

    if (challengeId) fetchTrace();
  }, [challengeId]);

  const drawTrace = useCallback((maxTimestamp: number) => {
    if (!trace || !canvasRef.current || trace.events.length === 0) return;

    const canvas = canvasRef.current;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Grid effect
    ctx.setLineDash([2, 4]);
    ctx.strokeStyle = "rgba(255, 255, 255, 0.05)";
    for (let i = 0; i < canvas.width; i += 40) {
      ctx.beginPath(); ctx.moveTo(i, 0); ctx.lineTo(i, canvas.height); ctx.stroke();
    }
    for (let i = 0; i < canvas.height; i += 40) {
      ctx.beginPath(); ctx.moveTo(0, i); ctx.lineTo(canvas.width, i); ctx.stroke();
    }

    const mouseEvents = trace.events.filter((e: CaptchaEvent) => e.type === "mousemove");
    if (mouseEvents.length === 0) return;

    // Find bounds for scaling
    const minX = Math.min(...mouseEvents.map((e: CaptchaEvent) => e.x));
    const maxX = Math.max(...mouseEvents.map((e: CaptchaEvent) => e.x));
    const minY = Math.min(...mouseEvents.map((e: CaptchaEvent) => e.y));
    const maxY = Math.max(...mouseEvents.map((e: CaptchaEvent) => e.y));

    const padding = 20;
    const width = canvas.width - padding * 2;
    const height = canvas.height - padding * 2;
    const scaleX = width / (maxX - minX || 1);
    const scaleY = height / (maxY - minY || 1);

    const visibleEvents = trace.events.filter((e: CaptchaEvent) => e.timestamp <= maxTimestamp);

    // Draw path
    ctx.beginPath();
    ctx.strokeStyle = "rgba(16, 185, 129, 0.6)"; 
    ctx.lineWidth = 2;
    ctx.setLineDash([]);

    let firstMove = true;
    visibleEvents.forEach((e: CaptchaEvent) => {
      if (e.type === "mousemove") {
        const px = padding + (e.x - minX) * scaleX;
        const py = padding + (e.y - minY) * scaleY;
        if (firstMove) { ctx.moveTo(px, py); firstMove = false; }
        else ctx.lineTo(px, py);
      }
    });
    ctx.stroke();

    // Draw last cursor position
    const lastEvent = visibleEvents.filter((e: CaptchaEvent) => e.type === "mousemove").pop();
    if (lastEvent) {
       const px = padding + (lastEvent.x - minX) * scaleX;
       const py = padding + (lastEvent.y - minY) * scaleY;
       ctx.beginPath();
       ctx.fillStyle = "rgba(16, 185, 129, 0.8)";
       ctx.arc(px, py, 3, 0, Math.PI * 2);
       ctx.fill();
    }

    // Draw clicks
    visibleEvents.filter((e: CaptchaEvent) => e.type === "click" || e.type === "mousedown").forEach((e: CaptchaEvent) => {
      const px = padding + (e.x - minX) * scaleX;
      const py = padding + (e.y - minY) * scaleY;
      ctx.beginPath();
      ctx.fillStyle = "rgba(244, 63, 94, 0.8)"; 
      ctx.arc(px, py, 5, 0, Math.PI * 2);
      ctx.fill();
      ctx.strokeStyle = "white";
      ctx.stroke();
    });
  }, [trace]);

  useEffect(() => {
    if (isPlaying && trace && trace.events.length > 0) {
      const totalDuration = trace.events[trace.events.length - 1].timestamp - trace.events[0].timestamp;
      
      const animate = (time: number) => {
        const elapsed = (time - startTimeRef.current) * playbackSpeed;
        const currentTs = trace.events[0].timestamp + elapsed;
        
        setCurrentTime(elapsed);
        drawTrace(currentTs);

        if (elapsed < totalDuration) {
          animationRef.current = requestAnimationFrame(animate);
        } else {
          setIsPlaying(false);
        }
      };

      startTimeRef.current = performance.now() - (currentTime / playbackSpeed);
      animationRef.current = requestAnimationFrame(animate);
      return () => cancelAnimationFrame(animationRef.current);
    } else if (!isPlaying && trace) {
        const start = trace.events[0]?.timestamp || 0;
        drawTrace(start + currentTime);
    }
  }, [isPlaying, trace, playbackSpeed, drawTrace, currentTime]);

  if (loading) return <div className="text-center p-10 text-muted-foreground animate-pulse">Initializing Lab Environment...</div>;
  if (!trace) return <div className="text-center p-10 text-red-glow">Trace Data Corrupted or Absent.</div>;

  const totalDuration = trace.events.length > 0 
    ? trace.events[trace.events.length - 1].timestamp - trace.events[0].timestamp 
    : 0;

  return (
    <div className="grid grid-cols-1 md:grid-cols-12 gap-5">
      <Card className="md:col-span-8 skeuo-panel overflow-hidden">
        <CardHeader className="pb-3 border-b border-border/10">
          <CardTitle className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider flex items-center justify-between">
            <div className="flex items-center gap-2">
               <span className="led-green"></span>
               <span>Expert Replay • {challengeId}</span>
            </div>
            <div className="flex items-center gap-2">
               <Badge variant="outline" className={trace.is_bot ? "text-red-glow border-red-glow/30" : "text-emerald-glow border-emerald-glow/30"}>
                 {trace.is_bot ? "BOT_SIGNATURE" : "HUMAN_TRACK"}
               </Badge>
               <span className="text-muted-foreground font-mono text-[9px] text-right min-w-[30px]">{((currentTime / totalDuration) * 100).toFixed(0)}%</span>
            </div>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0 bg-black/60 relative">
          <canvas ref={canvasRef} width={800} height={400} className="w-full h-auto aspect-[2/1] block" />
          
          {/* Keyboard Overlay */}
          <div className="absolute top-4 right-4 flex gap-1 pointer-events-none">
             {trace.events
               .filter(e => e.type === "keydown" && e.timestamp <= (trace.events[0].timestamp + currentTime))
               .slice(-5)
               .map((e, i) => (
                 <div key={i} className="bg-cyan-glow/20 border border-cyan-glow/40 text-cyan-glow px-2 py-1 rounded text-[10px] font-mono animate-in fade-in zoom-in duration-300">
                    {e.key === " " ? "SPACE" : e.key.toUpperCase()}
                 </div>
               ))
             }
          </div>

          <div className="absolute bottom-4 left-4 right-4 flex items-center gap-4 skeuo-panel bg-black/80 p-2 border-white/5">
             <Button variant="ghost" size="icon" onClick={() => setIsPlaying(!isPlaying)} className="h-8 w-8 text-cyan-glow">
                {isPlaying ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
             </Button>
             <Button variant="ghost" size="icon" onClick={() => { setIsPlaying(false); setCurrentTime(0); }} className="h-8 w-8 text-muted-foreground">
                <Square className="h-4 w-4" />
             </Button>
             
             <div className="flex-1 h-1 bg-white/5 rounded-full overflow-hidden">
                <div className="h-full bg-cyan-glow/40" style={{ width: `${(currentTime / (totalDuration || 1)) * 100}%` }} />
             </div>

             <div className="flex items-center gap-1">
                {[0.25, 0.5, 1, 2].map(speed => (
                  <Button 
                    key={speed}
                    variant={playbackSpeed === speed ? "secondary" : "ghost"} 
                    size="sm" 
                    onClick={() => setPlaybackSpeed(speed)} 
                    className="text-[9px] font-bold h-7 px-2"
                  >
                    {speed}x
                  </Button>
                ))}
             </div>
          </div>
        </CardContent>
      </Card>

      <Card className="md:col-span-4 skeuo-panel overflow-hidden flex flex-col">
        <CardHeader className="pb-3 border-b border-border/10">
          <CardTitle className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">
            Heuristic Analytics
          </CardTitle>
        </CardHeader>
        <CardContent className="flex-1 space-y-4 pt-4">
           <div className="skeuo-inset rounded-lg p-3 text-center bg-black/20">
              <div className="text-[9px] text-muted-foreground uppercase font-bold mb-1">Behavioral Integrity</div>
              <div className={`text-3xl font-bold font-mono ${(trace.bot_score ?? 0) > 0.5 ? "text-red-glow" : "text-emerald-glow"} glow-text`}>
                {((1 - (trace.bot_score ?? 0)) * 100).toFixed(1)}%
              </div>
           </div>

           <div className="space-y-2">
              <MetricRow label="Total Events" value={trace.metrics.total_events} />
              <MetricRow label="Mouse Velocity" value={`${trace.metrics.mouse_velocity.toFixed(1)} px/s`} />
              <MetricRow label="Path Entropy" value={(1 - trace.metrics.straightness).toFixed(3)} />
              <MetricRow label="Typing Cadence" value={`${trace.metrics.typing_speed.toFixed(1)} cps`} />
              <MetricRow label="Jitter/Noise" value={`${trace.metrics.event_intervals.toFixed(1)} ms`} />
              <MetricRow label="Stalls (Long Pauses)" value={trace.metrics.long_pauses} />
           </div>

           <div className="pt-2 border-t border-border/10">
             <div className="text-[9px] text-muted-foreground uppercase font-bold mb-2">Signature Flags</div>
             <div className="flex flex-wrap gap-1">
                {trace.metrics.straightness > 0.98 && <Badge variant="outline" className="text-[7px] text-red-glow border-red-glow/20 bg-red-glow/5">PRECISION_PATH</Badge>}
                {trace.metrics.mouse_velocity > 3000 && <Badge variant="outline" className="text-[7px] text-red-glow border-red-glow/20 bg-red-glow/5">WARP_SPEED</Badge>}
                {trace.metrics.event_intervals < 5 && <Badge variant="outline" className="text-[7px] text-red-glow border-red-glow/20 bg-red-glow/5">MACH_TIMING</Badge>}
                {!trace.is_bot && <Badge variant="outline" className="text-[7px] text-emerald-glow border-emerald-glow/20 bg-emerald-glow/5">ORGANIC_SIGNATURE</Badge>}
             </div>
           </div>
        </CardContent>
      </Card>
    </div>
  );
}

function MetricRow({ label, value }: { label: string, value: string | number }) {
  return (
    <div className="flex items-center justify-between py-1 border-b border-border/5 last:border-b-0">
      <span className="text-[9px] text-muted-foreground font-mono uppercase tracking-tighter">{label}</span>
      <span className="text-xs font-bold font-mono text-foreground">{value}</span>
    </div>
  );
}
