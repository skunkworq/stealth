"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToasts } from "@/components/Toasts";
import { CaptchaTraceVisualizer } from "./CaptchaTraceVisualizer";

interface CaptchaEvent {
  type: string;
  timestamp: number;
  x: number;
  y: number;
  key: string;
  delta: number;
}

interface TrainerChallenge {
  ID: string;
  Type: string;
  Challenge: any;
  SessionID: string;
}

export function CaptchaTrainer() {
  const [challenge, setChallenge] = useState<TrainerChallenge | null>(null);
  const [isRecording, setIsRecording] = useState(false);
  const [events, setEvents] = useState<CaptchaEvent[]>([]);
  const [solution, setSolution] = useState("");
  const [solveResult, setSolveResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const { addToast } = useToasts();
  
  const interactionAreaRef = useRef<HTMLDivElement>(null);

  const startTraining = async () => {
    setLoading(true);
    setSolveResult(null);
    setSolution("");
    setEvents([]);
    try {
      const res = await fetch("/api/captcha/random");
      if (res.ok) {
        const data = await res.json();
        setChallenge(data);
        setIsRecording(true);
        addToast("🧪 Lab Initialized", "Expert Track recording started. Solve the challenge normally.");
      }
    } catch (err) {
      console.error("Failed to start training:", err);
    } finally {
      setLoading(false);
    }
  };

  const recordEvent = useCallback((e: any) => {
    if (!isRecording) return;
    
    const rect = interactionAreaRef.current?.getBoundingClientRect();
    if (!rect) return;

    const event: CaptchaEvent = {
        type: e.type,
        timestamp: Date.now(),
        x: e.clientX ? e.clientX - rect.left : 0,
        y: e.clientY ? e.clientY - rect.top : 0,
        key: e.key || "",
        delta: e.deltaY || 0,
    };

    setEvents(prev => [...prev.slice(-1000), event]); // Cap at 1000 events
  }, [isRecording]);

  useEffect(() => {
    if (isRecording) {
      window.addEventListener("mousemove", recordEvent);
      window.addEventListener("mousedown", recordEvent);
      window.addEventListener("keydown", recordEvent);
      window.addEventListener("wheel", recordEvent);
      return () => {
        window.removeEventListener("mousemove", recordEvent);
        window.removeEventListener("mousedown", recordEvent);
        window.removeEventListener("keydown", recordEvent);
        window.removeEventListener("wheel", recordEvent);
      };
    }
  }, [isRecording, recordEvent]);

  const submitSolve = async () => {
    if (!challenge) return;
    setIsRecording(false);
    setLoading(true);

    try {
      const res = await fetch("/api/captcha/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          challenge_id: challenge.ID,
          solution: solution,
          events: events,
          is_expert: true // Flag as human expert track
        })
      });

      if (res.ok) {
        const data = await res.json();
        setSolveResult(data);
        if (data.solved) {
            addToast("🎖️ Expert Track Recorded", `Solution verified. Bot Score: ${(data.bot_score * 100).toFixed(1)}%`);
        } else {
            addToast("⚠️ Solve Failed", "Solution was incorrect. Track still saved for negative sample.");
        }
      }
    } catch (err) {
      console.error("Failed to submit solve:", err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        
        {/* Challenge Area */}
        <Card className="lg:col-span-12 skeuo-panel overflow-hidden">
          <CardHeader className="pb-3 border-b border-border/10 flex flex-row items-center justify-between">
            <CardTitle className="text-xs font-bold text-muted-foreground uppercase tracking-wider flex items-center gap-2">
              <span className="text-amber-glow animate-pulse">🧪</span>
              Intervention Lab: Expert Feedback Generation
            </CardTitle>
            {!challenge ? (
              <Button onClick={startTraining} size="sm" className="skeuo-panel bg-emerald-glow/20 text-emerald-glow border-emerald-glow/30 hover:bg-emerald-glow/30">
                Generate New Training Session
              </Button>
            ) : (
                <div className="flex items-center gap-3">
                  <Button onClick={startTraining} size="sm" variant="ghost" className="h-7 px-2 text-[10px] text-muted-foreground hover:text-cyan-glow">
                    ↻ Refresh
                  </Button>
                  <Badge variant="outline" className="text-[10px] text-amber-glow border-amber-glow/30 animate-pulse">
                    REC • EXPERT_TRACK_ACTIVE
                  </Badge>
                </div>
            )}
          </CardHeader>
          <CardContent className="p-0 min-h-[400px] flex flex-col">
            {!challenge ? (
              <div className="flex-1 flex flex-col items-center justify-center p-20 text-center space-y-4">
                 <div className="text-4xl">🔬</div>
                 <div className="space-y-2">
                   <h3 className="text-lg font-bold text-foreground">No Active Training Session</h3>
                   <p className="text-sm text-muted-foreground max-w-md">
                     Start a session to record your interactions. We use these "Expert Tracks" to calibrate the Sword RL Agent's behavioral simulation.
                   </p>
                 </div>
                 <Button onClick={startTraining} variant="outline">Initialize Lab</Button>
              </div>
            ) : (
              <div className="flex-1 flex flex-col md:flex-row">
                 {/* Capture Surface */}
                 <div 
                   ref={interactionAreaRef}
                   className="flex-1 bg-black/60 p-10 flex flex-col items-center justify-center relative cursor-crosshair"
                 >
                    <div className="skeuo-panel p-8 max-w-sm w-full bg-background border border-cyan-glow/20 shadow-2xl">
                       <h4 className="text-xs font-bold text-muted-foreground uppercase mb-4 border-b border-border/10 pb-2">
                          Type: {challenge.Type?.toUpperCase() || "UNKNOWN"}
                       </h4>
                       
                       <div className="space-y-4">
                          {challenge.Type === "text" && (
                            <div className="space-y-4">
                               <div className="skeuo-inset p-4 bg-white/5 flex items-center justify-center min-h-[100px]">
                                 {challenge.Challenge?.image ? (
                                   <img 
                                     src={`data:image/png;base64,${challenge.Challenge.image}`} 
                                     alt="CAPTCHA" 
                                     className="max-w-full h-auto brightness-90 contrast-125"
                                   />
                                 ) : (
                                   <span className="text-3xl font-mono tracking-[0.2em] select-none blur-[0.5px] rotate-[-2deg] italic opacity-80">
                                     {challenge.Challenge?.text || "CAPTCHA"}
                                   </span>
                                 )}
                               </div>
                               <input 
                                 type="text" 
                                 value={solution}
                                 onChange={(e) => setSolution(e.target.value)}
                                 placeholder="Enter characters..."
                                 className="w-full bg-black/40 border border-border/30 rounded px-3 py-2 text-sm font-mono focus:outline-none focus:border-cyan-glow/50 transition-colors"
                                 autoFocus
                               />
                            </div>
                          )}

                          {challenge.Type === "math" && (
                            <div className="space-y-4">
                               <div className="skeuo-inset p-4 bg-white/5 flex items-center justify-center min-h-[100px]">
                                 {challenge.Challenge?.image ? (
                                   <img 
                                     src={`data:image/png;base64,${challenge.Challenge.image}`} 
                                     alt="Math CAPTCHA" 
                                     className="max-w-full h-auto brightness-90 contrast-125"
                                   />
                                 ) : (
                                   <span className="text-2xl font-bold font-mono text-cyan-glow">
                                     {challenge.Challenge?.question} = ?
                                   </span>
                                 )}
                               </div>
                               <input 
                                 type="text" 
                                 value={solution}
                                 onChange={(e) => setSolution(e.target.value)}
                                 placeholder="Result..."
                                 className="w-full bg-black/40 border border-border/30 rounded px-3 py-2 text-sm font-mono focus:outline-none focus:border-cyan-glow/50 transition-colors"
                                 autoFocus
                               />
                            </div>
                          )}

                          {(challenge.Type === "hcaptcha" || challenge.Type === "image_selection" || challenge.Type === "image") && (
                             <div className="space-y-4">
                                <p className="text-xs text-muted-foreground italic">
                                  {challenge.Type === "image" ? `Select the character: ${challenge.Challenge?.target}` : "Simulated challenge. Select the correct variant."}
                                </p>
                                {challenge.Challenge?.image ? (
                                   <div className="skeuo-inset p-2 bg-white/5 flex items-center justify-center">
                                      <img 
                                        src={`data:image/png;base64,${challenge.Challenge.image}`} 
                                        alt="CAPTCHA grid" 
                                        className="max-w-full h-auto brightness-90 contrast-125"
                                        onClick={(e) => {
                                          // Simple heuristic for grid selection if needed, 
                                          // but for training lab we just want them to click the right vicinity
                                          addToast("Interaction Recorded", "Coordinate-based selection captured.");
                                        }}
                                      />
                                   </div>
                                ) : (
                                  <div className="grid grid-cols-2 gap-2">
                                     {[1,2,3,4].map(v => (
                                       <button 
                                         key={v}
                                         onClick={() => { setSolution(`option_${v}`); addToast("Selection Recorded", `Expert interaction captured for option ${v}`) }}
                                         className={`skeuo-panel p-4 aspect-square flex items-center justify-center hover:bg-cyan-glow/5 transition-colors ${solution === `option_${v}` ? 'border-cyan-glow/60 bg-cyan-glow/5' : ''}`}
                                       >
                                          <div className="w-8 h-8 rounded bg-border/20" />
                                       </button>
                                     ))}
                                  </div>
                                )}
                                <input 
                                  type="text" 
                                  value={solution}
                                  onChange={(e) => setSolution(e.target.value)}
                                  placeholder="Enter target character or option..."
                                  className="w-full bg-black/40 border border-border/30 rounded px-3 py-2 text-sm font-mono focus:outline-none focus:border-cyan-glow/50 transition-colors"
                                />
                             </div>
                          )}

                          {challenge.Type === "slider" && (
                             <div className="space-y-4">
                                <p className="text-xs text-muted-foreground italic">Drag the slider to solve the puzzle.</p>
                                {challenge.Challenge?.image && (
                                   <div className="skeuo-inset p-2 bg-white/5 flex items-center justify-center">
                                      <img 
                                        src={`data:image/png;base64,${challenge.Challenge.image}`} 
                                        alt="Slider CAPTCHA" 
                                        className="max-w-full h-auto brightness-90 contrast-125"
                                      />
                                   </div>
                                )}
                                <input 
                                  type="range" 
                                  min="0" max="200" 
                                  value={solution}
                                  onChange={(e) => setSolution(e.target.value)}
                                  className="w-full h-2 bg-black/60 rounded-full appearance-none cursor-pointer accent-cyan-glow"
                                />
                                <div className="text-[10px] text-muted-foreground font-mono text-center">Offset: {solution}px</div>
                             </div>
                          )}
                          
                          <Button 
                            onClick={submitSolve} 
                            disabled={!solution || loading}
                            className="w-full skeuo-panel bg-cyan-glow/20 text-cyan-glow border-cyan-glow/30 hover:bg-cyan-glow/30 mt-4"
                          >
                            {loading ? "Analyzing..." : "Verify & Save Track"}
                          </Button>
                       </div>
                    </div>
                    
                    <div className="absolute top-3 left-3 flex gap-2">
                       <Badge variant="outline" className="text-[8px] border-border/20 text-muted-foreground/40 bg-black/20">
                          X: {events[events.length-1]?.x ?? 0}
                       </Badge>
                       <Badge variant="outline" className="text-[8px] border-border/20 text-muted-foreground/40 bg-black/20">
                          Y: {events[events.length-1]?.y ?? 0}
                       </Badge>
                       <Badge variant="outline" className="text-[8px] border-border/20 text-muted-foreground/40 bg-black/20">
                          EVENTS: {events.length}
                       </Badge>
                    </div>
                 </div>

                 {/* Real-time Telemetry (Side Panel) */}
                 <div className="w-full md:w-80 border-t md:border-t-0 md:border-l border-border/10 bg-black/20 flex flex-col">
                    <div className="p-4 border-b border-border/10 bg-black/20 font-bold text-[10px] uppercase tracking-widest text-muted-foreground">
                       Live Telemetry Stream
                    </div>
                    <ScrollArea className="flex-1 p-2">
                       <div className="space-y-1">
                          {events.slice(-15).reverse().map((ev, i) => (
                            <div key={i} className="flex items-center justify-between font-mono text-[9px] py-1 border-b border-border/5">
                               <span className={ev.type === "click" || ev.type === "mousedown" ? "text-red-glow font-bold" : "text-emerald-glow/60"}>
                                  {ev.type.toUpperCase()}
                               </span>
                               <span className="text-muted-foreground/40">[{ev.x}, {ev.y}]</span>
                               <span className="text-muted-foreground">{ev.timestamp % 10000}</span>
                            </div>
                          ))}
                       </div>
                    </ScrollArea>
                 </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Verification Visualization (shows after solve) */}
        {solveResult && (
          <div className="lg:col-span-12 space-y-4 animate-in fade-in slide-in-from-top-2 duration-500">
             <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-amber-glow uppercase tracking-wider">Expert Track Analysis Result</h3>
                <Button variant="ghost" size="sm" onClick={() => setSolveResult(null)} className="text-[10px] uppercase font-bold text-muted-foreground">Dismiss</Button>
             </div>
             <CaptchaTraceVisualizer challengeId={challenge?.ID || ""} />
          </div>
        )}
      </div>
    </div>
  );
}
