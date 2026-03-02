"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToasts } from "@/components/Toasts";
import { CaptchaImage } from "@/components/CaptchaImage";
import { CaptchaTraceVisualizer } from "./CaptchaTraceVisualizer";

// Constants
const PERCENTAGE_MULTIPLIER = 100;
const SELECT_CHANGE_DELAY_MS = 50;
const GRID_ITEMS = 4;
const EVENTS_DISPLAY_COUNT = 15;
const TIMESTAMP_MODULUS = 10000;
const MAX_EVENTS = 1000;

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
  challenge: Record<string, unknown>;
  session_ID: string;
}

// API functions
async function fetchRandomChallenge(selectedType: string): Promise<unknown> {
  const url =
    selectedType === "random" ? "/api/captcha/random" : `/api/captcha/random?type=${selectedType}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error("Failed to fetch challenge");
  return res.json();
}

interface SubmitSolutionParams {
  challengeId: string;
  solution: string;
  events: CaptchaEvent[];
}

async function submitSolution({
  challengeId,
  solution,
  events,
}: SubmitSolutionParams): Promise<unknown> {
  const res = await fetch("/api/captcha/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ challenge_id: challengeId, solution, events, is_expert: true }),
  });
  if (!res.ok) throw new Error("Failed to submit solution");
  return res.json();
}

// Event recording logic
interface CreateEventRecorderParams {
  isRecording: boolean;
  interactionAreaRef: React.RefObject<HTMLDivElement | null>;
  setEvents: React.Dispatch<React.SetStateAction<CaptchaEvent[]>>;
}

function createEventRecorder({
  isRecording,
  interactionAreaRef,
  setEvents,
}: CreateEventRecorderParams) {
  return (e: Event) => {
    if (!isRecording) return;
    const rect = interactionAreaRef.current?.getBoundingClientRect();
    if (!rect) return;
    let clientX = 0,
      clientY = 0,
      key = "",
      deltaY = 0;
    if (e instanceof MouseEvent) {
      clientX = e.clientX;
      clientY = e.clientY;
    }
    if (e instanceof KeyboardEvent) key = e.key;
    if (e instanceof WheelEvent) deltaY = e.deltaY;
    const event: CaptchaEvent = {
      type: e.type,
      timestamp: Date.now(),
      x: clientX ? clientX - rect.left : 0,
      y: clientY ? clientY - rect.top : 0,
      key: key || "",
      delta: deltaY || 0,
    };
    setEvents(prev => [...prev.slice(-MAX_EVENTS), event]);
  };
}

// Hook for event recording
function useEventRecording(params: {
  isRecording: boolean;
  interactionAreaRef: React.RefObject<HTMLDivElement | null>;
  setEvents: React.Dispatch<React.SetStateAction<CaptchaEvent[]>>;
}) {
  const { isRecording, interactionAreaRef, setEvents } = params;
  const recordEvent = useCallback(
    (e: Event) => createEventRecorder({ isRecording, interactionAreaRef, setEvents })(e),
    [isRecording, interactionAreaRef, setEvents]
  );
  useEffect(() => {
    if (!isRecording) return;
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
  }, [isRecording, recordEvent]);
}

// Hook for fetching challenges
function useChallengeFetch(selectedType: string) {
  const [challenge, setChallenge] = useState<TrainerChallenge | null>(null);
  const [loading, setLoading] = useState(false);
  const { addToast } = useToasts();

  const resetAndFetch = useCallback(async () => {
    setLoading(true);
    try {
      const data = await fetchRandomChallenge(selectedType);
      setChallenge(data as TrainerChallenge);
      addToast(
        "🧪 Lab Initialized",
        "Expert Track recording started. Solve the challenge normally."
      );
    } catch (err) {
      console.error("Failed to start training:", err);
    } finally {
      setLoading(false);
    }
  }, [selectedType, addToast]);

  return { challenge, loading, setLoading, resetAndFetch };
}

// Hook for submitting solutions
function useSolutionSubmit(params: {
  challenge: TrainerChallenge | null;
  setIsRecording: (value: boolean) => void;
  setLoading: (value: boolean) => void;
}) {
  const { challenge, setIsRecording, setLoading } = params;
  const [solveResult, setSolveResult] = useState<Record<string, unknown> | null>(null);
  const { addToast } = useToasts();

  const submitSolve = useCallback(
    async (solution: string, events: CaptchaEvent[]) => {
      if (!challenge) return;
      setIsRecording(false);
      setLoading(true);
      try {
        const data = await submitSolution({ challengeId: challenge.ID, solution, events });
        setSolveResult(data as Record<string, unknown>);
        const solved = (data as Record<string, unknown>).solved as boolean;
        const botScore = (data as Record<string, unknown>).bot_score as number;
        if (solved)
          addToast(
            "🎖️ Expert Track Recorded",
            `Solution verified. Bot Score: ${(botScore * PERCENTAGE_MULTIPLIER).toFixed(1)}%`
          );
        else
          addToast(
            "⚠️ Solve Failed",
            "Solution was incorrect. Track still saved for negative sample."
          );
      } catch (err) {
        console.error("Failed to submit solve:", err);
      } finally {
        setLoading(false);
      }
    },
    [challenge, setIsRecording, setLoading, addToast]
  );

  return { solveResult, setSolveResult, submitSolve };
}

// Custom hook for managing training state and logic
function useCaptchaTraining() {
  const [selectedType, setSelectedType] = useState<string>("random");
  const [isRecording, setIsRecording] = useState(false);
  const [events, setEvents] = useState<CaptchaEvent[]>([]);
  const [solution, setSolution] = useState("");
  const interactionAreaRef = useRef<HTMLDivElement>(null);

  const { challenge, loading, setLoading, resetAndFetch } = useChallengeFetch(selectedType);
  const { solveResult, setSolveResult, submitSolve } = useSolutionSubmit({
    challenge,
    setIsRecording,
    setLoading,
  });

  const resetState = useCallback(() => {
    setSolveResult(null);
    setSolution("");
    setEvents([]);
  }, [setSolveResult]);

  const startTraining = useCallback(async () => {
    resetState();
    await resetAndFetch();
    setIsRecording(true);
  }, [resetState, resetAndFetch]);

  useEventRecording({ isRecording, interactionAreaRef, setEvents });

  const handleSubmit = useCallback(() => {
    submitSolve(solution, events);
  }, [submitSolve, solution, events]);

  return {
    challenge,
    selectedType,
    setSelectedType,
    events,
    solution,
    setSolution,
    solveResult,
    setSolveResult,
    loading,
    interactionAreaRef,
    startTraining,
    submitSolve: handleSubmit,
  };
}

// Initial type selector variant
function InitialTypeSelector({
  selectedType,
  setSelectedType,
  startTraining,
  loading,
}: {
  selectedType: string;
  setSelectedType: (type: string) => void;
  startTraining: () => void;
  loading: boolean;
}) {
  return (
    <div className="flex items-center gap-3">
      <label className="sr-only" htmlFor="captcha-type-select">
        CAPTCHA Type
      </label>
      <select
        id="captcha-type-select"
        value={selectedType}
        onChange={e => setSelectedType(e.target.value)}
        className="bg-black/40 border border-border/30 rounded px-3 py-1.5 text-xs text-muted-foreground focus:outline-none focus:border-cyan-glow/50"
      >
        <option value="random">Random Type</option>
        <option value="text">Text CAPTCHA</option>
        <option value="math">Math CAPTCHA</option>
        <option value="slider">Slider</option>
        <option value="image">Image Target</option>
        <option value="turnstile">Turnstile (Mock)</option>
        <option value="webgl">WebGL 3D</option>
        <option value="behavioral">Behavioral (Invisible)</option>
      </select>
      <Button
        onClick={startTraining}
        size="sm"
        className="skeuo-panel bg-emerald-glow/20 text-emerald-glow border-emerald-glow/30 hover:bg-emerald-glow/30"
        disabled={loading}
      >
        Generate New Training Session
      </Button>
    </div>
  );
}

// Active type selector variant
function ActiveTypeSelector({
  selectedType,
  setSelectedType,
  startTraining,
}: {
  selectedType: string;
  setSelectedType: (type: string) => void;
  startTraining: () => void;
}) {
  const handleChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setSelectedType(e.target.value);
    setTimeout(startTraining, SELECT_CHANGE_DELAY_MS);
  };
  return (
    <div className="flex items-center gap-3">
      <label className="sr-only" htmlFor="captcha-type-active">
        CAPTCHA Type
      </label>
      <select
        id="captcha-type-active"
        value={selectedType}
        onChange={handleChange}
        className="bg-black/40 border border-border/30 rounded px-3 py-1 h-7 text-[10px] text-muted-foreground focus:outline-none focus:border-cyan-glow/50"
      >
        <option value="random">Random</option>
        <option value="text">Text</option>
        <option value="math">Math</option>
        <option value="slider">Slider</option>
        <option value="image">Image Target</option>
        <option value="turnstile">Turnstile (Mock)</option>
        <option value="webgl">WebGL 3D</option>
        <option value="behavioral">Behavioral</option>
      </select>
      <Button
        onClick={startTraining}
        size="sm"
        variant="ghost"
        className="h-7 px-2 text-[10px] text-muted-foreground hover:text-cyan-glow"
      >
        ↻ Refresh
      </Button>
      <Badge
        variant="outline"
        className="text-[10px] text-amber-glow border-amber-glow/30 animate-pulse"
      >
        REC • EXPERT_TRACK_ACTIVE
      </Badge>
    </div>
  );
}

// Type selector that delegates to the appropriate variant
function TypeSelector({
  challenge,
  selectedType,
  setSelectedType,
  startTraining,
  loading,
}: {
  challenge: TrainerChallenge | null;
  selectedType: string;
  setSelectedType: (type: string) => void;
  startTraining: () => void;
  loading: boolean;
}) {
  if (!challenge) {
    return (
      <InitialTypeSelector
        selectedType={selectedType}
        setSelectedType={setSelectedType}
        startTraining={startTraining}
        loading={loading}
      />
    );
  }
  return (
    <ActiveTypeSelector
      selectedType={selectedType}
      setSelectedType={setSelectedType}
      startTraining={startTraining}
    />
  );
}

// Header component showing title and type selector
function TrainingHeader({
  challenge,
  selectedType,
  setSelectedType,
  startTraining,
  loading,
}: {
  challenge: TrainerChallenge | null;
  selectedType: string;
  setSelectedType: (type: string) => void;
  startTraining: () => void;
  loading: boolean;
}) {
  return (
    <>
      <CardTitle className="text-xs font-bold text-muted-foreground uppercase tracking-wider flex items-center gap-2">
        <span className="text-amber-glow animate-pulse">🧪</span>
        Intervention Lab: Expert Feedback Generation
      </CardTitle>
      <TypeSelector
        challenge={challenge}
        selectedType={selectedType}
        setSelectedType={setSelectedType}
        startTraining={startTraining}
        loading={loading}
      />
    </>
  );
}

// Empty state component when no challenge is active
function EmptyState({ onStart }: { onStart: () => void }) {
  return (
    <div className="flex-1 flex flex-col items-center justify-center p-20 text-center space-y-4">
      <div className="text-4xl">🔬</div>
      <div className="space-y-2">
        <h3 className="text-lg font-bold text-foreground">No Active Training Session</h3>
        <p className="text-sm text-muted-foreground max-w-md">
          Start a session to record your interactions. We use these &quot;Expert Tracks&quot; to
          calibrate the Sword RL Agent&apos;s behavioral simulation.
        </p>
      </div>
      <Button onClick={onStart} variant="outline">
        Initialize Lab
      </Button>
    </div>
  );
}

// Solution input component
function SolutionInput({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
}) {
  return (
    <input
      type="text"
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      className="w-full bg-black/40 border border-border/30 rounded px-3 py-2 text-sm font-mono focus:outline-none focus:border-cyan-glow/50 transition-colors"
      autoFocus
    />
  );
}

// Text challenge display
function TextChallenge({
  challenge,
  solution,
  setSolution,
}: {
  challenge: TrainerChallenge;
  solution: string;
  setSolution: (value: string) => void;
}) {
  return (
    <div className="space-y-4">
      <div className="skeuo-inset p-4 bg-white/5 flex items-center justify-center min-h-[100px]">
        {challenge.challenge?.image ? (
          <CaptchaImage
            src={String(challenge.challenge.image)}
            alt="CAPTCHA"
            className="max-w-full h-auto brightness-90 contrast-125"
          />
        ) : (
          <span className="text-3xl font-mono tracking-[0.2em] select-none blur-[0.5px] rotate-[-2deg] italic opacity-80">
            {String(challenge.challenge?.text ?? "CAPTCHA")}
          </span>
        )}
      </div>
      <SolutionInput value={solution} onChange={setSolution} placeholder="Enter characters..." />
    </div>
  );
}

// Math challenge display
function MathChallenge({
  challenge,
  solution,
  setSolution,
}: {
  challenge: TrainerChallenge;
  solution: string;
  setSolution: (value: string) => void;
}) {
  return (
    <div className="space-y-4">
      <div className="skeuo-inset p-4 bg-white/5 flex items-center justify-center min-h-[100px]">
        {challenge.challenge?.image ? (
          <CaptchaImage
            src={String(challenge.challenge.image)}
            alt="Math CAPTCHA"
            className="max-w-full h-auto brightness-90 contrast-125"
          />
        ) : (
          <span className="text-2xl font-bold font-mono text-cyan-glow">
            {String(challenge.challenge?.question ?? "")} = ?
          </span>
        )}
      </div>
      <SolutionInput value={solution} onChange={setSolution} placeholder="Result..." />
    </div>
  );
}

// Image grid for image challenges
function ImageGrid({
  solution,
  setSolution,
}: {
  solution: string;
  setSolution: (value: string) => void;
}) {
  const { addToast } = useToasts();
  const items = Array.from({ length: GRID_ITEMS }, (_, i) => i + 1);
  return (
    <div className="grid grid-cols-2 gap-2">
      {items.map(v => (
        <button
          key={v}
          onClick={() => {
            setSolution(`option_${v}`);
            addToast("Selection Recorded", `Expert interaction captured for option ${v}`);
          }}
          className={`skeuo-panel p-4 aspect-square flex items-center justify-center hover:bg-cyan-glow/5 transition-colors ${solution === `option_${v}` ? "border-cyan-glow/60 bg-cyan-glow/5" : ""}`}
        >
          <div className="w-8 h-8 rounded bg-border/20" />
        </button>
      ))}
    </div>
  );
}

// Image challenge display
function ImageChallenge({
  challenge,
  solution,
  setSolution,
}: {
  challenge: TrainerChallenge;
  solution: string;
  setSolution: (value: string) => void;
}) {
  const { addToast } = useToasts();
  const targetText =
    challenge.Type === "image"
      ? `Select the character: ${String(challenge.challenge?.target ?? "")}`
      : "Simulated challenge. Select the correct variant.";
  return (
    <div className="space-y-4">
      <p className="text-xs text-muted-foreground italic">{targetText}</p>
      {challenge.challenge?.image ? (
        <div className="skeuo-inset p-2 bg-white/5 flex items-center justify-center">
          <CaptchaImage
            src={String(challenge.challenge.image)}
            alt="CAPTCHA grid"
            className="max-w-full h-auto brightness-90 contrast-125"
            onClick={() => addToast("Interaction Recorded", "Coordinate-based selection captured.")}
          />
        </div>
      ) : (
        <ImageGrid solution={solution} setSolution={setSolution} />
      )}
      <SolutionInput
        value={solution}
        onChange={setSolution}
        placeholder="Enter target character or option..."
      />
    </div>
  );
}

// Slider challenge display
function SliderChallenge({
  challenge,
  solution,
  setSolution,
}: {
  challenge: TrainerChallenge;
  solution: string;
  setSolution: (value: string) => void;
}) {
  return (
    <div className="space-y-4">
      <p className="text-xs text-muted-foreground italic">Drag the slider to solve the puzzle.</p>
      {challenge.challenge?.image ? (
        <div className="skeuo-inset p-2 bg-white/5 flex items-center justify-center min-h-[100px]">
          <CaptchaImage
            src={String(challenge.challenge.image)}
            alt="Slider CAPTCHA Base"
            className="max-w-full h-auto brightness-90 contrast-125"
          />
        </div>
      ) : (
        <div className="skeuo-inset p-2 bg-white/5 flex items-center justify-center min-h-[100px] border border-dashed border-red-500/50">
          <p className="text-muted-foreground text-xs text-red-500">
            Image data missing from backend.
          </p>
        </div>
      )}
      <input
        type="range"
        min="0"
        max="200"
        value={solution}
        onChange={e => setSolution(e.target.value)}
        className="w-full h-2 bg-black/60 rounded-full appearance-none cursor-pointer accent-cyan-glow"
      />
      <div className="text-[10px] text-muted-foreground font-mono text-center">
        Offset: {solution}px
      </div>
    </div>
  );
}

// Challenge content switcher
function ChallengeContent({
  challenge,
  solution,
  setSolution,
}: {
  challenge: TrainerChallenge;
  solution: string;
  setSolution: (value: string) => void;
}) {
  switch (challenge.Type) {
    case "text":
      return <TextChallenge challenge={challenge} solution={solution} setSolution={setSolution} />;
    case "math":
      return <MathChallenge challenge={challenge} solution={solution} setSolution={setSolution} />;
    case "slider":
      return (
        <SliderChallenge challenge={challenge} solution={solution} setSolution={setSolution} />
      );
    case "hcaptcha":
    case "image_selection":
    case "image":
      return <ImageChallenge challenge={challenge} solution={solution} setSolution={setSolution} />;
    default:
      return <TextChallenge challenge={challenge} solution={solution} setSolution={setSolution} />;
  }
}

// Challenge display component for showing the challenge
function ChallengeDisplay({
  challenge,
  solution,
  setSolution,
}: {
  challenge: TrainerChallenge;
  solution: string;
  setSolution: (value: string) => void;
}) {
  return (
    <div className="skeuo-panel p-8 max-w-sm w-full bg-background border border-cyan-glow/20 shadow-2xl relative">
      <h4 className="text-xs font-bold text-muted-foreground uppercase mb-4 border-b border-border/10 pb-2">
        Type: {challenge.Type?.toUpperCase() || "UNKNOWN"}
      </h4>
      <div className="space-y-4">
        <ChallengeContent challenge={challenge} solution={solution} setSolution={setSolution} />
      </div>
    </div>
  );
}

// Telemetry badges showing current position and event count
function TelemetryBadges({ events }: { events: CaptchaEvent[] }) {
  const lastEvent = events[events.length - 1];
  return (
    <div className="absolute top-3 left-3 flex gap-2">
      <Badge
        variant="outline"
        className="text-[8px] border-border/20 text-muted-foreground/40 bg-black/20"
      >
        X: {lastEvent?.x ?? 0}
      </Badge>
      <Badge
        variant="outline"
        className="text-[8px] border-border/20 text-muted-foreground/40 bg-black/20"
      >
        Y: {lastEvent?.y ?? 0}
      </Badge>
      <Badge
        variant="outline"
        className="text-[8px] border-border/20 text-muted-foreground/40 bg-black/20"
      >
        EVENTS: {events.length}
      </Badge>
    </div>
  );
}

// Interaction area component for the recording area
function InteractionArea({
  challenge,
  solution,
  setSolution,
  events,
  interactionAreaRef,
  onSubmit,
  loading,
}: {
  challenge: TrainerChallenge;
  solution: string;
  setSolution: (value: string) => void;
  events: CaptchaEvent[];
  interactionAreaRef: React.RefObject<HTMLDivElement | null>;
  onSubmit: () => void;
  loading: boolean;
}) {
  return (
    <div
      ref={interactionAreaRef}
      className="flex-1 bg-black/60 p-10 flex flex-col items-center justify-center relative cursor-crosshair"
    >
      <ChallengeDisplay challenge={challenge} solution={solution} setSolution={setSolution} />
      <Button
        onClick={onSubmit}
        disabled={!solution || loading}
        className="w-full skeuo-panel bg-cyan-glow/20 text-cyan-glow border-cyan-glow/30 hover:bg-cyan-glow/30 mt-4 max-w-sm"
      >
        {loading ? "Analyzing..." : "Verify & Save Track"}
      </Button>
      <TelemetryBadges events={events} />
    </div>
  );
}

// Event log item component
function EventLogItem({ ev }: { ev: CaptchaEvent }) {
  const isClickEvent = ev.type === "click" || ev.type === "mousedown";
  return (
    <div className="flex items-center justify-between font-mono text-[9px] py-1 border-b border-border/5">
      <span className={isClickEvent ? "text-red-glow font-bold" : "text-emerald-glow/60"}>
        {ev.type.toUpperCase()}
      </span>
      <span className="text-muted-foreground/40">
        [{ev.x}, {ev.y}]
      </span>
      <span className="text-muted-foreground">{ev.timestamp % TIMESTAMP_MODULUS}</span>
    </div>
  );
}

// Event log component for the event list display
function EventLog({ events }: { events: CaptchaEvent[] }) {
  const displayEvents = events.slice(-EVENTS_DISPLAY_COUNT).reverse();
  return (
    <div className="w-full md:w-80 border-t md:border-t-0 md:border-l border-border/10 bg-black/20 flex flex-col">
      <div className="p-4 border-b border-border/10 bg-black/20 font-bold text-[10px] uppercase tracking-widest text-muted-foreground">
        Live Telemetry Stream
      </div>
      <ScrollArea className="flex-1 p-2">
        <div className="space-y-1">
          {displayEvents.map(ev => (
            <EventLogItem key={`${ev.timestamp}-${ev.type}`} ev={ev} />
          ))}
        </div>
      </ScrollArea>
    </div>
  );
}

// Result panel component for showing solve results
function ResultPanel({ challengeId, onDismiss }: { challengeId: string; onDismiss: () => void }) {
  return (
    <div className="lg:col-span-12 space-y-4 animate-in fade-in slide-in-from-top-2 duration-500">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-bold text-amber-glow uppercase tracking-wider">
          Expert Track Analysis Result
        </h3>
        <Button
          variant="ghost"
          size="sm"
          onClick={onDismiss}
          className="text-[10px] uppercase font-bold text-muted-foreground"
        >
          Dismiss
        </Button>
      </div>
      <CaptchaTraceVisualizer challengeId={challengeId} />
    </div>
  );
}

// Trainer content component for the main content area
function TrainerContent({
  challenge,
  solution,
  setSolution,
  events,
  interactionAreaRef,
  submitSolve,
  loading,
  startTraining,
}: {
  challenge: TrainerChallenge | null;
  solution: string;
  setSolution: (value: string) => void;
  events: CaptchaEvent[];
  interactionAreaRef: React.RefObject<HTMLDivElement | null>;
  submitSolve: () => void;
  loading: boolean;
  startTraining: () => void;
}) {
  if (!challenge) {
    return <EmptyState onStart={startTraining} />;
  }
  return (
    <div className="flex-1 flex flex-col md:flex-row">
      <InteractionArea
        challenge={challenge}
        solution={solution}
        setSolution={setSolution}
        events={events}
        interactionAreaRef={interactionAreaRef}
        onSubmit={submitSolve}
        loading={loading}
      />
      <EventLog events={events} />
    </div>
  );
}

// Main component
export function CaptchaTrainer() {
  const {
    challenge,
    selectedType,
    setSelectedType,
    events,
    solution,
    setSolution,
    solveResult,
    setSolveResult,
    loading,
    interactionAreaRef,
    startTraining,
    submitSolve,
  } = useCaptchaTraining();

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        <Card className="lg:col-span-12 skeuo-panel overflow-hidden">
          <CardHeader className="pb-3 border-b border-border/10 flex flex-row items-center justify-between">
            <TrainingHeader
              challenge={challenge}
              selectedType={selectedType}
              setSelectedType={setSelectedType}
              startTraining={startTraining}
              loading={loading}
            />
          </CardHeader>
          <CardContent className="p-0 min-h-[400px] flex flex-col">
            <TrainerContent
              challenge={challenge}
              solution={solution}
              setSolution={setSolution}
              events={events}
              interactionAreaRef={interactionAreaRef}
              submitSolve={submitSolve}
              loading={loading}
              startTraining={startTraining}
            />
          </CardContent>
        </Card>
        {solveResult && challenge && (
          <ResultPanel challengeId={challenge.ID} onDismiss={() => setSolveResult(null)} />
        )}
      </div>
    </div>
  );
}
