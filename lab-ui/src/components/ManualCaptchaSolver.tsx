"use client";

import { useState, useRef, useCallback, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useToasts } from "@/components/Toasts";
import { CaptchaImage } from "@/components/CaptchaImage";

interface CaptchaEvent {
  type: string;
  timestamp: number;
  x: number;
  y: number;
  key: string;
  delta: number;
}

interface SolveResult {
  bot_score: number;
  metrics: Record<string, number>;
  solved: boolean;
  message?: string;
}

const CAPTCHA_TYPES = [
  { value: "text", label: "Text CAPTCHA" },
  { value: "math", label: "Math CAPTCHA" },
  { value: "slider", label: "Slider" },
  { value: "image", label: "Image Selection" },
  { value: "hcaptcha", label: "hCaptcha" },
  { value: "turnstile", label: "Turnstile" },
] as const;

// Constants
const MAX_FILE_SIZE_KB = 500;
const BYTES_PER_KB = 1024;
const MAX_FILE_SIZE = MAX_FILE_SIZE_KB * BYTES_PER_KB;
const MAX_STORED_EVENTS = 1000;
const PERCENTAGE_MULTIPLIER = 100;
const TELEMETRY_DISPLAY_COUNT = 20;
const TIMESTAMP_MODULUS = 10000;
const BOT_SCORE_LOW_THRESHOLD = 0.3;
const BOT_SCORE_MEDIUM_THRESHOLD = 0.7;
const METRICS_DECIMAL_PLACES = 3;

// Hook for event recording logic
function useEventRecording(
  isRecording: boolean,
  interactionAreaRef: React.RefObject<HTMLDivElement | null>
) {
  const [events, setEvents] = useState<CaptchaEvent[]>([]);

  const recordEvent = useCallback(
    (e: MouseEvent | KeyboardEvent | WheelEvent) => {
      if (!isRecording) return;
      const rect = interactionAreaRef.current?.getBoundingClientRect();
      if (!rect) return;

      const event: CaptchaEvent = {
        type: e.type,
        timestamp: Date.now(),
        x: "clientX" in e ? e.clientX - rect.left : 0,
        y: "clientY" in e ? e.clientY - rect.top : 0,
        key: "key" in e ? (e as KeyboardEvent).key : "",
        delta: "deltaY" in e ? (e as WheelEvent).deltaY : 0,
      };
      setEvents(prev => [...prev.slice(-MAX_STORED_EVENTS), event]);
    },
    [isRecording, interactionAreaRef]
  );

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

  const clearEvents = useCallback(() => setEvents([]), []);

  return { events, setEvents, clearEvents };
}

// File processing helpers
function validateFile(file: File, addToast: (t: string, m: string) => void): boolean {
  if (!file.type.startsWith("image/")) {
    addToast("Invalid File", "Only image files are accepted.");
    return false;
  }
  if (file.size > MAX_FILE_SIZE) {
    addToast("File Too Large", "Maximum file size is 500KB.");
    return false;
  }
  return true;
}

function readFileAsBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result as string;
      resolve(result.split(",")[1] ?? result);
    };
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });
}

// Hook for file handling
function useFileUpload(
  addToast: (title: string, message: string) => void,
  onSuccess: (file: File, base64: string) => void
) {
  const processFile = useCallback(
    async (file: File) => {
      if (!validateFile(file, addToast)) return;
      onSuccess(file, await readFileAsBase64(file));
    },
    [addToast, onSuccess]
  );
  return { processFile };
}

// Hook for submit logic
function useCaptchaSubmission(addToast: (title: string, message: string) => void) {
  const submit = useCallback(
    async (payload: {
      imageBase64: string;
      selectedType: string;
      solution: string;
      events: CaptchaEvent[];
    }) => {
      const res = await fetch("/api/captcha/manual-solve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          image: payload.imageBase64,
          type: payload.selectedType,
          solution: payload.solution,
          events: payload.events,
        }),
      });
      if (!res.ok) {
        addToast("Request Failed", "Server returned an error.");
        return null;
      }
      const data: SolveResult = await res.json();
      if (data.solved) {
        addToast(
          "Solve Recorded",
          `Bot Score: ${(data.bot_score * PERCENTAGE_MULTIPLIER).toFixed(1)}%`
        );
      } else {
        addToast("Solve Failed", "Track saved as negative training sample.");
      }
      return data;
    },
    [addToast]
  );
  return { submit };
}

// Hook for file-related handlers
function useFileHandlers(
  processFile: (f: File) => Promise<void>,
  setIsDragging: (v: boolean) => void
) {
  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) processFile(file);
    },
    [processFile, setIsDragging]
  );
  const handleFileChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) processFile(file);
    },
    [processFile]
  );
  return { handleDrop, handleFileChange };
}

// Hook for captcha state
function useCaptchaState() {
  const [selectedType, setSelectedType] = useState<string>("text");
  const [solution, setSolution] = useState("");
  const [imageBase64, setImageBase64] = useState<string | null>(null);
  const [imageName, setImageName] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isRecording, setIsRecording] = useState(false);
  const [solveResult, setSolveResult] = useState<SolveResult | null>(null);
  const [loading, setLoading] = useState(false);
  const interactionAreaRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  return {
    selectedType,
    setSelectedType,
    solution,
    setSolution,
    imageBase64,
    setImageBase64,
    imageName,
    setImageName,
    isDragging,
    setIsDragging,
    isRecording,
    setIsRecording,
    solveResult,
    setSolveResult,
    loading,
    setLoading,
    interactionAreaRef,
    fileInputRef,
  };
}

// Config interface for useSubmitHandler
interface SubmitHandlerConfig {
  state: ReturnType<typeof useCaptchaState>;
  events: CaptchaEvent[];
  submit: ReturnType<typeof useCaptchaSubmission>["submit"];
  addToast: (t: string, m: string) => void;
}

// Hook for submit handler
function useSubmitHandler({ state, events, submit, addToast }: SubmitHandlerConfig) {
  return useCallback(async () => {
    if (!state.imageBase64 || !state.solution) return;
    state.setIsRecording(false);
    state.setLoading(true);
    try {
      const data = await submit({
        imageBase64: state.imageBase64,
        selectedType: state.selectedType,
        solution: state.solution,
        events,
      });
      if (data) state.setSolveResult(data);
    } catch (err) {
      console.error("Failed to submit manual solve:", err);
      addToast("Network Error", "Could not reach the server.");
    } finally {
      state.setLoading(false);
    }
  }, [state, events, submit, addToast]);
}

// Hook for reset handler
function useResetHandler(
  state: ReturnType<typeof useCaptchaState>,
  setEvents: (v: CaptchaEvent[] | ((p: CaptchaEvent[]) => CaptchaEvent[])) => void
) {
  return useCallback(() => {
    state.setImageBase64(null);
    state.setImageName(null);
    state.setSolution("");
    setEvents([]);
    state.setIsRecording(false);
    state.setSolveResult(null);
  }, [state, setEvents]);
}

// Config interface for useFileSuccessHandler
interface FileSuccessHandlerConfig {
  state: ReturnType<typeof useCaptchaState>;
  addToast: (t: string, m: string) => void;
  clearEvents: () => void;
}

// Hook for file success handler
function useFileSuccessHandler({ state, addToast, clearEvents }: FileSuccessHandlerConfig) {
  return useCallback(
    (file: File, base64: string) => {
      state.setImageBase64(base64);
      state.setImageName(file.name);
      state.setIsRecording(true);
      state.setSolveResult(null);
      clearEvents();
      state.setSolution("");
      addToast("Image Loaded", `Recording started for ${file.name}`);
    },
    [state, addToast, clearEvents]
  );
}

// Main hook composed of smaller hooks
function useManualCaptcha() {
  const state = useCaptchaState();
  const { addToast } = useToasts();
  const { events, setEvents, clearEvents } = useEventRecording(
    state.isRecording,
    state.interactionAreaRef
  );
  const { submit } = useCaptchaSubmission(addToast);
  const onFileSuccess = useFileSuccessHandler({ state, addToast, clearEvents });
  const { processFile } = useFileUpload(addToast, onFileSuccess);
  const { handleDrop, handleFileChange } = useFileHandlers(processFile, state.setIsDragging);
  const handleSubmit = useSubmitHandler({ state, events, submit, addToast });
  const handleReset = useResetHandler(state, setEvents);

  return {
    ...state,
    events,
    setEvents,
    handleDrop,
    handleFileChange,
    handleSubmit,
    handleReset,
  };
}

// RecordingBadge component
interface RecordingBadgeProps {
  isRecording: boolean;
  eventsCount: number;
}

function RecordingBadge({ isRecording, eventsCount }: RecordingBadgeProps) {
  if (!isRecording) return null;
  return (
    <Badge
      variant="outline"
      className="text-[10px] text-purple-glow border-purple-glow/30 animate-pulse"
    >
      REC -- EVENTS: {eventsCount}
    </Badge>
  );
}

// Header component
interface SolverHeaderProps {
  selectedType: string;
  setSelectedType: (type: string) => void;
  isRecording: boolean;
  eventsCount: number;
  imageBase64: string | null;
  onReset: () => void;
}

function SolverHeader({
  selectedType,
  setSelectedType,
  isRecording,
  eventsCount,
  imageBase64,
  onReset,
}: SolverHeaderProps) {
  return (
    <CardHeader className="pb-3 border-b border-border/10 flex flex-row items-center justify-between">
      <CardTitle className="text-xs font-bold text-muted-foreground uppercase tracking-wider flex items-center gap-2">
        <span className="text-purple-glow animate-pulse">&#9998;</span>
        Manual CAPTCHA Solver
      </CardTitle>
      <div className="flex items-center gap-3">
        <Select value={selectedType} onValueChange={setSelectedType}>
          <SelectTrigger
            size="sm"
            className="h-7 bg-black/40 border-border/30 text-[10px] text-muted-foreground w-[140px]"
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {CAPTCHA_TYPES.map(t => (
              <SelectItem key={t.value} value={t.value} className="text-xs">
                {t.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <RecordingBadge isRecording={isRecording} eventsCount={eventsCount} />
        {imageBase64 && (
          <Button
            onClick={onReset}
            variant="ghost"
            size="sm"
            className="h-7 px-2 text-[10px] text-muted-foreground hover:text-red-glow"
          >
            Reset
          </Button>
        )}
      </div>
    </CardHeader>
  );
}

// Drop zone component
interface DropZoneProps {
  isDragging: boolean;
  onDragOver: (e: React.DragEvent) => void;
  onDragLeave: () => void;
  onDrop: (e: React.DragEvent) => void;
  onClick: () => void;
  fileInputRef: React.RefObject<HTMLInputElement | null>;
  onFileChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
}

function DropZone({
  isDragging,
  onDragOver,
  onDragLeave,
  onDrop,
  onClick,
  fileInputRef,
  onFileChange,
}: DropZoneProps) {
  return (
    <div
      onDragOver={onDragOver}
      onDragLeave={onDragLeave}
      onDrop={onDrop}
      onClick={onClick}
      className={`skeuo-panel w-full max-w-md p-12 flex flex-col items-center justify-center cursor-pointer transition-all border-dashed border-2 ${
        isDragging
          ? "border-purple-glow/60 bg-purple-glow/5"
          : "border-border/20 hover:border-border/40 bg-black/20"
      }`}
    >
      <div className="text-4xl mb-4 filter grayscale opacity-60">&#128444;</div>
      <p className="text-xs text-muted-foreground text-center uppercase tracking-wider font-bold mb-1">
        Drop CAPTCHA Image Here
      </p>
      <p className="text-[9px] text-muted-foreground/40 text-center">
        or click to browse -- max 500KB, image/* only
      </p>
      <input
        ref={fileInputRef}
        type="file"
        accept="image/*"
        onChange={onFileChange}
        className="hidden"
      />
    </div>
  );
}

// Solution input component
interface SolutionInputProps {
  solution: string;
  onChange: (value: string) => void;
  onSubmit: () => void;
  loading: boolean;
}

function SolutionInput({ solution, onChange, onSubmit, loading }: SolutionInputProps) {
  return (
    <div className="space-y-2">
      <Label className="text-[9px] text-muted-foreground uppercase tracking-wider font-bold">
        Solution
      </Label>
      <Input
        value={solution}
        onChange={e => onChange(e.target.value)}
        placeholder="Enter CAPTCHA solution..."
        className="bg-black/40 border-border/30 font-mono text-sm focus-visible:border-purple-glow/50 focus-visible:ring-purple-glow/20"
        autoFocus
      />
      <Button
        onClick={onSubmit}
        disabled={!solution || loading}
        className="w-full skeuo-panel bg-purple-glow/20 text-purple-glow border-purple-glow/30 hover:bg-purple-glow/30"
      >
        {loading ? "Analyzing..." : "Submit & Record Track"}
      </Button>
    </div>
  );
}

// Coordinate overlay component
interface CoordinateOverlayProps {
  lastX: number;
  lastY: number;
  eventsCount: number;
}

function CoordinateOverlay({ lastX, lastY, eventsCount }: CoordinateOverlayProps) {
  return (
    <div className="absolute top-3 left-3 flex gap-2">
      <Badge
        variant="outline"
        className="text-[8px] border-border/20 text-muted-foreground/40 bg-black/20"
      >
        X: {lastX}
      </Badge>
      <Badge
        variant="outline"
        className="text-[8px] border-border/20 text-muted-foreground/40 bg-black/20"
      >
        Y: {lastY}
      </Badge>
      <Badge
        variant="outline"
        className="text-[8px] border-border/20 text-muted-foreground/40 bg-black/20"
      >
        EVENTS: {eventsCount}
      </Badge>
    </div>
  );
}

// Event telemetry component
interface EventTelemetryProps {
  events: CaptchaEvent[];
}

function EventTelemetry({ events }: EventTelemetryProps) {
  return (
    <div className="w-full md:w-80 border-t md:border-t-0 md:border-l border-border/10 bg-black/20 flex flex-col">
      <div className="p-4 border-b border-border/10 bg-black/20 font-bold text-[10px] uppercase tracking-widest text-muted-foreground">
        Live Telemetry Stream
      </div>
      <ScrollArea className="flex-1 p-2">
        <div className="space-y-1">
          {events.length === 0 ? (
            <div className="p-8 text-center text-[9px] text-muted-foreground/30 uppercase">
              Awaiting input events...
            </div>
          ) : (
            events
              .slice(-TELEMETRY_DISPLAY_COUNT)
              .reverse()
              .map(ev => (
                <div
                  key={ev.timestamp}
                  className="flex items-center justify-between font-mono text-[9px] py-1 border-b border-border/5"
                >
                  <span
                    className={
                      ev.type === "mousedown"
                        ? "text-red-glow font-bold"
                        : ev.type === "keydown"
                          ? "text-amber-glow font-bold"
                          : "text-emerald-glow/60"
                    }
                  >
                    {ev.type.toUpperCase()}
                  </span>
                  <span className="text-muted-foreground/40">
                    [{Math.round(ev.x)}, {Math.round(ev.y)}]
                  </span>
                  <span className="text-muted-foreground">{ev.timestamp % TIMESTAMP_MODULUS}</span>
                </div>
              ))
          )}
        </div>
      </ScrollArea>
    </div>
  );
}

// ScoreDisplay component
interface ScoreDisplayProps {
  botScore: number;
}

function ScoreDisplay({ botScore }: ScoreDisplayProps) {
  const scoreClass =
    botScore < BOT_SCORE_LOW_THRESHOLD
      ? "text-emerald-glow"
      : botScore < BOT_SCORE_MEDIUM_THRESHOLD
        ? "text-amber-glow"
        : "text-red-glow";
  return (
    <div className="skeuo-inset p-4 bg-black/20 space-y-1">
      <p className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold">
        Bot Score
      </p>
      <p className={`text-lg font-bold font-mono ${scoreClass}`}>
        {(botScore * PERCENTAGE_MULTIPLIER).toFixed(1)}%
      </p>
    </div>
  );
}

// MetricsList component
interface MetricsListProps {
  metrics: Record<string, number>;
}

function MetricsList({ metrics }: MetricsListProps) {
  if (!metrics || Object.keys(metrics).length === 0) return null;
  return (
    <div className="mt-5">
      <p className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold mb-3">
        Detailed Metrics
      </p>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        {Object.entries(metrics).map(([key, val]) => (
          <div key={key} className="skeuo-inset p-2 bg-black/10 flex justify-between items-center">
            <span className="text-[9px] text-muted-foreground/60 uppercase truncate mr-2">
              {key}
            </span>
            <span className="text-[10px] font-mono text-foreground">
              {typeof val === "number" ? val.toFixed(METRICS_DECIMAL_PLACES) : String(val)}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ResultActions component
interface ResultActionsProps {
  onDismiss: () => void;
}

function ResultActions({ onDismiss }: ResultActionsProps) {
  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={onDismiss}
      className="text-[10px] uppercase font-bold text-muted-foreground hover:text-red-glow"
    >
      Dismiss
    </Button>
  );
}

// Result display component
interface ResultDisplayProps {
  result: SolveResult;
  eventsCount: number;
  selectedType: string;
  onDismiss: () => void;
}

function ResultDisplay({ result, eventsCount, selectedType, onDismiss }: ResultDisplayProps) {
  return (
    <Card className="lg:col-span-12 skeuo-panel overflow-hidden animate-in fade-in slide-in-from-top-2 duration-500">
      <CardHeader className="pb-3 border-b border-border/10 flex flex-row items-center justify-between">
        <CardTitle className="text-xs font-bold text-muted-foreground uppercase tracking-wider">
          Solve Analysis Result
        </CardTitle>
        <ResultActions onDismiss={onDismiss} />
      </CardHeader>
      <CardContent className="p-5">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="skeuo-inset p-4 bg-black/20 space-y-1">
            <p className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold">
              Status
            </p>
            <Badge
              variant="outline"
              className={
                result.solved
                  ? "text-emerald-glow border-emerald-glow/30"
                  : "text-red-glow border-red-glow/30"
              }
            >
              {result.solved ? "SOLVED" : "FAILED"}
            </Badge>
          </div>
          <ScoreDisplay botScore={result.bot_score} />
          <div className="skeuo-inset p-4 bg-black/20 space-y-1">
            <p className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold">
              Events Captured
            </p>
            <p className="text-lg font-bold font-mono text-cyan-glow">{eventsCount}</p>
          </div>
          <div className="skeuo-inset p-4 bg-black/20 space-y-1">
            <p className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold">
              Type
            </p>
            <p className="text-sm font-bold font-mono text-purple-glow uppercase">{selectedType}</p>
          </div>
        </div>
        <MetricsList metrics={result.metrics} />
      </CardContent>
    </Card>
  );
}

// ChallengeImage component
interface ChallengeImageProps {
  imageBase64: string;
  imageName: string;
  selectedType: string;
}

function ChallengeImage({ imageBase64, imageName, selectedType }: ChallengeImageProps) {
  return (
    <div className="skeuo-panel p-8 max-w-sm w-full bg-background border border-purple-glow/20 shadow-2xl space-y-5">
      <div className="flex items-center justify-between border-b border-border/10 pb-2">
        <h4 className="text-xs font-bold text-muted-foreground uppercase">
          Type: {selectedType.toUpperCase()}
        </h4>
        <Badge variant="outline" className="text-[8px] border-border/20 text-muted-foreground/60">
          {imageName}
        </Badge>
      </div>
      <div className="skeuo-inset p-3 bg-white/5 flex items-center justify-center min-h-[120px]">
        <CaptchaImage
          src={imageBase64}
          alt="CAPTCHA"
          className="max-w-full max-h-[200px] h-auto brightness-90 contrast-125"
        />
      </div>
    </div>
  );
}

// InputSection component
interface InputSectionProps {
  solution: string;
  onSolutionChange: (value: string) => void;
  onSubmit: () => void;
  loading: boolean;
}

function InputSection({ solution, onSolutionChange, onSubmit, loading }: InputSectionProps) {
  return (
    <div className="skeuo-panel p-8 max-w-sm w-full bg-background border border-purple-glow/20 shadow-2xl space-y-5">
      <SolutionInput
        solution={solution}
        onChange={onSolutionChange}
        onSubmit={onSubmit}
        loading={loading}
      />
    </div>
  );
}

// DropZone wrapper for drag handling
interface DropZoneWrapperProps {
  isDragging: boolean;
  setIsDragging: (v: boolean) => void;
  onDrop: (e: React.DragEvent) => void;
  fileInputRef: React.RefObject<HTMLInputElement | null>;
  onFileChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
}

function DropZoneWrapper({
  isDragging,
  setIsDragging,
  onDrop,
  fileInputRef,
  onFileChange,
}: DropZoneWrapperProps) {
  return (
    <DropZone
      isDragging={isDragging}
      onDragOver={e => {
        e.preventDefault();
        setIsDragging(true);
      }}
      onDragLeave={() => setIsDragging(false)}
      onDrop={onDrop}
      onClick={() => fileInputRef.current?.click()}
      fileInputRef={fileInputRef}
      onFileChange={onFileChange}
    />
  );
}

// Challenge content component
interface ChallengeContentProps {
  imageBase64: string | null;
  imageName: string | null;
  selectedType: string;
  solution: string;
  onSolutionChange: (value: string) => void;
  onSubmit: () => void;
  loading: boolean;
}

function ChallengeContent({
  imageBase64,
  imageName,
  selectedType,
  solution,
  onSolutionChange,
  onSubmit,
  loading,
}: ChallengeContentProps) {
  if (!imageBase64) return null;
  return (
    <>
      <ChallengeImage
        imageBase64={imageBase64}
        imageName={imageName || ""}
        selectedType={selectedType}
      />
      <InputSection
        solution={solution}
        onSolutionChange={onSolutionChange}
        onSubmit={onSubmit}
        loading={loading}
      />
    </>
  );
}

// Challenge viewer component
interface ChallengeViewerProps {
  imageBase64: string | null;
  imageName: string | null;
  selectedType: string;
  solution: string;
  onSolutionChange: (value: string) => void;
  onSubmit: () => void;
  loading: boolean;
  events: CaptchaEvent[];
  isDragging: boolean;
  setIsDragging: (dragging: boolean) => void;
  onDrop: (e: React.DragEvent) => void;
  onFileChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  fileInputRef: React.RefObject<HTMLInputElement | null>;
  interactionAreaRef: React.RefObject<HTMLDivElement | null>;
}

function ChallengeViewer(props: ChallengeViewerProps) {
  const { events, isDragging, setIsDragging, interactionAreaRef } = props;
  const lastEvent = events[events.length - 1];
  return (
    <div
      ref={interactionAreaRef}
      className="flex-1 bg-black/60 p-8 flex flex-col items-center justify-center relative"
    >
      {!props.imageBase64 ? (
        <DropZoneWrapper
          isDragging={isDragging}
          setIsDragging={setIsDragging}
          onDrop={props.onDrop}
          fileInputRef={props.fileInputRef}
          onFileChange={props.onFileChange}
        />
      ) : (
        <ChallengeContent
          imageBase64={props.imageBase64}
          imageName={props.imageName}
          selectedType={props.selectedType}
          solution={props.solution}
          onSolutionChange={props.onSolutionChange}
          onSubmit={props.onSubmit}
          loading={props.loading}
        />
      )}
      {props.imageBase64 && (
        <CoordinateOverlay
          lastX={lastEvent?.x ?? 0}
          lastY={lastEvent?.y ?? 0}
          eventsCount={events.length}
        />
      )}
    </div>
  );
}

// Solver content component
interface SolverContentProps {
  events: CaptchaEvent[];
  isDragging: boolean;
  setIsDragging: (v: boolean) => void;
  handleDrop: (e: React.DragEvent) => void;
  handleFileChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  fileInputRef: React.RefObject<HTMLInputElement | null>;
  interactionAreaRef: React.RefObject<HTMLDivElement | null>;
  imageBase64: string | null;
  imageName: string | null;
  selectedType: string;
  solution: string;
  setSolution: (v: string) => void;
  handleSubmit: () => void;
  loading: boolean;
}

function SolverContent(props: SolverContentProps) {
  return (
    <CardContent className="p-0 min-h-[450px] flex flex-col">
      <div className="flex-1 flex flex-col md:flex-row">
        <ChallengeViewer
          events={props.events}
          isDragging={props.isDragging}
          setIsDragging={props.setIsDragging}
          onDrop={props.handleDrop}
          onFileChange={props.handleFileChange}
          fileInputRef={props.fileInputRef}
          interactionAreaRef={props.interactionAreaRef}
          imageBase64={props.imageBase64}
          imageName={props.imageName}
          selectedType={props.selectedType}
          solution={props.solution}
          onSolutionChange={props.setSolution}
          onSubmit={props.handleSubmit}
          loading={props.loading}
        />
        <EventTelemetry events={props.events} />
      </div>
    </CardContent>
  );
}

// Solver card component
interface SolverCardProps {
  selectedType: string;
  setSelectedType: (v: string) => void;
  isRecording: boolean;
  events: CaptchaEvent[];
  imageBase64: string | null;
  onReset: () => void;
  children: React.ReactNode;
}

function SolverCard({
  selectedType,
  setSelectedType,
  isRecording,
  events,
  imageBase64,
  onReset,
  children,
}: SolverCardProps) {
  return (
    <Card className="lg:col-span-12 skeuo-panel overflow-hidden">
      <SolverHeader
        selectedType={selectedType}
        setSelectedType={setSelectedType}
        isRecording={isRecording}
        eventsCount={events.length}
        imageBase64={imageBase64}
        onReset={onReset}
      />
      {children}
    </Card>
  );
}

// Result section component
interface ResultSectionProps {
  solveResult: SolveResult | null;
  eventsCount: number;
  selectedType: string;
  onDismiss: () => void;
}

function ResultSection({ solveResult, eventsCount, selectedType, onDismiss }: ResultSectionProps) {
  if (!solveResult) return null;
  return (
    <ResultDisplay
      result={solveResult}
      eventsCount={eventsCount}
      selectedType={selectedType}
      onDismiss={onDismiss}
    />
  );
}

// Layout wrapper component
function SolverLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">{children}</div>
    </div>
  );
}

// Main component
export function ManualCaptchaSolver() {
  const h = useManualCaptcha();
  return (
    <SolverLayout>
      <SolverCard
        selectedType={h.selectedType}
        setSelectedType={h.setSelectedType}
        isRecording={h.isRecording}
        events={h.events}
        imageBase64={h.imageBase64}
        onReset={h.handleReset}
      >
        <SolverContent
          events={h.events}
          isDragging={h.isDragging}
          setIsDragging={h.setIsDragging}
          handleDrop={h.handleDrop}
          handleFileChange={h.handleFileChange}
          fileInputRef={h.fileInputRef}
          interactionAreaRef={h.interactionAreaRef}
          imageBase64={h.imageBase64}
          imageName={h.imageName}
          selectedType={h.selectedType}
          solution={h.solution}
          setSolution={h.setSolution}
          handleSubmit={h.handleSubmit}
          loading={h.loading}
        />
      </SolverCard>
      <ResultSection
        solveResult={h.solveResult}
        eventsCount={h.events.length}
        selectedType={h.selectedType}
        onDismiss={() => h.setSolveResult(null)}
      />
    </SolverLayout>
  );
}
