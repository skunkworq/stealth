"use client";

import { useState, useCallback, useRef, useEffect } from "react";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import { useReCaptchaActions } from "./useReCaptchaActions/index";
import { WidgetContent } from "./RecaptchaWidget/WidgetContent";

const MAX_REFRESHES = 5;
const TIMER_INTERVAL_MS = 1000;
const MOUSE_THROTTLE_MS = 50;
const SUBPIXEL_JITTER = 0.5;
const MS_PER_SECOND = 1000;

interface CaptchaEvent {
  type: string;
  timestamp: number;
  elapsed_ms: number;
  x?: number;
  y?: number;
  key?: string;
  delta?: number;
}

interface ChallengeData {
  id: string;
  type: string;
  image_base64: string;
  num_chars: number;
}

interface BehavioralMetrics {
  behavioral_score?: number;
  [key: string]: unknown;
}

type WidgetState = "idle" | "checking" | "challenge" | "verifying" | "passed" | "failed";

interface ReCaptchaState {
  state: WidgetState;
  setState: (state: WidgetState) => void;
  sessionId: string | null;
  setSessionId: (id: string | null) => void;
  challenge: ChallengeData | null;
  setChallenge: (challenge: ChallengeData | null) => void;
  solution: string;
  setSolution: (solution: string) => void;
  token: string | null;
  setToken: (token: string | null) => void;
  tokenExpiry: number | null;
  setTokenExpiry: (expiry: number | null) => void;
  refreshesRemaining: number;
  setRefreshesRemaining: (count: number) => void;
  behavioralMetrics: BehavioralMetrics | null;
  setBehavioralMetrics: (metrics: BehavioralMetrics | null) => void;
  error: string | null;
  setError: (error: string | null) => void;
  events: CaptchaEvent[];
  setEvents: (events: CaptchaEvent[] | ((prev: CaptchaEvent[]) => CaptchaEvent[])) => void;
  reset: () => void;
}

function useReCaptchaState(): ReCaptchaState {
  const [state, setState] = useState<WidgetState>("idle");
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [challenge, setChallenge] = useState<ChallengeData | null>(null);
  const [solution, setSolution] = useState("");
  const [token, setToken] = useState<string | null>(null);
  const [tokenExpiry, setTokenExpiry] = useState<number | null>(null);
  const [refreshesRemaining, setRefreshesRemaining] = useState(MAX_REFRESHES);
  const [behavioralMetrics, setBehavioralMetrics] = useState<BehavioralMetrics | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [events, setEvents] = useState<CaptchaEvent[]>([]);

  const reset = useCallback(() => {
    setState("idle");
    setSessionId(null);
    setChallenge(null);
    setSolution("");
    setToken(null);
    setTokenExpiry(null);
    setBehavioralMetrics(null);
    setError(null);
    setEvents([]);
    setRefreshesRemaining(MAX_REFRESHES);
  }, []);

  return {
    state,
    setState,
    sessionId,
    setSessionId,
    challenge,
    setChallenge,
    solution,
    setSolution,
    token,
    setToken,
    tokenExpiry,
    setTokenExpiry,
    refreshesRemaining,
    setRefreshesRemaining,
    behavioralMetrics,
    setBehavioralMetrics,
    error,
    setError,
    events,
    setEvents,
    reset,
  };
}

function useEventRecorder(
  startTimeRef: React.MutableRefObject<number | null>,
  setEvents: (events: CaptchaEvent[] | ((prev: CaptchaEvent[]) => CaptchaEvent[])) => void
) {
  const recordEvent = useCallback(
    (type: string, e?: React.MouseEvent | React.KeyboardEvent | MouseEvent) => {
      const now = Date.now();
      const elapsed = startTimeRef.current ? now - startTimeRef.current : 0;
      const evt: CaptchaEvent = {
        type,
        timestamp: now,
        elapsed_ms: elapsed,
      };
      if (e && "clientX" in e) {
        evt.x = e.clientX + Math.random() * SUBPIXEL_JITTER;
        evt.y = e.clientY + Math.random() * SUBPIXEL_JITTER;
      }
      if (e && "key" in e) {
        evt.key = (e as React.KeyboardEvent).key;
      }
      setEvents((prev: CaptchaEvent[]) => [...prev, evt]);
    },
    [startTimeRef, setEvents]
  );

  return { recordEvent };
}

function useMouseTracking(recordEvent: (type: string, e?: React.MouseEvent) => void) {
  const lastRecordRef = useRef(0);

  const handleMouseMove = useCallback(
    (e: React.MouseEvent) => {
      const now = Date.now();
      if (now - lastRecordRef.current >= MOUSE_THROTTLE_MS) {
        lastRecordRef.current = now;
        recordEvent("mousemove", e);
      }
    },
    [recordEvent]
  );

  return { handleMouseMove };
}

function useTimer(tokenExpiry: number | null, onExpire: () => void) {
  const [remainingSec, setRemainingSec] = useState(0);

  useEffect(() => {
    if (!tokenExpiry) return;

    const updateRemaining = () => {
      const remaining = Math.max(0, Math.round((tokenExpiry - Date.now()) / MS_PER_SECOND));
      setRemainingSec(remaining);
      if (remaining === 0) {
        onExpire();
      }
    };

    updateRemaining();
    const interval = setInterval(updateRemaining, TIMER_INTERVAL_MS);

    return () => clearInterval(interval);
  }, [tokenExpiry, onExpire]);

  return remainingSec;
}

export function ReCaptchaWidget() {
  const captchaState = useReCaptchaState();
  const checkboxRef = useRef<HTMLDivElement>(null);
  const startTimeRef = useRef<number | null>(null);

  const { recordEvent } = useEventRecorder(startTimeRef, captchaState.setEvents);
  const { handleMouseMove } = useMouseTracking(recordEvent);

  const actions = useReCaptchaActions({ captchaState, startTimeRef, recordEvent });
  const remainingSec = useTimer(captchaState.tokenExpiry, actions.handleExpire);

  return (
    <Card className="w-full" onMouseMove={handleMouseMove}>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-bold uppercase tracking-widest text-foreground/80">
          reCAPTCHA v2 Widget
        </CardTitle>
      </CardHeader>
      <WidgetContent
        state={captchaState.state}
        challenge={captchaState.challenge}
        solution={captchaState.solution}
        refreshesRemaining={captchaState.refreshesRemaining}
        error={captchaState.error}
        token={captchaState.token}
        remainingSec={remainingSec}
        behavioralMetrics={captchaState.behavioralMetrics}
        events={captchaState.events}
        checkboxRef={checkboxRef}
        recordEvent={recordEvent}
        onCheckboxClick={actions.handleCheckboxClick}
        onSolutionChange={actions.handleSolutionChange}
        onVerify={actions.handleVerify}
        onRefresh={actions.handleRefresh}
        onReset={captchaState.reset}
      />
    </Card>
  );
}
