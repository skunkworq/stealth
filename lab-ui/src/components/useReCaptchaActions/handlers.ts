"use client";

import { useCallback } from "react";
import {
  initSession,
  createScrollEvent,
  createScrollEvents,
  submitCheckbox,
  createTypingEvents,
  submitVerification,
  refreshChallenge,
} from "./api";
import type { ReCaptchaState, WidgetState } from "./types";

const TOKEN_TTL_MS = 120_000;
const MAX_REFRESHES = 5;

interface CheckboxClickCtx {
  events: import("./types").CaptchaEvent[];
  recordEvent: (type: string, e?: React.MouseEvent) => void;
  startTimeRef: React.MutableRefObject<number | null>;
  captchaState: ReCaptchaState;
}

function useSetters(captchaState: ReCaptchaState) {
  return {
    setState: captchaState.setState,
    setSessionId: captchaState.setSessionId,
    setChallenge: captchaState.setChallenge,
    setToken: captchaState.setToken,
    setTokenExpiry: captchaState.setTokenExpiry,
    setRefreshesRemaining: captchaState.setRefreshesRemaining,
    setBehavioralMetrics: captchaState.setBehavioralMetrics,
    setError: captchaState.setError,
  };
}

export function useCheckboxClickHandler(ctx: CheckboxClickCtx) {
  const { events, recordEvent, startTimeRef, captchaState } = ctx;
  const setters = useSetters(captchaState);

  return useCallback(
    async (e: React.MouseEvent) => {
      recordEvent("click", e);
      setters.setState("checking");
      setters.setError(null);
      startTimeRef.current = Date.now();

      try {
        const sessionId = await initSession();
        setters.setSessionId(sessionId);

        const scrollEvt = createScrollEvent(startTimeRef.current);
        const checkData = await submitCheckbox(sessionId, [...events, scrollEvt]);

        setters.setBehavioralMetrics({ behavioral_score: checkData.behavioral_score });

        if (checkData.passed) {
          setters.setToken(checkData.token ?? null);
          setters.setTokenExpiry(Date.now() + TOKEN_TTL_MS);
          setters.setState("passed");
        } else {
          setters.setChallenge(checkData.challenge ?? null);
          setters.setRefreshesRemaining(MAX_REFRESHES);
          setters.setState("challenge");
        }
      } catch (err) {
        setters.setError(err instanceof Error ? err.message : "Unknown error");
        setters.setState("failed");
      }
    },
    [events, recordEvent, startTimeRef, setters]
  );
}

interface VerifyCtx {
  sessionId: string | null;
  solution: string;
  events: import("./types").CaptchaEvent[];
  startTimeRef: React.MutableRefObject<number | null>;
  setState: (s: WidgetState) => void;
  setError: (e: string | null) => void;
  setBehavioralMetrics: (m: import("./types").BehavioralMetrics | null) => void;
  setToken: (t: string | null) => void;
  setTokenExpiry: (e: number | null) => void;
}

export function useVerifyHandler(ctx: VerifyCtx) {
  const {
    sessionId,
    solution,
    events,
    startTimeRef,
    setState,
    setError,
    setBehavioralMetrics,
    setToken,
    setTokenExpiry,
  } = ctx;

  return useCallback(async () => {
    if (!sessionId || !solution) return;
    setState("verifying");
    setError(null);

    const typingEvents = createTypingEvents(solution, startTimeRef.current);
    const scrollEvents = createScrollEvents(startTimeRef.current);

    try {
      const data = await submitVerification({
        sessionId,
        solution,
        events: [...events, ...scrollEvents, ...typingEvents],
      });

      setBehavioralMetrics({ behavioral_score: data.behavioral_score, ...data });

      if (data.success) {
        setToken(data.token ?? null);
        setTokenExpiry(Date.now() + TOKEN_TTL_MS);
        setState("passed");
      } else {
        setError((data.error_codes || []).join(", ") || "Verification failed");
        setState("challenge");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
      setState("challenge");
    }
  }, [
    sessionId,
    solution,
    events,
    startTimeRef,
    setState,
    setError,
    setBehavioralMetrics,
    setToken,
    setTokenExpiry,
  ]);
}

interface RefreshCtx {
  sessionId: string | null;
  recordEvent: (type: string) => void;
  setError: (e: string | null) => void;
  setSolution: (s: string) => void;
  setChallenge: (c: import("./types").ChallengeData | null) => void;
  setRefreshesRemaining: (n: number) => void;
}

export function useRefreshHandler(ctx: RefreshCtx) {
  const { sessionId, recordEvent, setError, setSolution, setChallenge, setRefreshesRemaining } =
    ctx;

  return useCallback(async () => {
    if (!sessionId) return;
    setError(null);
    setSolution("");
    recordEvent("click");

    try {
      const data = await refreshChallenge(sessionId);
      setChallenge(data.challenge);
      setRefreshesRemaining(data.refreshes_remaining ?? 0);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    }
  }, [sessionId, recordEvent, setError, setSolution, setChallenge, setRefreshesRemaining]);
}

interface SolutionCtx {
  setSolution: (s: string) => void;
}

export function useSolutionChangeHandler(ctx: SolutionCtx) {
  const { setSolution } = ctx;
  return useCallback((value: string) => setSolution(value), [setSolution]);
}

interface ExpireCtx {
  setToken: (t: string | null) => void;
  setTokenExpiry: (e: number | null) => void;
  setState: (s: WidgetState) => void;
}

export function useExpireHandler(ctx: ExpireCtx) {
  const { setToken, setTokenExpiry, setState } = ctx;
  return useCallback(() => {
    setToken(null);
    setTokenExpiry(null);
    setState("idle");
  }, [setToken, setTokenExpiry, setState]);
}
