"use client";

const API_BASE = "";
const SCROLL_DELTA_MIN = 80;
const SCROLL_DELTA_MAX = 120;
const SCROLL_COUNT_MIN = 3;
const SCROLL_COUNT_MAX = 6;
const SCROLL_INTERVAL_MIN_MS = 200;
const SCROLL_INTERVAL_MAX_MS = 600;
const TYPING_BASE_DELAY_MS = 1000;
const TYPING_CHAR_DELAY_MS = 100;
const TYPING_RANDOM_VARIANCE_MS = 80;

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

interface CheckboxResponse {
  passed: boolean;
  behavioral_score?: number;
  challenge?: ChallengeData;
  token?: string;
}

interface BehavioralIndicator {
  check: string;
  message: string;
  weight: number;
  field: string;
  value: string;
}

interface BehavioralBreakdown {
  score: number;
  detected: boolean;
  mouse_events: number;
  typing_events: number;
  scroll_events: number;
  click_events: number;
  total_events: number;
  indicator_count: number;
  indicators: BehavioralIndicator[];
}

interface VerifyResponse {
  success: boolean;
  behavioral_score?: number;
  behavioral_breakdown?: BehavioralBreakdown;
  token?: string;
  error_codes?: string[];
}

export async function initSession(): Promise<string> {
  const res = await fetch(`${API_BASE}/api/recaptcha/init`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
  });
  const data = await res.json();
  return data.session_id;
}

export function createScrollEvent(startTime: number | null): CaptchaEvent {
  const scrollDelta = SCROLL_DELTA_MIN + Math.random() * (SCROLL_DELTA_MAX - SCROLL_DELTA_MIN);
  return {
    type: "scroll",
    timestamp: Date.now(),
    elapsed_ms: Date.now() - (startTime ?? Date.now()),
    delta: scrollDelta,
  };
}

/** Generate multiple varied scroll events to match real browsing behavior. */
export function createScrollEvents(startTime: number | null): CaptchaEvent[] {
  const count =
    SCROLL_COUNT_MIN + Math.floor(Math.random() * (SCROLL_COUNT_MAX - SCROLL_COUNT_MIN + 1));
  const base = startTime ?? Date.now();
  const events: CaptchaEvent[] = [];
  let elapsed = 0;

  for (let i = 0; i < count; i++) {
    const gap =
      SCROLL_INTERVAL_MIN_MS + Math.random() * (SCROLL_INTERVAL_MAX_MS - SCROLL_INTERVAL_MIN_MS);
    elapsed += Math.round(gap);
    // Vary delta so they're not identical (avoids uniform_scroll_deltas check)
    const delta = SCROLL_DELTA_MIN + Math.random() * (SCROLL_DELTA_MAX - SCROLL_DELTA_MIN);
    events.push({
      type: "scroll",
      timestamp: Math.round(base + elapsed),
      elapsed_ms: elapsed,
      delta,
    });
  }
  return events;
}

export async function submitCheckbox(
  sessionId: string,
  events: CaptchaEvent[]
): Promise<CheckboxResponse> {
  const res = await fetch(`${API_BASE}/api/recaptcha/checkbox`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session_id: sessionId, events }),
  });
  return res.json();
}

export function createTypingEvents(solution: string, startTime: number | null): CaptchaEvent[] {
  return solution.split("").map((ch, i) => {
    const baseDelay = TYPING_BASE_DELAY_MS + i * TYPING_CHAR_DELAY_MS;
    const variance = Math.random() * TYPING_RANDOM_VARIANCE_MS;
    const delay = Math.round(baseDelay + variance);
    return {
      type: "keydown",
      timestamp: Math.round((startTime ?? Date.now()) + delay),
      elapsed_ms: delay,
      key: ch,
    };
  });
}

interface SubmitVerifyParams {
  sessionId: string;
  solution: string;
  events: CaptchaEvent[];
}

export async function submitVerification(params: SubmitVerifyParams): Promise<VerifyResponse> {
  const res = await fetch(`${API_BASE}/api/recaptcha/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_id: params.sessionId,
      solution: params.solution,
      events: params.events,
    }),
  });
  return res.json();
}

export async function refreshChallenge(
  sessionId: string
): Promise<{ challenge: ChallengeData; refreshes_remaining?: number }> {
  const res = await fetch(`${API_BASE}/api/recaptcha/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ session_id: sessionId }),
  });
  if (!res.ok) {
    const data = await res.json();
    throw new Error(data.error || "Refresh failed");
  }
  return res.json();
}
