"use client";

export interface CaptchaEvent {
  type: string;
  timestamp: number;
  elapsed_ms: number;
  x?: number;
  y?: number;
  key?: string;
  delta?: number;
}

export interface ChallengeData {
  id: string;
  type: string;
  image_base64: string;
  num_chars: number;
}

export interface BehavioralMetrics {
  behavioral_score?: number;
  [key: string]: unknown;
}

export type WidgetState = "idle" | "checking" | "challenge" | "verifying" | "passed" | "failed";

export interface ReCaptchaState {
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
}

export interface ReCaptchaActions {
  handleCheckboxClick: (e: React.MouseEvent) => Promise<void>;
  handleVerify: () => Promise<void>;
  handleRefresh: () => Promise<void>;
  handleSolutionChange: (value: string) => void;
  handleExpire: () => void;
}

export interface ReCaptchaActionDeps {
  captchaState: ReCaptchaState;
  startTimeRef: React.MutableRefObject<number | null>;
  recordEvent: (type: string, e?: React.MouseEvent | React.KeyboardEvent | MouseEvent) => void;
}
