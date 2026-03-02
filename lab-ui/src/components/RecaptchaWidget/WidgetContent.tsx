"use client";

import { Button } from "@/components/ui/button";
import { ChallengeDialog } from "../ChallengeDialog";
import { CheckboxArea } from "./CheckboxArea";
import { SuccessOverlay } from "./SuccessOverlay";
import { BehavioralPanel } from "./BehavioralPanel";

type WidgetState = "idle" | "checking" | "challenge" | "verifying" | "passed" | "failed";

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

interface CaptchaEvent {
  type: string;
  timestamp: number;
  elapsed_ms: number;
  x?: number;
  y?: number;
  key?: string;
  delta?: number;
}

interface WidgetContentProps {
  state: WidgetState;
  challenge: ChallengeData | null;
  solution: string;
  refreshesRemaining: number;
  error: string | null;
  token: string | null;
  remainingSec: number;
  behavioralMetrics: BehavioralMetrics | null;
  events: CaptchaEvent[];
  checkboxRef: React.RefObject<HTMLDivElement | null>;
  recordEvent: (type: string, e?: React.MouseEvent | React.KeyboardEvent | MouseEvent) => void;
  onCheckboxClick: (e: React.MouseEvent) => Promise<void>;
  onSolutionChange: (value: string) => void;
  onVerify: () => Promise<void>;
  onRefresh: () => Promise<void>;
  onReset: () => void;
}

export function WidgetContent(props: WidgetContentProps) {
  const showChallenge =
    (props.state === "challenge" || props.state === "verifying") && props.challenge;
  const showSuccess = props.state === "passed" && props.token;

  return (
    <div className="p-6 pt-0 space-y-4">
      <CheckboxArea
        state={props.state}
        onClick={props.onCheckboxClick}
        checkboxRef={props.checkboxRef}
      />

      {showChallenge && (
        <ChallengeDialog
          challenge={props.challenge!}
          solution={props.solution}
          state={props.state}
          refreshesRemaining={props.refreshesRemaining}
          error={props.error}
          onSolutionChange={props.onSolutionChange}
          onVerify={props.onVerify}
          onRefresh={props.onRefresh}
          onKeyDown={() => props.recordEvent("keydown")}
        />
      )}

      {showSuccess && <SuccessOverlay token={props.token!} remainingSec={props.remainingSec} />}

      {props.behavioralMetrics && (
        <BehavioralPanel
          behavioralMetrics={props.behavioralMetrics}
          eventCount={props.events.length}
        />
      )}

      {props.state !== "idle" && (
        <Button
          variant="ghost"
          size="sm"
          onClick={props.onReset}
          className="w-full text-[10px] text-muted-foreground/50 uppercase tracking-wider"
        >
          Reset
        </Button>
      )}
    </div>
  );
}
