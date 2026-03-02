"use client";

import { useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

interface ChallengeData {
  id: string;
  type: string;
  image_base64: string;
  num_chars: number;
}

interface ChallengeDialogProps {
  challenge: ChallengeData;
  solution: string;
  state: string;
  refreshesRemaining: number;
  error: string | null;
  onSolutionChange: (value: string) => void;
  onVerify: () => void;
  onRefresh: () => void;
  onKeyDown: () => void;
}

const EVENT_LENGTH_INCREMENT = 2;

function ChallengeImage({ imageBase64 }: { imageBase64: string }) {
  return (
    <div className="border border-border/30 rounded-md overflow-hidden bg-white p-2 flex justify-center">
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img
        src={`data:image/png;base64,${imageBase64}`}
        alt="CAPTCHA challenge"
        className="max-h-20 select-none"
        draggable={false}
      />
    </div>
  );
}

function SolutionInput({
  solution,
  maxLength,
  placeholder,
  onChange,
  onKeyDown,
}: {
  solution: string;
  maxLength: number;
  placeholder: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  onKeyDown: (e: React.KeyboardEvent) => void;
}) {
  return (
    <Input
      value={solution}
      onChange={onChange}
      onKeyDown={onKeyDown}
      placeholder={placeholder}
      className="font-mono text-sm uppercase tracking-widest"
      maxLength={maxLength}
      autoFocus
    />
  );
}

function VerifyButton({
  onClick,
  disabled,
  isVerifying,
}: {
  onClick: () => void;
  disabled: boolean;
  isVerifying: boolean;
}) {
  return (
    <Button onClick={onClick} disabled={disabled} size="sm" className="shrink-0">
      {isVerifying ? "..." : "Verify"}
    </Button>
  );
}

function RefreshButton({
  onClick,
  disabled,
  remaining,
}: {
  onClick: () => void;
  disabled: boolean;
  remaining: number;
}) {
  return (
    <div className="flex items-center justify-between">
      <button
        onClick={onClick}
        disabled={disabled}
        className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors disabled:opacity-40"
        type="button"
      >
        <svg
          className="w-3.5 h-3.5"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
          />
        </svg>
        New challenge
      </button>
      <span className="text-[10px] text-muted-foreground/50 font-mono">{remaining} remaining</span>
    </div>
  );
}

function ErrorMessage({ error }: { error: string | null }) {
  return error ? <p className="text-xs text-red-400 font-mono">{error}</p> : null;
}

export function ChallengeDialog(props: ChallengeDialogProps) {
  // prettier-ignore
  const { challenge, solution, state, refreshesRemaining, error, onSolutionChange, onVerify, onRefresh, onKeyDown } = props;
  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      onSolutionChange(e.target.value);
      onKeyDown();
    },
    [onSolutionChange, onKeyDown]
  );
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter") onVerify();
    },
    [onVerify]
  );
  const isVerifying = state === "verifying";
  return (
    <div className="border border-border/50 rounded-lg p-4 bg-muted/10 space-y-3">
      <p className="text-xs font-mono text-muted-foreground uppercase tracking-wider">
        Type the characters you see:
      </p>
      <ChallengeImage imageBase64={challenge.image_base64} />
      <div className="flex gap-2">
        <SolutionInput
          solution={solution}
          maxLength={challenge.num_chars + EVENT_LENGTH_INCREMENT}
          placeholder={`${challenge.num_chars} characters`}
          onChange={handleChange}
          onKeyDown={handleKeyDown}
        />
        <VerifyButton
          onClick={onVerify}
          disabled={!solution || isVerifying}
          isVerifying={isVerifying}
        />
      </div>
      <RefreshButton
        onClick={onRefresh}
        disabled={refreshesRemaining <= 0}
        remaining={refreshesRemaining}
      />
      <ErrorMessage error={error} />
    </div>
  );
}
