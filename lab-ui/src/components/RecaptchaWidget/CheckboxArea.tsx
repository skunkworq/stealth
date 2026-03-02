"use client";

const CHECKMARK_STROKE_WIDTH = 3;

type WidgetState = "idle" | "checking" | "challenge" | "verifying" | "passed" | "failed";

interface CheckboxAreaProps {
  state: WidgetState;
  onClick: (e: React.MouseEvent) => void;
  checkboxRef: React.RefObject<HTMLDivElement | null>;
}

export function CheckboxArea({ state, onClick, checkboxRef }: CheckboxAreaProps) {
  return (
    <div ref={checkboxRef} className="border border-border/50 rounded-lg p-4 bg-muted/20">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <button
            onClick={onClick}
            disabled={state !== "idle"}
            className={`w-7 h-7 rounded border-2 flex items-center justify-center transition-all ${
              state === "passed"
                ? "border-emerald-500 bg-emerald-500/20 text-emerald-400"
                : state === "checking" || state === "verifying"
                  ? "border-amber-500 bg-amber-500/10 animate-pulse"
                  : "border-border/60 hover:border-foreground/40 cursor-pointer"
            }`}
            type="button"
          >
            {state === "passed" && (
              <svg
                className="w-4 h-4"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
                strokeWidth={CHECKMARK_STROKE_WIDTH}
              >
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
              </svg>
            )}
            {(state === "checking" || state === "verifying") && (
              <div className="w-3 h-3 border-2 border-amber-400 border-t-transparent rounded-full animate-spin" />
            )}
          </button>
          <span className="text-sm text-foreground/80">I&apos;m not a robot</span>
        </div>
        <div className="flex flex-col items-end gap-0.5">
          <span className="text-[9px] font-bold text-muted-foreground/60 tracking-wider">
            reCAPTCHA
          </span>
          <span className="text-[8px] text-muted-foreground/40">Privacy · Terms</span>
        </div>
      </div>
    </div>
  );
}
