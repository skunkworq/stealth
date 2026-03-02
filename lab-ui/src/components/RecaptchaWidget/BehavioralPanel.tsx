"use client";

import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";

const SCORE_DECIMAL_PLACES = 3;
const BOT_SCORE_THRESHOLD = 0.3;
const WEIGHT_DECIMAL_PLACES = 2;

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

interface BehavioralMetrics {
  behavioral_score?: number;
  behavioral_breakdown?: BehavioralBreakdown;
  [key: string]: unknown;
}

interface MetricRowProps {
  label: string;
  value: string;
  warn?: boolean;
}

function MetricRow({ label, value, warn }: MetricRowProps) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-[10px] font-mono text-muted-foreground/60">{label}</span>
      <span className={`text-[10px] font-mono ${warn ? "text-amber-400" : "text-foreground/70"}`}>
        {value}
      </span>
    </div>
  );
}

function EventCounts({ breakdown }: { breakdown: BehavioralBreakdown }) {
  return (
    <div className="grid grid-cols-2 gap-x-4 gap-y-1">
      <MetricRow label="mouse" value={String(breakdown.mouse_events)} />
      <MetricRow label="typing" value={String(breakdown.typing_events)} />
      <MetricRow label="scroll" value={String(breakdown.scroll_events)} />
      <MetricRow label="click" value={String(breakdown.click_events)} />
    </div>
  );
}

function IndicatorRow({ indicator }: { indicator: BehavioralIndicator }) {
  return (
    <div className="flex items-start gap-2 py-1">
      <Badge
        variant={indicator.weight >= BOT_SCORE_THRESHOLD ? "destructive" : "secondary"}
        className="text-[9px] shrink-0 font-mono"
      >
        +{indicator.weight.toFixed(WEIGHT_DECIMAL_PLACES)}
      </Badge>
      <div className="min-w-0">
        <div className="text-[10px] font-mono text-amber-400">{indicator.check}</div>
        <div className="text-[9px] text-muted-foreground/60 truncate">{indicator.message}</div>
        <div className="text-[9px] font-mono text-muted-foreground/40">
          {indicator.field}={indicator.value}
        </div>
      </div>
    </div>
  );
}

interface BehavioralPanelProps {
  behavioralMetrics: BehavioralMetrics;
  eventCount: number;
}

export function BehavioralPanel({ behavioralMetrics, eventCount }: BehavioralPanelProps) {
  const score = behavioralMetrics.behavioral_score ?? 0;
  const warn = score >= BOT_SCORE_THRESHOLD;
  const breakdown = behavioralMetrics.behavioral_breakdown as BehavioralBreakdown | undefined;

  return (
    <>
      <Separator className="opacity-30" />
      <div className="space-y-2">
        <p className="text-[10px] font-mono text-muted-foreground/50 uppercase tracking-widest">
          Behavioral Analysis
        </p>

        <div className="grid grid-cols-2 gap-x-4 gap-y-1">
          <MetricRow label="bot_score" value={score.toFixed(SCORE_DECIMAL_PLACES)} warn={warn} />
          <MetricRow label="total_events" value={String(eventCount)} />
        </div>

        {breakdown && (
          <>
            <p className="text-[9px] font-mono text-muted-foreground/40 uppercase tracking-widest pt-1">
              Event Breakdown
            </p>
            <EventCounts breakdown={breakdown} />

            {breakdown.indicators.length > 0 && (
              <>
                <p className="text-[9px] font-mono text-muted-foreground/40 uppercase tracking-widest pt-1">
                  Triggered Checks ({breakdown.indicator_count})
                </p>
                <div className="space-y-0.5">
                  {breakdown.indicators.map(ind => (
                    <IndicatorRow key={ind.check} indicator={ind} />
                  ))}
                </div>
              </>
            )}

            {breakdown.indicators.length === 0 && (
              <p className="text-[9px] text-emerald-400/70 italic">No suspicious indicators</p>
            )}
          </>
        )}
      </div>
    </>
  );
}
