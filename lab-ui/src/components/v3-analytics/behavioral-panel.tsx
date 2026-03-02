"use client";

import { Badge } from "@/components/ui/badge";
import { PanelMetricGrid, PanelMetric } from "@/components/Panel";
import type { V3Assessment, BehavioralCheck } from "./types";
import { scoreColor, SCORE_DECIMAL_PLACES, WEIGHT_DECIMAL_PLACES } from "./constants";

const BOT_WEIGHT_THRESHOLD = 0.3;
const NO_EVENTS_PENALTY = 0.85;

function CheckRow({ check }: { check: BehavioralCheck }) {
  return (
    <div className="flex items-start gap-2 py-1">
      <Badge
        variant={check.weight >= BOT_WEIGHT_THRESHOLD ? "destructive" : "secondary"}
        className="text-[9px] shrink-0 font-mono"
      >
        +{check.weight.toFixed(WEIGHT_DECIMAL_PLACES)}
      </Badge>
      <div className="min-w-0">
        <div className="text-[10px] font-mono text-amber-glow">{check.check}</div>
        <div className="text-[9px] text-muted-foreground truncate">{check.message}</div>
        <div className="text-[9px] font-mono text-muted-foreground/50">
          {check.field}={check.value}
        </div>
      </div>
    </div>
  );
}

function EventBreakdown({ breakdown }: { breakdown: Record<string, number> }) {
  const entries = Object.entries(breakdown).filter(([k]) => k !== "total");
  if (entries.length === 0) return null;

  return (
    <div className="grid grid-cols-4 gap-2">
      {entries.map(([key, count]) => (
        <div key={key} className="skeuo-inset rounded p-1.5 text-center">
          <div className="text-[9px] text-muted-foreground uppercase">{key}</div>
          <div className="text-xs font-mono font-bold text-foreground/80">{count}</div>
        </div>
      ))}
    </div>
  );
}

export function BehavioralBreakdownPanel({ record }: { record: V3Assessment | null }) {
  if (!record) {
    return (
      <p className="text-xs text-muted-foreground italic">Select an assessment to see details</p>
    );
  }

  const checks = record.behavioral_checks ?? [];
  const breakdown = record.behavioral_event_breakdown;

  return (
    <div className="space-y-3">
      <PanelMetricGrid cols={3}>
        <PanelMetric
          label="Behavioral"
          value={record.behavioral_score.toFixed(SCORE_DECIMAL_PLACES)}
          color={scoreColor(1 - record.behavioral_score)}
        />
        <PanelMetric
          label="Detection"
          value={record.detection_score.toFixed(SCORE_DECIMAL_PLACES)}
          color={scoreColor(1 - record.detection_score)}
        />
        <PanelMetric label="Events" value={record.event_count} color="text-cyan-glow" />
      </PanelMetricGrid>

      {record.event_count === 0 && (
        <div className="skeuo-inset rounded-lg p-2 text-center">
          <span className="text-[10px] font-mono text-amber-glow">
            No events sent — default penalty: {NO_EVENTS_PENALTY}
          </span>
        </div>
      )}

      {breakdown && <EventBreakdown breakdown={breakdown} />}

      {checks.length > 0 && (
        <div className="space-y-1">
          <p className="text-[10px] font-mono text-muted-foreground/50 uppercase tracking-widest">
            Triggered Checks ({checks.length})
          </p>
          {checks.map(check => (
            <CheckRow key={check.check} check={check} />
          ))}
        </div>
      )}

      {checks.length === 0 && record.event_count > 0 && (
        <p className="text-[10px] text-emerald-glow/70 italic">No behavioral checks triggered</p>
      )}
    </div>
  );
}
