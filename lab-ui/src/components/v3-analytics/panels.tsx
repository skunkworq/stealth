"use client";

import { useState, useCallback } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PanelMetricGrid, PanelMetric } from "@/components/Panel";
import type { V3Assessment, V3Metrics, DetectionVector, StealthIndicator } from "./types";
import {
  scoreColor,
  scoreBadgeVariant,
  severityColor,
  HISTORY_DISPLAY_LIMIT,
  SCORE_DECIMAL_PLACES,
  WEIGHT_DECIMAL_PLACES,
  SEVERITY_DECIMAL_PLACES,
  SEVERITY_THRESHOLD_HIGH,
  PERCENTAGE,
} from "./constants";

export function TriggerSection({ onAssess }: { onAssess: (action: string) => void }) {
  const [action, setAction] = useState("homepage");

  return (
    <div className="flex items-center gap-3">
      <Input
        value={action}
        onChange={e => setAction(e.target.value)}
        placeholder="Action name"
        className="max-w-[200px] font-mono text-xs bg-black/30 border-border/30"
      />
      <Button
        size="sm"
        variant="outline"
        onClick={() => onAssess(action)}
        className="text-xs font-mono uppercase tracking-wider"
      >
        Assess
      </Button>
    </div>
  );
}

export function ScoreOverview({ record }: { record: V3Assessment | null }) {
  if (!record) {
    return (
      <PanelMetricGrid cols={3}>
        <PanelMetric label="V3 Score" value="--" color="text-muted-foreground" />
        <PanelMetric label="Detection" value="--" color="text-muted-foreground" />
        <PanelMetric label="Behavioral" value="--" color="text-muted-foreground" />
      </PanelMetricGrid>
    );
  }

  return (
    <PanelMetricGrid cols={3}>
      <PanelMetric
        label="V3 Score"
        value={record.v3_score.toFixed(SCORE_DECIMAL_PLACES)}
        color={scoreColor(record.v3_score)}
      />
      <PanelMetric
        label="Detection"
        value={record.detection_score.toFixed(SCORE_DECIMAL_PLACES)}
        color={scoreColor(1 - record.detection_score)}
      />
      <PanelMetric
        label="Behavioral"
        value={record.behavioral_score.toFixed(SCORE_DECIMAL_PLACES)}
        color={scoreColor(1 - record.behavioral_score)}
      />
    </PanelMetricGrid>
  );
}

export function VectorsTable({ vectors }: { vectors: DetectionVector[] }) {
  if (!vectors || vectors.length === 0) {
    return <p className="text-xs text-muted-foreground italic">No detection vectors available</p>;
  }

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="text-xs">Name</TableHead>
          <TableHead className="text-xs">Category</TableHead>
          <TableHead className="text-xs text-right">Score</TableHead>
          <TableHead className="text-xs text-right">Weight</TableHead>
          <TableHead className="text-xs text-right">Status</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {vectors.map(v => (
          <TableRow key={v.name}>
            <TableCell className="text-xs font-mono">{v.name}</TableCell>
            <TableCell>
              <Badge variant="outline" className="text-[10px]">
                {v.category}
              </Badge>
            </TableCell>
            <TableCell className={`text-xs text-right font-mono ${scoreColor(1 - v.score)}`}>
              {v.score.toFixed(SCORE_DECIMAL_PLACES)}
            </TableCell>
            <TableCell className="text-xs text-right font-mono text-muted-foreground">
              {v.weight.toFixed(WEIGHT_DECIMAL_PLACES)}
            </TableCell>
            <TableCell className="text-right">
              <Badge variant={v.detected ? "destructive" : "default"} className="text-[10px]">
                {v.detected ? "DETECTED" : "CLEAN"}
              </Badge>
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function IndicatorsList({ indicators }: { indicators: StealthIndicator[] }) {
  if (!indicators || indicators.length === 0) {
    return <p className="text-xs text-muted-foreground italic">No indicators found</p>;
  }

  return (
    <div className="space-y-2">
      {indicators.map(ind => (
        <div key={ind.name} className="flex items-start gap-2 skeuo-inset rounded-lg p-2">
          <Badge
            variant={ind.severity >= SEVERITY_THRESHOLD_HIGH ? "destructive" : "secondary"}
            className="text-[10px] shrink-0"
          >
            {ind.severity.toFixed(SEVERITY_DECIMAL_PLACES)}
          </Badge>
          <div className="min-w-0">
            <div className={`text-xs font-mono font-medium ${severityColor(ind.severity)}`}>
              {ind.name}
            </div>
            <div className="text-[10px] text-muted-foreground truncate">{ind.message}</div>
            <Badge variant="outline" className="text-[9px] mt-1">
              {ind.vector}
            </Badge>
          </div>
        </div>
      ))}
    </div>
  );
}

function HistoryRow({
  record,
  isSelected,
  onClick,
}: {
  record: V3Assessment;
  isSelected: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`w-full text-left px-3 py-2 rounded-lg text-xs font-mono transition-colors ${
        isSelected ? "bg-cyan-glow/10 border border-cyan-glow/30" : "skeuo-inset hover:bg-white/5"
      }`}
    >
      <div className="flex items-center justify-between">
        <span className="text-muted-foreground">
          {new Date(record.timestamp).toLocaleTimeString()}
        </span>
        <Badge variant={scoreBadgeVariant(record.v3_score)} className="text-[10px]">
          {record.v3_score.toFixed(SCORE_DECIMAL_PLACES)}
        </Badge>
      </div>
      <div className="flex items-center gap-2 mt-1">
        <Badge variant="outline" className="text-[9px]">
          {record.action}
        </Badge>
        <span className="text-muted-foreground/60">{record.vectors?.length ?? 0} vectors</span>
      </div>
    </button>
  );
}

export function AssessmentHistory({
  assessments,
  selectedId,
  onSelect,
}: {
  assessments: V3Assessment[];
  selectedId: string | null;
  onSelect: (record: V3Assessment) => void;
}) {
  const display = assessments.slice(-HISTORY_DISPLAY_LIMIT).reverse();
  const handleClick = useCallback((record: V3Assessment) => () => onSelect(record), [onSelect]);

  return (
    <ScrollArea className="h-[300px]">
      <div className="space-y-1">
        {display.map(record => (
          <HistoryRow
            key={record.id}
            record={record}
            isSelected={selectedId === record.id}
            onClick={handleClick(record)}
          />
        ))}
        {display.length === 0 && (
          <p className="text-xs text-muted-foreground italic text-center py-4">
            No assessments yet. Trigger one above.
          </p>
        )}
      </div>
    </ScrollArea>
  );
}

export function AggregateMetrics({ metrics }: { metrics: V3Metrics }) {
  return (
    <PanelMetricGrid cols={3}>
      <PanelMetric label="Total" value={metrics.total} color="text-cyan-glow" />
      <PanelMetric
        label="Avg Score"
        value={metrics.avg_v3_score.toFixed(SCORE_DECIMAL_PLACES)}
        color={scoreColor(metrics.avg_v3_score)}
      />
      <PanelMetric
        label="Pass Rate"
        value={`${(metrics.pass_rate * PERCENTAGE).toFixed(1)}%`}
        color={scoreColor(metrics.pass_rate)}
      />
    </PanelMetricGrid>
  );
}
