"use client";

import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PanelMetricGrid, PanelMetric } from "@/components/Panel";
import type { ShieldEvalResponse, ProfileResult } from "./types";

const PERCENTAGE_MULTIPLIER = 100;
const RATE_DECIMAL_PLACES = 0;
const SCORE_DECIMAL_PLACES = 3;
const THRESHOLD_DECIMAL_PLACES = 2;
const MEDIUM_THRESHOLD = 0.7;
const MAX_INDICATORS = 3;
const LOW_SCORE_THRESHOLD = 0.1;
const MEDIUM_SCORE_THRESHOLD = 0.3;

function scoreBadge(score: number, threshold: number) {
  if (score >= threshold) return "destructive" as const;
  if (score >= threshold * MEDIUM_THRESHOLD) return "secondary" as const;
  return "outline" as const;
}

function vectorScoreColor(score: number): string {
  if (score <= 0) return "text-muted-foreground/30";
  if (score < LOW_SCORE_THRESHOLD) return "text-green-400";
  if (score < MEDIUM_SCORE_THRESHOLD) return "text-yellow-400";
  return "text-red-400";
}

export function SummaryMetrics({ data }: { data: ShieldEvalResponse }) {
  const { summary, profiles } = data;
  return (
    <PanelMetricGrid cols={4}>
      <PanelMetric
        label="Catch Rate"
        value={`${(summary.catch_rate * PERCENTAGE_MULTIPLIER).toFixed(RATE_DECIMAL_PLACES)}%`}
      />
      <PanelMetric label="Avg Score" value={summary.avg_score.toFixed(SCORE_DECIMAL_PLACES)} />
      <PanelMetric label="Threshold" value={summary.threshold.toFixed(THRESHOLD_DECIMAL_PLACES)} />
      <PanelMetric label="Profiles Tested" value={String(profiles.length)} />
    </PanelMetricGrid>
  );
}

export function ProfileTable({
  profiles,
  threshold,
}: {
  profiles: ProfileResult[];
  threshold: number;
}) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="font-mono text-[10px]">PROFILE</TableHead>
          <TableHead className="font-mono text-[10px]">PLATFORM</TableHead>
          <TableHead className="font-mono text-[10px] text-right">SCORE</TableHead>
          <TableHead className="font-mono text-[10px] text-center">STATUS</TableHead>
          <TableHead className="font-mono text-[10px]">INDICATORS</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {profiles.map(p => (
          <TableRow key={p.name}>
            <TableCell className="font-mono text-xs">{p.name}</TableCell>
            <TableCell className="font-mono text-xs text-muted-foreground">{p.platform}</TableCell>
            <TableCell className="font-mono text-xs text-right">
              {p.score.toFixed(SCORE_DECIMAL_PLACES)}
            </TableCell>
            <TableCell className="text-center">
              <Badge variant={scoreBadge(p.score, threshold)} className="text-[10px]">
                {p.is_bot ? "CAUGHT" : "PASS"}
              </Badge>
            </TableCell>
            <TableCell className="font-mono text-[10px] text-muted-foreground max-w-[300px] truncate">
              {p.indicators.length > 0 ? p.indicators.slice(0, MAX_INDICATORS).join(", ") : "—"}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}

export function VectorHeatmap({ profiles }: { profiles: ProfileResult[] }) {
  // Collect all unique vector names across profiles
  const allVectors = new Set<string>();
  for (const p of profiles) {
    for (const v of Object.keys(p.vectors)) {
      allVectors.add(v);
    }
  }
  const vectors = Array.from(allVectors).sort();

  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="font-mono text-[10px] sticky left-0 bg-background">
              VECTOR
            </TableHead>
            {profiles.map(p => (
              <TableHead key={p.name} className="font-mono text-[10px] text-center min-w-[80px]">
                {p.name.replace(/Chrome \d+ /, "").replace(/Firefox \d+ /, "FF ")}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {vectors.map(vec => (
            <TableRow key={vec}>
              <TableCell className="font-mono text-[10px] sticky left-0 bg-background">
                {vec}
              </TableCell>
              {profiles.map(p => {
                const score = p.vectors[vec] ?? 0;
                return (
                  <TableCell
                    key={p.name}
                    className={`font-mono text-[10px] text-center ${vectorScoreColor(score)}`}
                  >
                    {score > 0 ? score.toFixed(2) : "—"}
                  </TableCell>
                );
              })}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

export function IndicatorsList({ profiles }: { profiles: ProfileResult[] }) {
  const grouped = profiles.filter(p => p.indicators.length > 0);

  if (grouped.length === 0) {
    return <p className="text-xs text-muted-foreground font-mono">No indicators fired.</p>;
  }

  return (
    <div className="space-y-3">
      {grouped.map(p => (
        <div key={p.name}>
          <p className="text-[10px] font-mono font-bold text-muted-foreground uppercase tracking-wider mb-1">
            {p.name}
          </p>
          <ul className="space-y-0.5">
            {p.indicators.map((ind, i) => (
              <li
                key={i}
                className="text-xs font-mono text-muted-foreground pl-2 border-l border-red-500/30"
              >
                {ind}
              </li>
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}
