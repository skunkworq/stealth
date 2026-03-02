"use client";

import { Badge } from "@/components/ui/badge";
import { Panel, PanelHeader, PanelContent, PanelSection } from "@/components/Panel";
import { useV3Data, useSelectedAssessment, useV3Assess } from "./hooks";
import { scoreBadgeVariant, SCORE_DECIMAL_PLACES } from "./constants";
import type { V3Assessment, V3Metrics } from "./types";
import {
  TriggerSection,
  ScoreOverview,
  VectorsTable,
  IndicatorsList,
  AssessmentHistory,
  AggregateMetrics,
} from "./panels";
import { BehavioralBreakdownPanel } from "./behavioral-panel";

function ScorePanel({
  selected,
  onAssess,
}: {
  selected: V3Assessment | null;
  onAssess: (action: string) => void;
}) {
  return (
    <Panel>
      <PanelHeader title="reCAPTCHA v3 Analytics" icon={<span className="led-green" />} />
      <PanelContent>
        <PanelSection title="Trigger Assessment">
          <div className="flex items-center gap-3">
            <TriggerSection onAssess={onAssess} />
            {selected && (
              <Badge variant={scoreBadgeVariant(selected.v3_score)} className="text-xs">
                Latest: {selected.v3_score.toFixed(SCORE_DECIMAL_PLACES)}
              </Badge>
            )}
          </div>
        </PanelSection>
        <PanelSection title="Score Overview">
          <ScoreOverview record={selected} />
        </PanelSection>
      </PanelContent>
    </Panel>
  );
}

function HistoryPanel({
  assessments,
  metrics,
  selectedId,
  onSelect,
}: {
  assessments: V3Assessment[];
  metrics: V3Metrics | null;
  selectedId: string | null;
  onSelect: (record: V3Assessment) => void;
}) {
  return (
    <Panel>
      <PanelHeader title="Assessment History" icon={<span className="led-cyan" />} />
      <PanelContent>
        {metrics && metrics.total > 0 && (
          <PanelSection title="Aggregate Metrics">
            <AggregateMetrics metrics={metrics} />
          </PanelSection>
        )}
        <PanelSection title="Recent Assessments" count={assessments.length}>
          <AssessmentHistory
            assessments={assessments}
            selectedId={selectedId}
            onSelect={onSelect}
          />
        </PanelSection>
      </PanelContent>
    </Panel>
  );
}

export function V3AnalyticsDashboard() {
  const { assessments, metrics, refetch } = useV3Data();
  const { selected, select } = useSelectedAssessment(assessments);
  const handleAssess = useV3Assess(refetch);

  return (
    <div className="space-y-5">
      <ScorePanel selected={selected} onAssess={handleAssess} />
      <Panel>
        <PanelHeader title="Behavioral Analysis" icon={<span className="led-amber" />} />
        <PanelContent>
          <BehavioralBreakdownPanel record={selected} />
        </PanelContent>
      </Panel>
      <Panel>
        <PanelHeader title="Detection Vectors" icon={<span className="led-amber" />} />
        <PanelContent>
          <VectorsTable vectors={selected?.vectors ?? []} />
        </PanelContent>
      </Panel>
      <Panel>
        <PanelHeader title="Stealth Indicators" icon={<span className="led-red" />} />
        <PanelContent>
          <IndicatorsList indicators={selected?.indicators ?? []} />
        </PanelContent>
      </Panel>
      <HistoryPanel
        assessments={assessments}
        metrics={metrics}
        selectedId={selected?.id ?? null}
        onSelect={select}
      />
    </div>
  );
}
