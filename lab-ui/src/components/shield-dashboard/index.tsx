"use client";

import { Button } from "@/components/ui/button";
import { Panel, PanelHeader, PanelContent, PanelSection, PanelEmpty } from "@/components/Panel";
import { useShieldData } from "./hooks";
import { SummaryMetrics, ProfileTable, VectorHeatmap, IndicatorsList } from "./panels";

export function ShieldDashboard() {
  const { data, loading, error, runEvaluation } = useShieldData();

  return (
    <div className="space-y-5">
      <Panel>
        <PanelHeader title="Shield vs Sword Evaluation" icon={<span className="led-red" />} />
        <PanelContent>
          <PanelSection title="Run Evaluation">
            <div className="flex items-center gap-3">
              <Button
                onClick={runEvaluation}
                disabled={loading}
                variant="outline"
                size="sm"
                className="font-mono text-[10px] uppercase tracking-wider"
              >
                {loading ? "Evaluating..." : "Run Evaluation"}
              </Button>
              {error && <span className="text-xs text-red-400 font-mono">Error: {error}</span>}
            </div>
          </PanelSection>

          {data && (
            <PanelSection title="Summary Metrics">
              <SummaryMetrics data={data} />
            </PanelSection>
          )}

          {!data && !loading && (
            <PanelEmpty message='No Data — Click "Run Evaluation" to test sword profiles against the shield.' />
          )}
        </PanelContent>
      </Panel>

      {data && (
        <>
          <Panel>
            <PanelHeader title="Profile Results" icon={<span className="led-amber" />} />
            <PanelContent>
              <ProfileTable profiles={data.profiles} threshold={data.summary.threshold} />
            </PanelContent>
          </Panel>

          <Panel>
            <PanelHeader title="Vector Heatmap" icon={<span className="led-cyan" />} />
            <PanelContent>
              <VectorHeatmap profiles={data.profiles} />
            </PanelContent>
          </Panel>

          <Panel>
            <PanelHeader title="Detection Indicators" icon={<span className="led-red" />} />
            <PanelContent>
              <IndicatorsList profiles={data.profiles} />
            </PanelContent>
          </Panel>
        </>
      )}
    </div>
  );
}
