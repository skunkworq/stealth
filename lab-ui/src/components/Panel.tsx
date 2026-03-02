"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ReactNode } from "react";

interface PanelProps {
  children: ReactNode;
  className?: string;
}

function Panel({ children, className }: PanelProps) {
  return <Card className={`skeuo-panel overflow-hidden ${className ?? ""}`}>{children}</Card>;
}

interface PanelHeaderProps {
  title: string;
  icon?: ReactNode;
  children?: ReactNode;
}

function PanelHeader({ title, icon, children }: PanelHeaderProps) {
  return (
    <CardHeader className="relative pb-3">
      <div className="absolute top-3 right-3 flex gap-2">
        <div className="screw-hole" />
        <div className="screw-hole" />
      </div>
      <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
        {icon}
        {title}
      </CardTitle>
      {children}
    </CardHeader>
  );
}

interface PanelContentProps {
  children: ReactNode;
  className?: string;
}

function PanelContent({ children, className }: PanelContentProps) {
  return <CardContent className={`space-y-4 ${className ?? ""}`}>{children}</CardContent>;
}

interface PanelEmptyProps {
  message: string;
}

function PanelEmpty({ message }: PanelEmptyProps) {
  return (
    <>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
          <span className="led-red" />
          {message.split(" — ")[0]}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground italic">
          {message.includes(" — ") ? message.split(" — ")[1] : message}
        </p>
      </CardContent>
    </>
  );
}

interface PanelSectionProps {
  title: string;
  count?: number;
  children: ReactNode;
}

function PanelSection({ title, count, children }: PanelSectionProps) {
  return (
    <div>
      <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-2">
        {title} {count !== undefined && `(${count})`}
      </h4>
      {children}
    </div>
  );
}

interface PanelMetricGridProps {
  children: ReactNode;
  // eslint-disable-next-line no-magic-numbers
  cols?: 2 | 3 | 4;
}

const MIN_COLS = 2;
const MID_COLS = 3;
const MAX_COLS = 4;

function PanelMetricGrid({ children, cols = MIN_COLS }: PanelMetricGridProps) {
  const colClass: Record<number, string> = {
    [MIN_COLS]: "grid-cols-2",
    [MID_COLS]: "grid-cols-3",
    [MAX_COLS]: "grid-cols-4",
  };
  return <div className={`grid ${colClass[cols]} gap-3`}>{children}</div>;

  return <div className={`grid ${colClass} gap-3`}>{children}</div>;
}

interface PanelMetricProps {
  label: string;
  value: string | number;
  color?: string;
}

function PanelMetric({ label, value, color = "text-emerald-glow" }: PanelMetricProps) {
  return (
    <div className="skeuo-inset rounded-lg p-3 text-center">
      <div className="text-xs text-muted-foreground uppercase tracking-wide mb-1">{label}</div>
      <div className={`text-lg font-bold font-mono ${color} glow-text`}>{value}</div>
    </div>
  );
}

export { Panel, PanelHeader, PanelContent, PanelEmpty, PanelSection, PanelMetricGrid, PanelMetric };
