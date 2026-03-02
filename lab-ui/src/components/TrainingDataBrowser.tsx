"use client";

import { useState, useCallback, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useTrainingData } from "@/hooks/useTrainingData";
import { CaptchaTraceVisualizer } from "./CaptchaTraceVisualizer";
import type { TrainingSample, TrainingStats, TrainingFilters } from "@/hooks/useTrainingData";

const CAPTCHA_TYPE_OPTIONS = [
  { value: "all", label: "All Types" },
  { value: "text", label: "Text" },
  { value: "math", label: "Math" },
  { value: "slider", label: "Slider" },
  { value: "image", label: "Image" },
  { value: "hcaptcha", label: "hCaptcha" },
  { value: "turnstile", label: "Turnstile" },
];

const LABEL_OPTIONS = [
  { value: "all", label: "All Labels" },
  { value: "solved", label: "Solved" },
  { value: "failed", label: "Failed" },
];

const SCORE_LOW_THRESHOLD = 0.3;
const SCORE_MEDIUM_THRESHOLD = 0.7;
const PERCENTAGE_MULTIPLIER = 100;

const PAGINATION_MAX_VISIBLE = 5;
const PAGINATION_EDGE_THRESHOLD = 3;
const PAGINATION_OFFSET_NEAR = 2;
const PAGINATION_OFFSET_FAR = 4;

function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleString("en-US", {
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch {
    return ts;
  }
}

function botScoreColor(score: number): string {
  if (score < SCORE_LOW_THRESHOLD) return "text-emerald-glow";
  if (score < SCORE_MEDIUM_THRESHOLD) return "text-amber-glow";
  return "text-red-glow";
}

function botScoreBorderColor(score: number): string {
  if (score < SCORE_LOW_THRESHOLD) return "border-emerald-glow/30";
  if (score < SCORE_MEDIUM_THRESHOLD) return "border-amber-glow/30";
  return "border-red-glow/30";
}

function calculatePageNumbers(currentPage: number, totalPages: number): number[] {
  const length = Math.min(PAGINATION_MAX_VISIBLE, totalPages);
  return Array.from({ length }, (_, i) => {
    if (totalPages <= PAGINATION_MAX_VISIBLE) return i + 1;
    if (currentPage <= PAGINATION_EDGE_THRESHOLD) return i + 1;
    if (currentPage >= totalPages - PAGINATION_OFFSET_NEAR) {
      return totalPages - PAGINATION_OFFSET_FAR + i;
    }
    return currentPage - PAGINATION_OFFSET_NEAR + i;
  });
}

function getLabelClasses(label: string): string {
  return label === "solved"
    ? "text-emerald-glow border-emerald-glow/30"
    : "text-red-glow border-red-glow/30";
}

interface PaginationParams {
  totalCount: number;
  filters: TrainingFilters;
  setFilters: (f: (prev: TrainingFilters) => TrainingFilters) => void;
}

function usePagination({ totalCount, filters, setFilters }: PaginationParams) {
  const totalPages = useMemo(
    () => Math.max(1, Math.ceil(totalCount / filters.limit)),
    [totalCount, filters.limit]
  );
  const currentPage = useMemo(
    () => Math.floor(filters.offset / filters.limit) + 1,
    [filters.offset, filters.limit]
  );

  const goToPage = useCallback(
    (page: number) => {
      const clamped = Math.max(1, Math.min(page, totalPages));
      setFilters(prev => ({ ...prev, offset: (clamped - 1) * prev.limit }));
    },
    [totalPages, setFilters]
  );

  return { totalPages, currentPage, goToPage };
}

export function useTrainingBrowser() {
  const { samples, stats, loading, filters, setFilters, totalCount, refresh, exportCSV } =
    useTrainingData();
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const { totalPages, currentPage, goToPage } = usePagination({ totalCount, filters, setFilters });

  const handleTypeChange = useCallback(
    (val: string) => setFilters(prev => ({ ...prev, type: val, offset: 0 })),
    [setFilters]
  );
  const handleLabelChange = useCallback(
    (val: string) => setFilters(prev => ({ ...prev, label: val, offset: 0 })),
    [setFilters]
  );
  const handleMinScoreChange = useCallback(
    (value: number) => setFilters(prev => ({ ...prev, minScore: value, offset: 0 })),
    [setFilters]
  );
  const handleMaxScoreChange = useCallback(
    (value: number) => setFilters(prev => ({ ...prev, maxScore: value, offset: 0 })),
    [setFilters]
  );

  const toggleExpanded = useCallback((id: string) => {
    setExpandedId(prev => (prev === id ? null : id));
  }, []);
  const closeExpanded = useCallback(() => setExpandedId(null), []);

  return {
    samples,
    stats,
    loading,
    filters,
    totalCount,
    totalPages,
    currentPage,
    expandedId,
    refresh,
    exportCSV,
    goToPage,
    handleTypeChange,
    handleLabelChange,
    handleMinScoreChange,
    handleMaxScoreChange,
    toggleExpanded,
    closeExpanded,
  };
}

function StatsSummary({ stats }: { stats: TrainingStats | null }) {
  if (!stats) return null;
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      <StatCard label="Total Samples" value={stats.total_samples} color="text-cyan-glow" />
      <StatCard
        label="Avg Bot Score"
        value={`${(stats.avg_bot_score * PERCENTAGE_MULTIPLIER).toFixed(1)}%`}
        color={botScoreColor(stats.avg_bot_score)}
      />
      <StatCard label="Solved" value={stats.by_label["solved"] ?? 0} color="text-emerald-glow" />
      <StatCard label="Failed" value={stats.by_label["failed"] ?? 0} color="text-red-glow" />
    </div>
  );
}

function BrowserHeader({ onRefresh, onExport }: { onRefresh: () => void; onExport: () => void }) {
  return (
    <CardHeader className="pb-3 border-b border-border/10 flex flex-row items-center justify-between">
      <CardTitle className="text-xs font-bold text-muted-foreground uppercase tracking-wider flex items-center gap-2">
        <span className="text-red-glow">&#9632;</span>
        Training Dataset Browser
      </CardTitle>
      <div className="flex items-center gap-2">
        <Button
          onClick={onRefresh}
          variant="ghost"
          size="sm"
          className="h-7 px-2 text-[10px] text-muted-foreground hover:text-cyan-glow uppercase font-bold"
        >
          Refresh
        </Button>
        <Button
          onClick={onExport}
          size="sm"
          className="h-7 skeuo-panel bg-amber-glow/20 text-amber-glow border-amber-glow/30 hover:bg-amber-glow/30 text-[10px] uppercase font-bold"
        >
          Export CSV
        </Button>
      </div>
    </CardHeader>
  );
}

function TypeFilter({ value, onChange }: { value: string; onChange: (val: string) => void }) {
  return (
    <div className="space-y-1.5">
      <Label className="text-[9px] text-muted-foreground uppercase tracking-wider font-bold">
        Type
      </Label>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger
          size="sm"
          className="h-7 w-[130px] bg-black/40 border-border/30 text-[10px] text-muted-foreground"
        >
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {CAPTCHA_TYPE_OPTIONS.map(opt => (
            <SelectItem key={opt.value} value={opt.value} className="text-xs">
              {opt.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

function LabelFilter({ value, onChange }: { value: string; onChange: (val: string) => void }) {
  return (
    <div className="space-y-1.5">
      <Label className="text-[9px] text-muted-foreground uppercase tracking-wider font-bold">
        Label
      </Label>
      <Select value={value} onValueChange={onChange}>
        <SelectTrigger
          size="sm"
          className="h-7 w-[120px] bg-black/40 border-border/30 text-[10px] text-muted-foreground"
        >
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {LABEL_OPTIONS.map(opt => (
            <SelectItem key={opt.value} value={opt.value} className="text-xs">
              {opt.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
    </div>
  );
}

function ScoreInput({
  label,
  value,
  onChange,
}: {
  label: string;
  value: number;
  onChange: (value: number) => void;
}) {
  return (
    <div className="space-y-1.5">
      <Label className="text-[9px] text-muted-foreground uppercase tracking-wider font-bold">
        {label}
      </Label>
      <Input
        type="number"
        min={0}
        max={1}
        step={0.1}
        value={value}
        onChange={e => onChange(parseFloat(e.target.value) || 0)}
        className="h-7 w-[80px] bg-black/40 border-border/30 text-[10px] font-mono text-muted-foreground"
      />
    </div>
  );
}

interface FilterPanelProps {
  filters: TrainingFilters;
  totalCount: number;
  onTypeChange: (val: string) => void;
  onLabelChange: (val: string) => void;
  onMinScoreChange: (value: number) => void;
  onMaxScoreChange: (value: number) => void;
}

function FilterPanel({
  filters,
  totalCount,
  onTypeChange,
  onLabelChange,
  onMinScoreChange,
  onMaxScoreChange,
}: FilterPanelProps) {
  return (
    <div className="flex flex-wrap items-end gap-4 mb-5">
      <TypeFilter value={filters.type} onChange={onTypeChange} />
      <LabelFilter value={filters.label} onChange={onLabelChange} />
      <ScoreInput label="Min Score" value={filters.minScore} onChange={onMinScoreChange} />
      <ScoreInput label="Max Score" value={filters.maxScore} onChange={onMaxScoreChange} />
      <Badge
        variant="outline"
        className="text-[9px] border-border/20 text-muted-foreground/60 mb-0.5"
      >
        {totalCount} results
      </Badge>
    </div>
  );
}

interface SampleRowProps {
  sample: TrainingSample;
  isExpanded: boolean;
  onToggle: () => void;
}

function SampleRow({ sample, isExpanded, onToggle }: SampleRowProps) {
  const scoreColor = botScoreColor(sample.bot_score);
  const scoreBorder = botScoreBorderColor(sample.bot_score);
  const labelClasses = getLabelClasses(sample.label);

  return (
    <TableRow className="border-white/5 hover:bg-white/5 transition-colors group">
      <TableCell className="py-3">
        <span className="font-mono text-[10px] text-muted-foreground">
          {formatTimestamp(sample.timestamp)}
        </span>
      </TableCell>
      <TableCell>
        <Badge
          variant="outline"
          className="text-[9px] border-border/20 text-muted-foreground/80 uppercase font-mono"
        >
          {sample.type}
        </Badge>
      </TableCell>
      <TableCell className="text-center">
        <Badge variant="outline" className={`text-[9px] font-bold ${labelClasses}`}>
          {sample.label.toUpperCase()}
        </Badge>
      </TableCell>
      <TableCell className="text-center">
        <Badge variant="outline" className={`font-mono text-[9px] ${scoreColor} ${scoreBorder}`}>
          {(sample.bot_score * PERCENTAGE_MULTIPLIER).toFixed(1)}%
        </Badge>
      </TableCell>
      <TableCell className="text-center font-mono text-[10px] text-muted-foreground">
        {sample.solve_time_ms}ms
      </TableCell>
      <TableCell className="text-right pr-4">
        <Button
          variant="ghost"
          size="sm"
          onClick={onToggle}
          className="h-6 px-2 text-[9px] text-muted-foreground/40 hover:text-cyan-glow uppercase font-bold tracking-tighter"
        >
          {isExpanded ? "Collapse" : "Inspect"}
        </Button>
      </TableCell>
    </TableRow>
  );
}

interface SampleTableProps {
  samples: TrainingSample[];
  loading: boolean;
  expandedId: string | null;
  onToggleExpand: (id: string) => void;
}

function SampleTable({ samples, loading, expandedId, onToggleExpand }: SampleTableProps) {
  if (loading && samples.length === 0) {
    return (
      <TableBody>
        <TableRow>
          <TableCell
            colSpan={6}
            className="text-center py-12 text-muted-foreground font-mono text-xs animate-pulse"
          >
            LOADING_TRAINING_DATA...
          </TableCell>
        </TableRow>
      </TableBody>
    );
  }

  if (samples.length === 0) {
    return (
      <TableBody>
        <TableRow>
          <TableCell colSpan={6} className="text-center py-12 text-muted-foreground/40 text-xs">
            No training samples found matching filters.
          </TableCell>
        </TableRow>
      </TableBody>
    );
  }

  return (
    <TableBody>
      {samples.map(sample => (
        <SampleRow
          key={sample.id}
          sample={sample}
          isExpanded={expandedId === sample.id}
          onToggle={() => onToggleExpand(sample.id)}
        />
      ))}
    </TableBody>
  );
}

interface PageButtonProps {
  page: number;
  isActive: boolean;
  onClick: () => void;
}

function PageButton({ page, isActive, onClick }: PageButtonProps) {
  const classes = isActive
    ? "text-cyan-glow bg-cyan-glow/10 border border-cyan-glow/30"
    : "text-muted-foreground/40 hover:text-muted-foreground";

  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={onClick}
      className={`h-7 w-7 p-0 text-[10px] font-mono ${classes}`}
    >
      {page}
    </Button>
  );
}

interface PaginationProps {
  currentPage: number;
  totalPages: number;
  totalCount: number;
  onPageChange: (page: number) => void;
}

function Pagination({ currentPage, totalPages, totalCount, onPageChange }: PaginationProps) {
  const pageNumbers = useMemo(
    () => calculatePageNumbers(currentPage, totalPages),
    [currentPage, totalPages]
  );

  return (
    <div className="flex items-center justify-between mt-5 pt-4 border-t border-border/10">
      <div className="text-[9px] text-muted-foreground/40 uppercase tracking-wider font-bold">
        Page {currentPage} of {totalPages} -- {totalCount} total samples
      </div>
      <div className="flex items-center gap-2">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => onPageChange(currentPage - 1)}
          disabled={currentPage <= 1}
          className="h-7 px-3 text-[10px] text-muted-foreground hover:text-cyan-glow uppercase font-bold disabled:opacity-30"
        >
          Prev
        </Button>
        <div className="flex items-center gap-1">
          {pageNumbers.map(page => (
            <PageButton
              key={page}
              page={page}
              isActive={page === currentPage}
              onClick={() => onPageChange(page)}
            />
          ))}
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => onPageChange(currentPage + 1)}
          disabled={currentPage >= totalPages}
          className="h-7 px-3 text-[10px] text-muted-foreground hover:text-cyan-glow uppercase font-bold disabled:opacity-30"
        >
          Next
        </Button>
      </div>
    </div>
  );
}

function TraceVisualizerPanel({
  expandedId,
  samples,
  onClose,
}: {
  expandedId: string | null;
  samples: TrainingSample[];
  onClose: () => void;
}) {
  if (!expandedId) return null;

  const challengeId = samples.find(s => s.id === expandedId)?.challenge_id ?? expandedId;

  return (
    <div className="mt-4 animate-in fade-in slide-in-from-top-2 duration-300">
      <div className="border border-border/10 rounded-md overflow-hidden">
        <div className="p-3 bg-black/20 border-b border-border/10 flex items-center justify-between">
          <span className="text-[9px] text-muted-foreground uppercase tracking-wider font-bold">
            Trace Visualization -- {expandedId}
          </span>
          <Button
            variant="ghost"
            size="sm"
            onClick={onClose}
            className="h-5 px-2 text-[9px] text-red-glow hover:text-red-glow/80 uppercase font-bold"
          >
            Close
          </Button>
        </div>
        <div className="p-4">
          <CaptchaTraceVisualizer challengeId={challengeId} />
        </div>
      </div>
    </div>
  );
}

function StatCard({
  label,
  value,
  color,
}: {
  label: string;
  value: string | number;
  color: string;
}) {
  return (
    <Card className="skeuo-panel bg-black/40 border-white/5 group hover:border-white/10 transition-colors">
      <CardContent className="p-4 space-y-1">
        <p className="text-[9px] text-muted-foreground uppercase font-bold tracking-widest">
          {label}
        </p>
        <p className={`text-xl font-bold font-mono ${color}`}>{value}</p>
      </CardContent>
    </Card>
  );
}

function TableHeaders() {
  return (
    <TableHeader>
      <TableRow className="border-white/10 bg-white/5">
        <TableHead className="text-[9px] uppercase font-bold text-muted-foreground h-9">
          Timestamp
        </TableHead>
        <TableHead className="text-[9px] uppercase font-bold text-muted-foreground h-9">
          Type
        </TableHead>
        <TableHead className="text-[9px] uppercase font-bold text-muted-foreground text-center h-9">
          Label
        </TableHead>
        <TableHead className="text-[9px] uppercase font-bold text-muted-foreground text-center h-9">
          Bot Score
        </TableHead>
        <TableHead className="text-[9px] uppercase font-bold text-muted-foreground text-center h-9">
          Solve Time
        </TableHead>
        <TableHead className="text-[9px] uppercase font-bold text-muted-foreground text-right h-9 pr-4">
          Actions
        </TableHead>
      </TableRow>
    </TableHeader>
  );
}

function DataTable({ samples, loading, expandedId, onToggleExpand }: SampleTableProps) {
  return (
    <ScrollArea className="w-full">
      <Table>
        <TableHeaders />
        <SampleTable
          samples={samples}
          loading={loading}
          expandedId={expandedId}
          onToggleExpand={onToggleExpand}
        />
      </Table>
    </ScrollArea>
  );
}

function BrowserContent(p: ReturnType<typeof useTrainingBrowser>) {
  return (
    <div className="space-y-5">
      <StatsSummary stats={p.stats} />
      <Card className="skeuo-panel overflow-hidden border-white/5">
        <BrowserHeader onRefresh={p.refresh} onExport={p.exportCSV} />
        <CardContent className="p-4">
          <FilterPanel
            filters={p.filters}
            totalCount={p.totalCount}
            onTypeChange={p.handleTypeChange}
            onLabelChange={p.handleLabelChange}
            onMinScoreChange={p.handleMinScoreChange}
            onMaxScoreChange={p.handleMaxScoreChange}
          />
          <DataTable
            samples={p.samples}
            loading={p.loading}
            expandedId={p.expandedId}
            onToggleExpand={p.toggleExpanded}
          />
          <TraceVisualizerPanel
            expandedId={p.expandedId}
            samples={p.samples}
            onClose={p.closeExpanded}
          />
          <Pagination
            currentPage={p.currentPage}
            totalPages={p.totalPages}
            totalCount={p.totalCount}
            onPageChange={p.goToPage}
          />
        </CardContent>
      </Card>
    </div>
  );
}

export function TrainingDataBrowser() {
  const browserState = useTrainingBrowser();
  return <BrowserContent {...browserState} />;
}
