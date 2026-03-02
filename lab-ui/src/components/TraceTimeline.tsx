"use client";

import { useState, useMemo, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Button } from "@/components/ui/button";

export interface CaptchaEvent {
  type: string;
  timestamp: number;
  x: number;
  y: number;
  key: string;
  delta: number;
}

type SortField = "timestamp" | "type" | "x" | "y" | "key" | "delta";
type SortDir = "asc" | "desc";

const EVENT_TYPES = ["mousemove", "mousedown", "keydown", "wheel", "click"] as const;
type EventType = (typeof EVENT_TYPES)[number];

// Constants for UI styling
const INACTIVE_OPACITY = 0.3;

const EVENT_TYPE_COLORS: Record<string, string> = {
  mousemove: "border-emerald-glow/40 text-emerald-glow bg-emerald-glow/10",
  mousedown: "border-red-glow/40 text-red-glow bg-red-glow/10",
  click: "border-red-glow/40 text-red-glow bg-red-glow/10",
  keydown: "border-amber-glow/40 text-amber-glow bg-amber-glow/10",
  wheel: "border-purple-glow/40 text-purple-glow bg-purple-glow/10",
};

interface TraceTimelineProps {
  events: CaptchaEvent[];
  currentTime?: number;
}

interface UseTraceDataReturn {
  activeFilters: Set<EventType>;
  filterValue: string;
  sortField: SortField;
  sortDir: SortDir;
  baseTimestamp: number;
  filteredEvents: CaptchaEvent[];
  highlightIndex: number;
  eventCounts: Record<string, number>;
  handleFilterChange: (value: string) => void;
  toggleAllFilters: () => void;
  toggleFilter: (type: EventType) => void;
  handleSort: (field: SortField) => void;
  sortIndicator: (field: SortField) => string;
}

function getBaseTimestamp(events: CaptchaEvent[]): number {
  if (events.length === 0) return 0;
  return Math.min(...events.map(e => e.timestamp));
}

function getEventCounts(events: CaptchaEvent[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const e of events) {
    counts[e.type] = (counts[e.type] || 0) + 1;
  }
  return counts;
}

interface CompareEventsParams {
  a: CaptchaEvent;
  b: CaptchaEvent;
  field: SortField;
}

function compareEvents({ a, b, field }: CompareEventsParams): number {
  switch (field) {
    case "timestamp":
      return a.timestamp - b.timestamp;
    case "type":
      return a.type.localeCompare(b.type);
    case "x":
      return a.x - b.x;
    case "y":
      return a.y - b.y;
    case "key":
      return (a.key || "").localeCompare(b.key || "");
    case "delta":
      return a.delta - b.delta;
    default:
      return 0;
  }
}

interface FilterEventsParams {
  events: CaptchaEvent[];
  activeFilters: Set<EventType>;
  sortField: SortField;
  sortDir: SortDir;
}

function getFilteredEvents({
  events,
  activeFilters,
  sortField,
  sortDir,
}: FilterEventsParams): CaptchaEvent[] {
  const filtered = events.filter(e => activeFilters.has(e.type as EventType));
  filtered.sort((a, b) => {
    const cmp = compareEvents({ a, b, field: sortField });
    return sortDir === "asc" ? cmp : -cmp;
  });
  return filtered;
}

interface HighlightIndexParams {
  filteredEvents: CaptchaEvent[];
  currentTime?: number;
}

function getHighlightIndex({ filteredEvents, currentTime }: HighlightIndexParams): number {
  if (currentTime === undefined || filteredEvents.length === 0) return -1;
  let closest = 0;
  let minDiff = Math.abs(filteredEvents[0].timestamp - currentTime);
  for (let i = 1; i < filteredEvents.length; i++) {
    const diff = Math.abs(filteredEvents[i].timestamp - currentTime);
    if (diff < minDiff) {
      minDiff = diff;
      closest = i;
    }
  }
  return closest;
}

interface UseFilterStateReturn {
  activeFilters: Set<EventType>;
  filterValue: string;
  handleFilterChange: (value: string) => void;
  toggleAllFilters: () => void;
  toggleFilter: (type: EventType) => void;
}

function useFilterState(): UseFilterStateReturn {
  const [activeFilters, setActiveFilters] = useState<Set<EventType>>(new Set(EVENT_TYPES));
  const [filterValue, setFilterValue] = useState<string>("all");

  const handleFilterChange = useCallback((value: string) => {
    setFilterValue(value);
    if (value === "all") {
      setActiveFilters(new Set(EVENT_TYPES));
    } else {
      setActiveFilters(new Set([value as EventType]));
    }
  }, []);

  const toggleAllFilters = useCallback(() => {
    setActiveFilters(prev => {
      if (prev.size === EVENT_TYPES.length) {
        setFilterValue("none");
        return new Set();
      }
      setFilterValue("all");
      return new Set(EVENT_TYPES);
    });
  }, []);

  const toggleFilter = useCallback((type: EventType) => {
    setActiveFilters(prev => {
      const next = new Set(prev);
      if (next.has(type)) {
        next.delete(type);
      } else {
        next.add(type);
      }
      return next;
    });
    setFilterValue("custom");
  }, []);

  return {
    activeFilters,
    filterValue,
    handleFilterChange,
    toggleAllFilters,
    toggleFilter,
  };
}

interface UseSortStateReturn {
  sortField: SortField;
  sortDir: SortDir;
  handleSort: (field: SortField) => void;
  sortIndicator: (field: SortField) => string;
}

function useSortState(): UseSortStateReturn {
  const [sortField, setSortField] = useState<SortField>("timestamp");
  const [sortDir, setSortDir] = useState<SortDir>("asc");

  const handleSort = useCallback(
    (field: SortField) => {
      if (sortField === field) {
        setSortDir(prev => (prev === "asc" ? "desc" : "asc"));
      } else {
        setSortField(field);
        setSortDir("asc");
      }
    },
    [sortField]
  );

  const sortIndicator = useCallback(
    (field: SortField) => {
      if (sortField !== field) return "";
      return sortDir === "asc" ? " \u25B2" : " \u25BC";
    },
    [sortField, sortDir]
  );

  return { sortField, sortDir, handleSort, sortIndicator };
}

function useTraceData(events: CaptchaEvent[], currentTime?: number): UseTraceDataReturn {
  const { activeFilters, filterValue, handleFilterChange, toggleAllFilters, toggleFilter } =
    useFilterState();
  const { sortField, sortDir, handleSort, sortIndicator } = useSortState();

  const baseTimestamp = useMemo(() => getBaseTimestamp(events), [events]);

  const filteredEvents = useMemo(
    () => getFilteredEvents({ events, activeFilters, sortField, sortDir }),
    [events, activeFilters, sortField, sortDir]
  );

  const highlightIndex = useMemo(
    () => getHighlightIndex({ filteredEvents, currentTime }),
    [filteredEvents, currentTime]
  );

  const eventCounts = useMemo(() => getEventCounts(events), [events]);

  return {
    activeFilters,
    filterValue,
    sortField,
    sortDir,
    baseTimestamp,
    filteredEvents,
    highlightIndex,
    eventCounts,
    handleFilterChange,
    toggleAllFilters,
    toggleFilter,
    handleSort,
    sortIndicator,
  };
}

interface TimelineHeaderProps {
  filteredCount: number;
  totalCount: number;
}

function TimelineHeader({ filteredCount, totalCount }: TimelineHeaderProps) {
  return (
    <CardHeader className="relative pb-3">
      <div className="absolute top-3 right-3 flex gap-2">
        <div className="screw-hole" />
        <div className="screw-hole" />
      </div>
      <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
        <span className="text-lg">📋</span>
        Trace Timeline
        <Badge variant="secondary" className="ml-auto font-mono text-[10px] skeuo-raised">
          {filteredCount} / {totalCount}
        </Badge>
      </CardTitle>
    </CardHeader>
  );
}

interface TimelineLegendProps {
  eventCounts: Record<string, number>;
  activeFilters: Set<EventType>;
  onToggleFilter: (type: EventType) => void;
  onToggleAll: () => void;
}

function TimelineLegend({
  eventCounts,
  activeFilters,
  onToggleFilter,
  onToggleAll,
}: TimelineLegendProps) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {EVENT_TYPES.map(type => (
        <button
          key={type}
          onClick={() => onToggleFilter(type)}
          className="transition-opacity"
          style={{ opacity: activeFilters.has(type) ? 1 : INACTIVE_OPACITY }}
        >
          <Badge
            variant="outline"
            className={`text-[9px] font-mono font-bold uppercase cursor-pointer ${EVENT_TYPE_COLORS[type] || "border-border text-muted-foreground"}`}
          >
            {type}: {eventCounts[type] || 0}
          </Badge>
        </button>
      ))}
      <Button
        variant="ghost"
        size="xs"
        onClick={onToggleAll}
        className="text-[9px] uppercase font-bold text-muted-foreground/60 hover:text-foreground h-5 px-2"
      >
        {activeFilters.size === EVENT_TYPES.length ? "Clear All" : "Select All"}
      </Button>
    </div>
  );
}

interface TimelineFilterProps {
  filterValue: string;
  currentTime?: number;
  baseTimestamp: number;
  onFilterChange: (value: string) => void;
}

function TimelineFilter({
  filterValue,
  currentTime,
  baseTimestamp,
  onFilterChange,
}: TimelineFilterProps) {
  return (
    <div className="flex items-center gap-3">
      <label className="text-[9px] uppercase font-bold text-muted-foreground tracking-widest shrink-0">
        Quick Filter
      </label>
      <Select value={filterValue} onValueChange={onFilterChange}>
        <SelectTrigger className="skeuo-inset bg-black/20 border-0 h-7 text-[10px] font-mono w-[160px]">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all" className="text-xs font-mono">
            All Events
          </SelectItem>
          {EVENT_TYPES.map(type => (
            <SelectItem key={type} value={type} className="text-xs font-mono">
              {type}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      {currentTime !== undefined && (
        <Badge
          variant="outline"
          className="text-[9px] font-mono border-cyan-glow/30 text-cyan-glow bg-cyan-glow/5 ml-auto"
        >
          Sync: {(currentTime - baseTimestamp).toFixed(0)}ms
        </Badge>
      )}
    </div>
  );
}

interface EventRowProps {
  event: CaptchaEvent;
  baseTimestamp: number;
  isHighlighted: boolean;
}

function EventRow({ event, baseTimestamp, isHighlighted }: EventRowProps) {
  const relativeTime = event.timestamp - baseTimestamp;

  return (
    <TableRow
      className={`border-white/5 transition-all ${
        isHighlighted
          ? "bg-cyan-glow/10 border-l-2 border-l-cyan-glow shadow-[inset_0_0_20px_rgba(6,182,212,0.05)]"
          : "hover:bg-white/[0.02] border-l-2 border-l-transparent"
      }`}
    >
      <TableCell className="py-1.5 text-[10px] font-mono text-muted-foreground">
        {relativeTime.toFixed(0)}
      </TableCell>
      <TableCell className="py-1.5">
        <Badge
          variant="outline"
          className={`text-[8px] font-mono font-bold uppercase ${EVENT_TYPE_COLORS[event.type] || "border-border text-muted-foreground"}`}
        >
          {event.type}
        </Badge>
      </TableCell>
      <TableCell className="py-1.5 text-[10px] font-mono text-foreground/70">
        {event.x.toFixed(0)}
      </TableCell>
      <TableCell className="py-1.5 text-[10px] font-mono text-foreground/70">
        {event.y.toFixed(0)}
      </TableCell>
      <TableCell className="py-1.5 text-[10px] font-mono text-amber-glow/80">
        {event.key || "\u2014"}
      </TableCell>
      <TableCell className="py-1.5 text-[10px] font-mono text-muted-foreground/60 text-right">
        {event.delta !== 0 ? `delta: ${event.delta}` : "\u2014"}
      </TableCell>
    </TableRow>
  );
}

interface TableHeaderRowProps {
  sortField: SortField;
  sortDir: SortDir;
  onSort: (field: SortField) => void;
}

interface SortIndicatorParams {
  sortField: SortField;
  sortDir: SortDir;
  field: SortField;
}

function getSortIndicator({ sortField, sortDir, field }: SortIndicatorParams): string {
  if (sortField !== field) return "";
  return sortDir === "asc" ? " \u25B2" : " \u25BC";
}

const HEADER_COLUMNS = [
  { field: "timestamp" as SortField, label: "Time (ms)" },
  { field: "type" as SortField, label: "Event Type" },
  { field: "x" as SortField, label: "X" },
  { field: "y" as SortField, label: "Y" },
  { field: "key" as SortField, label: "Key" },
];

function TableHeaderRow({ sortField, sortDir, onSort }: TableHeaderRowProps) {
  const indicator = useCallback(
    (field: SortField) => getSortIndicator({ sortField, sortDir, field }),
    [sortField, sortDir]
  );

  return (
    <TableRow className="border-white/10 bg-white/5">
      {HEADER_COLUMNS.map(({ field, label }) => (
        <SortableHead
          key={field}
          field={field}
          label={label}
          current={sortField}
          onClick={onSort}
          indicator={indicator}
        />
      ))}
      <TableHead className="text-[9px] uppercase font-bold text-muted-foreground h-8 text-right">
        Details
      </TableHead>
    </TableRow>
  );
}

interface TimelineTableProps {
  filteredEvents: CaptchaEvent[];
  baseTimestamp: number;
  highlightIndex: number;
  totalEvents: number;
  sortField: SortField;
  sortDir: SortDir;
  onSort: (field: SortField) => void;
}

function TimelineTableBody({
  filteredEvents,
  baseTimestamp,
  highlightIndex,
  totalEvents,
}: Pick<
  TimelineTableProps,
  "filteredEvents" | "baseTimestamp" | "highlightIndex" | "totalEvents"
>) {
  if (filteredEvents.length === 0) {
    return (
      <TableRow>
        <TableCell colSpan={6} className="py-8 text-center">
          <p className="text-xs text-muted-foreground/60 italic font-mono">
            {totalEvents === 0 ? "No events recorded yet" : "No events match current filters"}
          </p>
        </TableCell>
      </TableRow>
    );
  }

  return (
    <>
      {filteredEvents.map((event, index) => (
        <EventRow
          key={`event-${event.timestamp}-${event.type}-${event.x}-${event.y}`}
          event={event}
          baseTimestamp={baseTimestamp}
          isHighlighted={index === highlightIndex}
        />
      ))}
    </>
  );
}

function TimelineTable({
  filteredEvents,
  baseTimestamp,
  highlightIndex,
  totalEvents,
  sortField,
  sortDir,
  onSort,
}: TimelineTableProps) {
  return (
    <ScrollArea className="h-[450px]">
      <Table>
        <TableHeader>
          <TableHeaderRow sortField={sortField} sortDir={sortDir} onSort={onSort} />
        </TableHeader>
        <TableBody>
          <TimelineTableBody
            filteredEvents={filteredEvents}
            baseTimestamp={baseTimestamp}
            highlightIndex={highlightIndex}
            totalEvents={totalEvents}
          />
        </TableBody>
      </Table>
    </ScrollArea>
  );
}

interface SortableHeadProps {
  field: SortField;
  label: string;
  current: SortField;
  onClick: (field: SortField) => void;
  indicator: (field: SortField) => string;
}

function SortableHead({ field, label, current, onClick, indicator }: SortableHeadProps) {
  return (
    <TableHead
      className={`text-[9px] uppercase font-bold h-8 cursor-pointer select-none transition-colors hover:text-foreground ${
        current === field ? "text-cyan-glow" : "text-muted-foreground"
      }`}
      onClick={() => onClick(field)}
    >
      {label}
      {indicator(field)}
    </TableHead>
  );
}

// Placeholder components for future canvas visualization
function _TimelineCanvas(): React.JSX.Element {
  return <div className="hidden" data-component="timeline-canvas" />;
}

function _TimelineTooltip(): React.JSX.Element {
  return <div className="hidden" data-component="timeline-tooltip" />;
}

function _drawTimeline(): void {
  // Placeholder for canvas drawing logic
}

export function TraceTimeline({ events, currentTime }: TraceTimelineProps) {
  const {
    activeFilters,
    filterValue,
    sortField,
    sortDir,
    baseTimestamp,
    filteredEvents,
    highlightIndex,
    eventCounts,
    handleFilterChange,
    toggleAllFilters,
    toggleFilter,
    handleSort,
  } = useTraceData(events, currentTime);

  return (
    <Card className="skeuo-panel overflow-hidden">
      <TimelineHeader filteredCount={filteredEvents.length} totalCount={events.length} />

      <CardContent className="space-y-3">
        <TimelineLegend
          eventCounts={eventCounts}
          activeFilters={activeFilters}
          onToggleFilter={toggleFilter}
          onToggleAll={toggleAllFilters}
        />

        <TimelineFilter
          filterValue={filterValue}
          currentTime={currentTime}
          baseTimestamp={baseTimestamp}
          onFilterChange={handleFilterChange}
        />

        <TimelineTable
          filteredEvents={filteredEvents}
          baseTimestamp={baseTimestamp}
          highlightIndex={highlightIndex}
          totalEvents={events.length}
          sortField={sortField}
          sortDir={sortDir}
          onSort={handleSort}
        />
      </CardContent>
    </Card>
  );
}
