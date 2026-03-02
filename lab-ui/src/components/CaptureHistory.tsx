"use client";

import { useState, useEffect, useCallback, useRef, memo, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useFingerprint } from "@/components/FingerprintProvider";

interface CaptureEntry {
  id?: string;
  timestamp: string;
  host?: string;
  source_ip?: string;
  ja3_hash?: string;
  ja4?: string;
  ext_count: number;
  protocol?: string;
  status_code?: number;
}

interface CapturesResponse {
  captures: CaptureEntry[];
}

const PAGE_SIZE = 30;
const MAX_FETCH_LIMIT = 500;
const FETCH_INTERVAL = 2000;
const SCROLL_THRESHOLD = 60;
const HASH_PREVIEW_LENGTH = 8;
const STATUS_SERVER_ERROR = 500;
const STATUS_CLIENT_ERROR = 400;
const STATUS_REDIRECT = 300;
const STATUS_SUCCESS = 200;

function useCaptures(searchQuery: string) {
  const [allCaptures, setAllCaptures] = useState<CaptureEntry[]>([]);
  const [totalCount, setTotalCount] = useState(0);
  const lastDataHash = useRef<string>("");
  const isFetching = useRef(false);

  const fetchCaptures = useCallback(async () => {
    if (isFetching.current) return;
    isFetching.current = true;
    try {
      const q = searchQuery ? `&q=${encodeURIComponent(searchQuery)}` : "";
      const res = await fetch(`/captures?limit=${MAX_FETCH_LIMIT}${q}`);
      if (!res.ok) return;
      const data: CapturesResponse = await res.json();
      const captures = data.captures ?? [];
      const hash = `${captures.length}:${captures[0]?.id ?? captures[0]?.timestamp ?? ""}:${searchQuery}`;
      if (hash !== lastDataHash.current) {
        lastDataHash.current = hash;
        setAllCaptures(captures);
        setTotalCount(captures.length);
      }
    } catch {
      // silently fail
    } finally {
      isFetching.current = false;
    }
  }, [searchQuery]);

  useEffect(() => {
    fetchCaptures();
    const interval = setInterval(fetchCaptures, FETCH_INTERVAL);
    return () => clearInterval(interval);
  }, [fetchCaptures]);

  return { allCaptures, totalCount };
}

function useVisibleCaptures(allCaptures: CaptureEntry[]) {
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);
  const scrollRef = useRef<HTMLDivElement>(null);

  const handleScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - SCROLL_THRESHOLD) {
      setVisibleCount(prev => Math.min(prev + PAGE_SIZE, allCaptures.length));
    }
  }, [allCaptures.length]);

  const visibleCaptures = useMemo(
    () => allCaptures.slice(0, visibleCount),
    [allCaptures, visibleCount]
  );

  const hasMore = visibleCount < allCaptures.length;
  const resetVisibleCount = useCallback(() => setVisibleCount(PAGE_SIZE), []);

  return { scrollRef, visibleCaptures, hasMore, handleScroll, resetVisibleCount };
}

function getStatusColor(statusCode: number): string {
  if (statusCode >= STATUS_SERVER_ERROR) return "text-red-400";
  if (statusCode >= STATUS_CLIENT_ERROR) return "text-orange-400";
  if (statusCode >= STATUS_REDIRECT) return "text-yellow-400";
  if (statusCode >= STATUS_SUCCESS) return "text-emerald-400";
  return "text-muted-foreground";
}

interface StatusBadgeProps {
  statusCode?: number;
}

function StatusBadge({ statusCode }: StatusBadgeProps) {
  if (!statusCode) return null;
  return (
    <span className={`text-[9px] font-mono font-bold ${getStatusColor(statusCode)}`}>
      {statusCode}
    </span>
  );
}

interface HashPreviewProps {
  hash?: string;
}

function HashPreview({ hash }: HashPreviewProps) {
  if (!hash) return null;
  return (
    <span className="text-[9px] font-mono text-muted-foreground/40">
      {hash.substring(0, HASH_PREVIEW_LENGTH)}
    </span>
  );
}

interface TimeDisplayProps {
  timestamp: string;
}

function TimeDisplay({ timestamp }: TimeDisplayProps) {
  const time = useMemo(
    () =>
      new Date(timestamp).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }),
    [timestamp]
  );
  return (
    <span className="text-[10px] font-mono text-muted-foreground/60 shrink-0 w-[58px]">{time}</span>
  );
}

interface CaptureRowProps {
  cap: CaptureEntry;
  isSelected: boolean;
  onSelect: () => void;
}

const CaptureRow = memo(function CaptureRow({ cap, isSelected, onSelect }: CaptureRowProps) {
  const host = cap.host || cap.source_ip || "—";

  return (
    <button
      onClick={onSelect}
      className={`w-full text-left px-2.5 py-2 flex items-center gap-2 border-b border-border/10 transition-all ${
        isSelected
          ? "bg-cyan-glow/10 border-l-2 border-l-cyan-glow"
          : "hover:bg-white/[0.03] border-l-2 border-l-transparent"
      }`}
    >
      <TimeDisplay timestamp={cap.timestamp} />
      <span
        className={`text-xs truncate flex-1 ${isSelected ? "text-cyan-glow" : "text-foreground/70"}`}
        title={host}
      >
        {host}
      </span>
      <div className="flex items-center gap-1.5 shrink-0">
        <StatusBadge statusCode={cap.status_code} />
        <HashPreview hash={cap.ja3_hash} />
        <Badge
          variant="outline"
          className="text-[8px] px-1 py-0 h-3.5 border-border/30 text-muted-foreground/50"
        >
          {cap.protocol || "TLS"}
        </Badge>
      </div>
    </button>
  );
});

interface CaptureListProps {
  captures: CaptureEntry[];
  selectedCaptureId?: string;
  onSelect: (id: string) => void;
  hasMore: boolean;
  scrollRef: React.RefObject<HTMLDivElement | null>;
  onScroll: () => void;
}

function CaptureList({
  captures,
  selectedCaptureId,
  onSelect,
  hasMore,
  scrollRef,
  onScroll,
}: CaptureListProps) {
  return (
    <div ref={scrollRef} onScroll={onScroll} className="overflow-y-auto max-h-[500px]">
      {captures.map(cap => (
        <CaptureRow
          key={cap.id ?? cap.timestamp}
          cap={cap}
          isSelected={selectedCaptureId === cap.id}
          onSelect={() => cap.id && onSelect(cap.id)}
        />
      ))}
      {hasMore && (
        <div className="py-2 text-center">
          <span className="text-[9px] text-muted-foreground/40 animate-pulse">
            Scroll for more • {captures.length} remaining
          </span>
        </div>
      )}
    </div>
  );
}

interface EmptyStateProps {
  message: string;
}

function EmptyState({ message }: EmptyStateProps) {
  return (
    <div className="px-6 pb-6">
      <div className="skeuo-inset rounded-lg p-4 text-center">
        <p className="text-xs text-muted-foreground italic">{message}</p>
      </div>
    </div>
  );
}

interface SearchInputProps {
  value: string;
  onChange: (value: string) => void;
}

function SearchInput({ value, onChange }: SearchInputProps) {
  return (
    <input
      type="text"
      placeholder="Search hosts, IPs, hashes..."
      value={value}
      onChange={e => onChange(e.target.value)}
      className="w-full bg-black/20 skeuo-inset border-0 rounded-md px-2.5 py-1.5 text-xs text-foreground placeholder-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-cyan-glow/50 transition-all font-mono"
    />
  );
}

function Header({
  totalCount,
  searchQuery,
  onSearchChange,
  selectedCaptureId,
  onBackToLive,
}: {
  totalCount: number;
  searchQuery: string;
  onSearchChange: (value: string) => void;
  selectedCaptureId?: string;
  onBackToLive: () => void;
}) {
  return (
    <CardHeader className="relative pb-2">
      <div className="absolute top-3 right-3 flex gap-2">
        <div className="screw-hole" />
        <div className="screw-hole" />
      </div>
      <CardTitle className="text-sm font-medium text-muted-foreground uppercase tracking-wider flex items-center gap-2">
        <span className="text-lg">📜</span>
        Captures
        <Badge variant="secondary" className="ml-auto font-mono text-[10px] skeuo-raised">
          {totalCount}
        </Badge>
      </CardTitle>
      <div className="mt-3">
        <SearchInput value={searchQuery} onChange={onSearchChange} />
      </div>
      {selectedCaptureId && (
        <button
          onClick={onBackToLive}
          className="text-[10px] text-cyan-glow/70 hover:text-cyan-glow mt-2 block"
        >
          ← Back to live capture
        </button>
      )}
    </CardHeader>
  );
}

export function CaptureHistory() {
  const { selectCapture, selectedCaptureId } = useFingerprint();
  const [searchQuery, setSearchQuery] = useState("");
  const { allCaptures, totalCount } = useCaptures(searchQuery);
  const { scrollRef, visibleCaptures, hasMore, handleScroll, resetVisibleCount } =
    useVisibleCaptures(allCaptures);

  const handleSearchChange = useCallback(
    (value: string) => {
      setSearchQuery(value);
      resetVisibleCount();
    },
    [resetVisibleCount]
  );

  const handleBackToLive = useCallback(() => {
    if (selectedCaptureId) {
      selectCapture(selectedCaptureId);
    }
  }, [selectedCaptureId, selectCapture]);

  return (
    <Card className="skeuo-panel overflow-hidden">
      <Header
        totalCount={totalCount}
        searchQuery={searchQuery}
        onSearchChange={handleSearchChange}
        selectedCaptureId={selectedCaptureId}
        onBackToLive={handleBackToLive}
      />
      <CardContent className="px-0 pb-0">
        {allCaptures.length === 0 ? (
          <EmptyState message="No captures yet. Browse through the proxy to start." />
        ) : (
          <CaptureList
            captures={visibleCaptures}
            selectedCaptureId={selectedCaptureId}
            onSelect={selectCapture}
            hasMore={hasMore}
            scrollRef={scrollRef}
            onScroll={handleScroll}
          />
        )}
      </CardContent>
    </Card>
  );
}
