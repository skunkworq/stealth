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

const CaptureRow = memo(function CaptureRow({
  cap,
  isSelected,
  onSelect,
}: {
  cap: CaptureEntry;
  isSelected: boolean;
  onSelect: () => void;
}) {
  const time = useMemo(
    () =>
      new Date(cap.timestamp).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }),
    [cap.timestamp]
  );
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
      <span className="text-[10px] font-mono text-muted-foreground/60 shrink-0 w-[58px]">
        {time}
      </span>
      <span
        className={`text-xs truncate flex-1 ${
          isSelected ? "text-cyan-glow" : "text-foreground/70"
        }`}
        title={host}
      >
        {host}
      </span>
      <div className="flex items-center gap-1.5 shrink-0">
        {cap.status_code && (
          <span className={`text-[9px] font-mono font-bold ${
            cap.status_code >= 500 ? "text-red-400" :
            cap.status_code >= 400 ? "text-orange-400" :
            cap.status_code >= 300 ? "text-yellow-400" :
            cap.status_code >= 200 ? "text-emerald-400" :
            "text-muted-foreground"
          }`}>
            {cap.status_code}
          </span>
        )}
        {cap.ja3_hash && (
          <span className="text-[9px] font-mono text-muted-foreground/40">
            {cap.ja3_hash.substring(0, 8)}
          </span>
        )}
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

export function CaptureHistory() {
  const { selectCapture, selectedCaptureId } = useFingerprint();
  const [allCaptures, setAllCaptures] = useState<CaptureEntry[]>([]);
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);
  const [totalCount, setTotalCount] = useState(0);
  const [searchQuery, setSearchQuery] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);
  const lastDataHash = useRef<string>("");
  const isFetching = useRef(false);

  const fetchCaptures = useCallback(async () => {
    if (isFetching.current) return;
    isFetching.current = true;
    try {
      const q = searchQuery ? `&q=${encodeURIComponent(searchQuery)}` : "";
      const res = await fetch(`/captures?limit=500${q}`);
      if (!res.ok) return;
      const data: CapturesResponse = await res.json();
      const captures = data.captures ?? [];
      const hash =
        captures.length + ":" + (captures[0]?.id ?? captures[0]?.timestamp ?? "") + ":" + searchQuery;
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
    const interval = setInterval(fetchCaptures, 2000);
    return () => clearInterval(interval);
  }, [fetchCaptures]);

  const handleScroll = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 60) {
      setVisibleCount((prev) => Math.min(prev + PAGE_SIZE, allCaptures.length));
    }
  }, [allCaptures.length]);

  const visibleCaptures = useMemo(
    () => allCaptures.slice(0, visibleCount),
    [allCaptures, visibleCount]
  );

  const hasMore = visibleCount < allCaptures.length;

  return (
    <Card className="skeuo-panel overflow-hidden">
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
          <input
            type="text"
            placeholder="Search hosts, IPs, hashes..."
            value={searchQuery}
            onChange={(e) => {
               setSearchQuery(e.target.value);
               setVisibleCount(PAGE_SIZE);
            }}
            className="w-full bg-black/20 skeuo-inset border-0 rounded-md px-2.5 py-1.5 text-xs text-foreground placeholder-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-cyan-glow/50 transition-all font-mono"
          />
        </div>
        {selectedCaptureId && (
          <button
            onClick={() => selectCapture(selectedCaptureId)}
            className="text-[10px] text-cyan-glow/70 hover:text-cyan-glow mt-2 block"
          >
            ← Back to live capture
          </button>
        )}
      </CardHeader>
      <CardContent className="px-0 pb-0">
        {allCaptures.length === 0 ? (
          <div className="px-6 pb-6">
            <div className="skeuo-inset rounded-lg p-4 text-center">
              <p className="text-xs text-muted-foreground italic">
                No captures yet. Browse through the proxy to start.
              </p>
            </div>
          </div>
        ) : (
          <div
            ref={scrollRef}
            onScroll={handleScroll}
            className="overflow-y-auto max-h-[500px]"
          >
            {visibleCaptures.map((cap) => (
              <CaptureRow
                key={cap.id ?? cap.timestamp}
                cap={cap}
                isSelected={selectedCaptureId === cap.id}
                onSelect={() => cap.id && selectCapture(cap.id)}
              />
            ))}
            {hasMore && (
              <div className="py-2 text-center">
                <span className="text-[9px] text-muted-foreground/40 animate-pulse">
                  Scroll for more • {allCaptures.length - visibleCount} remaining
                </span>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
